"""持久化任务队列的 worker（续49）。

为什么需要它：GUI 原先在 `_spawn()` 里 `threading.Thread(target=run_task, ...)` 直接起线程 ——
进程一重启，线程没了、任务却仍挂在 `running`（旧实现只能把它标 `failed`）。用户明确要求
**重启不丢任务**，于是改成：`_spawn()` 只把这次运行的入参写进库并置 `queued`（见
`db.enqueue_task`），由本模块的 worker 线程认领执行。进程重启后 `db.reconcile_orphan_tasks`
把死掉的 `running` **重新入队**，worker 接着跑。

几个刻意的设计取舍：

1. **不复用 `runner._STOP_EVENTS`**：那张表是"任务级取消信号"，按 `task_id` 覆盖式注册，语义是
   "谁在跑这个任务"。队列需要的是"worker 线程自己的存活 / 唤醒"信号，两者生命周期不同
   （worker 常驻、跨任务；停止事件随单次 run 生灭）。混用会让"停一个任务"与"停 worker"纠缠，
   也会让 `request_stop` 误判。所以这里**自带** `threading.Event`（停止）+ `threading.Condition`
   （唤醒），与任务级取消互不干扰。

2. **认领走"只读查询 + 原子 UPDATE"**（`db.claim_next_queued`）：空队列空转时**不抢全库唯一的
   写锁**（避免与 dirscan / portscan 那几百行一批的资产写入争锁），认领那一条 UPDATE 用
   `WHERE status='queued'` 兜住并发，保证**同一任务只有一个消费者** —— 因为
   `runner._register_stop` 是覆盖式注册，重复消费会让「停止」失效。

3. **默认单消费者**（`queue.workers=1`）：串行 = 最省目标侧带宽、最不易触发风控 / 封禁；
   服务器上可调大（上限 8）。`workers>1` 时靠上面的原子认领保证不重复消费。

4. **空转退避 + 事件唤醒**：没有任务时按 0.2s→2s 指数退避，`notify()` 立刻唤醒 —— 既不空转
   烧 CPU，也不会"入队后要等满一个退避周期才动"。唤醒用 `Condition` + 一个**代数计数器**
   （`_gen`）而非裸 `Event`：worker 在**不持锁**时做 DB 认领（避免与扫描写争锁），唤醒前再核对
   `_gen` 是否变化，从而既避免"clear 与 set 交错"的**丢唤醒**，又不在持锁期间做 I/O。

5. **worker 异常绝不杀线程**：单次 dispatch 抛异常只记日志并把该任务收成 `failed`，线程继续
   处理下一个 —— 否则一次坏任务会让整个队列永久停摆。
"""
import json
import threading

from . import db, runner
from .log import get_logger

logger = get_logger("queue")

# 空转退避区间与 worker 数上限（见文件头第 3/4 点）
_IDLE_MIN = 0.2
_IDLE_MAX = 2.0
_MAX_WORKERS = 8


def config(settings=None):
    """从 `settings["queue"]` 读出 worker 数（默认 1，夹到 1..8）。

    单消费者是**默认且推荐**的：串行最省目标侧带宽、最不容易触发风控；要并行请在
    `config/settings.yaml` 的 `queue.workers` 上调（服务器场景）。非法值一律回落到 1。
    """
    cfg = (settings or {}).get("queue") or {}
    try:
        n = int(cfg.get("workers", 1))
    except (TypeError, ValueError):
        n = 1
    return {"workers": max(1, min(_MAX_WORKERS, n))}


def _load_run_spec(task_id, mode):
    """从库里重建这次运行的入参：`(task, stages, options)`（续49）。

    优先用 `run_payload`（`_spawn` 入队时写的**精确入参**：本次运行阶段 + 运行期选项）；
    缺失时退回任务自身的 `stages` / `options`（老行 / 直接入队的场景）。这样"重启后重新入队"
    与"首次入队"走的是同一条重建路径。`mode` 只决定 append / resume 两个布尔，由调用方解释。
    """
    task = db.get_task(task_id)
    if not task:
        return None, [], {}
    keys = task.keys()
    payload = {}
    try:
        payload = json.loads((task["run_payload"] if "run_payload" in keys else "") or "{}")
    except (TypeError, ValueError):
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    stages = payload.get("stages")
    if not isinstance(stages, list) or not stages:
        stages = [s for s in (task["stages"] or "").split(",") if s]
    options = payload.get("options")
    if not isinstance(options, dict):
        try:
            options = json.loads(task["options"] or "{}")
        except (TypeError, ValueError):
            options = {}
        if not isinstance(options, dict):
            options = {}
    return task, stages, options


def _default_dispatch(task_id, mode, settings):
    """默认消费者：按 `mode` 调 `runner.run_task`（生产用；测试可注入自己的 `dispatch`）。"""
    task, stages, options = _load_run_spec(task_id, mode)
    if not task:
        return
    eff = settings or {}
    # 续50：开发模式「全流程自检」任务 —— 本次运行改用"压量到最小 + 全阶段打开"的 settings
    # **副本**（只影响这一个任务；绝不写回 config/settings.yaml，见 scanner/devmode.py 文件头）。
    # 标记写在任务 options 的 `dev_selfcheck` 上（由 GUI 自检按钮 / 调用方设置）。
    if isinstance(options, dict) and options.get("dev_selfcheck"):
        from . import devmode
        eff = devmode.enable_all_stages(devmode.apply(eff))
    runner.run_task(task_id, task["name"], task["targets"], stages, options,
                    eff, append=(mode == "append"), resume=(mode == "resume"))


class _Queue:
    """队列单例：管理 worker 线程 + 唤醒 / 停止信号（模块级 `_QUEUE` 持有）。"""

    def __init__(self):
        self._lock = threading.Lock()       # 保护 start/stop 的并发调用
        self._cv = threading.Condition()    # 空转等待 / 唤醒（见文件头第 4 点）
        self._gen = 0                       # 唤醒代数：notify() 自增，worker 靠它避免丢唤醒
        self._stop = threading.Event()
        self._threads = []
        self._dispatch = None

    # ---- 生命周期 ----

    def start(self, settings=None, dispatch=None):
        """启动 worker（**幂等**：已在跑则直接返回）。

        `dispatch(task_id, mode)` 可注入（测试用桩替代 `runner.run_task`）；缺省时按
        `runner.run_task` 执行。
        """
        with self._lock:
            if self._threads:
                return
            n = config(settings)["workers"]
            self._stop = threading.Event()
            if dispatch is None:
                def dispatch(tid, mode, _s=settings):
                    return _default_dispatch(tid, mode, _s)
            self._dispatch = dispatch
            self._threads = [threading.Thread(target=self._run, name=f"cs-queue-{i}",
                                              daemon=True) for i in range(n)]
            for t in self._threads:
                t.start()
            logger.info(f"[queue] 已启动 {n} 个 worker（queue.workers={n}）")

    def stop(self, timeout=5.0):
        """停止 worker 并 join（测试需要确定性收尾；生产里 daemon 线程随进程退出即可）。"""
        with self._lock:
            threads = list(self._threads)
            self._threads = []
        self._stop.set()
        with self._cv:
            self._cv.notify_all()
        for t in threads:
            t.join(timeout=timeout)

    def notify(self):
        """唤醒空转的 worker（入队后调用）。持锁自增代数并唤醒，避免丢唤醒；不做 I/O。"""
        with self._cv:
            self._gen += 1
            self._cv.notify_all()

    def running(self):
        return bool(self._threads)

    # ---- worker 主循环 ----

    def _run(self):
        idle = _IDLE_MIN
        while not self._stop.is_set():
            with self._cv:
                gen = self._gen
            # 认领**不持锁**：避免与扫描的批量写争 `db._WRITE_LOCK` 时把 notify() 也堵住
            row = db.claim_next_queued()
            if row is not None:
                idle = _IDLE_MIN
                self._handle(row)
                continue
            # 空队列：只有"自取 gen 以来没有新入队"时才安心退避等待（否则立刻再认领一次）
            with self._cv:
                if self._stop.is_set():
                    break
                if self._gen == gen:
                    self._cv.wait(timeout=idle)
                    idle = min(idle * 2.0, _IDLE_MAX)

    def _handle(self, row):
        """执行一次认领到的任务；任何异常都只收尾该任务，绝不杀 worker（见文件头第 5 点）。"""
        tid = row["id"]
        mode = str(row["run_mode"] or "fresh").strip().lower() or "fresh"
        try:
            self._dispatch(tid, mode)
        except Exception as e:      # noqa: BLE001 - worker 绝不能被单个任务拖死
            logger.error(f"[queue] 任务 #{tid} 执行异常：{e}")
            try:
                cur = db.get_task(tid)
                if cur and cur["status"] in ("running", "queued"):
                    db.finish_task_run(tid, status="failed")
                    db.append_task_error(tid, f"[queue] 执行异常：{e}")
            except Exception:
                pass


_QUEUE = _Queue()


# ---- 模块级入口（供 gui.app / 测试调用）----

def start(settings=None, dispatch=None):
    """启动队列 worker（幂等）。`settings` 提供 `queue.workers`；`dispatch` 可注入测试桩。"""
    _QUEUE.start(settings, dispatch)


def stop(timeout=5.0):
    """停止队列 worker 并 join。"""
    _QUEUE.stop(timeout)


def notify():
    """唤醒空转的 worker（入队后调用）。"""
    _QUEUE.notify()


def running():
    """worker 是否在跑（测试 / 诊断用）。"""
    return _QUEUE.running()
