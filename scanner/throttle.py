"""统一并发 / 限速 / 全局预算门控（F2）。

对外承诺「检测一律非破坏性」，但在此之前**并发量完全不受控**：

- 三条出口各自放大：HTTP（`utils.http_request`）、裸 socket（`portscan._probe_port`）、
  子进程（`utils.run_cmd`）；
- 任务内：`stages/portscan.py` 是 8 主机并发 × 每主机 `portscan.full_workers`（默认 256）
  → 最坏 **2048** 个在飞 socket（top 模式 8 × 64 = 512）；
- 跨任务：GUI 里 N 个任务线程各自 `pool_run(workers=20)` → N × 2048，**进程级零上限**。

本模块提供**两级闸（任务级 + 进程级，进程级跨任务共享）+ 令牌桶限速 + 任务预算**，
通过 `settings["_throttle"]` 注入（沿用 `auth.inject` 的"任务专用副本、绝不原地改"模式，
见 `scanner/auth.py`）；**调用点只读 `settings["_throttle"]`，从不直接碰全局**。

取消兼容（硬约束）：所有等待都是 `threading.Condition` + `wait(poll)` 轮询，每 `poll` 秒
检查一次 `stop_event`；置位即释放已持有的闸并抛 `StopRequested` ——
**绝不出现"点了停止却卡在等锁"**。

预算语义（与"静默失败"划清界限）：预算耗尽**不是**"网络故障"，而是**按停止处理** ——
`Throttle.exhausted()` 返回 True → `StageContext.stopped()` 为真 → 各阶段在循环边界干净收尾，
`PipelineRunner` 把任务标 `stopped` 并追加一条明确的错误行（见 `scanner/runner.py`）。
**残留（如实登记）**：被拒的那一次调用仍可能让调用点报出"网络不可达"这类文案，
但**任务级错误行与状态才是权威**。

v1 覆盖缺口（如实登记，不装作全覆盖）：

- **不覆盖** `scanner/certs.py` 的 TLS 握手、`scanner/dnsq.py` / `utils.resolve_host` 的 DNS 查询
  （量级远小于 portscan，且已被 `cert.max_sites` / `subdomain.max_resolve` 低量约束）；
- **不覆盖** GUI 里任务外的独立动作（如 `/api/domains/resolve` 用的是 `load_settings()` 原始
  settings、没有 `_throttle`）；
- **拦不住外部工具内部的连接**：我们只做"边界闸（同时起几个子进程）+ 把算好的线程数传进去"，
  `budget_total` **不约束外部工具内部发多少连接** —— 设了预算 ≠ 外部工具也被限住了。
"""
import threading
import time


class StopRequested(Exception):
    """等待闸门 / 令牌时被协作式取消（`stop_event` 置位）—— 调用方应停止当前动作。"""


class BudgetExhausted(Exception):
    """任务请求预算耗尽 —— 调用方应停止发起新请求（按"停止"语义处理）。"""


class _Gate:
    """计数信号量（带取消轮询）。`capacity<=0` 视为"无限"，`acquire` 恒 True。"""

    def __init__(self, capacity):
        self._capacity = int(capacity or 0)
        self._cond = threading.Condition()
        self._in_flight = 0

    def acquire(self, stop_event, poll=0.1):
        """拿到一个名额返回 True；等待中被取消返回 False（且不占名额）。"""
        if self._capacity <= 0:
            return True
        with self._cond:
            while self._in_flight >= self._capacity:
                if stop_event is not None and stop_event.is_set():
                    return False
                self._cond.wait(poll)
            self._in_flight += 1
            return True

    def release(self):
        if self._capacity <= 0:
            return
        with self._cond:
            if self._in_flight > 0:
                self._in_flight -= 1
            self._cond.notify()

    @property
    def in_flight(self):
        with self._cond:
            return self._in_flight


class TokenBucket:
    """令牌桶限速器。`rate_per_sec<=0` 视为"不限速"，`acquire` 恒 True。"""

    def __init__(self, rate_per_sec, burst):
        self._rate = float(rate_per_sec or 0)
        # 突发容量留空（<=0）时取 max(rate, 1)：允许"启动瞬间攒一小簇"，之后按速率放行。
        self._burst = float(burst or 0) or max(self._rate, 1.0)
        self._tokens = self._burst
        self._last = time.monotonic()
        self._cond = threading.Condition()

    def acquire(self, stop_event, poll=0.1):
        if self._rate <= 0:
            return True
        while True:
            with self._cond:
                now = time.monotonic()
                self._tokens = min(self._burst,
                                   self._tokens + (now - self._last) * self._rate)
                self._last = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return True
                need = (1.0 - self._tokens) / self._rate
            # 在锁外短睡：既不占着 condition，又能在 poll 粒度上响应取消。
            if stop_event is not None and stop_event.is_set():
                return False
            time.sleep(min(poll, max(0.001, need)))


class _Slot:
    """一次"在飞名额"的上下文管理器。取用顺序固定（防死锁），释放逆序。"""

    def __init__(self, th, kind, weight):
        self._th = th
        self._kind = kind
        self._weight = weight
        self._got_task = False
        self._got_global = False

    def __enter__(self):
        th = self._th
        # 0) 已请求停止 → 不发起新动作（哪怕闸有空位）。与"等待中被取消"同一语义，
        #    这样"点了停止"之后不会有任何新请求溜出去（配合各阶段循环边界的 stopped()）。
        if th._stop_event is not None and th._stop_event.is_set():
            raise StopRequested("任务已请求停止")
        # 1) 预算检查：**进入闸之前**先判，避免白占名额；耗尽即按停止处理。
        if th._budget_total > 0 and th._budget_left < self._weight:
            th._note_rejected()
            raise BudgetExhausted(f"任务预算耗尽（budget_total={th._budget_total}）")
        # 2) 任务级闸
        if not th._task_gate.acquire(th._stop_event):
            raise StopRequested("任务已请求停止")
        self._got_task = True
        # 3) 进程级闸（跨任务共享）
        if not th._global_gate.acquire(th._stop_event):
            th._task_gate.release()
            self._got_task = False
            raise StopRequested("任务已请求停止")
        self._got_global = True
        # 4) 令牌桶
        if not th._rate.acquire(th._stop_event):
            th._global_gate.release()
            th._task_gate.release()
            self._got_global = False
            self._got_task = False
            raise StopRequested("任务已请求停止")
        # 5) 记账
        th._note_granted(self._weight)
        return self

    def __exit__(self, exc_type, exc, tb):
        th = self._th
        th._note_released()
        if self._got_global:
            th._global_gate.release()
            self._got_global = False
        if self._got_task:
            th._task_gate.release()
            self._got_task = False
        return False        # 不吞异常


class Throttle:
    """单个任务的门控视图：引用进程级闸 + 自己的任务级闸 / 令牌桶 / 预算。"""

    def __init__(self, *, task_id, task_cap, global_cap, rate, burst, budget,
                 subprocess_weight, stop_event, logger, global_state):
        self.task_id = task_id
        self._budget_total = int(budget or 0)
        # 对外只读别名（runner 的错误行与 GUI 展示要用到预算总量）
        self.budget_total = self._budget_total
        self._task_cap = int(task_cap or 0)
        self._global_cap = int(global_cap or 0)
        self._subprocess_weight = max(1, int(subprocess_weight or 1))
        self._stop_event = stop_event
        self._logger = logger
        self._task_gate = _Gate(self._task_cap)
        self._global_gate = global_state.gate_for(self._global_cap)
        self._rate = TokenBucket(rate, burst)
        self._lock = threading.Lock()
        self._granted = 0
        self._rejected = 0
        self._in_flight = 0
        self._budget_left = self.budget_total
        self._exhausted = False

    def effective_cap(self, stage_workers):
        """`min(阶段并发, 任务上限, 进程上限)`；三者皆 0 表示不限，返回 0。"""
        caps = [c for c in (int(stage_workers or 0), self._task_cap, self._global_cap)
                if c > 0]
        return min(caps) if caps else 0

    def slot(self, kind="http", weight=None):
        """取一个在飞名额（上下文管理器）。`kind="subprocess"` 时默认按子进程权重计预算。"""
        if weight is None:
            weight = self._subprocess_weight if kind == "subprocess" else 1
        return _Slot(self, kind, max(1, int(weight or 1)))

    def snapshot(self):
        with self._lock:
            return {"granted": self._granted, "rejected": self._rejected,
                    "in_flight": self._in_flight, "budget_left": self._budget_left}

    def exhausted(self):
        with self._lock:
            return self._exhausted

    # ---- 内部记账（由 _Slot 调用）----

    def _note_granted(self, weight):
        with self._lock:
            self._granted += 1
            if self._budget_total > 0:
                self._budget_left -= weight
            self._in_flight += 1

    def _note_released(self):
        with self._lock:
            if self._in_flight > 0:
                self._in_flight -= 1

    def _note_rejected(self):
        with self._lock:
            self._rejected += 1
            first = not self._exhausted
            self._exhausted = True
        if first and self._logger is not None:
            self._logger.warning(
                f"[throttle] 请求预算耗尽（budget_total={self.budget_total}），"
                "后续请求将被拒绝，任务将提前结束")


class _GlobalState:
    """进程级共享状态：全局闸门（跨任务共享）+ 构建锁。"""

    def __init__(self):
        self.lock = threading.Lock()
        self.gate = None
        self.capacity = None

    def gate_for(self, capacity):
        """取（必要时重建）进程级闸门。容量变化时重建 —— 配置改了就按新值生效。"""
        with self.lock:
            if self.gate is None or self.capacity != capacity:
                self.gate = _Gate(capacity)
                self.capacity = capacity
            return self.gate


_GLOBAL_STATE = _GlobalState()


def _num(lim, key, default, cast):
    """从 limits 段取一个数值，非法/缺失时回退默认。"""
    try:
        return cast(lim.get(key, default))
    except (TypeError, ValueError):
        return cast(default)


def build(settings, task_id, stop_event, logger):
    """按 `settings["limits"]` 构建一个任务的 `Throttle`（引用共享的进程级闸）。"""
    lim = (settings or {}).get("limits", {}) or {}
    return Throttle(
        task_id=task_id,
        task_cap=_num(lim, "max_inflight_per_task", 256, int),
        global_cap=_num(lim, "max_inflight_global", 256, int),
        rate=_num(lim, "rate_per_sec", 0, float),
        burst=_num(lim, "rate_burst", 0, float),
        budget=_num(lim, "budget_total", 0, int),
        subprocess_weight=_num(lim, "budget_subprocess_weight", 1, int),
        stop_event=stop_event, logger=logger, global_state=_GLOBAL_STATE)


def inject(settings, task_id, stop_event, logger):
    """把限流器注入任务**专用**的 settings 副本（绝不原地改，沿用 `auth.inject` 的模式）。"""
    s = dict(settings or {})
    s["_throttle"] = build(s, task_id, stop_event, logger)
    return s
