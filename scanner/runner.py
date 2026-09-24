"""流水线编排：按顺序执行 Stage，统一更新任务状态与进度。

阶段顺序：subdomain -> takeover -> portscan -> probe -> cert -> screenshot -> osint
-> jsmine -> dirscan -> vulnscan -> intel -> heuristic
（默认开：takeover / jsmine / dirscan / vulnscan；默认关：portscan / cert / screenshot /
 osint / intel / heuristic，均可在「策略配置」按分类开关；
 subdomain 无开关，由任务勾选的 stages 决定）
单个阶段异常不中断整条流水线（保留已完成阶段的产物），错误**追加**记录进任务表。

停止机制（协作式取消）：
Python 线程无法被安全强杀，因此采用"取消事件 + 阶段内主动检查"的协作式方案：
GUI/CLI 调 `request_stop(task_id)` 置位事件，阶段在循环边界调 `ctx.stopped()` 主动退出，
最终任务状态写为 `stopped`（区别于 `failed`）。粒度是"当前一批请求跑完即停"，
不会对正在飞行的 HTTP 请求做中断。
"""
import threading
import time
import traceback
from pathlib import Path

from . import db
from .config import LOGS_DIR, load_settings
from . import auth as taskauth
from . import throttle
from .log import get_logger
from .stages.subdomain import SubdomainStage
from .stages.takeover import TakeoverStage
from .stages.portscan import PortscanStage
from .stages.probe import ProbeStage
from .stages.cert import CertStage
from .stages.screenshot import ScreenshotStage
from .stages.osint import OsintStage
from .stages.jsmine import JsmineStage
from .stages.dirscan import DirscanStage
from .stages.vulnscan import VulnscanStage
from .stages.intel import IntelStage
from .stages.heuristic import HeuristicStage

STAGE_ORDER = ["subdomain", "takeover", "portscan", "probe",
               # cert 与 screenshot 都需要"已有存活站点"，所以紧跟 probe；
               # cert 只做一次 TLS 握手（纯标准库、秒级），比截图廉价得多，故排在截图之前；
               # 它默认关闭（`cert.enabled`），打开后才对 https / tls_ports 站点取证
               "cert", "screenshot", "osint", "jsmine", "dirscan", "vulnscan",
               # 两个"线索"阶段固定排在最后：它们不产出被后续阶段消费的数据，
               # 只把外部情报（intel）与本地数据（heuristic）整理成人工复核用的线索。
               # 两者都默认关闭（`intel.enabled` / `heuristic.enabled`），
               # 且**只写 leads 表**，不写 vulns、不计入漏洞数。
               "intel", "heuristic"]
STAGE_REGISTRY = {c.name: c for c in (SubdomainStage, TakeoverStage, PortscanStage,
                                      ProbeStage, CertStage, ScreenshotStage, OsintStage,
                                      JsmineStage, DirscanStage, VulnscanStage, IntelStage,
                                      HeuristicStage)}

# 运行中任务的取消信号表：task_id -> threading.Event
_STOP_EVENTS = {}
_STOP_LOCK = threading.Lock()


def _register_stop(task_id):
    ev = threading.Event()
    with _STOP_LOCK:
        _STOP_EVENTS[task_id] = ev
    return ev


def _unregister_stop(task_id):
    with _STOP_LOCK:
        _STOP_EVENTS.pop(task_id, None)


def request_stop(task_id):
    """请求停止任务。返回 True 表示确有运行中的任务被标记（否则说明它已结束）。"""
    with _STOP_LOCK:
        ev = _STOP_EVENTS.get(task_id)
    if ev:
        ev.set()
        return True
    return False


def is_stopped(task_id):
    with _STOP_LOCK:
        ev = _STOP_EVENTS.get(task_id)
    return bool(ev and ev.is_set())


def running_task_ids():
    with _STOP_LOCK:
        return sorted(_STOP_EVENTS)


class StageContext:
    """贯穿一条流水线的上下文：目标、配置、结果、工作目录、取消信号。"""

    def __init__(self, task_id, name, targets, stages, options, settings, workdir, logger,
                 stop_event=None):
        self.task_id = task_id
        self.name = name
        self.targets = targets          # [(kind, raw), ...] 由 targets.parse_lines 产出
        self.stages = stages
        self.options = options or {}
        # 取消信号：**必须在注入限流器之前**赋值 —— `throttle.inject` 要把它交给限流器，
        # 让所有等待闸门 / 令牌的地方都能在 `stop_event` 置位时立刻醒来（见 scanner/throttle.py）。
        self.stop_event = stop_event or threading.Event()
        # 任务级**登录态请求头**（Cookie / Token，见 scanner/auth.py）：注入本次任务**专用**的
        # settings 副本。不做原地修改 —— CLI 与测试会复用同一个 settings dict，原地写会把
        # 一个任务的凭据带到另一个任务上（越权 + 误报源）。
        # 只在目标侧出口生效：`utils.http_request(auth=True)` 是各目标侧调用点显式声明的。
        self.settings = taskauth.inject(settings, taskauth.from_task_options(self.options))
        # 任务级限流器（F2，见 scanner/throttle.py）：同样是"任务专用副本、绝不原地改"。
        # 引用**进程级共享闸**，因此 N 个任务线程各自注入，但共享同一个全局并发上限。
        self.settings = throttle.inject(self.settings, task_id, self.stop_event, logger)
        self.workdir = Path(workdir)
        self.logger = logger
        self.results = {"subdomains": [], "sites": [], "dirs": [], "vulns": [],
                        "ports": [], "takeovers": [], "csegs": [], "osint_domains": []}

    @property
    def throttle(self):
        """本任务的限流器（`settings["_throttle"]`）；调用点只读它，从不直接碰全局。"""
        return self.settings.get("_throttle")

    def stopped(self):
        """是否应停止（阶段在循环边界调用）。

        两种来源合并为"停止"：**协作式取消**（用户点了停止 / `request_stop`）与
        **请求预算耗尽**（F2：`budget_total` 用光后限流器拒绝一切新请求）。二者都让阶段
        在循环边界干净收尾、保留已完成产物；`PipelineRunner` 会用不同文案区分它们。
        """
        th = self.throttle
        return self.stop_event.is_set() or bool(th and th.exhausted())


class PipelineRunner:
    def __init__(self, ctx):
        self.ctx = ctx

    def run(self):
        ctx = self.ctx
        stages = [s for s in ctx.stages if s in STAGE_REGISTRY]
        db.update_task(ctx.task_id, status="running", progress=0)
        total = max(1, len(stages))
        stopped = False
        failed = []
        for i, sname in enumerate(stages):
            if ctx.stopped():
                stopped = True
                break
            db.update_task(ctx.task_id, current_stage=sname, progress=int(i * 100 / total))
            ctx.logger.info(f"===== 阶段 {i + 1}/{total}：{sname} =====")
            try:
                STAGE_REGISTRY[sname](ctx).run()
            except Exception as e:  # 阶段级容错
                ctx.logger.error(f"[{sname}] 阶段异常：{e}")
                ctx.logger.debug(traceback.format_exc())
                # **追加**而不是覆盖：一条任务可能有多个阶段失败，覆盖式写法会让前面的错误丢失
                db.append_task_error(ctx.task_id, f"{sname}: {e}")
                failed.append(sname)
            if ctx.stopped():
                stopped = True
                break
        if failed:
            # "部分跑坏"必须在日志里一眼可见（此前只有分散的 error 行，容易被后面的日志淹没）
            ctx.logger.warning(f"[runner] {len(failed)} 个阶段异常：{', '.join(failed)}")
        th = ctx.throttle
        budget_exhausted = bool(th and th.exhausted() and not ctx.stop_event.is_set())
        if stopped:
            done = int((i + 1) * 100 / total) if stages else 0
            db.update_task(ctx.task_id, status="stopped", progress=done, current_stage="")
            if budget_exhausted:
                # 预算耗尽与"用户点了停止"是**两种原因**：都用 `stopped` 状态（结果确实不完整），
                # 但错误行必须写清楚，否则事后无法区分"被拒绝"与"被人为停"。
                snap = th.snapshot()
                ctx.logger.warning(
                    f"===== 任务因请求预算耗尽提前结束：已放行 {snap['granted']} 次、"
                    f"拒绝 {snap['rejected']} 次，结果不完整 =====")
                db.append_task_error(
                    ctx.task_id,
                    f"[throttle] 请求预算耗尽（budget_total={th.budget_total}），"
                    f"已拒绝 {snap['rejected']} 次请求，任务提前结束、结果不完整")
            else:
                ctx.logger.warning("===== 任务已按请求停止（已完成阶段产物保留）=====")
        else:
            db.update_task(ctx.task_id, status="done", progress=100, current_stage="")
            ctx.logger.info("===== 流水线完成 =====")


def sync_pocs(settings=None):
    """扫描 POC 目录并同步进注册表（GUI 可视、可开关）。"""
    from .pocs import engine
    for m in engine.load_all_meta(settings):
        db.upsert_poc(m.get("_path") or m.get("id"), m)


def run_task(task_id, name, targets_text, stages, options, settings):
    """CLI 与 GUI 共用的任务执行入口（阻塞执行，调用方负责放线程）。"""
    workdir = LOGS_DIR / f"task_{task_id}_{time.strftime('%Y%m%d_%H%M%S')}"
    workdir.mkdir(parents=True, exist_ok=True)
    logger = get_logger(f"task-{task_id}", workdir / "task.log")
    from .targets import parse_lines
    targets = parse_lines(targets_text.splitlines())
    stop_event = _register_stop(task_id)
    ctx = StageContext(task_id, name, targets, stages, options, settings or load_settings(),
                       workdir, logger, stop_event=stop_event)
    _auth = taskauth.from_task_options(options)
    if _auth:
        # 只记名字与掩码值：日志文件会被打包/分享，凭据不进日志
        logger.info(f"[auth] 本次任务带登录态请求头 {len(_auth)} 条："
                    f"{taskauth.summary(_auth)}（值已掩码）")
    db.update_task(task_id, log_file=str(workdir / "task.log"), status="running", error="")
    try:
        try:
            sync_pocs(ctx.settings)
        except Exception as e:
            # POC 注册表同步是"锦上添花"：它失败不该让整条流水线直接 failed
            # （并发场景下 upsert_poc 曾撞 UNIQUE 约束，实测 6 个任务里 5 个因此失败）。
            logger.warning(f"[pocs] 注册表同步失败，继续扫描：{e}")
        PipelineRunner(ctx).run()
    except Exception as e:
        logger.error(f"任务失败：{e}\n{traceback.format_exc()}")
        db.update_task(task_id, status="stopped" if ctx.stopped() else "failed")
        # 错误信息**追加**（不覆盖）：保留前面各阶段已经记下的错误（否则只剩这一条）
        db.append_task_error(task_id, str(e))
    finally:
        _unregister_stop(task_id)
    return ctx
