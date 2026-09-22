"""流水线编排：按顺序执行 Stage，统一更新任务状态与进度。

阶段顺序：subdomain -> takeover -> portscan -> probe -> osint -> jsmine -> dirscan -> vulnscan
（takeover / jsmine 默认开，portscan / osint 默认关，均可在「策略配置」按分类开关）
单个阶段异常不中断整条流水线（保留已完成阶段的产物），错误记录进任务表。

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
from .log import get_logger
from .stages.subdomain import SubdomainStage
from .stages.takeover import TakeoverStage
from .stages.portscan import PortscanStage
from .stages.probe import ProbeStage
from .stages.osint import OsintStage
from .stages.jsmine import JsmineStage
from .stages.dirscan import DirscanStage
from .stages.vulnscan import VulnscanStage

STAGE_ORDER = ["subdomain", "takeover", "portscan", "probe",
               "osint", "jsmine", "dirscan", "vulnscan"]
STAGE_REGISTRY = {c.name: c for c in (SubdomainStage, TakeoverStage, PortscanStage,
                                      ProbeStage, OsintStage, JsmineStage,
                                      DirscanStage, VulnscanStage)}

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
        self.settings = settings
        self.workdir = Path(workdir)
        self.logger = logger
        self.results = {"subdomains": [], "sites": [], "dirs": [], "vulns": [],
                        "ports": [], "takeovers": [], "csegs": [], "osint_domains": []}
        self.stop_event = stop_event or threading.Event()

    def stopped(self):
        """是否已被请求停止（阶段在循环边界调用）。"""
        return self.stop_event.is_set()


class PipelineRunner:
    def __init__(self, ctx):
        self.ctx = ctx

    def run(self):
        ctx = self.ctx
        stages = [s for s in ctx.stages if s in STAGE_REGISTRY]
        db.update_task(ctx.task_id, status="running", progress=0)
        total = max(1, len(stages))
        stopped = False
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
                db.update_task(ctx.task_id, error=f"{sname}: {e}")
            if ctx.stopped():
                stopped = True
                break
        if stopped:
            done = int((i + 1) * 100 / total) if stages else 0
            db.update_task(ctx.task_id, status="stopped", progress=done, current_stage="")
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
    db.update_task(task_id, log_file=str(workdir / "task.log"), status="running", error="")
    try:
        sync_pocs(ctx.settings)
        PipelineRunner(ctx).run()
    except Exception as e:
        logger.error(f"任务失败：{e}\n{traceback.format_exc()}")
        db.update_task(task_id,
                       status="stopped" if ctx.stopped() else "failed", error=str(e))
    finally:
        _unregister_stop(task_id)
    return ctx
