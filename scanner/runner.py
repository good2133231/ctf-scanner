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

from . import db, extdom
from .config import LOGS_DIR, load_settings
from . import auth as taskauth
from . import throttle
from . import devmode
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
from .stages.github import GithubStage

STAGE_ORDER = ["subdomain", "takeover", "portscan", "probe",
               # cert 与 screenshot 都需要"已有存活站点"，所以紧跟 probe；
               # cert 只做一次 TLS 握手（纯标准库、秒级），比截图廉价得多，故排在截图之前；
               # 它默认关闭（`cert.enabled`），打开后才对 https / tls_ports 站点取证
               "cert", "screenshot", "osint", "jsmine", "dirscan", "vulnscan",
               # 三个"线索"阶段固定排在最后：它们不产出被后续阶段消费的数据，
               # 只把外部情报（intel / github）与本地数据（heuristic）整理成人工复核用的线索。
               # 三者都默认关闭（`intel.enabled` / `github.enabled` / `heuristic.enabled`），
               # 且**只写 leads 表**，不写 vulns、不计入漏洞数。
               # github（续26）排在 intel 之后：它要发外部请求、受第三方限流约束，
               # 而 intel 只是拉一次 KEV，谁先谁后不影响结果，排在最后便于"只重跑本阶段"。
               "intel", "heuristic", "github"]
STAGE_REGISTRY = {c.name: c for c in (SubdomainStage, TakeoverStage, PortscanStage,
                                      ProbeStage, CertStage, ScreenshotStage, OsintStage,
                                      JsmineStage, DirscanStage, VulnscanStage, IntelStage,
                                      HeuristicStage, GithubStage)}


def resume_stages(stages, current_stage):
    """续29「断点续扫」：按 `current_stage`（= 最后**进入**的阶段）算出还要重跑哪些阶段。

    **为什么不需要额外的"已完成阶段"列**：`PipelineRunner.run()` 在**每个阶段开始前**写
    `current_stage=sname`，任务正常跑完时清空。所以这个字段天然就是断点 ——
    "进程被硬杀 / 用户点了停止 / 预算耗尽"时它指向的就是那个（可能只跑了一半的）阶段。
    落到这里的两处容易把断点抹掉，都已改掉（见 `PipelineRunner.run` 与 `db.reconcile_orphan_tasks`）。

    **返回值语义（`[]` 只表示"没有可用断点"）**：调用方应据此**拒绝**续跑并提示改用「重启」，
    不要在这里回退成"全量重跑" —— 静默换成全量重跑与用户"接着跑"的预期不符
    （请求量、耗时都是另一个量级）。`run_task(resume=True)` 里那条回退分支只服务于
    **直接调用方**（测试 / 未来 CLI），且会打一条 warning 明说。

    **重跑断点所在的那个阶段是故意的**：中断时它可能只跑了一半，跳过它才是真丢结果。
    各阶段产物按去重键入库，重跑不会产生重复行。
    """
    seq = [s for s in (stages or []) if s in STAGE_REGISTRY]
    cur = (current_stage or "").strip()
    if not seq or cur not in seq:
        return []
    return seq[seq.index(cur):]


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
        # 开发模式硬闸（续97）：`dev.enabled=true` 时，把"会真出网"的第三方段（FOFA / Shodan /
        # Quake / crt.sh / GitHub 检索 / CISA KEV）在**本任务副本**上一律关掉 —— 开发模式的意义
        # 就是"随便试都不会打到外面、不烧配额"，不指望用户记得先把策略页改回 false。
        # 同样是"任务专用副本、绝不原地改"，也不写 config/settings.yaml（见 scanner/devmode.py）。
        self.settings, self.dev_suppressed = devmode.suppress_external(self.settings)
        if self.dev_suppressed:
            # 必须说出来：这些段之后会以"未启用/已跳过"的面目出现在日志与页签里，
            # 不写这一行就成了本仓反复出事的静默降级。
            logger.info("[devmode] 开发模式已压制外部情报源：" + "、".join(self.dev_suppressed)
                        + "（仅本次任务副本；关掉 dev.enabled 即恢复，config/settings.yaml 未被改动）")
        self.workdir = Path(workdir)
        self.logger = logger
        self.results = {"subdomains": [], "sites": [], "dirs": [], "vulns": [],
                        "ports": [], "takeovers": [], "csegs": [], "osint_domains": [],
                        "flags": []}
        # 续126 敏感信息 / flag 候选抽取的并发原语：各阶段在 `pool_run` 的工作线程里**同时**调
        # `flagfind.harvest`，锁必须在这里就备好 —— "用时才建"就有两个线程各建一把的窗口
        # （那时去重与 max_per_task 都不成立）。`_flag_db_seen` 留 None：第一次要用的时候
        # 在锁内从库里读（新任务/重启后表是空的，那次读几乎免费）。
        self._flag_lock = threading.Lock()
        self._flag_stats = {"texts": 0, "bytes": 0, "oversize": 0, "new": 0, "dedup": 0,
                            "full": 0}
        self._flag_seen = set()
        self._flag_db_seen = None
        # 续127：指纹补标（`fingerprint.collect/flush`）攒的是 `{站点 URL: {标签}}`，
        # 与敏感信息候选同一形状：**阶段内多线程攒、阶段末尾一次写**。锁单独一把 ——
        # 复用 flag 那把会把两件不相干的事串在一起（flush 里的写库不该挡住 harvest）。
        self._tech_lock = threading.Lock()
        self._tech_pending = {}
        # 续88：**阶段级耗时**（秒）。自检据此出"耗时基线"、跨次对比找"哪一步突然变慢"。
        # 记在 ctx 上而不是库里：它是**诊断量**，不是任务产物，不该进 DB/报告。
        self.stage_seconds = {}
        # 续89：本任务**归属账号**（0 = 无归属）—— 黑名单等"按账号"的能力据此收窄。
        self.owner_id = 0
        # 续151：本轮**新追加为自身子域名**的归属域名（`extdom.promote_owned` 的产出）。
        # 「追加层数」据此决定要不要再排下一层；ext_depth=1（默认）时它始终为空。
        self.owned_new = []

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

    def append_scope(self):
        """续25「追加式执行」：本次勾选的目标集合（URL/host，已归一化）；非追加返回 None。

        追加执行时阶段可能回退到"库里的全部站点"（如 dirscan / vulnscan / screenshot），
        那样会把**没勾选**的资产也重扫一遍。返回这个集合让阶段把输入**限定到本次勾选**。
        URL 归一：去首尾空白、去末尾 `/`（`http://a/` 与 `http://a` 视为同一目标）。

        返回值三态，**调用方靠 `is None` 区分前两态**：
        - 非追加 → `None`（`scope_sites()` 原样返回，行为与续25 之前一致）；
        - 追加且勾选非空 → 目标集合；
        - 追加但**一个都没勾上** → **空集**（曾误写成 `scope or None`→`None`，被
          `scope_sites()` 当成"非追加"而放开全库，与下面 `scope_sites` 文档里
          「空集就是空集（不扫）」自相矛盾）。空集必须**原样返回**，不能折成 None。
        """
        if not self.options.get("append"):
            return None
        raw = self.options.get("append_targets") or []
        return {str(t).strip().rstrip("/") for t in raw if str(t).strip()}

    def scope_sites(self, sites):
        """把站点列表限定到本次追加勾选（按 URL 归一匹配）；非追加/无 scope 时原样返回。

        刻意在**各阶段拿到 sites 之后**再过滤，而不是预填 `ctx.results["sites"]` ——
        后者在"勾选目标一个都没匹配上"时会被阶段里的 `or db.list_sites(...)` 当成"空"
        而回退到全库，反而把未勾选的站点全扫了。这里显式过滤，空集就是空集（不扫）。
        """
        scope = self.append_scope()
        if scope is None:
            return sites
        return [s for s in sites
                if str((s.get("url") if isinstance(s, dict) else s) or "").strip().rstrip("/")
                in scope]


# 会**产出拓展域名**的阶段。它们的产物（`js:*` / `osint:*`）是在 subdomain 阶段之后才入库的，
# 所以流水线里没人给它们做过解析 —— 存在性判定与归属追加必须挂在**最后一个**这类阶段之后。
_EXT_STAGES = ("osint", "jsmine")

# 续151「追加层数」：`ext_depth` 是「送去探测」（api_scan_ext）时的任务级选项，含义是
# **最多采集多少层**。1 层 = 只对当下这批域名做一轮；N 层 = 每层把新挖出的、**归属本项目**
# （注册域命中任务目标）的拓展域名再作为 `append_targets` 追加成子域名、再采集一次，
# 最多 N 层，且**折叠在同一任务里**（不新建任务）。上限写死 10 并每层递减 —— 必须咬住。
EXT_DEPTH_MAX = 10


def clamp_ext_depth(value, default=1):
    """把 `ext_depth` 夹到 1..EXT_DEPTH_MAX（非法 / 缺省 → default，再夹）。"""
    try:
        n = int(value)
    except (TypeError, ValueError):
        n = default
    return max(1, min(EXT_DEPTH_MAX, n))


def depth_stages(stages):
    """追加层数 > 1 时，把「产出拓展域名」的阶段补进本层阶段表（按 STAGE_ORDER 归位）。

    多层采集的前提是**每一层都能重新挖出**拓展域名，否则就退化成「把同一批域名重复扫 N 遍」。
    js:* / osint:* 的产地只有 osint 与 jsmine（`extdom.promote_owned` 只认这两类来源），
    所以把这两个阶段补进来；已有则不重复加，probe / dirscan 等既有阶段保持不动。
    """
    keep = [s for s in (stages or []) if s in STAGE_REGISTRY]
    union = list(keep) + [s for s in _EXT_STAGES if s not in keep]
    order = {name: i for i, name in enumerate(STAGE_ORDER)}
    return sorted(dict.fromkeys(union), key=lambda s: order.get(s, len(order)))


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
        # 自动拓展扫描（任务级 `auto_expand`，见 `scanner/extdom.py`）：只在**最后一个**
        # 产出拓展域名的阶段之后跑一次 —— 挂在中间会把后一个阶段的产物漏掉，
        # 每个阶段后都跑则重复解析（虽然幂等，但白白多一轮 DNS）。
        auto_expand = ctx.options.get("auto_expand") is True
        last_ext = max((i for i, s in enumerate(stages) if s in _EXT_STAGES), default=-1) \
            if auto_expand else -1
        for i, sname in enumerate(stages):
            if ctx.stopped():
                stopped = True
                break
            db.update_task(ctx.task_id, current_stage=sname, progress=int(i * 100 / total))
            ctx.logger.info(f"===== 阶段 {i + 1}/{total}：{sname} =====")
            _t_stage = time.time()          # 续88：阶段级耗时（失败也记，才能看出"卡在哪一步"）
            try:
                STAGE_REGISTRY[sname](ctx).run()
            except Exception as e:  # 阶段级容错
                ctx.logger.error(f"[{sname}] 阶段异常：{e}")
                ctx.logger.debug(traceback.format_exc())
                # **追加**而不是覆盖：一条任务可能有多个阶段失败，覆盖式写法会让前面的错误丢失
                db.append_task_error(ctx.task_id, f"{sname}: {e}")
                failed.append(sname)
            finally:
                ctx.stage_seconds[sname] = round(time.time() - _t_stage, 3)
            if i == last_ext:
                # 拓展域名的存在性判定 + 归属追加（纯 DNS 只读 + 本地写库）。
                # 单独 try：这是**附加动作**，它挂了不该把 osint/jsmine 已经入库的产物牵连掉。
                try:
                    ext_res = extdom.process(ctx.task_id, ctx.settings, logger=ctx.logger,
                                             stopped=ctx.stopped)
                    # 续151：记下本轮**归属追加**产出的域名，供「追加层数」决定下一层目标。
                    ctx.owned_new = list(
                        (ext_res.get("promote") or {}).get("promoted") or [])
                except Exception as e:  # 附加动作级容错
                    ctx.logger.error(f"[extdom] 拓展域名后处理异常：{e}")
                    ctx.logger.debug(traceback.format_exc())
                    db.append_task_error(ctx.task_id, f"extdom: {e}")
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
            # **刻意不清 `current_stage`**（续29）：它是"最后进入的阶段"，也就是断点续扫的断点
            # （`resume_stages` 按它切片）。原来的 `current_stage=""` 会把断点抹掉 ——
            # "被停止 / 预算耗尽"恰恰是最需要续跑的两类收场。
            # 走 `finish_task_run` 而不是 `update_task`（续35）：收场时必须结一次运行时长的账。
            db.finish_task_run(ctx.task_id, status="stopped", progress=done)
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
            db.finish_task_run(ctx.task_id, status="done", progress=100, current_stage="")
            ctx.logger.info("===== 流水线完成 =====")


def sync_pocs(settings=None):
    """扫描 POC 目录并同步进注册表（GUI 可视、可开关）。"""
    from .pocs import engine
    for m in engine.load_all_meta(settings):
        db.upsert_poc(m.get("_path") or m.get("id"), m)


def _maybe_queue_next_layer(ctx, task_id, stages, options, logger):
    """续151「追加层数」收尾：本层挖出**新的归属本项目域名**且还剩层数时，再排一次追加运行。

    与既有 append 语义完全一致：**折叠在同一任务里**（`db.enqueue_task(task_id, "append")`，
    不新建任务、沿用同一日志），只是 `append_targets` 换成这批新域名、`ext_depth` 减 1。
    停止 / 未正常完成的收场一律不追加（不把一次没跑完的运行接下去）。
    """
    depth = clamp_ext_depth((options or {}).get("ext_depth"))
    if depth <= 1:
        return
    if ctx.stopped():
        logger.info("[extdom] 追加层数：任务已停止，不再排下一层")
        return
    cur = db.get_task(task_id)
    if not cur or (cur["status"] or "") != "done":
        logger.info("[extdom] 追加层数：本轮未正常完成，不再排下一层")
        return
    promoted = [d for d in (getattr(ctx, "owned_new", []) or []) if d]
    # `extdom.process`（归属追加）只在 `auto_expand` 打开时随流水线跑；「送去探测」不一定带它，
    # 这里补一次幂等、纯本地写库的归属追加 —— 保证「每层新挖出的归属域名」确实被算进来。
    try:
        res = extdom.promote_owned(task_id, ctx.settings, logger=logger)
        for d in (res.get("promoted") or []):
            if d and d not in promoted:
                promoted.append(d)
    except Exception as e:      # 归属追加失败不该影响上一层已完成的结果
        logger.error(f"[extdom] 归属追加异常：{e}")
    if not promoted:
        logger.info(f"[extdom] 追加层数：本层未挖出新的归属本项目域名，追加到此为止"
                    f"（还剩 {depth - 1} 层未用）")
        return
    try:
        layer = max(1, int((options or {}).get("ext_layer") or 1))
    except (TypeError, ValueError):
        layer = 1
    total = layer + depth - 1
    remaining = depth - 1
    next_opts = dict(options or {})
    next_opts["append"] = True
    next_opts["append_targets"] = promoted
    next_opts["ext_depth"] = remaining
    next_opts["ext_layer"] = layer + 1
    from . import queue as _queue      # 延迟导入：queue 顶层 import 本模块，避免循环导入
    db.enqueue_task(task_id, "append", depth_stages(stages), next_opts)
    _queue.notify()
    logger.info(f"[extdom] 追加层数：第 {layer}/{total} 层完成，新追加 {len(promoted)} 个归属域名"
                f"（{', '.join(promoted[:5])}{' 等' if len(promoted) > 5 else ''}）"
                f" → 已排入第 {layer + 1}/{total} 层追加运行，剩余 {remaining} 层")


def run_task(task_id, name, targets_text, stages, options, settings, append=False,
             resume=False):
    """CLI 与 GUI 共用的任务执行入口（阻塞执行，调用方负责放线程）。

    `append=True`（续25「同任务追加式执行」）与默认的"新建式"执行的差别只有三处：
    1. **续写原任务的日志/工作目录**（不新建 workdir），产物落在同一处；
    2. **不清空 `error`**（保留历史错误），`progress` 重置为 0、`current_stage` 清空；
    3. 阶段输入限定到 `options["append_targets"]`（本次勾选的目标，由各阶段调
       `ctx.scope_sites()` 落实），避免 dirscan/vulnscan/screenshot 回退到"库里全部站点"
       而重扫未勾选项。
    其余（阶段顺序、阶段级容错、停止/预算语义、任务状态）与原逻辑完全一致。

    `resume=True`（续29「断点续扫」）与 `append` 有两点相同、一点**关键不同**：
    - 相同：沿用原任务与**同一个日志/工作目录**（不新建 workdir、不新建任务）；
    - 相同：`error` 按"本次运行"清空（与 `append` 相反，理由见下）；
    - **不同**：**不设 `append_targets`**。续跑的输入就是库里已有的资产，
      走 `ctx.scope_sites()` 反而会把输入收窄 —— `append_scope()` 在"`append=True` 但没有
      `append_targets`"时返回**空集**，那会把所有站点过滤光、一次都不扫。所以这里必须是
      独立参数，不能复用 `append=True`。
    本次真正执行的阶段 = `resume_stages(stages, 任务的 current_stage)`（见该函数）。
    """
    log_file = None
    prev = None
    if append or resume:
        prev = db.get_task(task_id)
        if prev and prev["log_file"]:
            # 续写同一日志文件（D9）：workdir 沿用原任务目录，文本产物也落在同一处。
            log_file = Path(prev["log_file"])
            workdir = log_file.parent
            workdir.mkdir(parents=True, exist_ok=True)
    if log_file is None:
        workdir = LOGS_DIR / f"task_{task_id}_{time.strftime('%Y%m%d_%H%M%S')}"
        workdir.mkdir(parents=True, exist_ok=True)
        log_file = workdir / "task.log"
    # 同名的 logger 已绑定原日志文件时 `get_logger` 会直接复用（见 scanner/log.py）——
    # 追加执行正好靠这一点把新日志**续写**进原文件。
    logger = get_logger(f"task-{task_id}", log_file)
    if resume:
        # 这一段必须在下面 `db.update_task(..., error="")` **之前**跑完：
        # 清空前把上次的中断原因转存进任务日志（日志是持久产物，信息不丢）。
        prev_err = str(prev["error"] or "").strip() if prev else ""
        cur = str(prev["current_stage"] or "").strip() if prev else ""
        rest = resume_stages(stages, cur)
        if rest:
            logger.info(f"[resume] 从断点续跑：上次停在 {cur}，本次只跑 {'/'.join(rest)}"
                        f"（断点所在阶段会重跑 —— 中断时它可能只跑了一半；"
                        f"此前各阶段的产物沿用库中已有数据，不重扫）")
            stages = rest
        else:
            # 只服务直接调用方（测试 / 未来的 CLI）：GUI 的 `/api/tasks/<id>/resume`
            # 已经在路由层拒绝过这种情况，不会走到这里。
            logger.warning("[resume] 找不到可用断点（current_stage 为空或不在本任务阶段列表里），"
                           "按全部阶段重跑；如需清空已有资产请改用「重启」")
        if prev_err:
            logger.warning(f"[resume] 上次中断原因（转存到这里后，error 字段按本次运行清空）：{prev_err}")
    from .targets import parse_lines
    targets = parse_lines(targets_text.splitlines())
    # 续151「追加层数」：第 2 层起的采集根就是本层的新域名（`append_targets`）——
    # subdomain / probe 取的是 `ctx.targets`，不覆盖就会退回「重扫父任务原始目标」，
    # 这一层就白跑了。**只对追加层（ext_layer>=2）生效**，不改既有 append / resume 的输入口径。
    _depth = clamp_ext_depth((options or {}).get("ext_depth"))
    try:
        _layer = max(1, int((options or {}).get("ext_layer") or 1))
    except (TypeError, ValueError):
        _layer = 1
    if _layer >= 2 and (options or {}).get("append_targets"):
        _layer_hosts = [str(t).strip() for t in options["append_targets"] if str(t).strip()]
        if _layer_hosts:
            targets = parse_lines("\n".join(_layer_hosts))
    if _depth > 1:
        logger.info(f"[extdom] 追加层数：本轮为第 {_layer}/{_layer + _depth - 1} 层，"
                    f"待采集目标 {len(targets)} 个，剩余 {_depth} 层")
    stop_event = _register_stop(task_id)
    ctx = StageContext(task_id, name, targets, stages, options, settings or load_settings(),
                       workdir, logger, stop_event=stop_event)
    # 续89：从任务行取归属账号（`get_task` 是廉价读；老库没有该列时按 0 处理）。
    _orow = db.get_task(task_id)
    ctx.owner_id = int(_orow["owner_id"] or 0) \
        if (_orow and "owner_id" in _orow.keys()) else 0
    _auth = taskauth.from_task_options(options)
    if _auth:
        # 只记名字与掩码值：日志文件会被打包/分享，凭据不进日志
        logger.info(f"[auth] 本次任务带登录态请求头 {len(_auth)} 条："
                    f"{taskauth.summary(_auth)}（值已掩码）")
    # 追加执行**不清 error**（保留前面各阶段已记下的错误），只重置进度。
    fields = {"log_file": str(log_file)}
    if not append:
        fields["error"] = ""
    # 续35「运行时长」：`started_at` 在这里写（`status`/`progress`/`current_stage` 由 `start_task_run`
    # 一并置好），`finished_at` 与累计秒数由 `PipelineRunner.run()` 的两个终态分支和下面的 except
    # 经 `db.finish_task_run` 写入。`fresh` = **新建式执行**（含 GUI「重启」）→ 累计时长清零；
    # 续跑（续29）/ 追加执行（续25）沿用同一任务与同一份资产 → 累加，见 `db.start_task_run`。
    db.start_task_run(task_id, fresh=not (append or resume), **fields)
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
        # 第三条终态（续35）：异常收场同样要结一次运行时长，否则这条任务的时长永远停在 0
        db.finish_task_run(task_id, status="stopped" if ctx.stopped() else "failed")
        # 错误信息**追加**（不覆盖）：保留前面各阶段已经记下的错误（否则只剩这一条）
        db.append_task_error(task_id, str(e))
    finally:
        _unregister_stop(task_id)
    # 续151「追加层数」：正常完成后，本层若挖出新的归属域名且还剩层数，再排一次追加运行
    # （折叠在同一任务里，不再新建任务）。停止 / 未正常完成的收场不追加。
    _maybe_queue_next_layer(ctx, task_id, stages, options, logger)
    return ctx
