"""阶段：泄露检索（GitHub 续26 / 多平台 续150-附，11-调度 + 11-多平台）。

位置：本阶段固定排在流水线**最后** —— 它不产出任何被后续阶段消费的数据，只是拿任务的注册域
去公开代码库里搜一遍，把命中整理成**线索**（`leads` 表，kind=`github` / `grepapp`）供人工判断。

**续150-附（用户 2026-10-11 点单 11-调度）**：检索只依赖**注册域**（`ctx.targets`），与子域名
收集毫无数据依赖，串行排到流水线末端纯属白等。现在 `subdomain` 阶段**一开始**就并发触发一次
（`start_early_search()`：daemon 线程、异常吞掉并写日志、绝不拖垮子域阶段）；本阶段**保持可用**，
发现已经被子域阶段跑过（`ctx.results` 里有标记）就直接跳过、**不重复发请求**。

配置（`github` 段）：`enabled`（**默认关**）/ `max_domains` / `max_queries` / `per_page` /
`max_leads` / `timeout`；token 在 `config/keys.yaml` 的 `github.token`。
配置（`multileak` 段，续150-附 11-多平台）：`enabled`（**默认关**）/ `provider`（默认 `grepapp`，
免 key）/ `max_domains` / `max_queries` / `per_page` / `max_leads` / `timeout`。

三条硬边界（改代码前先读 `scanner/github_leak.py` 文件头，那里写得比这里细）：
1. **只落元数据，绝不落文件内容** —— 仓库 / 文件路径 / 命中规则名，避免凭据明文入库；
2. **`auth=False`** —— 任务级登录态（目标侧 Cookie / Token）绝不发给第三方；
3. **默认关 + 没 token 就零请求** —— GitHub 代码搜索接口要求认证，没配 token 时直接说明原因跳过；
   多平台源（grep.app）免 key，但同样默认关、且失败一律如实写原因。

产出：`db.insert_leads()` —— **不写 `vulns`、不计入漏洞数、不自动导入 POC**。
线索的出口是 **JSONL 导出**（`type=lead`）：按续24 口径，GUI 页签与人读报告（MD / HTML）
都不再露出「线索」。
"""
import threading

from .base import Stage
from .. import db, github_leak, multileak

# github 阶段等待"子域阶段提前触发的线程"的上限（秒）：子域阶段通常早已跑完，这里只是兜底；
# 等不到就跳过（线程自己会入库），**绝不重复发请求**。
EARLY_JOIN_TIMEOUT = 30


def _run_safe(ctx, runner, name):
    """后台线程入口：检索线程里的异常**一律吞掉并写日志** —— 绝不能拖垮子域阶段。"""
    try:
        runner(ctx)
    except Exception as e:  # noqa: BLE001 - 子域阶段的后台线程，异常外溢会把它拖坏
        try:
            ctx.logger.warning(f"[{name}] 子域阶段并发检索异常（已忽略，不影响子域收集）：{e}")
        except Exception:  # noqa: BLE001 - 连日志都失败时也不能抛
            pass


def _armed(ctx, name):
    """该源是否"值得在子域阶段提前并发触发"（启用 + 有凭据/免 key + 有注册域 + 非离线）。

    `--offline` 时**不提前触发**（离线语义＝不出网）；本阶段（github）末尾仍按原行为执行
    —— 那是既有口径，不在这里改。
    """
    if (ctx.options or {}).get("offline"):
        return False
    if name == "github":
        cfg = ctx.settings.get("github", {}) or {}
        if cfg.get("enabled") is not True:
            return False
        if not github_leak.load_token(ctx.settings):
            return False          # 没 token 就零请求（发了也是 401）
        return bool(github_leak.target_domains(ctx.targets, cfg.get("max_domains")))
    cfg = ctx.settings.get("multileak", {}) or {}
    if cfg.get("enabled") is not True:
        return False
    return bool(multileak.target_domains(ctx.targets, cfg.get("max_domains")))


def start_early_search(ctx):
    """在 `subdomain` 阶段**一开始**并发触发泄露检索（不阻塞子域收集，续150-附 11-调度）。

    - 每个源一个 `daemon` 线程，结果仍走 `collect()` → `db.insert_leads()`，只产出 leads；
    - 异常在线程里吞掉并写日志（见 `_run_safe`），子域阶段不会因此失败；
    - 线程登记在 `ctx._leak_threads` 上：阶段层据此判断"是否仍在进行"，避免重复发请求。
    """
    threads = dict(getattr(ctx, "_leak_threads", None) or {})
    for name, runner in _SEARCHERS:
        if name in threads or not _armed(ctx, name):
            continue
        t = threading.Thread(target=_run_safe, args=(ctx, runner, name),
                             name=f"leak-{name}-{getattr(ctx, 'task_id', '')}", daemon=True)
        threads[name] = t
        t.start()
    ctx._leak_threads = threads


def run_github_search(ctx):
    """幂等地跑一次 GitHub 检索并入库（续150-附：发现已跑过则**跳过**，不重复发请求）。"""
    if "leads_github" in ctx.results:
        ctx.logger.info("[github] 已在子域阶段检索过，跳过")
        return
    cfg = ctx.settings.get("github", {}) or {}
    if cfg.get("enabled") is not True:
        ctx.logger.info("[github] 未启用（策略配置 → 情报与线索 可打开），跳过")
        return
    if ctx.stopped():
        ctx.logger.warning("[github] 任务已请求停止，跳过")
        return

    # 没 token 就**一次请求都不发**：代码搜索接口要求认证，发了也是 401。
    # 这里刻意把原因写清楚（而不是报"没查到泄露"），否则用户会把 401 当成"确实没泄露"。
    if not github_leak.load_token(ctx.settings):
        ctx.logger.warning("[github] 未配置 github.token（见 config/keys.yaml）—— "
                           "GitHub 代码搜索接口要求认证，跳过（一次请求都不发）")
        return

    domains = github_leak.target_domains(ctx.targets, cfg.get("max_domains"))
    if not domains:
        ctx.logger.info("[github] 无可用注册域（目标是 IP / CIDR 或认不出主机），跳过")
        return
    ctx.logger.info(f"[github] 待检索注册域 {len(domains)} 个：{', '.join(domains)}"
                    f"（请求头 auth=False，不带任务登录态）")

    leads, meta = github_leak.collect(domains, ctx.settings,
                                      logger=ctx.logger, stopped=ctx.stopped)
    # `error` 只装真失败（限流 / 401 / 网络不可达）；`capped` 是**设计内的上限收手**，
    # 打 info —— 默认 max_domains=3 × 4 条规则 = 12 次潜在查询、上限 4，正常跑必触顶。
    if meta.get("error"):
        ctx.logger.warning(f"[github] {meta['error']}")
    elif meta.get("capped"):
        ctx.logger.info(f"[github] 已查满单任务上限 {meta.get('queries', 0)} 次"
                        f"（github.max_queries），剩余查询未发出 —— 属设计上限，不是失败")

    # 截断：先按"级别 → 域名 → 仓库:路径"排好序（github_leak 里已排），保高价值的
    cap = max(1, int(cfg.get("max_leads", github_leak.DEFAULT_MAX_LEADS)
                     or github_leak.DEFAULT_MAX_LEADS))
    if len(leads) > cap:
        ctx.logger.info(f"[github] 命中 {len(leads)} 条超过上限 {cap}，仅保留前 {cap} 条")
        leads = leads[:cap]

    added = db.insert_leads(ctx.task_id, leads)
    # 结束标记：即使零命中也要落，二次调用（阶段层）据此跳过；值只是列表，供 cli 汇总 len()。
    ctx.results["leads_github"] = leads
    if not leads:
        ctx.logger.info(f"[github] 检索 {meta.get('queries', 0)} 次，未命中（GitHub 报告共 "
                        f"{meta.get('hits', 0)} 条），未产生线索")
        return
    ctx.logger.info(f"[github] 检索 {meta.get('queries', 0)} 次（GitHub 报告共 "
                    f"{meta.get('hits', 0)} 条）→ 线索 {len(leads)} 条，入库 {added} 条"
                    f"（只记仓库/文件路径/命中规则，不保存文件内容）")
    ctx.logger.info("[github] 注意：线索≠漏洞结论，需人工确认（不写 vulns、不计入漏洞数）")


def run_multileak_search(ctx):
    """幂等地跑一次多平台检索并入库（续150-附 11-多平台：grep.app 免 key 源）。"""
    if "leads_multileak" in ctx.results:
        ctx.logger.info("[multileak] 已在子域阶段检索过，跳过")
        return
    cfg = ctx.settings.get("multileak", {}) or {}
    if cfg.get("enabled") is not True:
        ctx.logger.info("[multileak] 未启用（策略配置可打开），跳过")
        return
    if ctx.stopped():
        ctx.logger.warning("[multileak] 任务已请求停止，跳过")
        return

    domains = multileak.target_domains(ctx.targets, cfg.get("max_domains"))
    if not domains:
        ctx.logger.info("[multileak] 无可用注册域（目标是 IP / CIDR 或认不出主机），跳过")
        return
    ctx.logger.info(f"[multileak] 待检索注册域 {len(domains)} 个：{', '.join(domains)}"
                    f"（provider={multileak.provider_of(ctx.settings)}，请求头 auth=False，"
                    "不带任务登录态）")

    leads, meta = multileak.collect(domains, ctx.settings,
                                    logger=ctx.logger, stopped=ctx.stopped)
    if meta.get("error"):
        ctx.logger.warning(f"[multileak] {meta['error']}")
    elif meta.get("capped"):
        ctx.logger.info(f"[multileak] 已查满单任务上限 {meta.get('queries', 0)} 次"
                        f"（multileak.max_queries），剩余查询未发出 —— 属设计上限，不是失败")

    cap = max(1, int(cfg.get("max_leads", multileak.DEFAULT_MAX_LEADS)
                     or multileak.DEFAULT_MAX_LEADS))
    if len(leads) > cap:
        ctx.logger.info(f"[multileak] 命中 {len(leads)} 条超过上限 {cap}，仅保留前 {cap} 条")
        leads = leads[:cap]

    added = db.insert_leads(ctx.task_id, leads)
    ctx.results["leads_multileak"] = leads
    if not leads:
        ctx.logger.info(f"[multileak] 检索 {meta.get('queries', 0)} 次，未命中"
                        f"（grep.app 报告共 {meta.get('hits', 0)} 条），未产生线索")
        return
    ctx.logger.info(f"[multileak] 检索 {meta.get('queries', 0)} 次（grep.app 报告共 "
                    f"{meta.get('hits', 0)} 条）→ 线索 {len(leads)} 条，入库 {added} 条"
                    f"（只记仓库/文件路径/命中规则，不保存文件内容）")
    ctx.logger.info("[multileak] 注意：线索≠漏洞结论，需人工确认（不写 vulns、不计入漏洞数）")


# 源名 → 执行函数。两源同属"线索"性质，共用提前触发 / 幂等跳过机制（续150-附）。
_SEARCHERS = (("github", run_github_search), ("multileak", run_multileak_search))


class GithubStage(Stage):
    name = "github"
    description = "GitHub / 多平台公开代码泄露检索（只产出线索，不写 vulns）"

    def run(self):
        ctx = self.ctx
        # 子域阶段可能已经并发触发过（续150-附）：等它一小会（通常早已跑完）；仍在进行就跳过，
        # 不重复发请求 —— 线程自己会把结果入库。
        threads = getattr(ctx, "_leak_threads", None) or {}
        for name, runner in _SEARCHERS:
            th = threads.get(name)
            if th is not None:
                th.join(timeout=EARLY_JOIN_TIMEOUT)
                if th.is_alive():
                    ctx.logger.info(f"[{name}] 子域阶段已并发触发检索，仍在进行，"
                                    "本阶段不再重复发起")
                    continue
            runner(ctx)
