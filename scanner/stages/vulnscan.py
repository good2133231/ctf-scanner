"""阶段 4：漏洞扫描（POC 引擎 + OWASP Top10 启发式检查）。

输入为 probe 阶段的存活站点（或任务中直接给定的 URL）；
扫描在站点级并发，站点内部串行执行各检查，避免对单目标压力过大。

阶段总开关 `vulnscan.enabled`（默认开）：关闭后整阶段跳过，连请求都不发。
门控（`checks` 段）：`poc_engine` 为 POC 引擎总开关；`min_severity` 对 POC 结果同样生效
（内置 OWASP 检查在 `owasp.checks.run_all` 内部自行门控）。
另外每站点会做一次 WAF 指纹识别（`evasion.waf_detect`），命中则在日志中提示，
方便判断"扫不出来"到底是没漏洞还是被拦了。
"""
from .base import Stage
from .. import config, db
from ..evasion import detect as detect_waf
from ..owasp import checks as owasp_checks
from ..pocs import engine
from ..utils import pool_run


class VulnscanStage(Stage):
    name = "vulnscan"
    description = "POC 引擎 + OWASP Top10 启发式检查（级别/分类门控）"

    def run(self):
        ctx = self.ctx
        scfg = ctx.settings.get("vulnscan", {}) or {}
        if scfg.get("enabled") is not True:
            ctx.logger.info("[vulnscan] 未启用（策略配置 → 检测策略 可打开），跳过")
            return
        limits = ctx.settings.get("limits", {})
        ccfg = ctx.settings.get("checks", {}) or {}
        floor = str(ccfg.get("min_severity", "medium")).lower()
        use_pocs = ccfg.get("poc_engine", True) is not False
        sites = list(ctx.results.get("sites") or [])
        if not sites:
            # 回退库里的站点：单独跑本阶段（`-p vulnscan`）或进程重启后，内存结果已经没了
            # 但资产还在库里 —— 不回退的话这些场景会静默"无可扫描站点"。
            # `db.list_sites()` 是 sqlite3.Row，必须转 dict。
            sites = [dict(r) for r in db.list_sites(ctx.task_id)]
        if not sites:
            # 兼容仅导入 URL 且 probe 未产出站点的任务
            sites = [{"url": raw, "source": "input"} for kind, raw in ctx.targets if kind == "url"]
        sites = sites[: int(limits.get("vulnscan_max_urls", 100))]
        if not sites:
            ctx.logger.info("[vulnscan] 无可扫描站点，跳过")
            return

        pocs = engine.load_enabled_pocs(ctx.settings) if use_pocs else []
        link_tags = ccfg.get("poc_link_tags", True) is not False
        poc_cap = int(ccfg.get("poc_max_per_site", 80) or 80)
        skip_sev = sorted(config.skip_severities(ctx.settings))
        ctx.logger.info(
            f"[vulnscan] 目标 {len(sites)} 个；级别门槛 {floor}；"
            f"启用 POC {len(pocs)} 个{'（POC 引擎已关闭）' if not use_pocs else ''}；"
            f"内置检查 {len(owasp_checks.enabled_checks(ctx.settings))}/"
            f"{len(owasp_checks.CHECKS)} 项"
            + (f"；{'/'.join(skip_sev)} 级检测已跳过（连请求都不发）" if skip_sev else "")
            + ("；POC 按指纹标签优先" if link_tags and pocs else ""))

        workers = max(1, int(limits.get("max_workers", 20)) // 2)
        evcfg = ctx.settings.get("evasion", {}) or {}
        do_waf = evcfg.get("waf_detect", True)

        def _by_conf(items):
            """按置信度高低排序（P1-2）：high → medium → low，同级保持注册表内原顺序。

            `list.sort` 是稳定排序，所以"同级保持原顺序"是免费的；这里只加一层排序键，
            不改变"哪些 POC 会被执行"的集合 —— 那仍由注册表开关与级别门控决定。
            """
            return sorted(items, key=lambda p: -db.CONF_ORDER.index(
                p.get("_confidence") or "low"))

        def _pocs_for(site):
            """指纹→POC 联动（P1-1）：站点技术栈命中的 POC 先跑，其余按上限补在后面。

            命中项**不受 `poc_max_per_site` 限制**（既然指纹对上了，就是最可能有结果的那批）；
            未命中项只是排在后面并受上限约束，不会被整体丢弃 —— 指纹库只有十几条规则，
            直接"不匹配就不跑"会漏掉大量没有指纹的组件。
            批次内部再按置信度排序（P1-2）：注册表放开大批低置信规则时，
            额度先给高置信规则，避免"字母序的运气"决定谁被执行。
            """
            if not link_tags or not pocs:
                return _by_conf(pocs)[:poc_cap] if pocs else []
            tech = {t.strip().lower() for t in str(site.get("tech") or "").split(",") if t.strip()}
            if not tech:
                return _by_conf(pocs)[:poc_cap]
            hit, rest = [], []
            for p in pocs:
                tags = {str(t).lower() for t in ((p.get("info") or {}).get("tags") or [])}
                (hit if tags & tech else rest).append(p)
            return _by_conf(hit) + _by_conf(rest)[:max(0, poc_cap - len(hit))]

        def _scan_site(site):
            if ctx.stopped():
                return []
            url = site["url"] if isinstance(site, dict) else str(site)
            if do_waf:
                try:
                    detect_waf(url, ctx.settings, logger=ctx.logger)
                except Exception as e:
                    ctx.logger.debug(f"[vulnscan] WAF 探测失败（{url}）：{e}")
            # 把任务 logger 传给检查：需要写过程日志的检查（SSRF 回连在外部回调模式下
            # 要交代注入了哪些 token）才能写进 `logs/task_*/task.log`。
            found = list(owasp_checks.run_all(url, ctx.settings, logger=ctx.logger))
            for poc in _pocs_for(site if isinstance(site, dict) else {}):
                for v in engine.run_poc_on_target(poc, url, ctx.settings, site=site):
                    # POC 结果与内置检查共用同一级别门槛（critical 恒保留）
                    if not owasp_checks.severity_ok(v.get("severity", "medium"), floor):
                        continue
                    found.append(v)
            return found

        all_v = []
        for batch in pool_run(_scan_site, sites, workers=workers):
            all_v.extend(batch)
        if ctx.stopped():
            # 这里是"协作式取消"：已完成批次的结果是有效的，**照常入账**
            # （此前文案写"结果不再入账"却仍入库，与行为矛盾，改成如实描述）。
            ctx.logger.warning("[vulnscan] 任务已请求停止，只记录已完成批次的结果")

        uniq, seen = [], set()
        for v in all_v:
            key = (v.get("target"), v.get("poc_id"))
            if key in seen:
                continue
            seen.add(key)
            uniq.append(v)
        for v in uniq:
            db.insert_vuln(ctx.task_id, v)
        ctx.results["vulns"] = uniq
        by_sev = {}
        for v in uniq:
            by_sev[v.get("severity", "medium")] = by_sev.get(v.get("severity", "medium"), 0) + 1
        ctx.logger.info(
            f"[vulnscan] 潜在漏洞 {len(uniq)} 项"
            + (f"（{' / '.join(f'{k}:{n}' for k, n in sorted(by_sev.items()))}）" if uniq else "")
            + "，均为初筛结果，需人工确认")