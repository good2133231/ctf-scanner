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
from .dirscan import TECH_LANG, _dict_kind
from .. import afrog as afrog_mod
from .. import config, db, flagfind
from ..evasion import detect as detect_waf
from ..owasp import checks as owasp_checks
from ..pocs import engine
from ..utils import pool_run


def _lang_conflict(poc, site_lang):
    """该 POC 是否与本站点已判出的语言**冲突**（冲突则应跳过）。

    语言表直接复用 `dirscan.TECH_LANG`（**单一产地**，改一处两边都跟着变）；
    判定"站点是什么语言"也复用 `dirscan._dict_kind`（URL 后缀优先、再看指纹标签）。

    只有"站点语言已知"且"POC 标签点明了一种**不同**语言"才算冲突；通用 POC（标签里没有语言）
    或站点语言未知时**一律不拦**（宁可多跑，也不误伤 —— 指纹判错时不能连带把 POC 也丢了）。
    """
    if not site_lang:
        return False
    tags = {str(t).lower() for t in ((poc.get("info") or {}).get("tags") or [])}
    langs = {TECH_LANG[t] for t in tags if t in TECH_LANG}
    return bool(langs) and site_lang not in langs


def _retest_mark(ctx, new_vulns, sites):
    """独立复测三态（续150，用户点单）：把本轮"复测"结果与库中旧结论做对比并落库。

    判据（**不只是"没再报出来就算修好了"** —— 那会把"没探到"误报成"已修复"）：
      · 旧结论 `(target, poc_id)` 在本轮结果里**再次出现** → `reproduced`（仍可复现）；
      · 没出现，但它的 `target` 本轮**确实探过**（在 `sites` 里）→ `fixed`（已修复）；
      · 没出现，且 `target` 本轮**没探到** → `unconfirmed`（无法确认，**不是**已修复）。
    只写复测状态列，不改结论、不删行。
    """
    probed, probed_hosts = set(), set()
    for s in (sites or []):
        u = str((s.get("url") if isinstance(s, dict) else s) or "").strip()
        if not u:
            continue
        probed.add(u)
        try:
            from urllib.parse import urlsplit
            h = urlsplit(u).netloc.lower()
            if h:
                probed_hosts.add(h)
        except Exception:                                    # noqa: BLE001 - 解析失败不算错
            pass
    newkeys = set()
    for v in (new_vulns or []):
        newkeys.add((str(v.get("target") or ""), str(v.get("poc_id") or "")))
    rep, fixed, unc = [], [], []
    for row in db.list_vulns(ctx.task_id, limit=None):
        key = (str(row["target"] or ""), str(row["poc_id"] or ""))
        if key in newkeys:
            rep.append(row["id"])
        else:
            t = str(row["target"] or "").strip()
            try:
                from urllib.parse import urlsplit
                th = urlsplit(t).netloc.lower()
            except Exception:                                # noqa: BLE001 - 解析失败按未探到
                th = ""
            if t in probed or (th and th in probed_hosts):
                fixed.append(row["id"])          # 目标本轮探过、但没再报出来 ⇒ 已修复
            else:
                unc.append(row["id"])            # 目标本轮没探到 ⇒ 无法确认（**不**当已修复）
    if rep:
        db.bulk_set_vuln_retest(rep, "reproduced")
    if fixed:
        db.bulk_set_vuln_retest(fixed, "fixed")
    if unc:
        db.bulk_set_vuln_retest(unc, "unconfirmed")
    ctx.logger.info(f"[vulnscan] 复测三态：仍可复现 {len(rep)} / 已修复 {len(fixed)} / "
                    f"无法确认 {len(unc)}（没探到的目标记「无法确认」，**不**误报「已修复」）")


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
        sites = ctx.scope_sites(sites)          # 续25：追加执行时限定到本次勾选（非追加原样）
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
            if not pocs:
                return []
            # 续150：站点语言已知时，剔掉**另一种语言**的 POC（与 dirscan 的字典分桶同一口径）。
            # 未知语言的站点不拦（`_lang_conflict` 只在两边都明确时才算冲突）。
            _slang = _dict_kind(str(site.get("tech") or ""), str(site.get("url") or ""))
            pool = [p for p in pocs if not _lang_conflict(p, _slang)]
            if _slang and len(pool) != len(pocs):
                ctx.logger.debug(f"[vulnscan] {site.get('url')}：语言 {_slang}，"
                                 f"按语言跳过 {len(pocs) - len(pool)} 个异构 POC")
            if not link_tags or not pool:
                return _by_conf(pool)[:poc_cap] if pool else []
            tech = {t.strip().lower() for t in str(site.get("tech") or "").split(",") if t.strip()}
            if not tech:
                return _by_conf(pool)[:poc_cap]
            hit, rest = [], []
            for p in pool:
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
                # `registry=pocs`：workflow 里 `tags:` 步骤的候选集，直接用本阶段已加载好的
                # 那份（否则每个站点都会把 300+ 个 POC 文件重读一遍）。
                for v in engine.run_poc_on_target(poc, url, ctx.settings, site=site,
                                                  registry=pocs):
                    # POC 结果与内置检查共用同一级别门槛（critical 恒保留）
                    if not owasp_checks.severity_ok(v.get("severity", "medium"), floor):
                        continue
                    found.append(v)
            return found

        all_v = []
        for batch in pool_run(_scan_site, sites, workers=workers,
                            logger=ctx.logger, label="站点漏洞初筛"):
            all_v.extend(batch)
        # afrog（续121 接入；续149 默认开）。它是"另起一个自管请求的外部进程"，所以
        # ① 只喂它逐条判过的只读 + info 级模板（scanner/afrog.py::plan），② 结果按我们的
        # 级别门槛再筛一遍（它自己那套 -S 口径不作数），③ 日志里说清请求不经本任务预算。
        if afrog_mod.enabled(ctx.settings):
            af_v, af_note = afrog_mod.run(sites, ctx.settings, ctx.logger,
                                         workdir=ctx.workdir, throttle=ctx.throttle)
            if af_note.startswith("!"):
                ctx.logger.warning(f"[afrog] {af_note[1:]}（**不是**「没扫出东西」，是没跑成）")
            elif af_note.startswith("~"):
                # 续149：按设计跳过（未装 afrog / PoC 目录没有只读模板）—— 默认开后没装 afrog
                # 的机器每次都会走到这里，用 info 级说清楚即可，**不得**刷成 warning。
                ctx.logger.info(f"[afrog] {af_note[1:]}")
            else:
                kept = [v for v in af_v
                        if owasp_checks.severity_ok(v.get("severity", "medium"), floor)]
                ctx.logger.info(f"[afrog] {af_note}；过级别门槛 {floor} 的 {len(kept)} 条入账")
                all_v.extend(kept)
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
        # 跨运行去重（续25，D2）：追加「复查」时按 (target, poc_id) 跳过**已在库**的同键，
        # 只把**新增的脆弱对**入库 —— 既避免产生未复核的重复行，又保住用户已打的
        # review / review_note（那两列挂在旧行上，覆盖或删旧行都会丢）。
        new_v = db.drop_existing(ctx.task_id, "vulns", ("target", "poc_id"), uniq,
                                 lambda v: (v.get("target"), v.get("poc_id")))
        for v in new_v:
            db.insert_vuln(ctx.task_id, v)
        # 敏感信息候选（续126）：POC 的**证据与详情**里经常直接带着 flag（题目把 flag 放在
        # 回显里，POC 把回显抄进 evidence）。这一步只读已经在手的字符串，零额外请求。
        _flag0 = flagfind.begin(ctx)
        for v in uniq:
            for _txt in (v.get("evidence"), v.get("detail")):
                if _txt:
                    flagfind.harvest(ctx, v.get("target"), str(_txt), "poc")
        _fnote = flagfind.note(ctx, _flag0)
        if _fnote:
            ctx.logger.info("[vulnscan] 敏感信息候选 " + _fnote)
        ctx.results["vulns"] = uniq
        by_sev = {}
        for v in uniq:
            by_sev[v.get("severity", "medium")] = by_sev.get(v.get("severity", "medium"), 0) + 1
        _dup = len(uniq) - len(new_v)
        ctx.logger.info(
            f"[vulnscan] 潜在漏洞 {len(uniq)} 项"
            + (f"（{' / '.join(f'{k}:{n}' for k, n in sorted(by_sev.items()))}）" if uniq else "")
            + (f"（跨运行去重跳过 {_dup} 项已入库）" if _dup else "")
            + "，均为初筛结果，需人工确认")
        # 续150：独立复测模式（任务级选项 retest=True）—— 跑完与旧结论做三态对比。
        if ctx.options.get("retest") is True:
            _retest_mark(ctx, uniq, sites)