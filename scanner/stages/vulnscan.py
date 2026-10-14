"""阶段 4：漏洞扫描（POC 引擎 + OWASP Top10 启发式检查）。

输入为 probe 阶段的存活站点（或任务中直接给定的 URL）；
扫描在站点级并发，站点内部串行执行各检查，避免对单目标压力过大。

阶段总开关 `vulnscan.enabled`（默认开）：关闭后整阶段跳过，连请求都不发。
门控（`checks` 段）：`poc_engine` 为 POC 引擎总开关；`min_severity` 对 POC 结果同样生效
（内置 OWASP 检查在 `owasp.checks.run_all` 内部自行门控）。
另外每站点会做一次 WAF 指纹识别（`evasion.waf_detect`），命中则在日志中提示，
方便判断"扫不出来"到底是没漏洞还是被拦了。
"""
import threading

from .base import Stage
from .dirscan import TECH_LANG, _dict_kind
from .. import afrog as afrog_mod
from .. import config, db, flagfind, ml
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


def _retest_mark(ctx, new_vulns, sites, scan_errors=None):
    """独立复测三态（续150，用户点单）：把本轮"复测"结果与库中旧结论做对比并落库。

    判据（**不只是"没再报出来就算修好了"** —— 那会把"没探到"误报成"已修复"）：
      · 旧结论 `(target, poc_id)` 在本轮结果里**再次出现** → `reproduced`（仍可复现）；
      · 没出现，但它的 `target` 本轮**确实探过**（在 `sites` 里）→ `fixed`（已修复）；
      · `target` 站点本轮探过、但**检查执行失败**（`scan_errors`，续180 借鉴点①）→
        `unconfirmed` —— 一次请求失败不证明已修复，"没跑成"不许记成"已修复"；
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
            _err = bool(scan_errors) and (t in scan_errors or (th and th in scan_errors))
            if _err:
                unc.append(row["id"])    # 续180：目标活着但检查没跑成 ⇒ 无法确认，**不**当已修复
            elif t in probed or (th and th in probed_hosts):
                fixed.append(row["id"])          # 目标本轮探过、检查跑成且没再报出来 ⇒ 已修复
            else:
                unc.append(row["id"])            # 目标本轮没探到 ⇒ 无法确认（**不**当已修复）
    if rep:
        db.bulk_set_vuln_retest(rep, "reproduced")
    if fixed:
        db.bulk_set_vuln_retest(fixed, "fixed")
    if unc:
        db.bulk_set_vuln_retest(unc, "unconfirmed")
    _nerr180 = len(scan_errors or ())
    ctx.logger.info(f"[vulnscan] 复测三态：仍可复现 {len(rep)} / 已修复 {len(fixed)} / "
                    f"无法确认 {len(unc)}"
                    + (f"（其中 {_nerr180} 个目标检查执行失败 —— 一次请求失败不证明已修复）"
                       if _nerr180 else "")
                    + "（没探到/没跑成的目标记「无法确认」，**不**误报「已修复」）")


def _lang_summary(skips):
    """把"按语言少跑了多少"汇总成一句 INFO；没有跳过就返回空串（不打印）。

    单独成函数是为了让回归能**直接喂字典**验这句话的内容 —— 逐站 DEBUG 看不见总量，
    而"识别 php 就不跑 jsp 的 POC"这条功能的唯一证据就是那个总数（续155 主理人点单）。
    `skips` 的形状：`{"n": 累计跳过, "sites": 判出语言的站点数, "<语言>": 该语言跳过数}`。
    """
    n = int(skips.get("n") or 0)
    if not n:
        return ""
    by = {k: v for k, v in skips.items() if k not in ("n", "sites")}
    return ("按语言收敛：判出语言 %s 个站点、累计跳过 %d 次异构 POC（%s）；"
            "语言判不出的站点不拦，afrog 那一路由它自己的模板匹配决定"
            % (skips.get("sites", 0), n,
               "、".join("%s %s" % (k, v) for k, v in sorted(by.items()))))


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
        # 续151 无依赖 ML（**默认关**）：POC 优先级 —— 用 data/ml/poc_model.json（朴素贝叶斯，
        # 训练自历史 (站点,poc)→命中）给候选打分排序。**没模型就维持原顺序**，绝不改变
        # "哪些 POC 会被执行"的集合（那仍由注册表开关、级别门控、语言门控决定）。
        _ml_poc = None
        if ccfg.get("poc_priority") is True:
            from pathlib import Path as _P151
            _ml_poc = ml.NaiveBayes.load(_P151(config.BASE_DIR) / "data" / "ml" / "poc_model.json")
            ctx.logger.info("[vulnscan] POC 优先级 ML：" + (
                "已加载 data/ml/poc_model.json" if _ml_poc else
                "未找到 data/ml/poc_model.json，维持原顺序（哪些 POC 参与不受影响）"))
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

        def _by_conf(items, site=None):
            """按置信度高低排序（P1-2）：high → medium → low，同级保持注册表内原顺序。

            `list.sort` 是稳定排序，所以"同级保持原顺序"是免费的；这里只加一层排序键，
            不改变"哪些 POC 会被执行"的集合 —— 那仍由注册表开关与级别门控决定。

            续151：开了 `checks.poc_priority` 且模型已加载时，再按**学习到的命中概率**稳定排序
            （概率相同者保持上面那层顺序）—— 只改"先跑谁"，不改"跑不跑"。
            """
            ordered = sorted(items, key=lambda p: -db.CONF_ORDER.index(
                p.get("_confidence") or "low"))
            if _ml_poc is not None and ordered and site is not None:
                _feat = str(site.get("url") or "") + " " + str(site.get("tech") or "")

                def _mk(p):
                    _tg = " ".join(str(t) for t in ((p.get("info") or {}).get("tags") or []))
                    return (_feat + " " + str(p.get("id") or "") + " " + _tg)
                ordered = sorted(ordered, key=lambda p: -max(
                    _ml_poc.predict_proba(_mk(p)).values() or [0.0]))
            return ordered

        # 语言收敛的账：`{"n": 累计跳过, "sites": 判出语言的站点数, "<语言>": 该语言跳过数}`。
        # DEBUG 逐站、INFO 汇总、回归断言三处都读这一个 dict（判据一处，§5.14）。
        _lang_skips, _lang_lock = {"n": 0, "sites": 0}, threading.Lock()
        # 续176：「已执行且命中、但被 min_severity 结果闸挡下」的账。三个丢弃点
        # （下面的 run_all / POC 路 / afrog 路）各自 add()，阶段末汇总落库并说出口。
        # 与 `skip_severities` 那类"根本不执行"的分开说 —— 两件事混说就是假话。
        _blocked = owasp_checks.SeverityBlocked()
        # 续180（借鉴点①）：本轮**检查执行失败**的站点（host 集合）——
        # 复测三态要把它和「探过且跑成」分开：没跑成不许记「已修复」。
        _scan_err = set()

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
                if _slang and len(pool) != len(pocs):
                    # 续155（主理人点单"识别 php 就不跑 jsp 的目录扫描和漏洞测试"）：跳过数要
                    # **汇总后在 INFO 行说一次**。以前只有逐站 DEBUG ⇒ 用户在 task.log 里看到
                    # "启用 POC 312 个"却看不出实际跑了多少，而"少跑了多少"恰恰是这条功能的证据。
                    with _lang_lock:
                        _sk155 = len(pocs) - len(pool)
                        _lang_skips["n"] += _sk155
                        _lang_skips["sites"] += 1
                        _lang_skips[_slang] = _lang_skips.get(_slang, 0) + _sk155
                    ctx.logger.debug(f"[vulnscan] {site.get('url')}：语言 {_slang}，"
                                     f"按语言跳过 {_sk155} 个异构 POC")
            if not link_tags or not pool:
                return _by_conf(pool, site)[:poc_cap] if pool else []
            tech = {t.strip().lower() for t in str(site.get("tech") or "").split(",") if t.strip()}
            if not tech:
                return _by_conf(pool, site)[:poc_cap]
            hit, rest = [], []
            for p in pool:
                tags = {str(t).lower() for t in ((p.get("info") or {}).get("tags") or [])}
                (hit if tags & tech else rest).append(p)
            return _by_conf(hit, site) + _by_conf(rest, site)[:max(0, poc_cap - len(hit))]

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
            # 续180（借鉴点①）：检查**执行失败**的目标要记账（ARTEX retester 同一口径）——
            # "没报出来"与"没跑成"在复测三态里是两回事，混说就会把没跑成记成"已修复"。
            found = []
            try:
                found = list(owasp_checks.run_all(url, ctx.settings, logger=ctx.logger,
                                                  blocked=_blocked))
                for poc in _pocs_for(site if isinstance(site, dict) else {}):
                    # `registry=pocs`：workflow 里 `tags:` 步骤的候选集，直接用本阶段已加载好的
                    # 那份（否则每个站点都会把 300+ 个 POC 文件重读一遍）。
                    for v in engine.run_poc_on_target(poc, url, ctx.settings, site=site,
                                                      registry=pocs):
                        # POC 结果与内置检查共用同一级别门槛（critical 恒保留）
                        if not owasp_checks.severity_ok(v.get("severity", "medium"), floor):
                            _blocked.add()      # 续176：执行过、命中了，只是被结果闸挡下
                            continue
                        found.append(v)
            except Exception as e:              # noqa: BLE001 —— 单站失败不拖垮整批，但要记账
                from urllib.parse import urlsplit as _us180
                try:
                    _scan_err.add(_us180(url).netloc.lower())
                except Exception:               # noqa: BLE001 - 解析不了就记全 URL
                    _scan_err.add(str(url))
                ctx.logger.warning(f"[vulnscan] {url}：检查执行失败（{type(e).__name__}: "
                                   f"{str(e)[:160]}）—— 该站旧结论本轮记「无法确认」，不许当「已修复」")
            return found

        all_v = []
        for batch in pool_run(_scan_site, sites, workers=workers,
                            logger=ctx.logger, label="站点漏洞初筛"):
            all_v.extend(batch)
        # 续155：把"按语言少跑了多少"提到 INFO（未知语言的站点**不拦**，所以这里只算
        # 判出语言的；`dirscan` 那一侧的目录字典按同一张 `TECH_LANG` 分桶，两路口径一致）。
        _lang_line = _lang_summary(_lang_skips)
        if _lang_line:
            ctx.logger.info("[vulnscan] " + _lang_line)
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
                _af_dropped = len(af_v) - len(kept)
                if _af_dropped:
                    _blocked.add(_af_dropped)   # 续176：afrog 那一路同样要说清挡掉多少
                ctx.logger.info(f"[afrog] {af_note}；过级别门槛 {floor} 的 {len(kept)} 条入账"
                                + (f"（挡掉 {_af_dropped} 条）" if _af_dropped else ""))
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
        # 续176：把"已执行且命中、但被 min_severity 挡下"的量说出口并落库（§0 第 10 条）。
        # **覆盖写**不是累加：追加执行时同一隐藏项会被第二次运行重复计到，累加＝虚高，
        # 而本仓不接受虚高数字（§5.18：日志里的数字是人的判断依据）⇒ 页面只能说
        # "最近一次 vulnscan 运行"。
        _blk = _blocked.get()
        if _blk:
            ctx.logger.info(
                f"[vulnscan] 级别门槛 {floor}：另有 {_blk} 条已执行且命中的结果低于门槛、"
                f"未入库（入库数据一条未动；与 skip_severities 那类「根本不执行」的检查"
                f"是两回事 —— 这些是真正跑过、并且有命中的）")
        db.set_task_sev_blocked(ctx.task_id, floor, _blk)
        # 续150：独立复测模式（任务级选项 retest=True）—— 跑完与旧结论做三态对比。
        if ctx.options.get("retest") is True:
            _retest_mark(ctx, uniq, sites, scan_errors=_scan_err)