"""阶段：JS 资产挖掘（P0-3）。

从 probe 产出的存活站点抓取页面与 JS，提取其中的域名 / 接口 URL / 疑似凭据：
- 新域名并入 `subdomains` 表（source=`js:mine`）——只插当前任务还没有的，避免与
  subdomain 阶段重复；第三方公共域（统计/CDN 等）在 `scanner/jsmine.py` 里已过滤。
- 接口 URL 写 `workdir/js_urls.txt` 并放进 `ctx.results["js_urls"]`，**不直接进 sites/dirs 表**
  （数据模型不匹配，交由后续阶段判断是否值得探测）。
- 疑似凭据（AK/SK 等）以 high 级漏洞入库（`poc_id=js-secret-<规则名>`），detail 明确
  标注"需人工确认有效性与作用域"，evidence 为命中的前后文片段。

受 `jsmine.enabled` 开关控制（默认开），抓取量由 `max_pages` / `max_js` 限制。
"""
from urllib.parse import urlparse

from .base import Stage
from . import probe as probe_stage
import re

from .. import blacklist, cdn, db, dnsq, extdom, fingerprint, flagfind, jsmine, parked
from ..utils import pool_run, write_lines


_SECRET_VAL_RE = re.compile(r"，值 (.*?)；前后文：")


def _existing_js_secrets(task_id):
    """库里本任务已入库的 JS 凭据行 → `{(主机, 掩码值)}`，重跑/追加执行时靠它不再插重复行。

    掩码值是从 `evidence` 里回读的，而那句模板由**本文件**写（见下面 `db.insert_vuln` 那处）——
    改模板必须同时改这里的正则，否则第二次运行会安静地把重复行插进去。`[8bj]` 有一条判据
    专门盯"写方模板与读方正则同源"。
    """
    out = set()
    for r in db.list_vulns(task_id, limit=None):
        if not str(r["poc_id"] or "").startswith("js-secret-"):
            continue
        m = _SECRET_VAL_RE.search(str(r["evidence"] or ""))
        if m:
            out.add((str(r["target"] or "").lower(), m.group(1)))
    return out


class JsmineStage(Stage):
    name = "jsmine"
    description = "JS 资产挖掘（从站点 JS 提取域名/接口 URL/疑似凭据，含第三方黑名单降噪）"

    def _verify_candidates(self, domains):
        """JS 候选域名"宁缺毋滥"三道闸（2026-10-13 用户点单）——入库前的最后一道质检。

        背景（用户原话与实测样本）：拓展域名页里 `com.text.name` 这种一眼不是域名、
        `style.font.name` 能解析但打开是**域名转让页**、`at.alicdn.com` 是**第三方 JS
        资源（CDN）**。判定顺序与口径：

        ① **解析门**（`jsmine.verify_resolve`，总开关）：候选先做一次只读解析。明确
           `nxdomain`（域名不存在）→ 不入库；`servfail` / `timeout` 等 DNS 无结论 →
           放行 —— "解析可能会漏，但不会错"。**自有域名（任务目标及其注册域）无条件放行**。
        ② **CDN 门**（`drop_cdn`）：解析结果命中 CDN 厂商（CNAME 链 / IP 段，
           `scanner/cdn.py` 同一份名单）→ 是别人的基础设施，不入库。
        ③ **停车门**（`parking_check`，只读首页 GET，上限 `parking_check_max`）：
           首页命中停放/转让标记（`scanner/parked.py`）或 HTTPS/HTTP 均无响应（空壳）→
           不入库。活站 → 保留，且把这次解析结果回填（`ip/cdn/ip_note/cname`），
           「拓展域名」页与 `resolve_extended` 不必再查一遍。

        返回 `(保留域名, 统计, 解析回填, CNAME 回填)`。每一档拒绝**都带回样本与数量**
        由调用方打进日志 —— 静默丢条目是本仓红线（AGENTS §0 第 10 条）。
        """
        ctx = self.ctx
        cfg = ctx.settings.get("jsmine") or {}
        stats = {"nxdomain": [], "cdn": [], "parked": [], "dead": [], "unchecked": 0}
        if not domains or cfg.get("verify_resolve", True) is False:
            return list(domains), stats, {}, {}
        bases = extdom.task_bases(ctx.task_id)
        owned, cand = [], []
        for d in domains:
            (owned if extdom.is_owned(d, bases) else cand).append(d)
        if not cand:
            return owned, stats, {}, {}
        timeout = float((ctx.settings.get("subdomain") or {}).get("dns_timeout", 3) or 3)
        workers = max(1, min(20, int((ctx.settings.get("limits") or {}).get(
            "max_workers", 20) or 20)))

        def _resolve(host):
            if ctx.stopped():
                return None
            chain, ips, reason = dnsq.resolve_detail(host, timeout=timeout,
                                                     settings=ctx.settings)
            return host, chain, ips, reason

        results = [r for r in pool_run(_resolve, cand, workers=workers,
                                       logger=ctx.logger, label="JS 域名解析门") if r]
        drop_cdn = cfg.get("drop_cdn", True) is not False
        want_park = cfg.get("parking_check", True) is not False
        try:
            park_budget = max(0, int(cfg.get("parking_check_max", 100) or 0))
        except (TypeError, ValueError):
            park_budget = 100
        kept, net, cnames = [], {}, {}
        for host, chain, ips, reason in results:
            if ctx.stopped():
                kept.append(host)            # 停止时刻未判完的：放行，不假装修剪过
                continue
            if reason == "nxdomain":
                stats["nxdomain"].append(host)
                continue                     # 域名不存在 —— 唯一"不会错"的拒绝判据
            cdn_label = cdn.match(chain, ctx.settings, ips)
            if drop_cdn and cdn_label:
                stats["cdn"].append((host, cdn_label))
                continue
            if want_park and ips:
                if park_budget <= 0:
                    stats["unchecked"] += 1  # 超出预算：放行，但数量要报出来
                else:
                    park_budget -= 1
                    verdict, why = parked.probe(host, ctx.settings)
                    if verdict == "parked":
                        stats["parked"].append((host, why))
                        continue
                    if verdict == "dead":
                        stats["dead"].append((host, why))
                        continue
            if ips or reason:
                net[host] = (",".join(ips), cdn_label, reason)
            if chain:
                cnames[host] = chain[-1]
            kept.append(host)
        return sorted(kept + owned), stats, net, cnames

    def _log_verify_stats(self, stats):
        """三道闸的拒绝清单进日志（数量 + 样本）——"拦了多少、为什么拦"必须看得见。"""
        ctx = self.ctx
        parts = []
        if stats["nxdomain"]:
            parts.append(f"解析不存在 {len(stats['nxdomain'])} 个"
                         f"（如 {', '.join(stats['nxdomain'][:3])}）")
        if stats["cdn"]:
            parts.append(f"第三方 CDN {len(stats['cdn'])} 个"
                         f"（如 {', '.join(h for h, _ in stats['cdn'][:3])}）")
        if stats["parked"]:
            parts.append(f"停放/转让页 {len(stats['parked'])} 个"
                         f"（如 {', '.join(h for h, _ in stats['parked'][:3])}）")
        if stats["dead"]:
            parts.append(f"空壳无响应 {len(stats['dead'])} 个"
                         f"（如 {', '.join(h for h, _ in stats['dead'][:3])}）")
        if stats["unchecked"]:
            parts.append(f"超出停车检测预算放行 {stats['unchecked']} 个"
                         "（jsmine.parking_check_max）")
        if parts:
            ctx.logger.info("[jsmine] 候选域名质检拒收：" + "；".join(parts)
                            + "（判据与开关见 scanner/stages/jsmine.py::_verify_candidates）")

    def run(self):
        ctx = self.ctx
        _flag0 = flagfind.begin(ctx)
        cfg = ctx.settings.get("jsmine", {}) or {}
        if not cfg.get("enabled"):
            ctx.logger.info("[jsmine] 未启用（策略配置可打开），跳过")
            return
        if ctx.stopped():
            ctx.logger.warning("[jsmine] 任务已请求停止，跳过")
            return

        max_pages = int(cfg.get("max_pages", 20))
        sites = [s.get("url") for s in (ctx.results.get("sites") or []) if s.get("url")]
        if not sites:  # 回退数据库（例如单独跑该阶段 / 站点结果未在内存中）
            sites = [r["url"] for r in db.list_sites(ctx.task_id) if r["url"]]
        sites = list(dict.fromkeys(sites))[:max_pages]
        if not sites:
            ctx.logger.info("[jsmine] 无站点输入，跳过")
            return
        ctx.logger.info(f"[jsmine] 从 {len(sites)} 个站点挖掘 JS 资产 …")

        # 续155（主理人点单"同一站点同样匹配的值就不要二次出现了"）：去重键从"掩码值"
        # （那是**跨站全局**的键 ⇒ B 站同一个值被 A 站吃掉）改成 **(站点, 掩码值)**：同站点
        # 重复命中（多个 JS 文件、或两条规则抓到同一个值）只留一行，不同站点各报各的。
        # "站点"取入库的 target（主机名）而不是完整 JS URL，否则同一站的 app.js 与 vendor.js
        # 会各报一行 —— 那才是用户看到的"二次出现"。重跑/追加执行还要**先看库里已有什么**
        # （`insert_vuln` 没有 UNIQUE 约束，去重是写方的责任，AGENTS §5.6）。
        domains, urls, secrets = set(), set(), []
        seen_value = _existing_js_secrets(ctx.task_id)
        js_count = 0
        for u in sites:
            if ctx.stopped():
                ctx.logger.warning("[jsmine] 任务已请求停止，结果不再入账")
                return
            try:
                res = jsmine.mine(u, ctx.settings, logger=ctx.logger,
                                 # 续126/127：页面与每个 JS 的响应都已在手 ⇒ 一次回调同时喂两件事，
                                 # **零额外请求**：敏感信息抽取 + 组件指纹补标（后者要状态码与头）
                                 text_sink=lambda _r: (
                                     flagfind.harvest(ctx, _r.get("url") or u,
                                                      _r.get("text") or "", "js"),
                                     fingerprint.collect(ctx, u, _r, "js")))
            except Exception as e:
                ctx.logger.warning(f"[jsmine] {u} 挖掘失败：{e}")
                continue
            js_count += int(res.get("js_count") or 0)
            domains.update(res.get("domains") or [])
            urls.update(res.get("urls") or [])
            for s in res.get("secrets") or []:
                host155 = (urlparse(s.get("source", "") or "").hostname or "").lower()
                key155 = (host155, str(s.get("value") or ""))
                if key155 in seen_value:
                    continue
                seen_value.add(key155)
                secrets.append(s)

        if ctx.stopped():
            ctx.logger.warning("[jsmine] 任务已请求停止，结果不再入账")
            return

        # 1) 新域名：跳过任务中已有的（避免与 subdomain 阶段重复入库）
        existing = {r["domain"] for r in db.list_subdomains(ctx.task_id)}
        new_domains = sorted(d for d in domains if d not in existing)
        # 用户黑名单：命中的域名不入库，后续阶段也就不会扫它
        new_domains, blocked = blacklist.filter_domains(new_domains, ctx.settings,
                                                        owner_id=getattr(ctx, "owner_id", 0))
        if blocked:
            ctx.logger.info(f"[jsmine] 黑名单拦截 {blocked} 个域名（config/blacklist.txt）")
        # 续113：再拦一道**根本不是域名**的东西 —— JS 里点号连接的成员访问链
        # （`chat.floating.open`、`network.protocol.name`、那串欧盟国家码）。它们的末位 label
        # 恰好是合法公共后缀，所以 PSL 形态闸门放行；但它们的**注册域**压根没被注册。
        # 判据只有一处（`extdom.filter_absent_zones`），放在**入库前** —— 库里从此不会有这类行，
        # 而不是靠展示层"默认收起未解析"去遮（续112-D 那道门仍然留着，遮的是真没解析出来的域名）。
        new_domains, junk113 = extdom.filter_absent_zones(new_domains, ctx.settings,
                                                          logger=ctx.logger)
        if junk113 and not (ctx.settings.get("jsmine") or {}).get("drop_absent_zone", True):
            junk113 = []          # 开关关着时 filter 不会返回东西，这里只是把话说明白
        # 三道闸（2026-10-13 用户点单）：解析门 / CDN 门 / 停车门 —— 先质检再入库，
        # 库里从此没有"能解析但是转让页 / 是 CDN / 压根不存在"的行。自有域名不受影响。
        new_domains, vstats, vnet, vcnames = self._verify_candidates(new_domains)
        self._log_verify_stats(vstats)
        ctx.results["js_domains"] = new_domains
        if new_domains:
            db.insert_subdomains(ctx.task_id, [(d, "js:mine") for d in new_domains])
            # 解析门已发过的查询不浪费：结果直接回填（拓展页立刻有 IP/CDN/CNAME 可看，
            # resolve_extended 的 only_missing 也不会重复查这一批）
            if vnet:
                db.set_subdomain_net(ctx.task_id, vnet)
            if vcnames:
                db.set_subdomain_cnames(ctx.task_id, vcnames)
        # 二层遍历（续139）：JS 里挖出来的域名以前**只进表**，没有任何一条路把它们变成
        # 站点 —— 灯塔的站点数就是这么比我们有货的。这一轮**不要求本轮真挖到新域名**：
        # 补探的池子除了 js 新交的，还包括库里其余没试过的本任务域名（osint/cert 带回来的
        # 那些也在里面）。归属判定、DNS 预筛、上限与"跳过了多少"的日志都在
        # `probe.second_pass` 一处，口径不会分叉。
        probe_stage.second_pass(ctx, extra=new_domains)

        # 2) 接口 URL：落盘 + 进内存结果（不入 sites/dirs 表）
        url_list = sorted(urls)
        ctx.results["js_urls"] = url_list
        write_lines(ctx.workdir / "js_urls.txt", url_list)

        # 3) 疑似凭据：以 high 级漏洞入库 + 落盘（值已掩码，方便离线复核与人工确认）
        secrets.sort(key=lambda s: (s.get("type", ""), s.get("value", "")))
        ctx.results["js_secrets"] = secrets
        write_lines(ctx.workdir / "js_secrets.txt",
                    [f"{s.get('type', '')}\t{s.get('value', '')}\t{s.get('source', '')}"
                     for s in secrets])
        for s in secrets:
            # target 用**主机名**而不是完整 JS URL：同一个站点下的多个 JS 会命中同一个值，
            # 按主机名去重既少重复行，也让「拓展域名」页能直接按域名挂上敏感命中数。
            src = s.get("source", "") or ""
            host = urlparse(src).hostname or src
            db.insert_vuln(ctx.task_id, {
                "target": host,
                "poc_id": f"js-secret-{str(s.get('type', '')).lower()}",
                "name": f"JS 疑似凭据泄露（{s.get('type', '')}）",
                "severity": "high",
                "owasp": "A08",
                "detail": "JS 中发现疑似凭据，需人工确认其有效性与作用域",
                # 续143：证据里必须能**点开**——哪个 JS 文件、第几行、哪条规则、掩码后的值。
                # 旧实现只放前后文片段，用户拿不到源文件位置（他原话：js 的也是给我详细链接）。
                "evidence": "%s:%s 命中规则 %s，值 %s；前后文：%s｜所在行：%s" % (
                    src or "(未知来源)", s.get("line", "?"), s.get("type", ""),
                    s.get("value", ""), s.get("context", ""),
                    s.get("line_text", ""))[:800],
                "packets": "\n".join((
                    "来源 JS（点开即取原文）：%s" % (src or "(未知来源)"),
                    "命中位置：第 %s 行 / 字节偏移 %s" % (s.get("line", "?"), s.get("offset", "?")),
                    "命中规则：%s（`scanner/jsmine.py` 的凭据规则表）" % s.get("type", ""),
                    "值（已掩码，原文不入库）：%s" % s.get("value", ""),
                    "归属主机：%s" % (host or "(未知)"),
                    "前后文（空白已折叠，≤160 字）：%s" % s.get("context", ""),
                    "所在整行（键名与嵌套位置都在这行里，≤240 字）：%s" % s.get("line_text", ""),
                ))[:8000],
            })

        _fnote = flagfind.note(ctx, _flag0)
        if _fnote:
            ctx.logger.info("[jsmine] 敏感信息候选 " + _fnote)
        fingerprint.flush(ctx, ctx.logger, "jsmine")
        ctx.logger.info(f"[jsmine] JS 文件 {js_count} 个 / 新域名 {len(new_domains)} 个 / "
                        f"接口 URL {len(url_list)} 条 / 疑似凭据 {len(secrets)} 条"
                        + (f" / 另拒收 {len(junk113)} 个「不是域名」的碎片" if junk113 else ""))