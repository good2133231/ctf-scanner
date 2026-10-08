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
from .. import blacklist, db, extdom, fingerprint, flagfind, jsmine
from ..utils import write_lines


class JsmineStage(Stage):
    name = "jsmine"
    description = "JS 资产挖掘（从站点 JS 提取域名/接口 URL/疑似凭据，含第三方黑名单降噪）"

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

        domains, urls, secrets, seen_value = set(), set(), [], set()
        js_count = 0
        for u in sites:
            if ctx.stopped():
                ctx.logger.warning("[jsmine] 任务已请求停止，结果不再入账")
                return
            try:
                res = jsmine.mine(u, ctx.settings, logger=ctx.logger,
                                 # 续126/127：页面与每个 JS 的响应都已在手 ⇒ 一次回调同时喂两件事，
                                 # **零额外请求**：flag 候选抽取 + 组件指纹补标（后者要状态码与头）
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
                if s.get("value") in seen_value:
                    continue
                seen_value.add(s.get("value"))
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
        ctx.results["js_domains"] = new_domains
        if new_domains:
            db.insert_subdomains(ctx.task_id, [(d, "js:mine") for d in new_domains])

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
                "evidence": s.get("context", ""),
            })

        _fnote = flagfind.note(ctx, _flag0)
        if _fnote:
            ctx.logger.info("[jsmine] flag 候选 " + _fnote)
        fingerprint.flush(ctx, ctx.logger, "jsmine")
        ctx.logger.info(f"[jsmine] JS 文件 {js_count} 个 / 新域名 {len(new_domains)} 个 / "
                        f"接口 URL {len(url_list)} 条 / 疑似凭据 {len(secrets)} 条"
                        + (f" / 另拒收 {len(junk113)} 个「不是域名」的碎片" if junk113 else ""))