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
from .base import Stage
from .. import blacklist, db, jsmine
from ..utils import write_lines


class JsmineStage(Stage):
    name = "jsmine"
    description = "JS 资产挖掘（从站点 JS 提取域名/接口 URL/疑似凭据，含第三方黑名单降噪）"

    def run(self):
        ctx = self.ctx
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
                res = jsmine.mine(u, ctx.settings, logger=ctx.logger)
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
        new_domains, blocked = blacklist.filter_domains(new_domains, ctx.settings)
        if blocked:
            ctx.logger.info(f"[jsmine] 黑名单拦截 {blocked} 个域名（config/blacklist.txt）")
        ctx.results["js_domains"] = new_domains
        if new_domains:
            db.insert_subdomains(ctx.task_id, [(d, "js:mine") for d in new_domains])

        # 2) 接口 URL：落盘 + 进内存结果（不入 sites/dirs 表）
        url_list = sorted(urls)
        ctx.results["js_urls"] = url_list
        write_lines(ctx.workdir / "js_urls.txt", url_list)

        # 3) 疑似凭据：以 high 级漏洞入库
        secrets.sort(key=lambda s: (s.get("type", ""), s.get("value", "")))
        ctx.results["js_secrets"] = secrets
        for s in secrets:
            db.insert_vuln(ctx.task_id, {
                "target": s.get("source", ""),
                "poc_id": f"js-secret-{str(s.get('type', '')).lower()}",
                "name": f"JS 疑似凭据泄露（{s.get('type', '')}）",
                "severity": "high",
                "owasp": "A08",
                "detail": "JS 中发现疑似凭据，需人工确认其有效性与作用域",
                "evidence": s.get("context", ""),
            })

        ctx.logger.info(f"[jsmine] JS 文件 {js_count} 个 / 新域名 {len(new_domains)} 个 / "
                        f"接口 URL {len(url_list)} 条 / 疑似凭据 {len(secrets)} 条")