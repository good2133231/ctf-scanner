"""阶段：漏洞情报订阅（P3-2）。

位置：流水线**最后**（vulnscan 之后）—— 它不产出任何被后续阶段消费的数据，只是把
"外部已知被利用漏洞（CISA KEV）"与本次扫到的资产指纹对一遍，产出**线索**供人工判断。

配置（`intel` 段）：`enabled`（**默认关**）/ `source` / `url` / `cache_hours` / `timeout` /
`max_leads`。门控与 portscan / dirscan 一致：任务勾选了本阶段、且策略里 `enabled` 为真才跑。

产出：`db.insert_leads()`（`leads` 表，kind=`intel`）
—— **不写 `vulns`、不计入漏洞数、不自动导入 POC**。理由见 `scanner/intel.py` 的边界说明：
情报命中只是"这条 CVE 与你扫到的组件可能相关"，把它当漏洞结论就是放大误报。
"""
from .base import Stage
from .. import db, intel as intel_mod


class IntelStage(Stage):
    name = "intel"
    description = "漏洞情报订阅（CISA KEV 已知被利用漏洞 × 本地指纹匹配，只产出线索）"

    def run(self):
        ctx = self.ctx
        cfg = ctx.settings.get("intel", {}) or {}
        if cfg.get("enabled") is not True:
            ctx.logger.info("[intel] 未启用（策略配置 → 情报与线索 可打开），跳过")
            return
        if ctx.stopped():
            ctx.logger.warning("[intel] 任务已请求停止，跳过")
            return

        assets = self._assets()
        if not assets:
            ctx.logger.info("[intel] 无可用资产指纹（站点/端口），跳过")
            return

        items, err = intel_mod.load_items(ctx.settings, logger=ctx.logger)
        if err:
            ctx.logger.warning(f"[intel] {err}")
        if not items:
            ctx.logger.info("[intel] 无可匹配的情报记录，跳过")
            return
        if ctx.stopped():
            ctx.logger.warning("[intel] 任务已请求停止，结果不再入账")
            return

        # 逐资产 × 逐情报做匹配。代价是 O(资产数 × 情报条数)（KEV 约 1500 条、资产通常几十个），
        # 全是纯字符串判断，不发任何请求 —— 实测这个量级无需再做索引。
        leads, matched_cves = [], set()
        sig_count = {}
        for target, text in assets:
            for item in items:
                hits = intel_mod.match_item(item, text)
                if not hits:
                    continue
                matched_cves.add(item["cve"])
                sig_count[",".join(hits)] = sig_count.get(",".join(hits), 0) + 1
                leads.append(intel_mod.build_lead(item, target, hits))

        # 同一 CVE 命中多台主机时按优先级排序，交给 max_leads 截断（避免一屏全是同一条）
        leads.sort(key=lambda r: (0 if r["level"] == "high" else 1, r["code"], r["target"]))
        cap = max(1, int(cfg.get("max_leads", 50) or 50))
        if len(leads) > cap:
            ctx.logger.info(f"[intel] 命中 {len(leads)} 条超过上限 {cap}，仅保留前 {cap} 条")
            leads = leads[:cap]

        added = db.insert_leads(ctx.task_id, leads)
        ctx.results["leads_intel"] = leads
        top = " / ".join(f"{k}×{v}" for k, v in
                         sorted(sig_count.items(), key=lambda kv: -kv[1])[:5])
        ctx.logger.info(f"[intel] 情报 {len(items)} 条 × 资产 {len(assets)} 个 → 命中 {len(leads)} 条"
                        f"（{len(matched_cves)} 个 CVE，入库 {added} 条）"
                        + (f"；触发信号：{top}" if top else ""))
        ctx.logger.info("[intel] 注意：线索≠漏洞结论，需人工确认（不写 vulns、不计入漏洞数）")

    def _assets(self):
        """待匹配资产：`[(展示名, 参与匹配的指纹文本), ...]`（站点 + 端口）。

        站点优先用 `ctx.results`（同一流水线内更新），为空时回退数据库（老任务 / 只跑本阶段）。
        """
        ctx = self.ctx
        sites = [dict(r) for r in db.list_sites(ctx.task_id)]
        ports = [dict(r) for r in db.list_ports(ctx.task_id)]
        out = []
        for s in sites:
            text = intel_mod.asset_keywords(site=s)
            if text:
                out.append((s.get("url") or s.get("host") or "-", text))
        for p in ports:
            text = intel_mod.asset_keywords(port=p)
            if text:
                out.append((f"{p.get('host') or p.get('ip') or '-'}:{p.get('port')}", text))
        return out