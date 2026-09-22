"""阶段：启发式候选发现（P3-3）。

位置：流水线**最后**（vulnscan 之后）—— 它要读目录结果（dirscan）与初筛漏洞（vulnscan），
越晚跑看到的数据越全；本身**不发任何请求**，只做本地差分与异常聚合。

配置（`heuristic` 段）：`enabled`（**默认关**）/ `max_leads`。与其它阶段同一套两层门控。

产出：`db.insert_leads()`（`leads` 表，kind=`heuristic`，级别一律 info）
—— **不写 `vulns`、不计入漏洞数**。规则与阈值见 `scanner/heuristics.py`。
"""
from .base import Stage
from .. import db
from .. import heuristics as heur_mod


class HeuristicStage(Stage):
    name = "heuristic"
    description = "启发式候选发现（对已收集数据做差分/异常聚合，产出线索而非结论）"

    def run(self):
        ctx = self.ctx
        cfg = ctx.settings.get("heuristic", {}) or {}
        if cfg.get("enabled") is not True:
            ctx.logger.info("[heuristic] 未启用（策略配置 → 情报与线索 可打开），跳过")
            return
        if ctx.stopped():
            ctx.logger.warning("[heuristic] 任务已请求停止，跳过")
            return

        sites = [dict(r) for r in db.list_sites(ctx.task_id)]
        dirs = [dict(r) for r in db.list_dirs(ctx.task_id)]
        vulns = [dict(r) for r in db.list_vulns(task_id=ctx.task_id, limit=1000)]
        csegs = [dict(r) for r in db.list_csegs(ctx.task_id)]
        if not (sites or dirs or csegs):
            ctx.logger.info("[heuristic] 无可用数据（站点/目录/C 段都为空），跳过")
            return

        leads = heur_mod.find_leads(sites, dirs, vulns, csegs)
        if ctx.stopped():
            ctx.logger.warning("[heuristic] 任务已请求停止，结果不再入账")
            return

        cap = max(1, int(cfg.get("max_leads", 50) or 50))
        kept = leads[:cap]
        if len(leads) > cap:
            ctx.logger.info(f"[heuristic] 线索 {len(leads)} 条超过上限 {cap}，仅保留前 {cap} 条")
        added = db.insert_leads(ctx.task_id, kept)
        ctx.results["leads_heuristic"] = kept

        tally = {}
        for r in kept:
            tally[r["code"]] = tally.get(r["code"], 0) + 1
        ctx.logger.info(f"[heuristic] 数据源：站点 {len(sites)} / 目录 {len(dirs)} / 漏洞 {len(vulns)}"
                        f" / C 段 {len(csegs)} → 线索 {len(kept)} 条（入库 {added} 条）")
        if tally:
            ctx.logger.info("[heuristic] 分类：" + " / ".join(f"{k}×{v}" for k, v in
                                                             sorted(tally.items(), key=lambda kv: -kv[1])))
        ctx.logger.info("[heuristic] 注意：线索≠漏洞结论，需人工确认（不写 vulns、不计入漏洞数）")