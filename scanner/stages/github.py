"""阶段：GitHub 泄露检索（续26）。

位置：与 `intel` / `heuristic` 同属**线索阶段**，固定排在流水线最后 —— 它不产出任何
被后续阶段消费的数据，只是拿任务的注册域去 GitHub 公开代码里搜一遍，把命中整理成
**线索**（`leads` 表，kind=`github`）供人工判断。

配置（`github` 段）：`enabled`（**默认关**）/ `max_domains` / `max_queries` / `per_page` /
`max_leads` / `timeout`；token 在 `config/keys.yaml` 的 `github.token`（见下）。

三条硬边界（改代码前先读 `scanner/github_leak.py` 文件头，那里写得比这里细）：
1. **只落元数据，绝不落文件内容** —— 仓库 / 文件路径 / 命中规则名，避免凭据明文入库；
2. **`auth=False`** —— 任务级登录态（目标侧 Cookie / Token）绝不发给 GitHub；
3. **默认关 + 没 token 就零请求** —— 代码搜索接口要求认证，没配 token 时直接说明原因跳过。

产出：`db.insert_leads()` —— **不写 `vulns`、不计入漏洞数、不自动导入 POC**。
线索的出口是 **JSONL 导出**（`type=lead`）：按续24 口径，GUI 页签与人读报告（MD / HTML）
都不再露出「线索」。
"""
from .base import Stage
from .. import db, github_leak


class GithubStage(Stage):
    name = "github"
    description = "GitHub 泄露检索（公开仓库里出现目标注册域，只产出线索）"

    def run(self):
        ctx = self.ctx
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
        if meta.get("error"):
            ctx.logger.warning(f"[github] {meta['error']}")
        if not leads:
            ctx.logger.info(f"[github] 检索 {meta.get('queries', 0)} 次，未命中（GitHub 报告共 "
                            f"{meta.get('hits', 0)} 条），未产生线索")
            return

        # 截断：先按"级别 → 域名 → 仓库:路径"排好序（github_leak 里已排），保高价值的
        cap = max(1, int(cfg.get("max_leads", github_leak.DEFAULT_MAX_LEADS)
                         or github_leak.DEFAULT_MAX_LEADS))
        if len(leads) > cap:
            ctx.logger.info(f"[github] 命中 {len(leads)} 条超过上限 {cap}，仅保留前 {cap} 条")
            leads = leads[:cap]

        added = db.insert_leads(ctx.task_id, leads)
        ctx.results["leads_github"] = leads
        ctx.logger.info(f"[github] 检索 {meta.get('queries', 0)} 次（GitHub 报告共 "
                        f"{meta.get('hits', 0)} 条）→ 线索 {len(leads)} 条，入库 {added} 条"
                        f"（只记仓库/文件路径/命中规则，不保存文件内容）")
        ctx.logger.info("[github] 注意：线索≠漏洞结论，需人工确认（不写 vulns、不计入漏洞数）")
