"""阶段：子域接管检测（P0-2）。

位置：subdomain 之后、probe 之前/之后都可，默认接在 subdomain 后——
CNAME 解析本身就是资产数据，越早回填，后续阶段在日志/报表里越完整。

数据源：`ctx.results["subdomains"]`；为空时回退 `db.list_subdomains()`（老任务或只跑本阶段）。
产出：
- 资产回填：`db.set_subdomain_cnames()` 写回 subdomains.cname 列（CNAME 链，多跳用 " -> " 连接）；
- 漏洞：疑似接管项直接 `db.insert_vuln()`，并放入 `ctx.results["takeovers"]`；
- 中间产物：工作目录 `cnames.txt`。

配置（`takeover` 段）：`enabled`（默认关，策略配置可打开）/ `max_hosts`（默认 300）/
`http_check`（默认 True）。检测逻辑见 `scanner/takeover.py`，DNS 客户端见 `scanner/dnsq.py`。
"""
from .base import Stage
from .. import db, dnsq
from .. import takeover as takeover_mod
from ..utils import pool_run, write_lines


class TakeoverStage(Stage):
    name = "takeover"
    description = "子域接管检测（CNAME 指向已失效第三方服务，如 S3 / Heroku / GitHub Pages）"

    def run(self):
        ctx = self.ctx
        cfg = ctx.settings.get("takeover", {}) or {}
        if cfg.get("enabled") is not True:
            ctx.logger.info("[takeover] 未启用（策略配置可打开），跳过")
            return
        if ctx.stopped():
            ctx.logger.warning("[takeover] 任务已请求停止，跳过")
            return

        hosts = [h for h in (ctx.results.get("subdomains") or []) if h]
        if not hosts:
            # 老任务 / 只跑该阶段：回退数据库里的子域名资产
            hosts = [r["domain"] for r in db.list_subdomains(ctx.task_id) if r["domain"]]
        hosts = list(dict.fromkeys(hosts))
        if not hosts:
            ctx.logger.info("[takeover] 无子域名资产，跳过")
            return

        cap = int(cfg.get("max_hosts", 300))
        if len(hosts) > cap:
            ctx.logger.info(f"[takeover] 子域名 {len(hosts)} 个超过上限 {cap}，仅检查前 {cap} 个")
            hosts = hosts[:cap]

        limits = ctx.settings.get("limits", {}) or {}
        workers = max(1, int(limits.get("max_workers", 20)))
        dns_timeout = float(cfg.get("dns_timeout", 3) or 3)

        # ---------- 1) 并发做 CNAME 解析（兼作资产回填）----------
        ctx.logger.info(f"[takeover] CNAME 解析 {len(hosts)} 个子域名 …")

        def _chain(host):
            if ctx.stopped():
                return None
            chain, _ips = dnsq.cname_chain(host, timeout=dns_timeout)
            return (host, chain) if chain else None

        pairs = pool_run(_chain, hosts, workers=workers)
        mapping = {h: " -> ".join(c) for h, c in pairs}
        write_lines(ctx.workdir / "cnames.txt",
                    [f"{h}\t{c}" for h, c in sorted(mapping.items())])
        db.set_subdomain_cnames(ctx.task_id, mapping)
        ctx.logger.info(f"[takeover] 命中 CNAME {len(mapping)} 个子域名（已回填资产）")

        if ctx.stopped():
            ctx.logger.warning("[takeover] 任务已请求停止，结果不再入账")
            return

        # ---------- 2) 仅对存在 CNAME 的子域做接管指纹判定 ----------
        candidates = sorted(mapping)
        if candidates:
            ctx.logger.info(f"[takeover] 对 {len(candidates)} 个存在 CNAME 的子域做接管指纹判定 …")

        def _detect(host):
            if ctx.stopped():
                return None
            try:
                return takeover_mod.detect(host, ctx.settings, logger=ctx.logger)
            except Exception as e:
                ctx.logger.debug(f"[takeover] {host} 判定失败：{e}")
                return None

        found = pool_run(_detect, candidates, workers=workers)
        if ctx.stopped():
            ctx.logger.warning("[takeover] 任务已请求停止，结果不再入账")
            return

        uniq, seen = [], set()
        for v in found:
            key = (v.get("target"), v.get("poc_id"))
            if key in seen:
                continue
            seen.add(key)
            uniq.append(v)
        for v in uniq:
            db.insert_vuln(ctx.task_id, v)
        ctx.results["takeovers"] = uniq
        ctx.logger.info(f"[takeover] 疑似接管 {len(uniq)} 个 / 已解析 CNAME {len(mapping)} 条")