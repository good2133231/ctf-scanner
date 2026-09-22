"""阶段：端口/服务发现（P1-2）。

位置：subdomain 之后、probe 之前 —— 端口信息先于 HTTP 探测产出，
便于 probe/vulnscan 在日志与结果里出现"这个 8080 上跑的是什么"。
数据源（合并去重）：目标里直接给的 IP/CIDR 展开结果 + 子域名阶段产出的主机名。

默认**关闭**（`portscan.enabled=false`）：端口扫描耗时与噪声都明显高于其他阶段，
且 CTF 里经常只给一个 Web 入口。需要时在 GUI「策略配置 → 端口与服务」里打开。
"""
from .base import Stage
from .. import db, portscan
from ..utils import pool_run, resolve_host, which


class PortscanStage(Stage):
    name = "portscan"
    description = "端口与服务发现（nmap 优先，内置 TCP connect 兜底）"

    def run(self):
        ctx = self.ctx
        cfg = ctx.settings.get("portscan", {}) or {}
        if cfg.get("enabled") is not True:
            ctx.logger.info("[portscan] 未启用（策略配置 → 端口与服务 可打开），跳过")
            return
        if ctx.stopped():
            ctx.logger.warning("[portscan] 任务已请求停止，跳过")
            return

        hosts = []
        for kind, raw in ctx.targets:
            if kind == "ip":
                hosts.append(raw)
            elif kind == "url":
                from urllib.parse import urlparse
                h = urlparse(raw).hostname
                if h:
                    hosts.append(h)
            elif kind == "domain":
                hosts.append(raw)
        hosts.extend(ctx.results.get("domains_for_probe") or [])
        hosts = list(dict.fromkeys(h for h in hosts if h))
        cap = int(cfg.get("max_hosts", 100))
        if len(hosts) > cap:
            ctx.logger.info(f"[portscan] 主机数 {len(hosts)} 超过上限 {cap}，仅扫描前 {cap} 个")
            hosts = hosts[:cap]
        if not hosts:
            ctx.logger.info("[portscan] 无主机目标，跳过")
            return

        ports = portscan.parse_ports(cfg.get("ports"))
        workers = int(cfg.get("workers", 64))
        timeout = float(cfg.get("timeout", 1.0))
        banner = cfg.get("banner", True) is not False
        nmap_bin = which((ctx.settings.get("tools", {}) or {}).get("nmap", "nmap"))
        if nmap_bin:
            ctx.logger.info(f"[portscan] 使用 nmap 扫描 {len(hosts)} 个主机 x {len(ports)} 端口")
        else:
            ctx.logger.info(f"[portscan] nmap 不可用，内置 TCP connect 扫描 "
                            f"{len(hosts)} 个主机 x {len(ports)} 端口 …")

        def _one(host):
            if ctx.stopped():
                return []
            ips = [host] if host.replace(".", "").isdigit() else resolve_host(host)
            out = []
            for ip in ips[:2]:  # 一个主机名最多取前 2 个解析结果，避免 CDN 放大请求量
                found = None
                if nmap_bin:
                    found = portscan.nmap_scan(host, ip, ports, timeout=timeout,
                                               binary=nmap_bin)
                if found is None:
                    found = portscan.scan_host(host, ip, ports, timeout=timeout,
                                               workers=workers, banner=banner,
                                               stopped=ctx.stopped)
                out.extend(found)
            return out

        results = []
        for batch in pool_run(_one, hosts, workers=min(8, max(1, len(hosts)))):
            results.extend(batch)
        if ctx.stopped():
            ctx.logger.warning("[portscan] 任务已请求停止，结果不再入账")
            return

        uniq, seen = [], set()
        for r in results:
            key = (r["host"], r["ip"], r["port"])
            if key in seen:
                continue
            seen.add(key)
            uniq.append(r)
        uniq.sort(key=lambda r: (r["host"], r["port"]))
        ctx.results["ports"] = uniq
        db.insert_ports(ctx.task_id, uniq)
        services = {}
        for r in uniq:
            services[r["service"] or "unknown"] = services.get(r["service"] or "unknown", 0) + 1
        ctx.logger.info(
            f"[portscan] 开放端口 {len(uniq)} 个 / 主机 {len({r['host'] for r in uniq})} 台"
            + (f"（{' / '.join(f'{k}:{n}' for k, n in sorted(services.items()))}）" if uniq else ""))