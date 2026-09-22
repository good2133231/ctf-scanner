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
        # 任务选项 `portscan_full`（GUI「全端口扫描」页对某个 IP 发起的任务）视为显式授权：
        # 即使全局 `portscan.enabled` 关着，这种"用户点名要扫"的任务也要跑。
        forced = ctx.options.get("portscan_full") is True
        if cfg.get("enabled") is not True and not forced:
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

        # 全端口扫描（1-65535）：可由策略 `portscan.mode="full"` 打开，也可以由任务选项
        # `portscan_full` 单次触发（GUI「全端口扫描」页对某个 IP 发起的就是这种）。
        full = forced or cfg.get("mode") == "full"
        if full:
            ports = portscan.parse_ports(cfg.get("full_ports") or "1-65535",
                                         max_span=65535)
            scope = "全端口"
        else:
            ports = portscan.parse_ports(cfg.get("ports"))
            scope = "内置 TOP 端口"

        # 排除已扫过的端口：全端口时这一步能省掉重复连接（TOP 表那批刚扫过，
        # 再扫一遍纯属浪费；同一任务重跑时同样适用）。
        exclude_scanned = cfg.get("exclude_scanned", True) is not False
        scanned = {}
        if exclude_scanned:
            for r in db.list_ports(ctx.task_id):
                scanned.setdefault(r["host"], set()).add(int(r["port"] or 0))

        # **真实 IP 优先**（用户要求"端口服务就是要对真实 IP 进行扫描"）：
        # 库里 subdomain 阶段已经解析过每个域名（含 CDN 判定），直接复用：
        # - 非 CDN 且拿到 IP → 用这个 IP，不再现场解析（更快，也避免解析漂移）；
        # - 判定走 CDN → **跳过**：扫 CDN 边缘节点没有意义（那 IP 不是目标的机器）。
        net = {}
        for r in db.list_subdomains(ctx.task_id):
            if r["ip"] or r["cdn"]:
                net[r["domain"]] = (r["ip"] or "", r["cdn"] or "")

        workers = int(cfg.get("workers", 64))
        timeout = float(cfg.get("timeout", 1.0))
        if full:
            # 全端口用**另一组**并发/超时：默认的 64 并发 × 1.0s 超时下，关闭端口要等满超时，
            # 65535 端口的最坏耗时是分钟级往上一大截（实测本机回环都超过 17 分钟；
            # 换成 256 并发 × 0.3s 只要 82 秒）。这两个键只在 full 模式下生效，
            # 不影响 TOP 端口扫描的既有行为。
            workers = int(cfg.get("full_workers") or 256)
            timeout = float(cfg.get("full_timeout") or 0.5)
        banner = cfg.get("banner", True) is not False
        nmap_bin = which((ctx.settings.get("tools", {}) or {}).get("nmap", "nmap"))
        engine = "nmap" if nmap_bin else "内置 TCP connect"
        ctx.logger.info(f"[portscan] {scope}扫描：{engine}，"
                        f"{len(hosts)} 个主机 x {len(ports)} 端口"
                        + ("（自动排除本任务已扫过的端口）" if exclude_scanned else ""))
        if full:
            # 给个量级预期：远端主机上"关闭的端口"要等满 timeout 才判定，所以最坏耗时
            # ≈ 端口数 / 并发 × 单端口超时。实测本机回环 65535 端口 @workers=256/timeout=0.3 约 82 秒；
            # 远端目标按默认 workers=64/timeout=1.0 会慢得多，想让全端口"能接受"就调大并发、调小超时。
            est = len(ports) / max(1, workers) * max(0.05, timeout) * len(hosts)
            ctx.logger.info(f"[portscan] 全端口耗时量级：最坏约 {est / 60:.0f} 分钟"
                            f"（端口数/并发 × 单端口超时；调大 workers、调小 timeout 可显著缩短）")

        def _one(host):
            if ctx.stopped():
                return []
            if host.replace(".", "").isdigit():
                ips = [host]
            else:
                ip_text, cdn_label = net.get(host, ("", ""))
                if ip_text and not cdn_label:
                    ips = [x.strip() for x in ip_text.split(",") if x.strip()][:2]
                    ctx.logger.info(f"[portscan] {host} 使用已解析的真实 IP {','.join(ips)}")
                elif cdn_label:
                    ctx.logger.info(f"[portscan] {host} 走 CDN（{cdn_label}），"
                                    f"跳过端口扫描（扫到的不是源站）")
                    return []
                else:
                    ips = resolve_host(host)
            target_ports = ports
            if exclude_scanned and scanned.get(host):
                skipped = scanned[host]
                target_ports = [p for p in ports if p not in skipped]
                if target_ports != ports:
                    ctx.logger.info(f"[portscan] {host} 已扫过 {len(skipped)} 个端口，"
                                    f"本次只扫剩余 {len(target_ports)} 个")
            if not target_ports:
                return []
            out = []
            for ip in ips[:2]:  # 一个主机名最多取前 2 个解析结果，避免 CDN 放大请求量
                found = None
                if nmap_bin:
                    found = portscan.nmap_scan(host, ip, target_ports, timeout=timeout,
                                               binary=nmap_bin)
                if found is None:
                    found = portscan.scan_host(host, ip, target_ports, timeout=timeout,
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