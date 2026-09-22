"""端口/服务发现（P1-2）：nmap 优先，内置 TCP connect 兜底。

定位与红线：
- 只做 **TCP connect 扫描**（不构造原始包、不做 SYN 半开、不做 UDP、不做暴力破解），
  因此不需要 root/管理员权限，也不会留下半连接状态；
- banner 只在"服务端会先说话"的端口上被动读取（SSH/SMTP/MySQL/Redis 等），
  对 HTTP 类端口不发任何请求 —— 服务识别交给 probe 阶段；
- **不调用 masscan**：它依赖原始套接字与 root，且扫描速率激进，与"非破坏性"约束冲突。
  nmap 只使用 `-sT -Pn --open`（TCP connect、跳过主机发现、只列开放端口）。

TOP_PORTS 覆盖 CTF 里真正高频的面：Web 变体端口、数据库、远程管理、容器/中间件。
"""
import re
import socket

from .utils import pool_run, run_cmd, which

# 端口 -> 服务名（内置 TOP 表；`portscan.ports` 留空时用它）
TOP_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios", 143: "imap",
    443: "https", 445: "smb", 465: "smtps", 587: "smtp", 631: "ipp",
    873: "rsync", 993: "imaps", 995: "pop3s", 1080: "socks", 1433: "mssql",
    1521: "oracle", 1723: "pptp", 2049: "nfs", 2181: "zookeeper", 2375: "docker",
    3306: "mysql", 3389: "rdp", 5432: "postgres", 5601: "kibana", 5672: "rabbitmq",
    5900: "vnc", 6379: "redis", 7001: "weblogic", 8000: "http-alt", 8009: "ajp",
    8080: "http-alt", 8081: "http-alt", 8443: "https-alt", 8888: "http-alt",
    9000: "php-fpm", 9090: "http-alt", 9200: "elasticsearch", 9300: "elasticsearch",
    11211: "memcached", 15672: "rabbitmq-mgmt", 27017: "mongodb", 50000: "sap",
}

# 会主动"打招呼"的端口：连接后读一小段即可拿到 banner（其余端口读了只会白等超时）
_BANNER_PORTS = {21, 22, 23, 25, 110, 143, 587, 873, 1433, 3306, 5432, 6379,
                 11211, 27017, 9200}

_MAX_BANNER = 120


def parse_ports(spec, default=None):
    """解析端口配置：支持 "80,443,8080" 与 "1-1024" 混写；空值返回内置 TOP 表。"""
    default = sorted(default or TOP_PORTS)
    s = str(spec or "").strip()
    if not s:
        return default
    out = set()
    for chunk in s.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            a, _, b = chunk.partition("-")
            try:
                lo, hi = int(a), int(b)
            except ValueError:
                continue
            if 0 < lo <= hi <= 65535 and hi - lo <= 4096:
                out.update(range(lo, hi + 1))
        else:
            try:
                p = int(chunk)
            except ValueError:
                continue
            if 0 < p <= 65535:
                out.add(p)
    return sorted(out) or default


def _banner(sock, port):
    if port not in _BANNER_PORTS:
        return ""
    try:
        sock.settimeout(1.2)
        data = sock.recv(_MAX_BANNER)
    except OSError:
        return ""
    text = (data or b"").decode("utf-8", "replace")
    return " ".join(text.split())[:_MAX_BANNER]


def _probe_port(args):
    host, ip, port, timeout, want_banner = args
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) != 0:
                return None
            banner = _banner(s, port) if want_banner else ""
    except OSError:
        return None
    service = TOP_PORTS.get(port, "")
    if banner:
        low = banner.lower()
        for key, name in (("ssh-", "ssh"), ("mysql", "mysql"), ("redis", "redis"),
                          ("memcached", "memcached"), ("mongo", "mongodb"),
                          ("elastic", "elasticsearch"), ("ftp", "ftp"),
                          ("smtp", "smtp"), ("pop3", "pop3"), ("imap", "imap")):
            if key in low:
                service = name
                break
    return {"host": host, "ip": ip, "port": port, "service": service, "banner": banner}


def scan_host(host, ip, ports, timeout=1.0, workers=64, banner=True, stopped=None):
    """扫描单个主机的开放端口。`stopped` 是可选的 `() -> bool` 回调（协作式取消）。"""
    jobs = []
    for p in ports:
        if stopped and stopped():
            break
        jobs.append((host, ip, p, timeout, banner))
    if not jobs:
        return []
    found = pool_run(_probe_port, jobs, workers=min(workers, len(jobs)))
    return sorted(found, key=lambda r: r["port"])


# `nmap -oG` 输出的端口片段：80/open/tcp//http///
_GREP_PORT_RE = re.compile(r"(\d+)/open/(?:tcp|udp)//([^/]*)//")


def nmap_scan(host, ip, ports, timeout=1, binary=None):
    """nmap TCP connect 扫描（装了 nmap 时优先走这里，输出更权威）。失败返回 None。"""
    bin_path = binary or which("nmap")
    if not bin_path:
        return None
    port_arg = ",".join(str(p) for p in ports)
    rc, out, _ = run_cmd([bin_path, "-sT", "-Pn", "-n", "--open",
                          "--host-timeout", f"{max(30, timeout * len(ports) // 4)}s",
                          "-p", port_arg, "-oG", "-", ip],
                         timeout=max(120, len(ports) * timeout * 2))
    if rc != 0 or not out:
        return None
    results = []
    for line in out.splitlines():
        if not line.startswith("Host:"):
            continue
        for m in _GREP_PORT_RE.finditer(line):
            port, service = int(m.group(1)), (m.group(2) or "").strip()
            results.append({"host": host, "ip": ip, "port": port,
                            "service": service or TOP_PORTS.get(port, ""), "banner": ""})
    return sorted(results, key=lambda r: r["port"])