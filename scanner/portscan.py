"""端口/服务发现（P1-2）：fscan / nmap 优先，内置 TCP connect 兜底。

定位与红线：
- 只做 **TCP connect 扫描**（不构造原始包、不做 SYN 半开、不做 UDP、不做暴力破解），
  因此不需要 root/管理员权限，也不会留下半连接状态；
- banner 只在"服务端会先说话"的端口上被动读取（SSH/SMTP/MySQL/Redis 等），
  对 HTTP 类端口不发任何请求 —— 服务识别交给 probe 阶段；
- **不调用 masscan**：它依赖原始套接字与 root，且扫描速率激进，与"非破坏性"约束冲突。
  nmap 只使用 `-sT -Pn --open`（TCP connect、跳过主机发现、只列开放端口）。
- fscan（可选，`tools.fscan` 填了路径或它在 PATH 里才会用）**强制带 `-np -nobr`**，
  并额外带 `-nopoc`（fscan 帮助原文：`-nobr` 禁用暴力破解 / `-nopoc` 禁用POC扫描），
  这两条是本项目的非破坏性红线（见 TODO.md）；我们只要它的端口发现能力，
  漏洞检测交给 vulnscan 阶段。老版本 fscan 不认 `-nopoc` 时会退到 `-np -nobr` 重试一次。
  **实测补充**：`-nopoc` 只管 POC 模块，fscan 内置的**服务插件**（mysql/redis/webpoc 指纹）
  仍会跑，输出里可能出现 `[!] Redis未授权访问: ip:port` 这类**只读**探测结论 ——
  本模块只解析"端口开放"的事实行，不采信它的漏洞结论。
  **另一个实测补充**：fscan 默认 `-o result.txt` 且写的是**进程 CWD**，所以调用它时一律显式
  传 `cwd=`（任务产物目录），否则会在启动扫描器的那个目录里留下一个跨轮追加的结果文件。

TOP_PORTS 覆盖 CTF 里真正高频的面：Web 变体端口、数据库、远程管理、容器/中间件。
"""
import re
import socket
import tempfile

from . import throttle as _throttle_mod
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


def parse_ports(spec, default=None, max_span=4096):
    """解析端口配置：支持 "80,443,8080" 与 "1-1024" 混写；空值返回内置 TOP 表。

    `max_span` 是**单段区间允许的最大跨度**（默认 4096）—— 它存在的意义是防止
    "手滑写成 1-65535" 就把一个轻量阶段变成 6.5 万次连接。真要全端口扫描请显式
    传 `max_span=65535`（全端口入口会这么做，并同时打开排除已扫端口）。
    """
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
            if 0 < lo <= hi <= 65535 and hi - lo <= max_span:
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


def _connect_banner(ip, port, timeout, want_banner):
    """TCP connect（`connect_ex`）+ 可选被动 banner。连不上（拒绝/超时/出错）返回 None。

    抽出来是为了把"统一闸"（F2）套在外面 —— 拿不到名额就不该起这个连接。
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) != 0:
                return None
            return _banner(s, port) if want_banner else ""
    except OSError:
        return None


def _probe_port(args):
    host, ip, port, timeout, want_banner, throttle = args
    try:
        if throttle is not None:
            # 裸 socket 也走统一闸（F2）：一次在飞连接占一个 `"socket"` 名额。
            # 预算耗尽 / 被取消 → 不建连接、按"无结果"返回；真正的停止由 `ctx.stopped()`
            # （含 `throttle.exhausted()`）在阶段循环边界体现（见 scanner/throttle.py）。
            with throttle.slot("socket"):
                banner = _connect_banner(ip, port, timeout, want_banner)
        else:
            banner = _connect_banner(ip, port, timeout, want_banner)
    except _throttle_mod.BudgetExhausted:
        return None
    except _throttle_mod.StopRequested:
        return None
    if banner is None:
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


def scan_host(host, ip, ports, timeout=1.0, workers=64, banner=True, stopped=None,
              throttle=None):
    """扫描单个主机的开放端口。`stopped` 是可选的 `() -> bool` 回调（协作式取消）。

    `throttle`（`settings["_throttle"]`，F2）：传入时每个在飞连接占一个 `"socket"` 名额，
    并把线程数收敛到 `throttle.effective_cap(workers)` —— 这是"消灭 8×256"的关键：
    实际并发不再由阶段自己说了算，而是 `min(阶段并发, 任务上限, 进程上限)`。
    """
    jobs = []
    for p in ports:
        if stopped and stopped():
            break
        jobs.append((host, ip, p, timeout, banner, throttle))
    if not jobs:
        return []
    if throttle is not None:
        cap = throttle.effective_cap(workers)
        if cap > 0:
            workers = cap
    found = pool_run(_probe_port, jobs, workers=min(workers, len(jobs)))
    return sorted(found, key=lambda r: r["port"])


# `nmap -oG` 输出的端口片段：80/open/tcp//http///
_GREP_PORT_RE = re.compile(r"(\d+)/open/(?:tcp|udp)//([^/]*)//")


def format_ports(ports):
    """把端口列表压成 `80,443,8000-8010,8080` 形式（连续段合并成区间）。

    为什么必须压：外部工具（nmap/fscan）的命令行参数有长度上限 —— Windows
    `CreateProcess` 是 32767 字符，Linux 是 ~2MB。全端口扫描的 65535 个端口
    逐个数逗号拼出来是 ~38 万字符，**在 Windows 上会直接 OSError 起不来**。
    压成 `1-65535`（5 字符）就没事了。顺带也让命令行日志可读。
    """
    nums = sorted({int(p) for p in ports or [] if 0 < int(p) <= 65535})
    if not nums:
        return ""
    chunks, start, prev = [], nums[0], nums[0]
    for p in nums[1:]:
        if p == prev + 1:
            prev = p
            continue
        chunks.append(f"{start}-{prev}" if start != prev else str(start))
        start = prev = p
    chunks.append(f"{start}-{prev}" if start != prev else str(start))
    return ",".join(chunks)


def nmap_scan(host, ip, ports, timeout=1, binary=None, throttle=None):
    """nmap TCP connect 扫描（装了 nmap 时优先走这里，输出更权威）。失败返回 None。

    `throttle`（F2）：传入时这次子进程调用占一个 `"subprocess"` 名额（并消耗预算）。
    """
    bin_path = binary or which("nmap")
    if not bin_path:
        return None
    port_arg = format_ports(ports) or ",".join(str(p) for p in ports)
    # 两个超时都要封顶：全端口（65535）时按线性公式算出来的 host-timeout 会是 4 小时级、
    # 进程超时会是 36 小时级 —— 那等于"卡住也不会结束"。封顶后最坏情况 30 分钟结束并回退内置实现。
    host_timeout = min(1800, max(30, timeout * len(ports) // 4))
    proc_timeout = min(3600, max(120, int(len(ports) * timeout * 2)))
    rc, out, _ = run_cmd([bin_path, "-sT", "-Pn", "-n", "--open",
                          "--host-timeout", f"{host_timeout}s",
                          "-p", port_arg, "-oG", "-", ip],
                         timeout=proc_timeout, throttle=throttle)
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


# ---------- fscan 适配（可选外部工具） ----------

# fscan 打印结果时会带 ANSI 颜色码，不剥掉会污染解析
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

# 实测 fscan 2.2.1，"端口确实开着"的行形态有三种（外加老版本一种）：
#   ① `[*] 127.0.0.1:22   ssh   [Product:OpenSSH …]`        服务插件连上并识别出服务
#   ② `[*] http://127.0.0.1:888   http   [Product:nginx …]`  Web 插件连上并抓到 banner
#   ③ `[+] http://127.0.0.1:8081  code:302 len:358 …`        Web 插件拿到了响应码
#   ④ `[+] 192.168.1.1:8080 open`                            老版本（1.x）形态
# 这四种都只表达"端口开放"这一个事实，可以放心采信。
#
# **一律行首锚定**（`^\s*\[…\]\s*…`）：③ 行的 title 段里会出现
# `title:Redirecting to http://127.0.0.1:8081/system` 这种"跳转目标 URL"，
# 若在行中间乱搜 URL，会把跳转目标误记成本机开放端口。
_FSCAN_SVC_RE = re.compile(r"^\s*\[\*\]\s*(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})(?=\s)", re.M)
_FSCAN_WEB_RE = re.compile(
    r"^\s*\[[*+]\]\s*https?://(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})(?=[/\s])", re.M)
_FSCAN_OPEN_RE = re.compile(
    r"^\s*\[\+\]\s*(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})\s+open\b", re.I | re.M)
# 收尾统计行 `[*] 扫描完成，发现 8 个开放端口`（0 个时同样会打）—— 权威总数，用于交叉校验
_FSCAN_TOTAL_RE = re.compile(r"发现\s*(\d+)\s*个开放端口")

# 老版本 fscan 不认新参数时，stderr/stdout 会打 usage 或 "flag provided but not defined"
_FSCAN_BAD_FLAG_RE = re.compile(r"not defined|flag provided|Usage of|incorrect usage", re.I)

# 强制项（**任何**调用路径都必须带）：跳过主机存活探测 + 关掉内置暴力破解。
# `-nopoc` 是"再收敛一层"，老版本不认时会去掉它重试，但绝不连 `-np -nobr` 一起去掉。
def _fscan_flags(with_nopoc=True):
    return ["-np", "-nobr"] + (["-nopoc"] if with_nopoc else [])


def _parse_fscan(text):
    """从 fscan 输出里提取开放端口。返回 `(ports, declared)`。

    `ports` 是去重后的端口集合；`declared` 是收尾统计行自报的开放端口数
    （输出里没有那一行时为 None）。调用方拿两者判断"这份解析是否可信"。
    """
    ports = set()
    for rx in (_FSCAN_SVC_RE, _FSCAN_WEB_RE, _FSCAN_OPEN_RE):
        for m in rx.finditer(text):
            p = int(m.group(2))
            if 0 < p <= 65535:
                ports.add(p)
    m = _FSCAN_TOTAL_RE.search(text)
    return ports, (int(m.group(1)) if m else None)


def fscan_scan(host, ip, ports, timeout=1, binary=None, workers=None, throttle=None,
               workdir=None):
    """fscan 端口扫描（装了 fscan 时可用）。**解析不可信时返回 None** → 回退 nmap/内置。

    返回语义（踩过坑，务必保持）：
    - `None` —— 没装 / 起不来 / 退出码非 0 / **解析数与统计行不符**（统计行自报 N 个，
      我们解析出 ≠ N 个：少了说明该版本换了行格式、多了说明认进了不是"开放端口"的行）。
      调用方据此回退；
    - `[]`   —— 统计行明确写了 `发现 0 个开放端口`，即"确实没有开放端口"，不必回退。

    早先的实现只认 `[+] ip:port open`，而 fscan 2.x 早已改用 `[*] ip:port <service>`
    形态，于是"解析到 0 条 → 返回 [] → 阶段以为扫描成功、不再兜底"，
    造成**静默漏报**。现在用统计行交叉校验，数目不符一律返回 None 交回兜底。

    `-t` 跟着策略里的 `portscan.workers` 走（×8，封顶 600），让用户仍能节制请求量。

    `throttle`（F2）：传入时这次子进程调用占一个 `"subprocess"` 名额（并消耗预算）。
    **注意**：`budget_total` 只约束"我们起几个子进程"，**不约束 fscan 内部发多少连接**
    （见 scanner/throttle.py 的覆盖缺口说明）。

    `workdir`（2026-09-25 续45 真跑踩坑）：fscan 默认 `-o result.txt`（`common/flag.go`），
    而 `-o` 的相对路径是按**进程 CWD** 落的 —— 不显式指定 `cwd` 就会落到启动扫描器的那个目录
    （GUI/CLI 从仓库根启动 → 仓库根多出一个 `result.txt`，内容是**跨轮追加**的，还带着别的目标
    的服务 banner，`git add .` 会顺手把它带进提交）。因此这里一律显式给 `cwd`：优先任务的产物
    目录（与 dirmap/cert/screenshot 产物同级），没给就退到系统临时目录，**绝不继承进程 CWD**。
    """
    bin_path = binary or which("fscan")
    if not bin_path:
        return None
    port_arg = format_ports(ports) or ",".join(str(p) for p in ports)
    if not port_arg:
        return None
    threads = min(600, max(30, int(workers or 64) * 8))
    # 进程超时封顶：全端口时也要保证"最坏情况会结束"（不封顶会卡到天荒地老）
    proc_timeout = min(1800, max(60, int(len(ports) * timeout / 4)))
    cwd = str(workdir) if workdir else tempfile.gettempdir()
    base = [bin_path, "-h", ip, "-p", port_arg,
            "-t", str(threads), "-time", str(max(1, int(round(timeout))))]
    rc, out, err = run_cmd(base + _fscan_flags(), timeout=proc_timeout, throttle=throttle,
                           cwd=cwd)
    if rc != 0 and _FSCAN_BAD_FLAG_RE.search((out or "") + (err or "")):
        # 老版本不认 `-nopoc`：去掉它重试一次，`-np -nobr` 依然保留（红线不动）
        rc, out, err = run_cmd(base + _fscan_flags(with_nopoc=False), timeout=proc_timeout,
                               throttle=throttle, cwd=cwd)
    if rc != 0:
        return None
    found, declared = _parse_fscan(_ANSI_RE.sub("", out or ""))
    if declared is None or len(found) != declared:
        return None
    return [{"host": host, "ip": ip, "port": p,
             "service": TOP_PORTS.get(p, ""), "banner": ""} for p in sorted(found)]