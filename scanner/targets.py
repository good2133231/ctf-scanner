"""目标解析与归一化：每行一个目标，支持域名 / URL / IP / CIDR，# 开头为注释。"""
import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

from .utils import is_domain, to_ascii

IP_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
CIDR_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}$")

# CIDR 展开上限：只接受 /24 及更"小"的网段（最多 256 个地址）。
# 理由：本项目的定位是 Web/资产侦察，不是主机扫描器；放开 /16 会让 probe 阶段
# 瞬间产生数万次请求，既违反"非破坏性"红线也拖垮单机。
MAX_CIDR_ADDRESSES = 256


def expand_cidr(value):
    """把 CIDR 展开为 IP 列表；过大的网段返回空表（调用方按不支持处理）。

    /24 及以上（地址数 > 2）时去掉网络地址与广播地址——它们不是可探测主机。
    """
    try:
        net = ipaddress.ip_network(str(value), strict=False)
    except ValueError:
        return []
    if net.num_addresses > MAX_CIDR_ADDRESSES:
        return []
    if net.num_addresses > 2:
        return [str(h) for h in list(net.hosts())]
    return [str(h) for h in net]


def parse_line(line):
    s = str(line).strip().strip("/")
    if not s or s.startswith("#"):
        return None
    low = s.lower()
    if low.startswith(("http://", "https://")):
        # URL 形态的 IDN 目标：只在**主机含非 ASCII** 时才重建 URL（ASCII URL 必须逐字节
        # 不变）。用 urlsplit/urlunsplit 保留 scheme/端口/路径/query/fragment；归一失败
        # （to_ascii 返回 None）就退回原串，交给下游的形态判断兜（显式不静默）。
        sp = urlsplit(s)
        hostname = sp.hostname
        if hostname and any(ord(c) > 127 for c in hostname):
            try:
                port = sp.port
            except ValueError:
                port = None
            host = to_ascii(hostname)
            if host:
                netloc = host + (f":{port}" if port else "")
                s = urlunsplit((sp.scheme, netloc, sp.path, sp.query, sp.fragment))
        return ("url", s)
    if CIDR_RE.match(s):
        return ("cidr", s)
    m = IP_RE.match(s)
    if m and all(0 <= int(g) <= 255 for g in m.groups()):
        return ("ip", s)
    # 域名口径**收敛到一处**（`utils.to_ascii` + `utils.is_domain`）：IDN / 中文域名在此
    # 归一为 punycode 形入库（下游 DNS/HTTP/DB 全程用 ASCII），界面再回解成 Unicode。
    a = to_ascii(s)
    if a and is_domain(a):
        return ("domain", a)
    # 容错：host:port 或带路径的裸域名
    host = s.split("/")[0].split(":")[0]
    a = to_ascii(host)
    if a and is_domain(a):
        return ("domain", a)
    return ("unknown", s)


def parse_lines(lines):
    """解析多行目标，`cidr` 会被展开成多条 `ip`（过期/超限的网段直接丢弃）。"""
    out, seen = [], set()
    for ln in lines or []:
        t = parse_line(ln)
        if not t:
            continue
        items = [("ip", ip) for ip in expand_cidr(t[1])] if t[0] == "cidr" else [t]
        for it in items:
            if it not in seen:
                seen.add(it)
                out.append(it)
    return out
