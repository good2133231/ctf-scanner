"""目标解析与归一化：每行一个目标，支持域名 / URL / IP / CIDR，# 开头为注释。"""
import ipaddress
import re
from urllib.parse import urlparse, urlsplit, urlunsplit

from .utils import base_domain, is_domain, to_ascii

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


# ---------- 续146：目标 → 主机名 → 注册域（**唯一产地**） ----------
# 此前这六个地方各写了一份"URL 就取 hostname、域名就用自己"：subdomain 的收集根、
# extdom.task_bases 的归属判定、github_leak.target_domains 的检索词、diffview.target_set 的
# 可比性、osint 的证书反查与 C 段反查，另加 jsmine 的自家域名保护集。同一规则写 N 份必然漂
# （AGENTS §5.14），而且漂的方向总是"某一处少一道守门"——`github_leak` 就单独为
# `base_domain("127.0.0.1") → "0.1"` 加过一次注释与守门，而 `jsmine` 那处到今天都没有。


def host_of(kind, value):
    """一条**已解析**的目标（`parse_line` 的 `(kind, raw)`）→ 它的主机名；认不出就给空串。

    - `url`    → `urlparse().hostname`（已小写、已去端口）
    - `domain` → 它自己
    - `ip` / `cidr` / `unknown` → **空串**：IP 没有"收集根 / 归属域"这回事，它们的资产面归
      portscan / probe。**刻意不在这里替调用方决定"IP 要不要算"**：`diffview.target_set`
      判的是"两轮扫的是不是同一个目标"，那里 IP 目标也是身份 —— 它自己判 `kind == "ip"`。

    归一只做三件：小写、剥首尾点、能 punycode 就 punycode；**转不动就原样小写**（不猜也不丢 ——
    "是不是合法域名"由 `is_domain` / `root_of` 判，不由这里判，否则 `diffview` 那种
    "归一失败也要留着比"的调用方会被静默少一个目标）。
    """
    if kind == "url":
        raw = urlparse(str(value or "")).hostname or ""
    elif kind == "domain":
        raw = str(value or "")
    else:
        return ""
    raw = raw.strip().lower().strip(".")
    return to_ascii(raw) or raw


def hosts_of(items):
    """`parse_lines()` 的结果 → 去重**保序**的**合法域名**主机列表（顺序＝用户填目标的顺序）。

    保序不是洁癖：`subdomain` 的 `brute_max_domains`、`github_leak` 的 `max_domains`、
    `osint` 的 `max_hosts` 都是"取前 N 个"—— 用 set 就等于每次跑截到的都不是同一批。
    """
    out, seen = [], set()
    for kind, value in items or []:
        h = host_of(kind, value)
        if h and is_domain(h) and h not in seen:
            seen.add(h)
            out.append(h)
    return out


def root_of(host):
    """主机名 → **注册域（主域）**；不像域名（含裸 IP、单标签）时返回空串。

    判据只此一处，且**顺序不能反**：先 `is_domain` 守门、再 `base_domain`。反了会怎样：
    `base_domain("127.0.0.1")` 粗切成 `"0.1"` —— 一个**长得像域名**的垃圾，拿它去 GitHub 搜代码 /
    去 FOFA 反查证书纯属浪费额度。`base_domain` 自己读 `config/dicts/tlds.txt` 做最长匹配
    （含 `co.uk` 这类多段后缀与 punycode），清单缺失/为空时 fail-open（见 `utils.base_domain`）。
    `is_domain` 已经挡掉单标签（`intranet`）与 IP，所以本函数的非空返回值**必然带点** ——
    调用方不需要再写一遍 `"." in root`（那正是收敛前 osint / github_leak 各自的第二道冗余守门）。
    """
    h = str(host or "").strip().lower().strip(".")
    if not h or not is_domain(h):
        return ""
    return base_domain(h) or ""


def roots_of(items):
    """`parse_lines()` 的结果 → 去重保序的**注册域**列表（`root_of` 为空的丢掉）。"""
    out, seen = [], set()
    for h in hosts_of(items):
        r = root_of(h)
        if r and r not in seen:
            seen.add(r)
            out.append(r)
    return out
