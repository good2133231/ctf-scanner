"""CDN 判定：**两条判据** —— CNAME 链后缀（`config/dicts/cdn_cname.txt`）与
任播 IP 段（`config/dicts/cdn_ips.txt`），任一命中即算走 CDN。

为什么要它：一个子域名"解析到 CDN"还是"直连源站"，直接决定后续动作是否值得做 ——
CDN 节点上的端口/目录/漏洞扫描打的是边缘节点，既没结果也不礼貌；而资产视图里
标出 CDN/非 CDN 也能让人一眼分清"哪些域名是同一台源站"。

数据来源：参考项目的 `dict/information/cdn_cname.txt`（292 条厂商 CNAME 后缀），
本模块只做**只读加载 + 后缀匹配**，不发任何请求、不写文件。

匹配规则（对应数据文件里的三种写法，实测按"去掉前后点后是否还含点"即可区分）：
- `.alicdn.com`   → 含点的按**域名后缀**匹配：`x.alicdn.com` 命中；
- `.akamai.` / `.azureedge.` → 以点结尾的，是厂商域名里的固定**片段**（编号在前缀，
  如 `a1234.b.akamaiedge.net`），按**子串**匹配；
- `.cloudflare` / `.awsdns` → 去掉点后不含点的裸词，同样按**子串**匹配
  （`x.cloudflare.net` / `ns-1.awsdns-01.org`）。

子串匹配会带来少量误判（`notcloudflare.example.com` 也会命中），但它只用于**展示标签**，
不参与任何安全判定，宁可标得宽一点也不漏标。缓存：文件只在首次调用时读一次。

**为什么要加 IP 判据**（2026-09-25 续43，实跑 pengo.pro 逮到）：`cdn_cname.txt` 只能认出
"CNAME 指向厂商域名"的 CDN；Cloudflare 这类**任播** CDN 常常是 A 记录直接解析到边缘 IP、
CNAME 链为空（实测 pengo.pro / admin.pengo.pro / app.pengo.pro 三个主机都解析到
`172.66.40.229` / `172.66.43.27`，CNAME 链为空）。只按 CNAME 判会一律标成"非 CDN"，
后果是 ① 资产页看不出走 CDN；② `portscan` 会去打 Cloudflare 边缘节点，得出"30 个端口开放"
这种与本项目标无关的结论（同一时刻手工 TCP connect 22 端口是超时的）。IP 段取自厂商
**官方**发布的列表，文件头写明来源与取数日期，不用第三方汇总清单。
"""
import ipaddress
import threading

from .config import BASE_DIR, DEFAULTS, resolve
from .utils import read_lines

_LOCK = threading.Lock()
_CACHE = {"suffixes": None, "path": None}
# IP 段的缓存与 CNAME 名单**分开**：两份文件路径不同、格式不同，共用一个槽位会互相顶掉。
_IP_LOCK = threading.Lock()
_IP_CACHE = {"nets": None, "path": None}


def _normalize(path):
    """把数据文件读成 (域名后缀元组, 片段元组)。"""
    suffixes, fragments = [], []
    for raw in read_lines(path):
        line = raw.strip().lower()
        if not line or line.startswith("#"):
            continue
        body = line.strip(".")
        if not body:
            continue
        if line.endswith(".") or "." not in body:
            fragments.append(body)
        else:
            suffixes.append(body)
    return tuple(suffixes), tuple(fragments)


def suffixes(settings=None):
    """返回 (域名后缀元组, 片段元组)；文件缺失时返回空元组（判定结果一律"非 CDN"）。"""
    path = ((settings or {}).get("dicts") or {}).get("cdn_cname") \
        or DEFAULTS["dicts"]["cdn_cname"]
    full = str(resolve(path))
    with _LOCK:
        if _CACHE["path"] == full and _CACHE["suffixes"] is not None:
            return _CACHE["suffixes"]
    try:
        data = _normalize(full)
    except Exception:
        data = ((), ())
    with _LOCK:
        _CACHE["path"] = full
        _CACHE["suffixes"] = data
    return data


def _parse_nets(path):
    """把 IP 段文件读成 `((网络对象, 厂商), ...)`。

    容错：单行写坏（CIDR 不合法）只跳过那一行并继续 —— 一个数据文件里混进一行脏数据就
    让整份名单失效，属于"越修越糟"。厂商列为空时退回用 CIDR 原文当标签（至少能看出命中哪一段）。
    """
    out = []
    for raw in read_lines(path):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        cidr, _, vendor = line.partition("|")
        cidr, vendor = cidr.strip(), vendor.strip()
        if not cidr:
            continue
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        out.append((net, vendor or cidr))
    return tuple(out)


def networks(settings=None):
    """返回 `((网络对象, 厂商), ...)`；文件缺失/为空时返回空元组（判定结果一律"非 CDN"）。"""
    path = ((settings or {}).get("dicts") or {}).get("cdn_ips") \
        or DEFAULTS["dicts"]["cdn_ips"]
    full = str(resolve(path))
    with _IP_LOCK:
        if _IP_CACHE["path"] == full and _IP_CACHE["nets"] is not None:
            return _IP_CACHE["nets"]
    try:
        data = _parse_nets(full)
    except Exception:
        data = ()
    with _IP_LOCK:
        _IP_CACHE["path"] = full
        _IP_CACHE["nets"] = data
    return data


def ip_match(ips, settings=None):
    """在解析 IP 列表里找 CDN 任播段，返回命中的**厂商**名，否则空串。

    `ips` 是 `dnsq.resolve_detail()` 返回的 A 记录文本列表；非 IP 的条目（空串等）直接跳过。
    只做"属于哪个厂商的段"这一件事，不涉及任何请求，也不改变调用方的行为。
    """
    nets = networks(settings)
    if not nets or not ips:
        return ""
    for ip in ips:
        try:
            addr = ipaddress.ip_address(str(ip or "").strip())
        except ValueError:
            continue
        for net, vendor in nets:
            # 版本不同直接跳过：`ipaddress` 对不同版本做包含判断会抛 TypeError。
            if addr.version == net.version and addr in net:
                return vendor
    return ""


def match(cname_chain, settings=None, ips=None):
    """找 CDN 特征，返回命中的标签（用于展示），否则空串。

    `cname_chain` 是 `dnsq.cname_chain()` 的链（不含原始名字）；`ips` 是同一次解析出的
    A 记录列表（可选）。**CNAME 判据优先**（它是厂商明确的特征），CNAME 没命中再看 IP 段
    —— 后者覆盖"任播 CDN 直连 IP、无 CNAME"的情况，见模块 docstring。
    """
    suf_list, frag_list = suffixes(settings)
    for host in cname_chain or []:
        h = str(host or "").strip().lower().rstrip(".")
        if not h:
            continue
        for suf in suf_list:
            if h == suf or h.endswith("." + suf):
                return suf
        for frag in frag_list:
            if frag and frag in h:
                return frag
    return ip_match(ips, settings)


def dict_path():
    """当前数据文件的绝对路径（供日志/排错展示）。"""
    return BASE_DIR / DEFAULTS["dicts"]["cdn_cname"]