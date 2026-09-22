"""CDN 判定：按 CNAME 链后缀匹配 CDN 厂商名单（数据文件 `config/dicts/cdn_cname.txt`）。

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
"""
import threading

from .config import BASE_DIR, DEFAULTS, resolve
from .utils import read_lines

_LOCK = threading.Lock()
_CACHE = {"suffixes": None, "path": None}


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


def match(cname_chain, settings=None):
    """在 CNAME 链里找 CDN 特征，返回命中的名单条目（用于标签展示），否则空串。

    `cname_chain` 是 `dnsq.cname_chain()` 的链（不含原始名字）。
    """
    suf_list, frag_list = suffixes(settings)
    if not (suf_list or frag_list):
        return ""
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
    return ""


def dict_path():
    """当前数据文件的绝对路径（供日志/排错展示）。"""
    return BASE_DIR / DEFAULTS["dicts"]["cdn_cname"]