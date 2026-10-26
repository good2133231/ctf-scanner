"""FOFA 反查（P3-1 / todo #6）：用 favicon 哈希反查同源资产。

用户原话："ico 索引目标功能，提取目标的 ico，去 fofa 搜索，并且结果太多的 ico 判定为黑 ico，
就不去拓展了" —— 本模块实现后半段（反查 + 黑 ico 判定），前半段（favicon 采集与哈希）
在 `scanner/fingerprint.py` 与 `scanner/mmh3.py`。

依赖：凭据文件里的 `fofa: {email, key}`（`config/keys.yaml`，或口令加密的
`config/keys.enc.yaml`；独立文件、不入库、GUI 不碰 —— 续98 起两份谁生效看 `config.load_keys()`）。
**未填 key 时一律返回"不可用"并只记一行日志**，不影响流水线其它部分。

技术要点：
- FOFA 的 `icon_hash` 用的是 **mmh3**（不是 MD5），取值方式见 `scanner/mmh3.py::favicon_hash`；
- `qbase64` 必须 URL 编码（base64 里的 `+` `/` `=` 直接拼进 query 会被破坏）；
- 返回体形如 `{"error": false, "size": N, "results": [[host, domain, ip, port, title], ...]}`，
  `error: true` 时带 `errmsg`（常见于配额耗尽 / key 无效），这些都**显式报错**而不是静默无结果。
"""
import base64
import json
import time
import urllib.parse

from . import keystore
from .utils import http_request, is_domain, to_ascii

API = "https://fofa.info/api/v1/search/all"
FIELDS = "host,domain,ip,port,title"

# 单个 favicon 命中过多资产 → 说明这个图标是"公共图标"（默认页/通用框架/空图标），
# 继续按它拓展只会灌入大量无关资产。阈值见 fofa.black_ico_threshold（默认 200）。
DEFAULT_BLACK_ICO_THRESHOLD = 200

# 同一张证书被多少资产共用就不值得再按它拓展（公共 CA / 大厂通用证书）。
DEFAULT_CERT_THRESHOLD = 200

# 同一个标题命中多少资产就不值得再按它拓展 —— 与"黑 ico"同构，只是判据换成标题：
# `404 Not Found` / `Error` / `Apache2 Ubuntu Default Page` 这类**通用标题**一搜一大堆，
# 按它拓展只会灌进成千上万条无关资产。阈值见 fofa.title_threshold（默认 200）。
DEFAULT_TITLE_THRESHOLD = 200

# 续229：两次 FOFA 请求之间的最小间隔（秒）。FOFA 按 key 计频率，循环反查不节流就会撞
# HTTP 429（`min_interval` 与 VirusTotal 那路同款；填 0 = 不节流）。
DEFAULT_MIN_INTERVAL = 3.0
_LAST_TS = 0.0

# 这些标题一眼就是"模板页"，连一次查询都不值得发（省配额、也省时间）
GENERIC_TITLES = frozenset({
    "404", "404 not found", "not found", "error", "403 forbidden", "forbidden",
    "401 unauthorized", "unauthorized", "500 internal server error",
    "internal server error", "index of /", "welcome to nginx", "apache2 ubuntu default page",
    "apache2 debian default page", "iis windows server", "test page for apache",
    "403", "401", "500", "nginx", "apache", "iis", "default", "",
})

# 实测样本（2026-09-23，真实 FOFA 配额查询）：这些标题的命中数与"具体站点标题"差 4~6 个数量级，
# 说明它们就是公共模板标题，**一发查询就是浪费**（结果肯定超过 title_threshold 被丢弃）：
#   维保中心（具体站点标题）        → 15
#   后台管理系统                    → 192188
#   Index of /                      → 5974788
#   Welcome to nginx                → 8344737
#   登录                            → 39722277
# 结论：阈值本身（200）落在 15 与 19 万之间的巨大空隙里，**不需要调**；
# 真正值得做的是把上面这些"不用查也知道是公共"的标题前置到**零请求预筛**里。
GENERIC_TITLE_PREFIX = (
    # Apache/Nginx 目录列表页：`Index of /uploads`、`Index of /backup` 全是通用页
    "index of /",
    # 中文站点最常见的后台入口标题：`后台管理系统`、`后台管理系统 - 登录`、`后台管理系统v2`
    "后台管理系统",
    "directory listing for",
)

# 已知"占位证书"主体：实测 `cert="example.com"` → 2164696 条 —— 这是各家默认配置里的
# 自签占位证书，按它拓展只会灌进百万条无关资产，**连查询都不发**。
GENERIC_CERT_NAMES = frozenset({
    "example.com", "example.org", "example.net", "test.com", "test.local",
    "localhost", "localhost.localdomain", "invalid", "local", "domain.com",
    "yourdomain.com", "changeme", "smtp.example.com", "mail.example.com",
})
# 占位证书的域名后缀（`*.example.com` 这类整域都算）。
# 刻意**只收** RFC 2606 的示例域：像 `.test` / `.invalid` 这种保留后缀虽然也是"不该出现"，
# 但真实目标里绝不使用它们，收进来只会误伤用示例域做自测的场景，收益为负。
GENERIC_CERT_SUFFIX = (".example.com", ".example.org", ".example.net")


def credentials(settings):
    """从 `settings["keys"]["fofa"]` 取 (email, key)；缺失时返回 ("", "")。"""
    cfg = ((settings or {}).get("keys") or {}).get("fofa") or {}
    if not isinstance(cfg, dict):
        return "", ""
    return str(cfg.get("email") or "").strip(), str(cfg.get("key") or "").strip()


def available(settings):
    email, key = credentials(settings)
    return bool(email and key)


def black_ico_threshold(settings):
    cfg = (settings or {}).get("fofa", {}) or {}
    try:
        return int(cfg.get("black_ico_threshold") or DEFAULT_BLACK_ICO_THRESHOLD)
    except (TypeError, ValueError):
        return DEFAULT_BLACK_ICO_THRESHOLD


def is_black_ico(total, settings):
    """该 favicon 是否属于"黑 ico"（结果过多 = 公共图标，放弃拓展）。"""
    try:
        return int(total) > black_ico_threshold(settings)
    except (TypeError, ValueError):
        return False


def build_query(icon_hash):
    """构造 favicon 查询语句（icon_hash 为有符号 32 位整数）。"""
    return f'icon_hash="{int(icon_hash)}"'


def _quote_value(raw):
    """把值塞进 FOFA 的 `key="value"` 查询串：清掉引号与反斜杠。

    域名/标题都来自扫描结果（外部输入），值里的 `"` 会提前闭合查询串、
    `\\` 会把闭合引号转义掉，两种情况都会构造出错误甚至非预期的查询。
    （此前只有标题做了去引号，域名和反斜杠都没处理。）
    """
    return str(raw or "").strip().replace("\\", "").replace('"', "")


def build_cert_query(domain):
    """构造证书查询语句：`cert="example.com"` —— 找与该域名共用同一张 TLS 证书的其它资产。"""
    return f'cert="{_quote_value(str(domain or "").strip().strip("."))}"'


def build_title_query(title):
    """构造标题查询语句：`title="xxx"` —— 找与该站点**标题相同**的其它资产。"""
    return f'title="{_quote_value(title)}"'


def title_threshold(settings):
    cfg = (settings or {}).get("fofa", {}) or {}
    try:
        return int(cfg.get("title_threshold") or DEFAULT_TITLE_THRESHOLD)
    except (TypeError, ValueError):
        return DEFAULT_TITLE_THRESHOLD


def is_common_title(total, settings):
    """该标题是否"通用"（命中过多，如 404 / 默认页）—— 命中即放弃拓展（等同黑 ico）。"""
    try:
        return int(total) > title_threshold(settings)
    except (TypeError, ValueError):
        return False


def is_generic_title(title):
    """一眼就是模板/通用页的标题（`404` / `Error` / `Index of /uploads` …），连查询都不用发。

    两层判据（依据 2026-09-23 实测样本，见 `GENERIC_TITLES` 上方注释）：
    ① 精确命中 `GENERIC_TITLES`；
    ② 前缀命中 `GENERIC_TITLE_PREFIX` —— 抓 `Index of /uploads`、`后台管理系统 - 登录`
       这类"通用标题 + 后缀"的变体。②故意不设长度上限：这类标题无论后面跟什么都还是
       同一张公共模板页，查出来必然是百万级结果，跳过**严格优于**发一次注定被丢的查询。
    """
    t = str(title or "").strip().lower()
    if t in GENERIC_TITLES:
        return True
    return any(t.startswith(p) for p in GENERIC_TITLE_PREFIX)


def is_generic_cert(domain):
    """是否是已知的"占位证书"主体（`example.com` / `localhost` …），连查询都不用发。

    实测 `cert="example.com"` 命中 **2164696** 条 —— 这类名字出现在各种默认配置的
    自签证书里，按它拓展只会灌进百万条无关资产。
    """
    d = str(domain or "").strip().lower().strip(".")
    if not d:
        return True
    if d in GENERIC_CERT_NAMES:
        return True
    return any(d.endswith(sfx) for sfx in GENERIC_CERT_SUFFIX)


def search_title(title, settings, logger=None, size=None):
    """按标题反查：`title="xxx"`，返回 `(assets, total, error)`（结构同 `search`）。"""
    text = str(title or "").strip()
    if not text:
        return [], 0, "标题反查目标为空"
    return search_query(build_title_query(text), settings, logger=logger, size=size)


def search(icon_hash, settings, logger=None, size=None):
    """按 favicon 哈希反查，返回 `(assets, total, error)`。"""
    if not icon_hash:
        return [], 0, "favicon 哈希为空"
    return search_query(build_query(icon_hash), settings, logger=logger, size=size)


def search_cert(domain, settings, logger=None, size=None):
    """按证书反查：`cert="domain"`，返回 `(assets, total, error)`（结构同 `search`）。"""
    if not str(domain or "").strip().strip("."):
        return [], 0, "证书反查目标域名为空"
    return search_query(build_cert_query(domain), settings, logger=logger, size=size)


def cert_threshold(settings):
    cfg = (settings or {}).get("fofa", {}) or {}
    try:
        return int(cfg.get("cert_threshold") or DEFAULT_CERT_THRESHOLD)
    except (TypeError, ValueError):
        return DEFAULT_CERT_THRESHOLD


def is_common_cert(total, settings):
    """该证书是否"通用"（被过多域名共用，如公共 CA / 大厂证书）——命中即放弃拓展。"""
    try:
        return int(total) > cert_threshold(settings)
    except (TypeError, ValueError):
        return False


def min_interval(settings):
    """两次 FOFA 请求之间的最小间隔（秒）；`fofa.min_interval`，默认 `DEFAULT_MIN_INTERVAL`。

    为什么必须有（续229）：osint 阶段是**循环**反查 —— 每个 favicon 哈希一次、每个证书一次、
    每个标题一次，而 FOFA 按 key 计**频率**，连发就是把 429 撞出来（本模块此前完全没有节流，
    VirusTotal 那路早就有 `min_interval` 了）。填 0 表示不节流（自己承担 429）。
    """
    raw = ((settings or {}).get("fofa") or {}).get("min_interval")
    if raw is None:
        return DEFAULT_MIN_INTERVAL
    try:
        return max(0.0, float(raw))
    except (TypeError, ValueError):
        return DEFAULT_MIN_INTERVAL


def _rate_wait(settings, now=None, sleep=None):
    """按 `min_interval` 等够间隔；返回实际等待秒数（`now`/`sleep` 可注入，测试不用真睡）。"""
    global _LAST_TS
    now_fn = now or time.monotonic
    sleep_fn = sleep or time.sleep
    gap = min_interval(settings)
    if gap <= 0 or _LAST_TS <= 0:
        _LAST_TS = now_fn()
        return 0.0
    waited = 0.0
    while True:
        left = gap - (now_fn() - _LAST_TS)
        if left <= 0:
            break
        sleep_fn(left)
        waited += left
    _LAST_TS = now_fn()
    return waited


def _retry_after(resp):
    """响应头里的 `Retry-After`（秒）；读不到返回 0。FOFA 限流时会带它。"""
    hdrs = resp.get("headers") or {}
    if not isinstance(hdrs, dict):
        return 0.0
    for k, v in hdrs.items():
        if str(k).lower() == "retry-after":
            try:
                return float(str(v).strip()[:8])
            except (TypeError, ValueError):
                return 0.0
    return 0.0


def search_query(query, settings, logger=None, size=None):
    """按 FOFA 查询语句反查，返回 `(assets, total, error)`。

    - assets: `[{host, domain, ip, port, title}, ...]`（`error` 非空时为空表）
    - total:  FOFA 报告的命中总数（用于黑 ico / 通用证书判定）
    - error: 空串表示成功；否则是可直接展示给用户的原因
    """
    email, key = credentials(settings)
    if not (email and key):
        return [], 0, keystore.keys_hint("fofa.email / fofa.key")
    cfg = (settings or {}).get("fofa", {}) or {}
    try:
        size = int(size or cfg.get("max_assets") or 100)
    except (TypeError, ValueError):
        size = 100
    size = max(1, min(size, 10000))          # FOFA 单次上限 10000
    try:
        timeout = int((settings or {}).get("limits", {}).get("http_timeout", 10))
    except (TypeError, ValueError):
        timeout = 10

    qbase64 = urllib.parse.quote_plus(
        base64.b64encode(str(query).encode("utf-8")).decode("ascii"))
    url = (f"{API}?email={urllib.parse.quote_plus(email)}&key={urllib.parse.quote_plus(key)}"
           f"&qbase64={qbase64}&size={size}&fields={FIELDS}")
    # 续229：发之前先按 `fofa.min_interval` 等够间隔（循环反查不节流 = 把 429 撞出来）
    _rate_wait(settings)
    resp = http_request(url, timeout=timeout, settings=settings)
    if not resp:
        return [], 0, "请求 fofa 失败（网络不可达或超时）"
    if resp.get("status") == 429:
        # 频率超限：按 `Retry-After`（没有就用 min_interval）等一次再试一次；仍 429 就如实报，
        # 不说成"接口坏了"—— 429 的意思是"你发太快"，改 `fofa.min_interval` 就能解决。
        _gap = max(1.0, min(float(_retry_after(resp) or min_interval(settings) or 5.0), 60.0))
        if logger:
            logger.info(f"[fofa] HTTP 429（请求频率超限）：等 {_gap:.0f}s 后重试一次"
                        f"（fofa.min_interval={min_interval(settings)}s；"
                        f"仍被限就把它调大，或稍后重跑）")
        time.sleep(_gap)
        resp = http_request(url, timeout=timeout, settings=settings)
        if not resp:
            return [], 0, "请求 fofa 失败（429 后重试仍无响应）"
        if resp.get("status") == 429:
            return [], 0, (f"fofa 返回 HTTP 429（请求频率超限）：已等 {_gap:.0f}s 重试一次仍被限"
                           f" ⇒ 把 fofa.min_interval（当前 {min_interval(settings)}s）调大，"
                           f"或稍后重跑")
    if resp.get("status") != 200:
        return [], 0, f"fofa 返回 HTTP {resp.get('status')}"
    try:
        data = json.loads(resp.get("text") or "{}")
    except (ValueError, TypeError):
        return [], 0, "fofa 响应不是合法 JSON"
    if not isinstance(data, dict):
        return [], 0, "fofa 响应结构异常"
    if data.get("error"):
        msg = str(data.get("errmsg") or "未知错误")
        if logger:
            logger.warning(f"[fofa] 查询被拒：{msg}")
        return [], 0, msg
    total = data.get("size") or 0
    assets = []
    for row in (data.get("results") or []):
        if not isinstance(row, (list, tuple)):
            continue
        cols = list(row) + [""] * (5 - len(row))
        assets.append({"host": str(cols[0]), "domain": str(cols[1]), "ip": str(cols[2]),
                       "port": str(cols[3]), "title": str(cols[4])})
    return assets, total, ""


def _host_part(raw):
    """从 FOFA 的 `host` 字段取主机名：兼容 `https://a.test` / `a.test:443` / 裸域名。

    原实现（subdomain 阶段）是 `host.split(":", 1)[0]` —— 对 `https://a.test` 会切出
    `"https"` 这个"域名"写进库（真实事故：多任务出现 `domain='https'` 的垃圾行）。
    这里统一用 urlparse：没有 scheme 时补 `//`，让它按 netloc 解析；两种形态都不带端口。
    """
    text = str(raw or "").strip()
    if not text:
        return ""
    if "://" not in text:
        text = "//" + text
    try:
        return (urllib.parse.urlparse(text).hostname or "").strip(".")
    except ValueError:
        return ""


def domain_of(asset, prefer="domain"):
    """从 FOFA 资产行取**合法域名**；取不到、裸 IP、协议名就返回空串。

    `prefer` 决定先看哪个字段：
    - `"domain"`（默认，osint 阶段用）：FOFA 的 `domain` 列若合法优先，否则回退 `host`；
    - `"host"`（subdomain 阶段用）：先看 `host` 里的主机名 —— 子域名枚举要的是
      `sub.a.test`，而 `domain` 列可能只给注册域/空串，优先它会把子域抹平。

    形态判据一律复用 `utils.to_ascii()` + `utils.is_domain()`（与全仓"什么算域名"
    同一份产地），所以 `https` / `1.2.3.4` / 带端口 / 带路径 一律不会入库。
    """
    cands = ([_host_part(asset.get("host")), asset.get("domain")]
             if prefer == "host" else
             [asset.get("domain"), _host_part(asset.get("host"))])
    for raw in cands:
        a = to_ascii(str(raw or "").strip().lower().strip("."))
        if a and is_domain(a):
            return a
    return ""