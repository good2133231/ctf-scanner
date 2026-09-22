"""FOFA 反查（P3-1 / todo #6）：用 favicon 哈希反查同源资产。

用户原话："ico 索引目标功能，提取目标的 ico，去 fofa 搜索，并且结果太多的 ico 判定为黑 ico，
就不去拓展了" —— 本模块实现后半段（反查 + 黑 ico 判定），前半段（favicon 采集与哈希）
在 `scanner/fingerprint.py` 与 `scanner/mmh3.py`。

依赖：`config/keys.yaml` 的 `fofa: {email, key}`（独立文件、不入库、GUI 不碰）。
**未填 key 时一律返回"不可用"并只记一行日志**，不影响流水线其它部分。

技术要点：
- FOFA 的 `icon_hash` 用的是 **mmh3**（不是 MD5），取值方式见 `scanner/mmh3.py::favicon_hash`；
- `qbase64` 必须 URL 编码（base64 里的 `+` `/` `=` 直接拼进 query 会被破坏）；
- 返回体形如 `{"error": false, "size": N, "results": [[host, domain, ip, port, title], ...]}`，
  `error: true` 时带 `errmsg`（常见于配额耗尽 / key 无效），这些都**显式报错**而不是静默无结果。
"""
import base64
import json
import urllib.parse

from .utils import http_request

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


def search_query(query, settings, logger=None, size=None):
    """按 FOFA 查询语句反查，返回 `(assets, total, error)`。

    - assets: `[{host, domain, ip, port, title}, ...]`（`error` 非空时为空表）
    - total:  FOFA 报告的命中总数（用于黑 ico / 通用证书判定）
    - error: 空串表示成功；否则是可直接展示给用户的原因
    """
    email, key = credentials(settings)
    if not (email and key):
        return [], 0, "未配置 fofa.email / fofa.key（见 config/keys.yaml）"
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
    resp = http_request(url, timeout=timeout, settings=settings)
    if not resp:
        return [], 0, "请求 fofa 失败（网络不可达或超时）"
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