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


def build_cert_query(domain):
    """构造证书查询语句：`cert="example.com"` —— 找与该域名共用同一张 TLS 证书的其它资产。"""
    return f'cert="{str(domain or "").strip().strip(".")}"'


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