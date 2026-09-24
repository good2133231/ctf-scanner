"""Shodan favicon 反查（P3-1 的姊妹能力）：用同一个 mmh3 键去 Shodan 找同源资产。

与 `scanner/fofa.py` 是**同构**的：三家的 favicon 指纹都是 MurmurHash3（见 `scanner/mmh3.py`），
区别只在查询语句、鉴权方式与响应结构。这里刻意**照抄 fofa.py 的结构**（`credentials` /
`available` / `build_query` / `search` / `is_common_*` 阈值 / 无 key 显式报错），不去抽一个
公共基类 —— 三个厂商的字段与配额模型各不相同，过早抽象只会把差异塞进一堆分支里。

依赖：`config/keys.yaml` 的 `shodan: {key: ...}`（独立文件、不入库、GUI 不碰）。
**未填 key 时一律返回"未配置 shodan.key（见 config/keys.yaml）"并且一个请求都不发。**

**默认关**（`shodan.enabled=false`）：任何外部接口都不该在用户没点头时产生流量。
"""
import json
import urllib.parse

from .utils import http_request

API = "https://api.shodan.io/shodan/host/search"

# 单个 favicon 命中过多资产 → 这个图标是"公共图标"（默认页/通用框架/空图标），
# 继续按它拓展只会灌入大量无关资产。阈值见 shodan.black_ico_threshold（默认 200）。
DEFAULT_BLACK_ICO_THRESHOLD = 200

# Shodan 免费配额对单次查询的条数限制很紧，默认取小一点（可在配置里调大）。
DEFAULT_MAX_ASSETS = 100


def credentials(settings):
    """从 `settings["keys"]["shodan"]` 取 key；缺失时返回空串。"""
    cfg = ((settings or {}).get("keys") or {}).get("shodan") or {}
    if not isinstance(cfg, dict):
        return ""
    return str(cfg.get("key") or "").strip()


def available(settings):
    return bool(credentials(settings))


def black_ico_threshold(settings):
    cfg = (settings or {}).get("shodan", {}) or {}
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
    """构造 favicon 查询语句（Shodan 的字段名是 `http.favicon.hash`，值是同一个 mmh3）。"""
    return f"http.favicon.hash:{int(icon_hash)}"


def search(icon_hash, settings, logger=None, size=None):
    """按 favicon 哈希反查，返回 `(assets, total, error)`（结构同 `fofa.search`）。

    - assets: `[{host, domain, ip, port, title}, ...]`（`error` 非空时为空表）
    - total:  Shodan 报告的命中总数（用于黑 ico 判定）
    - error: 空串表示成功；否则是可直接展示给用户的原因
    """
    key = credentials(settings)
    if not key:
        return [], 0, "未配置 shodan.key（见 config/keys.yaml）"
    if not icon_hash:
        return [], 0, "favicon 哈希为空"
    cfg = (settings or {}).get("shodan", {}) or {}
    try:
        size = int(size or cfg.get("max_assets") or DEFAULT_MAX_ASSETS)
    except (TypeError, ValueError):
        size = DEFAULT_MAX_ASSETS
    size = max(1, min(size, 1000))
    try:
        timeout = int((settings or {}).get("limits", {}).get("http_timeout", 10))
    except (TypeError, ValueError):
        timeout = 10

    url = (f"{API}?key={urllib.parse.quote_plus(key)}"
           f"&query={urllib.parse.quote_plus(build_query(icon_hash))}"
           f"&limit={size}")
    resp = http_request(url, timeout=timeout, settings=settings)
    if not resp:
        return [], 0, "请求 shodan 失败（网络不可达或超时）"
    if resp.get("status") != 200:
        return [], 0, f"shodan 返回 HTTP {resp.get('status')}"
    try:
        data = json.loads(resp.get("text") or "{}")
    except (ValueError, TypeError):
        return [], 0, "shodan 响应不是合法 JSON"
    if not isinstance(data, dict):
        return [], 0, "shodan 响应结构异常"
    if data.get("error"):
        msg = str(data.get("error") or "未知错误")
        if logger:
            logger.warning(f"[shodan] 查询被拒：{msg}")
        return [], 0, msg

    assets = []
    for m in (data.get("matches") or []):
        if not isinstance(m, dict):
            continue
        http = m.get("http") or {}
        if not isinstance(http, dict):
            http = {}
        hostnames = [str(x) for x in (m.get("hostnames") or []) if x]
        domains = [str(x) for x in (m.get("domains") or []) if x]
        ip = str(m.get("ip_str") or "")
        port = str(m.get("port") or "")
        # `host` 给"能直接看出是什么"的形态（有主机名就用主机名），
        # `domain` 给"能进资产库"的形态；两者都交给 `osint._domain_of()` 收口，
        # 裸 IP 一律不会变成域名资产。
        host = (f"http://{hostnames[0]}" if hostnames else
                (f"http://{ip}:{port}" if ip else ""))
        assets.append({"host": host,
                       "domain": domains[0] if domains else
                                 (hostnames[0] if hostnames else ""),
                       "ip": ip, "port": port,
                       "title": str(http.get("title") or "")})
    return assets, int(data.get("total") or 0), ""
