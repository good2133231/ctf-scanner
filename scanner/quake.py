"""360 Quake favicon 反查（P3-1 的姊妹能力）：用 mmh3 键去 Quake 找同源资产。

与 `scanner/fofa.py` / `scanner/shodan.py` 是**同构**的：三家都用 MurmurHash3 做 favicon
指纹（见 `scanner/mmh3.py`），区别只在查询语句、鉴权方式与响应结构。这里刻意**照抄
fofa.py 的结构**（`credentials` / `available` / `build_query` / `search` / `is_common_*`
阈值 / 无 key 显式报错），不去抽一个公共基类 —— 三家的字段与配额模型各不相同，
过早抽象只会把差异塞进一堆分支里。

依赖：`config/keys.yaml` 的 `quake: {key: ...}`（独立文件、不入库、GUI 不碰）。
**未填 key 时一律返回"未配置 quake.key（见 config/keys.yaml）"并且一个请求都不发。**

**默认关**（`quake.enabled=false`）：任何外部接口都不该在用户没点头时产生流量。

接口形态与 FOFA/Shodan 的两点差异（照抄结构时**不能**抹平的地方）：
- Quake 是 **POST + JSON 请求体**，且凭据放在 `X-QuakeToken` 请求头里（不是查询串）；
- 响应是 `{"code": 0, "data": [...], "meta": {...}}`，`code != 0` 即为业务失败
  （配额耗尽 / token 无效），`meta.pagination.total` 才是命中总数。
"""
import json

from .utils import http_request

API = "https://quake.360.cn/api/v3/search/quake_service"

# 单个 favicon 命中过多资产 → 公共图标，继续按它拓展只会灌入无关资产。
# 阈值见 quake.black_ico_threshold（默认 200）。
DEFAULT_BLACK_ICO_THRESHOLD = 200

DEFAULT_MAX_ASSETS = 100


def credentials(settings):
    """从 `settings["keys"]["quake"]` 取 key；缺失时返回空串。"""
    cfg = ((settings or {}).get("keys") or {}).get("quake") or {}
    if not isinstance(cfg, dict):
        return ""
    return str(cfg.get("key") or "").strip()


def available(settings):
    return bool(credentials(settings))


def black_ico_threshold(settings):
    cfg = (settings or {}).get("quake", {}) or {}
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
    """构造 favicon 查询语句（Quake 的字段名是 `favicon`，值是同一个 mmh3）。"""
    return f'favicon: "{int(icon_hash)}"'


def search(icon_hash, settings, logger=None, size=None):
    """按 favicon 哈希反查，返回 `(assets, total, error)`（结构同 `fofa.search`）。

    - assets: `[{host, domain, ip, port, title}, ...]`（`error` 非空时为空表）
    - total:  Quake 报告的命中总数（用于黑 ico 判定）
    - error: 空串表示成功；否则是可直接展示给用户的原因
    """
    key = credentials(settings)
    if not key:
        return [], 0, "未配置 quake.key（见 config/keys.yaml）"
    if not icon_hash:
        return [], 0, "favicon 哈希为空"
    cfg = (settings or {}).get("quake", {}) or {}
    try:
        size = int(size or cfg.get("max_assets") or DEFAULT_MAX_ASSETS)
    except (TypeError, ValueError):
        size = DEFAULT_MAX_ASSETS
    size = max(1, min(size, 1000))
    try:
        timeout = int((settings or {}).get("limits", {}).get("http_timeout", 10))
    except (TypeError, ValueError):
        timeout = 10

    body = json.dumps({"query": build_query(icon_hash), "start": 0, "size": size},
                      ensure_ascii=False)
    resp = http_request(API, method="POST", data=body, timeout=timeout, settings=settings,
                        headers={"X-QuakeToken": key, "Content-Type": "application/json"})
    if not resp:
        return [], 0, "请求 quake 失败（网络不可达或超时）"
    if resp.get("status") != 200:
        return [], 0, f"quake 返回 HTTP {resp.get('status')}"
    try:
        data = json.loads(resp.get("text") or "{}")
    except (ValueError, TypeError):
        return [], 0, "quake 响应不是合法 JSON"
    if not isinstance(data, dict):
        return [], 0, "quake 响应结构异常"
    if data.get("code") not in (0, "0", None):
        msg = str(data.get("message") or data.get("msg") or "未知错误")
        if logger:
            logger.warning(f"[quake] 查询被拒：{msg}")
        return [], 0, msg

    total = 0
    meta = data.get("meta") or {}
    if isinstance(meta, dict):
        page = meta.get("pagination") or {}
        if isinstance(page, dict):
            try:
                total = int(page.get("total") or 0)
            except (TypeError, ValueError):
                total = 0
    assets = []
    for row in (data.get("data") or []):
        if not isinstance(row, dict):
            continue
        svc = row.get("service") or {}
        if not isinstance(svc, dict):
            svc = {}
        http = svc.get("http") or {}
        if not isinstance(http, dict):
            http = {}
        ip = str(row.get("ip") or "")
        port = str(row.get("port") or "")
        domain = str(row.get("domain") or "") or str(http.get("host") or "")
        host = (f"http://{domain}" if domain else (f"http://{ip}:{port}" if ip else ""))
        assets.append({"host": host, "domain": domain, "ip": ip, "port": port,
                       "title": str(http.get("title") or "")})
    return assets, total, ""
