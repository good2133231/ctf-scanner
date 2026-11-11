"""OpenAPI / GraphQL 探测（续374）。

只做两件事，都是**只读**：
1. 常见描述文件（`openapi.json` / `swagger.json` / `v3/api-docs` …）→ 解析 `paths`，
   把路径拼成绝对 URL（并入 `js_urls`，后续 dirscan/vulnscan 自然吃到）；
2. GraphQL introspection（`POST {"query":"{__schema{types{name kind}}}"}`）→ 类型名线索。

产物只到**线索层**（`leads`，`kind="api"`）与 `js_urls`：不写 vulns、不自动发利用请求、
不按 `paths` 里的参数去 fuzz —— 这一层只回答「这里有没有 API 面、大概长什么样」。

边界：只探同站（`_is_self_host` 由调用方保护集判定，本模块直接拒第三方 URL）；
每个站点最多探 `api.max_probes` 条路径；单个站点最多收 `api.max_urls` 个接口 URL。
"""
import json
from urllib.parse import urljoin, urlparse

from .utils import http_request

# 常见描述文件路径（按命中率排序；命中第一个就够，不必全探）
OPENAPI_PATHS = (
    "/openapi.json",
    "/swagger.json",
    "/v3/api-docs",
    "/v2/api-docs",
    "/swagger/v1/swagger.json",
    "/api-docs",
    "/openapi.yaml",
)
GRAPHQL_PATHS = ("/graphql", "/api/graphql")
INTROSPECTION = '{"query":"{__schema{types{name kind}}}"}'

DEFAULT_MAX_SITES = 5
DEFAULT_MAX_PROBES = 6
DEFAULT_MAX_URLS = 200


def _cfg(settings):
    cfg = (settings or {}).get("api") or {}
    enabled = cfg.get("enabled", True) is not False
    try:
        max_sites = max(0, int(cfg.get("max_sites", DEFAULT_MAX_SITES) or 0))
    except (TypeError, ValueError):
        max_sites = DEFAULT_MAX_SITES
    try:
        max_probes = max(1, int(cfg.get("max_probes", DEFAULT_MAX_PROBES) or 0))
    except (TypeError, ValueError):
        max_probes = DEFAULT_MAX_PROBES
    try:
        max_urls = max(1, int(cfg.get("max_urls", DEFAULT_MAX_URLS) or 0))
    except (TypeError, ValueError):
        max_urls = DEFAULT_MAX_URLS
    return enabled, max_sites, max_probes, max_urls


def limits(settings):
    """公开：`(enabled, max_sites, max_probes, max_urls)`，供调用方决定遍历几个站点。"""
    return _cfg(settings)


def openapi_paths(data):
    """从 OpenAPI/Swagger JSON 里取 `paths` 的键（只认以 `/` 开头的字符串）。"""
    if not isinstance(data, dict):
        return []
    paths = data.get("paths")
    if not isinstance(paths, dict):
        return []
    return [p for p in paths if isinstance(p, str) and p.startswith("/")]


def graphql_types(data):
    """从 introspection 响应里取类型名（失败返回空表）。"""
    try:
        types = data["data"]["__schema"]["types"]
    except (KeyError, TypeError):
        return []
    return [str(t.get("name")) for t in (types or [])
            if isinstance(t, dict) and t.get("name")]


def probe(site_url, settings, logger=None):
    """探测一个站点的 API 面，返回 `{"urls": [...], "leads": [...], "stats": {...}}`。

    只读；`api.enabled=false` 时**零请求**。第三方 URL（不在调用方保护集）由调用方先挡，
    本函数只按 `max_probes` 控制量。
    """
    enabled, _max_sites, max_probes, max_urls = _cfg(settings)
    out = {"urls": [], "leads": [], "stats": {"probed": 0, "openapi": 0, "graphql": 0}}
    if not enabled:
        return out
    seed = urlparse(str(site_url or ""))
    if seed.scheme not in ("http", "https") or not seed.hostname:
        return out
    base = f"{seed.scheme}://{seed.netloc}"
    limits = (settings or {}).get("limits") or {}
    timeout = int(limits.get("http_timeout", 10))

    probes = 0
    # 1) OpenAPI / Swagger 描述文件
    for path in OPENAPI_PATHS:
        if probes >= max_probes:
            break
        probes += 1
        url = urljoin(base + "/", path.lstrip("/"))
        resp = http_request(url, timeout=timeout, settings=settings, auth=True)
        if not resp or int(resp.get("status") or 0) != 200:
            continue
        text = str(resp.get("text") or "")
        try:
            data = json.loads(text)
        except (ValueError, TypeError):
            continue                        # YAML 描述文件本轮不解析（不引第三方依赖）
        paths = openapi_paths(data)
        if not paths:
            continue
        out["stats"]["openapi"] += 1
        for p in paths[:max_urls]:
            out["urls"].append(urljoin(base + "/", p.lstrip("/")))
        out["leads"].append({
            "kind": "api", "code": "openapi", "title": "OpenAPI/Swagger 描述文件可读",
            "target": site_url, "matched": url, "level": "info",
            "detail": f"paths {len(paths)} 条（接口 URL 已并入 js_urls，供 dirscan/vulnscan 使用）",
            "source": "jsmine", "url": url})
        if logger:
            logger.info(f"[api] {site_url} 命中 OpenAPI（{len(paths)} 条 path）：{url}")
        break                               # 同一个站点有一个就够

    # 2) GraphQL introspection
    for path in GRAPHQL_PATHS:
        if probes >= max_probes:
            break
        probes += 1
        url = urljoin(base + "/", path.lstrip("/"))
        resp = http_request(url, method="POST", data=INTROSPECTION,
                            headers={"Content-Type": "application/json"},
                            timeout=timeout, settings=settings, auth=True)
        if not resp or int(resp.get("status") or 0) != 200:
            continue
        try:
            data = json.loads(str(resp.get("text") or ""))
        except (ValueError, TypeError):
            continue
        types = graphql_types(data)
        if not types:
            continue
        out["stats"]["graphql"] += 1
        out["leads"].append({
            "kind": "api", "code": "graphql-introspection",
            "title": "GraphQL introspection 开启",
            "target": site_url, "matched": url, "level": "info",
            "detail": f"types {len(types)} 个（只记类型名，不展开字段、不自动查询）",
            "source": "jsmine", "url": url})
        if logger:
            logger.info(f"[api] {site_url} GraphQL introspection 可读（{len(types)} 个类型）：{url}")
        break

    out["stats"]["probed"] = probes
    return out
