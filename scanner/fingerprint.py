"""内置指纹识别：httpx 不可用时，从响应头/正文提取组件标签填充 sites.tech。

定位（客观说明）：
- 只是"信号级"标签（如 nginx / php / tomcat），不解析精确版本；版本类判断仍由
  owasp 检查（a06-legacy-banner）与 POC 库承担；
- 规则表刻意保持精简、可扩展：新增一行即可支持新组件，无需改动调用方。

favicon 指纹（P1-1 / P3-1，参考项目 `_get_favicon_md5` 的启发）：
同一套源码部署的系统 favicon 完全一致，因此它是**零请求前置指纹** —— POC 里声明
`favicon_md5_list` 后，目标 favicon 不匹配就不必再发任何探测请求（见 `pocs/engine.py`）。

这里同时计算**两种**指纹，用途不同、不要混用：
- MD5（`favicon_md5`）：我们自己的 `favicon_md5_list` 前置判定用，谁也不用对上；
- mmh3（`favicon_hash`）：**对外部平台**提问用 —— FOFA `icon_hash`、Shodan `http.favicon.hash`
  都以 mmh3 为键（算法实现见 `scanner/mmh3.py`，纯标准库，无需 mmh3 包）。
先前的注释说"我们只做 MD5，不做 mmh3，因为环境里没有可用的哈希库"——
该理由已不成立（`mmh3.py` 自带已知向量自检），故补齐，否则 `fofa.py` 无从提问。
"""
import hashlib
import re

# 标签 -> [(part, 正则)]；part: headers | body；任一规则命中即打该标签
SIGNATURES = {
    "nginx": [("headers", r"(?im)^server:\s*nginx(?![-\w])")],
    "openresty": [("headers", r"(?i)openresty")],
    "apache": [("headers", r"(?im)^server:\s*apache(?![-\w])")],
    "iis": [("headers", r"(?im)^server:\s*microsoft-iis")],
    "caddy": [("headers", r"(?im)^server:\s*caddy")],
    "tomcat": [("headers", r"(?i)tomcat|apache-coyote")],
    "jetty": [("headers", r"(?i)jetty")],
    "gunicorn": [("headers", r"(?im)^server:\s*gunicorn")],
    "werkzeug": [("headers", r"(?im)^server:\s*werkzeug")],
    "uvicorn": [("headers", r"(?im)^server:\s*uvicorn")],
    "python": [("headers", r"(?i)python/[\d.]+")],
    "php": [("headers", r"(?im)^x-powered-by:\s*php"), ("body", r"(?i)\.php\b")],
    "aspnet": [("headers", r"(?i)asp\.net")],
    "express": [("headers", r"(?im)^x-powered-by:\s*express")],
    "spring": [("headers", r"(?i)spring")],
    "django": [("headers", r"(?i)csrftoken")],
    "wordpress": [("body", r"(?i)wp-content|wp-includes")],
}

# favicon 体积上限：有些站点会用 404 页面或超大文件冒充 favicon，直接跳过
MAX_FAVICON = 512 * 1024


def identify(resp):
    """从 http_request 的响应 dict 中提取组件标签，返回排序去重后的列表。"""
    if not resp:
        return []
    parts = {
        "headers": "\n".join(f"{k}: {v}" for k, v in (resp.get("headers") or {}).items()),
        "body": resp.get("text") or "",
    }
    tags = []
    for tag, rules in SIGNATURES.items():
        for part, pattern in rules:
            if re.search(pattern, parts.get(part, "")):
                tags.append(tag)
                break
    return sorted(set(tags))


def fetch_favicon(base_url, settings=None, timeout=None):
    """抓取 /favicon.ico 并返回**过滤后的原始字节**；拿不到或不像图标时返回 b""。

    只做一次 GET（非破坏性），失败静默返回空——favicon 只是"加速判定"的辅助信号，
    拿不到不影响主流程（POC 侧对空值不做前置排除，避免误杀）。
    两种指纹（md5 / mmh3）共用这一份实现，保证判定口径一致。
    """
    from .utils import http_request
    if timeout is None:
        timeout = int((settings or {}).get("limits", {}).get("http_timeout", 10))
    url = str(base_url).rstrip("/") + "/favicon.ico"
    resp = http_request(url, timeout=timeout, settings=settings, want_bytes=True)
    if not resp or resp.get("status") != 200:
        return b""
    content = resp.get("content") or b""
    if not content or len(content) > MAX_FAVICON:
        return b""
    # 图标是二进制；若服务端把 HTML 错误页当 favicon 返回，长度特征会明显不同，
    # 这里用一句廉价判断排掉最常见的"HTML 404 页"（避免不同站点共享同一个假指纹）
    if content[:6].lstrip().lower().startswith((b"<!doctype", b"<html")):
        return b""
    return content


def favicon_md5(base_url, settings=None, timeout=None):
    """favicon 内容 MD5；拿不到或不像图标时返回 ""（用于 favicon_md5_list 前置判定）。"""
    content = fetch_favicon(base_url, settings, timeout)
    return hashlib.md5(content).hexdigest() if content else ""


def favicon_hash(base_url, settings=None, timeout=None):
    """favicon 的 mmh3 哈希（有符号 32 位）；拿不到或不像图标时返回 0。

    仅用于向外部平台（FOFA / Shodan）提问，**不要**拿去和 `favicon_md5_list` 比对。
    """
    from .mmh3 import favicon_hash as _murmur
    content = fetch_favicon(base_url, settings, timeout)
    return _murmur(content) if content else 0