"""urlfinder 式被动 URL 发现（续334）。

思路照 urlfinder：**查第三方历史索引，不碰目标站**。
Wayback CDX 一次请求就能拿回 `*.root` 历史上被公开记录过的 URL，再从 URL 里抽主机名
—— 这就是「拓展域名」里最快的一路：零目标请求、零爬取、一条 HTTP。

与 jsmine 的分工：jsmine 是主动抓 JS + 逐个探测（慢但对新接口最准），本模块只补
「历史上出现过的主机」。结果统一按 `osint:wayback` 入「拓展域名」页。
"""
from __future__ import annotations

import json
from urllib.parse import urlsplit, urlencode

from .utils import http_request

CDX_ENDPOINT = "https://web.archive.org/cdx/search/cdx"


def _hosts_of(urls, root):
    """URL 列表 → {主机名: 首个 URL}；只留 root 本身与它的子域（不含第三方跳转）。"""
    root = str(root or "").strip().lower().strip(".")
    out = {}
    if not root:
        return out
    for u in urls or []:
        try:
            host = (urlsplit(str(u)).hostname or "").strip(".").lower()
        except (TypeError, ValueError):
            continue
        if not host:
            continue
        if host == root or host.endswith("." + root):
            out.setdefault(host, str(u))
    return out


def collect(root, settings=None, logger=None):
    """查 Wayback CDX，返回 `{host: 首个 URL}`；失败一律返回空字典（情报阶段不许带崩任务）。"""
    cfg = (settings or {}).get("passive_urls", {}) or {}
    limit = int(cfg.get("max_urls", 2000) or 0)
    timeout = int(cfg.get("timeout", 10) or 10)
    if not root or limit <= 0:
        return {}
    query = urlencode({
        "url": f"*.{root}/*",
        "output": "json",
        "fl": "original",
        "limit": str(limit),
        "filter": "statuscode:200",
    })
    resp = http_request(f"{CDX_ENDPOINT}?{query}", timeout=timeout,
                        settings=settings, auth=False)
    if not resp or resp.get("status") != 200:
        if logger:
            logger.warning(f"[passive_urls] Wayback 无有效响应（{root}，"
                           f"status={(resp or {}).get('status')}），跳过")
        return {}
    try:
        rows = json.loads(resp.get("text") or "[]")
    except (TypeError, ValueError):
        if logger:
            logger.warning(f"[passive_urls] Wayback 返回非 JSON（{root}），跳过")
        return {}
    urls = []
    for row in rows if isinstance(rows, list) else []:
        if isinstance(row, (list, tuple)) and row:
            u = str(row[0])
        elif isinstance(row, str):
            u = row
        else:
            continue
        if u.startswith(("http://", "https://")):
            urls.append(u)
    return _hosts_of(urls, root)
