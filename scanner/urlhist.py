"""历史 URL 来源（续248）：wayback CDX + AlienVault OTX `url_list`。

gau（lc/gau）的核心价值是"**零目标流量**拿到历史 URL"——它能挖出早已下线、但暴露面依然
有意义的路径与参数（字典猜不到、JS 里也早删了）。本模块用**原生实现**达到同一效果，
不引入 Go 二进制：换台机器 `pip install -r requirements.txt` 就能跑（迁移性优先）。

产出形态：把历史 URL 归一化成**路径**（`/admin/x.php`），去重后交给 dirscan 作为候选路径，
来源标签写明 `历史URL(wayback)` / `历史URL(OTX)` —— 页面与报告上看得出这条路径是怎么来的。

两路都不发往目标：只查第三方档案（web.archive.org / otx.alienvault.com），因此
`auth` 一律 False（绝不把目标的会话凭据送给第三方，见 utils.http_request 的说明）。
"""
import json
from urllib.parse import urlsplit

WAYBACK_URL = ("https://web.archive.org/cdx/search/cdx?url=*.{d}"
               "&output=json&collapse=urlkey&limit={n}&filter=statuscode:200")
OTX_URL = "https://otx.alienvault.com/api/v1/indicators/domain/{d}/url_list"

LABEL_WAYBACK = "历史URL(wayback)"
LABEL_OTX = "历史URL(OTX)"

# 太长的路径多半是带随机串/长签名的资源，对目录发现无意义（还会吃掉候选额度）
MAX_PATH_LEN = 160


def to_path(url, with_query=False):
    """历史 URL → 归一化路径；不是本站能用的路径（空/纯静态资源也算可用，交给调用方过滤）
    时返回 \"\"。

    - 去掉 scheme 与 host，只留路径（默认不带 query —— 同一路径的不同参数会被折叠成一条，
      否则历史 URL 里一个 `?id=` 变体就能把额度吃光；`with_query=True` 才保留）。
    - 补前导斜杠；结尾斜杠保留（`/admin/` 与 `/admin` 是两种不同的存在形态）。
    """
    s = str(url or "").strip()
    query = ""
    if s.startswith(("http://", "https://")):
        try:
            parts = urlsplit(s)
        except ValueError:
            return ""
        path = parts.path or "/"
        query = parts.query or ""
    elif s.startswith("/"):                  # 已经是路径（OTX 有时给这种形态）
        path, _, query = s.partition("?")
    else:
        # 无 scheme 且不以 / 开头：只有 `host/path` 形态才取后半段（`a.test/x` → `/x`）；
        # 光秃秃一个词（没有路径）不是候选路径，直接丢 —— 别把 `admin` 当路径再补斜杠。
        if "/" not in s:
            return ""
        head, _, tail = s.partition("/")
        path = "/" + tail
        if "?" in path:
            path, _, query = path.partition("?")
    if with_query and query:
        path = f"{path}?{query}"
    if not path.startswith("/"):
        path = "/" + path
    if len(path) > MAX_PATH_LEN:
        return ""
    return path


def _wayback_rows(text):
    """CDX JSON：第一行是表头（original/timestamp/…），取 `original` 那一列。"""
    try:
        data = json.loads(text or "[]")
    except (TypeError, ValueError):
        return []
    if not isinstance(data, list) or len(data) < 2:
        return []
    head = [str(x).lower() for x in (data[0] or [])]
    if "original" not in head:
        return []
    idx = head.index("original")
    out = []
    for row in data[1:]:
        if isinstance(row, list) and idx < len(row):
            out.append(str(row[idx]))
    return out


def _otx_rows(text):
    """OTX：`{"url_list": [{"url": "..."}]}`，也有 `has_next` 分页（这里只取第一页，够用）。"""
    try:
        data = json.loads(text or "{}")
    except (TypeError, ValueError):
        return []
    if not isinstance(data, dict):
        return []
    out = []
    for it in (data.get("url_list") or []):
        u = (it or {}).get("url") if isinstance(it, dict) else it
        if u:
            out.append(str(u))
    return out


def collect(domain, settings=None, logger=None, cap=1000, with_query=False,
            timeout=10, request=None):
    """查一个注册域的历史 URL，返回 `[(路径, 来源标签), ...]`（去重保序，≤ cap）。

    任一路上游失败（超时 / 429 / 结构变了）⇒ 只记一行并跳过那一路，**绝不炸**：
    它只是候选词的一路补充，缺了也不影响字典扫描。
    """
    from .utils import http_request          # 就地导入：模块可被独立测试注入

    req = request or http_request
    d = str(domain or "").strip().lower().strip(".")
    if not d or cap <= 0:
        return []
    seen, out = set(), []

    def _add(urls, label):
        n = 0
        for u in urls or []:
            p = to_path(u, with_query=with_query)
            if not p or p == "/" or p in seen:
                continue
            seen.add(p)
            out.append((p, label))
            n += 1
            if len(out) >= cap:
                break
        return n

    try:
        r = req(WAYBACK_URL.format(d=d, n=max(1, min(cap * 3, 20000))),
                timeout=timeout, settings=settings)
        if r and int(r.get("status") or 0) == 200:
            n = _add(_wayback_rows(r.get("text") or ""), LABEL_WAYBACK)
            if logger and n:
                logger.info(f"[urlhist] wayback {d} → 历史路径 {n} 条")
        elif logger:
            logger.info(f"[urlhist] wayback {d} 未取到（HTTP {r.get('status') if r else '无响应'}）"
                        f"，跳过这一路")
    except Exception as e:                    # noqa: BLE001 - 第三方源，失败只记
        if logger:
            logger.info(f"[urlhist] wayback {d} 异常：{type(e).__name__}（跳过）")

    if len(out) >= cap:
        return out

    try:
        r = req(OTX_URL.format(d=d), timeout=timeout, settings=settings)
        if r and int(r.get("status") or 0) == 200:
            n = _add(_otx_rows(r.get("text") or ""), LABEL_OTX)
            if logger and n:
                logger.info(f"[urlhist] OTX {d} → 历史路径 {n} 条")
        elif logger:
            logger.info(f"[urlhist] OTX {d} 未取到（HTTP {r.get('status') if r else '无响应'}）"
                        f"，跳过这一路")
    except Exception as e:                    # noqa: BLE001
        if logger:
            logger.info(f"[urlhist] OTX {d} 异常：{type(e).__name__}（跳过）")
    return out
