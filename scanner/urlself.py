"""站点自曝入口（续250）：robots.txt + sitemap.xml。

主理人点单：把 katana 的增强项里**真正有价值的两块**补上 —— JS 那部分 jsmine 早就做了，
剩下 robots/sitemap：它们是站点**自己写出来**的入口清单，零猜测、误报率低：

- `robots.txt` 的 `Disallow:` 是站长亲手标注"别让搜索引擎收录"的路径 —— `/admin`、
  `/internal`、备份路径全在里面，恰恰是最敏感的；
- `sitemap.xml`（含 robots.txt 里 `Sitemap:` 指名的那份）列出全站公开入口，能挖到不带
  任何链接的孤立深层页与带参数 URL（注入面）；`<sitemapindex>` 会**再取一层**子表。

产出与历史 URL（`urlhist`）同一契约：`[(路径, 来源标签), ...]`，标签 `robots.txt` /
`sitemap.xml`，交给 dirscan 当候选路径（续222 的"第四项=来源标签"一路延用）。

每站 2~3 个 GET（robots + sitemap，索引表多一份），全部发往**目标自己的站**（不是第三方），
失败/404/超时只记一行跳过 —— 它只是候选词的一路补充。
"""
import re
from urllib.parse import urlsplit

from .urlhist import MAX_PATH_LEN, to_path

LABEL_ROBOTS = "robots.txt"
LABEL_SITEMAP = "sitemap.xml"

_DISALLOW_RE = re.compile(r"(?im)^\s*disallow\s*:\s*(\S+)")
_SITEMAP_IN_ROBOTS_RE = re.compile(r"(?im)^\s*sitemap\s*:\s*(\S+)")
_LOC_RE = re.compile(r"(?is)<loc>\s*(.*?)\s*</loc>")
_INDEX_RE = re.compile(r"(?is)<sitemapindex[\s>]")

# 索引表最多再取几份（防站点把 500 份子表列出来把请求量放大）
MAX_CHILD_SITEMAPS = 3


def _origin(url):
    """站点 URL → `scheme://host:port`（robots/sitemap 按**源**寻址，不是注册域）。"""
    s = str(url or "").strip()
    if not s.startswith(("http://", "https://")):
        s = "http://" + s.lstrip("/")
    try:
        p = urlsplit(s)
    except ValueError:
        return ""
    if not p.netloc:
        return ""
    return f"{p.scheme}://{p.netloc}"


def robots_paths(text):
    """robots.txt 文本 → Disallow 路径列表（去重保序；`/` 与空扔弃）。"""
    out, seen = [], set()
    for raw in _DISALLOW_RE.findall(text or ""):
        p = to_path(raw)
        if not p or p == "/" or p in seen:
            continue
        seen.add(p)
        out.append(p)
    return out


def robots_sitemaps(text):
    """robots.txt 里 `Sitemap:` 指名的那份（可能是多份，保序去重）。"""
    out, seen = [], set()
    for raw in _SITEMAP_IN_ROBOTS_RE.findall(text or ""):
        u = str(raw or "").strip()
        if u.startswith(("http://", "https://")) and u not in seen:
            seen.add(u)
            out.append(u)
    return out


def sitemap_locs(text):
    """sitemap 文本 → `<loc>` 清单（页面 URL；索引表的 loc 是子表地址，由调用方分辨）。"""
    return [str(m).strip() for m in _LOC_RE.findall(text or "") if str(m).strip()]


def is_index(text):
    return bool(_INDEX_RE.search(text or ""))


def collect(site_url, settings=None, logger=None, cap=500, timeout=10, request=None):
    """一个站点的自曝入口：robots.txt + sitemap.xml（+ 索引表一层）。

    返回 `[(路径, 标签), ...]`（去重保序，≤ cap）。任一路失败只记一行，不影响别的路。
    """
    from .utils import http_request          # 就地导入：模块可被独立测试注入

    req = request or http_request
    origin = _origin(site_url)
    if not origin or cap <= 0:
        return []
    seen, out = set(), []

    def _add(urls, label):
        n = 0
        for u in urls or []:
            p = to_path(u)
            if not p or p == "/" or len(p) > MAX_PATH_LEN or p in seen:
                continue
            seen.add(p)
            out.append((p, label))
            n += 1
            if len(out) >= cap:
                break
        return n

    # ① robots.txt：Disallow（敏感路径金矿）+ Sitemap: 指名
    robots_text = ""
    try:
        r = req(f"{origin}/robots.txt", timeout=timeout, settings=settings)
        if r and int(r.get("status") or 0) == 200:
            robots_text = r.get("text") or ""
            n = _add(robots_paths(robots_text), LABEL_ROBOTS)
            if logger and n:
                logger.info(f"[urlself] robots.txt {origin} → 入口 {n} 条")
        elif logger and r and int(r.get("status") or 0) != 404:
            logger.info(f"[urlself] robots.txt {origin} HTTP {r.get('status')}，跳过这一路")
    except Exception as e:                    # noqa: BLE001
        if logger:
            logger.info(f"[urlself] robots.txt {origin} 异常：{type(e).__name__}（跳过）")

    # ② sitemap.xml：robots 指名的那份优先，否则站根那一份；索引表再取一层
    if len(out) < cap:
        sm_urls = robots_sitemaps(robots_text) or [f"{origin}/sitemap.xml"]
        for sm in sm_urls[:1 + MAX_CHILD_SITEMAPS]:
            if len(out) >= cap:
                break
            try:
                r = req(sm, timeout=timeout, settings=settings)
                if not r or int(r.get("status") or 0) != 200:
                    if logger and r and int(r.get("status") or 0) != 404:
                        logger.info(f"[urlself] sitemap {sm} HTTP {r.get('status')}，跳过")
                    continue
                text = r.get("text") or ""
                locs = sitemap_locs(text)
                if is_index(text):
                    kids = [u for u in locs if u.startswith(("http://", "https://"))]
                    if logger and kids:
                        logger.info(f"[urlself] sitemap 索引 {sm} → 子表 {len(kids)} 份，"
                                    f"最多再取 {MAX_CHILD_SITEMAPS} 份")
                    for kid in kids[:MAX_CHILD_SITEMAPS]:
                        if len(out) >= cap:
                            break
                        try:
                            r2 = req(kid, timeout=timeout, settings=settings)
                            if r2 and int(r2.get("status") or 0) == 200:
                                n = _add(sitemap_locs(r2.get("text") or ""), LABEL_SITEMAP)
                                if logger and n:
                                    logger.info(f"[urlself] sitemap 子表 {kid} → 入口 {n} 条")
                        except Exception as e:    # noqa: BLE001
                            if logger:
                                logger.info(f"[urlself] sitemap 子表 {kid} 异常："
                                            f"{type(e).__name__}（跳过）")
                    continue
                n = _add(locs, LABEL_SITEMAP)
                if logger and n:
                    logger.info(f"[urlself] sitemap {sm} → 入口 {n} 条")
            except Exception as e:                # noqa: BLE001
                if logger:
                    logger.info(f"[urlself] sitemap {sm} 异常：{type(e).__name__}（跳过）")
    return out
