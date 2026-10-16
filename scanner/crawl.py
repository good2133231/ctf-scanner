"""站点爬虫：把**站点自己暴露出来的链接**收集成一张清单（续198，主理人点单）。

和既有几件事的分工（别混，混了就是两套口径）：
- `dirs`（dirscan）：**字典猜出来的路径** —— 我们要证明它存在不存在；
- `urls`（本模块）：**页面里本来就写着的链接** —— 它一定存在，是站点自己给出的入口面；
- `jsmine`：挖 **JS 文件里**的域名与接口（那是另一批请求、另一张表）。

三条红线（§1 非破坏性，写死在代码里而不是靠配置）：
1. **只发 GET**。`fetch` 由调用方注入，本模块内部没有任何 POST/PUT/DELETE 的出口。
2. **`<form method="post">` 只记录、绝不提交**：把 method 写进表是让人知道"这里有个表单入口"，
   拿它去发请求就越了"不写操作"那条界（爆破/表单提交一律不做）。
3. **不跟外链**（默认）：`same_site=true` 时只收同 host 的链接，站外链接（社交按钮、CDN 直链、
   别人的站点）默认丢弃并计数 —— 它们既不是目标资产，也会把请求量放大到不可控。

规模由配置夹住（默认都很小）：每站最多 `max_links` 条、最多再抓 `max_pages` 个页面、
最多再跟 `max_depth` 层。目的是"看清这个站有多少入口"，不是"把整站镜像下来"。

关于 robots.txt：**不读**。理由是授权测试场景里 robots 常写着 `Disallow: /` 而那正是要看的地方，
且本模块的请求量（默认每站 ≤ 8 页）远小于目录扫描那一档；真要尊重 robots 的用户不该开这个阶段。
这一条写在这里是为了让接手的人知道这是**刻意的**，不是忘了。
"""
import re

from urllib.parse import urljoin, urlsplit

# `<a href=…>`：只认 `href` 这个属性（`<a name=…>` 之类不关心）；值可以是引号包着或裸的
_A_RE = re.compile(r"<a\b[^>]*?\shref\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s>]+)", re.I | re.S)
# `<form …>`：整块属性串拿出来再单独抽 action / method（两个属性的顺序没有保证）
_F_RE = re.compile(r"<form\b([^>]*)>", re.I | re.S)
_ATTR_RE = re.compile(r"\b(action|method)\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s>]+)", re.I | re.S)

# 明显不是网页的协议：跟着它们既拿不到 HTML，也会把请求发到莫名其妙的地方
_SKIP_SCHEMES = ("mailto:", "javascript:", "tel:", "data:", "ftp:", "file:",
                 "about:", "sms:", "viber:", "skype:", "chrome-extension:")

# 静态资源扩展名：不值得为它再发一个请求（也几乎不可能从中提取出有用的入口）
_ASSET_EXT = (".css", ".js", ".mjs", ".map", ".png", ".jpg", ".jpeg", ".gif", ".webp",
              ".svg", ".ico", ".bmp", ".woff", ".woff2", ".ttf", ".eot", ".otf",
              ".pdf", ".zip", ".rar", ".7z", ".gz", ".tar", ".mp4", ".mp3", ".avi",
              ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".apk", ".exe",
              ".txt", ".json", ".xml", ".csv")


def _unquote(value):
    """剥掉属性值的引号（`"x"` / `'x'` / 裸 `x` 三种写法都要认）。"""
    v = str(value or "").strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        return v[1:-1].strip()
    return v


def normalize_url(href, base):
    """相对地址 → 绝对 URL，并顺手做掉三件"一定会出问题"的事。

    - 去 `#fragment`：同一个页面的不同锚点在资产表里是**同一条**（`?a=1#top` 与 `?a=1#mid`
      是两个 URL、一个入口），留着就是拿重复数据充数；
    - 挡掉 `javascript:` / `mailto:` / `data:` 这类"不是网页"的协议；
    - 只留 http/https。

    返回 `""` 表示"这条不该收"（调用方直接跳过，不必再判一次原因）。
    """
    h = _unquote(href)
    if not h or h.startswith("#"):
        return ""
    if h.lower().startswith(_SKIP_SCHEMES):
        return ""
    try:
        u = urljoin(str(base or ""), h)
    except ValueError:
        return ""
    u = u.split("#", 1)[0].strip()
    if not u.lower().startswith(("http://", "https://")):
        return ""
    return u


def extract_links(html, base):
    """从一段 HTML 里抽出 `(url, kind, method)` 列表 —— **未去重、未过滤同站**。

    `kind`: `link`（`<a href>`）/ `form`（`<form action>`）。
    `method`: `link` 恒为 `get`；`form` 取页面写的值（**只记录，不提交**，见模块 docstring 红线 2）。
    `<form>` 没写 `action` 时按 HTML 语义落到**当前页**。

    为什么用正则而不是解析库：本仓依赖只有 flask/requests/PyYAML（requirements.txt 里没有
    lxml/bs4），为一个"抽 href"的需求引一个新依赖不划算；而这几条正则对畸形 HTML（缺引号、
    换行、属性乱序）的容忍度恰好比严格解析更合适 —— 真实站点的 HTML 从来不是良构的。
    """
    out = []
    text = str(html or "")
    for m in _A_RE.finditer(text):
        u = normalize_url(m.group(1), base)
        if u:
            out.append((u, "link", "get"))
    for m in _F_RE.finditer(text):
        attrs = {str(k).lower(): _unquote(v) for k, v in _ATTR_RE.findall(m.group(1))}
        action = normalize_url(attrs.get("action", ""), base)
        # 没写 action = 提交回当前页（HTML 语义），这时记当前页才对得上"入口在哪"
        u = action or (str(base or "").split("#", 1)[0])
        if u:
            out.append((u, "form", (attrs.get("method") or "get").strip().lower()[:8] or "get"))
    return out


def _host_of(url):
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def same_site(url, base, include_subdomains=False):
    """`url` 与来源站点 `base` 是不是同一个站（同 host；可选放行子域）。

    **为什么默认是同 host**：一屏社交按钮（twitter/facebook/weibo）与 CDN 直链能让"外链数"
    是"真入口数"的十几倍，而它们既不是目标资产，也会让后面的漏洞下钻去打别人的站点。
    """
    ha, hb = _host_of(url), _host_of(base)
    if not ha or not hb:
        return False
    if ha == hb:
        return True
    if include_subdomains:
        return ha.endswith("." + hb) or hb.endswith("." + ha)
    return False


def looks_like_page(url, resp):
    """这个响应值不值得**再抓一层**（深度 > 0 时才用得到）。

    三道判据（任一为否即不跟）：① Content-Type 明确非 HTML（有的话最可靠）；
    ② 路径以静态资源扩展名结尾；③ 正文开头不像 HTML。
    """
    # ① 先按扩展名否：`.css` / `.zip` 这类就算服务器回了 `text/html`（有的站真这么配）
    #    也不值得再抓一次 —— 扩展名在这里是比响应头更强的信号，放后面就被它盖掉了。
    path = (urlsplit(str(url or "")).path or "").lower()
    if path.endswith(_ASSET_EXT):
        return False
    ctype = ""
    for k, v in ((resp or {}).get("headers") or {}).items():
        if str(k).lower() == "content-type":
            ctype = str(v or "").lower()
    if ctype:
        if "text/html" in ctype or "application/xhtml" in ctype:
            return True
        if not ctype.startswith("text/"):
            return False
    return bool(re.search(r"<\s*(html|a\s|form\b|body)", str((resp or {}).get("text") or "")[:4000],
                          re.I))


def crawl_site(base, fetch, cfg=None, seen=None):
    """爬一个站点，返回 `(rows, stats)`。

    `fetch(url)` 由调用方注入（阶段里是带登录态与超时的 `http_request`），返回响应 dict 或 None ——
    注入而不是内部发请求，是为了让**回归能零网络**验到全部逻辑（本仓一贯口径）。

    `rows` 每项 `{url, site_url, kind, method, depth}`；`stats` 是给日志用的计数
    （抓了几页 / 收了几条 / 各跳过了多少，跳过原因分得开才说得清"为什么这么少"）。
    """
    cfg = cfg or {}
    rows, stats = [], {"pages": 0, "links": 0, "dup": 0, "offsite": 0, "bad": 0, "full": 0}
    seen = seen if seen is not None else set()
    max_links = max(1, int(cfg.get("max_links", 60) or 60))
    max_pages = max(1, int(cfg.get("max_pages", 8) or 8))
    max_depth = max(0, int(cfg.get("max_depth", 1) or 0))
    include_sub = bool(cfg.get("include_subdomains", False))
    same = bool(cfg.get("same_site", True))

    frontier = [(str(base), 0)]
    base_root = str(base).split("#", 1)[0]
    while frontier and stats["pages"] < max_pages:
        url, depth = frontier.pop(0)
        resp = fetch(url)
        stats["pages"] += 1
        if not resp or not resp.get("status"):
            continue
        for u, kind, method in extract_links(resp.get("text") or "", url):
            if not u:
                stats["bad"] += 1
                continue
            if same and not same_site(u, base_root, include_sub):
                stats["offsite"] += 1
                continue
            if u in seen:
                stats["dup"] += 1
                continue
            if len(rows) >= max_links:
                stats["full"] += 1
                continue
            seen.add(u)
            rows.append({"url": u, "site_url": base_root, "kind": kind,
                         "method": method, "depth": depth})
            stats["links"] += 1
            # 再跟一层：只跟 `<a>`（form 的 action 提交我们不发），且先按扩展名粗筛掉静态资源
            if depth < max_depth and kind == "link" \
                    and not (urlsplit(u).path or "").lower().endswith(_ASSET_EXT):
                frontier.append((u, depth + 1))
    return rows, stats
