"""JS 资产挖掘（P0-3）：从站点 HTML/JS 中抽取域名、接口 URL 与疑似凭据。

定位与取舍（客观说明）：
- 只做 **只读 GET**：抓取站点页面 HTML → 取出 `<script src>` → 并发抓 JS 正文后做正则提取，
  不执行任何 JS、不改写目标数据（遵守框架的非破坏性红线）。
- **域名资产**是主要产出：JS 里出现的自有/兄弟域名是资产面的自然延伸；第三方公共域
  （统计/CDN/字体/埋点/命名空间）噪声极大，用内置 `THIRD_PARTY` / `NAMESPACE_NOISE`
  常量表 + 配置 `jsmine.blacklist` 双层过滤。**目标自身域名及其子域永不误杀**。
- **凭据提取**（AK/SK 等）误报率高，因此做两级降噪：① 规则必须命中厂商特征前缀或
  明确的赋值语境（`key: "value"`）；② 前后文/占位符判断丢弃 `your_ / example / xxx /
  changeme / ${} / process.env` 之类模板信号；同一 value 跨文件只保留一次。命中结果
  一律标注"需人工确认有效性与作用域"。

所有 HTTP 一律走 `scanner.utils.http_request`（统一 UA/超时/verify_tls 行为，不直接
使用 requests/urllib）。对外接口：`mine(url, settings, logger=None)`。
"""
import re
from urllib.parse import urljoin, urlparse

from .utils import base_domain, http_request, is_domain, pool_run

# ---------- 第三方域名黑名单（噪声源）----------

# 统计/埋点、公共 CDN、字体、前端框架托管等：在目标 JS 里高频出现但对资产面无价值。
THIRD_PARTY = frozenset({
    # Google 系
    "google-analytics.com", "googletagmanager.com", "googlesyndication.com",
    "googleadservices.com", "doubleclick.net", "gstatic.com", "googleapis.com",
    "googleusercontent.com", "google.com", "youtube.com", "ytimg.com", "ggpht.com",
    # 百度 / 国内统计与推送
    "bdstatic.com", "bdimg.com", "baidu.com", "cnzz.com", "umeng.com",
    "umengcloud.com", "bugly.qq.com", "gtimg.com",
    # 公共 CDN / 前端资源托管
    "jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com", "cdnjs.com",
    "cloudflare.com", "cloudfront.net", "bootcdn.net", "staticfile.org",
    "bootstrapcdn.com", "maxcdn.com", "jquery.com", "jquery.org", "polyfill.io",
    # 厂商云 / 地图（作为第三方资源引用时）
    "aliyuncs.com", "myqcloud.com", "qcloud.com", "amap.com", "autonavi.com",
    # 社交 / 内容平台
    "zhihu.com", "zhimg.com", "github.io", "github.com", "githubusercontent.com",
    "facebook.com", "fbcdn.net", "twitter.com", "instagram.com", "linkedin.com",
    "weibo.com", "sina.com.cn", "qq.com", "bytedance.com", "toutiao.com",
    "pstatp.com", "bytecdn.cn", "tiktok.com", "douyin.com", "kuaishou.com",
    # 监控 / 客服 / 分析 SDK
    "sentry.io", "sentry-cdn.com", "clarity.ms", "hotjar.com", "segment.com",
    "intercom.io", "zendesk.com", "zdassets.com", "matomo.org",
    # 字体 / 头像 / 媒体 / 地图
    "fonts.googleapis.com", "fonts.gstatic.com", "gravatar.com",
    "vimeo.com", "wistia.com", "mapbox.com", "openstreetmap.org", "highcharts.com",
    # 边缘加速
    "akamaihd.net", "akamai.net", "fastly.net",
})

# 纯命名空间 / 规范文档域名：只出现在属性、命名空间声明里，不构成资产。
NAMESPACE_NOISE = frozenset({
    "w3.org", "schema.org", "w3schools.com", "purl.org", "xmlns.com",
    "ogp.me", "ietf.org", "whatwg.org", "openxmlformats.org",
})

_ALL_NOISE = THIRD_PARTY | NAMESPACE_NOISE

# 第三方域名单改为**数据驱动**：优先读 `config/dicts/js_thirdparty.txt`
# （由内置清单 + URLFinder「含过滤规则版」的 jsFiler 合并而来，267 条，可手工增删），
# 文件缺失时回退上面的内置集合。用户 2026-09-22 要求参考 URLFinder 的黑名单。
_THIRD_PARTY_FILE = "config/dicts/js_thirdparty.txt"
_noise_cache = None


def _noise_set():
    """返回第三方域名集合（首次调用读文件，之后缓存；文件缺失/损坏回退内置）。"""
    global _noise_cache
    if _noise_cache is not None:
        return _noise_cache
    items = set()
    try:
        from .config import resolve
        from .utils import read_lines
        for line in read_lines(resolve(_THIRD_PARTY_FILE)):
            line = line.strip().lower().lstrip("*.").strip(".")
            if line and not line.startswith("#"):
                items.add(line)
    except Exception:
        items = set()
    _noise_cache = items or set(_ALL_NOISE)
    return _noise_cache

# 静态资源文件名后缀（出现在引号里的 `jquery.min.js` 之类会被误当域名，需排除）
_FILE_EXT = frozenset({
    "js", "css", "json", "map", "min", "vue", "txt",
    "png", "jpg", "jpeg", "gif", "svg", "webp", "bmp", "ico", "cur",
    "html", "htm", "woff", "woff2", "ttf", "otf", "eot",
    # 服务端脚本/文档后缀：`index.php`、`login.aspx` 在 JS 里是**文件名**而不是域名，
    # 但形态上与"两段域名"一样（TLD 都是 3 个字母），必须在这里挡掉，
    # 否则它们会被当成资产域名写进「拓展域名」页（用户 2026-09-22 要求"判断是不是域名"）。
    "php", "php3", "php4", "php5", "phtml", "phps", "asp", "aspx", "ashx", "asmx",
    "jsp", "jspx", "do", "action", "cgi", "pl", "py", "rb", "sh", "bat", "exe",
    "xml", "yaml", "yml", "ini", "conf", "config", "log", "sql", "bak", "zip", "rar",
    "gz", "tar", "7z", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "csv",
})

# 多段公共后缀（取注册域用）已移到 `utils.MULTI_TLD` / `utils.base_domain`

# JS 全局对象/字面量：`process.env.token` / `window.location.href` 这类成员访问链
# 形状与域名一致，靠首段标签剔除（代价：真实存在 process.xxx.com 类子域时会被漏掉）。
_CODE_LABELS = frozenset({
    "process", "window", "document", "global", "globalthis", "this", "self",
    "module", "exports", "require", "console", "navigator", "location",
    "undefined", "null", "true", "false", "function", "return", "typeof",
})

# ---------- 提取正则 ----------

# <script src="...">（单引号 / 双引号 / 无引号三种写法）
_SCRIPT_SRC_RE = re.compile(
    r"""<script[^>]*\bsrc\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s>]+))""", re.I)

# 绝对 URL：https?://host/...
_ABS_URL_RE = re.compile(r"""https?://[^\s'"<>()\\`]+""", re.I)

# 协议相对：//host[:port][/path]
_PROTO_REL_RE = re.compile(
    r"""//((?:[A-Za-z0-9\-]+\.)+[A-Za-z]{2,24})((?::\d+)?(?:/[^\s'"<>()\\`]*)?)""")

# 引号内的主机名/接口路径：`api.example.com/v1`
_QUOTED_HOST_RE = re.compile(
    r"""["'`]((?:[A-Za-z0-9\-]+\.)+[A-Za-z]{2,24})((?::\d+)?(?:/[A-Za-z0-9\-._~%/?#&=+@!$*]*)?)["'`]""")

# ---------- 敏感凭据规则 ----------

# (规则名, 正则, 取值分组)：规则名会拼进 poc_id（js-secret-<规则名小写>）
SECRET_RULES = (
    # 云厂商 AccessKey：AKIA(AWS) / LTAI(阿里云) / AKID(腾讯云，用户点名要的 AKID[0-9A-Z]{16,32})
    ("aws-access-key", re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), 1),
    ("aliyun-access-key", re.compile(r"\b(LTAI[0-9A-Za-z]{12,20})\b"), 1),
    ("tencent-access-key", re.compile(r"\b(AKID[A-Za-z0-9]{16,32})\b"), 1),
    ("cloud-access-id", re.compile(r"\b((?:AKID|AKIA|LTAI|ASIA)[A-Za-z0-9]{16,32})\b"), 1),
    ("google-api-key", re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})"), 1),
    ("github-token", re.compile(r"\b(gh[pousr]_[0-9A-Za-z]{36})"), 1),
    ("slack-token", re.compile(r"\b(xox[baprs]-[0-9A-Za-z\-]{10,})"), 1),
    ("slack-webhook", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9_/\-]{20,}"), 0),
    ("telegram-bot-token", re.compile(r"\b(\d{8,10}:[A-Za-z0-9_\-]{35})\b"), 1),
    ("sendgrid-key", re.compile(r"\b(SG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,})\b"), 1),
    ("stripe-key", re.compile(r"\b((?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,})\b"), 1),
    ("jwt", re.compile(r"\b(eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})\b"), 1),
    # 私钥文件：PEM 头出现即命中（后面的正文同样敏感，但取头足够定位）
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), 0),
    # 带凭据的连接串：mysql://user:pass@host 这类一眼就是资产
    ("db-uri", re.compile(r"\b((?:mongodb|postgres(?:ql)?|mysql|redis|amqp)://[^\s'\"<>]{8,120})"), 1),
    # 通用凭据：必须出现"键 : "值""的赋值语境，且值不是变量引用/函数调用
    ("generic-credential", re.compile(
        r"""(?i)(api[_-]?key|secret|token|access[_-]?key|password|passwd|pwd)"""
        r"""\s*[:=]\s*["']([^"']{8,64})["']"""), 2),
)

# 占位/模板信号：命中即判为噪声（用户明确要求前后文动态过滤）
_PLACEHOLDER_RE = re.compile(
    r"(?i)(your[_-]|example|xxxx|changeme|change[_-]?me|placeholder|test|demo|"
    r"null|undefined|123456|<[^>]*>|\$\{|\{\{|env\.|process\.env|sample|dummy|foobar)")

# 纯变量引用：myVar（标识符）/ obj.field（成员访问）
_IDENT_RE = re.compile(r"""[A-Za-z_$][A-Za-z0-9_$]*""")
_MEMBER_RE = re.compile(r"""[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z0-9_$]+)+""")


# ---------- 主机名判定 ----------

def _valid_host(host):
    """是否为"像域名的"主机（先走统一的 `utils.is_domain()` 形态判断，再排 JS 特有的噪声）。"""
    if not is_domain(host):
        return False
    host = host.lower().strip(".")
    labels = host.split(".")
    if labels[0] in _CODE_LABELS:                       # process.env.token 类成员访问链
        return False
    if not re.fullmatch(r"[a-z]{2,24}", labels[-1]):  # TLD 必须纯字母（排除 IP/端口残留）
        return False
    if labels[-1] in _FILE_EXT:
        return False
    return all(re.fullmatch(r"[a-z0-9\-_]{1,63}", lb) for lb in labels)


def _is_noise(host, protect, blacklist):
    """黑名单判定：目标自身域名（protected）优先放行，其余按后缀匹配过滤。"""
    host = (host or "").lower().strip(".")
    if not host:
        return True
    for p in protect:
        if p and (host == p or host.endswith("." + p)):
            return False
    for suf in blacklist:
        suf = str(suf or "").lower().strip(".")
        if suf and (host == suf or host.endswith("." + suf)):
            return True
    # 走 `_noise_set()`（= 内置清单 ∪ `config/dicts/js_thirdparty.txt` 的 267 条）。
    # 此前这里直接遍历内置 `_ALL_NOISE`，导致那个"参考 URLFinder 整理"的名单文件**加载了却没用**。
    for suf in _noise_set():
        if host == suf or host.endswith("." + suf):
            return True
    return False


# ---------- 提取 ----------

def _extract(text, scheme, protect, blacklist):
    """从一段文本（HTML 或 JS）中提取域名与接口 URL，返回 (domains, urls) 两个 set。"""
    hosts, urls = set(), set()

    def _add(host, raw_url=None):
        host = (host or "").lower().strip(".")
        if not _valid_host(host) or _is_noise(host, protect, blacklist):
            return
        hosts.add(host)
        if raw_url:
            urls.add(raw_url)

    # 1) 绝对 URL
    for m in _ABS_URL_RE.finditer(text):
        u = m.group(0).rstrip(").,;'\"\\")
        if not u or len(u) > 500:
            continue
        _add(urlparse(u).hostname, u)

    # 2) 协议相对 //host[/path]（补上种子页面的 scheme；跳过属于 https:// 的那部分）
    for m in _PROTO_REL_RE.finditer(text):
        if m.start() >= 1 and text[m.start() - 1] == ":":
            continue
        host = m.group(1)
        rest = (m.group(2) or "").rstrip(".,;!?")
        _add(host, f"{scheme}://{host}{rest}" if "/" in rest else None)

    # 3) 引号内的主机名（api.example.com/v1）；无路径时要求至少 3 段，压掉文件名的误判
    for m in _QUOTED_HOST_RE.finditer(text):
        host, rest = m.group(1), m.group(2) or ""
        if not _valid_host(host):
            continue
        if "/" in rest:
            _add(host, f"{scheme}://{host}{rest}")
        elif host.count(".") >= 2:
            _add(host)
    return hosts, urls


def _masked(value):
    """掩码：前 4 后 4，中间 ***（值过短时退化为前 2 后 2）。"""
    if len(value) > 8:
        return value[:4] + "***" + value[-4:]
    return value[:2] + "***" + value[-2:]


def _context(text, start, end, limit=160):
    """命中处前后文（≤160 字），空白折叠。"""
    frag = re.sub(r"\s+", " ", text[max(0, start - 60):end + 60]).strip()
    return frag[:limit]


def _looks_placeholder(value):
    """占位/模板/低熵值判定（降噪核心）。"""
    v = value.strip()
    if len(v) < 6 or re.search(r"\s", v):
        return True
    if _PLACEHOLDER_RE.search(v):
        return True
    if re.fullmatch(r"\d+", v):          # 纯数字
        return True
    if len(set(v)) <= 2:                 # "aaaa" / "1111"
        return True
    return False


def _find_secrets(text, source):
    """匹配凭据规则并降噪，返回带内部去重键 `_raw` 的列表。"""
    out = []
    for name, rx, group in SECRET_RULES:
        for m in rx.finditer(text):
            raw = m.group(group).strip()
            if name == "private-key":
                # PEM 头自带空格（`-----BEGIN PRIVATE KEY-----`），而降噪会一律丢弃"含空白"的
                # 取值（那条规则是为了滤掉 `Bearer xxx` 这类自然语言噪声）。私钥头是强信号，
                # 这里把空白压成 `-` 让它能过降噪，值本身仍然一眼可辨。
                raw = re.sub(r"\s+", "-", raw)
            if not raw or _looks_placeholder(raw):
                continue
            if name == "generic-credential":
                # 值不能是函数调用 / 成员访问 / 无数字的纯标识符（变量引用）
                if "(" in raw or ")" in raw:
                    continue
                if _MEMBER_RE.fullmatch(raw):
                    continue
                if _IDENT_RE.fullmatch(raw) and not any(ch.isdigit() for ch in raw):
                    continue
                # 键名本身是占位词的也丢弃
                if _PLACEHOLDER_RE.search(m.group(1)):
                    continue
            out.append({
                "type": name,
                "value": _masked(raw),
                "context": _context(text, m.start(), m.end()),
                "source": source,
                "_raw": raw,
            })
    return out


# ---------- 对外接口 ----------

def _new_result():
    return {"domains": [], "urls": [], "secrets": [], "js_count": 0}


def mine(url, settings, logger=None):
    """挖掘单个站点的 JS 资产。

    返回 {"domains": [...], "urls": [...], "secrets": [...], "js_count": N}
    （domains/urls 去重排序；secrets 按 (type, value) 排序去重，js_count 为成功抓取的
    JS 文件数，供调用方汇总日志）。
    """
    settings = settings or {}
    cfg = settings.get("jsmine") or {}
    limits = settings.get("limits") or {}
    timeout = int(limits.get("http_timeout", 10))
    max_js = max(0, int(cfg.get("max_js", 40)))
    want_secrets = cfg.get("secrets", True) is not False
    blacklist = cfg.get("blacklist") or []

    out = _new_result()
    seed = urlparse(url or "")
    if seed.scheme not in ("http", "https") or not seed.hostname:
        return out
    scheme = seed.scheme

    # 目标自身域名保护集：seed 主机 + 其注册域，避免被第三方黑名单误杀
    protect = {seed.hostname.lower().strip("."), base_domain(seed.hostname)}

    resp = http_request(url, timeout=timeout, settings=settings)
    if not resp:
        if logger:
            logger.info(f"[jsmine] {url} 页面不可达，跳过")
        return out
    page_url = resp.get("url") or url
    html = resp.get("text") or ""

    # 1) 页面自身文本
    hosts, urls = _extract(html, urlparse(page_url).scheme or scheme, protect, blacklist)
    secret_hits = _find_secrets(html, page_url) if want_secrets else []

    # 2) <script src> → 绝对化 → 并发抓正文
    scripts, seen = [], set()
    for m in _SCRIPT_SRC_RE.finditer(html):
        src = next((g for g in m.groups() if g), "").strip()
        if not src:
            continue
        full = urljoin(page_url, src)
        p = urlparse(full)
        if p.scheme not in ("http", "https") or not p.hostname:
            continue                      # data: / javascript: / 相对路径兜底
        if full not in seen:
            seen.add(full)
            scripts.append(full)
    scripts = scripts[:max_js]
    js_count = 0
    if scripts:
        workers = max(1, min(int(limits.get("max_workers", 20)), len(scripts)))

        def _get(u):
            r = http_request(u, timeout=timeout, settings=settings)
            if not r:
                return None
            return {"url": r.get("url") or u, "text": r.get("text") or ""}

        bodies = pool_run(_get, scripts, workers=workers)
        js_count = len(bodies)
        for b in bodies:
            h2, u2 = _extract(b["text"], scheme, protect, blacklist)
            hosts |= h2
            urls |= u2
            if want_secrets:
                secret_hits.extend(_find_secrets(b["text"], b["url"]))

    # 3) 去重（凭据同一 value 跨文件只保留一次）
    secrets, seen_raw = [], set()
    for s in secret_hits:
        raw = s.pop("_raw", s["value"])
        if raw in seen_raw:
            continue
        seen_raw.add(raw)
        secrets.append(s)

    out["domains"] = sorted(hosts)
    out["urls"] = sorted(urls)
    out["secrets"] = sorted(secrets, key=lambda s: (s["type"], s["value"]))
    out["js_count"] = js_count
    if logger and (hosts or urls or secrets):
        logger.info(f"[jsmine] {url} → JS {js_count} 个 / 域名 {len(hosts)} 个 / "
                    f"URL {len(urls)} 条 / 凭据 {len(secrets)} 条")
    return out