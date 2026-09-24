"""OWASP Top 10（2021）轻量启发式检查。

定位（客观说明）：
- 这里是"低噪、非破坏性"的通用初筛：全部为 GET 请求 + 被动读取，payload 无破坏性；
- 主要覆盖可用黑盒信号体现的 A01/A02/A03/A05/A06/A08；
- A04（不安全设计）、A07（认证失败）、A09（日志不足）、A10（SSRF）依赖业务上下文，
  黑盒自动化误报/漏报率极高，本模块仅做极少信号量极弱的探测或直接不做（详见 docs/owasp-mapping.md）；
- 所有输出都是"初筛信号"，必须人工确认，不能等同于漏洞结论。
"""
import inspect
import random
import re
import threading
import urllib.parse

from .. import config, evasion
from .. import ssrf as ssrf_mod
from ..utils import http_request, read_lines

CHECKS = []  # [{id, name, severity, owasp, fn}]

# 级别由高到低（门控比较用）；出现未知级别时按 info 处理
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

# OWASP Top10(2021) 分类（GUI「策略配置」按分类开关面板用，列表顺序即展示顺序）
CATEGORIES = [
    ("A01", "A01 访问控制失效"),
    ("A02", "A02 加密机制失效"),
    ("A03", "A03 注入"),
    ("A04", "A04 不安全设计"),
    ("A05", "A05 安全配置错误"),
    ("A06", "A06 自带缺陷与过时组件"),
    ("A07", "A07 身份认证失效"),
    ("A08", "A08 软件与数据完整性失效"),
    ("A09", "A09 日志与监控不足"),
    ("A10", "A10 SSRF"),
]


def severity_ok(severity, min_severity):
    """severity 是否达到 min_severity 门槛（未知级别一律视为 info）。"""
    try:
        return SEVERITY_ORDER.index(str(severity).lower()) <= SEVERITY_ORDER.index(
            str(min_severity).lower())
    except ValueError:
        return True


def enabled_checks(settings):
    """按 `disabled_categories` / `disabled_checks` / `skip_severities` 过滤出**会执行**的检查。

    `skip_severities`（默认 info + low）是"按级别分类批量关"：这些检查**连请求都不发**。
    因为它们的结论同样会被 `min_severity` 丢掉（见 `run_all`），跑了纯属浪费请求预算，
    还会让"太 low 的洞"占满运行日志 —— CTF 实战里这些项拿不到 flag。
    """
    cfg = (settings or {}).get("checks", {}) or {}
    cats = {str(c) for c in (cfg.get("disabled_categories") or [])}
    ids = {str(i) for i in (cfg.get("disabled_checks") or [])}
    skip = config.skip_severities(settings)
    return [m for m in CHECKS if m["owasp"] not in cats and m["id"] not in ids
            and str(m["severity"]).lower() not in skip]


def check(cid, name, severity, owasp):
    def deco(fn):
        CHECKS.append({"id": cid, "name": name, "severity": severity,
                       "owasp": owasp, "fn": fn})
        return fn
    return deco


def _mk(cid, name, severity, owasp, target, detail, evidence=""):
    return {"poc_id": cid, "name": name, "severity": severity, "owasp": owasp,
            "target": target, "detail": detail, "evidence": (evidence or "")[:800]}


def _get(url, settings, **kw):
    """OWASP 检查的统一出口（全部发往目标，**带上登录态**：登录后才会暴露的项才扫得到）。"""
    return http_request(url, timeout=int(settings.get("limits", {}).get("http_timeout", 10)),
                        settings=settings, auth=True, **kw)


def _low_headers(resp):
    return {str(k).lower(): v for k, v in (resp.get("headers") or {}).items()}


# ---------- A02 传输加密 ----------

@check("a02-no-https", "目标使用明文 HTTP", "low", "A02")
def _no_https(url, settings):
    if url.startswith("http://"):
        return _mk("a02-no-https", "目标使用明文 HTTP", "low", "A02", url,
                   "站点通过明文 HTTP 提供，传输层未加密，存在窃听与篡改风险；建议启用 HTTPS 并强制跳转。")
    return None


@check("a02-cookie-flags", "Cookie 安全属性缺失", "low", "A02")
def _cookie_flags(url, settings):
    r = _get(url, settings)
    if not r:
        return None
    raw = "; ".join(str(v) for k, v in (r.get("headers") or {}).items()
                    if str(k).lower() == "set-cookie")
    issues = []
    for chunk in raw.split(","):
        c = chunk.strip()
        name_part = c.split(";")[0]
        if "=" not in name_part or " " in name_part.split("=")[0]:
            continue  # 过滤 Expires 日期被逗号误切的部分（requests 合并重复头的已知限制）
        low = c.lower()
        flags = []
        if "httponly" not in low:
            flags.append("HttpOnly")
        if url.startswith("https://") and "secure" not in low:
            flags.append("Secure")
        if flags:
            issues.append(f"{name_part.split('=')[0]} 缺少 {','.join(flags)}")
    if issues:
        return _mk("a02-cookie-flags", "Cookie 安全属性缺失", "low", "A02", url,
                   "；".join(sorted(set(issues))) + "。会话 Cookie 缺少安全属性增加会话劫持面。")
    return None


# ---------- A05 安全配置 ----------

@check("a05-security-headers", "安全响应头缺失", "info", "A05")
def _security_headers(url, settings):
    r = _get(url, settings)
    if not r:
        return None
    h = _low_headers(r)
    missing = [x for x in ("content-security-policy", "x-content-type-options", "x-frame-options")
               if not h.get(x)]
    if url.startswith("https://") and not h.get("strict-transport-security"):
        missing.append("strict-transport-security")
    if missing:
        return _mk("a05-security-headers", "安全响应头缺失", "info", "A05", url,
                   f"缺少安全响应头：{', '.join(missing)}。"
                   "缺失不会直接导致漏洞，但会放大 XSS 点击劫持等攻击的影响。")
    return None


@check("a05-banner-disclosure", "服务器组件版本信息泄露", "info", "A05")
def _banner(url, settings):
    r = _get(url, settings)
    if not r:
        return None
    h = _low_headers(r)
    server, xpb = h.get("server", ""), h.get("x-powered-by", "")
    leak = []
    if re.search(r"\d+\.\d+", server):
        leak.append(f"Server: {server}")
    if xpb:
        leak.append(f"X-Powered-By: {xpb}")
    if leak:
        return _mk("a05-banner-disclosure", "服务器组件版本信息泄露", "info", "A05", url,
                   "响应头暴露带版本的组件信息，可被用于定向匹配历史漏洞。",
                   "；".join(leak))
    return None


@check("a01-directory-listing", "目录列表开启", "medium", "A01")
def _dir_listing(url, settings):
    r = _get(url, settings)
    text = (r or {}).get("text", "")
    if r and r.get("status") == 200 and (
            "<title>index of /" in text.lower() or "directory listing for" in text.lower()):
        return _mk("a01-directory-listing", "目录列表开启", "medium", "A01", url,
                   "Web 服务器目录列表开启，可能暴露备份、源码、日志等敏感文件。", text[:300])
    return None


@check("a05-default-pages", "默认示例页面暴露", "info", "A05")
def _default_pages(url, settings):
    for path, sig, name in (
            ("/phpinfo.php", "phpinfo()", "PHP phpinfo"),
            ("/info.php", "phpinfo()", "PHP phpinfo"),
            ("/server-status", "Apache Status", "Apache server-status"),
    ):
        r = _get(url.rstrip("/") + path, settings)
        if r and r.get("status") == 200 and sig.lower() in (r.get("text") or "").lower():
            return _mk("a05-default-pages", "默认示例页面暴露", "info", "A05", url,
                       f"检测到 {name} 页面对外可访问（{path}），泄露运行时信息。")
    return None


# ---------- A01 敏感文件 ----------

# 内置清单 = **兜底**（数据文件 `config/dicts/sensitive.txt` 缺失/没有可检测行时用它）。
# 现在这份清单与数据文件同格式，检测一律走 `sensitive_files()` 读出的行。
SENSITIVE_FILES = [
    ("/.git/config", ["[core]", "repositoryformatversion"], "high", "Git 仓库配置（可还原源码）"),
    ("/.git/HEAD", ["ref:"], "medium", "Git HEAD 指针（.git 可读的信号）"),
    ("/.env", ["db_password", "app_key", "secret", "database_url", "api_key"], "high", "环境变量文件"),
    ("/.svn/entries", ["dir"], "medium", "SVN 元数据"),
    ("/WEB-INF/web.xml", ["<web-app"], "high", "Java Web 部署描述符"),
    ("/backup.sql", ["insert into", "create table"], "high", "数据库备份"),
    ("/.DS_Store", ["bud1"], "low", "macOS 目录元数据（可能泄露文件名）"),
]

# 数据文件只在首次调用时读一次（按解析出的绝对路径做键，settings 换路径即失效）
_DICT_LOCK = threading.Lock()
_DICT_CACHE = {"path": None, "rows": None}


def _parse_sensitive_rows(lines):
    """解析数据文件 → [(路径, [特征关键字], 级别, 说明)]。

    为什么关键字是**必填**：不带关键字就凭"200 = 文件存在"下结论，会被统一返回 200 的
    软 404 页放大成一片误报 —— 这正是这份字典长期只当"预留位"、检查改用硬编码清单的原因。
    没有 `|` 的行（只有路径）按预留位跳过，既不裸判存在、也不必删掉。
    """
    rows = []
    for raw in lines or []:
        line = raw.strip()
        if not line or line.startswith("#") or "|" not in line:
            continue
        parts = [p.strip() for p in line.split("|")]
        path = parts[0]
        sigs = [s.strip().lower() for s in parts[1].split(",") if s.strip()]
        if not path.startswith("/") or not sigs:
            continue
        sev = (parts[2].lower() if len(parts) > 2 and parts[2] else "medium")
        rows.append((path, sigs, sev if sev in SEVERITY_ORDER else "medium",
                     parts[3] if len(parts) > 3 and parts[3] else path))
    return rows


def sensitive_files(settings=None):
    """返回 A01 检查要用的 [(路径, 特征关键字, 级别, 说明)]。

    数据源＝`settings["dicts"]["sensitive"]`（默认 `config/dicts/sensitive.txt`）；
    读不到、或一条可检测的行都没有时回退内置 `SENSITIVE_FILES`，保证任何机器上都能跑。
    """
    path = ((settings or {}).get("dicts") or {}).get("sensitive") \
        or config.DEFAULTS["dicts"]["sensitive"]
    full = str(config.resolve(path))
    with _DICT_LOCK:
        if _DICT_CACHE["path"] == full and _DICT_CACHE["rows"] is not None:
            return _DICT_CACHE["rows"]
    try:
        rows = _parse_sensitive_rows(read_lines(full))
    except Exception:            # 文件缺失/编码异常都只影响这一条检查的数据源，不影响整轮
        rows = []
    rows = rows or list(SENSITIVE_FILES)
    with _DICT_LOCK:
        _DICT_CACHE["path"] = full
        _DICT_CACHE["rows"] = rows
    return rows


@check("a01-sensitive-files", "敏感文件可匿名访问", "high", "A01")
def _sensitive_files(url, settings):
    base = url.rstrip("/")
    for path, sigs, sev, name in sensitive_files(settings):
        r = _get(base + path, settings)
        if not r or r.get("status") != 200:
            continue
        text = (r.get("text") or "").lower()
        if any(s in text for s in sigs):
            return _mk("a01-sensitive-files", "敏感文件可匿名访问", sev, "A01", base + path,
                       f"{name}（{path}）可被匿名访问，内容命中特征关键字。", text[:300])
    return None


# ---------- A03 注入类（仅"回显信号"） ----------

SQL_ERRORS = [
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"unclosed quotation mark",
    r"ora-\d{5}",
    r"postgresql.*error",
    r"sqlite3?::query",
    r"odbc.*driver.*error",
    r"mysqli?_[a-z_]+\(\)",
]

# 注入检查的请求预算：先打"原始 payload"（便宜、常见），全部未命中才升级到变形变体，
# 且总请求数封顶，避免对单站点产生过大压力（非破坏性约束）。
_SQLI_PARAMS = ("id", "page", "cat", "user", "item")
_SQLI_BASES = ("1'", '1"', "1')")
_SQLI_MAX_REQ = 30


def _bypass_level(settings):
    """当前生效的绕过等级（0 表示不做变形）。"""
    cfg = (settings or {}).get("evasion", {}) or {}
    return int(cfg.get("bypass_level", 2) or 0) if cfg.get("waf_bypass", True) else 0


def _ordered(seq):
    """参数顺序随机化。

    同一套 payload 每次都以完全相同的顺序、相同的参数名发出，很容易被 WAF 的
    频率/序列规则固化识别；打乱参数顺序让"请求形态"每次都不同（payload 语义不变）。
    """
    items = list(seq)
    random.shuffle(items)
    return items


@check("a03-sqli-error", "SQL 注入报错回显", "high", "A03")
def _sqli_error(url, settings):
    """报错型 SQL 注入探测（带动态变形，用于绕过 WAF 的规则匹配）。"""
    level = _bypass_level(settings)
    used = 0
    sep = "&" if "?" in url else "?"
    for round_level in ([0] if level == 0 else [0, level]):
        for param in _ordered(_SQLI_PARAMS):
            for base in _SQLI_BASES:
                for payload in evasion.mutate_sqli(base, round_level):
                    if used >= _SQLI_MAX_REQ:
                        return None
                    r = _get(f"{url}{sep}{param}={payload}", settings)
                    used += 1
                    if not r:
                        continue
                    text = (r.get("text") or "").lower()
                    for pat in SQL_ERRORS:
                        m = re.search(pat, text)
                        if m:
                            tip = ("" if payload == base else
                                   f"（命中 WAF 绕过变体：{payload}）")
                            return _mk("a03-sqli-error", "SQL 注入报错回显", "high", "A03", url,
                                       f"参数 {param} 注入后响应命中数据库报错特征 '{m.group(0)}'，"
                                       f"疑似存在 SQL 注入，需人工确认{tip}。", text[:300])
    return None


# ---- 布尔型盲注：只做"恒真 vs 恒假"的响应差分 ----
#
# **明确不做延时型**（`SLEEP()` / `BENCHMARK()` / `WAITFOR DELAY` / `pg_sleep()`），理由三条：
#   ① 项目红线写着"检测一律非破坏性……无 DoS 延时"—— 延时 payload 会让目标数据库的
#      连接/线程挂住 N 秒，并发一上去就是事实上的资源耗尽，这与"初筛"的定位冲突；
#   ② 延时判定依赖网络往返时间，跨公网抖动经常盖过 5 秒的差值，误报与漏报都高；
#   ③ 它慢：每个参数每个变体都要等满一个 sleep 周期，与"每站点几十个请求"的预算不兼容。
# 布尔差分没有这些问题：两次请求**只差一个布尔条件**，比状态码 / 长度 / 正文即可。
_SQLI_BLIND_PARAMS = ("id", "page", "cat", "user", "item")
_SQLI_BLIND_PAIRS = (
    ("1 AND 1=1", "1 AND 1=2"),
    ("1' AND '1'='1", "1' AND '1'='2"),
    ("1) AND (1=1", "1) AND (1=2"),
    ('1" AND "1"="1', '1" AND "1"="2'),
)
# 每参数固定 3 个请求（恒真 / 恒假 / 恒真复验），所以 12 = 4 个参数。
# 复验那一发不是浪费：页面自带随机数/时间戳时"恒真"自己都会抖动，不复验就会把抖动
# 当成注入信号 —— 这是布尔盲注最主要的误报源。
_SQLI_BLIND_MAX_REQ = 12
# "差异显著"的双阈值：绝对字节差 OR 相对比例（小页面靠比例，大页面靠绝对值）
_SQLI_BLIND_MIN_DELTA = 40
_SQLI_BLIND_MIN_RATIO = 0.05


def _resp_sig(resp):
    """响应指纹：`(状态码, 响应体长度)`。取不到（请求失败）返回 None。"""
    if not resp:
        return None
    text = resp.get("text") or ""
    try:
        status = int(resp.get("status") or 0)
    except (TypeError, ValueError):
        status = 0
    try:
        length = int(resp.get("length") or len(text))
    except (TypeError, ValueError):
        length = len(text)
    return status, length


def _diff_significant(sig_a, sig_b):
    """两次响应是否"差异显著"（足以说明布尔条件影响了输出）。"""
    if not sig_a or not sig_b:
        return False
    if sig_a[0] != sig_b[0]:
        return True                                  # 状态码都变了，是最强的信号
    delta = abs(sig_a[1] - sig_b[1])
    return bool(delta >= _SQLI_BLIND_MIN_DELTA
                or delta >= max(sig_a[1], sig_b[1], 1) * _SQLI_BLIND_MIN_RATIO)


@check("a03-sqli-blind", "SQL 注入布尔型盲注", "high", "A03")
def _sqli_blind(url, settings):
    """布尔型盲注探测（不做变形，理由见下）。

    为什么**不套 `evasion.mutate_sqli`**：差分判定的前提是"两次请求只差一个布尔条件"，
    变形会引入注释、编码、大小写这些额外变量，让"响应不同"无法归因 —— 宁可少绕一点
    WAF，也要保证结论站得住。预算仍受 `_SQLI_BLIND_MAX_REQ` 封顶。
    """
    used = 0
    sep = "&" if "?" in url else "?"
    for param in _ordered(_SQLI_BLIND_PARAMS):
        for true_p, false_p in _SQLI_BLIND_PAIRS:
            if used + 3 > _SQLI_BLIND_MAX_REQ:
                return None
            r_true = _get(f"{url}{sep}{param}={true_p}", settings)
            r_false = _get(f"{url}{sep}{param}={false_p}", settings)
            r_again = _get(f"{url}{sep}{param}={true_p}", settings)     # 复验稳定性
            used += 3
            s_t, s_f, s_a = _resp_sig(r_true), _resp_sig(r_false), _resp_sig(r_again)
            if not (s_t and s_f and s_a):
                continue
            if not _diff_significant(s_t, s_f):
                continue                             # 恒真与恒假没区别 → 这参数不受影响
            if _diff_significant(s_t, s_a):
                continue                             # 恒真自己都不稳定 → 页面抖动，不判
            delta = abs(s_t[1] - s_f[1])
            ratio = delta * 100 // max(s_t[1], s_f[1], 1)
            evidence = (f"恒真 {true_p} → HTTP {s_t[0]} / {s_t[1]}B；"
                        f"恒假 {false_p} → HTTP {s_f[0]} / {s_f[1]}B；"
                        f"长度差 {delta}B（约 {ratio}%）；"
                        f"复验恒真 → HTTP {s_a[0]} / {s_a[1]}B（与首次一致）")
            return _mk("a03-sqli-blind", "SQL 注入布尔型盲注", "high", "A03", url,
                       f"参数 {param} 的恒真/恒假两个 payload 得到显著不同的响应，"
                       f"且恒真结果可复现（排除页面自身抖动），疑似布尔型盲注，需人工确认。",
                       evidence)
    return None


XSS_MARKER = "ctfscan9x8marker"
_XSS_PARAMS = ("q", "search", "keyword", "name")
_XSS_BASE = f"<svg/onload={XSS_MARKER}>"
# 上下文探针：一段必然可回显的普通字符 + `" ' < >` 四个定界符。
# 它**不要求原样回显**（那是 base payload 的职责），而是看这四个字符里哪些"活着回来"：
# 引号活着 = 属性 / JS 串上下文有逃逸可能；尖括号活着 = 文本节点里能直接插标签。
# 为什么必须补这一条：大量站点会把 `<` `>` 转义却留下引号，于是 base payload 永远不原样
# 回显、旧逻辑整片漏报 —— 而"引号没被转义"恰恰是**属性注入**最常成立的场景。
# 预算不受影响：它只是 payload 池里多一条，总请求数仍由 `_XSS_MAX_REQ` 封顶。
_XSS_CTX_PROBE = f"{XSS_MARKER}\"'<>"
_XSS_MAX_REQ = 20
# 探针里定界符的顺序（与 `_XSS_CTX_PROBE` 严格一致，`_probe_escapes` 按此顺序扫描回显）
_XSS_PROBE_CHARS = ('"', "'", "<", ">")

# 回显上下文 → 中文名 / 级别 / "要逃逸出去必须活着的定界符"
# 空元组 = 靠本探针判不出来（HTML 注释要 `-->` 闭合），一律不报，避免幻觉。
XSS_CONTEXT_LABELS = {
    "text-node": "HTML 文本节点",
    "dquote-attr": "双引号属性值内",
    "squote-attr": "单引号属性值内",
    "unquoted-attr": "无引号属性值内",
    "tag-name": "标签名位置",
    "js-string": "<script> 内的 JS 字符串里",
    "js-code": "<script> 内的 JS 代码里",
    "html-comment": "HTML 注释内",
}
XSS_CONTEXT_SEVERITY = {
    # 可直接逃逸 / 直接执行 → high
    "js-string": "high",
    "js-code": "high",
    "unquoted-attr": "high",
    "tag-name": "high",
    # 需要先闭合引号 → medium
    "dquote-attr": "medium",
    "squote-attr": "medium",
    # 需要先有未转义的 `<` 才能插标签 → medium（证据里写明这一前提）
    "text-node": "medium",
    # 要先闭合注释，多数场景不可利用 → 降级（默认门槛 medium 下不产出）
    "html-comment": "low",
}
XSS_BREAK_CHAR = {
    "text-node": ("<",),
    "dquote-attr": ('"',),
    "squote-attr": ("'",),
    "unquoted-attr": ('"', "'", "<", ">"),
    "tag-name": ('"', "'", "<", ">"),
    "js-string": ('"', "'"),
    "js-code": ('"', "'", "<", ">"),
    "html-comment": (),
}

# 各定界符被转义后常见的形态（浏览器不会把它们当语法，故不算"活着"）
_XSS_ESCAPE_FORMS = {
    '"': ("&quot;", "&#34;", "&#x22;", "%22", "\\\""),
    "'": ("&#39;", "&#x27;", "&#039;", "&apos;", "%27", "\\'"),
    "<": ("&lt;", "&#60;", "&#x3c;", "%3c"),
    ">": ("&gt;", "&#62;", "&#x3e;", "%3e"),
}


def _context_of(body, idx):
    """看 `idx` 处的回显落在哪种上下文里（只做**局部**字符串判定，不引 HTML 解析器）。

    判定顺序是有讲究的：注释 → `<script>` 块 → 标签内 → 文本节点。
    注释必须最先判（它里面可以出现任何看起来像标签的东西），
    `<script>` 其次（它里面的 `<` `>` 不构成标签）。
    """
    head = body[:idx]
    low = head.lower()
    if low.rfind("<!--") > low.rfind("-->"):
        return "html-comment"
    s_open = low.rfind("<script")
    if s_open >= 0 and low.rfind("</script") < s_open:
        # 前一个字符是引号 → 在字符串里（可以直接闭合字符串）；否则在 JS 代码区
        return "js-string" if body[idx - 1:idx] in ("'", '"', "`") else "js-code"
    lt, gt = low.rfind("<"), low.rfind(">")
    if lt < 0 or lt < gt:
        return "text-node"
    if lt == idx - 1:                    # 紧跟 `<` → 标签名位置（可塞进完整标签/属性）
        return "tag-name"
    prev = body[idx - 1:idx]
    if prev == '"':
        return "dquote-attr"
    if prev == "'":
        return "squote-attr"
    if prev == "=":
        return "unquoted-attr"
    # 落在标签内但紧邻字符不是引号 / `=`（属性名位置之类）：按最宽松的"无引号属性"处理
    # —— 这里没有引号保护，判定偏宽松是刻意的（宁可让人复核一遍，也不静默漏掉）。
    return "unquoted-attr"


def _probe_escapes(tail):
    """按探针里 `"'<>` 的顺序，逐个看它在回显里是原样、被转义还是被剔除。

    顺序扫描而不是"在附近随便找"：探针是已知定长串，回显要么是原字符、要么是对应实体，
    逐个消费才能区分"引号被转义但尖括号没有"这种关键组合；全局 `in` 判断会把两种
    情况混成一种，上下文分析也就失去意义了。
    """
    out, pos = {}, 0
    for ch in _XSS_PROBE_CHARS:
        if pos < len(tail) and tail[pos] == ch:
            out[ch] = "raw"
            pos += 1
            continue
        hit = ""
        for form in _XSS_ESCAPE_FORMS[ch]:
            if tail.startswith(form, pos):
                hit = form
                break
        if hit:
            out[ch] = "escaped"
            pos += len(hit)
        else:
            out[ch] = "missing"           # 被删掉，或顺序对不上 —— 不猜，按"没活着"处理
    return out


def classify_xss(text, payload, marker=XSS_MARKER):
    """判定一次 XSS 回显的**上下文**，给出级别与判定依据。

    返回 None（这个 payload 没回显）或 dict：
      - `context` / `label`：上下文类型与中文名
      - `severity`：按上下文给出的级别（见 `XSS_CONTEXT_SEVERITY`）
      - `verbatim`：payload 是否**原样**回显（原样 = 完全没转义）
      - `escapes`：上下文探针里 `"'<>` 各自的状态（raw / escaped / missing）
      - `usable`：是否值得报（False 表示"有回显但这个上下文逃逸不出去"）
      - `reason` / `snippet`：判定依据与证据片段
    """
    body = str(text or "")
    idx = body.find(payload)
    verbatim = idx >= 0
    end = idx + len(payload) if verbatim else -1
    if not verbatim:
        idx = body.find(marker)
        if idx < 0:
            return None
        end = idx + len(marker)
    ctx = _context_of(body, idx)
    escapes = {} if verbatim else _probe_escapes(body[end: end + 64])

    need = XSS_BREAK_CHAR.get(ctx, ())
    if ctx == "js-string":
        delim = body[idx - 1:idx]
        need = (delim,) if delim in ("'", '"', "`") else ("'", '"')
    if verbatim:
        usable = True
        reason = "payload 原样回显（未做任何转义）"
    elif not need:
        usable = False
        reason = "落在 HTML 注释内且 payload 未原样回显，无法判定能否闭合注释"
    else:
        alive = [c for c in need if escapes.get(c) == "raw"]
        if alive:
            usable = True
            reason = ("回显中 " + "、".join(repr(c) for c in alive)
                      + " 未被转义，可闭合当前上下文")
        else:
            usable = False
            reason = ("回显中 " + "、".join(repr(c) for c in need)
                      + " 均已被转义或剔除，无法逃逸出当前上下文")
    snippet = body[max(0, idx - 60): end + 60].replace("\n", " ")
    return {"context": ctx, "label": XSS_CONTEXT_LABELS.get(ctx, ctx),
            "severity": XSS_CONTEXT_SEVERITY.get(ctx, "medium"),
            "verbatim": verbatim, "escapes": escapes, "usable": usable,
            "reason": reason, "snippet": snippet[:240]}


@check("a03-xss-reflect", "XSS 反射回显", "medium", "A03")
def _xss_reflect(url, settings):
    """反射型 XSS 探测：先找"有没有回显"，再判"回显落在哪个上下文"，按上下文定级。

    为什么级别不再固定 medium：同样是"值被回显"，落在 `<script>` 的字符串里
    （直接写 `';alert(1);//`）与落在一个双引号属性里（得先闭合引号）的可利用性差一个量级，
    而落在 HTML 注释里（要先闭合 `-->`）多数场景根本不可利用 —— 一律按 medium 报
    既淹没真正的高危项，也白白占用人工复核的时间。
    """
    level = _bypass_level(settings)
    used = 0
    sep = "&" if "?" in url else "?"
    fallback = None       # 只找到"降级"上下文时先存着；全跑完仍没有更好的才报它
    for round_level in ([0] if level == 0 else [0, level]):
        for param in _ordered(_XSS_PARAMS):
            for payload in evasion.mutate_xss(_XSS_BASE, round_level) + [_XSS_CTX_PROBE]:
                if used >= _XSS_MAX_REQ:
                    return fallback
                r = _get(f"{url}{sep}{param}={payload}", settings)
                used += 1
                # 只认"payload 原样出现"或"上下文探针的标记出现"：单看标记串会把
                # **被转义的**回显（`&lt;svg/onload=…marker…&gt;`，任何带搜索框的页面都会
                # 这样回显）也算成 XSS —— 那是典型误报，`classify_xss` 会按上下文否定掉。
                info = classify_xss((r or {}).get("text") or "", payload)
                if not info or not info["usable"]:
                    continue
                tip = ("" if payload in (_XSS_BASE, _XSS_CTX_PROBE) else
                       f"（命中 WAF 绕过变体：{payload}）")
                v = _mk("a03-xss-reflect", "XSS 反射回显", info["severity"], "A03", url,
                        f"参数 {param} 的值回显在{info['label']}：{info['reason']}"
                        f"{'，需该上下文的定界符未被转义' if info['context'] == 'text-node' else ''}"
                        f"，疑似反射型 XSS，需人工确认{tip}。", info["snippet"])
                if str(info["severity"]).lower() != "low":
                    return v
                fallback = fallback or v
    return fallback


@check("a01-open-redirect", "开放重定向", "medium", "A01")
def _open_redirect(url, settings):
    probe = "ctfscan-redirect.example"
    for param in ("next", "redirect", "url", "return", "returnUrl", "goto"):
        sep = "&" if "?" in url else "?"
        r = _get(f"{url}{sep}{param}=//{probe}", settings, allow_redirects=False)
        if r and 300 <= r.get("status", 0) < 400:
            h = _low_headers(r)
            loc = h.get("location", "")
            if probe in loc:
                return _mk("a01-open-redirect", "开放重定向", "medium", "A01", url,
                           f"参数 {param} 可控且参与 3xx 跳转，疑似开放重定向，需人工确认。", loc)
    return None


# ---------- A10 SSRF 受控回连（默认关） ----------

@check("a10-ssrf-callback", "服务端会发起出网请求（SSRF 受控回连）", "high", "A10")
def _ssrf_callback(url, settings, logger=None):
    """A10 SSRF 受控回连：**默认关**（`ssrf.enabled=true` 才跑），打开才有这一项。

    判定逻辑：为每个候选参数生成一个唯一 token，把 `http://<回调基址>/<token>` 喂进去，
    若监听端收到携带该 token 的请求 —— 说明目标服务端**真的按我们给的地址发起了出网请求**。
    这是"存在 SSRF"的直接证据，不依赖任何错误回显，也不用猜响应时间。

    刻意不做的事（详见 `scanner/ssrf.py` 文件头）：
    - **不用这个通道去打内网地址**（`127.0.0.1:8080` / `169.254.169.254`…）—— 那是利用，
      越过了本项目"只做初筛、非破坏性"的边界；这里只证明"它会出网"；
    - **不提交页面表单**（表单可能是写操作）—— 表单只被用来取**字段名**，注入一律走 GET；
    - **不做延时型判定**。

    两种模式：
    - `ssrf.callback_base` 留空 → 起本机监听，能**确认**命中才报；
    - 填了外部回调基址 → 我们读不到那侧的命中，因此**只注入、不报命中**（宁可不报也不谎报），
      并把注入过的 token 写进任务日志，由你在自己的 OOB 服务上核对。
    """
    if not ssrf_mod.enabled(settings):
        return None
    sep = "&" if "?" in url else "?"
    external = ssrf_mod.callback_base(settings)          # 非空 = 外部回调（无法自证）
    listener = None
    try:
        if external:
            base = external
        else:
            listener = ssrf_mod.CallbackListener(
                ssrf_mod.listen_host(settings), ssrf_mod.listen_port(settings)).start()
            base = listener.base_url
        params = ssrf_mod.candidate_params(url, settings, logger=logger)
        if not params:
            return None
        tokens = {}
        for param in params:
            token = ssrf_mod.new_token()
            tokens[token] = param
            target = ssrf_mod.payload_url(base, token)
            _get(f"{url}{sep}{param}={urllib.parse.quote(target, safe='')}", settings)
        if listener is None:
            # 外部回调：写清"注入了哪些 token"，但不伪造命中
            if logger:
                logger.info(f"[ssrf] 已向 {url} 注入 {len(tokens)} 个回调地址"
                            f"（基址 {base}）；本模块读不到该基址的命中，"
                            f"请在你的回调服务侧核对这些 token："
                            f"{', '.join(sorted(tokens))}")
            return None
        # 本机监听：等一段**有界**的时间（默认 6 秒），期间不再向目标发任何请求
        listener.wait(ssrf_mod.wait_seconds(settings))
        hits = [h for h in listener.hits() if h.get("token") in tokens]
    finally:
        if listener is not None:
            listener.close()                            # 用完即关，不留监听线程
    if not hits:
        return None
    h = hits[0]
    param = tokens.get(h.get("token"), "?")
    evidence = (f"回调基址 {base}；参数 {param} 注入 "
                f"{ssrf_mod.payload_url(base, h.get('token'))}；"
                f"收到 {h.get('method')} {h.get('path')} "
                f"（来源 {h.get('ip')}:{h.get('port')}，UA {h.get('ua') or '-'}，"
                f"时间 {h.get('time')}）；共 {len(hits)} 条命中")
    return _mk("a10-ssrf-callback", "服务端会发起出网请求（SSRF 受控回连）", "high", "A10",
               url, f"参数 {param} 被喂入回调地址后，服务端真的向该地址发起了请求"
                    f"（收到带唯一 token 的回连），说明该处存在服务端请求伪造（SSRF）面，"
                    f"需人工确认其可达范围（本模块刻意不去探测内网）。", evidence)


# ---------- A06 已知组件 ----------

@check("a06-legacy-banner", "老旧组件版本特征", "low", "A06")
def _legacy_banner(url, settings):
    r = _get(url, settings)
    if not r:
        return None
    h = _low_headers(r)
    banner = f"{h.get('server', '')} {h.get('x-powered-by', '')}"
    for pat, note in (
            (r"php/5\.", "PHP 5.x 已停止安全维护"),
            (r"tomcat/[678]\.", "Tomcat 6/7/8 旧版本"),
            (r"apache/2\.2\.", "Apache 2.2 已停止安全维护"),
            (r"iis/6", "IIS 6 旧版本"),
            (r"struts", "Struts 历史漏洞高发"),
            (r"weblogic", "WebLogic 历史漏洞高发"),
            (r"jboss", "JBoss 历史漏洞高发"),
            (r"thinkphp", "ThinkPHP 历史漏洞高发"),
    ):
        if re.search(pat, banner, re.I):
            return _mk("a06-legacy-banner", "老旧组件版本特征", "low", "A06", url,
                       f"组件特征命中：{note}（{banner.strip()}）。建议核对确切版本并比对已知 CVE。")
    return None


# ---------- A08 完整性 ----------

@check("a08-missing-sri", "外部脚本未启用 SRI", "info", "A08")
def _missing_sri(url, settings):
    r = _get(url, settings)
    text = (r or {}).get("text") or ""
    missing = 0
    for tag in re.findall(r"<script[^>]*>", text, re.I):
        m = re.search(r"src\s*=\s*[\"']([^\"']+)[\"']", tag, re.I)
        if not m:
            continue
        src = m.group(1)
        if src.startswith(("http://", "https://")) and not re.search(r"integrity\s*=", tag, re.I):
            missing += 1
    if missing:
        return _mk("a08-missing-sri", "外部脚本未启用 SRI", "info", "A08", url,
                   f"{missing} 个第三方脚本未设置 integrity 属性，存在 CDN/供应链篡改风险（信息级）。")
    return None


def _takes_logger(fn):
    """检查函数是否接受 `logger=` 关键字（只有需要写过程日志的检查才声明它）。

    用签名探测而不是"给所有检查都多传一个参数"，是为了**不动既有检查的签名**：
    12 个检查里只有 SSRF 回连需要往任务日志里写东西（外部回调模式下要交代注入了哪些
    token），为它一个人改 11 个函数的签名不划算，也会让第三方扩展更难写。
    """
    try:
        return "logger" in inspect.signature(fn).parameters
    except (TypeError, ValueError):
        return False


def run_all(url, settings, min_severity=None, logger=None):
    """顺序执行**启用**的检查，单个检查异常不影响其余；返回 vuln dict 列表。

    两级门控（配置在 `checks` 段，GUI「策略配置」页可改）：
    - 执行级：`disabled_categories` / `disabled_checks` / `skip_severities` 命中的检查
      **根本不执行**（连请求都不发，见 `enabled_checks`）；
    - 结果级：`min_severity`（可被入参覆盖）以下的发现直接丢弃。默认 medium，
      即"明文 HTTP / 安全响应头缺失 / 组件版本泄露"这类低危与 info 项默认不再产出
      —— CTF 实战里它们只会淹没真正能拿 flag 的注入/RCE 类结果。
    """
    cfg = (settings or {}).get("checks", {}) or {}
    floor = str(min_severity or cfg.get("min_severity", "medium")).lower()
    out = []
    for meta in enabled_checks(settings):
        try:
            if logger is not None and _takes_logger(meta["fn"]):
                v = meta["fn"](url, settings, logger=logger)
            else:
                v = meta["fn"](url, settings)
        except Exception:
            v = None
        if not v:
            continue
        v.setdefault("target", url)
        if not severity_ok(v.get("severity", "info"), floor):
            continue
        out.append(v)
    return out
