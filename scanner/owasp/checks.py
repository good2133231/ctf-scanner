"""OWASP Top 10（2021）轻量启发式检查。

定位（客观说明）：
- 这里是"低噪、非破坏性"的通用初筛：全部为 GET 请求 + 被动读取，payload 无破坏性；
- 主要覆盖可用黑盒信号体现的 A01/A02/A03/A05/A06/A08；
- A04（不安全设计）、A07（认证失败）、A09（日志不足）、A10（SSRF）依赖业务上下文，
  黑盒自动化误报/漏报率极高，本模块仅做极少信号量极弱的探测或直接不做（详见 docs/owasp-mapping.md）；
- 所有输出都是"初筛信号"，必须人工确认，不能等同于漏洞结论。
"""
import random
import re
from urllib.parse import urlparse

from .. import config, evasion
from ..utils import http_request

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
    return http_request(url, timeout=int(settings.get("limits", {}).get("http_timeout", 10)),
                        settings=settings, **kw)


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

SENSITIVE_FILES = [
    ("/.git/config", ["[core]", "repositoryformatversion"], "high", "Git 仓库配置（可还原源码）"),
    ("/.git/HEAD", ["ref:"], "medium", "Git HEAD 指针（.git 可读的信号）"),
    ("/.env", ["db_password", "app_key", "secret", "database_url", "api_key"], "high", "环境变量文件"),
    ("/.svn/entries", ["dir"], "medium", "SVN 元数据"),
    ("/WEB-INF/web.xml", ["<web-app"], "high", "Java Web 部署描述符"),
    ("/backup.sql", ["insert into", "create table"], "high", "数据库备份"),
    ("/.DS_Store", ["bud1"], "low", "macOS 目录元数据（可能泄露文件名）"),
]


@check("a01-sensitive-files", "敏感文件可匿名访问", "high", "A01")
def _sensitive_files(url, settings):
    base = url.rstrip("/")
    for path, sigs, sev, name in SENSITIVE_FILES:
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


XSS_MARKER = "ctfscan9x8marker"
_XSS_PARAMS = ("q", "search", "keyword", "name")
_XSS_BASE = f"<svg/onload={XSS_MARKER}>"
_XSS_MAX_REQ = 20


@check("a03-xss-reflect", "XSS 反射回显", "medium", "A03")
def _xss_reflect(url, settings):
    """反射型 XSS 探测（带大小写/属性分隔/编码等变形）。"""
    level = _bypass_level(settings)
    used = 0
    sep = "&" if "?" in url else "?"
    for round_level in ([0] if level == 0 else [0, level]):
        for param in _ordered(_XSS_PARAMS):
            for payload in evasion.mutate_xss(_XSS_BASE, round_level):
                if used >= _XSS_MAX_REQ:
                    return None
                r = _get(f"{url}{sep}{param}={payload}", settings)
                used += 1
                # 只认"标记原样出现"；编码形态若被服务端解码同样说明存在未编码回显
                if r and XSS_MARKER in (r.get("text") or ""):
                    tip = ("" if payload == _XSS_BASE else
                           f"（命中 WAF 绕过变体：{payload}）")
                    return _mk("a03-xss-reflect", "XSS 反射回显", "medium", "A03", url,
                               f"参数 {param} 的值未经编码原样回显到响应中，疑似反射型 XSS，"
                               f"需人工确认{tip}。")
    return None


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


def run_all(url, settings, min_severity=None):
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
