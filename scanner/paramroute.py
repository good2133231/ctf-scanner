"""参数路由：**按 URL 里的参数名**决定该跑哪几类漏洞检测（续203，主理人点单）。

主理人原话：「爬虫按参数名挑 POC（`?id=` 优先试注入类），其实有 `?` 的亦或是参数都该尝试」。

为什么需要它：爬虫收集到的带参链接是**注入面**，但一个链接上挂的参数不同，该试的漏洞类型
完全不同 —— `?file=xxx` 该试路径穿越/文件读取，`?url=xxx` 该试 SSRF/开放重定向，`?id=1`
该试 SQL 注入/越权。全部检查都跑一遍既慢又把请求量放大十几倍（目标侧压力），只跑匹配的
那几类才是"智能"。

设计口径（参照 nuclei templates 的 tag 命名与主流扫描器的分类习惯）：
- **参数名 → 类别**（`PARAM_KINDS`）：一个参数名可同时属多个类别（`url` 既是 SSRF 也是
  开放重定向，这是对的，那两类本来就可能同时命中）；
- **类别 → 检查 id**（`KIND_CHECKS`）：**只映射本框架真实存在的检查**。没有对应检查的类别
  （如 LFI / RCE）**不映射** —— 造一个"会跑但不报"的映射比没有更糟；`kinds()` 仍然返回它们，
  页面照实显示"这类参数已识别、暂无对应检查"，让人知道缺口在哪而不是假装覆盖了。
- 参数名取**去数字后缀**的形态：`id1` / `id2` 与 `id` 同类（真实站点大量这种命名）。

这个模块是**纯函数**（不读库、不发请求、不吃配置）—— 判据集中一处，页面说明与扫描路由
用的是同一份，不会出现"页面说会测 SSRF、扫描时却没跑"。
"""
import re
from urllib.parse import parse_qsl, urlsplit

# 参数名（小写）→ 类别。列表刻意**互有重叠**：同一个名字常该试多类。
PARAM_KINDS = {
    "sqli": ("id", "uid", "pid", "cid", "tid", "gid", "nid", "sid", "ids", "cat", "category",
             "page", "pageid", "newsid", "article", "view", "item", "query", "q", "search",
             "keyword", "key", "s", "w", "name", "user", "username", "login", "email", "order",
             "sort", "by", "limit", "offset", "table", "column", "select", "where", "num",
             "no", "type", "status"),
    "xss": ("q", "s", "search", "keyword", "key", "w", "query", "name", "title", "content",
            "text", "message", "msg", "comment", "input", "value", "data", "html", "url",
            "callback", "redirect", "next", "template", "lang"),
    "openredirect": ("url", "redirect", "redirect_uri", "redirect_url", "redirecturl", "next",
                     "return", "returnurl", "return_to", "goto", "target", "dest",
                     "destination", "rurl", "callback", "continue", "window", "link", "to",
                     "out", "forward", "jump", "site"),
    "ssrf": ("url", "uri", "path", "dest", "destination", "target", "host", "domain",
             "callback", "webhook", "fetch", "load", "open", "proxy", "site", "link", "img",
             "image", "feed", "src", "source", "download", "port", "ip"),
    "lfi": ("file", "path", "dir", "folder", "doc", "document", "template", "include",
            "filename", "download", "read", "cat", "load", "open", "view", "content", "conf",
            "config", "page"),
    "rce": ("cmd", "exec", "command", "system", "ping", "shell", "run", "do", "action",
            "eval", "code", "func", "call", "ip", "host", "addr", "domain", "server", "daemon"),
    "idor": ("id", "uid", "pid", "user_id", "userid", "account", "account_id", "order_id",
             "doc_id", "file_id", "no", "num", "number", "uuid", "guid", "key", "token",
             "oid", "fid", "rid"),
}

# 类别 → 本框架**已有**的检查 id（见 scanner/owasp/checks.py 的 @check 注册名）。
# 没有对应检查的类别（lfi / rce / idor）故意缺席 —— 见模块 docstring。
KIND_CHECKS = {
    "sqli": ("a03-sqli-error", "a03-sqli-blind"),
    "xss": ("a03-xss-reflect",),
    "openredirect": ("a01-open-redirect",),
    "ssrf": ("a10-ssrf-callback",),
    # 续204补上 LFI 与 IDOR 的落点（`a01-lfi-traversal` / `a01-idor-enum`）。
    "lfi": ("a01-lfi-traversal",),
    "idor": ("a01-idor-enum",),
    # `rce` **故意仍然缺席**：确认它要让目标真的把命令跑起来（`;ls` / `|id`），
    # 那越过 AGENTS §1 的"检测一律非破坏性、无写操作"红线。我们只识别"这个参数像命令入口"
    # （`kinds()` 里照旧返回 rce，页面标「暂无对应检查」），不假装能测。
}

# 中文名（页面展示用；与 KIND_CHECKS 的键同一套）
KIND_LABELS = {
    "sqli": "SQL 注入", "xss": "XSS 反射", "openredirect": "开放重定向",
    "ssrf": "SSRF", "lfi": "文件读取/穿越", "rce": "命令执行", "idor": "越权（IDOR）",
}

# 参数名末尾的数字（`id1` / `id2` / `page3` 与 `id` / `page` 同类）
_NUM_TAIL = re.compile(r"\d+$")


def params_of(url):
    """URL 的查询参数名（**去重、保序、小写**）。取不到查询串就返回空列表。"""
    try:
        pairs = parse_qsl(urlsplit(str(url or "")).query, keep_blank_values=True)
    except ValueError:
        return []
    out, seen = [], set()
    for name, _value in pairs:
        n = str(name or "").strip().lower()
        if n and n not in seen:
            seen.add(n)
            out.append(n)
    return out


def kinds(url):
    """这条 URL 的查询参数会牵出哪些漏洞类别（排序后的集合）。

    只按**参数名**判，不看参数值 —— 值里塞什么那是检查自己的事（而且很多站点
    参数值也是动态的，按值判等于把判据建立在沙上）。
    """
    out = set()
    for p in params_of(url):
        base = _NUM_TAIL.sub("", p) or p
        for kind, names in PARAM_KINDS.items():
            if p in names or base in names:
                out.add(kind)
    return out


def checks_for(url):
    """该跑哪些**检查 id**（`kinds` → `KIND_CHECKS` 的并集，排序）。

    没有映射到任何检查时返回**空列表** —— 调用方据此决定"这条 URL 不额外跑检查"
    （而不是回退到跑全部：那会让 `?file=` 这种也白跑一遍 SQL 注入）。
    """
    out = set()
    for k in kinds(url):
        out.update(KIND_CHECKS.get(k, ()))
    return sorted(out)


def has_params(url):
    """带不带查询参数（`?a=` 这种空值也算 —— 空值参数同样是注入面）。"""
    return "?" in str(url or "") and str(url).split("?", 1)[1].strip() != ""
