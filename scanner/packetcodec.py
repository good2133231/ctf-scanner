# -*- coding: utf-8 -*-
"""把库里存的"数据包"转成**可复现**的命令 / 脚本（curl / Python requests）。

先讲清边界（这决定了输出长什么样）：
- 我们**只记了请求行 + 响应摘要**（见 `scanner/owasp/checks.py::_packet`），多数 finding 并没有
  保存请求头 / 请求体。这种情况下生成的命令**只有方法 + URL**，并在输出里**明说"请求头/体未记录"**
  —— **绝不把响应头当请求头塞进去**（那会造出一条跑不通、看着还很专业的假命令）。
- 若 packets 里确实是**原始请求**（`METHOD /path HTTP/1.1` + `Host:` + 头 + 体），则原样转全。
- 目标侧凭据（Cookie / Authorization 的值）本就不入库（§7 红线），所以这里也不会有；若证据里
  出现 `set-cookie=有（值不记…）` 这类**掩码行**，一并不当作可复制的头。

只做字符串处理，**不发任何请求**。
"""
import re
import shlex

# `[check-id] GET http://x/` 或原始请求行 `GET /path HTTP/1.1`
_REQ = re.compile(r"(?:^|\]\s*)([A-Z]{3,7})\s+(\S+)")
_HEADER = re.compile(r"^([A-Za-z0-9][A-Za-z0-9\-]*):\s*(.*)$")
_MASKED = ("值不记", "值一律掩码", "掩码")
# 证据里"直接给了一个 URL"的形态（jsmine 的 `来源 JS（点开即取原文）：<url>`、或调用方给 target）
_URL_IN_TEXT = re.compile(r"https?://[^\s、，；）)\]\"'<>]+")


def parse(packets, target=""):
    """尽力从 packets 里抽出 `(method, url, headers, body)`；抽不到的部分为 `None` / `[]` / ""。"""
    text = str(packets or "")
    if not text.strip():
        # 续151：没有 packets 但调用方给了 URL（如 flags 页只有 `url` 列）⇒ 按 GET 复现它。
        t = str(target or "").strip()
        if t.lower().startswith(("http://", "https://")):
            return "GET", t, [], ""
        return None, "", [], ""
    lines = text.splitlines()
    method = url = None
    rest_from = 0
    for i, ln in enumerate(lines):
        m = _REQ.search(ln)
        if not m:
            continue
        method, raw = m.group(1).upper(), m.group(2)
        # 原始请求行会带 `HTTP/1.1` 尾巴
        if len(lines) > 0 and raw.upper().startswith("HTTP/"):
            continue
        url = raw
        rest_from = i + 1
        break
    if not method or not url:
        # 兜底（续151）：证据不是"请求行"形态，而是**直接给了 URL** —— 典型是 jsmine 的
        # `来源 JS（点开即取原文）：https://…`（"取原文"正是要 GET 这个 JS），或调用方传了 target。
        # 抽得到就按 GET 复现它；抽不到仍返回空串（**绝不编命令**）。
        m = _URL_IN_TEXT.search(text)
        if m:
            return "GET", m.group(0), [], ""
        t = str(target or "").strip()
        if t.lower().startswith(("http://", "https://")):
            return "GET", t, [], ""
        return None, "", [], ""
    headers, body, blank = [], "", False
    for ln in lines[rest_from:]:
        if ln.strip().startswith("→") or ln.strip().startswith("body md5"):
            break                                   # 到了"响应摘要"，请求部分到此为止
        if not ln.strip():
            blank = True
            continue
        hm = _HEADER.match(ln)
        if hm and not blank and not any(k in hm.group(2) for k in _MASKED):
            headers.append((hm.group(1), hm.group(2)))
            continue
        if blank:
            body += ln + "\n"
    url = _absolutize(url, headers, target)
    return method, url, headers, body.strip()


def _absolutize(url, headers, target):
    """把原始请求里的 `GET /path` 补成绝对 URL：优先 `Host:` 头，其次调用方给的 `target`。"""
    if url.lower().startswith(("http://", "https://")):
        return url
    host = ""
    for k, v in headers:
        if k.lower() == "host":
            host = v.strip()
            break
    if not host:
        host = str(target or "").strip()
    if not host:
        return url
    if host.lower().startswith(("http://", "https://")):
        return host.rstrip("/") + url
    return "https://" + host.rstrip("/") + url


def to_curl(packets, target=""):
    """生成 curl 命令；抽不到请求行时返回 ""（调用方据此不渲染这一块）。"""
    method, url, headers, body = parse(packets, target)
    if not method or not url:
        return ""
    parts = ["curl -i -sS", "-X " + method, shlex.quote(url)]
    for k, v in headers:
        parts.append("-H " + shlex.quote(f"{k}: {v}"))
    if body:
        parts.append("--data-raw " + shlex.quote(body))
    cmd = " ".join(parts)
    if not headers and not body:
        cmd += "\n# 注：本证据只记了请求行与响应摘要，**未保存请求头/请求体** —— 上面只按方法+URL 复现。"
    return cmd


def to_python(packets, target=""):
    """生成等价的 Python requests 脚本；抽不到请求行时返回 ""。"""
    method, url, headers, body = parse(packets, target)
    if not method or not url:
        return ""
    out = ["import requests", "",
           f"resp = requests.request({method!r}, {url!r},",
           "    headers={"]
    for k, v in headers:
        out.append(f"        {k!r}: {v!r},")
    out.append("    },")
    if body:
        out.append(f"    data={body!r},")
    out.append("    timeout=10, verify=False)")
    out.append("print(resp.status_code, len(resp.content))")
    if not headers and not body:
        out.append("")
        out.append("# 注：本证据只记了请求行与响应摘要，未保存请求头/请求体。")
    return "\n".join(out)
