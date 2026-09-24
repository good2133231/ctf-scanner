"""通用工具：外部命令调用、HTTP 请求（requests 优先、urllib 兜底）、线程池、DNS、文件读写。"""
import ipaddress
import re
import shutil
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from . import throttle as _throttle_mod


# ---------- 外部命令 ----------

def which(tool):
    return shutil.which(str(tool))


def verify_tool(bin_path, flag="-version", timeout=60):
    """进一步校验工具可用性：能执行且响应 -version。

    规避同名命令冲突：pip 安装的 Python httpx 包会在 PATH 留下 httpx.exe，
    但它不是 projectdiscovery 的 httpx，直接调用会失败。
    """
    if not bin_path:
        return False
    rc, _, _ = run_cmd([bin_path, flag], timeout=timeout)
    return rc == 0


def pick_python(configured="python"):
    """选择可用的 Python 解释器（dirmap 等 Python 编写的子工具适配器用）。

    跨平台：Windows 一般叫 python，多数 Linux 发行版只提供 python3；
    配置名不可用时退回当前解释器（正在运行本框架的那个，一定存在）。
    """
    if configured and which(configured):
        return configured
    return sys.executable


def run_cmd(argv, cwd=None, timeout=900, throttle=None):
    """执行外部命令，返回 (returncode, stdout, stderr)。

    命令不存在返回 127；超时返回 124。统一 shell=False，避免注入。

    `throttle` 是任务级限流器（`settings["_throttle"]`，见 `scanner/throttle.py`）：
    传入时本次子进程调用占用一个 `"subprocess"` 名额（并消耗预算），
    预算耗尽 / 被取消时**不启动进程**、直接返回 `(1, "", 原因)`。
    """
    if throttle is None:
        return _do_run_cmd(argv, cwd, timeout)
    try:
        with throttle.slot("subprocess"):
            return _do_run_cmd(argv, cwd, timeout)
    except _throttle_mod.BudgetExhausted:
        return 1, "", "throttle: 请求预算耗尽"
    except _throttle_mod.StopRequested:
        return 1, "", "throttle: 任务已请求停止"


def _do_run_cmd(argv, cwd, timeout):
    try:
        p = subprocess.run([str(a) for a in argv], cwd=str(cwd) if cwd else None,
                           capture_output=True, text=True, errors="replace",
                           timeout=timeout, shell=False)
        return p.returncode, p.stdout or "", p.stderr or ""
    except FileNotFoundError:
        return 127, "", f"executable not found: {argv[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except OSError as e:
        return 1, "", str(e)


# ---------- 域名 ----------

# 多段公共后缀：取"注册域"时避免切错（如 a.b.com.cn 的注册域是 b.com.cn 而非 com.cn）
MULTI_TLD = frozenset({
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "co.uk", "org.uk", "ac.uk",
    "com.hk", "com.tw", "com.au", "com.sg", "co.jp", "co.kr",
})


def base_domain(host):
    """取注册域（粗略版，不查公共后缀列表）：example.com / example.com.cn。

    粗略版会在 `foo.bar.co` 这类双段后缀上切错，但只用它做"同源判断/保护目标自身域"，
    切错只会偏保守，不会误杀；需要精确判定时请引入真正的公共后缀库。
    """
    host = (host or "").lower().strip(".")
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    if ".".join(parts[-2:]) in MULTI_TLD:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


# ---------- 域名形态 ----------

# 至少两段、TLD 纯字母 2-24 位、标签 1-63 位且不以 - 开头/结尾（不查 DNS，只看形态）
_DOMAIN_RE = re.compile(r"^(?=.{4,253}$)"
                        r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$")


def is_domain(text):
    """粗略判断"这串是不是域名"（**只看形态，不查 DNS**）。

    用于把 JS 里挖到的一堆字符串、外部情报返回的 host 字段收敛成真正的域名资产：
    - 至少两段（`localhost` 不算）；TLD 必须纯字母 2-24 位（挡掉 `1.2.3.4`、`a.b` 这类）；
    - 标签 1-63 位、不以 `-` 开头/结尾；总长 ≤253；
    - **IPv4 / IPv6 / 带端口 / 带路径 / 带通配符 / 含空格 一律 False**。

    注意：这是"形态判断"，`is_domain("foo.bar")` 会是 True —— 它不保证域名真实存在，
    真实存在与否由 DNS 解析（`dnsq.resolve_detail`）负责。
    """
    text = str(text or "").strip().lower().strip(".")
    if not text or " " in text or "/" in text or ":" in text or "*" in text:
        return False
    try:
        ipaddress.ip_address(text)        # 裸 IP 不是域名（IP 资产归 portscan/probe）
        return False
    except ValueError:
        pass
    return bool(_DOMAIN_RE.match(text))


# ---------- 路径 ----------

def rel_display(path, base=None):
    """把路径显示成"相对项目根"的形式（POSIX 分隔符）；项目外/空值原样返回。

    所有面向用户的位置（CLI 输出、GUI 表格、日志）都应该走它 ——
    绝对路径会暴露本机目录结构，且 Windows 反斜杠在跨平台日志里也会割裂。
    """
    text = str(path or "")
    if not text:
        return ""
    if base is None:
        from .config import BASE_DIR  # 延迟导入：避免 utils ↔ config 的导入顺序问题
        base = BASE_DIR
    try:
        return Path(text).resolve().relative_to(Path(base).resolve()).as_posix()
    except (ValueError, OSError):
        return text


# ---------- HTTP ----------

def _ua(settings=None):
    """当前生效的 User-Agent。

    `evasion.random_ua` 开启时每个请求随机取一个真实浏览器 UA（见 scanner/evasion.py），
    否则用配置里的固定值。这样"项目本身就相对动态"，不会被风控一眼认出扫描器。
    """
    try:
        from . import evasion
        ua = evasion.pick_ua(settings)
        if ua:
            return ua
    except Exception:
        pass
    if settings:
        return settings.get("http", {}).get("user_agent", "Mozilla/5.0 CTFScanner/0.1")
    return "Mozilla/5.0 CTFScanner/0.1"


def _headers(settings=None, extra=None, auth=False):
    """统一请求头：优先走 evasion.browser_headers（浏览器化 + 可选 XFF 伪装）。

    `auth=True` 时才带上任务的**登录态请求头**（`settings["_auth_headers"]`，由 runner 注入，
    见 scanner/auth.py）。默认不带是刻意的：同一个 `settings` 也会被 crt.sh / FOFA / CISA KEV /
    IP 反查这些**第三方**调用点使用，自动附带等于把目标的会话凭据发给第三方。
    优先级：调用点自己的 `extra` > 登录态 > 浏览器化默认头（POC 里显式写的头应当赢）。
    """
    merged = dict((settings or {}).get("_auth_headers") or {}) if auth else {}
    if extra:
        merged.update(extra)
    try:
        from . import evasion
        hdrs = evasion.browser_headers(settings, merged or None)
        if hdrs:
            return hdrs
    except Exception:
        pass
    hdrs = {"User-Agent": _ua(settings)}
    hdrs.update(merged)
    return hdrs


def _charset_of(content_type):
    """从 Content-Type 里取出 charset（不引 re，保持纯字符串解析）。"""
    for part in (content_type or "").split(";"):
        part = part.strip()
        if part.lower().startswith("charset="):
            return part.split("=", 1)[1].strip().strip("\"'")
    return ""


def _decode_body(raw, content_type):
    """响应体解码：响应头 charset → UTF-8 → GB18030 → 带替换的 UTF-8。

    为什么不直接用 requests 的 `r.text`：当 `Content-Type: text/html` **没有声明 charset** 时，
    requests 按历史行为回退 ISO-8859-1，UTF-8 的中文标题会被解成 `ç»´æ¤ä¸` 这类乱码并原样入库
    （实测站点标题就是这样坏的，且会一路带到 GUI 与报告里）。GB18030 是中文站未声明编码时
    最常见的实际情况，放在 UTF-8 之后作为兜底。
    """
    cs = _charset_of(content_type)
    if cs:
        try:
            return raw.decode(cs, "replace")
        except LookupError:
            pass
    for enc in ("utf-8", "gb18030"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", "replace")


def http_request(url, method="GET", headers=None, data=None, timeout=10,
                 verify=None, allow_redirects=True, settings=None, want_bytes=False,
                 auth=False):
    """统一 HTTP 入口。返回 dict(status, headers, text, length, url) 或 None。

    `want_bytes=True` 时额外返回 `content`（原始字节）——favicon MD5 这类场景需要
    真实字节而不是解码后的文本；默认不返回，避免每个响应都多留一份内存副本。

    `auth=True` 时带上任务的登录态请求头（`settings["_auth_headers"]`）。**只有发往目标侧**的
    调用点才该传 True；第三方接口（crt.sh / FOFA / KEV / IP 反查）保持默认 False，
    否则等于把目标的会话凭据送给第三方。

    requests 缺失时自动退回 urllib（urllib 不校验重定向语义差异，见文档）。
    verify 为 None 时取配置 limits.verify_tls（默认 False：CTF/靶场自签名证书常见，
    默认不校验；需要严格校验时在 settings.yaml 打开该开关）。

    限流（F2）：`settings["_throttle"]` 存在时本次请求占用一个 `"http"` 名额
    （见 `scanner/throttle.py`）。预算耗尽 / 被取消时返回 None —— 语义上按"停止"处理，
    不是网络故障（任务级错误行与状态才是权威）。
    """
    th = (settings or {}).get("_throttle")
    if th is None:
        return _do_http(url, method, headers, data, timeout, verify, allow_redirects,
                        settings, want_bytes, auth)
    try:
        with th.slot("http"):
            return _do_http(url, method, headers, data, timeout, verify,
                            allow_redirects, settings, want_bytes, auth)
    except _throttle_mod.BudgetExhausted:
        return None
    except _throttle_mod.StopRequested:
        return None


def _do_http(url, method, headers, data, timeout, verify, allow_redirects,
             settings, want_bytes, auth):
    if verify is None:
        verify = bool((settings or {}).get("limits", {}).get("verify_tls", False))
    hdrs = _headers(settings, headers, auth=auth)
    try:
        import requests
        try:
            r = requests.request(method, url, headers=hdrs, data=data, timeout=timeout,
                                 verify=verify, allow_redirects=allow_redirects)
            out = {"status": r.status_code, "headers": dict(r.headers),
                   "text": _decode_body(r.content or b"", r.headers.get("Content-Type", "")),
                   "length": len(r.content or b""), "url": r.url}
            if want_bytes:
                out["content"] = r.content or b""
            return out
        except requests.RequestException:
            return None
    except ImportError:
        return _urllib_request(url, method, hdrs, data, timeout, verify,
                               allow_redirects, want_bytes)


def _urllib_request(url, method, headers, data, timeout, verify, allow_redirects=True,
                    want_bytes=False):
    import http.cookiejar
    import ssl
    import urllib.error
    import urllib.request

    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    handlers = [urllib.request.HTTPSHandler(context=ctx),
                urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())]
    if not allow_redirects:
        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, h, newurl):
                return None
        handlers.append(_NoRedirect())
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(url, headers=headers, method=method,
                                 data=data.encode("utf-8") if isinstance(data, str) else data)
    try:
        resp = opener.open(req, timeout=timeout)
    except urllib.error.HTTPError as e:
        resp = e
    except Exception:
        return None
    body = resp.read() or b""
    hdrs_out = dict(resp.headers.items()) if resp.headers else {}
    out = {"status": getattr(resp, "code", 0) or 0, "headers": hdrs_out,
           "text": _decode_body(body, hdrs_out.get("Content-Type", "")),
           "length": len(body), "url": url}
    if want_bytes:
        out["content"] = body
    return out


# ---------- 并发 / DNS ----------

def pool_run(fn, items, workers=10):
    """线程池执行；单个任务异常不影响整体，结果为 None 的丢弃。"""
    results = []
    items = list(items)
    if not items:
        return results
    workers = max(1, min(int(workers), len(items)))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(fn, it): it for it in items}
        for fut in as_completed(futs):
            try:
                r = fut.result()
            except Exception:
                r = None
            if r is not None:   # 只丢"无结果"（None）；falsy 但有效的结果（0/""/[]）不该被吞
                results.append(r)
    return results


def resolve_host(host, timeout=3):
    """域名解析，返回 IP 列表（失败返回空表）。"""
    try:
        socket.setdefaulttimeout(timeout)
        infos = socket.getaddrinfo(host, None)
        return sorted({i[4][0] for i in infos})
    except Exception:
        return []


# ---------- 文件 ----------

def read_lines(path):
    p = Path(path)
    if not p.exists():
        return []
    return [ln.strip() for ln in p.read_text(encoding="utf-8", errors="replace").splitlines()
            if ln.strip()]


def write_text(path, text):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def write_lines(path, lines):
    return write_text(path, "\n".join(str(x) for x in lines) + ("\n" if lines else ""))
