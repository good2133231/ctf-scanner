"""A10 SSRF 受控回连（**默认关**）：本地 HTTP 回连监听 + 每参数唯一 token。

做什么
------
任务内起一个**本机** HTTP 监听（默认 127.0.0.1，端口由系统分配），为每个候选参数生成
一个唯一 token，把 `http://<回调基址>/<token>` 注入该参数；若监听端收到携带这个 token
的请求，就说明**目标服务端真的按我们给的地址发起了出网请求** —— 这是"存在 SSRF"的
直接证据，比"带内网地址看响应时间差"可靠得多，也不依赖任何目标侧的错误回显。

不做什么（红线，刻意如此，改动前请先读）
--------------------------------------
- **不拿这个通道去打内网地址**。`http://127.0.0.1:8080/admin`、`http://169.254.169.254/…`
  这类 payload 属于"利用 SSRF 去探测内网"，越过了本项目"只做初筛、非破坏性"的边界。
  本模块只证明"服务端会出网"，**不替你探测它能到哪儿**。
- **不做延时型判定**（不靠响应时间差猜端口开放），理由同 `owasp/checks.py` 的布尔盲注段。
- **不提交页面上的表单**：表单提交是写操作风险（你并不知道那个表单是"搜索"还是"新建用户"），
  所以这里只把表单里的**字段名**当作候选参数名，注入**一律走 GET 查询串**。
- 只诱使目标发**一个** GET，不做任何循环/轰炸。

局限（务必先看，别指望它在所有环境都有结果）
------------------------------------------
- 本机监听只在**目标能回访扫描机**时才有效。扫描机在 NAT 后 / 云主机没有公网 IP /
  目标出网被出口防火墙拦掉时，一条回连都收不到 —— 这是**环境限制，不是本模块的缺陷**。
- 需要外部可达的回调时填 `ssrf.callback_base`（自建 OOB 服务 / 反向代理地址）。
  填了之后本模块**不会**伪造命中：我们读不到你的 OOB 服务，只把注入过的 token 写进
  任务日志，由你在那侧核对（宁可不报，也不谎报）。
- 监听端口**用完即关**（`close()` 或上下文管理器）；等待回连的轮询支持传入
  `stop` 回调，任务请求停止时立即退出，不留线程泄漏。
"""
import re
import secrets
import socket
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .utils import http_request

# 内置候选参数名：都是实战里最常见的"喂 URL 给它"的参数。
# 真正决定覆盖面的是页面表单里的字段名（`form_field_names`），这份只是兜底。
DEFAULT_PARAMS = (
    "url", "uri", "link", "src", "source", "image", "img", "target",
    "feed", "api", "proxy", "next", "redirect", "callback", "webhook",
    "fetch", "load", "file", "path", "dest", "destination", "site", "page",
    "u", "q", "ref", "to", "open", "download",
)

DEFAULT_HOST = "127.0.0.1"
DEFAULT_WAIT = 6.0          # 注入完成后等回连的秒数（非破坏性：只是等，不再发请求）
DEFAULT_MAX_PARAMS = 12
DEFAULT_TIMEOUT = 10

# 回连响应体：故意写成一眼能认出来的常量，便于用户在自己的代理日志里搜
CALLBACK_BODY = b"ctfscanner-ssrf-callback-ok"

_INPUT_RE = re.compile(r"<(?:input|textarea|select|button)\b[^>]*>", re.I)
_NAME_RE = re.compile(r"\bname\s*=\s*([\"'])([^\"']*)\1", re.I)
_TYPE_RE = re.compile(r"\btype\s*=\s*([\"'])([^\"']*)\1", re.I)
_SKIP_TYPES = frozenset({"submit", "button", "reset", "image", "file"})
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{8,64}$")


# ---------- 配置 ----------

def _cfg(settings):
    return (settings or {}).get("ssrf", {}) or {}


def enabled(settings):
    """回连能力是否开启。默认关 —— 它会诱使目标向扫描机发起出网请求，属于需要用户点头的行为。"""
    return _cfg(settings).get("enabled") is True


def callback_base(settings):
    """外部可达的回调基址（如 `http://oob.example`）。留空 = 用本机监听地址。"""
    return str(_cfg(settings).get("callback_base") or "").strip().rstrip("/")


def wait_seconds(settings):
    try:
        return max(0.0, float(_cfg(settings).get("wait_seconds") or DEFAULT_WAIT))
    except (TypeError, ValueError):
        return DEFAULT_WAIT


def max_params(settings):
    try:
        return max(1, int(_cfg(settings).get("max_params") or DEFAULT_MAX_PARAMS))
    except (TypeError, ValueError):
        return DEFAULT_MAX_PARAMS


def listen_host(settings):
    return str(_cfg(settings).get("host") or DEFAULT_HOST).strip() or DEFAULT_HOST


def listen_port(settings):
    """监听端口；0 = 交给系统分配（默认，避免与本机其它服务抢端口）。"""
    try:
        return max(0, int(_cfg(settings).get("port") or 0))
    except (TypeError, ValueError):
        return 0


# ---------- token ----------

def new_token():
    """每参数唯一的 token（URL 安全、不可预测）。

    为什么必须"每参数唯一"：命中要能回指到"是哪个参数触发的出网请求"，
    否则证据里只能写"有回连"，人工没法定位；共用 token 还会让"一个参数回连"
    看起来像"所有参数都回连"。
    """
    return secrets.token_hex(8)


def token_of_path(path):
    """从请求路径里取出 token（`/<token>` 的第一段，容忍多余的查询串与斜杠）。"""
    text = str(path or "").split("?", 1)[0].split("#", 1)[0]
    seg = [s for s in text.split("/") if s]
    return seg[0] if seg else ""


def payload_url(base, token):
    """拼出注入用的回调地址：`http://<base>/<token>`。"""
    return f"{str(base).rstrip('/')}/{token}"


# ---------- 候选参数 ----------

def form_field_names(html):
    """从页面 HTML 里提取表单字段名（去重、保序、小写）。

    只看 `<input>/<textarea>/<select>/<button>` 的 `name` 属性；`submit/button/reset/
    image/file` 这些点了才会产生副作用的控件一律丢掉（我们不做写操作）。
    """
    out = []
    for tag in _INPUT_RE.findall(str(html or "")):
        kind = _TYPE_RE.search(tag)
        if kind and kind.group(2).strip().lower() in _SKIP_TYPES:
            continue
        m = _NAME_RE.search(tag)
        if not m:
            continue
        name = m.group(2).strip().lower()
        if name and name not in out:
            out.append(name)
    return out


def candidate_params(url, settings, logger=None, stop=None):
    """汇总要注入的候选参数名：URL 里已有的 + 页面表单里的 + 内置兜底清单。

    顺序是"页面真实存在的字段优先" —— 目标是授权范围内的业务系统时，它自己的表单字段
    才是最可能被服务端拿去发请求的地方，内置清单只是抓不到页面时的兜底。
    """
    cap = max_params(settings)
    names, seen = [], set()

    def _add(n):
        n = str(n or "").strip().lower()
        if n and n not in seen:
            seen.add(n)
            names.append(n)

    try:
        for k in urllib.parse.parse_qs(urllib.parse.urlparse(str(url)).query):
            _add(k)
    except (ValueError, AttributeError):
        pass
    if callable(stop) and stop():
        return names[:cap]
    try:
        resp = http_request(url, timeout=int((settings or {}).get("limits", {})
                                             .get("http_timeout", DEFAULT_TIMEOUT)),
                            settings=settings, auth=True)
    except Exception as e:                       # 取页面失败只影响"候选名单"，不该中断检查
        if logger:
            logger.info(f"[ssrf] 抓取页面失败，只用内置参数清单：{e}")
        resp = None
    if resp:
        for n in form_field_names(resp.get("text") or ""):
            _add(n)
    for n in DEFAULT_PARAMS:
        _add(n)
    return names[:cap]


# ---------- 回连监听 ----------

class CallbackHit(dict):
    """一条回连记录（dict 形态，便于直接进证据/JSON）：token/path/method/ua/ip/time。"""


class _Handler(BaseHTTPRequestHandler):
    """回连处理器：任何方法、任何路径都记一笔再回 200。

    不区分方法是因为"服务端会出网"这件事与它用什么方法无关；记录 UA 与来源端口
    则是为了让人工能一眼看出"是目标服务端来的，还是某个缓存/代理/安全扫描器来的"。
    """
    protocol_version = "HTTP/1.1"
    server_version = "CTFScannerCallback"
    sys_version = ""

    def log_message(self, *args):
        pass                                      # 靶场式监听，不打逐请求日志

    def _record(self, method):
        token = token_of_path(self.path)
        self.server.record({
            "token": token, "path": str(self.path or ""), "method": method,
            "ua": str(self.headers.get("User-Agent") or ""),
            "ip": (self.client_address or ("", 0))[0],
            "port": (self.client_address or ("", 0))[1],
            "time": time.strftime("%H:%M:%S"),
        })
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(CALLBACK_BODY)))
        self.end_headers()
        try:
            self.wfile.write(CALLBACK_BODY)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self):
        self._record("GET")

    def do_HEAD(self):
        self._record("HEAD")

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except (TypeError, ValueError):
            length = 0
        if length > 0:                            # 读掉请求体，否则客户端可能报连接重置
            try:
                self.rfile.read(min(length, 65536))
            except (OSError, ValueError):
                pass
        self._record("POST")


class CallbackListener:
    """本机回连监听（上下文管理器保证关闭）。

    `port=0` 时由系统分配端口，起完再用 `base_url` 拿真实地址 —— 硬编码高端口会与
    本机其它服务抢端口，分配式没有这个问题。
    """

    def __init__(self, host=DEFAULT_HOST, port=0):
        self.host = str(host or DEFAULT_HOST)
        self._wanted_port = int(port or 0)
        self.port = 0
        self._hits = []
        self._lock = threading.Lock()
        self._server = None
        self._thread = None

    @property
    def base_url(self):
        return f"http://{self.host}:{self.port}"

    def start(self):
        """起监听；端口被占用等异常原样抛出（调用方按"本次不判定"处理）。"""
        srv = ThreadingHTTPServer((self.host, self._wanted_port), _Handler)
        srv.daemon_threads = True
        srv.record = self.record          # 处理器通过 server 回写命中
        self.port = srv.server_address[1]
        self._server = srv
        self._thread = threading.Thread(target=srv.serve_forever,
                                        name="ssrf-callback", daemon=True)
        self._thread.start()
        return self

    def record(self, hit):
        with self._lock:
            self._hits.append(CallbackHit(hit))

    def hits(self):
        with self._lock:
            return [CallbackHit(h) for h in self._hits]

    def hits_for(self, token):
        return [h for h in self.hits() if h.get("token") == token]

    def wait(self, seconds=DEFAULT_WAIT, stop=None, poll=0.1):
        """等待**任意**回连；可被 `stop()` 提前打断（协作式取消）。

        返回命中条数。等的过程中本模块不再向目标发任何请求 —— 只是干等。
        """
        end = time.time() + max(0.0, float(seconds))
        while time.time() < end:
            if callable(stop) and stop():
                break
            if self.hits():
                return len(self.hits())
            time.sleep(poll)
        return len(self.hits())

    def close(self):
        """关闭监听并回收线程（可重复调用；没起过监听时是空操作）。

        线程必须**先取到局部变量再清空**：写成 `srv, self._server, self._thread = ..., None, None`
        会让下面那句 `if self._thread is not None: join()` 永远为假（死代码），
        代码与注释宣称的行为就对不上了。清空字段是为了让 `close()` 幂等，
        与"把线程 join 掉"是两件事，不能混在一条赋值里。
        """
        srv, th = self._server, self._thread
        self._server, self._thread = None, None
        if srv is None:
            return
        try:
            srv.shutdown()          # 阻塞到 serve_forever 退出
        except Exception:
            pass
        try:
            srv.server_close()
        except Exception:
            pass
        if th is not None:
            th.join(timeout=2)

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.close()
        return False


def free_port(host=DEFAULT_HOST):
    """取一个当前空闲的端口（仅用于测试/诊断，监听本身请用 port=0）。"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, 0))
        return s.getsockname()[1]
