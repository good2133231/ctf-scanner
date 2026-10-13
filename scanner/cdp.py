"""最小 CDP（Chrome DevTools Protocol）客户端：**纯标准库**，只为截图兜底而存在。

为什么要有这个模块（续170，主理人点单「让截图更有兼容性」）：
一次性 `chrome --headless --screenshot=…` 只在**页面 load 完成**时才写 PNG。授权目标里非常
常见的一类页面永远不 load —— 首屏引了一条回源慢/被墙的第三方脚本（主理人那轮 15 个站点里
6 个就是这个形状）。这种页面**任何 Chrome 开关都救不回来**：夹具是"一个正常返回的 HTML +
一条接了连接**就是不回包**的 `<script src>`"，本机 Chrome 154.0.8037.97 上
`--virtual-time-budget=4000`、`--timeout=6000`、old/new headless 四种组合**全部 20 秒 0 字节**。
而走 CDP 时可以先 `Network.setBlockedURLs` **只挡掉挂死的那类第三方埋点/统计域**，再
`Page.captureScreenshot`：同一条夹具从 0 字节变成 **9,636–12,584 字节**的 PNG
（这条差别每次跑全量门禁都验一遍 —— `tests/smoke.py [170]⑦` 起真浏览器跑那个夹具，
并**反过来钉"一次性必须救不回"**，否则那两条断言只是在证明"浏览器能截图"）。
没有它，那批站点**永远**没有截图。

三条边界：
① 只连**我们自己起的那个浏览器**（`127.0.0.1:<随机端口>`），不开放任何监听、不发给目标；
   端口由系统分配 + 只绑回环，浏览器进程用完即杀（`screenshot.capture_cdp()` 的 finally）。
② 只实现用得上的那一小块协议：RFC6455 文本帧 + `call()` 等同名 id 的回包。
   **不引 websocket 第三方库**（本仓的规矩：能标准库就不加依赖）。
③ `tests/browser_e2e.py` 里那份**同形**的手写客户端（约 110 行，`WS` + `CDP`）本应改成
   本模块的消费者（同一份实现写两处，迟早一边修了一边没修 —— AGENTS §5.14）。本轮**没动它**：
   那条路只有 `[7x]` 与 `quality.yml` 会真跑，改动要在门禁里重跑一整轮才验得着；
   已如实登记进 todo 的待办，动它时一并删掉 `base64/hashlib/struct/re/socket`
   那几条只剩它用的 import。
"""
import base64
import hashlib
import json
import os
import re
import socket
import struct
import time
import urllib.request

_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def free_port():
    """要一个系统分配的空闲端口（CDP 端口不许写死：同一台机器会并行跑多次）。"""
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


def ready(debug_port, timeout=1):
    """调试端口是否已经能应答 `/json/version` —— 起完浏览器后的就绪探针，判据只在这一处。

    刻意做成"永不抛"：调用方要的是"现在好了没有"这一个布尔值，把异常形态摊给它等于在
    两处各猜一遍"哪种失败算没起来"（连接被拒 / 超时 / 半个 HTTP 响应都会走到这里）。
    """
    try:
        with urllib.request.urlopen("http://127.0.0.1:%d/json/version" % debug_port,
                                    timeout=timeout):
            return True
    except Exception:
        return False


def ws_url_for(debug_port, timeout=5, target_hint="page"):
    """从 `http://127.0.0.1:<port>/json/version` 取浏览器级 WebSocket 地址。

    只走回环；`/json/list` 是**页面级**目标（多一次竞态：刚 createTarget 完列表可能还没有它），
    浏览器级 ws + `Target.createTarget` / `Target.attachToTarget` 才是稳的那条路。
    """
    with urllib.request.urlopen("http://127.0.0.1:%d/json/version" % debug_port,
                                timeout=timeout) as r:
        info = json.loads(r.read().decode("utf-8", "replace"))
    url = str(info.get("webSocketDebuggerUrl") or "")
    if not url.startswith("ws://127.0.0.1:"):
        raise RuntimeError("CDP 的 ws 地址不是回环形态，拒绝连接：%s" % url[:80])
    return url


class WS:
    """RFC6455 客户端（仅文本帧 + 客户端掩码），够 CDP 用 —— 不引 websocket 第三方库。"""

    def __init__(self, url, timeout=20):
        m = re.match(r"ws://([^:/]+):(\d+)(/.*)$", url)
        if not m:
            raise RuntimeError("不是合法的 ws:// 回环地址：%s" % str(url)[:80])
        host, port, path = m.group(1), int(m.group(2)), m.group(3)
        # ⚠ 只连回环：这个客户端是写给"我们自己起的浏览器"的，指到别处就是给远端开调试口。
        if host not in ("127.0.0.1", "localhost", "::1"):
            raise RuntimeError("只允许连本机调试端口，拒绝 %s" % host[:40])
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        key = base64.b64encode(os.urandom(16)).decode()
        req = (f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\n"
               f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
               "Sec-WebSocket-Version: 13\r\n\r\n")
        self.sock.sendall(req.encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise RuntimeError("WebSocket 握手没有响应")
            buf += chunk
        head, _, rest = buf.partition(b"\r\n\r\n")
        assert b"101" in head.split(b"\r\n")[0], head[:200]
        want = base64.b64encode(hashlib.sha1((key + _GUID).encode()).digest()).decode()
        assert want.encode() in head, "Sec-WebSocket-Accept 不匹配"
        self.buf = rest

    def send(self, text):
        data = text.encode("utf-8")
        n = len(data)
        hdr = bytearray([0x81])
        if n < 126:
            hdr.append(0x80 | n)
        elif n < 65536:
            hdr.append(0x80 | 126)
            hdr += struct.pack(">H", n)
        else:
            hdr.append(0x80 | 127)
            hdr += struct.pack(">Q", n)
        mask = os.urandom(4)
        hdr += mask
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
        self.sock.sendall(bytes(hdr) + masked)

    def _read_exact(self, n):
        while len(self.buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise EOFError("连接关闭")
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def recv(self):
        while True:
            b1, b2 = self._read_exact(2)
            opcode = b1 & 0x0F
            length = b2 & 0x7F
            if length == 126:
                length = struct.unpack(">H", self._read_exact(2))[0]
            elif length == 127:
                length = struct.unpack(">Q", self._read_exact(8))[0]
            payload = self._read_exact(length)
            if opcode == 0x9:                       # ping → pong（CDP 偶尔发）
                self.sock.sendall(b"\x8a\x80" + os.urandom(4))
                continue
            if opcode == 0x8:
                raise EOFError("服务端发来 close")
            if opcode in (0x1, 0x2):
                return payload.decode("utf-8", "replace")

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


class CDP:
    """最小 CDP 客户端：`call()` 发命令、等**同名 id** 的回包，事件（无 id）流走。

    两条不显然的：
    ① 必须把 socket 设成**有限超时**并自己数截止时间 —— 默认的阻塞 recv 会让"浏览器进程
       已经死了"这种情况永远等不到回包；
    ② 事件的 `method` 一律记进 `events`，调用方靠它判断 `Page.loadEventFired` 到没到
       （兜底截图"不等 load，到点就截"这件事需要它）。
    """

    def __init__(self, ws_url, timeout=20):
        self.ws = WS(ws_url, timeout=timeout)
        self.n = 0
        self.events = []

    def call(self, method, params=None, timeout=20, session_id=None):
        self.n += 1
        mid = self.n
        msg = {"id": mid, "method": method, "params": params or {}}
        if session_id:
            msg["sessionId"] = session_id
        self.ws.send(json.dumps(msg))
        deadline = time.time() + timeout
        while time.time() < deadline:
            self.ws.sock.settimeout(max(0.2, deadline - time.time()))
            try:
                got = json.loads(self.ws.recv())
            except (socket.timeout, TimeoutError):
                raise TimeoutError("%s 在 %.0fs 内没有回包" % (method, timeout))
            if got.get("sessionId") and not session_id:
                continue                       # 别的会话的消息，别拿它当这条命令的回包
            if got.get("id") == mid:
                if "error" in got:
                    raise RuntimeError("%s → %s" % (method, got["error"]))
                self.events.append(got)
                return got.get("result", {})
            if got.get("method"):
                self.events.append(got)
        raise TimeoutError("%s 超时" % method)

    def wait_event(self, method, session_id=None, timeout=5):
        """等某个事件（如 `Page.loadEventFired`）出现；到点没等到返回 False（**不抛**）。"""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if any(e.get("method") == method and
                   (not session_id or e.get("sessionId") == session_id) for e in self.events):
                return True
            self.events = [e for e in self.events if e.get("method") != "flushed"]
            try:
                self.ws.sock.settimeout(max(0.1, deadline - time.time()))
                got = json.loads(self.ws.recv())
            except (socket.timeout, TimeoutError, ValueError):
                continue
            if got.get("method"):
                self.events.append(got)
        return False

    def ev(self, expr, timeout=20, session_id=None):
        """求值并按值返回；**必须**把 `exceptionDetails` 抛出来（CDP 把 JS 异常放在正常回包里）。"""
        r = self.call("Runtime.evaluate",
                      {"expression": expr, "returnByValue": True, "awaitPromise": True},
                      timeout=timeout, session_id=session_id)
        if r.get("exceptionDetails"):
            det = r["exceptionDetails"]
            desc = (det.get("exception") or {}).get("description") or det.get("text") or "未知"
            raise RuntimeError("JS 求值异常（%s）：%s" % (expr[:60], str(desc).splitlines()[0]))
        return (r.get("result") or {}).get("value")

    def close(self):
        self.ws.close()
