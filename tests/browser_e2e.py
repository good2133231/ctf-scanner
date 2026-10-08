# -*- coding: utf-8 -*-
"""真浏览器端到端（E2E）：用无头 Chrome + 手写 CDP 驱动**真实交互**，补上多轮遗留的短板。

为什么必须单独一个文件、且必须起真进程：
`tests/smoke.py` 对 GUI 的断言走 Flask `test_client` —— 那只能看**服务端吐出的 HTML 文本**。
以下三类问题它一律测不出，前面每一轮都只能写"真浏览器端到端没跑过"：
  ① 点击后 **DOM 真的变了没**（分页"下一页"、页签切换、面板折叠）；
  ② **表单到底提交去了哪**（POC 表里的 `<button class="toggle">` 会不会误把外层筛选表单提交掉）；
  ③ **浏览器侧状态**（`window.open` 被调了几次、`localStorage` 有没有持久化）。
本文件因此自己起**真实 Flask 服务进程**（不是 test_client）+ 真实无头 Chrome，用 CDP 真点、真读。

约束（与仓库一致，违反即改坏项目）：
  * **只用标准库**（`socket` 手写 RFC6455 WebSocket 连 CDP），不新增任何依赖（离线强制）；
  * 找不到浏览器 → **跳过**（`ok=False` + 明确原因，绝不假绿、绝不抛异常）；
  * 临时产物（临时库 / 日志 / user-data-dir / 引导脚本）全部落在 `%TEMP%`，`try/finally` 回收；
  * 端口一律用系统分配的空闲端口，不留常驻进程。

单跑：`py -3 tests/browser_e2e.py`（退出码 0=全过 / 1=有断言失败 / 2=跳过）。
"""
import base64
import hashlib
import json
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# `--headless=new` 在 Windows 上拿不到 stdout（早期探针踩过），所以下面固定用 `--headless=old`。
_BROWSER_LEAF = (("Google", "Chrome", "Application", "chrome.exe"),
                 ("Microsoft", "Edge", "Application", "msedge.exe"))


def _browser_candidates():
    """枚举常见安装位置的 Edge / Chrome（本机实测两者都能被 CDP 驱动）。

    **刻意不写字面盘符路径**：`tests/smoke.py` 的源码红线里有一条"不得写死盘符路径"
    （这类写法在 Linux 上必然翻车，而 tests/ 也在扫描范围内）。改成从环境变量拼装，
    顺带能覆盖装在非系统盘的机器；POSIX 侧再补几个常见名字，这条口径不该只在 Windows 成立。
    """
    out = []
    for root in (os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)"),
                 os.environ.get("LOCALAPPDATA")):
        if not root:
            continue
        out.extend(str(Path(root).joinpath(*leaf)) for leaf in _BROWSER_LEAF)
    out += ["/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser",
            "/snap/bin/chromium"]
    return out


# 造数口径（断言里的"期望值"全部由这里派生 —— 证伪自检就是改这里的值看断言会不会红）。
_DIRS_TOTAL = 60          # 目录行数（> 每页 50，才有"下一页"）
_PAGE_SIZE = 50           # PAGE_SIZES 里最小的合法每页数
_SITES_TOTAL = 60         # 任务的站点数（> CONFIG 里每页 50，页签分页才有下一页；>20 才触发批量打开上限）
_FILTER_Q = "e2e-42"      # 服务端筛选用的关键字（只应命中 1 行）
_OPEN_CAP = 20            # 与 gui/static/app.js::OPEN_SITES_MAX 一致，改了模板要同步改这里

# 引导脚本：起**真实** Flask 服务，端口交给系统分配后写进 PORTFILE 让本进程读回。
# 刻意不写死端口：固定端口会与别的实例/服务撞车（仓库里 `_port_free` 的注释讲过这个坑）。
_GUI_BOOT = '''# -*- coding: utf-8 -*-
"""E2E 用 GUI 引导脚本（临时文件，跑完即删）：起真实 Werkzeug 服务，端口由系统分配。"""
import os
import sys

sys.path.insert(0, os.environ["CTFSCANNER_E2E_REPO"])
from gui.app import app                                  # import 期 create_app() 建表 / 同步 POC 注册表
from werkzeug.serving import make_server

srv = make_server("127.0.0.1", 0, app, threaded=True)    # 0 = 系统分配空闲端口
with open(os.environ["CTFSCANNER_E2E_PORTFILE"], "w", encoding="utf-8") as fh:
    fh.write(str(srv.server_port))
# 续108：登录页现在在**所有凭据分支之前**都要过验证码（答案只存服务端内存，页面/cookie 读不到，
#   这正是它存在的意义）。E2E 要验的是"真浏览器提交表单 → 真登录"，所以让这份**测试专用的引导
#   脚本**把自己刚发出的码抄进一个临时文件 —— 生产代码里没有任何"免码/固定码"的口子。
_capfile = os.environ.get("CTFSCANNER_E2E_CAPFILE") or ""
if _capfile:
    from scanner import captcha as _cap_boot
    _issue_orig = _cap_boot.issue

    def _issue_rec(_n=4, _ttl=None):
        _tok, _code = _issue_orig(_n)
        with open(_capfile, "a", encoding="utf-8") as _fh:
            print(_code, file=_fh)                      # 一行一张码，绕开三层转义
        return _tok, _code

    _cap_boot.issue = _issue_rec

srv.serve_forever()
'''


def _rel(p):
    """按仓库约定把路径显示成相对路径 —— 日志里**不出现盘符绝对路径**。

    这里不引 `scanner.utils.rel_display()`：那个函数只对"项目内"的路径有意义，而本文件的
    临时产物在 `%TEMP%` 下（必然落在项目外），引它反而要额外处理异常分支；用 `os.path.relpath`
    统一处理，落到项目外时也只显示 `..\\<相对段>`，不会漏出盘符。
    """
    try:
        return Path(os.path.relpath(str(p), str(ROOT))).as_posix()
    except ValueError:          # 跨盘符（如临时目录在 D:）→ 只留末段名
        return Path(str(p)).name


def find_browser():
    """找可用的无头浏览器；找不到返回空串（调用方据此**跳过**）。"""
    env = (os.environ.get("CTFSCANNER_CHROME") or os.environ.get("CHROME_PATH") or "").strip()
    for cand in ([env] if env else []) + _browser_candidates():
        if cand and os.path.isfile(cand):
            return cand
    return ""


def _free_port():
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


class WS:
    """RFC6455 客户端（仅文本帧 + 客户端掩码），够 CDP 用 —— 不引 websocket 第三方库。"""

    def __init__(self, url, timeout=20):
        m = re.match(r"ws://([^:/]+):(\d+)(/.*)$", url)
        host, port, path = m.group(1), int(m.group(2)), m.group(3)
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        key = base64.b64encode(os.urandom(16)).decode()
        req = (f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\n"
               f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
               "Sec-WebSocket-Version: 13\r\n\r\n")
        self.sock.sendall(req.encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            buf += self.sock.recv(4096)
        head, _, rest = buf.partition(b"\r\n\r\n")
        assert b"101" in head.split(b"\r\n")[0], head[:200]
        want = base64.b64encode(hashlib.sha1(
            (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
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
    """最小 CDP 客户端：`call()` 发命令等同名 id 的回包；事件（无 id）丢弃。"""

    def __init__(self, ws_url):
        self.ws = WS(ws_url)
        self.n = 0

    def call(self, method, params=None, timeout=20):
        self.n += 1
        mid = self.n
        self.ws.send(json.dumps({"id": mid, "method": method, "params": params or {}}))
        deadline = time.time() + timeout
        while time.time() < deadline:
            msg = json.loads(self.ws.recv())
            if msg.get("id") == mid:
                if "error" in msg:
                    raise RuntimeError(f"{method} → {msg['error']}")
                return msg.get("result", {})
        raise TimeoutError(method)

    def ev(self, expr, timeout=20):
        """求值并**按值返回**（数组/对象会被 JSON 化，方便直接断言）。

        ⚠️ 必须把 `exceptionDetails` 抛出来：CDP 把 JS 异常放在**正常回包**的
        `exceptionDetails` 里（不是 `error` 字段），不检查就会被静默吞掉 ——
        实测踩过一次：把裸选择器 `"#btn"` 当表达式传给 `.click()`，求值报
        `not a function`，但断言只看到"钩子没被调用"，白查半天。
        """
        r = self.call("Runtime.evaluate",
                      {"expression": expr, "returnByValue": True, "awaitPromise": True},
                      timeout=timeout)
        if r.get("exceptionDetails"):
            det = r["exceptionDetails"]
            desc = (det.get("exception") or {}).get("description") or det.get("text") or "未知"
            raise RuntimeError(f"JS 求值异常（{expr[:60]}）：{str(desc).splitlines()[0]}")
        return r.get("result", {}).get("value")

    def close(self):
        self.ws.close()


class Page:
    """页面级便捷封装：导航/重载/点击都在这里，断言层只调它。"""

    def __init__(self, cdp):
        self.cdp = cdp

    def ev(self, expr, timeout=20):
        return self.cdp.ev(expr, timeout)

    def href(self):
        """当前 URL；导航瞬间求值会报错（上下文被销毁），这时返回 None 让调用方重试。"""
        try:
            return self.cdp.ev("location.href")
        except Exception:                                       # noqa: BLE001
            return None

    def wait_ready(self, timeout=25):
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                if self.cdp.ev("document.readyState") == "complete":
                    return True
            except Exception:                                   # noqa: BLE001
                pass
            time.sleep(0.15)
        return False

    def navigate(self, url, timeout=30):
        """打开 URL 并等到**新文档**加载完（比对去掉锚点后的 href，避免把旧文档当新文档）。"""
        self.cdp.call("Page.navigate", {"url": url}, timeout=timeout)
        time.sleep(0.4)
        want = url.split("#")[0]
        deadline = time.time() + timeout
        while time.time() < deadline:
            href = self.href()
            if href and href.split("#")[0] == want:
                try:
                    if self.cdp.ev("document.readyState") == "complete":
                        return href
                except Exception:                               # noqa: BLE001
                    pass
            time.sleep(0.15)
        return self.href() or ""

    def reload(self, timeout=30):
        self.cdp.call("Page.reload", {"ignoreCache": True}, timeout=timeout)
        time.sleep(0.4)
        self.wait_ready(timeout)

    def click_js(self, expr, settle=0.35):
        """点一下表达式的元素（真实事件派发）—— 不涉及导航的点击用它。"""
        self.ev(f"({expr}).click()")
        time.sleep(settle)

    def click_nav(self, expr, timeout=30):
        """点一下会触发**导航**的元素（链接/提交按钮），返回变化后的 href。"""
        old = self.href()
        self.ev(f"({expr}).click()")
        deadline = time.time() + timeout
        while time.time() < deadline:
            href = self.href()
            if href and href != old:
                try:
                    if self.cdp.ev("document.readyState") == "complete":
                        return href
                except Exception:                               # noqa: BLE001
                    pass
            time.sleep(0.15)
        return self.href() or ""


class _Report:
    """断言收集器：每条检查都打印「期望 vs 实到」，失败不中断其余检查（一次跑完暴露全部问题）。"""

    def __init__(self):
        self.n = 0
        self.fails = []

    def check(self, name, cond, detail=""):
        self.n += 1
        if cond:
            print(f"    [OK] {name}" + (f" —— {detail}" if detail else ""))
        else:
            self.fails.append(f"{name}：{detail}")
            print(f"    [!!] {name} —— {detail}")
        return bool(cond)

    def eq(self, name, got, want):
        return self.check(name, got == want, f"期望 {want!r}，实到 {got!r}")


_E2E_USER = "e2e-admin"
_E2E_PW = "E2e#smoke-only-117"


def _seed_db():
    """先造好数据再起 GUI 进程 —— 避免"测试进程与 GUI 进程同时写库"的并发窗口。

    造的是**能被断言精确复算**的最小集合：60 条目录（每页 50 → 2 页）+ 60 个站点（触发
    批量打开上限 20）。目录的 `length` 逐行不同 —— 否则会被 `/dirs` 的"同站点+状态+大小"
    折叠规则合并，分页行数就不是 50/10 了（断言必须建立在"不会被折叠"的数据上）。
    """
    from scanner import db, users as _eu                    # 在 env 设好之后再导入，锁定临时库
    db.init_db()
    # 造一个管理员账号：e2e 走的是**真表单登录**，没有账号就连登录页都过不去
    if not _eu.get_by_name(_E2E_USER):
        ok, msg = _eu.create_user(_E2E_USER, _E2E_PW, _eu.ROLE_ADMIN, must_change=False)
        assert ok, f"e2e 造管理员失败：{msg}"
    tid = db.create_task("E2E-浏览器端到端", "http://e2e.local", ["dirscan"])
    db.update_task(tid, status="done", progress=100, current_stage="dirscan")
    db.insert_dirs(tid, [{"site_url": "http://e2e.local", "path": f"/e2e-{i:02d}",
                          "status": 200, "length": 1000 + i, "title": f"目录{i}"}
                         for i in range(_DIRS_TOTAL)])
    db.insert_sites(tid, [{"url": f"http://e2e.local/s{i:03d}", "host": "e2e.local",
                           "port": "80", "status": 200, "title": f"站点{i}",
                           "length": 500 + i, "server": "nginx", "tech": "nginx",
                           "source": "probe"} for i in range(_SITES_TOTAL)])
    # 续126：详情页新加的第 11 个页签「flag 候选」要有**能被断言**的数据。
    # 第二条刻意是 HTML 载荷 —— 页签必须把它当**文本**渲染（真浏览器里查"没有真的 img 元素"，
    # 这比在 test_client 里搜转义字符串更接近用户实际看到的东西）。
    db.insert_flag(tid, {"value": "E2e_Browser_Flag", "kind": "flag", "source": "dir",
                         "url": "http://e2e.local/.env", "context": "flag{E2e_Browser_Flag}"})
    db.insert_flag(tid, {"value": "<img src=x onerror=alert(1)>", "kind": "regex",
                         "source": "probe", "url": "http://e2e.local/",
                         "context": "flag{<img src=x onerror=alert(1)>}"})
    # 续93：再建一个**运行中**的任务 —— 任务列表页的轮询只该问"未结束"的行，这条就是 [8] 的探针；
    # 上面那个 done 的任务**必须不被**轮询（否则又回到"终态行也一直问"的旧写法）。
    tid_run = db.create_task("E2E-轮询中", "http://e2e-run.local", ["probe"])
    db.update_task(tid_run, status="running", progress=37, current_stage="probe")
    return tid, tid_run


def _start_gui(env, work):
    """起真实 Flask 服务进程，返回 `(port, proc)`；就绪判据 = 端口文件 + `/login` 可访问。"""
    boot = work / "_gui_boot.py"
    portfile = work / "port.txt"
    boot.write_text(_GUI_BOOT, encoding="utf-8")
    capfile = work / "cap.txt"                 # 服务端每发一张码追加一行（见 _GUI_BOOT 末尾）
    _CAPFILE["path"] = capfile
    errlog = open(work / "gui.err", "wb")                   # 不用 PIPE：没人读会写满缓冲把服务卡死
    child_env = dict(env, CTFSCANNER_E2E_REPO=str(ROOT), CTFSCANNER_E2E_PORTFILE=str(portfile),
                     CTFSCANNER_E2E_CAPFILE=str(capfile))
    proc = subprocess.Popen([sys.executable, str(boot)], env=child_env, cwd=str(ROOT),
                            stdout=subprocess.DEVNULL, stderr=errlog)
    port = 0
    deadline = time.time() + 60                             # import 期要同步 300+ 个 POC，给足时间
    while time.time() < deadline:
        if portfile.exists():
            txt = portfile.read_text(encoding="utf-8").strip()
            if txt.isdigit():
                port = int(txt)
                break
        if proc.poll() is not None:
            break
        time.sleep(0.2)
    if not port:
        err = ""
        try:
            err = (work / "gui.err").read_text(encoding="utf-8", errors="replace")[-600:]
        except OSError:
            pass
        raise RuntimeError(f"GUI 进程没能在 60s 内就绪（{err.strip() or '无 stderr 输出'}）")
    base = f"http://127.0.0.1:{port}"
    for _ in range(80):
        try:
            urllib.request.urlopen(base + "/login", timeout=2).read()
            return port, proc
        except Exception:                                   # noqa: BLE001
            time.sleep(0.25)
    raise RuntimeError("GUI 端口起来了但 /login 打不开")


def _start_chrome(browser, profile, work):
    """起无头 Chrome 并连上 CDP，返回 `(cdp, proc)`。"""
    port = _free_port()
    proc = subprocess.Popen([browser, "--headless=old", "--disable-gpu", "--no-first-run",
                             "--no-default-browser-check", "--disable-extensions",
                             "--disable-background-networking",
                             f"--remote-debugging-port={port}",
                             f"--user-data-dir={profile}", "--window-size=1200,900",
                             "about:blank"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{port}"
    for _ in range(120):
        try:
            urllib.request.urlopen(base + "/json/version", timeout=1).read()
            break
        except Exception:                                   # noqa: BLE001
            if proc.poll() is not None:
                raise RuntimeError("无头浏览器启动即退出")
            time.sleep(0.25)
    else:
        raise RuntimeError("CDP 端口没起来")
    with urllib.request.urlopen(base + "/json/list", timeout=5) as r:
        targets = json.loads(r.read().decode())
    target = next(t for t in targets if t.get("type") == "page")
    cdp = CDP(target["webSocketDebuggerUrl"])
    cdp.call("Runtime.enable")
    cdp.call("Page.enable")
    return cdp, proc


def _kill_tree(proc):
    """连同子进程一起收掉（Chrome 会派生一堆子进程，只 terminate 父进程收不干净）。"""
    if proc is None:
        return
    try:
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
    except Exception:                                       # noqa: BLE001
        try:
            proc.kill()
        except Exception:                                   # noqa: BLE001
            pass
    try:
        proc.wait(timeout=10)
    except Exception:                                       # noqa: BLE001
        pass


_CAPFILE = {"path": None}        # 单进程单 GUI，一个槽够了


def _cap_code(want=1, deadline=10.0):
    """取引导脚本抄录的第 `want` 张服务端验证码；超时返回空串（调用方据此**明确失败**，不假绿）。"""
    p = _CAPFILE.get("path")
    if not p:
        return ""
    end = time.time() + deadline
    while time.time() < end:
        try:
            txt = Path(p).read_text(encoding="utf-8", errors="replace")
        except OSError:
            txt = ""
        _codes = [x.strip() for x in txt.splitlines() if x.strip()]
        if len(_codes) >= want:
            return _codes[want - 1]
        time.sleep(0.05)
    return ""


def _login(page, base, user, password):
    """走**真实登录表单**拿到会话（续117：登录只有账号一条路，配置文件里没有任何凭据）。

    刻意不伪造 Cookie / 不塞 session：要验的就是"浏览器提交表单 → 服务端下发会话 → 后续页面
    不再 302"这条链路；伪造会话等于把要测的东西绕过去。

    续108：验证码门在所有凭据分支之前，任何形态的提交都**要填码** —— 旧版只填
      口令就提交，从那一刻起这条链路必然停在登录页（表现为整组断言红）。码取自 capfile
      （服务端自己抄录的那份）：页面仍然真读图、真填框、真提交，一点没绕。
    """
    page.navigate(base + "/login")
    has = page.ev("!!document.querySelector('input[name=password]')")
    if not has:
        raise RuntimeError("登录页没有口令输入框")
    if not page.ev("!!document.querySelector('input[name=captcha]')"):
        raise RuntimeError("登录页没有验证码输入框（续108 起两种模式都必须渲染）")
    _code = _cap_code()
    if not _code:
        raise RuntimeError("没取到服务端下发的验证码（capfile 超时）")
    page.ev(f"document.querySelector('input[name=username]').value={json.dumps(user)}")
    page.ev(f"document.querySelector('input[name=captcha]').value={json.dumps(_code)}")
    page.ev(f"document.querySelector('input[name=password]').value={json.dumps(password)}")
    href = page.click_nav("document.querySelector('.login-box form button[type=submit]')")
    return href


def _run_checks(page, base, rep, cred, tid, port, tid_run):
    """登录前提 + 8 条交互的断言（每条都是"点完之后 DOM/URL/钩子真的变了"，不是页面里有某字符串）。"""

    # ---------- [1] 登录（后续所有页面的前提；也是"302 墙"是否被真正推开的证据） ----------
    href = _login(page, base, cred[0], cred[1])
    rep.check("[1] 真表单登录后被重定向到仪表盘", (href or "").rstrip("/").endswith(f":{port}"),
              f"登录后 href={href!r}")
    rep.check("[1] 仪表盘侧边栏已渲染（非登录页/非 302）",
              page.ev("!!document.querySelector('nav.side-nav')") is True)

    # ---------- [2] 分页"下一页"真点下去会换页（服务端分页） ----------
    page.navigate(f"{base}/dirs?size={_PAGE_SIZE}")
    cnt1 = page.ev("document.querySelectorAll('#tbl-all-dirs tbody tr').length")
    txt1 = page.ev("document.querySelector('.pager').textContent") or ""
    rep.eq("[2] 第1页行数", cnt1, _PAGE_SIZE)
    rep.check("[2] 第1页分页条显示 1/2 页", "第 1 / 2 页" in txt1, f"pager={txt1.strip()!r}")
    href2 = page.click_nav(
        "[...document.querySelectorAll('.pager a')].find(a=>a.textContent.includes('下一页'))")
    cnt2 = page.ev("document.querySelectorAll('#tbl-all-dirs tbody tr').length")
    txt2 = page.ev("document.querySelector('.pager').textContent") or ""
    rep.check("[2] 点「下一页」后 URL 带 page=2", "page=2" in (href2 or ""),
              f"href={href2!r}")
    rep.eq("[2] 第2页行数", cnt2, _DIRS_TOTAL - _PAGE_SIZE)
    rep.check("[2] 第2页分页条显示 2/2 页", "第 2 / 2 页" in txt2, f"pager={txt2.strip()!r}")

    # ---------- [3] 服务端筛选表单提交后 URL / 结果都正确 ----------
    page.navigate(f"{base}/dirs?size={_PAGE_SIZE}")
    page.ev(f"document.querySelector('form.filters input[name=q]').value={json.dumps(_FILTER_Q)}")
    href3 = page.click_nav("document.querySelector('form.filters button[type=submit]')")
    cnt3 = page.ev("document.querySelectorAll('#tbl-all-dirs tbody tr').length")
    body3 = page.ev("document.querySelector('#tbl-all-dirs tbody').textContent") or ""
    rep.check("[3] 提交后 URL 带 q=e2e-42", f"q={_FILTER_Q}" in (href3 or ""), f"href={href3!r}")
    rep.eq("[3] 筛选后只剩 1 行", cnt3, 1)
    rep.check("[3] 命中行就是 /e2e-42", "e2e-42" in body3, f"tbody={body3.strip()[:80]!r}")
    rep.check("[3] 未命中的 /e2e-07 已不在结果里", "/e2e-07" not in body3)

    # ---------- [4]「批量打开」：一次手势只放行一个 window.open，其余必须给真链接 ----------
    #   续112：旧断言"window.open 恰好 20 次"测的其实是一个在真浏览器里**根本不可能发生**的场景
    #   （钩子把 window.open 换成永远返回真值的假函数），所以它一直在绿，而用户实际只能开一个。
    #   现在验的是修复后的真实形态：1 个直接开 + 其余 N-1 个渲染成带 rel=noopener 的真链接。
    page.navigate(f"{base}/tasks/{tid}#sites")
    page.ev("window.__opened=[]; window.open=function(u){window.__opened.push(String(u));"
            "return {};};")
    page.ev("document.querySelectorAll('#tbl-detail-sites .pick-row')"
            ".forEach(function(c){c.checked=true;});")
    page.click_js("document.getElementById('btn-open-sites')", settle=0.5)
    first = page.ev("document.querySelector('#tbl-detail-sites .pick-row').value")
    second = page.ev("document.querySelectorAll('#tbl-detail-sites .pick-row')[1].value")
    rep.eq("[4] window.open 只被调用 1 次（浏览器单次手势只放行一个标签页）",
           page.ev("window.__opened.length"), 1)
    rep.check("[4] 开出去的就是表格里第 1 个勾选值",
              (page.ev("window.__opened[0]") or "") == first,
              f"期望 {first!r}，实到 {(page.ev('window.__opened[0]') or '')!r}")
    rep.eq("[4] 其余 19 个渲染成可点击链接（退回『循环 window.open』这条就会红）",
           page.ev("document.querySelectorAll('#op-list a').length"), _OPEN_CAP - 1)
    rep.check("[4] 每条链接都是新标签 + rel 含 noopener（反向标签劫持）",
              page.ev("[...document.querySelectorAll('#op-list a')].every(function(a){"
                      "return a.target==='_blank' && /noopener/.test(a.rel);})") is True)
    rep.check("[4] 面板第一个链接就是第 2 个勾选值",
              second in (page.ev("document.querySelector('#op-list a').href") or ""),
              f"期望含 {second!r}")
    rep.eq("[4] 超过单次上限的 40 个不进列表（1 个开出去 + 19 个链接 = 20）",
           page.ev("window.__opened.length + document.querySelectorAll('#op-list a').length"),
           _OPEN_CAP)
    op_msg = page.ev("document.getElementById('op-msg').textContent") or ""
    tip = page.ev("document.querySelector('#op-list .muted') ? "
                  "document.querySelector('#op-list .muted').textContent : ''") or ""
    rep.check("[4] 提示如实说明浏览器限制与单次上限",
              "已打开第 1 个" in op_msg and f"另有 {_SITES_TOTAL - _OPEN_CAP} 个未列出" in op_msg
              and "一次点击开一个" in tip, f"msg={op_msg!r} tip={tip!r}")


    # ---------- [5] POC 表的 <button class="toggle"> 不会误提交外层筛选表单 ----------
    page.navigate(f"{base}/pocs?size={_PAGE_SIZE}")
    toggles = page.ev("document.querySelectorAll('button.toggle').length")
    rep.check("[5] POC 表里有 toggle 按钮（否则无从验起）", bool(toggles),
              f"toggle 数量={toggles}")
    rep.check("[5] toggle 不在任何 form 内（否则默认 type=submit 会提交表单）",
              page.ev("document.querySelector('button.toggle').closest('form') === null") is True)
    poc_id = page.ev("document.querySelector('button.toggle').dataset.id")
    # 钩住 fetch（返回永不 resolve 的 Promise → 处理器停在 await，不会 location.reload 打断观察）
    page.ev("window.__calls=[]; window.__submits=0;"
            "document.addEventListener('submit', function(){window.__submits++;}, true);"
            "window.fetch=function(u,o){window.__calls.push([String(u),(o&&o.method)||'GET']);"
            "return new Promise(function(){});};")
    page.click_js("document.querySelector('button.toggle')", settle=0.5)
    calls = page.ev("JSON.stringify(window.__calls)") or "[]"
    rep.eq("[5] 点击只触发一次 fetch", page.ev("window.__calls.length"), 1)
    rep.check("[5] fetch 打到 /api/pocs/<id>/toggle",
              f"/api/pocs/{poc_id}/toggle" in calls, f"calls={calls}")
    rep.check("[5] fetch 用 POST", '"POST"' in calls, f"calls={calls}")
    rep.eq("[5] 没有触发表单 submit 事件", page.ev("window.__submits"), 0)
    rep.check("[5] 页面没有整页跳走", (page.href() or "").find(f":{port}/pocs") > 0,
              f"href={page.href()!r}")

    # ---------- [6] 任务详情页页签切换 + 锚点/参数恢复 ----------
    page.navigate(f"{base}/tasks/{tid}#sites")
    rep.check("[6] 带 #sites 打开时站点页签被激活",
              page.ev("document.getElementById('pane-sites').classList.contains('active')") is True)
    rep.check("[6] 此时漏洞页签是收起的（确实换过，不是默认页签）",
              page.ev("document.getElementById('pane-vulns').classList.contains('active')") is False)
    page.click_js("document.querySelector('.tab[data-tab=\"dirs\"]')")
    rep.check("[6] 点「目录」页签后 pane-dirs 变 active",
              page.ev("document.getElementById('pane-dirs').classList.contains('active')") is True)
    rep.check("[6] 站点 pane 同时取消 active",
              page.ev("document.getElementById('pane-sites').classList.contains('active')") is False)
    page.click_js("document.querySelector('.tab[data-tab=\"ports\"]')")
    rep.check("[6] 再点「端口服务」→ pane-ports 变 active",
              page.ev("document.getElementById('pane-ports').classList.contains('active')") is True)
    page.click_js("document.querySelector('.tab[data-tab=\"flags\"]')")
    rep.check("[6] 点「flag 候选」→ pane-flags 变 active",
              page.ev("document.getElementById('pane-flags')"
                      ".classList.contains('active')") is True)
    _fx6 = page.ev("(()=>{const t=document.querySelector('#tbl-flags tbody');"
                   "return t?t.textContent:'NO-TABLE'})()") or ""
    rep.check("[6] 页签里真渲染出候选值（DOM 真的变了，不是只换了 class）",
              "E2e_Browser_Flag" in _fx6, _fx6[:90])
    _xss6 = page.ev("document.querySelectorAll('#tbl-flags img, #tbl-flags script').length")
    rep.check("[6] HTML 载荷当**文本**渲染：页签里没有任何真的 img/script 元素",
              _xss6 == 0 and "<img" in _fx6, f"元素数={_xss6} 文本={_fx6[:60]!r}")
    # 徽标数字必须是总数（续57 口径：`|length` 是当前页行数，拿它当总数会少报）
    rep.check("[6] 页签徽标显示候选总数 2",
              (page.ev("document.querySelector('.tab[data-tab=\"flags\"] .cnt').textContent") or "")
              .strip() == "2", page.ev("document.querySelector('.tab[data-tab=\"flags\"] .cnt')") )
    # 锚点 + 分页参数一起恢复：`?stsize=50#sites` 打开后站点页签 active，且自己的分页条带锚点
    page.navigate(f"{base}/tasks/{tid}?stsize={_PAGE_SIZE}#sites")
    rep.check("[6] 带参数+锚点打开时仍停在站点页签",
              page.ev("document.getElementById('pane-sites').classList.contains('active')") is True)
    next_href = page.ev(
        "[...document.querySelectorAll('#pane-sites .pager a')]"
        ".filter(a=>a.textContent.includes('下一页')).map(a=>a.getAttribute('href'))[0]") or ""
    rep.check("[6] 站点页签分页用独立参数 stpage 且带 #sites 锚点",
              f"stpage=2" in next_href and next_href.endswith("#sites"),
              f"下一页 href={next_href!r}")

    # ---------- [7] 策略配置：可折叠面板 + localStorage 持久化 ----------
    page.navigate(f"{base}/settings")
    rep.check("[7] 「检测策略」面板默认折叠",
              page.ev("document.querySelector('[data-panel=\"detect\"]').classList.contains('open')")
              is False)
    rep.check("[7] 折叠钮初始文案为「展开」",
              page.ev("document.querySelector('[data-panel=\"detect\"] .panel-toggle').textContent")
              == "展开")
    page.click_js("document.querySelector('[data-panel=\"detect\"] h2')")
    rep.check("[7] 点标题后 detect 面板展开",
              page.ev("document.querySelector('[data-panel=\"detect\"]').classList.contains('open')")
              is True)
    rep.check("[7] 展开状态写进了 localStorage 的 detect 键",
              page.ev("JSON.parse(localStorage.getItem('ctfscanner.panels')||'{}').detect") is True)
    rep.check("[7] 折叠钮文案变成「折叠」",
              page.ev("document.querySelector('[data-panel=\"detect\"] .panel-toggle').textContent")
              == "折叠")
    page.reload()
    opened_after = page.ev(
        "document.querySelector('[data-panel=\"detect\"]').classList.contains('open')")
    rep.eq("[7] 重载后 detect 面板仍是展开（localStorage 持久化）", opened_after, True)
    rep.check("[7] 未动过的 osint 面板重载后仍折叠（证明不是「全部展开」的假象）",
              page.ev("document.querySelector('[data-panel=\"osint\"]').classList.contains('open')")
              is False)

    # ---------- [7b] 外部引擎 afrog 的字段（续121）：真浏览器里存在、默认为关、点得动 ----------
    #      只验"HTML 里有这个 name"是不够的（[8z] 已经在 test_client 层验过渲染与 POST 回环）；
    #      这里要的是"用户看得见这个开关、点下去真的变勾选"，以及**默认必须是未勾选**
    #      （afrog 是外部进程、自管请求，默认开着就等于替用户决定要跑第三个引擎）。
    rep.eq("[7b] /settings 渲染出 8 个 afrog 字段（开关 + 目录 + 6 个限速/上限）",
           page.ev("document.querySelectorAll('input[name^=\"afrog_\"]').length"), 8)
    rep.eq("[7b] afrog 开关默认未勾选（外部引擎绝不默认开）",
           page.ev("document.querySelector('input[name=\"afrog_enabled\"]').checked"), False)
    rep.eq("[7b] PoC 目录默认为空（框架不替用户准备第三方 PoC）",
           page.ev("document.querySelector('input[name=\"afrog_poc_dir\"]').value"), "")
    page.click_js("document.querySelector('input[name=\"afrog_enabled\"]')")
    rep.eq("[7b] 点一下这个复选框真的变成勾选（不是画了个死控件）",
           page.ev("document.querySelector('input[name=\"afrog_enabled\"]').checked"), True)

    # ---------- [8] 任务列表页轮询：**一次批量**、只问未结束的行（续93） ----------
    # 旧写法是"每行一个 `/api/tasks/<id>/status`"（页大小 100 → 每 2.5 秒 100 个请求，且每个响应
    # 都让后端 `_tail()` 整份读一遍日志）。这里在**真浏览器**里钩住 fetch 数请求，而不是只看源码文本：
    # ① 不得出现任何按行请求；② 批量请求的 `ids` 只含**运行中**那个任务（done 的必须不在）。
    # 再让钩子回一个合成的 progress=99，验证"回写真的改到了 DOM"（不是发了请求但没渲染）。
    page.navigate(f"{base}/tasks")
    rep.check("[8] /tasks 上确实有一个运行中的行（否则本项无从验起）",
              page.ev(f"document.querySelector('#task-rows tr[data-id=\"{tid_run}\"]') !== null") is True)
    page.ev("window.__calls=[];"
            "window.fetch=function(u,o){var url=String(u); window.__calls.push(url);"
            "if(url.indexOf('/api/tasks/status?ids=')===0){"
            "return Promise.resolve({ok:true,json:function(){return Promise.resolve("
            "{ok:true,tasks:{%d:{status:'running',progress:99,current_stage:'probe'}}});}});}"
            "return Promise.resolve({ok:false,json:function(){return Promise.resolve({});}});};"
            % tid_run)
    time.sleep(4.0)                       # 轮询间隔 2.5s —— 睡够一轮，又不到两轮
    calls = json.loads(page.ev("JSON.stringify(window.__calls)") or "[]")
    batch = [u for u in calls if u.startswith("/api/tasks/status?ids=")]
    perrow = [u for u in calls if u.startswith("/api/tasks/") and u.endswith("/status")]
    rep.check("[8] 列表页轮询只发**批量**请求，没有任何按行请求",
              len(perrow) == 0 and len(batch) >= 1,
              f"批量={len(batch)} 按行={len(perrow)} calls={calls}")
    ids_arg = batch[0].split("ids=", 1)[1] if batch else ""
    rep.check("[8] 批量请求只带**未结束**的任务 id（done 的不在其中）",
              ids_arg.split(",") == [str(tid_run)], f"ids={ids_arg!r} 期望 {tid_run}")
    rep.eq("[8] 轮询回写真的改到了 DOM（合成 progress=99 已渲染）",
           page.ev(f"document.querySelector('#task-rows tr[data-id=\"{tid_run}\"] .progress')"
                   f".textContent"),
           "99%")

    # ---------- [9] 窄屏不得把整页撑出横向滚动条（续103：.grid2 > * { min-width:0 }） ----------
    # 元凶是网格子项默认的 `min-width:auto`：`1fr` 只约束**最大**宽度，于是带
    # `th{white-space:nowrap}` 的表用 min-content 把轨道顶开，整页出现横向滚动条，
    # 而 `main > section` 的 `overflow-x:auto` 因为轨道本身变宽根本不生效。
    # 续129：`/diff`（复测视图）也是一张宽表（6 列），新页面必须一起过这道关 ——
    # 否则"新页面上线时没人知道它在窄屏会不会撑出横向滚动条"就是续103 那条教训重演。
    for _p9 in ("/", "/settings", "/tasks/%d" % tid, "/diff?task=%d" % tid):
        page.cdp.call("Emulation.setDeviceMetricsOverride",
                      {"width": 430, "height": 900, "deviceScaleFactor": 1, "mobile": False})
        page.navigate(base + _p9)
        _ov9 = int(page.ev("document.documentElement.scrollWidth - window.innerWidth") or 0)
        rep.check("[9] %s 在 430px 下无横向溢出" % _p9, _ov9 <= 0, "溢出 %dpx" % _ov9)
    # 反向证伪（§6.1）：把承重的规则整条废掉（`.panel` 与 `main section` 两个选择器都要 ——
    # 只废一个会被另一个按特指度顶回去：`.panel`=0,1,0 高于 `main section`=0,0,2）。
    # 注一：刻意**不**用"打回 min-width:auto"做证伪 —— 真浏览器里它不改变结果
    #   （滚动容器的自动最小尺寸本就是 0），拿它当证据就是假证伪。
    # 注二：这条原本打在仪表盘 @430 上，续107 的窄屏档把主区从 265px 放宽到 345px 之后，
    #   那张表（min-content ~314px）本来就放得下、失去区分度 —— 承重关系随布局变了，
    #   于是挪到 /tasks（列多、min-content 远超视口）上，判据仍然是"退回旧规则必须红"。
    page.cdp.call("Emulation.setDeviceMetricsOverride",
                  {"width": 360, "height": 860, "deviceScaleFactor": 1, "mobile": False})
    page.navigate(base + "/tasks")
    page.ev("(()=>{const s=document.createElement('style');s.id='m9';"
            "s.textContent='.panel,main section{overflow-x:visible}';document.head.appendChild(s);})()")
    _ov9b = int(page.ev("document.documentElement.scrollWidth - window.innerWidth") or 0)
    rep.check("[9] 证伪：section 退回不自滚动必须重新溢出（/tasks @360）",
              _ov9b > 0, "实测 %dpx（应 >0）" % _ov9b)
    page.ev("document.getElementById('m9').remove()")
    _ov9c = int(page.ev("document.documentElement.scrollWidth - window.innerWidth") or 0)
    rep.check("[9] 撤掉注入后回到不溢出", _ov9c <= 0, "实测 %dpx" % _ov9c)
    # 续107：≤640px 那一档必须**真的生效**（侧栏翻成顶部横条），且**只在窄屏生效**
    # —— 两头都验，否则"把媒体查询写成全局规则"这种改法会一路绿灯。
    page.cdp.call("Emulation.setDeviceMetricsOverride",
                  {"width": 360, "height": 860, "deviceScaleFactor": 1, "mobile": False})
    for _p9b in ("/", "/tasks"):
        page.navigate(base + _p9b)
        _ov9b2 = int(page.ev("document.documentElement.scrollWidth - window.innerWidth") or 0)
        rep.check("[9] %s 在 360px 下无横向溢出" % _p9b, _ov9b2 <= 0, "溢出 %dpx" % _ov9b2)
    _narrow = page.ev("JSON.stringify({dir:getComputedStyle(document.querySelector('.layout'))"
                      ".flexDirection, pos:getComputedStyle(document.querySelector('.sidebar'))"
                      ".position, sw:document.querySelector('.sidebar').getBoundingClientRect().width,"
                      " vw:window.innerWidth})")
    _narrow = json.loads(_narrow)
    rep.check("[9] 360px 下侧栏已翻成顶部横条",
              _narrow["dir"] == "column" and _narrow["pos"] == "static"
              and _narrow["sw"] > _narrow["vw"] * 0.8,
              str(_narrow))
    page.cdp.call("Emulation.setDeviceMetricsOverride",
                  {"width": 1000, "height": 860, "deviceScaleFactor": 1, "mobile": False})
    page.navigate(base + "/")
    _wide = page.ev("JSON.stringify({dir:getComputedStyle(document.querySelector('.layout'))"
                    ".flexDirection, pos:getComputedStyle(document.querySelector('.sidebar'))"
                    ".position})")
    _wide = json.loads(_wide)
    rep.check("[9] 1000px 下仍是左侧栏（证明那是断点而不是全局规则）",
              _wide["dir"] == "row" and _wide["pos"] == "sticky", str(_wide))
    page.cdp.call("Emulation.setDeviceMetricsOverride",
                  {"width": 1280, "height": 900, "deviceScaleFactor": 1, "mobile": False})

    # ---------- [10] 建任务表单的「一键批量勾选」（续118，真点击、真读 DOM）----------
    # smoke 那边只能验页面结构；"点下去到底勾上了几项"必须在这里验（真表单登录同类口径）。
    page.navigate(base + "/tasks")
    _cb10 = "#task-form [data-ck-group] input[type=checkbox]"
    _tot10 = page.ev(f"document.querySelectorAll('{_cb10}').length")
    page.ev("document.querySelector('#task-form button[data-ck-mode=all]').click()")
    _on10 = page.ev(f"document.querySelectorAll('{_cb10}:checked').length")
    _off_on10 = page.ev("!!document.querySelector('#task-form input[name=offline]').checked")
    rep.check("[10] 「全部勾上」把 scope 覆盖的 17 项全勾上（13 阶段 + 3 深度 + 1 拓展）",
              _on10 == _tot10 - 1 == 17, f"总 {_tot10} / 勾上 {_on10}")
    rep.check("[10] 「全部勾上」不带动离线模式（勾它=禁用外部工具，与跑全相反）",
              _off_on10 is False, f"offline.checked={_off_on10}")
    page.ev("document.querySelector('#task-form button[data-ck-mode=none]').click()")
    _zero10 = page.ev(f"document.querySelectorAll('{_cb10}:checked').length")
    rep.check("[10] 「全部清掉」清成 0 项", _zero10 == 0, f"实测 {_zero10}")
    page.ev("document.querySelector('#task-form button[data-ck-mode=default]').click()")
    _back10 = page.ev(f"document.querySelectorAll('{_cb10}:checked').length")
    rep.check("[10] 「恢复默认」＝11 项（13 阶段减去策略级默认关的 cert/screenshot）",
              _back10 == 11, f"实测 {_back10}")
    # 证伪：按钮只管 stages 时会停在这里（13 项而非 17）—— 上面那条 all 的判据就是它的牙
    rep.check("[10] 点按钮不会把已填内容弄丢（按钮是 type=button，不提交表单）",
              page.ev("!!document.querySelector('#task-form button[data-ck-mode=all]')") is True
              and page.ev("document.querySelectorAll('#task-form form').length") == 0)


def run(settings=None):
    """跑完整套 E2E。返回 `(ok, note)`：跳过与失败都是 `ok=False`（**绝不假绿**）。"""
    browser = find_browser()
    if not browser:
        note = "跳过：未找到可用的无头 Chrome/Edge（可用环境变量 CTFSCANNER_CHROME 指定路径）"
        print("[跳过] " + note)
        return False, note

    cdp = None
    gui = None
    chrome = None
    work = Path(tempfile.mkdtemp(prefix="ctf-e2e-"))        # 临时产物全部落 %TEMP%
    try:
        # ⚠️ 顺序很重要：必须在导入 `scanner.*` **之前**设好环境变量 —— `scanner/config.py` 与
        # `scanner/db.py` 在 import 期就把 `LOGS_DIR` / `DB_PATH` 定死了（import 之后再设无效）。
        os.environ["CTFSCANNER_DB"] = str(work / "scanner.db")
        os.environ["CTFSCANNER_LOGS"] = str(work / "logs")
        env = dict(os.environ)
        (work / "profile").mkdir()

        # 续117：登录只有账号一条路 —— e2e 用**临时库里造的账号**登录（口令是本文件的常量、
        # 只在一次性沙箱里有效，不是任何真实凭据）。以前这里是"读 config 里的 gui.token，
        # 没配就整组跳过"，那种"跳过"在 CI 上等于把浏览器这条链路悄悄关掉。
        cred = (_E2E_USER, _E2E_PW)

        print(f"[*] 浏览器: {os.path.basename(browser)}；临时目录: {work.name}")
        tid, tid_run = _seed_db()
        print(f"[*] 已造数：目录 {_DIRS_TOTAL} 行 / 站点 {_SITES_TOTAL} 行，任务 #{tid}（另有运行中的 #{tid_run}）")
        port, gui = _start_gui(env, work)
        print(f"[*] Flask GUI 已在 127.0.0.1:{port} 就绪（临时库 {_rel(work / 'scanner.db')}）")
        cdp, chrome = _start_chrome(browser, work / "profile", work)
        print("[*] 无头浏览器已连上 CDP，开始交互断言")
        page = Page(cdp)
        rep = _Report()
        _run_checks(page, f"http://127.0.0.1:{port}", rep, cred, tid, port, tid_run)
        ok = not rep.fails
        if ok:
            note = f"通过：登录 + 8 项交互共 {rep.n} 条断言全绿（真浏览器 / 真 Flask 进程）"
        else:
            note = f"失败 {len(rep.fails)}/{rep.n} 条：" + "；".join(rep.fails[:4])
        print(("[通过] " if ok else "[失败] ") + note)
        return ok, note
    except Exception as e:                                  # noqa: BLE001 - 统一降级为 (False, note)
        note = f"失败：{type(e).__name__}: {e}"
        print("[失败] " + note)
        return False, note
    finally:
        # 清理三件套：CDP 连接、浏览器进程（连同子进程）、Flask 进程；最后删临时目录。
        try:
            if cdp is not None:
                cdp.close()
        except Exception:                                   # noqa: BLE001
            pass
        _kill_tree(chrome)
        _kill_tree(gui)
        for _ in range(5):                                  # 句柄释放有延迟，删不掉就再试
            shutil.rmtree(work, ignore_errors=True)
            if not work.exists():
                break
            time.sleep(0.4)
        if work.exists():
            print(f"[!] 临时目录未删净（不影响结论）：{work.name}")


if __name__ == "__main__":
    ok, note = run()
    if ok:
        sys.exit(0)
    # 跳过（无浏览器）与失败都**不是通过**，但用不同退出码区分，避免被当成同一种结果。
    sys.exit(2 if note.startswith("跳过") else 1)
