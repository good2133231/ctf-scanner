"""内置最小靶场（续50「全流程自检」用）：在临时目录生成一个最小静态站，只绑 `127.0.0.1`。

为什么单独成模块、**不复用** `tests/smoke.py` 的 `smoke_root/`：
- `smoke_root/` 是**测试夹具目录**，属于测试资产；生产/开发工具依赖它会把"测试"与
  "开发工具"缠在一起（改测试会波及开发自检，反之亦然）；
- 本模块只用标准库，`import` 它不引入任何测试代码，也不依赖仓库里的任何夹具文件。

⚠️ **安全边界（铁律）**：
- **只绑 `127.0.0.1`**，任何情况下都不允许 `0.0.0.0`（本项目铁律：控制台/服务不对外暴露）。
  `HOST` 是模块级常量且**故意写死回环**，调用方无法把它改成对外地址。
- 夹具里的 `.env` / `app.js` 是**流程夹具样本**，值明显是假的（如
  `devfixture-not-a-real-secret`），**不是任何真实凭据**，也**不得**替换成真值
  （口径与 `tests/smoke.py` 顶部对 `smoke_root/` 的声明一致）。
"""
import functools
import http.server
import pathlib
import shutil
import tempfile
import threading

# **固定回环**：绝不改成 0.0.0.0 —— 夹具只服务本机自检，不对外暴露。
HOST = "127.0.0.1"

_INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>DevFixture Site</title>
<link rel="icon" href="/favicon.ico">
</head>
<body>
<h1>CTFScanner dev fixture</h1>
<p>Local flow-check fixture. Not a real target.</p>
<script src="/app.js"></script>
</body>
</html>
"""

_ADMIN_HTML = """<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>DevFixture Admin</title></head>
<body><h1>Admin</h1><p>dev fixture admin page</p></body>
</html>
"""

_ROBOTS_TXT = "User-agent: *\nDisallow: /admin\n"

# 假的 API 路径 + 假的 key 形态（用于让 jsmine 有东西可挖）——**不是真实凭据**。
_APP_JS = """// dev fixture sample —— 假的 API 路径与假的 key 形态，不是任何真实凭据
var API_BASE = "/api/v1/internal";
var accessKey = "AKIAIOSFODNN7EXAMPLE";
"""

# 明显是假的样本值 ——**不是真实凭据**（用于让 dirscan 有"暴露面"可命中）。
_ENV = """# dev fixture sample —— 明显是假的，不是任何真实凭据
DB_PASSWORD=devfixture-not-a-real-secret
"""


class _QuietHandler(http.server.SimpleHTTPRequestHandler):
    """静态站处理器：关掉逐请求日志（自检输出已经很密）。"""

    def log_message(self, *args):
        pass


def start(port=0):
    """起内置靶场，返回 `(httpd, base_url)`。

    `port=0`（默认）= 交给系统分配空闲端口，避免与已占用端口冲突；返回的 `base_url`
    形如 `http://127.0.0.1:54321`（**用真实分配到的端口**，不是传进去的 0）。
    """
    root = pathlib.Path(tempfile.mkdtemp(prefix="devfixture-"))
    (root / "admin").mkdir()
    (root / "index.html").write_text(_INDEX_HTML, encoding="utf-8")
    (root / "admin" / "index.html").write_text(_ADMIN_HTML, encoding="utf-8")
    (root / "robots.txt").write_text(_ROBOTS_TXT, encoding="utf-8")
    (root / "app.js").write_text(_APP_JS, encoding="utf-8")
    (root / ".env").write_text(_ENV, encoding="utf-8")

    handler = functools.partial(_QuietHandler, directory=str(root))
    httpd = http.server.ThreadingHTTPServer((HOST, port), handler)
    # 临时目录挂在 httpd 上，供 stop() 清理（不引入模块级全局状态，可并发起多个夹具）。
    httpd.devfixture_root = root
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    host, real_port = httpd.server_address[0], httpd.server_address[1]
    return httpd, f"http://{host}:{real_port}"


def stop(httpd):
    """停掉靶场并删掉临时目录。**幂等**：重复调用 / 传 None 都不抛。"""
    if httpd is None:
        return
    try:
        httpd.shutdown()
    except Exception:      # noqa: BLE001 - 收尾绝不该抛
        pass
    try:
        httpd.server_close()
    except Exception:      # noqa: BLE001
        pass
    root = getattr(httpd, "devfixture_root", None)
    if root:
        shutil.rmtree(str(root), ignore_errors=True)
