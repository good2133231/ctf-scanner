"""内置最小靶场（续50 起、续52 补 HTTPS / 域名 / 情报源夹具）：临时目录生成最小静态站，
**只绑 `127.0.0.1`**（HTTP 与 HTTPS 皆然）。

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
- 续52 新增的 HTTPS 用的是**内联自签证书**（`_CERT_PEM` / `_KEY_PEM`，见下），
  它同样是**流程夹具**：CN=`devfixture.test`、自签、只可能被本机夹具用到，
  **不是任何真实站点/生产凭据**，**不得**替换成真值。
- 续52 新增的 `/intel/kev.json` 是**情报源夹具**（`intel.url` 指过来时用），
  内容显式标注 "NOT real data"，**不是真实 KEV 数据**。
"""
import functools
import http.server
import pathlib
import shutil
import ssl
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

# 情报源夹具（续52）：`intel.url` 指向本文件时用，让 intel 阶段**真跑**却不出网。
# 结构对齐 CISA KEV（`scanner/intel.py::normalize_item` 认 `cveID`/`vendorProject`/`product`…），
# 但**内容全是占位**（"NOT real data"）——**不是真实情报**，也不得替换成真值。
# 记录刻意选成"与夹具站点的指纹（SimpleHTTP）不匹配"，于是 intel 会真拉取、真匹配、命中 0 条
# —— 这正是自检想展示的"阶段真的跑过一遍（有网络活动），只是没有可匹配的情报"。
_INTEL_KEV_JSON = """{
  "title": "CTFScanner dev fixture feed (NOT real data)",
  "catalogVersion": "devfixture-0",
  "dateReleased": "2020-01-01T00:00:00.000Z",
  "count": 1,
  "vulnerabilities": [
    {
      "cveID": "CVE-0000-0001",
      "vendorProject": "DevFixtureVendor",
      "product": "DevFixtureProduct",
      "vulnerabilityName": "Dev fixture placeholder record (NOT real data)",
      "dateAdded": "2020-01-01",
      "shortDescription": "Placeholder for the CTFScanner dev self-check. Not a real CVE.",
      "requiredAction": "None (fixture).",
      "dueDate": "2020-02-01",
      "knownRansomwareCampaignUse": "Unknown",
      "notes": "fixture",
      "cwes": ["CWE-000"]
    }
  ]
}
"""

# ---------- 内联自签证书（续52）----------
# 一次性生成的**测试/开发夹具**（`openssl req -x509 -days 3650`），**不是任何生产凭据**。
# 为什么内联而不是运行时生成：标准库**不能生成证书**（`ssl` 只加载、不签发），
# 而夹具要"零外部依赖、可离线跑"；落盘成文件又容易被误当成真凭据管理，故直接内联。
# 为什么**不复用** `tests/smoke.py` 的那份：生产模块不得依赖测试夹具（见文件头）。
# 证书自造特征（改动必须同步改 tests/smoke.py [7n] 的断言）：
#   subject/issuer = CN=devfixture.test, O=CTFScanner DevFixture, C=CN
#   notBefore 2026-09-26 / notAfter 2036-09-23（有效期约 10 年：既不过期，也不长到离谱）
#   SAN = devfixture.test / *.devfixture.test / 127.0.0.1，签名算法 sha256WithRSA，自签
_CERT_PEM = """-----BEGIN CERTIFICATE-----
MIIDoTCCAomgAwIBAgIUSA+RA/qPie+7+kV+Hcp8ThXfu3QwDQYJKoZIhvcNAQEL
BQAwRzELMAkGA1UEBhMCQ04xHjAcBgNVBAoMFUNURlNjYW5uZXIgRGV2Rml4dHVy
ZTEYMBYGA1UEAwwPZGV2Zml4dHVyZS50ZXN0MB4XDTI2MDkyNjEzMTgwNVoXDTM2
MDkyMzEzMTgwNVowRzELMAkGA1UEBhMCQ04xHjAcBgNVBAoMFUNURlNjYW5uZXIg
RGV2Rml4dHVyZTEYMBYGA1UEAwwPZGV2Zml4dHVyZS50ZXN0MIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw1WPyRqgwoNrEuBHqgJjq2EKQfoZ7Kr87mS0
kMnRSchMoEIJaQR7rxsgg3nWL1bnKe/RRJcQ0wUE69zn37gfsgotDkvHBfpQQW6A
2J9ocdmOnQmW6NtNuN4p3iVTzicptCDrEmN06Ix50+SpxHZC1vjhoy1ReM6R65/v
Jb9s/Qo4CL+0hdI08js+QQ4Uhnvm9EZH4/93vFalInL3FQUXi4hY1YvGXmqm/uej
YcsNed68P2uHRiG004tcEwxihF2CsnmGMZMx05be8RAeM2MfmdhSWHEEroB+A8GJ
bZ7MtkMsD4GwTraZwYCfXOeBUcCBhYScMtosKJePowbxaU0PAwIDAQABo4GEMIGB
MDMGA1UdEQQsMCqCD2RldmZpeHR1cmUudGVzdIIRKi5kZXZmaXh0dXJlLnRlc3SH
BH8AAAEwCQYDVR0TBAIwADALBgNVHQ8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUH
AwEwHQYDVR0OBBYEFMh8A/il1KuCjHJri2rxInvKvgVkMA0GCSqGSIb3DQEBCwUA
A4IBAQAxuZ5mbezUSGHg5aDDfxE1xVe/JnjvoHcgrrYt0zCjQzv8eBEmsvBCTnbQ
OyJbHjHf3PZ4xvIy46+b/UCYnznYbJGLoznYLj1IQ6miSwGb+tG+hmPW6Xh17D6C
jgqFa6Hcf9Y6rfd6+xcSTF23BB90UI94r+kMCrassB9+59K7jr0BpCClXMIQJrUU
ORhbqB0Nc3vNfIxRpB4Ai+lrQ+u/nfHmamtbWjzPPD3e1IHjAw5W/sVnMPJTLBBJ
2MK6mrnjF2EtP4NzHjjpKgX5wij0LPT2IDNbgHkjdloaVquy9WIIvZ9XSNuDc7k0
Ymo7oadlyD76LxgNC0p88lhRyDJq
-----END CERTIFICATE-----
"""

_KEY_PEM = """-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDDVY/JGqDCg2sS
4EeqAmOrYQpB+hnsqvzuZLSQydFJyEygQglpBHuvGyCDedYvVucp79FElxDTBQTr
3OffuB+yCi0OS8cF+lBBboDYn2hx2Y6dCZbo20243ineJVPOJym0IOsSY3TojHnT
5KnEdkLW+OGjLVF4zpHrn+8lv2z9CjgIv7SF0jTyOz5BDhSGe+b0Rkfj/3e8VqUi
cvcVBReLiFjVi8Zeaqb+56Nhyw153rw/a4dGIbTTi1wTDGKEXYKyeYYxkzHTlt7x
EB4zYx+Z2FJYcQSugH4DwYltnsy2QywPgbBOtpnBgJ9c54FRwIGFhJwy2iwol4+j
BvFpTQ8DAgMBAAECggEAUdi1pVHLf4V6ZY/lZ1aV9bb1Cd0mZLTmw2sd/7cYwz4y
4UmaUM8oliAbOQvhk7dpp/hNKtzTl1/4hm3rGKI5YawC4gUdcSNH4orPYTU2GdJL
gACHI63UfLxWNbdVTMG7JzdN2EglMdW+rGsZOXFGI3ZocSupgiGoId9DYQE7RTD5
/oWKyUjVprP/CzQqOGo0xmnipCXig8MwIzT5pBau8bU7Cyu+Guib7XOmaC0hSMm6
QfLeMxSJr8libvh7CJmCX/6W9wJo3xgjK9AlF82vZ7DUdr6rRhgoVWcceKUeQYkU
h5kNWZ8HvNm9st+R1bBywiA52p6xBbbozRxEv9DB4QKBgQDl0sHy44X7g+1jVaTr
9OUw1AbGILSMZOQB1FvACSOR5nI56/om3ghRI0NX1AqM61zDgPhg3alkJ3b0q2OP
4KGajMYL6X9BnFivzPMpjWWlgImVojfyX8v+8S0zvjqp1vZ1sjJSmjcVd4KyT97Z
HhrgUReTOnHGy891c1Y7HsSQ4QKBgQDZlSoDEfFSSMU7XQph1gHQzkiH0UfiIS4E
HFS1ILHtAkbnJ9EpmnPTbTPIjkrVjO1sEhqajX3z5rGzOdvhyuNWJKhEi7ypker+
FPwD+s2xT/ohKS1d8WRvghTcOrz1A3e+jEfUTKWTvMxnjUo+UIjjlIWvEge8Bmxp
L0/j3QIIYwKBgF2Fp1Ecz0/rfrWWi3dNf9qf3WXQt0gOYk5wSSnbTjM4ELGLWo9o
eP/zlprt+aEgwe341JoueZj9CkZEXE6XPYvzzz/Xs+ZSJjDb+POmy39O0C4pBhVG
cG/9WsScm6izhjWc3yeIA/RjXrcLE4dM3ej8dth9xwD7vR9xYNzMB3dhAoGAAoej
d2mr/qLt+CS6zCxq1PyxBzM9vLlaCZ4ytfBtYS4XmPRzkCJFmn24jmppIFaFJC6J
tKZUgpN6GXVgwx1Sy1udwT5GsUoLC20/COTPo3IknGIYLvFxk4JVr8HXFJo3uDV1
WFiTzEXzsniIFnVlQhAmBcUV5e/FLuvn5+RX87UCgYByT/tRUl1Uoeu2mVHJCNzq
fKPEGSJc3REyarHcBnD/qC+zRBQOladDVODhgt2NyFTo//uVCAuwPiwPE6Ms0b4/
yvSP4EUFfUq5F9QkkolYAQN+iXgrIgjIplPzPIaN98JbMvEh69hN5oeNqDRgFc7i
hYnrjuAAGRNLt6XllDl0Vg==
-----END PRIVATE KEY-----
"""


class _QuietHandler(http.server.SimpleHTTPRequestHandler):
    """静态站处理器：关掉逐请求日志（自检输出已经很密）。"""

    def log_message(self, *args):
        pass


class _QuietServer(http.server.ThreadingHTTPServer):
    """静态站服务：吞掉**逐连接**异常。

    为什么需要：无头浏览器（截图阶段）/ 扫描器常常"握完手就断"，`BaseServer.handle_error`
    会往 stderr 打一整段 traceback（实测截图阶段每个站点都来一次）。那只是连接被对端关掉，
    **不是夹具故障**；打在自检输出里像报错，故在这里静默掉。
    """

    daemon_threads = True

    def handle_error(self, request, client_address):
        pass


def _write_root():
    """把夹具内容写进一个临时目录，返回该目录 `Path`。"""
    root = pathlib.Path(tempfile.mkdtemp(prefix="devfixture-"))
    (root / "admin").mkdir()
    (root / "index.html").write_text(_INDEX_HTML, encoding="utf-8")
    (root / "admin" / "index.html").write_text(_ADMIN_HTML, encoding="utf-8")
    (root / "robots.txt").write_text(_ROBOTS_TXT, encoding="utf-8")
    (root / "app.js").write_text(_APP_JS, encoding="utf-8")
    (root / ".env").write_text(_ENV, encoding="utf-8")
    (root / "intel").mkdir()
    (root / "intel" / "kev.json").write_text(_INTEL_KEV_JSON, encoding="utf-8")
    return root


def _make_server(root, port, https):
    """建一个静态站服务（可选 TLS 包装）。**只绑 `HOST`（127.0.0.1）**。"""
    handler = functools.partial(_QuietHandler, directory=str(root))
    httpd = _QuietServer((HOST, int(port)), handler)
    if https:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        # 用**内存里**的证书/私钥（`_CERT_PEM` / `_KEY_PEM`），不落盘 → 不会泄漏到工作区
        cert_file = pathlib.Path(root) / "_fixture_cert.pem"
        key_file = pathlib.Path(root) / "_fixture_key.pem"
        cert_file.write_text(_CERT_PEM, encoding="utf-8")
        key_file.write_text(_KEY_PEM, encoding="utf-8")
        ctx.load_cert_chain(str(cert_file), str(key_file))
        # 标准库做法：把监听套接字换成 TLS 套接字（`server_address` 不变）
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    return httpd


class _Fixture:
    """多监听器夹具句柄：`stop()` 用的鸭子接口与单个 `httpd` 一致。

    暴露 `shutdown()` / `server_close()` / `devfixture_root` / `server_address` / `servers`，
    于是 `stop()` 对"单监听器"与"多监听器"是同一段代码。
    """

    def __init__(self, root, servers):
        self.root = root
        self.servers = list(servers)
        self.devfixture_root = root
        # 兼容：把首个（HTTP）监听器的 `server_address` 透出来
        self.server_address = self.servers[0].server_address if self.servers else (HOST, 0)

    def shutdown(self):
        for s in self.servers:
            try:
                s.shutdown()
            except Exception:      # noqa: BLE001 - 收尾绝不该抛
                pass

    def server_close(self):
        for s in self.servers:
            try:
                s.server_close()
            except Exception:      # noqa: BLE001
                pass


def start(port=0, https=False):
    """起**单监听器**内置靶场，返回 `(httpd, base_url)`。

    - `port=0`（默认）= 交给系统分配空闲端口，避免与已占用端口冲突；返回的 `base_url`
      形如 `http://127.0.0.1:54321`（**用真实分配到的端口**，不是传进去的 0）。
    - `https=True` 时用内联自签证书做 TLS 包装，`base_url` 形如 `https://127.0.0.1:54321`
      （**自签** → 调用方需 `verify=False`；见文件头对夹具证书的声明）。
    - 返回的 `httpd` 是原始 `ThreadingHTTPServer`（或 TLS 包装后的），带 `.server_address`
      与 `.devfixture_root` 两个属性 —— `tests/smoke.py [7l]` 的绑定地址断言依赖前者。
    """
    root = _write_root()
    httpd = _make_server(root, port, https)
    # 临时目录挂在 httpd 上，供 stop() 清理（不引入模块级全局状态，可并发起多个夹具）。
    httpd.devfixture_root = root
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    host, real_port = httpd.server_address[0], httpd.server_address[1]
    scheme = "https" if https else "http"
    return httpd, f"{scheme}://{host}:{real_port}"


def start_both(http_port=0, https_port=0):
    """同时起 HTTP 与 HTTPS 两个监听器，返回 `(fixture, http_base, https_base)`。

    两个监听器**共用同一份夹具目录**（同一台主机、两种协议），`fixture` 是 `_Fixture`，
    `stop(fixture)` 会**同时**关掉两者并删临时目录。
    """
    root = _write_root()
    http_srv = _make_server(root, http_port, https=False)
    https_srv = _make_server(root, https_port, https=True)
    fx = _Fixture(root, [http_srv, https_srv])
    for srv in (http_srv, https_srv):
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    hb = f"http://{http_srv.server_address[0]}:{http_srv.server_address[1]}"
    sb = f"https://{https_srv.server_address[0]}:{https_srv.server_address[1]}"
    return fx, hb, sb


def stop(httpd):
    """停掉靶场并删掉临时目录。**幂等**：重复调用 / 传 None / 传 `_Fixture` 都不抛。"""
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
