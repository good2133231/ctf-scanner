"""站点截图：调用本机已有的无头浏览器给存活站点截图（只读 GET，非破坏性）。

设计取舍：
- **不引入新依赖**（不装 playwright/selenium）：直接用系统里已装好的
  Edge / Chrome 的 `--headless --screenshot` 能力，跨平台可用；
- **浏览器位置怎么找**（遵守 `AGENTS.md` §0：代码里不写本机绝对路径）：
  ① 先看配置 `screenshot.browser`（用户可在 settings.yaml 里填绝对路径）；
  ② 再 `shutil.which()` 探测常见命令名（`msedge` / `chrome` / `chromium` / `google-chrome`…）；
  ③ 最后用**环境变量 + 相对子路径**拼出标准安装位置（`%PROGRAMFILES%\\Microsoft\\Edge\\…` 这类），
     代码里只有相对片段，没有硬编码的盘符/用户名。
- **不碰用户的浏览器配置**：每次截图都用临时 `--user-data-dir`，跑完即删；
- 截图失败只记一行日志（截图是"锦上添花"，不该拖垮流水线）。
"""
import os
import shutil
import tempfile
import time
from pathlib import Path

from .utils import html_title, run_cmd

# 命令名（PATH 里能找到就用）
_CMD_NAMES = ("msedge", "chrome", "chromium", "google-chrome", "chromium-browser",
              "chrome.exe", "msedge.exe")

# 标准安装位置：环境变量 + 相对子路径（**不含任何硬编码绝对路径**）
_REL_CANDIDATES = (
    ("PROGRAMFILES", r"Microsoft\Edge\Application\msedge.exe"),
    ("PROGRAMFILES(X86)", r"Microsoft\Edge\Application\msedge.exe"),
    ("PROGRAMFILES", r"Google\Chrome\Application\chrome.exe"),
    ("PROGRAMFILES(X86)", r"Google\Chrome\Application\chrome.exe"),
    ("LOCALAPPDATA", r"Google\Chrome\Application\chrome.exe"),
    ("LOCALAPPDATA", r"Microsoft\Edge\Application\msedge.exe"),
    ("PROGRAMFILES", "Microsoft/Edge/Application/msedge.exe"),
    ("PROGRAMFILES(X86)", "Microsoft/Edge/Application/msedge.exe"),
    ("PROGRAMFILES", "Google/Chrome/Application/chrome.exe"),
)


# Windows 注册表里的标准登记位置（App Paths）：系统级"这个程序装在哪"的权威来源，
# 代码里不出现任何盘符/用户名（`winreg` 是标准库，非 Windows 上直接跳过）。
_REG_KEYS = (
    (r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\msedge.exe", None),
    (r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\chrome.exe", None),
    (r"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\App Paths\\msedge.exe", None),
    (r"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\App Paths\\chrome.exe", None),
)


# 无头浏览器的公共开关。`--ignore-certificate-errors` **不能省**：CTF 与内网授权目标多为
# 自签 / 过期 / 私有 CA 证书（`certs.py` 取证就是刻意 `CERT_NONE`），不加它浏览器会以
# `net::ERR_CERT_AUTHORITY_INVALID` 拒绝加载、`--screenshot` 一个字节都不产出
# （2026-09-28 实测：同一站点加/不加 = 13512 字节 vs 0 字节；且与 `--headless=new` 无关）。
# 它只影响**本机渲染**，不改变对目标的请求语义（仍是只读 GET），不越"非破坏性"红线。
# ⚠️ 浏览器参数（续74 修正续73 的结论，CI 实测；browser_e2e.py 走 CDP 且不在 CI 跑，
#   其“老无 --no-sandbox”只在本地 Windows 成立，不能代表 CI Linux runner）：
#    - **`--headless=old`**：`--headless=new` 在 GitHub 的 ubuntu runner 上会**挂死**（续71），保持 old。
#    - **必须加 `--no-sandbox`**：runner 禁用非特权用户命名空间，不加 chromium 起不来
#     （`FATAL: No usable sandbox!`）—— 续73 误以为“old 不必加”把它去掉，CI 立刻红
#      （同一 runner 直接 FATAL）；它只影响本机浏览器进程隔离，不越非破坏性红线。
#    - **必须加 `--disable-dev-shm-usage`**：runner 的 `/dev/shm` 过小（~64MB），chromium 渲染会
#      **30s 超时无产物** —— 这才是续72（带 --no-sandbox）超时的真正根因，不是 `--no-sandbox` 本身。
#      该开关让 chromium 改用 `/tmp`，跨平台无害（Windows 上被忽略）。
#    - `--disable-background-networking`：与 browser_e2e 一致，避免无头进程等后台网络初始化。

#    `--ignore-certificate-errors` 的理由见下方。
_FLAGS = (
    "--headless=old",
    "--no-sandbox",
    "--disable-dev-shm-usage",
    "--ignore-certificate-errors",
    "--disable-gpu",
    "--hide-scrollbars",
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-extensions",
    "--disable-background-networking",
)


def _from_registry():
    try:
        import winreg  # noqa: WPS433 （仅 Windows 有）
    except ImportError:
        return ""
    for sub, _ in _REG_KEYS:
        for root in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
            try:
                with winreg.OpenKey(root, sub) as key:
                    path, _typ = winreg.QueryValueEx(key, "")
                if path and Path(str(path)).exists():
                    return str(path)
            except OSError:
                continue
    return ""


def browser_path(settings=None):
    """返回可用的无头浏览器路径；找不到返回 ""。

    ⚠ 配置里写**相对路径**时必须按项目根折算（续167，§5.13 那同一个坑的第四次）：
    `Path("tools/browser/chrome").exists()` 吃的是**进程 CWD**，从仓库外启动 GUI / CLI 时
    它就"没找到"，症状是"明明配了浏览器，截图永远失败"。折算后一律返回**绝对路径** ——
    调用方要把它当 argv[0] 并显式换 `cwd=任务目录` 起子进程，相对串进了新 cwd 就起不来。
    """
    from .config import resolve          # 局部导入：折算规则只此一个产地
    cfg = (settings or {}).get("screenshot", {}) or {}
    configured = str(cfg.get("browser") or "").strip()
    if configured:
        if "/" in configured or "\\" in configured:
            p = resolve(configured)
            return str(p) if p.exists() else ""
        return shutil.which(configured) or ""
    for name in _CMD_NAMES:
        found = shutil.which(name)
        if found:
            return found
    found = _from_registry()
    if found:
        return found
    for env_key, rel in _REL_CANDIDATES:
        base = os.environ.get(env_key)
        if not base:
            continue
        candidate = Path(base) / rel
        if candidate.exists():
            return str(candidate)
    return ""


def available(settings=None):
    return bool(browser_path(settings))


# ---- 截图失败原因分档（续154：用户点单「有些截图经常截不到…失败要标注原因：301 跳转 / 超时 /
#      其他，方便排查」）。常量与 `classify()` 是**唯一产地**：阶段里的重试决策与落库标签都读这里
#      —— 两处各嗅一遍 `"timeout" in err.lower()` 迟早漂（§5.14）。
REASON_BROWSER = "无浏览器"
REASON_TIMEOUT = "超时"
REASON_REDIRECT = "跳转未落地"
REASON_DNS = "DNS 解析失败"
REASON_CONNECT = "连不上"
REASON_TLS = "HTTPS 握手失败"
REASON_EMPTY = "没产出图片"
REASON_BUDGET = "预算或已停止"
REASON_OTHER = "其他"
REASONS = (REASON_BROWSER, REASON_TIMEOUT, REASON_REDIRECT, REASON_DNS, REASON_CONNECT,
           REASON_TLS, REASON_EMPTY, REASON_BUDGET, REASON_OTHER)

# 续161「候补重试」（主理人 2026-10-12 点单「截图以及有些站点超时，建议加入候补运行，
# 在项目没完成前空闲再重试一下」）：**哪些失败档值得再排一轮**，判据只在这一处 ——
# runner 排轮、页面数"还剩几张"都读它，抄第二份迟早和 `classify()` 分家（§5.14）。
# 只收这三档的理由：`无浏览器` 重试一万次还是没有浏览器；`预算或已停止` 是人在停、预算在拦，
# 再排一轮等于绕过停止（红线）；`DNS 解析失败` / `HTTPS 握手失败` / `没产出图片` / `其他`
# 给不出"再来一次就成了"的证据，宁可只报原因，不自动加请求量。
RETRYABLE_REASONS = (REASON_TIMEOUT, REASON_REDIRECT, REASON_CONNECT)
RETRYABLE_MAX_ROUNDS = 2      # 候补轮数硬上限（与主理人达成的口径一致）：配得再大也只跑到这里

_DNS_KEYS = ("name or service not known", "name not known", "getaddrinfo", "nodename",
             "no such name", "temporary failure in name resolution", "dns")
_CONNECT_KEYS = ("refused", "unreachable", "err_network", "err_connection", "connection",
                 "reset", "eof occurred", "err_socket")
_TLS_KEYS = ("ssl", "certificate", "handshake", "err_cert", "err_https")


def classify(err, site=None):
    """`(失败文本, 站点行) -> 原因档`；认不出来落「其他」，**绝不落空**（空档统计不到＝页面一片沉默）。"""
    s = site or {}
    txt = str(err or "")
    low = txt.lower()
    if "browser" in low or "浏览器" in txt or "executable not found" in low:
        return REASON_BROWSER
    if low.startswith("throttle:") or "预算耗尽" in txt or "请求停止" in txt:
        return REASON_BUDGET
    if not txt.strip():
        return REASON_EMPTY
    if "timeout" in low or "超时" in txt:
        return REASON_TIMEOUT
    _red = str(s.get("redirect_url") or "").strip()
    if _red and _red.rstrip("/") != str(s.get("url") or "").rstrip("/"):
        return REASON_REDIRECT
    try:
        if int(s.get("status") or 0) in (301, 302, 303, 307, 308):
            return REASON_REDIRECT
    except (TypeError, ValueError):
        pass
    if any(k in low for k in _DNS_KEYS):
        return REASON_DNS
    if any(k in low for k in _TLS_KEYS):
        return REASON_TLS
    if any(k in low for k in _CONNECT_KEYS):
        return REASON_CONNECT
    if "没有产出" in txt or low.startswith("退出码") or "exit code" in low:
        return REASON_EMPTY
    return REASON_OTHER


def shot_bucket(stored, site=None):
    """把**落库的** `shot_error` 归回原因档：阶段写进去的是「档｜原文」，前缀就是当时判的那一档。

    为什么不把那段文本再喂一遍 `classify()`：档名与判据关键字不是一回事 —— 实测
    `classify("预算或已停止｜…")` 落「其他」（`REASON_BUDGET` 认的是 `throttle:` / 「预算耗尽」/
    「请求停止」三个词，档名本身一个都不含）。今天侥幸拼得回来，明天改一个档名就**静默改判**，
    而表现是"候补重试偷偷不再重试预算档"这种没人会注意的事。所以：有前缀用前缀，
    没有前缀才回退 `classify()`（续154 之前落的老数据不带档名前缀，那条路必须还走得通）。
    """
    txt = str(stored or "").strip()
    head = txt.split("｜", 1)[0].strip()
    if head in REASONS:
        return head
    return classify(txt, site)


def retryable_shot_error(stored, site=None):
    """这条落库的失败文本该不该进候补重试 —— 判据只有 `RETRYABLE_REASONS` 那一处。"""
    return shot_bucket(stored, site) in RETRYABLE_REASONS


def retry_rounds(settings=None):
    """`screenshot.retry_rounds`：任务正常完成后**最多**再排几轮候补重试。

    三档要分清：代码 `DEFAULTS` 是 0＝关，**随包 `config/settings.yaml` 出厂写 1**（续164，
    主理人点单"空闲再重试"）—— 所以 `load_settings()` 拿到的生效值是 1，而这里那个"键不存在时
    的兜底"仍跟 DEFAULTS 同为 0（`[8bs]` ③a 钉住两边不许分家：兜底跟着文件层走就会让"手工删掉
    这一行的 settings"静默变成"替目标再发一轮包"）。
    非法值 / 负数一律归 0（配歪了不许被读成"用默认悄悄打开"），正数夹到 `RETRYABLE_MAX_ROUNDS`。
    排轮的 runner 与页面上那句"上限几轮"都从这里读（§5.14）。
    """
    cfg = (settings or {}).get("screenshot") or {}
    try:
        n = int(cfg.get("retry_rounds", 0) or 0)
    except (TypeError, ValueError):
        return 0
    return max(0, min(RETRYABLE_MAX_ROUNDS, n))


def _abs_out(p):
    """产物路径**绝对化**：浏览器把 `--screenshot=<相对路径>` 写到**它自己的 CWD**，
    于是我们这边的 out_path 永远不存在 → 静默 0 字节（续64 QA 实测踩到）。
    调用方本来都传绝对路径，这里兜住"将来有人传相对路径"的那种静默失败。

    ⚠️ 用 `Path.absolute()` 而**不是** `Path.resolve()`：本机 Python 3.9.0 上 `resolve()`
    对**不存在**的相对路径会原样返回相对路径（2026-09-28 实测，`resolve()` 返 `rel-shot.png`），
    达不到"绝对化"目的；`absolute()` 稳定返回绝对路径。
    """
    return Path(p).absolute()


def capture(url, out_path, settings=None, timeout=30, throttle=None, want_title=False):
    """给单个 URL 截图，写入 `out_path`。返回 `(ok, err, title)`。

    `throttle`（F2）：传入时这次子进程调用占一个 `"subprocess"` 名额（并消耗预算）。

    成功＝**这一次**真的产出了非空 PNG（用 mtime 认出"旧图还在"不算成功，续140）；
    失败时不碰已有产物 —— 库里 `sites.shot` 可能还指着上一轮那张图，删了就是 GUI 裂图。

    `want_title=True`：在**同一次**浏览器调用里加 `--dump-dom`，把渲染完成后的 DOM 打到 stdout，
    从中取 `<title>` 作为第三个返回值（拿不到就是空串）。为什么要挤进同一次调用：
    有些站（Next.js / Vue 的 SPA 外壳）原始 HTML 里**根本没有** `<title>` —— 实测授权目标
    `agent.targ2.com` 的响应 1298 字节、9 个 `<script>`，无 `<title>` 也无 `og:title`，
    标题由 JS 注入；httpx 与内置探测取不到标题**不是抓取失败**，是源头没有。
    而再起一次浏览器是本模块最贵的动作（单站点 1~3 秒 + 明显内存），所以共用同一次进程、零额外启动。
    不传 `want_title` 时 argv 与改动前逐字节一致（截图行为不受任何影响）。
    """
    binary = browser_path(settings)
    if not binary:
        return False, "未找到可用的无头浏览器（Edge/Chrome）；可在策略配置里填 screenshot.browser", ""
    cfg = (settings or {}).get("screenshot", {}) or {}
    size = str(cfg.get("window") or "1280x900").replace(" ", "")
    out_path = _abs_out(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_profile = tempfile.mkdtemp(prefix="ctfscan-shot-")
    # 续140：成败判据从"文件存在且非空"改成"**这次调用之后**存在、非空、且 mtime 变新"。
    # 为什么：同一个 URL 的 `shots/<md5>.png` 在续跑/追加执行时是同一个路径，旧写法会让
    # "浏览器这次根本没渲染成功"也算成功（旧图替新失败背书 —— 本轮实测踩到）。
    # ⚠️ 不是"先删再跑"：删掉的话，这一轮失败时库里那条 `sites.shot`（上一轮写的）就指向一个
    # 已经不存在的文件 —— GUI 直接裂图，比"报错但旧图还在"更糟。**失败什么都不许动。**
    _t0 = time.time()
    try:
        argv = [binary, *_FLAGS, f"--user-data-dir={tmp_profile}",   # 隔离：不碰用户真实浏览器配置
                f"--window-size={size}", f"--screenshot={out_path}"]
        if want_title:
            argv.append("--dump-dom")             # 渲染后的 DOM 打到 stdout，顺带取标题
        argv.append(str(url))
        rc, _out, err = run_cmd(argv, timeout=int(timeout or 30), throttle=throttle)
        # mtime 必须**严格不早于**这次调用开始（同一次进程里时间戳只会往前走）
        _fresh = False
        try:
            _st = out_path.stat()
            _fresh = _st.st_size > 0 and _st.st_mtime >= _t0
        except OSError:
            _fresh = False
        # 只看 DOM 开头：`<title>` 一定在 `<head>` 里，而 `--dump-dom` 能把整页吐成几 MB，
        # 拿它跑正则纯属浪费（本阶段是给流水线"锦上添花"的，不许变成新的耗时大头）。
        title = html_title(str(_out or "")[:200000]) if want_title else ""
        if _fresh:
            return True, "", title
        # 截不出新图时标题仍可能已经拿到（DOM 出来了、PNG 没写成）—— 别把它一起丢掉；
        # 但**旧 PNG 在场不算成功**（那条 mtime 判据），所以这里如实报失败
        return False, (err or (f"退出码 {rc}" if rc else "没有产出新的截图文件"))[:200], title
    except Exception as e:                        # 兜底：截图失败绝不影响主流程
        return False, str(e)[:200], ""
    finally:
        shutil.rmtree(tmp_profile, ignore_errors=True)


def shot_name(url):
    """由 URL 生成稳定的截图文件名（同一 URL 多次截图会覆盖，不堆垃圾）。"""
    import hashlib
    digest = hashlib.md5(str(url).encode("utf-8", "replace")).hexdigest()[:12]
    return f"{digest}.png"
