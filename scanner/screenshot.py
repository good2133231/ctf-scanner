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
from urllib.parse import urlparse

from . import cdp as cdp_mod
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


def fontconfig_file(settings=None):
    """`screenshot.fontconfig` 指向的 fontconfig 配置文件（不存在返回 ""）。

    留空＝不注入（保持浏览器自己的字体配置）；相对路径按**仓库根**解释，也接受 `~`。
    只做"这个文件在不在"的判定，不读内容、不打印路径（GUI/日志都不需要知道它）。
    """
    cfg = (settings or {}).get("screenshot", {}) or {}
    raw = str(cfg.get("fontconfig") or "").strip()
    if not raw:
        return ""
    p = Path(os.path.expanduser(raw))
    if not p.is_absolute():
        p = Path(__file__).resolve().parent.parent / p
    return str(p) if p.is_file() else ""


def _browser_env(settings=None):
    """给浏览器子进程的环境变量（续175）：只有配了 fontconfig 才返回 dict，否则 None。"""
    fc = fontconfig_file(settings)
    if not fc:
        return None
    env = dict(os.environ)
    env["FONTCONFIG_FILE"] = fc
    return env


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
    """把**落库的** `shot_error` 归回原因档：阶段写进去的是「档｜尝试 N 次（方式 秒）｜原文」（续170 起中间多一段尝试记录），
    前缀仍是当时判的那一档。

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


def attempts_plan_note(settings=None):
    """一句人话：这一轮每张站点**最多**试几次、分别用什么方式。

    必须**由配置现算**（§5.19）：以前模板里写死"每张站点阶段内已先重试过一次"，
    而续170 之后"再打一次同一条 URL"这一支默认已经不做了 —— 那句话要是还留在页面上，
    就是在替代码说谎，而它正是用户判断"要不要再等一轮"的依据。
    """
    steps = ["一次性"]
    if cdp_fallback_enabled(settings):
        steps.append("CDP 兜底")
    txt = " → ".join(steps)
    if len(steps) > 1:
        txt += "（失败前先等 %ds，不等 load）" % fallback_wait(settings)
    else:
        txt += "（兜底已关：超时就是超时，不会再起第二个浏览器进程）"
    return "每张最多 %d 次：%s；3xx 未落地的那类会换成落地页再截一次" % (len(steps), txt)


def error_text(reason, err, attempts=()):
    """把一次失败拼成**落库文本**：`档｜尝试 N 次（一次性 30s + CDP 兜底 45s）｜原文`。

    三段顺序不能换：第一段必须是档名 —— `shot_bucket()` 就是按第一个「｜」前的字判档，
    候补重试与页面上的"还剩几张"都读它（§5.14）。
    `attempts` 是 `[(方式, 秒数), …]`；只成功一次也要写清"试过几次、分别是什么方式"，
    因为主理人问的原话就是「超时 你要显示重试了多少次」——只写"失败"等于让人重新猜。
    """
    parts = [str(reason or REASON_OTHER)]
    n = len(attempts or ())
    if n:
        detail = " + ".join("%s %ss" % (w, int(s or 0)) for w, s in attempts)
        parts.append("尝试 %d 次（%s）" % (n, detail))
    txt = str(err or "").strip()
    if txt:
        parts.append(txt)
    return "｜".join(parts)[:200]


def fallback_wait(settings=None):
    """一次性失败后**先等几秒**再走兜底（主理人：「可以不要那么快急着重试」）。默认 10 秒。

    这段等待必须是**可打断**的（阶段用 `ctx.stopped()` 轮询），否则"点停止"在这里变成摆设。
    夹到 0..120：填 0＝立刻兜底（旧形状），填得再大也不许变成"卡住 worker 十分钟"。
    """
    try:
        n = int(((settings or {}).get("screenshot") or {}).get("fallback_wait", 10))
    except (TypeError, ValueError):
        n = 10
    return max(0, min(120, n))


def settle_ms(settings=None):
    """一次性截图给页面跑完首屏 JS 的时间（`--virtual-time-budget`，毫秒；0=关，续225）。

    夹到 0..15000：填 0 ＝ 退回旧行为；填得再大也不许让一张图等十几秒以上。
    """
    try:
        n = int(((settings or {}).get("screenshot") or {}).get("settle_ms", 3000))
    except (TypeError, ValueError):
        n = 3000
    return max(0, min(15000, n))


def verify_after_js(settings=None):
    """jsmine 跑完后是否复核截图（`screenshot.verify_after_js`，续225）。默认开。"""
    cfg = (settings or {}).get("screenshot") or {}
    return cfg.get("verify_after_js") is not False


def file_md5(path):
    """文件内容 md5；读不到回空串（截图复核用，续225）。"""
    import hashlib
    try:
        return hashlib.md5(Path(path).read_bytes()).hexdigest()
    except OSError:
        return ""


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
                f"--window-size={size}"]
        # 续225：先让首屏 JS / 定时器跑一段时间再落图 —— 直接 `--screenshot` 常在
        # SPA 还停在 loading 骨架时就截了。0 = 不加这个参数（旧行为逐字节不变）。
        _settle = settle_ms(settings)
        if _settle:
            argv.append(f"--virtual-time-budget={_settle}")
        argv.append(f"--screenshot={out_path}")
        if want_title:
            argv.append("--dump-dom")             # 渲染后的 DOM 打到 stdout，顺带取标题
        argv.append(str(url))
        rc, _out, err = run_cmd(argv, timeout=int(timeout or 30), throttle=throttle,
                                extra_env=_browser_env(settings))
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


# ============================ CDP 兜底（续170）============================================
#
# 为什么要这第二条路（主理人点单「让截图更有兼容性」）：一次性 `--screenshot` 只在页面
# **load 完成**时才写 PNG。授权目标里非常常见的一类页面永远不 load —— 首屏引了一条回源慢 /
# 被墙的第三方脚本。本机 Google Chrome 154.0.8037.97 实测（夹具：一条永不返回的
# `<script src>`）：`--virtual-time-budget=4000`、`--timeout=6000`、old/new headless 四种组合
# **全部** 20 秒 0 字节 —— 也就是加开关救不回来；而 CDP 把那条子资源挡掉后同一页面
# 截出 **17,910 字节**（`logs/_shotab.py` / `logs/_cdpab.py`，两份脚本就是这两组数字的出处）。
#
# 三条边界，缺一条就不该上这条路：
# ① **只挡埋点/统计/广告那类域**，且**永不挡页面自己的注册域** —— 挡 CDN 会把页面截成
#    没有样式的空壳，那比"截不到"更误导人（人正是靠这张图判断站点的）；
# ② 只连我们自己起的那个浏览器（`127.0.0.1:<随机端口>`），端口由系统分配、只绑回环，
#    浏览器进程在 `finally` 里一定收掉；`scanner/cdp.py` 里还有一道"拒绝连非回环"的闸；
# ③ 全程仍受同一个 `throttle` 名额与预算约束（它是一次"起子进程"，不豁免）。

_TRACKER_HOSTS = (
    # 只列"对画面没有贡献、又最容易把 load 挂死"的那批。新增条目要说得清它属于哪一类，
    # 不收 CDN / 静态资源域（jsdelivr、unpkg、cloudfront…）—— 那些是页面的内容。
    "google-analytics.com", "googletagmanager.com", "analytics.google.com",
    "doubleclick.net", "googleadservices.com", "googlesyndication.com",
    "adservice.google.com", "facebook.net", "scorecardresearch.com", "quantserve.com",
    "hotjar.com", "clarity.ms", "mixpanel.com", "segment.io", "segment.com",
    "amplitude.com", "appsflyer.com", "branch.io", "cnzz.com", "umeng.com",
)


def cdp_fallback_enabled(settings=None):
    """`screenshot.cdp_fallback`：一次性截图失败后要不要再走一次 CDP 兜底（**默认开**）。

    开在这里而不是"悄悄改行为"：它只在一次性失败后启动，成功路径一个进程都不多起；
    关掉就退回续170 之前的行为（一次性 + 候补轮）。
    """
    return bool(((settings or {}).get("screenshot") or {}).get("cdp_fallback", True))


def cdp_wait(settings=None):
    """兜底这一趟最多花几秒（导航 + 等 load + 要图，全在这一个预算里）。默认 45 秒。

    刻意**不复用** `screenshot.timeout`：那是一次性的预算，两个数揉在一起，改一个会连带
    把另一条路的时间也改了（而页面/日志上写的秒数就成了假话，§5.19）。
    """
    try:
        n = int(((settings or {}).get("screenshot") or {}).get("cdp_wait", 45) or 45)
    except (TypeError, ValueError):
        n = 45
    return max(8, min(180, n))


def shot_block_patterns(url, settings=None):
    """这次兜底要挡的 URL 通配串 → `["*google-analytics.com*", …]`。

    两道收口：① 页面**自己的注册域**（及子域）永不进清单，配置里误填了也剔掉 —— 挡掉自己的
    内容等于截出一张没有样式的空壳，那比"截不到"更误导人；② `block_extra` 只吃"像个域名"
    的条目（去掉前导 `*`/`.` 与空白），别的形态一律不挡（宁可不挡，也不误挡内容）。
    """
    host = urlparse(str(url or "")).hostname or ""
    own = extdom_base(host)
    cfg = ((settings or {}).get("screenshot") or {}).get("block_extra") or []
    out, seen = [], set()
    for raw in list(_TRACKER_HOSTS) + [str(x) for x in cfg]:
        h = raw.strip().lower().lstrip(".*").rstrip("/")
        if not h or "." not in h or " " in h or "/" in h:
            continue                                     # 不像域名的条目一律不用（不猜它想挡什么）
        if h in seen:
            continue
        seen.add(h)
        if own and (h == own or h.endswith("." + own) or own.endswith("." + h)):
            continue        # 页面自己的域**和它的子域**都不挡：挡了就是把内容截成没有样式的空壳
        out.append("*%s*" % h)
    return out


def extdom_base(host):
    """主机名 → 注册域。**产地仍是 `extdom.base_of`**，这里只做一层薄壳避免循环导入。"""
    from .extdom import base_of
    return str(base_of(host) or "")


def capture_cdp(url, out_path, settings=None, timeout=None, throttle=None, want_title=False):
    """CDP 兜底截图：不等 load、只挡埋点域、到点直接问渲染器要一张图。

    返回 `(ok, err, title)`，与 `capture()` **同一个形状**（调用方可以把两条路的结果
    拼进同一句 `shot_error`）。失败原因一律带 `cdp:` 前缀，页面上才分得清是哪条路没成。
    """
    import base64
    import subprocess

    binary = browser_path(settings)
    if not binary:
        return False, "cdp: 未找到可用的无头浏览器（Edge/Chrome）", ""
    budget = float(timeout or cdp_wait(settings))
    t0 = time.time()
    out_path = _abs_out(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    cfg = (settings or {}).get("screenshot", {}) or {}
    size = str(cfg.get("window") or "1280x900").replace(" ", "")
    blocked = shot_block_patterns(url, settings)
    port = cdp_mod.free_port()
    profile = tempfile.mkdtemp(prefix="ctfscan-cdp-")
    argv = [binary, "--headless=old", "--no-sandbox", "--disable-dev-shm-usage",
            "--ignore-certificate-errors", "--disable-gpu", "--hide-scrollbars",
            "--no-first-run", "--no-default-browser-check", "--disable-extensions",
            "--disable-background-networking",
            f"--remote-debugging-port={port}", f"--user-data-dir={profile}",
            f"--window-size={size}", "about:blank"]
    proc = None
    client = None
    try:
        def _do():
            nonlocal proc, client
            proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                    env=_browser_env(settings))
            for _ in range(80):                       # 最多等 8 秒把 CDP 端口起来
                if cdp_mod.ready(port):
                    break
                if proc.poll() is not None:
                    raise RuntimeError("cdp: 无头浏览器启动即退出（退出码 %s）" % proc.returncode)
                time.sleep(0.1)
            else:
                raise RuntimeError("cdp: 调试端口没起来")
            client = cdp_mod.CDP(cdp_mod.ws_url_for(port), timeout=budget)
            sid = client.call("Target.attachToTarget",
                              {"targetId": client.call("Target.createTarget",
                                                       {"url": "about:blank"})["targetId"],
                               "flatten": True}, timeout=min(10, budget))["sessionId"]
            client.call("Page.enable", session_id=sid, timeout=min(10, budget))
            if blocked:
                client.call("Network.enable", session_id=sid, timeout=min(10, budget))
                client.call("Network.setBlockedURLs", {"urls": blocked},
                            session_id=sid, timeout=min(10, budget))
            client.call("Page.navigate", {"url": url}, session_id=sid, timeout=min(15, budget))
            # load 到不到都往下走：这条路的意义就是"不等一个可能永远不来的事件"
            remain = max(0.5, budget - (time.time() - t0) - 8)
            client.wait_event("Page.loadEventFired", session_id=sid, timeout=remain)
            got = client.call("Page.captureScreenshot", {"format": "png"},
                              session_id=sid, timeout=max(2, budget - (time.time() - t0)))
            data = str((got or {}).get("data") or "")
            if not data:
                raise RuntimeError("cdp: captureScreenshot 没带回图片数据")
            raw = base64.b64decode(data)
            if not raw:
                raise RuntimeError("cdp: 解码后是 0 字节")
            tmp = out_path.with_suffix(out_path.suffix + ".part")
            tmp.write_bytes(raw)
            os.replace(tmp, out_path)                # 原子替换：失败时绝不动已有产物
            title = ""
            if want_title:
                try:
                    title = str(client.ev("document.title || ''", session_id=sid,
                                           timeout=min(8, max(1, budget - (time.time() - t0)))) or "")
                except Exception:
                    title = ""
            return (True, "", title) if raw else (False, "cdp: 0 字节", title)

        if throttle is None:
            return _do()
        with throttle.slot("subprocess"):
            return _do()
    except Exception as e:
        return False, ("%s" % e)[:200], ""
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass
        if proc is not None:
            try:
                proc.terminate()
                proc.wait(timeout=8)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        shutil.rmtree(profile, ignore_errors=True)
