"""CTFScanner Web 控制台（仿 ARL 交互形态：任务管理 / 资产列表 / 漏洞列表 / POC 管理）。

说明（客观取舍）：
- 单进程 Flask + 后台线程执行流水线，满足 CTF 单机场景；生产化改造（任务队列、鉴权体系）
  见 docs/roadmap.md；
- 默认仅监听 127.0.0.1。续46 起是**多用户**：账号 + 口令登录（`scanner/users.py`，口令只存
  pbkdf2 派生值），分「管理员 / 子用户」两级角色 —— 子用户能建任务跑扫描、看结果，但**进不去**
  策略配置 / POC 管理 / 账号管理（路由层 + 侧边栏两层都挡，见 `admin_required`）；
  `config/settings.yaml` 的 `gui.token` 只作**迁移期的引导口令**：库里还没有任何账号时它仍可
  登录（管理员身份），一旦建了第一个账号就立即失效（防"旧口令长期是后门"）；
- 续32 起有两道**本机守卫**（Host 白名单防 DNS rebinding + 写操作的 Origin/Referer 校验，
  见 `create_app` 的 `_local_guard`），它们是**网络侧**兜底，与"你是谁、能看什么"是两件事；
- 续47 起**有 HTTPS 落地路径**：由反向代理终止 TLS（Caddy/Nginx 样例 + 自签路径见
  docs/deploy-https.md），应用侧只需 `gui.behind_proxy`（信任 X-Forwarded-*）、
  `gui.allowed_hosts`（放行部署域名）、`gui.secure_cookie`（会话 Cookie 加 Secure）三项配置，
  默认值都是**最保守**的关/空。
- 续48 起有**访问审计流水**（`scanner/audit.py`：谁/何时/从哪个 IP/做了什么/成败，只记元数据、
  绝不记口令凭据；管理员在「访问审计」页查看）与**登录限速/失败锁定**（`scanner/login_guard.py`：
  按 IP 为主、按用户名兜底，被锁返回 429 + Retry-After，文案与"账号是否存在"无关）；
  两项都是**保护性开关、默认开但阈值宽松**，可在策略配置里调（见 `gui.login_lockout` / `gui.audit`）。
  **故意暴露到局域网/公网前**，请读 docs/deploy-https.md 与 docs/security-notice.md。
"""
import functools
import html
import json
import shutil
import socket
import tempfile
import threading
import time
from pathlib import Path
from urllib.parse import quote, urlparse

from flask import (Flask, Response, abort, jsonify, redirect, send_file,
                   render_template, request, session, url_for)
# 反向代理支持（续47）：`ProxyFix` 随 werkzeug 一起装（Flask 的依赖），**不新增第三方依赖**。
# 只在 `gui.behind_proxy` 显式打开时才挂上 —— 见 `create_app` 里的说明。
from werkzeug.middleware.proxy_fix import ProxyFix

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner import (audit, auth as taskauth, blacklist, cdn, certs as certs_mod, db,
                     devfixture, devmode, dnsq,
                     extdom, login_guard, queue, screenshot, users)
from scanner.config import BASE_DIR, load_settings, save_settings
from scanner.log import get_logger
from scanner.owasp import checks as owasp_checks
from scanner.pocs import engine
from scanner import runner
from scanner.runner import STAGE_ORDER, run_task, sync_pocs
from scanner.stages.cert import pick_targets as cert_pick_targets
from scanner.utils import format_duration, pool_run, rel_display

logger = get_logger("gui")

# 资产来源 → 页面上的可读标签（「子域名 / 拓展域名」页的来源列用它渲染成中文标签）
# 解析失败/未解析原因 → 页面文案（子域名/拓展域名/IP 页共用）。
# 用户 2026-09-22 要求：没有 IP 时必须标出**具体原因**，不能只显示一个 "-"。
IP_NOTE_LABELS = {
    "nxdomain": "域名不存在(NXDOMAIN)",
    "no-a": "无 A 记录",
    "servfail": "DNS 故障",
    "refused": "DNS 拒绝",
    "timeout": "解析超时",
    "error": "解析异常",
    "empty": "空域名",
    "over-limit": "超出回填上限(subdomain.max_resolve)",
}


def _export_error_page(err, task_id):
    """导出失败时给用户看的页面（纯静态 HTML，不经模板）：说清**为什么**失败 + 下一步怎么走。

    之所以不用模板：这是一条只在异常路径上出现的极简页面，为它开模板/上下文不值得；
    里面的 `err` 与 `task_id` 都做了转义。
    """
    return ("<!DOCTYPE html><html lang='zh-CN'><head><meta charset='utf-8'>"
            "<title>导出失败</title></head><body style='font:14px/1.7 sans-serif;margin:32px'>"
            "<h1 style='font-size:18px'>导出 PDF 失败</h1>"
            f"<p>原因：<code>{html.escape(str(err or '未知错误'))}</code></p>"
            "<p>可以：①改导出 HTML（下载后用浏览器「打印 → 另存为 PDF」）；"
            "②在「策略配置 → 站点截图」里把浏览器路径填进 <code>screenshot.browser</code>，"
            "PDF 导出复用同一条探测路径。</p>"
            f"<p><a href='/tasks/{int(task_id)}'>← 返回任务</a> ｜ "
            f"<a href='/tasks/{int(task_id)}/export?fmt=html'>下载 HTML 报告</a></p>"
            "</body></html>")


def ip_note_label(note):
    """把原因码翻译成中文；空值返回空串（表示解析正常）。"""
    text = str(note or "").strip()
    if not text:
        return ""
    return IP_NOTE_LABELS.get(text, text)


SOURCE_LABELS = {
    "subfinder": "被动(subfinder)",
    "puredns": "爆破(puredns)",
    "dns-brute(fallback)": "爆破(内置)",
    "js:mine": "JS 挖掘",
    # 两个 FOFA 来源都显式带上「FOFA」字样：用户要求一眼看出哪些资产是 FOFA 找出来的
    "osint:cseg": "C 段反查",
    "osint:fofa": "FOFA·ICO 反查",
    "osint:fofa-cert": "FOFA·证书反查",
    "osint:fofa-title": "FOFA·标题反查",
    # 批次 4 新增的三家同源/同源类来源：都带厂商名，一眼看出是哪个平台找出来的
    "osint:shodan": "Shodan·ICO 反查",
    "osint:quake": "Quake·ICO 反查",
    "osint:ctlog": "CT 日志(crt.sh)",
    # 自动拓展扫描（`auto_expand`）：目标是子域时，把它自己也记成一条子域名资产
    "target": "目标自带子域",
}


def source_label(source):
    """把 `source` 字段翻译成可读标签；未知来源原样返回（如 `passive:crt.sh` 归一为"被动"）。"""
    text = str(source or "").strip()
    if not text:
        return "-"
    if text in SOURCE_LABELS:
        return SOURCE_LABELS[text]
    if text.startswith("passive:"):
        return f"被动({text.split(':', 1)[1]})"
    # 归属追加（`scanner/extdom.py`）：`promote:<原来源>` —— 说明这条**原本是拓展域名**，
    # 因为注册域命中任务目标而被追加成自身子域名（"分域名而来"的出处一眼可查）。
    if text.startswith(extdom.PROMOTE_PREFIX):
        return "归属追加(" + source_label(text[len(extdom.PROMOTE_PREFIX):]) + ")"
    return text


def _and_where(*parts):
    """把若干 SQL 条件用 AND 拼起来，忽略空值（避免条件为空时生成 `() AND ...`）。"""
    items = [p for p in parts if p]
    return " AND ".join(f"({p})" for p in items) if items else None


def _changed_sections(old, new):
    """比较"提交上来的配置"与"当前配置"，返回**顶层区块名**列表（续48 审计用）。

    只回**区块名**（`gui` / `limits` / `dirscan` …），不回叶子键名 —— 续48 的红线是
    "审计里不得出现口令/凭据值"；把键名也省掉，等于连 `gui.token` 这种**键名**都不落库，
    彻底断掉"键名 + 值"一起泄漏的可能。比较只针对 `new` 里出现的键：表单只提交它管的那些
    字段，未提交的（如 `gui.allowed_hosts`）不该被判成"变更"。
    """
    out = []
    for k, nv in (new or {}).items():
        if k == "keys":          # keys 段来自独立文件，不属于策略配置
            continue
        ov = (old or {}).get(k)
        if isinstance(nv, dict):
            if _changed_sections(ov if isinstance(ov, dict) else {}, nv):
                out.append(k)
        elif nv != ov:
            out.append(k)
    return sorted(out)


def _safe_next(target, fallback):
    """只放行**站内相对路径**的 `next` 跳转目标，其余一律回退（防开放重定向）。

    `next` 来自表单，可被构造（如 `next=https://evil.com`），直接 `redirect()` 会把
    用户带到任意外站。这里只接受以单个 `/` 开头、不含反斜杠的目标 —— 顺带挡住
    `//evil.com`（协议相对）与 `/\\evil.com`（浏览器按路径规范化当外站）两种绕过写法。
    """
    t = str(target or "").strip()
    if t.startswith("/") and not t.startswith("//") and "\\" not in t:
        return t
    return fallback


def _lockout_message(retry_after):
    """登录限速拦截页面的**固定文案**（续48）。

    刻意与"账号是否存在"完全无关：被锁的可能是真实账号，也可能根本不存在 —— 两种情形返回
    **逐字节相同**的页面，才不会被人拿来枚举用户名（"被锁=存在"本身就是一条泄漏）。
    """
    return (f"登录尝试过于频繁，已被暂时限制；请约 {int(retry_after)} 秒后重试，"
            "或联系管理员。")


def _source_auth(from_task):
    """从**来源任务**的 options 里取出登录态请求头，供补扫/拓展探测继承。

    为什么补扫要继承（而不是每次重填）：用户点「深度目录补扫 / 漏洞复查」时心里想的是
    "把刚才那个任务的资产再挖深一点"，如果新任务丢了 Cookie，扫的就是**未登录视角**——
    结果看起来"没洞"，而这恰恰是登录态扫描最容易产生的误判（false negative 被读成"安全"）。
    取不到（没有来源任务 / 原任务没配登录态）就返回 `{}`，即新任务不带登录态。
    """
    try:
        tid = int(from_task)
    except (TypeError, ValueError):
        return {}
    row = db.get_task(tid)
    if not row:
        return {}
    try:
        top = json.loads(row["options"] or "{}")
    except (TypeError, ValueError):
        return {}
    return taskauth.from_task_options(top if isinstance(top, dict) else {})


def parse_port_list(spec, default=None):
    """把页面上的端口清单（`443,8443 9443` 这类逗号/空格混写）解析成排序去重的列表。

    非法项直接跳过；解析结果为空时回退 `default`（默认 443/8443/9443）——
    否则用户把这一栏填错就会让 cert 阶段"永远挑不到站点"，且页面上看不出原因。
    """
    out = []
    for chunk in str(spec or "").replace(",", " ").split():
        if chunk.isdigit() and 0 < int(chunk) <= 65535 and int(chunk) not in out:
            out.append(int(chunk))
    return sorted(out) or list(default or [443, 8443, 9443])


def run_duration_text(task):
    """「目标与配置」页签里「运行时长」一行要显示的文案（续35）。

    四种情形各说各话，**不编数**是底线：
    - 本功能上线前建的老任务没有 `started_at` → `-`（不拿 `created_at` 顶一个假起点）；
    - 已收场（done / stopped / failed）→ 累计实际运行秒数（续跑 / 追加跑的每一段都在里面）；
    - 正在跑 → `运行中，已 X`（页面轮询时这个数会自己长）；
    - 进程被强杀且**还没被对账**（`finished_at` 空但不是 `running`）→ 只报已确认的累计值，
      并明确标注尾段没算进去 —— 静默少报会让人以为"扫得很快"。
    """
    if not str(task.get("started_at") or "").strip():
        return "-"
    seconds = format_duration(db.task_run_seconds(task))
    if str(task.get("finished_at") or "").strip():
        return seconds
    if str(task.get("status") or "") == "running":
        return "运行中，已 " + seconds
    return seconds + "（上次运行被中断，尾段未计入）"


# 本机访问的白名单口径（续32）：`127.0.0.1` / `localhost` / IPv6 回环。
# 用于两道"仅限本机"的技术落实 —— Host 白名单（挡 DNS rebinding）与会话 Cookie 的 SameSite。
# 注意：这里**不含** `0.0.0.0`（它是"监听所有网卡"的绑定地址，不是可访问的主机名）。
_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


def _host_of(netloc):
    """从 `host[:port]` / `[::1]:5000` 里取出**小写主机名**；取不出返回空串（不猜）。

    **只用于 Host 白名单**（"是不是回环名"）—— 回环地址上的任意端口都该放行。
    跨站校验不能用它：它**丢掉端口**，而端口恰恰是那道校验的关键（见 `_authority`）。
    """
    text = str(netloc or "").strip().lower()
    if text.startswith("["):                 # IPv6 字面量：`[::1]:5000`
        return text[1:].split("]", 1)[0]
    return text.rsplit(":", 1)[0] if ":" in text else text


def _allowed_hosts(gui):
    """Host 白名单的放行集合 = 回环名 ∪ `gui.allowed_hosts` 里归一化后的主机名。

    为什么必须可配置（续47）：控制台放到服务器给队友用时，由**反向代理终止 TLS** 并转发，
    浏览器发来的 `Host` 是**部署域名**（如 `scanner.example.com`）—— 续32 那道"只认回环名"
    的白名单会把**每一个请求都 403**（控制台整站打不开，且现象很像"服务没起来"）。
    所以放行集合要能显式扩；但**只允许显式枚举**：含 `*` / `?` 的值一律忽略并在启动时告警
    —— 宁可让用户 403 之后去看 `docs/deploy-https.md`，也不提供"一键关掉 DNS rebinding 防护"
    的口子（那种口子一旦存在，就一定会被图省事地打开）。

    返回 `(allowed, bad)`：`allowed` 是放行集合（`frozenset` 语义），`bad` 是被忽略的非法值
    （给 `serve()` 打告警用）。
    """
    allowed = set(_LOOPBACK_HOSTS)
    bad = []
    raw = (gui or {}).get("allowed_hosts") if isinstance(gui, dict) else None
    if isinstance(raw, str):                       # 也接受 "a.com,b.com" / "a.com b.com" 这种手写
        raw = raw.replace(",", " ").split()
    for item in (raw or []):
        text = str(item or "").strip()
        if not text:
            continue
        if "://" in text:                          # 顺手接受整条 URL：只取主机名部分
            text = urlparse(text).netloc or text
        if "*" in text or "?" in text:             # 通配一律不认（见 docstring）
            bad.append(text)
            continue
        name = _host_of(text)
        if not name or name in _LOOPBACK_HOSTS:
            continue                               # 空值 / 回环名：集合里本来就有
        allowed.add(name)
    return allowed, bad


# 默认端口：浏览器在默认端口下**不写端口**（Host 与 Origin 都省略），所以要按 scheme 归一，
# 否则 `http://127.0.0.1` 与 Host `127.0.0.1` 会被误判成不同源，正常请求被自己挡掉。
_DEFAULT_PORTS = {"http": "80", "https": "443"}


def _authority(value):
    """把 `[scheme://]host[:port]` 归一成**可比对的权威段**（小写、去默认端口）；取不出返回空串。

    跨站校验必须比到端口这一层：**Cookie 不按端口隔离** —— 同机另一个 Web 服务
    （如 `127.0.0.1:9999`）向本控制台发起的请求照样会带上会话 Cookie，
    只比主机名就会把这类请求放过去（它正是这道校验存在的理由）。
    """
    text = str(value or "").strip().lower()
    scheme = ""
    if "://" in text:
        parsed = urlparse(text)
        scheme, text = parsed.scheme, parsed.netloc
    text = text.rstrip(".")
    if not text:
        return ""
    if text.startswith("["):                 # IPv6 字面量：`[::1]:5000`
        end = text.find("]")
        if end == -1:
            return text
        host, rest = text[:end + 1], text[end + 1:]
    else:
        host, _, tail = text.partition(":")
        rest = f":{tail}" if tail else ""
    port = rest[1:] if rest.startswith(":") else ""
    if port and port == _DEFAULT_PORTS.get(scheme):
        port = ""
    return f"{host}:{port}" if port else host


def _client_ip():
    """客户端 IP（审计与登录限速用）—— 取 `request.remote_addr`。

    **behind_proxy 的注意点**（续47/续48）：开了 `gui.behind_proxy` 时，`ProxyFix` 会把
    `remote_addr` 改写成 `X-Forwarded-For` 的**最后一跳**；因此"应用只被自己的反向代理访问"
    这条前提必须成立（否则任何人都能伪造这个头，把限速按 IP 的判据整个绕开）。
    这一条写进 docs/deploy-https.md §7。取不到（极端环境）返回空串，审计里记 `-`。
    """
    try:
        return str(request.remote_addr or "")
    except Exception:      # noqa: BLE001 - 极端环境下没有 request 上下文
        return ""


# 续50：内置靶场的**进程内句柄**（由「开发模式」页的启动/停止按钮显式控制）。
# 生命周期刻意做成"显式按钮控制"，不做成"入队后自动起、跑完自动关" —— 队列里任务的收尾点
# 不可靠（进程被杀 / 异常收场），自动关容易泄漏端口。见 scanner/devfixture.py。
_DEV_FIXTURE = {"httpd": None, "base": ""}


def _dev_fixture_start(port=0):
    """起内置靶场（已在跑则复用），返回 `base_url`；失败返回空串。"""
    if _DEV_FIXTURE.get("httpd") is not None:
        return _DEV_FIXTURE.get("base") or ""
    try:
        httpd, base = devfixture.start(int(port or 0))
    except Exception as e:      # noqa: BLE001 - 端口占用等：只记一行，不让页面崩
        logger.warning(f"[dev] 内置靶场启动失败：{e}")
        return ""
    _DEV_FIXTURE["httpd"], _DEV_FIXTURE["base"] = httpd, base
    return base


def _dev_fixture_stop():
    """停内置靶场；返回 True 表示确实停了一个（本就没在跑返回 False）。"""
    httpd = _DEV_FIXTURE.get("httpd")
    if httpd is None:
        return False
    try:
        devfixture.stop(httpd)
    finally:
        _DEV_FIXTURE["httpd"], _DEV_FIXTURE["base"] = None, ""
    return True


def create_app():
    settings = load_settings()
    app = Flask(__name__)
    app.secret_key = f"ctfscanner::{settings.get('gui', {}).get('token', '')}"
    # 模板里可直接调用 `source_label('osint:fofa')` → 「ICO 反查」（来源列的可读标签）
    app.jinja_env.globals["source_label"] = source_label
    app.jinja_env.globals["ip_note_label"] = ip_note_label
    # 续50：开发模式开关 —— 供 base.html 决定是否渲染「开发模式」侧栏入口。
    # 与 gui.host / allowed_hosts 同口径：改 config/settings.yaml 后需**重启控制台**才生效。
    app.jinja_env.globals["dev_enabled"] = devmode.enabled(settings)
    db.init_db()
    # 启动时对账（续49 语义变更）：进程重启后，之前 status='running' 的孤儿任务没人推进 ——
    # 带队列运行规格的**重新入队**（等 worker 接着跑），无规格的（CLI 直跑 / 老库行）仍标 failed；
    # pid 仍存活的跳过。详见 db.reconcile_orphan_tasks。
    # 注意：**worker 不在这里启动** —— `create_app()` 会被测试/WSGI 在 import 期调用，
    # 在工厂里起后台线程会产生 import 副作用；真正的启动点在控制台进程入口 `serve()`。
    db.reconcile_orphan_tasks()
    sync_pocs(settings)
    # 续48：启动时清一次过期审计（保留期见 gui.audit.retention_days）与过期登录限速计数。
    # 两者都是 best-effort（内部已 try/except），失败只 warning，绝不影响控制台启动。
    audit.prune(settings=settings)
    login_guard.prune(settings=settings)

    # 续50：开发模式开启时**醒目提示** —— 它把所有配额压到 1，只适合流程自检，
    # 拿它扫真实目标会得到"几乎什么都没扫到"的假象。放在启动段（与上面两条 prune 同处）。
    if devmode.enabled(settings):
        print("[!] ⚠️ 开发模式已开启（dev.enabled=true）：所有配额压到 1，"
              "仅供流程自检，勿用于真实目标。侧栏「开发模式」页可起内置靶场 / 跑全流程自检。")

    # ---------- 鉴权 ----------

    # 会话 Cookie 显式收紧（续32）：不依赖浏览器默认值 —— `SameSite=Lax` 让**跨站 POST 不携带**
    # 这个 Cookie（现代浏览器默认就是 Lax，但"依赖默认值"在旧浏览器上等于没有），
    # `HttpOnly` 让页面脚本读不到它。注意 Cookie **不按端口隔离**，所以同机的另一个 Web 服务
    # 访问 `127.0.0.1:5000` 时仍算同站、Cookie 照样会带上 —— 这就是下面还必须校验 Origin 的原因。
    # `Secure`（续47）默认**关**：走 HTTP 时带 `Secure` 的 Cookie 浏览器**根本不回传**，
    # 等于登录不上 —— 所以它是"上 HTTPS（反向代理终止 TLS）之后才开"的开关，
    # 由 `gui.secure_cookie` 控制，见 docs/deploy-https.md。
    _gui_cfg = settings.get("gui") or {}
    app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                      SESSION_COOKIE_SECURE=bool(_gui_cfg.get("secure_cookie")))
    # 信任反向代理转发的 `X-Forwarded-*`（续47）：**必须显式打开，默认关**。
    # 为什么默认关：`X-Forwarded-*` 是**请求头**，任何客户端都能自己塞一个
    # `X-Forwarded-Host: evil.com` —— 无条件信任等于把"我以为你是谁"交给攻击者决定
    # （Host 白名单与 Origin 校验会一起失效）。只有"应用只被自己的反代访问"时才该开，
    # 且只信一跳（`x_for=1, x_proto=1, x_host=1`：只取最后一个代理追加的那段）。
    # 为什么需要它：反代常用 `Host: 127.0.0.1:5000` 回源、把真实域名放 `X-Forwarded-Host`，
    # 此时 `request.host` 是 `127.0.0.1:5000` 而浏览器 `Origin` 是 `https://<域名>` ——
    # 下面 `_local_guard` 的 Origin/Host 比对会**每个写请求都 403**。
    if _gui_cfg.get("behind_proxy"):
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    # Host 白名单（续32 立、续47 可配）：只在**绑定回环地址**或**显式配了 allowed_hosts**
    # 时强制校验；用户显式绑到局域网/公网又没配白名单时无法预知他用哪个地址访问，
    # 强制会把人直接挡在门外（那种用法本就该先做反向代理 + 白名单，`serve()` 会打警告）。
    # `gui.host` / `allowed_hosts` 改了要重启才生效，与 `app.run` 的取值时点一致。
    _bound_loopback = _host_of(_gui_cfg.get("host", "127.0.0.1")) in _LOOPBACK_HOSTS
    _allowed, _bad_allowed = _allowed_hosts(_gui_cfg)
    # 挂在 `app.config` 上（而不是闭包变量）有两个理由：① `serve()` 要打印放行清单；
    # ② 测试可以对它做**变异证伪**（把集合改坏，看断言是否真的变红，见 tests/smoke.py [7i]）。
    app.config["CS_ALLOWED_HOSTS"] = frozenset(_allowed)
    app.config["CS_GUARD_HOST"] = bool(_allowed - _LOOPBACK_HOSTS) or _bound_loopback
    app.config["CS_BAD_ALLOWED_HOSTS"] = tuple(_bad_allowed)

    @app.before_request
    def _local_guard():
        """续32「仅限本机使用」的两道**技术**落实（此前只有文档里一句"切勿部署到公网"）。

        ① **Host 白名单**（挡 DNS rebinding）：攻击者页面把自己的域名解析到 `127.0.0.1` 后，
           浏览器就认为它与本机控制台"同源"，于是能带着 Cookie 打进来；默认口令 `ctfscanner`
           又是公开写在代码里的 —— 两件事一叠加，用户只要在开着控制台时访问了恶意页面，
           扫描器就被整个接管（能拿它去打任意目标、并用上已配置的登录态）。校验 `Host`
           必须是回环名即可挡住整类攻击。续47 起放行集合可用 `gui.allowed_hosts`
           **显式枚举**扩展（部署到服务器时浏览器发来的 Host 是域名，不扩就整站 403），
           但**不含通配**：`*` 这类值被忽略（见 `_allowed_hosts`）。
        ② **跨站状态变更拦截**：只对写方法（POST/PUT/PATCH/DELETE）校验 `Origin`（无 `Origin`
           时退回 `Referer`），要求其**权威段**与本请求的 `Host` 一致 —— 比的是 `_authority()`
           归一后的 `主机[:端口]`，**端口参与比对**（Cookie 不按端口隔离，同机另一个服务
           发起的请求同样危险），默认端口按 scheme 归一（浏览器在默认端口下不写端口）。
           两者都缺失时放行（curl / 脚本 / 老浏览器本就不带这两个头，本机工具必须能用）；
           `Origin: null`（沙箱 iframe、`file://` 页面）**不放行**。

        刻意**不**做"每个表单塞 CSRF token"：本控制台的表单与 fetch 调用点有几十处，逐处改造
        与 ② 的防护面重叠，而漏掉任何一处就是"看起来有防护、实际有缺口"；`Origin` 校验在
        中间件层**一次性覆盖所有写操作**，不存在漏一个表单的可能。
        """
        # 放行集合**每次请求现读** `app.config`：测试里的"变异证伪"（把它改坏，看断言是否变红）
        # 才能落在同一条代码路径上；顺带避免把配置烤进闭包（`serve()` 之外没人会改它，代价是一次字典取值）。
        if app.config.get("CS_GUARD_HOST"):
            host = _host_of(request.host)
            if host not in app.config["CS_ALLOWED_HOSTS"]:
                abort(403, description="Host 不在允许列表内"
                                       "（未配置 gui.allowed_hosts 时仅允许回环地址；"
                                       "部署到服务器请见 docs/deploy-https.md）")
        if request.method in ("GET", "HEAD", "OPTIONS"):
            return None
        origin = (request.headers.get("Origin") or "").strip()
        if origin:
            if origin.lower() == "null" or _authority(origin) != _authority(request.host):
                abort(403, description="跨站请求被拒绝：Origin 与 Host 不一致")
            return None
        referer = (request.headers.get("Referer") or "").strip()
        if referer and _authority(referer) != _authority(request.host):
            abort(403, description="跨站请求被拒绝：Referer 与 Host 不一致")
        return None

    # 强制改密期间仍然放行的端点（少了这张白名单，"必须改密"会把自己卡成跳转死循环）
    _MUST_CHANGE_ENDPOINTS = {"login", "logout", "profile", "static"}

    def _session_user():
        """当前登录者（`{id, username, role, must_change}`）或 None —— **登录态的唯一口径**。

        三件事都在这里收口，别处不许自己读 session 判身份：
        ① 会话里要有身份（续32 那个布尔 `auth` 保留下来只为兼容老会话）；
        ② 有 `uid` 的会话**每次回库核一遍**：管理员刚把某账号停用或降级时，那人的浏览器里
           还留着旧会话 —— 不回库就等于"停用要等他下次登录才生效"，口令已经可疑的场景里
           这个延迟不可接受（核查时直接清会话，等于当场踢下线）；
        ③ 没有 `uid` 的是**引导会话**（用 `gui.token` 登进来的），只在"库里还没有任何账号"
           的迁移期有效；建了第一个账号后立刻作废 —— 旧口令不该长期是后门。
        """
        if not session.get("auth"):
            return None
        uid = session.get("uid")
        if uid:
            row = users.get_user(int(uid))
            if not row or int(row["enabled"] or 0) != 1:
                session.clear()          # 账号被删/被停用 → 当场下线，不等下次登录
                return None
            role = row["role"] if row["role"] in users.ROLES else users.ROLE_USER
            return {"id": int(row["id"]), "username": row["username"], "role": role,
                    "must_change": int(row["must_change"] or 0) == 1}
        if users.count_users() > 0:      # 已经有真账号了 → 引导会话作废
            session.clear()
            return None
        role = session.get("role")
        return {"id": 0, "username": str(session.get("user") or "admin"),
                "role": role if role in users.ROLES else users.ROLE_ADMIN,
                "must_change": False}

    @app.context_processor
    def _inject_me():
        """让每个模板都能拿到 `me`（当前登录者），侧边栏据此隐藏无权入口。"""
        return {"me": _session_user()}

    # ---------- 续48：访问审计 + 登录限速（统一收口，失败绝不影响主流程） ----------

    def _audit(kind, target="", detail="", ok=True, actor=None, actor_role=None):
        """审计写入的统一入口：actor/role 默认取当前登录者。

        `audit.record` 自身已 try/except；这里再包一层是为了兜住 `_session_user()` 可能抛的
        异常 —— 任何情况下审计都不能把主流程（建任务 / 改配置 / 登录）带崩。
        """
        try:
            me = _session_user()
            audit.record(kind,
                         actor if actor is not None else (me["username"] if me else ""),
                         _client_ip(), target=target, detail=detail, ok=ok,
                         actor_role=(actor_role if actor_role is not None
                                     else (me["role"] if me else "")),
                         settings=settings)
        except Exception as e:      # noqa: BLE001
            logger.warning(f"[gui] 审计写入失败（已忽略）：{e}")

    def _guard_check(ip, username):
        """问限速守卫（只读）。守卫自身出错 → 放行本次登录（可用性优先），并 warning。"""
        try:
            return login_guard.check(ip, username, settings)
        except Exception as e:      # noqa: BLE001
            logger.warning(f"[gui] 登录限速检查失败（放行本次）：{e}")
            return login_guard.Verdict(False, 0, "")

    def _guard_fail(ip, username):
        try:
            login_guard.record_fail(ip, username, settings)
        except Exception as e:      # noqa: BLE001
            logger.warning(f"[gui] 登录失败计数写入失败（已忽略）：{e}")

    def _guard_ok(ip, username):
        try:
            login_guard.record_success(ip, username, settings)
        except Exception as e:      # noqa: BLE001
            logger.warning(f"[gui] 登录成功计数清理失败（已忽略）：{e}")

    def login_required(fn):
        @functools.wraps(fn)
        def wrapper(*a, **k):
            me = _session_user()
            if not me:
                return redirect(url_for("login"))
            # 管理员建号时一定知道初始口令 → 首次登录强制改掉（`/profile` 自己放行）
            if me["must_change"] and request.endpoint not in _MUST_CHANGE_ENDPOINTS:
                return redirect(url_for("profile"))
            return fn(*a, **k)
        return wrapper

    def _denied(msg):
        """无权访问的**明确**响应：403 + 一句话说清"为什么"。

        刻意不做"悄悄跳回首页"：那会让人以为是自己点错了，而这里要传达的是
        "你的账号本来就没这个权限"—— 子用户看不到配置，正是本次要实现的东西。
        """
        who = str(session.get("user") or "-")
        return ("<!doctype html><meta charset='utf-8'><title>无权限</title>"
                "<div style='font:14px/1.7 sans-serif;margin:40px'>"
                "<h3 style='font-size:16px;margin:0 0 8px'>无权限</h3>"
                f"<p>{html.escape(str(msg))}</p>"
                f"<p style='color:#888'>当前账号：<code>{html.escape(who)}</code>"
                "（仅管理员可用）</p>"
                f"<p><a href='{url_for('dashboard')}'>← 返回仪表盘</a></p></div>"), 403

    def admin_required(fn):
        """管理员门：续46 的多用户里**只有管理员**能进策略配置 / POC 管理 / 账号管理。

        为什么是"装饰器 + 侧边栏隐藏"两层而不是只藏入口：藏入口只是 UI 纪律，
        URL 直接敲进来照样能打开 —— 真正的控制必须在路由层，且要**回库取角色**
        （不能信会话里那份，管理员刚把你降级时那份是过期的）。
        """
        @functools.wraps(fn)
        def wrapper(*a, **k):
            me = _session_user()
            if not me:
                return redirect(url_for("login"))
            if me["role"] != users.ROLE_ADMIN:
                # 续48：越权访问也留一条流水（"子用户试图打开管理页"本身是值得知道的事）
                _audit(audit.KIND_DENIED, target=request.path, ok=False,
                       detail="非管理员访问管理页被拒")
                return _denied("此页面仅管理员可访问（子用户只能使用扫描功能与查看结果）")
            return fn(*a, **k)
        return wrapper

    @app.route("/login", methods=["GET", "POST"])
    def login():
        error = ""
        # 迁移期引导的开关：**库里还没有账号**时旧的共享口令仍可登录（见下）
        bootstrap = users.count_users() == 0
        if request.method == "POST":
            ip = _client_ip()
            username = (request.form.get("username") or "").strip()
            password = request.form.get("password") or ""
            # `token` 是续32 时代老表单/脚本用的字段名，迁移期继续收（不收会让老脚本 401）
            token = request.form.get("token") or ""
            target = _safe_next(request.form.get("next"), url_for("dashboard"))
            # 续48 ① **先问限速守卫**（只读）：被锁就直接 429 + Retry-After，既不校验口令、
            #   也不累加计数。守卫只看"提交的用户名 + IP"、**不查库** → 账号是否存在不影响响应文案。
            #   这一步在**所有分支之前**，因此 `gui.token` 引导口令登录同样受 IP 限速。
            verdict = _guard_check(ip, username)
            if verdict.locked:
                # 续48 复核返工：**这里刻意不写审计**。被拦截的请求每次都会走到这一支，若在此写审计，
                # 未认证者可按请求速率持续往 audit_log 追加（磁盘增长 + 抢全库唯一的写锁 → 与扫描主流程
                # 的批量写入争锁、拖慢甚至搞挂）。"被拦截"的落库点已收口到 login_guard 里"锁刚被创建"
                # 那一刻（一个锁窗口内最多一条），见 scanner/login_guard.py::_audit_lock。
                logger.info(f"[gui] 登录被限速拦截：{username or '(引导口令)'}（{verdict.reason}）")
                resp = app.make_response(render_template(
                    "login.html", error=_lockout_message(verdict.retry_after), bootstrap=bootstrap))
                resp.status_code = 429
                resp.headers["Retry-After"] = str(int(verdict.retry_after))
                return resp
            # `login_fail` 侧**无需额外限流**：失败分支只在"守卫未判锁"时才可达，而 `record_fail` 一旦把
            # 该 IP / 用户名推到阈值就会创建锁 → 之后请求都在上面那一支被 429 拦下，根本到不了这里。
            # 因此每个键在一个窗口内最多留下 `max_fails_per_*` 条（默认 10 / 20），天然有界。
            # （若管理员把 `gui.login_lockout.enabled` 关掉、或把阈值设为 0，失败审计就不再被限 —— 那是
            #   管理员显式选择"不限速"，此时审计量随请求量增长属预期行为。）
            if username:
                row = users.check_login(username, password)
                if row is None:
                    error = "用户名或口令错误"
                    logger.info(f"[gui] 登录失败：{username}（用户名或口令错误）")
                    _guard_fail(ip, username)
                    _audit(audit.KIND_LOGIN_FAIL, actor=username, target=username, ok=False,
                           actor_role="", detail="用户名或口令错误")
                elif int(row["enabled"] or 0) != 1:
                    error = "该账号已被停用，请联系管理员"
                    logger.info(f"[gui] 登录失败：{username}（账号已停用）")
                    _guard_fail(ip, username)
                    _audit(audit.KIND_LOGIN_FAIL, actor=username, target=username, ok=False,
                           actor_role="", detail="账号已停用")
                else:
                    session.clear()        # 先清旧身份，避免上一份会话的角色残留
                    session["auth"] = True
                    session["uid"] = int(row["id"])
                    session["user"] = row["username"]
                    session["role"] = row["role"]
                    users.touch_login(int(row["id"]))
                    _guard_ok(ip, username)
                    _audit(audit.KIND_LOGIN_OK, actor=username, target=username, ok=True,
                           actor_role=row["role"], detail=f"登录成功（{row['role']}）")
                    logger.info(f"[gui] 登录成功：{row['username']}（{row['role']}）")
                    return redirect(target)
            elif bootstrap:
                real = str((load_settings().get("gui") or {}).get("token", "") or "")
                if real and (users.const_eq(token, real) or users.const_eq(password, real)):
                    session.clear()
                    session["auth"] = True
                    session["user"] = "admin"
                    session["role"] = users.ROLE_ADMIN
                    _guard_ok(ip, "")     # 引导登录无用户名：只记成功（IP 计数刻意不清）
                    _audit(audit.KIND_LOGIN_OK, actor="admin", ok=True,
                           actor_role=users.ROLE_ADMIN, detail="引导口令登录成功（迁移期，管理员身份）")
                    logger.info("[gui] 登录成功：引导口令（迁移期，管理员身份）")
                    return redirect(target)
                error = "口令错误"
                logger.info("[gui] 登录失败：引导口令错误")
                _guard_fail(ip, "")
                _audit(audit.KIND_LOGIN_FAIL, actor="", ok=False, detail="引导口令错误")
            else:
                error = "请输入用户名与口令"
        return render_template("login.html", error=error, bootstrap=bootstrap)

    @app.route("/logout")
    def logout():
        _audit(audit.KIND_LOGOUT, detail="退出登录")   # 先记（session.clear 之后就读不到身份了）
        session.clear()
        return redirect(url_for("login"))

    # ---------- 账号（续46：管理员建/改/停用子用户；本人改自己的口令） ----------

    def _users_page(error="", ok=""):
        return render_template("users.html", rows=users.list_users(), error=error, ok=ok,
                               total=users.count_users(),
                               admins=users.count_enabled_admins())

    def _users_back(error):
        """账号页的操作结果用重定向 + 查询串回传（表单 POST 后不留在危险的重提交里）。"""
        return redirect(url_for("users_page", error=error))

    @app.route("/users")
    @login_required
    @admin_required
    def users_page():
        return _users_page()

    @app.route("/api/users/create", methods=["POST"])
    @login_required
    @admin_required
    def api_user_create():
        """建账号。**防锁死**：库里还没有账号时，建出来的**必须是管理员** ——
        否则"第一个账号是子用户"就是一条单行道：子用户进不了本页，从此没人能再建号。
        """
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        role = users.ROLE_ADMIN if request.form.get("role") == "admin" else users.ROLE_USER
        if users.count_users() == 0:
            role = users.ROLE_ADMIN
        ok, msg = users.create_user(username, password, role=role, must_change=True)
        if not ok:
            return _users_back(msg)
        logger.info(f"[gui] 建账号：{msg}（{role}），操作者 {session.get('user')}")
        _audit(audit.KIND_ACCOUNT, target=msg, detail=f"创建账号（{role}）")
        return redirect(url_for("users_page",
                                ok=f"已创建 {msg}（{'管理员' if role == users.ROLE_ADMIN else '子用户'}），"
                                   f"初始口令请线下告知，首次登录须修改"))

    def _user_target(uid, allow_last_admin=False):
        """取出被操作账号 + 一条"动不了"的理由（没有则返回 ""）。

        两条防锁死判据都在这一处，任何新增的账号操作都绕不过去：
        ① **不能对自己下手**（停用/删除/降级自己 → 把自己关在门外，改口令走「修改口令」）；
        ② **至少留一个启用中的管理员**（动最后一个管理员＝永久失去账号管理入口）。
        `allow_last_admin=True` 只给"把停用的管理员重新启用"这一条**补救**路径用 ——
        那条路的另一端就是"一个启用中的管理员都没有"，此时正需要放行。
        """
        row = users.get_user(uid)
        if not row:
            return None, "账号不存在"
        if int(row["id"]) == int(session.get("uid") or -1):
            return row, "不能对自己做这个操作（改自己的口令请去「修改口令」）"
        if (not allow_last_admin and row["role"] == users.ROLE_ADMIN
                and users.count_enabled_admins() <= 1):
            return row, "至少要保留一个启用中的管理员（否则再也没人能进本页）"
        return row, ""

    @app.route("/api/users/<int:uid>/password", methods=["POST"])
    @login_required
    @admin_required
    def api_user_password(uid):
        """管理员重置他人口令（置 `must_change` → 对方首次登录必须改掉）。"""
        row, why = _user_target(uid)
        if not row or why:
            return _users_back(why)
        new = request.form.get("password") or ""
        ok, msg = users.set_password(uid, new, must_change=True)
        if not ok:
            return _users_back(msg)
        logger.info(f"[gui] 重置口令：{row['username']}，操作者 {session.get('user')}")
        _audit(audit.KIND_ACCOUNT, target=row["username"], detail="重置口令（对方下次登录须修改）")
        return redirect(url_for("users_page", ok=f"已重置 {row['username']} 的口令"
                                                 "（其下次登录须修改）"))

    @app.route("/api/users/<int:uid>/toggle", methods=["POST"])
    @login_required
    @admin_required
    def api_user_toggle(uid):
        """停用 / 启用。停用后对方的现有会话在**下一个请求**即失效（见 `_session_user`）。"""
        row, why = _user_target(uid, allow_last_admin=True)
        if not row or why:
            return _users_back(why)
        enable = int(row["enabled"] or 0) != 1      # 当前停用 → 这次是启用
        # 停用（不是启用）时才受"至少留一个管理员"约束 —— 那条约束是防锁死，
        # 不能反过来把"把最后一个停用的管理员救回来"这条路也堵上。
        if not enable and row["role"] == users.ROLE_ADMIN and users.count_enabled_admins() <= 1:
            return _users_back("至少要保留一个启用中的管理员（否则再也没人能进本页）")
        users.set_enabled(uid, enable)
        logger.info(f"[gui] {'启用' if enable else '停用'}账号：{row['username']}，"
                    f"操作者 {session.get('user')}")
        _audit(audit.KIND_ACCOUNT, target=row["username"],
               detail=('启用账号' if enable else '停用账号'))
        return redirect(url_for("users_page",
                                ok=f"已{'启用' if enable else '停用'} {row['username']}"))

    @app.route("/api/users/<int:uid>/role", methods=["POST"])
    @login_required
    @admin_required
    def api_user_role(uid):
        """升/降角色。降级管理员时同样受"至少留一个管理员"约束（`_user_target`）。"""
        row, why = _user_target(uid)
        if not row or why:
            return _users_back(why)
        role = users.ROLE_ADMIN if request.form.get("role") == "admin" else users.ROLE_USER
        users.set_role(uid, role)
        logger.info(f"[gui] 改角色：{row['username']} → {role}，操作者 {session.get('user')}")
        _audit(audit.KIND_ACCOUNT, target=row["username"], detail=f"改角色为 {role}")
        return redirect(url_for("users_page",
                                ok=f"{row['username']} 已改为"
                                   f"{'管理员' if role == users.ROLE_ADMIN else '子用户'}"))

    @app.route("/api/users/<int:uid>/delete", methods=["POST"])
    @login_required
    @admin_required
    def api_user_delete(uid):
        row, why = _user_target(uid)
        if not row or why:
            return _users_back(why)
        name = row["username"]
        users.delete_user(uid)
        logger.info(f"[gui] 删除账号：{name}，操作者 {session.get('user')}")
        _audit(audit.KIND_ACCOUNT, target=name, detail="删除账号")
        return redirect(url_for("users_page", ok=f"已删除 {name}"))

    @app.route("/profile", methods=["GET", "POST"])
    @login_required
    def profile():
        """改自己的口令（所有登录者都可用；被置了"必须改密"的人会先落到这里）。"""
        me = _session_user()
        error, ok = "", ""
        if request.method == "POST":
            old = request.form.get("old_password") or ""
            new = request.form.get("password") or ""
            again = request.form.get("password2") or ""
            if not me or not me["id"]:
                error = "引导登录没有账号可改，请先在「账号」页创建管理员账号"
            elif not users.get_user(me["id"]):
                error = "账号不存在（可能已被删除）"
            elif not users.check_login(me["username"], old):
                error = "当前口令不正确"
            elif new != again:
                error = "两次输入的新口令不一致"
            else:
                good, msg = users.set_password(me["id"], new, must_change=False)
                if not good:
                    error = msg
                else:
                    ok = "口令已修改"
                    logger.info(f"[gui] 修改口令：{me['username']}")
                    _audit(audit.KIND_ACCOUNT, target=me["username"], detail="本人修改口令")
        return render_template("profile.html", me=me, error=error, ok=ok,
                               must_change=bool(me and me["must_change"]))

    # ---------- 仪表盘 ----------

    @app.route("/")
    @login_required
    def dashboard():
        return render_template(
            "dashboard.html", stats=db.dashboard_stats(), trend=db.vuln_trend(),
            tasks=db.list_tasks(limit=8), vulns=db.list_vulns(limit=8))

    # ---------- 任务 ----------

    def _spawn(task_id, name, targets, stages, options, append=False, resume=False):
        """把任务**入队**执行（GUI 不阻塞）—— 续49 起不再直接起线程。

        `append=True` = 续25 同任务追加式执行；`resume=True` = 续29 断点续跑。
        两者的区别见 `runner.run_task` 的 docstring —— 最关键的一条：**续跑不能复用
        `append=True`**（那会带上 `append_targets` 的收窄语义，传空等于一次都不扫）。

        为什么改成入队（而不是 `threading.Thread(target=run_task, ...)`）：直接起线程的话，
        进程一重启线程就没了、任务却仍挂 `running`。入队把这次运行的**精确入参**（`stages` +
        `options`）写进 `tasks.run_payload`，由 `scanner/queue.py` 的 worker 认领执行；进程重启后
        `db.reconcile_orphan_tasks` 会把死掉的 `running` **重新入队** —— 任务不丢。

        `name` / `targets` 保留在签名里只为**调用点稳定**：worker 直接从任务行读它们（它们是
        任务的持久字段，不需要进 payload）。
        """
        mode = "resume" if resume else ("append" if append else "fresh")
        db.enqueue_task(task_id, mode, stages, options)
        queue.notify()

    def _append_guard(src_id):
        """续25：能否对源任务追加执行。返回 `(ok, 错误信息)`。

        **必须硬拒绝同任务并发**：`runner._register_stop` 是"同 task 覆盖式注册"，
        第二次追加会顶掉第一次的停止事件 —— 用户点「停止」就停不掉正在跑的那一次。
        所以只要该任务在 `running_task_ids()` 里、或库状态是 `running` / `queued`，一律拒绝
        （`queued` = 已入队还没轮到跑，同样不能被追加顶掉它的入队入参）。
        """
        task = db.get_task(src_id)
        if not task:
            return False, "源任务不存在"
        if src_id in runner.running_task_ids() or task["status"] in ("running", "queued"):
            return False, "该任务正在运行或排队中，无法追加（避免并发覆盖停止信号）；请先停止或等它跑完"
        return True, ""

    def _append_err(msg, fallback):
        """追加被拒：返回 409 + 一个可读的最小页面（表单 POST 直接看到原因）。"""
        return ("<!doctype html><meta charset='utf-8'>"
                f"<h3>无法追加执行</h3><p>{msg}</p>"
                f"<p><a href='{fallback}'>返回</a></p>"), 409

    def _do_append(src_raw, stages, text, targets, stage_opts, fallback):
        """续25：把 `stages` **追加到源任务**上执行（不新建任务）。

        - 无源任务（sites/ips/fullports 三个入口的表单没有任务号）→ 409「无法追加」；
        - 源任务在跑 / 并发第二次追加 → 409（见 `_append_guard`）；
        - 成功：沿用源任务、把本次勾选目标与阶段选项塞进**本次运行**的 options，
          持久化只记 `appended` / `append_count`（供详情页显示标记），302 回详情页。
        """
        if not str(src_raw or "").strip().isdigit():
            return _append_err("此入口没有源任务，无法追加执行"
                               "（请在**任务详情页**对已勾选资产点「追加」）", fallback)
        src_id = int(str(src_raw).strip())
        ok, err = _append_guard(src_id)
        if not ok:
            return _append_err(err, fallback)
        task = db.get_task(src_id)
        try:
            base = json.loads(task["options"] or "{}")
        except (TypeError, ValueError):
            base = {}
        if not isinstance(base, dict):
            base = {}
        run_opts = dict(base)
        run_opts.update(stage_opts or {})
        run_opts.pop("rescan_of", None)     # 追加是在**同一任务**里跑，不记"来源任务"
        run_opts["append"] = True
        run_opts["append_targets"] = list(targets)
        meta = dict(base)
        meta["appended"] = True
        meta["append_count"] = int(base.get("append_count") or 0) + 1
        db.update_task(src_id, options=json.dumps(meta), status="pending", current_stage="")
        _spawn(src_id, task["name"], text, stages, run_opts, append=True)
        logger.info(f"[gui] 任务 #{src_id} 追加执行（阶段 {'/'.join(stages)}，"
                    f"{len(targets)} 个目标，第 {meta['append_count']} 次追加）")
        _audit(audit.KIND_TASK, target=f"#{src_id}",
               detail=f"追加执行（{'/'.join(stages)}，{len(targets)} 个目标）")
        return redirect(url_for("task_detail", task_id=src_id))

    @app.route("/tasks")
    @login_required
    def tasks():
        rows = db.list_tasks(limit=200)
        # 「统计」列：站点/域名数量（对齐参考图的 站点: N / 域名: N 展示）
        counts = {t["id"]: db.task_counts(t["id"]) for t in rows}
        # 续36「运行时长」列：与详情页「目标与配置」**同一口径**（`run_duration_text`）。
        # 注意 `list_tasks` 返回的是 `sqlite3.Row`，必须先 `dict(...)` 再传 —— `run_duration_text`
        # 内部走 `task.get(...)`，而 `sqlite3.Row` **没有** `.get()`（`_site_titles()` 踩过同一个坑）。
        durations = {t["id"]: run_duration_text(dict(t)) for t in rows}
        # 续49：排队位置（队首=1）。队列按 id 升序消费（`db.claim_next_queued`），
        # 所以这里也按 id 升序数，页面才能和 worker 的取用顺序对得上。
        qpos = {}
        _qi = 0
        for _t in sorted(rows, key=lambda r: r["id"]):
            if _t["status"] == "queued":
                _qi += 1
                qpos[_t["id"]] = _qi
        return render_template("tasks.html", tasks=rows, stages=STAGE_ORDER,
                               counts=counts, durations=durations,
                               running=set(runner.running_task_ids()), qpos=qpos)

    @app.route("/api/tasks", methods=["POST"])
    @login_required
    def api_create_task():
        data = request.form if request.form else (request.get_json(silent=True) or {})
        name = (data.get("name") or "").strip() or time.strftime("task-%m%d-%H%M%S")
        targets = (data.get("targets") or "").strip()
        f = request.files.get("file")
        if f and f.filename:
            targets = (targets + "\n" + f.read().decode("utf-8", "replace")).strip()
        if not targets:
            return jsonify({"error": "目标为空：请填写目标或导入文件"}), 400
        stages = data.getlist("stages") if hasattr(data, "getlist") else data.get("stages", [])
        if isinstance(stages, str):
            stages = [s for s in stages.split(",") if s.strip()]
        stages = [s for s in stages if s in STAGE_ORDER] or list(STAGE_ORDER)
        offline = str(data.get("offline", "")).lower() in ("1", "true", "on")
        options = {"offline": offline}
        # 「全端口 / 全目录」是**任务级选项**（与 portscan_full 同一套语义：单任务强制全量档，
        # 不改全局策略）。用户很容易只勾了全量却忘勾对应阶段，那样勾选就等于白勾 ——
        # 这里自动把对应阶段补进来，并在响应里如实告知，避免"勾了没用"的错觉。
        auto_stages = []
        # 「目录递归」（续30）是深扫的附属能力（浅扫不递归），所以勾了它就等于点名要深扫 ——
        # 先把 `dirscan_full` 落上，后面这个循环自然会连 `dirscan` 阶段一起补。
        # 不这么做的话，勾了「目录递归」而没勾「全目录深扫」会**静默不递归**（跑完什么也没有，
        # 看起来像功能坏了）。
        if str(data.get("recursive_dir", "")).lower() in ("1", "true", "on"):
            options["recursive_dir"] = True
            options["dirscan_full"] = True
        # 「自动拓展扫描」（`auto_expand`，2026-09-25）：勾了就默认把拓展扫描做全 ——
        # ① 自动补 `osint` / `jsmine` 两个拓展阶段（只勾了「自动拓展」却没勾阶段 = 白勾，
        #    与上面对全量档的处理同一套"勾了就要生效"的口径）；
        # ② 流水线在拓展阶段结束后自动做**存在性判定**（DNS，判断域名存不存在）与
        #    **归属追加**（`pengo.pro` 拓展出 `aaa.pengo.pro` → 按正常子域对待）；
        # ③ 目标是子域（如 `aaa.pengo.pro`）时自动补收它的主域名 `pengo.pro`。
        # 全部只在本次任务生效（任务级选项），**不改全局策略、不改既有任务的默认行为**。
        if str(data.get("auto_expand", "")).lower() in ("1", "true", "on"):
            options["auto_expand"] = True
            for stage in ("osint", "jsmine"):
                if stage not in stages:
                    stages.append(stage)
                    auto_stages.append(stage)
        for flag, stage in (("portscan_full", "portscan"), ("dirscan_full", "dirscan")):
            # 判据是**生效选项**（options）或表单字段 —— 上面「目录递归」会直接把
            # `dirscan_full` 写进 options，而表单里并没有这个字段名；只看表单会漏掉它，
            # 结果是"任务里没有 dirscan 阶段"：勾了递归却连目录扫都不跑（静默失效）。
            if options.get(flag) is not True \
                    and str(data.get(flag, "")).lower() not in ("1", "true", "on"):
                continue
            options[flag] = True
            if stage not in stages:
                stages.append(stage)
                auto_stages.append(stage)
        # 补进来的阶段要回到流水线既定顺序：runner 按给定顺序执行，**不做排序**
        stages.sort(key=STAGE_ORDER.index)
        # 截图阶段策略级默认关（`screenshot.enabled=false`），但建任务表单里它是**默认不勾**的，
        # 勾了就是"这次我要截图"——落成任务级选项 `screenshot_on`，否则会出现
        # "勾了截图却静默跳过、页面上永远没有缩略图"的错觉（用户 2026-09-23 的实际反馈）。
        if "screenshot" in stages:
            options["screenshot_on"] = True
        # 证书取证同理：`cert.enabled` 策略级默认关，建任务勾了就落成 `cert_on`（只本次生效）。
        if "cert" in stages:
            options["cert_on"] = True
        # 登录态（可选）：`auth` 是每行一条「名称: 值」的 textarea。解析失败**拒绝建任务**
        # 并逐条列出原因 —— 少带一条 `Authorization` 会让"已登录扫描"变成假象，
        # 用户会把 false negative 读成"没洞"。这里刻意不做"尽力而为"的静默丢弃。
        auth_headers, auth_errors = taskauth.parse_headers(data.get("auth") or "")
        if auth_errors:
            return jsonify({"error": "登录态请求头有误：" + "；".join(auth_errors)}), 400
        if auth_headers:
            options["auth"] = auth_headers
        task_id = db.create_task(name, targets, stages, options)
        _spawn(task_id, name, targets, stages, options)
        _audit(audit.KIND_TASK, target=name, detail=f"创建任务 #{task_id}（阶段 {'/'.join(stages)}）")
        return jsonify({"id": task_id, "auto_stages": auto_stages})

    @app.route("/tasks/<int:task_id>")
    @login_required
    def task_detail(task_id):
        task = db.get_task(task_id)
        if not task:
            abort(404)
        # 页面只展示相对路径（日志文件路径在库里存的是绝对路径，因为要真的去读它）
        task = dict(task)
        task["log_file"] = rel_display(task.get("log_file") or "")
        # 子域名 Tab 只列目标自身的子域名；JS/情报拓展的域名单独计数并指到「拓展域名」页
        subs = [dict(r) for r in db.list_subdomains(task_id)]
        own = [r for r in subs if not (r["source"] or "").startswith(("js:", "osint:"))]
        # 拓展域名（JS 挖掘 / C 段 / FOFA）在任务详情里单列一个页签 ——
        # 用户要求它不再单独占侧栏，但任务维度仍要能看到（这些域名未必属于目标）
        ext_subs = [r for r in subs if (r["source"] or "").startswith(("js:", "osint:"))]
        # **按来源分类排序**（用户 2026-09-23：「这个顺序和分类还是没有 …… 如何 JS 挖掘与
        # FOFA 不要交叉」）：原实现只是 `ORDER BY domain`，于是 js:mine 与 osint:fofa-title
        # 按字母序交错在一起，看不出哪些是 JS 挖的、哪些是 FOFA 反查来的 —— 这里与
        # 跨任务 `/extdomains` 页用**同一张顺序表 EXT_SRC_TAGS**（JS → 标题 → 证书 → ICO → C 段），
        # 同类内新的在前；未知来源排最后。`?esrc=` 只显示某一类。
        _rank = {tag[2]: i for i, tag in enumerate(EXT_SRC_TAGS)}
        ext_counts = {}
        for r in ext_subs:
            ext_counts[r["source"]] = ext_counts.get(r["source"], 0) + 1
        ext_src = (request.args.get("esrc") or "").strip().lower()
        ext_pick = next((t for t in EXT_SRC_TAGS if t[0] == ext_src), None)
        if not ext_pick:
            ext_src = ""
        else:
            ext_subs = [r for r in ext_subs if r["source"] == ext_pick[2]]
        ext_subs.sort(key=lambda r: (_rank.get(r["source"], 99), -(r["id"] or 0)))
        # 目录结果同样默认折叠"重复长度"（同一站点下几百条同样长度的 200 基本是同一个软 404 模板）
        dirs, dirs_hidden = _fold_dirs(db.list_dirs(task_id), False)
        # 「线索」页签按用户口径在续24 移除（线索只在 JSONL 导出里按 `type=lead` 保留），
        # 所以这里不再查 `leads` 表、也不再往模板传 `leads` / `leads_intel`。
        # 「补扫」相关提示条只在"本次没做全量"时出现，避免误导：
        # 本任务带了 `dirscan_full`/`portscan_full`，或全局策略本身就是全量档 → 不提示。
        try:
            top = json.loads(task.get("options") or "{}")
        except (TypeError, ValueError):
            top = {}
        if not isinstance(top, dict):
            top = {}
        # 登录态：页面要能确认"这次带了登录态"，但**不能把凭据回显出去** ——
        # 下面「运行配置 → 选项」一行原样打印 options JSON，若含 `auth` 就是把明文 Cookie
        # 上屏（还会进页面截图、浏览器历史、导出的报告）。所以先把值掩码，再交给模板；
        # 日志同理（见 runner 的 [auth] 行）。
        auth_view = [(k, taskauth.mask_value(k, v))
                     for k, v in taskauth.from_task_options(top).items()]
        if "auth" in top:
            opts_display = dict(top)
            opts_display["auth"] = dict(auth_view)
            task["options"] = json.dumps(opts_display, ensure_ascii=False)
        dir_full = (top.get("dirscan_full") is True
                    or str((settings.get("dirscan") or {}).get("mode") or "quick") == "deep")
        port_full = (top.get("portscan_full") is True
                     or str((settings.get("portscan") or {}).get("mode") or "top") == "full")
        sites = db.list_sites(task_id)
        # 站点页签的截图状态：有站点却一张截图都没有时，页面上要说清"为什么没有"并给补截图入口
        # （用户 2026-09-23：「站点的截图显示为什么还没有完成」—— 实际是策略开关默认关、
        #   且当时建任务勾的 screenshot 阶段不生效，页面上只留一片空白）。
        shot_enabled = ((settings.get("screenshot") or {}).get("enabled") is True
                        or top.get("screenshot_on") is True)
        shot_missing = bool(sites) and not any((s["shot"] or "").strip() for s in sites)
        # 本机有没有可用的无头浏览器 —— 页面要区分"策略没开"和"没装浏览器"两种"没截图"
        shot_ready = screenshot.available(settings)
        # 「SSL 证书」页签：同样要说清"为什么没有证书"。分两种情况，用与 cert 阶段**同一个**
        # pick_targets() 判定"本次有没有可取证的目标"，避免页面解说与实际行为不一致。
        certs_rows = db.list_certs(task_id)
        cert_enabled = ((settings.get("cert") or {}).get("enabled") is True
                        or top.get("cert_on") is True)
        # 注意 `db.list_sites()` 返回的是 `sqlite3.Row`，而 `pick_targets()` 按 dict 取值
        # （阶段那边传的是 probe 的 dict 结果）—— 不转会在页面渲染时抛 AttributeError。
        cert_pick = len(cert_pick_targets([dict(s) for s in sites], certs_mod.tls_ports(settings)))
        # 续29「断点续扫」：断点 = `current_stage`（最后进入的阶段，见 runner.resume_stages）。
        # 没有断点（正常跑完 / 从没跑起来）时返回 `[]`，页面据此把「续跑」按钮置灰并给出解释，
        # 而不是让用户点了才收到一句报错。
        resume_rest = runner.resume_stages((task["stages"] or "").split(","),
                                           task["current_stage"])
        return render_template(
            "task_detail.html", task=task,
            subs=own, ext_subs=ext_subs,
            ext_src=ext_src, ext_counts=ext_counts, ext_src_tags=EXT_SRC_TAGS,
            resume_rest=resume_rest,
            sites=sites,
            ports=db.list_ports(task_id), csegs=db.list_csegs(task_id), certs=certs_rows,
            cert_enabled=cert_enabled, cert_pick=cert_pick,
            cert_tls_ports=sorted(certs_mod.tls_ports(settings)),
            dirs=dirs, dirs_hidden=dirs_hidden,
            vulns=db.list_vulns(task_id=task_id, limit=1000),
            review=db.review_counts(task_id),
            # 补扫入口：任务页对"本任务的站点/IP"直接发起新任务；rescan_of 用于反向回跳
            rescan_of=top.get("rescan_of"),
            # 续25：本任务是否被"追加执行"过（次数）—— 详情页据此显示标记与横幅
            append_count=int(top.get("append_count") or 0),
            # 登录态只显示**掩码后的**名字 + 值（`Cookie=abc***xyz`），见上面的 auth_view
            auth_view=auth_view,
            # 续35「运行时长」：目标是"这个任务一共跑了多久" —— 续跑 / 追加会跑多段，
            # 故报的是累计值（`tasks.elapsed_seconds`）+ 正在跑的这一段，见 `db.task_run_seconds`。
            run_duration=run_duration_text(task),
            dir_full=dir_full, port_full=port_full,
            shot_enabled=shot_enabled, shot_missing=shot_missing, shot_ready=shot_ready,
            dir_cap=int((settings.get("limits") or {}).get("dirscan_max_urls", 20) or 20),
            running=set(runner.running_task_ids()),
            # 续49：排队位置（0=不在队列里）。页面据此显示「排队中（第 N 位）」。
            queue_pos=db.queued_position(task_id), queued_total=db.queued_count())

    @app.route("/tasks/<int:task_id>/export")
    @login_required
    def task_export(task_id):
        """导出任务报告：`?fmt=md`（默认，下载 .md）/ `html`（下载 .html）/ `pdf`（下载 .pdf）/
        `jsonl`（下载 .jsonl，机器可读的 JSON Lines）。

        PDF 走本机无头浏览器的 `--print-to-pdf`（见 `report.export_pdf`）：找不到浏览器时
        **把原因显示出来**（而不是 500 或一个空文件），并提示可改导出 HTML。
        """
        task = db.get_task(task_id)
        if not task:
            abort(404)
        from scanner.report import (export_pdf, generate, generate_html,
                                    generate_jsonl)
        fmt = (request.args.get("fmt") or "md").strip().lower()
        stamp = time.strftime("%Y%m%d_%H%M%S")
        if fmt == "pdf":
            tmp_dir = Path(tempfile.mkdtemp(prefix="ctfscan-report-"))
            out = tmp_dir / f"task_{task_id}_{stamp}.pdf"
            try:
                ok, err = export_pdf(task_id, out, settings)
                if not ok:
                    return Response(_export_error_page(err, task_id), status=400,
                                    mimetype="text/html; charset=utf-8")
                # 读进内存再回：临时目录马上要删，交给 Flask 流式发送会有句柄竞争
                # （Windows 上更明显 —— 文件还被占着就删不掉）。
                data = out.read_bytes()
            finally:
                shutil.rmtree(tmp_dir, ignore_errors=True)
            return Response(data, mimetype="application/pdf",
                            headers={"Content-Disposition":
                                     f"attachment; filename=task_{task_id}_{stamp}.pdf"})
        if fmt == "html":
            body = generate_html(task_id) or ""
            return Response(body, mimetype="text/html; charset=utf-8",
                            headers={"Content-Disposition":
                                     f"attachment; filename=task_{task_id}_{stamp}.html"})
        if fmt == "jsonl":
            body = generate_jsonl(task_id) or ""
            # NDJSON 的标准 mimetype；`charset=utf-8` 保证中文可读（JSONL 用 ensure_ascii=False）
            return Response(body, mimetype="application/x-ndjson; charset=utf-8",
                            headers={"Content-Disposition":
                                     f"attachment; filename=task_{task_id}_{stamp}.jsonl"})
        md = generate(task_id) or ""
        fname = f"task_{task_id}_{stamp}.md"
        return Response(md, mimetype="text/markdown; charset=utf-8",
                        headers={"Content-Disposition": f"attachment; filename={fname}"})

    @app.route("/api/tasks/<int:task_id>/stop", methods=["POST"])
    @login_required
    def api_task_stop(task_id):
        task = db.get_task(task_id)
        if not task:
            return jsonify({"error": "not found"}), 404
        if task["status"] == "queued":
            # 排队中：还没有线程可发停止信号 —— 直接从队列移除（置 stopped）。同时试一次
            # `request_stop`，兜住"worker 刚好在那一刻把它认领走"的极小竞态（认领后才注册停止事件）。
            db.update_task(task_id, status="stopped")
            runner.request_stop(task_id)
            _audit(audit.KIND_TASK, target=f"#{task_id}", ok=True,
                   detail="从队列移除任务（尚未开始执行）")
            return jsonify({"ok": True, "msg": "已从队列移除（该任务尚未开始）"})
        ok = runner.request_stop(task_id)
        _audit(audit.KIND_TASK, target=f"#{task_id}", ok=bool(ok),
               detail=("请求停止任务" if ok else "请求停止任务（当时未在运行）"))
        return jsonify({"ok": ok, "msg": "已请求停止，当前批次跑完即停" if ok
                        else "该任务当前未在运行"})

    @app.route("/api/tasks/<int:task_id>/delete", methods=["POST"])
    @login_required
    def api_task_delete(task_id):
        if not db.get_task(task_id):
            return jsonify({"error": "not found"}), 404
        runner.request_stop(task_id)   # 先停线程，避免它继续往已删除的任务里写数据
        db.delete_task(task_id)
        _audit(audit.KIND_TASK, target=f"#{task_id}", detail="删除任务（已自动备份）")
        return jsonify({"ok": True})

    @app.route("/api/tasks/<int:task_id>/restart", methods=["POST"])
    @login_required
    def api_task_restart(task_id):
        """原地重启：清空该任务已有资产后按原参数重跑（历史任务保持单一结果集，不产生重复行）。"""
        task = db.get_task(task_id)
        if not task:
            return jsonify({"error": "not found"}), 404
        if task["status"] == "running":
            return jsonify({"ok": False, "error": "任务正在运行，请先停止再重启"})
        stages = [s for s in (task["stages"] or "").split(",") if s in STAGE_ORDER]
        db.clear_task_assets(task_id)
        db.update_task(task_id, status="pending", progress=0, current_stage="", error="")
        _spawn(task_id, task["name"], task["targets"], stages or list(STAGE_ORDER),
               json.loads(task["options"] or "{}"))
        _audit(audit.KIND_TASK, target=f"#{task_id}", detail="重启任务（清空资产后从头跑）")
        return jsonify({"ok": True})

    @app.route("/api/tasks/<int:task_id>/resume", methods=["POST"])
    @login_required
    def api_task_resume(task_id):
        """续29「断点续扫」：沿用原任务与库里已有的资产，只重跑断点及其之后的阶段。

        三个入口的分工（页面上三个按钮紧挨着，必须各不相同）：
        - **重启** —— 清空该任务全部资产，按原参数**从头**跑；
        - **续跑**（本条）—— **不清资产**、不从头跑，跳过已跑完的阶段；
        - **追加** —— 对源任务"再跑一遍某些目标/阶段"，输入收窄到本次勾选项。

        拒绝的两种情况都返回 `ok=False` + 可读原因（页面直接显示，不静默）：
        任务正在运行；没有可用断点（`current_stage` 为空或已不在阶段列表里）。
        """
        task = db.get_task(task_id)
        if not task:
            return jsonify({"error": "not found"}), 404
        if task_id in runner.running_task_ids() or task["status"] in ("running", "queued"):
            return jsonify({"ok": False,
                            "error": "任务正在运行或排队中，无需续跑（如需中断请先「停止」）"})
        rest = runner.resume_stages((task["stages"] or "").split(","), task["current_stage"])
        if not rest:
            return jsonify({"ok": False,
                            "error": "没有可用断点：该任务没有停在某个阶段上"
                                     "（已正常跑完、或从没真正跑起来）；如需从头重跑请用「重启」"})
        try:
            opts = json.loads(task["options"] or "{}")
        except (TypeError, ValueError):
            opts = {}
        if not isinstance(opts, dict):
            opts = {}
        # 上一次"追加执行"的**运行期**参数绝不能带进续跑：`append_targets` 会把输入
        # 收窄到那一次勾选的目标（本次续跑的输入应当是库里已有的全部资产）。
        opts.pop("append", None)
        opts.pop("append_targets", None)
        db.update_task(task_id, status="pending", progress=0)
        _spawn(task_id, task["name"], task["targets"], rest, opts, resume=True)
        logger.info(f"[gui] 任务 #{task_id} 从断点续跑：{task['current_stage']} 起，"
                    f"阶段 {'/'.join(rest)}")
        _audit(audit.KIND_TASK, target=f"#{task_id}",
               detail=f"从断点续跑（{'/'.join(rest)}）")
        return jsonify({"ok": True, "msg": f"已从断点续跑：{','.join(rest)}"})

    @app.route("/api/tasks/bulk", methods=["POST"])
    @login_required
    def api_tasks_bulk():
        """批量操作：stop / delete / restart。ids 可来自表单或 JSON。"""
        data = request.get_json(silent=True) or {}
        action = (data.get("action") or request.form.get("action") or "").strip()
        ids = data.get("ids") or request.form.getlist("ids")
        try:
            ids = [int(i) for i in (ids or [])]
        except (TypeError, ValueError):
            return jsonify({"error": "ids 必须是整数列表"}), 400
        if action not in ("stop", "delete", "restart"):
            return jsonify({"error": "action 必须是 stop / delete / restart"}), 400
        affected, skipped = 0, []
        for tid in ids:
            task = db.get_task(tid)
            if not task:
                skipped.append(tid)
                continue
            running = task["status"] == "running"
            if action == "stop":
                if running and runner.request_stop(tid):
                    affected += 1
                else:
                    skipped.append(tid)
            elif action == "delete":
                runner.request_stop(tid)
                db.delete_task(tid)
                affected += 1
            else:  # restart
                if running:
                    skipped.append(tid)
                    continue
                stages = [s for s in (task["stages"] or "").split(",") if s in STAGE_ORDER]
                db.clear_task_assets(tid)
                db.update_task(tid, status="pending", progress=0, current_stage="", error="")
                _spawn(tid, task["name"], task["targets"], stages or list(STAGE_ORDER),
                       json.loads(task["options"] or "{}"))
                affected += 1
        _audit(audit.KIND_TASK, target="批量", detail=f"批量 {action}：影响 {affected} 个任务")
        return jsonify({"ok": True, "action": action, "affected": affected,
                        "skipped": skipped})

    @app.route("/api/tasks/<int:task_id>/status")
    @login_required
    def api_task_status(task_id):
        t = db.get_task(task_id)
        if not t:
            return jsonify({"error": "not found"}), 404
        return jsonify({
            "status": t["status"], "progress": t["progress"],
            "current_stage": t["current_stage"],
            "log_tail": _tail(t["log_file"]) if t["log_file"] else [],
        })

    # ---------- POC 管理 ----------

    # POC 管理与策略配置**同为管理员门内**（续46）：它决定"扫什么、报什么"，且上传会往
    # config/pocs-user/ 落文件 —— 与策略配置是同一类"改平台行为"的操作，不是"看扫描结果"。
    @app.route("/pocs")
    @login_required
    @admin_required
    def pocs():
        # _query 返回 sqlite3.Row（只读），这里要往每行补 source 字段，故转成 dict
        rows = [dict(r) for r in db.list_pocs()]
        # 分类统计（来源 / 级别 / 置信度），供页面上的"按分类批量开关"展示当前分布
        stats = {"source": {}, "severity": {}, "confidence": {}, "enabled": 0, "total": len(rows)}
        for r in rows:
            src = db.poc_source(r["path"])    # 来源判定依赖原始路径，必须在相对化之前算
            r["source"] = src                 # 列表展示 / 前端筛选用
            # 置信度（P1-2）：库里为空的老记录按路径即时补算，页面永远有值可筛
            r["confidence"] = r["confidence"] or db.poc_confidence(r["path"])
            r["path"] = rel_display(r["path"])  # 页面只展示相对路径
            stats["source"][f"{src}:on" if r["enabled"] else f"{src}:off"] = \
                stats["source"].get(f"{src}:on" if r["enabled"] else f"{src}:off", 0) + 1
            stats["severity"][r["severity"] or "-"] = stats["severity"].get(r["severity"] or "-", 0) + 1
            stats["confidence"][r["confidence"]] = stats["confidence"].get(r["confidence"], 0) + 1
            stats["enabled"] += int(r["enabled"] or 0)
        return render_template("pocs.html", pocs=rows, stats=stats)

    @app.route("/api/pocs/upload", methods=["POST"])
    @login_required
    @admin_required
    def api_poc_upload():
        f = request.files.get("file")
        if not f or not f.filename.lower().endswith((".yaml", ".yml")):
            return jsonify({"error": "请上传 .yaml / .yml 文件"}), 400
        dest_dir = BASE_DIR / "config" / "pocs-user"
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / Path(f.filename).name
        f.save(str(dest))
        meta = engine.load_poc_file(dest)
        db.upsert_poc(str(dest), meta)
        _audit(audit.KIND_POC, target=dest.name, ok=meta.get("_status") == "ok",
               detail=f"上传 POC（{meta.get('_status', '?')}）")
        return jsonify({"ok": meta.get("_status") == "ok", "id": meta.get("id"),
                        "error": meta.get("_error", "")})

    @app.route("/api/pocs/<int:pid>/toggle", methods=["POST"])
    @login_required
    @admin_required
    def api_poc_toggle(pid):
        db.toggle_poc(pid)
        _audit(audit.KIND_POC, target=f"poc#{pid}", detail="切换 POC 启用状态")
        return jsonify({"ok": True})

    @app.route("/api/pocs/bulk", methods=["POST"])
    @login_required
    @admin_required
    def api_poc_bulk():
        """按分类批量开关 POC：body={action:'enable'|'disable', severity?, source?, confidence?, kind?}。"""
        data = request.get_json(silent=True) or request.form
        action = (data.get("action") or "").strip()
        if action not in ("enable", "disable"):
            return jsonify({"error": "action 必须是 enable 或 disable"}), 400
        n = db.bulk_set_poc_enabled(action == "enable",
                                    severity=(data.get("severity") or "").strip() or None,
                                    source=(data.get("source") or "").strip() or None,
                                    confidence=(data.get("confidence") or "").strip() or None,
                                    kind=(data.get("kind") or "").strip() or None)
        _audit(audit.KIND_POC, target="批量",
               detail=f"批量{'启用' if action == 'enable' else '停用'} POC：{n} 条")
        return jsonify({"ok": True, "affected": n})

    @app.route("/api/pocs/refresh", methods=["POST"])
    @login_required
    @admin_required
    def api_poc_refresh():
        sync_pocs(load_settings())
        _audit(audit.KIND_POC, target="注册表", detail="刷新 POC 注册表")
        return jsonify({"ok": True})

    # ---------- 漏洞 ----------

    @app.route("/vulns")
    @login_required
    def vulns():
        sev = request.args.get("severity") or None
        tid = request.args.get("task_id") or ""
        # 复核筛选（P1-1）：`review` 三态。用 "1" 表示"只看未复核"是给链接用的短写法，
        # 统一在 db.norm_review() 里归一，页面传任何非法值都只会落到"待复核"。
        rev = request.args.get("review")
        rev = (rev or "").strip().lower() or None
        if rev == "1":
            rev = "pending"
        try:
            tid = int(tid)
        except (TypeError, ValueError):
            tid = None
        # 分页 + 排序（P0，续51）：原先固定 `list_vulns(limit=500)`，>500 条静默丢结果。
        # 现在过滤（含关键字 q）与排序全走 SQL（`db.page_vulns`），q 从**前端过滤**移到服务端。
        page, size, q = _page_args()
        sort, desc = _vuln_sort_args()
        rows, total = db.page_vulns(limit=size, offset=(page - 1) * size, q=q or None,
                                    severity=sev, review=rev, task_id=tid, sort=sort, desc=desc)
        pages = max(1, (total + size - 1) // size)
        if page > pages:  # 页码越界（过滤后总页数变少）→ 回落到最后一页重查
            page = pages
            rows, total = db.page_vulns(limit=size, offset=(page - 1) * size, q=q or None,
                                        severity=sev, review=rev, task_id=tid,
                                        sort=sort, desc=desc)
        # 翻页必须带上**全部**筛选 + 排序状态；`q` / `severity` 要 URL 编码 ——
        # 关键字里带 `&` / `#` / 空格时不编码会让翻页、切筛选**丢掉条件**（见 _asset_page 注释）。
        parts = []
        if sev:
            parts.append(f"severity={quote(sev)}")
        if rev:
            parts.append(f"review={quote(rev)}")
        if tid:
            parts.append(f"task_id={tid}")
        if q:
            parts.append(f"q={quote(q)}")
        parts.append(f"sort={sort}")
        parts.append(f"desc={'1' if desc else '0'}")
        parts.append(f"size={size}")
        pager = {"page": page, "size": size, "total": total, "pages": pages,
                 "base": "/vulns", "qs": "&" + "&".join(parts)}
        # 跨任务视图里只有 `任务 #12` 没法辨认，这里带上任务名，并支持按任务筛选。
        tasks = db.list_tasks(limit=1000)
        return render_template("vulns.html", vulns=rows, sev=sev or "",
                               review=rev or "", counts=db.review_counts(tid),
                               task_id=tid or "", tasks=tasks,
                               task_names={t["id"]: t["name"] for t in tasks},
                               q=q, pager=pager, sort=sort, desc=desc,
                               page_sizes=PAGE_SIZES)

    @app.route("/api/vulns/review", methods=["POST"])
    @login_required
    def api_vuln_review():
        """人工复核打标（P1-1）：body={ids:[...], state:''|confirmed|false_positive, note?}。

        `state` 空串 = 退回"待复核"（复核结论可以撤销）。状态非法一律归一成待复核，
        不会把前端传来的任意字符串写进库（见 db.norm_review）。
        """
        data = request.get_json(silent=True) or request.form
        raw_ids = data.get("ids")
        if isinstance(raw_ids, str):
            raw_ids = [x for x in raw_ids.replace(",", " ").split()]
        ids = [str(i).strip() for i in (raw_ids or []) if str(i).strip()]
        if not ids:
            return jsonify({"error": "ids 不能为空"}), 400
        note = data.get("note")
        n = db.bulk_set_vuln_review(ids, data.get("state"), note=note)
        return jsonify({"ok": True, "affected": n, "state": db.norm_review(data.get("state"))})

    # ---------- 资产分栏 ----------
    #
    # 分页策略（P2-2）：跨任务资产页原来固定 `LIMIT 500`，数据量上去后会被静默截断。
    # 现在过滤与分页都走 SQL（`db.page_assets`），关键字用 `q`、页码用 `page`、每页 `size`。

    PAGE_SIZES = (50, 100, 200, 500)

    def _page_args():
        def _int(name, default):
            try:
                return int(request.args.get(name, default) or default)
            except (TypeError, ValueError):
                return default
        size = _int("size", 100)
        return max(1, _int("page", 1)), (size if size in PAGE_SIZES else 100), \
            (request.args.get("q") or "").strip()

    def _vuln_sort_args():
        """漏洞页排序参数（P0，续51）：`sort` 只认 `db.VULN_SORT_KEYS` 白名单，非法回落默认；
        `desc` 解析布尔（只有明确的"否"才算升序，缺省 / 非法一律回落**降序** = 最新在前）。"""
        sort = (request.args.get("sort") or "").strip().lower()
        if sort not in db.VULN_SORT_KEYS:
            sort = db.VULN_SORT_DEFAULT
        raw = (request.args.get("desc") or "").strip().lower()
        desc = raw not in ("0", "false", "no", "off")
        return sort, desc

    def _asset_page(table, base, extra_where=None, extra_params=(), order=None):
        page, size, q = _page_args()
        rows, total = db.page_assets(table, limit=size, offset=(page - 1) * size, q=q or None,
                                     extra_where=extra_where, extra_params=extra_params,
                                     order=order)
        pages = max(1, (total + size - 1) // size)
        if page > pages:  # 页码越界（例如过滤后总页数变少）→ 回落到最后一页重查
            page = pages
            rows, total = db.page_assets(table, limit=size, offset=(page - 1) * size,
                                         q=q or None, extra_where=extra_where,
                                         extra_params=extra_params, order=order)
        # q 必须 URL 编码：关键字里带 `&` / `#` / 空格时不编码会让翻页、切标签**丢掉筛选条件**
        qs = f"&q={quote(q)}&size={size}" if q else f"&size={size}"
        pager = {"page": page, "size": size, "total": total, "pages": pages,
                 "base": base, "qs": qs}
        return rows, pager, q

    def _cdn_tag():
        """子域名/拓展域名页的 CDN 标签过滤：全部 / cdn（走 CDN）/ nocdn（直连源站）。"""
        tag = (request.args.get("tag") or "").strip().lower()
        if tag == "cdn":
            return tag, "cdn <> ''", ()
        if tag == "nocdn":
            return tag, "cdn = ''", ()
        return "", None, ()

    def _overlap_args():
        """「是否显示重叠资产」开关：默认隐藏，`?all=1` 显示全部（两个资产页口径一致）。"""
        return request.args.get("all") == "1"

    def _secret_counts():
        """每个域名命中的 JS 敏感凭据条数（供「拓展域名」页的「敏感」列）。

        敏感项已随 jsmine 阶段以 `js-secret-*` 入 vulns 表，这里只按 target（主机名）聚合条数，
        不再另建一张表 —— 数据模型不变，页面上多一列"该域名下挖到过多少敏感串"。
        """
        out = {}
        try:
            for r in db._query("SELECT target t, COUNT(*) c FROM vulns "
                               "WHERE poc_id LIKE 'js-secret-%' GROUP BY target"):
                out[r["t"]] = r["c"]
        except Exception:
            return {}
        return out

    def _fold_dirs(rows, show_all):
        """目录结果按「站点 + 状态码 + 响应大小」折叠重复，返回 `(rows, hidden)`。

        为什么按大小折叠：一个站点下动辄几百条同样长度的 `200`（软 404 模板、统一的
        重定向页），它们不是真发现 —— 与 dirmap 把这类结果单独写进「重复长度.txt」
        是同一口径。默认只留首个，`?all=1`（`/dirs`）放开。

        **站点身份取 `dirs.site_url`，并把尾斜杠归一掉**（续24）：
        * 归一的原因：同一个站点在库里既可能是 `http://a:8080`（目标直接给域名/IP 时
          由 probe 拼出来）也可能是 `http://a:8080/`（httpx 回显的带斜杠形式），
          同一个站点的两组结果不该因为一个斜杠就分成两桶；
        * 折叠键能正确区分站点，**前提是 `site_url` 真的写了值** —— 早先 dirmap 解析行
          一律写空串（见 `scanner/stages/dirscan.py::_origin_of` 的说明），导致两个方向都错：
          同站点的 dirmap 行与内置行永不互折（"同样大小的没过滤"），
          而不同站点的 dirmap 行会因 site_url 都为空被误折成一条（真丢结果）。
          该缺陷已在解析侧修正；本函数只做归一，**不做"空值兜底估算"** ——
          站点身份必须来自数据本身，不能靠展示层猜。
        """
        rows = [dict(r) for r in rows]
        seen, hidden = {}, 0
        for r in rows:
            r["dup"] = 0
            key = ((r.get("site_url") or "").rstrip("/"), r.get("status"),
                   r.get("length") or -1)
            first = seen.get(key)
            if first is None:
                seen[key] = r
            else:
                first["dup"] += 1
                r["hidden_dup"] = True
                hidden += 1
        if not show_all:
            rows = [r for r in rows if not r.get("hidden_dup")]
        return rows, hidden

    def _agg_dirs(rows):
        """目录按「状态码 + 响应大小 + 标题」聚合（忽略站点），返回指纹分组列表。

        解决"同一响应（如 Cloudflare 的 403 拦截页、各站点大小都是 5665）在多个站点各显示
        一行、大小列重复"的问题：折叠成一行，显示命中条数 + 样本路径/站点（可展开）。
        与 `_fold_dirs` 的区别：那里按「站点 + 状态码 + 大小」折叠（保留每个站点的代表行），
        这里跨站点、按响应指纹折叠，专门对付"全库同一类响应刷屏"的观感问题。
        """
        groups, order = {}, []
        for r in rows:
            key = (r.get("status"), r.get("length") or -1, (r.get("title") or "").strip())
            g = groups.get(key)
            if g is None:
                g = {"status": r.get("status"), "length": r.get("length"),
                     "title": (r.get("title") or "").strip() or "-",
                     "count": 0, "samples": []}
                groups[key] = g
                order.append(key)
            g["count"] += 1
            if len(g["samples"]) < 12:
                g["samples"].append({"path": r.get("path"),
                                      "site": (r.get("site_url") or "").rstrip("/") or "-",
                                      "note": r.get("note") or "-"})
        return [groups[k] for k in order]

    @app.route("/shots/<int:task_id>/<path:name>")
    @login_required
    def shot_file(task_id, name):
        """返回任务截图（PNG）。

        安全要点：只允许读**该任务工作目录下 `shots/` 里**的文件 ——
        文件名里出现路径分隔符、或解析后不在 shots 目录内，一律 404（防目录穿越）。
        """
        task = db.get_task(task_id)
        if not task:
            abort(404)
        if "/" in name or "\\" in name or not name.lower().endswith(".png"):
            abort(404)
        # 注意：db.get_task 返回 sqlite3.Row，**没有 .get()**，必须下标取值
        base = Path(task["log_file"] or "").parent.resolve()
        target = (base / "shots" / name).resolve()
        if base not in target.parents or not target.is_file():
            abort(404)
        return send_file(str(target), mimetype="image/png")

    @app.route("/ips")
    @login_required
    def ips():
        """IP 资产页：按解析 IP 聚合域名。

        **默认只显示"非 CDN 解析"**（用户要求）：走 CDN 的域名解析出来是一堆边缘节点 IP，
        对"找到真实源站"没有帮助；`?cdn=1` 可把带 CDN 标记的也显示出来（仍单独标注厂商）。
        每行可勾选 → 直接对**真实 IP** 发起全端口扫描（复用 `/api/ports/full-scan`）。
        """
        include_cdn = request.args.get("cdn") == "1"
        agg = {}
        for r in db.list_subdomain_net():
            ip_text, cdn_label = (r["ip"] or ""), (r["cdn"] or "")
            if not ip_text:
                continue
            if cdn_label and not include_cdn:
                continue
            for ip in (x.strip() for x in ip_text.split(",")):
                if not ip:
                    continue
                item = agg.setdefault(ip, {"ip": ip, "domains": [], "cdn": cdn_label})
                if r["domain"] not in item["domains"]:
                    item["domains"].append(r["domain"])
                if cdn_label and not item["cdn"]:
                    item["cdn"] = cdn_label
        rows = sorted(agg.values(), key=lambda x: (-len(x["domains"]), x["ip"]))
        # 反查域名数：从 csegs 表按 IP 聚合（各任务里该 IP 的反查命中数之和）
        reverse_counts = {}
        for c in db._query("SELECT ip, SUM(count) c FROM csegs WHERE ip <> '' GROUP BY ip"):
            reverse_counts[c["ip"]] = int(c["c"] or 0)
        for row in rows:
            row["reverse"] = reverse_counts.get(row["ip"], 0)
        return render_template("ips.html", ips=rows, include_cdn=include_cdn)

    @app.route("/subdomains")
    @login_required
    def subdomains():
        # 只显示目标自身的子域名（被动收集 + 字典爆破）；JS/情报拓展出来的域名
        # 归到「拓展域名」页 —— 混在一起会让人误判资产归属。
        tag, where, params = _cdn_tag()
        rows, pager, q = _asset_page("subdomains", "/subdomains",
                                     extra_where=_and_where(db.OWN_SUBDOMAIN_WHERE, where),
                                     extra_params=params)
        if tag:
            pager["qs"] += f"&tag={tag}"
        return render_template("subdomains.html", subs=rows, pager=pager, q=q, tag=tag)

    # 拓展域名页的"来源分类"标签：用户要求分类浏览 + 分类排序，不要把 JS / FOFA 标题 /
    # 证书 / ICO / C 段混在一起。顺序即展示顺序（也是排序优先级）。
    EXT_SRC_TAGS = (
        ("js", "JS 挖掘", "js:mine", "js挖掘拓展"),
        ("title", "FOFA·标题反查", "osint:fofa-title", "fofa标题拓展"),
        ("cert", "FOFA·证书反查", "osint:fofa-cert", "fofa证书拓展"),
        ("ico", "FOFA·ICO 反查", "osint:fofa", "fofa-ico拓展"),
        ("shodan", "Shodan·ICO 反查", "osint:shodan", "shodan-ico拓展"),
        ("quake", "Quake·ICO 反查", "osint:quake", "quake-ico拓展"),
        ("ctlog", "CT 日志(crt.sh)", "osint:ctlog", "ct日志拓展"),
        ("cseg", "C 段反查", "osint:cseg", "c段反查拓展"),
    )
    # 分类排序表达式：按 EXT_SRC_TAGS 的顺序，未知来源排最后，同类内按 id 倒序（新的在前）。
    EXT_SRC_ORDER = "CASE source " + " ".join(
        f"WHEN '{s}' THEN {i}" for i, (_k, _l, s, _n) in enumerate(EXT_SRC_TAGS)
    ) + " ELSE 99 END, id DESC"
    # 分组模式下**每页多少个主域名**：分页单位是"组"，一页 20 个主域名足够扫一眼来源分布，
    # 再多就要滚很久（平铺模式下分页单位仍是行，走 `?size=`）。
    EXT_GROUPS_PER_PAGE = 20

    @app.route("/extdomains")
    @login_required
    def extdomains():
        """拓展域名：从 JS 与外部情报（C 段 / ICO / 标题 / 证书）带出来的关联域名。

        **按来源分类展示与排序**（JS 挖掘 → FOFA·标题 → FOFA·证书 → FOFA·ICO → C 段），
        用户要求"不要夹在一起"；`?src=` 只显示某一类。
        **默认隐藏重叠资产**：某域名若已经作为"目标自身子域名"存在过（任意任务），
        说明它早就在资产清单里，这里再列一遍纯属重复；`?all=1` 可显示全部。

        **默认按主域名（注册域）分组折叠**（用户 2026-09-25：「分域名而来」）：拓展出来的
        域名往往几十上百个同属一个主域名，摊平成一张长表看不出"这批是从哪个域来的"。
        分组必须按**组**分页才能不把同一个主域名切到两页上，所以分组模式下分页的
        单位是"主域名"而不是"行"。`?group=0` 回到原来的平铺表。
        """
        src = (request.args.get("src") or "").strip().lower()
        picked = next((t for t in EXT_SRC_TAGS if t[0] == src), None)
        if not picked:
            src = ""
        src_where = f"source = '{picked[2]}'" if picked else None
        scan_name = picked[3] if picked else "拓展域名"
        tag, where, params = _cdn_tag()
        show_all = _overlap_args()
        page, size, q = _page_args()
        grouped = request.args.get("group", "1") != "0"
        ext_where = _and_where(db.EXT_SUBDOMAIN_WHERE, where, src_where,
                               None if show_all else db.OVERLAP_EXT_WHERE)
        # 分组模式下 `size` 的含义变成"每页多少个主域名"：翻页链接与分页条必须同一个口径，
        # 否则链接里会出现两个 `size=`（Flask 取第一个，页面显示的却是第二个）。
        if grouped:
            size = EXT_GROUPS_PER_PAGE
        qs = f"&q={quote(q)}&size={size}" if q else f"&size={size}"
        for flag, value in (("tag", tag), ("src", src)):
            if value:
                qs += f"&{flag}={value}"
        if show_all:
            qs += "&all=1"
        if not grouped:
            qs += "&group=0"
        row_total, groups = 0, []
        if grouped:
            # 分组在 Python 里做（SQL 侧没有"注册域"函数），因此按上限取整批匹配行；
            # 上限之外的行不参与分组，页面会如实提示（见模板里的 `capped` 提示）。
            rows, row_total = db.page_assets("subdomains", limit=extdom.GROUP_ROW_CAP,
                                             offset=0, q=q or None, extra_where=ext_where,
                                             extra_params=params, order=EXT_SRC_ORDER)
            all_groups = extdom.group_by_base([dict(r) for r in rows])
            pages = max(1, (len(all_groups) + EXT_GROUPS_PER_PAGE - 1) // EXT_GROUPS_PER_PAGE)
            if page > pages:      # 页码越界（例如过滤后组数变少）→ 回落到最后一页
                page = pages
            groups = all_groups[(page - 1) * EXT_GROUPS_PER_PAGE: page * EXT_GROUPS_PER_PAGE]
            pager = {"page": page, "size": EXT_GROUPS_PER_PAGE, "total": len(all_groups),
                     "pages": pages, "base": "/extdomains", "qs": qs}
            subs = []
        else:
            subs, pager, q = _asset_page(
                "subdomains", "/extdomains", extra_where=ext_where,
                extra_params=params, order=EXT_SRC_ORDER)
            pager["qs"] = qs
            row_total = pager["total"]
        return render_template("extdomains.html", subs=subs, groups=groups, grouped=grouped,
                               row_total=row_total, pager=pager, q=q, tag=tag,
                               show_all=show_all, secrets=_secret_counts(),
                               src=src, src_tags=EXT_SRC_TAGS, scan_name=scan_name,
                               row_cap=extdom.GROUP_ROW_CAP)

    @app.route("/sites")
    @login_required
    def sites():
        show_all = _overlap_args()
        # 两层"重复"处理，都由 `?all=1` 一起放开：
        # 1) 重叠资产（跨任务）：同一 URL 在多个任务里都探到过时，只保留**最新一次扫描**的那条
        #    （`MAX(id)`）—— 站点行带的是当次扫描的 status/title/length/tech，留最旧那条意味着
        #    默认视图一直展示陈旧数据（重扫的目的正是刷新这些字段）；
        #    反复扫同一个目标时，站点列表也不会再被撑成 N 倍；
        # 2) 同任务内重复（标题 + 响应长度完全相同），多为同一台虚拟主机的别名/泛解析产物
        #    （灯塔类工具也做这层去重）。key 必须带 task_id：这是跨任务视图，若不带，
        #    A 任务的站点会因为 B 任务有同名同长度的站点而被折叠掉（实测把同一个靶场的
        #    15 条记录折成了 1 条，资产归属直接丢失）；标题为空的不参与折叠。
        # 注意：折叠只作用于**当前页**（分页条上的"共 N 条"是 SQL 的总数）。
        rows, pager, q = _asset_page(
            "sites", "/sites",
            extra_where=None if show_all else db.OVERLAP_SITE_WHERE)
        rows = [dict(r) for r in rows]
        seen, hidden = {}, 0
        for r in rows:
            r["dup"] = 0
            title = (r.get("title") or "").strip()
            if not title:
                continue
            key = (r.get("task_id"), title, r.get("length"))
            first = seen.get(key)
            if first is None:
                seen[key] = r
            else:
                first["dup"] += 1
                r["hidden_dup"] = True
                hidden += 1
        if not show_all:
            rows = [r for r in rows if not r.get("hidden_dup")]
        else:
            pager["qs"] += "&all=1"
        plain = request.args.get("plain") == "1"
        if plain:                     # 分页/筛选链接要带上，否则翻页会掉回完整模式
            pager["qs"] += "&plain=1"
        return render_template("sites.html", sites=rows, pager=pager, q=q,
                               show_all=show_all, hidden=hidden, plain=plain)

    @app.route("/ports")
    @login_required
    def ports():
        rows, pager, q = _asset_page("ports", "/ports")
        return render_template("ports.html", ports=rows, pager=pager, q=q)

    @app.route("/fullports")
    @login_required
    def fullports():
        """全端口扫描：**按任务分布**看端口资产，并可对勾选的主机发起全端口扫描。

        与 `/ports`（端口明细表）的区别：这里是"主机 × 任务"的视角 —— 一眼看出
        哪个任务在哪些主机上开了哪些端口，再决定要不要对某个 IP 补一次 1-65535 全端口。
        """
        raw_rows = db._query(
            "SELECT task_id, host, ip, COUNT(*) c, GROUP_CONCAT(port) ports "
            "FROM ports GROUP BY task_id, host, ip ORDER BY task_id DESC, host")
        names = {t["id"]: t["name"] for t in db.list_tasks(limit=1000)}
        rows = []
        for r in raw_rows:
            item = dict(r)      # sqlite3.Row 不支持赋值，先转成 dict 再加工
            item["ports"] = sorted(
                {int(p) for p in str(item.get("ports") or "").split(",")
                 if str(p).strip().isdigit()})
            item["task_name"] = names.get(item["task_id"], f"#{item['task_id']}")
            rows.append(item)
        return render_template("fullports.html", hosts=rows)

    @app.route("/api/ports/full-scan", methods=["POST"])
    @login_required
    def api_full_scan():
        """对勾选的主机发起**全端口扫描**（1-65535）。

        实现上走"新建一个只跑 portscan 的任务"（与「批量跑子域名」同一套做法）：
        任务选项 `portscan_full` 让这个任务无视全局 `portscan.enabled` 也会执行，
        并且会自动跳过本任务已经扫过的端口。

        续25-fix：本入口**不支持「追加」** —— IP/全端口页是跨任务视图（汇总所有任务的
        主机），没有唯一源任务可追加。此前 `append` 参数被**静默忽略**、照样新建任务，
        属静默失败；这里显式 409 拒绝，文案与 `ips.html` / `fullports.html` 的提示一致。
        """
        if str(request.form.get("append", "")).lower() in ("1", "true", "on"):
            return _append_err("IP 资产页是跨任务视图，没有唯一源任务，"
                               "此入口不支持追加执行；"
                               "请在任务详情页对已勾选资产点「追加」。",
                               url_for("fullports"))
        hosts, seen = [], set()
        for raw in request.form.getlist("host"):
            h = (raw or "").strip()
            if h and h not in seen:
                seen.add(h)
                hosts.append(h)
        if not hosts:
            return redirect(url_for("fullports"))
        name = (request.form.get("name") or "").strip() or \
            time.strftime("全端口-%m%d-%H%M%S")
        targets = "\n".join(hosts)
        stages = ["portscan"]
        options = {"portscan_full": True}
        task_id = db.create_task(name, targets, stages, options)
        _spawn(task_id, name, targets, stages, options)
        logger.info(f"[gui] 全端口扫描任务 #{task_id} 已创建（{len(hosts)} 个主机）")
        return redirect(url_for("task_detail", task_id=task_id))

    @app.route("/csegs")
    @login_required
    def csegs():
        rows, pager, q = _asset_page("csegs", "/csegs")
        return render_template("csegs.html", csegs=rows, pager=pager, q=q)

    @app.route("/dirs")
    @login_required
    def dirs():
        show_all = _overlap_args()
        agg = request.args.get("agg") == "1"
        rows, pager, q = _asset_page("dirs", "/dirs")
        # 重复长度默认隐藏：同一站点下状态码与响应大小都相同的多条只留首个，`?all=1` 放开
        rows, hidden = _fold_dirs(rows, show_all)
        if agg:
            # 聚合需跨全库（不再按页切）：拉全部（受 q 过滤），上限 5000 防极端库
            all_rows, _ = db.page_assets("dirs", limit=5000, offset=0, q=q or None)
            all_rows, _ = _fold_dirs(all_rows, show_all)
            groups = _agg_dirs(all_rows)
            pager["qs"] += "&agg=1"
            if show_all:
                pager["qs"] += "&all=1"
            return render_template("dirs.html", dirs=groups, pager=pager, q=q,
                                   show_all=show_all, hidden=hidden, agg=True)
        if show_all:
            pager["qs"] += "&all=1"
        return render_template("dirs.html", dirs=rows, pager=pager, q=q,
                               show_all=show_all, hidden=hidden)

    # ---------- 黑名单 / 批量子域名 ----------
    #
    # 黑名单落地在 `config/blacklist.txt`（纯文本，可手工编辑），命中即"不入资产库"，
    # 因此也不会被后续阶段扫到。这里提供批量加入/移除 —— 逐个手敲域名不现实。

    def _picked_domains():
        """勾选的域名（去重保序）：跨任务资产页里同一个域名可能出现在多个任务下。"""
        seen, out = set(), []
        for raw in request.form.getlist("domain"):
            d = raw.strip()
            if d and d not in seen:
                seen.add(d)
                out.append(d)
        return out

    @app.route("/api/blacklist/add", methods=["POST"])
    @login_required
    def api_blacklist_add():
        domains = _picked_domains()
        n = blacklist.add(domains, settings)
        logger.info(f"[gui] 黑名单新增 {n} 条（提交 {len(domains)} 个）")
        return redirect(_safe_next(request.form.get("next"), url_for("subdomains")))

    @app.route("/api/blacklist/remove", methods=["POST"])
    @login_required
    def api_blacklist_remove():
        n = blacklist.remove(_picked_domains(), settings)
        logger.info(f"[gui] 黑名单移除 {n} 条")
        return redirect(url_for("settings_page"))

    @app.route("/api/domains/run-subdomain", methods=["POST"])
    @login_required
    def api_run_subdomain():
        """把勾选的域名打包成**一个新任务**，只跑 subdomain 阶段。

        为什么新建任务而不是在当前任务下挂子任务：现有任务模型（一任务一线程、独立状态与
        独立停止/删除）可以直接复用，子任务要改表结构、任务树渲染、状态聚合与递归停止，
        收益只是 UI 好看一点 —— 按用户确认的口径选"新建任务"。
        """
        domains = _picked_domains()
        if not domains:
            return redirect(_safe_next(request.form.get("next"), url_for("subdomains")))
        stages = ["subdomain"]
        # 任务名：表单可显式指定前缀（拓展域名页按来源分类给出，如 `fofa标题拓展`），
        # 统一再拼上时间戳，避免同名任务互相覆盖辨认；没给前缀时退回旧的 "批量子域-…"。
        prefix = (request.form.get("name") or "").strip()
        if prefix:
            name = f"{prefix}-{time.strftime('%m%d-%H%M%S')}"
        else:
            name = time.strftime("批量子域-%m%d-%H%M%S")
        targets = "\n".join(domains)
        task_id = db.create_task(name, targets, stages, {})
        _spawn(task_id, name, targets, stages, {})
        logger.info(f"[gui] 批量子域名任务 #{task_id} 已创建（{len(domains)} 个域名，仅 subdomain 阶段）")
        return redirect(url_for("task_detail", task_id=task_id))

    @app.route("/api/domains/resolve", methods=["POST"])
    @login_required
    def api_resolve_domains():
        """对勾选域名做**纯 DNS 解析**并回填 `ip` / `cname` / `cdn`（零 HTTP 请求）。

        为什么需要（用户 2026-09-23：「我根据你这些域名都没有检测」）：扩展域名里的
        「解析 IP / CNAME」全是 `-` —— 因为 `_fill_net()` 只在 **subdomain 阶段**对目标自身
        子域名跑，而拓展域名是 jsmine / osint 在它之后才带出来的，没人给它们解析过。
        这里按用户勾选的范围补解析（DNS 只读、不改目标状态），并复用与子域名完全相同的
        解析器与 CDN 判据（`dnsq.resolve_detail` + `cdn.match`），`ip_note` 同样记下失败原因。

        规模由"勾选了多少"决定：单个域名 3 秒超时、并发 20，几十个域名在秒级完成。
        """
        task_id = (request.form.get("task_id") or "").strip()
        back = _safe_next(request.form.get("next"), url_for("tasks"))
        domains = _picked_domains()
        if not task_id.isdigit() or not domains:
            return redirect(back)
        tid = int(task_id)
        if not db.get_task(tid):
            return redirect(back)
        subs_cfg = settings.get("subdomain", {}) or {}
        timeout = float(subs_cfg.get("dns_timeout", 3) or 3)
        workers = max(1, min(20, int((settings.get("limits") or {}).get("max_workers", 20) or 20)))

        def _one(host):
            chain, ips, reason = dnsq.resolve_detail(host, timeout=timeout, settings=settings)
            # 与 subdomain/extdom 阶段同一口径：CNAME 链 + 解析 IP 段两条判据。
            return host, ",".join(ips), cdn.match(chain, settings, ips), reason, \
                (chain[-1] if chain else "")

        net, cnames = {}, {}
        for host, ips, cdn_label, reason, last_cname in pool_run(_one, domains, workers=workers):
            net[host] = (ips, cdn_label, reason)
            if last_cname:
                cnames[host] = last_cname
        db.set_subdomain_net(tid, net)
        db.set_subdomain_cnames(tid, cnames)
        ok = sum(1 for v in net.values() if v[0])
        logger.info(f"[gui] 任务 #{tid} 解析回填 {len(net)} 个域名（成功 {ok} 个）")
        return redirect(back)

    @app.route("/api/domains/scan-ext", methods=["POST"])
    @login_required
    def api_scan_ext():
        """把勾选的**拓展域名**送去真正检测：新建一个跑 `subdomain → probe → dirscan → vulnscan` 的任务。

        为什么需要（用户 2026-09-23：「我根据你这些域名都没有检测」）：拓展域名只入
        `subdomains` 表，而 probe / dirscan / vulnscan 的输入是**存活站点**（`sites`）——
        偏偏 osint 与 jsmine 两个阶段排在 probe **之后**，同一任务里它们新挖出来的域名
        赶不上本轮的存活探测，于是这些域名永远停在"有域名、无站点、无检测"的状态。

        **`subdomain` 阶段为什么也在里面**（用户 2026-09-25：「拓展域名如果再去检测也
        需要去子域名扫描」）：只探 `aaa.pengo.pro` 一个点是远远不够的，它下面往往还挂着
        `api.aaa.pengo.pro` 一类的资产。放在最前面是因为后续阶段的输入来自它的产出
        （`domains_for_probe` 含目标自身），这样子域也能一起进存活探测。
        代价是**多一轮被动收集 + DNS 字典爆破**（两者都是只读的 DNS / 公开接口查询，
        非破坏性），因此只对**用户明确勾选**的域名执行，不做全自动。

        为什么必须手动勾选而不是自动全跑：拓展域名里大量是第三方噪声
        （CDN、开源库站点、JS 命名空间碎片），全跑既越权又浪费请求额度。
        与「批量跑子域名」「补扫」同一套做法（新建任务、一任务一线程、可独立停止/删除）。
        """
        domains = _picked_domains()
        fallback = _safe_next(request.form.get("next"), url_for("tasks"))
        if not domains:
            return redirect(fallback)
        stages = ["subdomain", "probe", "dirscan", "vulnscan"]
        options = {}
        from_task = (request.form.get("task_id") or "").strip()
        if from_task.isdigit():          # 只收任务号，避免把任意文本写进任务选项
            options["rescan_of"] = int(from_task)
        # 登录态继承：新挖出的域名同样要用原来的会话去探（否则探到的是未登录视角）
        inherit = _source_auth(from_task)
        if inherit:
            options["auth"] = inherit
        name = (request.form.get("name") or "").strip() or \
            time.strftime("拓展探测-%m%d-%H%M%S")
        targets = "\n".join(domains)
        if str(request.form.get("append", "")).lower() in ("1", "true", "on"):
            return _do_append(from_task, stages, targets, domains, options, fallback)
        task_id = db.create_task(name, targets, stages, options)
        _spawn(task_id, name, targets, stages, options)
        logger.info(f"[gui] 拓展域名探测任务 #{task_id} 已创建"
                    f"（{len(domains)} 个域名，subdomain→probe→dirscan→vulnscan）")
        return redirect(url_for("task_detail", task_id=task_id))

    @app.route("/api/domains/promote", methods=["POST"])
    @login_required
    def api_promote_domains():
        """把勾选的**拓展域名**里"归属本项目"的那些**追加**为子域名（分域名而来）。

        判据（见 `scanner/extdom.promote_domains`）：域名的注册域命中**它所在任务**的目标
        注册域 —— 例如目标是 `pengo.pro`，JS 里挖出 `aaa.pengo.pro`（此前没发现），
        那它就是本项目的资产，不该一直躺在"拓展域名"里当第三方噪声。

        实现上是**新增一行** `source=promote:<原来源>`（原拓展行保留）：
        - 新行以 `promote:` 开头 → 属于"自身子域名"，于是「子域名资产」页按正常子域对待；
        - 原拓展行还在，但因为"该域名已作为自身子域名存在"，被 `db.OVERLAP_EXT_WHERE`
          默认隐藏（`?all=1` 仍可看）—— 既不重复占位，出处也永远可查。

        跨任务视图里勾选框只有域名，所以按域名反查它出现在哪些任务的拓展域名里，
        再逐个任务判定归属（同一个域名在两个任务里的归属结论可以不同）。
        """
        back = _safe_next(request.form.get("next"), url_for("extdomains"))
        domains = _picked_domains()
        if not domains:
            return redirect(back)
        task_id = (request.form.get("task_id") or "").strip()
        res = extdom.promote_domains(domains, settings, logger=logger,
                                     task_id=int(task_id) if task_id.isdigit() else None)
        logger.info(f"[gui] 归属追加：勾选 {len(domains)} 个 → 追加 {len(res['promoted'])} 个"
                    f"（任务 {res['tasks'] or '无'}）")
        return redirect(back)

    @app.route("/api/rescan", methods=["POST"])
    @login_required
    def api_rescan():
        """对勾选资产发起**补充扫描**：新建一个只跑对应阶段、走全量档的任务。

        `stage=dirscan` → 深度目录补扫（全量分层字典 + dirmap + 后缀派生）；
        `stage=portscan` → 全端口补扫（1-65535）；
        `stage=vulnscan` → **复查**（P1-1）：对勾选漏洞的目标重跑一次漏洞初筛，得到新鲜结论
        再回头去「漏洞风险」页给旧记录打「确认/误报」。任务级选项 `dirscan_full` / `portscan_full`
        让这个任务无视全局开关与档位走全量，**不改全局策略**；`rescan_of` 记下发起它的原任务，
        任务详情页据此显示「由任务 #N 的补扫发起」并可回跳。
        `stage=screenshot` → **补截图**（站点页签）：勾选站点单独截图，任务选项 `screenshot_on`
        让本次无视 `screenshot.enabled=false`（同样不改全局策略）。

        与「批量跑子域名」「发起全端口扫描」同一套做法（一任务一线程，可独立停止/删除）。
        """
        stage = (request.form.get("stage") or "").strip().lower()
        fallback = _safe_next(request.form.get("next"), url_for("tasks"))
        if stage not in ("dirscan", "portscan", "vulnscan", "screenshot"):
            return redirect(fallback)
        targets, seen = [], set()
        # 字段名沿用各页既有习惯（`target`），同时接受 `targets` 便于直接调 API
        for raw in request.form.getlist("target") + request.form.getlist("targets"):
            t = (raw or "").strip()
            if t and t not in seen:
                seen.add(t)
                targets.append(t)
        if not targets:
            return redirect(fallback)
        label = {"dirscan": "全目录", "portscan": "全端口", "vulnscan": "漏洞复查",
                 "screenshot": "站点截图"}[stage]
        name = (request.form.get("name") or "").strip() or \
            time.strftime(f"补扫{label}-%m%d-%H%M%S")
        # vulnscan 没有"全量档"的概念（漏洞初筛的额度由 checks/limits 决定），
        # 所以只给它记 rescan_of，不塞一个引擎根本不读的 `vulnscan_full`。
        # screenshot 同理：它要的不是"全量档"，而是"本次无视策略开关"（`screenshot_on`）。
        if stage == "vulnscan":
            options = {}
        elif stage == "screenshot":
            options = {"screenshot_on": True}
        else:
            options = {f"{stage}_full": True}
        from_task = (request.form.get("from_task") or "").strip()
        if from_task.isdigit():          # 只收任务号，避免把任意文本写进任务选项
            options["rescan_of"] = int(from_task)
        # 登录态继承（同 api_scan_ext）：补扫必须沿用原任务的会话，否则"复查"变成
        # 换一个未登录身份重看一遍，与用户点「复查」的预期不符。
        inherit = _source_auth(from_task)
        if inherit:
            options["auth"] = inherit
        text = "\n".join(targets)
        stages = [stage]
        if str(request.form.get("append", "")).lower() in ("1", "true", "on"):
            return _do_append(from_task, stages, text, targets, options, fallback)
        task_id = db.create_task(name, text, stages, options)
        _spawn(task_id, name, text, stages, options)
        logger.info(f"[gui] 补扫任务 #{task_id} 已创建（{stage} 全量档，"
                    f"{len(targets)} 个目标，来源任务 #{from_task or '-'}）")
        return redirect(url_for("task_detail", task_id=task_id))

    # ---------- 设置 ----------

    # 策略配置：FOFA/Shodan/Quake 的三方配置与全部策略开关都在这一页 —— 续46 起**仅管理员**。
    # 这是本次多用户需求的**核心**诉求：子用户能跑扫描、看结果，但看不到配置（含接口凭据入口）。
    @app.route("/settings", methods=["GET", "POST"])
    @login_required
    @admin_required
    def settings_page():
        nonlocal settings
        if request.method == "POST":
            f = request.form
            try:
                data = {
                    "gui": {"host": f.get("host", "127.0.0.1"),
                            "port": int(f.get("port", 5000) or 5000),
                            "token": f.get("token", "") or "ctfscanner"},
                    "limits": {"max_workers": int(f.get("max_workers", 20) or 20),
                               "http_timeout": int(f.get("http_timeout", 10) or 10),
                               "verify_tls": f.get("verify_tls") == "1",
                               "verify_tls_external": f.get("verify_tls_external") == "1",
                               "dirscan_max_urls": int(f.get("dirscan_max_urls", 20) or 20),
                               "vulnscan_max_urls": int(f.get("vulnscan_max_urls", 100) or 100),
                               "wildcard_filter": f.get("wildcard_filter") == "1",
                               "favicon_md5": f.get("favicon_md5") == "1",
                               # F2 统一并发 / 限速 / 全局预算门控（见 scanner/throttle.py）。
                               # 0 = 不限（保持向后兼容）；`max_inflight_*` 是"同时最多几个在飞请求"，
                               # 进程级那个跨任务共享 —— 这才是"进程级零上限"的解药。
                               "max_inflight_global": int(
                                   f.get("max_inflight_global", 256) or 256),
                               "max_inflight_per_task": int(
                                   f.get("max_inflight_per_task", 256) or 256),
                               "rate_per_sec": float(f.get("rate_per_sec", 0) or 0),
                               "rate_burst": float(f.get("rate_burst", 0) or 0),
                               "budget_total": int(f.get("budget_total", 0) or 0),
                               "budget_subprocess_weight": int(
                                   f.get("budget_subprocess_weight", 1) or 1)},
                    # 检测策略：级别门槛 + POC 引擎总开关 + 按 OWASP 分类/检查项/级别关闭
                    "checks": {"min_severity": f.get("min_severity", "medium"),
                               "skip_severities": f.getlist("skip_severities"),
                               "poc_engine": f.get("poc_engine") == "1",
                               "disabled_categories": f.getlist("disabled_categories"),
                               "disabled_checks": f.getlist("disabled_checks"),
                               "poc_link_tags": f.get("poc_link_tags") == "1",
                               "poc_max_per_site": int(f.get("poc_max_per_site", 80) or 80)},
                    "passive": {"enabled": f.get("passive_enabled") == "1",
                                "timeout": int(f.get("passive_timeout", 20) or 20)},
                    # 子域名收集：subfinder(-all) 与内置免 key 被动源是否取并集
                    "subdomain": {"max_resolve": int(
                                      (settings.get("subdomain") or {}).get("max_resolve", 500) or 500),
                                  "dns_timeout": float(
                                      (settings.get("subdomain") or {}).get("dns_timeout", 3) or 3),
                                  "union_passive": f.get("union_passive") == "1"},
                    "evasion": {"random_ua": f.get("random_ua") == "1",
                                "spoof_xff": f.get("spoof_xff") == "1",
                                "waf_bypass": f.get("waf_bypass") == "1",
                                "bypass_level": int(f.get("bypass_level", 2) or 0),
                                "waf_detect": f.get("waf_detect") == "1"},
                    "takeover": {"enabled": f.get("takeover_enabled") == "1",
                                 "max_hosts": int(f.get("takeover_max_hosts", 300) or 300),
                                 "http_check": f.get("takeover_http_check") == "1"},
                    # 阶段级总开关（与 takeover/portscan/jsmine 同一类）：默认开
                    # 目录扫描：默认开但只跑浅扫（用户要求"先浅浅过一遍再决定要不要深挖"）；
                    # 深扫走全量分层字典 + dirmap + 后缀派生
                    "dirscan": {"enabled": f.get("dirscan_enabled") == "1",
                                "mode": f.get("dirscan_mode", "quick"),
                                "quick_max_paths": int(
                                    f.get("dirscan_quick_max_paths", 150) or 150),
                                "suffix_aware": f.get("dirscan_suffix_aware") == "1",
                                "big_dict": f.get("dirscan_big_dict") == "1",
                                "tech_aware": f.get("dirscan_tech_aware") == "1",
                                "max_paths": int(f.get("dirscan_max_paths", 400) or 400),
                                "fw_max_paths": int(f.get("dirscan_fw_max_paths", 150) or 0),
                                # 目录递归（续30，默认关）：0 = 关闭
                                "recursive_depth": int(
                                    f.get("dirscan_recursive_depth", 0) or 0),
                                "recursive_max_dirs": int(
                                    f.get("dirscan_recursive_max_dirs", 5) or 0),
                                "recursive_max_paths": int(
                                    f.get("dirscan_recursive_max_paths", 40) or 0)},
                    "vulnscan": {"enabled": f.get("vulnscan_enabled") == "1"},
                    # 站点截图（可选，默认关）：无头 Edge/Chrome
                    "screenshot": {"enabled": f.get("screenshot_enabled") == "1",
                                   "max_sites": int(f.get("screenshot_max_sites", 20) or 20),
                                   "window": (f.get("screenshot_window") or "1280x900").strip(),
                                   "timeout": int(f.get("screenshot_timeout", 30) or 30),
                                   "browser": (f.get("screenshot_browser") or "").strip()},
                    # TLS 证书取证（可选，默认关）：只对 https / tls_ports 站点做一次只读握手
                    "cert": {"enabled": f.get("cert_enabled") == "1",
                             "max_sites": int(f.get("cert_max_sites", 30) or 30),
                             "timeout": int(f.get("cert_timeout", 8) or 8),
                             # 端口列表：页面输入 "443,8443" 这种逗号/空格分隔的写法；
                             # 全非法时回退默认值（不要让一个手滑把功能变成"永不触发"）
                             "tls_ports": parse_port_list(f.get("cert_tls_ports"))},
                    "portscan": {"enabled": f.get("portscan_enabled") == "1",
                                 "max_hosts": int(f.get("portscan_max_hosts", 100) or 100),
                                 "ports": f.get("portscan_ports", ""),
                                 # 全端口：top（内置 TOP 表）/ full（1-65535）
                                 "mode": "full" if f.get("portscan_mode") == "full" else "top",
                                 "full_ports": (f.get("portscan_full_ports") or "1-65535").strip(),
                                 # 全端口专用并发/超时（只在 full 模式生效）
                                 "full_workers": int(f.get("portscan_full_workers", 256) or 256),
                                 "full_timeout": float(f.get("portscan_full_timeout", 0.5) or 0.5),
                                 "exclude_scanned": f.get("portscan_exclude_scanned") == "1",
                                 "timeout": float(f.get("portscan_timeout", 1) or 1),
                                 "workers": int(f.get("portscan_workers", 64) or 64),
                                 "banner": f.get("portscan_banner") == "1",
                                 # auto / fscan / nmap / builtin（见 scanner/stages/portscan.py）
                                 "engine": (f.get("portscan_engine") or "auto").strip()},
                    "jsmine": {"enabled": f.get("jsmine_enabled") == "1",
                               "max_pages": int(f.get("jsmine_max_pages", 20) or 20),
                               "max_js": int(f.get("jsmine_max_js", 40) or 40),
                               "secrets": f.get("jsmine_secrets") == "1"},
                    # 外部情报拓展（OSINT）：C 段反查 + favicon 反查，两项默认都关
                    "iprecon": {"enabled": f.get("iprecon_enabled") == "1",
                                "api": f.get("iprecon_api", "") or
                                       "https://api.webscan.cc/?action=query&ip={ip}",
                                "max_ips": int(f.get("iprecon_max_ips", 500) or 500),
                                "max_hosts": int(f.get("iprecon_max_hosts", 200) or 200),
                                "max_domains_per_ip": int(
                                    f.get("iprecon_max_domains_per_ip", 30) or 30),
                                "workers": int(f.get("iprecon_workers", 5) or 5),
                                "timeout": float(f.get("iprecon_timeout", 10) or 10)},
                    "fofa": {"enabled": f.get("fofa_enabled") == "1",
                             "max_sites": int(f.get("fofa_max_sites", 30) or 30),
                             "max_assets": int(f.get("fofa_max_assets", 100) or 100),
                             "workers": int(f.get("fofa_workers", 5) or 5),
                             "black_ico_threshold": int(
                                 f.get("fofa_black_ico_threshold", 200) or 200),
                             # 证书反查：独立子开关 + 通用证书阈值 + 查询上限
                             "cert_enabled": f.get("fofa_cert_enabled") == "1",
                             "cert_threshold": int(f.get("fofa_cert_threshold", 200) or 200),
                             "max_cert_queries": int(
                                 f.get("fofa_max_cert_queries", 10) or 10),
                             # 标题反查：独立子开关 + 公共标题阈值 + 查询上限
                             "title_enabled": f.get("fofa_title_enabled") == "1",
                             "title_threshold": int(
                                 f.get("fofa_title_threshold", 200) or 200),
                             "max_title_queries": int(
                                 f.get("fofa_max_title_queries", 10) or 10),
                             # 标题反查的归属相关性：label（默认）/ substring（回退）
                             "title_match": (f.get("fofa_title_match") or "label")},
                    # A10 SSRF 受控回连（默认关）：本机监听 + 每参数唯一 token
                    "ssrf": {"enabled": f.get("ssrf_enabled") == "1",
                             # 留空 = 用本机监听地址；填了外部基址后本模块读不到命中，
                             # 只注入并把 token 写进任务日志（宁可不报也不谎报）
                             "callback_base": (f.get("ssrf_callback_base") or "").strip(),
                             "host": (f.get("ssrf_host") or "127.0.0.1").strip(),
                             "port": int(f.get("ssrf_port", 0) or 0),
                             "wait_seconds": float(f.get("ssrf_wait_seconds", 6) or 0),
                             "max_params": int(f.get("ssrf_max_params", 12) or 12)},
                    # Shodan / Quake favicon 反查：与 FOFA 同构，各自独立开关（默认都关）
                    "shodan": {"enabled": f.get("shodan_enabled") == "1",
                               "max_sites": int(f.get("shodan_max_sites", 30) or 30),
                               "max_assets": int(f.get("shodan_max_assets", 100) or 100),
                               "workers": int(f.get("shodan_workers", 5) or 5),
                               "black_ico_threshold": int(
                                   f.get("shodan_black_ico_threshold", 200) or 200)},
                    "quake": {"enabled": f.get("quake_enabled") == "1",
                              "max_sites": int(f.get("quake_max_sites", 30) or 30),
                              "max_assets": int(f.get("quake_max_assets", 100) or 100),
                              "workers": int(f.get("quake_workers", 5) or 5),
                              "black_ico_threshold": int(
                                  f.get("quake_black_ico_threshold", 200) or 200)},
                    # CT 日志（crt.sh，免 key）在线查询：证书维度记录 + 拓展域名来源
                    "ctlog": {"enabled": f.get("ctlog_enabled") == "1",
                              "max_domains": int(f.get("ctlog_max_domains", 10) or 10),
                              "max_records": int(f.get("ctlog_max_records", 50) or 50),
                              "max_domains_per_cert": int(
                                  f.get("ctlog_max_domains_per_cert", 50) or 50),
                              "timeout": int(f.get("ctlog_timeout", 25) or 25),
                              "write_certs": f.get("ctlog_write_certs") == "1"},
                    # 黑名单：开关可从页面改，文件路径保持原值（改路径请直接编辑 settings.yaml）
                    "blacklist": {"enabled": f.get("blacklist_enabled") == "1",
                                  "path": (settings.get("blacklist") or {}).get(
                                      "path", "config/blacklist.txt")},
                    # 情报与线索（P3-2 / P3-3）：两项都默认关，且只写 leads 表
                    "intel": {"enabled": f.get("intel_enabled") == "1",
                              "source": (f.get("intel_source") or "kev").strip(),
                              "url": (f.get("intel_url") or "").strip(),
                              "cache_hours": float(f.get("intel_cache_hours", 24) or 0),
                              "timeout": int(f.get("intel_timeout", 20) or 20),
                              "max_leads": int(f.get("intel_max_leads", 50) or 50)},
                    "heuristic": {"enabled": f.get("heuristic_enabled") == "1",
                                  "max_leads": int(f.get("heuristic_max_leads", 50) or 50)},
                    # GitHub 泄露检索（续26）：默认关；token 在 config/keys.yaml（本页不碰凭据）
                    "github": {"enabled": f.get("github_enabled") == "1",
                               "max_domains": int(f.get("github_max_domains", 3) or 3),
                               "max_queries": int(f.get("github_max_queries", 4) or 4),
                               "per_page": int(f.get("github_per_page", 30) or 30),
                               "max_leads": int(f.get("github_max_leads", 30) or 30),
                               "timeout": int(f.get("github_timeout", 20) or 20)},
                }
            except ValueError:
                return render_template("settings.html", s=load_settings(), checks=owasp_checks,
                                       bl=blacklist.load(settings),
                                       bl_path=rel_display(blacklist.path(settings)),
                                       error="参数必须是整数")
            # 续48：审计只记"改了哪几个区块"，**绝不记值**（键名也省掉 —— 见 `_changed_sections`）。
            _changed = _changed_sections(settings, data)
            settings = save_settings(data)
            _audit(audit.KIND_SETTINGS, target=",".join(_changed) or "（无变化）",
                   detail=f"保存策略配置（变更区块：{','.join(_changed) or '无'}）")
            return redirect(url_for("settings_page"))
        return render_template("settings.html", s=settings, checks=owasp_checks,
                               bl=blacklist.load(settings),
                               bl_path=rel_display(blacklist.path(settings)))

    # ---------- 访问审计（续48） ----------

    @app.route("/audit")
    @login_required
    @admin_required
    def audit_page():
        """访问审计流水页（管理员）：按 kind / actor / ip / 成败 / 关键字过滤 + 服务端分页。

        审计内容**只含元数据**（谁/何时/从哪个 IP/做了什么/成败），不含任何口令或凭据；
        写入侧与 `audit._scrub()` 两道网共同保证这一点（见 tests/smoke.py [7j] 的凭据红线）。
        """
        page, size, q = _page_args()
        kind = (request.args.get("kind") or "").strip()
        actor = (request.args.get("actor") or "").strip()
        ip = (request.args.get("ip") or "").strip()
        okarg = (request.args.get("ok") or "").strip()
        okf = None if okarg not in ("0", "1") else (okarg == "1")

        def _fetch(_page):
            return audit.query(kind=kind or None, actor=actor or None, ip=ip or None,
                               ok=okf, q=q or None, limit=size, offset=(_page - 1) * size)

        rows, total = _fetch(page)
        pages = max(1, (total + size - 1) // size)
        if page > pages:      # 页码越界（过滤后总页数变少）→ 回落最后一页重查
            page = pages
            rows, total = _fetch(page)
        parts = [f"size={size}"]
        for _k, _v in (("kind", kind), ("actor", actor), ("ip", ip), ("ok", okarg), ("q", q)):
            if _v:
                parts.append(f"{_k}={quote(_v)}")
        pager = {"page": page, "size": size, "total": total, "pages": pages,
                 "base": "/audit", "qs": "&" + "&".join(parts)}
        return render_template("audit.html", rows=rows, pager=pager, kinds=audit.KINDS,
                               labels=audit.KIND_LABELS, kind=kind, actor=actor, ip=ip,
                               okarg=okarg, q=q, summary=audit.summary(settings=settings),
                               retention=audit.config(settings)["retention_days"],
                               msg=(request.args.get("msg") or "").strip())

    @app.route("/api/audit/prune", methods=["POST"])
    @login_required
    @admin_required
    def api_audit_prune():
        """手动清理超过保留期（`gui.audit.retention_days`）的审计行 —— **只清 audit_log**。"""
        n = audit.prune(settings=settings)
        _audit(audit.KIND_ACCOUNT, target="audit_log", detail=f"手动清理过期审计 {n} 条")
        return redirect(url_for("audit_page", msg=f"已清理 {n} 条过期记录"))

    # ---------- 续50：开发模式 / 全流程自检（仅 dev.enabled=true 时侧栏才出现入口） ----------

    @app.route("/devmode")
    @login_required
    @admin_required
    def devmode_page():
        """开发模式页：起/停内置靶场 + 跑一次全流程自检（全 13 阶段、压量到最小）。

        夹具生命周期由「启动 / 停止」两个**显式按钮**控制（不做成"入队后自动起、跑完自动关"：
        队列里任务的收尾点不可靠，自动关容易泄漏端口）。
        """
        last = None
        for t in db.list_tasks(limit=200):
            if t["name"] == "dev-selfcheck":
                last = t
                break
        return render_template(
            "devmode.html",
            enabled=devmode.enabled(settings),
            base=_DEV_FIXTURE.get("base") or "",
            fixture_on=_DEV_FIXTURE.get("httpd") is not None,
            compressed=devmode.report(settings),
            kept=devmode.DEV_KEEP,
            fixture_port=(settings.get("dev") or {}).get("fixture_port", 0),
            last=last, stages=list(STAGE_ORDER),
            msg=(request.args.get("msg") or "").strip(),
            error=(request.args.get("error") or "").strip())

    @app.route("/api/devmode/fixture/start", methods=["POST"])
    @login_required
    @admin_required
    def api_devmode_fixture_start():
        if not devmode.enabled(settings):
            return redirect(url_for("devmode_page", error="开发模式未开启（dev.enabled=false）"))
        base = _dev_fixture_start((settings.get("dev") or {}).get("fixture_port", 0))
        if not base:
            return redirect(url_for("devmode_page", error="内置靶场启动失败（端口被占用？）"))
        _audit(audit.KIND_TASK, target="devfixture", detail=f"启动内置靶场 {base}")
        return redirect(url_for("devmode_page", msg=f"内置靶场已启动：{base}"))

    @app.route("/api/devmode/fixture/stop", methods=["POST"])
    @login_required
    @admin_required
    def api_devmode_fixture_stop():
        stopped = _dev_fixture_stop()
        _audit(audit.KIND_TASK, target="devfixture", detail="停止内置靶场")
        return redirect(url_for("devmode_page",
                                msg=("内置靶场已停止" if stopped else "内置靶场本就没在跑")))

    @app.route("/api/devmode/selfcheck", methods=["POST"])
    @login_required
    @admin_required
    def api_devmode_selfcheck():
        """起夹具（若未起）→ 入队一个**全 13 阶段 + dev 压量**的自检任务。

        压量由 `scanner/queue.py::_default_dispatch` 依据任务的 `dev_selfcheck` 选项施加
        （`devmode.apply` + `devmode.enable_all_stages`），**绝不写回 config/settings.yaml**。
        """
        if not devmode.enabled(settings):
            return redirect(url_for("devmode_page", error="开发模式未开启（dev.enabled=false）"))
        base = _dev_fixture_start((settings.get("dev") or {}).get("fixture_port", 0))
        if not base:
            return redirect(url_for("devmode_page", error="内置靶场启动失败（端口被占用？）"))
        targets = base + "/"
        stages = list(STAGE_ORDER)
        options = {"dev_selfcheck": True}
        tid = db.create_task("dev-selfcheck", targets, stages, options)
        _spawn(tid, "dev-selfcheck", targets, stages, options)
        _audit(audit.KIND_TASK, target=f"#{tid}",
               detail="开发模式全流程自检（全 13 阶段，配额压到最小）")
        return redirect(url_for("task_detail", task_id=tid))

    def _tail(path, n=150):
        try:
            return Path(path).read_text(encoding="utf-8", errors="replace").splitlines()[-n:]
        except OSError:
            return []

    return app


app = create_app()


def _port_free(host, port):
    """端口占用预检。

    必须自己做一次真实 bind：Windows 上 Werkzeug 对监听套接字设了 SO_REUSEADDR，
    第二个实例会**绑定成功**并照常打印 "Running on ..."，但页面其实打不开
    ——这正是之前诊断过的"控制台静默失败"（见 AGENTS.md 的经验教训）。
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, port))
        except OSError:
            return False
    return True


def _deploy_hints(gui_cfg):
    """启动时要说明白的**部署现状**（续47），返回待打印的行；`serve()` 只负责打印。

    为什么抽成纯函数：这些告警是"部署踩坑时的第一手线索"（整站 403、Cookie 不回传、
    伪造头被信任），必须有回归断言钉住；而 `serve()` 会起真实服务器、测试调不动它，
    "grep 源码里有这句话"又证明不了运行期真的会打印 —— 所以让文案可被直接调用。
    """
    lines = []
    cfg = gui_cfg or {}
    if cfg.get("behind_proxy"):
        lines.append("[*] 已启用 X-Forwarded-* 信任（gui.behind_proxy=true）："
                     "request.host / scheme 以反代转发的头为准。")
        lines.append("[!] 请确保本控制台**只被你的反向代理访问**（端口别对局域网/公网暴露）——"
                     "否则任何人都能自己塞 X-Forwarded-Host 来伪造 Host 与 scheme。")
        if not cfg.get("secure_cookie"):
            lines.append("[!] 警告：已确认在 TLS 反代后（behind_proxy=true）却没开 "
                         "gui.secure_cookie，会话 Cookie 不会带 Secure —— 等于白做一半，"
                         "建议打开（见 docs/deploy-https.md）。")
    allowed, bad = _allowed_hosts(cfg)
    if bad:
        lines.append("[!] 警告：gui.allowed_hosts 里这些值含通配符，已被**忽略**"
                     "（不允许放行一切）：" + ", ".join(bad))
    if allowed - _LOOPBACK_HOSTS:
        lines.append("[*] Host 白名单放行：" + ", ".join(sorted(allowed))
                     + "（可用 gui.allowed_hosts 扩展）")
    # 续32：绑到非回环地址 = **主动放弃了上面那道 Host 白名单**（我们无法预知你用哪个地址访问），
    # 这里必须**显式告警**，不能让"暴露"悄无声息地发生。续47 起 HTTPS 有了落地路径（反代终止 TLS），
    # 所以文案不再说"没有 HTTPS"，但**访问审计确实仍然没有**，这句要留着。
    if _host_of(cfg.get("host", "127.0.0.1")) not in _LOOPBACK_HOSTS:
        lines.append(f"[!] 警告：正在监听 {cfg.get('host')}（非回环地址），"
                     "局域网/公网上的任何人都能访问本控制台。")
        if cfg.get("allowed_hosts"):
            lines.append("    已配置 gui.allowed_hosts → Host 白名单仍然生效（只放行清单里的域名）。")
        else:
            lines.append("    未配置 gui.allowed_hosts → Host 白名单在本模式下已自动放宽。")
        lines.append("    HTTPS 需由反向代理终止（见 docs/deploy-https.md）；"
                     "**访问审计仍然没有**，请自行限制在可信网段。")
    return lines


def serve(start_queue=True):
    """控制台统一启动入口（run_gui.py 与 `python gui/app.py` 共用）。

    `start_queue=False` 用于**嵌入 / 测试**：只做端口预检 + 打印提示 + `app.run()`，**不起
    后台 worker**。回归 `[7i]` 会真调 `serve()` 校验启动提示，若在这里顺手起了 worker，
    测试库里残留的 `queued` 行会被真消费掉（污染其它用例）—— 故给它一个显式的关闭开关。
    """
    _settings = load_settings()
    s = _settings.get("gui", {})
    host, port = s.get("host", "127.0.0.1"), int(s.get("port", 5000))
    if not _port_free(host, port):
        print(f"[!] 启动失败：{host}:{port} 已被占用"
              "（上一次的控制台进程还在运行，或端口被其他服务占用）。")
        print("    处理：结束占用该端口的进程，或改 config/settings.yaml 的 gui.port 后重试。")
        raise SystemExit(1)
    # 续49：启动持久化任务队列的 worker（默认单消费者，见 scanner/queue.py）。
    # 放在控制台进程入口而不是 create_app()：create_app 会被测试 / WSGI 在 import 期调用，
    # 在工厂里起后台线程会产生 import 副作用。worker 与**控制台进程同生共死**（daemon 线程）。
    if start_queue:
        queue.start(_settings)
        print(f"[*] 任务队列已启动：{queue.config(_settings)['workers']} 个 worker"
              "（queue.workers；进程重启后未完成任务会自动重新入队）")
    print(f"[*] CTFScanner 控制台: http://{host}:{port}")
    # 续46：多用户之后，启动提示必须**分清两种状态** —— 有账号就别再宣扬那个共享口令
    # （它此时已经失效了，还打印出来等于引导人去试一个不存在的入口）。
    if users.count_users() == 0:
        print(f"[*] 尚未创建账号：可用 config/settings.yaml 的 gui.token"
              f"（{s.get('token', 'ctfscanner')}）以管理员身份登录，"
              f"随后到「账号」页创建账号 —— 建号后该口令立即失效。")
    else:
        print("[*] 多用户已启用：请用已创建的账号登录（管理员可在「账号」页建/停用子用户）。")
    # 续47：HTTPS 与 Host 白名单的现状**在启动时就说明白**（部署排错时最先看的就是这几行）。
    # 文案由 `_deploy_hints()` 生成 —— 抽成纯函数是为了让回归门禁能**真跑**这些告警
    # （`serve()` 会起真实服务器，测试不能调它；而"只 grep 源码里有这个字符串"证明不了运行期行为）。
    # 注意：这里**只**打印 `_deploy_hints()` 返回的行。续47 修复：原先循环体里还残留着旧
    # 非回环分支的第 3 句（"确需远程使用时，请走反向代理…"），它按 hint 行数**重复打印**，
    # 而且在回环地址下也会冒出来（用户就在本机，那句建议是错的）。这句想表达的意思已由
    # `_deploy_hints()` 非回环分支的最后一行覆盖，故直接删除、不搬移。
    for _line in _deploy_hints(s):
        print(_line)
    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    serve()
