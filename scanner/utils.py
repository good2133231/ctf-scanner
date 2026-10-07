"""通用工具：外部命令调用、HTTP 请求（requests 优先、urllib 兜底）、线程池、DNS、文件读写。"""
import ipaddress
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from . import throttle as _throttle_mod


# ---------- 外部命令 ----------

_BASE_DIR = Path(__file__).resolve().parent.parent


def _ext_variants(name):
    """同一个工具在 Windows / Linux 上的文件名变体：`fscan.exe` ↔ `fscan`（续61）。"""
    s = str(name)
    return [s, s[:-4]] if s.lower().endswith(".exe") else [s, s + ".exe"]


def _probe(path):
    """按文件系统**直接**判定"这个可执行文件在不在"（不依赖 `shutil.which` 的 PATHEXT 语义）。

    ⚠️ 续61 踩到的坑：Windows 上**只要路径里带目录**（`tools/fscan/fscan.exe` 就带），
    `shutil.which` 就退化成"精确探这一个名字"、**不会**替我们补 `.exe`；于是
    "配置写 `fscan.exe`、Linux 产物是无后缀的 `fscan`"（或反过来）在**两端各断一半** ——
    表现为工具明明在、却被判成未安装然后**静默降级**。这里直探文件系统即可两端通吃。
    POSIX 上再补一个可执行位判断（与 `shutil.which` 的原语义一致，避免把"存在但没 `+x`
    的普通文件"当成可用工具）；Windows 上没有可执行位概念，只看是不是文件。
    """
    try:
        p = Path(path)
        if not p.is_file():
            return None
    except OSError:
        return None
    if os.name == "posix" and not os.access(str(p), os.X_OK):
        return None
    return str(p)


def which(tool):
    """解析外部工具：裸名走 PATH；带路径分隔符的**相对路径按项目根**解析。

    为什么必须折算项目根：`shutil.which("tools/fscan/fscan.exe")` 是按**进程 CWD** 找的，
    从仓库外启动 GUI/CLI（或任何换了工作目录的调用方）就会找不到 —— 表现是"工具明明在，
    却被判成未安装"然后**静默降级**到内置实现。`config.py` 的 `tools` 段一直写着"可以填
    `tools/scanner/httpx.exe`"这类相对路径，这条折算才让那句话成立。

    **后缀容错（续61，跨平台）**：`config/settings.yaml` 里写的是 `tools/fscan/fscan.exe`
    —— 那是"本机是 Windows"的事实。同一个工具在 Linux 上的产物名是 `fscan`（没有 `.exe`），
    照配置值直找必然失败并**静默降级**。故：先按原值找，找不到再试"去掉/补上 `.exe`"的那个变体，
    于是**同一份配置在两端都能找到**（`nmap` 那种裸名不动 —— `shutil.which` 自己会按 PATHEXT 找）。
    带目录的路径一律走 `_probe()` 直探（`shutil.which` 在这些位置不补后缀，见 `_probe` 说明）。
    """
    t = str(tool or "").strip()
    if not t:
        return None
    found = shutil.which(t)
    if found:
        if "/" in t or "\\" in t:
            # 带目录的配置值（`tools/scanner/afrog`）会被 `shutil.which` 按**进程 CWD** 解析，
            # 并且**原样**返回相对串。而"显式换 cwd 起子进程"是外部工具的必需动作（portscan 续45
            # 为了不把 fscan 的 `result.txt` 落在仓库根、afrog 续121 为了不把 `reports/*.html`
            # 落在仓库根，都必须给 cwd）—— 那时这条相对路径指向的是**别处**：
            # 实测（从仓库根启动、配置 `tools/scanner/afrog`）不折算就是 rc=127，
            # 表现正是本函数注释里那句话："工具明明在，却被判成未安装"然后静默降级。
            return str(Path(found).resolve())
        return found
    if t.startswith(("/", "\\")) or (":" in t[:3]):
        for alt in _ext_variants(t):          # 绝对路径：不折算项目根，只补后缀变体
            found = _probe(alt)
            if found:
                return found
        return None
    if "/" not in t and "\\" not in t:
        return None                            # 裸名：只在 PATH 里找，不做任何臆造
    for alt in _ext_variants(t):
        found = _probe(str(_BASE_DIR / alt))
        if found:
            return found
    return None


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

# 多段公共后缀的**兜底**（`config/dicts/tlds.txt` 缺失/为空时才用）：取"注册域"时避免切错
# （如 a.b.com.cn 的注册域是 b.com.cn 而非 com.cn）。正常运行走 `_multi_part_suffixes()` ——
# 它从 tlds.txt 取**含点号的后缀**（含 punycode 形态），比这份硬编码全得多（实测 5415 条
# 多段，其中 287 条 punycode 多段，如 `xn--wcvs22d.xn--j6w193g` = 教育.香港）。
MULTI_TLD = frozenset({
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "co.uk", "org.uk", "ac.uk",
    "com.hk", "com.tw", "com.au", "com.sg", "co.jp", "co.kr",
})

_MULTI_PSL_CACHE = None


def _multi_part_suffixes():
    """多段公共后缀集合（**含 punycode 形态**）：`config/dicts/tlds.txt` 里含点号的后缀。

    模块级缓存（该文件只在 `tools/import_tlds.py --force` 重新生成时才变）；
    缺失/为空 → 返回 None，`base_domain` 回退到硬编码 `MULTI_TLD`。
    续68：`base_domain` 靠它修掉"多段 IDN 后缀切错"—— `base_domain('a.教育.香港')`
    曾返回后缀本身 `教育.香港`，导致 `*.教育.香港` 全被判成同一个注册域。
    """
    global _MULTI_PSL_CACHE
    if _MULTI_PSL_CACHE is not None:
        return _MULTI_PSL_CACHE or None
    items = set()
    try:
        from .config import resolve            # 函数内导入：不与 config 的加载顺序纠缠
        for line in read_lines(resolve("config/dicts/tlds.txt")):
            line = line.strip().lower().strip(".")
            if line and not line.startswith("#") and "." in line:
                items.add(line)
    except Exception:
        items = set()
    _MULTI_PSL_CACHE = items
    return items or None


def base_domain(host):
    """取注册域：**最长匹配**的多段公共后缀 + 1 段 label（example.com / example.com.cn /
    `a.xn--wcvs22d.xn--j6w193g`）。

    数据源是 `config/dicts/tlds.txt` 里含点号的后缀（**含 punycode**，续68）；清单缺失/为空
    时回退到硬编码 `MULTI_TLD`，再不行退回"末两段"的粗略版。只用于"同源判断/保护目标自身域"。
    续68 修掉：多段 **IDN** 后缀原先会切错 —— `base_domain('a.教育.香港')` 曾返回后缀本身
    `教育.香港`，导致 `*.教育.香港` 全被判成同一个注册域（方向是多留/fail-open，不误杀）。
    续84 补：入参**先过 `to_ascii()` 归一** —— 本函数是"咽喉点"之一，调用方五花八门
    （`urlparse().hostname` / 目标行 / 子域名表），都可能给**原始 Unicode**；而后缀表里存的是
    **punycode** 形态，不归一就仍会切错。归一后 Unicode 与 punycode 两种写法**结果一致**；
    非主机输入（含 `:` 或 `/`）→ 返回 `""`（比返回"http://x.com/"这类垃圾更安全）。
    """
    host = to_ascii(str(host or "").strip())      # 续84：Unicode → punycode（咽喉点归一）
    host = (host or "").strip(".")
    if not host:
        return ""
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    multi = _multi_part_suffixes() or MULTI_TLD
    best = ""
    for k in range(1, len(parts)):
        cand = ".".join(parts[k:])
        if cand in multi and len(cand) > len(best):
            best = cand
    if best:
        return ".".join(parts[-(len(best.split(".")) + 1):])
    return ".".join(parts[-2:])


# ---------- 域名形态 ----------

def to_ascii(text):
    """主机名 → ASCII(punycode) 小写形（IDN 归一化的**唯一入口**）。

    - **纯 ASCII 走快路径**（只 lower、**不调 idna**）：保证现有 ASCII 主机逐字节不变，
      也避免对已是 punycode 的串做二次编码。
    - 含非 ASCII 时才 `encode('idna')`（标准库 IDNA2003，零新依赖）。
    - 末尾的点先剥掉；空串 → 返回 **None**。
    - **本函数只做「归一化」，不做「合法性校验」**：长度 / 形态（≥2 段、label 合法、TLD 形态）
      一律由 `is_domain()` 负责。
    - 返回 None 的情形：**空串** / **非主机输入（含 `:` 或 `/`）** / **IDNA 编码失败**（非 ASCII 路径上 label>63B /
      非法 Unicode 会触发）；**纯 ASCII 输入只做小写、不做任何校验**，因此超长 ASCII label
      会原样返回 —— 这是**有意为之**（快路径保证 ASCII 行为逐字节不变），由 `is_domain` 兜住。
    - **只管主机名，不管端口/路径**：传入带端口 / 路径的串**返回 None**（不返回乱码 punycode）——
      冒号与斜杠会让 IDNA 把整串编成一个无效 label，那是**静默的错误值**，比显式失败更糟。
      调用方要端口/路径时自己先剥（`split(":")[0]` / `split("/")[0]`）。
    幂等：`to_ascii(to_ascii(x)) == to_ascii(x)`。
    """
    host = str(text or "").strip().lower().rstrip(".")
    if not host or ":" in host or "/" in host:
        return None
    try:
        if host.isascii():
            return host
        return host.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return None


def to_unicode(host):
    """ASCII(punycode) → Unicode 展示形。**展示层专用**，best-effort：任何失败原样返回、绝不抛。

    与 `to_ascii` 对称：那是"入库/比对前的归一"（失败必须返回 None），这是"给人看的回解"
    （失败退回原串）。因此 `to_unicode("http://…")` / 已是 Unicode 的串 / 非法 punycode
    都只是**原样返回**，绝不抛异常 —— 展示层不该因为一条脏数据整页崩掉。
    """
    text = str(host or "")
    if not text:
        return text
    try:
        return text.encode("ascii").decode("idna")
    except (UnicodeError, ValueError):
        return text


# 至少两段、TLD 为纯字母 2-24 位或 IDN 的 `xn--` punycode 形、
# 标签 1-63 位且不以 - 开头/结尾（不查 DNS，只看形态）
_DOMAIN_RE = re.compile(r"^(?=.{4,253}$)"
                        r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
                        r"(?:[a-z]{2,24}|xn--[a-z0-9-]{1,59})$")


def is_domain(text):
    """粗略判断"这串是不是域名"（**只看形态，不查 DNS**）。

    用于把 JS 里挖到的一堆字符串、外部情报返回的 host 字段收敛成真正的域名资产：
    - 至少两段（`localhost` 不算）；TLD 必须纯字母 2-24 位、或 IDN 的 `xn--` punycode 形
      （挡掉 `1.2.3.4`、`a.b` 这类）；
    - 标签 1-63 位、不以 `-` 开头/结尾；总长 ≤253；
    - **IPv4 / IPv6 / 带端口 / 带路径 / 带通配符 / 含空格 一律 False**。

    IDN 归一化：先 `to_ascii()` 把 Unicode/punycode 统一成 ASCII 形，再走形态正则 ——
    因此 `is_domain('例子.中国')` 与 `is_domain('xn--fsqu00a.xn--fiqs8s')` 都为 True。

    注意：这是"形态判断"，`is_domain("foo.bar")` 会是 True —— 它不保证域名真实存在，
    真实存在与否由 DNS 解析（`dnsq.resolve_detail`）负责。同样地 `is_domain('他.说')`
    也为 True（形态宽松是**有意为之**，语义闸门在 `jsmine._valid_host` 的 PSL 校验）。
    """
    text = str(text or "").strip()
    if not text or " " in text or "/" in text or ":" in text or "*" in text:
        return False
    try:
        ipaddress.ip_address(text)        # 裸 IP 不是域名（IP 资产归 portscan/probe）
        return False
    except ValueError:
        pass
    a = to_ascii(text)
    if a is None:
        return False
    return bool(_DOMAIN_RE.match(a))


# ---------- 站点显示（3xx 的「跳转后」） ----------

# 需要显示「跳转后」的状态码。放在这里而不是 probe 里：取证（probe）与显示（GUI 三处模板 +
# 报告两种格式）必须用**同一份**判断，写两遍迟早一边算 304 一边不算。
REDIRECT_STATUS = frozenset({301, 302, 303, 307, 308})


def _field(row, key, default=""):
    """从 **dict 或 `sqlite3.Row`** 里取一个字段（取不到 / 为 None 都回 `default`）。

    为什么不写 `row.get(...)`：本项目的"行"有两种 —— 阶段里构造的 `dict`，和从库里读出来的
    `sqlite3.Row`，而 **`sqlite3.Row` 没有 `.get()`**（本项目反复踩过，`gui/app.py` 里就有
    "必须先 `dict(...)` 再传"的注释）。`site_redirect` 同时服务 GUI（模板里的 Row）与报告
    （`db.list_sites` 的 Row），所以在这里把两种形态一次兜掉，调用点不必各自记得转 dict。
    """
    try:
        value = row[key]
    except (KeyError, IndexError, TypeError):
        return default
    return default if value is None else value


def site_redirect(row):
    """3xx 站点在页面 / 报告里该怎么显示（续112-B，用户 2026-10-06 的要求）。

    返回 `dict(status, title, jumped, final_url, note)`：
    - 不是 3xx，或跟随之后的取证没拿到（老库行 / 落地页不可达）→ 原样显示那一跳的
      状态与标题，**不编数**（绝不用"看起来像"的东西凑一个跳转后标题）；
    - 跟到了 → `status` = `301 → 200`，`title` = 落地页标题，`final_url` = 落地 URL，
      `note` = 给 title 提示用的整句话。

    ⚠️ 这里**只拼显示**：库里 `status` / `title` / `length` 仍是那一跳的事实本身，
    覆盖原始状态码等于谎报"这个端口直接回 200" —— 301 与 200 的安全含义不同。
    `row` 传 dict 或 `sqlite3.Row` 都行（见 `_field`）。
    """
    r = row if row is not None else {}
    st = int(_field(r, "status", 0) or 0)
    rs = int(_field(r, "redirect_status", 0) or 0)
    title = str(_field(r, "title") or "")
    if st not in REDIRECT_STATUS or not rs:
        return {"status": str(st), "title": title,
                "jumped": False, "final_url": "", "note": ""}
    final_title = str(_field(r, "redirect_title") or "").strip()
    final_url = str(_field(r, "redirect_url") or "")
    return {
        "status": f"{st} → {rs}",
        # 落地页没有 <title>（图片 / JSON / 空页）时保留原来那句（如「301 Moved Permanently」），
        # 并靠 `note` 说明"跟到了但落地页没标题"，而不是留个空位让人以为漏扫了。
        "title": final_title or title,
        "jumped": True,
        "final_url": final_url,
        "note": f"跟随 {st} 到达 {rs}：{final_url or '-'}"
                + ("" if final_title else "（落地页无 title）"),
    }


# ---------- 路径 ----------

def _mask_path(text):
    """把绝对路径压成「…/父目录/文件名」（只保留末尾两段）。

    **Web 展示层专用**：盘符、用户目录、整条目录树都不回显 ——
    只留"这是哪个目录下的哪个文件"这一条信息量。

    切段**同时按 `/` 与 `\\`**（而不是 `Path.parts`）：`Path.parts` 按运行平台选分隔符，
    在 Linux 上会把 `C:\\Users\\me\\x.txt` 整条当成一个名字（反斜杠在 POSIX 不是分隔符），
    于是"跨平台同一份代码"在两端给出不同结果。这里手工切，两端一致。
    """
    parts = [p for p in re.split(r"[\\/]+", str(text or "").strip())
             if p and not p.endswith(":")]
    if not parts:
        return "…"
    return "…/" + "/".join(parts[-2:])


def rel_display(path, base=None, mask_outside=False):
    """把路径显示成"相对项目根"的形式（POSIX 分隔符）；项目外/空值原样返回。

    所有面向用户的位置（CLI 输出、GUI 表格、日志）都应该走它 ——
    绝对路径会暴露本机目录结构，且 Windows 反斜杠在跨平台日志里也会割裂。

    `mask_outside=True` 是**更严的一档，Web 界面必须用它**（续61）：
    项目外的绝对路径不再原样返回，而是压成 `…/父/名`（见 `_mask_path`）。
    为什么要有这一档：项目里的工具可能装在项目外（`tools/fscan/` 是指向仓库外的目录联接、
    nmap 常装在 `Program Files`），`/tools` 页原来会把这些**本机绝对路径**直接打给浏览器；
    而 CLI 要保持原样（用户要拿这个路径去命令行复现），所以两者不能共用一个口径。
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
        # 非绝对路径（例如配置里的 `tools/fscan/fscan.exe`）本来就是相对形，不该被压缩
        if mask_outside and Path(text).is_absolute():
            return _mask_path(text)
        return text


# 自由文本里的本机绝对路径（Web 展示层要抹掉的形态）：
# ① 盘符开头：`C:\Program Files\...` / `D:/data/x`；② 引号里的绝对路径：
#    Python traceback 的 `File "/usr/lib/python3.10/x.py"`、errno 消息的 `'/home/u/x'`。
# ① 的**前置否定环视** `(?<!\w)` 不可省：没有它，`http://…` 里的 `p:/`、`https://…` 里的
#    `s:/` 会被当成盘符路径压成 `…/x/y` —— 而 scrub_paths 正是要处理**带 URL 的日志行**，
#    结果会把每条请求 URL 都毁掉（续61 实测出来的）。刻意**不**匹配裸的 `/xxx`：
#    那会把 URL 路径（`/api/pocs/1/toggle`）也一起毁掉。
_ABS_WIN_RE = re.compile(r"(?<!\w)[A-Za-z]:[\\/][^\s\"'<>|,;]*")
_QUOTED_ABS_RE = re.compile(r"([\"'])((?:[A-Za-z]:[\\/]|/)[^\"'\n]*)\1")


def scrub_paths(text, base=None):
    """把**自由文本**（子进程输出 / 日志行 / 异常消息）里的本机绝对路径抹掉（续61）。

    与 `rel_display` 的分工：那是"一个路径值 → 一个展示值"，这是"一段文本 → 一段文本"。
    Web 界面有三处会整段展示外部文本（`/devmode` 的自检 stdout、任务日志 tail、任务错误消息），
    里面的 Python traceback / 系统错误消息会带**本机绝对路径**，逐字段转换挡不住，必须在展示前过一遍。

    处理顺序（先项目根，再盘符，最后引号内的绝对路径）：
    ① 项目根前缀整体删掉 —— 仓库内的路径因此显示成 `scanner/db.py` 这种相对形；
    ② 剩下的盘符绝对路径压成 `…/父/名`；
    ③ 引号内的绝对路径（traceback 的 `File "…"`）同样压缩，**不改** URL 路径（它不带引号）。
    """
    s = str(text or "")
    if not s:
        return ""
    if base is None:
        from .config import BASE_DIR
        base = BASE_DIR
    for cand in {str(base), Path(base).as_posix()}:
        if cand:
            # 前缀 + 紧跟的一个分隔符一起吃掉，避免留下 `\scanner\db.py` 这种残缺形；
            # 大小写不敏感只为 Windows（盘符/目录名大小写不一致时也能对上），Linux 上无副作用
            s = re.sub(re.escape(cand) + r"[\\/]?", "", s, flags=re.IGNORECASE)
    s = _ABS_WIN_RE.sub(lambda m: _mask_path(m.group(0)), s)
    s = _QUOTED_ABS_RE.sub(lambda m: m.group(1) + _mask_path(m.group(2)) + m.group(1), s)
    return s


def format_duration(seconds):
    """把秒数格式化成中文时长：`1 小时 02 分 03 秒` / `12 分 05 秒` / `45 秒`。

    负数 / `None` / 非法值一律归 `0 秒` —— 时长是**展示值**，不该让页面或 CLI 抛错
    （真实的脏输入由 `db.finish_task_run` 的 `MAX(0, …)` 在写入侧就挡住）。

    放在 `utils` 而不是 `gui/app.py`：CLI 摘要（`cli/client.py`）与 GUI 详情页要显示**同一口径**，
    放 GUI 会让 CLI 反向依赖 Flask 应用。
    """
    try:
        total = int(seconds)
    except (TypeError, ValueError):
        total = 0
    if total < 0:
        total = 0
    hours, rem = divmod(total, 3600)
    minutes, secs = divmod(rem, 60)
    if hours:
        return f"{hours} 小时 {minutes:02d} 分 {secs:02d} 秒"
    if minutes:
        return f"{minutes} 分 {secs:02d} 秒"
    return f"{secs} 秒"


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

    verify 为 None 时**按出口分流**取配置（两把开关刻意不共用）：
    - `auth=True`（发往**目标侧**）→ `limits.verify_tls`（默认 False：CTF/靶场自签名常见）；
    - `auth=False`（发往**第三方接口**）→ `limits.verify_tls_external`（**默认 True**）。

    分流的原因（续42 修掉的缺陷）：第三方接口都是公网 CA 签名的，而且 FOFA / Shodan /
    Quake 要带 API key、api.github.com 要带 PAT —— 原先这条降级开关对**所有**出口生效，
    等于"为了扫自签名靶场，顺手把凭据挂上一条可被中间人读的信道"。
    企业 MITM 代理环境下若 certifi 认不出其根证书，可在 settings.yaml 把
    `verify_tls_external` 显式关掉（属用户显式选择，不做静默回退）。

    限流（F2）：`settings["_throttle"]` 存在时本次请求占用一个 `"http"` 名额
    （见 `scanner/throttle.py`）。预算耗尽 / 被取消时返回 None —— 语义上按"停止"处理，
    不是网络故障（任务级错误行与状态才是权威）。
    """
    th = (settings or {}).get("_throttle")
    if verify is None:
        # 出口分流放在**入口**里做（而不是 `_do_http` 里）：解析结果要能被调用方/测试
        # 直接观测到，且限流分支与非限流分支共用同一份判定，不会出现"两处各判一次"。
        _lim = (settings or {}).get("limits", {}) or {}
        if auth:
            # 目标侧：把**目标自己**的证书当不可信源处理（CTF 靶场自签名/过期是常态）
            verify = bool(_lim.get("verify_tls", False))
        else:
            # 第三方接口：公网 CA 签名，且多带 API key / PAT —— 默认校验
            # （与目标侧那项分开，绝不互相连带，见 docstring）
            verify = bool(_lim.get("verify_tls_external", True))
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


# ---------- HTTP 连接复用（续116）----------
#
# 原先每条请求走模块级 `requests.request()` —— 它内部**每次新建一个 Session、用完即关**，
# 于是每个请求都要重做一遍 TCP 三次握手（HTTPS 再叠一次 TLS 握手），同一个站点的第 15000 条
# 路径与第 1 条毫无关系。本机环回 A/B（同一把靶子、两条路都走 `_headers()`，只差连接怎么建）：
# 明文 HTTP 200 条请求 **200 条连接 → 1 条**、0.98 → 0.58 ms/请求；自签 TLS（RSA2048）
# **120 条连接 → 1 条**、**50.0 → 1.03 ms/请求（48.6x）** —— 一次 15348 条路径的 HTTPS 深扫
# 光握手就省约 12 分钟。真实远端目标还要再乘上 RTT（握手是 1~2 个来回）。
#
# 三条纪律保证"只快、不改语义"：
# 1) **Session 按线程持有**（`threading.local`）：requests 官方不保证 Session 并发安全，
#    真正会撞的是 cookie jar 与 `verify`（见第 3 条），按线程隔离两处都无所谓。
#    线程本地不损失收益：`pool_run` 每个 worker 一次批量里连着打同一个站几百条路径，
#    复用发生在**批内**；批与批之间本来就该从零开始（新阶段不该继承上一阶段的连接状态）。
# 2) **每次请求前后各清一次 cookie jar**：今天"每次新建 Session"等于"每次从空 jar 出发"，
#    复用后必须显式维持 —— 目录扫描里某条路径返回的 `Set-Cookie` 不该影响下一条的判定。
#    单次请求**内部**的重定向链照旧携带 cookie（今天那次调用自己的 Session 就是这么活的，
#    续112-B 的「跳转后」标题口径不能因为这次提速而漂）。
# 3) **按 `verify` 值分开缓存**：requests 的 `HTTPAdapter.cert_verify` 把 `cert_reqs` 写在
#    **连接池对象**上而不是单条连接上，同一主机若混用"目标侧 `verify=False`"与
#    "第三方 `verify=True`"就会互相改写。今天每次新建 Session 天然隔离，复用后必须显式隔离
#    （出口分流是续42 修过的真缺陷，不能靠这次提速把它悄悄并回来）。
#
# 刻意**不开自动重试**（`max_retries=False`）：连接错误一律 `None`，与今天一字不差。
# 陈旧 keep-alive 连接（服务端已悄悄关掉）会不会把活站报成"不可达"？实测 urllib3 2.x 在复用
# 前自己发现并新建连接，回归 `[8r] ⑤` 把这条钉住了 —— 所以不需要用重试去兜。
_POOL_CONNECTIONS = 16   # 每线程缓存多少个主机的连接池
_POOL_MAXSIZE = 16       # 每主机连接上限（一个线程同一时刻只有一个在飞请求，用不满）
_HTTP_LOCAL = threading.local()


def _http_session(verify):
    """本线程的 `requests.Session`，按 `verify` 分档缓存（见上方第 3 条）。"""
    cache = getattr(_HTTP_LOCAL, "sessions", None)
    if cache is None:
        cache = _HTTP_LOCAL.sessions = {}
    key = bool(verify)
    sess = cache.get(key)
    if sess is None:
        import requests
        import requests.adapters
        sess = requests.Session()
        adapter = requests.adapters.HTTPAdapter(pool_connections=_POOL_CONNECTIONS,
                                                pool_maxsize=_POOL_MAXSIZE,
                                                max_retries=False)
        sess.mount("http://", adapter)
        sess.mount("https://", adapter)
        cache[key] = sess
    return sess


def _do_http(url, method, headers, data, timeout, verify, allow_redirects,
             settings, want_bytes, auth):
    # `verify` 为 None 的分流在 `http_request` 入口处就解完了（见那里的注释）—— 这里拿到的
    # 一定是布尔值，不再自己读配置，避免两处判定漂移。
    hdrs = _headers(settings, headers, auth=auth)
    try:
        import requests
    except ImportError:
        return _urllib_request(url, method, hdrs, data, timeout, verify,
                               allow_redirects, want_bytes)
    sess = _http_session(verify)
    sess.cookies.clear()   # 每次请求从空 jar 出发（＝今天"每次新建 Session"的无状态语义）
    try:
        r = sess.request(method, url, headers=hdrs, data=data, timeout=timeout,
                         verify=verify, allow_redirects=allow_redirects)
    except requests.RequestException:
        return None
    finally:
        sess.cookies.clear()   # 本次响应种下的 cookie 不渗到下一条探测
    out = {"status": r.status_code, "headers": dict(r.headers),
           "text": _decode_body(r.content or b"", r.headers.get("Content-Type", "")),
           "length": len(r.content or b""), "url": r.url}
    if want_bytes:
        out["content"] = r.content or b""
    return out


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

_POOL_LOG = None          # 兜底 logger（只在调用方没传时惰性创建，见 `_pool_logger`）


def _pool_logger(logger):
    """调用方没给 logger 时的兜底：**绝不因为"没人传 logger"就退回静默**（续115）。

    进程级 logger 会写到控制台（GUI 启动时是 `logs/gui.out`），所以最坏情况是"日志不在任务文件里"，
    而不是"什么都不留"。这一层的存在理由就是本仓反复出事的那个形状：阶段里一个硬故障
    （实测：`fingerprint.identify()` 在 Python 3.14 抛 `PatternError`）被 `pool_run` 吞成 `None`，
    表现成「存活站点 0 个」，任务日志一个字都不写 —— 于是排查方向整个跑偏。
    """
    if logger is not None:
        return logger
    global _POOL_LOG
    if _POOL_LOG is None:
        from .log import get_logger
        _POOL_LOG = get_logger("scanner.pool")
    return _POOL_LOG


def pool_run(fn, items, workers=10, logger=None, label=""):
    """线程池执行；单个任务异常不影响整体，结果为 None 的丢弃。

    **返回值契约与历史完全一致**（只返回非 `None` 的结果，顺序为完成顺序）—— 各阶段的
    "0 条就按降级处理"的判定逻辑一处都不该被这次改动影响。新增的只有**说出来**这一件事：
    有异常被吞掉时写一行 WARNING（`N/M 个子任务异常：首个=<类型> <消息>`），
    否则"什么都没扫到"与"扫描器当场坏了"在日志里长得一模一样。

    `StopRequested`（用户点停止 / 预算耗尽）单独计数、按 info 说：那是**设计内的取消**，
    报成错误会把每次正常停止都刷成故障。
    """
    results = []
    items = list(items)
    if not items:
        return results
    workers = max(1, min(int(workers), len(items)))
    errs, stops = [], 0
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(fn, it): it for it in items}
        for fut in as_completed(futs):
            try:
                r = fut.result()
            except BaseException as e:       # noqa: BLE001 —— 旧行为就是"全吞"，这里只加"说出来"
                if isinstance(e, _throttle_mod.StopRequested):
                    stops += 1
                else:
                    errs.append(e)
                r = None
            if r is not None:   # 只丢"无结果"（None）；falsy 但有效的结果（0/""/[]）不该被吞
                results.append(r)
    _stop_note = (f"；另有 {stops}/{len(items)} 个因停止或预算耗尽未执行（设计内取消，不是故障）"
                  if stops else "")
    if errs:
        first = errs[0]
        _pool_logger(logger).warning(
            f"[pool] {label or '子任务'}：{len(errs)}/{len(items)} 个异常被跳过"
            f"（首个 {type(first).__name__}: {str(first)[:160]}）{_stop_note}"
            f"—— 结果可能不完整，别把「0 条」当成「确实没有」")
    elif stops and logger is not None:
        logger.info(f"[pool] {label or '子任务'}：{stops}/{len(items)} 个因停止或预算耗尽未执行")
    return results


def resolve_host(host, timeout=3):
    """域名解析，返回 IP 列表（失败返回空表）。

    `timeout` 现在**只是签名的一部分**（`stages/osint.py` 显式传 3，调用点保持稳定）。
    原来这里那句 `socket.setdefaulttimeout(timeout)` 两头都不成立（续116 移除）：
    - 管不住它想管的事 —— `socket.getaddrinfo` 是阻塞的系统调用，**不看** Python 侧的
      socket 默认超时，那句从来就没把解析限到 3 秒；
    - 却实在地改掉了**整个进程**的默认值且从不还原 —— 同一进程里别的任务线程新建的裸
      socket（portscan 的探测、certs 的 TLS 握手）会莫名其妙继承这里最后一次的 3 秒。
    真要"到点就放弃"只能把解析丢给另一个线程等它，而那种线程取消不掉
    （`concurrent.futures` 的 worker 在解释器退出时会被 join），一次挂死的解析就拖住关机 ——
    不划算，这里刻意不做。
    """
    try:
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


def tail_lines(path, n=150, chunk=64 * 1024):
    """文件**尾部** n 行 —— **有界读**：只为看最后几行，不该把整份读进内存。

    为什么不是 `read_text().splitlines()[-n:]` 一行完事：唯一的消费者是
    `gui/app.py::_tail`，而它在任务详情页被**每 2 秒轮询一次**（`/api/tasks/<id>/status`），
    一次目录深扫的日志能长到几 MB —— 整份读等于每秒把几 MB 拽进内存再扔掉 99%，
    任务跑得越久越贵（实测 4 MB 日志：整份读 12 ms/次 → 有界读 0.3 ms/次）。
    现在从文件尾按 `chunk` 一块一块往前回退，凑够 n 行就停。
    """
    if n <= 0:
        return []
    try:
        pos = Path(path).stat().st_size
        with open(path, "rb") as fh:
            buf = b""
            while pos > 0 and buf.count(b"\n") <= n:
                step = min(chunk, pos)
                pos -= step
                fh.seek(pos)
                buf = fh.read(step) + buf
    except OSError:
        return []
    lines = buf.decode("utf-8", errors="replace").splitlines()
    if pos > 0 and lines:
        # 首行可能被块边界截断（连带半个 UTF-8 字符），它不在这次读取的范围内 —— 宁丢不猜
        lines = lines[1:]
    return lines[-n:]


def write_text(path, text):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def write_lines(path, lines):
    return write_text(path, "\n".join(str(x) for x in lines) + ("\n" if lines else ""))
