"""外部工具版本管理（roadmap「工程化 → 工具版本管理：一键下载/更新 subfinder/httpx/puredns」）。

**为什么需要它**：subdomain / probe / 目录三个阶段的"上限"由外部工具决定 —— 没装
subfinder/httpx/puredns 时一律退到内置兜底（覆盖面与速度差一个量级），而 `cli --check`
只会打印"未找到（自动使用内置兜底）"，用户没有任何"把它装上"的路径。

**安全红线（改本模块前先读完整段）**：
1. **只在显式触发时联网**：CLI `--update-tools` / GUI「外部工具」页的按钮。扫描期**绝不**自动下载
   —— 任何阶段代码都不得调用本模块的 `install`/`update`（`tests/smoke.py [7p]` 用变异钉住这一条）。
2. 只允许 https，且主机必须在 `_ALLOWED_HOSTS` 内（含**跟随跳转后**的真实 URL —— GitHub 的
   release 资产会 302 到 `objects.githubusercontent.com`）。
3. **落盘前必须校验 SHA256**：比对不上**绝不落盘**。摘要有**两个产地**（结果里 `verify_source`
   区分）：① release 自带的 checksums 文件；② 本框架替某个工具**钉死**的产物摘要 `pin_sha256`
   （puredns 官方不发 checksums，走这条）。两个产地都没有时默认**拒绝**，只有显式
   `allow_unverified=True` 才继续，并在结果里如实标注"未校验"。
   **钉摘要不等于松绑**：字节仍必须与人工核过、写进本文件的那串十六进制一字不差，而且只装
   `pin_version` 那一版（tag 对不上就直接拒装 —— 新版＝新字节＝没核过）。
4. 解包**只按预期成员名取**（`ZipFile.read()` / `TarFile.extractfile()`，不用 `extractall`），
   并从根上拒绝 `..` / 绝对路径成员 —— zip slip 与 tar 路径穿越都不成立。
5. 落盘用"同目录临时文件 + `os.replace`"原子替换；任何一步失败都不留半成品（`.part` 会被删）。
6. 单产物大小上限 `_MAX_BYTES`（防超大响应打满磁盘），边收边判。
7. **绝不整份重写 config/settings.yaml**：写回走 `patch_settings_tool()` 的逐行文本替换 ——
   `config.save_settings()` 是 `yaml.safe_dump` 整份重写，会把 tools 段（以及全文件）的中文注释
   全抹掉，装个工具不该付这个代价。

**平台事实（2026-09-26 查 GitHub API 实测，不是推测）**：
- projectdiscovery/subfinder、httpx：产物 `{tool}_{ver}_{os}_{arch}.zip` + `{tool}_{ver}_checksums.txt`；
  os 标签是 `linux` / `windows` / `macOS`，arch 有 `386/amd64/arm/arm64`。
- d3mondev/puredns：产物 `puredns-{Linux|macOS}-{amd64|arm64}.tgz` —— **官方没有 Windows 产物，
  也没有 checksums 文件**。所以 Windows 上本模块会如实报"未提供当前平台产物"，**不猜、不自动编译**。
  续164 起本模块**自己替它钉住版本与四件产物的 SHA256**（见下方 TOOLS 的 `pin_version`/`pin_sha256`），
  并按**确切 tag** 取 release（不跟 latest）：上游哪天发新版，也不会把没核过的字节装进来。
- nmap / fscan / dirmap / massdns 走**手工安装**（本模块不为它们发任何请求）：逐条原因见下方 `MANUAL`，
  步骤见 `tools/scanner/README.md`「手工安装」。
"""
import hashlib
import io
import json
import os
import platform
import re
import shutil
import sys
import tarfile
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

_BASE_DIR = Path(__file__).resolve().parent.parent

# 下载落点（与 tools/scanner/README.md 的说明一致）。仓库内 → 回写成**相对路径**（项目硬规矩）。
DEFAULT_DEST = "tools/scanner"
_MAX_BYTES = 120 * 1024 * 1024
# `release-assets.githubusercontent.com` 是 GitHub release 资产**实际的跳转目标**
# （2026-09-28 实测：`/releases/download/…` 302 到它；没有它 `--update-tools` 一个
#  字节都下载不了，续54 的功能从未真正工作过）。`objects.githubusercontent.com` 保留
#  —— 旧跳转目标，防 GitHub 改回。
# 续166 为 `LOCAL_STACK`（工作目录内运行时组件）添的三个，每个都只对一件事开口：
#   `go.dev`               官方版本清单 `?mode=json`（**摘要的产地**，不是产物）
#   `dl.google.com`        Go 便携归档的实际下载主机（清单里 `url` 字段指的就是它）
#   `codeload.github.com`  `github.com/<repo>/archive/refs/tags/<tag>.tar.gz` 的 302 目标
#                          （源码包；GitHub 不为它发校验和 ⇒ 摘要由本框架钉住，见 LOCAL_STACK）
_ALLOWED_HOSTS = frozenset({"api.github.com", "github.com",
                            "objects.githubusercontent.com",
                            "release-assets.githubusercontent.com",
                            "go.dev", "dl.google.com", "codeload.github.com"})
_UA = "CTFScanner-toolmgr/0.1 (+authorized-testing-only)"

TOOLS = {
    "subfinder": {"repo": "projectdiscovery/subfinder", "style": "pd", "verify": "-version"},
    "httpx": {"repo": "projectdiscovery/httpx", "style": "pd", "verify": "-version"},
    # puredns 官方 release **不发 checksums 文件**（见文件头"平台事实"），而它在扫描路径里是
    # 真被调用的（subdomain 阶段的 DNS 爆破）—— 于是"默认必须有官方校验和"这条红线在这里只有一个
    # 后果：**永远装不上**，且把 `./install.sh` 的退出码拖成非 0（续163 在干净克隆上实测 rc=1）。
    # 出路不是"对 puredns 松手"，而是**由本框架替它核摘要并钉住**：
    #   摘要产地（2026-10-12 实测，不是从别处抄的）：https 取官方 v2.1.1 的四件产物 → 本机
    #   sha256 → 解包跑 `puredns --version` 得 `puredns version v2.1.1` 核对版本；
    #   最新 release 的 tag 也复核过仍是 v2.1.1（2023-04-11 发布，非 draft / 非 prerelease）。
    # ⚠️ 要升级它：**同时**改 `pin_version` 与 `pin_sha256`。只改一个会在下面"tag 必须等于钉住的
    #    那版"那条判据上拒装 —— 那是刻意的：新字节的摘要必须重新人工核过才配进这个文件。
    "puredns": {"repo": "d3mondev/puredns", "style": "puredns", "verify": None,
                "pin_version": "v2.1.1",
                "pin_sha256": {
                    "puredns-Linux-amd64.tgz":
                        "9f78ae91f4f58c3c3185be650c25ba38d5ef80fb092436054d17f67008a93344",
                    "puredns-Linux-arm64.tgz":
                        "d7bfc4d744af227e6cbbdb20920ea7b236ce9b86f17f69dde866e11854715272",
                    "puredns-macOS-amd64.tgz":
                        "c059a1f7ec349d939963f9864b611e8d1f0b8cab49455994e687b3005f053dde",
                    "puredns-macOS-arm64.tgz":
                        "d0f2bdf4d496aeb6b54a6277971aa6a8e697585676bc3a64d15aa4427d7988b4",
                }},
    # afrog（续119 进本模块；续121 接入 vulnscan 适配器；续149 起**默认开**）。
    #   2026-10-07 查官方 latest release（v3.5.7）实测：7 个产物 = linux / macOS / windows
    #   × amd64 / arm64 的 zip，外加 `afrog_3.5.7_checksums.txt`；命名与 projectdiscovery 同一规律
    #   （`{tool}_{ver}_{os}_{arch}.zip`，连 darwin 的官方标签都同样写作 `macOS`）⇒ 直接复用
    #   "pd" 这套挑法与 SHA256 校验，**不需要新增 style**。
    #   ⚠️ `verify: None` —— `afrog -version` 在 shell 里瞬间返回，但一旦 stdout 是**管道**
    #   （我们的 `run_cmd` / `verify_tool` 就是这么调的）它就**永不退出**、且不吐一个字节。
    #   所以不给握手参数，并在 `status()` 里跳过探测，页面上只报"已装 / 未装"。
    #   ⚠️ `fallback: False`：**没有内置兜底**。它缺了就是"本轮不跑外部引擎"，本就如此。
    #   续149 修正了一处**过期标记**：旧版写 `wired: False` + 一句"vulnscan 适配器还没写"，
    #   但续121 已把适配器接进 `scanner/stages/vulnscan.py` ⇒ 那面旗子是错的（会谎称"框架尚未
    #   调用它"、还会把它挡在 `--install` 自动层之外）。现在 `wired` 为真（确实会被调用），
    #   同时用 `fallback: False` 把"没内置兜底"这件事**单独说清** —— 两个语义各归各位。
    "afrog": {"repo": "zan8in/afrog", "style": "pd", "verify": None, "fallback": False},
}


# ---------- 摘要的两个产地（`verify_source`）与"校验"文案的单一产地 ----------
# CLI、GUI「外部工具」页、run_bootstrap 打印校验状态一律调 `verified_label()`；
# 页面顶部那句"落盘前必须过什么"调 `verify_policy()`。判据只这一处 —— 在文案里抄一份
# 版本/摘要来源，就是 AGENTS §5.19 说的那类会漂的成句（本项目被它绊过四次）。
VERIFY_RELEASE = "release"      # 官方 release 自带的 checksums 文件
VERIFY_PINNED = "pinned"        # 本框架人工核过并钉进 TOOLS 的产物摘要（`pin_sha256`）
_VERIFY_LABEL = {VERIFY_RELEASE: "SHA256 已校验（官方 checksums）",
                 VERIFY_PINNED: "SHA256 已校验（本框架钉住的产物摘要）"}
# 失败原因里要说的是**摘要从哪儿来**（人要照着它去核对），不是那两行结果标签 —— 长得像，
# 但抄成同一串会写成「摘要来自SHA256 已校验（…）」这种读不通的句子（本轮实测撞过一次）。
_VERIFY_SRC = {VERIFY_RELEASE: "官方 release 自带的 checksums 文件",
               VERIFY_PINNED: "scanner/toolmgr.py 里本框架钉住的产物摘要"}


def pin(tool):
    """该工具钉住的 `(版本, {产物名: SHA256})`；没钉 → `("", {})`。"""
    cfg = TOOLS.get(tool) or {}
    return str(cfg.get("pin_version") or ""), dict(cfg.get("pin_sha256") or {})


def verified_label(res):
    """一次安装结果里"校验"那一格该印的话。

    `verified` 是三态：`None`（没走到校验，比如失败/跳过）→ 返回 `""`，调用方自己决定占位；
    `False`（显式允许的未校验安装）→ 如实说"未校验"；`True` → 按 `verify_source` 说清算的是哪一份摘要。
    """
    v = res.get("verified")
    if v is None:
        return ""
    if v is not True:
        return "未校验（按你的显式要求）"
    return _VERIFY_LABEL.get(res.get("verify_source") or VERIFY_RELEASE, "SHA256 已校验")


def verify_policy():
    """「装之前必须过什么」这句**现取**自 TOOLS：新增或去掉一个钉摘要的工具，文案自己跟着变。"""
    pinned = sorted(t for t in TOOLS if pin(t)[0])
    plain = sorted(t for t in TOOLS if not pin(t)[0])
    parts = ["落盘前必须过 SHA256，比对不过一律拒绝落盘、也不覆盖已装好的："]
    if plain:
        parts.append(f"{'、'.join(plain)} 用官方 release 自带的 checksums 文件；")
    if pinned:
        parts.append("、".join(f"{t}（钉在 {pin(t)[0]}）" for t in pinned)
                     + " 官方不发 checksums，改用本框架人工核过并写进 scanner/toolmgr.py 的产物摘要；")
    parts.append("两个来源都没有时默认拒绝安装（要装得显式允许「未校验」，界面如实标注）。")
    return "".join(parts)


def wired(name):
    """这个工具**是否真的被扫描路径调用**（没标 = 是）。

    与"能自动下载"是两件事：混成一个就会出现"表里列着、页面说会自动兜底、实际谁都不调用"。
    自动安装层与 GUI 文案都按这一档走，`[8x]` 钉住。
    """
    return bool(TOOLS.get(name, {}).get("wired", True))


def fallback(name):
    """没装这个工具时，框架是否有**内置实现**兜底（默认有；afrog 这类外部引擎没有）。

    与 `wired()` 正交：`wired=True` 只说"装了会被调用"，**不**蕴含"没装也照跑"。
    afrog 缺了就是"本轮不跑外部引擎"（内置 POC 引擎照常，但那不是 afrog 的兜底）。
    文案层据此分档，避免把"没有兜底"说成"自动使用内置兜底"（那正是 [8x] 当初要拦的假话）。
    """
    return bool(TOOLS.get(name, {}).get("fallback", True))

#  「需手工安装」的工具 —— **刻意不进 `TOOLS`**：`TOOLS` 的语义是"能自动下载、且默认必须过
#  release 自带的 SHA256 校验才落盘"。这几项都不满足（nmap/fscan/dirmap 2026-09-27 实测；massdns 2026-10-13 实测官方 release 的`assets` 是空数组）：
#    - nmap   官方发布在 nmap.org/dist（**不在** GitHub release，本模块的 fetch_release 够不着）；
#             Windows 只发 NSIS 安装器 `nmap-7.991-setup.exe`（是"装到 Program Files"的系统级动作，
#             不是"解包取一个可执行文件"）；Linux 只发源码包（要编译）；macOS 只发 .dmg（要挂载）。
#             校验值是有的，但在 `sigs/<文件名>.digest.txt`（URL 模式与本模块的 "checksums" 不同）。
#    - fscan  官方不发二进制，本仓的既定做法是用 Go 从源码自编译（见 tools/scanner/README.md）。
#    - dirmap 最新 release 的 `assets` 是**空数组**（零二进制、零 checksums）；且它是纯 Python 项目
#             （要 `pip install` 依赖），不是单二进制 —— `extract_binary()` 的模型套不上。
#  之所以**写出来**而不是"眼不见为净"：GUI「外部工具」页若只列 `TOOLS`，会让人以为
#  "没列出来的框架不管"，而 `cli --check` 里它们又都是"未找到（自动使用内置兜底）"。
#  这几条只做**如实展示 + 指向 README 的手工步骤**，本模块不会为它们发任何请求。
MANUAL = {
    "nmap": "官方只发安装器 / 源码包 / dmg（无便携 zip），自动装会变成系统级安装"
            "（可交给包管理器：./install.sh --with-system --yes）",
    "fscan": "官方不发二进制，需用 Go 从源码自编译（本仓为避免 Defender 拦截的既定做法）"
             "（已提供自动化编译：./install.sh --full，或 python tools/build_fscan.py --fetch --wire"
             " —— 缺 Go / 缺源码就自己取进仓库、过 SHA256，缓存落 .cache/ 不写家目录）",
    "dirmap": "release 零产物、无 checksums，且是纯 Python 项目（需 pip 依赖）",
    "massdns": "官方只发 C 源码（make 出 bin/massdns），无带官方校验和的单二进制——"
               "而 puredns 的 bruteforce/resolve 会在进程内 exec 它，缺它 puredns 每个域名都退码 1"
               "（已提供自动化编译：./install.sh --full，或 python tools/build_massdns.py --fetch --wire"
               " —— 源码按确切 tag 取进仓库；**仍需本机 gcc/make**，C 工具链没有便携替代品）",
}


# ---------- 平台 / 命名 ----------

def host_arch():
    """返回官方产物命名用的 `(os_label, arch)`；认不出的平台如实返回 `("unknown", ...)`。

    刻意**不猜**：宁可让上层报"未提供当前平台产物"，也不要拿一个错的产物去覆盖现有二进制。
    """
    plat = sys.platform
    if plat.startswith("win"):
        os_label = "windows"
    elif plat.startswith("linux"):
        os_label = "linux"
    elif plat.startswith("darwin"):
        os_label = "macOS"
    else:
        return "unknown", "unknown"
    machine = (platform.machine() or "").lower()
    arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64",
            "i386": "386", "i686": "386", "x86": "386", "armv7l": "arm"}.get(machine, machine)
    return os_label, (arch or "unknown")


def binary_name(tool):
    """本平台上的可执行文件名（Windows 要 `.exe`）。"""
    return f"{tool}.exe" if os.name == "nt" else tool


def asset_name(tool, version, os_label=None, arch=None):
    """按官方命名规则算出该下载哪个产物；该平台没有产物时返回 `None`（**不回落、不猜**）。"""
    cfg = TOOLS.get(tool)
    if not cfg:
        return None
    os_label = os_label or host_arch()[0]
    arch = arch or host_arch()[1]
    ver = str(version or "").lstrip("vV")
    if not ver:
        return None
    if cfg["style"] == "pd":
        if os_label not in ("linux", "windows", "macOS"):
            return None
        if arch not in ("386", "amd64", "arm", "arm64"):
            return None
        return f"{tool}_{ver}_{os_label}_{arch}.zip"
    if cfg["style"] == "puredns":
        # 官方只出 Linux/macOS（见文件头"平台事实"）
        if os_label not in ("linux", "macOS") or arch not in ("amd64", "arm64"):
            return None
        return f"puredns-{'Linux' if os_label == 'linux' else 'macOS'}-{arch}.tgz"
    return None


def checksum_asset(assets, version=""):
    """release 里那份校验和文件的**名字**（找不到返回 `None` —— 不猜、不编 URL）。"""
    ver = str(version or "").lstrip("vV")
    for name in assets:
        low = name.lower()
        if "checksums" in low and (not ver or ver in low):
            return name
    for name in assets:                     # 退一步：只要是 checksum(s) 就认（少数 release 不带版本号）
        if "checksum" in name.lower():
            return name
    return None


def parse_checksums(text):
    """解析 `sha256sum` 风格文本 → `{文件名: 十六进制摘要}`（大小写与 `*` 前缀都归一）。"""
    out = {}
    for line in (text or "").splitlines():
        parts = line.strip().split()
        if len(parts) < 2:
            continue
        digest, name = parts[0].strip().lower(), parts[-1].lstrip("*").strip()
        if re.fullmatch(r"[0-9a-f]{64}", digest) and name:
            out[name] = digest
    return out


# ---------- 网络（**唯一的两个出口**，测试桩掉这两个即可全离线） ----------

def _check_url(url):
    """只放行 https + 白名单主机；返回解析后的 host（供调用方二次校验跳转目标）。"""
    p = urllib.parse.urlsplit(str(url))
    if p.scheme != "https":
        raise ValueError(f"只允许 https：{url}")
    host = (p.hostname or "").lower()
    if host not in _ALLOWED_HOSTS:
        raise ValueError(f"主机不在白名单内：{host}")
    return host


def download_bytes(url, timeout=120, max_bytes=_MAX_BYTES):
    """受限下载：https + 白名单主机（跳转后也校验）+ 大小上限。返回 `bytes`。

    ⚠️ 这是本模块**唯一**的下载实现（`fetch_release` 也走它），测试只需桩掉它就能全离线。
    """
    _check_url(url)
    req = urllib.request.Request(url, headers={"User-Agent": _UA, "Accept": "*/*"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        # 跳转后的真实 URL 必须**再校验一次**：否则白名单可被一个 302 绕过。
        _check_url(resp.geturl())
        buf = io.BytesIO()
        while True:
            chunk = resp.read(65536)
            if not chunk:
                break
            buf.write(chunk)
            if buf.tell() > max_bytes:
                raise ValueError(f"响应超过上限 {max_bytes // (1024 * 1024)} MB，已中止")
        return buf.getvalue()


def fetch_release(repo, timeout=30, tag=""):
    """查 release → `{"tag": "v1.2.3", "assets": {名字: 下载URL}}`。

    `tag` 给了就按**确切版本**取（`/releases/tags/<tag>`，钉了摘要的工具走这条），不给才看 latest。
    为什么要按 tag：只认 latest 的话，"上游一发新版 → 本框架没有那一版的摘要 → 装不上 → 安装脚本
    非 0"迟早复发；按 tag 取则装的就是当年核过摘要的那份字节。

    用**公开 API 且不传任何凭据**：只读、无副作用；未认证的 60 次/小时对"偶尔装个工具"绰绰有余
    （与本项目 github_leak 阶段"不把登录态发出去"的口径一致）。
    """
    _t = str(tag or "").strip()
    url = (f"https://api.github.com/repos/{repo}/releases/tags/{_t}" if _t
           else f"https://api.github.com/repos/{repo}/releases/latest")
    data = json.loads(download_bytes(url, timeout=timeout, max_bytes=4 * 1024 * 1024)
                      .decode("utf-8", "replace"))
    assets = {}
    for a in (data.get("assets") or []):
        if a.get("name") and a.get("browser_download_url"):
            assets[str(a["name"])] = str(a["browser_download_url"])
    return {"tag": str(data.get("tag_name") or ""), "assets": assets}


def _release_for(tool, fetch=None, timeout=120):
    """这个工具**该看哪一个 release**：钉了版本按 tag 精确取，没钉才看 latest。

    判据只这一处（`install` 自己联网时、`update` 用注入的 `fetch` 时都走它）—— 两处各写一遍
    "有没有 pin_version"迟早漂。
    ⚠️ 注入口径：`fetch` **必须接受 `tag=` 关键字**（`fetch_release` 接受）。桩少了这个形参，
    TypeError 会被调用方兜成"查询最新版本失败"并**如实上报**，不会退回去误装别的版本。
    刻意**不做**签名探测：本模块自己就有一个 `inspect()` 函数，`import inspect` 会被它整名遮蔽
    （实测 AttributeError），少写一个形参换来那种坑不值。
    """
    fetch = fetch or fetch_release
    repo = TOOLS[tool]["repo"]
    pinned = pin(tool)[0]
    if not pinned:
        return fetch(repo, timeout=timeout)
    return fetch(repo, timeout=timeout, tag=pinned)


# ---------- 解包 ----------

def _safe_member_name(name):
    """成员名安全校验：拒绝绝对路径与 `..`（即便我们只 `open` 不 `extractall`，也**从根上拒绝**）。"""
    n = str(name or "").replace("\\", "/")
    if n.startswith("/") or re.match(r"^[A-Za-z]:", n):
        return False
    return not any(part == ".." for part in n.split("/"))


def extract_binary(blob, asset, want):
    """从 zip/tgz 里取出名为 `want` 的可执行文件字节；找不到或成员名不安全 → `ValueError`。"""
    if asset.lower().endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            for info in zf.infolist():
                if not _safe_member_name(info.filename):
                    raise ValueError(f"压缩包成员名不安全（拒绝）：{info.filename}")
                if info.is_dir() or Path(info.filename).name != want:
                    continue
                return zf.read(info)
        raise ValueError(f"压缩包里没有 {want}")
    if asset.lower().endswith((".tgz", ".tar.gz")):
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
            for m in tf.getmembers():
                if not _safe_member_name(m.name):
                    raise ValueError(f"归档成员名不安全（拒绝）：{m.name}")
                if not m.isfile() or Path(m.name).name != want:
                    continue
                f = tf.extractfile(m)
                if f is None:
                    continue
                return f.read()
        raise ValueError(f"归档里没有 {want}")
    raise ValueError(f"未支持的归档类型：{asset}")


# ---------- 安装 ----------

def _setting_value(dest_file):
    """落盘路径 → 写进 settings.yaml 的值：仓库内用**相对路径**（项目硬规矩），仓库外才用绝对路径。"""
    try:
        return Path(dest_file).resolve().relative_to(_BASE_DIR).as_posix()
    except ValueError:
        return str(Path(dest_file).resolve())


def inspect(tool, os_label=None, arch=None):
    """只看"当前平台该下哪个产物"（**不联网**）：`{asset, checksums, binary, reason}`。

    `asset is None` 即"官方未提供当前平台产物"，`reason` 说明原因 —— GUI/CLI 都据此如实展示。
    """
    os_label = os_label or host_arch()[0]
    arch = arch or host_arch()[1]
    name = binary_name(tool)
    if tool not in TOOLS:
        return {"asset": None, "checksums": None, "binary": name,
                "reason": f"不支持的工具（可选：{'、'.join(TOOLS)}）"}
    # 版本号未知时先按命名规则留空：真正的产物名要等 release 拿到 tag 才能定（见 install）
    if os_label == "unknown" or arch == "unknown":
        return {"asset": None, "checksums": None, "binary": name,
                "reason": f"无法识别平台（{sys.platform}/{platform.machine()}）"}
    if TOOLS[tool]["style"] == "puredns" and os_label not in ("linux", "macOS"):
        return {"asset": None, "checksums": None, "binary": name,
                "reason": f"puredns 官方只发布 Linux / macOS 产物，没有 {os_label} 版本"
                          "（可用内置 DNS 爆破兜底，或自行 go install）"}
    if TOOLS[tool]["style"] == "pd" and arch not in ("386", "amd64", "arm", "arm64"):
        return {"asset": None, "checksums": None, "binary": name,
                "reason": f"官方未提供 {os_label}/{arch} 产物"}
    return {"asset": "(随版本号确定)", "checksums": None, "binary": name, "reason": ""}


def install(tool, dest_dir=None, allow_unverified=False, timeout=120, wire=True,
            settings_path=None, release=None, blob=None):
    """下载并安装单个工具，返回结果字典（**永不抛异常**，失败走 `ok=False` + `reason`）。

    `release` / `blob` 是给测试用的注入口（不传就真的联网）；`dest_dir` 默认 `tools/scanner/`。
    `wire=True` 时把 `tools.<name>` 写成刚装好的可执行文件路径 —— 否则"装了也用不上"
    （`which()` 只认 PATH 与配置里的相对路径）。
    """
    out = {"tool": tool, "ok": False, "version": "", "path": "", "verified": None, "reason": ""}
    if tool not in TOOLS:
        out["reason"] = f"不支持的工具（可选：{'、'.join(TOOLS)}）"
        return out
    os_label, arch = host_arch()
    pre = inspect(tool, os_label, arch)
    if pre["asset"] is None:
        out["reason"] = pre["reason"]
        return out
    pinned, pinmap = pin(tool)
    try:
        rel = release if release is not None else _release_for(tool, timeout=timeout)
    except Exception as e:                                   # 网络/解析失败一律如实报，不猜
        out["reason"] = f"查询最新版本失败：{e}"
        return out
    tag, assets = rel.get("tag") or "", rel.get("assets") or {}
    out["version"] = tag
    if pinned and tag != pinned:
        # 钉了版本却拿到别的版本＝那批字节没被人工核过。这里**不做**"只要官方 checksums 对得上
        # 也算"的变通：认钉住的版本就是认它的**摘要**，中途把口径换成官方文件等于没钉。
        out["reason"] = (f"本框架把 {tool} 钉在 {pinned}（产物摘要人工核过、写进 scanner/toolmgr.py），"
                         f"这次拿到的是 {tag or '没有版本号'} —— 拒绝安装"
                         "（升级请核过新版产物摘要后**同时**改 pin_version 与 pin_sha256）")
        return out
    want_asset = asset_name(tool, tag, os_label, arch)
    if not want_asset or want_asset not in assets:
        out["reason"] = (f"{tag or '最新版'} 未提供 {os_label}/{arch} 产物"
                         f"（release 里有：{'、'.join(sorted(assets)[:6])}…）")
        return out
    csum_name = checksum_asset(assets, tag)
    want_digest, verify_src = None, ""
    if csum_name:
        try:
            if blob is not None and csum_name in (blob or {}):
                text = blob[csum_name].decode("utf-8", "replace")
            else:
                text = download_bytes(assets[csum_name], timeout=timeout,
                                      max_bytes=2 * 1024 * 1024).decode("utf-8", "replace")
        except Exception as e:
            out["reason"] = f"下载校验和失败：{e}"
            return out
        want_digest = parse_checksums(text).get(want_asset)
        if not want_digest:
            out["reason"] = f"校验和文件 {csum_name} 里没有 {want_asset} 的条目（拒绝落盘）"
            return out
        verify_src = VERIFY_RELEASE
    elif want_asset in pinmap:
        # 官方不发 checksums，但本框架**替这一版这一个产物**钉了摘要：校验强度一个字没降，
        # 只是摘要的产地从"release 里的文件"换成"本文件里那串十六进制"（怎么核的见 TOOLS 注释）。
        want_digest, verify_src = str(pinmap[want_asset]).strip().lower(), VERIFY_PINNED
    elif not allow_unverified:
        out["reason"] = (f"{tag or '最新版'} 未发布校验和文件"
                         + (f"，而 {want_asset} 也不在本框架钉住的摘要里" if pinned else "")
                         + "；默认拒绝安装（确要安装请显式允许未校验安装）")
        return out
    try:
        data = (blob[want_asset] if blob is not None and want_asset in (blob or {})
                else download_bytes(assets[want_asset], timeout=timeout))
    except Exception as e:
        out["reason"] = f"下载 {want_asset} 失败：{e}"
        return out
    if want_digest:
        got = hashlib.sha256(data).hexdigest()
        if got != want_digest:
            out["reason"] = (f"SHA256 校验不符（期望 {want_digest[:16]}…，实得 {got[:16]}…，"
                             "期望值来自" + _VERIFY_SRC.get(verify_src, "未知产地")
                             + "）—— 拒绝落盘；摘要对不上通常是产物被换过或平台挑错了包，"
                             "不是重试能解决的事")
            return out
        out["verified"] = True
        out["verify_source"] = verify_src
    else:
        out["verified"] = False        # 显式允许的未校验安装（不是 True，页面要如实显示）
        out["verify_source"] = ""
    binary = binary_name(tool)
    try:
        payload = extract_binary(data, want_asset, binary)
    except Exception as e:
        out["reason"] = f"解包失败：{e}"
        return out
    dest = Path(dest_dir) if dest_dir else (_BASE_DIR / DEFAULT_DEST)
    tmp = dest / (binary + ".part")
    target = dest / binary
    try:
        dest.mkdir(parents=True, exist_ok=True)
        # 续86：装新的之前把**当前版本**留一份备份（`<名>.bak`），供 `rollback()` 回滚。
        # 备份失败**不阻断安装**（安装是主诉求），但如实记进结果（页面可据此说明"不可回滚"）。
        if target.exists():
            try:
                (dest / (binary + ".bak")).write_bytes(target.read_bytes())
                out["backed_up"] = True
            except Exception:
                out["backed_up"] = False
            # 续94：把**将被替换掉的这一份**也存进版本库（多版本共存）。
            # 问不出它的版本号就**不归档**（不编造 unknown 目录）；失败一律不阻断安装。
            try:
                _a = archive_version(tool, dest_dir=dest_dir, src=target)
                out["archived_previous"] = _a.get("version") or ""
            except Exception:                                # noqa: BLE001
                out["archived_previous"] = ""
        tmp.write_bytes(payload)
        if os.name != "nt":
            os.chmod(tmp, 0o755)
        os.replace(tmp, target)                 # 原子替换：要么旧的、要么完整的新的
        # 续94：把**刚装好的这一份**按 release tag 存进版本库 —— tag 是确切知道的，
        # 不必去问二进制（问不出来也不影响这一步）。失败同样不阻断安装。
        try:
            _a2 = archive_version(tool, dest_dir=dest_dir, version=tag, src=target,
                                  protect={_version_key(tag)})
            out["archived"] = _a2.get("version") or ""
            if _a2.get("pruned"):
                out["versions_pruned"] = _a2["pruned"]
        except Exception:                                    # noqa: BLE001
            out["archived"] = ""
    except Exception as e:
        try:
            tmp.unlink()
        except OSError:
            pass
        out["reason"] = f"落盘失败：{e}"
        return out
    out["ok"] = True
    out["path"] = _setting_value(dest / binary)
    if wire:
        ok, note = patch_settings_tool(tool, out["path"], path=settings_path)
        out["wired"] = ok
        if not ok:
            out["reason"] = (f"已安装到 {out['path']}，但写回 config/settings.yaml 失败：{note}"
                             "（请手动把 tools.%s 填成该路径）" % tool)
    return out


def backup_path(tool, dest_dir=None):
    """工具备份文件路径（`<可执行名>.bak`）；`install()` 替换前会写它（续86）。"""
    dest = Path(dest_dir) if dest_dir else (_BASE_DIR / DEFAULT_DEST)
    return dest / (binary_name(tool) + ".bak")


def can_rollback(tool, dest_dir=None):
    """该工具是否有可回滚的备份（GUI 据此决定要不要显示「回滚」按钮）。"""
    return tool in TOOLS and backup_path(tool, dest_dir).exists()


def rollback(tool, dest_dir=None, wire=True, settings_path=None):
    """把工具回滚到**上一次安装前**的版本（续86），返回结果字典（**永不抛异常**）。

    `install()` 在原子替换前会把旧二进制另存为 `<名>.bak`；本函数把当前版与备份**对调** ——
    所以再点一次就换回去（回滚是**可逆**的，不是"一次性的撤销"）。
    没有备份（从未装过 / 首次安装 / 备份时失败）→ `ok=False` + 原因。
    """
    out = {"tool": tool, "ok": False, "path": "", "reason": ""}
    if tool not in TOOLS:
        out["reason"] = f"不支持的工具（可选：{'、'.join(TOOLS)}）"
        return out
    binary = binary_name(tool)
    dest = Path(dest_dir) if dest_dir else (_BASE_DIR / DEFAULT_DEST)
    target = dest / binary
    bak = backup_path(tool, dest_dir)          # 单一来源：与 can_rollback 同一处
    if not bak.exists():
        out["reason"] = "没有可回滚的备份（只保留**上一次**安装前的版本）"
        return out
    if not target.exists():
        out["reason"] = "当前没有已安装的可执行文件（只有备份）"
        return out
    try:
        # 三步对调（每步都是同目录内的原子 rename）：cur → .swap、bak → cur、.swap → bak
        swap = dest / (binary + ".swap")
        os.replace(target, swap)
        os.replace(bak, target)
        os.replace(swap, bak)
        if os.name != "nt":
            os.chmod(target, 0o755)
    except Exception as e:
        out["reason"] = f"回滚失败：{e}"
        return out
    out["ok"] = True
    out["path"] = _setting_value(target)
    if wire:
        ok, note = patch_settings_tool(tool, out["path"], path=settings_path)
        out["wired"] = ok
        if not ok:
            out["reason"] = f"已回滚到 {out['path']}，但写回 config/settings.yaml 失败：{note}"
    return out


def _installed_banner(name, settings):
    """问本机已装的这个工具报的版本横幅（没有握手参数 / 未装 / 问不出 → `""`）。

    只给"先查最新、已最新就跳过"（`update(only_if_newer=True)`）用；afrog 没有握手参数（它在
    管道下不退出）⇒ 一律返回空，于是它永远不会被这条判据跳过（照旧每次重装，宁可多下一次）。
    """
    from .utils import which, run_cmd
    cfg = TOOLS.get(name) or {}
    if not cfg.get("verify"):
        return ""
    configured = str(((settings or {}).get("tools", {}) or {}).get(name, name) or name)
    path = which(configured)
    if not path:
        return ""
    try:
        _rc, out, err = run_cmd([path, cfg["verify"]], timeout=30)
    except Exception:                                        # noqa: BLE001 - 探测失败不算错误
        return ""
    first = ((out or "") + (err or "")).strip().splitlines()
    return first[0][:80] if first else ""


def update(tools=None, dest_dir=None, allow_unverified=False, wire=True, settings_path=None,
           timeout=120, fetch=fetch_release, blobs=None, only_if_newer=False, settings=None):
    """按顺序装/更新若干工具，返回结果列表。**只由显式入口调用**（CLI / GUI 按钮）。

    `fetch` 与 `blobs` 是给测试的注入口：`fetch` 换掉"查哪个 release"（**必须接受 `tag=` 关键字
    形参**，钉了版本的工具会带 tag 调用，见 `_release_for`），`blobs` 是 `{工具名: {资产名: bytes}}`
    —— 传了就完全不联网（`install` 优先用 blob）。

    `only_if_newer=True`（续149，GUI/CLI 显式开，默认关＝保持既有"总是重装"语义）：先用
    `check_updates` 同一套办法问本机版本，**已是最新就跳过**（结果里 `skipped=True`、
    `reason="已是最新（…）"`），省掉一次无谓的下载。装都没装的照常装。
    """
    names = [t for t in (tools or list(TOOLS)) if t]
    results = []
    for name in names:
        rel = None
        try:
            rel = _release_for(name, fetch, timeout) if name in TOOLS else None
        except Exception as e:
            results.append({"tool": name, "ok": False, "version": "", "path": "",
                            "verified": None, "reason": f"查询最新版本失败：{e}"})
            continue
        if only_if_newer and name in TOOLS and blobs is None:
            tag = str((rel or {}).get("tag") or "")
            inst = _installed_banner(name, settings or {})
            if inst and tag and not newer_version(tag, inst):
                results.append({"tool": name, "ok": True, "version": inst, "path": "",
                                "verified": None, "skipped": True,
                                "reason": f"已是最新（{inst}），无需更新"})
                continue
        results.append(install(name, dest_dir=dest_dir, allow_unverified=allow_unverified,
                               timeout=timeout, wire=wire, settings_path=settings_path,
                               release=rel, blob=(blobs or {}).get(name)))
    return results


# ---------- 回写 settings.yaml（**逐行文本替换，保住注释**） ----------

def patch_settings_tool(name, value, path=None):
    """把 `config/settings.yaml` 里 `tools.<name>` 的值改成 `value`；返回 `(ok, note)`。

    **为什么不复用 `config.save_settings()`**：那个实现是 `load_settings()` + `yaml.safe_dump`
    **整份重写** —— 会把 tools 段那一大段中文注释（以及全文件所有注释）一次抹掉。
    装工具是"改一个键"，不该有这种副作用，所以这里做**定点文本替换**：
    只在顶层 `tools:` 段内找 `  <name>: ...` 那一行替换；没有就插在 `tools:` 下一行。
    行尾符**沿用文件原有形态**（本仓 settings.yaml 实测是 CRLF，但这里不硬编码，
    而是探测首处换行 —— 迁移到别处也不会把整个文件的行尾搅乱）。
    """
    p = Path(path) if path else (_BASE_DIR / "config" / "settings.yaml")
    if not p.exists():
        return False, "config/settings.yaml 不存在（请手动把 tools.%s 填成该路径）" % name
    val = str(value or "").strip()
    if not val or "\n" in val or "\r" in val:
        return False, "值非法（空或含换行）"
    if p.read_bytes().find(b"\r\n") >= 0:
        eol = b"\r\n"
    else:
        eol = b"\n"
    raw = p.read_bytes()
    had_trailing = raw.endswith(b"\n")
    lines = raw.decode("utf-8").splitlines()
    start = next((i for i, ln in enumerate(lines)
                  if ln.startswith("tools:")), None)
    if start is None:
        return False, "settings.yaml 里没有顶层 tools: 段"
    end = len(lines)
    for j in range(start + 1, len(lines)):
        ln = lines[j]
        if ln and not ln[0].isspace() and not ln.lstrip().startswith("#"):
            end = j
            break
    pat = re.compile(r"^(\s+)" + re.escape(name) + r":(\s*)(.*)$")
    done = False
    for k in range(start + 1, end):
        m = pat.match(lines[k])
        if not m:
            continue
        comment = ""
        cur = m.group(3)
        idx = cur.find("#")
        if idx > 0:
            comment = "  " + cur[idx:]
        lines[k] = f"{m.group(1)}{name}: {val}{comment}"
        done = True
        break
    if not done:
        lines.insert(start + 1, f"  {name}: {val}")
    data = eol.join(ln.encode("utf-8") for ln in lines)
    if had_trailing:
        data += eol
    p.write_bytes(data)
    return True, ""


# ---------- 状态展示 ----------

def status(settings):
    """逐个列出 `TOOLS` 成员的当前状态（供 GUI/CLI 展示）：配置值 / 解析路径 / 版本 / 平台可用性。

    文案按**两个正交的档**组合（续149）：
      · `wired()`  —— 装了会不会被扫描路径调用；没接线的说"只在显式启用后被调用"。
      · `fallback()` —— 没装时框架有没有**内置实现**兜底；没有的（afrog）不许说"自动使用内置兜底"。
    """
    from .utils import which, run_cmd
    tools_cfg = (settings or {}).get("tools", {}) or {}
    rows = []
    for name, cfg in TOOLS.items():
        configured = str(tools_cfg.get(name, name) or name)
        path = which(configured)
        version = ""
        if path and cfg.get("verify"):
            # 8 秒（原先 30）：这是**打开「外部工具」页时同步等的**，一次版本横幅不需要半分钟；
            # 而"工具存在但一被管道捕获就不退出"这类情况实测有（afrog），30 秒会把整页钉住。
            rc, out, err = run_cmd([path, cfg["verify"]], timeout=8)
            if rc == 0:
                first = ((out or "") + (err or "")).strip().splitlines()
                version = first[0][:80] if first else "OK"
        pre = inspect(name)
        _wired = wired(name)
        if path:
            note = f"OK（{path}）" + ("" if _wired else "｜已装，但只在显式启用后被调用")
        elif not _wired:
            note = "未装（需在策略配置里显式启用；只纳入可下载/可校验管理）"
        elif fallback(name):
            note = "未找到（自动使用内置兜底）"
        else:
            # afrog 这类外部引擎**没有**内置替代：缺了就是"本轮不跑它"，不能说成有兜底。
            note = "未找到（不装则本轮不跑该外部引擎；本框架内置引擎不受影响）"
        rows.append({"tool": name, "configured": configured, "path": path or "",
                     "version": version, "asset": pre["asset"] or "",
                     "pinned": pin(name)[0],
                     "reason": pre["reason"], "wired": _wired, "note": note})
    return rows


# ---------- 「有新版本」提示（续87） ----------

_VER_RE = re.compile(r"v?(\d+)\.(\d+)\.(\d+)")


def _ver_tuple(text):
    """从任意文本里抠出 `(major, minor, patch)`（抠不到返回 None —— **不猜**）。"""
    m = _VER_RE.search(str(text or ""))
    return tuple(int(x) for x in m.groups()) if m else None


def newer_version(latest, installed):
    """`latest` 是否比 `installed` **新**（按 major.minor.patch 比大小）。

    任一侧抠不到版本号 → 一律 `False`：**宁可漏报"有新版本"，也不误报**（误报会让人白跑一次下载）。
    """
    a, b = _ver_tuple(latest), _ver_tuple(installed)
    return bool(a and b and a > b)


# ---------------- 多版本共存（续94） ----------------
#
# `rollback()` 只能退**一步**（单个 `<名>.bak` 槽位）。这里再加一层**版本库**：
# `<安装目录>/.versions/<工具>/<版本>/<可执行名>` —— 装/切换时把**将要被替换掉的那一份**
# 存进去，于是可以在多个版本之间来回切（`use_version()`），而不是只有"上一版"。
#
# 口径（与 rollback 同源，"宁可少做也不乱做"）：
# - 版本号**只从二进制自己嘴里问**（`<binary> -version`）；问不出来就**不归档** ——
#   绝不编一个 `unknown` 目录出来攒垃圾。
# - 目录名用归一后的 `major.minor.patch`，同版本重复归档＝覆盖（幂等）。
# - 切版本前先把**当前**这一份归档 + 写 `<名>.bak`，所以 `use_version()` 也是**可逆**的。
# - 版本库有上限（`VERSIONS_KEEP`），超出的**删掉并在返回值里如实上报** —— 不静默删。

VERSIONS_DIRNAME = ".versions"
VERSIONS_KEEP = 5      # 每个工具最多留几个历史版本（按版本号从旧到新删，删了什么会如实报出）


def versions_dir(tool, dest_dir=None):
    """版本库根目录：`<安装目录>/.versions/<工具>/`。"""
    dest = Path(dest_dir) if dest_dir else (_BASE_DIR / DEFAULT_DEST)
    return dest / VERSIONS_DIRNAME / str(tool)


def _version_key(text):
    """任意版本文本 → `major.minor.patch`；抠不到 → `""`（**不猜**）。"""
    t = _ver_tuple(text)
    return ".".join(str(x) for x in t) if t else ""


def detect_version(tool, path):
    """跑一次 `<binary> -version` 问版本，返回归一后的版本键（问不出来 → `""`）。"""
    flag = (TOOLS.get(tool) or {}).get("verify")
    if not flag or not path:
        return ""
    try:
        from .utils import run_cmd
        _rc, out, err = run_cmd([str(path), str(flag)], timeout=30)
    except Exception:                                        # noqa: BLE001 - 探测失败不是错误
        return ""
    for line in ((out or "") + "\n" + (err or "")).splitlines():
        key = _version_key(line)
        if key:
            return key
    return ""


def _sha256_file(path):
    """整份文件的 sha256（读不到 → `""`）。用于判定"版本库里哪一份＝当前在用的那一份"。"""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


def prune_versions(tool, keep=VERSIONS_KEEP, dest_dir=None, protect=()):
    """版本库只保留**版本号最大的 `keep` 个**（外加 `protect` 里的），返回被删掉的版本键。

    **不静默删**：删了什么原样返回，调用方负责报给用户。
    """
    root = versions_dir(tool, dest_dir)
    if not root.is_dir():
        return []
    keepset = {str(x) for x in (protect or ())}
    entries = [( _ver_tuple(d.name), d.name) for d in root.iterdir() if d.is_dir()]
    parseable = sorted([e for e in entries if e[0]], key=lambda x: x[0])
    keep_names = {n for _t, n in parseable[-int(keep):]} | keepset
    removed = []
    for _t, name in entries:
        if name in keep_names:
            continue
        try:
            shutil.rmtree(root / name)
        except OSError:
            continue
        removed.append(name)
    return sorted(removed)


def archive_version(tool, dest_dir=None, version=None, src=None, protect=()):
    """把一份二进制存进版本库，返回 `{ok, version, path, pruned, reason}`。

    `version` 显式给了就用它（安装路径知道确切 tag），否则跑 `<binary> -version` 问。
    `src` 默认是安装目录里的**当前**二进制。问不出版本号 → `ok=False`（不归档）。
    """
    out = {"ok": False, "version": "", "path": "", "pruned": [], "reason": ""}
    if tool not in TOOLS:
        out["reason"] = f"不支持的工具（可选：{'、'.join(TOOLS)}）"
        return out
    dest = Path(dest_dir) if dest_dir else (_BASE_DIR / DEFAULT_DEST)
    binary = binary_name(tool)
    source = Path(src) if src else (dest / binary)
    if not source.exists():
        out["reason"] = "当前没有已安装的可执行文件（无可归档）"
        return out
    key = _version_key(version) or detect_version(tool, source)
    if not key:
        out["reason"] = "问不出该二进制的版本号（不归档 —— 不编造 unknown 目录）"
        return out
    vdir = versions_dir(tool, dest_dir) / key
    try:
        vdir.mkdir(parents=True, exist_ok=True)
        (vdir / binary).write_bytes(source.read_bytes())
    except OSError as e:
        out["reason"] = f"归档失败：{e}"
        return out
    out.update(ok=True, version=key, path=_setting_value(vdir / binary))
    out["pruned"] = prune_versions(tool, dest_dir=dest_dir, protect=set(protect) | {key})
    return out


def list_versions(tool, dest_dir=None):
    """版本库里的版本列表（版本号**降序**），每项 `{version, path, size, active}`。

    `active` 用**内容哈希**与当前安装的二进制比对 —— 不是比版本号：切过去之后版本号会变，
    只有哈希能证明"版本库里这一份就是现在在用的那一份"。
    """
    dest = Path(dest_dir) if dest_dir else (_BASE_DIR / DEFAULT_DEST)
    binary = binary_name(tool)
    live = dest / binary
    live_hash = _sha256_file(live) if live.exists() else ""
    root = versions_dir(tool, dest_dir)
    rows = []
    if not root.is_dir():
        return rows
    for d in root.iterdir():
        f = d / binary
        if not d.is_dir() or not f.exists():
            continue
        rows.append({"version": d.name, "path": _setting_value(f),
                     "size": f.stat().st_size,
                     "active": bool(live_hash) and _sha256_file(f) == live_hash})
    rows.sort(key=lambda r: (_ver_tuple(r["version"]) or (0, 0, 0)), reverse=True)
    return rows


def use_version(tool, version, dest_dir=None, wire=True, settings_path=None):
    """把版本库里某个版本切回**当前使用**（续94）；返回结果字典（**永不抛异常**）。

    切换前会把**当前**这一份归档进版本库 + 写 `<名>.bak` —— 所以切过去再切回来是可行的，
    不会把手上这一份弄丢。`version` 必须在版本库里存在，否则如实报出可用版本。
    """
    out = {"tool": tool, "ok": False, "version": "", "path": "", "reason": ""}
    if tool not in TOOLS:
        out["reason"] = f"不支持的工具（可选：{'、'.join(TOOLS)}）"
        return out
    dest = Path(dest_dir) if dest_dir else (_BASE_DIR / DEFAULT_DEST)
    binary = binary_name(tool)
    target = dest / binary
    want = str(version)
    src = versions_dir(tool, dest_dir) / want / binary
    if not src.exists():
        have = "、".join(r["version"] for r in list_versions(tool, dest_dir)) or "无"
        out["reason"] = f"版本库里没有 {want}（可用版本：{have}）"
        return out
    if target.exists():
        # 先把手上这份存好（归档 + .bak），切换才是可逆的。protect 必须带上**目标版本** ——
        # 否则下面那次 prune 可能把"正要切过去的那一份"删掉。
        try:
            (dest / (binary + ".bak")).write_bytes(target.read_bytes())
        except OSError:
            pass
        archive_version(tool, dest_dir=dest_dir, src=target, protect={want})
    tmp = dest / (binary + ".part")
    try:
        dest.mkdir(parents=True, exist_ok=True)
        tmp.write_bytes(src.read_bytes())
        if os.name != "nt":
            os.chmod(tmp, 0o755)
        os.replace(tmp, target)
    except Exception as e:                                   # noqa: BLE001
        try:
            tmp.unlink()
        except OSError:
            pass
        out["reason"] = f"切换失败：{e}"
        return out
    out.update(ok=True, version=want, path=_setting_value(target))
    out["pruned"] = prune_versions(tool, dest_dir=dest_dir, protect={want})
    if wire:
        ok, note = patch_settings_tool(tool, out["path"], path=settings_path)
        out["wired"] = ok
        if not ok:
            out["reason"] = f"已切到 {out['path']}，但写回 config/settings.yaml 失败：{note}"
    return out


def check_updates(settings, fetch=fetch_release, timeout=30):
    """检查已装工具**是否有新版本**（续87）：联网查 release 最新 tag，与本地 `-version` 比对。

    ⚠️ **只在显式入口调用**（CLI `--check-updates` / GUI「外部工具」页的按钮）—— 与 `--update-tools`
    同一条红线：**扫描期绝不联网**（`tests/smoke.py [7p]` 的变异检测器把这条钉住）。

    返回 `[{tool, installed, latest, has_update, reason}]`；未装 / 查不到都如实写进 `reason`。
    `fetch` 是给测试的注入口（不传就真联网）。
    """
    from .utils import which, run_cmd
    tools_cfg = (settings or {}).get("tools", {}) or {}
    rows = []
    for name, cfg in TOOLS.items():
        row = {"tool": name, "installed": "", "latest": "", "has_update": False,
               "pinned": "", "reason": ""}
        path = which(str(tools_cfg.get(name, name) or name))
        if not path:
            row["reason"] = "未安装（可一键安装）"
            rows.append(row)
            continue
        if cfg.get("verify"):
            _rc, out, err = run_cmd([path, cfg["verify"]], timeout=30)
            first = ((out or "") + (err or "")).strip().splitlines()
            row["installed"] = first[0][:80] if first else ""
        try:
            rel = fetch(TOOLS[name]["repo"], timeout=timeout)
        except Exception as e:                       # noqa: BLE001 - 网络失败如实报，不猜
            row["reason"] = f"查询最新版本失败：{e}"
            rows.append(row)
            continue
        pinned = pin(name)[0]
        row["pinned"] = pinned
        row["latest"] = str((rel or {}).get("tag") or "")
        if pinned and row["latest"] and row["latest"] != pinned:
            # 钉了摘要的工具：官方出了新版**不等于**这边点一下就能更新 —— 新字节没有核过的摘要。
            # 报成 has_update=True 会诱导人去按「更新」，而那必然走到拒装分支（比不报更糟）。
            row["reason"] = (f"官方最新 {row['latest']}，本框架钉在 {pinned}"
                             "（升级须人工核新版产物摘要并同步改 pin_version/pin_sha256）")
            rows.append(row)
            continue
        if not row["latest"]:
            row["reason"] = "release 里没有版本号"
        elif not _ver_tuple(row["installed"]):
            row["reason"] = "本机版本号抠不出来，无法比对"
        else:
            row["has_update"] = newer_version(row["latest"], row["installed"])
        rows.append(row)
    return rows


# ---------- 续166：工作目录内运行时组件（`LOCAL_STACK`） ----------
#
# 与 `TOOLS` 的分工（两组名字不重叠，`tests/smoke.py [166]` 钉住）：
#   `TOOLS`       = 扫描期真被调用的**单二进制外部工具**：落 `tools/scanner/`、装完回写 `tools.<名>`；
#   `LOCAL_STACK` = 把环境**建起来**所需的运行时与源码件（Go 工具链、上游源码包）：落 `tools/<名>/`，
#                   **不回写 settings.yaml**（它们不是 `tools.<名>` 那一档），并且**一个字节都不写
#                   仓库外**（缓存也一样，见 `cache_path()`）。
# 为什么要有它：`./install.sh` 在裸机上到 fscan / massdns 就断了 —— 前者要 Go（本机没有就编不出），
# 后者要 C 源码（本仓不分发第三方源码）。这两件都能在**工作目录内**解决：Go 官方发便携归档、
# 且 `?mode=json` 里带 sha256；源码包按确切 tag 取、摘要由本框架钉住（与 puredns 同一先例）。
# 校验口径与 `TOOLS` **完全同源**（§5.14，不另写一份）：https + 白名单 + 大小上限走 `download_bytes`，
# "校验"那句话走 `verified_label()` / `verify_policy()`，"字节与摘要不符就拒装、`allow_unverified`
# 也越不过"与 `install()` 逐字同义。
STACK_DEST_ROOT = "tools"
CACHE_DIR = ".cache"                 # pip / Go 的缓存都收在这里（默认它们写 `~/.cache` 与 `~/go`）
_STACK_GOJSON = "gojson"             # 官方 JSON 里带 sha256（摘要产地＝release）
_STACK_GITHUB_TAG = "github-tag"     # GitHub 按 tag 生成的源码包（无官方校验和 ⇒ 钉摘要）
GOJSON_URL = "https://go.dev/dl/?mode=json"

LOCAL_STACK = {
    # 摘要产地：官方 `?mode=json` 的 `sha256` 字段 ⇒ `verify_source=release`（**不自己再钉一份** ——
    # 同一件产物两个摘要产地就是 §5.14 说的会漂的形状）。版本**钉死**：清单里查不到这一版就拒装，
    # 不跟 latest（跟 latest 等于把"没核过的字节"装进仓库，与 puredns 那条同一理由）。
    # 2026-10-13 本机实测：清单给 go1.27.2；`go1.27.2.linux-amd64.tar.gz` = 70,590,635 B，
    # 本机下载后算出的 sha256 与清单里那串**逐字相同**（`ecbadb99091a3f46…`）；解包 283 MB，
    # `GOROOT=<落点> <落点>/bin/go version` → `go version go1.27.2 linux/amd64`；
    # 用它（PATH 里**没有**系统 go）编 fscan 21.9 s 成功，产物 28,352,775 B。
    "go": {"kind": _STACK_GOJSON, "version": "1.27.2", "dest": "tools/go", "strip": 1,
           "marker_any": ("bin/go", "bin/go.exe"), "max_bytes": 400 * 1024 * 1024,
           "why": "fscan 官方不发二进制，只能用 Go 自编译；本机没装 Go 时用这一份"
                  "（GOROOT / GOCACHE / GOMODCACHE 全指进仓库，见 go_env()）"},
    # 摘要产地：**本框架钉住**（GitHub 不为 `archive/refs/tags/…` 发校验和）⇒ `verify_source=pinned`。
    # 2026-10-13 本机核实（不是抄来的）：取回 6,764,308 B、1225 个成员、顶层前缀 `fscan-2.2.1/`、
    # `go.mod` 是 `module fscan-lab-api`、`go.sum` 在（模块摘要由 Go 自己校验）；
    # 编出的 fscan 能跑（⚠ 它的 `-h` 是"指定主机"不是 help，见 §5.2）。
    "fscan-src": {"kind": _STACK_GITHUB_TAG, "repo": "shadow1ng/fscan", "version": "v2.2.1",
                  "dest": "tools/fscan-src", "strip": 1, "marker": ("go.mod", "go.sum"),
                  "max_bytes": 40 * 1024 * 1024,
                  "pin_sha256": {"v2.2.1.tar.gz":
                                 "ee9007ff29dad31fcf8afd0c4b8d3427e36927f92078163a7cda1fcdd1156d9e"},
                  "why": "本仓不分发第三方源码；tools/build_fscan.py 要它才能编译"},
    # 2026-10-13 本机核实：751,113 B、73 个成员、前缀 `massdns-1.1.0/`；`make` 2.7 s 出
    # `bin/massdns`（133,816 B）并能打印 usage。⚠ 从 tarball 编时目录里没有 `.git`，Makefile 那句
    # `git describe --tags` 会往 stderr 打一行 `Try --always, or create some tags.`、
    # `MASSDNS_REVISION` 为空 —— **make 仍 rc=0**，别把那行读成编译失败。
    "massdns-src": {"kind": _STACK_GITHUB_TAG, "repo": "blechschmidt/massdns", "version": "v1.1.0",
                    "dest": "tools/massdns-src", "strip": 1, "marker": ("Makefile",),
                    "max_bytes": 8 * 1024 * 1024,
                    "pin_sha256": {"v1.1.0.tar.gz":
                                   "93b14431496b358ee9f3a5b71bd9618fe4ff1af8c420267392164f7b2d949559"},
                    "why": "puredns 在进程内 exec massdns；tools/build_massdns.py 要它才能编译"
                           "（**仍需本机 gcc/make** —— 便携 C 编译器不存在，缺它就如实报）"},
}


def cache_path(*parts):
    """仓库内缓存目录（pip 的下载缓存、Go 的构建与模块缓存都收在这儿）。

    为什么要它：`pip` 默认写 `~/.cache/pip`，`go` 默认写 `~/go/pkg/mod` 与 `~/.cache/go-build`
    —— 实测本机编一次 fscan：GOMODCACHE **192 MB**、GOCACHE **239 MB**，全落在**家目录**。
    那正是"装一个项目却动了别的东西"的形状。落点判据只这一处（§5.14），消费方是
    `run_bootstrap.py`（pip）与 `tools/build_fscan.py`（go）。
    """
    return _BASE_DIR.joinpath(CACHE_DIR, *[str(p) for p in parts])


def go_env(dest_root=None):
    """编译 fscan 该带的 env：GOROOT / GOPATH / GOCACHE / GOMODCACHE（+ 仓库内 Go 的 PATH 前置）。

    **即使本机已有 Go 也要用它给的缓存变量**，否则一次编译就往家目录写几百 MB（数字见
    `cache_path`）。返回的是**增量**字典，调用方自己 `{**os.environ, **env}`；GOROOT 与 PATH
    只在仓库内那份 Go 真的存在时才给（本机有系统 Go 时不该把 GOROOT 指到不存在的目录）。

    另外这几个变量是**实测出来的**，不是顺手加的（2026-10-13，把 `HOME` 指到仓库内一个空目录
    再编一次，编完那目录里躺着 `.config/go/telemetry/local/go@go1.27.2-….count`）：
      `GOTOOLCHAIN=local` 不许它按 `go.mod` 里的 toolchain 行**再去下一份别的 Go**
                         （那会绕过我们钉住的版本，还会往模块缓存里塞一整个工具链）；
      `GOTELEMETRY=off`   关掉上传。⚠ **它挡不住本地那个计数目录** —— 实测给了它与不给它，
                         `$HOME/.config/go/telemetry/` 都照样建，所以真正管事的是下面两条；
      `XDG_CONFIG_HOME` / `GOENV` / `GOTMPDIR`：把配置、构建临时件都收进仓库内
                         （⚠ `GOTMPDIR` 要先 `mkdir`，Go 不自建）；
      `HOME`（POSIX）/ `USERPROFILE`+`APPDATA`+`LOCALAPPDATA`（Windows）：整份指到
                         `cache_path("gohome")`。为什么要这么重的一招：Go 取"用户配置目录"
                         在 macOS 是 `~/Library/Application Support`、Windows 是 `%AppData%`，
                         **两者都不认 `XDG_CONFIG_HOME`** ⇒ 只重定向 XDG 在那两个平台上仍会写家目录。
                         代价是子进程看不到用户的 `~/.gitconfig`：本仓的模块全走公共 proxy
                         （实测 fake HOME 下 192 MB 模块照样取齐），所以不需要它。
    """
    root = Path(dest_root) if dest_root else (_BASE_DIR / STACK_DEST_ROOT)
    goroot = root / "go"
    gohome = cache_path("gohome")
    env = {"GOPATH": str(cache_path("gopath")),
           "GOCACHE": str(cache_path("gobuild")),
           "GOMODCACHE": str(cache_path("gomod")),
           "GOTMPDIR": str(cache_path("gotmp")),
           "GOENV": str(cache_path("goenv")),
           "XDG_CONFIG_HOME": str(cache_path("goconfig")),
           "GOTELEMETRY": "off",
           "GOTOOLCHAIN": "local"}
    if os.name == "nt":
        env["USERPROFILE"] = str(gohome)
        env["APPDATA"] = str(gohome / "AppData" / "Roaming")
        env["LOCALAPPDATA"] = str(gohome / "AppData" / "Local")
    else:
        env["HOME"] = str(gohome)
    if (goroot / "bin" / binary_name("go")).is_file():
        env["GOROOT"] = str(goroot)
        env["PATH"] = os.pathsep.join([str(goroot / "bin"), os.environ.get("PATH", "")])
    return env


def stack_local_go(dest_root=None):
    """仓库内那份 Go 的可执行文件路径（没装 → `None`）。"""
    root = Path(dest_root) if dest_root else (_BASE_DIR / STACK_DEST_ROOT)
    p = root / "go" / "bin" / binary_name("go")
    return p if p.is_file() else None


def stack_asset(name, os_label=None, arch=None):
    """本平台该下哪个文件名；该平台没有产物 → `None`（**不猜、不回落**，与 `asset_name` 同口径）。"""
    cfg = LOCAL_STACK.get(name)
    if not cfg:
        return None
    os_label = os_label or host_arch()[0]
    arch = arch or host_arch()[1]
    if cfg["kind"] == _STACK_GOJSON:
        go_os = {"linux": "linux", "macOS": "darwin", "windows": "windows"}.get(os_label)
        if not go_os or arch not in ("386", "amd64", "arm64"):
            return None
        ext = "zip" if go_os == "windows" else "tar.gz"
        return f"go{cfg['version']}.{go_os}-{arch}.{ext}"
    if cfg["kind"] == _STACK_GITHUB_TAG:
        return f"{cfg['version']}.tar.gz"       # 源码包与平台无关（tag 原样，含前导 v）
    return None


def stack_url(name, os_label=None, arch=None):
    """下载地址（**纯计算、不联网**）；平台没有产物 → `None`。"""
    cfg = LOCAL_STACK.get(name)
    asset = stack_asset(name, os_label, arch)
    if not cfg or not asset:
        return None
    if cfg["kind"] == _STACK_GOJSON:
        return f"https://dl.google.com/go/{asset}"
    if cfg["kind"] == _STACK_GITHUB_TAG:
        return f"https://github.com/{cfg['repo']}/archive/refs/tags/{cfg['version']}.tar.gz"
    return None


def _gojson_digest(asset, version, timeout=60, fetch=None):
    """从官方 `?mode=json` 取该产物的 sha256 → `(digest, 原因)`；查不到就是查不到（不猜、不回落）。"""
    fetch = fetch or (lambda url, timeout=60: download_bytes(url, timeout=timeout,
                                                             max_bytes=8 * 1024 * 1024))
    try:
        data = json.loads(fetch(GOJSON_URL, timeout).decode("utf-8", "replace"))
    except Exception as e:                                       # noqa: BLE001 —— 如实报，不猜
        return None, f"取官方版本清单失败：{e}"
    for rel in data or []:
        if str(rel.get("version") or "")[2:] != version:         # "go1.27.2" → "1.27.2"
            continue
        for f in rel.get("files") or []:
            if f.get("filename") == asset and f.get("sha256"):
                return str(f["sha256"]).strip().lower(), ""
        return None, f"官方清单里 go{version} 没有 {asset} 这一件"
    return None, (f"官方清单里已经没有 go{version}（本框架把 Go 钉在这一版）—— "
                  "升级要先核过新版摘要，再改 LOCAL_STACK['go']['version']")


def stack_digest(name, asset, timeout=60, fetch=None):
    """该产物的摘要与产地 → `(digest, verify_source, 原因)`。

    与 `install()` 同口径：**官方清单里有就用官方的**（`release`），否则用本框架钉住的
    （`pinned`），两者都没有 ⇒ 返回空摘要，由调用方按 `allow_unverified` 决定拒还是放行。
    """
    cfg = LOCAL_STACK.get(name) or {}
    if cfg.get("kind") == _STACK_GOJSON:
        d, why = _gojson_digest(asset, str(cfg.get("version") or ""), timeout=timeout, fetch=fetch)
        if d:
            return d, VERIFY_RELEASE, ""
        return None, "", why
    pinned = (cfg.get("pin_sha256") or {}).get(asset)
    if pinned:
        return str(pinned).strip().lower(), VERIFY_PINNED, ""
    return None, "", f"{asset} 不在本框架钉住的摘要里（{name} 官方不发校验和）"


def _markers_ok(base, marker=(), marker_any=()):
    """「这一件装好了没」的判据 —— **只此一处**（`extract_tree` 收尾与 `stack_present` 共用）。

    `marker` 里的**每一项**都要在；`marker_any` 里的**至少一项**要在（平台二选一那种形状，
    如 Go 的 `bin/go` / `bin/go.exe`）。返回 `(是否就位, 缺什么)` —— 缺什么要能直接进报错，
    否则"解包成功却报失败"这种形状没法排查（本轮实测就是它：把二选一写成了"全部都要"，
    Linux 上永远缺 `bin/go.exe`）。
    """
    base = Path(base)
    miss = [str(mk) for mk in (marker or ()) if not (base / str(mk)).exists()]
    if miss:
        return False, miss[0]
    anys = tuple(str(mk) for mk in (marker_any or ()))
    if anys and not any((base / mk).exists() for mk in anys):
        return False, " / ".join(anys)
    return True, ""


def _stack_strip(member, strip):
    """归档成员名 → 剥掉 `strip` 层前缀后的相对路径；剥完为空（顶层目录本身）→ `None`。

    安全判据与 `extract_binary` 同一条：绝对路径 / 盘符 / 任何 `..` 段一律**抛**（不是跳过）——
    压缩包是外部输入，"少解一个文件"与"解到仓库外"必须区别对待。
    """
    if not _safe_member_name(member):
        raise ValueError(f"压缩包成员名不安全（拒绝）：{member}")
    parts = [p for p in str(member).replace("\\", "/").split("/") if p not in ("", ".")]
    if len(parts) <= strip:
        return None
    return str(Path(*parts[strip:]))


def extract_tree(blob, asset, dest, strip=1, marker=(), marker_any=()):
    """把归档**整棵树**解到 `dest`（`extract_binary` 只取一个文件，这里要的是目录）。

    三条口径：① 不用 `extractall`，逐个成员过 `_stack_strip`（内含 `_safe_member_name`）；
    ② 先解到 `dest.part-<pid>`，**marker 齐了才换上**（换是目录级 `os.replace`，失败会把旧的换回来），
    中途任何异常都不留半成品；③ 保留可执行位（tar 的 `mode`、zip 的 `external_attr`）——
    丢了它 `tools/go/bin/go` 就只是个普通文件，症状是"下载解包都成功、编译却说权限不够"。
    符号链接只在**目标也在仓库内**时才建（指到仓库外＝把"工作目录内自足"这条卖掉），建不了就跳过并计数。
    返回 `(解出的文件数, 跳过的成员数)`。
    """
    dest = Path(dest)
    part = dest.parent / f"{dest.name}.part-{os.getpid()}"
    if part.exists():
        shutil.rmtree(str(part), ignore_errors=True)
    part.mkdir(parents=True)
    n_files = n_skip = 0
    low = str(asset).lower()
    try:
        if low.endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(blob)) as zf:
                for info in zf.infolist():
                    rel = _stack_strip(info.filename, strip)
                    if rel is None:
                        n_skip += 1
                        continue
                    out = part / rel
                    if info.is_dir():
                        out.mkdir(parents=True, exist_ok=True)
                        continue
                    out.parent.mkdir(parents=True, exist_ok=True)
                    out.write_bytes(zf.read(info))
                    mode = (int(info.external_attr) >> 16) & 0o777
                    if mode & 0o111 and os.name != "nt":
                        os.chmod(str(out), mode)
                    n_files += 1
        elif low.endswith((".tgz", ".tar.gz")):
            with tarfile.open(fileobj=io.BytesIO(blob), mode="r:*") as tf:
                for m in tf.getmembers():
                    rel = _stack_strip(m.name, strip)
                    if rel is None:
                        n_skip += 1
                        continue
                    out = part / rel
                    if m.isdir():
                        out.mkdir(parents=True, exist_ok=True)
                        continue
                    if m.issym() or m.islnk():
                        tgt = str(m.linkname or "").replace("\\", "/")
                        if tgt.startswith("/") or re.match(r"^[A-Za-z]:", tgt) \
                                or any(p == ".." for p in tgt.split("/")):
                            raise ValueError(f"归档里的链接目标不安全（拒绝）：{m.name} → {tgt}")
                        out.parent.mkdir(parents=True, exist_ok=True)
                        try:
                            os.symlink(tgt, str(out))
                            n_files += 1
                        except (OSError, NotImplementedError, AttributeError):
                            n_skip += 1     # Windows 无权限建符号链接：跳过并计数（结果里如实报）
                        continue
                    if not m.isfile():
                        n_skip += 1
                        continue
                    f = tf.extractfile(m)
                    if f is None:
                        n_skip += 1
                        continue
                    out.parent.mkdir(parents=True, exist_ok=True)
                    out.write_bytes(f.read())
                    if os.name != "nt" and m.mode & 0o111:
                        os.chmod(str(out), m.mode & 0o777)
                    n_files += 1
        else:
            raise ValueError(f"未支持的归档类型：{asset}")
        ok, missing = _markers_ok(part, marker, marker_any)
        if not ok:
            raise ValueError(f"解包完成但缺关键文件 {missing}（归档形状与注册表对不上）")
        old = dest.parent / f"{dest.name}.old"
        if old.exists():
            shutil.rmtree(str(old), ignore_errors=True)
        if dest.exists():
            os.replace(str(dest), str(old))
        try:
            os.replace(str(part), str(dest))
        except OSError:
            if old.exists():
                os.replace(str(old), str(dest))
            raise
        shutil.rmtree(str(old), ignore_errors=True)
    except Exception:
        shutil.rmtree(str(part), ignore_errors=True)
        raise
    return n_files, n_skip


def stack_present(name, dest_root=None):
    """装没装：注册表里的 marker 是否都在（**只看文件系统**，不靠版本号猜）。"""
    cfg = LOCAL_STACK.get(name)
    if not cfg:
        return False
    d = (Path(dest_root) if dest_root else _BASE_DIR) / cfg["dest"]
    marks = tuple(cfg.get("marker") or ()) + tuple(cfg.get("marker_any") or ())
    if not marks:
        return d.is_dir()
    return _markers_ok(d, cfg.get("marker") or (), cfg.get("marker_any") or ())[0]


def stack_install(name, dest_root=None, allow_unverified=False, timeout=600,
                  blob=None, json_fetch=None):
    """下载并解包一个运行时组件，返回结果字典（**永不抛异常**，失败走 `ok=False` + `reason`）。

    `blob`（产物字节）与 `json_fetch`（官方清单的取法）是测试注入口 —— 给了就**零网络**。
    `dest_root` 只给门禁用（生产就是仓库根）；本函数**没有任何写仓库外的分支**，
    落点恒为 `<dest_root>/<cfg["dest"]>`，缓存恒为 `cache_path(...)`。
    """
    cfg = LOCAL_STACK.get(name) or {}
    out = {"name": name, "ok": False, "version": str(cfg.get("version") or ""), "path": "",
           "verified": None, "verify_source": "", "reason": "",
           "bytes": 0, "files": 0, "skipped": 0}
    if not cfg:
        out["reason"] = f"不支持的组件（可选：{'、'.join(LOCAL_STACK)}）"
        return out
    root = Path(dest_root) if dest_root else _BASE_DIR
    os_label, arch = host_arch()
    asset = stack_asset(name, os_label, arch)
    url = stack_url(name, os_label, arch)
    if not asset or not url:
        out["reason"] = f"官方未提供 {os_label}/{arch} 的 {name} 产物（不猜、不回落）"
        return out
    out["asset"] = asset
    digest, vsrc, why = stack_digest(name, asset, timeout=min(int(timeout), 120), fetch=json_fetch)
    if not digest and not allow_unverified:
        out["reason"] = (why or f"{asset} 没有可用的校验和") + "；默认拒绝安装" \
            "（确要安装请显式允许未校验安装）"
        return out
    data = blob
    if data is None:
        try:
            data = download_bytes(url, timeout=timeout,
                                  max_bytes=int(cfg.get("max_bytes") or _MAX_BYTES))
        except Exception as e:                                   # noqa: BLE001
            out["reason"] = f"下载 {asset} 失败：{e}"
            return out
    out["bytes"] = len(data)
    if digest:
        got = hashlib.sha256(data).hexdigest()
        if got != digest:
            out["reason"] = (f"SHA256 校验不符（期望 {digest[:16]}…，实得 {got[:16]}…，"
                             "期望值来自" + _VERIFY_SRC.get(vsrc, "未知产地")
                             + "）—— 拒绝落盘；摘要对不上通常是产物被换过，不是重试能解决的事")
            return out
        out["verified"] = True
        out["verify_source"] = vsrc
    else:
        out["verified"] = False          # 显式允许的未校验安装（不是 True，页面要如实显示）
    dest = root / cfg["dest"]
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        n_files, n_skip = extract_tree(data, asset, dest, strip=int(cfg.get("strip") or 0),
                                       marker=tuple(cfg.get("marker") or ()),
                                       marker_any=tuple(cfg.get("marker_any") or ()))
    except Exception as e:                                       # noqa: BLE001
        out["reason"] = f"解包失败：{e}"
        return out
    out["files"], out["skipped"] = n_files, n_skip
    out["ok"] = True
    out["path"] = _setting_value(dest)
    return out


def stack_update(names=(), dest_root=None, allow_unverified=False, timeout=600,
                 only_missing=True, json_fetch=None):
    """批量装运行时组件；`only_missing=True`（默认）时**已就位的一件都不重下**。"""
    wanted = [n for n in (names or list(LOCAL_STACK)) if n]
    rows = []
    for n in wanted:
        if n not in LOCAL_STACK:
            rows.append({"name": n, "ok": False, "verified": None,
                         "reason": f"不支持的组件（可选：{'、'.join(LOCAL_STACK)}）"})
            continue
        cfg = LOCAL_STACK[n]
        dest = (Path(dest_root) if dest_root else _BASE_DIR) / cfg["dest"]
        if only_missing and stack_present(n, dest_root):
            rows.append({"name": n, "ok": True, "verified": None, "already": True,
                         "version": str(cfg.get("version") or ""),
                         "path": _setting_value(dest), "reason": ""})
            continue
        rows.append(stack_install(n, dest_root=dest_root, allow_unverified=allow_unverified,
                                  timeout=timeout, json_fetch=json_fetch))
    return rows


def stack_status(dest_root=None):
    """给自举清单 / 页面用的现状行：`[{name, version, present, dest, why}]`（**零网络**）。"""
    rows = []
    for name, cfg in LOCAL_STACK.items():
        rows.append({"name": name, "version": str(cfg.get("version") or ""),
                     "present": stack_present(name, dest_root),
                     "dest": str(cfg.get("dest") or ""), "why": str(cfg.get("why") or "")})
    return rows
