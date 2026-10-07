"""外部工具版本管理（roadmap「工程化 → 工具版本管理：一键下载/更新 subfinder/httpx/puredns」）。

**为什么需要它**：subdomain / probe / 目录三个阶段的"上限"由外部工具决定 —— 没装
subfinder/httpx/puredns 时一律退到内置兜底（覆盖面与速度差一个量级），而 `cli --check`
只会打印"未找到（自动使用内置兜底）"，用户没有任何"把它装上"的路径。

**安全红线（改本模块前先读完整段）**：
1. **只在显式触发时联网**：CLI `--update-tools` / GUI「外部工具」页的按钮。扫描期**绝不**自动下载
   —— 任何阶段代码都不得调用本模块的 `install`/`update`（`tests/smoke.py [7p]` 用变异钉住这一条）。
2. 只允许 https，且主机必须在 `_ALLOWED_HOSTS` 内（含**跟随跳转后**的真实 URL —— GitHub 的
   release 资产会 302 到 `objects.githubusercontent.com`）。
3. **默认必须校验 release 自带的 checksums**：比对不上**绝不落盘**；release 没发布 checksums 时
   默认**拒绝**，只有显式 `allow_unverified=True` 才继续，并在结果里如实标注"未校验"。
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
- nmap / fscan / dirmap 走**手工安装**（本模块不为它们发任何请求）：逐条原因见下方 `MANUAL`，
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
_ALLOWED_HOSTS = frozenset({"api.github.com", "github.com",
                            "objects.githubusercontent.com",
                            "release-assets.githubusercontent.com"})
_UA = "CTFScanner-toolmgr/0.1 (+authorized-testing-only)"

TOOLS = {
    "subfinder": {"repo": "projectdiscovery/subfinder", "style": "pd", "verify": "-version"},
    "httpx": {"repo": "projectdiscovery/httpx", "style": "pd", "verify": "-version"},
    "puredns": {"repo": "d3mondev/puredns", "style": "puredns", "verify": None},
    # afrog（续119，用户点单"能不能给它加自动更新"）。2026-10-07 查官方 latest release（v3.5.7）实测：
    #   7 个产物 = linux / macOS / windows × amd64 / arm64 的 zip，外加 `afrog_3.5.7_checksums.txt`；
    #   命名与 projectdiscovery 同一规律（`{tool}_{ver}_{os}_{arch}.zip`，连 darwin 的官方标签都同样
    #   写作 `macOS`）⇒ 直接复用 "pd" 这套挑法与 SHA256 校验，**不需要新增 style**。
    #   ⚠️ `verify: None` —— **本轮真装真试出来的**：`afrog -version` 在 shell 里瞬间返回
    #   `Afrog 3.5.7`，但一旦 stdout 是**管道**（我们的 `run_cmd` / `verify_tool` 就是这么调的）
    #   它就**永不退出**、且不吐一个字节（6 秒超时，加 `stdin=/dev/null` 也一样）。所以它和
    #   fscan 落进同一档：§5.2 讲的"套默认探针会把**装好的**工具误报成未通过版本校验，
    #   随即静默降级"—— 这里更糟，是每次探测白等一个超时。做法：不给握手参数，
    #   并在 `status()` 里跳过探测（下一处改动），页面上只报"已装 / 未装"。
    # ⚠️ `wired: False` 是本轮特意加的诚实标记：**能装 ≠ 会被用**。vulnscan 的适配器还没写，
    #   在它接进来之前，扫描路径一次都不会调用这个二进制 —— 所以它也不进 `run_bootstrap --install`
    #   的自动层（不然每台新机器都白拉 25 MB），只接受显式 `--update-tools --tool afrog`。
    #   页面与 `status()` 的文案必须把"框架尚未调用它"说出来：旧文案一律写"未找到（自动使用
    #   内置兜底）"，对 afrog 是**假的**（没有任何东西在兜底），而静默误导正是这仓反复出事的地方。
    "afrog": {"repo": "zan8in/afrog", "style": "pd", "verify": None, "wired": False},
}


def wired(name):
    """这个工具**是否真的被扫描路径调用**（没标 = 是）。

    `TOOLS` 的含义一直是"能自动下载、且默认必须过官方 SHA256"，那只回答"能不能装"；
    "装好之后有没有代码去用它"是第二个问题 —— 混成一个，就会出现"表里列着、页面说会自动
    兜底、实际谁都不调用"。分档之后：自动安装层与 GUI 文案都按这一档走，`[8x]` 钉住。
    """
    return bool(TOOLS.get(name, {}).get("wired", True))

#  「需手工安装」的工具 —— **刻意不进 `TOOLS`**：`TOOLS` 的语义是"能自动下载、且默认必须过
#  release 自带的 SHA256 校验才落盘"。这三个都不满足（2026-09-27 实测，不是推测）：
#    - nmap   官方发布在 nmap.org/dist（**不在** GitHub release，本模块的 fetch_release 够不着）；
#             Windows 只发 NSIS 安装器 `nmap-7.991-setup.exe`（是"装到 Program Files"的系统级动作，
#             不是"解包取一个可执行文件"）；Linux 只发源码包（要编译）；macOS 只发 .dmg（要挂载）。
#             校验值是有的，但在 `sigs/<文件名>.digest.txt`（URL 模式与本模块的 "checksums" 不同）。
#    - fscan  官方不发二进制，本仓的既定做法是用 Go 从源码自编译（见 tools/scanner/README.md）。
#    - dirmap 最新 release 的 `assets` 是**空数组**（零二进制、零 checksums）；且它是纯 Python 项目
#             （要 `pip install` 依赖），不是单二进制 —— `extract_binary()` 的模型套不上。
#  之所以**写出来**而不是"眼不见为净"：GUI「外部工具」页若只列 `TOOLS`，会让人以为
#  "没列出来的框架不管"，而 `cli --check` 里它们又都是"未找到（自动使用内置兜底）"。
#  这三条只做**如实展示 + 指向 README 的手工步骤**，本模块不会为它们发任何请求。
MANUAL = {
    "nmap": "官方只发安装器 / 源码包 / dmg（无便携 zip），自动装会变成系统级安装",
    "fscan": "官方不发二进制，需用 Go 从源码自编译（本仓为避免 Defender 拦截的既定做法）",
    "dirmap": "release 零产物、无 checksums，且是纯 Python 项目（需 pip 依赖）",
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


def fetch_release(repo, timeout=30):
    """查最新 release → `{"tag": "v1.2.3", "assets": {名字: 下载URL}}`。

    用**公开 API 且不传任何凭据**：只读、无副作用；未认证的 60 次/小时对"偶尔装个工具"绰绰有余
    （与本项目 github_leak 阶段"不把登录态发出去"的口径一致）。
    """
    data = json.loads(download_bytes(
        f"https://api.github.com/repos/{repo}/releases/latest",
        timeout=timeout, max_bytes=4 * 1024 * 1024).decode("utf-8", "replace"))
    assets = {}
    for a in (data.get("assets") or []):
        if a.get("name") and a.get("browser_download_url"):
            assets[str(a["name"])] = str(a["browser_download_url"])
    return {"tag": str(data.get("tag_name") or ""), "assets": assets}


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
    try:
        rel = release if release is not None else fetch_release(TOOLS[tool]["repo"], timeout=timeout)
    except Exception as e:                                   # 网络/解析失败一律如实报，不猜
        out["reason"] = f"查询最新版本失败：{e}"
        return out
    tag, assets = rel.get("tag") or "", rel.get("assets") or {}
    out["version"] = tag
    want_asset = asset_name(tool, tag, os_label, arch)
    if not want_asset or want_asset not in assets:
        out["reason"] = (f"{tag or '最新版'} 未提供 {os_label}/{arch} 产物"
                         f"（release 里有：{'、'.join(sorted(assets)[:6])}…）")
        return out
    csum_name = checksum_asset(assets, tag)
    want_digest = None
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
    elif not allow_unverified:
        out["reason"] = (f"{tag or '最新版'} 未发布校验和文件；默认拒绝安装"
                         "（确要安装请显式允许未校验安装）")
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
            out["reason"] = f"SHA256 校验不符（期望 {want_digest[:16]}…，实得 {got[:16]}…）—— 拒绝落盘"
            return out
        out["verified"] = True
    else:
        out["verified"] = False        # 显式允许的未校验安装（不是 True，页面要如实显示）
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


def update(tools=None, dest_dir=None, allow_unverified=False, wire=True, settings_path=None,
           timeout=120, fetch=fetch_release, blobs=None):
    """按顺序装/更新若干工具，返回结果列表。**只由显式入口调用**（CLI / GUI 按钮）。

    `fetch` 与 `blobs` 是给测试的注入口：`fetch` 换掉"查最新版本"，
    `blobs` 是 `{工具名: {资产名: bytes}}` —— 传了就完全不联网（`install` 优先用 blob）。
    """
    names = [t for t in (tools or list(TOOLS)) if t]
    results = []
    for name in names:
        rel = None
        try:
            rel = fetch(TOOLS[name]["repo"], timeout=timeout) if name in TOOLS else None
        except Exception as e:
            results.append({"tool": name, "ok": False, "version": "", "path": "",
                            "verified": None, "reason": f"查询最新版本失败：{e}"})
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

    文案按 `wired()` 分档 —— "会用的"才说"未找到（自动使用内置兜底）"，
    "装上待接入"的必须写明框架尚未调用它（不谎报有兜底）。
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
            note = f"OK（{path}）" + ("" if _wired else "｜已装，但框架尚未调用它")
        else:
            note = ("未找到（自动使用内置兜底）" if _wired
                    else "未装（框架尚未调用它，只纳入可下载/可校验管理）")
        rows.append({"tool": name, "configured": configured, "path": path or "",
                     "version": version, "asset": pre["asset"] or "",
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
        row = {"tool": name, "installed": "", "latest": "", "has_update": False, "reason": ""}
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
        row["latest"] = str((rel or {}).get("tag") or "")
        if not row["latest"]:
            row["reason"] = "release 里没有版本号"
        elif not _ver_tuple(row["installed"]):
            row["reason"] = "本机版本号抠不出来，无法比对"
        else:
            row["has_update"] = newer_version(row["latest"], row["installed"])
        rows.append(row)
    return rows
