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
"""
import hashlib
import io
import json
import os
import platform
import re
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
_ALLOWED_HOSTS = frozenset({"api.github.com", "github.com", "objects.githubusercontent.com"})
_UA = "CTFScanner-toolmgr/0.1 (+authorized-testing-only)"

TOOLS = {
    "subfinder": {"repo": "projectdiscovery/subfinder", "style": "pd", "verify": "-version"},
    "httpx": {"repo": "projectdiscovery/httpx", "style": "pd", "verify": "-version"},
    "puredns": {"repo": "d3mondev/puredns", "style": "puredns", "verify": None},
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
    try:
        dest.mkdir(parents=True, exist_ok=True)
        tmp.write_bytes(payload)
        if os.name != "nt":
            os.chmod(tmp, 0o755)
        os.replace(tmp, dest / binary)          # 原子替换：要么旧的、要么完整的新的
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
    """列出三个工具的当前状态（供 GUI/CLI 展示）：配置值 / 解析到的路径 / 版本 / 平台可用性。"""
    from .utils import which, run_cmd
    tools_cfg = (settings or {}).get("tools", {}) or {}
    rows = []
    for name, cfg in TOOLS.items():
        configured = str(tools_cfg.get(name, name) or name)
        path = which(configured)
        version = ""
        if path and cfg.get("verify"):
            rc, out, err = run_cmd([path, cfg["verify"]], timeout=30)
            if rc == 0:
                first = ((out or "") + (err or "")).strip().splitlines()
                version = first[0][:80] if first else "OK"
        pre = inspect(name)
        rows.append({"tool": name, "configured": configured, "path": path or "",
                     "version": version, "asset": pre["asset"] or "",
                     "reason": pre["reason"],
                     "note": f"OK（{path}）" if path else "未找到（自动使用内置兜底）"})
    return rows
