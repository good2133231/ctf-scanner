"""迁移自举：换机器时一次点清"这台机器还缺什么"，能自动装的装上，不能的给命令。

用法：``python run_bootstrap.py``（等价 ``python cli/client.py --bootstrap``）
退出码：0＝缺口为零、或自动层全部补齐；1＝自动层里有项失败。

**为什么要单独一个入口**：本项目跨 Windows / Linux 两端，而"迁移后要不要动手装东西"的答案
散在三处 —— `cli --check` 只看外部工具在不在 PATH、`scanner/toolmgr.py` 只管
subfinder/httpx/puredns、`requirements.txt` 得自己记得 `pip install`；至于"这台机器该用 apt
还是 winget、fscan 要 Go 自编译、截图必须有浏览器"这些平台差异，没有任何一处汇总过。
本脚本把三者串成一次调用，并把结果按"能自动 / 只能手工"两栏如实分开。

**四条红线（沿用 `scanner/toolmgr.py` 的纪律，改本文件前先读完）**：

1. **只在显式触发时联网**：只有带 `--install` 才下载（含 `.venv` 缺 pip 时取的官方
   `get-pip.py`）；`probe()` 本身零网络（只读文件系统 + `shutil.which`）。扫描期任何阶段都不
   得调用本模块 —— 因此它**放在仓库根、刻意不进 `scanner/`
   包**：`tests/smoke.py [7p]` 钉的是"scanner 包内不得引用 toolmgr"，把本模块塞进 `scanner/`
   就得给那条红线开豁免，等于把红线削弱一次。
2. **自动层的边界＝三样**：① 建项目内 `.venv`（`python -m venv` 失败就退到 `--without-pip` +
   官方 `get-pip.py` 引导 —— Ubuntu/Debian 把 ensurepip 拆进 `python3.x-venv` 包，这是常态）；
   ② `pip install -r requirements.txt`；③ `toolmgr.update()`（官方产物 + release 自带 SHA256
   才落盘）。取 get-pip 用的是**另一套同纪律但独立**的白名单（只 `https://bootstrap.pypa.io` +
   大小上限）—— 刻意不复用 `toolmgr.download_bytes`，把该主机塞进 toolmgr 的白名单等于为了
   一个安装脚本去放宽那条校验红线。
   `toolmgr.MANUAL` 的 nmap / fscan / dirmap **一条请求都不发、一条命令都不代跑**：它们要么
   要装进系统目录（apt / 安装器 / dmg，需要 root），要么要用 Go 自编译 —— 代跑就是越
   "系统级动作"的界，还会绕过那条校验和红线。这里只**按平台打印**命令，由用户复制执行。
3. **只出现相对路径**（项目硬规矩）：打印的路径一律相对项目根（`tools/scanner/…`）；
   平台口径只有 `toolmgr.host_arch()` 一处，本文件不另写一份平台分支。
4. **写回只有一条路**：装完工具仍走 `toolmgr` 的逐行替换改 `tools.<名>`；本脚本不碰
   `config/keys.yaml`，也不整份重写 `config/settings.yaml`。
"""
import argparse
import importlib.util
import os
import re
import shutil
import subprocess
import sys
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent

# CI（.github/workflows/smoke.yml）与 Dockerfile 的口径都是 3.9：低于它直接判"跑不了"，
# 高于它只是"没在 CI 上验证过"（如实提示，不当错误）。
PY_MIN = (3, 9)
PY_CI = (3, 9)

# 一键就绪用的虚拟环境（`.gitignore` 已排除，不会脏仓库）
VENV_DIR = ".venv"
# Ubuntu/Debian 把 ensurepip 拆进 python3.x-venv 包 → 系统解释器常常 `python -m venv` 直接失败，
# 而用户的要求是"一上来就能运行"，所以这里自己引导 pip（官方 get-pip.py），不碰系统包。
GET_PIP_URL = "https://bootstrap.pypa.io/get-pip.py"
_GET_PIP_HOSTS = frozenset({"bootstrap.pypa.io"})
_MAX_PIP_BYTES = 8 * 1024 * 1024
_UA = "CTFScanner-bootstrap/0.1 (+authorized-testing-only)"
REEXEC_ENV = "CTFSCANNER_BOOTSTRAP_REEXEC"

# requirements.txt 里的分发名 → 可 import 的模块名（本项目只有 PyYAML 这一个不一致）
_IMPORT_ALIAS = {"pyyaml": "yaml"}

# 每平台候选包管理器，顺序＝推荐优先级；探测只 `shutil.which`，不发任何请求。
_MANAGER_CANDIDATES = {
    "linux": ("apt-get", "dnf", "yum", "pacman", "zypper", "apk"),
    "macOS": ("brew", "port"),
    "windows": ("winget", "choco", "scoop"),
}
_MANAGER_INSTALL = {
    "apt-get": "sudo apt-get install -y {pkg}",
    "dnf": "sudo dnf install -y {pkg}",
    "yum": "sudo yum install -y {pkg}",
    "pacman": "sudo pacman -S --noconfirm {pkg}",
    "zypper": "sudo zypper install -y {pkg}",
    "apk": "sudo apk add {pkg}",
    "brew": "brew install {pkg}",
    "port": "sudo port install {pkg}",
    "winget": "winget install -e --id {pkg}",
    "choco": "choco install -y {pkg}",
    "scoop": "scoop install {pkg}",
}
# 同一个东西在各包管理器下的名字（不同才需要登记；nmap 只有 winget 要写包 ID）。
_PKG_NAME = {
    "nmap": {"winget": "Insecure.Nmap"},
    "chromium": {"winget": "Google.Chrome", "choco": "googlechrome"},
    "golang": {"apt-get": "golang", "dnf": "golang", "yum": "golang", "brew": "go",
               "pacman": "go", "zypper": "go", "apk": "go", "winget": "GoLang.Go",
               "choco": "golang", "scoop": "go"},
}


def package_managers(os_label):
    """本机可用的包管理器（只查 PATH）。"""
    return [m for m in _MANAGER_CANDIDATES.get(os_label or "", ()) if shutil.which(m)]


def platform_info():
    """`(os_label, arch, managers)` —— 平台判定只走 `toolmgr.host_arch()` 这一处。"""
    from scanner import toolmgr
    os_label, arch = toolmgr.host_arch()
    return os_label, arch, package_managers(os_label)


def pkg_cmd(pkg, managers):
    """用第一个可用包管理器生成安装命令；一个都没有就返回 `[]`（**不猜命令**）。"""
    for mgr in managers:
        tmpl = _MANAGER_INSTALL.get(mgr)
        if tmpl:
            return [tmpl.format(pkg=_PKG_NAME.get(pkg, {}).get(mgr, pkg))]
    return []


# ---------- 虚拟环境：让"一上来就能运行"成立 ----------

def venv_python(root=None, windows=None):
    """venv 里的解释器路径。`windows=None` 按本机判；显式传 True/False 供测试两端都验。"""
    root = Path(root) if root is not None else ROOT
    if windows is None:
        windows = os.name == "nt"
    return root / VENV_DIR / ("Scripts" if windows else "bin") / ("python.exe" if windows else "python")


def in_venv():
    return sys.prefix != sys.base_prefix


def _check_pip_url(url):
    """get-pip 的下载纪律与 `toolmgr` 同源：只允许 https + 固定主机；大小有上限。

    刻意不复用 `toolmgr.download_bytes` —— 它的主机白名单只有 GitHub，把 `bootstrap.pypa.io`
    塞进去等于为了一个安装脚本去放宽那条校验红线。
    """
    parts = urllib.parse.urlsplit(url)
    host = (parts.hostname or "").lower()
    if parts.scheme != "https" or host not in _GET_PIP_HOSTS:
        raise RuntimeError(f"只允许从 {'、'.join(sorted(_GET_PIP_HOSTS))} 取 get-pip.py（https）")
    return host


def _bootstrap_pip(py, venv_dir):
    """在给定解释器里引导 pip（官方 get-pip.py，用完即删）。返回 `(ok, 说明)`，不抛。"""
    try:
        got = _fetch_get_pip(venv_dir / "get-pip.py")
        try:
            run = subprocess.run([str(py), str(venv_dir / "get-pip.py")], capture_output=True, text=True)
        finally:
            (venv_dir / "get-pip.py").unlink(missing_ok=True)
    except Exception as e:
        return False, f"取 get-pip.py 失败：{e}"
    if run.returncode != 0:
        tail = ((run.stderr or run.stdout or "").strip().splitlines() or ["无输出"])[-1]
        return False, f"get-pip 引导失败：{tail[:160]}"
    return True, f"已用官方 get-pip.py 引导 pip（下载 {got} 字节）"


def _fetch_get_pip(dst):
    """取官方 get-pip.py 到 dst（边收边判上限）。返回写入的字节数。"""
    _check_pip_url(GET_PIP_URL)
    req = urllib.request.Request(GET_PIP_URL, headers={"User-Agent": _UA})
    with urllib.request.urlopen(req, timeout=120) as resp:
        data = resp.read(_MAX_PIP_BYTES + 1)
    if len(data) > _MAX_PIP_BYTES:
        raise RuntimeError(f"get-pip.py 超过 {_MAX_PIP_BYTES} 字节上限，拒绝使用")
    Path(dst).write_bytes(data)
    return len(data)


def ensure_venv(root=None):
    """把项目内 `.venv` 建起来并保证里面有 pip。**幂等**：已可用就复用，绝不重建覆盖。

    返回 `(ok, 说明)`，**任何失败都不抛** —— 自动层要如实报"这步没成"，而不是把调用方崩掉。
    `python -m venv` 失败时退到 `--without-pip` + 官方 `get-pip.py` 引导：这正是 Ubuntu/Debian
    上系统解释器的常态（ensurepip 被拆进 `python3.x-venv` 包），而用户要的是一句命令就能跑，
    不该先逼人去装系统包。
    """
    root = Path(root) if root is not None else ROOT
    venv_dir = root / VENV_DIR
    py = venv_python(root)
    pre_existed = venv_dir.exists()          # 只有"本次新建的半成品"才敢删，见下面
    if py.exists():
        if subprocess.run([str(py), "-m", "pip", "--version"],
                          capture_output=True, text=True).returncode == 0:
            return True, f"复用 {VENV_DIR}（pip 可用）"
        ok, msg = _bootstrap_pip(py, venv_dir)
        return ok, (msg if not ok else f"{VENV_DIR} 已存在但缺 pip → {msg}")
    created = subprocess.run([sys.executable, "-m", "venv", str(venv_dir)],
                             capture_output=True, text=True)
    if created.returncode == 0:
        return True, f"已创建 {VENV_DIR}"
    # 建 venv 失败（ensurepip 缺失是常态）。**只清自己刚建的**：调用前目录就存在的话，
    # 里面可能是用户自己的东西（哪怕坏掉），删它就是破坏用户数据 —— 改成如实报并让他决定。
    if not pre_existed and (venv_dir / "pyvenv.cfg").exists():
        shutil.rmtree(venv_dir, ignore_errors=True)
    elif pre_existed:
        return False, (f"{VENV_DIR} 已存在但没有可用解释器，且 `python -m venv` 失败 —— "
                       f"不删目录（里面可能是你自己的东西），请手工检查或删掉 {VENV_DIR} 后重试")
    again = subprocess.run([sys.executable, "-m", "venv", "--without-pip", str(venv_dir)],
                           capture_output=True, text=True)
    if again.returncode != 0:
        tail = ((again.stderr or again.stdout or "").strip().splitlines() or ["无输出"])[-1]
        return False, f"创建 {VENV_DIR} 失败：{tail[:160]}"
    if not py.exists():
        return False, f"{VENV_DIR} 建好了但找不到解释器（结构非预期，不猜测路径）"
    ok, msg = _bootstrap_pip(py, venv_dir)
    return ok, (msg if ok else f"{VENV_DIR} 已建但 pip 引导失败：{msg}")


def rerun_in_venv(argv=None, root=None):
    """用 `.venv` 的解释器把本脚本**重跑一遍**（依赖才会装进 venv 而不是系统解释器）。

    返回子进程退出码；没建成 venv 或已在 venv 里 → 返回 `None` 让调用方继续就地执行。
    `REEXEC_ENV` 防递归：子进程带着它，绝不会再套一层。
    """
    if in_venv() or os.environ.get(REEXEC_ENV):
        return None
    py = venv_python(root)
    if not py.exists():
        return None
    env = dict(os.environ, **{REEXEC_ENV: "1"})
    sys.stdout.flush()          # 不 flush 的话，管道里父进程的提示会排到子进程输出之后
    run = subprocess.run([str(py), str(ROOT / "run_bootstrap.py")] + list(argv or sys.argv[1:]), env=env)
    return run.returncode


def requirement_names():
    """读 `requirements.txt` 的分发名（忽略注释/空行；只取名字，不比版本约束）。"""
    text = (ROOT / "requirements.txt").read_text(encoding="utf-8")
    out = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            out.append(re.split(r"[<>=!~\[\s;]", line, maxsplit=1)[0].strip())
    return [n for n in out if n]


# ---------- 探测（零网络）----------

def _row(name, kind, auto, status, detail, cmds=()):
    return {"name": name, "kind": kind, "auto": auto, "status": status,
            "detail": detail, "cmds": list(cmds)}


def probe(settings=None):
    """本机环境清单（**一条请求都不发**）。

    每行 `{name, kind, auto, status, detail, cmds}`：`kind` ∈ `runtime` / `auto` / `manual` /
    `browser`；`status` ∈ `ok` / `missing` / `warn`；`auto` ＝ "本脚本 `--install` 会不会动它"。
    """
    from scanner import screenshot, toolmgr
    from scanner.config import load_settings, resolve
    from scanner.utils import which

    st = settings or load_settings()
    tools_cfg = st.get("tools", {}) or {}
    os_label, arch, mgrs = platform_info()
    rows = [_row("__platform__", "runtime", False, "ok",
                 f"{os_label}/{arch}｜包管理器：{'、'.join(mgrs) or '未探测到'}")]

    ver = sys.version_info[:3]
    if ver < PY_MIN:
        rows.append(_row("python", "runtime", False, "missing",
                         f"{_dot(ver)} 低于下限 {_dot(PY_MIN)}（跑不了）"))
    else:
        rows.append(_row("python", "runtime", False, "ok",
                         _dot(ver) + ("" if ver[:2] == PY_CI[:2]
                                      else f"（CI 口径是 {_dot(PY_CI)}，本版本未在 CI 验证）")))
    has_pip = importlib.util.find_spec("pip") is not None
    rows.append(_row("pip", "runtime", False, "ok" if has_pip else "missing",
                     "可用" if has_pip else
                     "当前解释器没有 pip（Ubuntu/Debian 把 ensurepip 拆进 python3.x-venv 包）"
                     " —— 自动层会自己建 .venv 并用官方 get-pip.py 引导，不需要装系统包",
                     [] if has_pip else ["python run_bootstrap.py --install"]))
    _venv_hint = f"{VENV_DIR}/{('Scripts' if os.name == 'nt' else 'bin')}/" \
                 f"{'python.exe' if os.name == 'nt' else 'python'}"
    if in_venv():
        rows.append(_row("venv", "runtime", False, "ok", "在虚拟环境里运行", []))
    elif (ROOT / VENV_DIR).exists():
        rows.append(_row("venv", "runtime", False, "warn",
                         f"现在跑在系统解释器上，但 .venv 已就绪 —— 依赖应装进 venv 而不是系统",
                         [f"{_venv_hint} run_gui.py"]))
    else:
        rows.append(_row("venv", "runtime", False, "warn",
                         "系统解释器且没有 .venv —— 自动层会自动建（含 pip 引导）",
                         ["python run_bootstrap.py --install"]))
    for dist in requirement_names():
        mod = _IMPORT_ALIAS.get(dist.lower(), dist.lower().replace("-", "_"))
        found = importlib.util.find_spec(mod) is not None
        rows.append(_row("py:" + dist, "runtime", True, "ok" if found else "missing",
                         "已安装" if found else "未安装（`import scanner.*` 会直接失败）",
                         [] if found else ["python -m pip install -r requirements.txt"]))

    for name in toolmgr.TOOLS:
        cur = which(tools_cfg.get(name, name))
        insp = toolmgr.inspect(name)
        rows.append(_row(name, "auto", True,
                         "ok" if cur else ("missing" if insp["asset"] else "warn"),
                         f"已装 {cur}" if cur else
                         (insp["reason"] or f"未装（本平台产物：{insp['binary']}）"),
                         [] if cur else [f"python cli/client.py --update-tools --tool {name}"]))

    for name in toolmgr.MANUAL:
        rows.append(_manual_row(name, os_label, mgrs, tools_cfg, resolve))

    path = screenshot.browser_path(st)
    rows.append(_row("browser", "browser", False, "ok" if path else "missing",
                     "已找到浏览器（截图阶段与 PDF 导出可用）" if path else
                     "未找到 Edge/Chrome/Chromium：截图与 PDF 导出会如实跳过（不谎报）",
                     [] if path else (pkg_cmd("chromium", mgrs)
                                      or ["本平台没有已知包管理器：自行装 Chrome/Chromium/Edge"])))
    return rows


def _dot(ver):
    return ".".join(str(x) for x in ver)


def _manual_row(name, os_label, mgrs, tools_cfg, resolve):
    """nmap / fscan / dirmap：按平台**只打印**命令，本脚本不执行、也不发请求。"""
    from scanner import toolmgr
    from scanner.utils import which

    if name == "nmap":
        cmds = pkg_cmd("nmap", mgrs) or [
            "打开 https://nmap.org/dist/ 取本平台官方产物（Windows 只有安装器、Linux 只有源码包、"
            "macOS 只有 dmg）；摘要在 sigs/<文件名>.digest.txt"]
        found = which(tools_cfg.get("nmap", "nmap"))
        why = toolmgr.MANUAL["nmap"]
    elif name == "fscan":
        dest = "tools/scanner/fscan.exe" if os_label == "windows" else "tools/scanner/fscan"
        cmds = ["git clone https://github.com/shadow1ng/fscan",
                "cd fscan && git checkout v2.2.1",
                'go build -ldflags="-s -w" -trimpath -o ' + dest]
        found = which(tools_cfg.get("fscan", "fscan"))
        why = toolmgr.MANUAL["fscan"]
        if not found:
            for prereq, pkg in (("go", "golang"), ("git", "git")):
                if not shutil.which(prereq):
                    cmds += pkg_cmd(pkg, mgrs) or [f"本机没有 {prereq}：fscan 自编译需要它"]
    else:
        script = (tools_cfg.get("dirmap", {}) or {}).get("script",
                                                        "tools/scanner/dirmap-master/dirmap.py")
        cmds = ["git clone https://github.com/H4ckForJob/dirmap tools/scanner/dirmap-master",
                "python -m pip install -r tools/scanner/dirmap-master/requirements.txt",
                "再把 config/settings.yaml 的 tools.dirmap 两段填好（python / script）"
                "—— GUI「策略配置」页改不了 tools 段"]
        found = str(resolve(script)) if resolve(script).exists() else ""
        why = toolmgr.MANUAL["dirmap"]
    return _row(name, "manual", False, "ok" if found else "missing",
                (f"已装 {found}" if found else why), [] if found else cmds)


# ---------- 汇总 / 自动层 / 打印 ----------

def summarize(rows):
    """分成三堆：已就绪 / 本脚本能补（auto）/ 只能用户动手（manual）。"""
    return {"rows": rows,
            "ok": [r for r in rows if r["status"] == "ok"],
            "todo_auto": [r for r in rows if r["auto"] and r["status"] != "ok"],
            "todo_manual": [r for r in rows if not r["auto"] and r["status"] != "ok"]}


def render(s, failed=(), installed=(), install=False):
    """打印报告。CLI 口径：命令可直接复制，路径原样（不遮项目外路径）。"""
    os_label, arch, mgrs = platform_info()
    print(f"[*] 迁移自举｜平台 {os_label}/{arch}｜包管理器 {'、'.join(mgrs) or '无'}")
    print(f"  已就绪 {len(s['ok'])}｜可自动补齐 {len(s['todo_auto'])}｜需手工 {len(s['todo_manual'])}"
          + (f"｜本轮已装 {len(installed)}" if installed else "")
          + (f"｜自动层失败 {len(failed)}" if failed else ""))
    auto_title = "仍未就绪（自动层没补上）" if install else "可自动补齐（加 --install 就会装）"
    for title, items in (("需要手工安装（本框架不自动下载、也不代跑）", s["todo_manual"]),
                         (auto_title, s["todo_auto"])):
        if not items:
            continue
        print(f"\n—— {title} ——")
        for r in items:
            print(f"  {r['name']:<12} [{r['status']}] {r['detail']}")
            for cmd in r["cmds"]:
                print(f"      $ {cmd}")
    if failed:
        # 只有"失败 N"这个数字等于没说：哪一项、为什么失败必须逐条列出来。
        print("\n—— 自动层失败（本脚本试过了，没成）——")
        for f in failed:
            print(f"  {f['name']:<12} {f.get('reason') or '未知原因'}")
    if s["todo_manual"]:
        print("\n[i] 「需手工」那几类官方都没有\"可下载且带官方校验和的单二进制产物\"，"
              "所以框架不为它们发任何请求（逐条原因见 scanner/toolmgr.py 的 MANUAL）。")
    if not s["todo_auto"] and not s["todo_manual"]:
        print("\n[+] 环境齐了：可以直接 python cli/client.py --check 复核，再跑 tests/smoke.py。")
    print("\n[i] 装完外部工具请跑 `python tests/smoke.py` 复核（本项目的唯一回归门禁）。")
    return s


def install_auto(only=(), allow_unverified=False, dest_dir=None, wire=True):
    """自动层：pip 依赖 + `toolmgr.update`（联网只发生在这里）。返回 `(installed, failed)`。"""
    wanted = {n for n in only if n}
    rows = summarize(probe())["todo_auto"]
    installed, failed = [], []
    py_rows = [r for r in rows if r["kind"] == "runtime"]
    if py_rows and (not wanted or any(r["name"] in wanted for r in py_rows)):
        if importlib.util.find_spec("pip") is None:
            failed.append({"name": "requirements", "reason": "当前解释器没有 pip"})
            print("[!] 跳过 pip 依赖：当前解释器没有 pip（自动层装不了，见清单里的命令）")
        else:
            p = subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"],
                               cwd=str(ROOT), capture_output=True, text=True)
            tail = (p.stderr or p.stdout or "").strip().splitlines()
            if p.returncode == 0:
                installed.append({"tool": "requirements", "path": "requirements.txt"})
                print("[+] Python 依赖已装好（requirements.txt）")
            else:
                reason = tail[-1] if tail else f"rc={p.returncode}"
                failed.append({"name": "requirements", "reason": reason})
                print(f"[!] Python 依赖安装失败：{reason}")
    tool_names = [r["name"] for r in rows if r["kind"] == "auto"]
    if wanted:
        tool_names = [n for n in tool_names if n in wanted]
    if tool_names:
        from scanner import toolmgr
        for r in toolmgr.update(tool_names, dest_dir=dest_dir,
                                allow_unverified=allow_unverified, wire=wire):
            if r.get("ok"):
                installed.append(r)
                print(f"[+] {r['tool']} {r.get('version')} → {r.get('path')}")
            else:
                failed.append({"name": r["tool"], "reason": r.get("reason") or "未知原因"})
                print(f"[!] {r['tool']} 未装上：{r.get('reason')}")
    return installed, failed


def main(argv=None):
    ap = argparse.ArgumentParser(description="迁移自举：按平台点清并补齐环境依赖")
    ap.add_argument("--install", action="store_true",
                    help="执行自动层（pip 依赖 + toolmgr 的 TOOLS）；不加只探测，零网络")
    ap.add_argument("--only", action="append", default=[],
                    help="只自动补这几项（可重复；名字见清单，如 httpx / py:flask）")
    ap.add_argument("--allow-unverified", action="store_true",
                    help="透传 toolmgr：release 没校验和时也照装（默认拒绝）")
    ap.add_argument("--tools-dest", default=None, help="透传 toolmgr 的落点目录")
    ap.add_argument("--no-wire", action="store_true", help="透传 toolmgr：装完不写回 settings.yaml")
    ap.add_argument("--no-venv", action="store_true",
                    help="不要自动建 .venv，就用当前解释器装依赖（容器/受控环境里常用）")
    args = ap.parse_args(argv)

    # 一键就绪：`--install` 时先保证有个带 pip 的 .venv，再用**它**重跑本脚本 ——
    # 否则在 Ubuntu 那种"系统解释器没 pip/ensurepip"的机器上，自动层只能报"装不了"。
    if args.install and not args.no_venv and not in_venv():
        ok, msg = ensure_venv()
        print(f"[{'+' if ok else '!'}] 虚拟环境：{msg}")
        code = rerun_in_venv(sys.argv[1:])
        if code is not None:
            return code
        if not ok:
            print("[!] 退回当前解释器继续（依赖会装到系统解释器上）")

    s = summarize(probe())
    installed, failed = ([], [])
    if args.install:
        installed, failed = install_auto(tuple(args.only), args.allow_unverified,
                                        args.tools_dest, not args.no_wire)
        s = summarize(probe())          # 复探：以"真的装上没有"为准，不按安装返回值吹
    render(s, failed, installed, install=args.install)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
