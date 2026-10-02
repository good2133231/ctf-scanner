"""迁移自举：换机器时一次点清"这台机器还缺什么"，能自动装的装上，不能的给命令。

用法：``python run_bootstrap.py``（等价 ``python cli/client.py --bootstrap``）
退出码：0＝缺口为零、或自动层全部补齐；1＝自动层里有项失败。

**为什么要单独一个入口**：本项目跨 Windows / Linux 两端，而"迁移后要不要动手装东西"的答案
散在三处 —— `cli --check` 只看外部工具在不在 PATH、`scanner/toolmgr.py` 只管
subfinder/httpx/puredns、`requirements.txt` 得自己记得 `pip install`；至于"这台机器该用 apt
还是 winget、fscan 要 Go 自编译、截图必须有浏览器"这些平台差异，没有任何一处汇总过。
本脚本把三者串成一次调用，并把结果按"能自动 / 只能手工"两栏如实分开。

**四条红线（沿用 `scanner/toolmgr.py` 的纪律，改本文件前先读完）**：

1. **只在显式触发时联网**：只有带 `--install` 才下载；`probe()` 本身零网络（只读文件系统 +
   `shutil.which`）。扫描期任何阶段都不得调用本模块 —— 因此它**放在仓库根、刻意不进 `scanner/`
   包**：`tests/smoke.py [7p]` 钉的是"scanner 包内不得引用 toolmgr"，把本模块塞进 `scanner/`
   就得给那条红线开豁免，等于把红线削弱一次。
2. **自动层的边界＝`toolmgr.TOOLS`**（官方产物 + release 自带 SHA256 才落盘）与 pip 依赖。
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
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent

# CI（.github/workflows/smoke.yml）与 Dockerfile 的口径都是 3.9：低于它直接判"跑不了"，
# 高于它只是"没在 CI 上验证过"（如实提示，不当错误）。
PY_MIN = (3, 9)
PY_CI = (3, 9)

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
                     "可用" if has_pip else "当前解释器没有 pip（Ubuntu 把 ensurepip 拆成单独的 "
                                            "python3.x-venv 包），自动装依赖会跳过",
                     [] if has_pip else ["sudo apt install python3-venv  # 或从 get-pip.py 引导"]))
    in_venv = sys.prefix != sys.base_prefix
    rows.append(_row("venv", "runtime", False, "ok" if in_venv else "warn",
                     "在虚拟环境里" if in_venv else "装在系统解释器上（建议 venv，见 docs/usage.md）"))
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
    args = ap.parse_args(argv)

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
