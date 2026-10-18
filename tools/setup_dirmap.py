#!/usr/bin/env python3
"""dirmap 的依赖自检 / 安装入口（续217）。

为什么需要它：dirmap 是**手工安装**的第三方纯 Python 项目（`tools/dirmap/`），
依赖 `gevent` / `lxml` / `progressbar2` / `requests`。这些不是本框架的核心依赖，
不能塞进 `requirements.txt` 让所有人付安装成本；但缺了它们，dirmap 会在导入阶段
直接失败，症状又很容易被误读成"dirmap 不支持本平台"。

两条实测事实（2026-10-18，dirmap v1.1 / master）：
1. 上游 `lib/core/option.py` 有 `import imp`，但**全仓库没有任何 `imp.` 调用**；
   Python 3.12 起标准库删了 `imp`，所以 dirmap 在 3.14 上会 ImportError。
   `scanner/stages/dirscan.py` 已自动把 `tools/dirmap_compat/` 注入子进程
   `PYTHONPATH`，用一个空 `imp` 模块解决 —— **不需要为此装便携 CPython**。
2. 上游 master 没有 `-e` 参数；dirscan 会退成"按 dirmap 自己的 `dirmap.conf`
   跑一轮"，不再逐技术栈白跑。

用法（联网只发生在显式 `--install`）：
    python tools/setup_dirmap.py                 # 只检查，不发请求
    python tools/setup_dirmap.py --install       # 用项目 .venv 装依赖
    python tools/setup_dirmap.py --python tools/python311/bin/python3 --install
    python tools/setup_dirmap.py --src tools/dirmap --check
"""
import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

DEPS = ("gevent", "lxml", "progressbar")


def _rel(p):
    try:
        return Path(p).resolve().relative_to(BASE_DIR).as_posix()
    except Exception:                                   # noqa: BLE001 - 外部解释器原样打印
        return str(p)


def _portable_candidates():
    """仓库内可选的便携解释器（有就用；没有也不影响 3.12+ 的垫片路线）。"""
    names = ("bin/python3", "bin/python3.11", "python.exe", "python3.exe")
    return [BASE_DIR / "tools" / "python311" / n for n in names]


def pick_python(explicit=None):
    if explicit:
        return str(explicit)
    for p in _portable_candidates():
        if p.is_file():
            return str(p)
    venv = BASE_DIR / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    if venv.is_file():
        return str(venv)
    return sys.executable


def _script_path(raw=None):
    if raw:
        return Path(raw)
    try:
        from scanner.config import load_settings, resolve
        cfg = (load_settings().get("tools", {}) or {}).get("dirmap", {}) or {}
        return resolve(cfg.get("script") or "tools/dirmap/dirmap.py")
    except Exception:                                   # noqa: BLE001 - 配置坏了也要能检查
        return BASE_DIR / "tools" / "dirmap" / "dirmap.py"


def _child_env():
    """dirmap 子进程要的 PYTHONPATH：兼容垫片在前，其余继承。"""
    compat = str(BASE_DIR / "tools" / "dirmap_compat")
    old = os.environ.get("PYTHONPATH", "")
    return {**os.environ, "PYTHONPATH": compat + (os.pathsep + old if old else "")}


def check(py, script):
    print(f"[*] 解释器：{_rel(py)}")
    print(f"[*] dirmap ：{_rel(script)}")
    if not script.is_file():
        print(f"[!] 找不到 {_rel(script)} —— 先按 README「手工安装」把 dirmap clone 进来")
        return 2
    ver = subprocess.run([py, "-V"], capture_output=True, text=True)
    if ver.returncode != 0:
        print(f"[!] 解释器跑不起来：{ver.stderr.strip() or ver.stdout.strip()}")
        return 2
    _ver_txt = (ver.stdout or ver.stderr).strip()
    print(f"[*] 版本   ：{_ver_txt}")
    code = ("import sys; sys.path.insert(0, r'%s'); "
            "import gevent, lxml, progressbar; "
            "print('gevent', gevent.__version__); "
            "print('lxml', lxml.__version__); "
            "print('progressbar', getattr(progressbar, '__version__', 'ok'))"
            % (BASE_DIR / "tools" / "dirmap_compat"))
    got = subprocess.run([py, "-c", code], capture_output=True, text=True, env=_child_env())
    if got.returncode != 0:
        print("[!] 依赖不齐：")
        print((got.stderr or got.stdout).strip()[:800])
        print("    补法：python tools/setup_dirmap.py --install")
        return 1
    print("[+] 依赖齐：" + "；".join((got.stdout or "").strip().splitlines()))
    _m = re.search(r"Python (\d+)\.(\d+)", _ver_txt)
    if _m and (int(_m.group(1)), int(_m.group(2))) >= (3, 12):
        print("[i] 该解释器 ≥3.12：dirscan 会自动用 tools/dirmap_compat/imp.py 兜住"
              "上游那句无用的 `import imp`")
    return 0


def install(py, script):
    """装依赖：优先用本框架钉的 `tools/dirmap_requirements.txt`。

    上游 `dirmap/requirement.txt` 是 2020 年的 pin（gevent 20.12.1 / lxml 4.5.0），
    Python 3.12+ 编不出 wheel（实测 greenlet 的 C 扩展直接编译失败）——照着装只会得到
    "dirmap 仍起不来"。`dirmap_requirements.txt` 是 2026-10-18 在 3.14 上实测通过的组合；
    没有它才退回上游清单，并明确说清风险。
    """
    if not script.is_file():
        print(f"[!] 找不到 {_rel(script)} —— 先按 README「手工安装」把 dirmap clone 进来")
        return 2
    upstream = script.parent / "requirement.txt"    # 上游文件名少一个 s，别按惯例猜
    local = BASE_DIR / "tools" / "dirmap_requirements.txt"
    if local.is_file():
        req = local
        print(f"[i] 用本框架钉的 {_rel(req)}（上游 requirement.txt 的 2020 年 pin 在 "
              "Python 3.12+ 编不过）")
    elif upstream.is_file():
        req = upstream
        print(f"[!] 没有 {_rel(local)}，退回上游 {_rel(req)}；Python 3.12+ 很可能编不过")
    else:
        print(f"[!] 找不到 {_rel(upstream)}（也没有 {_rel(local)}）—— 先 clone dirmap")
        return 2
    print(f"[*] 用 {_rel(py)} 安装 {_rel(req)}（显式 --install，联网只发生在这里）")
    cmd = [py, "-m", "pip", "install", "--disable-pip-version-check", "-r", str(req)]
    got = subprocess.run(cmd)
    if got.returncode != 0:
        print(f"[!] pip 退出码 {got.returncode}；依赖没装全，dirmap 仍会回退内置扫描")
        return got.returncode
    return check(py, script)


def main(argv=None):
    ap = argparse.ArgumentParser(description="dirmap 依赖自检 / 安装（续217）")
    ap.add_argument("--install", action="store_true", help="显式联网安装 requirement.txt")
    ap.add_argument("--check", action="store_true",
                    help="只检查不联网（默认行为；此旗标只为把文档里的写法变真）")
    ap.add_argument("--python", default=None, help="指定解释器（默认 .venv / 便携 / 当前）")
    ap.add_argument("--src", default=None, help="dirmap.py 路径（默认读 settings.yaml）")
    args = ap.parse_args(argv)
    py = pick_python(args.python)
    script = _script_path(args.src)
    if args.install:
        return install(py, script)
    return check(py, script)


if __name__ == "__main__":
    sys.exit(main())
