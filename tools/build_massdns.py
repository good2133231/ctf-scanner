#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""从源码编译 massdns（C，用本机 gcc + make），并可选把路径写回 `config/settings.yaml`。

为什么单独一个脚本，而不是塞进 `run_bootstrap.py`：与 `tools/build_fscan.py` 同理 ——
`run_bootstrap` 的自动层有一条**被测试钉死的红线**（`tests/smoke.py [8d]`）：只许跑
"建 venv / 装 pip / 官方 get-pip / 自重跑"四类，**禁止**代跑任何系统级动作（包管理器、编译、clone）。
编译器命令做成**显式入口**：用户敲本脚本才发生。

为什么 massdns 必须在这里解决（不是可选工具）：`puredns` 的 `bruteforce` / `resolve` 会在
**进程内 exec `massdns`**，靠 PATH 找它。官方只发 C 源码（`make` 出 `bin/massdns`），
没有"可直接下载且带官方校验和的单二进制"，所以进不了 `toolmgr.TOOLS` 的 SHA256 通道
—— 与 fscan 的情形完全一致。缺 massdns 时 puredns 每个域名都退码 1，报
`exec: "massdns": executable file not found in $PATH`（实测）。
`scanner/stages/subdomain.py` 里已加**预检**：缺 massdns 时不硬跑 puredns、不浪费整轮时间，
并指向本脚本。

用法：
    python tools/build_massdns.py --src /path/to/massdns          # 编译到 tools/scanner/massdns
    python tools/build_massdns.py --src /path/to/massdns --wire    # 顺便写回 tools.massdns

`--src` 缺省按顺序找：环境变量 `CTFSCANNER_MASSDNS_SRC` → `tools/massdns-src` → `/opt/tools/ctf/massdns-src`。
找不到源码 / 没装 gcc+make 都**如实报**并给出获取步骤，不静默跳过（静默跳过正是本项目反复栽的坑）。
"""
import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DEST = "tools/scanner"


def find_source(explicit=None):
    """定位 massdns 源码目录（含 Makefile）；找不到返回 `None`。"""
    cands = []
    if explicit:
        cands.append(Path(explicit))
    env = (os.environ.get("CTFSCANNER_MASSDNS_SRC") or "").strip()
    if env:
        cands.append(Path(env))
    cands.append(ROOT / "tools" / "massdns-src")
    cands.append(Path("/opt/tools/ctf/massdns-src"))
    for c in cands:
        if (c / "Makefile").is_file():
            return c
    return None


def main(argv=None):
    ap = argparse.ArgumentParser(description="从源码编译 massdns（需本机 gcc + make）")
    ap.add_argument("--src", default=None, help="massdns 源码目录（含 Makefile）")
    ap.add_argument("--dest", default=DEFAULT_DEST, help=f"产物落点（默认 {DEFAULT_DEST}/）")
    ap.add_argument("--wire", action="store_true",
                    help="装好后把 tools.massdns 写回 config/settings.yaml（相对路径）")
    args = ap.parse_args(argv)

    for tool in ("make", "cc"):
        if not shutil.which(tool):
            print(f"[X] 没装 {tool} —— massdns 官方只发 C 源码，要用它自编译。")
            print("    装编译工具链：apt/dnf install build-essential（或 gcc + make）后重跑本脚本。")
            return 1
    src = find_source(args.src)
    if not src:
        print("[X] 找不到 massdns 源码目录（需要含 Makefile）。获取方式（钉到 tag v1.1.0）：")
        print("    git clone https://github.com/blechschmidt/massdns && "
              "git -C massdns checkout v1.1.0")
        print("    然后：python tools/build_massdns.py --src ./massdns --wire")
        return 1

    dest = (ROOT / args.dest) if not Path(args.dest).is_absolute() else Path(args.dest)
    dest.mkdir(parents=True, exist_ok=True)
    out = dest / ("massdns.exe" if os.name == "nt" else "massdns")
    print(f"[*] 编译：make（cwd={src}）")
    p = subprocess.run(["make"], cwd=str(src), capture_output=True, text=True)
    if p.returncode != 0:
        tail = (p.stderr or p.stdout or "").strip().splitlines()
        print("[X] 编译失败：", tail[-1] if tail else f"rc={p.returncode}")
        return 1
    built = src / "bin" / ("massdns.exe" if os.name == "nt" else "massdns")
    if not built.is_file():
        print(f"[X] make 报成功但产物不在 {built} —— 不猜，报出来")
        return 1
    shutil.copy2(str(built), str(out))
    try:
        os.chmod(str(out), 0o755)
    except OSError:
        pass
    print(f"[+] 编译完成：{out}（{out.stat().st_size / 1024:.0f} KB）")
    if args.wire:
        from scanner import toolmgr
        try:
            rel = out.resolve().relative_to(ROOT).as_posix()
        except ValueError:
            rel = str(out.resolve())
        ok, note = toolmgr.patch_settings_tool("massdns", rel)
        if ok:
            print(f"[+] 已把 tools.massdns 写回 config/settings.yaml（{rel}）")
        else:
            print(f"[!] 写回 config/settings.yaml 失败：{note}（请手动把 tools.massdns 填成 {rel}）")
    else:
        print("[i] 未写回配置 —— 需要的话加 --wire，或手动把 tools.massdns 填成上面那行路径。")
    print("[i] puredns 会在进程内按 PATH 找 massdns，本框架调用时已自动把它所在目录加进 PATH。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
