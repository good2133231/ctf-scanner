#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""从源码编译 fscan（跨平台，用本机 Go），并可选把路径写回 `config/settings.yaml`。

为什么单独一个脚本，而不是塞进 `run_bootstrap.py`：
  fscan 官方**不发二进制**，本仓既定做法是用 Go 从源码自编译（避免 Windows Defender 拦那个
  众所周知的壳）。但 `run_bootstrap` 有一条**被测试钉死的红线**（`tests/smoke.py [8d]`）：
  它的自动层只许跑"建 venv / 装 pip / 跑官方 get-pip / 自重跑"四类，**禁止**代跑任何系统级动作
  （包管理器、`go build`、`git clone`）。那条红线的意图是"绝不替用户静默做系统级决定"。
  所以编译这件事做成**显式入口**：用户敲 `./install.sh --with-build` 或直接跑本脚本才发生。

用法：
    python tools/build_fscan.py --src /path/to/fscan-src          # 编译到 tools/scanner/fscan
    python tools/build_fscan.py --src /path/to/fscan-src --wire    # 顺便写回 tools.fscan
    ./install.sh --with-build                                      # 标准安装 + 顺手编译 fscan

`--src` 缺省时按顺序找：环境变量 `CTFSCANNER_FSCAN_SRC` → `tools/fscan-src` → `/opt/tools/ctf/fscan-src`。
找不到源码 / 没装 Go 都**如实报**并给出获取步骤，不静默跳过（静默跳过正是本项目反复栽的坑）。
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
    """定位 fscan 源码目录（含 go.mod）；找不到返回 `None`。"""
    cands = []
    if explicit:
        cands.append(Path(explicit))
    env = (os.environ.get("CTFSCANNER_FSCAN_SRC") or "").strip()
    if env:
        cands.append(Path(env))
    cands.append(ROOT / "tools" / "fscan-src")
    cands.append(Path("/opt/tools/ctf/fscan-src"))
    for c in cands:
        if (c / "go.mod").is_file():
            return c
    return None


def main(argv=None):
    ap = argparse.ArgumentParser(description="从源码编译 fscan（需本机 Go）")
    ap.add_argument("--src", default=None, help="fscan 源码目录（含 go.mod）")
    ap.add_argument("--dest", default=DEFAULT_DEST, help=f"产物落点（默认 {DEFAULT_DEST}/）")
    ap.add_argument("--wire", action="store_true",
                    help="装好后把 tools.fscan 写回 config/settings.yaml（相对路径）")
    args = ap.parse_args(argv)

    go = shutil.which("go")
    if not go:
        print("[X] 没装 Go —— fscan 官方不发二进制，只能用 Go 从源码自编译。")
        print("    装 Go：https://go.dev/dl/（或发行版包管理器 apt/dnf install golang）后重跑本脚本。")
        return 1
    src = find_source(args.src)
    if not src:
        print("[X] 找不到 fscan 源码目录（需要含 go.mod）。获取方式：")
        print("    git clone https://github.com/shadow1ng/fscan && git -C fscan checkout v2.2.1")
        print("    然后：python tools/build_fscan.py --src ./fscan --wire")
        return 1

    dest = (ROOT / args.dest) if not Path(args.dest).is_absolute() else Path(args.dest)
    dest.mkdir(parents=True, exist_ok=True)
    out = dest / ("fscan.exe" if os.name == "nt" else "fscan")
    argv_build = [go, "build", "-ldflags", "-s -w", "-trimpath", "-o", str(out), "."]
    print(f"[*] 编译：{' '.join(argv_build)}  （cwd={src}）")
    p = subprocess.run(argv_build, cwd=str(src), capture_output=True, text=True)
    if p.returncode != 0:
        tail = (p.stderr or p.stdout or "").strip().splitlines()
        print("[X] 编译失败：", tail[-1] if tail else f"rc={p.returncode}")
        return 1
    if not out.exists():
        print(f"[X] go build 报成功但产物不在 {out} —— 不猜，报出来")
        return 1
    size_mb = out.stat().st_size / 1048576
    print(f"[+] 编译完成：{out}（{size_mb:.1f} MB）")
    if args.wire:
        from scanner import toolmgr
        try:
            rel = out.resolve().relative_to(ROOT).as_posix()
        except ValueError:
            rel = str(out.resolve())
        ok, note = toolmgr.patch_settings_tool("fscan", rel)
        if ok:
            print(f"[+] 已把 tools.fscan 写回 config/settings.yaml（{rel}）")
        else:
            print(f"[!] 写回 config/settings.yaml 失败：{note}（请手动把 tools.fscan 填成 {rel}）")
    else:
        print("[i] 未写回配置 —— 需要的话加 --wire，或手动把 tools.fscan 填成上面那行路径。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
