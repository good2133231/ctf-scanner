#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""从源码编译 fscan（跨平台），并可选把路径写回 `config/settings.yaml`。

为什么单独一个脚本，而不是塞进 `run_bootstrap.py`：
  fscan 官方**不发二进制**，本仓既定做法是用 Go 从源码自编译（避免 Windows Defender 拦那个
  众所周知的壳）。但 `run_bootstrap` 有一条**被测试钉死的红线**（`tests/smoke.py [8d]`）：
  它的自动层只许跑"建 venv / 装 pip / 跑官方 get-pip / 自重跑"四类，**禁止**代跑任何系统级动作
  （包管理器、`go build`、`git clone`）。那条红线的意图是"绝不替用户静默做系统级决定"。
  所以编译这件事做成**显式入口**：用户敲 `./install.sh --with-build`（或 `--full`）才发生。

**续166 起它能在裸机上自己把缺的件取齐**（此前缺 Go 或缺源码就只能打印命令让人手工做）：
  源码包与 Go 便携归档都从 `toolmgr.LOCAL_STACK` 走（https + 主机白名单 + 落盘前过 SHA256；
  Go 的摘要来自官方 `?mode=json`，源码包的摘要由本框架钉住），落点全在仓库内。
  编译缓存也全在仓库内（`toolmgr.cache_path`）：实测一次编译 GOMODCACHE 192 MB、GOCACHE 239 MB，
  默认那套会写进**家目录**（`~/go`、`~/.cache/go-build`），正是"装一个项目却动了别的东西"。

用法：
    python tools/build_fscan.py --fetch --wire     # 缺源码/缺 Go 就自己取，编完写回配置
    python tools/build_fscan.py --src ./fscan      # 用你给的源码目录（本机 Go）
    ./install.sh --full                            # 标准安装 + 工作目录内取件 + 编译 fscan/massdns

`--src` 缺省时按顺序找：环境变量 `CTFSCANNER_FSCAN_SRC` → `tools/fscan-src`（`--fetch` 的落点）。
**刻意不再兜到仓库外的绝对路径**（续166 摘掉）：那会让"这台机器编得出、换一台编不出"，
而且默认就读项目外目录违反 §0.2。找不到源码 / 没 Go 又不给 `--fetch` 都**如实报**并给出下一步。
"""
import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    # ⚠ 不能省：`tools/` 下有个**同名**的 `tools/scanner/`（外部工具落点），脚本直跑时
    # `sys.path[0]` 是 `tools/`，于是 `from scanner import toolmgr` 会撞到那个命名空间包并报
    # `ImportError: cannot import name 'toolmgr' from 'scanner' (unknown location)` —— 续166 实测，
    # 那正是 `--wire` 这条路从来没通过的原因（而文档一直在教人这么敲）。
    sys.path.insert(0, str(ROOT))

DEFAULT_DEST = "tools/scanner"


def find_source(explicit=None):
    """定位 fscan 源码目录（含 go.mod）；找不到返回 `None`。只在**仓库内**与环境变量里找。"""
    cands = []
    if explicit:
        cands.append(Path(explicit))
    env = (os.environ.get("CTFSCANNER_FSCAN_SRC") or "").strip()
    if env:
        cands.append(Path(env))
    cands.append(ROOT / "tools" / "fscan-src")
    for c in cands:
        if (c / "go.mod").is_file():
            return c
    return None


def find_go():
    """Go 可执行文件：先本机 PATH，再仓库内那份（`tools/go/bin/go`）；都没有 → `None`。"""
    sysgo = shutil.which("go")
    if sysgo:
        return sysgo, False
    from scanner import toolmgr
    local = toolmgr.stack_local_go()
    return (str(local), True) if local else (None, False)


def fetch(name, allow_unverified=False):
    """从 `LOCAL_STACK` 取一件（源码包 / Go 便携归档）。返回 `(ok, 一句话)`，绝不抛。"""
    from scanner import toolmgr
    print(f"[*] 取 {name}（{toolmgr.LOCAL_STACK[name]['version']}）→ "
          f"{toolmgr.LOCAL_STACK[name]['dest']} …")
    r = toolmgr.stack_install(name, allow_unverified=allow_unverified)
    if r.get("ok"):
        lbl = toolmgr.verified_label(r)
        print(f"[+] {name} 就位：{r.get('files')} 个文件、{r.get('bytes', 0) / 1048576:.1f} MB"
              + (f"（{lbl}）" if lbl else ""))
        if r.get("skipped"):
            print(f"[i] 另有 {r['skipped']} 个成员被跳过（目录项 / 建不了的符号链接），已如实计数")
        return True, ""
    why = r.get("reason") or "未知原因"
    print(f"[X] {name} 没取到：{why}")
    return False, why


def main(argv=None):
    ap = argparse.ArgumentParser(description="从源码编译 fscan（缺件时可自动取，全落仓库内）")
    ap.add_argument("--src", default=None, help="fscan 源码目录（含 go.mod）")
    ap.add_argument("--dest", default=DEFAULT_DEST, help=f"产物落点（默认 {DEFAULT_DEST}/）")
    ap.add_argument("--wire", action="store_true",
                    help="编好后把 tools.fscan 写回 config/settings.yaml（相对路径）")
    ap.add_argument("--settings", default=None,
                    help="写回哪个 settings.yaml（默认 config/settings.yaml；门禁用沙箱副本）")
    ap.add_argument("--fetch", action="store_true",
                    help="缺源码 / 缺 Go 时自动取（源码包与 Go 便携归档都过 SHA256，落仓库内）")
    ap.add_argument("--allow-unverified", action="store_true",
                    help="配合 --fetch：官方与钉住的摘要都拿不到时也照装（默认拒绝）")
    args = ap.parse_args(argv)

    if args.fetch and not find_source(args.src):
        ok, why = fetch("fscan-src", args.allow_unverified)
        if not ok:
            print("[!] 也可以自己放源码：git clone https://github.com/shadow1ng/fscan && "
                  "git -C fscan checkout v2.2.1，再 --src ./fscan 重跑")
            return 1
    src = find_source(args.src)
    if not src:
        print("[X] 找不到 fscan 源码目录（需要含 go.mod）。两条路：")
        print("    ① 自动取（推荐）：python tools/build_fscan.py --fetch --wire")
        print("    ② 自己放：git clone https://github.com/shadow1ng/fscan && "
              "git -C fscan checkout v2.2.1，再 --src ./fscan --wire")
        return 1

    go, go_local = find_go()
    if not go:
        if args.fetch:
            ok, _ = fetch("go", args.allow_unverified)
            go, go_local = (None, False)
            if ok:
                go, go_local = find_go()
        if not go:
            print("[X] 没有 Go —— fscan 官方不发二进制，只能用 Go 从源码自编译。")
            print("    自动取一份进仓库（不碰系统）：python tools/build_fscan.py --fetch --wire")
            print("    或自己装：https://go.dev/dl/（或发行版包管理器 apt/dnf install golang）")
            return 1

    from scanner import toolmgr
    env = dict(os.environ)
    env.update(toolmgr.go_env())          # 缓存/配置/遥测/临时件一律指进仓库内（见 go_env 的实测注）
    for _k in ("GOTMPDIR", "GOCACHE", "GOMODCACHE", "GOPATH", "XDG_CONFIG_HOME",
               "HOME" if os.name != "nt" else "USERPROFILE"):
        Path(env[_k]).mkdir(parents=True, exist_ok=True)   # GOTMPDIR 必须先存在，Go 不自建
    dest = (ROOT / args.dest) if not Path(args.dest).is_absolute() else Path(args.dest)
    dest.mkdir(parents=True, exist_ok=True)
    out = dest / ("fscan.exe" if os.name == "nt" else "fscan")
    argv_build = [go, "build", "-ldflags", "-s -w", "-trimpath", "-o", str(out), "."]
    print(f"[*] 编译：{' '.join(argv_build)}  （cwd={src}）")
    print(f"[*] Go 来自{'仓库内 tools/go' if go_local else '本机 PATH'}；"
          f"模块与构建缓存 → {toolmgr.CACHE_DIR}/（不写家目录）")
    p = subprocess.run(argv_build, cwd=str(src), capture_output=True, text=True, env=env)
    if p.returncode != 0:
        tail = (p.stderr or p.stdout or "").strip().splitlines()
        print("[X] 编译失败：", tail[-1] if tail else f"rc={p.returncode}")
        print("    （首次编译要联网取 Go 模块，模块摘要由 fscan 自带的 go.sum 校验；"
              "离线机器上这一步必然失败）")
        return 1
    if not out.exists():
        print(f"[X] go build 报成功但产物不在 {out} —— 不猜，报出来")
        return 1
    size_mb = out.stat().st_size / 1048576
    print(f"[+] 编译完成：{out}（{size_mb:.1f} MB）")
    if args.wire:
        try:
            rel = out.resolve().relative_to(ROOT).as_posix()
        except ValueError:
            rel = str(out.resolve())
        ok, note = toolmgr.patch_settings_tool("fscan", rel, path=args.settings)
        if ok:
            print(f"[+] 已把 tools.fscan 写回 "
                  f"{args.settings or 'config/settings.yaml'}（{rel}）")
        else:
            print(f"[!] 写回配置失败：{note}（请手动把 tools.fscan 填成 {rel}）")
    else:
        print("[i] 未写回配置 —— 需要的话加 --wire，或手动把 tools.fscan 填成上面那行路径。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
