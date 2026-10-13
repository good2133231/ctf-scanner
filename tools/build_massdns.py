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

**续166 起源码可以自动取**（此前只能 `git clone`）：`--fetch` 从 `toolmgr.LOCAL_STACK` 取
`massdns-src`（按确切 tag `v1.1.0`，摘要由本框架钉住、落盘前核对），解到 `tools/massdns-src/`。
⚠ **编译器仍然只能来自本机**：C 工具链没有"便携且可校验"的官方产物，缺 gcc/make 时本脚本
如实报并给命令，**不假装编成了**（`--fetch` 也救不了这一档）。

用法：
    python tools/build_massdns.py --fetch --wire     # 自动取源码 → make → 写回配置
    python tools/build_massdns.py --src ./massdns --wire
    ./install.sh --full

`--src` 缺省时按顺序找：环境变量 `CTFSCANNER_MASSDNS_SRC` → `tools/massdns-src`（`--fetch` 的落点）。
**刻意不再兜到仓库外的绝对路径**（续166 摘掉，理由与 build_fscan 同）。
"""
import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    # ⚠ 不能省：脚本直跑时 `sys.path[0]` 是 `tools/`，而那里有个同名的 `tools/scanner/`
    # （外部工具落点）⇒ `from scanner import toolmgr` 会撞到它并报
    # `ImportError: cannot import name 'toolmgr' from 'scanner' (unknown location)`（续166 实测）。
    sys.path.insert(0, str(ROOT))

DEFAULT_DEST = "tools/scanner"


def find_source(explicit=None):
    """定位 massdns 源码目录（含 Makefile）；找不到返回 `None`。只在仓库内与环境变量里找。"""
    cands = []
    if explicit:
        cands.append(Path(explicit))
    env = (os.environ.get("CTFSCANNER_MASSDNS_SRC") or "").strip()
    if env:
        cands.append(Path(env))
    cands.append(ROOT / "tools" / "massdns-src")
    for c in cands:
        if (c / "Makefile").is_file():
            return c
    return None


def fetch(name, allow_unverified=False):
    """从 `LOCAL_STACK` 取源码包。返回 `(ok, 原因)`，绝不抛。"""
    from scanner import toolmgr
    cfg = toolmgr.LOCAL_STACK[name]
    print(f"[*] 取 {name}（{cfg['version']}）→ {cfg['dest']} …")
    r = toolmgr.stack_install(name, allow_unverified=allow_unverified)
    if r.get("ok"):
        lbl = toolmgr.verified_label(r)
        print(f"[+] {name} 就位：{r.get('files')} 个文件、{r.get('bytes', 0) / 1048576:.1f} MB"
              + (f"（{lbl}）" if lbl else ""))
        return True, ""
    why = r.get("reason") or "未知原因"
    print(f"[X] {name} 没取到：{why}")
    return False, why


def main(argv=None):
    ap = argparse.ArgumentParser(description="从源码编译 massdns（需本机 gcc + make）")
    ap.add_argument("--src", default=None, help="massdns 源码目录（含 Makefile）")
    ap.add_argument("--dest", default=DEFAULT_DEST, help=f"产物落点（默认 {DEFAULT_DEST}/）")
    ap.add_argument("--wire", action="store_true",
                    help="装好后把 tools.massdns 写回 config/settings.yaml（相对路径）")
    ap.add_argument("--settings", default=None,
                    help="写回哪个 settings.yaml（默认 config/settings.yaml；门禁用沙箱副本）")
    ap.add_argument("--fetch", action="store_true",
                    help="缺源码时自动取（按确切 tag，摘要由本框架钉住，落 tools/massdns-src/）")
    ap.add_argument("--allow-unverified", action="store_true",
                    help="配合 --fetch：拿不到摘要时也照装（默认拒绝）")
    args = ap.parse_args(argv)

    for tool in ("make", "cc"):
        if not shutil.which(tool):
            print(f"[X] 没装 {tool} —— massdns 官方只发 C 源码，要用它自编译；"
                  "**这一档没有便携替代品**（`--fetch` 只能取源码，取不来编译器）。")
            print("    装编译工具链：apt/dnf install build-essential（或 gcc + make）后重跑本脚本。")
            return 1
    if args.fetch and not find_source(args.src):
        ok, _ = fetch("massdns-src", args.allow_unverified)
        if not ok:
            print("[!] 也可以自己放源码：git clone https://github.com/blechschmidt/massdns && "
                  "git -C massdns checkout v1.1.0，再 --src ./massdns 重跑")
            return 1
    src = find_source(args.src)
    if not src:
        print("[X] 找不到 massdns 源码目录（需要含 Makefile）。两条路：")
        print("    ① 自动取（推荐）：python tools/build_massdns.py --fetch --wire")
        print("    ② 自己放：git clone https://github.com/blechschmidt/massdns && "
              "git -C massdns checkout v1.1.0，再 --src ./massdns --wire")
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
    print("[i] 从 tarball 编时目录里没有 .git，make 会往 stderr 打一行 "
          "`Try --always, or create some tags.`、版本串为空 —— 那是**正常**的（rc 仍是 0）。")
    if args.wire:
        from scanner import toolmgr
        try:
            rel = out.resolve().relative_to(ROOT).as_posix()
        except ValueError:
            rel = str(out.resolve())
        ok, note = toolmgr.patch_settings_tool("massdns", rel, path=args.settings)
        if ok:
            print(f"[+] 已把 tools.massdns 写回 "
                  f"{args.settings or 'config/settings.yaml'}（{rel}）")
        else:
            print(f"[!] 写回 config/settings.yaml 失败：{note}（请手动把 tools.massdns 填成 {rel}）")
    else:
        print("[i] 未写回配置 —— 需要的话加 --wire，或手动把 tools.massdns 填成上面那行路径。")
    print("[i] puredns 会在进程内按 PATH 找 massdns，本框架调用时已自动把它所在目录加进 PATH。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
