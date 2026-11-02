#!/usr/bin/env python3
"""重启控制台：按 pidfile + cmdline + cwd 核归属，**绝不按端口认人**。

为什么单独一个脚本：重启要**先停自己再起新的**，写在 GUI 进程里会把自己杀掉、后半段没人执行。
脚本由 GUI 的「重启服务」按钮以独立会话拉起（`--delay 3` 留出把 HTTP 响应发出去的时间），
也可手工跑：`python tools/restart_gui.py [--dry-run]`。

三道拒绝（任一命中就 exit 2，不动任何进程）：
① 归属三证：pidfile 的 PID 必须满足 cmdline 含 `run_gui.py`、cwd 就是本仓库根 —— 防 PID
   复用误杀别人（续306 按端口认人的事故形态）；
② 仓库内不能有外部引擎进程在跑（dirmap/nmap/...）：续311 实测，重启留下一个 dirmap 孤儿，
   与活进程同 `-iF` 同 cwd 抢 `output/<netloc>.txt`，整文件 r+ 重写互相丢行；
③ 不能有 `running`/`queued` 任务（`--force` 可跳过这一条；②那条不可跳过）。

退出码：0=成功（dry-run 表示计划可行）；2=拒绝；1=执行失败。
"""
from __future__ import annotations

import argparse
import os
import signal
import socket
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PIDFILE = ROOT / "logs" / "_gui307.pid"
GUI_ENTRY = "run_gui.py"
ENGINE_NAMES = ("subfinder", "puredns", "httpx", "nmap", "afrog", "fscan", "dirmap")
OUT_LOG = ROOT / "logs" / "_restart_gui.out"


def read_pid(pidfile: Path) -> int:
    """pidfile 里的 PID；读不到就是 0（调用方按“没有 PID”拒绝）。"""
    try:
        return int((Path(pidfile).read_text(encoding="utf-8").strip() or "0"))
    except (OSError, ValueError):
        return 0


def proc_alive(pid: int) -> bool:
    """进程是否存活（零依赖）。POSIX 用 kill(pid, 0)；Windows 用 OpenProcess+Wait。"""
    if pid <= 0:
        return False
    if os.name == "nt":
        return _win_alive(pid)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True          # 拿不准 → 视为存活（fail-safe，不误杀）
    return True


def _win_alive(pid: int) -> bool:
    import ctypes
    from ctypes import wintypes

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    k32.OpenProcess.restype = wintypes.HANDLE
    k32.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    k32.WaitForSingleObject.restype = wintypes.DWORD
    k32.CloseHandle.argtypes = (wintypes.HANDLE,)
    h = k32.OpenProcess(0x00100000, False, int(pid))   # SYNCHRONIZE
    if not h:
        return True
    try:
        return k32.WaitForSingleObject(h, 0) == 0x00000102   # WAIT_TIMEOUT
    finally:
        k32.CloseHandle(h)


def proc_info(pid: int):
    """`(cmdline, cwd)`；读不到返回 `([], "")`。POSIX 读 /proc；Windows 用可选的 psutil。"""
    if pid <= 0:
        return [], ""
    if os.name != "nt":
        try:
            raw = Path(f"/proc/{pid}/cmdline").read_bytes()
        except OSError:
            return [], ""
        cmdline = [x.decode("utf-8", "replace") for x in raw.split(b"\0") if x]
        try:
            cwd = os.path.realpath(f"/proc/{pid}/cwd")
        except OSError:
            cwd = ""
        return cmdline, cwd
    try:
        import psutil
        p = psutil.Process(pid)
        return list(p.cmdline()), os.path.realpath(p.cwd())
    except Exception:
        return [], ""


def verify_owner(pid: int, repo: Path, cmdline, cwd):
    """纯函数：三证对不上就 `(False, 原因)`。门禁直接调它，不需要真进程。"""
    if pid <= 0:
        return False, f"pidfile 里没有 PID（{DEFAULT_PIDFILE}）"
    if not cmdline:
        return False, (f"PID {pid} 读不到 cmdline（进程已退出 / 无权限 / "
                       "这台机器不支持进程归属校验）")
    if not any(GUI_ENTRY in a for a in cmdline):
        return False, (f"PID {pid} 不是控制台（cmdline 里没有 {GUI_ENTRY}）："
                       + " ".join(cmdline)[:200])
    if not cwd:
        return False, f"PID {pid} 读不到 cwd，无法确认归属"
    want = os.path.realpath(str(repo))
    got = os.path.realpath(cwd)
    if got != want:
        return False, f"PID {pid} 的 cwd 是 {got}，不是本仓库 {want}"
    return True, f"PID {pid} 归属确认：cmdline 含 {GUI_ENTRY}、cwd={got}"


def scan_engines(repo: Path, names=ENGINE_NAMES, procs=None):
    """`[(pid, cmdline)]`：cwd 在仓库内且命令行含引擎名。`procs` 仅供门禁注入。"""
    repo = os.path.realpath(str(repo))
    hits = []
    items = procs.items() if procs is not None else _iter_procs()
    for pid, (cmdline, cwd) in items:
        if not cmdline or not cwd:
            continue
        real = os.path.realpath(cwd)
        if real != repo and not real.startswith(repo + os.sep):
            continue
        joined = " ".join(cmdline)
        base = " ".join(os.path.basename(a) for a in cmdline)
        if any(n in base or n in joined for n in names):
            hits.append((int(pid), joined[:200]))
    return hits


def _iter_procs():
    if not os.path.isdir("/proc"):
        return
    for ent in os.listdir("/proc"):
        if not ent.isdigit():
            continue
        cmdline, cwd = proc_info(int(ent))
        yield int(ent), (cmdline, cwd)


def pending_tasks(db_path: Path):
    """`(running, queued)`；库不存在按 `(0, 0)`。只读连接，绝不改库。"""
    db_path = Path(db_path)
    if not db_path.exists():
        return 0, 0
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        rows = dict(con.execute(
            "SELECT status, COUNT(*) FROM tasks "
            "WHERE status IN ('running','queued') GROUP BY status"))
    finally:
        con.close()
    return int(rows.get("running", 0)), int(rows.get("queued", 0))


def _bind(repo: Path):
    """监听地址；读配置失败就按 `127.0.0.1:5000`（只影响“验端口”这一步）。"""
    try:
        sys.path.insert(0, str(repo))
        from scanner.config import gui_bind, load_settings
        return gui_bind(load_settings())
    except Exception as e:                                  # noqa: BLE001
        print(f"[!] 读配置失败（按默认 127.0.0.1:5000 验端口）：{e}")
        return "127.0.0.1", 5000


def _probe(host, port, timeout=1.5):
    h = "127.0.0.1" if str(host) in ("0.0.0.0", "::", "") else str(host)
    try:
        with socket.create_connection((h, int(port)), timeout=timeout):
            return True
    except OSError:
        return False


def main(argv=None):
    ap = argparse.ArgumentParser(description="按 pidfile 核归属后重启控制台")
    ap.add_argument("--pidfile", default=str(DEFAULT_PIDFILE))
    ap.add_argument("--dry-run", action="store_true", help="只打印计划与拒绝原因，不动进程")
    ap.add_argument("--force", action="store_true",
                    help="跳过 running/queued 检查（外部引擎检查不可跳过）")
    ap.add_argument("--delay", type=float, default=0.0,
                    help="发信号前的等待秒数（GUI 按钮传 3，留时间把 HTTP 响应发出去）")
    ap.add_argument("--wait", type=float, default=15.0,
                    help="等旧进程退出 / 新端口就绪的秒数")
    args = ap.parse_args(argv)

    pidfile = Path(args.pidfile).resolve()
    pid = read_pid(pidfile)
    cmdline, cwd = proc_info(pid)
    ok, why = verify_owner(pid, ROOT, cmdline, cwd)
    if not ok:
        print(f"[!] 拒绝重启：{why}")
        return 2
    print(f"[*] {why}")
    if not proc_alive(pid):
        print(f"[!] 拒绝重启：{why}，但进程已不在（pidfile 过期？）")
        return 2

    engines = scan_engines(ROOT)
    if engines:
        print(f"[!] 拒绝重启：仓库内还有 {len(engines)} 个外部引擎进程在跑 "
              f"（重启会留下孤儿抢同一份 output）：")
        for _p, _c in engines:
            print(f"    pid={_p}  {_c}")
        return 2

    # 库路径跟 `CTFSCANNER_DB` 走：门禁/CI 用它指到临时库，脚本不能在那种环境里读真实库
    _db = Path(os.environ.get("CTFSCANNER_DB") or (ROOT / "data" / "scanner.db"))
    running, queued = pending_tasks(_db)
    if (running or queued) and not args.force:
        print(f"[!] 拒绝重启：还有 {running} 个 running / {queued} 个 queued 任务；"
              f"等它们跑完，或确认是孤儿后加 --force")
        return 2

    host, port = _bind(ROOT)
    print(f"[*] 计划：停 PID {pid} → 用 {sys.executable} 起 {GUI_ENTRY} → "
          f"验 {host}:{port} → 写回 {pidfile}")
    if args.dry_run:
        print("[dry-run] 只打印，不动进程")
        return 0

    if args.delay > 0:
        print(f"[*] {args.delay:.1f}s 后发信号（留时间把 HTTP 响应发出去）", flush=True)
        time.sleep(args.delay)

    try:
        os.kill(pid, signal.SIGTERM)
    except OSError as e:
        print(f"[!] 发 SIGTERM 失败：{e}")
        return 1
    deadline = time.time() + args.wait
    while time.time() < deadline and proc_alive(pid):
        time.sleep(0.2)
    if proc_alive(pid):
        print(f"[!] PID {pid} 在 {args.wait:.0f}s 内没退出 → SIGKILL")
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
        time.sleep(0.5)

    OUT_LOG.parent.mkdir(parents=True, exist_ok=True)
    out = open(OUT_LOG, "ab", buffering=0)
    try:
        child = subprocess.Popen(
            [sys.executable, str(ROOT / GUI_ENTRY)],
            cwd=str(ROOT), stdin=subprocess.DEVNULL, stdout=out,
            stderr=subprocess.STDOUT, start_new_session=True)
    finally:
        out.close()

    ok_port = False
    deadline = time.time() + args.wait
    while time.time() < deadline:
        if _probe(host, port):
            ok_port = True
            break
        if child.poll() is not None:
            print(f"[!] 新进程已退出（rc={child.returncode}），看 {OUT_LOG}")
            return 1
        time.sleep(0.3)
    if not ok_port:
        print(f"[!] 新进程 PID {child.pid} 起来了，但 {host}:{port} 在 "
              f"{args.wait:.0f}s 内没监听（看 {OUT_LOG}）")
        return 1
    pidfile.write_text(str(child.pid), encoding="utf-8")
    print(f"[+] 重启完成：PID {child.pid}，{host}:{port} 在监听，pidfile 已写回")
    return 0


if __name__ == "__main__":
    sys.exit(main())
