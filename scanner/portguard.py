"""端口占用处置（续233，主理人规则）：GUI 起动时端口被占 ⇒ **直接结束占用者，端口归我们**。

背景：续150 的行为是"被占就自动顺延换端口"——但主理人换服务器部署时，端口被旧进程占着
会让控制台"开在一个看不见的端口上"。新规则：优先**杀掉占用者、占回首选端口**；杀不动
（权限/身份不明）才退回顺延。

护栏（写死，不做配置）：
- **绝不杀**：自己的 PID、PID 1、以及 `cmdline` 读不到的进程（身份不明＝宁可失败并说明）；
- 每杀一个都把 `PID + cmdline` 交给 `log`（进启动横幅与 `logs/server.log`，审计可见）；
- 只作用于 **GUI 监听端口**：fixture（8765）、队列、探测目标一概不适用；
- 开关：`gui.kill_port_on_conflict`（默认 True，随包 settings.yaml 也写 true）＋ 环境变量
  `CTFSCANNER_GUI_KILL_PORT`（`0`/`1`，**优先于配置**）。关掉 ⇒ 退回续150 的"自动顺延"。
"""
import os
import signal
import time


def enabled(settings, env=None):
    """规则是否生效：环境变量 `CTFSCANNER_GUI_KILL_PORT`（0/1）优先，其次 `gui.kill_port_on_conflict`。"""
    _env = os.environ if env is None else env
    raw = str(_env.get("CTFSCANNER_GUI_PORT_KILL", _env.get("CTFSCANNER_GUI_KILL_PORT", "")) or "").strip()
    if raw in ("0", "1"):
        return raw == "1"
    return ((settings or {}).get("gui") or {}).get("kill_port_on_conflict") is not False


def _cmdline(pid):
    """读进程 cmdline（NUL 连成一行）；读不到返回空串（身份不明，调用方据此跳过）。"""
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            return f.read().replace(b"\0", b" ").decode("utf-8", "replace").strip()
    except OSError:
        return ""


def find_listeners(port):
    """谁在监听这个 TCP 端口：返回 `[(pid, cmdline), ...]`（纯 /proc 解析，无子进程、无依赖）。

    走 `/proc/net/tcp|tcp6` 找 LISTEN（state 0A）且本地端口匹配的 socket inode，
    再扫 `/proc/<pid>/fd/*` 的 `socket:[inode]` 符号链接回pid。读不了 /proc（非 Linux）
    返回空表 —— 调用方据此退回"顺延"行为，绝不瞎杀。
    """
    want = int(port) & 0xFFFF
    inodes = set()
    for table in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(table, "r", encoding="utf-8", errors="replace") as f:
                for line in f.readlines()[1:]:
                    cols = line.split()
                    if len(cols) < 10 or cols[3] != "0A":   # 0A = LISTEN
                        continue
                    local = cols[1]
                    try:
                        if int(local.split(":")[1], 16) != want:
                            continue
                    except (IndexError, ValueError):
                        continue
                    inodes.add(cols[9])
        except OSError:
            continue
    if not inodes:
        return []
    hit = {}
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        pid = int(entry)
        fddir = f"/proc/{entry}/fd"
        try:
            fds = os.listdir(fddir)
        except OSError:
            continue
        for fd in fds:
            try:
                target = os.readlink(f"{fddir}/{fd}")
            except OSError:
                continue
            if target.startswith("socket:[") and target[8:-1] in inodes:
                hit.setdefault(pid, _cmdline(pid))
                break
    return sorted(hit.items())


def kill_occupiers(port, *, log=None, find=None, kill=None, sleep=None,
                   deadline=8.0, env=None, own_pid=None):
    """结束 `port` 上的占用进程，直到端口腾空或超时。返回 `(freed, killed, skipped)`。

    - 先对占用者发 **SIGTERM**（优雅退出），等 1.5 秒还活着再 **SIGKILL**（升级）；
    - `killed`：`[(pid, cmdline)]` —— 被我们发过信号的进程（审计口径）；
    - `skipped`：`[(pid, 原因)]` —— 身份不明 / 是自己 / 是 PID 1 / 权限不够；
    - `find` / `kill` / `sleep` 可注入（门禁用桩，**绝不真杀任何进程**）；
    - `deadline` 秒内没腾空 ⇒ `freed=False`，调用方退回"顺延换端口"。
    """
    find_fn = find or find_listeners
    kill_fn = kill or os.kill
    sleep_fn = sleep or time.sleep
    me = own_pid if own_pid is not None else os.getpid()
    killed, skipped = [], []
    term_done, kill_done = set(), set()
    t0 = time.monotonic()
    while time.monotonic() - t0 < deadline:
        listeners = find_fn(port)
        if not listeners:
            return True, killed, skipped
        targets = []
        for pid, cmd in listeners:
            if pid == me:
                _reason = "端口被本进程自己占用（重复启动？）"
            elif pid <= 1:
                _reason = "PID 1 / 系统进程，不杀"
            elif not str(cmd or "").strip():
                _reason = "cmdline 读不到（身份不明，不盲杀）"
            else:
                targets.append((pid, cmd))
                continue
            if (pid, _reason) not in skipped:
                skipped.append((pid, _reason))
        if not targets:
            sleep_fn(0.2)
            continue
        for pid, cmd in targets:                       # ① 优雅退出（SIGTERM）
            if pid in term_done:
                continue
            try:
                kill_fn(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            except PermissionError:
                if (pid, "权限不够，杀不掉") not in skipped:
                    skipped.append((pid, "权限不够，杀不掉"))
                continue
            term_done.add(pid)
            killed.append((pid, cmd))
            if log:
                log(f"[portguard] 端口 {port} 被 PID {pid} 占用（{cmd[:120]}）"
                    f"→ 按规则发送 SIGTERM，端口归本程序")
        sleep_fn(1.5)
        if not find_fn(port):
            return True, killed, skipped
        for pid, cmd in targets:                       # ② 升级（SIGKILL）
            if pid in kill_done:
                continue
            try:
                kill_fn(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except PermissionError:
                continue
            kill_done.add(pid)
            if log:
                log(f"[portguard] PID {pid} 对 SIGTERM 没反应，升级 SIGKILL（端口 {port}）")
        sleep_fn(0.5)
    return (not find_fn(port)), killed, skipped
