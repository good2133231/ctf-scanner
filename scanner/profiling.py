"""单任务资源画像（续215，P2-12：真任务 CPU/内存实测 → 动态并发档）。

**为什么单独成模块**：续179 的动态并发档基准是**合成回环 HTTP**（16/80 个空请求），
它只能回答"线程池本身吃多少 CPU"，回答不了"一条真流水线（DNS/HTTP/解析/写库）跑一次
到底占几核、峰值内存多少"。这里补的是后者：`TaskProfile` 跟着 `runner.run_task` 走一遍
真实阶段，采样本进程的 CPU 时间与 RSS，并把"这台机器还能同时跑几条这样的任务"算成
一个**只会往下收**的并发建议（`suggest_workers`）。

三条边界（与项目的保守口径一致）：
1. **只测量、不改变任务行为**；采样线程是 daemon，任务结束就 join，不拖住进程。
2. **建议值只会 ≤ 配置值**：画像不是"放开并发"的许可证，只是"别把机器打满"的证据。
3. 队列 `workers>1` 时 CPU/内存是**进程级**的（`time.process_time()` / `/proc` 都按进程算），
   多个任务会互相污染 ⇒ 读数只会**偏大**、建议只会更保守，不会把并发放大。
   想要单任务干净读数，用 `tools/profile_task.py`（独立库、单 worker、跑完即退）。

平台覆盖：Linux 读 `/proc`；Windows 走 `psapi.GetProcessMemoryInfo` +
`GlobalMemoryStatusEx`（只用标准库 ctypes）；macOS 用 `resource.getrusage` 兜底。
探不到就给 `None`，调用方按"没有证据"处理 —— **绝不编一个数字**。
"""
import os
import sys
import threading
import time

_MB = 1024.0 * 1024.0
PROFILE_VERSION = 1


# ---------------------------------------------------------------- 进程/本机读数

def _linux_meminfo():
    """`(MemTotal MB, MemAvailable MB)`；读不到返回 `(None, None)`。"""
    total = avail = None
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("MemTotal:"):
                    total = int(line.split()[1]) / 1024.0
                elif line.startswith("MemAvailable:"):
                    avail = int(line.split()[1]) / 1024.0
                if total is not None and avail is not None:
                    break
    except (OSError, ValueError, IndexError):
        return None, None
    if total is not None and avail is None:
        avail = total          # 老内核没有 MemAvailable：退回总量（只影响建议精度）
    return (round(total, 1) if total else None,
            round(avail, 1) if avail else None)


def _windows_meminfo():
    """Windows 的 `(总内存 MB, 可用 MB)`；取不到返回 `(None, None)`。"""
    try:
        import ctypes

        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]

        st = MEMORYSTATUSEX()
        st.dwLength = ctypes.sizeof(st)
        if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(st)):
            return None, None
        return (round(st.ullTotalPhys / _MB, 1), round(st.ullAvailPhys / _MB, 1))
    except Exception:                                   # noqa: BLE001 - 探不到就交给调用方
        return None, None


def _windows_rss_mb():
    """当前进程 WorkingSetSize（MB）；失败返回 None。"""
    try:
        import ctypes
        from ctypes import wintypes

        class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        counters = PROCESS_MEMORY_COUNTERS()
        counters.cb = ctypes.sizeof(counters)
        # GetCurrentProcess 返回伪句柄（-1），不需要 CloseHandle
        handle = ctypes.windll.kernel32.GetCurrentProcess()
        if ctypes.windll.psapi.GetProcessMemoryInfo(
                handle, ctypes.byref(counters), counters.cb):
            return round(counters.WorkingSetSize / _MB, 2)
    except Exception:                                   # noqa: BLE001
        return None
    return None


def _resource_rss_mb():
    """`resource.getrusage` 兜底：Linux 单位 KB，macOS 单位字节。"""
    try:
        import resource
        val = float(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
        return round(val / _MB if sys.platform == "darwin" else val / 1024.0, 2)
    except Exception:                                   # noqa: BLE001
        return None


def current_rss_mb():
    """当前进程常驻内存（MB，float）—— `None` 表示这个平台探不到。"""
    if os.name == "nt":
        val = _windows_rss_mb()
        return val if val is not None else _resource_rss_mb()
    if sys.platform.startswith("linux"):
        try:
            with open("/proc/self/status", "r", encoding="utf-8") as fh:
                for line in fh:
                    if line.startswith("VmRSS:"):
                        return round(int(line.split()[1]) / 1024.0, 2)
        except (OSError, ValueError, IndexError):
            pass
    return _resource_rss_mb()


def system_info():
    """本机规格：`{cpu_count, mem_total_mb, mem_available_mb}`（探不到给 None）。"""
    cpu = os.cpu_count() or 1
    if os.name == "nt":
        total, avail = _windows_meminfo()
    elif sys.platform.startswith("linux"):
        total, avail = _linux_meminfo()
    else:
        total = avail = None
    return {"cpu_count": int(cpu), "mem_total_mb": total, "mem_available_mb": avail}


# ---------------------------------------------------------------- 采样器

class TaskProfile:
    """跟着一次 `run_task` 走的资源采样器（用法：`start()` → … → `stop()`）。

    `stop()` **幂等**；没 `start()` 就 `stop()` 返回空 dict。采样周期默认 0.2s，
    峰值 RSS 取"基线 + 运行期所有采样 + 收尾读数"的最大值 —— 单点读数会漏掉
    parse/写库那一下的尖峰。
    """

    def __init__(self, interval=0.2):
        self.interval = max(0.05, float(interval or 0.2))
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None
        self._t0 = None
        self._c0 = None
        self._base_rss = None
        self._peak_rss = None
        self._samples = 0
        self._summary = None

    def start(self):
        if self._t0 is not None:
            return self
        self._t0 = time.perf_counter()
        self._c0 = time.process_time()
        self._base_rss = current_rss_mb()
        self._peak_rss = self._base_rss
        self._thread = threading.Thread(target=self._sample, name="cs-profile", daemon=True)
        self._thread.start()
        return self

    def _sample(self):
        while not self._stop.wait(self.interval):
            rss = current_rss_mb()
            if rss is None:
                continue
            with self._lock:
                self._samples += 1
                if self._peak_rss is None or rss > self._peak_rss:
                    self._peak_rss = rss

    def stop(self):
        if self._summary is not None:
            return self._summary
        if self._t0 is None:
            self._summary = {}
            return self._summary
        wall = max(0.0, time.perf_counter() - self._t0)
        cpu = max(0.0, time.process_time() - self._c0)
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        tail = current_rss_mb()
        with self._lock:
            peak = self._peak_rss
            if tail is not None and (peak is None or tail > peak):
                peak = tail
            samples = self._samples
        base = self._base_rss
        info = system_info()
        self._summary = {
            "version": PROFILE_VERSION,
            "wall_s": round(wall, 3),
            "cpu_s": round(cpu, 3),
            # 1.0 = 吃满一个核。多线程阶段会 >1；队列多 worker 时按进程累计（见文件头第 3 条）
            "cpu_ratio": round(cpu / wall, 3) if wall > 0 else 0.0,
            "rss_base_mb": round(base, 1) if base is not None else None,
            "rss_peak_mb": round(peak, 1) if peak is not None else None,
            "rss_delta_mb": round(max(0.0, (peak or 0.0) - (base or 0.0)), 1)
            if peak is not None else None,
            "samples": samples,
            "at": time.strftime("%Y-%m-%d %H:%M:%S"),
            **info,
        }
        return self._summary

    def summary(self):
        return self._summary or {}

    @property
    def ok(self):
        """拿到了一份**可用来算建议**的读数（至少有墙钟与 CPU 两项）。"""
        return bool(self._summary and self._summary.get("wall_s", 0) > 0)


# ---------------------------------------------------------------- 建议值

def from_row(row, info=None):
    """把 `db.task_profile()` 的行（`cpu_seconds` / `peak_rss_mb` / `profile_wall_s`）
    映射成 `suggest_workers` 认的画像 dict；行空/脏值返回 `None`。

    补上**当下**的 CPU/可用内存（库里的旧内存值可能早已不同）—— 这一步是
    runner 与 queue 两条消费路径的共同产地，避免各写一份映射（§5.14）。
    """
    if not row:
        return None
    try:
        cpu = float(row.get("cpu_seconds") or 0)
        ratio = float(row.get("cpu_ratio") or 0)
        wall = float(row.get("profile_wall_s") or 0)
        rss = float(row.get("peak_rss_mb") or 0)
    except (TypeError, ValueError):
        return None
    if wall <= 0 and cpu <= 0:
        return None
    if ratio <= 0 and wall > 0:
        ratio = cpu / wall
    sysinfo = info or system_info()
    return {
        "cpu_ratio": ratio,
        "rss_peak_mb": rss,
        "wall_s": wall,
        "cpu_count": sysinfo.get("cpu_count"),
        "mem_available_mb": sysinfo.get("mem_available_mb"),
        "profiled_at": str(row.get("profiled_at") or ""),
    }


def suggest_workers(profile, configured=8, headroom=0.25,
                    min_free_mb=256, cpu_count=None, mem_available_mb=None):
    """把一份实测画像换算成"这台机器再跑几条这种任务"的上限。

    - **只会 ≤ `configured`**（配置永远是天花板）；返回 `cap=1` 是最保守的合法值。
    - CPU 侧：`cpu_count * (1-headroom) / cpu_ratio`（留 25% 余量给系统/其他进程）。
    - 内存侧：`(可用 - min_free_mb) / (峰值 * 1.5)`（按 1.5 倍余量估峰值波动）。
    - **证据不足不降档**：墙钟 < 0.5s 或 CPU 占比 ≤ 0.02（纯 I/O 或刚启动）时，
      CPU 侧不下结论；峰值内存探不到同理。这样短任务不会被误判成"很省"或"很吃"。
    - `bound` 说明**是哪一侧先到顶**：`cpu` / `mem` / `io`（CPU 占比 ≤0.15 且内存不紧）。
    """
    prof = profile or {}
    try:
        configured = max(1, int(configured))
    except (TypeError, ValueError):
        configured = 8
    cpu = int(cpu_count or prof.get("cpu_count") or os.cpu_count() or 1)
    try:
        ratio = float(prof.get("cpu_ratio") or 0.0)
    except (TypeError, ValueError):
        ratio = 0.0
    try:
        wall = float(prof.get("wall_s") or 0.0)
    except (TypeError, ValueError):
        wall = 0.0
    try:
        rss = float(prof.get("rss_peak_mb") or 0.0)
    except (TypeError, ValueError):
        rss = 0.0
    try:
        avail = float(mem_available_mb if mem_available_mb is not None
                      else (prof.get("mem_available_mb") or 0.0))
    except (TypeError, ValueError):
        avail = 0.0

    # CPU：证据不足（短任务 / 纯 I/O）时视为"不限制"
    if wall < 0.5 or ratio <= 0.02:
        cpu_cap = 32
    else:
        cpu_cap = max(1, int((cpu * (1.0 - headroom)) / ratio))
    # 内存：没有峰值或没有可用内存数据时同样不限制
    usable = max(0.0, avail - float(min_free_mb or 0))
    if rss <= 0 or usable <= 0:
        mem_cap = 32
    else:
        mem_cap = max(1, int(usable / (rss * 1.5)))

    limit = max(1, min(cpu_cap, mem_cap, 32))
    cap = max(1, min(configured, limit))
    # 谁先到顶：配置低于两侧实测上限时是"配置先到顶"（不是 CPU/内存），
    # 不然会出现"cap=20=配置，却写 CPU 先到顶"的误导（2026-10-18 实测踩到）。
    if configured <= limit:
        bound = "config"
    elif cpu_cap <= mem_cap:
        bound = "io" if ratio <= 0.15 else "cpu"
    else:
        bound = "mem"
    return {
        "cap": cap,
        "configured": configured,
        "cpu_cap": max(1, min(cpu_cap, 32)),
        "mem_cap": max(1, min(mem_cap, 32)),
        "bound": bound,
        "cpu_ratio": round(ratio, 3),
        "rss_peak_mb": round(rss, 1) if rss else None,
        "mem_available_mb": round(avail, 1) if avail else None,
        "wall_s": round(wall, 3),
    }
