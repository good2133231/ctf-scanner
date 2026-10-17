"""CLI 前台进度条 + 「日志不刷乱进度条」（借鉴草案 P3-14①，续212 落地）。

背景：参考项目的 tqdm 彩色 CLI 输出值得学（`docs/ref-projects-2026-10-14.md`
第 37 行原话：「tqdm 彩色 CLI 输出（`tqdm.write` 打在进度条上方）值得学」），
但本仓**零第三方依赖** —— 所以这里用一个 ~90 行的等价物，只取真正有用的那一瓣：
**日志行打在进度条上方**（tqdm 的 `tqdm.write` 同思路），阶段级进度。

三条设计约束（都不是洁癖）：
① **只在 TTY 下渲染**。管道 / 重定向 / CI / 测试里一个字节都不多 ——
   `tests/smoke.py` 有大批"逐字比对 stdout"的回归，`> log.txt` 的用户也不该
   收到一堆 `\\r`。判据就是 `stream.isatty()`；另给 `enabled=` 显式覆盖供测试。
② **日志行不许直接 print**。条在的时候要先擦掉当前行、打完日志再重画 ——
   这就是"不刷乱"的全部机制。入口是 `progress.write()`：
   `scanner/log.py` 的控制台 handler 与 CLI 的输出都走它。
③ **纯 ASCII 控制序列**（`\\r` + 空格回退），不碰 ANSI `\\033[K` ——
   Windows 旧 conhost 不开 VT 处理时 `\\033[K` 会原样印出来，那比乱更糟。
   代价是"只能擦掉自己画过的长度"，所以 `Bar` 记 `last_len`（见 `_draw`）。
"""
import sys
import threading

# 串行化「擦条 → 写行 → 重画」这一段：GUI 的 worker 线程与阶段内线程池都会
# 打日志（CLI 前台只有主线程画条，但写日志的线程不止一个）。
_LOCK = threading.RLock()
# 当前活跃的进度条（None = 没有条）。write() 看它决定走哪条路。
_BAR = None


def _isatty(stream):
    try:
        return bool(stream.isatty())
    except Exception:                                   # noqa: BLE001 - 怪 stream 不当 TTY
        return False


class Bar:
    """阶段级进度条：`任务 #12 存活探测 [#####---------------] 25% (3/12)`。

    `head` 是固定前缀（任务行），`stage()` 换的是阶段名与计数 —— 两者分开，
     Runner 每个阶段边界只报 `stage(done, total, 阶段中文名)`，不关心前缀。
    """

    def __init__(self, head="", total=100, stream=None, enabled=None, width=20):
        self.head = str(head or "")
        self.label = ""
        self.total = max(1, int(total or 1))
        self.n = 0
        self.width = max(4, int(width))
        self.stream = stream if stream is not None else sys.stdout
        # enabled 显式覆盖只给测试用；默认按 TTY 判（①）
        self.enabled = _isatty(self.stream) if enabled is None else bool(enabled)
        self.last_len = 0
        self._closed = False

    def stage(self, done, total, label=None):
        """阶段边界回调（`PipelineRunner` 每个阶段开始前调一次）。"""
        with _LOCK:
            if label is not None:
                self.label = str(label)
            if total:
                self.total = max(1, int(total))
            self.n = max(0, min(self.total, int(done)))
            self._draw()

    def _line(self):
        frac = self.n / self.total
        fill = int(round(self.width * frac))
        bar = "#" * fill + "-" * (self.width - fill)
        parts = [p for p in (self.head, self.label) if p]
        head = " ".join(parts) + " " if parts else ""
        return f"{head}[{bar}] {int(frac * 100)}% ({self.n}/{self.total})"

    def _draw(self):
        """画/重画。**调用方持锁**（write() 整段持锁，stage() 自己持）。"""
        if not self.enabled or self._closed:
            return
        line = self._line()
        self.stream.write("\r" + line)
        self.stream.flush()
        self.last_len = len(line)

    def finish(self):
        """收条：擦掉画过的长度并摘除活跃登记。幂等；任何收场都应调一次。"""
        with _LOCK:
            global _BAR
            if _BAR is self:
                _BAR = None
            if self.enabled and not self._closed and self.last_len:
                self.stream.write("\r" + " " * self.last_len + "\r")
                self.stream.flush()
            self._closed = True


def start(head="", total=100, stream=None, **kw):
    """建条并登记为活跃条（非 TTY 时返回的 Bar 是 no-op，不登记）。"""
    bar = Bar(head, total, stream, **kw)
    with _LOCK:
        global _BAR
        _BAR = bar if bar.enabled else None
    bar._draw()
    return bar


def stop(bar=None):
    """收条（默认收当前活跃条）。"""
    b = bar if bar is not None else _BAR
    if b is not None:
        b.finish()


def active():
    """当前活跃的进度条（没有则 None）—— 测试与诊断用。"""
    return _BAR


def write(msg, end="\n", stream=None):
    """**进度条安全地**写一行。

    - 没有活跃条（或条的 stream 不是这个 stream）⇒ 与普通写逐字节一致；
    - 有活跃条 ⇒ 先擦掉画过的长度、写行、再重画（tqdm.write 同思路）。
    `end` 非 "\\n" 时不与条交互（本仓没有这种调用；真出现了也别把条搞乱）。
    任何写失败都不外抛：日志链路炸了比没有日志更糟。
    """
    st = stream if stream is not None else sys.stdout
    text = str(msg)
    if end and not text.endswith(end):
        text += end
    try:
        with _LOCK:
            bar = _BAR
            interactive = (bar is not None and bar.enabled and not bar._closed
                           and bar.stream is st and end == "\n")
            if interactive:
                st.write("\r" + " " * bar.last_len + "\r")
            st.write(text)
            st.flush()
            if interactive:
                bar._draw()
    except Exception:                                   # noqa: BLE001 - 见文件头
        try:
            st.write(text)
            st.flush()
        except Exception:                               # noqa: BLE001 - 真没救就算了
            pass
