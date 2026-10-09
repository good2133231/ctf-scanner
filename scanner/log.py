"""日志：控制台 + 文件双通道。

三档，各管一段，别混：
① 任务级 —— `get_logger(name, log_file)`：每个任务一个 logger 名 + 一个独立日志文件
   （`logs/task_<id>_<ts>/task.log`，由 `runner` 建）；
② 服务进程级（续145，用户点单"服务器启动能不能日志输出在文件"）—— `attach_server_log()`：
   把 `logs/server.log` 挂成**共用一个 handler** 的滚动文件通道，启动横幅与运行期的
   `[gui]` 日志都进它；
③ 启动横幅的落盘副本 —— `boot_logger()`：`serve()` 的十几行横幅是 `print()` 出来的
   （既有回归按**逐字**比对 stdout，不能改成 logging 的带前缀格式），所以另给一个
   **只进文件、不进 stdout** 的 logger，由 `serve()` 的 `say()` 一行两处写。
"""
import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

BOOT_LOGGER = "ctfscanner.boot"
SERVER_LOG_NAME = "server.log"
# 滚动而不是无限追加：控制台是常驻进程，`logs/` 又是 gitignore 的运行产物目录 —— 没人会去清它。
SERVER_LOG_BYTES = 2 * 1024 * 1024
SERVER_LOG_BACKUP = 3


def get_logger(name, log_file=None):
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S")
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    sh.setLevel(logging.INFO)
    logger.addHandler(sh)
    if log_file:
        fh = logging.FileHandler(str(log_file), encoding="utf-8")
        fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        fh.setLevel(logging.DEBUG)
        logger.addHandler(fh)
    return logger


def server_log_path():
    """服务进程日志的落点：`LOGS_DIR/server.log`（`CTFSCANNER_LOGS` 一重定向就进测试沙箱）。"""
    from .config import LOGS_DIR      # 延迟导入：与 utils.rel_display 同一手法，避开导入环
    return Path(LOGS_DIR) / SERVER_LOG_NAME


def boot_logger():
    """启动横幅的落盘通道。**只进文件、不进 stdout**（横幅的 stdout 由 `print()` 负责）。

    `propagate=False` 是必须的：它挂在 root 下面，一旦往上冒泡就会撞见别的 handler，
    同一行横幅在终端里出现两次 —— 而 `[7i]` 钉的正是"启动提示逐行恰好一次、无重复行"。
    """
    lg = logging.getLogger(BOOT_LOGGER)
    lg.setLevel(logging.INFO)
    lg.propagate = False
    return lg


def attach_server_log(*loggers, path=None):
    """把服务进程日志挂成这些 logger **共用的一个**滚动文件通道；返回 `(path, note)`。

    成功时 `note` 是空串；失败时 `path` 是 None、`note` 是原因 —— **不抛异常**
    （写不出启动日志不是"控制台不许起"的理由），但调用方**必须把 note 打印出来**：
    静默降级是本仓反复出事的地方（AGENTS §7）。

    两条实现约束（都不是洁癖）：
    ① 多个 logger 必须挂**同一个 handler 实例**。两个 handler 各写同一个文件时，
       滚动判定各算各的：A 刚把 `server.log` 滚成 `.1`，B 再滚一次就把 `.1` 挤成 `.2`
       （历史被覆盖），而且两边都以为自己写的是 `server.log`。
    ② 按**已解析的文件路径**去重。`serve()` 在同一进程里可以被调多次（回归 `[7i]` 真调三次），
       不去重就是每条日志写 N 遍。`get_logger` 的"有 handler 就早退"挡不住这件事 ——
       它只在**建 logger 时**判一次，事后补挂只能在这里判。
    """
    dst = Path(path) if path else server_log_path()
    try:
        real = str(dst.resolve())
    except OSError:
        real = str(dst)
    targets = list(loggers)
    boot = boot_logger()
    if boot not in targets:
        targets.append(boot)
    for lg in targets:
        for h in lg.handlers:
            if getattr(h, "baseFilename", None) == real:
                return dst, ""                     # 已经挂过：复用，绝不重复挂
    try:
        dst.parent.mkdir(parents=True, exist_ok=True)
        h = RotatingFileHandler(str(dst), maxBytes=SERVER_LOG_BYTES,
                                backupCount=SERVER_LOG_BACKUP, encoding="utf-8")
    except OSError as e:
        # 刻意不拼 `e` 本身 —— 它的字符串里带**绝对路径**，而 §0.3 要求日志里只出现相对路径；
        # `strerror` 已经够指路（"File exists" / "Permission denied" / "Not a directory"）。
        return None, (f"{dst.name} 打不开：{e.__class__.__name__}: "
                      f"{getattr(e, 'strerror', None) or '原因不明'}")
    h.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    h.setLevel(logging.INFO)
    for lg in targets:
        lg.addHandler(h)
    return dst, ""
