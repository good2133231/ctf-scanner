"""日志：控制台 + 文件双通道。

四档，各管一段，别混：
① 任务级 —— `get_logger(name, log_file)`：每个任务一个 logger 名 + 一个独立日志文件
   （`logs/task_<id>_<ts>/task.log`，由 `runner` 建）；
② 服务进程级（续145，用户点单"服务器启动能不能日志输出在文件"）—— `attach_server_log()`：
   把 `logs/server.log` 挂成**共用一个 handler** 的滚动文件通道，启动横幅与运行期的
   `[gui]` 日志都进它；
③ 启动横幅的落盘副本 —— `boot_logger()`：`serve()` 的十几行横幅是 `print()` 出来的
   （既有回归按**逐字**比对 stdout，不能改成 logging 的带前缀格式），所以另给一个
   **只进文件、不进 stdout** 的 logger，由 `serve()` 的 `say()` 一行两处写。
④ 逐请求访问日志（续146-附3，用户点单"静音 console + 单独落一个 logs/access.log"）——
   `attach_access_log()`：接管 `werkzeug` 那个 logger，一是让每个 HTTP 请求真的有一行落盘
   （以前终端里看得见、文件里一行都没有），二是顺手把终端刷掉。它**必须带前缀脱敏**。
"""
import logging
import re
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

BOOT_LOGGER = "ctfscanner.boot"
SERVER_LOG_NAME = "server.log"
ACCESS_LOG_NAME = "access.log"
WERKZEUG_LOGGER = "werkzeug"          # 逐请求行由它产出（`werkzeug.serving.WSGIRequestHandler`）
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


# ---- ④ 逐请求访问日志（续146-附3）----

# 命中本次随机后台前缀时的替身：只说"这里抹过"，不复述任何片段。
MASKED_PREFIX = "<前缀已脱敏>"
# Werkzeug 给非 200 的行套了 ANSI 颜色码（Linux 上 `_log_add_style` 恒为 True），终端里好看，
# 落到文件里就是 `GET /x 33m…0m` 这种垃圾字节 —— 写文件前必须剥掉。
_ANSI_RE = re.compile(r"\033\[[0-9;]*m")
# 同进程反复 `serve()`（回归真会调好几次）时前缀集合的上界：只留最近的这些，最老的先退场。
_MAX_MASKS = 64


class PrefixMask(logging.Filter):
    """把每条记录里的随机后台前缀（连同它的单层片段）抹掉，顺带剥 ANSI 颜色码。

    为什么在 **filter** 里做，而不是干脆不记 path：逐请求行的价值全在 path 上，而 path 的第一段
    恰好就是那个不许落盘的前缀 —— `werkzeug` 记的是客户端送来的**原始请求行**（见
    `WSGIRequestHandler.log_request`），不是应用层的 `request.path`。片段也要抹：只抹整串的话，
    有人探单层（`GET /abcd1234ef/`）就会把第一段原样留在文件里。
    """

    def __init__(self, secrets=()):
        super().__init__()
        self.secrets = []
        self.add(secrets)

    def add(self, secrets):
        for s in secrets:
            s = str(s or "").strip("/")
            if s and s not in self.secrets:
                self.secrets.append(s)
        while len(self.secrets) > _MAX_MASKS:
            self.secrets.pop(0)
        # 长的排前面：整串前缀先抹掉，才不会留下「已脱敏/已脱敏」这种碎片形状
        self._order = sorted(self.secrets, key=len, reverse=True)

    def filter(self, record):
        text = _ANSI_RE.sub("", record.getMessage())
        for s in self._order:
            if s in text:
                text = text.replace(s, MASKED_PREFIX)
        # 改写 msg 并清空 args：格式化已经在这里做完了，留着 args 会让下游 handler 再替换一遍
        record.msg, record.args = text, ()
        return True


def _prefix_pieces(prefix):
    """`/a1b2…/c3d4…` → 整串（去首尾斜杠）+ 每一层，供 `PrefixMask` 逐长度抹。"""
    p = str(prefix or "").strip()
    out = [p.strip("/")] if p.strip("/") else []
    out += [s for s in p.split("/") if len(s) >= 4]
    return out


def access_log_path():
    """逐请求日志的落点：`LOGS_DIR/access.log`（与 `server.log` 同一个可重定向目录）。"""
    from .config import LOGS_DIR
    return Path(LOGS_DIR) / ACCESS_LOG_NAME


def attach_access_log(prefix="", path=None):
    """把 Werkzeug 的逐请求访问日志单独落一个文件，并让它**不再刷终端**。返回 `(path, note)`。

    为什么"挂上自己的文件 handler"就等于静音终端：`werkzeug._internal._log()` 只在本进程
    **第一次**记日志时补一个 `_ColorStreamHandler`（那段 `if _logger is None:` 里判
    `_has_level_handler`）。我们先挂上这个 INFO 级的文件 handler，补动作就不会发生；为了让
    「先记过日志再调用」的进程里也成立，这里还会把该 logger 上**已有的流式 handler**摘掉。

    三条不能省的细节：
    ① 必须挂 `PrefixMask` —— 落盘行里带着本次随机后台前缀，不抹就违反续138「前缀绝不落盘」，
       这是硬约束不是整洁偏好。
    ② `propagate=False` —— 否则任何给 root 挂过 handler 的东西（`basicConfig` 一类）都会把
       访问行重新喷回终端，"静音"就成了看运气的承诺。
    ③ 与 `server.log` **分文件** —— 一个是"服务做了什么"、一个是"谁打过来"，混在一起两边都难读。
       去重按各自的 `baseFilename` 算，所以两个文件互不干扰。

    失败时 `path` 为 None、`note` 是原因，**不抛异常**（写不出访问日志不该拦住启动），
    但调用方必须把 note 打印出来（AGENTS §7：绝不静默降级）。
    """
    lg = logging.getLogger(WERKZEUG_LOGGER)
    dst = Path(path) if path else access_log_path()
    try:
        real = str(dst.resolve())
    except OSError:
        real = str(dst)
    for h in lg.handlers:
        if getattr(h, "baseFilename", None) == real:
            for f in h.filters:
                if isinstance(f, PrefixMask):
                    f.add(_prefix_pieces(prefix))     # 换了一次启动 = 换了一个前缀，必须补进掩码
            return dst, ""                            # 已经挂过：绝不重复挂
    try:
        dst.parent.mkdir(parents=True, exist_ok=True)
        h = RotatingFileHandler(str(dst), maxBytes=SERVER_LOG_BYTES,
                                backupCount=SERVER_LOG_BACKUP, encoding="utf-8")
    except OSError as e:
        # 刻意不拼 `e` 本身 —— 它的字符串里带**绝对路径**，§0.3 要求日志里只出现相对路径。
        return None, (f"{dst.name} 打不开：{e.__class__.__name__}: "
                      f"{getattr(e, 'strerror', None) or '原因不明'}")
    # 逐请求行自带时间戳（`ip - - [10/Oct/2026 12:00:00] "GET …" 200 -`），不要再加一层
    h.setFormatter(logging.Formatter("%(message)s"))
    h.setLevel(logging.INFO)
    h.addFilter(PrefixMask(_prefix_pieces(prefix)))
    for st in [x for x in lg.handlers if isinstance(x, logging.StreamHandler)
               and not isinstance(x, logging.FileHandler)]:
        lg.removeHandler(st)          # 兜住"werkzeug 已经先自己补过终端 handler"的顺序
    lg.addHandler(h)
    lg.setLevel(logging.INFO)         # 不等 werkzeug 惰性设置：NOTSET 会继承 root 的 WARNING，
    lg.propagate = False              # 那样 info() 整个丢掉 —— 现象是"日志文件是空的"
    return dst, ""
