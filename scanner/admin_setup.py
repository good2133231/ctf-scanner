"""第一个管理员账号的建立（续117）。

为什么要有这个模块：建"能登录控制台的人"这件事有**两个入口**——
① 首次启动的向导（`gui/app.py::serve()`，库里 0 个账号时）；
② 命令行（`run_users.py --create-admin` / `--reset-password`，容器 / 只读挂载 / 忘了口令 /
被登录锁定挡在门外时）。两处如果各写一份"怎么问口令、什么算合法、怎么落库"，
迟早会漂移成本不同 —— 本仓在 `cdn.py` / `extdom.py` 上修过两次同形状的错。

三条纪律（与全仓一致）：
- 口令**只**从 `getpass`（不回显、不进 shell 历史）或调用方显式传入的参数来，
  **任何返回值与输出里都不含口令**；库里只存 `users.hash_password` 的 PBKDF2 派生值。
- 非交互环境**不动手**、只把该跑的命令说清楚 —— 静默跳过是这仓反复出事的地方。
- **绝不碰配置文件**：`config/settings.yaml` 被 git 跟踪，那里面从此不再有任何登录凭据。
"""
import getpass
import sys

from . import users

ENV_PASSWORD = "CTFSCANNER_ADMIN_PASSWORD"
DEFAULT_NAME = "admin"

# 向导/命令行的两种"没建成"都必须说得出原因，且**不静默**
ST_HAS_USERS = "has-users"      # 库里已有账号 → 首启动根本不该问
ST_NO_TTY = "no-tty"            # 无终端 → 只能走命令行
ST_CANCELLED = "cancelled"      # 交互中被用户放弃（空输入 / 两次不一致）
ST_CREATED = "created"
ST_INVALID = "invalid"          # 用户名或口令不合规则

NO_TTY_HINT = (f"非交互环境（容器 / 无终端 / stdin 不可读）不代填口令："
               f"请跑 `python run_users.py --create-admin`，"
               f"或用环境变量 {ENV_PASSWORD} 提供口令（临时变量，别写进任何入库文件）")


def read_password(who, confirm=True):
    """终端隐式读一个口令；非交互环境只认环境变量。拿不到就返回 None（不猜、不默认）。

    两次确认是给命令行用的：这里没有"登录失败再试一次"的余地 —— 手滑打错就把人锁在
    一个自己不知道的口令后面。
    """
    if not sys.stdin.isatty():
        import os
        return os.environ.get(ENV_PASSWORD) or None
    first = getpass.getpass(f"为「{who}」设置口令：")
    if not first:
        return None
    if confirm:
        again = getpass.getpass("再输入一次以确认：")
        if again != first:
            return None
    return first


def create_admin(username, password):
    """建一个管理员：`(ok, 说明)`。**说明里永不含口令**，也不含哈希。"""
    name = str(username or "").strip() or DEFAULT_NAME
    ok, msg = users.validate_username(name)
    if not ok:
        return False, f"用户名不合法：{msg}"
    if users.get_by_name(name):
        return False, f"账号「{name}」已存在（要改它的口令用 `--reset-password {name}`）"
    if not password:
        return False, "空口令拒绝 —— 建了也登不进去"
    ok, msg = users.create_user(name, str(password), role=users.ROLE_ADMIN, must_change=False)
    if not ok:
        return False, f"建号失败：{msg}"
    return True, f"已建管理员账号「{name}」（库里只存 PBKDF2 派生值，口令不进任何文件）"


def reset_password(username, password):
    """重设已存在账号的口令。用户名不存在时**不新建**（那是另一条命令的语义）。"""
    row = users.get_by_name(str(username or "").strip())
    if not row:
        return False, f"没有这个账号：{username}"
    if not password:
        return False, "空口令拒绝"
    ok, msg = users.validate_password(str(password), row["username"])
    if not ok:
        return False, f"口令不合法：{msg}"
    users.set_password(int(row["id"]), str(password), must_change=False)
    return True, f"已重设账号「{row['username']}」的口令（只落派生值）"


def wizard(ask_name=None, ask_password=None, isatty=None):
    """首次启动向导：库里 0 个账号时，交互式建第一个管理员。

    返回 `(状态, 一句话)` —— 调用方（`serve()`）负责打印，回归负责断言文案；
    真正"建成"的凭据只进 `users` 表。`ask_name` / `ask_password` / `isatty` 都可注入，
    为的是**不必造假终端**也能测（口径与 `keystore.unlock()` 的 `passphrase=` 同款）。
    """
    if users.count_users() > 0:
        return ST_HAS_USERS, "库里已有账号，不重复建号"
    if isatty is None:
        isatty = sys.stdin.isatty()
    if not isatty:
        return ST_NO_TTY, NO_TTY_HINT
    ask_name = ask_name or (lambda: input(f"管理员用户名（直接回车用 {DEFAULT_NAME}）："))
    ask_password = ask_password or (lambda who: read_password(who))
    try:
        name = (ask_name() or "").strip() or DEFAULT_NAME
    except (EOFError, KeyboardInterrupt):
        return ST_CANCELLED, "输入被打断，未建号（控制台照常启动，此时无人能登录）"
    pw = ask_password(name)
    if pw is None:
        return ST_CANCELLED, ("没拿到口令（空输入 / 两次不一致 / 读不到），未建号 —— "
                              "控制台照常启动，但**没人能登录**：补建用 `python run_users.py --create-admin`")
    ok, msg = create_admin(name, pw)
    return (ST_CREATED if ok else ST_INVALID), msg
