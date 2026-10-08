"""401 边缘认证门（HTTP Basic）。

为什么存在：`config/settings.yaml` 的 `gui.host` 现在是 `0.0.0.0`（用户 2026-10-08 点名），
控制台不再只监听回环 —— 任何能路由到这台机器 5000 端口的人都打得到登录页。这道门在
**任何路由逻辑之前**把不带 Basic 凭据的请求退回 401，于是登录页、验证码、`login_guard`
的失败计数都不会再被陌生流量碰到。

与 AGENTS.md §5.10 的冲突是**用户明确批准的豁免**：那一条写「新增任何"绕过账号的登录路"
都算违反本条」，而本模块正是一条独立于 `users` 表的登录路。用户知悉代价后选了"独立边缘
口令"这一档，豁免记录在 AGENTS.md 里，不在这里自证合理。

三条设计边界：

① **口令绝不进任何被 git 跟踪的文件**。`config/settings.yaml` 与 `scanner/config.py`
   都在仓库里，而这个仓库是公开的（AGENTS.md §2）。所以这里只把 `users.hash_password()`
   的派生值写进 `<库同目录>/edge_auth.secret`（`data/` 在 `.gitignore` 第 6 行）并 chmod
   0600 —— 与续109 的 `session.secret` 同一套落点与口径，`CTFSCANNER_DB` 一重定向就自动
   跟着进测试沙箱，回归不会往真实 `data/` 里塞东西。

② **启用但没设口令 = 一律 401（fail-closed）**，并且启动时明说怎么设。宁可暂时打不开，
   也不能出现"配了开关、其实没门"这种看着有防护的缺口。

③ **校验结果按会话缓存**。`pbkdf2_sha256` 是 20 万次迭代（约 0.1 秒），而 `app.js` 是
   轮询式的（状态、日志、页签）—— 每个请求重算一遍等于把 CPU 烧在同一个口令上。通过后
   在会话里打一个标记，后续请求直接放行；伪造这个会话需要那个 0600 的 `session.secret`，
   与窃听 Basic 头不是同一个代价量级。

口令的**唯一入口**是本模块的交互式 CLI（`getpass`，不回显、不进 argv、不进任何输出），
`settings.yaml` 里只有开关 —— 这样"改配置"和"改口令"是两件事，配置文件不会漂成凭据仓库。
"""
import argparse
import base64
import binascii
import getpass
import pathlib
import sys

from scanner import users

SECRET_FILE = "edge_auth.secret"
EDGE_USER = "edge"                 # Basic 的用户名固定，只有口令是秘密
REALM = "CTFScanner"
SESSION_KEY = "edge_ok"            # 通过后打在会话里，避免每个请求重算 pbkdf2（见 ③）
# 设置口令的那条命令 —— **全仓唯一产地**（AGENTS.md §5.14：面向用户的同一句提示只许有一个产地，
# 三处手写同一句必然漂，续124 真踩过）。401 响应体、启动横幅、CLI 输出都引这一个常量。
SET_HINT = "python -m scanner.edgeauth --set"

# 401 的正文刻意**不写用户名**：`WWW-Authenticate` 已经暴露"这里有一道 Basic 门"，
# 再把"用户名固定是 edge"印在响应里，等于把爆破面从「用户名+口令」收窄到只剩口令 ——
# 与 `login_guard` 那条"被锁的文案与账号是否存在无关"是同一个取向。主人要查用户名：`--status`。
CHALLENGE_BODY = (
    "401 需要边缘认证口令。用户名不是控制台的登录账号 —— 查看与设置：\n"
    f"    {SET_HINT}          # 口令只交互输入，不落任何文件\n"
    f"    python -m scanner.edgeauth --status\n"
)


def secret_path():
    """派生值文件的位置 = **库同目录**（与 `session.secret` 同一口径，见模块 docstring ①）。

    刻意在函数内 import `db`：`db.DB_PATH` 受 `CTFSCANNER_DB` 覆盖且在 import 期定型，
    本模块不能因为"被谁先 import"而把落点烤死。
    """
    from scanner import db
    return pathlib.Path(str(db.DB_PATH)).parent / SECRET_FILE


def enabled(settings):
    """这道门开不开 —— 只看 `gui.edge_auth.enabled`，与"口令有没有设"是两件事。"""
    gui = (settings or {}).get("gui") or {}
    ea = gui.get("edge_auth")
    if isinstance(ea, dict):
        return bool(ea.get("enabled"))
    return bool(ea)                 # 容忍写成 `edge_auth: true` 的手改


def read_token():
    p = secret_path()
    try:
        return p.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError):
        return ""


def set_password(password):
    """写入派生值（0600）。返回落点路径 —— **返回值里不含口令也不含派生值**。"""
    p = secret_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(users.hash_password(password) + "\n", encoding="utf-8")
    try:
        p.chmod(0o600)
    except OSError:                 # Windows 上 chmod 语义有限：不因此放弃落盘
        pass
    return p


def clear_password():
    p = secret_path()
    try:
        p.unlink()
        return True
    except OSError:
        return False


def state(settings):
    """三态 + 一句给人看的话。`no_secret` 是**必须点名**的降级（本仓"绝不静默降级"的规矩）。"""
    if not enabled(settings):
        return "off", "未启用（`gui.edge_auth.enabled` 为假）"
    if not read_token():
        return "no_secret", (f"已启用但**没有口令** → 现在所有请求都会被 401 拒；设置：{SET_HINT}")
    return "ready", f"已启用，口令已设置（用户名 {EDGE_USER}，派生值落在 {SECRET_FILE}，0600）"


def _split_basic(header):
    """`Authorization: Basic <b64>` → `(用户名, 口令)`；形态不对返回 `("", "")`。"""
    text = str(header or "").strip()
    scheme, _, rest = text.partition(" ")
    if scheme.lower() != "basic" or not rest.strip():
        return "", ""
    try:
        pair = base64.b64decode(rest.strip(), validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return "", ""
    # 用户名按 RFC 7617 不得含 `:`，所以只能在**第一个**冒号处切：口令里的冒号要保留
    name, _, password = pair.partition(":")
    return name, password


def verify(header):
    """校验一条 Basic 头。口令错、用户名错、派生值缺失/坏 —— 一律 False，不抛。"""
    stored = read_token()
    if not stored:
        return False
    name, password = _split_basic(header)
    # 两项**都算完**再合并：短路返回会让"用户名错"比"口令错"快 20 万次迭代，
    # 那是 `users._dummy_verify` 挡过的同一类计时侧信道
    ok_user = users.const_eq(name, EDGE_USER)
    ok_pass = users.verify_password(stored, password)
    return ok_user and ok_pass


def challenge_headers():
    """401 的响应头（body 由调用方拼，`scanner/` 这一层刻意不依赖 flask）。"""
    return [
        ("WWW-Authenticate", f'Basic realm="{REALM}", charset="UTF-8"'),
        ("Content-Type", "text/plain; charset=utf-8"),
        ("X-Content-Type-Options", "nosniff"),
    ]


# ---- 命令行入口：`python -m scanner.edgeauth --set | --status | --clear` ----

def _display_path():
    from scanner import utils
    return utils.rel_display(secret_path())


def _main(argv=None):
    ap = argparse.ArgumentParser(
        prog="python -m scanner.edgeauth",
        description="401 边缘认证门的口令管理（用户名固定为 `%s`）" % EDGE_USER)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--set", action="store_true", help="交互式设置口令（不回显、不落任何文件）")
    g.add_argument("--status", action="store_true", help="看有没有设置过（只报有无，不报值）")
    g.add_argument("--clear", action="store_true", help="删除派生值文件")
    a = ap.parse_args(argv)

    if a.status:
        print(f"边缘口令：{'已设置' if read_token() else '未设置'}"
              f"    用户名：{EDGE_USER}    派生值落点：{_display_path()}")
        return 0
    if a.clear:
        if not secret_path().exists():
            print("没有可删除的派生值文件。")
            return 0
        if clear_password():
            print("已删除派生值；`gui.edge_auth.enabled` 仍为真时，所有请求都会被 401 拒。")
        else:
            print("删除失败（权限？），文件保持原样。")
        return 0

    # --set：口令只从 getpass 来，两次输入不一致就放弃（不写文件）
    if not sys.stdin.isatty():
        print("[!] 非交互环境不做代填 —— 请在自己的终端里跑这条命令。")
        return 1
    pw = getpass.getpass(f"边缘口令（用户名 {EDGE_USER}，至少 {users.MIN_PASSWORD_LEN} 位）：")
    ok, why = users.validate_password(pw, EDGE_USER)
    if not ok:
        print(f"[!] 口令不合格：{why}")
        return 1
    if pw != getpass.getpass("再输一次确认："):
        print("[!] 两次输入不一致，未做任何修改。")
        return 1
    set_password(pw)
    print(f"已写入派生值（0600）：{_display_path()}")
    print("下一步：改 `config/settings.yaml` 的 `gui.edge_auth.enabled: true` 并重启控制台。")
    print("提示：明文 HTTP 下 Basic 会把口令随每个请求带出去，跨不可信链路请上 TLS 反代。")
    return 0


if __name__ == "__main__":
    sys.exit(_main())
