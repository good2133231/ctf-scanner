"""401 边缘认证门（HTTP Basic）。

为什么存在：`config/settings.yaml` 的 `gui.host` 现在是 `0.0.0.0`（用户 2026-10-08 点名），
控制台不再只监听回环 —— 任何能路由到这台机器 5000 端口的人都打得到登录页。这道门在
**任何路由逻辑之前**把不带 Basic 凭据的请求退回 401，于是登录页、验证码、`login_guard`
的失败计数都不会再被陌生流量碰到。

与 AGENTS.md §5.10 的冲突是**用户明确批准的豁免**：那一条写「新增任何"绕过账号的登录路"
都算违反本条」，而本模块正是一条独立于 `users` 表的登录路。豁免记在 §5.10 原地。

口令放哪（用户 2026-10-08 定了两次，最终口径）：**明文写在 `config/edge_auth.yaml` 里**，
体验就是"改配置文件就行"。这个文件**与 `config/keys.yaml` 同类，进 `.gitignore`** —— 不是
吹毛求疵：`config/settings.yaml` 被 git 跟踪、而仓库是公开的（AGENTS.md §2「不带凭据访问
GitHub API 就是 200」），明文口令写进那儿再 `git add -A` 一次就等于交给全世界，且
**git 历史不会忘**，事后删行没用。所以开关在 `settings.yaml`（只有 `enabled: true/false`），
凭据在 `edge_auth.yaml`（只有口令），两个文件的用途由 `.gitignore` 分开。

四条设计边界：

① **口令不出现在任何被跟踪文件里**，也不出现在任何输出、日志、异常消息里。`status()` /
   `state()` 只回"有/无"。
② **fail-closed**：`enabled: true` 而文件缺失/为空 = 一律 401，启动横幅点名怎么补。
   空口令本身**不算凭据** —— `const_eq("", "")` 会为真，所以读到的 stored 为空就直接拒。
③ **用户名固定 `edge`，不参与存储**：它是代码常量，不是秘密。401 的响应体刻意**不写**用户名
   （`WWW-Authenticate` 已经暴露"这里有一道 Basic 门"，再把用户名印出来等于把爆破面从
   「用户名+口令」收窄到只剩口令 —— 与 `login_guard` 那条"被锁文案与账号是否存在无关"同取向）。
④ **通过后在会话里打标记**，不每个请求重读+重比：`app.js` 是轮询式的（状态/日志/页签），
   逐请求走一遍校验没意义。会话本身由 `session.secret`（0600、随机 32 字节）签名。

路径走 `config.BASE_DIR` 而不是 import 期烤死：`[8v]` 已有"把 `BASE_DIR` 指到临时目录"的
测试隔离先例，沿用它可以为本模块做回归而完全不碰本机真实的 `config/`。
"""
import argparse
import base64
import binascii
import getpass
import pathlib
import sys

import yaml

from scanner import users

PASSWORD_FILE = "edge_auth.yaml"
EDGE_USER = "edge"                 # Basic 的用户名固定，只有口令是秘密
REALM = "CTFScanner"
SESSION_KEY = "edge_ok"            # 通过后打在会话里，避免每个请求重算校验（见 ④）
MIN_PASSWORD_LEN = 8               # 与 users.MIN_PASSWORD_LEN 同口径（那道门protects 的是一个真服务）

# 设置口令的那条命令 —— **全仓唯一产地**（AGENTS.md §5.14：面向用户的同一句提示只许有一个产地，
# 三处手写同一句必然漂，续124 真踩过）。401 响应体、启动横幅、CLI 输出都引这一个常量。
SET_HINT = "编辑 config/edge_auth.yaml 写 password: <口令>，或跑 python -m scanner.edgeauth --set"

# 401 的正文刻意**不写用户名**（见模块 docstring ③）。
CHALLENGE_BODY = (
    "401 需要边缘认证口令。用户名不是控制台的登录账号 —— 查看与设置：\n"
    f"    python -m scanner.edgeauth --status\n"
    f"    {SET_HINT}\n"
)


def password_path():
    """凭据文件的位置：`<项目根>/config/edge_auth.yaml`（与 `keys.yaml` 同类，`.gitignore` 内）。

    每次现读 `config.BASE_DIR` —— 测试靠改它把整个模块指向临时目录（`[8v]` 的同一手法），
    import 期烤死路径就让回归没法隔离。
    """
    from scanner import config
    return pathlib.Path(str(config.BASE_DIR)) / "config" / PASSWORD_FILE


def enabled(settings):
    """这道门开不开 —— 只看 `gui.edge_auth.enabled`，与"口令有没有写"是两件事。"""
    gui = (settings or {}).get("gui") or {}
    ea = gui.get("edge_auth")
    if isinstance(ea, dict):
        return bool(ea.get("enabled"))
    return bool(ea)


def read_password():
    """读出明文口令；文件缺失/坏/空一律返回空串（**不抛** —— 抛出去会把启动打断）。"""
    p = password_path()
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError):
        return ""
    if not isinstance(data, dict):
        return ""
    return str(data.get("password") or "").strip()


def set_password(password):
    """按 YAML 规则写入明文口令（`safe_dump` 负责必要的引号，避免含 `#`/引号的口令被写坏）。

    返回落点路径 —— **返回值里不含口令**。
    """
    p = password_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(yaml.safe_dump({"password": str(password)}, allow_unicode=True,
                                default_flow_style=False), encoding="utf-8")
    try:
        p.chmod(0o600)
    except OSError:                 # Windows 上 chmod 语义有限：不因此放弃落盘
        pass
    return p


def clear_password():
    p = password_path()
    try:
        p.unlink()
        return True
    except OSError:
        return False


def _read_or_none():
    """`read_password()` 的别名位 —— 只为让 `wizard()` 的"有没有口令"与 `verify()` 走同一个函数。"""
    return read_password()


# ---- 启动时的补口令向导（形状照 `scanner/admin_setup.py::wizard()`，续117）----
# 为什么要有它：这道门 fail-closed，而"开了开关、口令还没设"这件事以前只在
# `_deploy_hints()` 的**非回环分支**里说 —— 于是绑 127.0.0.1 又开了门的人会被**静默锁死**，
# 一句提示都没有（本仓的红线恰恰是"绝不静默降级"）。首启动向导的先例是：库里 0 个账号时
# 当场问你要设什么口令，而不是让人去翻文档。
ST_DISABLED = "disabled"         # 门没开 → 一个字都不多说（默认配置必须保持安静）
ST_CONFIGURED = "configured"     # 口令已在，无事可做
ST_NO_TTY = "no-tty"             # 无终端：只能提醒，不代填（与 admin_setup 同一取舍）
ST_CANCELLED = "cancelled"       # 用户留空 / 两次输入不一致
ST_INVALID = "invalid"           # 口令不合规则
ST_SET = "set"                   # 本次交互写入成功


def wizard(settings, ask_password=None, isatty=None):
    """启动时的补口令向导。返回 `(状态, 一句话)`；**任何返回值与输出里都不含口令**。

    `ask_password` / `isatty` 可注入 —— 与 `admin_setup.wizard()` 同一理由：`serve()` 会起真
    服务器、回归调不动它，把输入口开成参数才能对每种状态做断言（含"非交互绝不代填"这条）。
    """
    if not enabled(settings):
        return ST_DISABLED, ""
    if read_password():
        return ST_CONFIGURED, ""
    tty = sys.stdin.isatty() if isatty is None else bool(isatty)
    if not tty:
        return ST_NO_TTY, (f"已启用但**没有口令** → 现在所有请求都会被 401 拒；"
                           f"非交互环境不代填口令，请补设：{SET_HINT}")
    ask = ask_password or getpass.getpass
    pw = ask(f"边缘口令（用户名 {EDGE_USER}；直接回车=这次不设，之后所有请求都会被 401 拒）：")
    if not pw:
        return ST_CANCELLED, f"本次未设置口令 → 所有请求都会被 401 拒；补设：{SET_HINT}"
    ok, why = users.validate_password(pw, EDGE_USER)
    if not ok:
        return ST_INVALID, f"口令不合格：{why}（未做任何修改，仍会一律 401）"
    if pw != ask("再输一次确认："):
        return ST_CANCELLED, f"两次输入不一致，未做任何修改 —— 仍会一律 401；补设：{SET_HINT}"
    set_password(pw)
    return ST_SET, (f"已写入 {PASSWORD_FILE}（0600、不进仓库）；Basic 用户名固定 {EDGE_USER}。"
                    "注意：明文 HTTP 下 Basic 会把口令随每个请求带出去。")


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
    """校验一条 Basic 头。口令不符、用户名不符、文件缺失/为空 —— 一律 False，不抛。"""
    stored = read_password()
    if not stored:
        # 空 stored 必须直接拒：否则 `const_eq("", "")` 会为真，"没配口令"就退化成
        # "任何人用空口令都能进" —— 那是 fail-open，与 ② 正好相反
        return False
    name, password = _split_basic(header)
    # 两项**都算完**再合并：短路返回会让"用户名错"比"口令错"快一点，
    # 那是 `users._dummy_verify` 挡过的同一类计时侧信道
    ok_user = users.const_eq(name, EDGE_USER)
    ok_pass = users.const_eq(password, stored)
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
    return utils.rel_display(password_path())


def _main(argv=None):
    ap = argparse.ArgumentParser(
        prog="python -m scanner.edgeauth",
        description="401 边缘认证门的口令（用户名固定为 `%s`；口令明文存 %s，该文件不进仓库）"
                    % (EDGE_USER, "config/" + PASSWORD_FILE))
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--set", action="store_true", help="写入口令（不回显、不进 argv、不进任何输出）")
    g.add_argument("--status", action="store_true", help="看有没有配置（只报有无，不报值）")
    g.add_argument("--clear", action="store_true", help="删除凭据文件")
    a = ap.parse_args(argv)

    if a.status:
        print(f"边缘口令：{'已配置' if read_password() else '未配置'}"
              f"    用户名：{EDGE_USER}    文件：{_display_path()}")
        return 0
    if a.clear:
        if not password_path().exists():
            print("没有可删除的凭据文件。")
            return 0
        if clear_password():
            print("已删除凭据文件；`gui.edge_auth.enabled` 仍为真时，所有请求都会被 401 拒。")
        else:
            print("删除失败（权限？），文件保持原样。")
        return 0

    # --set：口令只从 getpass 来，两次输入不一致就放弃（不写文件）
    if not sys.stdin.isatty():
        print(f"[!] 非交互环境不做代填 —— 也可以直接编辑文件：{SET_HINT}")
        return 1
    pw = getpass.getpass(f"边缘口令（用户名 {EDGE_USER}，至少 {MIN_PASSWORD_LEN} 位）：")
    ok, why = users.validate_password(pw, EDGE_USER)
    if not ok:
        print(f"[!] 口令不合格：{why}")
        return 1
    if pw != getpass.getpass("再输一次确认："):
        print("[!] 两次输入不一致，未做任何修改。")
        return 1
    set_password(pw)
    print(f"已写入（0600）：{_display_path()}")
    print("这个文件在 .gitignore 里；口令**不要**写进 config/settings.yaml —— 那文件被 git 跟踪、仓库公开。")
    print("提示：明文 HTTP 下 Basic 会把口令随每个请求带出去，跨不可信链路请上 TLS 反代。")
    return 0


if __name__ == "__main__":
    sys.exit(_main())
