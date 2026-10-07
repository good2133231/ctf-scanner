"""管理员账号的命令行入口（续117）：看现状 / 建号 / 重设口令 / 清掉配置里的历史残留。

为什么需要它：控制台原先有一条"引导口令"（`config/settings.yaml` 的 `gui.token`）—— 那是
多用户（续46）之前唯一的登录入口，后来被留成"库里没账号时的救命门"。但那个文件**被 git 跟踪**、
仓库是公开的，明文口令写进去就等于把管理员入口交给每个读者；而它唯一非用不可的场景
（新环境第一次登录）用一次交互式建号就能覆盖。续117 于是把那条门整支摘掉，改成：

- 首次启动（库里 0 个账号 + 终端可交互）→ `gui/app.py::serve()` 里直接向导建管理员；
- 非交互环境（容器 / 只读挂载 / CI），或事后忘了口令、被登录锁定挡在门外 → **跑本文件**。

建号与改口令的规则集中在 `scanner/admin_setup.py`（两个入口共用一份判据）。三条纪律：
口令只从 `getpass`（不回显、不进 shell 历史）或 `CTFSCANNER_ADMIN_PASSWORD` 来，
**任何输出里都不出现口令值**，落库的只有 PBKDF2 派生值，配置文件一律不碰。

用法：
    python run_users.py --status                    # 账号数 + 配置里是否还有历史残留（不打印任何值）
    python run_users.py --create-admin [用户名]      # 建一个管理员（默认用户名 admin）
    python run_users.py --reset-password 用户名      # 重设已存在账号的口令
    python run_users.py --purge-legacy-token         # 删掉 settings.yaml 里已废弃的 gui.token 残留
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from scanner import admin_setup, config as scfg, users  # noqa: E402


def _legacy_keys():
    """配置文件里残留的 gui 登录键名（**只看键名，绝不取值**）。"""
    gui = (scfg.load_settings().get("gui") or {})
    return [k for k in ("token", "token_hash") if str(gui.get(k) or "").strip()]


def do_status(_args):
    n = users.count_users()
    admins = users.count_enabled_admins()
    print(f"[*] 账号：共 {n} 个，其中启用中的管理员 {admins} 个")
    if n == 0:
        print("    库里还没有账号 —— 此时控制台**无人能登录**（旧版那条配置引导口令已在续117 摘掉）。")
        print("    建第一个：python run_users.py --create-admin")
    elif admins == 0:
        print("[!] 没有启用中的管理员：策略配置 / POC 管理 / 账号管理都进不去。")
        print("    补救：python run_users.py --create-admin，或 --reset-password <已有用户名>")
    legacy = _legacy_keys()
    if legacy:
        print(f"[!] config/settings.yaml 里还留着**已不再被读取**的 gui 登录键：{legacy}（值不打印）。")
        print("    它仍在被 git 跟踪的文件里 —— 清掉：python run_users.py --purge-legacy-token")
    else:
        print("[+] settings.yaml 的 gui 段里没有任何登录凭据。")
    return 0


def do_create_admin(args):
    ok, msg = admin_setup.create_admin(args.create_admin, admin_setup.read_password(
        (args.create_admin or admin_setup.DEFAULT_NAME)))
    if not ok:
        print(f"[!] {msg}")
        return 1
    print(f"[+] {msg}")
    print("[+] 现在用这个用户名 + 刚设的口令登录控制台即可。")
    return 0


def do_reset_password(args):
    ok, msg = admin_setup.reset_password(args.reset_password,
                                         admin_setup.read_password(args.reset_password))
    if not ok:
        print(f"[!] {msg}")
        return 1
    print(f"[+] {msg}")
    print("[*] 登录失败锁定按 IP 与用户名计数（`scanner/login_guard.py`）：如果这台机器上该用户名"
          "已计满，等窗口过了再登，或 `python -m scanner.login_guard` 清理。")
    return 0


def do_purge_legacy_token(_args):
    """删掉 gui 段里**已不再被代码读取**的两个键（显式动作，不在启动时自动做）。"""
    legacy = _legacy_keys()
    if not legacy:
        print("[*] 没有残留，什么都没改。")
        return 0
    removed = scfg.remove_settings_keys(*[("gui", k) for k in legacy])
    print(f"[+] 已从 config/settings.yaml 删掉 {removed}（值从头到尾没打印过）。")
    print("[*] 该文件被 git 跟踪：如果这个口令以前**提交并推送过**，删掉当前值不等于收回历史 —— "
          "要看一眼 GitHub 上的提交记录，必要时重写历史或换用其它部署方式。")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="CTFScanner 管理员账号的命令行入口（口令只落哈希）")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--status", action="store_true",
                   help="看现状：账号数 + 配置里是否还有历史残留（不打印任何值）")
    g.add_argument("--create-admin", metavar="用户名", nargs="?", const=admin_setup.DEFAULT_NAME,
                   help="建一个管理员账号（默认用户名 admin），口令隐式输入")
    g.add_argument("--reset-password", metavar="用户名", help="重设已存在账号的口令")
    g.add_argument("--purge-legacy-token", action="store_true",
                   help="删掉 settings.yaml 里已废弃的 gui.token / gui.token_hash 残留")
    args = ap.parse_args(argv)
    if args.status:
        return do_status(args)
    if args.create_admin is not None:
        return do_create_admin(args)
    if args.reset_password:
        return do_reset_password(args)
    return do_purge_legacy_token(args)


if __name__ == "__main__":
    sys.exit(main())
