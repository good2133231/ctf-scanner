"""本地验证三件套（续240）：Windows / Linux / macOS 用**同一条命令**。

背景：`.venv/bin/pip` 是 Linux/macOS 路径，Windows 是 `.venv\\Scripts\\pip` ——
文档里写死任何一边都会让另一边报"不是内部或外部命令"。本启动器把路径差异吃掉：

    python dev.py setup    # 一次性：建 .venv + 装依赖（两平台同一条命令）
    python dev.py smoke    # 用 .venv 跑全量门禁（额外参数原样透传给 tests/smoke.py）
    python dev.py check    # 同步体检（tools/sync_check.py --strict，跨机同步前必跑）

**没有 `gui`**：控制台只在服务器上跑（真实数据库/密钥都在那边），本地起 GUI 无意义。
不需要 activate：所有子命令都用 `.venv` 里的 python 绝对路径起子进程。
"""
import os
import subprocess
import sys
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VENV = ROOT / ".venv"

USAGE = """用法：python dev.py <命令>
  setup    建 .venv + 安装依赖（一次性；Windows/Linux 同一条命令）
  smoke    用 .venv 跑全量门禁 tests/smoke.py（额外参数原样透传）
  check    同步体检 tools/sync_check.py --strict（跨机同步/开工前必跑）
"""


def venv_python():
    """`.venv` 里的 python 解释器绝对路径（Windows 是 Scripts\\python.exe，POSIX 是 bin/python）。"""
    if os.name == "nt":
        return VENV / "Scripts" / "python.exe"
    return VENV / "bin" / "python"


def ensure_venv():
    if not venv_python().exists():
        print("[dev] 创建虚拟环境 .venv …")
        subprocess.run([sys.executable, "-m", "venv", str(VENV)], check=True)
    else:
        print(f"[dev] 已有 .venv：{venv_python()}")


def cmd_setup(_extra):
    ensure_venv()
    print("[dev] 安装依赖（requirements.txt）…")
    subprocess.run([str(venv_python()), "-m", "pip", "install",
                    "-r", str(ROOT / "requirements.txt")], check=True)
    print("[dev] 完成。跑门禁：python dev.py smoke")
    return 0


def cmd_smoke(extra):
    ensure_venv()
    print("[dev] 全量门禁 tests/smoke.py（约 7 分钟）…")
    return subprocess.run([str(venv_python()), str(ROOT / "tests" / "smoke.py"), *extra],
                          cwd=str(ROOT)).returncode


def cmd_check(extra):
    # 体检不依赖 .venv（纯标准库）——用当前解释器即可
    return subprocess.run([sys.executable, str(ROOT / "tools" / "sync_check.py"),
                           "--strict", *extra], cwd=str(ROOT)).returncode


COMMANDS = {"setup": cmd_setup, "smoke": cmd_smoke, "check": cmd_check}


def main(argv):
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(USAGE)
        return 2
    cmd, extra = argv[0], argv[1:]
    fn = COMMANDS.get(cmd)
    if fn is None:
        print(f"[dev] 未知命令：{cmd}\n{USAGE}")
        return 2
    return fn(extra)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
