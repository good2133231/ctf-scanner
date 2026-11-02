"""本地验证四件套（续240 / 续311）：Windows / Linux / macOS 用**同一条命令**。

背景：`.venv/bin/pip` 是 Linux/macOS 路径，Windows 是 `.venv\\Scripts\\pip` ——
文档里写死任何一边都会让另一边报"不是内部或外部命令"。本启动器把路径差异吃掉：

    python dev.py setup    # 一次性：建 .venv + 装依赖（两平台同一条命令）
    python dev.py smoke    # 用 .venv 跑全量门禁（额外参数原样透传给 tests/smoke.py）
    python dev.py check    # 同步体检（tools/sync_check.py --strict，跨机同步前必跑）
    python dev.py gate     # 按本轮改动算出该跑哪些门禁组（只打印；--run 代跑）

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
  gate     按本轮改动算出该跑哪些门禁组（只打印；加 --run 直接代跑）
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
    # 那句"约 7 分钟"必须跟着参数走：带 `--only` 时它是秒级~分钟级，写死就是假话（§5.19）。
    _local308 = "--only" in extra
    print("[dev] %s tests/smoke.py（%s）…" % ("局部门禁" if _local308 else "全量门禁",
          "只跑点名的组，**不等于全量通过** —— 收尾仍要跑不带 --only 的那一次" if _local308
          else "约 7 分钟"))
    return subprocess.run([str(venv_python()), str(ROOT / "tests" / "smoke.py"), *extra],
                          cwd=str(ROOT)).returncode


def cmd_check(extra):
    # 体检不依赖 .venv（纯标准库）——用当前解释器即可
    return subprocess.run([sys.executable, str(ROOT / "tools" / "sync_check.py"),
                           "--strict", *extra], cwd=str(ROOT)).returncode


def cmd_gate(extra):
    """按 `docs/gate-map.md` 的映射表把本轮改动翻译成门禁命令（续311）。"""
    from scanner import gateplan
    run = "--run" in extra
    changed, why = gateplan.changed_paths(ROOT)
    if why:
        print(f"[gate] 拿不到改动清单（{why}）⇒ 按全量处理")
        return cmd_smoke([]) if run else 0
    if not changed:
        print("[gate] 工作树没有改动 ⇒ 不用跑（强制全量：python dev.py smoke）")
        return 0
    rows, problems = gateplan.map_rows()
    for p in problems:
        print("[gate] 警告：" + p)
    hits, groups, full = gateplan.match_changed(changed, rows)
    head = ", ".join(changed[:8]) + (" …" if len(changed) > 8 else "")
    print(f"[gate] 改动 {len(changed)} 个文件：{head}")
    if not hits:
        print("[gate] 没命中映射表任何一行 —— 若改的是共享代码，请跑全量")
        return 0
    _hitfiles = {f for h in hits for f in h["files"]}
    _rest = [f for f in changed if f not in _hitfiles]
    if _rest:
        print("[gate] 未命中映射：" + ", ".join(_rest[:8])
              + (" …" if len(_rest) > 8 else "") + "（新增/改名的文件记得补进 docs/gate-map.md）")
    for h in hits:
        print("[gate]   命中「%s」：%s ⇒ %s"
              % (h["what"], ", ".join(h["files"][:3]),
                 " ".join("[%s]" % g for g in h["groups"])))
    heavy = [h for h in hits if len(h["groups"]) >= 6]
    strict = [h for h in hits if "smoke.py" in h["what"] or "gateplan" in h["what"]]
    if heavy or strict or full:
        for r in full:
            print("[gate] 全量的理由：" + r)
        for h in heavy:
            print("[gate] 全量的理由：「%s」点名了 %d 组（含依赖），局部跑容易漏"
                  % (h["what"], len(h["groups"])))
        for h in strict:
            print("[gate] 全量的理由：「%s」是门禁自身/映射表，局部跑等于用门禁验门禁"
                  % h["what"])
        print("[gate] 建议：**跑全量**（python dev.py smoke）")
        return cmd_smoke([]) if run else 0
    print("[gate] 建议局部：python dev.py smoke --only " + ",".join(groups))
    print("[gate] 提示：报 NameError ⇒ 换成 --only <最后一个组> --prefix")
    return cmd_smoke(["--only", ",".join(groups)]) if run else 0


COMMANDS = {"setup": cmd_setup, "smoke": cmd_smoke, "check": cmd_check,
            "gate": cmd_gate}


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
