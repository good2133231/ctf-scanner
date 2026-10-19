#!/usr/bin/env python3
"""logs/ 精确清理（续226）——只删**逐个点名**的临时产物。

为什么不用 `rm -rf logs/*`：`logs/` 里同时躺着
- 审计证据（`devflow_baseline.json` / `smoke-timing.jsonl` / HANDOFF / DB 备份 / access·server 日志）；
- **数据库仍在引用的任务工作目录**（`tasks.log_file` 指向的 `task_*`，里面是截图、favicon、
  JS 产物与运行日志）—— 通配符清理会把它们一起带走，页面立刻裂图、报告也复现不了。

用法：
    python tools/clean_logs.py --list
    python tools/clean_logs.py --apply <名字> [<名字> ...]

规则（刻意保守）：
- 只接受 `logs/` 的**顶层名字**；含 `* ? [ ]`、路径分隔符或 `..` 一律拒绝；
- 只允许「可删」规则命中的临时产物；「必留」/ 数据库引用的任务目录一律拒绝；
- `--apply` 必须显式列出名字，**没有**"全部/通配"开关；默认（不带 `--apply`）只列清单。
"""
import argparse
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LOGS = ROOT / "logs"

# 必留：审计证据 / 运行日志 / DB 备份（按确切名字或明确前缀）
KEEP_FILES = {"devflow_baseline.json", "smoke-timing.jsonl", "access.log", "server.log"}
KEEP_PREFIXES = ("HANDOFF-", "access.log.", "scanner.db.bak-")

# 可删：明确前缀/名字的临时产物（`task_*` 另行判断，见 classify）
CAND_PREFIXES = ("_smoke", "smoke", "h8am-", "w178b-", "verify", "profile-", "scan_")
CAND_DIRS = {"preview", "__pycache__"}


def _db_referenced_task_dirs():
    """返回 `{task_* 目录名}`：数据库里 `tasks.log_file` 仍指向的工作目录。

    库读不到（CI / 干净克隆）⇒ 返回空集，但调用方对 `task_*` 仍会**拒绝删除**
    （"读不到"不等于"没引用"）。
    """
    db_path = ROOT / "data" / "scanner.db"
    if not db_path.is_file():
        return set()
    try:
        sys.path.insert(0, str(ROOT))
        from scanner import db as _db
        rows = _db._query("SELECT log_file FROM tasks WHERE log_file<>''")
        return {Path(str(r["log_file"])).parent.name for r in rows}
    except Exception:
        return set()


def classify(name):
    """`keep` / `candidate` / `task` / `other`。顺序不能反：KEEP 先判。"""
    if name in KEEP_FILES or name.startswith(KEEP_PREFIXES):
        return "keep"
    if name.startswith("task_"):
        return "task"
    if name in CAND_DIRS:
        return "candidate"
    if name.startswith(CAND_PREFIXES):
        return "candidate"
    if name.startswith("_") and name.endswith((".py", ".json", ".txt")):
        return "candidate"
    if name.endswith(".log"):
        return "candidate"
    return "other"


def _entries():
    if not LOGS.is_dir():
        return []
    return sorted(LOGS.iterdir(), key=lambda p: p.name)


def cmd_list():
    counts = {"keep": 0, "candidate": 0, "task": 0, "other": 0}
    examples = {"candidate": [], "keep": [], "other": []}
    ref = _db_referenced_task_dirs()
    ref_hits = []
    for p in _entries():
        k = classify(p.name)
        counts[k] += 1
        if k in examples and len(examples[k]) < 8:
            examples[k].append(p.name)
        if k == "task" and p.name in ref:
            ref_hits.append(p.name)
    print(f"logs/ 顶层 {sum(counts.values())} 项：必留 {counts['keep']} / "
          f"可删候选 {counts['candidate']} / 任务目录 {counts['task']} / 其它 {counts['other']}")
    print("可删候选示例：" + "、".join(examples["candidate"] or ["（无）"]))
    print("必留示例：" + "、".join(examples["keep"] or ["（无）"]))
    if ref_hits:
        print(f"数据库仍在引用的任务目录（**禁止删**）：{'、'.join(ref_hits[:8])}"
              + (" …" if len(ref_hits) > 8 else ""))
    print("用法：python tools/clean_logs.py --apply <确切名字>；不接受通配符。")
    return 0


def cmd_apply(names):
    bad = [n for n in names
           if not n or n != Path(n).name or ".." in n or any(c in n for c in "*?[]/\\")]
    if bad:
        print(f"[拒绝] 只能是 logs/ 下的顶层确切名字（不许通配/路径）：{bad}", file=sys.stderr)
        return 2
    ref = _db_referenced_task_dirs()
    rc = 0
    for n in names:
        p = LOGS / n
        if not p.exists():
            print(f"[跳过] 不存在：{n}", file=sys.stderr)
            rc = rc or 2
            continue
        k = classify(n)
        if k in ("keep", "other"):
            print(f"[拒绝] {n} 属于「必留」或不在清理清单里", file=sys.stderr)
            rc = rc or 2
            continue
        if k == "task":
            if not ref:
                print(f"[拒绝] {n} 是任务目录，但读不到数据库引用表 —— 读不到不等于没引用",
                      file=sys.stderr)
                rc = rc or 2
                continue
            if n in ref:
                print(f"[拒绝] {n} 仍被 tasks.log_file 引用（截图/产物还在用）", file=sys.stderr)
                rc = rc or 2
                continue
        try:
            if p.is_dir():
                shutil.rmtree(p)
            else:
                p.unlink()
            print(f"[已删] {n}")
        except OSError as e:
            print(f"[失败] {n}: {e}", file=sys.stderr)
            rc = rc or 1
    return rc


def main(argv=None):
    ap = argparse.ArgumentParser(description="logs/ 精确清理（只删逐个点名的临时产物）")
    ap.add_argument("--list", action="store_true", help="列出分类与候选（默认动作）")
    ap.add_argument("--apply", nargs="+", metavar="NAME",
                    help="删除这些确切名字（必须显式列出；不接受通配符）")
    args = ap.parse_args(argv)
    if args.apply:
        return cmd_apply(args.apply)
    return cmd_list()


if __name__ == "__main__":
    sys.exit(main())
