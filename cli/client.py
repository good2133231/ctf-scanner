#!/usr/bin/env python3
"""CTFScanner 命令行客户端：导入目标文件 -> 全自动流水线执行。

示例：
  python cli/client.py -f examples/targets.txt                  # 全阶段
  python cli/client.py -t http://testphp.vulnweb.com/ -p probe,vulnscan
  python cli/client.py -f targets.txt --offline                 # 不调用外部工具
  python cli/client.py -f targets.txt --report logs/report.md   # 结束后出 Markdown 报告
  python cli/client.py --check                                  # 检查外部工具可用性
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner import db
from scanner.config import load_settings, resolve
from scanner.report import generate
from scanner.runner import STAGE_ORDER, STAGE_REGISTRY, run_task
from scanner.utils import which, verify_tool


def check_tools(settings):
    rows = []

    def _row(name, bin_path, verified):
        if not bin_path:
            rows.append((name, "未找到（自动使用内置兜底）"))
        elif verified:
            rows.append((name, f"OK（{bin_path}）"))
        else:
            rows.append((name, f"找到 {bin_path} 但未通过版本校验（自动使用内置兜底）"))

    for t in ("subfinder", "httpx"):
        p = which(settings.get("tools", {}).get(t, t))
        _row(t, p, verify_tool(p) if p else False)
    pd = which(settings.get("tools", {}).get("puredns", "puredns"))
    rows.append(("puredns", f"OK（{pd}）" if pd else "未找到（自动使用内置兜底）"))
    dm = settings.get("tools", {}).get("dirmap", {}) or {}
    dm_script = resolve(dm.get("script", "tools/scanner/dirmap-master/dirmap.py"))
    rows.append(("dirmap", "OK" if dm_script.exists() else f"缺少 {dm_script}（自动使用内置兜底）"))
    return rows


def main():
    ap = argparse.ArgumentParser(
        description="CTFScanner CLI —— 仅用于授权测试与 CTF 场景")
    ap.add_argument("-f", "--file", help="目标文件（每行一个：域名/URL/IP，# 为注释）")
    ap.add_argument("-t", "--target", action="append", default=[], help="单目标，可多次指定")
    ap.add_argument("-n", "--name", default="", help="任务名（默认取文件名或 cli-task）")
    ap.add_argument("-p", "--stages", default=",".join(STAGE_ORDER),
                    help=f"逗号分隔的阶段，可选：{','.join(STAGE_ORDER)}")
    ap.add_argument("--offline", action="store_true",
                    help="离线模式：不调用 subfinder/puredns/httpx/dirmap，仅用内置实现")
    ap.add_argument("--report", metavar="PATH", help="结束后生成 Markdown 报告到指定路径")
    ap.add_argument("--check", action="store_true", help="检查外部工具可用性后退出")
    args = ap.parse_args()

    settings = load_settings()
    if args.check:
        print("外部工具可用性：")
        for name, status in check_tools(settings):
            print(f"  {name:<10} {status}")
        return

    lines = list(args.target)
    if args.file:
        p = resolve(args.file)
        if not p.exists():
            print(f"[!] 目标文件不存在：{p}")
            sys.exit(1)
        lines.extend(p.read_text(encoding="utf-8", errors="replace").splitlines())
    if not lines:
        print("[!] 未提供目标：使用 -f 目标文件 或 -t 单目标")
        sys.exit(1)

    stages = [s.strip() for s in args.stages.split(",") if s.strip()]
    bad = [s for s in stages if s not in STAGE_REGISTRY]
    if bad:
        print(f"[!] 未知阶段：{','.join(bad)}（可选：{','.join(STAGE_ORDER)}）")
        sys.exit(1)

    db.init_db()
    name = args.name or (Path(args.file).stem if args.file else "cli-task")
    options = {"offline": bool(args.offline)}
    targets_text = "\n".join(lines)
    task_id = db.create_task(name, targets_text, stages, options)
    mode = "，离线模式" if args.offline else ""
    print(f"[*] 任务 #{task_id} 开始：{name}（阶段：{','.join(stages)}{mode}）")

    ctx = run_task(task_id, name, targets_text, stages, options, settings)

    task = db.get_task(task_id)
    print(f"[*] 任务 #{task_id} 结束：status={task['status']}")
    print(f"    子域名 {len(ctx.results.get('subdomains', []))} | "
          f"站点 {len(ctx.results.get('sites', []))} | "
          f"目录 {len(ctx.results.get('dirs', []))} | "
          f"潜在漏洞 {len(ctx.results.get('vulns', []))}")
    print(f"    日志：{ctx.workdir / 'task.log'}")
    print(f"    数据库：{db.DB_PATH}")
    if args.report:
        md = generate(task_id)
        if md:
            out = resolve(args.report)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(md, encoding="utf-8")
            print(f"[*] 报告已生成：{out}")


if __name__ == "__main__":
    main()
