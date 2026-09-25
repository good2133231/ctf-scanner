#!/usr/bin/env python3
"""CTFScanner 命令行客户端：导入目标文件 -> 全自动流水线执行。

示例：
  python cli/client.py -f examples/targets.txt                  # 全阶段
  python cli/client.py -t http://testphp.vulnweb.com/ -p probe,vulnscan
  python cli/client.py -f targets.txt --offline                 # 不调用外部工具
  python cli/client.py -f targets.txt --report logs/report.md   # 结束后出 Markdown 报告
  python cli/client.py --check                                  # 检查外部工具可用性
  python cli/client.py --resume-task 12                         # 续跑任务 #12 的断点
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner import auth as taskauth
from scanner import db
from scanner.config import load_settings, resolve
from scanner.report import export_pdf, generate, generate_html, generate_jsonl
from scanner.runner import STAGE_ORDER, STAGE_REGISTRY, resume_stages, run_task
from scanner.utils import format_duration, rel_display, which, verify_tool


def _print_summary(task_id, ctx):
    """任务结束时的统一摘要（新建 / 追加 / 续跑三条入口共用，避免副本漂移）。"""
    task = db.get_task(task_id)
    print(f"[*] 任务 #{task_id} 结束：status={task['status']} | "
          # 续35：续跑 / 追加执行会跑多段，报的是该任务的**累计**运行时长（脚本里可直接抓这一行）
          f"运行时长 {format_duration(db.task_run_seconds(dict(task)))}"
          f"（{task['started_at'] or '-'} → {task['finished_at'] or '-'}）")
    print(f"    子域名 {len(ctx.results.get('subdomains', []))} | "
          f"站点 {len(ctx.results.get('sites', []))} | "
          f"目录 {len(ctx.results.get('dirs', []))} | "
          f"潜在漏洞 {len(ctx.results.get('vulns', []))} | "
          f"线索 {len(ctx.results.get('leads_intel', [])) + len(ctx.results.get('leads_heuristic', [])) + len(ctx.results.get('leads_github', []))}"
          f"（情报/启发式/GitHub，非漏洞结论）")
    print(f"    日志：{rel_display(ctx.workdir / 'task.log')}")
    print(f"    数据库：{rel_display(db.DB_PATH)}")


def _emit_reports(args, task_id, settings):
    """按 `--report*` 参数导出报告（四条入口共用）。"""
    if args.report:
        md = generate(task_id)
        if md:
            out = resolve(args.report)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(md, encoding="utf-8")
            print(f"[*] 报告已生成：{rel_display(out)}")
    if args.report_html:
        body = generate_html(task_id)
        if body:
            out = resolve(args.report_html)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(body, encoding="utf-8")
            print(f"[*] HTML 报告已生成：{rel_display(out)}")
    if args.report_pdf:
        out = resolve(args.report_pdf)
        ok, err = export_pdf(task_id, out, settings)
        # 失败时**不静默**：打印原因并让退出码非 0（脚本里能立刻发现少了一份交付物）。
        if ok:
            print(f"[*] PDF 报告已生成：{rel_display(out)}")
        else:
            print(f"[!] PDF 报告生成失败：{err}")
            sys.exit(1)
    if args.report_jsonl:
        body = generate_jsonl(task_id)
        if body:
            out = resolve(args.report_jsonl)
            out.parent.mkdir(parents=True, exist_ok=True)
            # 用 write_bytes 而不是 write_text：Windows 文本模式会把 `\n` 翻成 `\r\n`，
            # 而 JSONL 规范要求行尾是 `\n`（`generate_jsonl()` 与 HTTP 路由产出的都是 `\n`）。
            # Python 3.9 的 `write_text` 没有 `newline` 参数，故显式写字节，保证两条导出路径
            # 字节一致。（MD / HTML 仍用 write_text —— 它们对行尾不敏感，不在本次范围内。）
            out.write_bytes(body.encode("utf-8"))
            print(f"[*] JSONL 报告已生成：{rel_display(out)}")


def do_resume(args, settings):
    """`--resume-task`：续跑已有任务的断点（等价 GUI 任务详情页的「续跑」按钮）。

    为什么**不复用** `-f/-t/-p/--offline/...`：续跑的输入是"库里已有的资产"与"任务自身记的
    阶段/选项"，这些参数一律不生效。静默忽略它们会让人以为改了参数（比如以为这次能换目标或
    加上 `--offline`），实际没变 —— 所以冲突就**直接报错退出**，不猜。
    """
    conflicts = [name for name, val in (("-f/--file", args.file), ("-t/--target", args.target),
                                        ("-n/--name", args.name), ("-p/--stages", args.stages),
                                        ("--offline", args.offline),
                                        ("--full-ports", args.full_ports),
                                        ("--full-dir", args.full_dir),
                                        ("--recursive-dir", args.recursive_dir),
                                        ("-H/--header", args.header),
                                        ("--cookie", args.cookie)) if val]
    if conflicts:
        print(f"[!] --resume-task 不能与这些参数同用：{', '.join(conflicts)}")
        print("    续跑用的是**该任务已有的**目标/阶段/选项（不会重新解析本次输入）；"
              "要换参数请新建任务。")
        sys.exit(1)

    db.init_db()
    db.reconcile_orphan_tasks()
    task = db.get_task(args.resume_task)
    if not task:
        print(f"[!] 任务 #{args.resume_task} 不存在")
        sys.exit(1)
    if task["status"] == "running":
        print(f"[!] 任务 #{args.resume_task} 正在运行，请先停止再续跑")
        sys.exit(1)
    stages = [s for s in (task["stages"] or "").split(",") if s in STAGE_REGISTRY]
    stages = stages or list(STAGE_ORDER)
    # **入口就拒绝**"没有可用断点"，不交给 `run_task` 的回退分支 —— 那条分支会**全量重跑**
    # （请求量与耗时是另一个量级），与用户"接着跑"的预期不符。GUI 路由层也是同一口径。
    rest = resume_stages(stages, task["current_stage"])
    if not rest:
        cur = (task["current_stage"] or "").strip()
        print(f"[!] 任务 #{args.resume_task} 没有可用断点"
              f"（current_stage={'（空）' if not cur else cur}）")
        print("    没有断点意味着它已跑完或从未开始；要从头重跑请新建任务（续跑不清资产）。")
        sys.exit(1)
    options = json.loads(task["options"] or "{}")
    print(f"[*] 续跑任务 #{args.resume_task}：{task['name']}"
          f"（断点 {task['current_stage']} → 本次只跑 {','.join(rest)}）")
    print("    已有资产沿用库中数据，不清空、不重扫已完成阶段。")
    ctx = run_task(args.resume_task, task["name"], task["targets"], stages, options, settings,
                   resume=True)
    _print_summary(args.resume_task, ctx)
    _emit_reports(args, args.resume_task, settings)


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
    # 端口扫描的两个外部引擎（portscan 阶段）。
    # nmap 可以走版本握手：实测 `nmap -version` → rc=0（7.98）。
    # fscan **必须跳过握手**：它的 `-h` 是"指定主机"而非 help，也没有 `-version`，
    # 拿默认的 `-version` 去探只会把装好的 fscan 误报成"未通过版本校验"。
    # 与 puredns 一样，只判定"二进制在不在"。
    nm = which(settings.get("tools", {}).get("nmap", "nmap"))
    _row("nmap", nm, verify_tool(nm) if nm else False)
    fs = which(settings.get("tools", {}).get("fscan", "fscan"))
    rows.append(("fscan", f"OK（{fs}；调用带 -np -nobr -nopoc）" if fs
                 else "未找到（自动回退 nmap / 内置 TCP connect）"))
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
    ap.add_argument("-p", "--stages", default=None,
                    help=f"逗号分隔的阶段（默认全部：{','.join(STAGE_ORDER)}）；"
                         "显式点名 cert / screenshot 时该阶段只对本次生效，不改全局策略")
    ap.add_argument("--offline", action="store_true",
                    help="离线模式：不调用 subfinder/puredns/httpx/dirmap，仅用内置实现")
    # 两个"全量档"开关都是**单次**语义（等价 GUI 的任务级选项，与建任务勾选同义）：
    # 只影响本次任务，不改全局策略。
    ap.add_argument("--full-ports", action="store_true",
                    help="本次任务端口走全端口 1-65535（等价 GUI 任务选项 portscan_full）")
    ap.add_argument("--full-dir", action="store_true",
                    help="本次任务目录走深扫：全量分层字典 + dirmap + 后缀派生"
                         "（等价 GUI 任务选项 dirscan_full）")
    ap.add_argument("--recursive-dir", action="store_true",
                    help="本次任务开启**目录递归**：对命中的目录再往下打一层（等价 GUI 任务选项 "
                         "recursive_dir + dirscan_full；额度见策略 dirscan.recursive_*）")
    ap.add_argument("--auto-expand", action="store_true",
                    help="本次任务开启**自动拓展扫描**（等价 GUI 任务选项 auto_expand）："
                         "自动补 osint/jsmine 阶段、拓展结束后自动做 DNS 存在性判定、"
                         "把注册域属于本项目的拓展域名追加成子域名；目标是子域时自动补收其主域名")
    ap.add_argument("--report", metavar="PATH", help="结束后生成 Markdown 报告到指定路径")
    ap.add_argument("--report-html", metavar="PATH", help="结束后生成 HTML 报告（自包含单文件）")
    ap.add_argument("--report-pdf", metavar="PATH",
                    help="结束后生成 PDF 报告（用本机无头 Edge/Chrome 打印；没有浏览器会明确报错）")
    ap.add_argument("--report-jsonl", metavar="PATH",
                    help="结束后生成 JSONL 报告（每行一个 JSON 对象，机器可读；漏洞含复核状态）")
    ap.add_argument("-H", "--header", action="append", default=[], metavar="'名称: 值'",
                    help="本次任务的**登录态请求头**，可重复（如 -H \"Authorization: Bearer xxx\"）；"
                         "只发给目标侧，第三方接口（crt.sh/FOFA/KEV/IP 反查）不带")
    ap.add_argument("--cookie", default="", metavar="COOKIE",
                    help="本次任务的 Cookie（等价 -H \"Cookie: ...\"），用于扫登录后才存在的资产")
    ap.add_argument("--check", action="store_true", help="检查外部工具可用性后退出")
    ap.add_argument("--resume-task", type=int, metavar="ID",
                    help="续跑**指定任务的断点**：沿用该任务已有的目标/阶段/选项与库中资产，"
                         "只重跑断点及其之后的阶段（等价 GUI 任务详情页的「续跑」按钮）。"
                         "与 -f/-t/-n/-p/--offline/--full-*/--recursive-dir/-H/--cookie 互斥")
    args = ap.parse_args()

    settings = load_settings()
    if args.check:
        print("外部工具可用性：")
        for name, status in check_tools(settings):
            print(f"  {name:<10} {status}")
        return
    # 续跑走独立入口：它不需要 `-f/-t`（输入来自库），也不该被下面"未提供目标"的判断拦掉。
    if args.resume_task is not None:
        do_resume(args, settings)
        return

    lines = list(args.target)
    if args.file:
        p = resolve(args.file)
        if not p.exists():
            print(f"[!] 目标文件不存在：{rel_display(p)}")
            sys.exit(1)
        lines.extend(p.read_text(encoding="utf-8", errors="replace").splitlines())
    if not lines:
        print("[!] 未提供目标：使用 -f 目标文件 或 -t 单目标")
        sys.exit(1)

    # `-p` 不给＝全部阶段（与旧默认值同义，行为不变）；给了＝用户**显式点名**。
    explicit = args.stages is not None
    stages = [s.strip() for s in (args.stages or ",".join(STAGE_ORDER)).split(",")
              if s.strip()]
    bad = [s for s in stages if s not in STAGE_REGISTRY]
    if bad:
        print(f"[!] 未知阶段：{','.join(bad)}（可选：{','.join(STAGE_ORDER)}）")
        sys.exit(1)

    db.init_db()
    # 启动时对账：进程重启后残留的 status='running' 孤儿任务标为 failed（见 db.reconcile_orphan_tasks）
    db.reconcile_orphan_tasks()
    name = args.name or (Path(args.file).stem if args.file else "cli-task")
    options = {"offline": bool(args.offline)}
    # 登录态请求头（任务级）：解析出问题就**直接退出**，不静默丢弃 ——
    # 少带一条 Authorization 会让"已登录扫描"变成假象（扫不到还以为本来就没洞）。
    auth_lines = list(args.header)
    if args.cookie:
        auth_lines.append(f"Cookie: {args.cookie}")
    auth_headers, auth_errors = taskauth.parse_headers("\n".join(auth_lines))
    if auth_errors:
        print("[!] 登录态请求头有误，已中止（不静默丢弃）：")
        for e in auth_errors:
            print(f"    - {e}")
        sys.exit(1)
    if auth_headers:
        options["auth"] = auth_headers
    # cert / screenshot 是**策略级默认关**的阶段。写进 `-p` 就是在说"这次要跑"，
    # 因此落成任务级开关（与 GUI 建任务勾选同一套语义：只影响本次，不改全局策略）。
    # 不点名时不加这些开关，照旧由 `settings.*.enabled` 决定 —— 不能因为 CLI 的
    # 默认 `-p` 含全部阶段就偷偷把它们打开。
    if explicit:
        for st in ("screenshot", "cert"):
            if st in stages:
                options[f"{st}_on"] = True
    if args.full_ports:
        options["portscan_full"] = True
    if args.full_dir:
        options["dirscan_full"] = True
    # 目录递归只存在于**深扫**里（浅扫不递归），所以勾它就等于点名要深扫 ——
    # 与 GUI 建任务同一套处理（`gui/app.py` 的 `api_task_create`）。
    if args.recursive_dir:
        options["recursive_dir"] = True
        options["dirscan_full"] = True
    # 自动拓展扫描（与 GUI 建任务的「自动拓展扫描」同一套语义）：勾了就等于点名要拓展，
    # 所以这里同样把 osint / jsmine 两个阶段补进 -p（否则选项生效却没有阶段去挖）。
    if args.auto_expand:
        options["auto_expand"] = True
        for st in ("osint", "jsmine"):
            if st not in stages:
                stages.append(st)
    # 与 GUI 建任务一致：选了全量档却没把对应阶段写进 -p 时**自动补上**（否则勾了等于白勾）。
    # `run_task` 按给定顺序执行、不排序，所以要按 STAGE_ORDER 归位。
    for flag, stage in (("portscan_full", "portscan"), ("dirscan_full", "dirscan")):
        if options.get(flag) and stage not in stages:
            stages.append(stage)
    stages.sort(key=STAGE_ORDER.index)
    targets_text = "\n".join(lines)
    task_id = db.create_task(name, targets_text, stages, options)
    mode = "，离线模式" if args.offline else ""
    print(f"[*] 任务 #{task_id} 开始：{name}（阶段：{','.join(stages)}{mode}）")
    if auth_headers:
        print(f"[*] 登录态请求头 {len(auth_headers)} 条："
              f"{taskauth.summary(auth_headers)}（值已掩码）")

    ctx = run_task(task_id, name, targets_text, stages, options, settings)

    _print_summary(task_id, ctx)
    _emit_reports(args, task_id, settings)


if __name__ == "__main__":
    main()
