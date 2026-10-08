#!/usr/bin/env python3
"""CTFScanner 命令行客户端：导入目标文件 -> 全自动流水线执行。

示例：
  python cli/client.py -f examples/targets.txt                  # 全阶段
  python cli/client.py -t http://testphp.vulnweb.com/ -p probe,vulnscan
  python cli/client.py -f targets.txt --offline                 # 不调用外部工具
  python cli/client.py -f targets.txt --report logs/report.md   # 结束后出 Markdown 报告
  python cli/client.py --check                                  # 检查外部工具可用性
  python cli/client.py --update-tools                           # 联网下载/更新 subfinder/httpx/puredns
  python cli/client.py --bootstrap                            # 迁移自举：按平台点清/补齐环境依赖（加 --bootstrap-install 才联网）
  python cli/client.py --resume-task 12                         # 续跑任务 #12 的断点
"""
import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner import auth as taskauth
from scanner import db
from scanner import keystore
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
          # 续126：flag 候选单独报数并注明**不是结论**（同形状大量是模板/JS 占位符）
          f"flag 候选 {len(ctx.results.get('flags', []))}（按形状抽取，需人工判真）| "
          f"线索 {len(ctx.results.get('leads_intel', [])) + len(ctx.results.get('leads_heuristic', [])) + len(ctx.results.get('leads_github', []))}"
          f"（情报/启发式/GitHub，非漏洞结论）")
    print(f"    日志：{rel_display(ctx.workdir / 'task.log')}")
    print(f"    数据库：{rel_display(db.DB_PATH)}")


def _emit_reports(args, task_id, settings):
    """按 `--report*` 参数导出报告（四条入口共用）。

    `--full-report` 只影响 MD / HTML / PDF 的**资产小节上限**（默认每节 100/200 条，续56 起
    被截断时会在小节标题里写明总数）：续59-2 给报告加了「完整版」出口，CLI 侧就是它。
    JSONL 本来就是全量（机器格式），不受此开关影响。
    """
    full = bool(getattr(args, "full_report", False))
    if args.report:
        md = generate(task_id, full=full)
        if md:
            out = resolve(args.report)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(md, encoding="utf-8")
            print(f"[*] 报告已生成：{rel_display(out)}")
    if args.report_html:
        body = generate_html(task_id, full=full)
        if body:
            out = resolve(args.report_html)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(body, encoding="utf-8")
            print(f"[*] HTML 报告已生成：{rel_display(out)}")
    if args.report_pdf:
        out = resolve(args.report_pdf)
        ok, err = export_pdf(task_id, out, settings, full=full)
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
            rows.append((name, f"OK（{rel_display(bin_path)}）"))
        else:
            rows.append((name, f"找到 {rel_display(bin_path)} 但未通过版本校验（自动使用内置兜底）"))

    # 只列**默认就会用**的那些。afrog 也在 toolmgr.TOOLS 里（能下载/校验/更新），续121 起
    # vulnscan 也**会**调它 —— 但那是"用户在策略里显式勾了、且备好了 PoC 目录"之后的事，
    # 而且它没有内置兜底这回事（缺它就是这一轮外部检测不做），所以印成
    # "未找到（自动使用内置兜底）"仍然是假话。它的状态在 GUI「外部工具」页与 `run_bootstrap`
    # 清单里如实展示；这一列不给它，改由 `--check-afrog-pocs` 自查（见下面那个函数）。
    for t in ("subfinder", "httpx"):
        p = which(settings.get("tools", {}).get(t, t))
        _row(t, p, verify_tool(p) if p else False)
    pd = which(settings.get("tools", {}).get("puredns", "puredns"))
    rows.append(("puredns", f"OK（{rel_display(pd)}）" if pd else "未找到（自动使用内置兜底）"))
    # 端口扫描的两个外部引擎（portscan 阶段）。
    # nmap 可以走版本握手：实测 `nmap -version` → rc=0（7.98）。
    # fscan **必须跳过握手**：它的 `-h` 是"指定主机"而非 help，也没有 `-version`，
    # 拿默认的 `-version` 去探只会把装好的 fscan 误报成"未通过版本校验"。
    # 与 puredns 一样，只判定"二进制在不在"。
    nm = which(settings.get("tools", {}).get("nmap", "nmap"))
    _row("nmap", nm, verify_tool(nm) if nm else False)
    fs = which(settings.get("tools", {}).get("fscan", "fscan"))
    rows.append(("fscan", f"OK（{rel_display(fs)}；调用带 -np -nobr -nopoc）" if fs
                 else "未找到（自动回退 nmap / 内置 TCP connect）"))
    dm = settings.get("tools", {}).get("dirmap", {}) or {}
    # 缺省值必须与 `scanner/config.py` 的 DEFAULTS 同一处口径（本仓既定 `tools/dirmap/`）：
    # 写死第三方项目的历史目录名 `dirmap-master`，就等于"用户照文档装完，这一行仍然说缺少"。
    dm_script = resolve(dm.get("script", "") or "tools/dirmap/dirmap.py")
    rows.append(("dirmap", "OK" if dm_script.exists() else f"缺少 {rel_display(dm_script)}（自动使用内置兜底）"))
    return rows


def do_update_tools(args):
    """`--update-tools`：显式联网下载/更新外部工具（subfinder/httpx/puredns）。

    **联网只发生在这里**（以及 GUI「外部工具」页的按钮）—— 扫描期任何阶段都不会调用
    `scanner.toolmgr` 的 `install`/`update`（红线见 scanner/toolmgr.py 文件头，测试用变异钉住）。
    装完默认把 `config/settings.yaml` 的 `tools.<名>` 改成刚装好的相对路径 —— 否则
    "装了但 which() 找不到"，等于白装。
    """
    from scanner import toolmgr
    names = [t.strip() for t in (args.tool or []) if t.strip()]
    unknown = [t for t in names if t not in toolmgr.TOOLS]
    if unknown:
        print(f"[!] 不支持的工具：{','.join(unknown)}（可选：{'、'.join(toolmgr.TOOLS)}）")
        sys.exit(1)
    os_label, arch = toolmgr.host_arch()
    print(f"[*] 外部工具更新：平台 {os_label}/{arch}"
          f"（{'允许未校验安装' if args.allow_unverified else '默认必须通过校验和'}；"
          f"{'仅下载，不写回配置' if args.no_wire else '装好后写回 config/settings.yaml'}）")
    results = toolmgr.update(names or None, dest_dir=args.tools_dest,
                             allow_unverified=args.allow_unverified,
                             wire=not args.no_wire)
    bad = 0
    for r in results:
        tag = r.get("version") or "-"
        if not r.get("ok"):
            bad += 1
            print(f"  {r['tool']:<10} 未安装：{r.get('reason') or '未知原因'}")
            continue
        mark = "SHA256 已校验" if r.get("verified") else "**未校验**，按你的显式要求"
        print(f"  {r['tool']:<10} OK  {tag}（{mark}）→ {r['path']}")
        if r.get("wired") is False and r.get("reason"):
            print(f"     注意：{r['reason']}")
    if bad:
        print(f"[!] {bad} 个工具未安装成功（原因见上；内置兜底仍然可用）")
        sys.exit(1)


def do_check_updates(args):
    """`--check-updates`：查各外部工具**是否有新版本**（续87，**显式触发才联网**）。"""
    from scanner import toolmgr
    rows = toolmgr.check_updates(load_settings())
    print("外部工具版本检查（联网查 GitHub release 的最新 tag，与本机 `-version` 比对）：")
    n = 0
    for r in rows:
        if not r["installed"]:
            print(f"  {r['tool']:<10} {r['reason']}")
            continue
        if r["has_update"]:
            n += 1
            print(f"  {r['tool']:<10} **有新版本 {r['latest']}**（本机 {r['installed']}）")
        elif r["reason"]:
            print(f"  {r['tool']:<10} {r['reason']}（本机 {r['installed']}）")
        else:
            print(f"  {r['tool']:<10} 已是最新（{r['installed']}）")
    print(f"  → {n} 个有新版本" + ("；用 `--update-tools` 更新" if n else ""))


def do_rollback(args):
    """`--rollback <工具>`：把工具回滚到**上一次安装前**的版本（续86）。

    备份是 `install()` 在原子替换前写的 `<可执行名>.bak`；回滚是**对调**（可逆）。
    """
    from scanner import toolmgr
    names = [t.strip() for t in (args.rollback or []) if t.strip()]
    unknown = [t for t in names if t not in toolmgr.TOOLS]
    if unknown:
        print(f"[!] 不支持的工具：{','.join(unknown)}（可选：{'、'.join(toolmgr.TOOLS)}）")
        sys.exit(1)
    bad = 0
    for name in names:
        r = toolmgr.rollback(name)
        if not r.get("ok"):
            bad += 1
            print(f"  {name:<10} 回滚失败：{r.get('reason') or '未知原因'}")
            continue
        print(f"  {name:<10} 已回滚 → {r['path']}")
        if r.get("reason"):
            print(f"     注意：{r['reason']}")
    if bad:
        print(f"[!] {bad} 个工具未能回滚（原因见上）")
        sys.exit(1)


def do_tool_versions(args):
    """`--tool-versions <工具>`：列出该工具**版本库里存过的版本**（续94，**不联网**）。

    版本库是 `install()` / `use_version()` 在替换前留下的历史副本；`*` 标出"当前在用的那一份"
    （按文件内容哈希判，不是比版本号）。
    """
    from scanner import toolmgr
    names = [t.strip() for t in (args.tool_versions or []) if t.strip()] or list(toolmgr.TOOLS)
    unknown = [t for t in names if t not in toolmgr.TOOLS]
    if unknown:
        print(f"[!] 不支持的工具：{','.join(unknown)}（可选：{'、'.join(toolmgr.TOOLS)}）")
        sys.exit(1)
    print(f"外部工具版本库（{toolmgr.DEFAULT_DEST}/{toolmgr.VERSIONS_DIRNAME}/，不联网）：")
    for name in names:
        rows = toolmgr.list_versions(name)
        if not rows:
            print(f"  {name:<10} （空 —— 还没通过 --update-tools 装过，或问不出版本号未归档）")
            continue
        print(f"  {name:<10} " + "  ".join(
            ("*" + r["version"]) if r["active"] else r["version"] for r in rows))
    print(f"  → 切版本用 `--tool-use <工具>=<版本>`（同样不联网；切换可逆）")


def do_tool_use(args):
    """`--tool-use <工具>=<版本>`：切到版本库里已有的版本（续94，**不联网**）。

    与 `--rollback` 的区别：回滚只能退**一步**（`.bak`），这里能在任意存过的版本之间来回切。
    切换前会把当前这一份先归档 + 写 `.bak`，所以**可逆**。
    """
    from scanner import toolmgr
    bad = 0
    for spec in (args.tool_use or []):
        if "=" not in spec:
            print(f"[!] 格式应为 <工具>=<版本>，实到：{spec}")
            bad += 1
            continue
        name, _, ver = spec.partition("=")
        name, ver = name.strip(), ver.strip()
        if name not in toolmgr.TOOLS:
            print(f"[!] 不支持的工具：{name}（可选：{'、'.join(toolmgr.TOOLS)}）")
            bad += 1
            continue
        if not ver:
            print(f"[!] {name}：版本号不能为空")
            bad += 1
            continue
        r = toolmgr.use_version(name, ver)
        if not r.get("ok"):
            bad += 1
            print(f"  {name:<10} 切换失败：{r.get('reason') or '未知原因'}")
            continue
        print(f"  {name:<10} 已切到 {ver} → {r['path']}")
        if r.get("pruned"):
            print(f"     版本库超出上限，已删除更旧的：{'、'.join(r['pruned'])}")
        if r.get("reason"):
            print(f"     注意：{r['reason']}")
    if bad:
        print(f"[!] {bad} 项未能切换（原因见上）")
        sys.exit(1)


def do_nodes(args):
    """节点管理（续80）：新建 / 列出 / 吊销执行节点。

    令牌**只在新建时显示一次**（库里只存 sha256）；丢了就吊销重建。
    """
    from scanner import nodes
    if args.node_add:
        nid, token = nodes.create(args.node_add)
        if nid is None:
            print(f"[!] {token}")
            sys.exit(1)
        print(f"[*] 已新建节点 #{nid}：{args.node_add}")
        print("    令牌（**只显示这一次**，请立刻保存）：")
        print(f"    {token}")
        print("    节点端启动（在**节点机器**上跑）：")
        print(f"      py -3 run_node.py --controller http://<控制端>:5000 "
              f"--token {token} --name {args.node_add}")
        return
    if args.node_revoke:
        nodes.revoke(args.node_revoke)
        print(f"[*] 已吊销节点 #{args.node_revoke}（该令牌立刻失效）")
        return
    rows = nodes.list_all()
    if not rows:
        print("（还没有任何节点；用 --node-add <名> 新建）")
        return
    now = time.time()
    print("ID   名称                 状态       在线  当前任务  最后心跳")
    for r in rows:
        on = "是" if nodes.is_online(r, now=now) else "否"
        print(f"{r['id']:<4} {r['name']:<20} {(r['status'] or '-'):<10} "
              f"{on}    #{r['current_task'] or 0:<8} {r['last_seen'] or '-'}")


def do_migrate(args):
    """扫描数据导出 / 导入（续136）的实现入口：拼参数、打摘要，返回退出码。

    口径不在这里写第二遍 —— 默认带什么、不带什么、为什么，全部见 `scanner/migrate.py` 文件头。
    """
    from scanner import migrate

    if args.export_scan is not None:
        ids = [int(x) for x in str(args.only_tasks or "").replace("，", ",").split(",")
               if x.strip().isdigit()]
        pw = ""
        if args.encrypt_bundle:
            pw = migrate.bundle_passphrase()
            if not pw:
                # 不做"没给口令就默默导一份明文包"：那样用户以为包里是加密的，实际发出去的是明文。
                print(f"[!] --encrypt-bundle 需要口令，但环境变量 "
                      f"{migrate.ENV_BUNDLE_PASSPHRASE} 没设 —— 已停止，没写出任何文件。")
                print(f"    做法：{migrate.ENV_BUNDLE_PASSPHRASE}='一句口令' "
                      "python cli/client.py --export-scan --encrypt-bundle")
                print("    （口令不要写进命令行参数本身：argv 会留在 ps / history / "
                      "/proc/<pid>/cmdline 里）")
                return 1
        try:
            info = migrate.export_bundle(dst=(args.export_scan or None), task_ids=ids or None,
                                         with_users=args.with_users,
                                         with_task_auth=args.with_task_auth,
                                         passphrase=pw or None, with_logs=args.with_logs)
        except OSError as e:
            print(f"[!] 导出失败：{e}")
            return 1
        inc = info["includes"]
        assets = " | ".join(f"{t} {n}" for t, n in inc["assets"].items() if n) or "（无资产）"
        print(f"[*] 迁移包已写出：{rel_display(Path(info['path']))}"
              f"（{info['bytes'] / 1024:.1f} KB，权限 0600）")
        print(f"    任务 {inc['tasks']} 条｜{assets}")
        print(f"    账号表（口令/令牌哈希）与 config 凭据文件："
              + ("**已打进包**" if inc["accounts"] else "不带")
              + (f"（实际带上：{', '.join(inc['credential_files_present'])}）"
                 if inc.get("credential_files_present") else ""))
        if inc.get("accounts_absent"):
            print(f"    [!] 本机库里没有这些表，这一档没数据可带：{', '.join(inc['accounts_absent'])}")
        print(f"    任务登录态请求头：" + ("保留" if inc["task_auth"]
                                    else f"已剥掉 {inc['task_auth_stripped']} 条"))
        if inc.get("log_paths_dropped"):
            print(f"    任务日志路径：{inc['log_paths_dropped']} 条落在本项目根之外，"
                  "包里已置空（不把本机目录结构带出去）")
        if inc.get("encrypted"):
            print("    整包已**加密**（CTFSCANNER-BUNDLE-V1）：解包要同一个口令，"
                  "没口令时这个文件与一堆随机字节无异。")
        if inc.get("logs"):
            print(f"    任务日志：带上 {inc.get('logs_included', 0)} 个"
                  f"（{inc.get('logs_bytes', 0) / 1048576:.1f} MB）"
                  + (f"，跳过 {inc['logs_skipped']} 个（越出 logs/、超上限或读不到）"
                     if inc.get("logs_skipped") else ""))
        elif inc.get("logs_skipped"):
            print(f"    任务日志：没带（--with-logs 没开）")
        else:
            print("    另：`logs/` 下的任务日志、报告、截图**不在包里**（包只装库里的行）—— "
                  "要带日志加 --with-logs，要连报告截图就整目录拷 `logs/`")
        if inc["accounts"]:
            print("    [!] 这份文件现在**能登录被迁走的那套系统**（含口令哈希与第三方接口凭据）。"
                  "别把它发进群里 / 传网盘 / 提交进仓库；用完请删，两台机器都归你时才这样导。")
        else:
            print("    提示：账号与凭据**不在包里** —— 新机器请自己 `run_users.py` 建账号、"
                  "`run_keys.py` 配第三方接口 key，迁移包不该替你做这件事。")
        return 0

    try:
        res = migrate.import_bundle(args.import_scan, dry_run=args.dry_run,
                                    passphrase=migrate.bundle_passphrase() or None)
    except ValueError as e:
        print(f"[!] 导入中止：{e}")
        snap = getattr(e, "snapshot", None)
        if snap:
            print(f"    整库快照：{rel_display(Path(snap))}｜要退回就把它复制回 "
                  f"{rel_display(db.DB_PATH)}（GUI/CLI 得先停，别在被退回的库上继续写）")
        return 1
    tag = "试算（dry-run，不写任何数据行）" if res["dry_run"] else "完成"
    print(f"[*] 导入{tag}：任务 {len(res['tasks'])} 条｜资产 "
          f"{sum(res['assets'].values())} 行（{', '.join(f'{t} {n}' for t, n in res['assets'].items()) or '无'}）")
    if res["tasks"] and not res["dry_run"]:
        print("    任务 id 映射（包里的旧号 → 本机新号，**旧号一概不覆盖**）："
              + "，".join(f"#{o}→#{n}" for o, n in sorted(res["tasks"].items(),
                                                        key=lambda kv: int(kv[0]))))
        print(f"    整库快照：{rel_display(Path(res['snapshot']))}（出过事就退回这里）")
    if res["users"]["added"] or res["users"]["skipped"]:
        print(f"    账号：新增 {res['users']['added']}，跳过 {res['users']['skipped']}"
              "（本机已有同名 = 不覆盖它的口令哈希）")
    if res["nodes"]["added"] or res["nodes"]["skipped"]:
        print(f"    节点：新增 {res['nodes']['added']}，跳过 {res['nodes']['skipped']}")
    for c in res["credentials"]:
        print(f"    凭据文件 {c['file']}：{c['status']}（{c['reason']}）")
    lg = res.get("logs") or {}
    if lg:
        _key = "打算写" if res["dry_run"] else "已写到"
        print(f"    任务日志：{_key} {lg.get('would_write' if res['dry_run'] else 'written', 0)} 个"
              f" → {rel_display(Path(lg['dir']))}（同名不覆盖、0600；"
              f"跳过 {lg.get('skipped', 0)}、越界拒绝 {lg.get('refused', 0)}）")
    for w in res["warnings"]:
        print(f"    [!] {w}")
    return 0


def check_afrog_pocs(settings, poc_dir=None):
    """自查某个 afrog PoC 目录里**有多少条模板真会被喂给外部引擎**，以及每条被拒的原因。

    为什么要这个入口：策略页那个开关背后是"外部引擎 + 只读闸门"，闸门在 `scanner/afrog.py`
    里逐份 YAML 判请求语义。没有自查入口的话，用户只能看到"命中 0 条"，分不清
    「我的目录里根本没有只读模板」与「模板都对，但目标确实没这些东西」—— 这两件事差得很远。
    本函数**只读本地文件**：不发任何请求，也不改任何配置。
    """
    import os.path as _ospath
    from collections import Counter
    from pathlib import Path as _Path
    from scanner import afrog as afrog_mod, extcost
    d = (poc_dir or afrog_mod.cfg(settings)["poc_dir"] or "").strip()
    if not d:
        print("[!] 没有 PoC 目录：`python cli/client.py --check-afrog-pocs <目录>`，"
              "或在策略配置里填 afrog.poc_dir")
        return 1
    from scanner.config import resolve as _resolve
    if not _Path(d if _ospath.isabs(d) else str(_resolve(d))).is_dir():
        # 目录不存在**不能记成"拒收 1 个"** —— 那是"没东西可查"，与"有模板但都不只读"是两回事
        print(f"[!] 目录不存在或不是目录：{rel_display(d)}")
        return 1
    allow, refuse = afrog_mod.plan(d)
    print(f"afrog PoC 目录自查：{rel_display(d)}")
    print(f"  可喂给外部引擎 {len(allow)} 个（只读 + info 级）｜拒收 {len(refuse)} 个")
    if not allow:
        print("  [!] 可喂的一个都没有 —— 就算把开关打开，vulnscan 这一轮也不会跑 afrog")
    for why, n in Counter(w for _f, w in refuse).most_common():
        print(f"    {n:4d} × {why}")
    print('  注：拒因只回答"这条模板会不会动目标"，不评价判据写得好不好；'
          "站点数/级别/限速仍由策略里的 afrog 段决定（填再大也有内置封顶）。")
    # 续128：把"这个引擎自己会发多少请求"换算成一个数字。此前闸门与日志都只说"不经本任务
    # 预算"，却没有量 —— 没有量就没法判断该把上限设在哪里，于是上限永远没人设。
    _c128 = afrog_mod.cfg(settings)
    _est128 = extcost.afrog(_c128["max_targets"], len(allow), settings)
    print(f"  {_est128['line']}（站点数按策略里的 afrog.max_targets="
          f"{_c128['max_targets']} 计）")
    if not afrog_mod.cfg(settings)["enabled"]:
        print("  当前策略里 afrog 是**关闭**的（本命令不改配置，只如实报）。")
    return 0


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
    ap.add_argument("--full-report", action="store_true",
                    help="报告资产小节**不截断**（「完整版」）：默认每节限 100/200 条（截断时"
                         "小节标题会写明总数）；需要按资产逐条核对时用。只影响 --report / "
                         "--report-html / --report-pdf，JSONL 本来就是全量")
    ap.add_argument("-H", "--header", action="append", default=[], metavar="'名称: 值'",
                    help="本次任务的**登录态请求头**，可重复（如 -H \"Authorization: Bearer xxx\"）；"
                         "只发给目标侧，第三方接口（crt.sh/FOFA/KEV/IP 反查）不带")
    ap.add_argument("--cookie", default="", metavar="COOKIE",
                    help="本次任务的 Cookie（等价 -H \"Cookie: ...\"），用于扫登录后才存在的资产")
    ap.add_argument("--check", action="store_true", help="检查外部工具可用性后退出")
    ap.add_argument("--check-afrog-pocs", nargs="?", const="", default=None, metavar="DIR",
                    help='只读自查 afrog 的 PoC 目录：多少条属于"只读 + info 级"会被喂给外部引擎、'
                         "每条被拒的原因（不发任何请求、不改配置，然后退出；目录省略则用策略里的值）")
    # ---- 外部工具版本管理（roadmap「工具版本管理」；实现见 scanner/toolmgr.py）----
    # **只有敲了 `--update-tools` 才会联网** —— 扫描期任何阶段都不会自动下载（红线见该模块文件头）。
    ap.add_argument("--update-tools", action="store_true",
                    help="联网下载/更新外部工具（subfinder/httpx/puredns）并回写 tools 配置后退出")
    ap.add_argument("--tool", action="append", default=None, metavar="NAME",
                    help="只更新指定工具，可重复（默认三个都更新）")
    ap.add_argument("--allow-unverified", action="store_true",
                    help="允许安装**没有官方校验和**的 release（默认拒绝；装了会在输出里标注「未校验」）")
    ap.add_argument("--no-wire", action="store_true",
                    help="只下载不写回 config/settings.yaml（默认写回 tools.<名> 为相对路径）")
    ap.add_argument("--tools-dest", metavar="DIR",
                    help="安装目录（默认 tools/scanner/）")
    # ---- 迁移自举（跨 Windows / Linux 换机器时用；联网只在 --bootstrap-install 时发生）----
    ap.add_argument("--bootstrap", action="store_true",
                    help="按平台点清环境缺口（解释器/pip 依赖/外部工具/浏览器）后退出；**不联网**")
    ap.add_argument("--bootstrap-install", action="store_true",
                    help="探测后执行「自动层」：pip 依赖 + toolmgr 的 TOOLS；nmap/fscan/dirmap 只打印命令、绝不代跑（见 run_bootstrap.py 文件头）")
    ap.add_argument("--resume-task", type=int, metavar="ID",
                    help="续跑**指定任务的断点**：沿用该任务已有的目标/阶段/选项与库中资产，"
                         "只重跑断点及其之后的阶段（等价 GUI 任务详情页的「续跑」按钮）。"
                         "与 -f/-t/-n/-p/--offline/--full-*/--recursive-dir/-H/--cookie 互斥")
    # ---- 分布式节点（续80）：节点管理入口 ----
    ap.add_argument("--node-add", metavar="NAME",
                    help="新建一个执行节点并打印**一次性令牌**（节点端 run_node.py 用它连控制端）")
    ap.add_argument("--node-list", action="store_true",
                    help="列出所有节点及其在线 / 占用状态")
    ap.add_argument("--node-revoke", type=int, metavar="ID",
                    help="吊销节点（令牌立刻失效）")
    ap.add_argument("--check-updates", action="store_true",
                    help="联网查各外部工具是否有新版本（只查不装；显式触发才联网）")
    # ---- 工具版本回滚（续86）----
    ap.add_argument("--rollback", action="append", default=None, metavar="NAME",
                    help="把工具回滚到上一次安装前的版本（可重复；备份是 install 时写的 .bak）")
    # ---- 多版本共存（续94，**不联网**：版本库是本机的）----
    ap.add_argument("--tool-versions", action="append", nargs="?", const="", default=None,
                    metavar="NAME",
                    help="列出该工具版本库里存过的版本（可重复；裸用＝三个都列）")
    ap.add_argument("--tool-use", action="append", default=None, metavar="NAME=VER",
                    help="切到版本库里已有的版本（可重复；不联网、可逆）")
    # ---- 扫描数据迁移（续136）：默认**不带**任何凭据，红线口径见 scanner/migrate.py 文件头 ----
    ap.add_argument("--export-scan", nargs="?", const="", default=None, metavar="FILE",
                    help="导出任务与资产成一份迁移包后退出（默认落 data/export/migration_<时间>.json，0600）。"
                         "默认不含账号表、不含 config 凭据文件、任务登录态请求头会被剥掉")
    ap.add_argument("--import-scan", metavar="FILE",
                    help="导入迁移包：任务一律给**新 id**、running/queued 归一为 stopped、"
                         "本机已有的同名账号与凭据文件**不覆盖**")
    ap.add_argument("--only-tasks", default="", metavar="IDS",
                    help="配合 --export-scan：只导这些任务 id（逗号分隔）")
    ap.add_argument("--with-users", action="store_true",
                    help="配合 --export-scan：把 users/nodes 的口令与令牌哈希 + config/keys*.yaml + "
                         "edge_auth.yaml 一起打进包。**这会让迁移包变成能登录的凭据包**，"
                         "只在两台机器都归你时用")
    ap.add_argument("--with-task-auth", action="store_true",
                    help="配合 --export-scan：保留任务里的登录态请求头（Cookie/Authorization）。"
                         "默认剥掉并打印剥了几条")
    ap.add_argument("--encrypt-bundle", action="store_true",
                    help="配合 --export-scan：整包加密成 .enc（AES-256-GCM，PBKDF2 60 万次）。"
                         "口令**只**从环境变量 CTFSCANNER_BUNDLE_PASSPHRASE 读 —— 不给"
                         "「命令行传口令」这条路：argv 会留在 ps / shell history / 别的进程可读的 "
                         "/proc/<pid>/cmdline 里（与凭据同一条口径）。导入侧同样只读该变量，"
                         "并按文件头自动识别要不要解密")
    ap.add_argument("--with-logs", action="store_true",
                    help="配合 --export-scan：把任务日志一起带走。默认不带 —— 日志里有第三方接口的"
                         "返回原文、目标响应体，甚至偶发的口令痕迹，比表里的行更适合留在本机。"
                         "只带落在 logs/ 之内的文件，单文件 5 MB / 总量 25 MB 封顶（超的计入跳过）")
    ap.add_argument("--dry-run", action="store_true",
                    help="配合 --import-scan：只报「会导入什么」，不写任何数据行（幂等建表仍会做）")
    args = ap.parse_args()

    # 不给 `--update-tools` 却给了它的附属参数 → **直接报错**，不静默忽略
    # （静默忽略会让人以为"已经按我说的装了某个工具"，实际没生效）。
    stray = [n for n, v in (("--tool", args.tool), ("--allow-unverified", args.allow_unverified),
                            ("--no-wire", args.no_wire), ("--tools-dest", args.tools_dest)) if v]
    if stray and not args.update_tools:
        print(f"[!] 这些参数只在 --update-tools 时有效：{', '.join(stray)}")
        sys.exit(1)

    # 同上口径：迁移的附属参数不许"给了却没生效"。
    _mig_stray = [(n, v) for n, v in (
        ("--only-tasks", args.only_tasks), ("--with-users", args.with_users),
        ("--with-task-auth", args.with_task_auth), ("--with-logs", args.with_logs),
        ("--encrypt-bundle", args.encrypt_bundle)) if v]
    if _mig_stray and args.export_scan is None:
        print(f"[!] 这些参数只在 --export-scan 时有效：{', '.join(n for n, _ in _mig_stray)}")
        sys.exit(1)
    if args.dry_run and not args.import_scan:
        print("[!] --dry-run 只在 --import-scan 时有效（导出不写库，本来就是只读的）")
        sys.exit(1)
    if args.export_scan is not None and args.import_scan:
        print("[!] --export-scan 与 --import-scan 不能同时给")
        sys.exit(1)

    # 迁移入口排在**凭据解锁之前**：导出不需要解开 `keys.enc.yaml`（带 --with-users 时是连密文
    # 文件本体一起搬，不解密）。拦在这儿，用户就不会在"我只是想导一份数据走"之前被问一次口令。
    if args.export_scan is not None or args.import_scan:
        sys.exit(do_migrate(args))

    # 凭据解锁（续98）：口令**只在这里要一次** —— 紧接着的 load_settings() 会把 keys
    # 读进配置，之后工作线程与 GUI 每个请求都会反复调它，绝不能再提示。没加密文件时静默通过。
    _ks = keystore.unlock()
    if not _ks["ok"] and keystore.status()["encrypted"]:
        print(f"[!] {keystore.lock_notice(_ks['reason'])}")
    settings = load_settings()
    if args.check:
        print("外部工具可用性：")
        rows = check_tools(settings)
        for name, status in rows:
            print(f"  {name:<10} {status}")
        # 一键安装入口要在**能找到它的地方**提示（此前只有"未找到"，用户没有任何安装路径）。
        missing = [n for n, s in rows if n in ("subfinder", "httpx", "puredns") and "未找到" in s]
        if missing:
            print(f"  提示：{'、'.join(missing)} 可用 `python cli/client.py --update-tools` "
                  "联网下载安装（或 GUI「外部工具」页一键更新）。")
        # 这三个**永远不在** `--update-tools` 的覆盖范围内（官方不发"可校验的单二进制产物"）。
        # 不写出来，用户会一直等一个不会出现的"一键安装"；也不必真去下载 —— 本框架不为它们发请求。
        from scanner import toolmgr
        print("  需手工安装（本框架不自动下载）：")
        for _mn, _mwhy in toolmgr.MANUAL.items():
            print(f"    {_mn:<10} {_mwhy}（步骤见 tools/scanner/README.md「手工安装」）")
        return

    if args.check_afrog_pocs is not None:
        # 只读诊断：不建任务、不发请求、不写配置。退出码要透出去（脚本据此判断"有没有可喂的模板"），
        # 所以这里用 sys.exit(...) 而不是 return —— return 会把码丢掉
        sys.exit(check_afrog_pocs(settings, args.check_afrog_pocs))
    if args.update_tools:
        do_update_tools(args)
    if args.bootstrap or args.bootstrap_install:
        # 复用既有开关（--tool/--allow-unverified/--no-wire/--tools-dest），不另立一套
        import run_bootstrap
        _bs = ["--install"] if args.bootstrap_install else []
        for _t in (args.tool or []):
            _bs += ["--only", _t]
        if args.allow_unverified:
            _bs.append("--allow-unverified")
        if args.no_wire:
            _bs.append("--no-wire")
        if args.tools_dest:
            _bs += ["--tools-dest", args.tools_dest]
        sys.exit(run_bootstrap.main(_bs))
        return
    if args.check_updates:
        do_check_updates(args)
        return
    if args.node_add or args.node_list or args.node_revoke:
        do_nodes(args)
        return
    if args.rollback:
        do_rollback(args)
        return
    if args.tool_versions:
        do_tool_versions(args)
        return
    if args.tool_use:
        do_tool_use(args)
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
    # 启动时对账（续49 语义变更）：进程重启后残留的 status='running' 孤儿任务 —— 带队列运行
    # 规格的**重新入队**（等控制台 worker 接着跑），无规格的（CLI 直跑 / 老库行）仍标 failed
    # （CLI 是前台阻塞、没有 worker，重排只会让它永远停在 queued）。见 db.reconcile_orphan_tasks。
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
