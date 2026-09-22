"""任务 Markdown 报告生成（骨架版：概览 + 潜在漏洞 + 资产清单）。"""
from . import db

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _c(value):
    """Markdown 表格单元格转义：`|` 转义成 `\\|`，换行/回车压成空格。

    标题、URL、evidence 都可能带 `|` 或换行，直接拼进表格会把表格冲散。
    """
    s = str("" if value is None else value)
    return s.replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def generate(task_id):
    task = db.get_task(task_id)
    if not task:
        return None
    subs = db.list_subdomains(task_id)
    sites = db.list_sites(task_id)
    dirs = db.list_dirs(task_id)
    ports = db.list_ports(task_id)
    csegs = db.list_csegs(task_id)
    vulns = sorted(db.list_vulns(task_id=task_id, limit=1000),
                   key=lambda r: SEV_ORDER.get(r["severity"], 9))

    lines = [f"# 扫描报告：{task['name']}（任务 #{task_id}）", ""]
    lines.append(f"- 时间：{task['created_at']} ｜ 状态：{task['status']} ｜ 阶段：{task['stages']}")
    lines.append("- 目标：")
    lines.append("```")
    lines.append(task["targets"])
    lines.append("```")
    lines.append("")
    lines.append("## 概览")
    lines.append("")
    lines.append("| 子域名 | 存活站点 | 目录发现 | 开放端口 | C 段 IP | 潜在漏洞 |")
    lines.append("|---|---|---|---|---|---|")
    lines.append(f"| {_c(len(subs))} | {_c(len(sites))} | {_c(len(dirs))} | {_c(len(ports))} | "
                 f"{_c(len(csegs))} | {_c(len(vulns))} |")
    lines.append("")
    lines.append("> 以下「潜在漏洞」均为自动化初筛结果，存在误报可能，处置前需人工验证。")
    lines.append("")
    if vulns:
        lines.append("## 潜在漏洞")
        lines.append("")
        lines.append("| 级别 | 名称 | 检查/POC | OWASP | 目标 |")
        lines.append("|---|---|---|---|---|")
        for v in vulns:
            lines.append(f"| {_c(v['severity'])} | {_c(v['name'])} | {_c(v['poc_id'])} | "
                         f"{_c(v['owasp'] or '-')} | {_c(v['target'])} |")
        lines.append("")
    if sites:
        lines.append("## 存活站点")
        lines.append("")
        lines.append("| URL | 状态 | 标题 | 技术栈 | Server |")
        lines.append("|---|---|---|---|---|")
        for s in sites[:100]:
            lines.append(f"| {_c(s['url'])} | {_c(s['status'])} | {_c(s['title'] or '-')} | "
                         f"{_c(s['tech'] or '-')} | {_c(s['server'] or '-')} |")
        lines.append("")
    if ports:
        lines.append("## 开放端口与服务（前 200）")
        lines.append("")
        lines.append("| 主机 | IP | 端口 | 服务 | banner |")
        lines.append("|---|---|---|---|---|")
        for p in ports[:200]:
            lines.append(f"| {_c(p['host'] or '-')} | {_c(p['ip'] or '-')} | {_c(p['port'])} | "
                         f"{_c(p['service'] or '-')} | {_c((p['banner'] or '-')[:80])} |")
        lines.append("")
    if csegs:
        lines.append("## C 段视野（前 200）")
        lines.append("")
        lines.append("| C 段 | IP | 域名数 | 反查到的域名 |")
        lines.append("|---|---|---|---|")
        for c in csegs[:200]:
            lines.append(f"| {_c(c['segment'] or '-')} | {_c(c['ip'] or '-')} | {_c(c['count'])} | "
                         f"{_c((c['domains'] or '-')[:120])} |")
        lines.append("")
    if subs:
        lines.append("## 子域名（前 200）")
        lines.append("")
        lines.append("```")
        lines.extend(r["domain"] for r in subs[:200])
        lines.append("```")
        lines.append("")
    if dirs:
        lines.append("## 目录发现（前 100）")
        lines.append("")
        lines.append("| 状态 | 路径 |")
        lines.append("|---|---|")
        for d in dirs[:100]:
            lines.append(f"| {_c(d['status'])} | {_c(d['path'])} |")
        lines.append("")
    return "\n".join(lines)
