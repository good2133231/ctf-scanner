"""任务 Markdown 报告生成（骨架版：概览 + 潜在漏洞 + 资产清单）。"""
from . import db

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# 复核状态（P1-1）在报告里的展示名
REVIEW_LABEL = {"": "待复核", "confirmed": "已确认", "false_positive": "误报"}


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
    all_vulns = sorted(db.list_vulns(task_id=task_id, limit=1000),
                       key=lambda r: SEV_ORDER.get(r["severity"], 9))
    # 人工复核（P1-1）：判为误报的**不再计入「潜在漏洞」**，单独成节放在文末 ——
    # 报告是给人看的交付物，把已排除的噪声混在结论里等于把复核工作白做。
    vulns = [v for v in all_vulns if (v["review"] or "") != "false_positive"]
    review = db.review_counts(task_id)
    # 线索（intel 情报订阅 / heuristic 启发式）：**不是漏洞结论**，只作为附录列出，
    # 既不进上面的「潜在漏洞」表，也不参与任何计数（见 scanner/intel.py 的边界说明）。
    leads = list(db.list_leads(task_id))

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
    if review["confirmed"] or review["pending"] or review["false_positive"]:
        line = (f"> 人工复核台账：已确认 {review['confirmed']} ｜ 待复核 {review['pending']}"
                f" ｜ 已判误报 {review['false_positive']}")
        if review["false_positive"]:
            line += "（误报不计入上表，见文末附录）"
        lines.append(line)
    lines.append("")
    if vulns:
        lines.append("## 潜在漏洞")
        lines.append("")
        lines.append("| 级别 | 名称 | 检查/POC | OWASP | 目标 | 复核 |")
        lines.append("|---|---|---|---|---|---|")
        for v in vulns:
            lines.append(f"| {_c(v['severity'])} | {_c(v['name'])} | {_c(v['poc_id'])} | "
                         f"{_c(v['owasp'] or '-')} | {_c(v['target'])} | "
                         f"{_c(REVIEW_LABEL.get(v['review'] or '', '待复核'))} |")
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
    if leads:
        # 附录：只在线索非空时输出，避免给"没开这两个阶段"的常规报告塞空表
        lines.append("## 线索（非漏洞结论，需人工确认）")
        lines.append("")
        lines.append("> 本节来自「情报订阅（CISA KEV × 本地指纹）」与「启发式候选」两个默认关闭的阶段。")
        lines.append("> 它们是**待确认的线索**，不是漏洞结论：不进上表、不计入漏洞数，请人工核实后再处置。")
        lines.append("")
        lines.append("| 类型 | 级别 | CVE/规则 | 名称 | 目标 | 触发物 |")
        lines.append("|---|---|---|---|---|---|")
        for ld in leads:
            kind = "情报" if ld["kind"] == "intel" else "启发式"
            lines.append(f"| {_c(kind)} | {_c(ld['level'])} | {_c(ld['code'])} | "
                         f"{_c(ld['title'])} | {_c(ld['target'])} | {_c(ld['matched'])} |")
        lines.append("")
    fp = [v for v in all_vulns if (v["review"] or "") == "false_positive"]
    if fp:
        # 附录：人工复核判定的误报留痕。**保留**而不是从报告里删掉，理由是
        # ① 交付时能说明"这条扫出来过、但已排除"；② 反向校准 POC/检查项的误报率。
        lines.append("## 已判误报（人工复核排除）")
        lines.append("")
        lines.append("> 这些条目由人工复核判定为误报，**不计入上表与概览**；保留在此供溯源与规则校准。")
        lines.append("")
        lines.append("| 级别 | 名称 | 检查/POC | 目标 | 复核备注 |")
        lines.append("|---|---|---|---|---|")
        for v in fp:
            lines.append(f"| {_c(v['severity'])} | {_c(v['name'])} | {_c(v['poc_id'])} | "
                         f"{_c(v['target'])} | {_c(v['review_note'] or '-')} |")
        lines.append("")
    return "\n".join(lines)
