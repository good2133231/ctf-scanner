"""任务报告生成：Markdown（默认）/ HTML（自包含单文件）/ PDF（本机无头浏览器打印）/
JSONL（机器可读，每行一个 JSON 对象）。

四种格式**共用 `collect()` 取到的同一份数据快照** —— 否则"Markdown 里有 TLS 证书、
HTML 里没有"这类漂移没人会发现。HTML 必须走 `html.escape` 全量转义：报告里的标题 /
URL / banner 都来自被测目标，不转义等于把对方的内容当我们的页面渲染（反射型 XSS）。
JSONL 是**唯一面向机器**的格式，与 MD/HTML 有一处**刻意差异**：它导出 `collect()` 的
`all_vulns`（含已判误报的行），把复核状态原样交给下游自己筛（理由见 `generate_jsonl`）。
"""
import html
import json
import shutil
import tempfile
from pathlib import Path

from . import db
from .utils import run_cmd

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# 复核状态（P1-1）在报告里的展示名
REVIEW_LABEL = {"": "待复核", "confirmed": "已确认", "false_positive": "误报"}


def _cert_source(row):
    """证书行的来源标签：`ct` = 公开 CT 日志（crt.sh），其余 = 本次真实 TLS 握手。

    `db.list_certs()` 返回的是 `sqlite3.Row`，**没有 `.get()`**（本文件其它处踩过同类坑），
    所以这里先按下标取、取不到再退回 dict 形态，不能只写 `row.get(...)`。
    """
    src = ""
    try:
        if "source" in row.keys():
            src = row["source"] or ""
    except (AttributeError, IndexError, TypeError):
        try:
            src = (row or {}).get("source") or ""
        except (AttributeError, TypeError):
            src = ""
    return "CT 日志" if str(src) == "ct" else "TLS 握手"


def _row_dict(row):
    """`sqlite3.Row`（或 None）→ 普通 dict。

    `db.*` 的多数访问器返回 `sqlite3.Row`，**没有 `.get()`**、也不能直接当 dict 交给
    `json.dumps`（见 `_cert_source()` 里的同类坑）。JSONL 导出必须先把行转成 dict 再
    序列化，否则要么抛异常、要么漏字段。
    """
    return dict(row) if row is not None else {}


def _c(value):
    """Markdown 表格单元格转义：`|` 转义成 `\\|`，换行/回车压成空格。

    标题、URL、evidence 都可能带 `|` 或换行，直接拼进表格会把表格冲散。
    """
    s = str("" if value is None else value)
    return s.replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _h(value):
    """HTML 转义。**必须**用它而不是裸拼接：标题 / URL / banner / evidence 都来自被测目标，
    不转义等于把对方控制的内容当我们的页面渲染（反射型 XSS）。"""
    return html.escape(str("" if value is None else value), quote=True)


def _append_count(task):
    """续25：任务被"追加执行"的次数（0 = 从未追加）。`options` 是 JSON 文本。"""
    try:
        top = json.loads(task["options"] or "{}")
    except (TypeError, ValueError):
        return 0
    if not isinstance(top, dict):
        return 0
    try:
        return int(top.get("append_count") or 0)
    except (TypeError, ValueError):
        return 0


def collect(task_id):
    """把一份报告要用的数据一次性取出来（Markdown / HTML / PDF 共用），任务不存在返回 None。"""
    task = db.get_task(task_id)
    if not task:
        return None
    subs = db.list_subdomains(task_id)
    sites = db.list_sites(task_id)
    dirs = db.list_dirs(task_id)
    ports = db.list_ports(task_id)
    csegs = db.list_csegs(task_id)
    certs = db.list_certs(task_id)
    all_vulns = sorted(db.list_vulns(task_id=task_id, limit=1000),
                       key=lambda r: SEV_ORDER.get(r["severity"], 9))
    # 人工复核（P1-1）：判为误报的**不再计入「潜在漏洞」**，单独成节放在文末 ——
    # 报告是给人看的交付物，把已排除的噪声混在结论里等于把复核工作白做。
    vulns = [v for v in all_vulns if (v["review"] or "") != "false_positive"]
    # 线索（intel 情报订阅 / heuristic 启发式）：**不是漏洞结论**，续24 起不再进**人读报告**
    # （MD / HTML）——与 GUI 的「线索」页签同步移除（用户口径：只隐藏页签与报告附录）。
    # **数据层照旧**：`leads` 表、两个阶段都不变；**机器格式仍全量输出**（`generate_jsonl`
    # 的 `type=lead` 行与 `counts.leads`），沿用续20 的取舍「机器格式保留全部、筛选权交下游」。
    leads = list(db.list_leads(task_id))
    return {"task": task, "subs": subs, "sites": sites, "dirs": dirs, "ports": ports,
            "csegs": csegs, "certs": certs, "all_vulns": all_vulns, "vulns": vulns,
            "review": db.review_counts(task_id), "leads": leads}


def generate(task_id):
    d = collect(task_id)
    if not d:
        return None
    task, subs, sites, dirs = d["task"], d["subs"], d["sites"], d["dirs"]
    ports, csegs, certs = d["ports"], d["csegs"], d["certs"]
    all_vulns, vulns, review = d["all_vulns"], d["vulns"], d["review"]

    lines = [f"# 扫描报告：{task['name']}（任务 #{task_id}）", ""]
    lines.append(f"- 时间：{task['created_at']} ｜ 状态：{task['status']} ｜ 阶段：{task['stages']}")
    # 续25：追加执行过的任务在报告顶部留**横幅**（提示"结果为多次运行的合并"），不阻断导出。
    _ap = _append_count(task)
    if _ap:
        lines.append(f"- ⚠ 本任务含**追加执行** ×{_ap}：结果是多次运行的合并"
                     f"（同名资产已跨运行去重，不产生重复行）。")
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
    if certs:
        # TLS 证书取证（默认关闭的 cert 阶段产物）。措辞刻意说清"取证 ≠ 漏洞"，
        # 避免把自签名/过期当成结论直接写进交付物。
        lines.append("## TLS 证书（取证，非漏洞结论）")
        lines.append("")
        lines.append("> 一次只读 TLS 握手的取证结果：握手**不校验证书**，因此"
                     "「自签 / 已过期」是证书本身的属性，不等于漏洞。")
        lines.append("")
        lines.append("> 「来源」列区分两件事：**TLS 握手**＝本次真的连上去取到的证书；"
                     "**CT 日志**＝公开证书透明度日志里与该域名相关的历史证书"
                     "（开关 `ctlog.enabled`，默认关）—— 后者是线索，不等于"
                     "「目标此刻在用这张证书」。")
        lines.append("")
        lines.append("| 来源 | 主机 | 端口 | CN | 颁发者 | 有效期 | 剩余 | 自签 | 签名算法 |"
                     " 指纹(SHA256) |")
        lines.append("|---|---|---|---|---|---|---|---|---|---|")
        for c in certs[:200]:
            left = ("已过期" if c["expired"] else
                    (f"{c['days_left']} 天" if c["days_left"] is not None else "-"))
            lines.append(f"| {_c(_cert_source(c))} | {_c(c['host'])} | {_c(c['port'])} | "
                         f"{_c(c['cn'] or '-')} | "
                         f"{_c(c['issuer'] or '-')} | "
                         f"{_c((c['not_before'] or '-') + ' → ' + (c['not_after'] or '-'))} | "
                         f"{_c(left)} | {_c('是' if c['self_signed'] else '-')} | "
                         f"{_c(c['sig_algo'] or '-')} | {_c(c['sha256'] or '-')} |")
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


# ---------- HTML 报告 ----------

# 自包含单文件：样式内联、不引任何外部资源（CTF 现场常常离线；也避免"报告里有外链"
# 这种交付物被质疑的东西）。`@media print` 一节是给"另存为 PDF"用的。
_HTML_CSS = """
body{font:14px/1.6 -apple-system,"Segoe UI","Microsoft YaHei",sans-serif;color:#222;
     margin:24px;max-width:1120px}
h1{font-size:20px;margin:0 0 4px} h2{font-size:16px;margin:24px 0 8px;
     border-left:4px solid #4b5563;padding-left:8px}
.cards{display:flex;flex-wrap:wrap;gap:8px;margin:10px 0}
.card{border:1px solid #e5e7eb;border-radius:6px;padding:8px 14px;min-width:88px}
.card b{display:block;font-size:18px} .card span{color:#6b7280;font-size:12px}
table{border-collapse:collapse;width:100%;font-size:12.5px;margin:6px 0}
th,td{border:1px solid #e5e7eb;padding:4px 6px;text-align:left;vertical-align:top}
th{background:#f3f4f6;white-space:nowrap}
.muted{color:#6b7280} .sev{font-weight:600}
.sev-critical{color:#b91c1c} .sev-high{color:#c2410c} .sev-medium{color:#b45309}
.sev-low{color:#4b5563} .sev-info{color:#6b7280}
.note{color:#4b5563;background:#f9fafb;border-left:3px solid #d1d5db;padding:6px 10px;
      margin:6px 0}
pre{background:#f8f8f8;border:1px solid #eee;padding:8px;overflow:auto;font-size:12px}
.bar{display:inline-block;width:110px;height:8px;background:#e5e7eb;border-radius:4px;
     overflow:hidden;vertical-align:middle}
.bar>i{display:block;height:100%}
@media print{body{margin:8mm;max-width:none} a{color:inherit;text-decoration:none}
     h2{break-after:avoid} tr{break-inside:avoid}}
"""

_BAR_COLOR = {"critical": "#b91c1c", "high": "#c2410c", "medium": "#b45309",
              "low": "#4b5563", "info": "#6b7280"}


def _html_table(headers, rows, empty=""):
    """拼一张表；`rows` 里每个单元格已经是转义好的 HTML 片段（调用方负责）。"""
    if not rows:
        return f'<p class="muted">{_h(empty or "暂无数据。")}</p>'
    head = "".join(f"<th>{_h(x)}</th>" for x in headers)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def _sev_bars(by_sev, total):
    """级别分布条（HTML 报告里的"漏洞趋势统计"）。"""
    items = []
    for k in SEV_ORDER:
        n = by_sev.get(k, 0) or 0
        pct = (n / total * 100) if total else 0
        items.append(
            f'<tr><td><span class="sev sev-{_h(k)}">{_h(k)}</span></td><td>{n}</td>'
            f'<td><span class="bar"><i style="width:{pct:.1f}%;'
            f'background:{_BAR_COLOR.get(k, "#6b7280")}"></i></span></td></tr>')
    return "".join(items)


def generate_html(task_id):
    """生成自包含的 HTML 报告（单文件、内联样式、无外链）。任务不存在返回 None。"""
    d = collect(task_id)
    if not d:
        return None
    task, subs, sites, dirs = d["task"], d["subs"], d["sites"], d["dirs"]
    ports, csegs, certs = d["ports"], d["csegs"], d["certs"]
    all_vulns, vulns, review = d["all_vulns"], d["vulns"], d["review"]
    by_sev = {}
    for v in vulns:
        by_sev[v["severity"]] = by_sev.get(v["severity"], 0) + 1

    p = [f'<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">',
         f'<meta name="viewport" content="width=device-width,initial-scale=1">',
         f'<title>扫描报告：{_h(task["name"])}（任务 #{task_id}）</title>',
         f"<style>{_HTML_CSS}</style></head><body>",
         f'<h1>扫描报告：{_h(task["name"])}（任务 #{task_id}）</h1>',
         f'<p class="muted">时间：{_h(task["created_at"])} ｜ 状态：{_h(task["status"])} '
         f'｜ 阶段：{_h(task["stages"])}</p>',
         "<h2>目标</h2>", f"<pre>{_h(task['targets'])}</pre>"]
    # 续25：追加执行过的任务在报告顶部留**横幅**（提示"结果为多次运行的合并"），不阻断导出。
    _ap = _append_count(task)
    if _ap:
        p.append(f'<div class="note">⚠ 本任务含<b>追加执行</b> ×{_ap}：'
                 f'结果为多次运行的合并（同名资产已跨运行去重，不产生重复行）。</div>')
    cards = [("子域名", len(subs)), ("存活站点", len(sites)), ("目录发现", len(dirs)),
             ("开放端口", len(ports)), ("C 段 IP", len(csegs)), ("TLS 证书", len(certs)),
             ("潜在漏洞", len(vulns))]
    p.append("<h2>概览</h2><div class='cards'>")
    p.extend(f"<div class='card'><b>{n}</b><span>{_h(k)}</span></div>" for k, n in cards)
    p.append("</div>")
    p.append('<div class="note">以下「潜在漏洞」均为自动化初筛结果，存在误报可能，'
             "处置前需人工验证。</div>")
    if review["confirmed"] or review["pending"] or review["false_positive"]:
        line = (f'<div class="note">人工复核台账：已确认 {review["confirmed"]} ｜ '
                f'待复核 {review["pending"]} ｜ 已判误报 {review["false_positive"]}')
        if review["false_positive"]:
            line += "（误报不计入概览，见文末附录）"
        p.append(line + "</div>")
    if vulns:
        p.append("<h2>漏洞趋势统计（本任务级别分布，已判误报不计入）</h2>")
        p.append('<table><thead><tr><th>级别</th><th>数量</th><th>占比</th></tr></thead><tbody>'
                 + _sev_bars(by_sev, len(vulns)) + "</tbody></table>")
        p.append("<h2>潜在漏洞</h2>")
        p.append(_html_table(
            ["级别", "名称", "检查/POC", "OWASP", "目标", "复核"],
            [[f'<span class="sev sev-{_h(v["severity"])}">{_h(v["severity"])}</span>',
              _h(v["name"]), _h(v["poc_id"]), _h(v["owasp"] or "-"), _h(v["target"]),
              _h(REVIEW_LABEL.get(v["review"] or "", "待复核"))] for v in vulns]))
    if sites:
        p.append("<h2>存活站点</h2>")
        p.append(_html_table(
            ["URL", "状态", "标题", "技术栈", "Server"],
            [[_h(s["url"]), _h(s["status"]), _h(s["title"] or "-"),
              _h(s["tech"] or "-"), _h(s["server"] or "-")] for s in sites[:100]]))
    if ports:
        p.append("<h2>开放端口与服务（前 200）</h2>")
        p.append(_html_table(
            ["主机", "IP", "端口", "服务", "banner"],
            [[_h(x["host"] or "-"), _h(x["ip"] or "-"), _h(x["port"]),
              _h(x["service"] or "-"), _h((x["banner"] or "-")[:80])] for x in ports[:200]]))
    if csegs:
        p.append("<h2>C 段视野（前 200）</h2>")
        p.append(_html_table(
            ["C 段", "IP", "域名数", "反查到的域名"],
            [[_h(x["segment"] or "-"), _h(x["ip"] or "-"), _h(x["count"]),
              _h((x["domains"] or "-")[:120])] for x in csegs[:200]]))
    if certs:
        p.append("<h2>TLS 证书（取证，非漏洞结论）</h2>")
        p.append('<div class="note">一次只读 TLS 握手的取证结果：握手<b>不校验证书</b>，因此'
                 "「自签 / 已过期」是证书本身的属性，不等于漏洞。<br>"
                 "「来源」列区分：<b>TLS 握手</b>＝本次真的连上去取到的证书；"
                 "<b>CT 日志</b>＝公开证书透明度日志里与该域名相关的历史证书"
                 "（开关 <code>ctlog.enabled</code>，默认关）—— 后者是线索，不等于"
                 "「目标此刻在用这张证书」。</div>")
        p.append(_html_table(
            ["来源", "主机", "端口", "CN", "颁发者", "有效期", "剩余", "自签", "签名算法",
             "指纹(SHA256)"],
            [[_h(_cert_source(c)), _h(c["host"]), _h(c["port"]), _h(c["cn"] or "-"),
              _h(c["issuer"] or "-"),
              _h((c["not_before"] or "-") + " → " + (c["not_after"] or "-")),
              _h("已过期" if c["expired"] else
                 (f"{c['days_left']} 天" if c["days_left"] is not None else "-")),
              _h("是" if c["self_signed"] else "-"), _h(c["sig_algo"] or "-"),
              _h(c["sha256"] or "-")] for c in certs[:200]]))
    if subs:
        p.append("<h2>子域名（前 200）</h2>")
        p.append("<pre>" + _h("\n".join(r["domain"] for r in subs[:200])) + "</pre>")
    if dirs:
        p.append("<h2>目录发现（前 100）</h2>")
        p.append(_html_table(["状态", "路径"],
                             [[_h(x["status"]), _h(x["path"])] for x in dirs[:100]]))
    fp = [v for v in all_vulns if (v["review"] or "") == "false_positive"]
    if fp:
        p.append("<h2>已判误报（人工复核排除）</h2>")
        p.append('<div class="note">这些条目由人工复核判定为误报，<b>不计入上表与概览</b>；'
                 "保留在此供溯源与规则校准。</div>")
        p.append(_html_table(
            ["级别", "名称", "检查/POC", "目标", "复核备注"],
            [[_h(v["severity"]), _h(v["name"]), _h(v["poc_id"]), _h(v["target"]),
              _h(v["review_note"] or "-")] for v in fp]))
    p.append(f'<p class="muted">由 CTFScanner 生成 ｜ 任务 #{task_id}</p></body></html>')
    return "\n".join(p)


def generate_jsonl(task_id):
    """生成 JSON Lines 导出（每行一个 JSON 对象，含末尾换行），任务不存在返回 None。

    与 Markdown / HTML 的**刻意差异**：漏洞导出的是 `collect()` 的 `all_vulns`
    （**全部**行，含 `review` / `review_note`），而不是已过滤掉误报的 `vulns`。
    理由：JSONL 是给**机器消费**的中间产物，复核状态（待复核 / 已确认 / 误报）本就是
    数据的一部分，应当原样交给下游、由下游按自己的口径筛选；替它静默丢掉
    `false_positive` 行，等于把"这里曾经扫出过、只是被人工排除了"这一事实抹掉。
    MD / HTML 是给人看的交付物，才需要"误报不进结论表"。

    每行带 `"type"` 判别字段：首行 `meta`（任务 id / name / status / stages / created_at /
    targets / 各资产计数 / review 台账），随后每条记录一行，`type` ∈ `vuln` / `site` /
    `subdomain` / `dir` / `port` / `cseg` / `cert` / `lead`。`ensure_ascii=False` + UTF-8
    （中文原样可读）；每行（**含最后一行**）都以 `\\n` 结尾，才是合法 JSON Lines。
    """
    d = collect(task_id)
    if not d:
        return None
    task, subs, sites, dirs = d["task"], d["subs"], d["sites"], d["dirs"]
    ports, csegs, certs = d["ports"], d["csegs"], d["certs"]
    all_vulns, review, leads = d["all_vulns"], d["review"], d["leads"]

    lines = []

    def emit(obj):
        lines.append(json.dumps(obj, ensure_ascii=False, default=str))

    def emit_row(kind, row):
        obj = {"type": kind}
        obj.update(_row_dict(row))
        emit(obj)

    emit({
        "type": "meta",
        "task_id": task["id"],
        "name": task["name"],
        "status": task["status"],
        "stages": task["stages"],
        "created_at": task["created_at"],
        "targets": task["targets"],
        "counts": {
            "subdomains": len(subs), "sites": len(sites), "dirs": len(dirs),
            "ports": len(ports), "csegs": len(csegs), "certs": len(certs),
            "vulns": len(all_vulns), "leads": len(leads),
        },
        "review": review,
    })
    for v in all_vulns:
        emit_row("vuln", v)
    for s in sites:
        emit_row("site", s)
    for s in subs:
        emit_row("subdomain", s)
    for r in dirs:
        emit_row("dir", r)
    for p in ports:
        emit_row("port", p)
    for c in csegs:
        emit_row("cseg", c)
    for c in certs:
        emit_row("cert", c)
    for ld in leads:
        emit_row("lead", ld)
    return "\n".join(lines) + "\n"


def export_pdf(task_id, out_path, settings=None, timeout=90):
    """把 HTML 报告交给本机无头浏览器打印成 PDF（`--print-to-pdf`），返回 `(ok, err)`。

    为什么用浏览器而不是自己写 PDF：中文要嵌字体，纯标准库写 PDF 等于自带一个排版引擎；
    截图功能已经在用 Edge/Chrome，这里复用**同一条浏览器探测路径**，不引入任何新依赖。
    找不到浏览器时返回**明确原因**（GUI 会把它显示出来，并提示改导出 HTML / 在策略里
    填 `screenshot.browser`），不做静默失败。
    """
    html_text = generate_html(task_id)
    if html_text is None:
        return False, "任务不存在"
    from .screenshot import browser_path          # 延迟导入：report 不被 GUI 之外的场景拖住
    binary = browser_path(settings)
    if not binary:
        return False, ("未找到可用的无头浏览器（Edge/Chrome），无法打印 PDF；"
                       "可改导出 HTML 后用浏览器另存为 PDF，"
                       "或在「策略配置」里填 screenshot.browser")
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_dir = Path(tempfile.mkdtemp(prefix="ctfscan-pdf-"))
    tmp_profile = Path(tempfile.mkdtemp(prefix="ctfscan-pdf-profile-"))
    try:
        html_path = tmp_dir / "report.html"
        # 必须显式 encoding（AGENTS.md §0）：报告里有中文，读默认编码在 Windows 上会炸。
        html_path.write_text(html_text, encoding="utf-8")
        argv = [binary, "--headless=new", "--disable-gpu", "--no-first-run",
                "--no-default-browser-check", "--disable-extensions",
                f"--user-data-dir={tmp_profile}",
                "--no-pdf-header-footer",       # 别把浏览器的页眉页脚（URL/日期）印进去
                f"--print-to-pdf={out_path}",
                html_path.as_uri()]
        rc, _out, err = run_cmd(argv, timeout=int(timeout or 90))
        if out_path.exists() and out_path.stat().st_size > 0:
            return True, ""
        return False, (err or f"浏览器退出码 {rc}")[:200]
    except Exception as e:                        # 兜底：由调用方决定怎么告知用户
        return False, str(e)[:200]
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        shutil.rmtree(tmp_profile, ignore_errors=True)
