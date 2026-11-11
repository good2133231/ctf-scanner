"""IP 维度证据聚合（续375）。

目的：把散落在 `subdomains` / `ports` / `certs` 里的三条证据归并到 **IP 维度**，
回答「这个 IP 是 CDN 边缘，还是目标的源站/真实承载」。

证据只有三种，全部来自**本任务已入库的数据**（零外部请求，不新增配额）：
- `port`     —— `ports` 表里有这个 IP 的开放端口（说明确实在承载服务）；
- `cert_san` —— 该 IP 对应主机的证书 SAN 覆盖了本任务其它域名（共享证书 = 同源信号）；
- `pdns`     —— 这个 IP 出现在 `osint:*` 反查来的域名解析结果里（历史 PDNS 关联）。

**刻意不做 ASN**：项目没有任何 ASN 数据源，凭空接一个免 key 接口等于新开一条
未经评估的出口；这里留 `asn` 字段（空串）给后续接，不假装有。

分档（fail-safe：拿不准就往低档放）：
- `cdn`    —— `subdomains.cdn` 非空（已知 CDN 标签）；
- `real`   —— 非 CDN 且 ≥2 条证据（`port` + `cert_san`/`pdns`）；
- `likely` —— 非 CDN 且只有 1 条证据；
- `unknown`—— 非 CDN 且零证据（只有解析、没有任何承载/共享信号）。
"""
from . import db

RANK_ORDER = {"real": 0, "likely": 1, "unknown": 2, "cdn": 3}


def _ips(raw):
    return [x.strip() for x in str(raw or "").replace(";", ",").split(",") if x.strip()]


def aggregate(task_id):
    """读库聚合并排序，返回 `[{ip, domains, cdn, evidence, rank, asn, note}]`。"""
    subs = [dict(r) for r in db.list_subdomains(task_id)]
    ports = [dict(r) for r in db.list_ports(task_id)]
    certs = [dict(r) for r in db.list_certs(task_id)]

    dom_ips = {}                    # domain -> set(ip)
    cdn_of = {}                     # ip -> cdn 标签（同一 IP 取第一个非空）
    for s in subs:
        dom = str(s.get("domain") or "").strip().lower()
        if not dom:
            continue
        for ip in _ips(s.get("ip")):
            dom_ips.setdefault(dom, set()).add(ip)
            label = str(s.get("cdn") or "").strip()
            if label and not cdn_of.get(ip):
                cdn_of[ip] = label

    rec = {}

    def _rec(ip):
        return rec.setdefault(ip, {"ip": ip, "domains": set(), "cdn": "",
                                   "evidence": set(), "asn": "", "note": ""})

    for dom, ips in dom_ips.items():
        for ip in ips:
            _rec(ip)["domains"].add(dom)

    # 证据 1：有开放端口（说明在承载）
    for p in ports:
        ip = str(p.get("ip") or "").strip()
        if ip in rec:
            rec[ip]["evidence"].add("port")

    # 证据 2：历史反查（osint:* 来源的域名解析到该 IP）
    for s in subs:
        if not str(s.get("source") or "").startswith("osint:"):
            continue
        for ip in _ips(s.get("ip")):
            if ip in rec:
                rec[ip]["evidence"].add("pdns")

    # 证据 3：共享证书（该 IP 主机的证书 SAN 覆盖了本任务其它域名）
    task_domains = set(dom_ips)
    for c in certs:
        host = str(c.get("host") or "").strip().lower()
        if not host:
            continue
        san = {x.strip().lower() for x in str(c.get("san") or "").split(",") if x.strip()}
        shared = (task_domains & san) - {host}
        if not shared:
            continue
        for ip in dom_ips.get(host, ()):
            if ip in rec:
                rec[ip]["evidence"].add("cert_san")

    out = []
    for ip, r in rec.items():
        r["cdn"] = cdn_of.get(ip, "")
        ev = r["evidence"]
        if r["cdn"]:
            r["rank"] = "cdn"
            r["note"] = f"已知 CDN 标签：{r['cdn']}"
        elif len(ev) >= 2:
            r["rank"] = "real"
            r["note"] = "非 CDN 且 ≥2 条独立证据"
        elif len(ev) == 1:
            r["rank"] = "likely"
            r["note"] = "非 CDN 且仅 1 条证据"
        else:
            r["rank"] = "unknown"
            r["note"] = "只有解析、没有承载/共享信号"
        r["domains"] = sorted(r["domains"])
        r["evidence"] = sorted(ev)
        out.append(r)
    out.sort(key=lambda x: (RANK_ORDER.get(x["rank"], 9), x["ip"]))
    return out


def to_leads(rows):
    """把 `real` / `likely` 的 IP 转成线索（`kind=ip`）；`cdn` / `unknown` 不写，免得刷屏。"""
    leads = []
    for r in rows:
        if r["rank"] not in ("real", "likely"):
            continue
        leads.append({
            "kind": "ip", "code": f"ip-{r['rank']}", "title": f"IP 证据：{r['rank']}",
            "target": r["ip"], "matched": ",".join(r["evidence"]),
            "level": "info" if r["rank"] == "likely" else "medium",
            "detail": (f"证据 {','.join(r['evidence']) or '无'}；"
                       f"域名 {len(r['domains'])} 个：{', '.join(r['domains'][:5])}"
                       f"{' …' if len(r['domains']) > 5 else ''}；{r['note']}"),
            "source": "osint", "url": "",
        })
    return leads
