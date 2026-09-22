"""启发式候选发现（P3-3）：对**已收集的数据**做差分与异常聚合，产出"值得人工看一眼"的线索。

为什么是"零请求"的：P3-3 的原意是"未知漏洞挖掘"，但框架里能拿到的可靠信号只有已经采回来的
资产数据（站点指纹 / 目录结果 / 端口 / 初筛漏洞）。在检测层成熟度与样本量都不够时做主动 fuzz
只会放大误报噪声（`TODO.md` P3-3 的原始结论），所以本模块：
- **不发任何 HTTP 请求**，只读 `sites / dirs / vulns / csegs` 四张表的数据；
- 结果写 `leads` 表（`kind=heuristic`），级别一律 `info`，**不写 `vulns`、不进漏洞计数、不进报告表格**。

它做两件事，正好对应 `TODO.md` 里"差分 / 异常聚合"的措辞：
- **差分**：同一站点目录结果里的"主导 (状态码, 长度)"占比 —— 占比过高说明目标对不存在的路径
  返回同一个模板页（软 404），那么这批"命中"就不该被当成存在的路径；
- **异常聚合**：跨站点同名标题（同一套系统多实例）、单站点目录命中数离群、同一 /24 段内多个 IP
  都反查到了域名 —— 这些是"值得优先看"的排序线索，不是漏洞结论。

每条线索都带**为什么报**与**建议怎么用**，因为"线索"和"结论"的区别就在这里。
"""
import re
from collections import Counter, defaultdict

from .fofa import is_generic_title

# ---------- 阈值（保守值，宁可少报：线索多了就没人看）----------

# 软 404 差分：单站点至少这么多条目录结果才做判断，主导键占比超过此值即判"统一模板页"
SOFT404_MIN_ROWS = 8
SOFT404_RATIO = 0.7

# 同标题多主机：标题至少这么长（过短的标题如 "首页" 无区分度），且至少这么多台主机
TITLE_MIN_LEN = 4
TITLE_MIN_HOSTS = 2

# 目录命中离群：命中数至少这么多，且是其它站点中位数的这么多倍
OUTLIER_MIN_HITS = 15
OUTLIER_RATIO = 3

# C 段聚集：同一 /24 段里至少这么多 IP 反查到了域名
CSEG_MIN_IPS = 3

# 高价值入口：目录命中了这些路径、但检测层没给出任何对应结论 → 值得人工确认。
# 每条配一个"为什么值得看"，避免下一个人把它当成"又一个 200 就报"。
HIGH_VALUE_PATHS = (
    (re.compile(r"/\.git(?:/|$)", re.I), "git-dir", "Git 目录暴露", "源码与提交历史可能整体可读"),
    (re.compile(r"/\.(?:env|svn)(?:/|$)", re.I), "env-file", "敏感文件/旧版本目录", "凭据或源码片段可能直接可读"),
    (re.compile(r"/actuator(?:/|$)", re.I), "actuator", "Spring Boot 端点", "env/heapdump 类端点常未授权"),
    (re.compile(r"/druid(?:/|$)", re.I), "druid", "Druid 监控台", "监控台未授权访问很常见"),
    (re.compile(r"/(?:swagger-ui|swagger-resources|v2/api-docs|openapi\.json)", re.I),
     "swagger", "接口文档暴露", "接口清单可用于扩大攻击面"),
    (re.compile(r"/(?:phpmyadmin|pma)(?:/|$)", re.I), "phpmyadmin", "数据库管理台", "弱口令/未授权是常见入口"),
    (re.compile(r"/(?:wp-admin|wp-login\.php)", re.I), "wordpress", "WordPress 后台", "插件/主题漏洞的高频入口"),
    (re.compile(r"/(?:manager/html|host-manager)(?:/|$)", re.I), "tomcat", "Tomcat 管理台", "弱口令部署 WAR 是经典路径"),
    (re.compile(r"/console(?:/|$)", re.I), "console", "控制台/注册中心入口", "Weblogic/JMX 类控制台常未授权"),
    (re.compile(r"/_cat/indices", re.I), "elasticsearch", "Elasticsearch 接口", "未授权即可读取全部索引"),
    (re.compile(r"/nacos(?:/|$)", re.I), "nacos", "Nacos 配置中心", "未授权可读配置甚至注入"),
    (re.compile(r"/(?:jenkins|script)(?:/|$)", re.I), "jenkins", "Jenkins 后台/脚本接口", "脚本控制台可直接执行命令"),
    (re.compile(r"\.(?:sql|bak|zip|tar\.gz|rar|7z)$", re.I), "backup", "备份/归档文件", "整站源码或数据库导出可能可直接下载"),
    (re.compile(r"/solr/(?:admin|coreadmin)", re.I), "solr", "Solr 管理台", "管理台未授权可读写核心"),
    (re.compile(r"/eureka(?:/|$)", re.I), "eureka", "Eureka 注册中心", "可读取内部服务清单"),
)


def _lead(code, title, target, matched, detail, source="启发式"):
    return {"kind": "heuristic", "code": code, "title": title, "target": target,
            "matched": matched, "level": "info", "detail": detail, "source": source, "url": ""}


def _soft404(dirs):
    """差分：单站点目录结果被同一个 (状态码, 长度) 主导 → 那是软 404 模板，不是路径。"""
    groups = defaultdict(list)
    for d in dirs or []:
        groups[d.get("site_url") or "-"].append(d)
    out = []
    for url, rows in groups.items():
        n = len(rows)
        if n < SOFT404_MIN_ROWS:
            continue
        (status, length), hit = Counter((r.get("status"), r.get("length")) for r in rows).most_common(1)[0]
        if hit / n < SOFT404_RATIO:
            continue
        out.append(_lead(
            "soft404", "目录结果疑似软 404 模板", url,
            f"状态 {status} / 大小 {length}：{hit}/{n} 条",
            f"该站点 {n} 条目录结果里有 {hit} 条是同一个 (状态码, 大小)，说明目标对不存在的路径"
            f"返回统一响应（软 404）。建议：只手工看**不落在这个组合里**的条目，"
            f"其余当作「路径不存在」处理，别按 200 逐条验证。"))
    return out


def _high_value_entries(dirs, vulns):
    """目录命中的高价值入口 vs 检测层结论：命中但没结论的，才值得人工看。"""
    blob = " ".join(str(v.get("target") or "") + " " + str(v.get("detail") or "") + " "
                    + str(v.get("evidence") or "") for v in (vulns or [])).lower()
    grouped = {}
    for d in dirs or []:
        path = str(d.get("path") or "")
        if not path:
            continue
        for pattern, code, name, why in HIGH_VALUE_PATHS:
            if not pattern.search(path):
                continue
            # 检测层已经就这条路径（或这个组件）给过结论 → 不再重复报线索
            if path.lower() in blob or code in blob:
                break
            key = (d.get("site_url") or "-", code)
            grouped.setdefault(key, {"name": name, "why": why, "paths": []})
            if len(grouped[key]["paths"]) < 5 and path not in grouped[key]["paths"]:
                grouped[key]["paths"].append(path)
            break
    out = []
    for (url, code), info in grouped.items():
        out.append(_lead(
            f"entry-{code}", f"高价值入口暴露（{info['name']}）", url,
            f"{len(info['paths'])} 条：{' / '.join(info['paths'])}",
            f"{info['why']}。目录扫描命中了这些入口，但初筛阶段**没有**给出对应结论 —— "
            f"建议人工确认访问控制是否缺失（未授权/弱口令/可直接下载）。"))
    return out


def _same_title(sites):
    """异常聚合：多台主机标题完全相同 → 大概率是同一套系统多实例（一处问题可复用）。"""
    groups = defaultdict(set)
    for s in sites or []:
        title = (s.get("title") or "").strip()
        if len(title) < TITLE_MIN_LEN or is_generic_title(title):
            continue      # 模板页标题（如"后台管理系统"）不是"同一套系统"，那是公共标题
        host = s.get("host") or s.get("url") or ""
        if host:
            groups[title].add(host)
    out = []
    for title, hosts in groups.items():
        if len(hosts) < TITLE_MIN_HOSTS:
            continue
        shown = sorted(hosts)[:5]
        out.append(_lead(
            "same-title", "多台主机标题相同（疑似同一套系统）", ", ".join(shown),
            f"{len(hosts)} 台主机：{title}",
            f"{len(hosts)} 台主机返回同一个标题「{title}」。同一套源码部署的多实例通常共享"
            f"同一批组件与配置问题 —— 在其中一个上验证出的问题，建议在其余实例上复测。"))
    return out


def _dir_outlier(dirs):
    """异常聚合：某站点目录命中数远超其它站点 → 它要么真有大面暴露，要么判定口径被污染。"""
    counts = Counter(d.get("site_url") or "-" for d in (dirs or []))
    if len(counts) < 2:
        return []
    top_url, top = counts.most_common(1)[0]
    others = sorted(c for u, c in counts.items() if u != top_url)
    mid = others[len(others) // 2] if others else 0
    if top < OUTLIER_MIN_HITS or top < OUTLIER_RATIO * max(1, mid):
        return []
    return [_lead(
        "dir-outlier", "目录命中数离群", top_url,
        f"{top} 条（其它站点中位数 {mid}）",
        f"该站点目录命中 {top} 条，是其它站点中位数（{mid}）的 {OUTLIER_RATIO} 倍以上。"
        f"建议先确认它不是软 404 模板（见「目录结果疑似软 404 模板」线索），"
        f"再挑状态码 200/403 且大小不同的条目优先看。")]


def _cseg_cluster(csegs):
    """异常聚合：同一 /24 段里多个 IP 都反查到了域名 → 可能是同一批资产（含非目标）。"""
    groups = defaultdict(list)
    for c in csegs or []:
        if int(c.get("count") or 0) <= 0:
            continue
        groups[c.get("segment") or "-"].append(c.get("ip") or "")
    out = []
    for seg, ips in groups.items():
        if len(ips) < CSEG_MIN_IPS:
            continue
        out.append(_lead(
            "cseg-cluster", "同 C 段多 IP 有域名反查结果", seg,
            f"{len(ips)} 个 IP：{' / '.join(sorted(ips)[:6])}",
            f"同一 C 段（{seg}）里有 {len(ips)} 个 IP 反查到了域名，说明这批 IP 属于同一批资产"
            f"（同一机房/同一业务）。其中**未必都属于本次目标**，拓展前请先确认资产边界。"))
    return out


def find_leads(sites, dirs, vulns, csegs):
    """跑全部规则，返回 `leads` 行列表（顺序＝规则顺序，稳定可测）。"""
    leads = []
    leads += _soft404(dirs)
    leads += _high_value_entries(dirs, vulns)
    leads += _same_title(sites)
    leads += _dir_outlier(dirs)
    leads += _cseg_cluster(csegs)
    return leads