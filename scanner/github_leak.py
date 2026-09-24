"""GitHub 泄露检索（续26，**最小形态**）：拿目标的**注册域**去 GitHub 公开代码里搜命中。

定位：这是**外部情报**，不是漏洞检测 —— 产出只进 `leads` 表（kind=`github`），
**不写 `vulns`、不计入漏洞数、不自动导入 POC**（与 `scanner/intel.py` 同一条边界）。

改代码前先读这三条硬边界（用户 2026-09-24 拍板，续26 的范围就是这三条）：

1. **只落元数据，绝不落明文 secret**。GitHub 代码搜索默认只回 `repository.full_name` /
   `path` / `html_url`，但一旦带上 `text-match` 之类的 Accept 头，响应里就会出现
   `text_matches`（**命中片段，可能含凭据明文**）。本模块用**字段白名单**取值
   （见 `normalize_hit()`），响应里多出来的内容片段一律**不读、不存、不打印** ——
   让"凭据明文"只存在于你的浏览器里，不进我们的库 / 日志 / 报告。
2. **`auth=False`**。所有 GitHub 请求都走 `utils.http_request` 且**不传 `auth=True`**：
   GitHub 自己的 token（`config/keys.yaml` 的 `github.token`）只作为 `Authorization`
   请求头发出，**任务级登录态（目标侧 Cookie / Token）绝不发给 GitHub**
   （`utils._headers()` 的说明：默认不带是刻意的）。
3. **默认关 + 限额 + 没 token 就零请求**。`github.enabled` 默认 false；
   单任务最多 `max_queries` 次搜索请求（GitHub 代码搜索认证后限流约 **10 次/分钟**）；
   没配 token 时**一次请求都不发** —— 代码搜索接口要求认证，发了也是 401，
   不如把原因直接写在日志里。

为什么查"注册域"而不是"每个子域名"：子域名动辄几百个，逐个查会瞬间打满限流，
而 `a.example.com` 与 `example.com` 的泄露命中高度重叠 —— 查注册域即可覆盖。
"""
import json
from urllib.parse import quote

from .utils import base_domain, http_request, is_domain

API_URL = "https://api.github.com/search/code"

# 检索规则：`(规则名, 追加关键词/限定符, 级别, 说明)`
#
# 顺序即**优先级**，且 `collect()` 是"外层按规则、内层按域名"遍历 ——
# 于是最便宜的 `mention` 会先覆盖到**所有**域名，额度用尽时才轮到凭据类规则。
# 级别只用于 `leads.level` 的排序着色（**不是漏洞级别**，同 intel 的口径）。
SEARCH_RULES = (
    ("mention", "", "info", "目标域名出现在公开仓库的代码/配置里"),
    ("credential", "password", "medium", "目标域名与口令关键字出现在同一份文件里"),
    ("apikey", "api_key", "medium", "目标域名与 API key 关键字出现在同一份文件里"),
    ("env-file", "filename:.env", "medium", "目标域名出现在 .env 配置文件里"),
)

_LEVEL_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# 相对 `max_queries` 的默认值：代码搜索限流约 10 次/分钟，留足余量给同一分钟内的其它调用
DEFAULT_MAX_QUERIES = 4
DEFAULT_MAX_DOMAINS = 3
DEFAULT_PER_PAGE = 30
DEFAULT_MAX_LEADS = 30
DEFAULT_TIMEOUT = 20


def load_token(settings):
    """从 `config/keys.yaml` 取 GitHub token（`github.token`）；没配返回空串。

    与 `fofa.credentials()` 同一口径：凭据**只读 `settings["keys"]`**，不读 settings.yaml ——
    GUI「策略配置」保存时会整体写回 settings.yaml，凭据混在里面容易被覆盖 / 回显。
    """
    cfg = ((settings or {}).get("keys") or {}).get("github") or {}
    if not isinstance(cfg, dict):
        return ""
    return str(cfg.get("token") or "").strip()


def rule_of(rule_id):
    """按规则名取规则 `(名, 关键词, 级别, 说明)`；未知规则名返回 None（**不猜**）。"""
    rid = str(rule_id or "").strip()
    for r in SEARCH_RULES:
        if r[0] == rid:
            return r
    return None


def build_query(domain, keyword=""):
    """构造一次 code search 的 `q` 值：`"<域名>"` + 可选关键词 / 限定符。

    域名**必须带引号**（phrase 查询），否则 `a.example.com` 会被拆成多个词，
    命中一堆恰好含 `a` / `example` / `com` 的无关仓库。
    """
    q = f'"{str(domain or "").strip()}"'
    kw = str(keyword or "").strip()
    return f"{q} {kw}" if kw else q


def search_url(domain, keyword="", per_page=DEFAULT_PER_PAGE):
    """完整请求 URL。`q` 整体 percent 编码 —— 引号与 `filename:.env` 的冒号都必须编码，
    否则 GitHub 直接 422。"""
    try:
        size = int(per_page or DEFAULT_PER_PAGE)
    except (TypeError, ValueError):
        size = DEFAULT_PER_PAGE
    size = max(1, min(size, 100))          # GitHub 的 per_page 上限就是 100
    return f"{API_URL}?q={quote(build_query(domain, keyword), safe='')}&per_page={size}"


def normalize_hit(raw, rule_id):
    """把一条搜索命中规整成**只含元数据**的结构（字段白名单，见文件头边界 1）。

    - **刻意不读 `text_matches`**：那是命中处的文件片段，可能包含凭据明文；
    - `repository` 也只取 `full_name`，不整个对象塞进来（里面还有 owner 详情等无关字段）。
    """
    if not isinstance(raw, dict):
        return None
    repo = ""
    r = raw.get("repository")
    if isinstance(r, dict):
        repo = str(r.get("full_name") or "").strip()
    path = str(raw.get("path") or "").strip()
    if not repo or not path:
        return None          # 拿不到仓库或路径就没法溯源，这条命中没有意义
    return {"repo": repo, "path": path,
            "url": str(raw.get("html_url") or "").strip(),
            "rule": str(rule_id or "").strip()}


def parse_response(text, rule_id):
    """解析搜索响应 → `(hits, total, error)`。结构异常**不抛异常**，返回空表 + 原因。"""
    try:
        data = json.loads(text or "{}")
    except (TypeError, ValueError):
        return [], 0, "GitHub 响应不是合法 JSON"
    if not isinstance(data, dict):
        return [], 0, "GitHub 响应结构异常（顶层不是对象）"
    try:
        total = int(data.get("total_count") or 0)
    except (TypeError, ValueError):
        total = 0
    hits = []
    for raw in (data.get("items") or []):
        h = normalize_hit(raw, rule_id)
        if h:
            hits.append(h)
    return hits, total, ""


def _header(headers, name):
    """大小写无关地取一个响应头（requests 的 `dict(r.headers)` 保留服务端原始大小写）。"""
    want = str(name or "").lower()
    for k, v in (headers or {}).items():
        if str(k).lower() == want:
            return str(v)
    return ""


def _status_reason(status):
    """把 GitHub 的状态码翻成"能直接给用户看"的原因（别让人以为'查过了、没泄露'）。"""
    if status == 401:
        return ("GitHub 拒绝认证（HTTP 401）：github.token 无效或已过期 —— "
                "代码搜索接口要求认证，未认证一律 401")
    if status == 422:
        return "GitHub 拒绝查询语法（HTTP 422）：该账号 / 该限定符不受支持"
    return (f"GitHub 限流（HTTP {status}）：代码搜索限流约 10 次/分钟，"
            "等一分钟后重试，或调小 github.max_queries")


def build_lead(domain, repo, path, rules, url=""):
    """组装一条 `leads` 行（kind=github）。

    **只写元数据**：仓库 / 文件路径 / 命中规则名 —— 不写文件内容（见文件头边界 1）。
    """
    rules = [str(r) for r in (rules or [])]
    level, notes = "info", []
    for rid in rules:
        r = rule_of(rid)
        if not r:
            continue
        if _LEVEL_RANK.get(r[2], 0) > _LEVEL_RANK.get(level, 0):
            level = r[2]
        notes.append(f"· {r[0]}：{r[3]}")
    detail = (f"仓库：{repo}\n文件：{path}\n命中规则：{' / '.join(rules) or '-'}\n"
              + ("".join(n + "\n" for n in notes))
              + "\n说明：本线索**只记录仓库 / 文件路径 / 命中规则**，不保存文件内容 —— "
                "避免把可能出现的凭据明文写进本地库、日志与报告。要看内容请人工打开下面的 URL，"
                "并注意其中可能含真实凭据。\n"
                "注意：线索≠漏洞结论（命中只说明「这个域名出现在某个公开仓库里」），需人工确认。")
    return {"kind": "github", "code": f"{repo}:{path}", "title": f"{repo} · {path}",
            "target": domain, "matched": " / ".join(rules), "level": level,
            "detail": detail, "source": "GitHub", "url": url}


def _leads_from(bucket):
    """把 `{(域名, 仓库, 路径): {rules, url}}` 摊平成按时序稳定的线索列表。"""
    rows = [build_lead(domain, repo, path, sorted(slot["rules"]), slot.get("url") or "")
            for (domain, repo, path), slot in bucket.items()]
    # 排序：级别高的在前（凭据类规则 > 纯提及），同级按 域名 → 仓库:路径，保证输出可复现
    rows.sort(key=lambda r: (-_LEVEL_RANK.get(r["level"], 0), r["target"], r["code"]))
    return rows


def collect(domains, settings, logger=None, stopped=None):
    """按规则优先级逐个注册域检索，返回 `(leads, meta)`。

    `leads` 已按 `(域名, 仓库, 路径)` **合并**：同一个文件被多条规则命中只出一条，
    规则名并进 `matched`（`db.insert_leads` 的去重键是 `(kind, code, target)`，
    `code` 就是 `仓库:路径`，所以合并必须在这里做完，否则后面的规则会被静默丢掉）。

    `meta` = `{"queries", "hits", "error", "capped"}`：
    - `queries` 实际发出的请求数（**没 token 时为 0**）；
    - `hits` GitHub 报告的命中总数（`total_count` 累加，不是我们取回的条数）；
    - `error` 空串表示正常；非空是"可直接展示给用户"的原因，**不是异常**；
    - `capped` 为 True 表示**因 `max_queries` 上限主动收手** —— 这是**设计内的行为，
      不是错误**（默认 `max_domains=3` × 4 条规则 = 12 次潜在查询，而上限是 4，
      所以正常跑就一定会触顶），调用方应据此打 info 而不是 warning。
    """
    cfg = (settings or {}).get("github", {}) or {}
    token = load_token(settings)
    if not token:
        return [], {"queries": 0, "hits": 0, "capped": False,
                    "error": "未配置 github.token（见 config/keys.yaml）——"
                             "GitHub 代码搜索接口要求认证，已跳过（一次请求都不发）"}

    def _int(key, default):
        try:
            return int(cfg.get(key, default) or default)
        except (TypeError, ValueError):
            return default

    timeout = _int("timeout", DEFAULT_TIMEOUT)
    per_page = _int("per_page", DEFAULT_PER_PAGE)
    max_queries = max(1, _int("max_queries", DEFAULT_MAX_QUERIES))

    headers = {"Accept": "application/vnd.github+json",
               "Authorization": f"Bearer {token}",
               "X-GitHub-Api-Version": "2022-11-28"}

    bucket, hits_total, queries, err = {}, 0, 0, ""
    capped = False
    for rule in SEARCH_RULES:
        if err:
            break                      # 已经是"致命原因"（限流 / 认证失败 / 网络不可达），不再发请求
        for domain in domains:
            if queries >= max_queries:
                # 上限触顶是**设计内的收手**，不是失败：默认 max_domains=3 × 4 条规则
                # = 12 次潜在查询 > 默认上限 4，正常跑就一定在这里停住。故不进 `error`
                # （否则每次正常运行都会打一条 warning，把"正常"说成"出错"）。
                capped = True
                break
            if stopped and stopped():
                err = "任务已请求停止，后续查询未发出"
                break
            queries += 1
            resp = http_request(search_url(domain, rule[1], per_page), headers=headers,
                                timeout=timeout, settings=settings)
            if not resp:
                err = "请求失败（网络不可达 / 超时 / 预算耗尽）"
                break
            status = int(resp.get("status") or 0)
            if status != 200:
                err = _status_reason(status)
                if logger:
                    logger.warning(f"[github] {err}")
                break
            hits, total, perr = parse_response(resp.get("text"), rule[0])
            hits_total += total
            if perr:
                err = perr
                break
            for h in hits:
                slot = bucket.setdefault((domain, h["repo"], h["path"]),
                                         {"rules": set(), "url": ""})
                slot["rules"].add(h["rule"])
                if not slot["url"]:
                    slot["url"] = h["url"]
            if logger:
                logger.info(f"[github] 规则 {rule[0]} × {domain} → 命中 {total} 条"
                            f"（本次取回 {len(hits)} 条）")
            # 配额见底就主动收手：GitHub 每次响应都会带这个头，不必等它回 403
            if _header(resp.get("headers"), "X-RateLimit-Remaining") == "0":
                err = ("GitHub 配额已用尽（X-RateLimit-Remaining=0），"
                       "等配额重置后再跑，或调小 github.max_queries")
                break
    return _leads_from(bucket), {"queries": queries, "hits": hits_total,
                                 "error": err, "capped": capped}


def target_domains(targets, max_domains=DEFAULT_MAX_DOMAINS):
    """把任务目标压成待检索的**注册域**列表（去重、保序、最多 `max_domains` 个）。

    - 只取目标的注册域（`utils.base_domain`）：子域名与主域的泄露命中高度重叠，
      逐个子域名去查不会扩大覆盖面，只会把限流额度瞬间打满；
    - IP / CIDR 目标跳过：拿 IP 去搜会命中大量别人的日志与文档，价值低、噪声高；
    - 认不出主机的目标（`kind=unknown`）跳过 —— **不猜**。
    """
    try:
        cap = max(1, int(max_domains or DEFAULT_MAX_DOMAINS))
    except (TypeError, ValueError):
        cap = DEFAULT_MAX_DOMAINS
    out, seen = [], set()
    for item in (targets or []):
        kind, raw = (item + ("", ""))[:2] if isinstance(item, (tuple, list)) else ("", "")
        host = ""
        if kind == "url":
            from urllib.parse import urlparse
            host = urlparse(str(raw)).hostname or ""
        elif kind == "domain":
            host = str(raw)
        # `is_domain` 不只是查 "\." ——它是纯形态判断：`127.0.0.1`（**URL 目标里的裸 IP**，
        # `urlparse().hostname` 拿到的就是它）会被它挡下，而 `base_domain("127.0.0.1")`
        # 会切出 `"0.1"` 这种**误判成域名**的垃圾，拿它去搜 GitHub 纯属浪费额度。
        if not host or not is_domain(host):
            continue
        d = base_domain(host)
        if not d or "." not in d or d in seen:
            continue
        seen.add(d)
        out.append(d)
        if len(out) >= cap:
            break
    return out
