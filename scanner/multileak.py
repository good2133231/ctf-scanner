"""多平台公开代码检索（续150-附，用户 2026-10-11 点单 11-多平台）：GitHub 之外的敏感信息检索源。

定位与 `scanner/github_leak.py` **完全同源**：这是**外部情报**，产出只进 `leads` 表
（kind=`grepapp` / `gitlab`），**不写 `vulns`、不计入漏洞数、不自动导入 POC**。

三条硬边界（改代码前先读 `scanner/github_leak.py` 文件头，那里写得比这里细）：

1. **只落元数据，绝不落文件内容**。grep.app 的每条命中带 `content.snippet`（命中处的
   **文件片段 HTML**，可能含凭据明文）—— 本模块用**字段白名单**取值（见 `normalize_hit()`），
   `content` / `snippet` 一律**不读、不存、不打印**；GitLab 命中的 `data` 是同类东西
   （命中处文件片段），`normalize_gitlab_hit()` 同样一个字都不读。
2. **`auth=False`**。所有请求走 `utils.http_request` 且**不传 `auth=True`**：任务级登录态
   （目标侧 Cookie / Token）绝不外发。本模块只在 GitLab provider 下带一个头：`PRIVATE-TOKEN`
   —— 那是 GitLab **接口本身要求**的自家只读 token（同 `github.token` 走 `Authorization`），
   与"目标侧登录态"是两回事；grepapp 依旧免 key、零凭据。
3. **默认关 + 限额**。`multileak.enabled` 默认 false；单任务最多 `max_queries` 次检索请求。

provider（续158 起两源都可用，默认仍是免 key 的 `grepapp`）：
- `grepapp`（免 key 公开接口，2026-10-11 实测可用）：
    GET https://grep.app/api/search?q=<短语>&per_page=<N>
    响应 `{"hits": {"total": N, "hits": [{"repo", "path", "branch", ...}]}}`。
- `gitlab`（2026-10-12 按官方 Search API 文档实现）：`/api/v4/search?scope=blobs&search=<域名>`，
    **每个调用都必须认证**（2026-10-11 实测匿名 401）—— token 取 `config/keys.yaml` 的
    `gitlab.token`（只读 scope 即可），**没配就零请求**并如实报"未配置"；
    实例根由 `multileak.gitlab_base` 决定（自建 GitLab 改这一项）。
失败 / 限流一律**如实写原因**，绝不把失败说成"没查到"。
"""
import json
from urllib.parse import quote

from . import github_leak, keystore
from .utils import http_request

# provider 表：kind=入库 leads 的 kind；source=展示名；api/web=检索接口与人工查看页
SOURCES = {
    "grepapp": {"kind": "grepapp", "source": "grep.app",
                "api": "https://grep.app/api/search",
                "web": "https://grep.app/search"},
    # 续158 H：GitLab 代码检索（**每个调用都必须认证**，见官方 Search API 文档）。
    # api/web 的 host 由 `multileak.gitlab_base` 决定（自建实例改这一项）；凭据读 keys.gitlab.token。
    "gitlab": {"kind": "gitlab", "source": "GitLab", "api": None, "web": None},
}
DEFAULT_PROVIDER = "grepapp"
GITLAB_DEFAULT_BASE = "https://gitlab.com"

# 检索规则：`(规则名, 级别, 说明)`。当前只有"域名出现"这一条 —— grep.app 的 `q` 是**整串文本**
# 检索（空格会被当作短语的一部分，2026-10-11 实测），无法可靠表达"域名 + 关键字"的 AND 语义，
# 故不去拼凭据类关键词（宁可少查，也不去猜一个查不准的语法）。
SEARCH_RULES = (
    ("mention", "info", "目标域名出现在公开仓库的代码/配置里"),
)
_LEVEL_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

DEFAULT_MAX_QUERIES = 4
DEFAULT_MAX_DOMAINS = 3
DEFAULT_PER_PAGE = 10
DEFAULT_MAX_LEADS = 30
DEFAULT_TIMEOUT = 20


def target_domains(targets, max_domains=DEFAULT_MAX_DOMAINS):
    """待检索**注册域**列表 —— 与 github 同口径，直接复用 `github_leak` 的收敛判据。"""
    return github_leak.target_domains(targets, max_domains)


def query_variants(domain):
    """检索短语（完整注册域优先，其次主标签）—— 复用 `github_leak` 的口径。"""
    return github_leak.query_variants(domain)


def provider_of(settings):
    """当前配置的 provider 名（缺省 / 脏值一律回落默认值，不抛）。"""
    cfg = (settings or {}).get("multileak", {}) or {}
    return str(cfg.get("provider") or DEFAULT_PROVIDER).strip().lower()


def search_url(domain, per_page=DEFAULT_PER_PAGE):
    """grep.app 检索 API 的完整 URL（`q` 整体 percent 编码）。"""
    try:
        size = int(per_page or DEFAULT_PER_PAGE)
    except (TypeError, ValueError):
        size = DEFAULT_PER_PAGE
    size = max(1, min(size, 100))
    return (f"{SOURCES[DEFAULT_PROVIDER]['api']}?"
            f"q={quote(str(domain or ''), safe='')}&per_page={size}")


def web_url(domain):
    """给人打开的检索页 URL（命中的**文件内容**只能在浏览器里看，不落库）。"""
    return f"{SOURCES[DEFAULT_PROVIDER]['web']}?q={quote(str(domain or ''), safe='')}"


# ---- 续158 H：GitLab provider（按官方 Search API 文档实现；本机缺 keys 口令 ⇒ 未做真机实测） ----
def gitlab_base(settings):
    """GitLab 实例根（`multileak.gitlab_base`，缺省 gitlab.com）。"""
    cfg = (settings or {}).get("multileak", {}) or {}
    b = str(cfg.get("gitlab_base") or GITLAB_DEFAULT_BASE).strip().rstrip("/")
    return b or GITLAB_DEFAULT_BASE


def gitlab_token(settings):
    """`config/keys.yaml` 的 `gitlab.token`（**只读** PAT）；没配返回空串。"""
    cfg = ((settings or {}).get("keys") or {}).get("gitlab") or {}
    return str(cfg.get("token") or "").strip() if isinstance(cfg, dict) else ""


def gitlab_search_url(domain, settings, per_page=DEFAULT_PER_PAGE):
    """GitLab 全局 blobs 搜索 URL：`/api/v4/search?scope=blobs&search=<词>&per_page=N`。"""
    try:
        size = int(per_page or DEFAULT_PER_PAGE)
    except (TypeError, ValueError):
        size = DEFAULT_PER_PAGE
    size = max(1, min(size, 100))
    return (f"{gitlab_base(settings)}/api/v4/search?scope=blobs&"
            f"search={quote(str(domain or ''), safe='')}&per_page={size}")


def gitlab_web_url(domain, settings):
    """给人打开的 GitLab 搜索页（文件内容只在浏览器里看）。"""
    return f"{gitlab_base(settings)}/search?scope=blobs&search={quote(str(domain or ''), safe='')}"


def normalize_gitlab_hit(raw, rule_id):
    """GitLab 命中 → **只留元数据**。刻意**不读 `data`**（那是命中处的文件片段，可能含凭据明文）。

    GitLab 的 blobs 响应**不含仓库名**（只有 `project_id`）—— 故 `repo` 记为 `gitlab#<id>`，
    不做额外 `GET /projects/:id`（省配额，且文档未承诺该字段）。
    """
    if not isinstance(raw, dict):
        return None
    pid = raw.get("project_id")
    path = str(raw.get("path") or "").strip()
    if pid in (None, "") or not path:
        return None
    return {"repo": f"gitlab#{pid}", "path": path,
            "ref": str(raw.get("ref") or "").strip(), "rule": str(rule_id or "").strip()}


def parse_gitlab_response(text, rule_id):
    """GitLab 响应（**顶层是数组**）→ `(hits, total, error)`；结构异常不抛，返回空表 + 原因。"""
    try:
        data = json.loads(text or "[]")
    except (TypeError, ValueError):
        return [], 0, "GitLab 响应不是合法 JSON"
    if not isinstance(data, list):
        return [], 0, "GitLab 响应结构异常（顶层不是数组）"
    hits = [h for h in (normalize_gitlab_hit(r, rule_id) for r in data) if h]
    return hits, len(data), ""


def _gitlab_status_reason(status):
    """GitLab 非 200 → 能直接看的原因（别把失败说成「没查到」）。"""
    if status in (401, 403):
        return (f"GitLab 拒绝认证（HTTP {status}）：keys.gitlab.token 无效 / 过期，"
                "或该 PAT 缺少 read_api / read_repository 权限")
    if status == 429:
        return "GitLab 限流（HTTP 429）：稍后重试，或调小 multileak.max_queries"
    return f"GitLab 检索失败（HTTP {status}）：已如实记录失败原因（**不等于「没查到」**）"


def normalize_hit(raw, rule_id):
    """把一条命中规整成**只含元数据**的结构（字段白名单）。

    刻意**不读 `content` / `content.snippet`** —— 那是命中处的文件片段 HTML，可能含凭据明文
    （见文件头边界 1）。拿不到仓库或路径的命中直接丢弃（无从溯源）。
    """
    if not isinstance(raw, dict):
        return None
    repo = str(raw.get("repo") or "").strip()
    path = str(raw.get("path") or "").strip()
    if not repo or not path:
        return None
    return {"repo": repo, "path": path, "rule": str(rule_id or "").strip()}


def parse_response(text, rule_id, query=""):
    """解析 grep.app 响应 → `(hits, total, error)`；结构异常**不抛异常**，返回空表 + 原因。"""
    try:
        data = json.loads(text or "{}")
    except (TypeError, ValueError):
        return [], 0, "grep.app 响应不是合法 JSON"
    if not isinstance(data, dict):
        return [], 0, "grep.app 响应结构异常（顶层不是对象）"
    hits_obj = data.get("hits")
    total, items = 0, []
    if isinstance(hits_obj, dict):
        try:
            total = int(hits_obj.get("total") or 0)
        except (TypeError, ValueError):
            total = 0
        items = hits_obj.get("hits") or []
    hits = []
    for raw in items:
        h = normalize_hit(raw, rule_id)
        if h:
            hits.append(h)
    return hits, total, ""


def _status_reason(status):
    """把非 200 状态码翻成"能直接给用户看"的原因（别让人以为"查过了、没泄露"）。"""
    if status == 429:
        return ("grep.app 限流（HTTP 429）：免 key 公共接口有速率限制，稍后重试，"
                "或调小 multileak.max_queries")
    return (f"grep.app 检索失败（HTTP {status}）：已如实记录失败原因"
            "（**不等于「没查到」**）")


def build_lead(domain, repo, path, rules, url="", weak=False, provider=DEFAULT_PROVIDER):
    """组装一条 `leads` 行 —— 字段口径与 `github_leak.build_lead` 一致。

    **只写元数据**：仓库 / 文件路径 / 命中规则名 —— 不写文件内容（见文件头边界 1）。
    """
    src = SOURCES.get(provider) or SOURCES[DEFAULT_PROVIDER]
    rules = [str(r) for r in (rules or [])]
    level, notes = "info", []
    for rid in rules:
        r = github_leak.rule_of(rid)
        if not r:
            continue
        if _LEVEL_RANK.get(r[2], 0) > _LEVEL_RANK.get(level, 0):
            level = r[2]
        notes.append(f"· {r[0]}：{r[3]}")
    # 与 github 同一口径：命中"公共分流名单"形态 → 标注 + **只降不升**（宁标不删）。
    if github_leak.listy_public_list(path) and level != "info":
        level = "info"
        notes.append("· 疑似公共分流名单/路由规则表：这类文件整批抄入几千个域名，"
                     "「域名 + 关键字同文件」是常态，**不等于目标方凭据泄露**"
                     "（已降为 info，仅作参考）")
    # 续157：#11 弱相关改由 `_leads_from` 按配置决定后传进来（与 github_leak.build_lead 同口径）；
    # 此前**无条件降级**，配了 `multileak.weak_downgrade=false` 也不生效。
    if weak and level != "info":
        level = "info"
        notes.append("· 弱相关：仓库名与文件路径里都没有出现目标域名或其主标签，命中只可能来自"
                     "文件内容（同名字符串 / 无关项目）—— 已降为 info，请人工核对后再判断")
    detail = (f"仓库：{repo}\n文件：{path}\n命中规则：{' / '.join(rules) or '-'}\n"
              + "".join(n + "\n" for n in notes)
              + "\n说明：本线索**只记录仓库 / 文件路径 / 命中规则**，不保存文件内容 —— "
                "避免把可能出现的凭据明文写进本地库、日志与报告。要看内容请人工打开下面的 URL，"
                "并注意其中可能含真实凭据。\n"
                "注意：线索≠漏洞结论（命中只说明「这个域名出现在某个公开仓库里」），需人工确认。")
    return {"kind": src["kind"], "code": f"{repo}:{path}", "title": f"{repo} · {path}",
            "target": domain, "matched": " / ".join(rules), "level": level,
            "detail": detail, "source": src["source"], "url": url}


def _leads_from(bucket, weak_downgrade=True, whitelist=(), provider=DEFAULT_PROVIDER):
    """把 `{(域名, 仓库, 路径): {rules, url}}` 摊平成按时序稳定的线索列表。

    续157：#11 弱相关判定与 `github_leak._leads_from` **同一口径**（此前硬编码在 build_lead 里）。
    `weak_downgrade=False` 关掉降级；`whitelist` 里任一子串出现在仓库名/文件路径即视为相关。
    """
    wl = tuple(str(x).strip().lower() for x in (whitelist or ()) if str(x).strip())

    def _weak(domain, repo, path):
        blob = f"{repo} {path}".lower()
        nd = str(domain or "").strip().lower()
        lab = github_leak.label_of(nd)
        if any(x in blob for x in wl):
            return False
        return not ((nd and nd in blob) or (lab and lab in blob))

    rows = [build_lead(domain, repo, path, sorted(slot["rules"]), slot.get("url") or "",
                       weak=(weak_downgrade and _weak(domain, repo, path)), provider=provider)
            for (domain, repo, path), slot in bucket.items()]
    rows.sort(key=lambda r: (-_LEVEL_RANK.get(r["level"], 0), r["target"], r["code"]))
    return rows


def collect(domains, settings, logger=None, stopped=None):
    """按注册域逐个检索，返回 `(leads, meta)`（口径与 `github_leak.collect` 一致）。

    `meta` = `{"queries", "hits", "error", "capped"}`：
    - `queries` 实际发出的请求数（provider 未实现时为 0）；
    - `hits` 接口报告的命中总数（`hits.total` 累加）；
    - `error` 空串表示正常；非空是"可直接展示给用户"的原因，**不是异常**；
    - `capped` 为 True 表示因 `max_queries` 上限主动收手（**设计内行为，不是错误**）。
    """
    cfg = (settings or {}).get("multileak", {}) or {}
    provider = provider_of(settings)
    if provider == "gitlab":
        # 续158 H：GitLab 搜索**每个调用都必须认证**（官方文档）⇒ 没 token 一次请求都不发。
        if not gitlab_token(settings):
            return [], {"queries": 0, "hits": 0, "capped": False,
                        "error": keystore.keys_hint("gitlab.token") + "—— GitLab 搜索接口"
                                 "要求认证，已跳过（一次请求都不发）"}
    elif provider not in SOURCES:
        return [], {"queries": 0, "hits": 0, "capped": False,
                    "error": f"未实现的多平台检索源 {provider!r}（当前 grepapp / gitlab）—— "
                             "已跳过（一次请求都不发）"}

    def _int(key, default):
        try:
            return int(cfg.get(key, default) or default)
        except (TypeError, ValueError):
            return default

    timeout = _int("timeout", DEFAULT_TIMEOUT)
    per_page = _int("per_page", DEFAULT_PER_PAGE)
    max_queries = max(1, _int("max_queries", DEFAULT_MAX_QUERIES))

    # grepapp：只带 Accept。gitlab：另加 `PRIVATE-TOKEN` —— 那是**第三方凭据**（同 github.token
    # 走 Authorization），与「任务级登录态绝不外发」（见文件头边界 2）不是一回事。
    _is_gl = provider == "gitlab"
    headers = ({"Accept": "application/json", "PRIVATE-TOKEN": gitlab_token(settings)}
               if _is_gl else {"Accept": "application/json"})

    bucket, hits_total, queries, err, capped = {}, 0, 0, "", False
    stop = False
    for rule in SEARCH_RULES:
        if stop:
            break
        for domain in domains:
            if stop:
                break
            for variant in query_variants(domain):
                if queries >= max_queries:
                    capped = True          # 上限触顶是设计内收手，不进 error
                    stop = True
                    break
                if stopped and stopped():
                    err = "任务已请求停止，后续查询未发出"
                    stop = True
                    break
                queries += 1
                _u = (gitlab_search_url(variant, settings, per_page) if _is_gl
                      else search_url(variant, per_page))
                resp = http_request(_u, headers=headers, timeout=timeout, settings=settings)
                if not resp:
                    err = "请求失败（网络不可达 / 超时 / 预算耗尽）"
                    stop = True
                    break
                status = int(resp.get("status") or 0)
                if status != 200:
                    err = (_gitlab_status_reason(status) if _is_gl else _status_reason(status))
                    if logger:
                        logger.warning(f"[multileak] {err}")
                    stop = True
                    break
                hits, total, perr = (parse_gitlab_response(resp.get("text"), rule[0]) if _is_gl
                                     else parse_response(resp.get("text"), rule[0], variant))
                hits_total += total
                if perr:
                    err = perr
                    stop = True
                    break
                for h in hits:
                    slot = bucket.setdefault((domain, h["repo"], h["path"]),
                                             {"rules": set(), "url": ""})
                    slot["rules"].add(h["rule"])
                    if not slot["url"]:
                        slot["url"] = (gitlab_web_url(variant, settings) if _is_gl
                                       else web_url(variant))
                if logger:
                    logger.info(f"[multileak] 注册域 {domain}（{SOURCES[provider]['source']}）"
                                f"× {variant} → 命中 {total} 条（本次取回 {len(hits)} 条）")
    # 续157：#11 弱相关降级 / 白名单可配（缺省 = 旧行为：降级开、无白名单）
    _raw_wd = cfg.get("weak_downgrade", True)
    weak_downgrade = not (_raw_wd is False
                          or str(_raw_wd).strip().lower() in ("false", "0", "no", "off"))
    _wl = cfg.get("relevance_whitelist") or []
    if not isinstance(_wl, (list, tuple)):
        _wl = [x for x in str(_wl).split(",") if x.strip()]
    return _leads_from(bucket, weak_downgrade=weak_downgrade, whitelist=_wl,
                       provider=provider), \
        {"queries": queries, "hits": hits_total, "error": err, "capped": capped}
