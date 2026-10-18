"""ICP 备案反查（续205，主理人点单"备案接口不通就想办法弄新的接口或别的方式"）。

**先说清为什么做成"可插拔 + 预检"**：国内备案数据的源头只有一个 —— 工信部
`hlwicpfwc.miit.gov.cn`（`beian.miit.gov.cn` 是它的前端）。开源项目
（`wongzeon/ICP-Checker`、`HG-ha/ICP_Query`）最终都打这个域名，而它是**国内托管**，
在海外出口的机器上 DNS 就失败（本机实测：同机 GitHub 200、这些域名 `http=000`）。
所以"换一个免费接口"解决不了问题 —— 要么换机器/加代理，要么用一个**海外托管**的
镜像或付费 API（如阿里云市场的 APPCODE 型接口）。

于是本模块的设计目标是：**源全部走配置，加源不改代码**。
- `icp.sources`（`config/settings.yaml`）是一个列表，每项
  `{"name": "aliyun", "url": "https://…/icp?domain={{domain}}", "key_header": "APPCODE"}`；
  `{{domain}}` 会被替换成要查的域名；`key_header` 非空时会把 `icp.api_key`（**只进
  `config/keys.enc.yaml`，不落明文**）按那个头名带上。
- 预置源只有**确认存在**的那个（官方，路径来自上面两个开源项目的实际调用）。
- **连通性预检**（照 `iprecon.preflight` 的口径）：开跑前每个源先探一次，不通的
  **整轮跳过并说清原因**，不让它对每个域名各打一条失败日志（500 个域名全白跑一遍
  就是这个症状）。
- 产出按 `osint:icp` 前缀落 `subdomains` ⇒ 与 C 段反查、FOFA 同属"外部情报拓展"面
  （`OWN_SUBDOMAIN_WHERE` 因此自动把它划到拓展域名页，不混进自家子域名）。
  价值最大的一块是**同主体其他域名**：备案主体名下的域名往往就是同一个客户的其它站。

**边界**：只读 GET/POST 查询，不写任何东西；`icp.enabled` **出厂关**。
"""
import json
import re

from .utils import http_request

# 预置源：**只有路径是确认存在的**（来自两个开源项目的实际调用）。
# 官方源需要 token + 验证码，且域名在国内 ⇒ 海外出口通常不可达；留着它是为了
# "换机器/加代理后立刻可用"，以及作为配置格式的范例。
DEFAULT_SOURCES = [
    {"name": "miit",
     "url": "https://hlwicpfwc.miit.gov.cn/icpproject_query/api/"
            "icpAbbreviateInfo/queryByCondition",
     "key_header": "token",
     "note": "工信部官方（需 token+验证码；域名在国内，海外出口通常不可达）"},
]

# 响应里"域名"字段的常见形态（不同源命名不一，尽量都认）
_DOMAIN_KEYS = ("domain", "domainName", "domains", "siteDomain", "webDomain")
_NAME_KEYS = ("unitName", "orgName", "company", "ownerName", "name")
_NOISE_DOMAIN = re.compile(r"^[a-z0-9.-]*\b(xxx|test|example|localhost)\b", re.I)


def _sources(settings):
    """配置里的源列表（缺省用预置）。每条至少要有 `name` 与 `url`。"""
    cfg = (settings or {}).get("icp", {}) or {}
    srcs = [s for s in (cfg.get("sources") or DEFAULT_SOURCES)
            if isinstance(s, dict) and str(s.get("url") or "").strip()]
    for i, s in enumerate(srcs, 1):
        s.setdefault("name", f"src{i}")
        s.setdefault("key_header", "")
    return srcs


def _api_key(settings):
    """查询用的 key：优先 `settings["keys"]["icp"]["api_key"]`（加密凭据，**不落明文**）。

    settings.yaml 里那个 `icp.api_key` 是历史占位（也已写死为空），只在没有 keys 段时兜底 ——
    续216 的安装凭据录入把值写进 `keys.enc.yaml`，若这里只读 settings 段，用户填了也等于没填。
    """
    keys = ((settings or {}).get("keys") or {}).get("icp") or {}
    val = str(keys.get("api_key") or "").strip()
    if val:
        return val
    cfg = (settings or {}).get("icp", {}) or {}
    return str(cfg.get("api_key") or "").strip()


def _fill(url, domain):
    return str(url).replace("{{domain}}", str(domain)).replace("{{ target }}", str(domain))


def preflight(sources, settings, logger=None, timeout=10):
    """每个源先探一次，返回 `(可用源, {源: 不可用原因})`。

    口径与 `iprecon.preflight` 一致：**探通才算活**（空结果也算活 —— 接口通、
    只是这个域名没备案）；非 200 / 异常 ⇒ 整轮跳过。关掉预检（`icp.preflight=false`）
    或没有可探的域名时原样返回，不做无意义探测。
    """
    cfg = (settings or {}).get("icp", {}) or {}
    srcs = sources or _sources(settings)
    if cfg.get("preflight", True) is False or not srcs:
        return list(srcs), {}
    probe = str(cfg.get("probe_domain") or "example.com").strip() or "example.com"
    ok, bad = [], {}
    for s in srcs:
        url = _fill(s["url"], probe)
        try:
            r = http_request(url, timeout=timeout, settings=settings, auth=False)
        except Exception as e:                       # noqa: BLE001 —— 探活不许把整轮带崩
            bad[s["name"]] = f"请求异常：{type(e).__name__}"
            continue
        if not r or not r.get("status"):
            bad[s["name"]] = "没有响应（DNS 失败 / 连接被拒 / 超时）"
            continue
        code = int(r.get("status") or 0)
        if code != 200:
            bad[s["name"]] = f"HTTP {code}"
            continue
        ok.append(s)
    if logger:
        for s in srcs:
            if s["name"] in bad:
                logger.info(f"[icp] 源 {s['name']} 不可用，本轮跳过：{bad[s['name']]}"
                            f"（{s.get('note') or ''}）")
    return ok, bad


def _domains_of(payload):
    """从一份源的响应里抠出域名（JSON 优先；认多种常见字段名）。"""
    out = []
    if isinstance(payload, dict):
        for k in _DOMAIN_KEYS:
            v = payload.get(k)
            if isinstance(v, str) and v.strip():
                out.extend(re.split(r"[,;\s]+", v.strip()))
            elif isinstance(v, list):
                out.extend(str(x) for x in v if str(x).strip())
        # 嵌套一层（有些源包在 params/result 里）。**直接 extend 返回值** ——
        # 写成 `extend(_domains_of(x) for x in …)` 会把一个个 list 塞进 out，
        # 后面 `.strip()` 就炸（本轮实测就是这个形状）。
        for k in ("params", "result", "data", "list"):
            v = payload.get(k)
            if isinstance(v, list):
                for x in v:
                    if isinstance(x, dict):
                        out.extend(_domains_of(x))
            elif isinstance(v, dict):
                out.extend(_domains_of(v))
    return [d.strip().lower().strip(".") for d in out if d and d.strip()]


def query(domain, settings, source, logger=None, timeout=10):
    """向单个源查一个域名，返回 `{domains: [...], org: str}` 或 None。"""
    url = _fill(source["url"], domain)
    headers = {}
    kh = str(source.get("key_header") or "").strip()
    key = _api_key(settings)
    if kh and key:
        headers[kh] = key          # 值只进请求头，不进日志、不进 argv
    try:
        r = http_request(url, timeout=timeout, settings=settings, auth=False,
                         headers=headers or None)
    except Exception as e:                       # noqa: BLE001 —— 单源失败不该带崩整轮
        if logger:
            logger.debug(f"[icp] {source['name']} 查 {domain} 异常：{type(e).__name__} {e}")
        return None
    if not r or not r.get("status"):
        return None
    try:
        payload = json.loads(r.get("text") or "")
    except Exception:
        payload = None
    doms = _domains_of(payload) if payload is not None else []
    org = ""
    if isinstance(payload, dict):
        for k in _NAME_KEYS:
            if str(payload.get(k) or "").strip():
                org = str(payload[k]).strip()
                break
    return {"domains": [d for d in doms if not _NOISE_DOMAIN.match(d)],
            "org": org}


def run(ctx, logger=None):
    """跑一轮备案反查：返回 `(新增域名数, 说清情况的一行字)`。

    输入域名来自本任务的子域名（`own` 口径 + 全部，取前 `max_domains` 个 —— 备案查询
    是按次计费的/限流的，全量打一遍既慢又把配额烧光）。
    """
    log = logger or getattr(ctx, "logger", None)
    cfg = (ctx.settings.get("icp", {}) or {}) if ctx else {}
    if cfg.get("enabled") is not True:
        return 0, "未启用（策略 icp.enabled=false）"
    from . import db
    rows = db._query("SELECT domain FROM subdomains WHERE task_id=?", (ctx.task_id,))
    domains = [str(r["domain"]).strip().lower().strip(".") for r in rows if r["domain"]]
    domains = list(dict.fromkeys(domains))[: int(cfg.get("max_domains", 50) or 50)]
    if not domains:
        return 0, "本任务没有可查的域名"
    ok, bad = preflight(_sources(ctx.settings), ctx.settings, logger=log)
    if not ok:
        why = "；".join(f"{k}={v}" for k, v in list(bad.items())[:3])
        return 0, f"全部源都不可用，本轮跳过（{why}）—— 换机器/加代理，或在 icp.sources 里加一个可达的源"
    found, orgs = set(), set()
    for d in domains:
        for s in ok:
            got = query(d, ctx.settings, s, logger=log)
            if not got:
                continue
            orgs.update([x for x in [got.get("org")] if x])
            found.update(got.get("domains") or [])
            break                      # 一个域名有一个源答了就够（不重复烧配额）
    new = sorted(x for x in found if x and x not in set(domains))
    if not new:
        return 0, f"查了 {len(domains)} 个域名，没有反查出新域名（{len(ok)} 个源可用）"
    n = db.insert_subdomains(ctx.task_id, [(d, "osint:icp") for d in new])
    if log:
        log.info(f"[icp] 备案反查：{len(domains)} 个域名 → 新域名 {n} 条"
                 f"（同主体：{'、'.join(sorted(orgs)[:3]) or '未知'}）")
    return n, f"反查出 {n} 个同主体域名"
