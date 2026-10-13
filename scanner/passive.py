"""多来源被动子域名收集（免 API key 的公开接口）。

设计约束：
- 所有请求必须走 `utils.http_request`（统一 UA / 超时 / `limits.verify_tls`）；
- **单源失败只影响该源**（记一条日志后返回空集），绝不中断整轮收集；
- 全是只读查询，不产生任何写入型请求，符合非破坏性约束。

来源选择依据：只接"免 key 且响应体里直接含子域名字符串"的接口。
参考项目（对标物，路径见 `TODO.md` 末尾的「参考项目借鉴清单」）的 `spider/thirdLib/*`
共 20+ 源，其中**需要 key 的一律不接**（fofa / shodan / quake / censys / virustotal /
threatbook / securitytrails / riskiq / fullhunt / bevigil / chinaz），
它们留给 `TODO.md` P0-5 的 `config/keys.yaml` 方案。

解析策略（重要取舍）：**不为每个源写专用 JSON 解析**。那些接口随时改字段名/改结构，
写死的解析器会集体失效；实测这些源返回的域名都是明文出现在 JSON/HTML 文本里，
因此统一用 `_extract()` 正则提取"以根域名结尾的主机名"，通吃且稳。
"""
import re
import time

from .utils import http_request, http_last_error, pool_run

# 注册表：源名 -> URL 模板（{d} 为根域名）。全部免 key。
SOURCES = {
    "crt.sh": "https://crt.sh/?q=%25.{d}&output=json",
    "certspotter": ("https://api.certspotter.com/v1/issuances?domain={d}"
                    "&include_subdomains=true&expand=dns_names"),
    "alienvault": "https://otx.alienvault.com/api/v1/indicators/domain/{d}/passive_dns",
    "hackertarget": "https://api.hackertarget.com/hostsearch/?q={d}",
    "rapiddns": "https://rapiddns.io/subdomain/{d}?full=1",
    "sublist3r": "https://api.sublist3r.com/search.php?domain={d}",
    # 以下两个历史上不稳定（HTTP 站点/接口变更），默认不启用，但保留可随时在配置里打开
    "sitedossier": "http://www.sitedossier.com/parentdomain/{d}",
    "bufferover": "http://dns.bufferover.run/dns?q=.{d}",
}

# 默认启用的源（config/settings.yaml 的 passive.sources 可覆盖）
DEFAULT_SOURCES = ["crt.sh", "certspotter", "alienvault",
                   "hackertarget", "rapiddns", "sublist3r"]

_TOKEN_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_\-.]{0,253}")


def _extract(text, domain):
    """从任意响应体（JSON / HTML / 纯文本）提取以 domain 结尾的主机名。"""
    out = set()
    suffix = "." + domain.lower()
    for tok in _TOKEN_RE.findall(text or ""):
        tok = tok.strip(".-").lower()
        if tok.endswith(suffix) and "*" not in tok and ".." not in tok:
            out.add(tok)
    return out


def _probe(source, url, domain, settings, timeout):
    """探一个源：返回 `(source, 子域名集合或 None, 原因)`。

    `原因` 只在没取到时非空，并且**必须说清是哪一种**（续165）：网络不可达（还能区分超时 /
    DNS / TLS / 连接被拒）/ HTTP 非 200 / 空响应体 / 响应正常但零匹配。此前这四种全被压成
    一句"无结果或不可达"，实测里"源挂了"与"这个域名真没有记录"完全分不开。
    计时一并带上：能看出是"打到超时"还是"秒回空"。
    """
    t0 = time.time()
    try:
        resp = http_request(url, timeout=timeout, settings=settings)
    except Exception as e:                      # noqa: BLE001 —— 单源失败绝不许炸整轮
        return source, None, f"内部异常：{type(e).__name__}"
    dt = time.time() - t0
    if not resp:
        # 失败原因由 `http_request` 旁路写进线程本地（同线程紧接着读，见 utils.http_last_error）
        why = http_last_error() or "无响应"
        return source, None, f"不可达：{why}（耗时 {dt:.1f}s，上限 {timeout}s）"
    status = resp.get("status")
    text = resp.get("text") or ""
    nbytes = resp.get("length") or len(text)
    if not text:
        return source, None, f"HTTP {status} 空响应体（{nbytes} 字节，耗时 {dt:.1f}s）"
    found = _extract(text, domain)
    if not found:
        # 语义不变：只要有响应体就尝试提取；这里只是把"提取到 0 个"的原因说全
        if status and int(status) >= 400:
            return source, None, f"HTTP {status}（响应 {nbytes} 字节，未匹配到子域名，耗时 {dt:.1f}s）"
        return source, None, f"HTTP {status} 响应 {nbytes} 字节，未匹配到 {domain} 的子域名"
    return source, found, ""


def collect(domain, settings, logger=None, workers=6):
    """并发跑全部启用来源，返回 {subdomain: "passive:<源名>"}（同名只记首个来源）。"""
    cfg = (settings or {}).get("passive", {}) or {}
    if cfg.get("enabled") is False:
        return {}
    names = cfg.get("sources") or DEFAULT_SOURCES
    timeout = int(cfg.get("timeout", 20) or 20)
    jobs = [(n, SOURCES[n].format(d=domain)) for n in names if n in SOURCES]
    if not jobs:
        return {}

    out, hit_sources = {}, 0
    unreachable = zero = 0
    for source, found, why in pool_run(
            lambda j: _probe(j[0], j[1], domain, settings, timeout),
            jobs, workers=min(workers, len(jobs)),
            logger=logger, label="被动来源"):
        if not found:
            if why.startswith("不可达"):
                unreachable += 1
            else:
                zero += 1
            if logger:
                logger.info(f"[passive] {source} 未取到（{domain}）：{why}")
            continue
        hit_sources += 1
        for name in found:
            out.setdefault(name, f"passive:{source}")
        if logger:
            logger.info(f"[passive] {source} → {len(found)} 个（{domain}）")

    # 只保留"确实来自某个源"的名字；调用方负责与其它来源合并、去重
    if logger:
        logger.info(f"[passive] {domain} 汇总 {len(out)} 个（{hit_sources}/{len(jobs)} 个源有结果；"
                    f"其余 {zero} 个无结果、{unreachable} 个不可达）")
    return out