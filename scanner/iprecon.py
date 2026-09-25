"""IP 反查域名 + C 段归纳（P1-4，参考项目 `spider/ip2domain.py` 的启发）。

用途（发散思维的那一条腿）：CTF 里主目标常常只有一个 IP/域名，但**同一个 C 段**里的
相邻主机往往属于同一套业务（同机房/同客户/同备案主体），是拿 flag 的常见旁路。
本模块把已有 IP 反查成域名，并把 IP 归纳成 `/24` C 段，供 `osint` 阶段落库。

**免 key**：默认走公共接口 `https://api.webscan.cc/?action=query&ip={ip}`（可配置替换）。
公共接口可用性无保障，因此 `iprecon.enabled` **默认关闭**，失败只记日志不影响主流程。

与参考项目的差异（必须说明，见 TODO.md B-3）：
- 参考项目用 `eval(text)` 解析响应 —— 那是**危险写法**（响应内容可控即任意代码执行）。
  本实现用 `json.loads` 并逐项校验结构，非法数据一律丢弃。
- 参考项目每请求新建 aiohttp ClientSession（性能反模式）；本实现沿用
  `utils.http_request` + `pool_run`，与全框架的 UA 随机化 / 超时 / TLS 策略保持一致。
- 限流：公共接口默认只开 5 个并发、单 IP 只查一次、**失败不重试**，不做任何轰炸。
"""
import ipaddress
import json
import re

from .utils import http_request, pool_run

DEFAULT_API = "https://api.webscan.cc/?action=query&ip={ip}"
# 默认反查源顺序；可在 settings["iprecon"]["sources"] 覆盖（名字须在 _SOURCES 注册）
DEFAULT_SOURCES = ["webscan", "hackertarget", "ip138"]

# 反查回来的域名做基本合法性过滤（公共接口的返回里偶尔混入 IP 或空值）
_DOMAIN_OK = set("abcdefghijklmnopqrstuvwxyz0123456789.-*")  # 不含 `_`：与 utils.is_domain 口径一致


def is_public_ip(ip):
    """是否可用于对外反查（私有/保留/环回/组播地址一律跳过 —— 查了也是浪费配额）。"""
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_multicast or addr.is_reserved or addr.is_unspecified)


def segment_of(ip):
    """把 IPv4 归纳为 `/24` C 段（如 `1.2.3.4` → `1.2.3.0/24`）。

    非 IPv4（含 IPv6）返回 "" —— IPv6 的"段"概念与 IPv4 完全不同，不做臆测。
    """
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return ""
    if addr.version != 4:
        return ""
    return str(ipaddress.ip_network(f"{addr}/24", strict=False))


def group_segments(ips):
    """按 C 段分组：{segment: [ip, ...]}（IP 有序去重，段按字符串排序）。"""
    groups = {}
    for ip in dict.fromkeys(str(i).strip() for i in (ips or []) if str(i).strip()):
        seg = segment_of(ip)
        if not seg:
            continue
        groups.setdefault(seg, []).append(ip)
    return {k: sorted(v, key=lambda s: ipaddress.ip_address(s)) for k, v in sorted(groups.items())}


def normalize_domain(raw):
    """归一化反查结果：去端口/去通配前缀/去空白/转小写；不合格返回 ""。"""
    d = str(raw or "").strip().lower()
    if not d or " " in d:
        return ""
    d = d.split(":")[0].lstrip("*.")
    if "." not in d or set(d) - _DOMAIN_OK:
        return ""
    if not d.split(".")[-1].isalpha() or len(d.split(".")[-1]) < 2:
        return ""
    return d


def parse_domains(text):
    """解析反查响应，返回归一化后的域名列表（顺序去重）。

    兼容三种形态，全部**先 `json.loads` 再校验**：
    - `null`（接口对无结果 IP 的约定返回）→ 空表；
    - `[{"domain": "a.example.com", ...}, ...]`（webscan.cc 形态）；
    - `["a.example.com", ...]`（部分镜像接口直接给字符串数组）。
    非 JSON / 结构不符一律返回空表，绝不 `eval`。
    """
    raw = (text or "").strip()
    if not raw or raw.lower() in ("null", "none"):
        return []
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return []
    if isinstance(data, dict):
        data = data.get("data") or data.get("result") or []
    if not isinstance(data, list):
        return []
    out, seen = [], set()
    for item in data:
        if isinstance(item, dict):
            item = item.get("domain") or item.get("host") or ""
        d = normalize_domain(item)
        if d and d not in seen:
            seen.add(d)
            out.append(d)
    return out


def _reverse_webscan(ip, settings, logger=None, timeout=None):
    """默认源：api.webscan.cc（免 key，可配置替换 URL，见 settings["iprecon"]["api"]）。"""
    cfg = (settings or {}).get("iprecon", {}) or {}
    api = str(cfg.get("api") or DEFAULT_API)
    url = api.format(ip=ip) if "{ip}" in api else f"{api}{ip}"
    try:
        resp = http_request(url, timeout=timeout, settings=settings)
    except Exception as e:  # 网络层异常不该影响流水线
        if logger:
            logger.debug(f"[iprecon] {ip} webscan 反查异常：{e}")
        return []
    if not resp or resp.get("status") != 200:
        if logger:
            logger.debug(f"[iprecon] {ip} webscan 反查失败（HTTP {resp.get('status') if resp else '-'}）")
        return []
    return parse_domains(resp.get("text"))


def _reverse_hackertarget(ip, settings, logger=None, timeout=None):
    """HackerTarget 反向 IP 查询（免 key，纯文本每行一个域名；失败即弃，绝不 eval）。

    `https://api.hackertarget.com/reverseiplookup/?q={ip}` 限流时返回 "error: ..." 文本，
    这里直接判为非结果返回空表，不抛异常。
    """
    cfg = (settings or {}).get("iprecon", {}) or {}
    api = str(cfg.get("api_hackertarget")
              or "https://api.hackertarget.com/reverseiplookup/?q={ip}")
    url = api.format(ip=ip) if "{ip}" in api else f"{api}{ip}"
    try:
        resp = http_request(url, timeout=timeout, settings=settings)
    except Exception as e:
        if logger:
            logger.debug(f"[iprecon] {ip} hackertarget 反查异常：{e}")
        return []
    if not resp or resp.get("status") != 200:
        return []
    text = (resp.get("text") or "").strip()
    if not text or text.lower().startswith("error"):
        return []
    out, seen = [], set()
    for line in text.splitlines():
        d = normalize_domain(line)
        if d and d not in seen:
            seen.add(d)
            out.append(d)
    return out


def _reverse_ip138(ip, settings, logger=None, timeout=None):
    """ip138 反查（免 key，HTML 页面提取域名；失败即弃，绝不 eval）。

    仅作补充源：HTML 结构可能变动导致返回空，属预期降级（webscan/hackertarget 保底）。
    不解析 JS、不 eval，只用正则从 `<a href="/example.com/">` 形态的链接里抽域名，
    天然排除 `/static/` 等站内资源路径与自身站点域名。
    """
    cfg = (settings or {}).get("iprecon", {}) or {}
    api = str(cfg.get("api_ip138") or "https://site.ip138.com/{ip}/domain/")
    url = api.format(ip=ip) if "{ip}" in api else f"{api}{ip}"
    try:
        resp = http_request(url, timeout=timeout, settings=settings)
    except Exception as e:
        if logger:
            logger.debug(f"[iprecon] {ip} ip138 反查异常：{e}")
        return []
    if not resp or resp.get("status") != 200:
        return []
    text = resp.get("text") or ""
    out, seen = [], set()
    # 只认「整段就是域名」的相对链接（如 /example.com/），排除 /static/ 与自身站点
    for m in re.finditer(r'href=["\']/((?:[a-z0-9-]+\.)+[a-z]{2,})/?["\']', text, re.I):
        d = normalize_domain(m.group(1))
        if d and d not in seen and not d.endswith(("ip138.com", "ip138.net")):
            seen.add(d)
            out.append(d)
    return out


def _reverse_dnsdblookup(ip, settings, logger=None, timeout=None):
    """dnsdblookup 反查（可选第四源，HTML 爬取，失败即弃，默认**不**启用）。

    默认不在 `DEFAULT_SOURCES` 里；需用户在 settings["iprecon"]["sources"] 显式加
    "dnsdblookup" 才会跑。无稳定 JSON 接口，退化为从页面抽域名，脏数据一律 normalize 后丢弃。
    """
    cfg = (settings or {}).get("iprecon", {}) or {}
    api = str(cfg.get("api_dnsdblookup") or "https://dnsdblookup.com/?query={ip}")
    url = api.format(ip=ip) if "{ip}" in api else f"{api}{ip}"
    try:
        resp = http_request(url, timeout=timeout, settings=settings)
    except Exception as e:
        if logger:
            logger.debug(f"[iprecon] {ip} dnsdblookup 反查异常：{e}")
        return []
    if not resp or resp.get("status") != 200:
        return []
    text = resp.get("text") or ""
    out, seen = [], set()
    for m in re.finditer(r'((?:[a-z0-9-]+\.)+[a-z]{2,})', text, re.I):
        d = normalize_domain(m.group(1))
        if d and d not in seen and not d.endswith(("dnsdblookup.com",)):
            seen.add(d)
            out.append(d)
    return out


# 反查源注册表：名字 → 适配器（任何源失败一律返回 []，永不向外抛异常）
_SOURCES = {
    "webscan": _reverse_webscan,
    "hackertarget": _reverse_hackertarget,
    "ip138": _reverse_ip138,
    "dnsdblookup": _reverse_dnsdblookup,
}


def reverse_lookup(ip, settings, logger=None, timeout=None):
    """单个 IP 反查域名，返回域名列表（失败/无结果返回空表，异常不外抛）。

    多源：依次尝试 `settings["iprecon"]["sources"]`（默认 webscan → hackertarget → ip138），
    各源结果做 **union**（任一源非空即采用合并结果；单源失败/空继续下一个；全部失败返回 []）。
    所有请求均走 `utils.http_request`（共享 UA/超时/TLS），解析只用 `json.loads`/正则，绝不 eval。
    """
    cfg = (settings or {}).get("iprecon", {}) or {}
    sources = cfg.get("sources") or DEFAULT_SOURCES
    if timeout is None:
        timeout = float(cfg.get("timeout") or 10)
    merged, got = set(), False
    for name in sources:
        adapter = _SOURCES.get(str(name).strip().lower())
        if adapter is None:
            if logger:
                logger.debug(f"[iprecon] {ip} 未知反查源：{name}")
            continue
        try:
            doms = adapter(ip, settings, logger=logger, timeout=timeout)
        except Exception as e:  # 兜底：任何源抛异常都不该影响流水线
            if logger:
                logger.debug(f"[iprecon] {ip} 源 {name} 反查异常：{e}")
            doms = []
        if doms:
            got = True
            merged.update(doms)
    return sorted(merged) if got else []


def lookup_many(ips, settings, logger=None, stop=None):
    """并发反查多个 IP，返回 `(mapping, stats)`。

    mapping: `{ip: [domain, ...]}`（只含查到结果的 IP）
    stats:   `{"attempted": n, "hit_ips": n, "domains": n}`
    仅公开 IP 会被查询，私有地址由 `is_public_ip` 直接过滤（参考项目同样这么做，
    但它是逐条 try/except，这里用标准库 `ipaddress` 显式判定，语义更清楚）。
    """
    cfg = (settings or {}).get("iprecon", {}) or {}
    candidates = [ip for ip in dict.fromkeys(ips or []) if is_public_ip(ip)]
    stats = {"attempted": len(candidates), "skipped_private": len(list(dict.fromkeys(ips or []))) - len(candidates),
             "hit_ips": 0, "domains": 0}
    if not candidates:
        return {}, stats
    workers = max(1, min(int(cfg.get("workers") or 5), len(candidates)))
    timeout = float(cfg.get("timeout") or 10)

    def _one(ip):
        if stop and stop():
            return None
        return (ip, reverse_lookup(ip, settings, logger=logger, timeout=timeout))

    results = pool_run(_one, candidates, workers=workers)
    mapping = {ip: doms for ip, doms in results if doms}
    stats["hit_ips"] = len(mapping)
    stats["domains"] = sum(len(v) for v in mapping.values())
    return mapping, stats