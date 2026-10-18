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
import threading

from .utils import http_last_error, http_request, is_domain, pool_run, to_ascii

DEFAULT_API = "https://api.webscan.cc/?action=query&ip={ip}"
# 默认反查源顺序；可在 settings["iprecon"]["sources"] 覆盖（名字须在 _SOURCES 注册）
DEFAULT_SOURCES = ["webscan", "hackertarget", "ip138"]

# 续173：每个源**这一次调用**的 HTTP 状态/失败原因。适配器仍然返回"域名列表"这一份契约
# （旧调用方一个都不改），状态只作旁路；按线程存放，`reverse_lookup_detail` 在同一个线程里
# 紧接着读。为什么不在适配器里直接改返回形状：`_SOURCES` 还被 preflight/测试直接调用，
# 改形状会把"空结果"与"HTTP 530"混成同一个 []。
_SRC_LOCAL = threading.local()


def _src_mark(status=0, reason="", found=None):
    _SRC_LOCAL.status = int(status or 0)
    _SRC_LOCAL.reason = str(reason or "")
    _SRC_LOCAL.found = found


def source_last():
    """本线程最近一次源调用的 `{status, reason, found}`（没有调用过返回 0/空）。"""
    return {"status": int(getattr(_SRC_LOCAL, "status", 0) or 0),
            "reason": str(getattr(_SRC_LOCAL, "reason", "") or ""),
            "found": getattr(_SRC_LOCAL, "found", None)}


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
    """归一化反查结果：去端口/去通配前缀/去空白/转小写，再统一成 ASCII(punycode) 形；不合格返回 ""。

    口径**收敛到 `utils.is_domain`**（不再维护本地逐字符白名单 `_DOMAIN_OK`）：IDN 反查结果
    （`例子.中国` 或 `xn--fsqu00a.xn--fiqs8s`）现在能返回，代价是两条**收紧**——
    ① 中段 `*`（`a.*.com`）由"接受"变"拒绝"（反向查询不会返回中段 `*`；前导 `*.` 仍在检查前
    `lstrip`）；② 总长 ≤253 / 单 label ≤63 现在被 `is_domain` 强制（原先无上限）。
    不变项：拆端口、去前导 `*.`、小写、拒空格、≥2 段、拒 IP。
    """
    d = str(raw or "").strip().lower()
    if not d or " " in d:
        return ""
    d = d.split(":")[0].lstrip("*.")
    d = to_ascii(d) or ""
    return d if is_domain(d) else ""


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


def _reverse_webscan(ip, settings, logger=None, timeout=None, raw=False):
    """默认源：api.webscan.cc（免 key，可配置替换 URL，见 settings["iprecon"]["api"]）。

    `raw=True` 是**探活模式**（续184）：把原始响应 `{"status": …, "text": …}` 原样返回，
    供 `preflight()` 只看状态码判断这个接口还活不活 —— 解析留给正式那一次。
    """
    cfg = (settings or {}).get("iprecon", {}) or {}
    api = str(cfg.get("api") or DEFAULT_API)
    url = api.format(ip=ip) if "{ip}" in api else f"{api}{ip}"
    _src_mark(0, "")
    try:
        resp = http_request(url, timeout=timeout, settings=settings)
    except Exception as e:  # 网络层异常不该影响流水线
        _src_mark(0, http_last_error() or type(e).__name__)
        if logger:
            logger.debug(f"[iprecon] {ip} webscan 反查异常：{e}")
        return {"status": 0} if raw else []
    status = int((resp or {}).get("status") or 0)
    _src_mark(status, "" if status == 200 else (f"HTTP {status}" if status else "不可达"))
    if raw:
        return resp or {"status": 0}
    if not resp or status != 200:
        if logger:
            logger.debug(f"[iprecon] {ip} webscan 反查失败（HTTP {status or '-'}）")
        return []
    out = parse_domains(resp.get("text"))
    _src_mark(200, "", len(out))
    return out


def _reverse_hackertarget(ip, settings, logger=None, timeout=None, raw=False):
    """HackerTarget 反向 IP 查询（免 key，纯文本每行一个域名；失败即弃，绝不 eval）。

    `https://api.hackertarget.com/reverseiplookup/?q={ip}` 限流时返回 "error: ..." 文本，
    这里直接判为非结果返回空表，不抛异常。`raw=True` 同 `preflight()` 探活模式。
    """
    cfg = (settings or {}).get("iprecon", {}) or {}
    api = str(cfg.get("api_hackertarget")
              or "https://api.hackertarget.com/reverseiplookup/?q={ip}")
    url = api.format(ip=ip) if "{ip}" in api else f"{api}{ip}"
    _src_mark(0, "")
    try:
        resp = http_request(url, timeout=timeout, settings=settings)
    except Exception as e:
        _src_mark(0, http_last_error() or type(e).__name__)
        if logger:
            logger.debug(f"[iprecon] {ip} hackertarget 反查异常：{e}")
        return {"status": 0} if raw else []
    status = int((resp or {}).get("status") or 0)
    _src_mark(status, "" if status == 200 else (f"HTTP {status}" if status else "不可达"))
    if raw:
        return resp or {"status": 0}
    if not resp or status != 200:
        return []
    text = (resp.get("text") or "").strip()
    if not text or text.lower().startswith("error"):
        _src_mark(200, "接口返回 error 文本", 0)
        return []
    out, seen = [], set()
    for line in text.splitlines():
        d = normalize_domain(line)
        if d and d not in seen:
            seen.add(d)
            out.append(d)
    _src_mark(200, "", len(out))
    return out


def _reverse_ip138(ip, settings, logger=None, timeout=None, raw=False):
    """ip138 反查（免 key，HTML 页面提取域名；失败即弃，绝不 eval）。

    仅作补充源：HTML 结构可能变动导致返回空，属预期降级（webscan/hackertarget 保底）。
    不解析 JS、不 eval，只用正则从 `<a href="/example.com/">` 形态的链接里抽域名，
    天然排除 `/static/` 等站内资源路径与自身站点域名。`raw=True` 同探活模式。
    """
    cfg = (settings or {}).get("iprecon", {}) or {}
    api = str(cfg.get("api_ip138") or "https://site.ip138.com/{ip}/domain/")
    url = api.format(ip=ip) if "{ip}" in api else f"{api}{ip}"
    _src_mark(0, "")
    try:
        resp = http_request(url, timeout=timeout, settings=settings)
    except Exception as e:
        _src_mark(0, http_last_error() or type(e).__name__)
        if logger:
            logger.debug(f"[iprecon] {ip} ip138 反查异常：{e}")
        return {"status": 0} if raw else []
    status = int((resp or {}).get("status") or 0)
    _src_mark(status, "" if status == 200 else (f"HTTP {status}" if status else "不可达"))
    if raw:
        return resp or {"status": 0}
    if not resp or status != 200:
        return []
    text = resp.get("text") or ""
    out, seen = [], set()
    # 只认「整段就是域名」的相对链接（如 /example.com/），排除 /static/ 与自身站点
    for m in re.finditer(r'href=["\']/((?:[a-z0-9-]+\.)+[a-z]{2,})/?["\']', text, re.I):
        d = normalize_domain(m.group(1))
        if d and d not in seen and not d.endswith(("ip138.com", "ip138.net")):
            seen.add(d)
            out.append(d)
    _src_mark(200, "", len(out))
    return out


def _reverse_dnsdblookup(ip, settings, logger=None, timeout=None, raw=False):
    """dnsdblookup 反查（备用源，HTML 爬取，失败即弃）。

    续184 起进了**备用池**（`fallback_sources`）：默认源预检全挂时才上场。
    无稳定 JSON 接口，退化为从页面抽域名，脏数据一律 normalize 后丢弃。`raw=True` 同探活模式。
    """
    cfg = (settings or {}).get("iprecon", {}) or {}
    api = str(cfg.get("api_dnsdblookup") or "https://dnsdblookup.com/?query={ip}")
    url = api.format(ip=ip) if "{ip}" in api else f"{api}{ip}"
    _src_mark(0, "")
    try:
        resp = http_request(url, timeout=timeout, settings=settings)
    except Exception as e:
        _src_mark(0, http_last_error() or type(e).__name__)
        if logger:
            logger.debug(f"[iprecon] {ip} dnsdblookup 反查异常：{e}")
        return {"status": 0} if raw else []
    status = int((resp or {}).get("status") or 0)
    _src_mark(status, "" if status == 200 else (f"HTTP {status}" if status else "不可达"))
    if raw:
        return resp or {"status": 0}
    if not resp or status != 200:
        return []
    text = resp.get("text") or ""
    out, seen = [], set()
    for m in re.finditer(r'((?:[a-z0-9-]+\.)+[a-z]{2,})', text, re.I):
        d = normalize_domain(m.group(1))
        if d and d not in seen and not d.endswith(("dnsdblookup.com",)):
            seen.add(d)
            out.append(d)
    _src_mark(200, "", len(out))
    return out


def _html_domains(text, exclude=()):
    """从 HTML 里抽"看着像域名"的串（备用源共用；脏数据一律 normalize 后丢弃，绝不 eval）。"""
    out, seen = [], set()
    for m in re.finditer(r'((?:[a-z0-9-]+\.)+[a-z]{2,})', text or "", re.I):
        d = normalize_domain(m.group(1))
        if not d or d in seen:
            continue
        if any(d == e or d.endswith("." + e) for e in exclude):
            continue
        seen.add(d)
        out.append(d)
    return out


def _reverse_rapiddns(ip, settings, logger=None, timeout=None, raw=False):
    """rapiddns 反查（备用源，免 key；续184 入备用池）。`raw=True` 为探活模式。"""
    cfg = (settings or {}).get("iprecon", {}) or {}
    api = str(cfg.get("api_rapiddns") or "https://rapiddns.io/s/{ip}?full=1")
    url = api.format(ip=ip) if "{ip}" in api else f"{api}{ip}"
    _src_mark(0, "")
    try:
        resp = http_request(url, timeout=timeout, settings=settings)
    except Exception as e:
        _src_mark(0, http_last_error() or type(e).__name__)
        if logger:
            logger.debug(f"[iprecon] {ip} rapiddns 反查异常：{e}")
        return {"status": 0} if raw else []
    status = int((resp or {}).get("status") or 0)
    _src_mark(status, "" if status == 200 else (f"HTTP {status}" if status else "不可达"))
    if raw:
        return resp or {"status": 0}
    if not resp or status != 200:
        return []
    out = _html_domains(resp.get("text"), exclude=("rapiddns.io",))
    _src_mark(200, "", len(out))
    return out


def _reverse_viewdns(ip, settings, logger=None, timeout=None, raw=False):
    """viewdns 反查（备用源，免 key；续184 入备用池）。`raw=True` 为探活模式。"""
    cfg = (settings or {}).get("iprecon", {}) or {}
    api = str(cfg.get("api_viewdns") or "https://viewdns.info/reverseip/?host={ip}&t=1")
    url = api.format(ip=ip) if "{ip}" in api else f"{api}{ip}"
    _src_mark(0, "")
    try:
        resp = http_request(url, timeout=timeout, settings=settings)
    except Exception as e:
        _src_mark(0, http_last_error() or type(e).__name__)
        if logger:
            logger.debug(f"[iprecon] {ip} viewdns 反查异常：{e}")
        return {"status": 0} if raw else []
    status = int((resp or {}).get("status") or 0)
    _src_mark(status, "" if status == 200 else (f"HTTP {status}" if status else "不可达"))
    if raw:
        return resp or {"status": 0}
    if not resp or status != 200:
        return []
    out = _html_domains(resp.get("text"), exclude=("viewdns.info",))
    _src_mark(200, "", len(out))
    return out


def _reverse_ptr(ip, settings=None, logger=None, timeout=None, raw=False):
    """**本框架自己实现**的原生反查：直接问 DNS 的 PTR 记录（`x.x.x.x.in-addr.arpa`）。

    第三方 HTTP 接口会挂（530 / 429 / 改版 / 封出口），PTR 是唯一不求人的一路：
    它**不发 HTTP**，因此也不参与接口存活预检。拿不到（没配 PTR / NXDOMAIN / DNS 不可达）
    就返回 []，绝不臆造 —— 有 PTR 的主机多半给出机房或 CDN 的主机名，那是**事实**不是结论，
    落库按来源标 `ptr`，判断留给使用者（续184，用户 2026-10-14 点单）。
    """
    import socket
    _ip = str(ip).strip()
    _src_mark(0, "")
    try:
        _old = socket.getdefaulttimeout()
        socket.setdefaulttimeout(float(timeout or 5))
        try:
            host = socket.gethostbyaddr(_ip)[0]
        finally:
            socket.setdefaulttimeout(_old)
    except Exception as e:      # 没 PTR / 超时 / DNS 挂了 —— 都算"没查到"
        _src_mark(0, f"无 PTR 记录（{type(e).__name__}）")
        if logger:
            logger.debug(f"[iprecon] {_ip} 原生 PTR 无结果：{e}")
        return {"status": 0} if raw else []
    d = normalize_domain(host or "")
    if not d or not is_domain(d):
        _src_mark(200, "PTR 结果不是合法域名", 0)
        return {"status": 0} if raw else []
    _src_mark(200, "", 1)
    return {"status": 200} if raw else [d]


# 反查源注册表：名字 → 适配器（任何源失败一律返回 []，永不向外抛异常）
_SOURCES = {
    "webscan": _reverse_webscan,
    "hackertarget": _reverse_hackertarget,
    "ip138": _reverse_ip138,
    "dnsdblookup": _reverse_dnsdblookup,
    "rapiddns": _reverse_rapiddns,
    "viewdns": _reverse_viewdns,
    "ptr": _reverse_ptr,
}
# 原生源（不依赖任何第三方 HTTP 接口）：**不参与**接口存活预检，恒可用
DNS_SOURCES = {"ptr"}
# 默认源全部预检失败时的备用池（原生 PTR 排第一 —— 接口全挂时它还在）
DEFAULT_FALLBACK = ["ptr", "dnsdblookup", "rapiddns", "viewdns"]


def preflight(sources, settings, logger=None, timeout=None, probe_ip=""):
    """开跑前**先探一次**每个源还活不活（续184；用户 2026-10-14：「开始之前就要看接口存活状态」）。

    返回 `(可用源名单, {源: 不可用原因})`：HTTP 源对 `probe_ip` 发**一次**请求，拿到 200
    即存活（空结果也算活 —— 接口通、只是这个 IP 没记录）；非 200 / 异常 ⇒ **整轮跳过**该源，
    不再让它对每个 IP 各打一条 DEBUG（实测 500 个 IP 全白跑一遍就是这个症状）。
    原生源（`DNS_SOURCES`）不发 HTTP，恒可用。没有探活 IP 时原样返回，不做无意义探测。
    """
    cfg = (settings or {}).get("iprecon", {}) or {}
    srcs = [str(s).strip().lower() for s in (sources or DEFAULT_SOURCES)]
    if not cfg.get("preflight", True) or not probe_ip:
        return srcs, {}
    ok, report = [], {}
    for n in srcs:
        adapter = _SOURCES.get(n)
        if adapter is None:
            report[n] = "未注册的源名"
            continue
        if n in DNS_SOURCES:
            ok.append(n)
            continue
        try:
            resp = adapter(probe_ip, settings, logger=None, timeout=timeout, raw=True)
            status = int((resp or {}).get("status") or 0)
        except Exception as e:
            report[n] = f"异常 {type(e).__name__}"
            continue
        if status == 200:
            ok.append(n)
        else:
            report[n] = f"HTTP {status}" if status else "不可达"
    return ok, report


def _classify_source(domains, last):
    """把"这次源调用"归成五档之一（续173；页面/日志只要这一句就够）。"""
    if domains:
        return "ok"
    status = int((last or {}).get("status") or 0)
    reason = str((last or {}).get("reason") or "")
    if status >= 400:
        return "http_error"
    if status == 200:
        return "empty"
    if status == 0 and reason and not reason.startswith(("无 PTR", "PTR 结果")):
        return "network_error"
    return "empty" if reason else "error"


def reverse_lookup_detail(ip, settings, logger=None, timeout=None, sources=None):
    """单个 IP 反查域名，返回 `(域名列表, 逐源结果)`（续173）。

    域名列表与旧 `reverse_lookup` **同一口径**：依次试 `sources`、各源 union、全空返回 []。
    逐源结果是旁路，形状 `[{name, status, http, found, reason}]`：
    `status` ∈ `ok` / `empty` / `http_error` / `network_error` / `unregistered`。
    这样"主源被挡 / 备源压根没试 / 三路都空"在页面上分得开，不再只有一句"反查失败"。
    """
    cfg = (settings or {}).get("iprecon", {}) or {}
    # 显式传 `[]` = "预检后一个源都不剩" ⇒ 真的一个都不试；旧写法 `sources or …` 会把空表
    # 当成"没传"，回头再打一遍已判定挂掉的源（续216 连带修复）。
    sources = sources if sources is not None else (cfg.get("sources") or DEFAULT_SOURCES)
    if timeout is None:
        timeout = float(cfg.get("timeout") or 10)
    merged, got, detail = set(), False, []
    for name in sources:
        key = str(name).strip().lower()
        adapter = _SOURCES.get(key)
        if adapter is None:
            if logger:
                logger.debug(f"[iprecon] {ip} 未知反查源：{name}")
            detail.append({"name": key or str(name), "status": "unregistered",
                           "http": 0, "found": 0, "reason": "未注册的源名"})
            continue
        _src_mark(0, "")
        try:
            doms = adapter(ip, settings, logger=logger, timeout=timeout)
        except Exception as e:  # 兜底：任何源抛异常都不该影响流水线
            _src_mark(0, http_last_error() or type(e).__name__)
            if logger:
                logger.debug(f"[iprecon] {ip} 源 {name} 反查异常：{e}")
            doms = []
        last = source_last()
        detail.append({"name": key, "status": _classify_source(doms, last),
                       "http": last["status"], "found": len(doms or []),
                       "reason": last["reason"]})
        if doms:
            got = True
            merged.update(doms)
    return (sorted(merged) if got else []), detail


def reverse_lookup(ip, settings, logger=None, timeout=None, sources=None, detail=None):
    """单个 IP 反查域名，返回域名列表（旧 API，行为不变；`detail` 传入 list 时原地填逐源结果）。"""
    domains, rows = reverse_lookup_detail(ip, settings, logger=logger, timeout=timeout,
                                          sources=sources)
    if isinstance(detail, list):
        detail.extend(rows)
    return domains


def format_source_stats(stats):
    """把 `lookup_many` 的逐源汇总压成**一行**中文（日志/落档共用，续173）。

    `stats` 形状见 `lookup_many` 的 `stats["sources"]`；没有数据返回空串。
    只报次数与原因，绝不带任何凭据/响应正文。
    """
    parts = []
    for name, s in sorted((stats or {}).items()):
        if not isinstance(s, dict):
            continue
        if s.get("skipped"):
            parts.append(f"{name} 未试（{s.get('reason') or '预检失败'}）")
            continue
        bits = [f"试{s.get('attempted', 0)}", f"成{s.get('ok', 0)}",
                f"空{s.get('empty', 0)}", f"错{s.get('error', 0)}"]
        codes = s.get("http") or {}
        if codes:
            bits.append("HTTP " + "/".join(f"{k}×{v}" for k, v in sorted(codes.items())))
        reasons = s.get("reasons") or {}
        if reasons:
            top = sorted(reasons.items(), key=lambda kv: (-kv[1], kv[0]))[:2]
            bits.append("原因 " + "、".join(f"{k}×{v}" for k, v in top))
        parts.append(f"{name} " + "，".join(bits))
    return "；".join(parts)


def lookup_many(ips, settings, logger=None, stop=None):
    """并发反查多个 IP，返回 `(mapping, stats)`。

    mapping: `{ip: [domain, ...]}`（只含查到结果的 IP）
    stats:   `{"attempted": n, "hit_ips": n, "domains": n}`
    仅公开 IP 会被查询，私有地址由 `is_public_ip` 直接过滤（参考项目同样这么做，
    但它是逐条 try/except，这里用标准库 `ipaddress` 显式判定，语义更清楚）。
    """
    cfg = (settings or {}).get("iprecon", {}) or {}
    candidates = [ip for ip in dict.fromkeys(ips or []) if is_public_ip(ip)]
    stats = {"attempted": len(candidates),
             "skipped_private": len(list(dict.fromkeys(ips or []))) - len(candidates),
             "hit_ips": 0, "domains": 0, "sources": {}}
    if not candidates:
        return {}, stats
    workers = max(1, min(int(cfg.get("workers") or 5), len(candidates)))
    timeout = float(cfg.get("timeout") or 10)

    # 续184：开跑前先探活 —— 挂掉的源**整轮跳过**（不再每个 IP 各打一条 DEBUG）；
    # 默认源全挂时换备用池，备用池里第一个是**原生 PTR**（不发 HTTP，接口全挂它还在）。
    _srcs = cfg.get("sources") or DEFAULT_SOURCES
    _ok, _bad = preflight(_srcs, settings, logger=logger, timeout=timeout,
                          probe_ip=candidates[0])
    if _bad and logger:
        logger.warning("[iprecon] 反查源预检：" +
                       "；".join(f"{k} {v}" for k, v in _bad.items()) +
                       f" —— 本轮跳过这几个源（{len(candidates)} 个 IP 不再逐个白跑）")
    _preflight_bad = dict(_bad or {})
    if not _ok:
        _fb = cfg.get("fallback_sources") or DEFAULT_FALLBACK
        _ok, _bad2 = preflight(_fb, settings, logger=logger, timeout=timeout,
                               probe_ip=candidates[0])
        _preflight_bad.update(_bad2 or {})
        if logger:
            logger.warning(f"[iprecon] 默认源全部不可用，改用备用源：{_ok or '（无）'}"
                           + (f"；仍不可用：{_bad2}" if _bad2 else ""))

    def _one(ip):
        if stop and stop():
            return None
        rows = []
        doms = reverse_lookup(ip, settings, logger=logger, timeout=timeout,
                              sources=_ok, detail=rows)
        return (ip, doms, rows)

    results = pool_run(_one, candidates, workers=workers, logger=logger, label="ip 反查")
    src_stats = {str(name): {"skipped": 1, "attempted": 0, "ok": 0, "empty": 0,
                             "error": 0, "domains": 0, "reason": str(why)}
                 for name, why in _preflight_bad.items()}
    mapping = {}
    for item in results or []:
        if not item:
            continue
        ip, doms, rows = item
        if doms:
            mapping[ip] = doms
        for row in rows or []:
            name = row.get("name") or "未知"
            s = src_stats.setdefault(name, {"skipped": 0, "attempted": 0, "ok": 0,
                                             "empty": 0, "error": 0, "domains": 0,
                                             "http": {}, "reasons": {}})
            s["attempted"] = int(s.get("attempted", 0)) + 1
            status = row.get("status")
            if status == "ok":
                s["ok"] = int(s.get("ok", 0)) + 1
            elif status == "empty":
                s["empty"] = int(s.get("empty", 0)) + 1
            else:
                s["error"] = int(s.get("error", 0)) + 1
            s["domains"] = int(s.get("domains", 0)) + int(row.get("found") or 0)
            code = int(row.get("http") or 0)
            if code:
                s.setdefault("http", {})
                s["http"][str(code)] = int(s["http"].get(str(code), 0)) + 1
            why = str(row.get("reason") or "")
            if why:
                s.setdefault("reasons", {})
                s["reasons"][why] = int(s["reasons"].get(why, 0)) + 1
    stats["sources"] = src_stats
    stats["hit_ips"] = len(mapping)
    stats["domains"] = sum(len(v) for v in mapping.values())
    return mapping, stats