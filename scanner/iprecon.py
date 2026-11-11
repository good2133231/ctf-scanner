"""IP 反查域名 +（历史）C 段归纳（P1-4，参考项目 `spider/ip2domain.py` 的启发）。

用途（发散思维的那一条腿）：CTF 里主目标常常只有一个域名，域名解析出的**精确 IP** 上
可能还挂着同一套业务的其他域名，是拿 flag 的常见旁路。本模块把已有 IP 反查成域名；
`osint._ip_reverse()` 按精确 IP 调用，不展开 `/24`。`group_segments()` 与 C 段归纳只保留
给历史数据/回归测试，生产新任务不再写入。

**免 key**：默认走 `mnemonic, otx, urlscan, hackertarget` 四个免 key 公共接口
（Mnemonic/OTX/URLScan 不需要注册；HackerTarget 有免费日配额）；webscan/ip138 退备用池。
公共接口可用性无保障，因此 `iprecon.enabled` **代码默认关闭、随包配置打开**；
失败只记日志、不重试、不影响主流程；每个 HTTP 源有独立的 10 次失败/100 次跳过熔断。

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
import time

from .utils import http_last_error, http_request, is_domain, pool_run, to_ascii

DEFAULT_API = "https://api.webscan.cc/?action=query&ip={ip}"
DEFAULT_MNEMONIC_API = "https://api.mnemonic.no/pdns/v3/{ip}?limit={limit}"
DEFAULT_URLSCAN_API = "https://urlscan.io/api/v1/search/?q=ip:{ip}&size={limit}"
# 默认反查源顺序；可在 settings["iprecon"]["sources"] 覆盖（名字须在 _SOURCES 注册）
# 续339：Mnemonic 公共 PDNS 免 key、历史覆盖好；URLScan 免 key 但只覆盖最近 30 天；
# webscan / ip138 退到备用池（webscan 实测 530、ip138 常 200-空，不再占默认名额）。
DEFAULT_SOURCES = ["mnemonic", "otx", "urlscan", "hackertarget"]

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


# ---------- 接口熔断（续339，主理人 2026-11-05 口述规则） ----------
# 规则：同一个源连续失败 fail_threshold（默认 10）次 → 熔断；之后**跳过** cooldown
# （默认 100）次调用；第 101 次做半开探测：能用就恢复，继续每次检查；再失败则重新
# 计数并再次跳过 100 次。跳过本身也计数（不是只按时间），这样「一个接口10次都不能用
# 100次之内不调用他」在并发/多任务里也是确定的。
# 状态放进程内存（GUI 队列 worker 与任务同进程；重启后重置是刻意的：重启后重新观察）。
_BREAKER_LOCK = threading.Lock()
_BREAKER = {}


def _breaker_cfg(settings):
    cfg = (settings or {}).get("iprecon", {}) or {}
    try:
        threshold = max(1, int(cfg.get("breaker_fail_threshold") or 10))
    except (TypeError, ValueError):
        threshold = 10
    try:
        cooldown = max(1, int(cfg.get("breaker_cooldown") or 100))
    except (TypeError, ValueError):
        cooldown = 100
    return bool(cfg.get("breaker_enabled", True)), threshold, cooldown


def reset_breaker(sources=None):
    """测试/人工排障用：清空熔断状态（传空=全部清空）。"""
    with _BREAKER_LOCK:
        if sources is None:
            _BREAKER.clear()
        else:
            for name in sources:
                _BREAKER.pop(str(name).strip().lower(), None)


def breaker_snapshot():
    """返回源健康快照（只读拷贝；页面/日志/测试用，不返回任何凭据）。"""
    with _BREAKER_LOCK:
        return {k: dict(v) for k, v in _BREAKER.items()}


def _breaker_allow(name, settings):
    """调用前检查：`(是否允许, 跳过原因)`；打开状态会消耗一次 cooldown 名额。"""
    key = str(name).strip().lower()
    if key in DNS_SOURCES:
        return True, ""
    enabled, _threshold, cooldown = _breaker_cfg(settings)
    if not enabled:
        return True, ""
    with _BREAKER_LOCK:
        st = _BREAKER.setdefault(key, {
            "failures": 0, "open": False, "skipped": 0, "half_open": False,
            "last_reason": "", "opened_at": 0.0})
        if not st["open"]:
            return True, ""
        if int(st["skipped"]) < cooldown:
            st["skipped"] = int(st["skipped"]) + 1
            return False, f"熔断中，跳过 {st['skipped']}/{cooldown} 次"
        st["half_open"] = True
        return True, "半开探测"


def _breaker_record(name, ok, settings, logger=None, reason=""):
    """记录一次真实调用结果；连续失败到阈值则打开，半开成功则关闭。"""
    key = str(name).strip().lower()
    if key in DNS_SOURCES:
        return
    enabled, threshold, cooldown = _breaker_cfg(settings)
    if not enabled:
        return
    with _BREAKER_LOCK:
        st = _BREAKER.setdefault(key, {
            "failures": 0, "open": False, "skipped": 0, "half_open": False,
            "last_reason": "", "opened_at": 0.0})
        if ok:
            was_open = bool(st.get("open"))
            st.update(failures=0, open=False, skipped=0, half_open=False,
                      last_reason="")
            _msg = None
            if was_open:
                _msg = f"[iprecon] 源 {key} 半开探测成功，已恢复；之后每次调用继续检查"
        elif st.get("open") and st.get("half_open"):
            st.update(half_open=False, skipped=0,
                      last_reason=str(reason or "半开探测失败")[:200])
            _msg = (f"[iprecon] 源 {key} 半开探测仍失败（{reason or '无原因'}），"
                    f"重新熔断，再跳过 {cooldown} 次")
        else:
            st["failures"] = int(st.get("failures") or 0) + 1
            st["last_reason"] = str(reason or "")[:200]
            _msg = None
            if st["failures"] >= threshold:
                st.update(open=True, skipped=0, half_open=False,
                          opened_at=time.time())
                _msg = (f"[iprecon] 源 {key} 连续失败 {st['failures']} 次"
                        f"（{reason or '无原因'}），熔断；接下来跳过 {cooldown} 次调用，"
                        f"第 {cooldown + 1} 次再探活")
    if _msg and logger:
        (logger.warning if st.get("open") else logger.info)(_msg)


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
    # 续255：`.arpa` 是 IANA 保留给反向 DNS / 基础设施的 TLD（`8.8.8.8.in-addr.arpa`、
    # `…ip6.arpa`），永远不是可扫资产。真机实测（2026-10-21，hackertarget 对 8.8.8.8 /
    # 1.1.1.1 的响应）：这类反解链占据返回列表前列；IP 命中数 ≤30（未判共享主机）时
    # 整页 arpa 链会被当"域名"写进 `csegs.domains` 与 `osint:cseg` 资产面。挡在归一化
    # 出口 = 六个适配器与 PTR 一并生效，不逐源打补丁。`utils.is_domain` 形态上仍认
    # `.arpa`（那是通用形态判据），这里只收 IP 反查这一条出口。
    if d.endswith(".arpa"):
        return ""
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
    except Exception as e:      # noqa: BLE001 - 第三方源适配器：网络/解析任何异常都只算该源没查到
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
    except Exception as e:      # noqa: BLE001 - 第三方源适配器：网络/解析任何异常都只算该源没查到
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
    # 续255：真机实测（2026-10-21 连跑几批后）hackertarget 配额耗尽时返回
    # **HTTP 200** + "API count exceeded - Increase Quota with Membership" 文本。
    # 不识别的话它会被归进 `empty`，与"这个 IP 没记录"混为一谈 —— 续173 要的
    # "成败说清"在配额这条路上又聋了。五档契约不动（仍 empty：确实没拿到域名），
    # 但 reason 点名配额，`format_source_stats` 的原因列会把它顶上汇总行。
    if text.lower().startswith("api count exceeded"):
        _src_mark(200, "接口配额耗尽（hackertarget 免费配额，HTTP 200 但不出数）", 0)
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
    except Exception as e:      # noqa: BLE001 - 第三方源适配器：网络/解析任何异常都只算该源没查到
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
    except Exception as e:      # noqa: BLE001 - 第三方源适配器：网络/解析任何异常都只算该源没查到
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
    # 续315：复用 `_html_domains`（原来这里自写一遍正则，绕过了文件后缀/CDN 过滤）
    out = _html_domains(text, exclude=("dnsdblookup.com",))
    _src_mark(200, "", len(out))
    return out


# 续319（主理人 2026-11-03 点单）：补两个**被动 DNS（历史解析）**源。
# 与 FOFA `ip=`（当前资产快照）互补：FOFA 找"现在同 IP 的活资产"，这两个找"历史上解析到该 IP 的域名"。
# VT 需要 key（免费 4 次/分钟）；OTX 免 key、有限速。
VT_API = ("https://www.virustotal.com/api/v3/ip_addresses/{ip}/resolutions"
          "?limit={limit}")
OTX_API = "https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/passive_dns"


def _vt_key(settings):
    """VT key 从 `settings["keys"]["virustotal"]["key"]` 取（keystore 加密档同一条通道）。"""
    cfg = ((settings or {}).get("keys") or {}).get("virustotal") or {}
    return str(cfg.get("key") or "").strip() if isinstance(cfg, dict) else ""


def _reverse_virustotal(ip, settings, logger=None, timeout=None, raw=False):
    """VirusTotal v3 `/ip_addresses/{ip}/resolutions`（历史解析；无 key 不发请求）。"""
    key = _vt_key(settings)
    if not key:
        _src_mark(0, "未配置 virustotal.key（config/keys.enc.yaml）", 0)
        return {"status": 0} if raw else []
    try:
        limit = int(((settings or {}).get("iprecon") or {}).get("vt_limit", 40) or 40)
    except (TypeError, ValueError):
        limit = 40
    limit = max(1, min(limit, 40))          # VT v3 resolutions 单页上限 40
    resp = http_request(VT_API.format(ip=ip, limit=limit), timeout=timeout or 20,
                        headers={"x-apikey": key}, settings=settings)
    status = int((resp or {}).get("status") or 0)
    if status == 401:
        _src_mark(401, "VT key 无效（HTTP 401）", 0)
        return {"status": 401} if raw else []
    if status == 429:
        _src_mark(429, "VT 限速（免费 key 4 次/分钟）", 0)
        return {"status": 429} if raw else []
    _src_mark(status, "" if status == 200 else (f"HTTP {status}" if status else "不可达"))
    if raw:
        return resp or {"status": 0}
    if not resp or status != 200:
        return []
    try:
        data = json.loads(resp.get("text") or "{}")
    except (ValueError, TypeError):
        _src_mark(200, "响应不是合法 JSON", 0)
        return []
    out, seen = [], set()
    for item in (data.get("data") or []):
        if not isinstance(item, dict):
            continue
        attrs = item.get("attributes") or {}
        d = normalize_domain(str(attrs.get("host_name") or ""))
        if d and is_domain(d) and d not in seen:
            seen.add(d)
            out.append(d)
    _src_mark(200, "", len(out))
    return out


def _reverse_otx(ip, settings, logger=None, timeout=None, raw=False):
    """AlienVault OTX passive DNS（历史解析，免 key）。结果过 `_html_domains` 同一套噪声过滤。"""
    resp = http_request(OTX_API.format(ip=ip), timeout=timeout or 20, settings=settings)
    status = int((resp or {}).get("status") or 0)
    _src_mark(status, "" if status == 200 else (f"HTTP {status}" if status else "不可达"))
    if raw:
        return resp or {"status": 0}
    if not resp or status != 200:
        return []
    try:
        data = json.loads(resp.get("text") or "{}")
    except (ValueError, TypeError):
        _src_mark(200, "响应不是合法 JSON", 0)
        return []
    names = [str(r.get("hostname") or "") for r in (data.get("passive_dns") or [])
             if isinstance(r, dict)]
    # 复用统一过滤：OTX 实测会回 0137246.com 这类垃圾，静态资源名/CDN 域也要挡
    out = _html_domains("\n".join(names))
    _src_mark(200, "", len(out))
    return out


def _reverse_mnemonic(ip, settings, logger=None, timeout=None, raw=False):
    """Mnemonic 公共 Passive DNS（免 key，历史覆盖好；续339 实测一个 IP 回 35 条）。

    响应形态：`{"responseCode":200,"data":[{"query":"www.example.com","answer":"1.2.3.4"},...]}`。
    只取 `query`，交给 `_html_domains` 统一去噪；不做 eval。`raw=True` 为预检模式。
    """
    cfg = (settings or {}).get("iprecon", {}) or {}
    api = str(cfg.get("api_mnemonic") or DEFAULT_MNEMONIC_API)
    try:
        limit = max(1, min(int(cfg.get("mnemonic_limit") or 100), 1000))
    except (TypeError, ValueError):
        limit = 100
    url = api.replace("{ip}", ip).replace("{limit}", str(limit))
    if "{ip}" not in api and "{limit}" not in api:
        url = f"{api}{ip}"
    _src_mark(0, "")
    try:
        resp = http_request(url, timeout=timeout or 20, settings=settings)
    except Exception as e:      # noqa: BLE001 - 第三方源适配器：网络/解析任何异常都只算该源没查到
        _src_mark(0, http_last_error() or type(e).__name__)
        if logger:
            logger.debug(f"[iprecon] {ip} mnemonic 反查异常：{e}")
        return {"status": 0} if raw else []
    status = int((resp or {}).get("status") or 0)
    _src_mark(status, "" if status == 200 else (f"HTTP {status}" if status else "不可达"))
    if raw:
        return resp or {"status": 0}
    if not resp or status != 200:
        return []
    try:
        data = json.loads(resp.get("text") or "{}")
    except (ValueError, TypeError):
        _src_mark(200, "响应不是合法 JSON", 0)
        return []
    try:
        _code = int(data.get("responseCode") or 200)
    except (TypeError, ValueError):
        _code = 200
    if _code != 200:
        _src_mark(200, f"API responseCode {_code}", 0)
        return []
    names = [str(item.get("query") or "") for item in (data.get("data") or [])
             if isinstance(item, dict)]
    out = _html_domains("\n".join(names))
    _src_mark(200, "", len(out))
    return out


def _reverse_urlscan(ip, settings, logger=None, timeout=None, raw=False):
    """urlscan.io 搜索（免 key；只覆盖最近 30 天，作为补充源，续339）。

    只认 `page.ip == 目标 IP` 的记录；返回 `page.domain` / `task.domain`，统一去噪。
    搜索接口无 key 也能用；命中少/为空不视为接口故障。
    """
    cfg = (settings or {}).get("iprecon", {}) or {}
    api = str(cfg.get("api_urlscan") or DEFAULT_URLSCAN_API)
    try:
        limit = max(1, min(int(cfg.get("urlscan_limit") or 100), 100))
    except (TypeError, ValueError):
        limit = 100
    url = api.replace("{ip}", ip).replace("{limit}", str(limit))
    if "{ip}" not in api and "{limit}" not in api:
        url = f"{api}{ip}"
    _src_mark(0, "")
    try:
        resp = http_request(url, timeout=timeout or 20, settings=settings)
    except Exception as e:      # noqa: BLE001 - 第三方源适配器：网络/解析任何异常都只算该源没查到
        _src_mark(0, http_last_error() or type(e).__name__)
        if logger:
            logger.debug(f"[iprecon] {ip} urlscan 反查异常：{e}")
        return {"status": 0} if raw else []
    status = int((resp or {}).get("status") or 0)
    _src_mark(status, "" if status == 200 else (f"HTTP {status}" if status else "不可达"))
    if raw:
        return resp or {"status": 0}
    if not resp or status != 200:
        return []
    try:
        data = json.loads(resp.get("text") or "{}")
    except (ValueError, TypeError):
        _src_mark(200, "响应不是合法 JSON", 0)
        return []
    names = []
    for item in (data.get("results") or []):
        if not isinstance(item, dict):
            continue
        page = item.get("page") or {}
        if not isinstance(page, dict):
            page = {}
        # 搜索 ip: 可能命中「页面里的请求」，只收真正落在这个 IP 的页面。
        if str(page.get("ip") or "").strip() and str(page.get("ip")).strip() != ip:
            continue
        names.append(str(page.get("domain") or ""))
        task = item.get("task") or {}
        if isinstance(task, dict):
            names.append(str(task.get("domain") or ""))
    # urlscan 的扫描页大量是 Cloudflare Workers 临时子域（*.workers.dev），不是目标资产。
    out = _html_domains("\n".join(names), exclude=("workers.dev",))
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
        if d.endswith(_FILE_SUFFIXES):      # 续315：avatar.jpg / adsbygoogle.js 不是域名
            continue
        if d.startswith(_JS_PSEUDO):        # 续315：JS 属性链不是域名
            continue
        if d in _PUBLIC_EXACT:
            continue
        if d.split(".")[0] in _JS_WORDS or d.split(".")[-1] in _JS_WORDS:
            continue
        if any(d == e.lstrip(".") or d.endswith(e) for e in _PUBLIC_NOISE):
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
    except Exception as e:      # noqa: BLE001 - 第三方源适配器：网络/解析任何异常都只算该源没查到
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
    except Exception as e:      # noqa: BLE001 - 第三方源适配器：网络/解析任何异常都只算该源没查到
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
    except (OSError, UnicodeError) as e:      # 没 PTR / 超时 / DNS 挂了 —— 都算"没查到"（herror/gaierror 都是 OSError 子类）
        _src_mark(0, f"无 PTR 记录（{type(e).__name__}）")
        if logger:
            logger.debug(f"[iprecon] {_ip} 原生 PTR 无结果：{e}")
        return {"status": 0} if raw else []
    d = normalize_domain(host or "")
    if not d or not is_domain(d):
        _src_mark(200, "PTR 结果不是合法域名", 0)
        return {"status": 0} if raw else []
    if d.endswith(_PTR_NOISE):            # 续315：云厂商 PTR，不是业务域名
        _src_mark(200, "PTR 只返回云厂商主机名", 0)
        return {"status": 0} if raw else []
    _src_mark(200, "", 1)
    return {"status": 200} if raw else [d]


# 续315：HTML 反查页里静态资源名（avatar.jpg / adsbygoogle.js）形态上是"合法域名"，
# utils.is_domain 会收下；它们不是资产。六个 HTML 源共用这一道过滤（探针实测 rapiddns
# 67 条里 60+ 条是这类垃圾）。
_FILE_SUFFIXES = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
                  ".woff", ".woff2", ".ttf", ".eot", ".map", ".txt", ".xml", ".html",
                  ".htm", ".php", ".asp", ".aspx", ".jsp", ".json")
# 云厂商 PTR（x.x.x.x.bc.googleusercontent.com / ec2-….amazonaws.com）不是业务域名，
# 落库只会把"历史·待确认"刷成噪声；PTR 这一路单独挡。
# 反查页里引用的公共 CDN / 广告 / 字体域（页面模板自带，不是资产）
_PUBLIC_NOISE = (".googlesyndication.com", ".googleapis.com", ".gstatic.com",
                 ".jsdelivr.net", ".cdnjs.cloudflare.com", ".bootstrapcdn.com",
                 ".unpkg.com", ".google-analytics.com", ".doubleclick.net",
                 ".facebook.com", ".twitter.com", ".youtube.com",
                 ".cloudflareinsights.com", ".baidu.com", ".googleusercontent.com",
                 ".hackerone.com", ".w3.org")
# JS 源码里的属性链（document.getelementbyid / location.href）会被域名正则误收
_JS_PSEUDO = ("document.", "window.", "location.", "this.", "self.", "event.",
              "console.", "navigator.", "history.", "arguments.", "response.", "request.",
              "input.", "dropdown.", "user-dropdown.")
# 首段/末段是这些词的"域名"都是 JS/HTML 片段（input.addeventlistener、dropdown.classlist.contains）
_JS_WORDS = {"getelementbyid", "addeventlistener", "classlist", "contains", "active",
             "href", "src", "value", "target", "length", "push", "slice", "split",
             "queryselectorall", "logout", "insertbefore", "parentnode", "preventdefault"}
# 公共词汇表/标准组织（页面模板里引用，不是资产）
_PUBLIC_EXACT = {"schema.org", "w3.org", "w3schools.com"}
_PTR_NOISE = (".googleusercontent.com", ".amazonaws.com", ".cloudfront.net",
              ".azure.com", ".cloudapp.net", ".aliyuncs.com", ".tencent-cloud.net")

# 反查源注册表：名字 → 适配器（任何源失败一律返回 []，永不向外抛异常）
_SOURCES = {
    "webscan": _reverse_webscan,
    "hackertarget": _reverse_hackertarget,
    "ip138": _reverse_ip138,
    "dnsdblookup": _reverse_dnsdblookup,
    "rapiddns": _reverse_rapiddns,
    "viewdns": _reverse_viewdns,
    "ptr": _reverse_ptr,
    # 续319：被动 DNS 两源（OTX 免 key、VT 需 key）
    "otx": _reverse_otx,
    "virustotal": _reverse_virustotal,
    # 续339：免 key 的两个补充源
    "mnemonic": _reverse_mnemonic,
    "urlscan": _reverse_urlscan,
}
# 原生源（不依赖任何第三方 HTTP 接口）：**不参与**接口存活预检与熔断，恒可用
DNS_SOURCES = {"ptr"}
# 默认源全部预检失败时的备用池（原生 PTR 排第一 —— 接口全挂时它还在）
DEFAULT_FALLBACK = ["ptr", "dnsdblookup", "rapiddns", "viewdns", "webscan", "ip138"]


def preflight(sources, settings, logger=None, timeout=None, probe_ip=""):
    """开跑前先探一次每个源；续339 起交给熔断器决定「跳过」还是「继续观察」。

    返回 `(可用源名单, {源: 不可用原因})`：
    - 熔断打开且未到探测点 ⇒ 原因写「熔断中」，本轮跳过；
    - 熔断关闭 / 半开探测 ⇒ 探一次；成功算活；
    - 失败但还没到连续失败阈值 ⇒ **仍返回可用**，让后续每个 IP 真实调用继续累计，
      到 10 次才熔断（主理人 2026-11-05 的「10 次都不能用再停 100 次」）；
    - 原生源（`DNS_SOURCES`）不发 HTTP、不参与熔断，恒可用。
    关闭熔断（`breaker_enabled=false`）时保持旧行为：一次预检失败就整轮跳过。
    """
    cfg = (settings or {}).get("iprecon", {}) or {}
    srcs = [str(s).strip().lower() for s in (sources or DEFAULT_SOURCES)]
    if not cfg.get("preflight", True) or not probe_ip:
        return srcs, {}
    _breaker_on, _threshold, _cooldown = _breaker_cfg(settings)
    ok, report = [], {}
    for n in srcs:
        adapter = _SOURCES.get(n)
        if adapter is None:
            report[n] = "未注册的源名"
            continue
        if n in DNS_SOURCES:
            ok.append(n)
            continue
        allow, why = _breaker_allow(n, settings)
        if not allow:
            report[n] = why
            continue
        _status = 0
        try:
            resp = adapter(probe_ip, settings, logger=None, timeout=timeout, raw=True)
            _status = int((resp or {}).get("status") or 0)
        except Exception as e:      # noqa: BLE001 - 源适配器返回形态由第三方决定，异常只记该源失败
            _src_mark(0, type(e).__name__)
            if logger:
                logger.debug(f"[iprecon] 预检源 {n} 异常：{e}")
        _last = source_last()
        _healthy = _status == 200 and not str(_last.get("reason") or "").strip()
        _breaker_record(n, _healthy, settings, logger=logger,
                        reason=_last.get("reason") or (f"HTTP {_status}" if _status else "不可达"))
        _st = (breaker_snapshot().get(n) or {})
        if _st.get("open"):
            report[n] = (f"HTTP {_status}" if _status else "不可达") + "；熔断中"
        elif _status == 200:
            ok.append(n)
        elif _breaker_on:
            # 还没到阈值：不整轮丢弃，后续每个 IP 的真实调用继续累计失败次数。
            ok.append(n)
            if logger:
                logger.warning(
                    f"[iprecon] 预检源 {n} 返回 {_status or '不可达'}，连续失败 "
                    f"{_st.get('failures', 1)}/{_threshold}，继续观察（未到熔断阈值）")
        else:
            report[n] = f"HTTP {_status}" if _status else "不可达"
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


def domain_note(ip, sources, original=0, cap=0, shared=False, kept=None):
    """反查域名的备注：历史依据 IP + 实际返回它的接口（单一产地）。

    页面上的「解析 IP」是当前 DNS，和这里的 ``ip=``（第三方历史索引）本来就可能不同；
    备注写「历史解析」和接口名，避免把反查源当成当前解析结果。
    ``original`` 是接口返回的域名总数；``kept`` 是过滤/去重后、截断前的数量。
    截断标注必须看 ``kept``，否则共享 IP 过滤后剩 10 条也会误写「150→100 已截断」。
    """
    srcs = []
    for s in (sources or []):
        s = str(s or "").strip()
        if s and s not in srcs:
            srcs.append(s)
    note = f'ip="{ip}" · 历史解析 · 来源={"/".join(srcs) or "未知"} · 待确认'
    try:
        original, cap = int(original or 0), int(cap or 0)
    except (TypeError, ValueError):
        original, cap = 0, 0
    try:
        kept_n = original if kept is None else int(kept or 0)
    except (TypeError, ValueError):
        kept_n = original
    if shared and original > 0:
        note += f" · 共享IP（{original} 个反查域名）"
    if cap > 0 and kept_n > cap:
        note += f" · 共享IP已截断（{kept_n}→{cap}）"
    return note


def reverse_lookup_detail(ip, settings, logger=None, timeout=None, sources=None):
    """单个 IP 反查域名，返回 `(域名列表, 逐源结果)`（续173）。

    域名列表与旧 `reverse_lookup` **同一口径**：依次试 `sources`、各源 union、全空返回 []。
    逐源结果是旁路，形状 `[{name, status, http, found, reason, domains}]`：
    `domains` 是该源这次真正返回的域名（用于溯源“这个域名是谁查出来的”）。
    `status` ∈ `ok` / `empty` / `http_error` / `network_error` / `unregistered` / `skipped`
    （`skipped` = 该源正在熔断，本次没发请求）。
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
                           "http": 0, "found": 0, "reason": "未注册的源名",
                           "domains": []})
            continue
        allow, why = _breaker_allow(key, settings)
        if not allow:
            detail.append({"name": key, "status": "skipped", "http": 0, "found": 0,
                           "reason": why, "domains": []})
            continue
        _src_mark(0, "")
        try:
            doms = adapter(ip, settings, logger=logger, timeout=timeout)
        except Exception as e:      # noqa: BLE001 - 兜底：任何源抛异常都不该影响流水线
            _src_mark(0, http_last_error() or type(e).__name__)
            if logger:
                logger.debug(f"[iprecon] {ip} 源 {name} 反查异常：{e}")
            doms = []
        last = source_last()
        # 200-空且没有错误原因 = 接口通、这个 IP 没记录；算健康。
        # 200 + 「配额耗尽/响应不是 JSON」等 reason = 接口活着但不可用；算失败。
        _healthy = bool(doms) or (int(last["status"] or 0) == 200
                                  and not str(last["reason"] or "").strip())
        _breaker_record(key, _healthy, settings, logger=logger,
                        reason=last["reason"] or (f"HTTP {last['status']}"
                                                  if last["status"] else "不可达"))
        detail.append({"name": key, "status": _classify_source(doms, last),
                       "http": last["status"], "found": len(doms or []),
                       "reason": last["reason"],
                       "domains": list(doms or [])})
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
        if s.get("skipped") and not s.get("attempted"):
            parts.append(f"{name} 未试（{s.get('reason') or '预检/熔断跳过'}）")
            continue
        bits = [f"试{s.get('attempted', 0)}", f"成{s.get('ok', 0)}",
                f"空{s.get('empty', 0)}", f"错{s.get('error', 0)}"]
        if s.get("skipped"):
            bits.append(f"熔断跳过{s.get('skipped')}")
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
    整批零命中时会对**没试过**的备用源再追洗一批（续255：预检把 200-空判为"存活"，
    `if not _ok` 覆盖不了"默认源全活着但全不出数"这种静默失败）。
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

    def _one(ip, srcs):
        if stop and stop():
            return None
        rows = []
        doms = reverse_lookup(ip, settings, logger=logger, timeout=timeout,
                              sources=srcs, detail=rows)
        return (ip, doms, rows)

    results = pool_run(lambda ip: _one(ip, _ok), candidates, workers=workers,
                       logger=logger, label="ip 反查")
    src_stats = {str(name): {"skipped": 1, "attempted": 0, "ok": 0, "empty": 0,
                             "error": 0, "domains": 0, "reason": str(why)}
                 for name, why in _preflight_bad.items()}
    mapping = {}
    _tried = set(_ok)          # 这一轮真试过的源（含预检全灭后接班的备用源）

    # 续341：域名 → 实际返回它的源列表；页面用这个字段在 note 里标“来源=mnemonic/otx”，
    # 而不是只给一句笼统的“第三方接口”。
    domain_sources = {}

    def _absorb(items):
        """把一批 `(ip, doms, rows)` 并进 mapping / src_stats / domain_sources。"""
        for item in items or []:
            if not item:
                continue
            ip, doms, rows = item
            if doms:
                got = mapping.setdefault(ip, [])
                for _d in doms:
                    if _d not in got:
                        got.append(_d)
            for row in rows or []:
                name = row.get("name") or "未知"
                s = src_stats.setdefault(name, {"skipped": 0, "attempted": 0, "ok": 0,
                                                 "empty": 0, "error": 0, "domains": 0,
                                                 "http": {}, "reasons": {}})
                status = row.get("status")
                if status == "skipped":
                    s["skipped"] = int(s.get("skipped", 0)) + 1
                    s["reason"] = str(row.get("reason") or "熔断跳过")
                    continue
                s["attempted"] = int(s.get("attempted", 0)) + 1
                if status == "ok":
                    s["ok"] = int(s.get("ok", 0)) + 1
                elif status == "empty":
                    s["empty"] = int(s.get("empty", 0)) + 1
                else:
                    s["error"] = int(s.get("error", 0)) + 1
                for _d in (row.get("domains") or []):
                    _bucket = domain_sources.setdefault(ip, {}).setdefault(_d, [])
                    if name not in _bucket:
                        _bucket.append(name)
                s["domains"] = int(s.get("domains", 0)) + int(row.get("found") or 0)
                code = int(row.get("http") or 0)
                if code:
                    s.setdefault("http", {})
                    s["http"][str(code)] = int(s["http"].get(str(code), 0)) + 1
                why = str(row.get("reason") or "")
                if why:
                    s.setdefault("reasons", {})
                    s["reasons"][why] = int(s["reasons"].get(why, 0)) + 1

    _absorb(results)

    # 续255：默认源"活着但全军覆没"（整批每个 IP 都零域名）时，上面的 `if not _ok`
    # 覆盖不到 —— ip138 那种 200-空的源预检永远算"存活"，备用池于是永远不上场，
    # 续173 点单要的"反查失败时有备用接口"在静默失败这条路上是空的。这里补一次：
    # 整批零命中 ⇒ 对**没试过**的备用源预检 + 再跑一批（有界：最多追加一轮，
    # 请求数 ≤ 候选 IP × 备用源数；只在全军覆没时发生，正常路径零成本）。
    if not mapping:
        _fb = cfg.get("fallback_sources") or DEFAULT_FALLBACK
        _todo = [str(n).strip().lower() for n in _fb
                 if str(n).strip().lower() not in _tried
                 and str(n).strip().lower() in _SOURCES]
        if _todo:
            if stop and stop():
                stats["sources"] = src_stats
                stats["hit_ips"] = 0
                stats["domains"] = 0
                return {}, stats
            _ok2, _bad2 = preflight(_todo, settings, logger=logger, timeout=timeout,
                                    probe_ip=candidates[0])
            for _n, _why in (_bad2 or {}).items():
                src_stats.setdefault(_n, {"skipped": 1, "attempted": 0, "ok": 0,
                                          "empty": 0, "error": 0, "domains": 0,
                                          "reason": str(_why)})
            if _ok2:
                if logger:
                    logger.warning("[iprecon] 默认源整批零命中，追加未试过的备用源："
                                   + ",".join(_ok2)
                                   + f"（{len(candidates)} 个 IP 再跑一批）")
                _absorb(pool_run(lambda ip: _one(ip, _ok2), candidates, workers=workers,
                                 logger=logger, label="ip 反查备用源"))
    stats["sources"] = src_stats
    stats["domain_sources"] = {
        _ip: {_d: sorted(_srcs) for _d, _srcs in _doms.items()}
        for _ip, _doms in domain_sources.items()
    }
    stats["breaker"] = breaker_snapshot()
    stats["hit_ips"] = len(mapping)
    stats["domains"] = sum(len(v) for v in mapping.values())
    return mapping, stats