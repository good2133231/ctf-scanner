"""动态免杀（evasion）：UA 随机化 / 请求头伪装 / 注入 payload 变形 / WAF 指纹识别。

为什么需要（实战动机）：
- 固定 UA（尤其 `CTFScanner/0.1` 这种自报家门的）会被 WAF 与风控一眼识别并封禁；
- 靶场/CTF 里最常见的失分点不是"没有 POC"，而是**注入 payload 被 WAF 拦掉**，
  于是明明存在注入却扫不出来。这里提供"同一语义、多种编码形态"的 payload 变体，
  逐个尝试，命中即止。

设计约束（重要）：
- 全部为只读 **GET/POST 探测**，不写数据、不反弹、不做 DoS；变形只改变 payload 的
  *编码形态*，不改变其语义（`/**/` 与空格在 SQL 里等价，`%0a` 与换行等价）；
- WAF 识别以**被动指纹**为主（分析正常响应的响应头/响应体），只在被动无果时补一次
  主动探测；主动探测虽带 XSS 标记但仍是单个只读 GET，不会触发拦截策略升级。
"""
import random
import re
from urllib.parse import quote

# 真实浏览器 UA 池（Chrome / Edge / Firefox / Safari，Win/macOS/Linux 混合）
UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
]

ACCEPT_LANGS = [
    "zh-CN,zh;q=0.9,en;q=0.8",
    "en-US,en;q=0.9,zh-CN;q=0.8",
    "zh-CN,zh;q=0.9",
    "en-GB,en;q=0.9",
]

ACCEPT_TYPES = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "text/html,application/json;q=0.9,*/*;q=0.8",
]


def _cfg(settings):
    return (settings or {}).get("evasion", {}) or {}


def pick_ua(settings=None):
    """返回本次请求应使用的 UA；`evasion.random_ua` 关闭时返回配置里的固定 UA。"""
    cfg = _cfg(settings)
    if cfg.get("random_ua", True):
        pool = cfg.get("ua_pool") or UA_POOL
        return random.choice(list(pool))
    return None


def browser_headers(settings=None, extra=None):
    """构造一组贴近真实浏览器的请求头；extra 覆盖同名项。

    刻意**不设置 Accept-Encoding**：urllib 兜底分支不会自动解压，
    带上它反而会让响应体变成乱码，得不偿失。
    """
    hdrs = {
        "User-Agent": pick_ua(settings) or
                      (settings or {}).get("http", {}).get("user_agent", "Mozilla/5.0"),
        "Accept": random.choice(ACCEPT_TYPES),
        "Accept-Language": random.choice(ACCEPT_LANGS),
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }
    cfg = _cfg(settings)
    if cfg.get("spoof_xff"):
        # 部分 WAF 对"来自内网"的请求放宽策略，这是常见的绕过思路之一
        ip = ".".join(str(random.randint(1, 254)) for _ in range(4))
        hdrs["X-Forwarded-For"] = ip
        hdrs["X-Real-IP"] = ip
        hdrs["X-Originating-IP"] = ip
    if extra:
        hdrs.update(extra)
    return hdrs


# ---------- payload 变形（动态绕 WAF） ----------

_SQL_KEYWORDS = ("union", "select", "and", "or", "from", "where", "sleep", "benchmark",
                 "extractvalue", "updatexml", "information_schema")


def _random_case(text):
    """SQL 关键字大小写随机化：`select` → `SeLeCt`（SQL 关键字不区分大小写）。"""
    def flip(m):
        return "".join(c.upper() if random.random() < 0.5 else c.lower() for c in m.group(0))
    return re.sub(r"\b(" + "|".join(_SQL_KEYWORDS) + r")\b", flip, text, flags=re.I)


def _split_keywords(text):
    """关键字中间插入注释：`select` → `sel/**/ect`（SQL 解析器会忽略注释）。"""
    def split(m):
        w = m.group(0)
        mid = max(1, len(w) // 2)
        return w[:mid] + "/**/" + w[mid:]
    return re.sub(r"\b(" + "|".join(_SQL_KEYWORDS) + r")\b", split, text, flags=re.I)


def _inline_comment(text):
    """关键字换成 MySQL 内联注释形式：`select` → `/*!50000select*/`。"""
    return re.sub(r"\b(" + "|".join(_SQL_KEYWORDS) + r")\b",
                  lambda m: f"/*!50000{m.group(0)}*/", text, flags=re.I)


def _dedup(items):
    seen, uniq = set(), []
    for p in items:
        if p and p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq


def _shuffle_tail(items):
    """保留首个变体（原始 payload），其余打乱顺序。

    为什么打乱：固定的尝试顺序会让"请求序列"本身成为一个可被 WAF 规则固化的特征；
    每次运行顺序不同，请求形态就"相对动态"。原始 payload 仍排第一 —— 它最便宜、
    命中率最高，先打它不会浪费请求预算。
    """
    if len(items) <= 2:
        return items
    tail = items[1:]
    random.shuffle(tail)
    return [items[0]] + tail


def mutate_sqli(payload, level=2):
    """返回同语义的 SQL 注入 payload 变体列表（含原始 payload，已去重）。

    level: 0 只返回原始；1 轻量（注释替空格/大小写）；2 进阶（换行编码/URL 编码/内联注释）；
           3 激进（双重编码/关键字分片）。
    """
    level = max(0, int(level or 0))
    out = [payload]
    if level >= 1:
        out.append(re.sub(r"\s+", "/**/", payload))
        out.append(payload.replace(" ", "+"))
        out.append(_random_case(payload))
    if level >= 2:
        out.append(re.sub(r"\s+", "%0a", payload))
        out.append(re.sub(r"\s+", "%09", payload))
        out.append(_inline_comment(payload))
        out.append(quote(payload, safe=""))
    if level >= 3:
        out.append(_split_keywords(payload))
        out.append(_split_keywords(_random_case(payload)))
        out.append(quote(quote(payload, safe=""), safe=""))  # 双重 URL 编码
    return _shuffle_tail(_dedup(out))


def mutate_xss(payload, level=2):
    """返回同语义的 XSS payload 变体列表（大小写/属性分隔/实体编码等）。"""
    level = max(0, int(level or 0))
    out = [payload]
    if level >= 1:
        out.append(re.sub(r"\s+", "/", payload))
        out.append(re.sub(r"\s*/\s*", " ", payload))
        out.append(re.sub(r"\b(onerror|onload|onfocus|script)\b",
                          lambda m: m.group(0).upper(), payload, flags=re.I))
    if level >= 2:
        out.append(quote(payload, safe=""))
        out.append(re.sub(r"\s+", "\t", payload))
        out.append(re.sub(r"<(\w+)", r"<\1/xss", payload))  # <img/xss src=...> 形态
    if level >= 3:
        out.append(re.sub(r"script", "scr&#105;pt", payload, flags=re.I))
        out.append(quote(quote(payload, safe=""), safe=""))
    return _shuffle_tail(_dedup(out))


def mutate(payload, level=2, kind="sqli"):
    return mutate_sqli(payload, level) if kind == "sqli" else mutate_xss(payload, level)


# ---------- WAF 指纹识别 ----------

# (厂商, 响应头命中正则, 响应体命中正则)；响应头与响应体任一命中即判定
WAF_SIGNATURES = [
    ("Cloudflare",        r"cf-ray|__cfduid|cf-cache-status", r"cloudflare\.com/5xx|Attention Required! \| Cloudflare"),
    ("安全狗 SafeDog",     r"waf/2\.0|safedog",                r"safedog|安全狗"),
    ("云锁 Yunsuo",        r"yunsuo_session",                  r"yunsuo|云锁"),
    ("阿里云盾",           r"aliyungf_tc|aliyungf",             r"aliyungf|errors\.aliyun\.com|云盾"),
    ("腾讯云 WAF",         r"stgw|tencent-waf",                r"waf\.tencent\.com|腾讯云"),
    ("长亭雷池",           r"chaitin|x-waf-",                  r"chaitin|雷池"),
    ("知道创宇创宇盾",      r"yunaq|x-cache:.*yunaq",           r"yunaq|创宇盾"),
    ("360 网站卫士",       r"x-via:.*360|x-waf-360",           r"360wzb|网站卫士"),
    ("ModSecurity",       r"mod_security|modsecurity",         r"mod_security|Not Acceptable!"),
    ("Naxsi",             r"naxsi",                            r"naxsi"),
    ("宝塔 WAF",          r"btwaf|bt-waf",                     r"btwaf|宝塔"),
    ("Imperva/Incapsula", r"x-iinfo|incap_ses|visid_incap",    r"incapsula|_Incapsula_Resource"),
    ("AWS WAF/CloudFront", r"awselb|x-amz-cf-id|x-amzn-requestid", r"aws\.amazon\.com/.*(403|Blocked)|Request blocked"),
    ("F5 BIG-IP ASM",     r"bigipserver|x-wa-info",            r"the requested url was rejected"),
    ("华为云 WAF",         r"huaweicloud|hw-waf",               r"huaweicloud\.com/.*waf"),
    ("Google Cloud Armor", r"x-cloud-trace-context",           r"googleusercontent"),
]


def fingerprint_from(resp):
    """从一次响应中识别 WAF；返回 (名称, 命中位置) 或 None。"""
    if not resp:
        return None
    hdr = "\n".join(f"{k}: {v}" for k, v in (resp.get("headers") or {}).items()).lower()
    body = (resp.get("text") or "")[:6000].lower()
    for name, hpat, bpat in WAF_SIGNATURES:
        if re.search(hpat, hdr, re.I):
            return name, "响应头"
        if re.search(bpat, body, re.I):
            return name, "响应体"
    return None


_ACTIVE_MARKER = "<script>ctfscan_waf_probe</script>"
_BLOCK_STATUS = (403, 406, 429, 501, 512)


def detect(url, settings, logger=None):
    """识别目标 WAF。

    先做被动指纹（分析一次正常响应）；被动无果且 `evasion.waf_detect` 开启时，
    再用一个只读 GET 携带标记探测是否被拦截。返回 WAF 名称或 ""。"""
    from .utils import http_request  # 局部导入：避免与 utils 形成循环依赖

    cfg = _cfg(settings)
    timeout = int((settings or {}).get("limits", {}).get("http_timeout", 10) or 10)
    resp = http_request(url, timeout=timeout, settings=settings, auth=True)
    hit = fingerprint_from(resp)
    found = hit[0] if hit else ""
    where = hit[1] if hit else ""

    if not found and cfg.get("waf_detect", True):
        sep = "&" if "?" in url else "?"
        probe = http_request(f"{url}{sep}ctfscan_waf_probe={_ACTIVE_MARKER}",
                             timeout=timeout, settings=settings, auth=True)
        if probe:
            marker_echoed = _ACTIVE_MARKER.lower() in (probe.get("text") or "").lower()
            if not marker_echoed and probe.get("status") in _BLOCK_STATUS:
                found, where = "未知 WAF（主动探测被拦截）", "响应状态 %s" % probe.get("status")
            else:
                hit = fingerprint_from(probe)
                if hit:
                    found, where = hit[0], hit[1] + "（主动探测）"

    if found and logger:
        logger.info(f"[evasion] 目标疑似存在 WAF：{found}（依据：{where}）")
    return found