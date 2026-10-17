"""VirusTotal 子域名反查（续214，借鉴清单里最后一项"等 key"的能力）。

为什么单独一个文件、不复用 `_platform_assets`：FOFA / Shodan / Quake 那三家都是
**favicon 哈希反查**（同一个 mmh3 键，见 `scanner/mmh3.py`），而 VT 的子域名能力是
另一条路 —— `GET /v3/domains/<注册域>/subdomains`，输入是**注册域**、产出是**子域名列表**。
它恰好补上我们缺的那一格：前三家回答"还有谁用了同一个图标"，VT 回答"这个域名下还有
哪些子域"（与被动收集互补，且是**权威关系**而不是相似度推断）。

与 `scanner/shodan.py` 同构（`credentials` / `available` / `search` / 无 key 显式报错），
**刻意不抽公共基类**：四家的鉴权方式、响应结构、配额模型各不相同，过早抽象只会把
差异塞进一堆分支里（shodan.py 文件头同一条理由）。

依赖：`config/keys.yaml`（或密文 `keys.enc.yaml`）的 `virustotal: {key: ...}`。
**未填 key 时一个请求都不发**，返回 `keystore.keys_hint("virustotal.key")` 现取的那句
（按当下状态分"没文件 / 密文没解锁 / 已解锁但没这一组"三档，续162）。

三条边界（都不是洁癖）：
① **出厂关**（`virustotal.enabled=false`）—— 任何外部接口都不该在用户没点头时产生流量；
② **自带节流**：免费档是 4 次/分钟、500 次/天（`min_interval` 默认 15 秒；`_rate_wait`
   在每次请求前等够间隔），撞 429 时**如实报出**而不是重试（重试只会把它变成"扫得很慢"）；
③ **第三方不带登录态**（`auth=False` 是 `utils.http_request` 的默认值，§5.1）——
   否则等于把目标的会话凭据送给 VT。
"""
import json
import time
import urllib.parse

from . import keystore
from .utils import http_request

API = "https://www.virustotal.com/api/v3/domains"

# 免费档单次最多 40 条（v3 的硬上限），付费档也按配置调，不擅自放大
DEFAULT_LIMIT = 40
MAX_LIMIT = 40
# 免费档 4 次/分钟 ⇒ 15 秒一个请求才不会撞 429
DEFAULT_MIN_INTERVAL = 15.0
DEFAULT_TIMEOUT = 10

# 上一次请求的时刻（模块级）：节流只看"距上次多久"，不做滑动窗口 —— 我们一秒最多
# 也只发得起一个请求，滑动窗口的复杂度换不来任何东西。
_LAST_TS = 0.0


def credentials(settings):
    """从 `settings["keys"]["virustotal"]` 取 key；缺失时返回空串。"""
    cfg = ((settings or {}).get("keys") or {}).get("virustotal") or {}
    if not isinstance(cfg, dict):
        return ""
    return str(cfg.get("key") or "").strip()


def available(settings):
    return bool(credentials(settings))


def cfg_of(settings):
    return (settings or {}).get("virustotal") or {}


def limit_of(settings):
    # ⚠ 必须判 `is None` 而不是 `or DEFAULT_*`：显式写 0 的意思是"用最小值 / 不节流"，
    # 而 `0 or 15.0` 在 Python 里等于 15.0 —— 那会把"关掉节流"的配置**读成开到最大**
    # （本轮 [214] 断言就是这么卡住 60 秒的，实测抓出来的）。
    raw = cfg_of(settings).get("limit")
    if raw is None:
        return DEFAULT_LIMIT
    try:
        return max(1, min(MAX_LIMIT, int(raw)))
    except (TypeError, ValueError):
        return DEFAULT_LIMIT


def min_interval(settings):
    raw = cfg_of(settings).get("min_interval")
    if raw is None:
        return DEFAULT_MIN_INTERVAL
    try:
        return max(0.0, float(raw))
    except (TypeError, ValueError):
        return DEFAULT_MIN_INTERVAL


def _rate_wait(settings, now=None, sleep=None):
    """按 `min_interval` 等够间隔；返回实际等待的秒数（测试据此断言节流生效）。

    `now` / `sleep` 可注入：默认用 `time.monotonic` / `time.sleep`，测试传桩即可
    （不真的睡 15 秒，也不依赖真实时钟）。
    """
    global _LAST_TS
    now_fn = now or time.monotonic
    sleep_fn = sleep or time.sleep
    gap = min_interval(settings)
    if gap <= 0 or _LAST_TS <= 0:
        _LAST_TS = now_fn()
        return 0.0
    waited = 0.0
    while True:
        cur = now_fn()
        left = gap - (cur - _LAST_TS)
        if left <= 0:
            break
        sleep_fn(left)
        waited += left
        # ⚠ `_LAST_TS` 只能在**退出循环时**推进一次：若在 sleep 之后立刻改成当前时刻，
        # 下一轮的 `cur - _LAST_TS` 又变回 0 ⇒ `left` 永远等于 gap ⇒ 死循环
        # （本轮 [214] ④ 的断言就是这么挂住的，实测抓出来的）。
    _LAST_TS = now_fn()
    return waited


def query_of(domain):
    """这次反查用的"语法"（入库进 `subdomains.note`，拓展域名页「语法」列展示）。

    与续171 那条口径一致：反查结果必须标明用的是哪条语法（`icon_hash="123"` /
    `cert="x"` / `title="x"`），否则事后无法解释这条域名是怎么来的。
    """
    return f'domain="{domain}"（VT v3 /domains/<注册域>/subdomains）'


def search(domain, settings, logger=None, limit=None, now=None, sleep=None):
    """按注册域查子域名，返回 `(subs, total, error)`（结构同 `shodan.search`）。

    - subs:  `[{"domain": ..., "ip": ...}, ...]`（`error` 非空时为空表）
    - total: VT 报告的命中总数（`meta.count`；没有就按返回条数算）
    - error: 空串表示成功（**含"该域名没有子域记录"**）；否则是可直接展示的原因
    """
    key = credentials(settings)
    if not key:
        return [], 0, keystore.keys_hint("virustotal.key")
    domain = str(domain or "").strip().strip("/").lower()
    if not domain:
        return [], 0, "域名为空"
    try:
        size = int(limit or limit_of(settings))
    except (TypeError, ValueError):
        size = limit_of(settings)
    size = max(1, min(MAX_LIMIT, size))
    try:
        timeout = int((settings or {}).get("limits", {}).get("http_timeout", DEFAULT_TIMEOUT))
    except (TypeError, ValueError):
        timeout = DEFAULT_TIMEOUT

    _rate_wait(settings, now=now, sleep=sleep)
    url = f"{API}/{urllib.parse.quote(domain, safe='')}/subdomains?limit={size}"
    resp = http_request(url, headers={"x-apikey": key}, timeout=timeout, settings=settings)
    if not resp:
        return [], 0, f"请求 virustotal 失败（网络不可达或超时 {timeout}s）"
    status = int(resp.get("status") or 0)
    if status == 401 or status == 403:
        return [], 0, f"virustotal key 无效或未授权（HTTP {status}）"
    if status == 429:
        return [], 0, "virustotal 已达速率/日配额上限（免费档 4 次/分钟、500 次/天）"
    if status == 404:
        # 没有这条域名的记录 —— 不是错误，是"它确实没被收录过"（与查询失败必须分开）
        return [], 0, ""
    if status != 200:
        return [], 0, f"virustotal 返回 HTTP {status}"
    try:
        data = json.loads(resp.get("text") or "{}")
    except (ValueError, TypeError):
        return [], 0, "virustotal 响应不是合法 JSON"
    if not isinstance(data, dict):
        return [], 0, "virustotal 响应结构异常"

    subs, seen = [], set()
    for row in (data.get("data") or []):
        if not isinstance(row, dict):
            continue
        d = str(row.get("id") or "").strip().lower().strip(".")
        if not d or d in seen or d == domain:
            continue
        seen.add(d)
        attrs = row.get("attributes") or {}
        if not isinstance(attrs, dict):
            attrs = {}
        subs.append({"domain": d, "ip": str(attrs.get("ip_address") or "")})
    meta = data.get("meta") or {}
    if not isinstance(meta, dict):
        meta = {}
    try:
        total = int(meta.get("count") or len(subs))
    except (TypeError, ValueError):
        total = len(subs)
    if logger:
        logger.info(f"[virustotal] {domain} → {len(subs)} 个子域 / 共 {total} 条")
    return subs, total, ""
