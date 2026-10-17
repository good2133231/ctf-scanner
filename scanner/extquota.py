"""外部引擎**配额/积分预检**（续211-P1-4，借鉴 ShuiZe 的 quakeApi/qianxinApi 查询前先看额度）。

为什么需要它：FOFA / Shodan / Quake 三家按 key 计费或限流，额度耗尽时的现状是
**逐条请求失败**、日志里刷一片归因错的失败原因（"网络不可达""HTTP 403"）——
用户看到的是"工具坏了"，而事实是"额度用完了"。这与续184 的 `iprecon.preflight()`
是同一族需求：那个问"源还活不活"，这个问"**我还有多少次**"。

口径（照 iprecon.preflight，两条硬规矩）：
  ① **跳过必须点名** —— 预检不过就整轮跳过该源，并在日志里说清是哪个源、剩多少、
     为什么跳（§0 第 10 条：被收起 ≠ 不存在）；
  ② `auth=False`（§5.1 第三方永不带登录态）—— 额度查询只用 key，不带目标侧任何凭据。
  ③ **不算目标侧请求预算** —— 它不吃 `throttle` 的请求额度（那是目标侧的事），
     但**吃一次 HTTP**，所以默认只在每轮开始前查一次（`preflight()` 由阶段调用，
     不在每个目标上各查一遍）。

各家的"额度端点"不一样（Shodan 有 `/api/info/query`，FOFA 是用户信息里的
`fofa_point`/`fofa_free`，Quake 是 `/v3/info`），所以**适配器按源注册**，
预检流程只有一份。查不到额度（端点变了/字段没了）时**不跳过** ——
那是"我不知道"，不是"没额度"（§6.2：没读到 ≠ 没有）。
"""
import json

from .utils import http_request

# 预检端点（三家各自的官方文档端点；改了只改这里）
_INFO_URLS = {
    "fofa": "https://fofa.info/api/v1/info/my?key={key}",
    "shodan": "https://api.shodan.io/api/info/query?key={key}",
    "quake": "https://quake.360.net/api/v3/user/info?key={key}",
}

# 每种源怎么从响应里取"剩余次数"：返回 `(剩余, 说明)` 或 None（取不到 ⇒ 不跳过）
def _fofa_quota(data):
    if not isinstance(data, dict):
        return None
    # FOFA：`fofa_point`（付费积分）与 `fofa_free`（免费次数，日重置）
    point, free = data.get("fofa_point"), data.get("fofa_free")
    if point is None and free is None:
        return None
    try:
        left = int(point or 0) + int(free or 0)
    except (TypeError, ValueError):
        return None
    return left, f"付费积分 {point} + 免费 {free}"


def _shodan_quota(data):
    if not isinstance(data, dict):
        return None
    # Shodan：`scan_credits`（扫描额度）与 `query_credits`（查询额度）
    scan, query = data.get("scan_credits"), data.get("query_credits")
    if scan is None and query is None:
        return None
    try:
        left = int(query or 0)
    except (TypeError, ValueError):
        return None
    return left, f"查询额度 {query} / 扫描额度 {scan}"


def _quake_quota(data):
    if not isinstance(data, dict):
        return None
    # Quake：`data.credit` / `data.month_remaining_credit`（字段名随版本漂过，两个都试）
    d = data.get("data") if isinstance(data.get("data"), dict) else data
    for k in ("month_remaining_credit", "remaining_credit", "credit"):
        v = d.get(k) if isinstance(d, dict) else None
        if v is not None:
            try:
                return int(v), f"{k}={v}"
            except (TypeError, ValueError):
                continue
    return None


_ADAPTERS = {"fofa": _fofa_quota, "shodan": _shodan_quota, "quake": _quake_quota}

# 低于这个数就整轮跳过（0 = 一次都不剩当然跳；给个小余量是防"够查 1 次但不够查完"）
DEFAULT_MIN_LEFT = 1


def check(source, settings, logger=None, timeout=None):
    """查一个源的剩余额度，返回 `(剩余次数|None, 说明)`。

    `None` = **查不到**（端点变了/字段没了/网络不通）—— 调用方按"不跳过"处理：
    那是"我不知道"，不是"没额度"。这条区分是刻意的（§6.2 第十七起同族：
    把"没读到"当成"没有"会让功能静默失效）。
    """
    from . import fofa as _fofa211, quake as _quake211, shodan as _shodan211
    # key 的取法**只走各源自己的 `credentials()`**（那是唯一产地，§5.14）——
    # 自己再读一遍 `settings["keys"]` 就会有两份取法，哪天某家多加个字段必然漂。
    _CRED = {"fofa": lambda s: _fofa211.credentials(s)[1],
             "shodan": lambda s: _shodan211.credentials(s),
             "quake": lambda s: _quake211.credentials(s)}
    key = (_CRED.get(source)(settings) or "").strip()
    if not key:
        return None, f"{source} 未配 key"
    url = _INFO_URLS.get(source, "").format(key=key)
    if not url:
        return None, f"{source} 没有预检端点"
    try:
        resp = http_request(url, timeout=int(timeout or 10), settings=settings, auth=False)
    except Exception as e:                       # noqa: BLE001 —— 预检不许把整轮带崩
        return None, f"{source} 额度查询异常：{type(e).__name__}"
    if not resp or resp.get("status") != 200:
        return None, f"{source} 额度查询失败（HTTP {resp.get('status') if resp else '无响应'}）"
    try:
        data = json.loads(resp.get("text") or "")
    except (ValueError, TypeError):
        return None, f"{source} 额度响应不是合法 JSON"
    adapter = _ADAPTERS.get(source)
    got = adapter(data) if adapter else None
    if got is None:
        return None, f"{source} 响应里没有可认的额度字段（端点变了？）"
    left, detail = got
    return left, detail


def preflight(sources, settings, logger=None, timeout=None, min_left=None):
    """开跑前逐源查额度，返回 `(可用源, {源: 原因})`（口径同 `iprecon.preflight`）。

    只有"**确认剩得很少**"才跳过；查不到的一律放行（理由见 `check` 的 docstring）。
    """
    from .config import resolve  # noqa: F401（保持与 iprecon 一致的导入风格）
    cfg = (settings or {}).get("extquota", {}) or {}
    if cfg.get("enabled") is False:
        return list(sources or []), {}
    floor = int(min_left if min_left is not None
                else cfg.get("min_left", DEFAULT_MIN_LEFT))
    ok, bad = [], {}
    for name in (sources or []):
        left, detail = check(name, settings, logger=logger, timeout=timeout)
        if left is None:
            ok.append(name)                       # 查不到 ⇒ 不跳过（"我不知道"≠"没额度"）
            if logger:
                logger.debug(f"[extquota] {name} 额度查不到，本轮照常尝试：{detail}")
            continue
        if left < floor:
            bad[name] = f"剩余 {left}（{detail}）低于下限 {floor}"
            if logger:
                logger.info(f"[extquota] {name} 剩余额度 {left}（{detail}），"
                            f"低于下限 {floor} ⇒ **本轮跳过该源**（换 key 或等重置）")
            continue
        ok.append(name)
        if logger:
            logger.debug(f"[extquota] {name} 剩余 {left}（{detail}）")
    return ok, bad
