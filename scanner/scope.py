"""授权范围（scope）判定 —— 目标侧请求的统一闸（续372）。

为什么放在 `utils.http_request` 里而不是各阶段自己判：目标侧出口有十几处
（probe / dirscan / vulnscan / jsmine / cert / screenshot / evasion / pocs / ssrf …），
任何一处漏判就等于「授权范围」形同虚设；而第三方接口（`auth=False`：FOFA / crt.sh /
CISA KEV / IP 反查）**不该**受这份 scope 约束 —— 它们不是被扫目标。

三条语义（fail-closed 优先，宁可少扫也不越界）：
- `enabled=false`（默认）⇒ 全部放行，零行为变化；
- 开了但 `allow_domains` 与 `allow_cidrs` **都为空** ⇒ **全部拒绝**（配置不完整不等于不限）；
- 域名走后缀匹配（`a.example.com` 命中 `example.com`）、IP 走 CIDR；端口 / 路径 / 时间窗
  为空表示**不限**（这一档才是"不限"，与上面"空白即拒绝"刻意不同，注释写清楚）。

本模块**零请求、零副作用**，只做纯计算；是否拦截由调用方决定（`http_request` 返回 None，
`http_last_error()` 给出 `scope 拒绝：…`）。
"""
import ipaddress
import time
from urllib.parse import urlsplit

# 规范化后的键集合（也是 `options.scope` 允许覆盖的键）
KEYS = ("enabled", "allow_domains", "allow_cidrs", "time_window",
        "allow_ports", "allow_paths")

DEFAULTS = {
    "enabled": False,
    "allow_domains": [],
    "allow_cidrs": [],
    "time_window": "",
    "allow_ports": [],
    "allow_paths": [],
}


def _as_list(raw):
    if isinstance(raw, str):
        return [x.strip() for x in raw.replace("\n", ",").split(",") if x.strip()]
    if isinstance(raw, (list, tuple)):
        return [str(x).strip() for x in raw if str(x or "").strip()]
    return []


def _cidr(text):
    try:
        return ipaddress.ip_network(str(text).strip(), strict=False)
    except ValueError:
        return None


def _as_ports(raw):
    out = set()
    for x in _as_list(raw):
        try:
            p = int(x)
        except (TypeError, ValueError):
            continue
        if 0 < p < 65536:
            out.add(p)
    return out


def normalize(settings, options=None):
    """全局 `scope` 段 + 任务级 `options.scope` 覆盖 → 规范化配置。

    只接受 `KEYS` 里的键：任务选项来自请求体，不能让一个拼错的键悄悄改掉别的语义。
    """
    base = dict(DEFAULTS)
    for src in ((settings or {}).get("scope"), (options or {}).get("scope")):
        if isinstance(src, dict):
            base.update({k: v for k, v in src.items() if k in KEYS})
    return {
        "enabled": bool(base.get("enabled")),
        "allow_domains": [d.lower().strip(".")
                          for d in _as_list(base.get("allow_domains")) if d.strip(".")],
        "allow_cidrs": [net for net in (_cidr(c) for c in _as_list(base.get("allow_cidrs")))
                        if net is not None],
        "time_window": str(base.get("time_window") or "").strip(),
        "allow_ports": sorted(_as_ports(base.get("allow_ports"))),
        "allow_paths": [p if p.startswith("/") else "/" + p
                        for p in _as_list(base.get("allow_paths"))],
    }


def _host_ok(host, cfg):
    h = str(host or "").strip().lower().rstrip(".")
    if not h:
        return False, "host 为空"
    try:
        addr = ipaddress.ip_address(h)
    except ValueError:
        addr = None
    if addr is not None:
        if not cfg["allow_cidrs"]:
            return False, f"IP {h} 不在 allow_cidrs（该清单为空）"
        for net in cfg["allow_cidrs"]:
            if addr.version == net.version and addr in net:
                return True, ""
        return False, f"IP {h} 不在 allow_cidrs"
    if not cfg["allow_domains"]:
        return False, f"域名 {h} 不在 allow_domains（该清单为空）"
    for d in cfg["allow_domains"]:
        if h == d or h.endswith("." + d):
            return True, ""
    return False, f"域名 {h} 不在 allow_domains"


def _in_window(cfg, now_hm=None):
    raw = str(cfg.get("time_window") or "").strip()
    if not raw:
        return True, ""
    try:
        a, b = raw.split("-", 1)
        sh, sm = [int(x) for x in a.strip().split(":", 1)]
        eh, em = [int(x) for x in b.strip().split(":", 1)]
    except (ValueError, AttributeError):
        return False, f"time_window 格式非法：{raw}（应为 HH:MM-HH:MM）"
    cur = now_hm or time.strftime("%H:%M")
    try:
        ch, cm = [int(x) for x in str(cur).split(":", 1)]
    except (ValueError, AttributeError):
        return False, f"当前时间格式非法：{cur}"
    cur_m, s_m, e_m = ch * 60 + cm, sh * 60 + sm, eh * 60 + em
    if s_m <= e_m:
        ok = s_m <= cur_m <= e_m
    else:                                   # 跨零点：22:00-06:00
        ok = cur_m >= s_m or cur_m <= e_m
    return (True, "") if ok else (False, f"当前 {cur} 不在时间窗 {raw}")


def check_url(url, cfg, now_hm=None):
    """目标侧 URL 是否在授权范围内 → `(ok, reason)`；`reason` 空串表示放行。"""
    if not cfg or not cfg.get("enabled"):
        return True, ""
    text = str(url or "").strip()
    try:
        parts = urlsplit(text if "://" in text else "//" + text)
    except ValueError:
        return False, "URL 解析失败"
    ok, why = _host_ok(parts.hostname, cfg)
    if not ok:
        return False, why
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError:
        return False, "端口非法"
    if cfg["allow_ports"] and port not in cfg["allow_ports"]:
        return False, f"端口 {port} 不在 allow_ports"
    path = parts.path or "/"
    if cfg["allow_paths"] and not any(path.startswith(p) for p in cfg["allow_paths"]):
        return False, f"路径 {path} 不在 allow_paths"
    return _in_window(cfg, now_hm)


def check_host(host, cfg, now_hm=None):
    """只判 host（portscan 这类不走 URL 的出口）→ `(ok, reason)`。"""
    if not cfg or not cfg.get("enabled"):
        return True, ""
    ok, why = _host_ok(host, cfg)
    if not ok:
        return False, why
    return _in_window(cfg, now_hm)
