"""泛解析（wildcard DNS）识别与过滤。

为什么需要：目标若开了 `*.example.com` 通配解析，字典爆破里**每一个词都会"命中"**，
子域名表会被垃圾灌满，并连带污染 probe/dirscan/vulnscan（实测这是最伤信噪比的一环）。

两步法（纯 DNS 查询，不发任何 HTTP，符合非破坏性约束）：
1. `detect()`：随机生成若干个几乎不可能存在的标签去解析，能解析出来的 IP 记为"通配 IP"
   —— 能解析出来本身就说明该域名开了泛解析（注入 `wk3f9x2a1b7c.example.com` 这类名字
   真实存在的概率可以忽略）。
2. `resolve_all()` + `filter_hits()`：并发解析候选词，凡**解析结果全部落在通配 IP 内**的候选
   判为泛解析产物丢弃；解析出"混合 IP"（既有通配 IP 又有别的 IP）的保留，
   避免把共享同一负载均衡 IP 的真实子域一起误杀。

局限（客观说明）：只用系统解析器（`socket.getaddrinfo`），**取不到 CNAME**，
所以无法用"通配 CNAME 黑名单"这个维度（参考项目 `core/utils/wildcard.py` 有，
因为它直接查 DNS 记录拿 CNAME；我们不加 DNS 库依赖，故不做）。
"""
import random
import string

from .utils import pool_run, resolve_host

_ALPHABET = string.ascii_lowercase + string.digits


def random_label(n=12):
    """生成一个随机标签，用于探测泛解析。"""
    return "".join(random.choice(_ALPHABET) for _ in range(n))


def detect(domain, samples=3, resolve=None):
    """探测 domain 的泛解析，返回通配 IP 集合；无泛解析返回空集合。"""
    resolve = resolve or resolve_host
    ips = set()
    for _ in range(max(1, int(samples))):
        ips.update(resolve(f"{random_label()}.{domain}") or [])
    return ips


def resolve_all(names, workers=20, resolve=None):
    """并发解析，返回 {name: [ip, ...]}（只保留解析成功的项）。"""
    resolve = resolve or resolve_host
    out = {}
    for item in pool_run(lambda n: (n, resolve(n)), names, workers=workers):
        name, ips = item
        if ips:
            out[name] = ips
    return out


def filter_hits(resolved, wildcard_ips):
    """按通配 IP 过滤解析结果。

    resolved: {name: [ip, ...]}；wildcard_ips: 该域名探测到的通配 IP（可为空集）。
    返回 (kept_names, dropped) —— dropped 为 [(name, "ip,ip"), ...]，便于日志与排查。
    未探测到泛解析时（wildcard_ips 为空）不做任何丢弃。
    """
    wild = set(wildcard_ips or ())
    if not wild:
        return list(resolved.keys()), []
    kept, dropped = [], []
    for name, ips in resolved.items():
        if set(ips) <= wild:
            dropped.append((name, ",".join(sorted(ips))))
        else:
            kept.append(name)
    return kept, dropped