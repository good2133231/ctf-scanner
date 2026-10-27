"""同 IP 绑不同 Host 头找隐藏站点（续183，借鉴点②；ShuiZe hostCollide 思路，纯工程落地）。

法律边界照旧：**只读 GET**、单任务请求预算封顶、**默认开**（`hostcollide.enabled: true`，续203），
策略开着就跑（建任务**不用勾**）；任务选项 `hostcollide: true` 只在策略被关掉时给单次任务强制开。

产出是「这个域名在这台 IP 上也能服务」的绑定关系：落 `subdomains`，source=`collide:<ip>`
—— 前缀不匹配 `js:` / `osint:`，自动归 own 口径（判据复用 `db.OWN_SUBDOMAIN_WHERE`，§5.14）。
命中判据：响应可用（100-599）**且指纹（状态码+长度+标题）与该 IP 的默认虚机不同** ——
与默认一样，说明看到的是 IP 的默认页，不是藏着的站点。
"""
from . import db
from .utils import html_title, http_request


def plan(task_id):
    """本任务可碰撞的 `[(ip, [hosts])]`（纯读库，不发请求）。

    IP 取本任务 own 口径、已解析且**非多 IP**（`,` 串联是 CDN/多 A 记录链，碰撞无意义）
    的行；候选 Host = 本任务全部 own 域名。判据复用 `db.OWN_SUBDOMAIN_WHERE`（§5.14）。
    """
    rows = db._query("SELECT domain, ip FROM subdomains WHERE task_id=? AND ip<>'' AND "
                     + db.OWN_SUBDOMAIN_WHERE, (task_id,))
    hosts = sorted({str(r["domain"] or "").strip() for r in rows
                    if str(r["domain"] or "").strip()})
    ips = sorted({str(r["ip"] or "").strip() for r in rows
                  if str(r["ip"] or "").strip() and "," not in str(r["ip"])})
    return [(ip, hosts) for ip in ips]


def _fp(ip, host, timeout, settings=None):
    """一次探测的指纹 `(status, length, title)`；请求失败给 `None`（不算命中也不算错）。

    续286（审计续285 发现的漂移）：改走 `utils.http_request` —— 与全框架同一个 HTTP 出口，
    UA 伪装、`limits.verify_tls` 分流、`_throttle` 名额/预算（`settings["_throttle"]`）一并生效。
    只保留本能力自己的语义：`Host:` 覆盖探测 + 不跟随重定向。
    """
    r = http_request(f"http://{ip}/", timeout=timeout, allow_redirects=False,
                     headers={"Host": host} if host else {}, settings=settings)
    if not r:
        return None
    status = int(r.get("status") or 0)
    if not (100 <= status <= 599):
        return None
    try:
        title = (html_title(r.get("text") or "") or "").strip()[:80]
    except Exception:                                   # noqa: BLE001 - 标题解析失败不算错
        title = ""
    return (status, int(r.get("length") or 0), title)


def collide(ip, hosts, settings, stopped=None):
    """对一个 IP 逐个绑 Host 试探 → `[(host, status, length, title)]`（只命中与默认不同的）。

    预算：`hostcollide.max_requests` 封住单个 IP 的候选数（超出截断，日志由 run() 说出口）。
    """
    cfg = (settings or {}).get("hostcollide") or {}
    try:
        timeout = int(cfg.get("timeout", 5) or 5)
    except (TypeError, ValueError):
        timeout = 5
    try:
        cap = int(cfg.get("max_requests", 200) or 200)
    except (TypeError, ValueError):
        cap = 200
    todo = [h for h in (hosts or ()) if h][:max(0, cap)]
    default = _fp(ip, None, timeout, settings)
    hits = []
    for h in todo:
        if stopped is not None and stopped():
            break
        fp = _fp(ip, h, timeout, settings)
        if fp is None or fp == default:
            continue        # 与默认虚机一样 ⇒ 不是藏着的站点；请求失败 ⇒ 不猜
        hits.append((h,) + fp)
    return hits, len(todo)


def run(ctx):
    """任务级入口（PipelineRunner 在阶段跑完后按任务选项 `hostcollide: true` 调用）。

    策略开关 `hostcollide.enabled` 关着就**一个请求都不发**，只打一行 info 说清"没跑是因为没开"
    —— 与 afrog 的"没开启 ≠ 没扫到"同一口径（§0 第 10 条）。
    命中写 `subdomains`（source=`collide:<ip>`），日志逐条带 IP 与指纹。
    """
    cfg = (ctx.settings or {}).get("hostcollide") or {}
    if not cfg.get("enabled", False):
        ctx.logger.info("[hostcollide] 未开启（hostcollide.enabled=false），本轮零请求 —— "
                        "不是「没碰出东西」，是没跑；要开请改策略文件")
        return
    pairs = plan(ctx.task_id)
    if not pairs:
        ctx.logger.info("[hostcollide] 本任务没有可碰撞的 IP（own 口径下无已解析非多 IP 行）")
        return
    total_hosts = max((len(h) for _, h in pairs), default=0)
    ctx.logger.info(f"[hostcollide] 同 IP 绑 Host 碰撞：{len(pairs)} 个 IP × "
                    f"{total_hosts} 个候选 Host（只读 GET，指纹与默认虚机比对）")
    found = {}
    for ip, hosts in pairs:
        if ctx.stopped():
            ctx.logger.warning("[hostcollide] 任务已请求停止，只记录已完成 IP 的结果")
            break
        hits, tried = collide(ip, hosts, ctx.settings, stopped=ctx.stopped)
        if hits:
            found[ip] = hits
            rows = [(h, f"collide:{ip}") for h, _s, _l, _t in hits]
            db.insert_subdomains(ctx.task_id, rows)
            for h, st, ln, ti in hits:
                ctx.logger.info(f"[hostcollide] 命中 {h} @ {ip}（{st}/{ln}「{ti}」）—— "
                                "已按 collide: 来源入库（own 口径）")
        if tried < len(hosts):
            ctx.logger.info(f"[hostcollide] {ip}：候选 {len(hosts)} 个受预算截断为 {tried} 个"
                            f"（hostcollide.max_requests）")
    if not found:
        ctx.logger.info("[hostcollide] 未发现隐藏绑定（所有响应都与默认虚机一致或不可达）")
    else:
        ctx.logger.info(f"[hostcollide] 完成：{len(found)} 个 IP 上发现 "
                        f"{sum(len(v) for v in found.values())} 个隐藏绑定")
