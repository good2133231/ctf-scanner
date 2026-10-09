"""阶段 2：HTTP 存活探测与站点信息提取。

工具适配器：httpx（`-nfs` 锁 scheme、不设状态码白名单，输出 JSONL，含 title/tech-detect）
内置兜底：requests/urllib 探测（https 优先、失败回退 http），提取标题/Server/技术栈
（技术栈由 scanner/fingerprint.py 从响应头与正文识别）。

存活口径见下面 `is_alive`：**服务端回了真实状态码就记站点**（521/502/400 也记），
旧版那条 `-mc 200,301,302,403,404` 会把整台主机抹掉，实测少记 49 台（其中 34 台有子域名）。

对应参考流水线：
  ./tools/scanner/httpx -l ./logs/httpx_url -mc 200,301,302,403,404 -o ./logs/dir_out
  （`-mc` 这一项**已有意偏离**，理由与实测数据见 `is_alive`；`-nfs` 是本轮补上的。）
"""
import json
from urllib.parse import urlparse

from .base import Stage
from .. import blacklist, db, extdom, flagfind, wildcard
from ..fingerprint import identify, favicon_md5
from ..utils import (REDIRECT_STATUS, html_title, which, verify_tool, run_cmd, read_lines,
                     write_lines, pool_run, http_request)


# 「哪些状态算需要跟随的跳转」由 `scanner/utils.py` 单独定义（取证这里与显示侧
# `site_redirect` 必须用同一份，写两遍迟早一边算 304 一边不算）；`REDIRECT_STATUS` 只是
# 被上面的 import 带进本模块命名空间 —— [8k] 的变异打桩的就是这个名字。


def is_alive(status):
    """这台主机算不算「存活站点」：**只要服务端回了一个真实 HTTP 状态码就算**。

    取代旧版白名单 `ALLOW_STATUS = {200, 301, 302, 403, 404}`。改动理由不是口径偏好，是实测：
    2026-10-08 对 weex.com 与灯塔逐条比对，灯塔记为站点、我们一条都没入库的主机有 **49 台**
    （其中 **34 台**我们本来就有子域名、另外 15 台连域名都没生成，那部分差在字典），
    它们在 `-mc` 下**整行被过滤掉**（不是标成死站，是根本不出现在 httpx 输出里）。挑 6 台实测：
    带 `-mc` 收上来 0 行，去掉 `-mc` 收上来 6 行，状态码是 `301`/`521`/`502`/`400` ——
    CDN 边缘活着、源站挂了，这本身就是资产事实，而灯塔那 66 个站点里 301 占 36 个、403 占 15 个，
    真正 200 的只有 6 个：它一直就是"能回就记"，我们之前是"回得好看才记"，两边没法比。

    边界收紧到 100–599：`None`/`0`/`999`/非数字一律不算，所以 DNS 不可达、连接被拒、超时
    照旧被丢掉（实测死主机在 httpx 里是 0 行，不会因去掉白名单而混进来）。
    """
    try:
        code = int(status)
    except (TypeError, ValueError):
        return False
    return 100 <= code <= 599


def attach_redirect_info(sites, fetch, workers=8, logger=None):
    """给 3xx 站点补 `redirect_url` / `redirect_status` / `redirect_title`，返回补到的条数。

    `fetch(url)` 由调用方提供（probe 里就是带节流与登录态的 `http_request`），返回
    `dict(status, url, text)` 或 None。**就地改传入的条目**，不复制一份 —— 站点条目随后要进
    任务快照、进 `db.insert_sites`，复制那份改了也白改（`[8k]` 的断言就看库里读回来的值）。

    三条底线：
    - **原始那一跳不动**：`status` / `title` / `length` 仍是那次响应的实况。把 301 覆盖成落地页
      的 200 等于谎报"这个端口直接回 200"，而跳转链本身是信息（301 与 200 的安全含义不同）。
    - **拿不到就不编数**：落地页打不开 / 请求失败 → 三个字段留空，页面按原样显示那一跳
      （显示口径在 `scanner/utils.py::site_redirect`：没有 `redirect_status` 就不打「跳转后」标记）。
    - **只在确实有 3xx 时才发请求**：一个都不多打（限流预算是按请求数计的）。
    """
    red = [s for s in (sites or []) if int(s.get("status") or 0) in REDIRECT_STATUS]
    if not red:
        return 0

    def _one(s):
        r = fetch(s.get("url"))
        if not r or not r.get("status"):
            return None
        return {"url": s.get("url"), "redirect_url": str(r.get("url") or ""),
                "redirect_status": int(r.get("status") or 0),
                "redirect_title": html_title(r.get("text"))}

    got = {x["url"]: x for x in pool_run(_one, red, workers=workers, logger=logger,
                                       label="跳转后取证") if x}
    n = 0
    for s in sites:
        k = got.get(s.get("url"))
        if not k:
            continue
        s["redirect_url"] = k["redirect_url"]
        s["redirect_status"] = k["redirect_status"]
        s["redirect_title"] = k["redirect_title"]
        n += 1
    if logger:
        logger.info(f"[probe] 3xx 站点 {len(red)} 个，补到「跳转后」信息 {n} 个"
                    + ("" if n == len(red)
                       else "（落地页取不到的那些不编数，页面仍显示原始那一跳）"))
    return n


def probe_candidates(ctx, candidates):
    """一轮 HTTP 探测的全部机器：httpx 优先、内置兜底，返回**未去重、未入库**的站点 dict 列表。

    第一轮（`ProbeStage.run`）与二层遍历（`second_pass`）共用这一份 —— 两处各写一遍的话，
    "什么算存活"迟早一边一个口径（续139 那次 `-mc` 丢掉 34 台主机正是藏在其中一遍里）。
    """
    th = ctx.throttle        # F2 统一门控：本任务的限流器（可能是 None）
    limits = ctx.settings.get("limits", {})
    workers = int(limits.get("max_workers", 20))
    timeout = int(limits.get("http_timeout", 10))
    sites = []
    # 登记"这一轮发过请求的候选"，**httpx 与内置两条路都要登记**：只靠 httpx 那份
    # `httpx_url.txt` 的话，没装 httpx（或 `--offline`）的机器上二层会把第一轮超时的主机
    # 整批重探一遍（本机实测踩过这个形状：判据吃的是另一个分支才写的文件）。
    _tried_f = ctx.workdir / "probe_tried.txt"
    write_lines(_tried_f, list(dict.fromkeys(read_lines(_tried_f) + list(candidates))))
    offline = ctx.options.get("offline")
    hx_bin = which(ctx.settings.get("tools", {}).get("httpx", "httpx"))
    if hx_bin and not verify_tool(hx_bin):
        hx_bin = None
        ctx.logger.info("[probe] PATH 中的 httpx 未通过版本校验"
                        "（可能是 Python httpx 同名命令），使用内置探测")
    if hx_bin and not offline:
        ctx.logger.info(f"[probe] 使用 httpx 探测 {len(candidates)} 个候选 …")
        # 二轮的产物**另名落盘**（`*_r2.*`）：两条轮次共用同一个文件名的话，第二轮会把第一轮
        # 的输入清单与输出覆掉 —— 事后翻工作目录会以为"那次只探了这几个"，而 docs/pipeline.md
        # 恰恰把 `httpx_url.txt` 登记成任务产物。
        _r2 = bool(ctx.results.get("sites"))
        url_file = write_lines(ctx.workdir / ("httpx_url_r2.txt" if _r2 else "httpx_url.txt"),
                               candidates)
        out_json = ctx.workdir / ("httpx_out_r2.json" if _r2 else "httpx_out.json")
        # `-mc` 去掉，存活口径统一到 `is_alive`（见那里的实测数据）。
        # `-nfs` 加上（= 只按输入里写明的 scheme 探，不替我们回退到另一个 scheme）：
        # 默认行为下 `http://h` 那一行最终变成 `https://h` 的落地状态（实测 ws-spot.weex.com：
        # 默认 → `https` + 521，加 `-nfs` → `http` + 301），**原始那一跳就再也看不见**，
        # 而每个主机的 https/http 两条候选本来都在我们自己的候选列表里，回退是多余的。
        # 锁住 scheme 后 301 行才会稳定出现，续112-B 的「跳转后」取证才有输入。
        # 不加 `-fr`：跟随跳转会把第一跳覆盖成落地页状态，正是 `attach_redirect_info`
        # 刻意避免的谎报（它用「原始不动 + redirect_* 另存」做同一件事）。
        rc, _, err = run_cmd(
            [hx_bin, "-l", str(url_file), "-nfs",
             "-title", "-tech-detect", "-status-code", "-content-length",
             "-json", "-silent", "-o", str(out_json)], timeout=3600, throttle=th)
        if rc == 0 and out_json.exists():
            for line in read_lines(out_json):
                try:
                    j = json.loads(line)
                except Exception:
                    continue
                url = j.get("url") or j.get("input") or ""
                if not str(url).startswith("http"):
                    continue
                if j.get("failed") or not is_alive(j.get("status_code")):
                    # 去掉 `-mc` 后**这一层就是唯一的存活口径**（两条探测路共用同一个函数）。
                    # httpx 在 `-silent` 下对彻底失败的候选本来就给不出行（实测 0 行），
                    # 这里兜的是"有行但没有真实状态码"那一种。
                    continue
                tech = j.get("tech") or []
                p = urlparse(str(url))
                sites.append({
                    "url": url, "host": p.hostname,
                    "port": str(p.port or (443 if p.scheme == "https" else 80)),
                    "status": j.get("status_code"),
                    "title": (j.get("title") or "").strip()[:200],
                    "length": j.get("content_length"),
                    "server": j.get("webserver") or "",
                    "tech": ",".join(tech) if isinstance(tech, list) else str(tech),
                    "source": "httpx",
                })
        else:
            ctx.logger.warning(f"[probe] httpx 退出码 {rc}，回退内置探测：{err.strip()[:200]}")

    if not sites:
        ctx.logger.info(f"[probe] 内置探测 {len(candidates)} 个候选（https 优先，逐个回退 http）…")

        def _probe(c):
            if ctx.stopped():
                return None
            tries = [c] if str(c).startswith("http") else [f"https://{c}", f"http://{c}"]
            for u in tries:
                resp = http_request(u, timeout=timeout, settings=ctx.settings, auth=True)
                if resp and is_alive(resp.get("status")):
                    title = html_title(resp.get("text"))
                    # flag 候选（续126）：正文已经在手（上面刚用它取过标题），**不多发一个请求**。
                    flagfind.harvest(ctx, resp.get("url") or u, resp.get("text") or "", "probe")
                    p = urlparse(resp.get("url") or u)
                    try:
                        port = p.port
                    except ValueError:
                        port = None
                    return {
                        "url": resp.get("url") or u, "host": p.hostname,
                        "port": str(port or (443 if p.scheme == "https" else 80)),
                        "status": resp.get("status"),
                        "title": title,
                        "length": resp.get("length"),
                        "server": (resp.get("headers") or {}).get("Server", ""),
                        "tech": ",".join(identify(resp)), "source": "builtin",
                    }
            return None

        sites = pool_run(_probe, candidates, workers=workers, logger=ctx.logger,
                         label="存活探测")
    return sites



def register_sites(ctx, sites, round2=False):
    """去重 + favicon + 「跳转后」取证 + 落库 + 日志；返回本轮入库的站点列表。

    `round2=True` 是二层遍历那一轮：`ctx.results["sites"]` **追加而不是覆盖** —— 否则 jsmine
    之后的 dirscan / vulnscan 读到的仍是第一轮那份，新探出来的站点白探（落库了却没人用）。
    """
    limits = ctx.settings.get("limits", {})
    workers = int(limits.get("max_workers", 20))
    timeout = int(limits.get("http_timeout", 10))
    # 去重入库
    uniq, seen = [], set()
    for s in sites:
        if s["url"] in seen:
            continue
        seen.add(s["url"])
        uniq.append(s)

    # favicon MD5（P1-1）：存活站点各补一次 GET，作为 POC 的"零请求前置指纹"
    if limits.get("favicon_md5", True) and uniq:
        def _fav(s):
            return {"url": s["url"],
                    "md5": favicon_md5(s["url"], ctx.settings, timeout=timeout)}
        favs = {r["url"]: r["md5"] for r in pool_run(_fav, uniq, workers=workers,
                                      logger=ctx.logger, label="favicon 指纹")}
        for s in uniq:
            s["favicon"] = favs.get(s["url"], "")
        hits = sum(1 for s in uniq if s["favicon"])
        ctx.logger.info(f"[probe] favicon 指纹 {hits}/{len(uniq)} 个站点已获取")

    # 3xx 站点补一次「跳转后」取证（续112-B，用户 2026-10-06：「301 的状态码我希望给跳转
    # 之后的标题，标记一个跳转后」）：httpx 不跟随重定向，收上来的 301 行标题就是
    # 字面的「301 Moved Permanently」，完全看不出这跳去了哪儿、落地页是什么。
    # （本轮去掉 `-mc` + 加 `-nfs` 之后这条路的输入才**稳定存在**：之前 301 行要么被白名单
    # 过滤掉，要么被 httpx 的 scheme 回退换成 https 的落地状态，3xx 站点十有八九根本进不来。）
    attach_redirect_info(
        uniq,
        lambda u: None if ctx.stopped() else http_request(
            u, timeout=timeout, settings=ctx.settings, auth=True, allow_redirects=True),
        workers=workers, logger=ctx.logger)

    if round2:
        # **追加**：jsmine 之后的 dirscan / vulnscan 读的是 `ctx.results["sites"]`，
        # 覆盖写法会把第一轮的站点从内存里抹掉（库里却有）—— 两处口径又不一致了。
        _old = list(ctx.results.get("sites") or [])
        _known = {s.get("url") for s in _old}
        ctx.results["sites"] = _old + [s for s in uniq if s.get("url") not in _known]
    else:
        ctx.results["sites"] = uniq
    _all_urls = [s["url"] for s in (ctx.results["sites"] or [])] if round2 else \
        [s["url"] for s in uniq]
    if round2:
        # 二层那轮：`sites.txt` 是任务产物，必须是**全量**（内存里没有第一轮那批时，回库里取 ——
        # 只跑 jsmine 的补扫就会走到这里）
        _all_urls = list(dict.fromkeys(
            _all_urls + [s["url"] for s in uniq]
            + [r["url"] for r in db.list_sites(ctx.task_id)]))
    write_lines(ctx.workdir / "sites.txt", _all_urls)
    # 跨运行去重（续25）：追加执行时已在库的站点 URL 不再重复入库（新任务/重启为空表，零影响）
    new_sites = db.drop_existing(ctx.task_id, "sites", ("url",), uniq,
                                 lambda s: (s["url"],))
    db.insert_sites(ctx.task_id, new_sites)
    _dup = len(uniq) - len(new_sites)
    # 口径改了，日志就必须把**组成**写出来：否则"存活站点 168 个"会被读成"168 个打得开的站"。
    _cls = {}
    for s in uniq:
        try:
            k = int(str(s.get("status") or "0")[0])
        except (TypeError, ValueError):
            k = 0
        _cls[k] = _cls.get(k, 0) + 1
    # 「有站点却没有标题」是用户会盯着问的事（2026-10-09 实测 agent.weex.com 原始 HTML 无
    # `<title>`，标题由 JS 注入）。在这里就说清"不是抓取失败"以及"在哪儿能补到"，
    # 而不是留一排 `-` 让人以为漏扫了。
    _nt = sum(1 for s in uniq if not str(s.get("title") or "").strip())
    ctx.logger.info(
        f"[probe] {'二层新增站点' if round2 else '存活站点'} {len(uniq)} 个（按状态码首位 "
        + " ".join(f"{k}xx={_cls[k]}" for k in sorted(_cls))
        + "；口径＝服务端回了真实状态码就算，4xx/5xx 多为 CDN 边缘活着、源站挂了，不等于站点可用"
        + (f"；{_nt}/{len(uniq)} 个原始 HTML 里没有 <title>（SPA 外壳常见，**不是抓取失败**；"
           f"勾选「截图」会用无头浏览器渲染后补标题）" if _nt else "")
        + (f"；跨运行去重跳过 {_dup} 个已入库站点" if _dup else "") + ")")
    return uniq


def second_pass(ctx, extra=()):
    """二层遍历：把**第一轮之后才长出来的域名**补探成站点（续139）。

    第一轮为什么不够：`subdomain` 跑完之后，`jsmine`（JS 里挖出的域名）、`cert`（SAN 名字）、
    `osint`（IP 反查）还在继续长新名字，而这些名字此前**只进 `subdomains` 表，没有任何一条路
    把它们变成站点** —— 这正是"我们子域名不比它少、站点却比它少"的另一半原因。

    三条纪律，缺一条就会变成给互联网发无意义请求：
    - 只探**本任务归属**的域名（`extdom.task_bases` + `is_owned`），别人的域名不碰；
    - 先过一遍 **DNS** 再上 HTTP：被动来源带回来的名字一大半早就不解析了（任务 8 的
      1309 条里 1150 条没有 A 记录），逐条去 HTTP 探是纯浪费；
    - 有**上限**（`limits.recrawl_max_hosts`）并且**分批预筛**：攒够上限就停止扫描 DNS，
      不把全库重扫一遍。
    每一步跳了多少、为什么跳，都写进日志 —— 二层遍历最容易变成"看起来跑了其实一个都没探"。
    返回本轮入库的站点数。
    """
    cfg = ctx.settings.get("jsmine", {}) or {}
    if not cfg.get("recrawl", True):
        ctx.logger.info("[probe] 二层遍历已关闭（jsmine.recrawl=false），跳过")
        return 0
    if ctx.stopped():
        ctx.logger.warning("[probe] 任务已请求停止，跳过二层遍历")
        return 0
    # 二层是"补探"，前提是**这个任务真的跑过第一轮探测**：只勾 jsmine 的补扫、或 probe
    # 被关掉的流水线里，第一轮那份候选清单根本不存在，此时把全库域名拿去首发 HTTP 就是
    # 越过了用户关掉 probe 的决定（库里 `sites` 有行也算跑过 —— 续跑/追加执行的情形）。
    if "probe" not in (ctx.stages or []) and not db.list_sites(ctx.task_id):
        ctx.logger.info("[probe] 二层遍历跳过：本任务没有第一轮探测记录（probe 阶段没跑过，"
                        "库里也没有站点），二层只做「补探」，不做「首探」")
        return 0
    limits = ctx.settings.get("limits", {})
    # `limits.recrawl_max_hosts = 0` 按本仓"0=不限"的一贯口径理解，但**留一个硬顶**：
    # 二层是补探，不是把全库重扫；真要大范围重扫应该新建一条完整任务（阶段顺序、限速、
    # 预算都齐），所以这里 0 夹到 2000 并说出来，而不是当成"一条都不探"。
    raw_cap = int(limits.get("recrawl_max_hosts", 300))
    cap = raw_cap if raw_cap > 0 else 2000
    workers = int(limits.get("max_workers", 20))
    bases = extdom.task_bases(ctx.task_id)
    if not bases:
        ctx.logger.info("[probe] 二层遍历跳过：任务目标里没有可归属的域名"
                        "（纯 IP / 纯 URL 目标没有“二层”可走）")
        return 0

    probed = {r["host"] for r in db.list_sites(ctx.task_id) if r["host"]}
    for s in ctx.results.get("sites") or []:
        if s.get("host"):
            probed.add(s["host"])
    # 第一轮**发过请求**的那些主机（连没回应的也算）同样算已探过：再探一次还是不回，纯白发消息。
    # 判据取 `probe_tried.txt`（两条探测路都写，见 `probe_candidates`）；`httpx_url.txt` 一并读，
    # 是为了让改动之前那批任务目录（续跑/补扫）不至于突然把已探过的主机当成新名字。
    for _line in read_lines(ctx.workdir / "probe_tried.txt") + \
            read_lines(ctx.workdir / "httpx_url.txt"):
        _h = urlparse(str(_line)).hostname
        if _h:
            probed.add(_h)
    names = list(dict.fromkeys(
        list(ctx.results.get("js_domains") or []) + list(extra or [])
        + [r["domain"] for r in db.list_subdomains(ctx.task_id)]))
    pool, skip_scope, skip_known = [], 0, 0
    # 用户黑名单再过一道（`config/blacklist.txt`）：`subdomains` 表里的名字入库前已经过滤过，
    # 但 `js_domains`/`extra` 是本轮新交的，而"黑名单命中的域名连子域都不该被扫描"是硬承诺。
    names, _bl = blacklist.filter_domains(names, ctx.settings,
                                         owner_id=getattr(ctx, "owner_id", 0))
    for raw in names:
        h = str(raw or "").strip().lower()
        if not h:
            continue
        if not extdom.is_owned(h, bases):
            skip_scope += 1
            continue
        if h in probed:
            skip_known += 1
            continue
        pool.append(h)
    if not pool:
        ctx.logger.info(f"[probe] 二层遍历：{len(names)} 个候选名全部跳过"
                        f"（非本任务归属 {skip_scope}、第一轮已探过 {skip_known}）")
        return 0

    live, scanned = [], 0
    chunk = max(1, min(cap, 200))     # 跟着上限走：devmode 压到 1 时才是真的只查 1 个
    # DNS 预筛本身也要有上限（续139）：装了 puredns + 17.8 万条深字典之后，池子里可能躺着
    # 十万个名字，而绝大多数是不解析的历史噪声 —— 一个都不解析时"扫到攒够为止"等于扫完全库。
    dns_max = max(cap * 10, 50)
    while scanned < min(len(pool), dns_max) and len(live) < cap:
        if ctx.stopped():
            break
        batch = pool[scanned:scanned + chunk]
        scanned += len(batch)
        got = wildcard.resolve_all(batch, workers=workers)
        live += [h for h in batch if h in got]
    take = live[:cap]
    ctx.logger.info(
        f"[probe] 二层遍历：候选 {len(pool)} 个（另跳过 非归属 {skip_scope} / 已探过 "
        f"{skip_known}）→ DNS 预筛 {scanned} 个，可解析 {len(live)} 个"
        f"（不可解析 {scanned - len(live)} 个，探了也是白发请求）→ 本轮补探 {len(take)} 个"
        + (f"，其中 {len(live) - len(take)} 个受 limits.recrawl_max_hosts={cap} 上限留到下轮"
           if len(live) > len(take) else "")
        + (f"；另有 {len(pool) - scanned} 个候选没做预筛（攒够上限就停，不为报数把全库查一遍）"
           if scanned < len(pool) and len(take) >= cap else "")
        + (f"；预筛只扫了前 {dns_max} 个（上限 max(10×上限, 50)，池子还有 "
           f"{len(pool) - scanned} 个没查）—— 不是漏探，是不肯为一个二层把全库查一遍"
           if scanned < len(pool) and scanned >= dns_max else ""))
    if not take:
        return 0
    cands = []
    for h in take:
        cands.extend([f"https://{h}", f"http://{h}"])
    return len(register_sites(ctx, probe_candidates(ctx, cands), round2=True))


class ProbeStage(Stage):
    name = "probe"
    description = "HTTP 存活探测（httpx 或内置探测），提取标题/Server/技术栈"

    def run(self):
        ctx = self.ctx
        _flag0 = flagfind.begin(ctx)
        if ctx.stopped():
            ctx.logger.warning("[probe] 任务已请求停止，跳过")
            return

        candidates = []
        # 直接给出的 URL 目标原样参与
        for kind, raw in ctx.targets:
            if kind == "url":
                candidates.append(raw)
            elif kind == "ip":
                candidates.extend([f"https://{raw}", f"http://{raw}"])
            elif kind == "domain":
                # 域名目标此前只靠 subdomain 阶段写进 `domains_for_probe` 才被探测：
                # 用户只勾 probe（不勾 subdomain）时，域名目标会**静默产出 0 个站点**（日志只写"无可探测目标"）。
                # 这里自己补上候选，与子域名同规则（https 优先、失败回退 http）；
                # 两条路都走时后面的 `dict.fromkeys` 会去重，不会产生重复请求。
                candidates.extend([f"https://{raw}", f"http://{raw}"])
        # 域名 / 子域名按 https、http 两种 scheme 生成候选
        for h in ctx.results.get("domains_for_probe") or []:
            candidates.extend([f"https://{h}", f"http://{h}"])
        # 已发现的开放端口也要参与探测：灯塔能扫出 `http://host:9007` 这类站点，是因为它在
        # **开放端口**上补做了 HTTP 探测；我们此前只生成 :443/:80，所以永远看不到非标端口站点。
        # 输入来自 portscan（该阶段默认关，开了才有端口；其 max_hosts 已限制规模，无需另加上限）。
        ports = ctx.results.get("ports") or db.list_ports(ctx.task_id) or []
        extra = []
        for p in ports:
            try:
                pno = int(p["port"])
            except (KeyError, IndexError, TypeError, ValueError):
                continue
            host = (p["host"] or p["ip"] or "").strip()
            if host and pno not in (80, 443):
                extra.append(f"{host}:{pno}")
        if extra:
            ctx.logger.info(f"[probe] 额外纳入 {len(extra)} 个开放端口候选（来自 portscan）")
        for h in extra:
            candidates.extend([f"https://{h}", f"http://{h}"])
        candidates = list(dict.fromkeys(candidates))
        if not candidates:
            ctx.logger.info("[probe] 无可探测目标，跳过")
            return

        sites = probe_candidates(ctx, candidates)
        _reg = register_sites(ctx, sites)
        # flag 候选：走 httpx 那一档时**根本没有正文**（它只回 title/tech 的 JSONL），
        # 所以这一路的输入是 0 份 —— 必须说出来，否则"probe 没报 flag"会被读成"扫过了、没有"。
        _fnote = flagfind.note(ctx, _flag0)
        if _fnote:
            ctx.logger.info("[probe] flag 候选 " + _fnote)
        elif any(s.get("source") == "httpx" for s in _reg):
            ctx.logger.info("[probe] flag 候选：httpx 档不返回正文，本阶段无输入可扫"
                            "（jsmine / dirscan / vulnscan 三路仍会扫各自拿到的正文）")
