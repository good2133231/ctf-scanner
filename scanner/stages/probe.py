"""阶段 2：HTTP 存活探测与站点信息提取。

工具适配器：httpx（-mc 200,301,302,403,404，输出 JSONL，含 title/tech-detect）
内置兜底：requests/urllib 探测（https 优先、失败回退 http），提取标题/Server/技术栈
（技术栈由 scanner/fingerprint.py 从响应头与正文识别）。

对应参考流水线：
  ./tools/scanner/httpx -l ./logs/httpx_url -mc 200,301,302,403,404 -o ./logs/dir_out
"""
import json
import re
from urllib.parse import urlparse

from .base import Stage
from .. import db
from ..fingerprint import identify, favicon_md5
from ..utils import (REDIRECT_STATUS, which, verify_tool, run_cmd, read_lines, write_lines,
                     pool_run, http_request)

ALLOW_STATUS = {200, 301, 302, 403, 404}
# 「哪些状态算需要跟随的跳转」由 `scanner/utils.py` 单独定义（取证这里与显示侧
# `site_redirect` 必须用同一份，写两遍迟早一边算 304 一边不算）；`REDIRECT_STATUS` 只是
# 被上面的 import 带进本模块命名空间 —— [8k] 的变异打桩的就是这个名字。


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
        t = TITLE_RE.search(r.get("text") or "")
        return {"url": s.get("url"), "redirect_url": str(r.get("url") or ""),
                "redirect_status": int(r.get("status") or 0),
                "redirect_title": (t.group(1).strip()[:200] if t else "")}

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
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


class ProbeStage(Stage):
    name = "probe"
    description = "HTTP 存活探测（httpx 或内置探测），提取标题/Server/技术栈"

    def run(self):
        ctx = self.ctx
        th = ctx.throttle        # F2 统一门控：本任务的限流器（可能是 None）
        limits = ctx.settings.get("limits", {})
        workers = int(limits.get("max_workers", 20))
        timeout = int(limits.get("http_timeout", 10))
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

        sites = []
        offline = ctx.options.get("offline")
        hx_bin = which(ctx.settings.get("tools", {}).get("httpx", "httpx"))
        if hx_bin and not verify_tool(hx_bin):
            hx_bin = None
            ctx.logger.info("[probe] PATH 中的 httpx 未通过版本校验"
                            "（可能是 Python httpx 同名命令），使用内置探测")
        if hx_bin and not offline:
            ctx.logger.info(f"[probe] 使用 httpx 探测 {len(candidates)} 个候选 …")
            url_file = write_lines(ctx.workdir / "httpx_url.txt", candidates)
            out_json = ctx.workdir / "httpx_out.json"
            rc, _, err = run_cmd(
                [hx_bin, "-l", str(url_file), "-mc", "200,301,302,403,404",
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
                    if resp and resp.get("status") in ALLOW_STATUS:
                        t = TITLE_RE.search(resp.get("text") or "")
                        p = urlparse(resp.get("url") or u)
                        try:
                            port = p.port
                        except ValueError:
                            port = None
                        return {
                            "url": resp.get("url") or u, "host": p.hostname,
                            "port": str(port or (443 if p.scheme == "https" else 80)),
                            "status": resp.get("status"),
                            "title": (t.group(1).strip()[:200] if t else ""),
                            "length": resp.get("length"),
                            "server": (resp.get("headers") or {}).get("Server", ""),
                            "tech": ",".join(identify(resp)), "source": "builtin",
                        }
                    if resp and resp.get("status") and resp["status"] not in (502, 503):
                        # 明确的非白名单响应也停止对该候选的下一 scheme 尝试
                        break
                return None

            sites = pool_run(_probe, candidates, workers=workers, logger=ctx.logger,
                             label="存活探测")

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
        # 之后的标题，标记一个跳转后」）：httpx 默认**不跟随**重定向，收上来的 301 行标题就是
        # 字面的「301 Moved Permanently」，完全看不出这跳去了哪儿、落地页是什么。
        attach_redirect_info(
            uniq,
            lambda u: None if ctx.stopped() else http_request(
                u, timeout=timeout, settings=ctx.settings, auth=True, allow_redirects=True),
            workers=workers, logger=ctx.logger)

        ctx.results["sites"] = uniq
        write_lines(ctx.workdir / "sites.txt", [s["url"] for s in uniq])
        # 跨运行去重（续25）：追加执行时已在库的站点 URL 不再重复入库（新任务/重启为空表，零影响）
        new_sites = db.drop_existing(ctx.task_id, "sites", ("url",), uniq,
                                     lambda s: (s["url"],))
        db.insert_sites(ctx.task_id, new_sites)
        _dup = len(uniq) - len(new_sites)
        ctx.logger.info(f"[probe] 存活站点 {len(uniq)} 个"
                        + (f"（跨运行去重跳过 {_dup} 个已入库站点）" if _dup else ""))
