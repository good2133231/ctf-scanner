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
from ..utils import which, verify_tool, run_cmd, read_lines, write_lines, pool_run, http_request

ALLOW_STATUS = {200, 301, 302, 403, 404}
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


class ProbeStage(Stage):
    name = "probe"
    description = "HTTP 存活探测（httpx 或内置探测），提取标题/Server/技术栈"

    def run(self):
        ctx = self.ctx
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
                 "-json", "-silent", "-o", str(out_json)], timeout=3600)
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
                    resp = http_request(u, timeout=timeout, settings=ctx.settings)
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

            sites = pool_run(_probe, candidates, workers=workers)

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
            favs = {r["url"]: r["md5"] for r in pool_run(_fav, uniq, workers=workers)}
            for s in uniq:
                s["favicon"] = favs.get(s["url"], "")
            hits = sum(1 for s in uniq if s["favicon"])
            ctx.logger.info(f"[probe] favicon 指纹 {hits}/{len(uniq)} 个站点已获取")

        ctx.results["sites"] = uniq
        write_lines(ctx.workdir / "sites.txt", [s["url"] for s in uniq])
        db.insert_sites(ctx.task_id, uniq)
        ctx.logger.info(f"[probe] 存活站点 {len(uniq)} 个")
