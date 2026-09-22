"""阶段 3：目录/路径发现。

工具适配器：dirmap（python dirmap.py -iF <urls> -e all，解析其 output/ 目录产物）
内置兜底：requests/urllib 字典扫描，带随机路径基线做软 404 过滤。

对应参考流水线：
  cd tools/scanner/dirmap-master && python dirmap.py -iF ../../../logs/dir_out -e all
"""
import random
import re

from .base import Stage
from .. import db
from ..config import resolve
from ..utils import read_lines, write_lines, pool_run, http_request, pick_python

URL_RE = re.compile(r"https?://[^\s'\"<>()]+")
STATUS_RE = re.compile(r"^\s*[\[(]?(\d{3})[\])]?\s*[,\s]")


class DirscanStage(Stage):
    name = "dirscan"
    description = "目录/路径爆破（dirmap 或内置字典扫描）"

    def run(self):
        ctx = self.ctx
        limits = ctx.settings.get("limits", {})
        sites = [s["url"] for s in ctx.results.get("sites", [])]
        sites = sites[: int(limits.get("dirscan_max_urls", 20))]
        if not sites:
            ctx.logger.info("[dirscan] 无存活站点，跳过")
            return
        if ctx.stopped():
            ctx.logger.warning("[dirscan] 任务已请求停止，跳过")
            return

        entries = []
        cfg = ctx.settings.get("tools", {}).get("dirmap", {}) or {}
        script = resolve(cfg.get("script", "tools/scanner/dirmap-master/dirmap.py"))
        used_dirmap = False
        if script.exists() and not ctx.options.get("offline"):
            ctx.logger.info(f"[dirscan] dirmap 处理 {len(sites)} 个站点 …")
            in_file = write_lines(ctx.workdir / "dirmap_in.txt", sites)
            rc, out, err = run_cmd(
                [pick_python(cfg.get("python", "python")), str(script),
                 "-iF", str(in_file), "-e", "all"],
                cwd=script.parent, timeout=7200)
            for f in self._latest_outputs(script.parent):
                entries.extend(self._parse_output(f))
            used_dirmap = bool(entries)
            if not used_dirmap:
                ctx.logger.warning(f"[dirscan] dirmap 未解析到结果（rc={rc}）：{err.strip()[:150]}，回退内置扫描")
            else:
                ctx.logger.info(f"[dirscan] dirmap 输出 {len(entries)} 条")
        else:
            ctx.logger.info("[dirscan] dirmap 不可用（或 --offline），使用内置字典扫描")

        if not used_dirmap:
            entries = self._builtin_scan(sites, limits)

        uniq, seen = [], set()
        for e in entries:
            key = (e.get("path"), e.get("status"))
            if key in seen:
                continue
            seen.add(key)
            uniq.append(e)
        ctx.results["dirs"] = uniq
        write_lines(ctx.workdir / "dirs.txt",
                    [f"{d.get('status', '')} {d.get('path', '')}" for d in uniq])
        db.insert_dirs(ctx.task_id, uniq)
        ctx.logger.info(f"[dirscan] 目录发现 {len(uniq)} 条")

    # ---------- dirmap 适配 ----------

    @staticmethod
    def _latest_outputs(dirmap_dir, limit=5):
        out_dir = dirmap_dir / "output"
        if not out_dir.is_dir():
            return []
        files = [f for f in out_dir.iterdir() if f.is_file()]
        files.sort(key=lambda f: f.stat().st_mtime, reverse=True)
        return files[:limit]

    @staticmethod
    def _parse_output(path):
        rows = []
        try:
            lines = read_lines(path)
        except OSError:
            return rows
        for line in lines:
            urls = URL_RE.findall(line)
            if not urls:
                continue
            m = STATUS_RE.match(line)
            status = int(m.group(1)) if m else None
            for u in urls:
                rows.append({"site_url": "", "path": u, "status": status,
                             "length": None, "method": "GET", "note": "dirmap"})
        return rows

    # ---------- 内置兜底 ----------

    def _builtin_scan(self, sites, limits):
        ctx = self.ctx
        workers = int(limits.get("max_workers", 20))
        timeout = int(limits.get("http_timeout", 10))
        dic = [p for p in read_lines(resolve(
            ctx.settings.get("dicts", {}).get("dirs", ""))) if not p.startswith("#")]
        if not dic or not sites:
            return []

        ctx.logger.info(f"[dirscan] 内置扫描：{len(sites)} 站点 x {len(dic)} 字典 …")
        soft404 = {}

        def _baseline(u):
            if u not in soft404:
                marker = f"/{random.randint(10 ** 6, 10 ** 7 - 1)}/ctfscan-none"
                r = http_request(u.rstrip("/") + marker, timeout=timeout, settings=ctx.settings)
                soft404[u] = (r or {}).get("length") if (r or {}).get("length") else -1
            return soft404[u]

        def _hit(item):
            if ctx.stopped():
                return None
            u, p = item
            base = _baseline(u)
            url = u.rstrip("/") + "/" + p.lstrip("/")
            r = http_request(url, timeout=timeout, settings=ctx.settings)
            if not r:
                return None
            st = r.get("status")
            if st not in (200, 301, 302, 403):
                return None
            # 软 404 过滤：与随机路径基线长度几乎一致视为不存在
            if st == 200 and base >= 0 and abs((r.get("length") or 0) - base) < 8:
                return None
            return {"site_url": u, "path": url, "status": st,
                    "length": r.get("length"), "method": "GET", "note": "builtin"}

        return pool_run(_hit, [(u, p) for u in sites for p in dic], workers=workers)
