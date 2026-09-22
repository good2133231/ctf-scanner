"""阶段：目录/路径发现。

工具适配器：dirmap（`python dirmap.py -iF <urls> -e all`），解析其 `output/<域名>/*.txt` 产物
内置兜底：requests/urllib 字典扫描 + **多样本软 404 基线**（借鉴 dirmap 的 auto_check_404）。

阶段总开关 `dirscan.enabled`（**默认关** —— 目录爆破请求量最大、噪声最多，
且绝大多数 CTF 拿分不靠它；要用请在「策略配置 → 资产面拓展」打开）：关闭后整阶段跳过。

两个"别浪费预算"的约束（用户要求，与站点资产的折叠口径一致）：
- **只对不重复站点扫描**：同一任务内「标题 + 响应长度」完全相同的站点是同一台主机的别名/泛解析
  产物，对它们各扫一遍大字典纯属浪费；
- **重复长度的目录结果默认不显示**（`/dirs` 页），`?all=1` 才放开 —— 一个站点下几百条
  同样长度的 `200` 基本都是同一个软 404 模板，列出来只会淹没真信号。
"""
import hashlib
import random
import re
import time

from .base import Stage
from .. import db
from ..config import resolve
from ..utils import read_lines, write_lines, pool_run, http_request, pick_python, run_cmd

URL_RE = re.compile(r"https?://[^\s'\"<>()]+")
# dirmap 的产出格式：[状态码][content-type][大小] URL（大小形如 `1.23kb` / `512.00b`）
DIRMAP_RE = re.compile(r"^\s*\[(\d{3})\]\s*\[([^\]]*)\]\s*\[([^\]]*)\]\s*(\S+)\s*$")
SIZE_RE = re.compile(r"^\s*([\d.]+)\s*([tgmkb])?b?\s*$", re.I)
_UNITS = {"": 1, "b": 1, "k": 1024, "m": 1024 ** 2, "g": 1024 ** 3, "t": 1024 ** 4}

# dirmap 自己已经把"重复长度"的 200 单独写到 `重复长度.txt`，我们不读它（默认不展示重复）
DIRMAP_KEEP = ("res.txt", "403.txt")


def _size_to_int(text):
    """把 dirmap 的 `1.23kb` / `512.00b` 转回字节数；解析不了返回 None。"""
    m = SIZE_RE.match(str(text or ""))
    if not m:
        return None
    try:
        return int(float(m.group(1)) * _UNITS.get((m.group(2) or "").lower(), 1))
    except (TypeError, ValueError):
        return None


class DirscanStage(Stage):
    name = "dirscan"
    description = "目录/路径爆破（dirmap 或内置字典扫描）"

    def run(self):
        ctx = self.ctx
        cfg = ctx.settings.get("dirscan", {}) or {}
        if cfg.get("enabled") is not True:
            ctx.logger.info("[dirscan] 未启用（策略配置 → 资产面拓展 可打开），跳过")
            return
        limits = ctx.settings.get("limits", {})
        sites = self._dedup_sites(ctx.results.get("sites", []))
        sites = sites[: int(limits.get("dirscan_max_urls", 20))]
        if not sites:
            ctx.logger.info("[dirscan] 无存活站点，跳过")
            return
        if ctx.stopped():
            ctx.logger.warning("[dirscan] 任务已请求停止，跳过")
            return

        entries = []
        used_dirmap = False
        tool = ctx.settings.get("tools", {}).get("dirmap", {}) or {}
        script = resolve(tool.get("script") or "tools/dirmap/dirmap.py")
        if script.exists() and not ctx.options.get("offline"):
            ctx.logger.info(f"[dirscan] dirmap 处理 {len(sites)} 个站点 …")
            entries = self._run_dirmap(script, [s["url"] for s in sites], tool)
            used_dirmap = bool(entries)
            if used_dirmap:
                ctx.logger.info(f"[dirscan] dirmap 输出 {len(entries)} 条")
            else:
                ctx.logger.warning("[dirscan] dirmap 未解析到结果，回退内置扫描")
        else:
            ctx.logger.info("[dirscan] dirmap 不可用（或 --offline），使用内置字典扫描")

        if not used_dirmap:
            entries = self._builtin_scan(sites, cfg, limits)

        uniq, seen = [], set()
        for e in entries:
            key = (e.get("path"), e.get("status"))
            if key in seen:
                continue
            seen.add(key)
            uniq.append(e)
        ctx.results["dirs"] = uniq
        write_lines(ctx.workdir / "dirs.txt",
                    [f"{d.get('status', '')} {d.get('length') or '-'} {d.get('path', '')}"
                     for d in uniq])
        db.insert_dirs(ctx.task_id, uniq)
        ctx.logger.info(f"[dirscan] 目录发现 {len(uniq)} 条")

    # ---------- 目标筛选 ----------

    @staticmethod
    def _dedup_sites(sites):
        """只对"不重复"的站点做目录扫描：同一任务内 标题+长度 相同的只留首个。

        （与 `/sites` 页的折叠口径完全一致 —— 那些重复项是同一虚拟主机的别名，
        对它们各跑一遍大字典不会得到任何新东西。）
        """
        kept, seen = [], set()
        for s in sites or []:
            title = (s.get("title") or "").strip()
            key = (title, s.get("length")) if title else None
            if key and key in seen:
                continue
            if key:
                seen.add(key)
            kept.append(s)
        return kept

    # ---------- 字典 ----------

    def _dict_path(self, cfg):
        dicts = self.ctx.settings.get("dicts", {}) or {}
        key = "dirs_big" if cfg.get("big_dict") is not False else "dirs"
        return dicts.get(key) or dicts.get("dirs") or ""

    # ---------- dirmap 适配 ----------

    def _run_dirmap(self, script, urls, tool):
        """调用 dirmap 并解析产出。

        两个坑（都是实测踩过的）：
        - dirmap 把结果写进 `output/<域名>/` **子目录**（`res.txt` / `403.txt` / `404.txt` /
          `重复长度.txt` …），不再是早年的 `output/<域名>.txt`，所以必须递归找文件；
        - `output/` 是**持久目录**，直接"取最新 N 个文件"会读到上一次运行的残留 ——
          这里记录启动时间，只解析**本次运行之后**被写过的文件。
        """
        ctx = self.ctx
        in_file = write_lines(ctx.workdir / "dirmap_in.txt", urls)
        started = time.time() - 1.0     # 留 1 秒余量，避免文件系统时间戳精度问题漏掉本次产物
        argv = [pick_python(tool.get("python", "python")), str(script),
                "-iF", str(in_file), "-e", "all", "-t",
                str(int(tool.get("threads", 30) or 30))]
        rc, out, err = run_cmd(argv, cwd=script.parent, timeout=7200)
        if rc != 0 and err.strip():
            ctx.logger.info(f"[dirscan] dirmap rc={rc}：{err.strip()[:150]}")
        rows = []
        for f in self._outputs_since(script.parent / "output", started):
            rows.extend(self._parse_output(f))
        return rows

    @staticmethod
    def _outputs_since(out_dir, started, limit=200):
        if not out_dir.is_dir():
            return []
        found = []
        for f in out_dir.rglob("*.txt"):
            try:
                if f.stat().st_mtime >= started:
                    found.append(f)
            except OSError:
                continue
        found.sort(key=lambda f: f.stat().st_mtime, reverse=True)
        return found[:limit]

    @staticmethod
    def _parse_output(path):
        """解析 dirmap 的一行结果；读不懂的行跳过（宁可少报，不猜）。"""
        rows = []
        if path.name not in DIRMAP_KEEP:
            return rows
        try:
            lines = read_lines(path)
        except OSError:
            return rows
        for line in lines:
            m = DIRMAP_RE.match(line)
            if m:
                rows.append({"site_url": "", "path": m.group(4), "status": int(m.group(1)),
                             "length": _size_to_int(m.group(3)), "method": "GET",
                             "note": "dirmap"})
                continue
            urls = URL_RE.findall(line)
            if not urls:
                continue
            sm = re.match(r"^\s*[\[(]?(\d{3})[\])]?", line)
            rows.append({"site_url": "", "path": urls[0],
                         "status": int(sm.group(1)) if sm else None,
                         "length": None, "method": "GET", "note": "dirmap"})
        return rows

    # ---------- 内置兜底 ----------

    def _builtin_scan(self, sites, cfg, limits):
        ctx = self.ctx
        workers = int(limits.get("max_workers", 20))
        timeout = int(limits.get("http_timeout", 10))
        dic = [p for p in read_lines(resolve(self._dict_path(cfg)))
               if p and not p.startswith("#")]
        max_paths = int(cfg.get("max_paths", 400) or 400)
        if len(dic) > max_paths:      # 大字典有 1.5 万条，全量打一个站点要打到天亮
            dic = dic[:max_paths]
        if not dic or not sites:
            return []

        ctx.logger.info(f"[dirscan] 内置扫描：{len(sites)} 站点 x {len(dic)} 字典 …")
        baseline = {}

        def _baseline(u):
            """多样本软 404 基线（借鉴 dirmap 的 auto_check_404_page）。

            只用一个随机路径当基线时，碰上"随机路径也命中路由"的站点会误杀真实结果；
            取 3 个随机路径的 md5 与长度集合，命中其中任意一个即判为不存在。
            """
            if u not in baseline:
                md5s, sizes = set(), set()
                for _ in range(3):
                    marker = f"/{random.randint(10 ** 6, 10 ** 7 - 1)}/ctfscan-none"
                    r = http_request(u.rstrip("/") + marker, timeout=timeout,
                                     settings=ctx.settings)
                    if not r:
                        continue
                    md5s.add(hashlib.md5((r.get("text") or "").encode(
                        "utf-8", "replace")).hexdigest())
                    if r.get("length"):
                        sizes.add(int(r["length"]))
                baseline[u] = (md5s, sizes)
            return baseline[u]

        def _hit(item):
            if ctx.stopped():
                return None
            u, p = item
            md5s, sizes = _baseline(u)
            url = u.rstrip("/") + "/" + p.lstrip("/")
            r = http_request(url, timeout=timeout, settings=ctx.settings)
            if not r:
                return None
            st = r.get("status")
            if st not in (200, 301, 302, 403):
                return None
            # 软 404 过滤：与随机路径基线的 md5 或长度一致 → 视为"不存在"的模板页
            if st == 200:
                digest = hashlib.md5((r.get("text") or "").encode("utf-8", "replace")).hexdigest()
                if digest in md5s or (sizes and (r.get("length") or 0) in sizes):
                    return None
            return {"site_url": u, "path": url, "status": st,
                    "length": r.get("length"), "method": "GET", "note": "builtin"}

        return [e for e in pool_run(_hit, [(u, p) for u in (s["url"] for s in sites)
                                           for p in dic], workers=workers) if e]
