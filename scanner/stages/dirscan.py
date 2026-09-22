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
from urllib.parse import urlparse

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


# 技术栈标签 -> 语言桶。标签来自 probe 阶段 `fingerprint.identify()`（sites.tech），
# 以及 URL 后缀判定；判不出就是 ""（未知 → 全量字典）。
TECH_LANG = {
    # Java 系
    "jsp": "jsp", "java": "jsp", "tomcat": "jsp", "jetty": "jsp", "spring": "jsp",
    "struts": "jsp", "weblogic": "jsp", "jboss": "jsp", "resin": "jsp", "jenkins": "jsp",
    "glassfish": "jsp", "websphere": "jsp",
    # PHP 系
    "php": "php", "wordpress": "php", "thinkphp": "php", "laravel": "php",
    "dedecms": "php", "discuz": "php", "typecho": "php", "phpmyadmin": "php",
    "yii": "php", "codeigniter": "php", "symfony": "php",
    # ASP/.NET 系
    "asp": "asp", "aspnet": "asp", "aspx": "asp", "iis": "asp", "dotnet": "asp",
}
# URL 后缀 -> 语言桶（最直接的判据）
_EXT_LANG = {
    "php": "php", "php3": "php", "php4": "php", "php5": "php", "phtml": "php", "phps": "php",
    "jsp": "jsp", "jspx": "jsp", "jspf": "jsp", "do": "jsp", "action": "jsp", "jspa": "jsp",
    "asp": "asp", "aspx": "asp", "ashx": "asp", "asmx": "asp", "ascx": "asp",
}


def _dict_kind(tech, url=""):
    """判定站点的语言桶：`"jsp"` / `"php"` / `"asp"` / `""`（未知）。

    先看 URL 后缀（`/index.php` 这种最直接），再看指纹标签；都判不出返回 ""，
    调用方会用全量字典兜底 —— **不猜**，猜错等于把预算花在无关后缀上。
    """
    tail = str(url or "").rsplit("/", 1)[-1].split("?")[0].lower()
    if "." in tail:
        ext = tail.rsplit(".", 1)[-1]
        if ext in _EXT_LANG:
            return _EXT_LANG[ext]
    for tag in re.split(r"[,\s;|]+", str(tech or "").lower()):
        if tag in TECH_LANG:
            return TECH_LANG[tag]
    return ""


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
        # 站点来源：优先内存结果；为空时**回退数据库**（单独跑本阶段 / 进程重启后内存结果丢失）。
        # 注意 `db.list_sites()` 返回 sqlite3.Row（没有 `.get()`），必须转 dict 再用。
        sites = ctx.results.get("sites") or [dict(r) for r in db.list_sites(ctx.task_id)]
        sites = self._dedup_sites(sites)
        sites = sites[: int(limits.get("dirscan_max_urls", 20))]
        if not sites:
            ctx.logger.info("[dirscan] 无存活站点，跳过")
            return
        if ctx.stopped():
            ctx.logger.warning("[dirscan] 任务已请求停止，跳过")
            return

        tech_aware = cfg.get("tech_aware") is not False
        # 按技术栈把站点分组：Java 站只吃 jsp 字典、PHP 站只吃 php 字典……判不出的走全量
        groups = self._group_by_kind(sites, tech_aware)
        ctx.logger.info("[dirscan] 技术栈分组：" + " / ".join(
            f"{k or '未知'}={len(v)} 站点" for k, v in groups.items()))

        entries = []
        used_dirmap = False
        tool = ctx.settings.get("tools", {}).get("dirmap", {}) or {}
        script = resolve(tool.get("script") or "tools/dirmap/dirmap.py")
        if script.exists() and not ctx.options.get("offline"):
            ctx.logger.info(f"[dirscan] dirmap 处理 {len(sites)} 个站点 …")
            entries = self._run_dirmap(script, groups, tool)
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

    # ---------- 技术栈分组 / 字典选择 ----------

    @staticmethod
    def _group_by_kind(sites, tech_aware=True):
        """把站点按语言桶分组：`{kind: [site, ...]}`，kind ∈ "jsp"/"php"/"asp"/""（未知）。

        用户要求："如果确定是 java 就不要用 php asp，反之亦然" —— 一个站点只可能是其中一种
        技术栈（或都不是），把三种语言的后缀路径全打一遍纯属浪费 `max_paths` 的额度。
        判定依据（按可靠性排序）：
        1. **URL 自身的后缀**（`/index.php`、`/login.do`）—— 最直接；
        2. **`sites.tech` 指纹标签**（probe 阶段 `fingerprint.identify()` 写入，如 tomcat/php/aspnet）；
        3. 都判不出 → 未知，走全量字典（保守，不猜）。
        """
        groups = {}
        for s in sites or []:
            kind = _dict_kind(s.get("tech"), s.get("url")) if tech_aware else ""
            groups.setdefault(kind, []).append(s)
        return groups

    def _dict_paths_for(self, kind, cfg):
        """给出某语言桶要用的字典文件列表（**语言字典在前、通用字典在后**）。

        顺序很关键：`dirscan.max_paths` 是硬上限，语言专属条目排在前面才能保证
        "这个站是 Java 就一定会扫到 .jsp/.do 那些路径"，通用条目用来填满剩余额度。
        未知技术栈时回退全量字典（`dirs_big`，或配置里的 `dirs` 小字典）。
        """
        dicts = self.ctx.settings.get("dicts", {}) or {}
        if kind:
            return [p for p in (dicts.get(f"dirs_{kind}"), dicts.get("dirs_common")) if p]
        return [dicts.get("dirs_big") if cfg.get("big_dict") is not False else dicts.get("dirs")]

    def _load_paths(self, kind, cfg):
        """读字典（去注释、按 max_paths 截断），返回路径列表。"""
        max_paths = int(cfg.get("max_paths", 400) or 400)
        paths = []
        for rel in self._dict_paths_for(kind, cfg):
            paths.extend(p for p in read_lines(resolve(rel)) if p and not p.startswith("#"))
            if len(paths) >= max_paths:
                break
        return paths[:max_paths]

    def _dict_path(self, cfg):
        """（兼容旧调用）不区分技术栈时的单字典路径。"""
        dicts = self.ctx.settings.get("dicts", {}) or {}
        key = "dirs_big" if cfg.get("big_dict") is not False else "dirs"
        return dicts.get(key) or dicts.get("dirs") or ""

    # ---------- dirmap 适配 ----------

    def _run_dirmap(self, script, groups, tool):
        """**按技术栈分组**调用 dirmap，并解析产出。

        分组的意义（用户要求"确定是 java 就不要用 php asp"）：dirmap 自带按语言拆分的字典，
        `-e` 支持 `php` / `jsp` / `asp` / `d` / `big` / `all` —— 对每个分组各跑一次、
        各带对应的 `-e`，Java 站就不会被 PHP/ASP 的后缀浪费请求；未知栈的组用 `all`。

        三个坑（都是实测踩出来的）：
        - dirmap 把结果写进 `output/<域名>/` **子目录**（`res.txt` / `403.txt` / `404.txt` /
          `重复长度.txt` …），不再是早年的 `output/<域名>.txt`，所以要按目录找文件；
        - `output/` 是**持久目录**，直接"取最新 N 个文件"会读到上一次运行的残留；
        - 但**只按 mtime 过滤也不对**：dirmap 的 `saveResults()` 会跟文件里已有的行去重，
          所以"重扫同一个目标、结果和上次一样"时它**根本不写新内容**，文件 mtime 保持旧值 ——
          实测表现为"dirmap 跑了 37 秒却解析出 0 条、白白回退内置扫描"。
        因此这里改成**按目标定位**：dirmap 用 `netloc`（`:` 换成 `_`）当目录名，我们直接读
        `output/<我们扫过的主机>/*.txt`；再用 mtime 过滤兜底（目录命名变了也不会全丢），
        最后才回退内置扫描。
        """
        ctx = self.ctx
        py = pick_python(tool.get("python", "python"))
        threads = str(int(tool.get("threads", 30) or 30))
        started = time.time() - 1.0     # 留 1 秒余量，避免文件系统时间戳精度问题漏掉本次产物
        targets = set()
        for kind, sites in (groups or {}).items():
            urls = [s["url"] for s in sites if s.get("url")]
            if not urls:
                continue
            targets.update(u for u in (urlparse(x).netloc for x in urls) if u)
            e_arg = kind or "all"
            in_file = write_lines(ctx.workdir / f"dirmap_in_{kind or 'all'}.txt", urls)
            ctx.logger.info(f"[dirscan] dirmap：{len(urls)} 个站点（技术栈 {kind or '未知'}"
                            f" → -e {e_arg}）…")
            rc, _, err = run_cmd([py, str(script), "-iF", str(in_file),
                                  "-e", e_arg, "-t", threads],
                                 cwd=script.parent, timeout=7200)
            if rc != 0 and err.strip():
                ctx.logger.info(f"[dirscan] dirmap（-e {e_arg}）rc={rc}：{err.strip()[:150]}")

        out_dir = script.parent / "output"
        rows = []
        for d in self._target_dirs(out_dir, targets):
            for f in sorted(d.glob("*.txt")):
                rows.extend(self._parse_output(f))
        if not rows:      # 兜底：目录命名/层级变了，退回"本次运行写过的文件"
            for f in self._outputs_since(out_dir, started):
                rows.extend(self._parse_output(f))
        # 只保留确实属于我们扫过的主机的行（防读到别人的历史产物）
        if targets:
            rows = [r for r in rows if urlparse(r.get("path") or "").netloc in targets]
        return rows

    @staticmethod
    def _target_dirs(out_dir, targets):
        """dirmap 的产物目录名 = 目标 netloc 把 `:` 换成 `_`（如 `127.0.0.1_8765`）。"""
        if not out_dir.is_dir():
            return []
        found = []
        for netloc in targets:
            d = out_dir / netloc.replace(":", "_")
            if d.is_dir():
                found.append(d)
        return found

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
        """内置字典扫描（按站点技术栈选字典）。

        每个站点用**它自己的**字典：Java 站 = `dirs_jsp` + `dirs_common`，
        PHP 站 = `dirs_php` + `dirs_common`，未知栈 = `dirs_big`（全部），
        都受 `dirscan.max_paths` 截断。这样同一个任务里混合栈的站点也各扫各的，
        不会互相浪费额度。
        """
        ctx = self.ctx
        workers = int(limits.get("max_workers", 20))
        timeout = int(limits.get("http_timeout", 10))
        tech_aware = cfg.get("tech_aware") is not False

        jobs, tally = [], {}
        for s in sites:
            kind = _dict_kind(s.get("tech"), s.get("url")) if tech_aware else ""
            paths = self._load_paths(kind, cfg)
            if not paths:
                continue
            tally[kind or "未知"] = tally.get(kind or "未知", 0) + 1
            jobs.extend((s["url"], p) for p in paths)
        if not jobs:
            return []

        ctx.logger.info(f"[dirscan] 内置扫描：{len(sites)} 站点 x 按栈选字典 "
                        f"（{' / '.join(f'{k}:{v} 站' for k, v in tally.items())}），"
                        f"共 {len(jobs)} 个请求 …")
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

        return [e for e in pool_run(_hit, jobs, workers=workers) if e]
