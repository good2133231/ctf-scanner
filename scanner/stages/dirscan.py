"""阶段：目录/路径发现。

工具适配器：dirmap（`python dirmap.py -iF <urls> -e all`），解析其 `output/<域名>/*.txt` 产物
内置兜底：requests/urllib 字典扫描 + **多样本软 404 基线**（借鉴 dirmap 的 auto_check_404）。

阶段总开关 `dirscan.enabled`（**默认开，但默认只跑浅扫**）：用户要求"先浅浅过一遍，看清结果后
再手动决定要不要深度扫"，所以默认档位是 `mode=quick` —— 只打 `config/dicts/dirs_shallow.txt`
这份精选敏感路径（约 150 条/站，按价值排序），请求量与噪声都可控。
深度扫（`mode=deep`）才走全量分层字典 + dirmap + 后缀派生；它有三个入口：
① 策略配置把 `dirscan.mode` 改成 `deep`（全局）；② 建任务时勾「全目录」（任务级选项
`dirscan_full`）；③ 结果页对选定站点发起「深度目录补扫」（同样落 `dirscan_full` 的新任务）。

**目录递归**（`dirscan.recursive_depth`，续30，**默认 0 = 关**）：深扫时对**目录型命中**
（`/admin`、`/api/v1` —— 最后一段不含 `.` 且不以 `.` 开头）再往下打层，字典用浅扫精选那份
（`dirs_shallow`）截断到 `recursive_max_paths`。它是**三重闸**限流：层数 `recursive_depth`、
每站跨层累计目录数 `recursive_max_dirs`、每目录路径数 `recursive_max_paths`。
限"目录数"不能省 —— 单站浅扫约 153 请求，一层递归 = `+K×(3 软404基线 + M)`，
K=5/M=40 时 +215 请求**比第一轮还多**，而 K 由"扫出多少个目录"决定、不受字典大小控制。
刻意**不从 `tools/dirmap/dirmap.conf` 打开 dirmap 自带的递归**（`conf.recursive_scan`
当前为 0，保持不动）。**2026-09-25 续44 复核源码后的更正**：`recursiveScan()`（`bruter.py`）
**没有任何生效的调用点** —— 唯一的引用那段早已被整块注释掉，`conf.recursive_scan` 现在只影响
两句控制台文案与进度条长度。原注释写的「触发条件只有 `[301,403]`、深度靠
`recursive_scan_max_url_length=60` 兜底」是**这段死代码的描述、不是可用行为**；
结论不变（递归一律走本阶段自己的三重闸，额度才可预测），理由据此改写。

字典分层（越具体的排越前，`max_paths` 截断时先保住高价值路径）：
**框架字典**（`dirs_<框架>.txt`，`tools/import_fw_dicts.py` 从全量字典派生，凭 `sites.tech` 指纹命中）
→ **语言字典**（`dirs_jsp` / `dirs_php` / `dirs_asp`）→ **通用暴露面**（`dirs_exposure`：
`.git` / `.env` / 备份文件）→ **通用字典**（`dirs_common`）。判不出语言栈的站点直接用全量字典
（`dirs_big` 本身就是超集，不再叠加前几层）。
为什么再拆一层框架：`dirs_common` 有上万条，400 条的额度根本轮不到 `wp-login.php` / `/actuator/env`
这类真正决定 CTF 拿分的路径 —— 按框架单独成文件、排最前，才能保证"是 WordPress 就先扫 wp-*"。
dirmap 的 `-e` 只认 `php/jsp/asp/d/big/all`，**吃不下自定义字典**，所以框架层只在**内置扫描**生效；
但 dirmap 跑出结果后仍会补一轮"框架 + 暴露面"的小扫描（`dirscan.fw_max_paths`，默认 150，
置 0 关闭），否则用户机器上装了 dirmap 时框架字典就等于死代码。

两个"别浪费预算"的约束（用户要求，与站点资产的折叠口径一致）：
- **只对不重复站点扫描**：同一任务内「标题 + 响应长度」完全相同的站点是同一台主机的别名/泛解析
  产物，对它们各扫一遍大字典纯属浪费；
- **重复长度的目录结果默认不显示**（`/dirs` 页），`?all=1` 才放开 —— 一个站点下几百条
  同样长度的 `200` 基本都是同一个软 404 模板，列出来只会淹没真信号。
"""
import hashlib
import random
import re
import threading
import time
from urllib.parse import urlparse

from .base import Stage
from .probe import TITLE_RE      # 命中页的 <title> 提取（与 probe 同一套正则，避免两处定义漂移）
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


# 框架桶 -> 命中它的指纹标签（标签来自 probe 阶段 `fingerprint.identify()`，写在 `sites.tech`）。
# 桶名即 `config/dicts/dirs_<桶名>.txt` 的文件名后缀，两处必须一一对应。
FRAMEWORK_TAGS = {
    "wordpress": "wordpress", "wp": "wordpress",
    "phpmyadmin": "phpmyadmin",
    "druid": "druid",
    "spring": "spring", "springboot": "spring",
    "weblogic": "weblogic",
    "tomcat": "tomcat",
    "jenkins": "jenkins",
    "elasticsearch": "elastic",
    "swagger": "swagger", "fastapi": "swagger",
    "confluence": "confluence",
    "gitlab": "gitlab",
}
# 一个站点同时命中多个框架标签时，按这个顺序取**第一个**（越前越"抢占先机"，
# 也就是越值得优先扫）。顺序与 `tools/import_fw_dicts.py` 的 BUCKETS 保持一致。
FRAMEWORK_ORDER = ("wordpress", "phpmyadmin", "druid", "spring", "weblogic", "tomcat",
                   "jenkins", "elastic", "swagger", "confluence", "gitlab")

# URL 兜底判据：指纹抓的是首页，而框架可能只暴露在某个路径上（`/wp-content/`、`/actuator/`…）。
_FW_URL_HINTS = (
    (re.compile(r"(?i)/wp-(?:content|includes|admin|login|json)"), "wordpress"),
    (re.compile(r"(?i)/phpmyadmin|/pma(?:/|$)"), "phpmyadmin"),
    (re.compile(r"(?i)/druid(?:/|$)"), "druid"),
    (re.compile(r"(?i)/actuator(?:/|$)"), "spring"),
    (re.compile(r"(?i)/swagger|/api-docs|/openapi"), "swagger"),
    (re.compile(r"(?i)/confluence(?:/|$)"), "confluence"),
    (re.compile(r"(?i)/gitlab(?:/|$)|/users/sign_in"), "gitlab"),
)


def _framework_of(tech, url=""):
    """判定站点的框架桶：`"wordpress"` / `"spring"` / … / `""`（判不出）。

    先看指纹标签（probe 阶段写进 `sites.tech`），多命中时按 `FRAMEWORK_ORDER` 取最优先的一个；
    再看 URL 里的特征路径兜底。都判不出返回 ""，调用方会跳过框架层 —— **不猜**。
    """
    tags = {t for t in re.split(r"[,\s;|]+", str(tech or "").lower()) if t}
    hits = {FRAMEWORK_TAGS[t] for t in tags if t in FRAMEWORK_TAGS}
    for fw in FRAMEWORK_ORDER:
        if fw in hits:
            return fw
    low = str(url or "").lower()
    for rx, fw in _FW_URL_HINTS:
        if rx.search(low):
            return fw
    return ""


# 内置扫描的字典层次组合（越具体的排越前）。
# `_FW_LAYERS` 专给"框架补充扫描"用：dirmap 跑完后只补「框架 + 暴露面」两层，
# 不再重复吃语言/通用字典（那些 dirmap 自己已经按 `-e` 打过了）。
# `shallow` 是**深扫的兜底层**：深扫必须是浅扫的超集，否则"花更多请求却扫得更少"。
# 实测（同一靶场）：浅扫 150 条命中 `.env` + `.git/config`，深扫 400 条只命中 `.git` ——
# 技术栈未知时语言层是 `dirs_big`（11882 条、未排序），会一口气把 `max_paths` 吃光，
# 而这两条在 big 里排在第 560 / 1919 位，永远够不着。
# 位置是**随技术栈变**的（见 `_layer_paths`）：已知栈时排在语言层之后，保住
# "语言专属路径优先占额度"这条既有不变量；未知栈时提到语言层之前。
_FULL_LAYERS = ("fw", "lang", "shallow", "exposure", "common")
_FW_LAYERS = ("fw", "exposure")
# `_SHALLOW_LAYERS` 专给"浅扫"（mode=quick）用：**只吃精选敏感路径字典**，
# 不碰框架/语言/通用层，也不跑 dirmap —— 浅扫的意义就是"快而少"。
_SHALLOW_LAYERS = ("shallow",)

# 后缀派生（深扫专用，借鉴 dirmap 的备份文件扩展）：只对命中的**文件名型**路径生效。
_SUFFIXES = (".bak", ".zip", ".tar.gz", ".rar", ".old", "~", ".swp", ".copy", ".save", ".txt")


def _size_to_int(text):
    """把 dirmap 的 `1.23kb` / `512.00b` 转回字节数；解析不了返回 None。"""
    m = SIZE_RE.match(str(text or ""))
    if not m:
        return None
    try:
        return int(float(m.group(1)) * _UNITS.get((m.group(2) or "").lower(), 1))
    except (TypeError, ValueError):
        return None


def _origin_of(url):
    """从一条完整 URL 反推**站点入口** `scheme://netloc/`；反推不出返回空串（不猜）。

    dirmap 的解析行只有完整 URL（`path` 存的就是它），没有独立的站点字段 —— 早先这里
    一律写空串，直接造成两处缺陷（续24 修）：

    ① **目录折叠判错站点**：`gui/app.py::_fold_dirs` 的折叠键是
       `(site_url, 状态码, 大小)`。dirmap 行的 site_url 全是空串，于是
       a) 与同站点的内置行（site_url 是真 URL）**永远折不到一起** —— 表现为"同站点同样大小
          的重复没被过滤"；
       b) 更糟：**不同站点**的 dirmap 行因为 site_url 都等于 `""`，只要 (状态码, 大小) 相同
          就被误折成一条 —— `/dirs` 是跨任务视图，这等于**真丢结果**。
    ② **启发式分组被污染**：`scanner/heuristics.py` 的软 404（`_soft404`）与目录离群
       （`_dir_outlier`）都按 `site_url` 分组，dirmap 行全被并进 `"-"` 一组，判据失去意义。

    之所以修在**写入侧**而不是展示侧兜底：`site_url` 是这条目录结果的**数据身份**，
    库里的 `dirs.site_url`、跨运行去重键 `("site_url", "path")`、启发式分组都在消费它；
    只在展示侧临时推算等于让库里的数据继续错。
    """
    p = urlparse(str(url or ""))
    if p.scheme not in ("http", "https") or not p.netloc:
        return ""
    return f"{p.scheme}://{p.netloc}/"


class DirscanStage(Stage):
    name = "dirscan"
    description = "目录/路径爆破（dirmap 或内置字典扫描）"

    def run(self):
        ctx = self.ctx
        cfg = ctx.settings.get("dirscan", {}) or {}
        # 任务选项 `dirscan_full`（建任务勾「全目录」/结果页发起「深度目录补扫」）视为显式授权：
        # 即使全局 `dirscan.enabled` 关着，这种"用户点名要扫"的任务也要跑 —— 与 portscan 一致。
        forced = ctx.options.get("dirscan_full") is True
        if cfg.get("enabled") is not True and not forced:
            ctx.logger.info("[dirscan] 未启用（策略配置 → 资产面拓展 可打开），跳过")
            return
        limits = ctx.settings.get("limits", {})
        # 站点来源：优先内存结果；为空时**回退数据库**（单独跑本阶段 / 进程重启后内存结果丢失）。
        # 注意 `db.list_sites()` 返回 sqlite3.Row（没有 `.get()`），必须转 dict 再用。
        sites = ctx.results.get("sites") or [dict(r) for r in db.list_sites(ctx.task_id)]
        if not sites:
            # 只跑本阶段的补扫任务没有 probe 产物（内存与库里都没有站点），用目标本身兜底
            sites = self._sites_from_targets(ctx)
        sites = self._dedup_sites(sites)
        sites = ctx.scope_sites(sites)          # 续25：追加执行时限定到本次勾选（非追加原样）
        sites = sites[: int(limits.get("dirscan_max_urls", 20))]
        if not sites:
            ctx.logger.info("[dirscan] 无存活站点，跳过")
            return
        if ctx.stopped():
            ctx.logger.warning("[dirscan] 任务已请求停止，跳过")
            return

        tech_aware = cfg.get("tech_aware") is not False
        # 档位：浅扫（quick，默认）只打精选敏感路径；深扫（deep）走全量字典 + dirmap。
        # 任务级选项 `dirscan_full`（建任务勾「全目录」/结果页发起「补扫」）可把**单个任务**
        # 强制成深扫，不改全局策略 —— 与 portscan 的 `portscan_full` 同一套语义。
        deep = (forced or str(cfg.get("mode") or "quick").strip().lower() == "deep")
        # 按技术栈把站点分组：Java 站只吃 jsp 字典、PHP 站只吃 php 字典……判不出的走全量
        groups = self._group_by_kind(sites, tech_aware)
        ctx.logger.info(f"[dirscan] {'深扫' if deep else '浅扫'}模式；技术栈分组：" + " / ".join(
            f"{k or '未知'}={len(v)} 站点" for k, v in groups.items()))

        entries = []
        used_dirmap = False
        tool = ctx.settings.get("tools", {}).get("dirmap", {}) or {}
        script = resolve(tool.get("script") or "tools/dirmap/dirmap.py")
        if not deep:
            # 浅扫：不跑 dirmap（那是深扫的重武器），只用精选敏感路径字典
            ctx.logger.info(f"[dirscan] 浅扫：仅打敏感路径精选字典（上限 "
                            f"{int(cfg.get('quick_max_paths', 150) or 0)} 条/站）")
            entries = self._builtin_scan(sites, cfg, limits, shallow=True)
        elif script.exists() and not ctx.options.get("offline"):
            ctx.logger.info(f"[dirscan] dirmap 处理 {len(sites)} 个站点 …")
            entries = self._run_dirmap(script, groups, tool)
            used_dirmap = bool(entries)
            if used_dirmap:
                ctx.logger.info(f"[dirscan] dirmap 输出 {len(entries)} 条")
            else:
                ctx.logger.warning("[dirscan] dirmap 未解析到结果，回退内置扫描")
        else:
            ctx.logger.info("[dirscan] dirmap 不可用（或 --offline），使用内置字典扫描")

        # 浅扫结果在上面已经拿到，不再叠加任何字典（那是深扫的事）
        if deep and not used_dirmap:
            entries = self._builtin_scan(sites, cfg, limits)
        elif deep:
            # dirmap 的 `-e` 只认 php/jsp/asp/d/big/all，**吃不下我们的框架字典**
            # （`dirs_wordpress` / `dirs_exposure` 这些自定义文件喂不进去）。装了 dirmap 的
            # 机器上框架层会变成死代码，所以这里补一轮"框架 + 暴露面"的小扫描。
            extra = self._builtin_scan(sites, cfg, limits, only_fw=True)
            if extra:
                ctx.logger.info(f"[dirscan] 框架补充扫描新增 {len(extra)} 条")
                entries.extend(extra)

        # 目录递归（续30，**默认关**）：策略级 `recursive_depth>0` 才生效；但建任务勾了
        # 「目录递归」时落成任务级选项 `recursive_dir` —— 那种情况下**即使策略是关的**也要
        # 为本次开启（与 `screenshot_on` / `cert_on` 同一套"只本次生效、不改全局策略"语义，
        # 否则用户勾了却没反应）。勾了就至少一层，策略里填了更大的值就按策略走。
        rec_cfg = cfg
        if ctx.options.get("recursive_dir") is True:
            rec_cfg = dict(cfg)
            rec_cfg["recursive_depth"] = max(1, int(cfg.get("recursive_depth", 0) or 0))

        # 目录递归（续30）：对上面两种产物**一视同仁** —— 装了 dirmap 的机器走的是 `only_fw`
        # 那条分支，所以不能挂进 `_builtin_scan` 内部，否则"有 dirmap 的机器反而没有递归"
        # （离网 CTF 现场才是常态）。
        if deep and entries:
            entries.extend(self._recursive_scan(sites, entries, rec_cfg, limits))

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
        # 跨运行去重（续25）：追加执行时同一 (站点, 路径) 不再重复入库
        new_dirs = db.drop_existing(ctx.task_id, "dirs", ("site_url", "path"), uniq,
                                    lambda e: (e.get("site_url"), e.get("path")))
        db.insert_dirs(ctx.task_id, new_dirs)
        _dup = len(uniq) - len(new_dirs)
        ctx.logger.info(f"[dirscan] 目录发现 {len(uniq)} 条"
                        + (f"（跨运行去重跳过 {_dup} 条已入库）" if _dup else ""))

    # ---------- 目标筛选 ----------

    @staticmethod
    def _sites_from_targets(ctx):
        """从任务目标直接搭出"站点"列表 —— **只跑 dirscan 的补扫任务**用。

        正常任务里 sites 由 probe 阶段产出；但结果页发起的「深度目录补扫」是只跑本阶段的
        任务（不重跑 probe，省一遍请求），内存结果与库里都没有站点。这里用目标本身兜底：
        URL 原样用；域名 / IP 补 `http://` 前缀（猜协议，成功率不如 probe 出来的真实 URL，
        但比直接"无存活站点，跳过"强得多）。
        """
        out, seen = [], set()
        for kind, raw in ctx.targets or []:
            if kind == "url":
                url = raw
            elif kind in ("domain", "ip"):
                url = "http://" + raw
            else:
                continue
            if url in seen:
                continue
            seen.add(url)
            out.append({"url": url, "tech": "", "title": "", "length": None})
        if out:
            ctx.logger.info(f"[dirscan] 目标直用兜底：{len(out)} 个 URL（无 probe 产物的补扫任务）")
        return out

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

    def _dict_paths_for(self, kind, cfg, fw=""):
        """给出某站点要用的字典文件列表（**越具体的排越前**）。

        顺序很关键：`dirscan.max_paths` 是硬上限，专属条目排在前面才能保证
        "这个站是 Java 就一定会扫到 .jsp/.do 那些路径"。完整层次：
        框架字典 → 语言字典 → 通用暴露面 → 通用字典。
        未知技术栈时语言层回退全量字典（`dirs_big`，或配置里的 `dirs` 小字典）。
        """
        return self._layer_paths(kind, cfg, fw, _FULL_LAYERS)

    def _layer_paths(self, kind, cfg, fw, layers):
        """按 `layers` 挑出要用哪些层的字典文件（返回相对路径列表）。

        单独抽出来是为了"框架补充扫描"能复用同一套取词逻辑：那种场景只要
        `_FW_LAYERS = ("fw", "exposure")` 两层，不吃语言/通用字典。
        """
        dicts = self.ctx.settings.get("dicts", {}) or {}
        # **未知技术栈**时把精选层提到语言层之前：那一档的语言字典是 `dirs_big`
        # （11882 条、未排序），`max_paths` 截断后拿到的是"字母序的运气"，实测会漏掉
        # 浅扫能命中的 `.env` / `.git/config`（它们在 big 里排 560 / 1919）。
        # 已知技术栈时语言字典很小（jsp 116 / php 933），保持"语言专属路径优先"不动。
        if "shallow" in layers and "lang" in layers and not kind:
            layers = ("shallow",) + tuple(x for x in layers if x != "shallow")
        # **按 `layers` 的给定顺序**取词（不能写成"几个独立 if 依次 append"：
        # 那样 `shallow` 永远排在语言层之前，上面那段"未知栈才提前"的调整就成了空操作，
        # 已知栈的站点会先被精选层吃掉额度，语言专属路径反而排到后面去）。
        out = []
        for name in layers:
            if name == "shallow":
                out.append(dicts.get("dirs_shallow"))
            elif name == "fw":
                if fw:
                    out.append(dicts.get(f"dirs_{fw}"))
            elif name == "lang":
                if kind:
                    out.append(dicts.get(f"dirs_{kind}"))
                else:
                    out.append(dicts.get("dirs_big") if cfg.get("big_dict") is not False
                               else dicts.get("dirs"))
            elif name == "exposure":
                out.append(dicts.get("dirs_exposure"))
            elif name == "common" and kind:
                out.append(dicts.get("dirs_common"))
        return [p for p in out if p]

    def _load_paths(self, kind, cfg, fw="", layers=_FULL_LAYERS, limit=None):
        """读字典（去注释、保序去重、截断到上限），返回路径列表。

        `limit` 给了就用它当上限（框架补充扫描用 `dirscan.fw_max_paths`），
        否则用 `dirscan.max_paths`。多个字典文件之间可能有重复条目（框架字典就是
        从全量字典里抽出来的），去重后额度才不会被重复项吃掉。
        """
        max_paths = int(limit if limit is not None else (cfg.get("max_paths", 400) or 400))
        paths, seen = [], set()
        for rel in self._layer_paths(kind, cfg, fw, layers):
            for p in read_lines(resolve(rel)):
                if not p or p.startswith("#") or p in seen:
                    continue
                seen.add(p)
                paths.append(p)
                if len(paths) >= max_paths:
                    return paths
        return paths

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
        th = ctx.throttle        # F2 统一门控：本任务的限流器（可能是 None）
        py = pick_python(tool.get("python", "python"))
        threads = str(int(tool.get("threads", 30) or 30))
        started = time.time() - 1.0     # 留 1 秒余量，避免文件系统时间戳精度问题漏掉本次产物
        targets = set()
        for kind, sites in (groups or {}).items():
            if ctx.stopped():
                ctx.logger.warning("[dirscan] 任务已请求停止，中止 dirmap 扫描")
                break
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
                                 cwd=script.parent, timeout=7200, throttle=th)
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
                rows.append({"site_url": _origin_of(m.group(4)), "path": m.group(4),
                             "status": int(m.group(1)),
                             "length": _size_to_int(m.group(3)), "method": "GET",
                             "note": "dirmap"})
                continue
            urls = URL_RE.findall(line)
            if not urls:
                continue
            sm = re.match(r"^\s*[\[(]?(\d{3})[\])]?", line)
            rows.append({"site_url": _origin_of(urls[0]), "path": urls[0],
                         "status": int(sm.group(1)) if sm else None,
                         "length": None, "method": "GET", "note": "dirmap"})
        return rows

    # ---------- 内置兜底 ----------

    def _builtin_scan(self, sites, cfg, limits, only_fw=False, shallow=False):
        """内置字典扫描（按站点技术栈 + 框架选字典）。

        每个站点用**它自己的**字典，越具体的排越前：框架字典（`dirs_wordpress`…）
        → 语言字典（`dirs_jsp` / `dirs_php` / `dirs_asp`）→ 暴露面（`dirs_exposure`）
        → 通用（`dirs_common`），未知栈 = `dirs_big`（本身是超集，不再叠加）。
        都受 `dirscan.max_paths` 截断。这样同一个任务里混合栈的站点也各扫各的，
        不会互相浪费额度。

        `only_fw=True` 是"框架补充扫描"模式：dirmap 已经按 `-e` 打过语言/通用字典了，
        这里只用「框架 + 暴露面」两层、每个站点最多 `dirscan.fw_max_paths` 条
        （默认 150，置 0 表示不做补充扫描），把 dirmap 吃不到的自定义字典补上。

        `shallow=True` 是"浅扫"模式（`dirscan.mode=quick`，默认）：**只吃
        `dirs_shallow` 一份精选敏感路径字典**，上限 `dirscan.quick_max_paths`，
        与框架/语言/大字典完全无关，也不做后缀派生。
        """
        ctx = self.ctx
        workers = int(limits.get("max_workers", 20))
        timeout = int(limits.get("http_timeout", 10))
        tech_aware = cfg.get("tech_aware") is not False
        fw_cap = int(cfg.get("fw_max_paths", 150) or 0)
        if shallow:
            layers = _SHALLOW_LAYERS
            limit = int(cfg.get("quick_max_paths", 150) or 0)
            if limit <= 0:
                ctx.logger.warning("[dirscan] 浅扫额度 quick_max_paths<=0，跳过")
                return []
        elif only_fw:
            if fw_cap <= 0:
                return []
            layers, limit = _FW_LAYERS, fw_cap
        else:
            layers, limit = _FULL_LAYERS, None

        jobs, tally = [], {}
        for s in sites:
            kind = _dict_kind(s.get("tech"), s.get("url")) if tech_aware else ""
            fw = _framework_of(s.get("tech"), s.get("url")) if tech_aware else ""
            if only_fw and not fw:
                continue          # 补充扫描只针对判得出框架的站点
            paths = self._load_paths(kind, cfg, fw=fw, layers=layers, limit=limit)
            if not paths:
                continue
            label = f"{fw}/{kind}" if fw else (kind or "未知")
            tally[label] = tally.get(label, 0) + 1
            jobs.extend((s["url"], p, s["url"]) for p in paths)
        if not jobs:
            if only_fw:
                ctx.logger.info("[dirscan] 无可识别的框架站点，跳过框架补充扫描")
            return []

        ctx.logger.info(f"[dirscan] 内置扫描：{len(sites)} 站点 x "
                        f"{'敏感路径精选' if shallow else ('框架+暴露面' if only_fw else '栈+框架')}"
                        f"选字典{'（浅扫）' if shallow else ('（框架补充）' if only_fw else '')}"
                        f"（{' / '.join(f'{k}:{v} 站' for k, v in tally.items())}），"
                        f"共 {len(jobs)} 个请求 …")
        entries = self._scan(jobs, limits)

        # 后缀派生（深扫专用，借鉴 dirmap 的备份文件扩展）：第一轮命中的**文件名型**路径
        # 再派生 `.bak/.zip/.old/…` 变体补一轮。浅扫与框架补充扫描都不做（省请求）。
        if entries and not shallow and not only_fw and cfg.get("suffix_aware") is not False:
            cap = int(cfg.get("max_paths", 400) or 400)
            # `_suffix_jobs` 只回 `(站点根, 相对路径)`：派生轮的请求基址**就是站点根**
            # （备份文件与它在同一层），补成 `_scan` 要的三元组。
            extra_jobs = [(s, p, s) for s, p in self._suffix_jobs(entries, cap)]
            if extra_jobs and not ctx.stopped():
                ctx.logger.info(f"[dirscan] 后缀派生：对 {len(extra_jobs)} 个变体补扫 …")
                entries.extend(self._scan(extra_jobs, limits))
        return entries

    # ---------- 单轮扫描（软 404 基线 + 命中提取）----------

    def _scan(self, jobs, limits):
        """跑一轮扫描，返回命中条目。`jobs` 元素是 `(基址, 相对路径, 站点根)` 三元组。

        抽成独立方法是为了**目录递归能复用同一套请求语义**（续30）：递归那一轮同样要
        「按基址缓存的软 404 基线 + 标题提取 + 只收 200/301/302/403」。复制一份实现
        必然与这里漂移，而软 404 恰恰是本阶段最容易被改坏的地方（见 `_baseline` 注释）。

        **基址与站点根为什么分开**：递归时请求要打到子目录（`http://h/admin`），但入库的
        `site_url` 必须仍是**站点根** —— 它是这条目录结果的**数据身份**（见 `_origin_of`
        的注释：`dirs` 折叠、跨运行去重键、启发式分组都在消费它）。若把子目录写进去，
        「目录」页签会把一个站点按子目录拆成十几行，跨运行去重也会失效。
        """
        ctx = self.ctx
        workers = int(limits.get("max_workers", 20))
        timeout = int(limits.get("http_timeout", 10))
        baseline = {}
        baseline_lock = threading.Lock()

        def _baseline(u):
            """多样本软 404 基线（借鉴 dirmap 的 auto_check_404_page）。

            只用一个随机路径当基线时，碰上"随机路径也命中路由"的站点会误杀真实结果；
            取 3 个随机路径的 md5 与长度集合，命中其中任意一个即判为不存在。

            **每个基址只算一次**：本函数是被 `pool_run` 的 20 个线程并发调用的，
            原先的"惰性填字典"没有同步 —— 多线程同时 miss 就各算一遍，
            实测单站点 3 个基线请求膨胀成 27~36 个（占 dirscan 请求量约 18%）。
            这里用锁把「查缓存 + 计算 + 回填」整体串起来：首个线程真算，其余线程
            阻塞在锁上、拿到锁后直接命中缓存，于是请求数恒定 = 3 × 基址数。
            （不要把锁拆开成"锁内查、锁外算"——那样等于没锁。）

            `u` 既是缓存键也是请求基址：第一轮是站点根，目录递归轮是命中的子目录前缀，
            两者天然各算一份 —— 子目录常有**自己的**统一跳转页，复用站点根的基线会把
            子目录下的真实命中整片滤掉。
            """
            with baseline_lock:
                cached = baseline.get(u)
                if cached is not None:
                    return cached
                md5s, sizes = set(), set()
                for _ in range(3):
                    marker = f"/{random.randint(10 ** 6, 10 ** 7 - 1)}/ctfscan-none"
                    r = http_request(u.rstrip("/") + marker, timeout=timeout,
                                     settings=ctx.settings, auth=True)
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
            u, p, root = item
            md5s, sizes = _baseline(u)
            url = u.rstrip("/") + "/" + p.lstrip("/")
            r = http_request(url, timeout=timeout, settings=ctx.settings, auth=True)
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
            # 命中页的标题：响应体已经在手里（上面算 md5 用过），提取 <title> 是零额外请求。
            # 为什么值得存：路径命中后光看 `/backup.tar.gz 200 1818` 判断不了这是真备份包
            # 还是一个"统一跳转页"；标题能立刻分辨（用户 2026-09-23 明确要求）。
            t = TITLE_RE.search(r.get("text") or "")
            return {"site_url": root, "path": url, "status": st,
                    "length": r.get("length"), "method": "GET", "note": "builtin",
                    "title": (t.group(1).strip()[:200] if t else "")}

        return [e for e in pool_run(_hit, jobs, workers=workers) if e]

    @staticmethod
    def _suffix_jobs(entries, cap):
        """由第一轮命中结果派生"备份后缀"补扫任务（`(site_url, path)` 列表）。

        只处理**文件名型**路径（最后一段含 `.`，如 `config.php`、`.env`），
        目录型路径（`admin/`）不派生 —— 备份文件才有后缀，目录没有。
        去重后按 `cap` 截断，避免这一轮把请求量放大到失控。
        """
        if cap <= 0:
            return []
        jobs, seen = [], set()
        for e in entries:
            site = str(e.get("site_url") or "")
            full = str(e.get("path") or "")
            prefix = site.rstrip("/") + "/"
            if not site or not full.startswith(prefix):
                continue
            rel = full[len(prefix):]
            last = rel.rsplit("/", 1)[-1]
            if not rel or rel.endswith("/") or "." not in last:
                continue
            for suf in _SUFFIXES:
                cand = rel + suf
                if cand in seen:
                    continue
                seen.add(cand)
                jobs.append((site, cand))
                if len(jobs) >= cap:
                    return jobs
        return jobs

    # ---------- 目录递归（续30，默认关）----------

    @staticmethod
    def _dir_prefix(root, full, status):
        """命中条目是**目录型**时返回它的前缀 URL（可继续往下打），否则 `None`。

        判据（三条都是"往下拼路径有意义吗"这一件事）：
        - 状态码 ∈ `{200, 301, 302, 403}`，与 `_scan::_hit` 的收口一致。
          `403` 的目录值得递归（"看得见进不去"的目录里常放备份与配置）；
          `301/302` 是目录补斜杠（`/admin` → `/admin/`）的常见形态，不能一刀切掉；
          其余状态（404/500/401…）是"不存在或没权限"，递归没有意义。
        - `path` 在站点根之下、去掉 query/fragment 后**最后一段不含 `.`** ——
          `/admin`、`/api/v1` 是目录；`/config.php`、`/.env`、`/backup.zip` 是文件，
          在它们后面拼路径等于请求不存在的路径。
        - **第一段不以 `.` 开头**：`.git/config`、`.svn/entries`、`.github/...` 的最后一段
          也不含 `.`，但它们不是"可以爆破了"的目录（`.git` 本身就是要找的目标，
          不是往里再钻的入口）。这条能挡掉一批纯浪费的递归（每个浪费 = 3 基线 + N 路径）。
        """
        if status not in (200, 301, 302, 403):
            return None
        root = str(root or "").rstrip("/")
        full = str(full or "")
        if not root or not full.startswith(root + "/"):
            return None
        rel = full[len(root) + 1:].split("#", 1)[0].split("?", 1)[0].strip("/")
        if not rel:
            return None
        first = rel.split("/", 1)[0]
        last = rel.rsplit("/", 1)[-1]
        if not last or "." in last or first.startswith("."):
            return None
        return root + "/" + rel

    def _recursive_scan(self, sites, entries, cfg, limits):
        """对目录型命中再往下打 `recursive_depth` 层（**默认 0 = 关**），返回新命中。

        **为什么必须同时限目录数**：单站浅扫约 153 请求（150 路径 + 3 软 404 基线），
        一层递归 = `+K × (3 基线 + M)`（K = 递归目录数、M = 每目录路径数）。K=5/M=40 时
        `+215` 请求，**比第一轮还多** —— 而 K 是"扫出多少个目录"决定的，不受字典大小控制，
        所以只限深度不限 K 会随命中数线性放大。这里是**三重闸**：
        层数 `recursive_depth`、每站**跨层累计**目录数 `recursive_max_dirs`、
        每目录路径数 `recursive_max_paths`（用浅扫精选字典，不是再来一遍大字典）。

        **软 404 基线按基址各算一份**（3 请求/目录）：`_scan` 里的基线缓存键就是基址，
        递归前缀天然各算各的。这是必须的 —— 子目录常有**自己的**统一跳转页，
        复用站点根的基线会把子目录下的真实命中整片滤掉（那正是"看起来扫了、其实全是空"）。

        防环：`visited` 记已递归过的前缀（`/a` → `/a/a` → … 靠它和层数上限一起挡住）。
        """
        depth = int(cfg.get("recursive_depth", 0) or 0)
        max_dirs = int(cfg.get("recursive_max_dirs", 5) or 0)
        max_paths = int(cfg.get("recursive_max_paths", 40) or 0)
        if depth <= 0 or max_dirs <= 0 or max_paths <= 0:
            return []
        ctx = self.ctx
        paths = self._load_paths("", cfg, layers=_SHALLOW_LAYERS, limit=max_paths)
        if not paths:
            ctx.logger.warning("[dirscan] 目录递归：浅扫精选字典为空，跳过")
            return []
        # 只对**本轮真实扫过的站点**递归（dirmap 产物行可能带着别的 netloc）。
        # 同时收站点原始 URL 与它的 origin：probe 存下来的站点可能是带路径的入口
        # （`http://h/app`），而 dirmap 行的 site_url 一律是 origin（`http://h/`）。
        roots = set()
        for s in sites:
            u = str(s.get("url") or "").rstrip("/")
            if not u:
                continue
            roots.add(u)
            o = _origin_of(u).rstrip("/")
            if o:
                roots.add(o)
        used, visited = {}, set()
        frontier, found = list(entries), []
        for level in range(1, depth + 1):
            jobs, dirs = [], []
            for e in frontier:
                root = str(e.get("site_url") or "").rstrip("/")
                if not root or root not in roots:
                    continue
                if used.get(root, 0) >= max_dirs:
                    continue
                prefix = self._dir_prefix(root, e.get("path"), e.get("status"))
                if not prefix or prefix in visited:
                    continue
                visited.add(prefix)
                used[root] = used.get(root, 0) + 1
                dirs.append(prefix)
                jobs.extend((prefix, p, root) for p in paths)
            if not jobs:
                break
            ctx.logger.info(f"[dirscan] 目录递归第 {level} 层：{len(dirs)} 个目录 x "
                            f"{len(paths)} 条浅扫字典 = {len(jobs)} 个请求 …")
            if ctx.stopped():
                ctx.logger.warning("[dirscan] 任务已请求停止，中止目录递归")
                break
            frontier = self._scan(jobs, limits)
            if not frontier:
                break
            found.extend(frontier)
        if found:
            ctx.logger.info(f"[dirscan] 目录递归新增 {len(found)} 条"
                            f"（共递归 {len(visited)} 个目录，上限 {max_dirs} 个/站）")
        return found
