"""拓展域名（js:* / osint:*）的后处理：存在性判定、归属判定、按主域名分组。

「拓展域名」与「目标自身子域名」在库里的**唯一**区别就是 `subdomains.source` 的前缀
（见 `db.EXT_SUBDOMAIN_WHERE` / `db.OWN_SUBDOMAIN_WHERE`），所以本模块的一切判断都只
在这一列上做文章 —— 不新增表、不改既有来源的语义、不加第三方依赖。

三件事（2026-09-25 的用户需求）：
1. `resolve_extended()` —— **自动判断"这个域名到底存不存在"**（纯 DNS 只读解析），
   把 `ip / cname / cdn / ip_note` 回填到资产行上；`ip_note` 会记下"为什么没有 IP"
   （`nxdomain` 即域名不存在），页面上不必再靠人工点「解析」去猜。
2. `promote_owned()` —— 拓展出来的域名若**归属本项目**（注册域命中任务目标的注册域，
   例如目标 `pengo.pro` 拓展出 `aaa.pengo.pro`），就"追加"一条**自身子域名**行
   （source = `promote:<原来源>`）：
   - 该域名随即在「子域名资产」页按正常子域对待（参与 probe/dirscan 的候选资产口径一致）；
   - 拓展页里原来那一行因为"该域名已作为自身子域名存在"被 `db.OVERLAP_EXT_WHERE`
     **自动默认隐藏**（`?all=1` 仍可看），既不留重复占位，又保留了"分域名而来"的来源。
3. `group_by_base()` —— 按注册域分组，供拓展域名页**折叠**展示。

刻意不引入公共后缀库（离线 CTF 场景）：`utils.base_domain` 的粗切在 `foo.bar.co`
这类双段后缀上会切错，但它只影响"算不算归属本项目"，且**偏保守**（切错 → 少归一些，
不会把别人的域名误当成自己的资产）。

所有写库路径都过 `blacklist` —— 被拦的域名既不解析也不追加。
"""
from urllib.parse import urlparse

from . import blacklist, cdn, db, dnsq, targets
from .utils import base_domain, is_domain, pool_run

# 追加来源前缀：以它开头的 source **不属于** `js:` / `osint:`，因此按"自身子域名"对待；
# 冒号后面原样保留拓展来源（`promote:js:mine`），"分域名而来"的出处一眼可查。
PROMOTE_PREFIX = "promote:"

# 分组视图一次最多参与分组的行数（超了只取前 N 条并在页面提示）——分组必须在 Python 里做
# （SQL 侧没有注册域函数），这是为不把整表读进内存设的上限。
GROUP_ROW_CAP = 4000


def base_of(host):
    """注册域（归一化后取 `utils.base_domain`）：`aaa.pengo.pro` → `pengo.pro`。"""
    return base_domain(str(host or "").strip().lower().rstrip("."))


def _norm(host):
    return str(host or "").strip().lower().rstrip(".")


def is_owned(host, bases):
    """`host` 是否归属给定的注册域集合（等于自身或为其子域）。"""
    h = _norm(host)
    if not h:
        return False
    for b in bases:
        b = _norm(b)
        if b and (h == b or h.endswith("." + b)):
            return True
    return False


def task_bases(task_id, targets_text=None):
    """任务目标 → 归属判定的"主域名集合"。

    同时收下**目标本身**与它的注册域：目标是 `aaa.pengo.pro` 时，`pengo.pro` 与
    `aaa.pengo.pro` 都算本项目（`base_domain()` 粗切失手时前者也能兜住）。
    """
    if targets_text is None:
        task = db.get_task(int(task_id))
        targets_text = "" if not task else (task["targets"] or "")
    out = set()
    for kind, value in targets.parse_lines(str(targets_text or "").splitlines()):
        host = str(value or "").strip().lower().rstrip(".")
        if kind == "url":
            host = (urlparse(str(value)).hostname or "").strip().lower().rstrip(".")
        if not host or not is_domain(host):
            continue
        out.add(host)
        out.add(base_of(host))
    return {b for b in out if b}


def ext_rows(task_id):
    """任务下的全部拓展域名行（`js:*` / `osint:*`）。"""
    return [dict(r) for r in db._query(
        "SELECT * FROM subdomains WHERE task_id=? AND " + db.EXT_SUBDOMAIN_WHERE + " ORDER BY id",
        (int(task_id),))]


def _own_domains(task_id):
    return {r["domain"] for r in db._query(
        "SELECT domain FROM subdomains WHERE task_id=? AND " + db.OWN_SUBDOMAIN_WHERE,
        (int(task_id),))}


def _chunks(items, size=300):
    """切块（SQLite 变量数上限 999，`IN (...)` 一次别喂太多）。"""
    items = list(items)
    for i in range(0, len(items), size):
        yield items[i:i + size]


def resolve_extended(task_id, settings=None, logger=None, only_missing=True,
                     cap=None, workers=None, stopped=None):
    """自动判断拓展域名"存不存在"（纯 DNS 只读），回填 `ip / cname / cdn / ip_note`。

    - `only_missing=True`（默认）只解析**还没结论**的行（ip 与 ip_note 都为空），
      因此重复调用是幂等的、不会把已有结论冲掉、也不会重复消耗请求；
    - `cap` 上限沿用 `subdomain.max_resolve`（默认 500），超出的行标 `over-limit`；
    - 返回 `{total, scanned, alive, dead, skipped, blocked}`（**静态可测**：全部走桩解析器）。
    """
    settings = settings or {}
    cfg = settings.get("subdomain", {}) or {}
    limits = settings.get("limits", {}) or {}
    timeout = float(cfg.get("dns_timeout", 3) or 3)
    if cap is None:
        cap = int(cfg.get("max_resolve", 500) or 500)
    if workers is None:
        workers = max(1, min(20, int(limits.get("max_workers", 20) or 20)))

    rows = ext_rows(task_id)
    todo = []
    for r in rows:
        if only_missing and ((r.get("ip") or "").strip() or (r.get("ip_note") or "").strip()):
            continue
        if r.get("domain"):
            todo.append(r["domain"])
    todo, blocked = blacklist.filter_domains(todo, settings)
    skipped = 0
    over = []
    if len(todo) > cap:
        over, todo = todo[cap:], todo[:cap]
        skipped = len(over)

    def _one(host):
        if stopped is not None and stopped():
            return None
        chain, ips, reason = dnsq.resolve_detail(host, timeout=timeout, settings=settings)
        return host, ",".join(ips), cdn.match(chain, settings), reason, (chain[-1] if chain else "")

    net, cnames = {}, {}
    for host, ips, cdn_label, reason, last in pool_run(_one, todo, workers=workers):
        net[host] = (ips, cdn_label, reason)
        if last:
            cnames[host] = last
    for host in over:
        net[host] = ("", "", "over-limit")
    db.set_subdomain_net(task_id, net)
    db.set_subdomain_cnames(task_id, cnames)

    alive = sum(1 for v in net.values() if v[0])
    dead = sum(1 for v in net.values() if v[2])
    # `blacklist.filter_domains` 返回 `(保留列表, 被拦条数)` —— 被拦的是**条数**不是列表，
    # 别按 `filter_pairs` 的口径去 len()。
    summary = {"total": len(rows), "scanned": len(todo), "alive": alive, "dead": dead,
               "skipped": skipped, "blocked": int(blocked)}
    if logger:
        logger.info(f"[extdom] 存在性判定：拓展域名 {summary['total']} 条，"
                    f"本次解析 {summary['scanned']} 个 → 可解析 {alive} / 无结论 {dead}"
                    + (f"，超出上限 {skipped} 个" if skipped else "")
                    + (f"，黑名单拦截 {blocked} 个" if blocked else ""))
    return summary


def promote_owned(task_id, settings=None, logger=None, bases=None):
    """把**归属本项目**的拓展域名"追加"为自身子域名（分域名而来）。

    判据：`domain` 等于任务目标的注册域、或是它的子域。命中后插入一行
    source = `promote:<原来源>` 的记录（**原拓展行保留不动**，于是"它是从哪来的"永远可查）。
    已有自身子域名行的域名不再重复插入 —— 重复调用是幂等的。
    """
    settings = settings or {}
    if bases is None:
        bases = task_bases(task_id)
    if not bases:
        if logger:
            logger.info("[extdom] 任务目标里没有可用域名，跳过归属追加")
        return {"promoted": [], "bases": set(), "blocked": 0}

    own = _own_domains(task_id)
    cands = []
    for r in ext_rows(task_id):
        d = r.get("domain") or ""
        if not d or d in own or not is_owned(d, bases):
            continue
        cands.append(r)
    pairs = [(r["domain"], r.get("source") or "") for r in cands]
    kept, blocked = blacklist.filter_pairs(pairs, settings)
    kept_rows = {r["domain"]: r for r in cands}
    if not kept:
        return {"promoted": [], "bases": bases, "blocked": len(blocked)}

    insert = []
    net = {}
    for domain, src in kept:
        r = kept_rows[domain]
        insert.append((domain, PROMOTE_PREFIX + src, r.get("cname") or ""))
        net[domain] = (r.get("ip") or "", r.get("cdn") or "", r.get("ip_note") or "")
    db.insert_subdomains(int(task_id), insert)
    db.set_subdomain_net(int(task_id), net)
    promoted = [d for d, _ in kept]
    if logger:
        logger.info(f"[extdom] 归属追加 {len(promoted)} 个拓展域名为子域名"
                    f"（主域名 {' / '.join(sorted(bases))}）"
                    + (f"，黑名单拦截 {len(blocked)} 个" if blocked else ""))
    return {"promoted": promoted, "bases": bases, "blocked": len(blocked)}


def promote_domains(domains, settings=None, logger=None, task_id=None):
    """跨任务视图里勾选的域名 → 在**它所属的任务**下追加为自身子域名。

    拓展域名页是跨任务的，勾选框里只有域名；这里按域名反查它出现在哪些任务的拓展域名里，
    再逐个任务用 `promote_owned()` 判定归属（同一个域名在两个任务里归属结论可以不同）。
    `task_id` 给了就只在该任务下处理（任务详情页签用）。
    """
    settings = settings or {}
    wanted = {_norm(d) for d in (domains or []) if _norm(d)}
    if not wanted:
        return {"promoted": [], "tasks": []}

    pairs = set()
    if task_id is not None:
        tid = int(task_id)
        for r in ext_rows(tid):
            if _norm(r.get("domain")) in wanted:
                pairs.add((tid, r["domain"]))
    else:
        for chunk in _chunks(sorted(wanted)):
            marks = ",".join("?" for _ in chunk)
            for r in db._query(
                    "SELECT task_id, domain FROM subdomains WHERE (" + db.EXT_SUBDOMAIN_WHERE
                    + f") AND domain IN ({marks})", tuple(chunk)):
                pairs.add((r["task_id"], r["domain"]))

    by_task = {}
    for tid, domain in pairs:
        by_task.setdefault(int(tid), set()).add(domain)
    promoted, touched = [], []
    for tid in sorted(by_task):
        bases = task_bases(tid)
        hit = sorted(d for d in by_task[tid] if is_owned(d, bases))
        if not hit:
            continue
        res = promote_owned(tid, settings, logger=logger, bases=bases)
        if res.get("promoted"):
            promoted.extend(res["promoted"])
            touched.append(tid)
    if logger:
        logger.info(f"[extdom] 手动归属追加：勾选 {len(wanted)} 个域名 → 追加 {len(promoted)} 个"
                    f"（涉及任务 {touched or '无'}）")
    return {"promoted": promoted, "tasks": touched}


def group_by_base(rows):
    """按注册域分组；返回 `[{base, count, alive, rows}]`，组按「条数降序 → 主域名升序」。

    `rows` 的**组内顺序原样保留**（调用方已按来源分类排好序），只做稳定分组不重排。
    """
    agg = {}
    for r in rows:
        agg.setdefault(base_of(r.get("domain") or ""), []).append(r)
    groups = []
    for base, items in agg.items():
        alive = sum(1 for i in items if (i.get("ip") or "").strip())
        groups.append({"base": base, "rows": items, "count": len(items), "alive": alive})
    groups.sort(key=lambda g: (-g["count"], g["base"]))
    return groups


def process(task_id, settings=None, logger=None, stopped=None):
    """流水线上用的入口：存在性判定 + 归属追加（都只在 `auto_expand` 打开时由 runner 调）。

    顺序**必须先判定再追加**：追加时会把拓展行的 `ip / cdn / ip_note` 一起复制到新行上，
    先解析能让新行一落库就带"存不存在"的结论。
    """
    resolved = resolve_extended(task_id, settings=settings, logger=logger, stopped=stopped)
    promoted = promote_owned(task_id, settings=settings, logger=logger)
    return {"resolve": resolved, "promote": promoted}
