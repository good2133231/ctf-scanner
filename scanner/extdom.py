"""拓展域名（js:* / osint:*）的后处理：存在性判定、归属判定、按主域名分组。

「拓展域名」与「目标自身子域名」在库里的**唯一**区别就是 `subdomains.source` 的前缀
（见 `db.EXT_SUBDOMAIN_WHERE` / `db.OWN_SUBDOMAIN_WHERE`），所以本模块的一切判断都只
在这一列上做文章 —— 不新增表、不改既有来源的语义、不加第三方依赖。

三件事（2026-09-25 的用户需求）：
1. `resolve_extended()` —— **自动判断"这个域名到底存不存在"**（纯 DNS 只读解析），
   把 `ip / cname / cdn / ip_note` 回填到资产行上；`ip_note` 会记下"为什么没有 IP"
   （`nxdomain` 即域名不存在），页面上不必再靠人工点「解析」去猜。
2. `promote_owned()` —— 拓展出来的域名若**归属本项目**（注册域命中任务目标的注册域，
   例如目标 `targ1.pro` 拓展出 `aaa.targ1.pro`），就"追加"一条**自身子域名**行
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
from . import blacklist, cdn, db, dnsq, targets
from .utils import base_domain, is_domain, pool_run

# 追加来源前缀：以它开头的 source **不属于** `js:` / `osint:`，因此按"自身子域名"对待；
# 冒号后面原样保留拓展来源（`promote:js:mine`），"分域名而来"的出处一眼可查。
PROMOTE_PREFIX = "promote:"

# 分组阶段只取这三列：分组要 `domain`、算"可解析条数"要 `ip`、取回整行要 `id`。
# 只为分组把这些小列读进内存，而**不是** `SELECT *`（整行含 banner 级的大字段），
# 也**不再**设"前 N 行"的上限 —— 见 `group_page()` 的注释。
GROUP_LIGHT_COLS = ("id", "domain", "ip")


def base_of(host):
    """注册域：`aaa.targ1.pro` → `targ1.pro`。

    续146：判据本体收敛到 `targets.root_of()`（唯一产地，含 `is_domain` 守门）。这里保留一个
    **薄壳**给三个"数据来自库里、形状可能怪"的调用点（`zone_is_absent` / `filter_absent_zones`
    的日志 / `group_by_base`）：`root_of` 对不像域名的输入返回空串，而**分组需要一个非空且稳定
    的键** —— 空串会把所有怪值并成同一组。所以守门失败时退回旧的"直接 `base_domain`"
    （宁可给个粗切的键，也不并组）。对合法域名两者逐字相同。
    """
    h = str(host or "").strip().lower().rstrip(".")
    return targets.root_of(h) or base_domain(h)


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

    同时收下**目标本身**与它的注册域：目标是 `aaa.targ1.pro` 时，`targ1.pro` 与
    `aaa.targ1.pro` 都算本项目（`base_domain()` 粗切失手时前者也能兜住）。
    续146：主机名提取改走 `targets.hosts_of()`（此前这里自己写了一份 URL→hostname）。
    """
    if targets_text is None:
        task = db.get_task(int(task_id))
        targets_text = "" if not task else (task["targets"] or "")
    hosts = targets.hosts_of(targets.parse_lines(str(targets_text or "").splitlines()))
    return {b for b in set(hosts) | {base_of(h) for h in hosts} if b}


def owner_of(task_id):
    """任务归属账号（续89）；取不到 / 老库无该列 → 0（= 只看全局黑名单）。"""
    try:
        row = db.get_task(int(task_id))
    except (TypeError, ValueError):
        return 0
    return int(row["owner_id"] or 0) if (row and "owner_id" in row.keys()) else 0


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
    todo, blocked = blacklist.filter_domains(todo, settings, owner_id=owner_of(task_id))
    skipped = 0
    over = []
    if len(todo) > cap:
        over, todo = todo[cap:], todo[:cap]
        skipped = len(over)

    def _one(host):
        if stopped is not None and stopped():
            return None
        chain, ips, reason = dnsq.resolve_detail(host, timeout=timeout, settings=settings)
        # CDN 判定同 subdomain 阶段：CNAME 链 + 解析 IP 段两条判据（后者兜"无 CNAME 的任播 CDN"）。
        return host, ",".join(ips), cdn.match(chain, settings, ips), reason, \
            (chain[-1] if chain else "")

    net, cnames = {}, {}
    for host, ips, cdn_label, reason, last in pool_run(_one, todo, workers=workers,
                                                     logger=logger, label="拓展域名解析"):
        net[host] = (ips, cdn_label, reason)
        if last:
            cnames[host] = last
    for host in over:
        net[host] = ("", "", "over-limit")
    db.set_subdomain_net(task_id, net)
    db.set_subdomain_cnames(task_id, cnames)

    alive = sum(1 for v in net.values() if v[0])
    dead = sum(1 for v in net.values() if v[2])
    # 解析回填之后立刻做一次"注册域是否存在"的清理（判据与理由见 `drop_absent_zones`）：
    # 这一步只用**已经有结论**的行，不额外发解析请求（注册域查询是按 base 去重后的少量查询）。
    dropped = drop_absent_zones(task_id, settings, logger=logger, timeout=timeout)
    # `blacklist.filter_domains` 返回 `(保留列表, 被拦条数)` —— 被拦的是**条数**不是列表，
    # 别按 `filter_pairs` 的口径去 len()。
    summary = {"total": len(rows), "scanned": len(todo), "alive": alive, "dead": dead,
               "skipped": skipped, "blocked": int(blocked), "dropped": dropped}
    if logger:
        logger.info(f"[extdom] 存在性判定：拓展域名 {summary['total']} 条，"
                    f"本次解析 {summary['scanned']} 个 → 可解析 {alive} / 无结论 {dead}"
                    + (f"，超出上限 {skipped} 个" if skipped else "")
                    + (f"，黑名单拦截 {blocked} 个" if blocked else "")
                    + (f"，其中 {dropped} 条判为「不是域名」已删除" if dropped else ""))
    return summary


def zone_is_absent(host, settings=None, cache=None, timeout=3.0):
    """这个宿主的**注册域**是否明确未被注册（唯一判据：查 NS 得到 NXDOMAIN）。

    `cache` 是调用方给的 `{注册域: 状态}` 字典 —— 一批宿主常常共享同一个注册域
    （`chat.floating.open` / `voice.room.open` …），按注册域缓存才不会一个查询一次。

    三种结果里**只有 `absent` 算数**：`exists` 放行、`unknown`（SERVFAIL / REFUSED / 超时 /
    没配到解析器）也放行 —— "没问到"绝不能当成"不存在"，否则内网或 DNS 抖动时会把真资产判掉
    （丢资产比留噪声严重，与 `jsmine` 的 PSL 清单 fail-open 同一条方向）。
    """
    base = base_of(host)
    if not base or not is_domain(base):
        return False                       # 连"像个域名"都不像的输入不由这里判（见 _valid_host）
    if cache is not None and base in cache:
        return cache[base] == "absent"
    state = dnsq.zone_state(base, timeout=timeout, settings=settings)
    if cache is not None:
        cache[base] = state
    return state == "absent"


def filter_absent_zones(hosts, settings=None, logger=None, timeout=3.0):
    """把「注册域不存在」的宿主从一批域名里挑出去，返回 `(保留, 被去掉的列表)`（续113）。

    开关 `jsmine.drop_absent_zone`（默认开）关着时原样返回、一次查询都不发。
    调用点有两处，共用**同一个**判据：`stages/jsmine.py` 入库前拦（根本不进库），以及
    `resolve_extended()` 解析回填后清历史行（库里已有的碎片）。
    """
    cfg = (settings or {}).get("jsmine") or {}
    if not cfg.get("drop_absent_zone", True):
        return list(hosts or []), []
    cache = {}
    kept, dropped = [], []
    for h in (hosts or []):
        if zone_is_absent(h, settings=settings, cache=cache, timeout=timeout):
            dropped.append(h)
        else:
            kept.append(h)
    if dropped and logger:
        bases = sorted({base_of(h) for h in dropped})
        logger.info(f"[extdom] 去掉 {len(dropped)} 个「不是域名」的 JS 碎片（点号连接的成员访问链，"
                    f"注册域查询返回 NXDOMAIN；涉及注册域 {len(bases)} 个，样例 "
                    f"{', '.join(bases[:3])}）；判据只在明确 NXDOMAIN 时动手，DNS 无结论一律放行")
    return kept, dropped


def drop_absent_zones(task_id, settings=None, logger=None, timeout=3.0):
    """删掉库里「注册域压根不存在」的 JS 碎片行（判据同上，只多一条来源限制）。

    只动 `js:*` / `promote:js:*` 且**自己解析不到地址、原因还是 `nxdomain`** 的行：
    - `over-limit` / `timeout` / `servfail` 不算"不存在"，一律保留；
    - `osint:*`（C 段 / FOFA / 证书反查）来的域名是第三方数据库里的实际观测，
      "现在解析不到"不是"它不是资产"的证据，所以不在清理范围内。
    """
    rows = db._query(
        "SELECT id, domain, source FROM subdomains WHERE task_id=? AND ip='' "
        "AND ip_note='nxdomain' AND (source LIKE 'js:%' OR source LIKE ?)",
        (task_id, f"{PROMOTE_PREFIX}js:%"))
    if not rows:
        return 0
    cache = {}
    dead = [r["id"] for r in rows
            if zone_is_absent(r["domain"], settings=settings, cache=cache, timeout=timeout)]
    if not dead:
        return 0
    marks = ",".join("?" * len(dead))
    db._exec(f"DELETE FROM subdomains WHERE id IN ({marks})", tuple(dead))
    if logger:
        logger.info(f"[extdom] 清掉 {len(dead)} 条库里已有的 JS 碎片行（注册域不存在）；"
                    f"另 {len(rows) - len(dead)} 条 nxdomain 行保留（注册域存在或 DNS 无结论）")
    return len(dead)


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
    kept, blocked = blacklist.filter_pairs(pairs, settings, owner_id=owner_of(task_id))
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


def promote_domains(domains, settings=None, logger=None, task_id=None, owner_id=None):
    """跨任务视图里勾选的域名 → 在**它所属的任务**下追加为自身子域名。

    拓展域名页是跨任务的，勾选框里只有域名；这里按域名反查它出现在哪些任务的拓展域名里，
    再逐个任务用 `promote_owned()` 判定归属（同一个域名在两个任务里归属结论可以不同）。
    `task_id` 给了就只在该任务下处理（任务详情页签用）。

    `owner_id`（续94）：多租户收口。`None` ＝ 管理员不限制；否则**只处理归属该账号的任务**。
    这是必须的：跨任务视图的勾选框里只有域名，同一个域名可能同时出现在**别人的**任务里 ——
    不过滤就会把 `source=promote:*` 行**写进别人的任务**（越权**写**，比越权读更严重）。
    """
    settings = settings or {}
    wanted = {_norm(d) for d in (domains or []) if _norm(d)}
    if not wanted:
        return {"promoted": [], "tasks": []}

    pairs = set()
    if task_id is not None:
        tid = int(task_id)
        # 显式指定任务时也校验归属：GUI 调用方通常已校验，这里是**纵深防御** ——
        # 少依赖一处调用方，就少一个"将来新加的调用点忘了校验"的口子。
        if owner_id is None or owner_of(tid) == int(owner_id):
            for r in ext_rows(tid):
                if _norm(r.get("domain")) in wanted:
                    pairs.add((tid, r["domain"]))
    else:
        # `subdomains` 没有 owner 列，用 `_owner_asset_clause()` 的"任务属于我"子查询收口
        owner_sql, owner_params = db._owner_asset_clause(owner_id)
        extra = (" AND " + owner_sql) if owner_sql else ""
        for chunk in _chunks(sorted(wanted)):
            marks = ",".join("?" for _ in chunk)
            for r in db._query(
                    "SELECT task_id, domain FROM subdomains WHERE (" + db.EXT_SUBDOMAIN_WHERE
                    + f") AND domain IN ({marks})" + extra,
                    tuple(chunk) + tuple(owner_params)):
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


def group_page(q=None, extra_where=None, extra_params=(), page=1, per_page=20, order=None,
               dedupe_domain=False):
    """分组视图的分页：返回 `{groups, page, pages, group_total, row_total}`。

    - `groups` 是**当前页**的主域名组，每组的 `rows` 是**完整资产行**（模板要渲染 IP/CDN/CNAME/来源）；
    - `group_total` 是主域名个数，`row_total` 是匹配到的行数 —— 页面上两个数都会显示。

    为什么分两步查：SQLite 没有"注册域"函数，分组只能在 Python 里做（`base_of`）。于是
    ① 先在**全量匹配行**上只取 `GROUP_LIGHT_COLS` 做分组；
    ② 再对当前页的组按 id 取回整行。

    这里**刻意不设"前 N 行"上限**：旧实现（写死的 `GROUP_ROW_CAP = 4000`）只把前 4000 行拿去
    分组，于是第 4001 行起所属的主域名组**在任何一页都不会出现**，分页条上的"共 N 个主域名"
    也是截断后的假数字（与续51/53/55/57 一路在修的"固定上限 + 静默丢"是同一个病）。省内存的
    正确做法是"分组阶段只查三列"，而不是"少查几行"。
    """
    light, row_total = db.page_assets(
        "subdomains", limit=None, offset=0, q=q or None, extra_where=extra_where,
        extra_params=extra_params, order=order, columns=GROUP_LIGHT_COLS,
        dedupe_domain=dedupe_domain)
    all_groups = group_by_base([dict(r) for r in light])
    group_total = len(all_groups)
    per_page = max(1, int(per_page))
    pages = max(1, (group_total + per_page - 1) // per_page)
    page = min(max(1, int(page)), pages)     # 越界（过滤后组数变少）→ 回落到最后一页
    picked = all_groups[(page - 1) * per_page: page * per_page]

    # 取回当前页各组的整行。组内顺序按分组阶段的先后**原样展开**，不能用 `ORDER BY id` 重排
    # （那会丢掉调用方排好的"按来源分类"顺序）。
    ids = [int(r["id"]) for g in picked for r in g["rows"]]
    full = {}
    for chunk in _chunks(ids):
        marks = ",".join("?" for _ in chunk)
        for r in db._query(f"SELECT * FROM subdomains WHERE id IN ({marks})", tuple(chunk)):
            full[int(r["id"])] = dict(r)
    for g in picked:
        g["rows"] = [full[i] for i in (int(r["id"]) for r in g["rows"]) if i in full]
    return {"groups": picked, "page": page, "pages": pages,
            "group_total": group_total, "row_total": row_total}


def process(task_id, settings=None, logger=None, stopped=None):
    """流水线上用的入口：存在性判定 + 归属追加（都只在 `auto_expand` 打开时由 runner 调）。

    顺序**必须先判定再追加**：追加时会把拓展行的 `ip / cdn / ip_note` 一起复制到新行上，
    先解析能让新行一落库就带"存不存在"的结论。
    """
    resolved = resolve_extended(task_id, settings=settings, logger=logger, stopped=stopped)
    promoted = promote_owned(task_id, settings=settings, logger=logger)
    return {"resolve": resolved, "promote": promoted}
