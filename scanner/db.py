"""SQLite 存储层：任务 / 子域名 / 站点 / 目录 / 漏洞 / POC 注册表。

设计取舍（客观说明）：
- 为降低部署成本选择 SQLite 单文件库，不做 ORM；
- 每次调用独立连接、用完即关，天然线程安全，代价是高频写入略有开销，单机 CTF 场景足够；
- 若后续需要多节点/高并发，替换本层为 PostgreSQL 或 MongoDB 即可，上层接口不变。
"""
import json
import sqlite3
import time
from pathlib import Path

from .config import BASE_DIR, env_path

# 库路径可用环境变量 CTFSCANNER_DB 覆盖 —— **测试必须走独立库**：
# 回归测试（tests/smoke.py）会创建任务、写资产、改 POC 开关，若直接落在 data/scanner.db，
# 真实任务库就会被测试数据污染（此前"站点计数不稳定"类问题正源于此）。
# 走 `config.env_path()`：Git Bash 传进来的 `/c/...` 在 Windows 上会被 pathlib 解析成
# "当前盘符根下的 c 目录"（库被建到盘符根），归一化逻辑与 LOGS_DIR 共用同一处实现。
DB_PATH = env_path("CTFSCANNER_DB", BASE_DIR / "data" / "scanner.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS tasks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  targets TEXT NOT NULL,
  stages TEXT NOT NULL,
  options TEXT DEFAULT '{}',
  status TEXT DEFAULT 'pending',
  progress INTEGER DEFAULT 0,
  current_stage TEXT DEFAULT '',
  log_file TEXT DEFAULT '',
  error TEXT DEFAULT '',
  created_at TEXT, updated_at TEXT
);
CREATE TABLE IF NOT EXISTS subdomains (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id INTEGER NOT NULL,
  domain TEXT NOT NULL,
  source TEXT DEFAULT '',
  cname TEXT DEFAULT '',
  ip TEXT DEFAULT '',
  cdn TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS sites (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id INTEGER NOT NULL,
  url TEXT NOT NULL, host TEXT, port TEXT,
  status INTEGER, title TEXT, length INTEGER, server TEXT, tech TEXT, source TEXT,
  favicon TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS ports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id INTEGER NOT NULL,
  host TEXT, ip TEXT, port INTEGER, service TEXT DEFAULT '', banner TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS csegs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id INTEGER NOT NULL,
  segment TEXT DEFAULT '',
  ip TEXT DEFAULT '',
  domains TEXT DEFAULT '',
  count INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS dirs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id INTEGER NOT NULL,
  site_url TEXT, path TEXT NOT NULL, status INTEGER, length INTEGER,
  method TEXT DEFAULT 'GET', note TEXT
);
CREATE TABLE IF NOT EXISTS vulns (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id INTEGER NOT NULL,
  target TEXT, poc_id TEXT, name TEXT, severity TEXT DEFAULT 'medium',
  owasp TEXT DEFAULT '', detail TEXT, evidence TEXT, created_at TEXT
);
CREATE TABLE IF NOT EXISTS pocs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  path TEXT UNIQUE NOT NULL,
  poc_id TEXT, name TEXT, severity TEXT DEFAULT 'medium', tags TEXT DEFAULT '',
  enabled INTEGER DEFAULT 1, status TEXT DEFAULT 'ok',
  updated_at TEXT
);
CREATE TABLE IF NOT EXISTS leads (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id INTEGER NOT NULL,
  kind TEXT DEFAULT '',        -- intel（外部情报订阅）/ heuristic（本地启发式候选）
  code TEXT DEFAULT '',        -- CVE 号 / 规则 id（去重与溯源用）
  title TEXT DEFAULT '',
  target TEXT DEFAULT '',      -- 命中的资产（站点 URL / 主机 / C 段）
  matched TEXT DEFAULT '',     -- 触发物（指纹信号 / 规则依据）
  level TEXT DEFAULT 'info',   -- 仅用于排序着色：**不是漏洞级别**（见 scanner/intel.py 边界说明）
  detail TEXT DEFAULT '',
  source TEXT DEFAULT '',
  url TEXT DEFAULT '',
  created_at TEXT
);
"""


def _now():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def get_conn():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    # 并发写保护：GUI 无任务队列，多个任务线程 + Flask 请求线程会同时写库。
    # 默认超时只有 5 秒且读写冲突时会立刻抛 "database is locked"，
    # 这里给个显式的 10 秒忙等，让写操作排队而不是失败。
    conn.execute("PRAGMA busy_timeout=10000")
    return conn


def init_db():
    with get_conn() as conn:
        conn.executescript(SCHEMA)
        _ensure_columns(conn)


# 老库轻量迁移：`CREATE TABLE IF NOT EXISTS` 不会给已存在的表补列，
# 这里按需 ADD COLUMN（SQLite 的 ADD COLUMN 是原地元数据操作，代价极低）。
_COLUMN_PATCHES = {
    "subdomains": {"cname": "TEXT DEFAULT ''", "ip": "TEXT DEFAULT ''",
                   "cdn": "TEXT DEFAULT ''",
                   # 解析失败/未解析的原因码（nxdomain / no-a / timeout / over-limit…）
                   "ip_note": "TEXT DEFAULT ''"},
    "sites": {"favicon": "TEXT DEFAULT ''",
              # 站点截图的**相对项目根**路径（logs/task_x/shots/xxx.png）
              "shot": "TEXT DEFAULT ''"},
}


def _ensure_columns(conn):
    for table, cols in _COLUMN_PATCHES.items():
        have = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}
        if not have:
            continue
        for col, decl in cols.items():
            if col not in have:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")


def _exec(sql, params=(), many=False):
    conn = get_conn()
    try:
        cur = conn.cursor()
        (cur.executemany if many else cur.execute)(sql, params)
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def _query(sql, params=(), one=False):
    conn = get_conn()
    try:
        rows = conn.execute(sql, params).fetchall()
        return (rows[0] if rows else None) if one else rows
    finally:
        conn.close()


# ---------- 任务 ----------

def create_task(name, targets, stages, options=None):
    return _exec(
        "INSERT INTO tasks(name, targets, stages, options, created_at, updated_at) "
        "VALUES(?,?,?,?,?,?)",
        (name, targets, ",".join(stages), json.dumps(options or {}), _now(), _now()))


def update_task(task_id, **fields):
    fields["updated_at"] = _now()
    sets = ", ".join(f"{k}=?" for k in fields)
    _exec(f"UPDATE tasks SET {sets} WHERE id=?", (*fields.values(), task_id))


def get_task(task_id):
    return _query("SELECT * FROM tasks WHERE id=?", (task_id,), one=True)


def list_tasks(limit=200):
    return _query("SELECT * FROM tasks ORDER BY id DESC LIMIT ?", (limit,))


ASSET_TABLES = ("subdomains", "sites", "ports", "csegs", "dirs", "vulns", "leads")


def clear_task_assets(task_id):
    """清空某任务的全部资产（子域名/站点/端口/C段/目录/漏洞/线索），用于"重启"前重置。"""
    for t in ASSET_TABLES:
        _exec(f"DELETE FROM {t} WHERE task_id=?", (task_id,))


# 备份目录跟随库位置（默认 data/trash —— 与库同处 data/ 下）：
# 用独立测试库时，测试产生的备份不会混进真实库的回收站。
TRASH_DIR = DB_PATH.parent / "trash"


def backup_task(task_id):
    """把某任务及其全部资产导出成一份 JSON 落到 data/trash/，返回备份路径（任务不存在则返回 None）。

    为什么做成"删除前的固定动作"而不是可选项：`delete_task` 是**硬删除**，
    SQLite 释放的页虽可能残留数据，但随时会被后续写入覆盖；而 `data/` 被 .gitignore 排除、
    没有外部备份。实测发生过一次批量误删（GUI 批量删除），事后只能靠扫描 free 页勉强抢救，
    约一半任务行已被后续写入覆盖、永久丢失。单任务备份只有几十 KB，成本远低于代价。
    """
    row = get_task(task_id)
    if row is None:
        return None
    payload = {"task": dict(row), "assets": {}}
    for t in ASSET_TABLES:
        payload["assets"][t] = [
            dict(r) for r in _query(f"SELECT * FROM {t} WHERE task_id=?", (task_id,))]
    TRASH_DIR.mkdir(parents=True, exist_ok=True)
    dst = TRASH_DIR / f"task_{task_id}_{time.strftime('%Y%m%d_%H%M%S')}.json"
    dst.write_text(json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8")
    return dst


def delete_task(task_id, backup=True):
    """删除任务及其全部资产；默认**先备份**到 `data/trash/`（`backup=False` 仅用于测试清理）。

    备份失败（磁盘满/权限）不阻断删除，但会显式打印告警 —— 不允许"以为有备份"。
    """
    if backup:
        try:
            backup_task(task_id)
        except OSError as e:
            print(f"[db] 警告：任务 #{task_id} 删除前备份失败：{e}")
    clear_task_assets(task_id)
    _exec("DELETE FROM tasks WHERE id=?", (task_id,))


def task_counts(task_id):
    """任务资产计数（任务列表「统计」列用）。"""
    def count(sql):
        row = _query(sql, (task_id,), one=True)
        return row["c"] if row else 0
    return {
        "sites": count("SELECT COUNT(*) c FROM sites WHERE task_id=?"),
        "subdomains": count("SELECT COUNT(*) c FROM subdomains WHERE task_id=?"),
        "ports": count("SELECT COUNT(*) c FROM ports WHERE task_id=?"),
        "csegs": count("SELECT COUNT(*) c FROM csegs WHERE task_id=?"),
        "dirs": count("SELECT COUNT(*) c FROM dirs WHERE task_id=?"),
        "vulns": count("SELECT COUNT(*) c FROM vulns WHERE task_id=?"),
    }


# ---------- 资产 ----------

def insert_subdomains(task_id, items):
    """items: [(domain, source[, cname]), ...]"""
    if not items:
        return
    rows = []
    for it in items:
        domain, source = it[0], it[1]
        cname = it[2] if len(it) > 2 else ""
        rows.append((task_id, domain, source, cname or ""))
    _exec("INSERT INTO subdomains(task_id, domain, source, cname) VALUES(?,?,?,?)",
          rows, many=True)


def set_subdomain_cnames(task_id, mapping):
    """回填子域名的 CNAME（客户端接管/泛解析分析用）。mapping: {domain: cname}"""
    rows = [(c, task_id, d) for d, c in (mapping or {}).items() if c]
    if not rows:
        return
    _exec("UPDATE subdomains SET cname=? WHERE task_id=? AND domain=?", rows, many=True)


def set_site_shots(task_id, pairs):
    """写入站点截图路径：`pairs` 是 `[(url, rel_path), ...]`。"""
    rows = [(rel or "", task_id, url) for url, rel in (pairs or []) if url]
    if not rows:
        return
    _exec("UPDATE sites SET shot=? WHERE task_id=? AND url=?", rows, many=True)


def set_subdomain_net(task_id, mapping):
    """回填子域名的解析 IP、CDN 标记与**未解析原因**。

    mapping: `{domain: (ip_text, cdn_label)}` 或 `{domain: (ip_text, cdn_label, note)}`；
    `ip_text` 是逗号连接的 A 记录，`cdn_label` 为空串表示判定为非 CDN（直连源站），
    `note` 是解析失败/未解析的原因码（`nxdomain` / `no-a` / `timeout` / `over-limit`…）。

    三者全空才跳过（避免把"没查到"覆盖成空字符串而抹掉已有数据）；只要带 note 就写，
    因为"为什么没有 IP"本身就是要展示给用户的信息。
    """
    rows = []
    for d, value in (mapping or {}).items():
        ip, cdn, note = (list(value) + ["", ""])[:3]
        if not (ip or cdn or note):
            continue
        rows.append((ip or "", cdn or "", note or "", task_id, d))
    if not rows:
        return
    _exec("UPDATE subdomains SET ip=?, cdn=?, ip_note=? WHERE task_id=? AND domain=?",
          rows, many=True)


def insert_sites(task_id, sites):
    if not sites:
        return
    _exec("INSERT INTO sites(task_id,url,host,port,status,title,length,server,tech,source,"
          "favicon) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
          [(task_id, s.get("url", ""), s.get("host", ""), str(s.get("port", "") or ""),
            s.get("status"), s.get("title", ""), s.get("length"), s.get("server", ""),
            s.get("tech", ""), s.get("source", ""), s.get("favicon", "")) for s in sites],
          many=True)


def insert_ports(task_id, ports):
    """items: [{host, ip, port, service, banner}, ...]"""
    if not ports:
        return
    _exec("INSERT INTO ports(task_id,host,ip,port,service,banner) VALUES(?,?,?,?,?,?)",
          [(task_id, p.get("host", ""), p.get("ip", ""), int(p.get("port") or 0),
            p.get("service", ""), (p.get("banner") or "")[:300]) for p in ports], many=True)


def insert_csegs(task_id, rows):
    """C 段归纳结果（P1-4）。items: [{segment, ip, domains, count}, ...]

    `domains` 存该 IP 反查到的域名（逗号连接，已按上限截断），`count` 是**截断前**的数量
    —— 后者用于判断"这个 IP 是不是共享主机/CDN"（一个 IP 挂几百个域名时噪声极大）。
    """
    if not rows:
        return
    _exec("INSERT INTO csegs(task_id,segment,ip,domains,count) VALUES(?,?,?,?,?)",
          [(task_id, str(r.get("segment", "")), str(r.get("ip", "")),
            ",".join(r.get("domains") or [])[:4000], int(r.get("count") or 0))
           for r in rows], many=True)


def insert_dirs(task_id, dirs):
    if not dirs:
        return
    _exec("INSERT INTO dirs(task_id,site_url,path,status,length,method,note) VALUES(?,?,?,?,?,?,?)",
          [(task_id, d.get("site_url", ""), d.get("path", ""), d.get("status"),
            d.get("length"), d.get("method", "GET"), d.get("note", "")) for d in dirs], many=True)


def insert_vuln(task_id, v):
    _exec("INSERT INTO vulns(task_id,target,poc_id,name,severity,owasp,detail,evidence,created_at) "
          "VALUES(?,?,?,?,?,?,?,?,?)",
          (task_id, v.get("target", ""), v.get("poc_id", ""), v.get("name", ""),
           v.get("severity", "medium"), v.get("owasp", ""), v.get("detail", ""),
           (v.get("evidence", "") or "")[:2000], _now()))


def list_subdomains(task_id):
    return _query("SELECT * FROM subdomains WHERE task_id=? ORDER BY domain", (task_id,))


def list_subdomain_net(limit=20000):
    """跨任务返回解析过的子域名（domain/ip/cdn）——「IP 资产」页用。

    只取 `ip <> ''` 的行（没解析出来的行对"按 IP 聚合"没有意义），并给个上限防止
    大库把页面拖死。
    """
    return _query("SELECT domain, ip, cdn FROM subdomains WHERE ip <> '' LIMIT ?", (limit,))


def list_sites(task_id):
    return _query("SELECT * FROM sites WHERE task_id=? ORDER BY id", (task_id,))


def list_dirs(task_id):
    return _query("SELECT * FROM dirs WHERE task_id=? ORDER BY id", (task_id,))


def list_ports(task_id):
    return _query("SELECT * FROM ports WHERE task_id=? ORDER BY host, port", (task_id,))


def insert_leads(task_id, rows):
    """写入线索（`leads` 表），返回实际新增条数。

    `(kind, code, target)` 相同的线索**不重复插入**：去重放在写入侧而不是靠表约束 ——
    任务"只重跑 intel 阶段"或阶段被重复执行时，同一批线索会再次产出，
    页面上看起来就像重复报（重启任务会走 `clear_task_assets`，不在此列）。
    """
    if not rows:
        return 0
    have = {(r["kind"], r["code"], r["target"]) for r in list_leads(task_id)}
    fresh = []
    for r in rows:
        key = (str(r.get("kind") or ""), str(r.get("code") or ""), str(r.get("target") or ""))
        if key in have:
            continue
        have.add(key)
        fresh.append((task_id, key[0], key[1], str(r.get("title") or ""), key[2],
                      str(r.get("matched") or ""), str(r.get("level") or "info"),
                      str(r.get("detail") or ""), str(r.get("source") or ""),
                      str(r.get("url") or ""), _now()))
    if not fresh:
        return 0
    _exec("INSERT INTO leads(task_id,kind,code,title,target,matched,level,detail,source,url,"
          "created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)", fresh, many=True)
    return len(fresh)


def list_leads(task_id):
    """任务线索（intel 在前、heuristic 在后，同级按 id 稳定排序）。"""
    return _query("SELECT * FROM leads WHERE task_id=? ORDER BY kind, level DESC, id", (task_id,))


def list_csegs(task_id):
    return _query("SELECT * FROM csegs WHERE task_id=? ORDER BY segment, ip", (task_id,))


# ---------- 全局资产视图（GUI 资产分栏用） ----------

# 表 -> (默认排序, 可被关键字过滤的文本列)
_ASSET_PAGES = {
    "subdomains": ("task_id DESC, domain",
                   ("domain", "source", "cname", "ip", "cdn", "ip_note")),
    "sites": ("task_id DESC, id DESC", ("url", "host", "title", "server", "tech")),
    "ports": ("task_id DESC, port", ("host", "ip", "service", "banner")),
    "csegs": ("task_id DESC, segment, ip", ("segment", "ip", "domains")),
    "dirs": ("task_id DESC, id DESC", ("site_url", "path", "note")),
}

# 子域名来源分类（资产视图的"子域名 / 拓展域名"两个页面靠它分流）：
# 「自身子域名」= 被动收集（subfinder / passive:*）与字典爆破（puredns / dns-brute）的产物；
# 「拓展域名」= 从 JS（js:mine）与外部情报（osint:cseg / osint:fofa）里带出来的关联域名，
# 它们未必属于目标，混在子域名页里会让人误判资产归属。
OWN_SUBDOMAIN_WHERE = "source NOT LIKE 'js:%' AND source NOT LIKE 'osint:%'"
EXT_SUBDOMAIN_WHERE = "(source LIKE 'js:%' OR source LIKE 'osint:%')"

# 「重叠资产」判据（用户要求：默认不显示重叠，手动勾选才显示）：
# - 拓展域名：该域名若已经作为**目标自身子域名**存在过（任意任务），说明它早就在资产清单里，
#   拓展页再列一遍纯属重复 —— 域名级全局判重（用户确认口径）；
# - 站点：同一 URL 在多个任务里都探到过时只留一条，避免"重复扫同一个目标"把列表撑成 N 倍。
#   **保留 `MAX(id)`（最新一次扫描的那条）而不是 `MIN(id)`**：站点行带的是当次扫描的
#   status / title / length / tech，留最旧那条意味着默认视图里看到的是陈旧数据
#   （实测：新任务已扫出 404 + 新标题，页面仍显示旧任务的 200 + 旧标题），
#   而重扫的目的恰恰是刷新这些字段。去重效果不变，展示的却是最新的资产状态。
OVERLAP_EXT_WHERE = f"domain NOT IN (SELECT domain FROM subdomains WHERE {OWN_SUBDOMAIN_WHERE})"
OVERLAP_SITE_WHERE = "id IN (SELECT MAX(id) FROM sites GROUP BY url)"


def page_assets(table, limit=200, offset=0, q=None, extra_where=None, extra_params=(),
                order=None):
    """跨任务资产分页查询，返回 (rows, total)。

    `q` 是"整行关键字"（对若干文本列做 LIKE），与前端 `initFilters()` 的体验一致，
    区别是过滤与分页都放在 SQL 侧 —— 数据量上去后不再被固定 `LIMIT 500` 截断。
    `extra_where` 是**服务端**附加条件（如子域名来源分流、CDN 标签），参数走 `extra_params`。
    `order` 留空用 `_ASSET_PAGES` 里的表默认排序；拓展域名页用它做"按来源分类排序"
    （`CASE source ... END` 显式指定分类先后），不改动表默认行为。
    """
    default_order, cols = _ASSET_PAGES[table]
    clauses, params = [], []
    if extra_where:
        clauses.append(f"({extra_where})")
        params.extend(extra_params)
    if q:
        clauses.append("(" + " OR ".join(f"{c} LIKE ?" for c in cols) + ")")
        params.extend([f"%{q}%"] * len(cols))
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    total = _query(f"SELECT COUNT(*) c FROM {table}{where}", tuple(params), one=True)
    rows = _query(f"SELECT * FROM {table}{where} ORDER BY {order or default_order} LIMIT ? OFFSET ?",
                  tuple(params) + (int(limit), int(offset)))
    return rows, (total["c"] if total else 0)


def list_all_subdomains(limit=500):
    return page_assets("subdomains", limit=limit)[0]


def list_all_sites(limit=500):
    return page_assets("sites", limit=limit)[0]


def list_all_dirs(limit=500):
    return page_assets("dirs", limit=limit)[0]


def list_all_ports(limit=500):
    return page_assets("ports", limit=limit)[0]


def list_vulns(task_id=None, severity=None, limit=200):
    sql, params = "SELECT * FROM vulns WHERE 1=1", []
    if task_id:
        sql += " AND task_id=?"
        params.append(task_id)
    if severity:
        sql += " AND severity=?"
        params.append(severity)
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    return _query(sql, tuple(params))


def dashboard_stats():
    def count(sql):
        row = _query(sql, one=True)
        return row["c"] if row else 0
    return {
        "tasks": count("SELECT COUNT(*) c FROM tasks"),
        "sites": count("SELECT COUNT(*) c FROM sites"),
        "subdomains": count("SELECT COUNT(*) c FROM subdomains"),
        "vulns": count("SELECT COUNT(*) c FROM vulns"),
        "pocs": count("SELECT COUNT(*) c FROM pocs WHERE status='ok'"),
    }


# ---------- POC 注册表 ----------

# 批量导入的第三方 POC（tools/import_ref_pocs.py 产物）默认**关闭**：
# 它们多为指纹式匹配，误报率高，需要人工在 POC 管理页挑选后再启用。
IMPORTED_HINT = "pocs-imported"


def default_poc_enabled(path):
    return 0 if IMPORTED_HINT in str(path).replace("\\", "/") else 1


def upsert_poc(path, meta):
    """按 `path` 插入或更新一条 POC 记录（**并发安全**）。

    旧实现是"先 SELECT 再 INSERT"：GUI 启动 + 多个任务线程会同时调 `sync_pocs()`，
    两个线程都 SELECT 到"不存在"→ 都 INSERT → 后者撞 UNIQUE(path) 抛
    `IntegrityError: UNIQUE constraint failed: pocs.path`（实测 6 个并发任务里 **5 个失败**）。
    这里改成**原子 UPSERT**（`ON CONFLICT(path) DO UPDATE`），并用 `last_insert_rowid()`
    拿回 id；同时 `DO UPDATE` **不动 `enabled`** —— 用户手动开关过的不该被同步覆盖。
    极老的 SQLite（<3.24 不支持 UPSERT）则回退到"INSERT 失败再 UPDATE"。
    """
    info = meta.get("info", {}) or {}
    tags = ",".join([str(t) for t in (info.get("tags") or [])])
    path = str(path)
    poc_id = meta.get("id", "")
    name = info.get("name", "")
    severity = info.get("severity", "medium")
    status = meta.get("_status", "ok")
    now = _now()
    try:
        conn = get_conn()
        try:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO pocs(path,poc_id,name,severity,tags,enabled,status,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?) "
                "ON CONFLICT(path) DO UPDATE SET poc_id=excluded.poc_id, name=excluded.name, "
                "severity=excluded.severity, tags=excluded.tags, status=excluded.status, "
                "updated_at=excluded.updated_at",
                (path, poc_id, name, severity, tags, default_poc_enabled(path), status, now))
            rid = cur.lastrowid
            if rid in (None, 0):     # UPSERT 走 DO UPDATE 分支时 lastrowid 仍返回原行 id
                row = conn.execute("SELECT id FROM pocs WHERE path=?", (path,)).fetchone()
                rid = row["id"] if row else rid
            conn.commit()
            return rid
        finally:
            conn.close()
    except sqlite3.OperationalError:        # 老 SQLite 不支持 UPSERT 语法
        row = _query("SELECT id FROM pocs WHERE path=?", (path,), one=True)
        if row:
            _exec("UPDATE pocs SET poc_id=?, name=?, severity=?, tags=?, status=?, updated_at=? "
                  "WHERE id=?", (poc_id, name, severity, tags, status, now, row["id"]))
            return row["id"]
        try:
            return _exec("INSERT INTO pocs(path,poc_id,name,severity,tags,enabled,status,updated_at) "
                         "VALUES(?,?,?,?,?,?,?,?)",
                         (path, poc_id, name, severity, tags, default_poc_enabled(path), status, now))
        except sqlite3.IntegrityError:      # 仍然并发冲突 → 退化为更新
            row = _query("SELECT id FROM pocs WHERE path=?", (path,), one=True)
            if row:
                _exec("UPDATE pocs SET poc_id=?, name=?, severity=?, tags=?, status=?, updated_at=? "
                      "WHERE id=?", (poc_id, name, severity, tags, status, now, row["id"]))
                return row["id"]
            raise


def list_pocs():
    return _query("SELECT * FROM pocs ORDER BY id")


def get_poc(pid):
    return _query("SELECT * FROM pocs WHERE id=?", (pid,), one=True)


def toggle_poc(pid):
    row = get_poc(pid)
    if row:
        _exec("UPDATE pocs SET enabled=? WHERE id=?", (0 if row["enabled"] else 1, pid))


# POC 分类维度：级别 / 来源。来源按路径前缀判定，与默认开关策略（default_poc_enabled）同一口径。
_POC_SOURCES = {
    "builtin": "scanner/pocs/pocs",
    "imported": "config/pocs-imported",
    "nuclei": "config/nuclei-templates",
    "user": "config/pocs-user",
}


def poc_source(path):
    """把 POC 路径归类为 builtin / imported / nuclei / user（未知返回 other）。"""
    norm = str(path).replace("\\", "/")
    for name, prefix in _POC_SOURCES.items():
        if prefix in norm:
            return name
    return "other"


def bulk_set_poc_enabled(enabled, severity=None, source=None, kind=None, only_ok=True):
    """按分类批量开关 POC（POC 管理页的"按分类开关"，避免 312 个逐个点）。

    - severity：critical/high/medium/low/info
    - source：builtin/imported/nuclei/user/other
    - kind：全部 / 变更（当前状态与目标状态不同的，便于"只改需要改的"）
    返回被更新的条数。
    """
    rows = _query("SELECT id, path, severity, enabled, status FROM pocs")
    target = 1 if enabled else 0
    ids = []
    for r in rows:
        if only_ok and r["status"] != "ok":
            continue
        if severity and (r["severity"] or "") != severity:
            continue
        if source and poc_source(r["path"]) != source:
            continue
        if kind == "diff" and int(r["enabled"] or 0) == target:
            continue
        ids.append(r["id"])
    if not ids:
        return 0
    marks = ",".join("?" for _ in ids)
    _exec(f"UPDATE pocs SET enabled=? WHERE id IN ({marks})", tuple([target] + ids))
    return len(ids)


def enabled_poc_paths():
    return [r["path"] for r in _query("SELECT path FROM pocs WHERE enabled=1 AND status='ok'")]
