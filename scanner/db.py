"""SQLite 存储层：任务 / 子域名 / 站点 / 目录 / 漏洞 / POC 注册表。

设计取舍（客观说明）：
- 为降低部署成本选择 SQLite 单文件库，不做 ORM；
- 每次调用独立连接、用完即关，天然线程安全，代价是高频写入略有开销，单机 CTF 场景足够；
- 若后续需要多节点/高并发，替换本层为 PostgreSQL 或 MongoDB 即可，上层接口不变。
"""
import json
import os
import sqlite3
import threading
import time
from pathlib import Path

from .config import BASE_DIR, env_path

# 库路径可用环境变量 CTFSCANNER_DB 覆盖 —— **测试必须走独立库**：
# 回归测试（tests/smoke.py）会创建任务、写资产、改 POC 开关，若直接落在 data/scanner.db，
# 真实任务库就会被测试数据污染（此前"站点计数不稳定"类问题正源于此）。
# 走 `config.env_path()`：Git Bash 传进来的 `/c/...` 在 Windows 上会被 pathlib 解析成
# "当前盘符根下的 c 目录"（库被建到盘符根），归一化逻辑与 LOGS_DIR 共用同一处实现。
DB_PATH = env_path("CTFSCANNER_DB", BASE_DIR / "data" / "scanner.db")

# 写操作串行化（进程内）。
# 为什么还要一把锁：SQLite 是**单写者**库，WAL 只让"读不被写阻塞"，`busy_timeout=10000`
# 也只是"冲突时最多等 10 秒再抛 database is locked"，两者都**不保证写一定成功**。
# 而本框架没有任务队列：GUI 里 N 个任务线程各自 `pool_run(workers=20)`，subdomain / dirscan
# 阶段每完成一项就要回填（`set_subdomain_net` / `insert_dirs`），峰值是完全可能同时打满的。
# 加锁后并发写退化为"排队执行"（锁内只有 execute + commit，是常数级开销），
# 代价换来的是：**不会再有 OperationalError: database is locked 这类偶发失败**。
# 用 RLock 而非 Lock：`init_db` 等路径内部还会再调到 `_exec`（可重入，避免自锁死）。
_WRITE_LOCK = threading.RLock()

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
  -- 创建该任务时跑流水线的进程 pid（0 = 老库遗留行）：进程重启后靠它识别孤儿任务
  pid INTEGER DEFAULT 0,
  -- 运行时长（续35）：下面三列由 `start_task_run` / `finish_task_run` 维护，
  -- `created_at`/`updated_at` 不能拿来算时长 —— `updated_at` 会被补扫/补截图/复核等**非运行期**
  -- 写入刷新（越等越长），`created_at` 到 `updated_at` 之间还可能夹着几天的停机。
  started_at TEXT DEFAULT '',        -- 最近一次运行的开始时刻
  finished_at TEXT DEFAULT '',       -- 最近一次运行的结束时刻（'' = 还没收场）
  -- 同一任务多次运行（续跑 / 追加执行）的**累计**实际运行秒数，见 `finish_task_run`
  elapsed_seconds INTEGER DEFAULT 0,
  -- 续49「持久化任务队列」：任务不再由 GUI 直接起线程，而是**入队**、由 `scanner/queue.py`
  -- 的 worker 消费 —— 这样进程重启后任务不丢（见 `enqueue_task` / `claim_next_queued`）。
  --   run_mode    ：本次运行模式 fresh / append / resume（''=非队列任务：CLI 直跑、老库行）。
  --                 重启对账靠它判断"该按什么模式重新入队"（见 `reconcile_orphan_tasks`）。
  --   queued_at   ：入队时刻（排队位置、"排了多久"都靠它）。
  --   run_payload ：本次运行的**精确入参**（`{"stages":[...], "options":{...}}` 的 JSON）——
  --                 队列必须能在进程重启后原样重建这一次运行（尤其"追加执行"的运行阶段与
  --                 任务自身的 `stages` **不同**）。刻意与 `options` 分列：`options` 是任务的
  --                 **持久配置**，而 `append_targets` 这类**运行期**参数不能污染它，否则下次
  --                 「重启」会把它误当成追加、把输入收窄成空集（一次都不扫）。
  run_mode TEXT DEFAULT '',
  queued_at TEXT DEFAULT '',
  run_payload TEXT DEFAULT '',
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
CREATE TABLE IF NOT EXISTS certs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id INTEGER NOT NULL,
  url TEXT DEFAULT '',             -- 在哪个站点入口上取到的（同 host:port 可能对应多条 URL）
  host TEXT DEFAULT '',
  port INTEGER DEFAULT 0,
  cn TEXT DEFAULT '',              -- 主体 CN（表格里最好读的一列）
  subject TEXT DEFAULT '',
  issuer TEXT DEFAULT '',
  not_before TEXT DEFAULT '',
  not_after TEXT DEFAULT '',
  days_left INTEGER,               -- 距过期天数（已过期为负）
  expired INTEGER DEFAULT 0,
  self_signed INTEGER DEFAULT 0,   -- 主体与颁发者是同一组 RDN
  san TEXT DEFAULT '',             -- dNSName / iPAddress，逗号连接（已按上限截断）
  serial TEXT DEFAULT '',
  sig_algo TEXT DEFAULT '',
  sha256 TEXT DEFAULT '',          -- 指纹，AA:BB:… 大写冒号格式
  source TEXT DEFAULT '',          -- tls（握手取证；留字段给后续 pem/ct 来源）
  created_at TEXT
);
CREATE TABLE IF NOT EXISTS dirs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id INTEGER NOT NULL,
  site_url TEXT, path TEXT NOT NULL, status INTEGER, length INTEGER,
  method TEXT DEFAULT 'GET', note TEXT,
  title TEXT DEFAULT ''            -- 命中页面的 <title>（仅内置扫描有；dirmap 解析行没有 body 取不到）
);
CREATE TABLE IF NOT EXISTS vulns (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id INTEGER NOT NULL,
  target TEXT, poc_id TEXT, name TEXT, severity TEXT DEFAULT 'medium',
  owasp TEXT DEFAULT '', detail TEXT, evidence TEXT, created_at TEXT,
  review TEXT DEFAULT '',          -- 人工复核（P1-1）：'' 待复核 / confirmed 确认存在 / false_positive 误报
  review_note TEXT DEFAULT '',     -- 复核备注（判误报/确认的理由，进报告附录）
  reviewed_at TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS pocs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  path TEXT UNIQUE NOT NULL,
  poc_id TEXT, name TEXT, severity TEXT DEFAULT 'medium', tags TEXT DEFAULT '',
  enabled INTEGER DEFAULT 1, status TEXT DEFAULT 'ok',
  -- 置信度分层（P1-2）：high/medium/low，由 poc_confidence() 按来源+匹配器结构推导（不是人手填）
  confidence TEXT DEFAULT '',
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
-- 续46 多用户：账号密码登录 + 管理员/子用户两级角色（见 scanner/users.py）。
-- 与上面各表同走 `CREATE TABLE IF NOT EXISTS` —— 老库**原地补表**，不需要删库重建；
-- 新增列时按本文件 `_COLUMN_PATCHES` 的老办法 `ALTER TABLE ADD COLUMN` 追加。
-- `password` 列存的是 `pbkdf2_sha256$<迭代>$<盐>$<哈希>`，**绝不是明文**（同上）。
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  role TEXT DEFAULT 'user',        -- admin / user（见 scanner/users.ROLES）
  enabled INTEGER DEFAULT 1,       -- 0 = 停用（其会话在下一个请求即失效）
  must_change INTEGER DEFAULT 0,   -- 1 = 首次登录强制改口令（管理员建号默认置 1）
  created_at TEXT, updated_at TEXT,
  last_login_at TEXT DEFAULT ''
);
-- 续48 访问审计流水（scanner/audit.py）：谁（actor/actor_role）在何时（at）从哪个 IP（ip）
-- 对什么对象（target）做了什么（kind），成败如何（ok），并附一句人类可读说明（detail）。
-- **只记元数据，绝不记口令/凭据**：写入侧只传"改了哪一块 / 动了哪个对象"，detail 再经 _scrub() 兜底擦洗。
-- 与 users 同走 `CREATE TABLE IF NOT EXISTS` —— 老库**原地补表**，不需要删库重建。
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at TEXT NOT NULL,                -- 'YYYY-MM-DD HH:MM:SS'（与全库 _now() 同格式，可直接字符串比大小）
  kind TEXT DEFAULT '',            -- login_ok/login_fail/login_blocked/logout/account/settings/poc/task/denied
  actor TEXT DEFAULT '',           -- 操作者用户名（登录类事件里是"被尝试的用户名"）
  actor_role TEXT DEFAULT '',      -- admin/user/''（引导口令登录时为空）
  ip TEXT DEFAULT '',              -- 客户端 IP（request.remote_addr；见 docs/deploy-https.md 的 behind_proxy 说明）
  target TEXT DEFAULT '',          -- 被操作对象（任务名 / 账号名 / 资源…）
  detail TEXT DEFAULT '',          -- 补充说明（**已擦洗**，不得含口令/凭据）
  ok INTEGER DEFAULT 1             -- 1 成功 / 0 失败
);
CREATE INDEX IF NOT EXISTS idx_audit_at ON audit_log(at);
-- 续48 登录限速计数（scanner/login_guard.py 专用）：**可变状态**，与只读的 audit_log **刻意分表** ——
-- audit_log 是只追加的审计流水（只按保留期清），限速计数要"成功清用户名计数 / 锁定打标记 / 清过期行"，
-- 两种语义混在一张表里，任一侧改动都会波及另一侧；分表后 `gui.audit` 关掉不影响限速、反之亦然。
-- kind='fail' 记一次失败；kind='lock' 是"已触发锁定"的标记（锁定从该行时刻起持续 lockout_seconds）。
CREATE TABLE IF NOT EXISTS login_fails (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at TEXT NOT NULL,                -- 'YYYY-MM-DD HH:MM:SS'
  ip TEXT DEFAULT '',              -- 失败来源 IP（IP 级判据）
  username TEXT DEFAULT '',        -- 归一后的用户名（用户名级判据；与 users.get_by_name 同口径）
  kind TEXT DEFAULT 'fail'         -- fail / lock
);
CREATE INDEX IF NOT EXISTS idx_login_fails_at ON login_fails(at);
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
    # 建表 + 补列是**多个 DDL 语句**，必须整体串行（否则两个线程同时 ADD COLUMN 会互相撞）
    with _WRITE_LOCK, get_conn() as conn:
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
    # P1-1 误报复核 / P1-2 置信度分层：老库补列（新库由 SCHEMA 直接建出）
    "vulns": {"review": "TEXT DEFAULT ''", "review_note": "TEXT DEFAULT ''",
              "reviewed_at": "TEXT DEFAULT ''"},
    "pocs": {"confidence": "TEXT DEFAULT ''"},
    # 目录命中页的 <title>：老库补列（新库由 SCHEMA 直接建出）
    "dirs": {"title": "TEXT DEFAULT ''"},
    # 孤儿任务对账用：老库补 pid 列（0 = 老库遗留行，一律视为进程已死）
    "tasks": {"pid": "INTEGER DEFAULT 0",
              # 续35「运行时长」：老库补三列（新库由 SCHEMA 直接建出）。
              # 老行的 `started_at` 为空 → `task_run_seconds()` 返回 0、页面显示 `-`（**不编数**）
              "started_at": "TEXT DEFAULT ''", "finished_at": "TEXT DEFAULT ''",
              "elapsed_seconds": "INTEGER DEFAULT 0",
              # 续49「持久化任务队列」：老库补三列（新库由 SCHEMA 直接建出）。
              # 老行的 `run_mode=''` → 重启对账按"非队列任务"处理（仍标 failed，见 `reconcile`）。
              "run_mode": "TEXT DEFAULT ''", "queued_at": "TEXT DEFAULT ''",
              "run_payload": "TEXT DEFAULT ''"},
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
    with _WRITE_LOCK:            # 全框架所有写入的**唯一**收口，见文件头 `_WRITE_LOCK` 说明
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
        "INSERT INTO tasks(name, targets, stages, options, pid, created_at, updated_at) "
        "VALUES(?,?,?,?,?,?,?)",
        (name, targets, ",".join(stages), json.dumps(options or {}), os.getpid(), _now(), _now()))


def update_task(task_id, **fields):
    fields["updated_at"] = _now()
    sets = ", ".join(f"{k}=?" for k in fields)
    _exec(f"UPDATE tasks SET {sets} WHERE id=?", (*fields.values(), task_id))


# ---------- 持久化任务队列（续49）----------
# 设计要点（为什么是"入队 + worker 消费"而不是"直接起线程"）：
# GUI 原来是 `threading.Thread(target=run_task, ...)`，进程一重启线程就没了、任务却仍挂
# `running`（旧实现只能把它标 `failed`）。改成"把这次运行的**入参**写进库 + 置 `queued`"，
# 由 worker 认领执行 —— 重启后对账把死掉的 `running` **重新入队**，任务不丢。
# 队列的**认领**必须原子（`claim_next_queued`）：`runner._register_stop` 是"同 task 覆盖式
# 注册"，若同一任务被两个消费者拿到，第二次会顶掉第一次的停止事件 → 用户点「停止」停不掉。
_QUEUE_MODES = ("fresh", "append", "resume")


def enqueue_task(task_id, mode="fresh", stages=None, options=None):
    """把任务置为 `queued` 并记下本次运行的**精确入参**，等待 worker 认领（续49）。

    - `mode`：`fresh` / `append` / `resume`（非法值一律归一为 `fresh`）。
    - `stages`：本次要执行的阶段列表（**与任务自身的 `stages` 可能不同** —— 追加执行的运行
      阶段就是本次勾选的阶段；续跑则是"断点及其之后"的切片）。
    - `options`：本次运行的选项（含 `append` / `append_targets` 这类**运行期**参数）。

    这两者写进 `run_payload`（JSON）而**不碰任务的 `stages` / `options` 列**：那些列是任务的
    持久配置，被运行期参数污染会让下一次「重启」误判（详见 `tasks` 建表处 run_payload 注释）。
    进程重启后 `reconcile_orphan_tasks` 会把死掉的 `running` 重新入队，`run_payload` 原样还在，
    于是这一次运行能被**逐字重建**。
    """
    m = str(mode or "fresh").strip().lower()
    if m not in _QUEUE_MODES:
        m = "fresh"
    fields = {"status": "queued", "run_mode": m, "queued_at": _now()}
    if stages is not None:
        payload = {"stages": [str(s) for s in stages]}
        if options is not None:
            payload["options"] = options
        fields["run_payload"] = json.dumps(payload, ensure_ascii=False)
    update_task(task_id, **fields)


def claim_next_queued():
    """原子地认领队首任务：把它从 `queued` 置为 `running` 并返回该行；无任务返回 `None`（续49）。

    两步，各有理由：
    1. **只读探一下队首**（`_query`）—— 用只读连接、**不进 `_WRITE_LOCK`**：队列是**空**的绝大多数
       时间（worker 空转），空转时若也去抢那把全库唯一的写锁，就会和 dirscan / portscan 那几百行
       一批的资产写入**争锁**。所以"有没有活"这件事走只读查询。
    2. **一条原子 UPDATE 认领**（`WHERE id=? AND status='queued'`）：只有真正把状态从 `queued`
       改成 `running` 的那一次 `rowcount==1` 才算认领成功 —— 并发下另一个消费者抢到同一行时
       这里会得 0，于是返回 `None`、不重复消费（重复消费会顶掉停止事件，见文件头说明）。
    """
    head = _query("SELECT id FROM tasks WHERE status='queued' ORDER BY id ASC LIMIT 1", one=True)
    if not head:
        return None
    tid = head["id"]
    with _WRITE_LOCK:
        conn = get_conn()
        try:
            cur = conn.cursor()
            cur.execute("UPDATE tasks SET status='running', updated_at=? "
                        "WHERE id=? AND status='queued'", (_now(), tid))
            conn.commit()
            claimed = cur.rowcount == 1
        finally:
            conn.close()
    return get_task(tid) if claimed else None


def queued_position(task_id):
    """该任务在队列里的位置（从 1 开始）；不在队列里返回 0（续49，页面展示用）。"""
    rows = _query("SELECT id FROM tasks WHERE status='queued' ORDER BY id ASC")
    for i, r in enumerate(rows):
        if r["id"] == task_id:
            return i + 1
    return 0


def queued_count():
    """当前排队中的任务数（续49）。"""
    return int(_query("SELECT COUNT(*) c FROM tasks WHERE status='queued'", one=True)["c"] or 0)


def start_task_run(task_id, fresh=False, **fields):
    """记一次运行的**开始**（续35「运行时长」）：置 `running` 并写 `started_at`。

    `fresh=True` = **新建式执行**（CLI 首跑 / GUI「重启」）→ 累计时长清零。理由：「重启」会先
    `clear_task_assets()` 把结果集推翻重来，旧的累计时长与新的结果集不是一回事。而**续跑**
    （续29）与**追加执行**（续25）沿用同一任务、同一份资产 → 累加不清零。

    其余 `fields`（`log_file` / `error` …）与 `update_task` 同义。`started_at` 必须由本模块写：
    它的格式由 `task_run_seconds()` 解析，两处各写一份 strftime 格式串一旦漂移，时长会**静默**算错。
    `finished_at` 一并清空（续49）：一次新运行的开始意味着"上一段的结束时刻"已过期 ——
    不清的话，被队列重新入队后又跑起来的任务会一直显示旧 `finished_at`，页面上的
    「运行中，已 X」不再增长（`task_run_seconds` 见 `finished_at` 非空即只报累计值）。
    """
    fields.update({"status": "running", "progress": 0, "current_stage": "",
                   "started_at": _now(), "finished_at": ""})
    if fresh:
        fields["elapsed_seconds"] = 0
    update_task(task_id, **fields)


def finish_task_run(task_id, ended_at=None, **fields):
    """记一次运行的**结束**（续35）：写 `finished_at`，并把本次用时**累加**进 `elapsed_seconds`。

    为什么是"累加"而不是每次算 `finished_at - started_at`：同一任务会被续跑（续29）与追加执行
    （续25）跑多次，页面要的是"这个任务一共跑了多久" —— 只留最后一段的话，"跑了 20 分钟、
    中断后接着跑 2 分钟"的任务会显示成 2 分钟。

    为什么累加必须在**同一条 UPDATE** 里做算术：与 `append_task_error` 同理 —— "先读 elapsed
    再写回"两步之间没有锁，同一任务的并发收尾会静默丢时长。`MAX(0, …)` 兜住两种脏输入：
    `started_at` 为空（本功能上线前的老行、或被直接调用的 `PipelineRunner`）与时钟回拨，
    二者都记 0 秒而不写负数（`strftime('%s', 空)` 为 NULL，靠 `COALESCE` 退化成 0）。

    `ended_at` 显式指定"结束时刻"（默认当前时间）：**启动对账**（`reconcile_orphan_tasks`）发现
    进程早已不在时，只能用该行最后一次写入的 `updated_at` 当"最后已知存活时刻" ——
    用当前时间会把停机时长也算进去（进程可能几天前就死了）。
    """
    end = str(ended_at).strip() if ended_at else _now()
    sets = "".join(f"{k}=?, " for k in fields)
    _exec(f"UPDATE tasks SET {sets}finished_at=?, "
          "elapsed_seconds = COALESCE(elapsed_seconds, 0) + "
          "MAX(0, strftime('%s', ?) - COALESCE(strftime('%s', started_at), strftime('%s', ?))), "
          "updated_at=? WHERE id=?",
          (*fields.values(), end, end, end, end, task_id))


def append_task_error(task_id, msg):
    """把一条错误信息**追加**到任务的 `error` 字段（`\\n` 分隔），而不是覆盖。

    为什么是追加不是覆盖：`update_task(task_id, error=...)` 是**纯覆盖**写，而流水线的
    阶段级容错**刻意不中断**（一条任务里可能有多个阶段失败）—— 覆盖式写法下，N 个阶段
    失败只有**最后一条**能留下，`runner.run_task` 的外层 except 还会再用 `error=str(e)`
    覆盖一次，前面的错误信息**永久丢失**。追加让"部分跑坏"可回溯、可见。

    `msg` 为空/纯空白时是 **no-op**：避免产生前导分隔符（只留一个 `\\n`）或把 error 写脏。
    这个判断放在**进入 SQL 之前**，空 msg 不会写出一条空行。

    **单条 UPDATE 完成"读-改-写"**：走 `_exec` 即进入 `_WRITE_LOCK`，同时拿到**原子性**与
    写锁保护。旧实现是"先 `get_task` 读、再 `_exec` 写"，两步之间没有锁 —— 同一 `task_id`
    并发追加会**静默丢更新**（实测 16 线程 × 40 次期望 640、实际只剩 43 条）。现有调用点
    虽不可达（阶段循环/外层 except 同线程、reconcile 各 task_id 不同且启动单线程），
    但那是"埋了个陷阱"：任何新增的并发写 error 的调用点都会静默丢错误，故直接消灭。
    `CASE WHEN COALESCE(error,'') = ''` 保证 error 为空时不产生前导分隔符。
    """
    text = str(msg or "").strip()
    if not text:
        return
    _exec("UPDATE tasks SET error = CASE WHEN COALESCE(error, '') = '' THEN ? "
          "ELSE error || char(10) || ? END, updated_at = ? WHERE id = ?",
          (text, text, _now(), task_id))


# Windows `OpenProcess` 失败时的错误码（`GetLastError`），用于 fail-safe 判定。
_WIN_ERROR_ACCESS_DENIED = 5         # 受保护/跨用户进程：**不是**"进程不存在"
_WIN_ERROR_INVALID_PARAMETER = 87    # pid 无效/进程不存在


def _win_open_alive(err):
    """Windows `OpenProcess` **失败**时按错误码做 fail-safe 判定：返回 True = 视为**存活**。

    对用户的承诺是"宁可漏杀不可误杀"（把可能仍在跑的任务误标 `failed` 会掩盖它）：
    - `ERROR_ACCESS_DENIED`（5，权限被拒）→ **存活**（进程在，只是我们无权打开）；
    - `ERROR_INVALID_PARAMETER`（87，pid 无效/不存在）→ 已死；
    - 其它拿不准的错误码 → **存活**（fail-safe，绝不误杀）。

    单独抽成纯函数是为了能直接单测这条判定（真实的"权限被拒"在本机不易稳定构造）。
    """
    if err == _WIN_ERROR_INVALID_PARAMETER:
        return False
    return True


def _pid_alive(pid):
    """判断 `pid` 指向的进程是否仍存活（零依赖、跨平台）。

    - Windows：`OpenProcess(SYNCHRONIZE)` + `WaitForSingleObject(h, 0)`，返回
      `WAIT_TIMEOUT` 即进程仍在运行；句柄必须在 `finally` 里 `CloseHandle`（否则泄漏内核句柄）。
      必须显式声明 `argtypes`/`restype`：默认按 32 位 int 处理会**截断 64 位句柄**。
      `OpenProcess` **失败**时不直接判"已死"，而是按 `GetLastError` 走 `_win_open_alive()`
      （权限被拒/拿不准 → 视为存活，fail-safe 不误杀）。
    - POSIX：`os.kill(pid, 0)` —— `ProcessLookupError` 即进程已死；`PermissionError`
      表示进程存在但无权限（仍算存活）。
    - `pid` 为 0 / None / 非法 → 一律视为已死（老库遗留行没有 pid 语义）。
    """
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return False
    if pid <= 0:
        return False
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes
        SYNCHRONIZE = 0x00100000
        WAIT_TIMEOUT = 0x00000102
        # use_last_error=True：ctypes 在每次调用后把 GetLastError 存到线程局部，
        # 这样 `ctypes.get_last_error()` 才能拿到 OpenProcess 的真实失败原因。
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        kernel32.WaitForSingleObject.restype = wintypes.DWORD
        kernel32.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
        kernel32.CloseHandle.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
        handle = kernel32.OpenProcess(SYNCHRONIZE, False, pid)
        if not handle:
            # 失败 ≠ 已死：权限被拒时按存活处理（fail-safe，见 _win_open_alive）。
            # 注意失败路径**在 try 之前 return**，不调用 CloseHandle（本就没有有效句柄）。
            return _win_open_alive(ctypes.get_last_error())
        try:
            return kernel32.WaitForSingleObject(handle, 0) == WAIT_TIMEOUT
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def reconcile_orphan_tasks():
    """启动时对账：进程重启后把"进程已不在、状态却仍是 `running`"的孤儿任务**重新入队**。

    背景：`runner._STOP_EVENTS` 是**进程内**字典，进程一重启，之前 `status='running'`
    的任务就再也没人推进。续20~续35 的语义是"启动时标 `failed`、不自动续跑"；**续49 起
    用户要求"重启不丢任务"**，于是带队列运行规格的任务改为**自动重新入队**（`status='queued'`），
    由控制台的队列 worker（`scanner/queue.py`）接着跑。

    判据：
    - `pid` 指向**存活进程** → **跳过**（可能另一个进程正在正常跑它，绝不能误杀）；
    - `pid` 已死 / 为 0 **且该行带队列运行规格**（`run_mode` 非空）→ 重新入队；
    - `pid` 已死 / 为 0 **且不带**运行规格（CLI 直跑、老库遗留行）→ 仍标 `failed`：
      这类任务没有持久化的运行入参，且 CLI 是**前台阻塞、根本没有 worker**，重排只会让它
      永远停在 `queued` —— 对它旧语义（明说中断）才是对的，也是既有回归 `[6d]`/`[6v]` 的口径。

    重新入队的运行模式（续49 规则）：
    - 原 `resume` → `resume`；原 `append` → `append`（`run_payload` 已含运行阶段与
      `append_targets`，**注意 `run_task(append=True)` 不按 `current_stage` 切片** —— 追加执行
      本就没有"断点续跑"语义，原样重跑那批阶段即可）；
    - 原 `fresh` + 有断点（`current_stage` 非空）→ `resume`（从断点续跑，不白跑已完成的阶段）；
    - 原 `fresh` + 无断点 → `fresh`（从头跑）。
    **刻意保留 `current_stage`**（续29）：它是"最后进入的阶段"，也就是断点续扫的断点
    （`runner.resume_stages` 按它切片）。清理它由两种显式操作负责：正常跑完与 GUI「重启」。

    **运行时长按"最后已知存活时刻"结账**（续35）：走 `finish_task_run(ended_at=本行原来的
    `updated_at`)` 而不是普通 `update_task`。`updated_at` 是进程死前最后一次写库（阶段切换 /
    进度回填）的时刻，用它当结束时刻能把这段运行的时长**回收**进 `elapsed_seconds`；
    若改用"对账时刻"，进程几天前就死了的话会把停机时长整段算成运行时长。

    整体包一层 try/except：启动流程**不能被它拖垮**（库损坏 / 列缺失都应静默跳过）。
    返回被处理（重新入队或标失败）的任务 id 列表（便于日志与测试断言）。
    """
    handled = []
    try:
        rows = _query("SELECT id, pid, updated_at, run_mode, current_stage "
                      "FROM tasks WHERE status='running'")
        for r in rows:
            if _pid_alive(r["pid"]):
                continue
            tid = r["id"]
            try:
                mode = str(r["run_mode"] or "").strip().lower()
                if mode in _QUEUE_MODES:
                    # 带队列运行规格 → 重新入队（保留 run_payload，worker 能原样重建这次运行）
                    new_mode = mode
                    if mode == "fresh":
                        new_mode = "resume" if str(r["current_stage"] or "").strip() else "fresh"
                    finish_task_run(tid, ended_at=r["updated_at"], status="queued",
                                    run_mode=new_mode, queued_at=_now())
                    append_task_error(tid, "进程重启，任务已重新入队（自动续跑，启动时对账）")
                else:
                    # 无运行规格（CLI 直跑 / 老库行）→ 维持旧语义：标 failed
                    finish_task_run(tid, ended_at=r["updated_at"], status="failed")
                    append_task_error(tid, "进程重启，任务中断（启动时对账）")
                handled.append(tid)
            except Exception:
                continue
    except Exception:
        return handled
    return handled


def get_task(task_id):
    return _query("SELECT * FROM tasks WHERE id=?", (task_id,), one=True)


def list_tasks(limit=200):
    """任务列表（`id DESC`）。

    `limit=None` ＝ **不加上限**（续55）：给"确实要全量"的调用方用（如全端口页的
    任务名映射 —— 那里对 `ports` 做的是**全表** GROUP BY，名称表却只取最新 1000 个任务，
    结果老任务的名字显示为空）。**`limit=0` 仍然是"一条都不要"**，与 `None` 语义刻意区分，
    避免老调用方被静默反转成"全部"。要分页请用 `page_tasks()`。
    """
    if limit is None:
        return _query("SELECT * FROM tasks ORDER BY id DESC")
    return _query("SELECT * FROM tasks ORDER BY id DESC LIMIT ?", (int(limit),))


def find_task_by_name(name):
    """按名字取**最新**的一个任务（无则 None）。`devmode` 用它找 `dev-selfcheck`（续55）。

    原先是在 `list_tasks(limit=200)` 里线性找第一个同名任务 —— 任务数一超过 200，
    自检任务被挤出这 200 条后就"凭空消失"（开发模式页显示"没有自检任务"），
    与本次修的其它几处同源：**固定上限 + 不提示 = 静默失效**。
    """
    return _query("SELECT * FROM tasks WHERE name=? ORDER BY id DESC LIMIT 1",
                  (str(name),), one=True)


def page_tasks(limit=100, offset=0, q=None, status=None, stages=None):
    """任务列表分页查询（续53），返回 `(rows, total)`。

    **为什么要它**：`/tasks` 页原先固定 `list_tasks(limit=200)` —— 任务超过 200 个就**静默丢**、
    界面不提示（与续51 修的漏洞页 `limit=500` 截断同源）。本函数把过滤与分页**全部下推到 SQL**，
    并返回**应用了同样过滤条件**后的 `total`（不是全表数），供分页条显示"共 N 条"。

    过滤口径**对齐原前端 `initTaskTable()`**（`data-tfilter`，逐字段 `String.includes`）：
    - `q`      → `name` / `targets` 子串（`LIKE`，参数两份 `%q%`）；
    - `status` → **精确等值**（前端是下拉框，本就精确）；
    - `stages` → `stages` 列**子串包含**（对齐前端 `includes`，刻意**不**做精确等值）。

    **绝不把用户输入拼进 SQL** —— 进 f-string 的只有常量列名 / 常量 SQL 片段，值一律走 `?` 占位。
    排序恒 `id DESC`（与 `list_tasks` 一致，页面行序**不变**）。`total` 与 `rows` 共用同一组 where，
    保证"共 N 条"与页内行数一致（不重不漏）。
    """
    clauses, params = [], []
    if q:
        clauses.append("(name LIKE ? OR targets LIKE ?)")
        params.extend([f"%{q}%", f"%{q}%"])
    if status:
        clauses.append("status = ?")
        params.append(str(status))
    if stages:
        clauses.append("stages LIKE ?")
        params.append(f"%{stages}%")
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    total_row = _query(f"SELECT COUNT(*) c FROM tasks{where}", tuple(params), one=True)
    total = total_row["c"] if total_row else 0
    rows = _query(f"SELECT * FROM tasks{where} ORDER BY id DESC LIMIT ? OFFSET ?",
                  tuple(params) + (int(limit), int(offset)))
    return rows, total


def _parse_ts(text):
    """把 `_now()` 格式的时间戳解析成 epoch 秒；解不出返回 `None`（**不猜**）。"""
    try:
        return time.mktime(time.strptime(str(text or "").strip(), "%Y-%m-%d %H:%M:%S"))
    except (ValueError, TypeError, OverflowError):
        return None


def task_run_seconds(task, now=None):
    """任务**当前**的累计实际运行秒数（续35）= `elapsed_seconds` + 正在跑的这一段。

    四种情形，页面按 `status` / `finished_at` 分别措辞（见 `gui.app.run_duration_text`）：
    - 从没跑起来（`started_at` 为空：老库遗留行 / 刚建的任务）→ 只报已累计的值（这种行恒为 0）；
    - 本次已收场（`finished_at` 非空：done / stopped / failed）→ 累计值就是答案；
    - 正在跑 → 累计值 + (`started_at` → 现在)；
    - 进程被强杀且**还没被对账**（`finished_at` 为空但不是 `running`）→ 只报已确认的累计值
      （尾段无据可依，不拿"现在"去顶）。

    `task` 传 **dict**（`dict(sqlite3.Row)`，页面里本来就是这么转的）；`now` 是测试注入点。
    """
    try:
        acc = max(0, int(task.get("elapsed_seconds") or 0))
    except (TypeError, ValueError):
        acc = 0
    started = _parse_ts(task.get("started_at"))
    if started is None or str(task.get("finished_at") or "").strip():
        return acc
    if str(task.get("status") or "") != "running":
        return acc
    cur = _parse_ts(now) if now is not None else _parse_ts(_now())
    return acc if cur is None else acc + max(0, int(cur - started))


ASSET_TABLES = ("subdomains", "sites", "ports", "csegs", "certs", "dirs", "vulns", "leads")


def clear_task_assets(task_id):
    """清空某任务的全部资产（子域名/站点/端口/C段/证书/目录/漏洞/线索），用于"重启"前重置。"""
    for t in ASSET_TABLES:
        _exec(f"DELETE FROM {t} WHERE task_id=?", (task_id,))


def _norm_key_val(v):
    """`drop_existing` 自然键的取值归一：`None` → `""`，其余一律 `str()` 化。

    刻意**不用** `v or ""`：那会把 `0`、`None`、`""` 三种值全归一成 `""`，
    于是库里 `port=0` 时，内存侧的 `0` / `None` / `""` 被判成**同一个键** ——
    `certs` 表（自然键 host/port/sha256/serial）里 CT 日志来源的记录常是 `port=0`
    且 sha256/serial 同时为空，同一 host 的多条证书会被合并成 1 条，资产凭空变少。
    这里 `0 → "0"`、`None → ""`、`"" → ""`，0 与空值不再混为一谈。
    """
    return "" if v is None else str(v)


def drop_existing(task_id, table, cols, items, key):
    """过滤掉"该任务该表里**已存在**"的条目 —— 续25「同任务追加式执行」的跨运行去重。

    追加执行时阶段会**第二次**（第 N 次）往同一任务里写资产，若不过滤就会灌入重复行。
    这里按 `cols` 组成自然键、与库里已有行比对：命中即丢弃该条（返回未命中的部分）。

    - `key(item)` 返回组成自然键的元组，顺序与 `cols` 一致；
    - 两侧都 `str()` 化再比 —— SQLite 里 `port` 存的是 int、内存里可能是 str，
      `443` 与 `"443"` 必须算同一个键，否则去重会漏；
    - 两侧**共用同一个** `_norm_key_val()`（库行与内存项不能各写一套、也不能只改一边，
      否则去重直接失效，比原 bug 更糟）：`None → ""`、其余 `str()` 化，
      因此 `0` 与 `None` / `""` **不是**同一个键。
    - **只在"阶段即将 insert"这一步调用**：新任务 / 重启（已清空）时表为空 → 空过滤，
      对既有流程零影响；只有追加执行才有非空交集。
    """
    if not items:
        return []
    have = {tuple(_norm_key_val(r[c]) for c in cols)
            for r in _query(f"SELECT {', '.join(cols)} FROM {table} WHERE task_id=?",
                            (task_id,))}
    if not have:
        return list(items)
    out = []
    for it in items:
        if tuple(_norm_key_val(x) for x in key(it)) in have:
            continue
        out.append(it)
    return out


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
        "certs": count("SELECT COUNT(*) c FROM certs WHERE task_id=?"),
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


def insert_certs(task_id, rows):
    """TLS 证书取证结果。items: `certs.parse_der()` 的返回 + {url, host, port, source}。

    `san` 是列表（dNSName / iPAddress），这里按 `MAX_SAN` 之后再截一次总长：
    一个 IP 直连的站点可能带着几百条 SAN，全塞进页面只会把表格撑爆。
    只写**取证成功**的行（握手失败不进库，只留日志与 certs.txt）——
    与截图阶段同一口径：表里出现的每一行都是"确认拿到的东西"。
    """
    if not rows:
        return
    _exec("INSERT INTO certs(task_id,url,host,port,cn,subject,issuer,not_before,not_after,"
          "days_left,expired,self_signed,san,serial,sig_algo,sha256,source,created_at) "
          "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
          [(task_id, r.get("url", ""), r.get("host", ""), int(r.get("port") or 0),
            r.get("cn", ""), r.get("subject", ""), r.get("issuer", ""),
            r.get("not_before", ""), r.get("not_after", ""), r.get("days_left"),
            int(r.get("expired") or 0), int(r.get("self_signed") or 0),
            ",".join(r.get("san") or [])[:2000], r.get("serial", ""),
            r.get("sig_algo", ""), r.get("sha256", ""), r.get("source", ""), _now())
           for r in rows], many=True)


def insert_dirs(task_id, dirs):
    if not dirs:
        return
    _exec("INSERT INTO dirs(task_id,site_url,path,status,length,method,note,title) "
          "VALUES(?,?,?,?,?,?,?,?)",
          [(task_id, d.get("site_url", ""), d.get("path", ""), d.get("status"),
            d.get("length"), d.get("method", "GET"), d.get("note", ""),
            d.get("title", "")) for d in dirs], many=True)


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
    # 默认排序按"可读性"而非插入顺序（用户 2026-09-23 明确要求）：
    # ① `200` 排最前（403/302 是"路径存在但看不了"，价值低于能直接访问的 200）；
    # ② 同状态码内按**响应大小降序** —— 大响应体更可能是真页面/真文件（备份包、源码泄露），
    #    统一跳转页那种几百字节的小响应自然沉底；
    # ③ 最后才按 id 兜底，保证顺序稳定（分页/折叠结果可复现）。
    return _query("SELECT * FROM dirs WHERE task_id=? "
                  "ORDER BY CASE WHEN status=200 THEN 0 ELSE 1 END, status, "
                  "length IS NULL, length DESC, id", (task_id,))


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


def list_certs(task_id):
    """证书取证结果。默认排序：**异常优先**（已过期 → 自签 → 剩余天数升序）。

    CTF / 授权测试里最该先看的就是"过期"与"自签"（往往是靶机临时自签、或旧版本残留），
    按 id 排会把它们埋在几十行正常证书后面，所以按"可疑程度"排而不是按插入顺序。
    """
    return _query("SELECT * FROM certs WHERE task_id=? "
                  "ORDER BY expired DESC, self_signed DESC, "
                  "CASE WHEN days_left IS NULL THEN 1 ELSE 0 END, days_left, id",
                  (task_id,))


# ---------- 全局资产视图（GUI 资产分栏用） ----------

# 表 -> (默认排序, 可被关键字过滤的文本列)
_ASSET_PAGES = {
    "subdomains": ("task_id DESC, domain",
                   ("domain", "source", "cname", "ip", "cdn", "ip_note")),
    "sites": ("task_id DESC, id DESC", ("url", "host", "title", "server", "tech")),
    "ports": ("task_id DESC, port", ("host", "ip", "service", "banner")),
    "csegs": ("task_id DESC, segment, ip", ("segment", "ip", "domains")),
    "dirs": ("task_id DESC, id DESC", ("site_url", "path", "note", "title")),
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


REVIEW_STATES = ("", "confirmed", "false_positive")   # '' = 待复核


def norm_review(state):
    """归一复核状态：只认 confirmed / false_positive，其余（含 None/未知值）一律当"待复核"。

    单独成一个函数是为了让"API 传进来的任意字符串"永远写不进库 ——
    否则前端传个 `x` 就会造出一条既不属于待复核、也不属于两种结论的幽灵状态。
    """
    s = str(state or "").strip().lower()
    return s if s in ("confirmed", "false_positive") else ""


def set_vuln_review(vuln_id, state, note=None):
    """标记一条漏洞的复核状态（P1-1）。`note` 为 None 表示不改备注，返回受影响行数。"""
    st = norm_review(state)
    now = _now()
    with _WRITE_LOCK:
        conn = get_conn()
        try:
            cur = conn.cursor()
            if note is None:
                cur.execute("UPDATE vulns SET review=?, reviewed_at=? WHERE id=?",
                            (st, now, int(vuln_id)))
            else:
                cur.execute("UPDATE vulns SET review=?, review_note=?, reviewed_at=? WHERE id=?",
                            (st, str(note)[:500], now, int(vuln_id)))
            conn.commit()
            return cur.rowcount or 0
        finally:
            conn.close()


def bulk_set_vuln_review(ids, state, note=None):
    """批量标记复核状态，返回受影响行数（只更新真实存在的 id，不做全表兜底）。"""
    ids = [int(i) for i in (ids or []) if str(i).strip().lstrip("-").isdigit()]
    if not ids:
        return 0
    st = norm_review(state)
    now = _now()
    marks = ",".join("?" for _ in ids)
    # 必须用 `rowcount`，不能用 `_exec` —— 它返回的是 `lastrowid`，在 UPDATE 语句上恒为 0，
    # 那样 `/api/vulns/review` 会一直回 `affected: 0`，前端会以为一条都没改。
    with _WRITE_LOCK:
        conn = get_conn()
        try:
            cur = conn.cursor()
            if note is None:
                cur.execute(f"UPDATE vulns SET review=?, reviewed_at=? WHERE id IN ({marks})",
                            tuple([st, now] + ids))
            else:
                cur.execute(f"UPDATE vulns SET review=?, review_note=?, reviewed_at=? "
                            f"WHERE id IN ({marks})", tuple([st, str(note)[:500], now] + ids))
            conn.commit()
            return cur.rowcount or 0
        finally:
            conn.close()


def review_counts(task_id=None):
    """复核台账：{'pending': n, 'confirmed': n, 'false_positive': n}（供 GUI 概览与报告）。"""
    sql = "SELECT review r, COUNT(*) c FROM vulns"
    params = ()
    if task_id:
        sql += " WHERE task_id=?"
        params = (task_id,)
    out = {"pending": 0, "confirmed": 0, "false_positive": 0}
    for row in _query(sql + " GROUP BY review", params):
        out["pending" if not row["r"] else row["r"]] = row["c"]
    return out


# 漏洞趋势统计用的级别顺序（与 report.SEV_ORDER / GUI 徽标同一套取值）
SEV_LEVELS = ("critical", "high", "medium", "low", "info")


def vuln_trend(limit_tasks=15):
    """漏洞趋势统计：**级别分布** + **最近 N 个任务的逐任务计数**。

    口径与报告一致：**已判误报（`review='false_positive'`）不计入**（否则复核过的噪声
    会在趋势里反复出现，等于把人工复核工作白做）；未知级别归入 `other` 而不是静默丢掉
    （脏数据要看得见）。
    """
    by_sev = {k: 0 for k in SEV_LEVELS}
    by_sev["other"] = 0
    for row in _query("SELECT severity s, COUNT(*) c FROM vulns "
                      "WHERE COALESCE(review,'') <> 'false_positive' GROUP BY severity"):
        by_sev[row["s"] if row["s"] in by_sev else "other"] += row["c"]
    tasks = list(_query("SELECT id, name, created_at FROM tasks ORDER BY id DESC LIMIT ?",
                        (int(limit_tasks),)))
    counts = {}
    ids = [t["id"] for t in tasks]
    if ids:
        marks = ",".join("?" for _ in ids)
        for row in _query(f"SELECT task_id t, severity s, COUNT(*) c FROM vulns "
                          f"WHERE task_id IN ({marks}) "
                          f"AND COALESCE(review,'') <> 'false_positive' "
                          f"GROUP BY task_id, severity", tuple(ids)):
            counts.setdefault(row["t"], {})[row["s"]] = row["c"]
    recent = []
    for t in tasks:
        sev = counts.get(t["id"], {})
        item = {k: sev.get(k, 0) for k in SEV_LEVELS}
        item.update({"task_id": t["id"], "name": t["name"], "created_at": t["created_at"],
                     "total": sum(sev.values())})
        recent.append(item)
    return {"by_severity": by_sev, "total": sum(by_sev.values()),
            "review": review_counts(), "recent": recent}


def list_vulns(task_id=None, severity=None, limit=200, review=None):
    """列出漏洞（`id DESC`）。`review` 三态：None=全部 / "pending"=待复核 / confirmed / false_positive。

    `limit=None` ＝ **不加上限**（续55）：给"要全量、不能漏"的调用方用 —— 报告导出
    （`report.collect`：交付物里少 1000 条以外的东西是**静默丢结果**）与启发式阶段
    （`stages/heuristic`：规则只看最新 1000 条，大任务的结论会失真）。
    **`limit=0` 仍然是"一条都不要"**，与 `None` 语义刻意区分。要分页请用 `page_vulns()`。
    """
    sql, params = "SELECT * FROM vulns WHERE 1=1", []
    if task_id:
        sql += " AND task_id=?"
        params.append(task_id)
    if severity:
        sql += " AND severity=?"
        params.append(severity)
    if review is not None:
        sql += " AND review=?"
        params.append(norm_review(review))
    if limit is None:
        sql += " ORDER BY id DESC"          # 不加上限（续55），与 limit=0（一条都不要）不同
        return _query(sql, tuple(params))
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(int(limit))
    return _query(sql, tuple(params))


def tasks_with_vulns():
    """**有漏洞的任务**（`id DESC`），「漏洞风险」页的任务下拉与「任务」列名用它（续55）。

    为什么不用 `list_tasks()`：那个下拉原先取 `list_tasks(limit=1000)`（最新 1000 个任务），
    任务数一超就**两处都不对** —— 老任务在下拉里**根本选不到**（筛不了），
    且它出现在表格里时「任务」列取不到名字、退化成 `#123`（模板兜底，见 `vulns.html`）。
    这里的口径是"页面上可能出现的行，其任务一定在内"：漏洞表里出现过的 `task_id`
    恰好就是全集，而且规模只跟"有多少任务出过漏洞"相关，不会随任务总数膨胀成几千项的下拉框。
    """
    return _query("SELECT t.* FROM tasks t WHERE t.id IN (SELECT DISTINCT task_id FROM vulns) "
                  "ORDER BY t.id DESC")


# ---------- 漏洞页分页 + 排序（P0，续51） ----------

# 排序白名单：键 = 前端 `sort` 参数，值 = 排序表达式。**只允许这里的常量进 SQL** ——
# 绝不把用户传入的字符串拼进语句（那是 SQL 注入面）。`severity` 用**有序 CASE**：
# 直接 `ORDER BY severity` 是字典序，会排出 high < info < low < medium < critical 这种垃圾顺序
# （取值口径以 `SEV_LEVELS` / GUI 徽标为准）。未知键一律回落 `VULN_SORT_DEFAULT`。
_VULN_SORT = {
    "id": "id",
    "task": "task_id",
    "severity": ("CASE severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 "
                 "WHEN 'medium' THEN 3 WHEN 'low' THEN 2 WHEN 'info' THEN 1 ELSE 0 END"),
}
VULN_SORT_KEYS = ("id", "task", "severity")   # 供 GUI 校验 / 模板高亮（顺序 = 页面列序）
VULN_SORT_DEFAULT = "id"

# 关键字 `q` 参与匹配的文本列（按 `vulns` 表实际列名：name=名称/标题、target=目标 URL、
# poc_id=检查项/POC id）。severity / review / id / task_id 有各自的筛选控件，不进 `q`。
_VULN_Q_COLS = ("name", "target", "poc_id", "owasp", "detail")


def norm_vuln_sort(sort):
    """把外部传入的 `sort` 归一到白名单键；未知 / 非法一律回落默认（`id`）。"""
    s = str(sort or "").strip().lower()
    return s if s in _VULN_SORT else VULN_SORT_DEFAULT


def page_vulns(limit=100, offset=0, q=None, severity=None, review=None, task_id=None,
               sort=None, desc=True):
    """漏洞分页查询（P0，续51），返回 `(rows, total)`。

    **为什么要它**：漏洞页原先固定 `list_vulns(..., limit=500)`，既无分页也无排序 ——
    扫出 800 条只能看到 500 条、界面还不提示，属**静默丢结果**（数据正确性问题）。
    本函数把过滤（severity / review / task_id / 关键字 `q`）与排序**全部下推到 SQL**，
    并返回**应用了同样过滤条件**后的 `total`（不是全表数），供分页条显示"共 N 条"。

    `sort` 只接受 `_VULN_SORT` 白名单键（未知回落默认 `id`），**绝不拼用户输入**；
    `severity` 排序走有序 CASE（见 `_VULN_SORT`）。默认 `id DESC`（最新在前），与旧行为一致。
    次级排序键恒为 `id`，保证同级别 / 同时间的行顺序**稳定**（否则翻页会重复或漏行）。
    `desc` 兼容布尔与字符串（`"0"/"false"/"no"/"off"` 视为升序，其余视为降序）。
    """
    clauses, params = [], []
    if task_id:
        clauses.append("task_id = ?")
        params.append(int(task_id))
    if severity:
        clauses.append("severity = ?")
        params.append(str(severity))
    if review is not None:
        clauses.append("review = ?")
        params.append(norm_review(review))
    if q:
        clauses.append("(" + " OR ".join(f"{c} LIKE ?" for c in _VULN_Q_COLS) + ")")
        params.extend([f"%{q}%"] * len(_VULN_Q_COLS))
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    total_row = _query(f"SELECT COUNT(*) c FROM vulns{where}", tuple(params), one=True)
    total = total_row["c"] if total_row else 0
    if isinstance(desc, str):
        desc = desc.strip().lower() not in ("0", "false", "no", "off")
    direction = "DESC" if desc else "ASC"
    order_by = f"{_VULN_SORT[norm_vuln_sort(sort)]} {direction}, id {direction}"
    rows = _query(f"SELECT * FROM vulns{where} ORDER BY {order_by} LIMIT ? OFFSET ?",
                  tuple(params) + (int(limit), int(offset)))
    return rows, total


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

    `confidence`（P1-2）每次同步都**重算**：它是由来源+匹配器结构推导的客观分层，
    模板内容改了（或分层规则升级了）就该跟着变，与 `enabled`（用户意图）性质不同。
    """
    info = meta.get("info", {}) or {}
    tags = ",".join([str(t) for t in (info.get("tags") or [])])
    path = str(path)
    poc_id = meta.get("id", "")
    name = info.get("name", "")
    severity = info.get("severity", "medium")
    status = meta.get("_status", "ok")
    conf = poc_confidence(path, meta)
    now = _now()
    try:
        # 主路径整段（execute + 取回 id + commit）在同一把写锁内；
        # 下面的老 SQLite 回退分支走 `_exec`（本身已加锁），并发窗口由 IntegrityError 重试兜住。
        with _WRITE_LOCK:
            conn = get_conn()
            try:
                cur = conn.cursor()
                cur.execute(
                    "INSERT INTO pocs(path,poc_id,name,severity,tags,enabled,status,confidence,updated_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?) "
                    "ON CONFLICT(path) DO UPDATE SET poc_id=excluded.poc_id, name=excluded.name, "
                    "severity=excluded.severity, tags=excluded.tags, status=excluded.status, "
                    "confidence=excluded.confidence, updated_at=excluded.updated_at",
                    (path, poc_id, name, severity, tags, default_poc_enabled(path), status,
                     conf, now))
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
            _exec("UPDATE pocs SET poc_id=?, name=?, severity=?, tags=?, status=?, "
                  "confidence=?, updated_at=? WHERE id=?",
                  (poc_id, name, severity, tags, status, conf, now, row["id"]))
            return row["id"]
        try:
            return _exec("INSERT INTO pocs(path,poc_id,name,severity,tags,enabled,status,"
                         "confidence,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                         (path, poc_id, name, severity, tags, default_poc_enabled(path),
                          status, conf, now))
        except sqlite3.IntegrityError:      # 仍然并发冲突 → 退化为更新
            row = _query("SELECT id FROM pocs WHERE path=?", (path,), one=True)
            if row:
                _exec("UPDATE pocs SET poc_id=?, name=?, severity=?, tags=?, status=?, "
                      "confidence=?, updated_at=? WHERE id=?",
                      (poc_id, name, severity, tags, status, conf, now, row["id"]))
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


# 置信度分层（P1-2）：high > medium > low，由**来源 + 匹配器结构**推导，不靠人手填。
CONF_ORDER = ("low", "medium", "high")

_SRC_CONFIDENCE = {"builtin": "high", "user": "medium", "nuclei": "medium",
                   "imported": "low", "other": "low"}

# "证明漏洞"的匹配器类型：判响应内容/长度，而不是只看 HTTP 状态码
_CONTENT_MATCHERS = ("word", "words", "regex", "size", "length")


def _has_content_matcher(meta):
    """POC 是否用**响应内容**做证据（word/regex/size），而不是只判状态码。

    只判 `status: [200]` 的规则在真实站点上几乎必中（404 页、WAF 拦截页、统一跳转页
    都可能回 200），这类规则是误报的主要来源，必须降一级。
    """
    blocks = meta.get("http") or meta.get("requests") or []
    for b in (blocks if isinstance(blocks, list) else []):
        if not isinstance(b, dict):
            continue
        for m in (b.get("matchers") or []):
            if isinstance(m, dict) and str(m.get("type") or "").lower() in _CONTENT_MATCHERS:
                return True
    return False


def poc_confidence(path, meta=None):
    """给 POC 定置信度分层（P1-2）：high / medium / low。

    依据（可复核，不是拍脑袋）：
    ① **来源**：`builtin` 是人工精选的暴露面检查（每条都带内容特征关键字）→ high；
       用户上传 → medium；官方 nuclei 模板 → medium；`tools/import_ref_pocs.py` 从参考项目
       静态导入的**指纹型规则**（`tags: imported/finger`，本意是"识别组件"而不是"证明漏洞"）
       → low；
    ② **结构降权**：没有任何内容匹配器（只判状态码）的规则再降一级（见 `_has_content_matcher`）。

    `meta=None` 表示只有路径、拿不到模板内容（例如从库里读老记录），此时只按来源定级。
    """
    base = _SRC_CONFIDENCE.get(poc_source(path), "low")
    if meta is not None and not _has_content_matcher(meta or {}):
        base = CONF_ORDER[max(0, CONF_ORDER.index(base) - 1)]
    return base


def bulk_set_poc_enabled(enabled, severity=None, source=None, kind=None, only_ok=True,
                         confidence=None):
    """按分类批量开关 POC（POC 管理页的"按分类开关"，避免 312 个逐个点）。

    - severity：critical/high/medium/low/info
    - source：builtin/imported/nuclei/user/other
    - confidence：high/medium/low（P1-2 分层；库里为空的老记录按路径即时补算）
    - kind：全部 / 变更（当前状态与目标状态不同的，便于"只改需要改的"）
    返回被更新的条数。
    """
    rows = _query("SELECT id, path, severity, enabled, status, confidence FROM pocs")
    target = 1 if enabled else 0
    ids = []
    for r in rows:
        if only_ok and r["status"] != "ok":
            continue
        if severity and (r["severity"] or "") != severity:
            continue
        if source and poc_source(r["path"]) != source:
            continue
        if confidence and (r["confidence"] or poc_confidence(r["path"])) != confidence:
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
