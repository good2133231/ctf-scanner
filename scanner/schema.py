# -*- coding: utf-8 -*-
"""SQLite 建表 SQL（续377：从 db.py 抽出，纯数据、零逻辑）。

`db.py` 顶部 `from .schema import SCHEMA` 把名字原样暴露出去，
所以 `db.SCHEMA` 的所有既有引用、门禁里的 SCHEMA 文本比较都不用改。
"""

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
  -- 续79 多租户：任务归属账号（0 = 无归属/老库行，仅管理员可见）。
  owner_id INTEGER DEFAULT 0,
  -- 续176（用户点单"被 min_severity 挡掉的条数要说出口"）：**最近一次 vulnscan 运行**的
  -- 结果闸计数与当时门槛。老库靠 `_COLUMN_PATCHES` 的 ALTER TABLE ADD COLUMN 补；
  -- 老行两列皆空/0 ⇒ 展示侧不渲染（不编数）。放在 created_at/updated_at 之前，
  -- 与 `_COLUMN_PATCHES` 的列序一致。
  sev_floor TEXT DEFAULT '',       -- 该次运行的 checks.min_severity（如 high）
  sev_blocked INTEGER DEFAULT 0,   -- 该次运行"已执行且命中但低于门槛"的条数（未入库）
  -- 续185（主理人点单）：**任务层级**的父任务号（0 = 顶层任务）。
  -- 拓展域名「送去探测」新建的任务挂在这里 —— 那是**子任务**，与「把域名追加成父任务的
  -- 子域名」（资产层，promote_too）是两件事，别混。老库靠 `_COLUMN_PATCHES` 补。
  parent_id INTEGER DEFAULT 0,
  -- 续284（主理人点单「子任务不占编号」）：**门面号**，仅根任务有、连续递增；子任务
  -- 为 NULL（页面显示成 `79-a` 派生编号）。与内部 `id` 解耦 —— 送探子任务消耗 `id` 但
  -- 不消耗门面号，手工任务号保持连续（79 之后是 80，不因子任务跳号）。回填见 _backfill_display_no。
  display_no INTEGER,
  -- 续211-P2-10：具名取消/停止原因（`scanner/cancelcause.py` 的封闭枚举）。
  -- `tasks.error` 照旧是人话（给人读的），这一列是给机器判的 —— 两不重复、不互推。
  -- 空串 = 正常跑完（done）或压根没被取消。老库靠 `_COLUMN_PATCHES` 补。
  stop_reason TEXT DEFAULT '',
  -- 续360：跨进程停止请求（1 = 正在跑这个任务的进程应在下一个检查点收场）。
  -- 停止请求必须落库：5000/5099 共库，进程内 Event 传不过去。新 run 由 start_task_run 清零。
  stop_requested INTEGER DEFAULT 0,
  -- 续215-P2-12：**最近一次运行**的单任务资源画像（`scanner/profiling.py`）。
  -- `cpu_seconds` / `cpu_ratio` 是进程 CPU 时间与"几个核"；`peak_rss_mb` 是采样峰值；
  -- `worker_hint` 是 `profiling.suggest_workers` 的建议并发（只会 ≤ 配置值）。
  -- 老行全 0 ⇒ 页面不渲染（不编数）。**覆盖写**：与 sev_blocked 同口径，最近一次运行说了算。
  cpu_seconds REAL DEFAULT 0,
  cpu_ratio REAL DEFAULT 0,
  peak_rss_mb REAL DEFAULT 0,
  profile_wall_s REAL DEFAULT 0,
  worker_hint INTEGER DEFAULT 0,
  profiled_at TEXT DEFAULT '',
  created_at TEXT, updated_at TEXT
);

CREATE TABLE IF NOT EXISTS subdomains (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id INTEGER NOT NULL,
  domain TEXT NOT NULL,
  source TEXT DEFAULT '',
  cname TEXT DEFAULT '',
  ip TEXT DEFAULT '',
  cdn TEXT DEFAULT '',
  note TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS sites (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id INTEGER NOT NULL,
  url TEXT NOT NULL, host TEXT, port TEXT,
  status INTEGER, title TEXT, length INTEGER, server TEXT, tech TEXT,
  tech_detail TEXT DEFAULT '',      -- 续223：标签来源（JSON：[{t,src,origin}]，src=doc/js、
                                    --   origin=builtin/external/unknown；页面据此分主次）
  source TEXT,
  favicon TEXT DEFAULT '',
  redirect_url TEXT DEFAULT '', redirect_status INTEGER DEFAULT 0,
  redirect_title TEXT DEFAULT '', shot_error TEXT DEFAULT '',
  shot_last_at TEXT DEFAULT '',         -- 续218：最近一次截图尝试时间（轮转用）
  page_hash TEXT DEFAULT '',           -- 续337：根页面归一化正文 SHA1（probe 顺手算）
  page_simhash TEXT DEFAULT '',        -- 续337：64 位 SimHash 十六进制（近重复判定）
  same_app_of TEXT DEFAULT ''          -- 续337：同功能代表站 URL（非空 ⇒ 跳过目录/漏洞）
);
CREATE TABLE IF NOT EXISTS ports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id INTEGER NOT NULL,
  host TEXT, ip TEXT, port INTEGER, service TEXT DEFAULT '', banner TEXT DEFAULT '',
  -- 续331：资产来源（portscan / fofa，空串按 portscan 显示）
  source TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS csegs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id INTEGER NOT NULL,
  segment TEXT DEFAULT '',
  ip TEXT DEFAULT '',
  domains TEXT DEFAULT '',
  note TEXT DEFAULT '',
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
  title TEXT DEFAULT '',           -- 命中页面的 <title>（仅内置扫描有；dirmap 解析行没有 body 取不到）
  dict_src TEXT DEFAULT ''         -- 续222：这一行来自哪份字典（`dirs_php` / `dirsearch/api`…
                                  -- 只放**字典名/分类名**，绝不放绝对路径 —— 报告是交付物）
);
-- 续198（主理人点单「加个爬虫，获取和网站相关的链接」）：与 `dirs` 是**两件事**，别合并 ——
--   `dirs` 是**字典猜出来的路径**（我们要证明它存在），`urls` 是**页面里本来就写着的链接**
--   （它一定存在，是站点自己暴露的面）。合并会让"猜中了几条"和"站点有多少入口"混成一个数。
--   `query` 非空 = **带参链接**（注入面），漏洞检测只对这一类下钻（见 `stages/vulnscan.py`）。
--   `method` 只**记录** `<form method=...>`：POST 表单**永远不提交**（§1 非破坏性红线），
--   写下来只是让人知道"这里有个表单入口"。
--   去重是**调用方**责任（§5.6 同一口径），表上不加 UNIQUE。
CREATE TABLE IF NOT EXISTS urls (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id INTEGER NOT NULL,
  site_url TEXT DEFAULT '',      -- 从哪个站点/页面爬出来的（溯源用）
  url TEXT NOT NULL,             -- 绝对 URL（已归一化：去掉 #fragment）
  host TEXT DEFAULT '',
  path TEXT DEFAULT '',
  query TEXT DEFAULT '',         -- 查询串（不含 '?'）；非空即"带参"
  method TEXT DEFAULT 'get',     -- link 恒为 get；form 按页面写的记（不提交）
  depth INTEGER DEFAULT 0,       -- 0=站点首页上发现的，1=再跟一层
  status INTEGER DEFAULT 0,      -- 0 = 没探测过（爬虫默认**不逐个探测**，见 crawl.probe 开关）
  title TEXT DEFAULT '',
  length INTEGER DEFAULT 0,
  kind TEXT DEFAULT 'link',      -- link（<a>/<link>） / form（<form action>） / redirect（3xx 目标）
  source TEXT DEFAULT 'crawl',
  note TEXT DEFAULT '',          -- 被跳过/降级的理由（外链 / 非 HTTP / 超上限 / 重复）
  created_at TEXT
);
CREATE TABLE IF NOT EXISTS vulns (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id INTEGER NOT NULL,
  target TEXT, poc_id TEXT, name TEXT, severity TEXT DEFAULT 'medium',
  owasp TEXT DEFAULT '', detail TEXT, evidence TEXT, created_at TEXT,
  review TEXT DEFAULT '',          -- 人工复核（P1-1）：'' 待复核 / confirmed 确认存在 / false_positive 误报
  review_note TEXT DEFAULT '',     -- 复核备注（判误报/确认的理由，进报告附录）
  reviewed_at TEXT DEFAULT '',
  -- 续143：可复核的请求/响应摘要（请求行、状态与长度、关键响应头、正文指纹）。
  -- 为什么单独一列而不塞进 evidence：evidence 是给人读的一句话结论，packets 是
  -- 「凭什么这么说」的原始材料；挤在一列里页面就没法只展开后者（用户原话：数据包都没有）。
  -- 位置刻意放在**最后一列**：老库靠 `_COLUMN_PATCHES` 的 ALTER TABLE ADD COLUMN 补，
  -- 新建库与迁移库的列序必须一致，否则 `SELECT *` 两种库给出不同形状。
  packets TEXT DEFAULT '',
  -- 续150（用户点单「漏洞独立复测三态」）：'' 未复测 / reproduced 仍可复现 /
  -- fixed 已修复 / unconfirmed 无法确认（本次没探到该目标）。放**最后一列**，
  -- 与 `_COLUMN_PATCHES` 的列序一致，否则老库/新库 `SELECT *` 形状不同。
  retest_state TEXT DEFAULT '',
  retested_at TEXT DEFAULT ''
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
-- 续126 建表、续148 装的东西扩到敏感信息（scanner/flagfind.py）：**单独一张表**，不并进 vulns ——
-- 一个 `flag{...}` 或一串 AK 既不是漏洞结论（不该进「潜在漏洞」计数与复核台账），也不是线索
-- （线索是"人再决定要不要看"的东西，而这两类是要直接抄走的）。混进哪一边都会误导。
-- `value` 保留**原文大小写**（取值大小写敏感；被小写化的只是用于定位的那份副本）；
-- 存原文 ⇒ 这张表**默认不进迁移包**（`scanner/migrate.py::SECRET_TABLES`，要带得显式 `--with-secrets`）。
-- `context` 带前后文，因为同一形状经常是模板/JS 里的占位符，判真假日的是人不是模块。
-- 去重在**调用方**（scanner/flagfind.py::harvest），表上没有 UNIQUE 约束 —— 与 AGENTS §5.6
-- 「漏洞去重是调用方约定」同一口径：新增写路径必须自己保证不重复。
CREATE TABLE IF NOT EXISTS flags (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id INTEGER NOT NULL,
  value TEXT NOT NULL,
  kind TEXT DEFAULT '',        -- 命中的形状名（aws-access-key / jwt / flag / ctf / …）；自定义正则记 "regex"
  source TEXT DEFAULT '',      -- probe / js / dir / poc：**哪个阶段手里的那份正文**
  url TEXT DEFAULT '',
  context TEXT DEFAULT '',
  created_at TEXT
);
-- 续177 JS 凭据**原文**表（主理人 2026-10-14 点单"显示具体值 + 复核 + 值级黑名单"）：
-- 存原文的只有这一张表 —— vulns 里的 `js-secret-*` 行照旧只存掩码（evidence/packets），
-- 报告与迁移包沿用它；原文的可见面按 AGENTS.md §5.10 凭据红线新解（2026-10-14 续176）：
-- 授权目标身上挖到的是**扫描产物**，入库（本库 gitignore）、GUI 展开看、默认不进迁移包。
-- `masked` 是 `jsmine._masked(raw)` 的唯一落地列（与 vulns evidence 同键同值，GUI 靠它对齐两表）；
-- 去重在调用方（§5.6 同 flags/vulns），表上无 UNIQUE。
CREATE TABLE IF NOT EXISTS js_secrets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id INTEGER NOT NULL,
  host TEXT DEFAULT '',        -- 来源主机名（与 vulns.target 同键，[8bj] 去重键的一半）
  type TEXT DEFAULT '',        -- 命中的形状名（aws-access-key / jwt / …）
  value TEXT NOT NULL,         -- **原文**（凭据红线新解，见上）
  masked TEXT DEFAULT '',      -- 掩码形态（jsmine._masked 唯一产地）
  source TEXT DEFAULT '',      -- 命中它的 JS URL
  context TEXT DEFAULT '',
  line INTEGER DEFAULT 0,
  line_text TEXT DEFAULT '',
  created_at TEXT
);
-- 续178「送去探测」的送探记录：哪个域名、从哪个任务、送到哪个任务、哪种方式。
-- 手工送探（api_scan_ext 新建任务 / 追加执行）与"归属追加"（api_promote_domains）都记一行
-- —— extdomains 页的「已送探 → #N」徽章与组内送探子标签都从这张表出（主理人：
-- "不管是手工还是置信度自己去扫描，都要标记扫描"；自动递归发生在同一任务内，
-- 其痕迹就是 subdomains 行本身，不在此表）。
-- 任务关联数据（跨任务）⇒ **不进 ASSET_TABLES**；不设外键 —— 任务删除不级联，
-- 历史记录保留，页面按任务存在与否降级显示。
-- 续184「数据探测」：邮箱等从正文里顺带抽出来的产物（用户 2026-10-14 点单）。
-- 是**任务关联资产** ⇒ 进 ASSET_TABLES（重启重置 / 迁移包口径一致）；只记「在哪份正文
-- 里见过它」，**不验证**（不发验证邮件、不查 MX）。
CREATE TABLE IF NOT EXISTS emails (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id INTEGER NOT NULL,
  email TEXT NOT NULL,       -- 原文（域名部分已小写归一）
  domain TEXT DEFAULT '',    -- 域名部分：页面按它分组统计
  source TEXT DEFAULT '',    -- 出处（JS / 页面的 URL）
  created_at TEXT
);

CREATE TABLE IF NOT EXISTS ext_probes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  domain TEXT NOT NULL,
  from_task INTEGER DEFAULT 0,  -- 从哪个任务的拓展域名页送出（0=跨任务视图）
  task_id INTEGER DEFAULT 0,    -- 送到哪个任务（probe=新建任务；append=源任务自身）
  kind TEXT DEFAULT 'probe',    -- probe / append / promote
  created_at TEXT
);
-- 续177 值级黑名单（与 config/blacklist.txt 的**域名级**黑名单是两件事，见 scanner/secretbl.py）：
-- 挡的是凭据 / flag **值**（匹配之后），整值精确比对、大小写敏感；按账号隔离（0=全局，
-- 仅管理员可写），任务无关 ⇒ **不进 ASSET_TABLES**（clear_task_assets 按任务清，清不掉它）。
CREATE TABLE IF NOT EXISTS secret_blacklist (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  value TEXT NOT NULL,         -- 原文整值（strip 后比对）
  kind TEXT DEFAULT '',        -- 命中的形状名（可空）
  note TEXT DEFAULT '',        -- 用户注：为什么这是误报
  owner_id INTEGER DEFAULT 0,  -- 0=全局；其余=该账号私有（续46 同款口径）
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
  actor_role TEXT DEFAULT '',      -- admin/user/''（登录失败这类无身份事件为空）
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
-- 续116：资产表补 `task_id` 索引。按任务过滤是**每一条**读取路径的公共条件（任务详情页的
-- 10 个页签、跨任务资产页、`task_counts_bulk` 的 10 条 GROUP BY、`delete_task` 的批量删、
-- 去重用的 `drop_existing`），而此前全库只有 audit_log / login_fails 两张表有索引 ——
-- 于是每条查询都是 SCAN 整表 + TEMP B-TREE 排序。实测（30000 行的 dirs 表）：
-- COUNT 形态 20 次 71 ms → 5 ms，详情页签的分页形态 34 ms → 9 ms。
-- 与建表同口径用 `IF NOT EXISTS`：老库启动时原地补，不需要删库重建。
CREATE INDEX IF NOT EXISTS idx_subdomains_task ON subdomains(task_id);
-- 续360：OVERLAP_EXT_WHERE 的相关子查询按 (domain, source) 查 own；没有这条索引，
-- 每条外层行仍会扫整张 subdomains。
CREATE INDEX IF NOT EXISTS idx_subdomains_domain_source ON subdomains(domain, source);
CREATE INDEX IF NOT EXISTS idx_sites_task ON sites(task_id);
CREATE INDEX IF NOT EXISTS idx_ports_task ON ports(task_id);
CREATE INDEX IF NOT EXISTS idx_csegs_task ON csegs(task_id);
CREATE INDEX IF NOT EXISTS idx_certs_task ON certs(task_id);
CREATE INDEX IF NOT EXISTS idx_dirs_task ON dirs(task_id);
CREATE INDEX IF NOT EXISTS idx_vulns_task ON vulns(task_id);
CREATE INDEX IF NOT EXISTS idx_leads_task ON leads(task_id);
CREATE INDEX IF NOT EXISTS idx_flags_task ON flags(task_id);
"""
