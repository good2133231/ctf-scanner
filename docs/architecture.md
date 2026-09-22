# 架构说明

## 分层

```
┌────────────────────────────────────────────────────────────┐
│  入口层    cli/client.py（全自动批处理）   gui/app.py（控制台） │
├────────────────────────────────────────────────────────────┤
│  编排层    scanner/runner.py                                │
│            StageContext（上下文/取消信号） + PipelineRunner   │
│            协作式取消：request_stop / is_stopped（终态 stopped）│
├────────────────────────────────────────────────────────────┤
│  阶段层    scanner/stages/                                  │
│            subdomain（+ wildcard/passive）→ takeover →       │
│            portscan（默认关）→ probe → screenshot（默认关）→   │
│            osint（默认关）→ jsmine → dirscan（默认关）→       │
│            vulnscan → intel / heuristic（默认关，只产"线索"）  │
│            （11 个阶段，见 runner.STAGE_ORDER）               │
│  资产层    scanner/dnsq.py（DNS 客户端）                      │
│            scanner/cdn.py（CDN 判定：CNAME 后缀匹配厂商名单）  │
│            scanner/takeover.py（子域接管指纹 41 条）           │
│            scanner/portscan.py（fscan/nmap 优先 + 内置 connect 兜底）│
│            scanner/screenshot.py（本机无头 Edge/Chrome 截图）  │
│            scanner/iprecon.py（IP 反查域名 + /24 C 段归纳）    │
│            scanner/fofa.py + mmh3.py（favicon/证书反查 + 阈值排除）│
│            scanner/jsmine.py（JS 域名/接口/疑似凭据挖掘）       │
│            scanner/intel.py（CISA KEV 情报 × 本地指纹白名单匹配）│
│            scanner/heuristics.py（零请求差分/异常聚合，产线索）  │
│            scanner/blacklist.py（用户黑名单：入库前过滤）      │
│            scanner/portscan.py::parse_ports(max_span)（防手滑全端口）│
│  检测层    scanner/pocs/engine.py（POC 引擎，nuclei 兼容子集）│
│            scanner/owasp/checks.py（启发式检查 + 三级门控）    │
│  伪装层    scanner/evasion.py（HTTP 出口统一伪装 + payload 变形）│
├────────────────────────────────────────────────────────────┤
│  基础层    utils（HTTP/命令/线程池/DNS/IO/路径相对化） config log │
│  存储层    scanner/db.py → SQLite（data/scanner.db，可用        │
│            CTFSCANNER_DB 覆盖路径；任务工作目录用 CTFSCANNER_LOGS）│
└────────────────────────────────────────────────────────────┘
```

`scanner/evasion.py` 是**所有 HTTP 出口的统一伪装层**：`utils.http_request` → `_headers()` → `evasion.browser_headers()`
（UA 随机化、浏览器化请求头、可选 XFF 伪装）；注入类检查再叠加 `evasion.mutate_sqli/mutate_xss` 的 payload 变形。
`scanner/wildcard.py`（泛解析识别/过滤）与 `scanner/passive.py`（免 key 多来源被动收集）只在 subdomain 阶段被调用。
`scanner/dnsq.py` 是纯标准库 DNS 客户端（takeover 阶段用它拿 CNAME 链，不依赖外部命令）。
`scanner/cdn.py` 同样是**只读加载 + 纯字符串匹配**：读 `config/dicts/cdn_cname.txt` 的 292 条厂商后缀，
按 CNAME 链判定"CDN / 直连源站"（数据文件缺失时一律判非 CDN），供 `subdomain` 阶段回填 `subdomains.cdn`。
`scanner/mmh3.py` 是**纯标准库**的 MurmurHash3 x86_32 实现 —— 第三方平台（FOFA `icon_hash`、
Shodan `http.favicon.hash`）的 favicon 指纹统一用 mmh3 **而不是 MD5**，而 `mmh3` 包是 C 扩展、
离线环境装不上，故自实现并附公开已知向量自检。MD5（`sites.favicon`）仍用于我们自己的零请求前置判定，
两者分工不重叠。
`scanner/blacklist.py` 是**用户黑名单**（纯文本 `config/blacklist.txt`，一行一个域名、`#` 注释）：
在 subdomain / jsmine / osint 三个阶段**入库前过滤**（命中的域名连其子域一起丢弃），
因此黑名单里的目标后续 takeover / probe / dirscan / vulnscan 都不会扫到 —— 语义是"不入资产库"而非"入库打标"。
文件每次调用都重读、不缓存，改完立即生效。
`utils.rel_display(path)` 是**展示层**的相对化工具：把项目内绝对路径转成相对项目根的 POSIX 形式
（`logs/task_1_x/task.log`），项目外路径与空值原样返回；CLI / GUI / 报告对外显示路径都走它，
不向外暴露本机绝对目录。

## 关键设计决策

| 决策 | 理由 | 代价 |
|---|---|---|
| 外部工具优先 + 内置兜底 | 你的手工流水线效果最好时用原工具；任何裸机也能跑通框架 | 兜底实现能力弱于本体 |
| SQLite 单文件 | 零部署成本，单机 CTF 场景足够 | 不支持多节点并发写，需要时替换 db.py 即可 |
| Flask + 后台线程 | GUI 只做"发任务 + 看结果"，逻辑全部复用核心引擎 | 无任务队列，进程重启则运行中任务中断 |
| POC 引擎向 nuclei 语法靠拢 | 社区事实标准（数千模板、可直接加载官方模板），声明式 YAML、无外部依赖 | 仅兼容核心子集（raw/dsl/flow/workflows 不支持） |
| 启发式检查全部 GET + 无破坏 payload | 控制误伤与法律风险 | 检出率有限，定位是"初筛信号" |
| 分级门控（`skip_severities` 执行级 + `min_severity` 结果级，默认 info/low 不执行、门槛 medium） | 默认屏蔽低危/info 噪声，连请求都不发，只留能拿 flag 的高位结果 | 想广谱信息收集需**同时**放宽级别开关与门槛 |
| **阶段级 `enabled` 总开关**（`takeover`/`jsmine`/`dirscan`/`vulnscan` 默认开，`portscan` 默认关、`osint` 由 `iprecon`/`fofa` 两个子开关代替；`subdomain`/`probe` 刻意不设） | 用户要求"大功能都要有按分类的总开关"；关掉即整阶段跳过、连请求都不发，便于按需裁剪（如"只做资产测绘不探测"） | 开关分散在各段，新增阶段必须记得补 `enabled` 与 GUI 复选框（`tests/smoke.py` 的 `[3d]`/`[5b]` 已加断言防漏） |
| 动态免杀（evasion）只改变 payload 编码形态与请求伪装 | 提升隐蔽性与 WAF 绕过率，同时不越过非破坏性红线 | 变形不改变语义，对非规则型 WAF 效果有限 |
| 指纹用自研精简规则表（scanner/fingerprint.py） | 无外部依赖；httpx 缺失时也能填充 sites.tech | 规则少、只给组件标签不解析版本 |
| 外部情报（osint）默认全关，且"两个子开关都关＝一次请求都不发" | 依赖第三方公共接口（api.webscan.cc / FOFA），可用性不由我们掌控；不配置就不该有网络行为 | 想用 C 段/favicon 拓展需先去「策略配置 → 外部情报拓展」显式打开 |
| mmh3 自实现（`scanner/mmh3.py`）而非引入 mmh3 包 | 平台指纹的社区统一键就是 mmh3；C 扩展包在离线 CTF 环境装不上 | 只实现社区在用的 `x86_32`，未做 128 位变体 |
| 目录扫描**默认关** + 只扫不重复站点 + 单站点 `max_paths` 节流 | 目录爆破是全流水线请求量最大的一段（大字典 15333 条），而多数 CTF 拿分不靠它；不重复站点（同任务内标题+长度相同）是同一主机的别名，扫了也是白扫 | 想用必须显式打开；大字典必须配 `max_paths`，否则一个站点就要打到天亮 |
| 全端口扫描走**任务选项**（`portscan_full`）而不是全局开关 | 6.5 万端口逐连接是分钟级，改成全局 `portscan.mode=full` 会让每个任务都变慢 | GUI 只提供"对勾选 IP 发起"的入口；任务列表会多出只跑 portscan 的任务行 |
| 用户黑名单**入库前过滤**（`scanner/blacklist.py`）而非入库打标 | 命中即不进资产库，后续阶段自然不扫；不必在每个阶段重复判"要不要跳过"，也不会被历史数据干扰 | 已入库的历史资产不受影响（需手动删任务）；`config/blacklist.txt` 为纯文本、需人工维护 |
| 重叠资产**默认隐藏**（拓展域名域名级全局 / 站点 URL 级跨任务） | 反复扫同一目标时列表不被撑成 N 倍；默认视图是"新发现"，全量用 `?all=1` 显式打开 | 判重是"保留最早一条"，后扫到的新信息（如状态码变化）不会覆盖旧行 |
| 批量跑子域名**新建任务**而非挂子任务 | 现有任务模型（一任务一线程 / 独立状态 / 独立停止删除）可直接复用 | 任务列表会多出一行；无法在一个树里聚合查看（收益不抵改表结构 + 任务树渲染的成本） |

## 数据流

1. 用户通过 CLI（`-f` 文件）或 GUI（文本框/上传文件）提交目标；
2. `targets.parse_lines` 把每行归一化为 `("domain"|"url"|"ip"|"unknown", raw)`；
   CIDR（上限 256 个地址）在这一步展开为多条 `("ip", …)`，超限整体丢弃；
3. `runner.run_task` 创建任务工作目录 `LOGS_DIR/task_<id>_<ts>/`，绑定日志，按顺序执行启用的阶段；
   `LOGS_DIR` 取自 `scanner/config.py`，默认 `BASE_DIR/logs`，可用环境变量 `CTFSCANNER_LOGS` 覆盖
   （测试/并行开发时指向临时目录，真实工作区不被污染）；数据库同理支持 `CTFSCANNER_DB`；
4. 每个阶段把结果同时写入三处：任务工作目录的文本产物、SQLite、`ctx.results`（供下一阶段直接使用）；
5. GUI 通过 `tasks` 表轮询状态（status/progress/current_stage），详情页从 SQLite 读资产与漏洞。

## 数据库表

| 表 | 字段要点 | 说明 |
|---|---|---|
| tasks | targets, stages, options, status, progress, current_stage, log_file, error | 任务状态机：pending → running → done/stopped/failed |
| subdomains | domain, source, cname, ip, cdn | source 标记来源：**目标自身**（subfinder / puredns / dns-brute(fallback) / passive:\*）与**拓展域名**（js:mine / osint:cseg / osint:fofa / osint:fofa-cert）两类；cname 由 takeover 阶段回填，ip / cdn 由 subdomain 阶段回填（cdn 为空即"非 CDN"）。两类在 GUI 分栏展示，SQL 判据是 `db.OWN_SUBDOMAIN_WHERE` / `db.EXT_SUBDOMAIN_WHERE`；拓展域名页默认隐藏重叠（`db.OVERLAP_EXT_WHERE`：域名已存在于任意任务的"目标自身子域名"里） |
| sites | url, host, port, status, title, length, server, tech, favicon, shot, source | 存活站点（probe 阶段产出）；favicon 为 MD5，供 POC 零请求前置判定；shot 为截图相对路径（screenshot 阶段回填，默认关） |
| ports | host, ip, port, service, banner | 端口与服务（portscan 阶段产出，该阶段默认关闭） |
| csegs | segment, ip, domains, count | `/24` C 段视野（osint 阶段产出，默认关闭）：每行一个 IP 与其反查到的域名（domains 截断存储、count 为截断前数量） |
| dirs | site_url, path, status, length, note | 目录发现（dirscan 阶段产出；`length` 即返回包大小，页面按它折叠重复长度） |
| vulns | target, poc_id, name, severity, owasp, detail, evidence | 统一存放 POC 命中与 OWASP 检查结果 |
| leads | task_id, kind, code, title, target, matched, level, detail, source, url | **「线索」**（intel / heuristic 两个默认关阶段产出）：`kind` 区分情报/启发式，`level` 只用于排序着色、**不是漏洞级别**。**不是漏洞结论** —— 不进 `vulns`、不计入漏洞数、不自动导入 POC；GUI 单独页签、报告单独附录 |
| pocs | path(唯一), poc_id, name, severity, tags, enabled, status | POC 注册表：由扫描目录同步生成，GUI 控制启停 |

**老库原地迁移**：`db._ensure_columns()` 用 `ALTER TABLE ADD COLUMN` 给已存在的库补齐新增列
（如 `subdomains.ip` / `subdomains.cdn`），不需要删库重建；`data/` 不入 git，各人本地库版本可以不同。

## GUI 路由与分栏

侧边栏 **9 栏**（以 `gui/templates/base.html` 的 `nav_items` 为准）：
`/`（仪表盘）/ `/tasks` / `/subdomains`（**只列目标自身子域名**，可勾选批量加黑名单 / 批量跑子域名）/
`/sites`（默认折叠重复站点，`?all=1` 看全部）/ `/ips`（IP 资产）/ `/fullports`（全端口扫描）/
`/vulns`（级别筛选 + `?task_id=` 按任务筛选）/ `/pocs` / `/settings`。
`/ports` / `/csegs` / `/dirs` / `/extdomains`（JS 与情报带出的拓展域名，**默认隐藏重叠**，`?all=1` 看全部）
四条路由**仍在**（可直接访问 URL），但**已从侧边栏移除** ——
前三条是任务维度数据，在任务详情页签里看更贴合上下文；`/extdomains` 与 `/subdomains` 是同一份
`subdomains` 表的不同视图，单列一栏反而让人分不清资产归属。这是用户明确要求的收敛。
筛选/分页统一走 `db.page_assets(table, limit, offset, q, extra_where, extra_params)`：
`extra_where` 用于叠加业务条件（子域名分流、CDN 标签、重叠隐藏），`q` 是跨文本列的 LIKE。
来源列统一走 `gui/app.py::source_label()`（`subfinder → 被动(subfinder)`、`passive:x → 被动(x)`、
`osint:fofa → FOFA·ICO 反查`、`osint:fofa-cert → FOFA·证书反查` …），模板里以
`app.jinja_env.globals["source_label"]` 注册；未知来源原样返回，不吞信息。
「策略配置」页由 **9 个可折叠面板**组成（默认全折叠，展开状态存 `localStorage`，页顶有全部展开/折叠），
面板切换与勾选交互在 `gui/static/app.js`（`initCollapsiblePanels` / `initPickAll`）。

## 扩展点

- **新增阶段**：在 `scanner/stages/` 建一个 `Stage` 子类（实现 `name` 与 `run()`），到 `runner.STAGE_REGISTRY` 注册即可被 CLI `-p` 与 GUI 复选框识别；
- **新增 POC**：把 YAML 放进 `scanner/pocs/pocs/`（内置）、`config/pocs-user/`（用户上传）、`config/pocs-imported/`（批量导入，**默认关闭**）或 `config/nuclei-templates/`（官方 nuclei 模板投放点），控制台「重新扫描 POC 目录」或重启即生效；含 `raw`/`dsl`/`flow`/`workflows` 的模板会被标记 `unsupported`；
- **接入 nuclei**（可选）：引擎已兼容 nuclei 模板核心子集，官方模板可直接投放加载；若仍需 nuclei 二进制的完整能力，可在 vulnscan 阶段加适配器，把 sites 导出为 `-l` 文件调用 nuclei，结果解析回 `vulns` 表；
- **替换存储/队列**：`db.py` 与 `runner.run_task` 是唯一边界，替换后 CLI/GUI 不用动。

## 线程模型

- GUI：Flask 请求线程 + 每任务一个 daemon 线程（`threading.Thread(run_task)`）；
- 扫描内部：`utils.pool_run` 线程池，阶段级并发（探测/目录/漏洞扫描），站点内检查串行；
- **协作式取消**：`runner` 维护 task_id → `threading.Event` 的取消表，`request_stop` 置位、阶段在循环边界
  调 `ctx.stopped()` 主动退出，终态记为 `stopped`（粒度是"当前批次跑完即停"，不强杀飞行中的请求）；
- SQLite 每次操作独立连接，规避跨线程共享连接问题。
