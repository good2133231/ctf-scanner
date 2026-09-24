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
│            portscan（默认关）→ probe → cert（默认关）→         │
│            screenshot（默认关）→ osint（默认关）→ jsmine →     │
│            dirscan（默认开·浅扫）→ vulnscan →                 │
│            intel / heuristic / github（默认关，只产"线索"）    │
│            （13 个阶段，见 runner.STAGE_ORDER）               │
│  资产层    scanner/dnsq.py（DNS 客户端）                      │
│            scanner/cdn.py（CDN 判定：CNAME 后缀匹配厂商名单）  │
│            scanner/takeover.py（子域接管指纹 41 条）           │
│            scanner/portscan.py（fscan/nmap 优先 + 内置 connect 兜底）│
│            scanner/certs.py（TLS 证书取证：纯标准库 DER/ASN.1） │
│            scanner/screenshot.py（本机无头 Edge/Chrome 截图）  │
│            scanner/iprecon.py（IP 反查域名 + /24 C 段归纳）    │
│            scanner/fofa.py + mmh3.py（favicon/证书反查 + 阈值排除）│
│            scanner/jsmine.py（JS 域名/接口/疑似凭据挖掘）       │
│            scanner/intel.py（CISA KEV 情报 × 本地指纹白名单匹配）│
│            scanner/heuristics.py（零请求差分/异常聚合，产线索）  │
│            scanner/github_leak.py（GitHub 公开代码搜目标注册域，  │
│              只落仓库/路径/规则名；auth=False、没 token 零请求）  │
│            scanner/blacklist.py（用户黑名单：入库前过滤）      │
│            scanner/portscan.py::parse_ports(max_span)（防手滑全端口）│
│  检测层    scanner/pocs/engine.py（POC 引擎，nuclei 兼容子集）│
│            scanner/owasp/checks.py（启发式检查 + 三级门控）    │
│  伪装层    scanner/evasion.py（HTTP 出口统一伪装 + payload 变形）│
│  门控层    scanner/throttle.py（F2 统一并发/限速/预算：          │
│            HTTP + 子进程 + 裸 socket，两级闸+令牌桶+预算）        │
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

`scanner/auth.py` 是**任务级登录态请求头**（Cookie / Authorization / 自定义头），用于扫"登录后才存在"
的资产（`/admin`、业务接口、需要会话的 POC）。设计上是 **fail-closed**：`utils.http_request(auth=False)`
是默认值，只有**目标侧**调用点显式传 `auth=True` 才带上凭据 —— 因为 `settings` 被 16 处调用点共用，
其中 4 处是第三方接口（crt.sh / FOFA / CISA KEV / IP 反查），"有 settings 就自动附"等于把目标会话
Cookie 外发给第三方。凭据由使用者在授权范围内自行取得（框架**不做**登录爆破 / 自动提交表单），
解析非法行时**不静默丢弃**（CLI 退出码非 0、GUI 400 并列出原因），日志/页面/报告一律走
`mask_value()` 掩码。注入方式是把凭据写进**本次任务专用的 settings 副本**（`inject()` 返回副本），
避免 CLI/测试复用同一个 dict 时把凭据带到别的任务上。

`scanner/throttle.py` 是**统一并发 / 限速 / 全局预算门控（F2）**：项目对外承诺"检测一律非破坏性"，
但在此之前**并发量完全不受控** —— HTTP（`utils.http_request`）、裸 socket（`portscan._probe_port`）、
子进程（`utils.run_cmd`）三条出口各自放大，且跨任务没有进程级上限（`stages/portscan.py` 是
8 主机并发 × `full_workers`(256) = 最坏 2048 在飞 socket，GUI 里 N 个任务各跑各的）。
它用**两级闸（任务级 + 进程级共享，`_GLOBAL_STATE`）+ 令牌桶 + 任务预算**把三条出口统一收口，
通过 `settings["_throttle"]` 注入（沿用 `auth.inject` 的"任务专用副本、绝不原地改"模式），
调用点只读它、从不直接碰全局。实际并发是 `min(阶段并发, max_inflight_per_task, max_inflight_global)`。
**预算耗尽＝按停止处理**（不是"网络故障"）：`Throttle.exhausted()` → `StageContext.stopped()` 为真
→ 任务标 `stopped` 并追加 `[throttle]` 错误行。取消兼容是硬约束：所有等待都是
`threading.Condition + wait(poll)` 轮询 + 入口检查，置位即抛 `StopRequested`，
绝不"点了停止却卡在等锁"。v1 覆盖缺口（TLS 握手 / DNS 查询 / 外部工具内部连接 / 任务外动作）
见 `AGENTS.md §7`。

`scanner/report.py` 提供**三种报告格式**，共用 `collect(task_id)` 的同一份数据快照
（避免"Markdown 有 TLS 证书小节、HTML 没有"这类格式漂移）：
`generate()`（Markdown，默认）/ `generate_html()`（**自包含单文件**：样式内联、不引外链，
所有来自被测目标的文本走 `html.escape` —— 漏一处就是"打开报告即执行 JS"的反射型 XSS）/
`export_pdf()`（把 HTML 交给本机无头 Edge/Chrome 的 `--print-to-pdf`，**不引入新依赖**；
找不到浏览器时返回明确原因，GUI 显示为 400 说明页、CLI 退出码非 0）。
跨任务维度的「漏洞趋势统计」在 `db.vuln_trend()`（级别分布 + 最近 15 任务逐任务计数）。

## 关键设计决策

| 决策 | 理由 | 代价 |
|---|---|---|
| 外部工具优先 + 内置兜底 | 你的手工流水线效果最好时用原工具；任何裸机也能跑通框架 | 兜底实现能力弱于本体 |
| SQLite 单文件 | 零部署成本，单机 CTF 场景足够 | 不支持多节点并发写，需要时替换 db.py 即可 |
| Flask + 后台线程 | GUI 只做"发任务 + 看结果"，逻辑全部复用核心引擎 | 无任务队列，进程重启则运行中任务中断 |
| POC 引擎向 nuclei 语法靠拢 | 社区事实标准（数千模板、可直接加载官方模板），声明式 YAML、无外部依赖 | 仅兼容核心子集（raw/flow/workflows 为子集支持，dsl、oob、flow 的 JS/循环等显式标 unsupported） |
| 启发式检查全部 GET + 无破坏 payload | 控制误伤与法律风险 | 检出率有限，定位是"初筛信号" |
| 分级门控（`skip_severities` 执行级 + `min_severity` 结果级，默认 info/low 不执行、门槛 medium） | 默认屏蔽低危/info 噪声，连请求都不发，只留能拿 flag 的高位结果 | 想广谱信息收集需**同时**放宽级别开关与门槛 |
| **阶段级 `enabled` 总开关**（`takeover`/`jsmine`/`dirscan`/`vulnscan` 默认开，`portscan` 默认关、`osint` 由 `iprecon`/`fofa` 两个子开关代替；`subdomain`/`probe` 刻意不设） | 用户要求"大功能都要有按分类的总开关"；关掉即整阶段跳过、连请求都不发，便于按需裁剪（如"只做资产测绘不探测"） | 开关分散在各段，新增阶段必须记得补 `enabled` 与 GUI 复选框（`tests/smoke.py` 的 `[3d]`/`[5b]` 已加断言防漏） |
| 动态免杀（evasion）只改变 payload 编码形态与请求伪装 | 提升隐蔽性与 WAF 绕过率，同时不越过非破坏性红线 | 变形不改变语义，对非规则型 WAF 效果有限 |
| 指纹用自研精简规则表（scanner/fingerprint.py） | 无外部依赖；httpx 缺失时也能填充 sites.tech | 规则少、只给组件标签不解析版本 |
| 外部情报（osint）默认全关，且"两个子开关都关＝一次请求都不发" | 依赖第三方公共接口（api.webscan.cc / FOFA），可用性不由我们掌控；不配置就不该有网络行为 | 想用 C 段/favicon 拓展需先去「策略配置 → 外部情报拓展」显式打开 |
| mmh3 自实现（`scanner/mmh3.py`）而非引入 mmh3 包 | 平台指纹的社区统一键就是 mmh3；C 扩展包在离线 CTF 环境装不上 | 只实现社区在用的 `x86_32`，未做 128 位变体 |
| 目录扫描**默认开但只跑浅扫**（`dirscan.mode=quick`：`dirs_shallow` 精选敏感路径约 150 条/站） + 只扫不重复站点 + 单站点 `quick_max_paths`/`max_paths` 节流 | 用户要求"先用偏敏感信息的通用路径浅浅过一遍，看清结果再手动决定深扫"；浅扫档请求量可控，深扫（全量分层字典 + dirmap + 后缀派生）才需要在建任务时勾「全目录深扫」或结果页发起「补扫」 | 浅扫覆盖有限（不碰全量字典与框架桶）；深扫必须配 `max_paths`，否则一个站点就要打到天亮 |
| 深扫走**任务选项**（`dirscan_full`）+ 独立补扫任务，而不是把全局改成 deep | 与 `portscan_full` 同一语义：用户点名要扫的那次才慢，跑完不改全局策略；补扫只跑单阶段、可独立停止/删除 | 任务列表会多出只跑 dirscan 的补扫任务行 |
| 全端口扫描走**任务选项**（`portscan_full`）而不是全局开关 | 6.5 万端口逐连接是分钟级，改成全局 `portscan.mode=full` 会让每个任务都变慢 | GUI 只提供"对勾选 IP 发起"的入口；任务列表会多出只跑 portscan 的任务行 |
| **统一并发/限速/预算门控**（F2，`scanner/throttle.py`）：HTTP + 子进程 + 裸 socket 三条出口过同一套**两级闸（任务级 + 进程级共享）+ 令牌桶 + 任务预算** | "非破坏性"是红线，但并发量此前完全不受控（任务内 8×256、跨任务进程级零上限）；一个入口统一收口比在三条出口各写一套更可靠，也让"停止/预算耗尽"有唯一落点 | 门控是**边界闸**，拦不住外部工具内部发多少连接；默认值取"恰好等于现有单任务最大并发"（`max_inflight_*`=256），故默认不改变既有行为 |
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
   `StageContext` 先注入**任务级登录态**（`auth.inject`）再注入**统一限流器**（`throttle.inject`），
   两者都写进**任务专用 settings 副本**（绝不原地改共享 dict）；
4. 阶段结果落点**并不统一**（改代码前先看具体阶段，不要假定"都写三处"）：
   - **文本产物 + SQLite + `ctx.results` 三处都写**：`subdomain` / `takeover` / `probe` / `jsmine` / `dirscan`
     （文本产物如 `sites.txt`，`ctx.results` 供下一阶段直接使用）；
   - **只写 SQLite + `ctx.results`（不落文本产物）**：`portscan` / `osint` / `vulnscan` / `intel` / `heuristic` / `github`
     （`intel` / `heuristic` / `github` 只写 `leads` 表）；
   - **只写文本产物 + SQLite（不写 `ctx.results`）**：`cert`（`certs.txt` + `certs` 表）/
     `screenshot`（`shots/*.png` + `sites.shot`）—— 二者排在流水线后段，没有后续阶段消费其结果；
5. GUI 通过 `tasks` 表轮询状态（status/progress/current_stage），详情页从 SQLite 读资产与漏洞。

## 数据库表

| 表 | 字段要点 | 说明 |
|---|---|---|
| tasks | targets, stages, options, status, progress, current_stage, log_file, error | 任务状态机：pending → running → done/stopped/failed |
| subdomains | domain, source, cname, ip, cdn, **ip_note** | source 标记来源：**目标自身**（subfinder / puredns / dns-brute(fallback) / passive:\*）与**拓展域名**（js:mine / osint:cseg / osint:fofa / osint:fofa-cert / osint:fofa-title / osint:shodan / osint:quake / osint:ctlog）两类；cname 由 takeover 阶段回填，ip / cdn / ip_note 由 subdomain 阶段回填（cdn 为空即"非 CDN"；`ip_note` 是解析失败/未解析的**原因码**：nxdomain / no-a / servfail / refused / timeout / error / empty / over-limit，页面上经 `gui.app.ip_note_label` 翻成中文）。两类在 GUI 分栏展示，SQL 判据是 `db.OWN_SUBDOMAIN_WHERE` / `db.EXT_SUBDOMAIN_WHERE`；拓展域名页默认隐藏重叠（`db.OVERLAP_EXT_WHERE`：域名已存在于任意任务的"目标自身子域名"里） |
| sites | url, host, port, status, title, length, server, tech, favicon, shot, source | 存活站点（probe 阶段产出）；favicon 为 MD5，供 POC 零请求前置判定；shot 为截图相对路径（screenshot 阶段回填，默认关） |
| ports | host, ip, port, service, banner | 端口与服务（portscan 阶段产出，该阶段默认关闭） |
| csegs | segment, ip, domains, count | `/24` C 段视野（osint 阶段产出，默认关闭）：每行一个 IP 与其反查到的域名（domains 截断存储、count 为截断前数量） |
| dirs | site_url, path, status, length, note, title | 目录发现（dirscan 阶段产出；`length` 即返回包大小，`title` 为命中页 `<title>` —— 内置扫描从已在手里的响应体提取、零额外请求，dirmap 解析行没有响应体故留空。默认排序为 `200 优先 → 大小降序`，页面按 `(site_url,status,length)` 折叠重复长度） |
| vulns | target, poc_id, name, severity, owasp, detail, evidence, **review, review_note, reviewed_at** | 统一存放 POC 命中与 OWASP 检查结果。`review` 是**人工复核三态**（`""` 待复核 / `confirmed` 已确认 / `false_positive` 误报，见 `db.REVIEW_STATES`，非法值经 `db.norm_review()` 归一）；**判误报的行不进「潜在漏洞」计数与报告主表**，改为报告文末「已判误报（人工复核排除）」附录 |
| leads | task_id, kind, code, title, target, matched, level, detail, source, url | **「线索」**（intel / heuristic / github 三个默认关阶段产出）：`kind` 区分情报/启发式/GitHub，`level` 只用于排序着色、**不是漏洞级别**。**不是漏洞结论** —— 不进 `vulns`、不计入漏洞数、不自动导入 POC；**出口只有 JSONL 导出**（`type=lead` 行 + `counts.leads`），GUI 页签与人读报告（MD / HTML）自 2026-09-24（续24）起不再露出。GitHub 线索（`kind="github"`）的 `code` 是 `仓库:文件路径`、`detail` 写明只记录了仓库/路径/命中规则 —— **文件内容与命中的凭据明文不入库** |
| certs | url, host, port, cn, subject, issuer, not_before, not_after, days_left, expired, self_signed, san, serial, sig_algo, sha256, source | TLS 证书取证（cert 阶段产出，**默认关**）：一个 `host:port` 一行。`san` 用 `,` 拼接截断到 2000 字符；`expired` / `self_signed` 是**证书属性而非漏洞结论**（握手不校验证书）。默认排序 `已过期 → 自签 → 剩余天数升序`，让异常项先露头；进 `db.ASSET_TABLES`，重启任务会一并清掉 |
| pocs | path(唯一), poc_id, name, severity, tags, enabled, status, **confidence** | POC 注册表：由扫描目录同步生成，GUI 控制启停。`enabled` 是**用户意图**（同步时不覆盖）；`confidence`（low/medium/high）是**推导值**，每次同步按 `db.poc_confidence(path, meta)` 重算（来源分 × 内容型匹配器，**只降级不升级**），仅作 `vulnscan` 同批候选的排序键，**不做过滤** |

**老库原地迁移**：`db._ensure_columns()` 用 `ALTER TABLE ADD COLUMN` 给已存在的库补齐新增列
（如 `subdomains.ip` / `subdomains.cdn`），不需要删库重建；`data/` 不入 git，各人本地库版本可以不同。

## GUI 路由与分栏

侧边栏 **9 栏**（以 `gui/templates/base.html` 的 `nav_items` 为准）：
`/`（仪表盘）/ `/tasks` / `/subdomains`（**只列目标自身子域名**，可勾选批量加黑名单 / 批量跑子域名）/
`/sites`（默认折叠重复站点，`?all=1` 看全部）/ `/ips`（IP 资产）/ `/fullports`（全端口扫描）/
`/vulns`（级别筛选 + `review=` 复核状态筛选 + `?task_id=` 按任务筛选，页内三态下拉与批量打标走
`POST /api/vulns/review`）/ `/pocs`（含置信度列与按层批量启停）/ `/settings`。
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
- **新增 POC**：把 YAML 放进 `scanner/pocs/pocs/`（内置）、`config/pocs-user/`（用户上传）、`config/pocs-imported/`（批量导入，**默认关闭**）或 `config/nuclei-templates/`（官方 nuclei 模板投放点），控制台「重新扫描 POC 目录」或重启即生效；`raw`/`flow`/`workflows` 已支持核心子集，超出部分（`dsl`、oob、flow 的 JS/循环等）会被标记 `unsupported` 并显示原因；
- **接入 nuclei**（可选）：引擎已兼容 nuclei 模板核心子集，官方模板可直接投放加载；若仍需 nuclei 二进制的完整能力，可在 vulnscan 阶段加适配器，把 sites 导出为 `-l` 文件调用 nuclei，结果解析回 `vulns` 表；
- **替换存储/队列**：`db.py` 与 `runner.run_task` 是唯一边界，替换后 CLI/GUI 不用动。

## 线程模型

- GUI：Flask 请求线程 + 每任务一个 daemon 线程（`threading.Thread(run_task)`）；
- 扫描内部：`utils.pool_run` 线程池，阶段级并发（探测/目录/漏洞扫描），站点内检查串行；
- **协作式取消**：`runner` 维护 task_id → `threading.Event` 的取消表，`request_stop` 置位、阶段在循环边界
  调 `ctx.stopped()` 主动退出，终态记为 `stopped`（粒度是"当前批次跑完即停"，不强杀飞行中的请求）；
- SQLite 每次操作独立连接，规避跨线程共享连接问题；
- **写操作在进程内串行化**（`db._WRITE_LOCK`，可重入锁）：SQLite 是单写者库，WAL 只让"读不被写阻塞"、
  `busy_timeout` 只是"冲突时排队等待的上限"，两者都不保证写成功 —— 而无任务队列时
  N 个任务线程 × `pool_run(workers=20)` 的回填会同时打满。所有写路径（`_exec` / `init_db` /
  复核打标 / `upsert_poc`）都在锁内；**新增写路径必须走 `_exec` 或显式加锁**。
