# 路线图

按优先级排列。**勾选状态反映实际代码**（[x] 已落地 / [~] 部分落地 / [ ] 未做），
与 `TODO.md` 的待确认清单、`CHANGELOG_AI.md` 的变更记录保持一致。

## 引擎能力

- [x] **端口扫描阶段**（portscan）：nmap 适配器 + 内置 TCP connect 兜底，产出入 `ports` 表与「端口服务」页；
      **默认关闭**；明确不调用 masscan（需 root 且激进）；
      **全端口扫描（1-65535）**（第十五轮）：侧栏「全端口扫描」页按任务分布展示，可对单个 IP 发起
      一次性全端口任务（自动跳过已扫端口，不污染全局策略）；
- [x] **CIDR 目标支持**：`targets.expand_cidr` 展开为多条 IP，上限 `MAX_CIDR_ADDRESSES = 256`，超限整体丢弃；
- [~] **nuclei 兼容**：引擎已兼容 nuclei 模板核心子集（官方模板可直接投放 `config/nuclei-templates/`，
      与本引擎不冲突，无需二进制）；参考项目的 305 个 Python POC 已静态转换为 YAML 放 `config/pocs-imported/`（默认关闭）；
      仍需 nuclei 二进制完整能力时，再于 vulnscan 阶段加适配器调用并解析其 JSONL 结果入 vulns 表；
- [x] **子域接管检测**：`scanner/dnsq.py` 取 CNAME 链 + `scanner/takeover.py` 41 条第三方服务指纹（can-i-take-over-xyz 思路）；
- [x] **外部情报拓展阶段**（osint，**默认全关**）：IP 反查域名 + `/24` C 段归纳（`iprecon.py`，入 `csegs` 表与任务详情「C 段」页签）、
      favicon 的 mmh3（`mmh3.py`，纯标准库自实现）去 FOFA 反查同源资产（`fofa.py`），
      命中数超过「黑 ico 阈值」的公共图标主动放弃拓展；两个子开关都关时整阶段一次请求都不发；
- [x] **子域名 IP / CDN 标记**（`scanner/cdn.py` + `config/dicts/cdn_cname.txt` 292 条厂商后缀，纯 DNS 只读判定）；
      关联域名（JS 挖掘 / C 段 / favicon 反查）与目标自身子域名**分页展示**（「拓展域名」/「子域名资产」）；
- [x] **FOFA 三种反查齐活**（第十五轮）：favicon（`icon_hash`）/ 证书（`cert="domain"`）/ **标题**（`title="xxx"`），
      三者都有"命中过多即放弃拓展"的黑名单阈值（黑 ico / 通用证书 / 公共标题），模板页标题连查询都不发；
- [x] **favicon 反查的姊妹能力**（续18）：Shodan（`scanner/shodan.py`，`http.favicon.hash:<mmh3>`）
      与 360 Quake（`scanner/quake.py`，`favicon: "<mmh3>"`，POST + `X-QuakeToken`）各自一个文件，
      与 `fofa.py` **同构照抄**（刻意不抽公共基类）；`shodan.enabled` / `quake.enabled` **默认关**，
      无 key 时显式返回"未配置 …（见 config/keys.yaml）"且**一个请求都不发**；
      沿用"命中过多即放弃拓展"的黑 ico 阈值；结果走 `osint._domain_of()` 收口（**裸 IP 不进资产库**）；

- [x] **站点证书取证**（续15）：一次只读 TLS 握手 + **纯标准库** ASN.1/DER 解析（`scanner/certs.py`），
      产出 CN / 颁发者 / 有效期 / 剩余天数 / 是否自签 / 签名算法 / SAN / 指纹 → `certs` 表 +
      任务详情「SSL 证书」页签 + 报告小节（`cert` 阶段，**默认关**，可在任务级点名）；**不校验证书**。
      续18 起页签与报告都带**来源列**（`TLS 握手` vs `CT 日志`），两类记录不会被混着看；
- [x] **CT 日志（crt.sh）在线查询**（续18）：`scanner/ctlog.py` 查
      `https://crt.sh/?q=<域>&output=json`，产出**证书维度**记录（签发者 / 生效失效时间 / 序列号 /
      CT 条目数 / 涉及域名），字段口径与 `certs.py` 对齐 → 写进 `certs` 表（`source='ct'`）并进
      「SSL 证书」页签；这些域名同时作拓展域名来源（`osint:ctlog`）。
      **免 key 但属外部接口 → 默认关**（`ctlog.enabled=false`）；走 `utils.http_request` 且
      **`auth=False`**（第三方绝不带登录态）；crt.sh 的非 JSON / 429 限流 / 超时一律容错
      （记一行日志继续跑，不让阶段挂掉）；`name_value` 的通配符 `*.x` 剥掉 `*.` 并单独标记
      （**绝不把 `*` 写进资产库**）。它与 `passive.py` 的 crt.sh（只取主机名做子域收集）、
      `certs.py`（真握手取线上证书）、FOFA 的 `cert=`（拿证书反查共用资产）是**四件不同的事**，
      区别写在 `scanner/ctlog.py` 文件头；
- [x] **截图取证**（第十五轮）：无头浏览器（本机 Edge/Chrome，`--headless=new`）对存活站点截图，
      **默认关闭**（`screenshot.enabled`），截图落在任务目录并在站点页 URL 旁显示缩略图；
      浏览器路径探测见 `scanner/screenshot.py`（配置 → PATH → 注册表 → 标准安装位置，无硬编码绝对路径）；
- [x] **登录态扫描**（第十七轮）：任务级 Cookie/Token 配置（GUI 文本框 / CLI `-H` 与 `--cookie`），
      只发往目标侧（第三方接口 fail-closed 不带），非法行拒绝建任务并列出原因，日志/页面/报告全部掩码；
      补扫与拓展域名探测**自动继承**来源任务的登录态。

## 检测深化

- [x] **A10 SSRF 受控回连**（续18）：`scanner/ssrf.py` + 检查项 `a10-ssrf-callback`（high）。
      任务内起一个**本机** HTTP 回连监听（`127.0.0.1`，端口 0 由系统分配），每参数一个唯一 token，
      把 `http://<回调基址>/<token>` 注入候选参数（参数名来自 URL 查询串 + 页面表单字段名 + 内置清单），
      收到该 token 的访问即判"**目标服务端会发起出网请求**"。
      **默认关**（`ssrf.enabled`）；`ssrf.callback_base` 留空＝本机监听地址，填了外部 OOB 时
      **读不到命中 → 只注入不报，绝不伪造**；监听端口用完即关（`finally`）。
      **刻意不做**：不打内网地址（那属于利用，越线）、不提交表单（可能是写操作）、不做延时判定。
      **局限**：只在目标能回访扫描机时有效，NAT / 云主机场景大概率一条都收不到 —— 见 AGENTS.md §7；
      只做 **HTTP 回连**，**未做** DNS 回连（需要自有域名与 NS 托管，属部署前置条件，暂不排期）；
- [x] **XSS 上下文分析**（续18）：`a03-xss-reflect` 不再一律 medium —— 判回显上下文（文本节点 /
      双引号属性 / 单引号属性 / 无引号属性 / `<script>` 内 JS 字符串 / JS 代码 / 标签名 / HTML 注释）
      并按上下文定级（JS 与无引号属性→high；引号属性与文本节点→medium；HTML 注释→降级为 low）。
      补了 1 条"上下文探针"（标记串 + `"'<>`）看哪些定界符**活着回来** ——
      大量站点只转义 `<` `>` 却留下引号，那正是属性注入最常成立的场景，旧逻辑整片漏报。
      请求预算**不变**（仍是 `_XSS_MAX_REQ=20`），`poc_id` 不变；**全转义的回显一律不报**；
- [~] POC 引擎补齐 nuclei 常用语义：`payloads` 池变量与 `extractors`（regex/kval）已实现；
      `raw` / `flow`（布尔子集）/ `workflows`（子模板编排）已于第十七轮落地，见 docs/poc-guide.md；
      仍缺 `dsl` 表达式、oob 反连、flow 的 JS/循环、workflow 的 `subtemplates`/`args`
      ——这类模板（或未实现子项）被标 `unsupported`/`_note`，不静默失效；
- [x] **盲注类 SQL 检测（布尔型）**（续18）：`a03-sqli-blind`（high）—— 同一参数发"恒真"与"恒假"
      两个 payload 比状态码 / 响应长度 / 正文差异，**再发一次恒真做稳定性复验**（页面自带随机数或
      时间戳时恒真自己都会抖，不复验就是误报）；命中必须给出**对比数字**（两次的状态码与长度）。
      **明确不做延时型**（`SLEEP`/`BENCHMARK`/`WAITFOR`/`pg_sleep`）：会挂住目标数据库连接线程
      （并发一上去就是事实上的 DoS，与"非破坏性"红线冲突），且跨公网抖动常盖过几秒的时间差。
      **2 种形态 × 5 个参数 × 3 请求 = 总预算 30**（与同文件报错型的 `_SQLI_MAX_REQ=30` 内部一致）；
      循环是**形态外层、参数内层** —— 预算优先保证 5 个参数都被覆盖（没测到的参数是必然盲区）。
      **已知覆盖缺口**：刻意放弃 `)` 与 `"` 两种上下文，需要时加回并同步调大预算；
- [x] **误报管理**（P1-1，2026-09-23 续12）：漏洞记录的人工复核三态（待复核/已确认/误报）+ 复查通道。
      `vulns.review/review_note/reviewed_at` + `db.set_vuln_review`/`bulk_set_vuln_review`/`review_counts`
      + `POST /api/vulns/review`（漏洞页三态下拉 + 批量打标）+ 报告「人工复核台账」；
      **判误报的条目不进「潜在漏洞」表、不计入漏洞数**，单列文末附录保留可回溯；
- [x] **POC 置信度分层**（P1-2，2026-09-23 续12）：`pocs.confidence` 由 `db.poc_confidence(path, meta)`
      按来源分（builtin=high / user·nuclei=medium / imported·other=low）× 内容型匹配器降级得出，
      **只降级不升级**；`vulnscan` 在同批候选里按置信度排序（指纹命中仍优先），
      「POC 管理」页新增置信度列/分布/按层批量启停。
      **"实测校准"仍是开放的长期项**：305 个导入 POC 目前只是"默认关闭 + 标了低置信并且排在后面"，
      要真的放开它们，仍需在真实授权目标上把"哪些规则真的准"跑出来 —— 本条是"自动灌 POC"的前置，
      情报订阅（P3-2）至今只到「线索」层，正是卡在这里；
- [x] **osint 阈值校准**（2026-09-23 用真实配额实测）：样本为 维保中心 15 / 后台管理系统 192188 /
      `Index of /` 5974788 / `Welcome to nginx` 8344737 / 登录 39722277 —— 阈值 200 落在 15 与 19 万
      之间，**不需要调**；实际动作是把公共标题（`GENERIC_TITLES`/`GENERIC_TITLE_PREFIX`）与占位证书
      （`GENERIC_CERT_NAMES`/`GENERIC_CERT_SUFFIX`）前置到零请求预筛，连查询都不发；
- [x] **实时漏洞情报订阅**（P3-2，第十七轮续8）：`scanner/intel.py` 拉 **CISA KEV**（免 key 公开 JSON，
      只收录已被在野利用的 CVE）→ 与本地指纹**白名单式匹配**（`MATCH_RULES` 显式写过的信号才参与，
      信号带词边界）→ 产出**「线索」**（`leads` 表，kind=intel），
      `intel.enabled` **默认关**，**不写 vulns / 不计入漏洞数 / 不自动导 POC**
      （不自动灌 POC 的原委见上方"POC 置信度分层"仍是前置条件）；
- [x] **启发式候选发现**（P3-3，第十七轮续8）：`scanner/heuristics.py` **零请求**，只对已采回的数据做
      差分 + 异常聚合（软 404 模板 / 高价值入口暴露 / 多主机同标题 / 目录命中离群 / 同 C 段多 IP），
      产出「线索」（kind=heuristic，级别 info），`heuristic.enabled` 默认关；
      **主动 fuzz 仍不做**（样本量不够时那是纯噪声）——这条与下面的 POC 校准一起，才是"能做 0day 挖掘"的前提。

## 工程化

- [ ] 任务队列（Celery/RQ 或 asyncio）替代后台线程，支持并发任务与断点续扫；
- [ ] 鉴权加固：多用户、CSRF、HTTPS 部署指引（当前仅限本机使用）；
- [x] **报告升级**（续16）：Markdown（原有）+ **HTML**（`report.generate_html()`，自包含单文件、
      内联样式、不引外链，全量 `html.escape`）+ **PDF**（`report.export_pdf()`，复用本机无头
      Edge/Chrome 的 `--print-to-pdf`，**不引入新依赖**；没有浏览器时明确报错并指向 HTML 替代路径）
      + **漏洞趋势统计**（`db.vuln_trend()`：级别分布 + 最近 15 个任务的逐任务计数，
      **已判误报不计入**、未知级别归 `other`；HTML 报告内与仪表盘都有）。
      入口：GUI 任务详情「导出 MD / HTML / PDF」、CLI `--report` / `--report-html` / `--report-pdf`。
      **未做**：报告在线托管 / 分享链接（刻意不做，控制台仅限本机使用）；
      **残留未验**：Linux 实机上未跑 `--print-to-pdf`（本机 Windows + Edge 已实跑出 `%PDF-1.4`）；
- [x] **Linux 实机验证**（P2-3，2026-09-23 续12 已达成）：在 Ubuntu 22.04.5 / Python 3.10.12 实机
      跑 `python3 tests/smoke.py` → **SMOKE PASS**（同一份代码，无平台分支）；同时实机验证了
      无头截图（snap `chromium` 出图 0.9s / 11274 字节合法 PNG）与外部二进制真实调用
      （`/usr/bin/nmap` + fscan 2.2.1，fscan 的输出形态据此校准并修掉一个解析缺陷）。
      `tests/smoke.py [5o]` 是**跨平台静态审计**（全量 compile / 全量 import / 禁 shell 直通与盘符路径 /
      文本 IO 必带 encoding / `run_cmd` 实测 127·124 / `pick_python` 回退），会按运行平台自报状态。
      **残留未验**：subfinder / puredns / httpx（那台机器上未装，代码走 `which` + 内置兜底）；
- [x] **进度与线索分流**（第十七轮续8）：「漏洞」与「线索」分表、分页签、分计数
      （`leads` 表 + 任务详情第 9 个页签 + 报告附录），从结构上保证「线索」不会被算成漏洞数；
- [ ] 分布式节点：多个执行节点认领任务（需要先替换 SQLite）；
- [ ] 工具版本管理：一键下载/更新 subfinder/httpx/puredns。

## 刻意推迟（不是不做，是这一轮刻意收窄改动面）

> 来源：续 9 的设计稿（`.trae/documents/`，该目录已 gitignore）。当时为了避免"一次改动过大"，
> 明确把这三条留在了实现范围之外 —— 抄到这里，防止随工具目录一起被忽略掉。

- [ ] **目录递归爬取**：dirmap 会顺着命中的目录继续往下爬。要做必须单独设计请求量控制与深度上限，
      否则一次任务就能把请求量放大一个数量级；
- [ ] **重写 dirmap 等价的多语言字典引擎**：现有「分层字典 + 12 个框架桶 + 暴露面」已覆盖它的主要收益，
      重写属于重复投入；
- [ ] **运行时联网下载字典**：CTF 离网现场与供应链风险两条理由，字典一律内置或本地生成
      （`tools/import_dir_dict.py` / `tools/import_fw_dicts.py`）。若要改成"可配置的联网更新字典"，
      那是一条独立需求，需要单独评估。

## 刻意不做

- 破坏性利用代码、口令爆破、DDoS 类功能——与定位（CTF 初筛与授权测试辅助）不符；
- 低危/info 噪声项（明文 HTTP、安全响应头缺失、组件版本泄露等）：`checks.skip_severities`
  默认整级跳过，连请求都不发（需要时可在「策略配置」放回）。