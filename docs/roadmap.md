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
- [ ] **favicon 反查的姊妹能力**：Shodan / Quake 的 favicon 反查（同一 mmh3 键已具备，只差各自 API 客户端）；
- [ ] **证书透明度补强**：SSL 证书解析（颁发者/有效期/SAN），支撑「SSL证书」页签与证书类资产统计；
- [x] **截图取证**（第十五轮）：无头浏览器（本机 Edge/Chrome，`--headless=new`）对存活站点截图，
      **默认关闭**（`screenshot.enabled`），截图落在任务目录并在站点页 URL 旁显示缩略图；
      浏览器路径探测见 `scanner/screenshot.py`（配置 → PATH → 注册表 → 标准安装位置，无硬编码绝对路径）；
- [ ] **登录态扫描**：任务级 Cookie/Token 配置，检查登录后才能覆盖的面。

## 检测深化

- [ ] A10 SSRF 受控回连（内置 DNS/HTTP 回连服务，判定出网行为）；
- [ ] XSS 上下文分析（当前仅未编码回显信号）；
- [~] POC 引擎补齐 nuclei 常用语义：`payloads` 池变量与 `extractors`（regex/kval）已实现；
      尚缺多请求串联（`raw`/`flow`/`workflows`）——这类模板被标 `unsupported`，不静默失效；
- [ ] 盲注类 SQL 检测（当前只做报错回显型，避免破坏性与长耗时的延时探测）；
- [ ] 误报管理：漏洞记录的人工复核状态（确认/误报）与复查工作流；
- [ ] **POC 置信度分层与实测校准**：312 个 POC 里 305 个是参考项目静态提取的低置信规则（默认关闭），
      先把"哪些规则真的准"用真实目标校准出来，再谈自动灌入新 POC
      （P3-2 情报订阅已落地，但**只到「线索」层**，正是卡在这条前置条件上——不自动灌 POC）；
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
- [ ] 报告升级：HTML/PDF 模板、漏洞趋势统计；
- [~] Linux 实机验证（当前 CI 与开发机均为 Windows + Python 3.9，代码层已按跨平台约束编写，
      并已把可自动化的部分变成 `tests/smoke.py [5o]` 的断言：全量 compile / 全量 import /
      禁 shell 直通与盘符路径 / 文本 IO 必带 encoding / `run_cmd` 实测 127·124 / `pick_python` 回退；
      **实机仍未跑过** —— 无 WSL/Docker，需在 Linux 上 `python3 tests/smoke.py` 才算验收）；
- [x] **进度与线索分流**（第十七轮续8）：「漏洞」与「线索」分表、分页签、分计数
      （`leads` 表 + 任务详情第 9 个页签 + 报告附录），从结构上保证「线索」不会被算成漏洞数；
- [ ] 分布式节点：多个执行节点认领任务（需要先替换 SQLite）；
- [ ] 工具版本管理：一键下载/更新 subfinder/httpx/puredns。

## 刻意不做

- 破坏性利用代码、口令爆破、DDoS 类功能——与定位（CTF 初筛与授权测试辅助）不符；
- 低危/info 噪声项（明文 HTTP、安全响应头缺失、组件版本泄露等）：`checks.skip_severities`
  默认整级跳过，连请求都不发（需要时可在「策略配置」放回）。