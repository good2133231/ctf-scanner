# 路线图

按优先级排列。**勾选状态反映实际代码**（[x] 已落地 / [~] 部分落地 / [ ] 未做），
与 `TODO.md` 的待确认清单、`CHANGELOG_AI.md` 的变更记录保持一致。

## 引擎能力

- [x] **端口扫描阶段**（portscan）：nmap 适配器 + 内置 TCP connect 兜底，产出入 `ports` 表与「端口服务」页；
      **默认关闭**；明确不调用 masscan（需 root 且激进）；
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
- [ ] **favicon 反查的姊妹能力**：Shodan / Quake 的 favicon 反查（同一 mmh3 键已具备，只差各自 API 客户端）；
- [ ] **证书透明度补强**：SSL 证书解析（颁发者/有效期/SAN），支撑「SSL证书」页签与证书类资产统计；
- [ ] **截图取证**：无头浏览器对存活站点截图，任务详情页展示；
- [ ] **登录态扫描**：任务级 Cookie/Token 配置，检查登录后才能覆盖的面。

## 检测深化

- [ ] A10 SSRF 受控回连（内置 DNS/HTTP 回连服务，判定出网行为）；
- [ ] XSS 上下文分析（当前仅未编码回显信号）；
- [~] POC 引擎补齐 nuclei 常用语义：`payloads` 池变量与 `extractors`（regex/kval）已实现；
      尚缺多请求串联（`raw`/`flow`/`workflows`）——这类模板被标 `unsupported`，不静默失效；
- [ ] 盲注类 SQL 检测（当前只做报错回显型，避免破坏性与长耗时的延时探测）；
- [ ] 误报管理：漏洞记录的人工复核状态（确认/误报）与复查工作流；
- [ ] **POC 置信度分层与实测校准**：312 个 POC 里 305 个是参考项目静态提取的低置信规则（默认关闭），
      先把"哪些规则真的准"用真实目标校准出来，再谈自动灌入新 POC（这也是 P3-2 实时情报的前置条件）；
- [ ] **osint 阈值校准**：黑 ico 阈值（200）与"单 IP 域名数判共享主机"（30）目前是保守估计值，需真实数据校正；
- [ ] **实时漏洞情报订阅**（P3-2）：依赖外部漏洞源（需 key/网络/解析规则），排在置信度分层之后；
- [ ] **启发式 0day 挖掘**（P3-3）：本质依赖检测层成熟度与大量样本验证，现阶段做只会放大误报噪声。

## 工程化

- [ ] 任务队列（Celery/RQ 或 asyncio）替代后台线程，支持并发任务与断点续扫；
- [ ] 鉴权加固：多用户、CSRF、HTTPS 部署指引（当前仅限本机使用）；
- [ ] 报告升级：HTML/PDF 模板、漏洞趋势统计；
- [ ] Linux 实机验证（当前 CI 与开发机均为 Windows + Python 3.9，代码层已按跨平台约束编写但未在 Linux 上跑过）；
- [ ] 分布式节点：多个执行节点认领任务（需要先替换 SQLite）；
- [ ] 工具版本管理：一键下载/更新 subfinder/httpx/puredns。

## 刻意不做

- 破坏性利用代码、口令爆破、DDoS 类功能——与定位（CTF 初筛与授权测试辅助）不符；
- 低危/info 噪声项（明文 HTTP、安全响应头缺失、组件版本泄露等）：`checks.skip_severities`
  默认整级跳过，连请求都不发（需要时可在「策略配置」放回）。