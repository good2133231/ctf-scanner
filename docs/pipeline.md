# 流水线说明

默认阶段顺序（**13 个**，权威来源 `scanner/runner.py::STAGE_ORDER`）：
`subdomain → takeover → portscan → probe → cert → screenshot → osint → jsmine → dirscan → vulnscan → intel → heuristic → github`
（CLI 可用 `-p` 裁剪，GUI 用复选框勾选）。

其中 `takeover` / `jsmine` / `dirscan` / `vulnscan` 由**策略级开关**控制、默认开，
`portscan` / `cert` / `screenshot` / `osint` / `intel` / `heuristic` / `github` 默认关：
勾选只表示"这个阶段参与本次任务"，真正执行与否还看
`settings.takeover.enabled` / `portscan.enabled` / `cert.enabled` / `screenshot.enabled` / `jsmine.enabled` /
`dirscan.enabled` / `vulnscan.enabled` / `intel.enabled` / `heuristic.enabled` / `github.enabled`
（阶段内部自查后打日志跳过，且**连请求都不发**）。`osint` 更特殊 —— 它没有自己的 `enabled`，
而是由两个**子能力开关** `iprecon.enabled` / `fofa.enabled` 控制，**两者都关时整阶段直接跳过**。
`github`（续26）另有一条"没配 token 就**一次请求都不发**"的前置门：GitHub 代码搜索接口要求认证，
没配 `github.token` 时直接写明原因跳过（而不是报"没查到"）。

> `cert` 与 `screenshot` 是"默认关但**能在任务级点名**"的一对：建任务时勾选、或 CLI 显式写
> `-p cert` / `-p screenshot`，即落任务级选项 `cert_on` / `screenshot_on`，**只对本次生效、不改全局策略**。
> 注意 CLI 的 `-p` 默认值是 `None`（不给＝全部阶段）：只有**显式点名**才落这两个 `*_on`，
> 否则默认的"全部阶段"会偷偷打开两个默认关的阶段。

> `dirscan` 走**浅/深两档**（`dirscan.mode`）：默认 `quick` 只打精选敏感路径（约 150 条/站），
> `deep` 才启用全量分层字典 + dirmap + 后缀派生。用户要求"先浅浅过一遍，看清结果再手动决定深度扫"，
> 所以**默认开的是浅扫**；深扫用建任务勾选「全目录深扫」（`dirscan_full`，同时写任务选项
> **并自动补上 `dirscan` 阶段**）或结果页的「补扫」按钮单独立任务，详见 ⑦。

末尾三个阶段（`intel` / `heuristic` / `github`）的产物是**「线索」而不是漏洞**：它们只写独立的 `leads` 表，
**不写 `vulns`、不计入漏洞数、不自动导入 POC**。**出口只有 JSONL 导出**（`type=lead` 行与
`counts.leads`）—— 任务详情页签与人读报告（MD / HTML）自 2026-09-24（续24）起不再露出，
沿用续20「机器格式保留全部、筛选权交下游」的取舍。
理由是这三类结论分别来自外部情报匹配、本地统计推断与第三方代码搜索，误报率天然高于实测型检查，
混进「潜在漏洞」表只会污染漏洞数（详见 `docs/security-notice.md` 与 `TODO.md` P3-2/P3-3）。

> `subdomain` / `probe` 刻意**没有**阶段级开关：它们的产物（域名、存活站点）是所有后续阶段的输入，
> 关掉等于整个任务不做 —— 这种需求用任务级的阶段勾选（建任务时的复选框 / CLI 的 `-p`）表达更清楚。

## 与手工流水线的对应关系

| 你的命令 | 框架阶段 | 框架实现 |
|---|---|---|
| `subfinder -dL url -all -t 200 -o logs/passive.txt` | subdomain | subfinder 适配器，参数一致（`-dL`/`-all`/`-t 200`） |
| `puredns bruteforce ./config/subdomains.txt -d url -r resolvers -w brute.txt` | subdomain | puredns 适配器，逐域名执行；字典/resolvers 用 `config/dicts/` |
| `cat passive.txt brute.txt \| sort -u` | subdomain | Python 端 `sorted(set(...))` 等价合并去重 |
| （无 subfinder 时的被动收集） | subdomain | 内置 `scanner/passive.py` 多来源免 key 接口（crt.sh / certspotter / alienvault / hackertarget / rapiddns / sublist3r） |
| （字典爆破前先测通配） | subdomain | `scanner/wildcard.py` 泛解析识别与过滤（纯 DNS 查询） |
| （手工常忘的 CNAME 检查） | takeover | `scanner/dnsq.py` 解析 CNAME 链 → `scanner/takeover.py` 比对 41 条第三方服务指纹 |
| `fscan -np -nobr -nopoc -p <ports> <host>` | portscan | fscan 适配器（只取端口发现，不跑 POC/爆破）；解析其四种开放端口行 + 统计行交叉校验 |
| `nmap -sT -Pn -n --open -p <ports> -oG -` | portscan | nmap 适配器（`-sT` 免 root）；未装则内置 TCP connect 兜底 + 被动 banner |
| （手工没有的部分） | osint | IP 反查域名 + `/24` C 段归纳；favicon（mmh3）→ FOFA 反查同源资产，黑 ico 放弃拓展 |
| （手工没有的部分） | jsmine | 抓站点 JS → 提取域名/接口 URL/疑似凭据，第三方域黑名单 + 前后文降噪 |
| `httpx -l httpx_url -mc 200,301,302,403,404` | probe | httpx 适配器（另加 `-title -tech-detect -json` 提取信息）；`-mc` 白名单一致 |
| `python dirmap.py -iF dir_out -e all` | dirscan | dirmap 适配器（`-iF` 批量 URL），并解析其 `output/` 产物；**仅 `mode=deep` 时调用**（浅扫不碰外部工具） |
| （手工没有的部分） | vulnscan | POC 引擎 + OWASP Top10 启发式检查（分级/分类门控 + WAF 探测） |
| （手工没有的部分） | screenshot | 本机无头 Edge/Chrome（`--headless=new`）截图，产物 `shots/*.png` 并回填 `sites.shot`；默认关 |
| `openssl s_client -connect host:443 -showcerts` | cert | 一次只读 TLS 握手取 DER → 纯标准库 ASN.1 解析（CN/SAN/有效期/自签/指纹）→ `certs` 表；**不校验证书**（自签/过期是常态）；默认关 |
| （手工没有的部分） | intel | 拉 CISA KEV 公开 JSON → 与本地指纹**白名单式**匹配 → 「线索」（`leads` 表）；单向下行、默认关 |
| （手工没有的部分） | heuristic | 对已采集数据做**零请求**差分/异常聚合（软 404 / 高价值入口 / 同标题 / 目录离群 / 同 C 段）→ 「线索」；默认关 |
| （手工没有的部分） | github | 拿目标**注册域**去 GitHub 公开代码里搜命中（`api.github.com/search/code`）→ 「线索」（只落仓库/文件路径/命中规则名）；默认关、没 token 零请求 |

## 各阶段细节

> 小节编号 ①~⑧ 沿用历史书写顺序（那批里还没有 `screenshot`，且 ⑤/⑥ 的位置是旧编号），
> **实际执行顺序一律以 `STAGE_ORDER` 为准**：`screenshot` 在 ④ probe 与 ⑤ osint 之间，
> ⑨~⑬ 是后补的阶段（编号只是书写顺序，`cert` 实际排在 `screenshot` **之前**；
> 其中 `intel` / `heuristic` / `github` 固定在流水线最末）。

### ① subdomain 子域名收集

- 输入：目标中的裸域名（URL/IP 目标不参与，直接进入 probe）；
- **四条获取路径（按执行顺序，可对照 `scanner/stages/subdomain.py` 逐个核）**：
  1. **subfinder**（外部工具，装了才用）：`scanner/stages/subdomain.py` → `which(tools.subfinder)` →
     `subfinder -dL <workdir/subfinder_in.txt> -all -t 200 -o <workdir/passive.txt>`，
     来源标记 `subfinder`。**恒带 `-all`**（使用全部数据源；不加时只用默认源集合，覆盖明显更小），
     用户要求"要主动且全"故写死在 argv 里；工具路径见 `config/settings.yaml` → `tools.subfinder`；
  2. **内置多来源被动收集**（免 key 公开接口）：`scanner/passive.py` 的 `SOURCES` 注册表 ——
     `crt.sh` / `certspotter` / `alienvault` / `hackertarget` / `rapiddns` / `sublist3r`
     （默认启用；`sitedossier` / `bufferover` 因历史不稳定默认不启用，可在 `passive.sources` 打开），
     来源标记 `passive:<源名>`；**与第 1 步取并集**（`subdomain.union_passive`，默认开）——
     原实现是 `elif`，装了 subfinder 就完全不跑这批证书/情报源，等于白丢覆盖；
  3. **DNS 字典爆破**：`puredns` 优先（`puredns bruteforce <dicts.subdomains> -d <域> -r <dicts.resolvers> -w <out>`，
     来源标记 `puredns`），未安装则内置 `scanner/wildcard.py::resolve_all` 兜底（`socket.getaddrinfo`，
     来源标记 `dns-brute(fallback)`）；字典 `config/dicts/subdomains.txt`（85 条），
     域名上限 `limits.brute_max_domains`；
  4. **被动来源的泛解析复核**：被动源里混进的通配产物，用第 3 步同一套判据清掉（`_PASSIVE_SRC`）。
- 泛解析过滤：`limits.wildcard_filter` 开启时，先用 `scanner/wildcard.py` 探测 `*.domain` 通配 IP，
  丢弃"解析结果全部落在通配 IP 内"的字典/被动候选（纯 DNS 查询，零 HTTP）；
- **IP/CDN 回填**：入账后对子域名做一次 `scanner/dnsq.py` 的 **CNAME 链 + A 记录**解析
  （上限 `subdomain.max_resolve`，默认 500，超出的仍入表、只是没有这两列；DNS 超时 `subdomain.dns_timeout`），
  回填 `subdomains.ip`（逗号连接的 A 记录）与 `subdomains.cdn`
  （`scanner/cdn.py` 用 `config/dicts/cdn_cname.txt` 的 292 条厂商 CNAME 后缀匹配，未命中留空 = 非 CDN）。
  纯 DNS 只读查询、零 HTTP；数据文件缺失时一律判"非 CDN"，不会抛错；
- 产物：`subdomains.txt`、`passive_multi.txt`（被动来源命中）、`hosts.txt`（子域名 ∪ 主域名，交给下一阶段）、SQLite `subdomains` 表（含 `ip` / `cdn`）；
- **入库前过用户黑名单**（`scanner/blacklist.py`，文件 `config/blacklist.txt`）：命中的域名**不入资产库**，
  因此后续 takeover / probe / dirscan / vulnscan 也不会扫它。语义详见 `docs/usage.md`「黑名单与批量操作」；
- 属性归属：本阶段的产物都是**目标自身**的子域名（来源 `subfinder` / `passive:*` / `puredns` / `dns-brute`），
  在「子域名资产」页展示；JS 与外部情报带出的关联域名（`js:mine` / `osint:*`）归「拓展域名」页，见 `db.OWN_SUBDOMAIN_WHERE` / `EXT_SUBDOMAIN_WHERE`；
- 降级：无 puredns 时用内置 `socket.getaddrinfo` 爆破（系统解析器，忽略自定义 resolvers——这是已知差异）；
  `--offline` 时不调用外部工具、也不跑被动收集，仅内置 DNS 爆破。

### ② takeover 子域接管（`takeover.enabled`，默认开）

- 输入：`ctx.results["subdomains"]`（为空时回退 `db.list_subdomains`），上限 `takeover.max_hosts`（默认 300）；
- 处理：`scanner/dnsq.py` 并发解析 **CNAME 链**（多跳用 `" -> "` 连接）并回填 `subdomains.cname`；
  仅对存在 CNAME 的子域做指纹比对（`scanner/takeover.py` 的 41 条第三方服务 suffix）；
  `takeover.http_check=true` 时再补一次只读 GET，比对停用页特征以降低误报；
- 产物：`cnames.txt`、SQLite `subdomains.cname` 回填、疑似接管以 **high** 级进 `vulns`（`owasp=A05`）；
- 降级/局限：`http_check=false` 时退化为纯 CNAME 判定，误报明显上升；第三方服务文案会变，指纹需定期维护。

### ③ portscan 端口与服务（`portscan.enabled`，**默认关**）

- 输入：目标里的 `ip` / `url` 主机名 / `domain` + `ctx.results["domains_for_probe"]`，
  上限 `portscan.max_hosts`（默认 100）；
- 处理：**引擎顺序 `portscan.engine="auto"` = fscan → nmap → 内置 TCP connect**（也可钉死其中一个）。
  fscan 调用强制 `-np -nobr -nopoc`（不暴力破解、不跑 POC，只取端口发现），老版本不认 `-nopoc`
  时自动去掉重试；nmap 用 `-sT -Pn -n --open -p <ports> -oG -`（`-sT` 无需 root）；
  未装则内置 TCP connect 兜底。`portscan.ports` 留空用内置 48 项 TOP 表，
  也可写 `"80,443,8080"` 或 `"1-1024"`；连接成功后对会主动问候的端口读 **banner**（纯被动读取）。
  **fscan 的返回语义（2026-09-23 续12 按 2.2.1 真实输出校准）**：开放端口行是
  `[*] ip:port <service>` / `[*] http://ip:port` / `[+] http://ip:port code:NNN`（老版本 `[+] ip:port open`），
  收尾固定打 `发现 N 个开放端口`。解析器用三条**行首锚定**正则取端口并与该统计行**交叉校验**，
  数目不符一律交回回退（`None`）—— 所以"少解析"不会变成静默漏报；统计行写 0 个则返回 `[]`（不回退）。
  `-nopoc` **管不到 fscan 内置的服务插件**（仍可能打印 `[!] Redis未授权访问` 这类只读结论），
  本阶段**只采信"端口开放"的事实行，不采信它的漏洞结论**；
- **全端口扫描（1-65535）**：`portscan.mode="full"`（配合 `portscan.full_ports`，默认 `1-65535`）
  或**任务选项** `portscan_full=true`。后者是 GUI「全端口扫描」页对单个 IP 发起的用法：
  它新建一个只跑 `portscan` 的阶段任务，**即使全局 `portscan.enabled=false` 也会执行**
  （用户点名要扫），跑完不改动全局策略 —— 全局开 full 会让每个任务都变成分钟级。
  `parse_ports()` 默认 `max_span=4096` 是**防手滑**：直接写 `1-65535` 只会回落到 TOP 表，
  全端口必须显式放开（代码里由 full 分支传 `max_span=65535`）。
- **排除已扫端口**：`portscan.exclude_scanned`（默认开）会跳过**本任务已入库**的端口
  （`db.list_ports(task_id)`），全端口补扫时省掉刚扫过的那批连接，日志会写明"已扫过 N 个端口"。
- 产物：SQLite `ports` 表、任务详情页「端口服务」页签、报告「开放端口与服务」小节
  （原侧边栏「端口服务」全局栏已移除 —— 该数据属任务维度，在详情页看更贴合上下文；数据未删）；
  同时 `ports` 会被下一阶段 `probe` 消费（见 ④）—— 这是"能扫出 `:9007` 这类非标端口站点"的原因；
- 为什么默认关：端口扫描耗时与噪声明显高于其他阶段，CTF 里常只给一个 Web 入口；
  **明确不调用 masscan**（需 root 且激进，违反非破坏性红线）。
- **并发受统一门控约束（F2）**：本阶段"8 主机并发 × 每主机 `full_workers`(默认 256)"此前最坏会到
  **2048 个在飞 socket**；现在每个裸连接都要过 `throttle.slot("socket")`，且 `scan_host` 的线程数会被
  收敛到 `min(阶段并发, max_inflight_per_task, max_inflight_global)`。外部工具（fscan/nmap）调用走
  `run_cmd(..., throttle=...)` 计一个 `"subprocess"` 名额。详见 `docs/architecture.md` 与 `AGENTS.md §5/§7`。

### ④ probe 存活探测

- 输入：URL 目标原样；IP 生成 `https/http` 两个候选；域名/子域名同样生成两种 scheme；
  **额外候选**：`portscan` 已跑过时，消费其 `ports` 表（同任务）里**除 80/443 外**的开放端口，
  为对应主机补出 `https://host:port` / `http://host:port` 两种候选（`probe` 日志会写
  `额外纳入 N 个开放端口候选（来自 portscan）`）。因此想覆盖非标端口 Web 服务，需**同时打开
  `portscan` 阶段**（默认关）—— 只跑默认阶段时仍只探 80/443；
- 处理：httpx 适配器（JSONL 输出解析 status/title/server/tech）；状态白名单 `200,301,302,403,404`；
- 产物：`sites.txt`、SQLite `sites` 表；`ctx.results["sites"]` 供后续阶段使用；
- 降级：内置探测（requests/urllib），https 优先、失败回退 http，提取标题、Server 头与技术栈（技术栈由
  `scanner/fingerprint.py` 从响应头/正文识别，属信号级标签、不含版本）；
  **响应体解码**统一走 `scanner/utils.py::_decode_body`（响应头 charset → UTF-8 → GB18030 → 带替换 UTF-8），
  修掉"服务器不声明 charset 时 requests 回退 ISO-8859-1 导致中文标题乱码"的问题。

### ⑤ osint 外部情报拓展（`iprecon.enabled` / `fofa.enabled`，**默认全关**）

发散思维的那一条腿：主目标常常只有一个，但**同一个 C 段**、**同一个 favicon**、**同一张 TLS 证书**
背后往往是同一套业务（同机房/同客户/同备案主体），这是找旁路的常见起点。产出是**新域名**，
所以位置放在 `probe` 之后、`jsmine` 之前 —— 越早入账，后面的 `dirscan` / `vulnscan` 覆盖越广。

三个子能力互相独立（`fofa.cert_enabled` 是 favicon 开关下的独立子开关）：

- **C 段反查**（`scanner/iprecon.py`）：汇总 IP（目标里的 IP 直接用；`url`/`domain` 目标、
  已入账子域名、存活站点 host 各做一次解析，受 `iprecon.max_hosts` 限制）→ `is_public_ip()`
  过滤掉私有/环回/保留地址（查公共接口对它们没意义，纯浪费配额）→ `max_ips` 截断 →
  `group_segments()` 归纳成 `/24` → 并发反查（`iprecon.workers`，默认 5，单 IP 只查一次、失败不重试）→
  落 `csegs` 表。**单 IP 反查到的域名数超过 `iprecon.max_domains_per_ip`（默认 30）判为共享主机/CDN**：
  C 段数据照常入库（仍是有价值的视野），但**不纳入域名资产**，否则一次就能灌进几十个无关域名。
  响应解析走 `json.loads` + 逐项结构校验，**不用 `eval`**（见 `TODO.md` B-3）。
- **favicon 反查**（`scanner/fofa.py` + `scanner/mmh3.py`）：对存活站点（受 `fofa.max_sites` 限制）
  并发算 favicon 的 **mmh3**（`fingerprint.favicon_hash`）→ 按哈希去重 → 逐个 `icon_hash="N"` 查询 FOFA →
  **命中数 > `fofa.black_ico_threshold`（默认 200）判为"黑 ico"**（公共图标：默认页、通用框架图标），
  放弃拓展并记日志。未配置 `config/keys.yaml` 的 `fofa.email/key` 时**显式提示后跳过**，不静默失败。
- **证书反查**（`fofa.cert_enabled`，默认跟随 favicon 开关）：把目标、存活站点与已入账子域名
  折算成**注册域**（`utils.base_domain`，含 `com.cn` / `co.uk` 等多段后缀）→ 跳过裸 IP（证书主体是域名）→
  `max_cert_queries`（默认 10）截断 → 逐个 `cert="domain"` 查询 FOFA。
  **命中数 > `fofa.cert_threshold`（默认 200）判为"通用证书"**（公共 CA / 大厂通用证书，
  共用者成千上万，按它拓展只会灌噪声），放弃拓展并记日志。
  折到注册域而不是逐个主机名查，是为了省 FOFA 配额（同注册域下各子域证书内容常重叠）。

- **标题反查**（`fofa.title_enabled`，默认跟随 favicon 开关）：取存活站点的**标题**
  （跳过 <4 字与模板页标题）→ 去重 → `max_title_queries`（默认 10）截断 → 逐个 `title="xxx"` 查询。
  **黑名单是两层的**（对应用户原话"只要结果找出一定熵值就判断为黑名单，比如 404 这种一找一大堆"）：
  ① `fofa.GENERIC_TITLES`（`404` / `Error` / `Welcome to nginx` / `Apache2 Ubuntu Default Page` …）
  **连查询都不发**；② 查完发现命中数 > `fofa.title_threshold`（默认 200）判为"公共标题"，放弃拓展。
  **③ 归属相关性过滤**（`fofa.title_match`，续22）：把标题按非字母数字切 token（去停用词与纯数字），
  默认 `label` 档要求**至少一个 token 与候选域名的某个 label 完全相等**才入库 —— 挡掉"标题里恰好含
  同一子串"的无关域名（标题含 `pengo` 时保留 `pengo.money`，丢弃 `silviapengo.com`/`pengowireline.com`）；
  设 `substring` 可回退到旧的子串匹配。切不出 token 的标题（如纯中文）**fail-open 保留**。
  来源 `osint:fofa-title`（页面显示「FOFA·标题反查」）。
- 产物：SQLite `csegs` 表（任务详情「C 段」页签、报告「C 段视野」小节；
  `/csegs` 路由仍在但已不进侧边栏 —— 该数据属任务维度）、
  新域名以 `source="osint:cseg"` / `"osint:fofa"` / `"osint:fofa-cert"` 补入 `subdomains` ——
  它们是**关联域名**，在「拓展域名」页展示（不进「子域名资产」页，判据 `db.EXT_SUBDOMAIN_WHERE`），
  来源列显示为 `C 段反查` / `FOFA·ICO 反查` / `FOFA·证书反查`，便于一眼认出哪些是 FOFA 找出来的；
- **入库前过用户黑名单**（`scanner/blacklist.py`）：命中的域名连子域一起丢弃，
  因此它们同样不会被后续 dirscan / vulnscan 扫到；
- 为什么默认全关：三项都依赖**第三方公共接口**（`api.webscan.cc` / FOFA），可用性不由我们掌控；
  且 FOFA 需要 key 与配额。接口地址做成配置项（`iprecon.api`，留空回落到默认）以便随时替换；
- 局限：公共接口的返回结构随时可能变；黑 ico / 通用证书 / "共享主机"三个阈值都是保守估计值，
  未经真实数据校准（证书反查的"通用证书"判定尤其粗：只按命中总数比阈值）。

### ⑥ jsmine JS 资产挖掘（`jsmine.enabled`，默认开）

- 输入：`ctx.results["sites"]`（为空时回退 `db.list_sites`），页面上限 `jsmine.max_pages`（默认 20）、
  JS 文件上限 `jsmine.max_js`（默认 40）；
- 处理：抓页面与其中引用的 JS，正则提取**域名 / 接口 URL / 疑似凭据**；
  第三方公共域走黑名单过滤（统计/CDN/开源库等，`config/dicts/js_thirdparty.txt`，**黑名单不可能穷尽**），
  **目标自身域永不误杀**；域名形态判断含**公共后缀（PSL）校验**（`config/dicts/tlds.txt`，含 `co.uk`/
  `com.cn` 等多段后缀）—— 挡掉 `wallet.filter.withdraw` 这类"点号连接的 JS 成员访问链"；清单缺失时
  fail-open 回退宽松判断并告警一次；
  `jsmine.secrets=true` 时启用凭据提取：**17 条规则**（`AKID[0-9A-Za-z]{16,32}` / `AKIA` / `LTAI` /
  `AIza` / `gh[pousr]_` / `xox[baprs]-` / Slack webhook / Telegram bot / SendGrid / Stripe /
  **JWT** / **私钥 PEM 头** / 数据库连接串 `mysql://user:pass@host` / 通用 `api_key=...` 等），
  经两级降噪（厂商前缀/赋值语境 → 占位符/变量引用/成员访问过滤）；
- 产物：新域名补入 `subdomains`（`source="js:mine"`，只补任务里还没有的；在「拓展域名」页展示）、
  接口 URL 落 `js_urls.txt` 并进 `ctx.results["js_urls"]`、疑似凭据落 `js_secrets.txt`（`类型<TAB>掩码值<TAB>来源`）
  并以 **high** 级进 `vulns`（`poc_id=js-secret-*`，值掩码脱敏，`target` 用**主机名**而不是完整 JS URL
  —— 同一站点多个 JS 命中同一个值不再重复入库，且「拓展域名」页能按域名显示"敏感 N"）；
  入库前同样过用户黑名单（`config/blacklist.txt`）；
- 局限：纯正则（不做 sourcemap 还原）；短 token 与含 `test/demo` 的真实值会被保守丢弃。

### ⑦ dirscan 目录发现（`dirscan.enabled`，**默认开，且默认只跑浅扫**）

- 开关：`dirscan.enabled`（默认开）。**但默认档位是 `dirscan.mode="quick"`** —— 只打
  `config/dicts/dirs_shallow.txt` 里精选的通用敏感路径（**约 150 条/站**，见下），
  请求量与噪声都可控。这是对早期"默认关闭"决策的**有意反转**：用户要求
  "先用偏敏感信息的通用路径浅浅过一遍，看清结果再手动决定是否深度扫"。
- **浅 / 深两档**（`dirscan.mode`）：

  | 档位 | 触发方式 | 字典 | 外部工具 | 后缀派生 |
  |---|---|---|---|---|
  | `quick`（默认） | 默认 / 策略配置选 quick | **只用 `dicts.dirs_shallow`**（9 个分区：VCS 泄露 → 环境/配置 → 备份转储 → 日志调试 → 中间件控制台 → 管理入口 → 目录泄露面 → 源码残留 → 健康检查） | **不调用** dirmap | 不做 |
  | `deep` | `dirscan.mode=deep`，或建任务勾「全目录深扫」，或结果页「补扫」 | 全量分层字典（框架桶 → 语言栈 → 暴露面 → 通用/全量） | 装了 `tools/dirmap/dirmap.py` 就优先用 | 对文件名型命中派生备份变体 |

  浅扫单站点上限 `dirscan.quick_max_paths`（默认 150），深扫仍是 `dirscan.max_paths`（默认 400）。
  两档都受 `limits.dirscan_max_urls` 站点数上限约束。
- **`dirscan_full` 任务选项**：值为 `true` 时把**该任务**强制成 deep 档，且
  **即使全局 `dirscan.enabled=false` 也执行**（与 `portscan_full` 同一语义：用户点名要扫，
  跑完不改全局策略）。GUI 在 `/api/tasks` 里除了写选项**还会自动补上 `dirscan` 阶段**，
  并按 `STAGE_ORDER` 归位（`runner` 按给定顺序执行、不排序），响应里用 `auto_stages` 提示。
- 输入：存活站点，先做**去重**（`_dedup_sites`：同一任务内「标题 + 响应长度」相同的别名站只留首个，
  与 `/sites` 页折叠同一口径），再按 `limits.dirscan_max_urls` 截断；
  **补扫任务兜底**：只跑 `dirscan` 的补扫任务没有 `probe` 产物（内存与库里都没有站点），
  此时用 `_sites_from_targets` 从 `ctx.targets` 兜底（URL 原样用，domain/ip 补 `http://`）——
  否则补扫会"无存活站点，跳过"，功能等于废掉；
- **字典按技术栈拆分 + 运行时按栈选择**（`dirscan.tech_aware`，默认开，深扫生效）：
  `tools/import_dir_dict.py --src <外部字典>` 把源字典切成
  `dirs_common`（与语言无关）/ `dirs_jsp`（Java 系）/ `dirs_php`（PHP 系）/ `dirs_asp`（ASP.NET 系）
  + `dirs_big`（全量）。运行时按 `sites.tech`（probe 阶段的指纹）与 URL 后缀判定技术栈，
  只取「语言字典 + 通用字典」—— 用户要求"确定是 java 就不要用 php asp"，一个站只可能是
  一种栈，把三种语言的后缀全打一遍纯属浪费 `max_paths` 额度。判不出技术栈才用全量字典。
  **语言字典排在通用字典之前**：`max_paths` 截断时先保语言专属路径。
  实测：PHP 站 40 条请求 100% 是 `.php`，Java 站无一条 `.php/.aspx`；
- **框架字典在语言字典之前**（`tools/import_fw_dicts.py` 派生 12 桶 = 11 框架 + 暴露面，
  运行时按 `sites.tech` 命中的框架把对应桶排最前）；**判不出框架时不吃框架字典额度**，
  `dirscan.fw_max_paths=0` 时零请求；
- **后缀派生**（`dirscan.suffix_aware`，默认开，**仅 deep**，借鉴 dirmap 的备份文件扩展）：
  对命中的**文件名型**路径再派生 `.bak` / `.zip` / `.tar.gz` / `.rar` / `.old` / `~` / `.swp` /
  `.copy` / `.save` / `.txt` 变体，去重后占用同一份 `max_paths` 额度（`_suffix_jobs`）；
- **目录递归**（`dirscan.recursive_depth`，**默认 0 = 关**，**仅 deep**，续30）：对**目录型命中**
  继续往下打 `recursive_depth` 层。目录型判据（`_dir_prefix`）：status ∈ {200,301,302,403}、
  路径去掉 query/fragment 后**最后一段不含 `.`**、且**第一段不以 `.` 开头**
  （`.git/config`、`.svn/entries` 的最后一段也不含 `.`，但它们不是"可以爆破了"的目录）。
  递归轮只吃**浅扫精选字典**（截断到 `recursive_max_paths`，默认 40），不是再来一遍大字典。
  **三重闸**：`recursive_depth`（层数）/ `recursive_max_dirs`（每站**所有层合计**最多递归几个目录，
  默认 5）/ `recursive_max_paths`。限目录数不能省 —— 一层递归 = `+K×(3 软404基线 + M)`，
  K 由"扫出多少个目录"决定、**不受字典大小控制**（K=5/M=40 时 +215 请求，比第一轮 153 还多）。
  两个容易写错的地方：① 软 404 基线**按基址各算一份**（子目录常有**自己的**统一跳转页，
  复用站点根的基线会把子目录下的真实命中整片滤掉）；② 入库的 `site_url` **仍是站点根**
  （它是折叠 / 跨运行去重 / 启发式分组的数据维度，写成子目录会把一个站点拆成十几行）。
  递归放在 `run()` 里、对内置扫描与 dirmap 的补充扫描**一视同仁**（挂进 `_builtin_scan`
  会让"装了 dirmap 的机器反而没有递归"）。任务级勾选 `recursive_dir`（GUI 复选框 / CLI
  `--recursive-dir`）只本次生效，且**自动带上 `dirscan_full` 与 `dirscan` 阶段**。
  刻意**不打开** dirmap 自带的 `conf.recursive_scan`：它只对 `[301,403]` 递归、深度靠
  `recursive_scan_max_url_length=60` 兜底，与上面这套额度不可预测地叠加（保持 `0` 不动）；
- 字典文件（`config/dicts/`）：`dirs_shallow`（浅扫专用，206 条，按价值排序）/
  `dirs_big`（全量）/ `dirs_common` / `dirs_jsp` / `dirs_php` / `dirs_asp` /
  框架桶 12 份 / `dirs_exposure`，另保留 `dirs_small`（55 条，快速档）；
  非目录类：`tlds`（6423，公共后缀，`tools/import_tlds.py` 生成）与 `js_thirdparty`（287，JS 第三方域名单）；
- 处理（外部工具优先，**仅 deep**）：`tools/dirmap/dirmap.py` 存在时调用 dirmap
  （`-iF <目标文件> -e all -t <线程>`，cwd 固定在其项目目录），解析其 `output/<域名>/*.txt`：
  **只读 `res.txt` 与 `403.txt`**（`重复长度.txt` / `404.txt` / `othercode.txt` 不读 —— 重复长度按用户要求默认不展示），
  **只解析本次运行写过的文件**（按启动时间过滤，`output/` 是持久目录）；
- 降级：内置字典扫描 —— 每个站点先用**3 个随机路径**建立"软 404 基线"（md5 集合 + 长度集合，
  借鉴 dirmap 的 `auto_check_404_page`），命中任一基线的 200 响应视为不存在；
- 产物：`dirs.txt`（`状态 大小 路径`）、SQLite `dirs` 表（含 `length` 返回包大小）；
  `/dirs` 与任务详情「目录」页签**默认折叠"重复长度"**（同一站点下状态码 + 大小都相同的只留首个），
  `/dirs?all=1` 放开。

### ⑧ vulnscan 漏洞初筛

- 开关：`vulnscan.enabled`（**默认开**）—— 关闭后整阶段跳过（连请求都不发），
  适合"只做资产测绘、暂不探测"的场景；
- 输入：存活站点（上限 `limits.vulnscan_max_urls`）；
- 处理：每站点先做一次 WAF 指纹识别（`evasion.waf_detect`，命中在日志中提示厂商，便于判断"扫不出来"是没漏洞还是被拦），
  再跑**启用**的 OWASP 启发式检查（见 docs/owasp-mapping.md），最后逐个执行启用的 POC（每 POC 每目标最多一次命中）；
- 门控四层：
  0. `vulnscan.enabled` —— **阶段级**：关掉则整阶段不执行；
  1. `checks.skip_severities`（默认 `["info","low"]`）—— **执行级**：这些级别连请求都不发
     （内置检查与 POC 引擎同规则），因为它们的结论本来就会被 `min_severity` 丢掉；
  2. `checks.poc_engine` = POC 引擎总开关；`checks.disabled_categories` / `disabled_checks`
     命中的检查根本不执行；注入类检查（SQLi/XSS）走 `scanner/evasion.py` 的 payload 变形绕过 WAF；
  3. `checks.min_severity`（默认 medium）—— **结果级**：过滤残余的低危/info 结果；
- POC 选取顺序：`checks.poc_link_tags=true` 时，**站点技术栈命中的 POC 优先且不受
  `checks.poc_max_per_site` 约束**，其余 POC 排在其后受限执行；**同一批候选内再按 POC 的
  `confidence` 排序**（`db.poc_confidence`：来源分 × 内容型匹配器，只降级不升级 —— 详见
  docs/poc-guide.md「置信度分层」），预算有限时先跑更可能准的规则；POC 若声明了 `favicon_md5_list`
  且与 `sites.favicon` 不符，**零请求**直接跳过；
- 注入探测的"动态性"：payload 变体按 `evasion.bypass_level` 生成（注释替空格/大小写/内联注释/
  URL 编码/双重编码/关键字分片），**每次运行的变体顺序随机**，参数顺序也随机 —— 请求形态不固定，
  降低被 WAF 规则固化识别的概率；原始 payload 始终排第一（最便宜、命中率最高）；
- 产物：SQLite `vulns` 表、GUI 漏洞页、**三种格式的报告**（Markdown / 自包含单文件 HTML / PDF）。
  **人工复核（P1-1）**：结果可在 GUI 漏洞页标「已确认 / 误报」，**判误报的行不计入漏洞数**，
  报告里另立「已判误报（人工复核排除）」附录（判错可改回）；
- 并发：站点级并发（max_workers/2），站点内部串行，避免对单目标压力过大。

### ⑨ screenshot 站点截图（`screenshot.enabled`，**默认关**）

- 位置：**`probe` 之后、`osint` 之前**（必须先有存活站点才能截图；旧编号里没有它，故排在 ①~⑧ 之后书写）；
- 门控：`screenshot.enabled` 默认关；即便打开，`screenshot.available()` 探测不到可用浏览器时**只告警跳过、不抛错**；
- 输入：`ctx.results["sites"]`（为空回退 `db.list_sites`），上限 `screenshot.max_sites`（默认 20，超出只截前 N 个）；
- 处理：调用本机已装的 Edge/Chrome 无头模式（`--headless=new`）截整页，视口 `screenshot.window`
  （默认 `1280x900`）、单站点超时 `screenshot.timeout`（默认 30s）；浏览器路径 `screenshot.browser`
  留空则自动探测（配置值 → PATH → 注册表 → 标准安装位置，**无硬编码绝对路径**）；
  **不引入任何新依赖**（不装 selenium/playwright）；
- 产物：`shots/<md5>.png` + `shots.txt`；`sites.shot` 只存**相对任务工作目录**的路径（`shots/xxx.png`），
  GUI 站点页 / 任务详情「站点」页签显示缩略图（点击看大图）；
- 为什么默认关：拉起无头浏览器单站点通常 1~3 秒、内存占用明显高于纯 HTTP 探测，
  且它不直接帮助"拿 flag"——需要看站点长相时再打开。

### ⑫ cert TLS 证书取证（`cert.enabled`，**默认关**）

- 位置：**`probe` 之后、`screenshot` 之前**（同截图，必须先有存活站点才知道去连谁；书写编号排在最后）；
- 门控：`cert.enabled` 默认关；建任务勾选「SSL 证书」或 CLI 显式 `-p cert` → 任务级 `cert_on`，
  **只对本次生效、不改全局策略**（与 `screenshot_on` 完全同一套门控）；
- 输入：`ctx.results["sites"]`（为空回退 `db.list_sites`），只挑**值得握手**的目标（`pick_targets`）：
  URL 是 `https://` 的，**或**端口命中 `cert.tls_ports`（默认 `443,8443,9443`）的
  —— 覆盖"HTTPS 服务被 probe 记成 `http://host:8443`"这种情形；同一 `host:port` 去重；
  上限 `cert.max_sites`（默认 30），单次超时 `cert.timeout`（默认 8s）；
- 处理：**一次只读 TLS 握手**（`ssl`，`verify_mode=CERT_NONE` + `getpeercert(binary_form=True)` 取 DER），
  再用**纯标准库** ASN.1/DER 解析（`scanner/certs.py`，**不引 cryptography**）；
  取出 CN / subject / issuer / notBefore / notAfter / 剩余天数 / 是否自签（RDN 集合比较）/
  签名算法 / 序列号（剥 DER 正数补位 0x00）/ SHA256 指纹 / SAN（上限 20 条）；
- 产物：`certs` 表（一个 `host:port` 一行）+ `<workdir>/certs.txt`（13 列，带表头）；
  任务详情「SSL 证书」页签 + 报告「TLS 证书」小节；进 `ASSET_TABLES`，重启任务会一并清掉；
- **为什么用 `CERT_NONE`**：CTF / 授权测试里最常见的就是自签、过期、域名不匹配的证书，
  恰恰是校验会失败的场景 —— 本阶段是**取证**（把颁发者与有效期读出来给人看），不是建立可信连接；
  因此**「自签 / 已过期」是证书属性，不是漏洞结论**，报告与页签里都显式声明了这一点；
- **不做什么**：不校验证书链、不做 CRL/OCSP、不做多协议/多密码套件试探（一次握手、只读）；
  **CT 日志（crt.sh）在线查询未实现** —— 那属于外部接口，与 Shodan/Quake 一起排在后续批次；
  `osint` 阶段里已有的 FOFA 证书反查是**另一件事**（按证书找同源资产，不是读站点证书）。

### ⑩ intel 漏洞情报订阅（`intel.enabled`，**默认关**）

- 位置：流水线**最末**（`vulnscan` 之后）—— 它不产出任何被后续阶段消费的数据；
- 情报源：内置 `scanner/intel.py::FEEDS`（默认 `kev` = CISA `known_exploited_vulnerabilities.json`，
  **免 key 公开 JSON**，只收录"已被在野利用"的 CVE）；`intel.url` 填了就覆盖内置地址
  （需同结构 JSON，可指向自建镜像以**完全离线**）；
- 缓存：落在 `data/intel/<source>.json`（目录跟随库位置 `db.DB_PATH.parent / "intel"`，
  故测试用 `CTFSCANNER_DB` 时会自动隔离），有效期 `intel.cache_hours`（默认 24 小时，设 0 则每次拉取）；
  **拉取失败会退回过期缓存并告警**（不静默失败，也不因一次网络抖动清空情报）；
- 匹配（**白名单式**）：只有 `MATCH_RULES` 里显式写过的资产信号才参与，且要求
  「资产侧信号命中 + 情报侧产品关键词命中 + 厂商关键词对得上」**三条同时成立**；
  信号词带词边界 `(?<![a-z0-9])signal(?![a-z0-9])`，防止短信号（如 `iis`）被 `heliis` 这类单词吞掉。
  参与匹配的资产指纹文本：站点 = `tech + server`（**刻意不含标题**，标题噪声太大），端口 = `service + banner`；
- 代价：O(资产数 × 情报条数) 的纯字符串判断，**不发任何请求**（整个阶段只有"拉情报源"这一个出站请求）；
  同一 CVE 命中多台主机时按 `high` 优先排序，再由 `max_leads`（默认 50）截断；
- 产物：`leads` 表（`kind="intel"`）；级别：情报 `knownRansomwareCampaignUse == "Known"` → `high`，否则 `medium`；
- **边界**：不写 `vulns`、不计入漏洞数、不自动导入 POC；方向是**单向下行**
  （不向任何第三方发送目标信息，隐私方向与 `osint` 相反）；
- 局限：KEV 覆盖面窄于全量 CVE 库；匹配到**产品/厂商关键词级**、**不含版本比对**，
  命中只说明"这条已知被利用的 CVE 与你扫到的组件可能相关"，是不是真漏洞必须人工确认。

### ⑪ heuristic 启发式候选发现（`heuristic.enabled`，**默认关**，零出站请求）

- 位置：流水线**最末**（与 `intel` 同批）—— 它要读 `dirscan` 的目录结果与 `vulnscan` 的漏洞，
  越晚跑看到的数据越全；本身**不发任何请求**，只对已采回的本机数据做差分与异常聚合；
- 输入：`db.list_sites` / `db.list_dirs` / `db.list_vulns(limit=1000)` / `db.list_csegs`
  （站点、目录、C 段**全空则整阶段跳过**）；
- 5 条规则（阈值常量见 `scanner/heuristics.py`）：
  1. **软 404 模板**：单站点 ≥ `SOFT404_MIN_ROWS`(8) 条"200 但内容重复"的目录记录、占比 ≥
     `SOFT404_RATIO`(0.7) → 提示该站有软 404 兜底页，目录命中可能全是假的；
  2. **高价值入口暴露**：已命中的目录路径匹配 `HIGH_VALUE_PATHS`（**15 条**：`.git` / `.env` /
     `actuator` / `druid` / `swagger` / `phpmyadmin` / WordPress / Tomcat manager / ES / Nacos /
     Jenkins / 备份文件 / Solr / Eureka / 控制台）**却没有对应漏洞结论** → 提出人工复核候选；
  3. **多主机同标题**：同一标题出现在 ≥ `TITLE_MIN_HOSTS`(2) 台主机、标题长度 ≥ `TITLE_MIN_LEN`(4)
     且非模板标题（复用 `scanner/fofa.py::is_generic_title`）→ 可能是同一套系统的多个入口；
  4. **目录命中离群**：某站点目录命中数 ≥ `OUTLIER_MIN_HITS`(15) 且 ≥ 同任务站点中位数 ×
     `OUTLIER_RATIO`(3) → 该站目录面异常宽（常意味着后台/调试接口暴露）；
  5. **同 C 段多 IP**：单个 `/24` 归纳出 ≥ `CSEG_MIN_IPS`(3) 个 IP → 提示段内其它主机值得看
     （`csegs` 非空本身来自默认关的 `osint`）；
- 产物：`leads` 表（`kind="heuristic"`，级别一律 `info`）；`max_leads`（默认 50）截断；
- **边界**：只写 `leads`，不写 `vulns`、不计入漏洞数；**主动 fuzz 仍不做**（样本量不够时那是纯噪声）。

### ⑫ github GitHub 泄露检索（`github.enabled`，**默认关**，需 `config/keys.yaml` 的 `github.token`）

- 位置：流水线**最末**（排在 `intel` 之后）—— 它要发外部请求、受第三方限流约束，
  不产出任何被后续阶段消费的数据，放在最后便于"只重跑本阶段"；
- 目标收敛（`scanner/github_leak.py::target_domains`）：只对目标的**注册域**检索 ——
  子域名与主域的泄露命中高度重叠，逐个查只会把额度瞬间打满；IP / CIDR / 认不出主机的目标一律跳过（不猜）。
  注意这里用 `utils.is_domain` 做形态守门：`http://127.0.0.1:8765/` 这类 **URL 里的裸 IP**
  若直接交给 `base_domain()` 会切出 `"0.1"` 这种垃圾域名；
- 4 条检索规则（`SEARCH_RULES`，顺序即优先级，"外层按规则、内层按域名"遍历，
  于是最便宜的 `mention` 先覆盖到所有域名）：`mention`(info) / `credential`(medium，`password`) /
  `apikey`(medium，`api_key`) / `env-file`(medium，`filename:.env`)；级别只用于 `leads.level` 排序着色；
- **三条硬边界**（改代码前先读 `scanner/github_leak.py` 文件头）：
  1. **只落元数据**：字段白名单只取 `repository.full_name` / `path` / `html_url` + 规则名。
     代码搜索若带上 `text-match` 类 Accept 头，响应里会出现 `text_matches`（**命中片段，可能含凭据明文**）——
     `normalize_hit()` **刻意不读它**，让凭据明文只存在于浏览器里，不进本地库 / 日志 / 报告 / JSONL。
     `tests/smoke.py [6p]` 直接用「含 `text_matches` 的响应」验这一点（并在入库与 JSONL 里断言 0 处明文）；
  2. **`auth=False`**：GitHub 自己的 token 只作为 `Authorization` 头发出，
     **任务级登录态（目标侧 Cookie / Token）绝不发给 GitHub**；
  3. **默认关 + 限额 + 没 token 零请求**：代码搜索认证后限流约 **10 次/分钟**，
     `max_queries`（默认 4）到顶即收手；每次 200 响应后检查 `X-RateLimit-Remaining=0` 也主动收手；
     没配 token 时**一次请求都不发**并把原因写进日志（不报"没查到"，否则用户会把 401 当成"确实没泄露"）。
     触顶属**设计内的收手、不是失败**：`collect()` 用独立的 `meta["capped"]` 表达，
     阶段层打 info；`meta["error"]` 只装真失败（401 / 403 / 限流 / 网络不可达 / 非 JSON）。
     （默认 `max_domains=3` × 4 条规则 = 12 次潜在查询 > 上限 4，所以正常跑必然触顶 ——
     若把触顶塞进 `error`，每次正常运行都会打一条 warning，把"正常"说成"出错"。）
- 产物：`leads` 表（`kind="github"`，`code="<仓库>:<路径>"`，`source="GitHub"`），`max_leads`（默认 30）截断；
  同一 `(域名, 仓库, 路径)` 被多条规则命中只出一条、规则名并进 `matched`
  （`db.insert_leads` 的去重键是 `(kind, code, target)`，不在这里合并后面的规则会被静默丢掉）；
- **边界**：只写 `leads`，不写 `vulns`、不计入漏洞数、不自动导入 POC —— 命中只说明
  "这个域名出现在某个公开仓库里"，**不是漏洞结论**，需人工打开 URL 确认（并注意其中可能含真实凭据）。

## 阶段产物示例

```
logs/task_1_mytask/
├── task.log          # 全程日志（GUI 详情页实时显示尾部）
├── subfinder_in.txt  # 传给 subfinder 的域名列表
├── passive.txt       # subfinder 输出
├── passive_multi.txt # 内置多来源被动收集命中（scanner/passive.py）
├── brute_*.txt       # puredns 输出（每域名一个）
├── subdomains.txt    # 合并去重后的子域名
├── cnames.txt        # 子域名 → CNAME 链（takeover 阶段产物）
├── hosts.txt         # 参与探测的主机全集
├── httpx_url.txt     # 传给 httpx 的候选 URL
├── httpx_out.json    # httpx JSONL 输出
├── sites.txt         # 存活站点
├── js_urls.txt       # 从 JS 提取到的接口 URL（jsmine 阶段产物）
├── shots/            # 站点截图 PNG（screenshot 阶段，默认关）
├── shots.txt         # 截图清单：URL<TAB>相对路径
├── certs.txt         # TLS 证书取证（cert 阶段，默认关）13 列带表头
├── dirmap_in.txt     # 传给 dirmap 的 URL
└── dirs.txt          # 目录发现
```

> `portscan` / `osint` 阶段不落文本产物（结果直接进 SQLite `ports` / `csegs` 表，新域名进 `subdomains` 表）；
> `intel` / `heuristic` / `github` 同理 —— 只写 `leads` 表（情报缓存另落 `data/intel/<source>.json`，**不在任务目录**；
> `github` 连缓存都不落，命中只以元数据进 `leads`）；
> `cert` 两条都落：`certs` 表 + `certs.txt`（每次握手只成功一次，文本产物便于直接比对）；
> 子域名阶段的 **IP / CDN 回填**同样只进 `subdomains` 表（`ip` / `cdn` 两列），不额外落文件；
> `vulnscan` 结果进 `vulns` 表，报告由 `scanner/report.py` 或 GUI 导出按钮生成 ——
> 三种格式**共用同一份数据快照**（`collect(task_id)`，防格式漂移）：`generate()`（Markdown，默认）/
> `generate_html()`（自包含单文件，所有来自被测目标的文本全量 `html.escape`）/
> `export_pdf()`（复用本机无头 Edge/Chrome 的 `--print-to-pdf`，无浏览器时**明确报错**不静默丢交付物）。

## 配置项速查（config/settings.yaml）

| 配置 | 默认 | 作用 |
|---|---|---|
| limits.max_workers | 20 | HTTP/DNS 并发线程数 |
| limits.http_timeout | 10 | 单请求超时 |
| limits.verify_tls | false | 是否校验 HTTPS 证书；默认关闭以适配自签名靶场/CTF |
| limits.dirscan_max_urls | 20 | 参与目录扫描的站点上限 |
| limits.vulnscan_max_urls | 100 | 参与漏洞扫描的站点上限 |
| dirscan.enabled | **true** | **阶段级**开关：目录/路径发现整阶段开关（关掉连请求都不发）。**默认开，但只跑浅扫**（见下一行 `dirscan.mode`） |
| dirscan.mode / quick_max_paths | quick / 150 | `quick` = 只吃 `dicts.dirs_shallow`（精选敏感路径）；`deep` = 全量分层字典 + dirmap + 后缀派生。任务选项 `dirscan_full=true` 把单任务强制成 deep |
| dirscan.suffix_aware | true | 深扫专用：对命中的文件名型路径派生 `.bak`/`.zip`/`.old` 等备份变体（额度同 `max_paths`） |
| dirscan.recursive_depth | **0（关）** | 深扫专用：对命中的**目录型**路径再往下打几层。任务选项 `recursive_dir=true` 至少开 1 层（策略填了更大的值按策略走） |
| dirscan.recursive_max_dirs | 5 | 每个站点在**所有递归层合计**最多递归几个目录（不是每层各算一份）。限"目录数"不能省：K 由扫出多少个目录决定，不受字典大小控制 |
| dirscan.recursive_max_paths | 40 | 每个递归目录再打多少条**浅扫精选**字典（不是再来一遍大字典） |
| dirscan.tech_aware | true | 按 `sites.tech` 选字典：Java 站只吃 jsp+common，PHP 站只吃 php+common |
| dirscan.big_dict / max_paths | true / 400 | 未知栈时用全量字典；单站点最多扫多少条（硬节流） |
| portscan.mode / full_ports | top / 1-65535 | `full` 走全端口；也可由任务选项 `portscan_full` 单次触发 |
| portscan.exclude_scanned | true | 跳过本任务已扫过的端口 |
| fofa.title_enabled / title_threshold | true / 200 | 标题反查开关；命中数超过阈值判为"公共标题"放弃拓展 |
| fofa.title_match | label | 标题反查**归属相关性**：`label`＝标题 token 须与候选域名某个 label 完全相等；`substring`＝旧的子串匹配（回退/对照） |
| fofa.max_title_queries | 10 | 每任务最多反查多少个站点标题 |
| vulnscan.enabled | true | **阶段级**开关：漏洞初筛整阶段开关（关掉即"只测绘不探测"） |
| takeover.enabled / jsmine.enabled | true | 子域接管 / JS 挖掘的阶段级开关 |
| portscan.enabled / screenshot.enabled | false | 端口与服务扫描 / 站点截图 的阶段级开关（**均默认关**） |
| cert.enabled / max_sites / timeout / tls_ports | **false** / 30 / 8s / [443,8443,9443] | TLS 证书取证（**默认关**）：握手目标上限与超时；`tls_ports` 决定"非 https 但端口命中"的站点是否也试。建任务勾选或 CLI `-p cert` → 任务级 `cert_on` 单次生效 |
| dirscan.enabled / vulnscan.enabled | true / true | 目录发现（**默认开、默认只浅扫**）/ 漏洞初筛（默认开）的阶段级开关。想要早期那种"目录默认不扫"的行为，把 `dirscan.mode` 之外的总开关关掉即可 |
| intel.enabled / heuristic.enabled / github.enabled | false | 三个「**线索**」阶段的阶段级开关（均默认关；只写 `leads` 表，不写 `vulns`） |
| limits.brute_max_domains | 50 | 参与 DNS 爆破的域名上限 |
| limits.wildcard_filter | true | 泛解析过滤：目标开 `*.domain` 时丢弃通配命中的字典结果 |
| limits.favicon_md5 | true | probe 阶段计算 favicon MD5（POC 可据此做零请求前置判定） |
| limits.max_inflight_global | 256 | **F2 统一门控**：进程级在飞上限（**跨任务共享**）；0 = 不限 |
| limits.max_inflight_per_task | 256 | F2：单任务在飞上限；0 = 不限。实际并发 = `min(阶段并发, 本项, max_inflight_global)` |
| limits.rate_per_sec | 0 | F2：全局限速（令牌桶，次/秒）；0 = 不限速 |
| limits.rate_burst | 0 | F2：令牌桶突发容量；0 → 取 `max(rate_per_sec, 1)` |
| limits.budget_total | 0 | F2：单任务请求总预算（HTTP / 裸 socket / 子进程共用）；0 = 不设预算。**耗尽＝按停止**（任务标 `stopped` + `[throttle]` 错误行） |
| limits.budget_subprocess_weight | 1 | F2：一次外部工具调用消耗的预算单位 |
| subdomain.union_passive | true | subfinder(-all) 与内置免 key 被动源**取并集**（关掉＝只用 subfinder，省时间） |
| subdomain.max_resolve / dns_timeout | 500 / 3s | 子域名 IP/CDN 回填的解析上限与单次 DNS 超时（超上限的子域名仍入表，只是无 IP/CDN） |
| checks.min_severity | medium | 最低报告级别（结果级门控）；info/low 项默认不产出 |
| checks.skip_severities | ["info","low"] | **执行级**门控：这些级别连请求都不发（内置检查 + POC 引擎同规则） |
| checks.poc_engine | true | POC 引擎总开关（关闭后只跑内置启发式检查） |
| checks.disabled_categories / disabled_checks | [] | 按 OWASP 分类 / check id 关闭（根本不执行） |
| checks.poc_link_tags | true | 指纹→POC 联动：站点技术栈命中的 POC 优先执行且不受每站点上限约束 |
| checks.poc_max_per_site | 80 | 每站点最多执行多少个 POC（联动命中项不计入） |
| takeover.enabled / max_hosts / http_check | true / 300 / true | 子域接管检测：开关、主机上限、是否补一次 HTTP 特征比对降误报 |
| portscan.enabled / max_hosts / ports / timeout / workers / banner | **false** / 100 / 空(TOP 表) / 1.0s / 64 / true | 端口与服务扫描（默认关）；端口支持 `"80,443"` 或 `"1-1024"` |
| jsmine.enabled / max_pages / max_js / secrets / blacklist | true / 20 / 40 / true / [] | JS 资产挖掘：开关、页面/JS 上限、是否提取凭据、额外排除的第三方域后缀 |
| iprecon.enabled / api / max_ips / max_hosts / max_domains_per_ip / workers / timeout | **false** / api.webscan.cc / 500 / 200 / 30 / 5 / 10s | C 段反查（默认关）：接口地址（留空回落默认）、待查 IP/主机上限、单 IP 域名上限（超过判共享主机，不纳入资产）、并发与超时 |
| fofa.enabled / max_sites / max_assets / workers / black_ico_threshold | **false** / 30 / 100 / 5 / 200 | favicon（mmh3）反查同源资产（默认关）：算 favicon 的站点上限、单次查询资产上限、并发、黑 ico 阈值（命中数超过即放弃拓展） |
| fofa.cert_enabled / cert_threshold / max_cert_queries | true / 200 / 10 | 证书反查（`cert="domain"`，跟随 favicon 开关）：通用证书阈值（命中数超过即放弃拓展）、每任务最多查几个注册域 |
| blacklist.enabled / path | true / config/blacklist.txt | 用户黑名单：命中即不入资产库（含其所有子域）；纯文本、每次重读、可直接手工编辑 |
| （`config/keys.yaml`） | 空占位 | 第三方 API key 专用文件，**不在本文件里**；`load_keys()` 只读、GUI 不写回 |
| passive.enabled / sources / timeout | true / 默认 6 源 / 20s | 多来源被动子域名收集的开关、来源清单、单源超时 |
| evasion.random_ua / spoof_xff / waf_bypass / bypass_level / waf_detect | true / false / true / 2 / true | 动态免杀：UA 随机化、XFF 伪装、payload 变形及强度、WAF 探测 |
| dirscan.fw_max_paths | 150 | 深扫时补一轮「框架字典 + 暴露面字典」内置扫描的额度（0 = 关闭，判不出框架也不吃这份额度） |
| portscan.engine / full_workers / full_timeout | auto / 256 / 0.5s | 端口扫描引擎：`auto` = fscan → nmap → 内置 TCP connect（也可钉 `fscan`/`nmap`/`builtin`）；全端口模式的并发与超时 |
| screenshot.enabled / max_sites / window / timeout / browser | **false** / 20 / 1280x900 / 30s / 空 | 站点截图（默认关）：站点上限、视口、单站超时、浏览器路径（留空自动探测 Edge/Chrome） |
| intel.enabled / source / url / cache_hours / timeout / max_leads | **false** / kev / 空 / 24h / 20s / 50 | 情报订阅（默认关）：源名（内置 `FEEDS`）、覆盖地址（留空用内置，可换自建镜像）、缓存有效期（0 = 每次拉取）、拉取超时、单任务线索上限 |
| heuristic.enabled / max_leads | **false** / 50 | 启发式候选（默认关、零出站）：阶段开关与单任务线索上限 |
| github.enabled / max_domains / max_queries / per_page / max_leads / timeout | **false** / 3 / 4 / 30 / 30 / 20s | GitHub 泄露检索（默认关）：待检索注册域上限、查询条数上限、单查询返回条数、单任务线索上限、请求超时。**token 不在这里** —— 填 `config/keys.yaml` 的 `github.token`，没配就一次请求都不发（代码搜索接口要求认证）；只落仓库/文件路径/命中规则名，且请求恒 `auth=False` |
| tools.fscan | fscan | fscan 二进制名/路径（缺省只在 PATH 找，找不到跳过）；调用时强制 `-np -nobr -nopoc`，只用其端口发现能力 |
| tools.* | — | 外部工具路径/命令（subfinder / puredns / httpx / nmap / dirmap.python·script·threads …） |
| dicts.* | — | 各字典路径：**浅扫 `dirs_shallow`** + 技术栈字典（`dirs_common`/`dirs_jsp`/`dirs_php`/`dirs_asp`）+ 框架字典（`dirs_wordpress`/`dirs_spring`/`dirs_weblogic`…12 桶）+ 暴露面 `dirs_exposure` + `dicts.cdn_cname`（CDN 厂商 CNAME 后缀名单） |
