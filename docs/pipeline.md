# 流水线说明

默认阶段顺序：`subdomain → takeover → portscan → probe → osint → jsmine → dirscan → vulnscan`
（CLI 可用 `-p` 裁剪，GUI 用复选框勾选）。

其中 `takeover` / `jsmine` / `dirscan` / `vulnscan` 由**策略级开关**控制、默认开，
`portscan` / `osint` 默认关：
勾选只表示"这个阶段参与本次任务"，真正执行与否还看
`settings.takeover.enabled` / `portscan.enabled` / `jsmine.enabled` /
`dirscan.enabled` / `vulnscan.enabled`
（阶段内部自查后打日志跳过，且**连请求都不发**）。`osint` 更特殊 —— 它没有自己的 `enabled`，
而是由两个**子能力开关** `iprecon.enabled` / `fofa.enabled` 控制，**两者都关时整阶段直接跳过**。

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
| `nmap -sT -Pn -n --open -p <ports> -oG -` | portscan | nmap 适配器（`-sT` 免 root）；未装则内置 TCP connect 兜底 + 被动 banner |
| （手工没有的部分） | osint | IP 反查域名 + `/24` C 段归纳；favicon（mmh3）→ FOFA 反查同源资产，黑 ico 放弃拓展 |
| （手工没有的部分） | jsmine | 抓站点 JS → 提取域名/接口 URL/疑似凭据，第三方域黑名单 + 前后文降噪 |
| `httpx -l httpx_url -mc 200,301,302,403,404` | probe | httpx 适配器（另加 `-title -tech-detect -json` 提取信息）；`-mc` 白名单一致 |
| `python dirmap.py -iF dir_out -e all` | dirscan | dirmap 适配器（`-iF` 批量 URL），并解析其 `output/` 产物 |
| （手工没有的部分） | vulnscan | POC 引擎 + OWASP Top10 启发式检查（分级/分类门控 + WAF 探测） |

## 各阶段细节

### ① subdomain 子域名收集

- 输入：目标中的裸域名（URL/IP 目标不参与，直接进入 probe）；
- 处理：subfinder 被动收集（装了才用）→ 不稳定时改用内置 `scanner/passive.py` 多来源免 key 被动收集
  （`passive.enabled` 控制；单源失败只影响该源）→ puredns 对域名字典爆破（上限 `limits.brute_max_domains`）→ 合并去重；
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
- 处理：nmap 优先（`-sT -Pn -n --open -p <ports> -oG -`，`-sT` 无需 root），
  未装则内置 TCP connect 兜底；`portscan.ports` 留空用内置 48 项 TOP 表，
  也可写 `"80,443,8080"` 或 `"1-1024"`；连接成功后对会主动问候的端口读 **banner**（纯被动读取）；
- 产物：SQLite `ports` 表、任务详情页「端口服务」页签、报告「开放端口与服务」小节
  （原侧边栏「端口服务」全局栏已移除 —— 该数据属任务维度，在详情页看更贴合上下文；数据未删）；
  同时 `ports` 会被下一阶段 `probe` 消费（见 ④）—— 这是"能扫出 `:9007` 这类非标端口站点"的原因；
- 为什么默认关：端口扫描耗时与噪声明显高于其他阶段，CTF 里常只给一个 Web 入口；
  **明确不调用 masscan**（需 root 且激进，违反非破坏性红线）。

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
  第三方公共域走 78 条黑名单过滤（统计/CDN 等），**目标自身域永不误杀**；
  `jsmine.secrets=true` 时启用凭据提取，经两级降噪（厂商前缀/赋值语境 → 占位符/变量引用/成员访问过滤）；
- 产物：新域名补入 `subdomains`（`source="js:mine"`，只补任务里还没有的；在「拓展域名」页展示）、
  接口 URL 落 `js_urls.txt` 并进 `ctx.results["js_urls"]`、疑似凭据以 **high** 级进 `vulns`（`poc_id=js-secret-*`，值掩码脱敏）；
  入库前同样过用户黑名单（`config/blacklist.txt`）；
- 局限：纯正则（不做 sourcemap 还原）；短 token 与含 `test/demo` 的真实值会被保守丢弃。

### ⑦ dirscan 目录发现

- 开关：`dirscan.enabled`（**默认开**）—— 关闭后整阶段跳过；CTF 里 `.git` / 备份文件 / 后台入口
  这类高价值路径主要靠它发现，所以默认开，纯资产测绘任务可整体关掉省时间；
- 输入：存活站点（上限 `limits.dirscan_max_urls`，防止大目标拖爆）；
- 处理：dirmap 适配器（cwd 固定在其项目目录运行，扫描 `output/` 最新产物解析 URL 与状态码）；
- 产物：`dirs.txt`、SQLite `dirs` 表；
- 降级：内置字典扫描（`config/dicts/dirs_small.txt`），每个站点先用随机路径建立"软 404 基线"，与基线长度几乎相同的 200 响应视为不存在。

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
  `checks.poc_max_per_site` 约束**，其余 POC 排在其后受限执行；POC 若声明了 `favicon_md5_list`
  且与 `sites.favicon` 不符，**零请求**直接跳过；
- 注入探测的"动态性"：payload 变体按 `evasion.bypass_level` 生成（注释替空格/大小写/内联注释/
  URL 编码/双重编码/关键字分片），**每次运行的变体顺序随机**，参数顺序也随机 —— 请求形态不固定，
  降低被 WAF 规则固化识别的概率；原始 payload 始终排第一（最便宜、命中率最高）；
- 产物：SQLite `vulns` 表、GUI 漏洞页、Markdown 报告；
- 并发：站点级并发（max_workers/2），站点内部串行，避免对单目标压力过大。

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
├── dirmap_in.txt     # 传给 dirmap 的 URL
└── dirs.txt          # 目录发现
```

> `portscan` / `osint` 阶段不落文本产物（结果直接进 SQLite `ports` / `csegs` 表，新域名进 `subdomains` 表）；
> 子域名阶段的 **IP / CDN 回填**同样只进 `subdomains` 表（`ip` / `cdn` 两列），不额外落文件；
> `vulnscan` 结果进 `vulns` 表，Markdown 报告用 `scanner/report.py` 或 GUI 导出按钮生成。

## 配置项速查（config/settings.yaml）

| 配置 | 默认 | 作用 |
|---|---|---|
| limits.max_workers | 20 | HTTP/DNS 并发线程数 |
| limits.http_timeout | 10 | 单请求超时 |
| limits.verify_tls | false | 是否校验 HTTPS 证书；默认关闭以适配自签名靶场/CTF |
| limits.dirscan_max_urls | 20 | 参与目录扫描的站点上限 |
| limits.vulnscan_max_urls | 100 | 参与漏洞扫描的站点上限 |
| dirscan.enabled | true | **阶段级**开关：目录/路径发现整阶段开关（关掉连请求都不发） |
| vulnscan.enabled | true | **阶段级**开关：漏洞初筛整阶段开关（关掉即"只测绘不探测"） |
| takeover.enabled / jsmine.enabled | true | 子域接管 / JS 挖掘的阶段级开关 |
| portscan.enabled | false | 端口与服务扫描的阶段级开关（默认关） |
| limits.brute_max_domains | 50 | 参与 DNS 爆破的域名上限 |
| limits.wildcard_filter | true | 泛解析过滤：目标开 `*.domain` 时丢弃通配命中的字典结果 |
| limits.favicon_md5 | true | probe 阶段计算 favicon MD5（POC 可据此做零请求前置判定） |
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
| tools.* | — | 外部工具路径/命令 |
| dicts.* | — | 各字典路径（含 `dicts.cdn_cname` = CDN 厂商 CNAME 后缀名单，供子域名 CDN 标记） |
