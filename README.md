# CTFScanner

面向 **CTF 与授权渗透测试** 的一体化资产测绘与漏洞初筛框架。参考灯塔（ARL）的任务化思路，把常用的「子域名收集 → 子域接管 → 端口服务 → 存活探测 → TLS 证书取证 → 站点截图 → 外部情报拓展 → JS 资产挖掘 → 目录发现 → 漏洞初筛 → 情报订阅 / 启发式候选 / GitHub 泄露检索」**13 阶段**流水线产品化：

- **CLI 客户端**：导入目标文件，全自动执行完整流水线；
- **Web 控制台（GUI）**：仿 ARL 的任务/资产/漏洞/POC 管理界面（**14 栏侧边栏**：仪表盘 / 任务管理 / 子域名资产 / 站点资产 / IP 资产 / **全端口扫描** / 漏洞风险 / POC 管理 / **外部工具** / 策略配置 / **账号管理** / **执行节点** / **访问审计** / **数据迁移**；后 7 栏 `admin_only` —— 子用户**不渲染**且路由层 403；`dev.enabled=true` 时管理员另有第 15 栏「开发模式」），可视化添加目标并发起扫描，支持任务批量停止/重启/删除与报告导出，任务详情页可对**中断的任务「续跑」**（从断点接着跑，不清已有资产）；子域名标出**解析 IP 与 CDN/非 CDN**（可标签过滤）、**来源可读标签**（能一眼看出哪些是 FOFA 找出来的），可勾选行**批量加入黑名单**或**批量跑子域名（新建任务）**；拓展域名与站点页**默认隐藏重叠资产**（页顶开关 `?all=1` 放开），站点页另折叠同任务内「标题+响应长度」相同的重复项；**六个资产页都能「按任务筛选」**（与漏洞页同口径，筛选状态活过翻页与切标签）；子域名/拓展域名**同一域名只显示一行**（来源按权威性排序，被并掉的写进「另见于 …」）且**默认只列解析成功的**（被收起的条数报出来，`?nores=1` 展开）；3xx 站点显示**「跳转后」**（`301 → 200` + 落地页标题与最终 URL，原始那一跳不改写）；
- **换机器迁移有界面了（续138）**：「数据迁移」页（仅管理员）导出任务与资产成一份 JSON 包、
  或把别人给的包**先预检再确认**地导入。默认**零凭据** —— 账号口令哈希、`config/keys*.yaml`、
  任务里带的 Cookie/Authorization 一个都不带，页面上也**没有**打开它们的开关（那是 CLI 的
  `--with-users` / `--with-task-auth`，警告会在终端逐条列给你看）；反过来，包里真带这些东西的，
  页面直接拒收。导入前的整库快照会保留，导进来的任务一律 `stopped`（不会因为导入就自己开扫）；
  要跨不可信信道发包，加 `--export-scan --encrypt-bundle`（口令只走环境变量
  `CTFSCANNER_BUNDLE_PASSPHRASE`）；要连日志一起带走加 `--with-logs`（默认不带，只带 `logs/` 内的）；
- **多用户与角色（2026-09-26 起）**：账号 + 口令登录（口令只存 `pbkdf2_sha256` 派生值 —— 20 万次迭代 + 每账号随机盐，**不存明文、也不进日志**，零第三方依赖），分**管理员 / 子用户**两级：管理员可创建 / 停用 / 重置子用户，能进策略配置与 POC 管理；**子用户只能使用扫描功能与查看结果** —— 策略配置、POC 管理、账号管理三处在**路由层**即返回 403（侧边栏对子用户也不显示，但真正的控制是路由那层，直接敲 URL 同样被挡）。迁移口径：旧的 `gui.token` 只作**引导口令**（库里还没有任何账号时仍可登录并作为管理员），一旦建了第一个账号就**立即失效**；引导口令本身在续113 起**也只存 PBKDF2 派生值**（在策略配置页重设一次即可，明文列被清空、输入框不再回显）；第一个账号被强制设为管理员，保证不会把老部署锁在门外；管理员口令全丢时可在项目根执行 `py -3 -c "from scanner import db, users; db.init_db(); print(users.create_user('admin','新口令',role='admin'))"` 重建（不动任务与资产数据）；
- **POC 管理**：YAML 格式 POC 引擎（**nuclei 语法兼容子集**：含 `raw` / `flow` / `workflows` 子集支持），可直接加载官方 nuclei 模板，支持上传、启停、目录扫描；
- **检测分级门控（四层）**：阶段级总开关（`vulnscan.enabled`，关闭即"只测绘不探测"）+ 按级别整体跳过（`skip_severities`，默认 info/low **连请求都不发**）+ 按最低报告级别收敛结果（默认 medium）+ OWASP 分类 / 单项检查开关，默认屏蔽"太 low 的洞"；
- **动态免杀**：UA 随机化、浏览器化请求头、WAF 指纹识别、注入 payload 变形（分级 0~3，变体与参数顺序每次随机）；
- **信息收集增强**：免 key 多来源被动子域名收集（crt.sh / certspotter / alienvault 等）+ 泛解析过滤 + 子域接管指纹（41 条第三方服务）+ 子域名**解析 IP / CDN 标记**（`config/dicts/cdn_cname.txt` 292 条厂商 CNAME 后缀 + `config/dicts/cdn_ips.txt` 15 段厂商任播 IP 段，CNAME 优先、IP 段兜底，纯 DNS 只读判定）+ JS 资产挖掘（域名/接口/疑似凭据，JS 与情报带出的域名归入**拓展域名**页）+ **外部情报拓展**（`/24` C 段反查域名；favicon 的 mmh3 去 FOFA 反查同源资产，命中过多的"黑 ico"主动放弃拓展；**TLS 证书反查** `cert="domain"` 与**标题反查** `title="xxx"`，命中过多的"通用证书 / 公共标题"（如 404 默认页）同样放弃 —— 模板页标题连查询都不发）+ **用户黑名单**（`config/blacklist.txt`，入库前过滤，命中域名连子域都不入资产库）；**拓展域名**按来源分类排序（JS 挖掘 → FOFA·标题 / 证书 / ICO → C 段，不交错），并可对勾选域名手动**解析 DNS / 送去探测（新建 `subdomain→probe→dirscan→vulnscan` 任务）/ 归属本项目的追加为子域名 / 加入黑名单** —— 这类域名未必属于目标，不自动全跑）；拓展域名页**按主域名分组折叠**（`?group=0` 切回平铺）；
- **站点存活口径与二层遍历（续139）**：`probe` 不再挂状态码白名单 —— **服务端回了一个真实 HTTP 状态码就记站点**（`probe.is_alive`，含 301/403/429/500/502/521），因为 CDN 边缘活着、源站挂了本身就是资产事实（旧口径 `-mc 200,301,302,403,404` 实测漏掉 **49 台**主机 —— 灯塔记为站点、我们连行都没有，其中 **34 台**我们本来就有子域名、探过却被整行丢掉）；httpx 加 `-nfs` 锁住 scheme，`http://h` 的 301 才会稳定成行，再配「跳转后」取证（库里存的仍是那一跳，落地 url/状态/标题另存 `redirect_*` 三列）；站点日志按状态码首位摊开组成（`2xx=… 3xx=… 5xx=…`），免得"存活站点 168 个"被读成"168 个打得开的站"；`jsmine` 之后触发**二层遍历**（`probe.second_pass`）：把第一轮之后才长出来的域名（JS 挖的 + 库里本任务还没探过的）先过 DNS 预筛再补探一轮，只探归属本任务的域名、有上限（`limits.recrawl_max_hosts`，预筛另有 `max(10×上限, 50)`）、跳过的每条都报原因；子域名那层字典**分两档**：`config/dicts/subdomains.txt` 精简档（永远全量参与）+
  `config/dicts/subdomains_deep.txt` 深档（**续139 随仓库分发 177,875 条**，来源写在文件头；
  `subfinder` 之外的爆破覆盖面就靠它，不想要就 `git rm config/dicts/subdomains_deep.txt`）；
  再深的一档自己喂：`python tools/import_subdomain_dict.py --src <你那份深字典>`（清洗 + 去重 + 并集，
  **默认写回目标就是上面那份深档**，精简档一字不动；纯离线，`--dry-run` 只看数不写文件）；
  词数闸门 `limits.brute_max_words`（puredns 那一路的深档上限，0=全量）/ `limits.brute_fallback_max`
  （内置那一路的深档上限，默认 3000）只做**等距抽样且只冲深档**（精简档任何闸门都不冲），
  内置那一路另有独立并发 `limits.brute_workers`（默认 64：纯 DNS 等待，实测 3000 条 @20 线程
  ≈ 53 秒 ⇒ 全量 17.8 万条即使 128 线程也跑了 45 分钟仍未跑完，128 线程跑 45 分钟仍未跑完（全量只有 puredns 现实可行）），
  **没导入深档时**按 `limits.brute_dict_warn_min`（默认 1000）主动喊（随包带深档 ⇒ 默认安装不触发），每轮报「N 域名 × M 词 = X 次 DNS 查询」；没有 puredns 时深档按抽样跑（日志指路装它）；建任务（或 CLI `--auto-expand`）勾「**自动拓展扫描**」后本次任务自动补 `osint`/`jsmine` 阶段、拓展结束后自动做 DNS **存在性判定**、把**注册域属于本项目**的拓展域名（如目标 `pengo.pro` 拓展出 `aaa.pengo.pro`）**追加成正常子域**（原拓展行保留、出处可查）、目标是子域时自动补收其主域名；
  另有**组合爆破**（`limits.brute_combo_max`，默认 4000）：把精简档词与本任务已发现名字的首段两两拼成
  `a-b` 再爆一轮 —— 与灯塔逐条比实时，它独有的域名里有 10 个**任何字典里都没有**（`api-contract`、
  `ws-spot`、`admin-oss`），只有拼得出来；这类结果的来源标记是 `dns-brute(combo)`。
- **端口与目录**：内置 TOP 48 端口表 + **fscan / nmap 适配**（`portscan.engine`：`auto` = fscan → nmap → 内置 TCP connect；调用 fscan 时强制 `-np -nobr -nopoc`，只用它的端口发现能力，输出解析按 fscan 2.2.1 **真实形态校准**并用其"发现 N 个开放端口"统计行交叉校验，数目不符即回退、不静默漏报）+ 内置 TCP connect 兜底；**全端口扫描（1-65535）**可从侧栏「全端口扫描」页对单个 IP 发起（按任务分布展示，自动跳过已扫过的端口，不污染全局策略）；**目录发现走「浅 / 深两档」**——默认**开**但只跑**浅扫**（`dirscan.mode=quick`：`config/dicts/dirs_shallow.txt` 精选通用敏感路径约 150 条/站，如 `.git`、`.env`、备份与数据库转储、中间件控制台），适合"先浅浅过一遍"；**深度扫**（`mode=deep` / 建任务勾「全目录深扫」/ 结果页「补扫」）才启用 **11882 条大字典**、dirmap 优先调用与备份后缀派生，**只扫不重复站点**、**按技术栈与框架选字典**（Java/PHP/ASP 各自的语言字典 + WordPress/Spring/Weblogic 等 12 个框架字典 + 通用暴露面字典），结果按「**站点 + 状态码 + 响应大小**」折叠重复长度并展示包大小与**命中页标题**；**整站统一的 WAF/CDN 拦截页不计为目录发现**（`config/dicts/waf_block_titles.txt` 的厂商专属标题文案 + 随机路径同内容的 403 基线两条判据，滤掉几条按站点写进任务日志，不静默少结果）（内置扫描从已在手里的响应体提取，零额外请求），默认排序为 **200 优先 → 大小降序**；浅扫结果页可勾选站点**一键发起独立补扫任务**（`POST /api/rescan`，只跑 dirscan/portscan/screenshot 单阶段，不改全局策略）；
- **TLS 证书取证**（策略级默认关，**建任务勾「SSL 证书」或 CLI `-p cert` 即对本次生效**）：对值得握手的站点（`https://` 或端口命中 `cert.tls_ports`）做**一次只读 TLS 握手**，用**纯标准库** ASN.1/DER 解析出 CN / 颁发者 / 有效期 / 剩余天数 / 是否自签 / 签名算法 / SAN / SHA256 指纹，进 `certs` 表 + 任务详情「SSL 证书」页签 + 报告小节，**不引入 `cryptography`**。握手**不校验证书**（CTF 目标多为自签/过期）—— **「自签 / 已过期」是证书属性、不是漏洞结论**，页签与报告都写明了这一点；页签按数据源实有出现，没有产物时说明原因；
- **站点截图**（策略级默认关，**建任务勾「截图」即对本次生效**）：调用本机已装的 Edge/Chrome 无头模式截图，产物落在任务目录并在站点页 URL 旁显示缩略图，不引入任何新依赖；站点页签可对勾选站点**补截图**（`stage=screenshot`），没有产物时页面会说明原因（策略关 / 本机无可用浏览器 / 截图失败）；
  同一次浏览器调用还会**顺带补「渲染后标题」**（续140，`--dump-dom` 零额外启动）：
  Next.js/Vue 这类 SPA 外壳的原始 HTML 里**根本没有** `<title>`，标题是 JS 注入的，
  所以那一列的 `-` 不是抓取失败；只补空标题、绝不覆盖已经拿到的，且没开截图时探测日志会直接说出
  「多少个站点原始 HTML 里没有 `<title>`」并指出这条出路；
- **线索层：情报订阅 + 启发式候选 + GitHub 泄露检索**（三个阶段**默认关**）：拉取 **CISA KEV**（免 key 公开 JSON，只收录已被在野利用的 CVE）与本地指纹做**白名单式匹配**；对已采集数据做**零请求**的差分/异常聚合（软 404 模板 / 高价值入口暴露 / 同标题多主机 / 目录命中离群 / 同 C 段多 IP）；以及拿目标的**注册域**去 **GitHub 公开代码**里搜命中（需在 `config/keys.yaml` 填 `github.token`，**没配就一次请求都不发**）。三者产出**只是「线索」**：独立 `leads` 表 + **JSONL 导出**（`type=lead` 行与 `counts.leads`），**不写漏洞、不计入漏洞数、不自动导入 POC**；页签与人读报告（MD / HTML）自 2026-09-24 起不再露出（用户口径），机器格式的口径不变。GitHub 检索另有两条硬边界：**只落仓库 / 文件路径 / 命中规则名**（绝不保存文件内容，避免把凭据明文写进本地库、日志与报告），且所有请求 **`auth=False`** —— 任务级登录态（目标侧 Cookie / Token）绝不发给 GitHub；
- **JS 敏感字符**：17 条凭据规则（AKID/LTAI/AKIA、JWT、私钥 PEM、数据库连接串、Slack/Telegram/SendGrid/Stripe 等）+ 两级降噪（占位符、变量引用、成员访问），命中值掩码脱敏后以 high 级入库，「拓展域名」页按域名显示敏感命中数；
- **OWASP Top 10**：内置轻量启发式检查（全部非破坏性，结论为"潜在漏洞/初筛信号"，需人工确认）；其中 **A01 敏感文件检查是数据驱动的** —— 路径、特征关键字、级别、说明都写在 `config/dicts/sensitive.txt`（`路径 | 关键字 | 级别 | 说明`，签名必填以免被统一 200 的软 404 页放大成误报），文件缺失时自动回退内置清单。
- **报告三格式 + 漏洞趋势**：三种格式共用**同一份数据快照**（`report.collect()`，防"某种格式少一节"的漂移）——**Markdown**（默认，CLI `--report` / GUI 任务行「导出」）、**自包含单文件 HTML**（样式内联、不引外链，可直接发人）、**PDF**（复用本机无头 Edge/Chrome 的 `--print-to-pdf`，**不引入新依赖**）；报告里所有来自被测目标的文本（标题 / URL / banner / evidence）**全量 HTML 转义**，避免"打开报告即执行 JS"的反射型 XSS。本机没有可用浏览器时 PDF **明确报错**（GUI 给一页说明 + 替代路径，CLI 退出码 1），不静默丢交付物；仪表盘另有**漏洞趋势统计**面板（级别分布条 + 最近 15 个任务逐任务计数，口径与报告一致：**已判误报不计入**，未知级别归入 `other` 不静默丢）；

> **法律与授权声明**：本工具仅可用于自己拥有或已获得书面授权的目标（CTF 平台、靶场、委托测试范围）。对未授权目标使用属于违法行为，后果自负。详见 [docs/security-notice.md](docs/security-notice.md)。

## 架构总览

```
                ┌────────────────────────────────────────────┐
                │           目标导入（文件 / 文本框）          │
                └──────────────┬─────────────────────────────┘
                               ▼
   ┌────────────────────── PipelineRunner（任务编排） ──────────────────────┐
   │                                                                        │
   │  ① subdomain 子域名收集      ② takeover 子域接管（CNAME 指纹）          │
   │     subfinder / puredns         dnsq CNAME 链 + 41 条第三方服务指纹      │
   │     内置 DNS 字典爆破兜底                                                │
   │                                                                        │
   │  ③ portscan 端口服务（默认关） ④ probe 存活探测（含二层遍历）                          │
   │     nmap 适配器 / 内置 connect   httpx 适配器 / 内置 requests 兜底        │
   │                                                                        │
   │  ⑤ screenshot 站点截图（默认关） ⑥ osint 外部情报拓展（默认关）        │
   │     本机无头 Edge/Chrome 截图     /24 C 段 IP→域名反查            │
   │                                   favicon(mmh3)/证书/标题→FOFA 反查│
   │                                                                     │
   │  ⑦ jsmine JS 资产挖掘            ⑧ dirscan 目录发现（默认开·浅扫） │
   │     域名 / 接口 URL / 疑似凭据      浅扫=精选敏感路径；深扫=dirmap/   │
   │                                   内置字典（技术栈+框架选字典，软404基线）│
   │                                                                     │
   │  ⑨ vulnscan 漏洞初筛             ⑩⑪⑫ intel / heuristic / github（默认关）│
   │     POC 引擎（YAML，nuclei 兼容子集） KEV 情报 × 本地指纹白名单匹配│
   │     OWASP Top10 检查 + 四层门控 + 绕 WAF  零请求差分/异常聚合      │
   │                                    GitHub 公开代码里搜目标注册域   │
   │                                    三者只产「线索」，不写 vulns   │
   └──────────────┬──────────────────────────────────────┬─────────────────┘
                  ▼                                      ▼
        SQLite（data/scanner.db）                logs/<task>/ 产物与日志
                  ▼
     ┌──────────────────────────┐   ┌─────────────────────────────────┐
     │ CLI：cli/client.py       │   │ Web 控制台：gui/app.py（Flask）  │
     │ 导入文件 → 全自动执行      │   │ 仿 ARL：任务/资产/漏洞/POC/设置  │
     └──────────────────────────┘   └─────────────────────────────────┘
```

设计原则：**外部工具优先、内置实现兜底**。subfinder / puredns / httpx / dirmap 存在时直接调用（与你的手工流水线一致），不存在时自动降级到内置实现，保证框架在任何机器上都能跑通。

## 安装与运行

### 0. 环境要求

- **Python 3.8+**（已在 **3.9.0 / 3.10.12** 上实测；代码无平台专属依赖，Windows / Linux / macOS 均可）
- 运行时依赖只有三个：`flask` / `requests` / `PyYAML`（见 `requirements.txt`）
- 可选外部工具：`fscan` / `nmap` / `dirmap` / `subfinder` / `httpx` / `puredns` —— **没有也能跑通**，
  会自动降级到内置实现（只是覆盖面和速度不如外部工具）
- 可选本机浏览器：Edge / Chrome / Chromium（仅"站点截图"与 PDF 报告需要）

> Windows 上如果 `python` 命令不可用，请试 **`py -3`**（AI 工具启动的 shell 里尤其常见 ——
> 详见 `AGENTS.md §2`：根因是 PATH 条目编码损坏，不是没装）。

### 1. 安装依赖

**一把就绪（续99，推荐）**：在项目根跑一条命令就够了 —— 它会自己建 `.venv`、**在系统解释器
没有 pip 时**用官方 `get-pip.py` 引导 pip（Ubuntu/Debian 把 ensurepip 拆进 `python3.x-venv`
包，这是常态）、装 `requirements.txt`，再把**官方带 SHA256 校验和**的外部工具
（subfinder / httpx / puredns）按平台装进 `tools/scanner/` 并回写 `tools.<名>`：

```bash
python3 run_bootstrap.py --install        # Linux / macOS
py -3 run_bootstrap.py --install          # Windows
python3 run_bootstrap.py                  # 只探测，**零网络**：先看这台机器还缺什么
```

之后请用虚拟环境里的解释器运行：`./venv/bin/python run_gui.py`（Windows 是
`venv\Scripts\python.exe run_gui.py`）。`nmap / fscan / dirmap` **不会被自动下载也不会被代跑**
（官方没有「可下载且带官方校验和的单二进制产物」），脚本会按平台打印该执行的命令。

手工路线（想自己管环境时）：

```bash
# ---- Linux / macOS（推荐虚拟环境）----
python3 -m venv venv && source venv/bin/activate
python3 -m pip install -r requirements.txt

# ---- Windows（PowerShell / cmd）----
py -3 -m venv venv
venv\Scripts\activate
py -3 -m pip install -r requirements.txt
```

不想用虚拟环境也可以 `python3 run_bootstrap.py --install --no-venv`（直接装到当前解释器），
或手工 `pip install -r requirements.txt`（全局）。

> **换机器请照 `requirements.lock` 装**：`python3 -m pip install -r requirements.lock`
> （Windows 是 `py -3 -m pip install -r requirements.lock`）。两份清单的分工是——
> `requirements.txt` ＝ **我要什么**（直接依赖 + 允许区间），
> `requirements.lock` ＝ **这次实测装出来的是哪些版本**（把传递闭包逐条钉成 `==`，
> Python 3.9 与 3.14 两边都实测装得动）。`run_bootstrap.py --install` 会优先用 lock、
> 当前解释器装不动就回落 `requirements.txt`，并在输出里明说这次用的是哪一份。
> **CI 也吃 lock**（`smoke.yml` 与 `quality.yml` 共四处安装步骤），这样"CI 绿的版本"和
> "你本机装出来的版本"才是同一批 —— 手工路线照 txt 装当然也行，只是别奇怪版本对不上。

### 2. 配置（**可跳过** —— 不配任何 key 也能完成子域名 / 端口 / 探测 / 目录 / 漏洞初筛）

只有「外部情报拓展」（FOFA / Shodan / Quake / GitHub 检索）需要 key：

```bash
cp config/keys.yaml.example config/keys.yaml    # 然后填真实值；该文件已被 .gitignore 忽略，切勿提交
```

其余策略（阶段开关、并发限速、目录浅/深档、截图等）写在 `config/settings.yaml`，
也可以起服务后在「策略配置」页图形化修改（仅管理员）。详见下方 [配置说明](#配置说明部署前必看)。

### 3. 自检（第一次跑之前建议先做）

```bash
py -3 cli/client.py --check        # 检查外部工具可用性；没装的会如实列出，不会假装能用
```

### 4. 跑第一个任务（CLI）

```bash
# 从文件导入目标（每行一个：域名 / URL / IP / CIDR，# 开头为注释）
py -3 cli/client.py -f examples/targets.txt -n my-first-task

# 或直接给单目标；-p 是逗号分隔的阶段列表（缺省 = 全部 13 个阶段）
py -3 cli/client.py -t example.com -p subdomain,probe,dirscan,vulnscan -n quick-look
```

**轻扫建议**：默认就是轻档（端口扫 TOP 表、目录只打 `dirs_shallow.txt` 约 150 条精选路径）。
别一上来就 `--full-ports`（1-65535）或 `--full-dir`（深扫大字典）—— 那是投放/深度排查时才用的。
结束后可加 `--report out.md --report-html out.html --report-jsonl out.jsonl` 一并导出报告。

### 5. 起 Web 控制台

```bash
py -3 run_gui.py                   # 只绑本机 5000；入口见启动横幅（路径每次随机）
```

- **首次启动会直接向导问你要设什么管理员口令**（库里还没有账号时）。非交互环境（容器 / CI）
  跑 `python run_users.py --create-admin`。`config/settings.yaml` 里**没有任何登录凭据** ——
  那文件被 git 跟踪，能换管理员身份的串写在里面就等于公开（续117 摘掉了旧的 `gui.token`）。
- **后台地址每次启动随机生成**（续138）：控制台挂在 `http://127.0.0.1:5000/<10 位>/<10 位>/` 下，
  入口就是启动横幅那行 `[*] 控制台地址：…` —— **重启即换、不写进任何文件**。直接开
  `http://127.0.0.1:5000` 会得到 **404 空响应**（根路径与任何错误路径都是这个形状，故意的：
  不给扫端口的人留下"这儿有个后台"的信号）。⚠ 这**不是访问控制** —— 拿到那条 URL 的人照样到得了
  登录页，真门槛是 401 边缘门 + 账号口令这两道。要固定：`export CTFSCANNER_WEB_PATH=/console`
  （空串＝挂回根路径），或 `gui.web_path_random: false`。
- ⚠️ 改了任何会被控制台调用的代码后**必须重启进程**（`debug=False` 不重载代码也不重载模板），
  否则会误判成"代码没生效"。
- 要部署到服务器给队友用，**必须走 HTTPS**（反向代理终止 TLS）—— 见
  [docs/deploy-https.md](docs/deploy-https.md) 与下方 [配置说明](#配置说明部署前必看)。

### 5.5 用 Docker 跑（可选）

```bash
docker compose up -d --build     # 起控制台；数据/配置/日志都挂在宿主机上
                                 # （仓库根那个 docker-compose.yml 只是指向 docker_todo/ 的包装）
```

- **只改配置或字典不用重新打包**（它们是挂载进去的）；**改了代码**才需要 `--build`，
  或者用 `docker_todo/docker-compose.dev.yml` 把源码挂进容器（改完 `restart` 即可；两个 `-f`
  要一起给，写法见 `docker_todo/README.md` —— 拿根包装去拼 dev 覆盖会把仓库的**上一级目录**挂进去）。
- 端口默认只发布到**宿主机回环**（`127.0.0.1:5000`），要让队友用必须先配
  `gui.allowed_hosts` + 反向代理 —— 完整步骤与坑见 [docs/docker.md](docs/docker.md)。
- ⚠️ **容器化 ≠ 源码保密**：镜像是 `COPY . /app` 打出来的，同机任何能执行 `docker` 的人
  都能读走源码（而 `docker` 组 ≈ root）。真在乎就别把代码放上共享服务器 ——
  做法见 [docs/docker.md](docs/docker.md) 第 7 节。

### 6.（可选）一键装外部工具 / 全流程自检

```bash
py -3 cli/client.py --update-tools    # 一键装 subfinder / httpx / puredns（只在显式触发时联网）
py -3 run_devflow.py                  # 全流程自检：起内置靶场 → 压量到最小 → 真跑全 13 阶段
```

开发模式开关在 `config/settings.yaml` 的 `dev.enabled`，打开后控制台侧栏才出现「开发模式」页。

### 6.5 分布式执行节点（可选）

控制端（上面起的 GUI）**继续独占数据库**；其它机器可以作为**执行节点**来领任务跑：

```bash
# ① 在控制端生成一个节点令牌（**只显示一次**，请保存）
py -3 cli/client.py --node-add node-1

# ② 在**节点机器**上（同一份代码）跑：
py -3 run_node.py --controller http://<控制端>:5000 --token ctfsn_xxx --name node-1
```

- 节点在**自己机器**上跑扫描（写它自己的本地库 `logs/node-<名>/`），跑完把**资产快照**回传给
  控制端合并 —— 节点拿不到控制端的库，也看不到别的任务（令牌鉴权，可随时吊销）。
- 控制端建任务**不用**额外操作：任务照常入队，哪个节点先领到就哪个跑。
- 远程节点要求控制端的 `gui.allowed_hosts` 含控制端地址（见 [docs/deploy-https.md](docs/deploy-https.md)）。
- `py -3 cli/client.py --node-list` 看节点在线 / 占用；`--node-revoke <id>` 吊销令牌（立刻失效）。

### 7. 跑测试（改完代码必须做）

```bash
py -3 tests/smoke.py               # 唯一回归门禁：自包含起靶场，**约 9 分钟**
py -3 tests/browser_e2e.py         # 真浏览器端到端（可选；找不到浏览器会跳过而不是假绿）
```

smoke 会自己建临时库与临时目录（`CTFSCANNER_DB` / `CTFSCANNER_LOGS`），**不会污染**
`data/scanner.db` 与真实任务数据；跑完自动清理。

### 8. 常见坑（都已实测过）

| 现象 | 原因 / 办法 |
|---|---|
| Windows 上 `python` 找不到 | AI 工具启动的 shell 里 PATH 条目编码损坏 → 用 `py -3` |
| 改了代码页面没变 | 控制台进程没重启（不热重载）→ 重启 `run_gui.py` |
| 端口 5000 被占用 | 旧进程还在 → 结束它或改 `gui.port`；请求仍打到旧进程是新路由 404 的常见原因 |
| 目录扫出 0 条 | 看看是不是浅扫档（默认 150 条/站）；深扫要 `--full-dir` 或结果页「补扫」 |
| FOFA 没查询 | `fofa.enabled` 默认关；`config/keys.yaml` 也要填真实凭据 |

## 配置说明（部署前必看）

框架**开箱即跑**：不配任何 key 也能完成子域名 / 端口 / 探测 / 目录 / 漏洞初筛（这些走内置兜底或免 key 来源）。只有「外部情报拓展」的几条线路需要 key。

- **`config/keys.yaml`（第三方 API key，必须自建，已被 `.gitignore` 忽略）**：从仓库的 `config/keys.yaml.example` 复制一份 `config/keys.yaml` 填真实值。**切勿把真实 key 提交进仓库**（它已 gitignore；CI 跑者无此文件时 `load_keys()` 返回 `{}`，整轮冒烟仍可通过）。结构：
  ```yaml
  fofa:   {email: "", key: ""}   # FOFA（favicon / 证书 / 标题反查；settings.yaml 里 fofa.enabled 现为 false，配好 key 并显式打开才会真查并消耗配额）
  shodan: {key: ""}              # Shodan favicon 反查（默认关）
  quake:  {key: ""}              # 360 Quake favicon 反查（默认关）
  github: {token: ""}            # GitHub 泄露检索（默认关；没配就一次请求都不发）
  ```
- **`config/settings.yaml`（全局策略，已随仓库提交）**：GUI「策略配置」页可图形化修改并写回；CLI 也可直接编辑。常见开关：`fofa.enabled` / `iprecon.enabled` / `shodan` / `quake` / `ctlog` / `intel` / `heuristic` / `github`（外部情报类默认关）；`dirscan.mode`（`quick` 浅扫 / `deep` 深扫）；`screenshot.enabled`（站点截图，默认关，需本机有 Edge/Chrome 无头）；`portscan.engine`（`auto` = fscan → nmap → 内置）。
- **`config/blacklist.txt`**：一行一个域名，命中即不入资产库（入库前过滤）。
- **`config/dicts/`**：子域名字典、`dirs_shallow.txt`（浅扫精选路径 ~150 条）、`dirs_big.txt`（深扫大字典 11882 条）、`cdn_cname.txt`（CDN 厂商后缀）、`cdn_ips.txt`（CDN 厂商任播 IP 段）、`sensitive.txt`（A01 敏感文件检查的数据源：`路径 | 关键字 | 级别 | 说明`）。
- **外部工具（可选）**：`subfinder` / `puredns` / `httpx` / `dirmap` / `nmap` / `fscan` 存在时优先调用、否则降级内置实现，无这些工具框架仍能跑通。前三个（子域收集 / DNS 爆破 / 存活探测）可**一键安装**：CLI `python cli/client.py --update-tools`，或控制台管理员侧栏「外部工具」页；也可手工放进 PATH 或 `tools/scanner/`。一键安装**只在显式触发时联网**（扫描期零下载），只允许 https + 官方主机，默认必须通过 release 自带的 SHA256 校验和。

> 部署 checklist：① 复制 `config/keys.yaml.example` → `config/keys.yaml` 并填 key（仅当要用 FOFA 等外部情报）；② 按需改 `config/settings.yaml`（或 GUI 策略配置页，**仅管理员可改**）；③ `pip install -r requirements.txt`；④ 跑 `python cli/client.py --check` 自检；⑤ 起控制台后用 `gui.token` 引导登录，**立即到「账号管理」建管理员与子用户账号**（建号后引导口令失效）。

### 部署到服务器（给队友用 → 必须走 HTTPS）

控制台默认只绑 `127.0.0.1:5000`、只认回环 Host，入口路径每次启动随机（续138）—— **本机单人使用**的开箱形态。
要放到服务器上用域名访问，请**由反向代理终止 TLS**（应用侧不碰证书），并按需打开三项配置：
`gui.allowed_hosts`（放行部署域名，**不填会整站 403**）、`gui.behind_proxy`（信任
`X-Forwarded-*`，默认关）、`gui.secure_cookie`（会话 Cookie 加 `Secure`，TLS 就绪后再开）。
Caddy / Nginx 配置样例、自签证书路径、`curl` 验证清单与排错对照表见
**[docs/deploy-https.md](docs/deploy-https.md)**。
> 多用户上线后口令是**账号密码**，明文 HTTP 下会明文过线 —— 这一项不是"可选优化"。

放到服务器后，**访问审计流水**（`gui.audit`：谁/何时/从哪 IP/做了什么/成败，只记元数据、绝不记口令凭据；
管理员在「访问审计」页查看）与**登录限速/失败锁定**（`gui.login_lockout`：按 IP 为主、按用户名兜底，
被锁返回 429 + `Retry-After` 且不泄漏账号存在性）**默认就开**（续108 把 IP 阈值由 10 收到 **5**）；
两段阈值都**只能手改 `config/settings.yaml`** ——「策略配置」页的 gui 段只有 host/port 两项（续117 起没有口令那一栏）。
登录页另有一道**验证码**门（续108 起任何登录提交都**要**先过码，答案只存服务端内存、一次性）。
被锁在门外时用 `py -3 -m scanner.login_guard --clear` 自救（详见 docs/deploy-https.md §7）。

## 开发模式 + 全流程自检

**用途**：把各阶段的「量」（并发数 / 在飞数 / 速率 / 每阶段配额，共 47 项）**全部压到最小 `1`**，
用最小代价把整条流水线走一遍，验证**流程本身**跑得通、在哪一阶段断 —— 而不是测覆盖面（那是生产跑的事）。

- **开发模式开关**：`config/settings.yaml` 的 `dev.enabled`（默认 `false`）。打开后控制台侧边栏**才出现**
  「开发模式」一栏（**仅管理员可见**，未打开时该栏**根本不渲染**，直接敲 `/devmode` 也进不去）。
- **全流程自检**（本功能的验收手段，控制台与 CLI 双入口）：
  - **控制台**：「开发模式」页「跑一次全流程自检」按钮 —— 它**以子进程**调 `py -3 run_devflow.py`
    （`gui/app.py::api_devmode_selfcheck`），把子进程 stdout 原文渲染到页面。**为什么必须是子进程**：
    自检要在进程内装 **DNS 覆盖**（`socket.getaddrinfo` 的进程级全局钩子）+ 起本地夹具 + 把配额压到最小；
    装在**长驻的 web 进程**里非常危险（全局钩子会影响控制台自身的每一次解析、夹具端口/线程也可能泄漏）。
    放进子进程后覆盖随它退出一起消失，**控制台进程一个字节都不受影响**。页内另有「启动 / 停止内置靶场」
    两个按钮 —— 它们起的夹具**与自检用的夹具无关**（自检在子进程里起自己的），仅供**手动打开看一眼**，
    **不装任何 DNS 覆盖**。
  - **CLI**：`py -3 run_devflow.py`（与 `run_gui.py` 对称的独立入口）。它先起夹具 → 压量 → 依次跑全部
    13 阶段（`runner.run_task` 前台执行）→ 打印**每阶段 `真跑 / 跳过（带原因）/ FAIL` + 网络活动数 + 耗时**，
    无 `FAIL` 退出码 0，否则 1。**这是本功能的验收证据**。核心逻辑在 `scanner/devflow.py`
    （CLI 与 `tests/smoke.py [7n]` **共用**，避免两处判定漂移）。
  - **功能向量**（续62，用户指令「每个功能向量打一些，确保流程正确」）：阶段级判定之上再往下沉一层 ——
    `devflow.VECTORS` 列 **35 条阶段内子能力**（自动拓展/泛解析/内置爆破/回填、CNAME、fscan 引擎、
    内置探测/端口候选/favicon、TLS、截图、JS 挖掘、目录 模式/内置扫描/dirmap/框架/派生/递归、
    内置检查/POC 引擎、情报 拉取/匹配、启发式聚合、osint 3 项、github 检索），判据取自**本次运行的
    原生证据**（该阶段日志 / 外部命令 `argv[0]` / 请求 URL），**不做"跑过就默认全绿"**；三态
    `OK`（真点到）/ `MISS`（覆盖缺口）/ `N-A`（本次不该跑，**必带原因**）。CLI 会打印向量表 +
    `18 个点到、0 个覆盖缺口、17 个本次不可达` 汇总句与覆盖缺口清单。
- **内置靶场**（`scanner/devfixture.py`）：标准库 `ThreadingHTTPServer`，**HTTP 与 HTTPS 都只绑 `127.0.0.1`
  （绝不 `0.0.0.0`）**、**临时端口**（不占 80/443）。即时生成 `index.html` / `admin/index.html` /
  `robots.txt` / `app.js` / `.env`（`.env` 是**明显假的样例值** `devfixture-not-a-real-secret`）+
  `/intel/kev.json`（**情报源夹具**，内容标注 "NOT real data"）。HTTPS 用**内联自签证书**
  （CN=`devfixture.test`，有效期约 10 年，**不是任何生产凭据**）。每次启动写独立临时目录、停止即清理。
  它**不复用** `tests/smoke.py` 的 `smoke_root/`，是产品侧模块（不依赖测试夹具）。
- **自检怎么让"该跑的真的跑"**（续52）：目标是**夹具域名** `devfixture.test` / `www.devfixture.test`
  （RFC 2606 保留 TLD，**永远不解析到公网**）+ 一个带显式端口的 HTTPS URL。自检装**只覆盖白名单主机名**
  的 DNS 覆盖（`devfixture.test` 及其子域 → `127.0.0.1`，**其它域名一律放行给真实解析器、绝不重定向**，
  `try/finally` 保证还原）—— 于是 `subdomain`（有裸域名目标 + DNS 爆破）与 `cert`（有 https 站点可取证）
  都会**真跑**而不是空转。**零外网铁律**：自检副本里关掉会真出网的第三方能力（FOFA / Shodan / Quake /
  crt.sh）、**清空第三方凭据**（`keys` 置空，免得一次自检真花掉用户配额），`intel` 改指**本地夹具源**。
- **「跳过」的口径（续52 起带原因分类）**：某阶段**本次零网络活动**即记为 `SKIP`，**原因取自任务日志里
  该阶段的真实文本**（不是写死一张表），并归到 `无输入` / `未配置` / `无匹配` / `命中缓存` 之一 ——
  不再用一句笼统的"零网络活动"把四种原因混在一起。`portscan`（裸 socket）与 `heuristic`（零请求）恒为 `OK`。
  报告末句不再是"13 个阶段均无异常"，而是「**N 个真跑、M 个跳过（原因见上）、0 个 FAIL**」。
- **网络活动怎么数**（续52 起）：除了 `http_request` / `run_cmd`，还数**系统解析器**（`socket.getaddrinfo`）——
  因为 `subdomain` 的内置 DNS 爆破、`cert` 的 TLS 握手、`osint` 的 IP 反查都**不走** HTTP / 子进程。
- **`budget_total` 例外（**不压到 1**）**：`limits.budget_total` 与 `limits.budget_subprocess_weight`
  **刻意不压缩** —— 若把 `budget_total` 压到 `1`，第 2 个请求就被预算拒绝、流水线**永远跑不完**，
  自检本身自相矛盾（见 `scanner/devmode.py` 的 `DEV_KEEP` 与文件头注释）。
- **铁律（绝不写回）**：`devmode.apply()` 对入参**深拷贝**后逐项压量，**从不修改入参**，更**绝不把压缩结果
  写回真实 `config/settings.yaml`** —— 它只是运行时内存里的副本（与项目一贯的「任务专用副本」原则一致）。
  `devmode.report()` 返回「路径: 原值 → 1」清单，控制台开发模式页会把它列出来，便于核对压了哪些项。

> 打开开发模式后 `create_app()` 启动时会打印一行显式告警，提醒"当前是开发模式（量已压到最小）"。

## 目录结构

```
ctf-scanner/
├── cli/client.py            # CLI 客户端（导入文件、全自动执行）
├── run_devflow.py           # 全流程自检 CLI 入口（起内置靶场 → 压缩配置 → 跑全 13 阶段 → 打 OK/SKIP/FAIL）
├── gui/                     # Web 控制台（Flask + 原生 JS，仿 ARL）
│   ├── app.py               #   路由与后台任务线程
│   ├── templates/ static/   #   页面与样式
├── scanner/                 # 核心引擎（CLI/GUI 共用）
│   ├── runner.py            #   流水线编排、任务执行入口、协作式取消
│   ├── stages/              #   13 个阶段：subdomain / takeover / portscan / probe / cert / screenshot / osint / jsmine / dirscan / vulnscan / intel / heuristic / github
│   ├── pocs/                #   POC 引擎（nuclei 兼容子集）+ 内置示例 POC
│   ├── owasp/               #   OWASP Top10 启发式检查 + 分级/分类门控
│   ├── evasion.py           #   动态免杀（UA/请求头伪装/WAF 指纹/payload 变形）
│   ├── wildcard.py          #   泛解析识别与过滤
│   ├── passive.py           #   免 key 多来源被动子域名收集
│   ├── dnsq.py              #   纯标准库 DNS 客户端（含 CNAME 链解析）
│   ├── cdn.py               #   CDN 判定（按 CNAME 后缀匹配厂商名单，只读加载）
│   ├── takeover.py          #   子域接管指纹库（41 条第三方服务）
│   ├── portscan.py          #   端口/服务扫描（fscan / nmap 优先，内置 TCP connect 兜底）
│   ├── certs.py             #   TLS 证书取证（纯标准库 DER/ASN.1 解析，不引 cryptography）
│   ├── screenshot.py        #   站点截图（本机无头 Edge/Chrome 路径探测 + 截图）
│   ├── jsmine.py            #   JS 资产挖掘（域名/接口/疑似凭据 + 黑名单降噪）
│   ├── blacklist.py         #   用户黑名单（config/blacklist.txt，入库前过滤）
│   ├── auth.py              #   任务级登录态请求头（只发目标侧；fail-closed + 掩码 + 非法行不静默丢弃）
│   ├── users.py             #   控制台多用户：账号/角色 + 口令派生与校验（pbkdf2_sha256，零依赖、不存明文）
│   ├── login_guard.py       #   登录限速/失败锁定（续48：按 IP 为主 + 按用户名兜底，DB 计数，命令行自救）
│   ├── audit.py             #   访问审计流水（续48：只记元数据、绝不记口令凭据；按保留期清理）
│   ├── iprecon.py           #   IP 反查域名 + /24 C 段归纳（C 段视野）
│   ├── fofa.py  mmh3.py     #   FOFA favicon/证书反查 + 黑 ico / 通用证书判定；纯标准库 MurmurHash3
│   ├── intel.py             #   漏洞情报订阅：CISA KEV × 本地指纹白名单匹配（只产「线索」）
│   ├── heuristics.py        #   启发式候选发现：零请求差分/异常聚合（只产「线索」）
│   ├── github_leak.py       #   GitHub 泄露检索：GitHub 公开代码里搜目标注册域（只产「线索」）
│   ├── fingerprint.py       #   内置指纹识别 + favicon MD5/mmh3（httpx 不可用时填充技术栈）
│   ├── db.py  config.py  utils.py  targets.py
│   ├── queue.py             #   持久化任务队列 worker（续49：原子认领 + 重启重新入队）
│   ├── devmode.py           #   开发模式：把各阶段「量」压到最小 1（深拷贝、不写回、budget_total 例外）
│   ├── devfixture.py        #   内置靶场（标准库 HTTP/HTTPS，只绑 127.0.0.1，自检用；含内联自签证书 + 情报源夹具）
│   ├── devflow.py           #   全流程自检核心（夹具域名 + DNS 覆盖 + 压量 + 逐阶段 真跑/跳过/FAIL 分类；CLI 与 smoke 共用）
│   ├── report.py            #   报告三格式（Markdown / 自包含 HTML / 无头浏览器打印 PDF），共用 collect() 快照
│   ├── toolmgr.py           #   外部工具版本管理（续54：查 release → SHA256 校验 → 解包落盘 → 回写 tools.<名>；仅显式入口触发）
├── tools/import_ref_pocs.py #   参考项目 Python POC 静态导入器（产物默认关闭）
├── tools/import_dir_dict.py #   目录扫描大字典生成器（读 dirmap 字典 → config/dicts/dirs_big.txt）
├── tools/import_fw_dicts.py #   目录字典按框架细分生成器（从大字典派生 12 个框架字典 + 暴露面）
├── tools/import_subdomain_dict.py # 深档子域名字典导入器（续139：清洗 + 去重 + 并集写 config/dicts/subdomains_deep.txt，纯离线）
├── tools/dirmap/            #   dirmap 落点（目录联接，第三方项目不随仓库分发）
├── config/
│   ├── settings.yaml        # 全局配置（GUI「策略配置」页覆盖 gui/limits/checks/subdomain/passive/evasion/takeover/portscan/jsmine/dirscan/vulnscan/screenshot/iprecon/fofa/blacklist/intel/heuristic/github；另有 queue/dev 两个非策略页配置）
│   ├── keys.yaml            # 第三方 API key 专用文件（gitignore，GUI 不写回）
│   ├── blacklist.txt        # 用户黑名单（一行一个域名，# 注释；命中即不入资产库）
│   ├── dicts/               #   子域名两档字典（`subdomains.txt` 精简档 84 条，永远全量参与 + `subdomains_deep.txt` 深档 177,875 条，续139 随仓库导入）、resolvers、目录字典（dirs_shallow 206 浅扫精选 / dirs_small 55 / dirs_big 11882 / 技术栈与框架细分 + 暴露面）、cdn_cname.txt（CDN 厂商后缀）、cdn_ips.txt（CDN 厂商任播 IP 段）、sensitive.txt（A01 敏感文件检查的数据源：路径 | 关键字 | 级别 | 说明）
│   ├── pocs-user/           # 用户上传的 POC（GUI 上传后落在这里）
│   ├── pocs-imported/       # 批量导入的 POC（默认关闭，需在 POC 管理页挑选启用）
│   └── nuclei-templates/    # 官方 nuclei 模板投放点（可被本引擎直接加载）
├── tools/scanner/           # 外部工具放置区（subfinder/httpx/puredns/dirmap；前三个可一键安装，见该目录 README）
├── docs/                    # 文档（架构/流水线/POC 开发/OWASP 映射/使用/路线图）
├── data/scanner.db          # SQLite（首次运行自动创建）
├── data/trash/              # 删除任务前的自动备份（每任务一个 JSON，误删可据此找回）
└── logs/<task_*/>           # 每任务的工作目录与日志
```

## 文档索引

| 文档 | 内容 |
|---|---|
| [docs/architecture.md](docs/architecture.md) | 模块划分、数据流、数据库表结构、扩展点 |
| [docs/pipeline.md](docs/pipeline.md) | 13 个阶段的输入输出、与你手工流水线命令的对应关系、降级策略 |
| [docs/poc-guide.md](docs/poc-guide.md) | POC YAML 格式、匹配器语义、编写规范、如何上传与启停 |
| [docs/owasp-mapping.md](docs/owasp-mapping.md) | OWASP Top 10 逐项映射：已实现检查、实现方式、局限 |
| [docs/usage.md](docs/usage.md) | CLI 全参数、GUI 操作流程、常见问题 |
| [docs/deploy-https.md](docs/deploy-https.md) | **部署到服务器**：反向代理终止 TLS（Caddy / Nginx 样例）、自签证书、三项 `gui` 配置对照、验证清单与排错 |
| [docs/docker.md](docs/docker.md) | **Docker 部署**：一键起控制台、要不要重新打包、数据备份、外部工具、给队友用、**共享服务器上的源码保护**（含"容器化不等于保密"的实话） |
| [docs/roadmap.md](docs/roadmap.md) | 实际完成度对照与后续计划（含刻意不做的项及理由） |
| [docs/security-notice.md](docs/security-notice.md) | 授权与法律边界 |

## 客观说明（当前能力边界）

- 7 个内置示例 POC + **305 个由参考项目静态转换而来的 POC**（默认关闭，需在 POC 管理页挑选启用）
  + 14 项 OWASP 启发式检查 + 十余条内置指纹规则；检测规则库仍偏小，误报/漏报都不可避免，所有产出都需要人工确认；
  因此漏洞页提供**人工复核三态**（待复核 / 已确认 / **误报**）与批量打标 —— **判误报的行不计入漏洞数**，
  报告里单列「已判误报」附录；POC 另带**置信度分层**（来源分 × 是否含内容型匹配器，只降级不升级），
  用于同批候选内排序与按层批量启停（**它只是结构先验，不等于"实测校准过"**）；
- 列表页均为**服务端分页 + 服务端筛选**（不再固定 `LIMIT` 静默截断）：跨任务漏洞页（`/vulns`）、
  **任务列表页**（`/tasks`）、**任务详情页的「潜在漏洞」列表**都已分页（每页 50/100/200/500），
  筛选与排序下推到 SQL、翻页保持全部条件；任务详情页的 **7 个资产页签**（站点 / 子域名 / 拓展域名 /
  端口服务 / C 段 / SSL 证书 / 目录）**同样已服务端分页 + 服务端筛选**（续57；8 个分页条各用独立
  页码参数，翻页带锚点）—— 其中**目录页签是唯一例外**：「折叠同长度重复」是整表语义，故走
  「取全量 → 折叠 → 过滤 → 切片」。
- 14 项内置检查里**默认只有 7 项执行**（medium 级及以上），info/low 项由 `checks.skip_severities` 整级跳过、连请求都不发；
  其中 `a10-ssrf-callback`（受控回连）另有 `ssrf.enabled` 总开关、**默认关**；
- 内置兜底实现（DNS 爆破、目录扫描、探测）在覆盖面与性能上**不如** subfinder/puredns/httpx/dirmap 本体，生产效果依赖外部工具的安装；
- 内置的隧道/绕过能力只改变 payload 的**编码形态**与请求伪装，不改变语义，不能绕过需要业务逻辑的 WAF 规则；
- OWASP 检查刻意排除了破坏性 payload（无盲注延时、无爆破、无利用代码），它做的是"初筛信号"而不是"漏洞利用"；
  **盲注只做布尔型差分**（恒真 vs 恒假 + 恒真复验），**不做 `SLEEP`/`BENCHMARK` 延时型**；
  **XSS 按回显上下文分级**（JS 串/无引号属性→high，引号属性/文本节点→medium，HTML 注释→降级）；
  **A10 SSRF 只做受控回连**（证明"服务端会出网"），**刻意不去打内网地址**；
- A04（不安全设计）、A07（认证缺陷）、A09（日志与监控）等依赖业务上下文的类别，黑盒自动化无法可靠覆盖，文档中如实标注；
- 外部情报（`osint` 阶段：C 段反查 / FOFA favicon 反查 / FOFA 证书反查）：**`fofa.enabled` 当前为 `false`**
  （2026-09-26 用户决定"先关，投入生产时再开"）—— 即默认任务不会碰 FOFA。需要时在「策略配置」页打开，
  打开后每次任务都会真查 FOFA 并消耗配额（前提是 `config/keys.yaml` 已配真实凭据）；`iprecon.enabled` /
  `shodan` / `quake` / `ctlog` 与 `intel` / `heuristic` / `github` 默认关。`osint` 的阈值
  （黑 ico 200、通用证书 200、"共享主机"单 IP 域名数 30）是保守估计值、未经真实数据校准，
  其联网往返也无法离线自测（`tests/smoke.py` 只覆盖纯函数与门控，全阶段真跑见 `[6u]`）。

## 许可

本仓库**自有代码**采用 **MIT**，见 [`LICENSE`](LICENSE)。

`config/` 下的部分**数据文件**派生自第三方项目，**不受 MIT 覆盖**，仍适用其原始条款
（其中 `config/dicts/dirs_*.txt` 派生自 GPL-3.0 的 dirmap）。逐项来源与边界见
[`NOTICE.md`](NOTICE.md)。

> **使用边界**：本工具仅用于**自有或已获得书面授权**的目标。检测一律非破坏性（只做探测类请求，
> 无爆破、无写操作、无 DoS 延时）。详见 [`docs/security-notice.md`](docs/security-notice.md)。
