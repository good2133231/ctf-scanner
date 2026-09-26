# CTFScanner

面向 **CTF 与授权渗透测试** 的一体化资产测绘与漏洞初筛框架。参考灯塔（ARL）的任务化思路，把常用的「子域名收集 → 子域接管 → 端口服务 → 存活探测 → TLS 证书取证 → 站点截图 → 外部情报拓展 → JS 资产挖掘 → 目录发现 → 漏洞初筛 → 情报订阅 / 启发式候选 / GitHub 泄露检索」**13 阶段**流水线产品化：

- **CLI 客户端**：导入目标文件，全自动执行完整流水线；
- **Web 控制台（GUI）**：仿 ARL 的任务/资产/漏洞/POC 管理界面（**9 栏侧边栏**：仪表盘 / 任务 / 子域名 / 站点 / IP 资产 / **全端口扫描** / 漏洞 / POC / 策略；管理员另有第 10 栏「账号管理」，后三栏对子用户隐藏且路由层 403），可视化添加目标并发起扫描，支持任务批量停止/重启/删除与报告导出，任务详情页可对**中断的任务「续跑」**（从断点接着跑，不清已有资产）；子域名标出**解析 IP 与 CDN/非 CDN**（可标签过滤）、**来源可读标签**（能一眼看出哪些是 FOFA 找出来的），可勾选行**批量加入黑名单**或**批量跑子域名（新建任务）**；拓展域名与站点页**默认隐藏重叠资产**（页顶开关 `?all=1` 放开），站点页另折叠同任务内「标题+响应长度」相同的重复项；
- **多用户与角色（2026-09-26 起）**：账号 + 口令登录（口令只存 `pbkdf2_sha256` 派生值 —— 20 万次迭代 + 每账号随机盐，**不存明文、也不进日志**，零第三方依赖），分**管理员 / 子用户**两级：管理员可创建 / 停用 / 重置子用户，能进策略配置与 POC 管理；**子用户只能使用扫描功能与查看结果** —— 策略配置、POC 管理、账号管理三处在**路由层**即返回 403（侧边栏对子用户也不显示，但真正的控制是路由那层，直接敲 URL 同样被挡）。迁移口径：旧的 `gui.token` 只作**引导口令**（库里还没有任何账号时仍可登录并作为管理员），一旦建了第一个账号就**立即失效**；第一个账号被强制设为管理员，保证不会把老部署锁在门外；管理员口令全丢时可在项目根执行 `py -3 -c "from scanner import db, users; db.init_db(); print(users.create_user('admin','新口令',role='admin'))"` 重建（不动任务与资产数据）；
- **POC 管理**：YAML 格式 POC 引擎（**nuclei 语法兼容子集**：含 `raw` / `flow` / `workflows` 子集支持），可直接加载官方 nuclei 模板，支持上传、启停、目录扫描；
- **检测分级门控（四层）**：阶段级总开关（`vulnscan.enabled`，关闭即"只测绘不探测"）+ 按级别整体跳过（`skip_severities`，默认 info/low **连请求都不发**）+ 按最低报告级别收敛结果（默认 medium）+ OWASP 分类 / 单项检查开关，默认屏蔽"太 low 的洞"；
- **动态免杀**：UA 随机化、浏览器化请求头、WAF 指纹识别、注入 payload 变形（分级 0~3，变体与参数顺序每次随机）；
- **信息收集增强**：免 key 多来源被动子域名收集（crt.sh / certspotter / alienvault 等）+ 泛解析过滤 + 子域接管指纹（41 条第三方服务）+ 子域名**解析 IP / CDN 标记**（`config/dicts/cdn_cname.txt` 292 条厂商 CNAME 后缀 + `config/dicts/cdn_ips.txt` 15 段厂商任播 IP 段，CNAME 优先、IP 段兜底，纯 DNS 只读判定）+ JS 资产挖掘（域名/接口/疑似凭据，JS 与情报带出的域名归入**拓展域名**页）+ **外部情报拓展**（`/24` C 段反查域名；favicon 的 mmh3 去 FOFA 反查同源资产，命中过多的"黑 ico"主动放弃拓展；**TLS 证书反查** `cert="domain"` 与**标题反查** `title="xxx"`，命中过多的"通用证书 / 公共标题"（如 404 默认页）同样放弃 —— 模板页标题连查询都不发）+ **用户黑名单**（`config/blacklist.txt`，入库前过滤，命中域名连子域都不入资产库）；**拓展域名**按来源分类排序（JS 挖掘 → FOFA·标题 / 证书 / ICO → C 段，不交错），并可对勾选域名手动**解析 DNS / 送去探测（新建 `subdomain→probe→dirscan→vulnscan` 任务）/ 归属本项目的追加为子域名 / 加入黑名单** —— 这类域名未必属于目标，不自动全跑）；拓展域名页**按主域名分组折叠**（`?group=0` 切回平铺）；建任务（或 CLI `--auto-expand`）勾「**自动拓展扫描**」后本次任务自动补 `osint`/`jsmine` 阶段、拓展结束后自动做 DNS **存在性判定**、把**注册域属于本项目**的拓展域名（如目标 `pengo.pro` 拓展出 `aaa.pengo.pro`）**追加成正常子域**（原拓展行保留、出处可查）、目标是子域时自动补收其主域名；
- **端口与目录**：内置 TOP 48 端口表 + **fscan / nmap 适配**（`portscan.engine`：`auto` = fscan → nmap → 内置 TCP connect；调用 fscan 时强制 `-np -nobr -nopoc`，只用它的端口发现能力，输出解析按 fscan 2.2.1 **真实形态校准**并用其"发现 N 个开放端口"统计行交叉校验，数目不符即回退、不静默漏报）+ 内置 TCP connect 兜底；**全端口扫描（1-65535）**可从侧栏「全端口扫描」页对单个 IP 发起（按任务分布展示，自动跳过已扫过的端口，不污染全局策略）；**目录发现走「浅 / 深两档」**——默认**开**但只跑**浅扫**（`dirscan.mode=quick`：`config/dicts/dirs_shallow.txt` 精选通用敏感路径约 150 条/站，如 `.git`、`.env`、备份与数据库转储、中间件控制台），适合"先浅浅过一遍"；**深度扫**（`mode=deep` / 建任务勾「全目录深扫」/ 结果页「补扫」）才启用 **15333 条大字典**、dirmap 优先调用与备份后缀派生，**只扫不重复站点**、**按技术栈与框架选字典**（Java/PHP/ASP 各自的语言字典 + WordPress/Spring/Weblogic 等 12 个框架字典 + 通用暴露面字典），结果按「**站点 + 状态码 + 响应大小**」折叠重复长度并展示包大小与**命中页标题**（内置扫描从已在手里的响应体提取，零额外请求），默认排序为 **200 优先 → 大小降序**；浅扫结果页可勾选站点**一键发起独立补扫任务**（`POST /api/rescan`，只跑 dirscan/portscan/screenshot 单阶段，不改全局策略）；
- **TLS 证书取证**（策略级默认关，**建任务勾「SSL 证书」或 CLI `-p cert` 即对本次生效**）：对值得握手的站点（`https://` 或端口命中 `cert.tls_ports`）做**一次只读 TLS 握手**，用**纯标准库** ASN.1/DER 解析出 CN / 颁发者 / 有效期 / 剩余天数 / 是否自签 / 签名算法 / SAN / SHA256 指纹，进 `certs` 表 + 任务详情「SSL 证书」页签 + 报告小节，**不引入 `cryptography`**。握手**不校验证书**（CTF 目标多为自签/过期）—— **「自签 / 已过期」是证书属性、不是漏洞结论**，页签与报告都写明了这一点；页签按数据源实有出现，没有产物时说明原因；
- **站点截图**（策略级默认关，**建任务勾「截图」即对本次生效**）：调用本机已装的 Edge/Chrome 无头模式截图，产物落在任务目录并在站点页 URL 旁显示缩略图，不引入任何新依赖；站点页签可对勾选站点**补截图**（`stage=screenshot`），没有产物时页面会说明原因（策略关 / 本机无可用浏览器 / 截图失败）；
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
   │  ③ portscan 端口服务（默认关） ④ probe 存活探测                          │
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

## 快速开始

跨平台：Windows 与 Linux 均可运行（Python 3.8+），代码无平台专属依赖。
**Linux 实机已验收**（2026-09-23：Ubuntu 22.04.5 / Python 3.10.12 上 `python3 tests/smoke.py` → SMOKE PASS；
无头截图与 fscan/nmap 真实调用也已在该机器上验证）。

```bash
# ---- Windows（PowerShell/cmd）----
pip install -r requirements.txt
python cli\client.py --check
python cli\client.py -f examples\targets.txt -n my-first-task
python run_gui.py

# ---- Linux / macOS ----
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python3 cli/client.py --check
python3 cli/client.py -f examples/targets.txt -n my-first-task
python3 run_gui.py
```

> 2. （可选）放置外部工具到 PATH 或 tools/scanner/，见 tools/scanner/README.md —— 需下载对应操作系统的版本（Windows 取 .exe，Linux 取 linux_amd64）。


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
- **`config/dicts/`**：子域名字典、`dirs_shallow.txt`（浅扫精选路径 ~150 条）、`dirs_big.txt`（深扫大字典 15333 条）、`cdn_cname.txt`（CDN 厂商后缀）、`cdn_ips.txt`（CDN 厂商任播 IP 段）、`sensitive.txt`（A01 敏感文件检查的数据源：`路径 | 关键字 | 级别 | 说明`）。
- **外部工具（可选）**：把 `subfinder` / `puredns` / `httpx` / `dirmap` / `nmap` / `fscan` 放进 PATH 或 `tools/scanner/`，存在时优先调用、否则降级内置实现。无这些工具框架仍能跑通。

> 部署 checklist：① 复制 `config/keys.yaml.example` → `config/keys.yaml` 并填 key（仅当要用 FOFA 等外部情报）；② 按需改 `config/settings.yaml`（或 GUI 策略配置页，**仅管理员可改**）；③ `pip install -r requirements.txt`；④ 跑 `python cli/client.py --check` 自检；⑤ 起控制台后用 `gui.token` 引导登录，**立即到「账号管理」建管理员与子用户账号**（建号后引导口令失效）。

## 目录结构

```
ctf-scanner/
├── cli/client.py            # CLI 客户端（导入文件、全自动执行）
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
│   ├── iprecon.py           #   IP 反查域名 + /24 C 段归纳（C 段视野）
│   ├── fofa.py  mmh3.py     #   FOFA favicon/证书反查 + 黑 ico / 通用证书判定；纯标准库 MurmurHash3
│   ├── intel.py             #   漏洞情报订阅：CISA KEV × 本地指纹白名单匹配（只产「线索」）
│   ├── heuristics.py        #   启发式候选发现：零请求差分/异常聚合（只产「线索」）
│   ├── github_leak.py       #   GitHub 泄露检索：GitHub 公开代码里搜目标注册域（只产「线索」）
│   ├── fingerprint.py       #   内置指纹识别 + favicon MD5/mmh3（httpx 不可用时填充技术栈）
│   ├── db.py  config.py  utils.py  targets.py
│   ├── report.py            #   报告三格式（Markdown / 自包含 HTML / 无头浏览器打印 PDF），共用 collect() 快照
├── tools/import_ref_pocs.py #   参考项目 Python POC 静态导入器（产物默认关闭）
├── tools/import_dir_dict.py #   目录扫描大字典生成器（读 dirmap 字典 → config/dicts/dirs_big.txt）
├── tools/import_fw_dicts.py #   目录字典按框架细分生成器（从大字典派生 12 个框架字典 + 暴露面）
├── tools/dirmap/            #   dirmap 落点（目录联接，第三方项目不随仓库分发）
├── config/
│   ├── settings.yaml        # 全局配置（GUI「策略配置」页覆盖 gui/limits/checks/subdomain/passive/evasion/takeover/portscan/jsmine/dirscan/vulnscan/screenshot/iprecon/fofa/blacklist/intel/heuristic/github）
│   ├── keys.yaml            # 第三方 API key 专用文件（gitignore，GUI 不写回）
│   ├── blacklist.txt        # 用户黑名单（一行一个域名，# 注释；命中即不入资产库）
│   ├── dicts/               #   子域名字典、resolvers、目录字典（dirs_shallow 206 浅扫精选 / dirs_small 55 / dirs_big 15333 / 技术栈与框架细分 + 暴露面）、cdn_cname.txt（CDN 厂商后缀）、cdn_ips.txt（CDN 厂商任播 IP 段）、sensitive.txt（A01 敏感文件检查的数据源：路径 | 关键字 | 级别 | 说明）
│   ├── pocs-user/           # 用户上传的 POC（GUI 上传后落在这里）
│   ├── pocs-imported/       # 批量导入的 POC（默认关闭，需在 POC 管理页挑选启用）
│   └── nuclei-templates/    # 官方 nuclei 模板投放点（可被本引擎直接加载）
├── tools/scanner/           # 外部工具放置区（subfinder/httpx/puredns/dirmap）
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
| [docs/roadmap.md](docs/roadmap.md) | 实际完成度对照与后续计划（含刻意不做的项及理由） |
| [docs/security-notice.md](docs/security-notice.md) | 授权与法律边界 |

## 客观说明（当前能力边界）

- 7 个内置示例 POC + **305 个由参考项目静态转换而来的 POC**（默认关闭，需在 POC 管理页挑选启用）
  + 14 项 OWASP 启发式检查 + 十余条内置指纹规则；检测规则库仍偏小，误报/漏报都不可避免，所有产出都需要人工确认；
  因此漏洞页提供**人工复核三态**（待复核 / 已确认 / **误报**）与批量打标 —— **判误报的行不计入漏洞数**，
  报告里单列「已判误报」附录；POC 另带**置信度分层**（来源分 × 是否含内容型匹配器，只降级不升级），
  用于同批候选内排序与按层批量启停（**它只是结构先验，不等于"实测校准过"**）；
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
