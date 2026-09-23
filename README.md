# CTFScanner

面向 **CTF 与授权渗透测试** 的一体化资产测绘与漏洞初筛框架。参考灯塔（ARL）的任务化思路，把常用的「子域名收集 → 子域接管 → 端口服务 → 存活探测 → 站点截图 → 外部情报拓展 → JS 资产挖掘 → 目录发现 → 漏洞初筛 → 情报订阅 / 启发式候选」**11 阶段**流水线产品化：

- **CLI 客户端**：导入目标文件，全自动执行完整流水线；
- **Web 控制台（GUI）**：仿 ARL 的任务/资产/漏洞/POC 管理界面（**9 栏侧边栏**：仪表盘 / 任务 / 子域名 / 站点 / IP 资产 / **全端口扫描** / 漏洞 / POC / 策略），可视化添加目标并发起扫描，支持任务批量停止/重启/删除与报告导出；子域名标出**解析 IP 与 CDN/非 CDN**（可标签过滤）、**来源可读标签**（能一眼看出哪些是 FOFA 找出来的），可勾选行**批量加入黑名单**或**批量跑子域名（新建任务）**；拓展域名与站点页**默认隐藏重叠资产**（页顶开关 `?all=1` 放开），站点页另折叠同任务内「标题+响应长度」相同的重复项；
- **POC 管理**：YAML 格式 POC 引擎（**nuclei 语法兼容子集**），可直接加载官方 nuclei 模板，支持上传、启停、目录扫描；
- **检测分级门控（四层）**：阶段级总开关（`vulnscan.enabled`，关闭即"只测绘不探测"）+ 按级别整体跳过（`skip_severities`，默认 info/low **连请求都不发**）+ 按最低报告级别收敛结果（默认 medium）+ OWASP 分类 / 单项检查开关，默认屏蔽"太 low 的洞"；
- **动态免杀**：UA 随机化、浏览器化请求头、WAF 指纹识别、注入 payload 变形（分级 0~3，变体与参数顺序每次随机）；
- **信息收集增强**：免 key 多来源被动子域名收集（crt.sh / certspotter / alienvault 等）+ 泛解析过滤 + 子域接管指纹（41 条第三方服务）+ 子域名**解析 IP / CDN 标记**（`config/dicts/cdn_cname.txt` 292 条厂商 CNAME 后缀，纯 DNS 只读判定）+ JS 资产挖掘（域名/接口/疑似凭据，JS 与情报带出的域名归入**拓展域名**页）+ **外部情报拓展**（`/24` C 段反查域名；favicon 的 mmh3 去 FOFA 反查同源资产，命中过多的"黑 ico"主动放弃拓展；**TLS 证书反查** `cert="domain"` 与**标题反查** `title="xxx"`，命中过多的"通用证书 / 公共标题"（如 404 默认页）同样放弃 —— 模板页标题连查询都不发）+ **用户黑名单**（`config/blacklist.txt`，入库前过滤，命中域名连子域都不入资产库）；
- **端口与目录**：内置 TOP 48 端口表 + **fscan / nmap 适配**（`portscan.engine`：`auto` = fscan → nmap → 内置 TCP connect；调用 fscan 时强制 `-np -nobr -nopoc`，只用它的端口发现能力）+ 内置 TCP connect 兜底；**全端口扫描（1-65535）**可从侧栏「全端口扫描」页对单个 IP 发起（按任务分布展示，自动跳过已扫过的端口，不污染全局策略）；**目录发现走「浅 / 深两档」**——默认**开**但只跑**浅扫**（`dirscan.mode=quick`：`config/dicts/dirs_shallow.txt` 精选通用敏感路径约 150 条/站，如 `.git`、`.env`、备份与数据库转储、中间件控制台），适合"先浅浅过一遍"；**深度扫**（`mode=deep` / 建任务勾「全目录深扫」/ 结果页「补扫」）才启用 **15333 条大字典**、dirmap 优先调用与备份后缀派生，**只扫不重复站点**、**按技术栈与框架选字典**（Java/PHP/ASP 各自的语言字典 + WordPress/Spring/Weblogic 等 12 个框架字典 + 通用暴露面字典），结果按**响应大小**折叠重复长度并展示包大小；浅扫结果页可勾选站点**一键发起独立补扫任务**（`POST /api/rescan`，只跑 dirscan/portscan 单阶段，不改全局策略）；
- **站点截图**（默认关）：调用本机已装的 Edge/Chrome 无头模式截图，产物落在任务目录并在站点页 URL 旁显示缩略图，不引入任何新依赖；
- **线索层：情报订阅 + 启发式候选**（两个阶段**默认关**）：拉取 **CISA KEV**（免 key 公开 JSON，只收录已被在野利用的 CVE）与本地指纹做**白名单式匹配**；以及对已采集数据做**零请求**的差分/异常聚合（软 404 模板 / 高价值入口暴露 / 同标题多主机 / 目录命中离群 / 同 C 段多 IP）。两者产出**只是「线索」**：独立 `leads` 表、任务详情独立页签、报告独立附录，**不写漏洞、不计入漏洞数、不自动导入 POC**；
- **JS 敏感字符**：17 条凭据规则（AKID/LTAI/AKIA、JWT、私钥 PEM、数据库连接串、Slack/Telegram/SendGrid/Stripe 等）+ 两级降噪（占位符、变量引用、成员访问），命中值掩码脱敏后以 high 级入库，「拓展域名」页按域名显示敏感命中数；
- **OWASP Top 10**：内置轻量启发式检查（全部非破坏性，结论为"潜在漏洞/初筛信号"，需人工确认）。

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
   │  ⑨ vulnscan 漏洞初筛             ⑩⑪ intel / heuristic（默认关） │
   │     POC 引擎（YAML，nuclei 兼容子集） KEV 情报 × 本地指纹白名单匹配│
   │     OWASP Top10 检查 + 四层门控 + 绕 WAF  零请求差分/异常聚合      │
   │                                    两者只产「线索」，不写 vulns   │
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


## 目录结构

```
ctf-scanner/
├── cli/client.py            # CLI 客户端（导入文件、全自动执行）
├── gui/                     # Web 控制台（Flask + 原生 JS，仿 ARL）
│   ├── app.py               #   路由与后台任务线程
│   ├── templates/ static/   #   页面与样式
├── scanner/                 # 核心引擎（CLI/GUI 共用）
│   ├── runner.py            #   流水线编排、任务执行入口、协作式取消
│   ├── stages/              #   11 个阶段：subdomain / takeover / portscan / probe / screenshot / osint / jsmine / dirscan / vulnscan / intel / heuristic
│   ├── pocs/                #   POC 引擎（nuclei 兼容子集）+ 内置示例 POC
│   ├── owasp/               #   OWASP Top10 启发式检查 + 分级/分类门控
│   ├── evasion.py           #   动态免杀（UA/请求头伪装/WAF 指纹/payload 变形）
│   ├── wildcard.py          #   泛解析识别与过滤
│   ├── passive.py           #   免 key 多来源被动子域名收集
│   ├── dnsq.py              #   纯标准库 DNS 客户端（含 CNAME 链解析）
│   ├── cdn.py               #   CDN 判定（按 CNAME 后缀匹配厂商名单，只读加载）
│   ├── takeover.py          #   子域接管指纹库（41 条第三方服务）
│   ├── portscan.py          #   端口/服务扫描（fscan / nmap 优先，内置 TCP connect 兜底）
│   ├── screenshot.py        #   站点截图（本机无头 Edge/Chrome 路径探测 + 截图）
│   ├── jsmine.py            #   JS 资产挖掘（域名/接口/疑似凭据 + 黑名单降噪）
│   ├── blacklist.py         #   用户黑名单（config/blacklist.txt，入库前过滤）
│   ├── iprecon.py           #   IP 反查域名 + /24 C 段归纳（C 段视野）
│   ├── fofa.py  mmh3.py     #   FOFA favicon/证书反查 + 黑 ico / 通用证书判定；纯标准库 MurmurHash3
│   ├── intel.py             #   漏洞情报订阅：CISA KEV × 本地指纹白名单匹配（只产「线索」）
│   ├── heuristics.py        #   启发式候选发现：零请求差分/异常聚合（只产「线索」）
│   ├── fingerprint.py       #   内置指纹识别 + favicon MD5/mmh3（httpx 不可用时填充技术栈）
│   ├── db.py  config.py  utils.py  targets.py  report.py
├── tools/import_ref_pocs.py #   参考项目 Python POC 静态导入器（产物默认关闭）
├── tools/import_dir_dict.py #   目录扫描大字典生成器（读 dirmap 字典 → config/dicts/dirs_big.txt）
├── tools/import_fw_dicts.py #   目录字典按框架细分生成器（从大字典派生 12 个框架字典 + 暴露面）
├── tools/dirmap/            #   dirmap 落点（目录联接，第三方项目不随仓库分发）
├── config/
│   ├── settings.yaml        # 全局配置（GUI「策略配置」页覆盖 gui/limits/checks/subdomain/passive/evasion/takeover/portscan/jsmine/dirscan/vulnscan/screenshot/iprecon/fofa/blacklist/intel/heuristic）
│   ├── keys.yaml            # 第三方 API key 专用文件（gitignore，GUI 不写回）
│   ├── blacklist.txt        # 用户黑名单（一行一个域名，# 注释；命中即不入资产库）
│   ├── dicts/               #   子域名字典、resolvers、目录字典（dirs_shallow 206 浅扫精选 / dirs_small 55 / dirs_big 15333 / 技术栈与框架细分 + 暴露面）、cdn_cname.txt（CDN 厂商后缀）
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
| [docs/pipeline.md](docs/pipeline.md) | 11 个阶段的输入输出、与你手工流水线命令的对应关系、降级策略 |
| [docs/poc-guide.md](docs/poc-guide.md) | POC YAML 格式、匹配器语义、编写规范、如何上传与启停 |
| [docs/owasp-mapping.md](docs/owasp-mapping.md) | OWASP Top 10 逐项映射：已实现检查、实现方式、局限 |
| [docs/usage.md](docs/usage.md) | CLI 全参数、GUI 操作流程、常见问题 |
| [docs/roadmap.md](docs/roadmap.md) | 实际完成度对照与后续计划（含刻意不做的项及理由） |
| [docs/security-notice.md](docs/security-notice.md) | 授权与法律边界 |

## 客观说明（当前能力边界）

- 7 个内置示例 POC + **305 个由参考项目静态转换而来的 POC**（默认关闭，需在 POC 管理页挑选启用）
  + 12 项 OWASP 启发式检查 + 十余条内置指纹规则；检测规则库仍偏小，误报/漏报都不可避免，所有产出都需要人工确认；
- 12 项内置检查里**默认只有 5 项执行**（medium 级及以上），info/low 项由 `checks.skip_severities` 整级跳过、连请求都不发；
- 内置兜底实现（DNS 爆破、目录扫描、探测）在覆盖面与性能上**不如** subfinder/puredns/httpx/dirmap 本体，生产效果依赖外部工具的安装；
- 内置的隧道/绕过能力只改变 payload 的**编码形态**与请求伪装，不改变语义，不能绕过需要业务逻辑的 WAF 规则；
- OWASP 检查刻意排除了破坏性 payload（无盲注延时、无爆破、无利用代码），它做的是"初筛信号"而不是"漏洞利用"；
- A04（不安全设计）、A07（认证缺陷）、A09（日志与监控）等依赖业务上下文的类别，黑盒自动化无法可靠覆盖，文档中如实标注；
- 外部情报（`osint` 阶段：C 段反查 / FOFA favicon 反查 / FOFA 证书反查）**默认全关**且依赖第三方接口/配额，
  其阈值（黑 ico 200、通用证书 200、"共享主机"单 IP 域名数 30）是保守估计值、未经真实数据校准；
  `osint` 的联网往返也无法离线自测（`tests/smoke.py` 只覆盖纯函数与门控）。
