# AGENTS.md —— 给下一个接手 AI 的项目速览

> 本文件描述**实际代码状态**，不描述愿望。若与 docs/ 下其它文档冲突，以代码为准，并把冲突修掉。
> 2026-09-23 新负责人接手后的复核报告见 [docs/takeover-2026-09-23.md](docs/takeover-2026-09-23.md)
> —— 里面有"文档没记录的问题"与下一步排期建议，接手时先看它，能省一轮重复调研。

## 0. 硬规矩（最高优先级，违反即视为改坏项目）

> 用户 2026-09-22 明确下达，**优先级高于本文件其它所有内容**。新接手者请先读完本节再动手。

1. **改动必须标注实施者**（本项目会同时存在多个 AI 会话）：
   提交信息末行写 `WorkBuddy · <模型名>`，并在 `CHANGELOG_AI.md` 的轮次标题下写明实施者。
   例：`WorkBuddy · DeepSeek-V4.1-Flash`。用途：事后分辨"某处是谁改的"。
2. **默认只读本项目目录；读项目外文件必须先拿到用户的逐次授权。**
   - 默认禁止：读取、扫描、遍历本项目目录以外的任何代码或文件
     （包括"顺手看一眼参考项目""去隔壁目录找找有没有现成的"）。
   - **例外＝用户当场手动批准**，只要用户说了就照读，不必再确认第二遍。形式包括：
     ① 用户直接给出路径（如"你可以读取 `C:\Users\材料\Desktop\tools\dirmap-master`"）；
     ② 用户说"可以去读 X"；③ 用户回答"是/可以"这类确认。
   - **批准是按次、按路径生效的**：上次批准 A 目录，不等于这次可以读 B；换新的外部路径要重新问。
     已批准清单（便于接手者知道哪些是"批准过的"，不构成新授权）：
     `C:\Users\材料\Desktop\tools\dirmap-master` —— 用户 2026-09-22 批准用于 dirmap 适配审查。
   - 本项目目录 = 本仓库根目录（`ctf-scanner/`）以内的内容；`tools/` 下的目录联接**指向外部**时，
     视同外部路径（同样需要批准）。
   - *注：联网检索公开文档不算"读项目外代码"，但也不要把外部仓库整份拉进来。*
3. **代码、配置、模板、日志里一律只出现相对路径**，禁止出现本机绝对路径
   （`C:\Users\...` / `/home/...` 等）。展示给用户的路径统一走
   `utils.rel_display()`（项目内相对项目根，项目外原样返回）。
   文档里不可避免的操作性路径（如 git 便携版位置）集中在 §2 说明，不要散落到各处。

## 1. 这是什么

CTFScanner：面向 **CTF / 授权渗透测试** 的资产测绘与漏洞初筛框架。参考 ARL 的任务化思路，
把「子域名收集 → 存活探测 → 目录发现 → 漏洞初筛」做成可复用的流水线，同时提供 CLI 与
Flask Web 控制台（仿 ARL）。

**法律边界（不可越过）**：仅用于自有或已书面授权的目标。检测一律非破坏性（只 GET/POST 探测，
无爆破、无写操作、无 DoS 延时）。新功能必须维持这一约束。

## 2. 运行环境（本机实际情况）

- Python 3.9。**结论要先分清是哪个 shell**：
  - 用户在**自己的 cmd** 里 `python` 完全可用（实测 `Python 3.9.0`，`where python` 三条命中：
    Python39 / Python38 / WindowsApps）；用户 PATH 里**确实有** `…\Programs\Python\Python39\`。
  - **AI 工具启动的 shell 里 `python` 不可解析**，根因不是"没装/没进 PATH"，而是**该 PATH 条目
    编码损坏**：`$env:PATH` 里它是乱码 `C:\Users\锟斤拷锟斤拷\AppData\Local\Programs\Python\Python39\`
    —— 用户名"材料"的 UTF-8 字节（`E6 9D 90 E6 96 99`）被按 GBK 解读成"锟斤拷"这种典型乱码，
    于是路径整体失效，`where python` / `Get-Command python` 找不到、`python -V` 报
    CommandNotFoundException。
  - `py -3` 之所以照常可用：`C:\WINDOWS\py.exe` 是**纯 ASCII 路径**不受影响，且 py.exe 自己查
    注册表定位版本（实测 `Python 3.9.0`）。**在 AI shell 里请一律写 `py -3`**，
    但**不要下"这台机器没有 python"的结论**（会误导你去做无意义的排查）。
  *（说明：第八轮写成"`python` / `py -3` 均在 PATH"、第九轮又反改成"`python` 不在 PATH"，
  两次都不准确 —— 真相是"用户 shell 有、AI shell 因编码损坏找不到"。第十一轮按 `$env:PATH`
  实测定位到真根因并改为此写法，请以此为准。
  功能上无影响：框架取解释器一律走 `utils.pick_python()` —— `which(configured)` 不中则回退
  `sys.executable`，实测返回 `…\Programs\Python\Python39\python.exe`。）*
- 依赖已装：flask 3.1、requests 2.22、PyYAML 6.0（见 requirements.txt）。
- 外部工具：subfinder / puredns / httpx **均未安装** → 走内置兜底。**两个例外**：
  **nmap 已安装**（`C:\Program Files (x86)\Nmap\nmap`，实测 `which` 命中）→ 端口扫描默认走 nmap 适配器；
  **dirmap 可用**：
  它的 Python 依赖（gevent 24.11 / lxml / progressbar）本机都有，且已在 `tools/dirmap/` 建了
  **目录联接**指向机器上的 dirmap 源码 —— 因此 dirscan 阶段在**深扫档**（`dirscan.mode=deep`、
  建任务勾「全目录深扫」或结果页「补扫」）会**优先真的调用 dirmap**（第十五轮实测
  15348 条字典跑完约 588 秒、解析正确）；找不到 `tools/dirmap/dirmap.py` 时自动回退内置扫描。
  **默认档 `quick` 不调用任何外部工具**：只吃 `config/dicts/dirs_shallow.txt` 的精选敏感路径。
- **git（2026-09-22 起）**：本仓库已是 git 仓库（`main` 分支，首次提交 `2267e51`）。
  git 二进制用 **MinGit 便携版**：`C:\Users\材料\MinGit\cmd\git.exe`（不在 PATH，
  choco/winget 因非管理员权限走不通，便携版是刻意选择）。仓库级 `user.name=CTFScanner`
  是占位身份，个人使用请自行改。

## 3. 目录地图

```
ctf-scanner/
├── cli/client.py          # CLI 入口：导入目标 → run_task（阻塞）
├── run_gui.py             # Web 控制台入口
├── gui/
│   ├── app.py             # create_app()：路由 + 每任务一个后台线程；serve() 为统一启动入口；含跨任务资产页（子域名/拓展域名/站点/漏洞，另有 /ports /csegs /dirs）
│   ├── templates/ static/ # 页面与原生 JS（app.js：轮询状态/日志、建任务、POC 管理、页签、表格筛选、任务批量操作）
│   │                      #   外壳＝左侧固定侧边栏 + 顶栏 + 内容区（9 栏，以 base.html 的 nav_items 为准：
│   │                      #     仪表盘/任务管理/子域名资产/站点资产/IP 资产/全端口扫描/漏洞风险/POC 管理/策略配置）
│   │                      #   （原「端口服务/C 段视野/目录发现/拓展域名」四栏已移除，路由 /ports /csegs /dirs /extdomains
│   │                      #    仍在，只是不进侧栏；前三条是任务维度数据，/extdomains 与 /subdomains 是同一张表的不同视图）
│   │                      #   任务详情＝横向 11 个页签（潜在漏洞(默认)/站点/子域名/拓展域名/端口服务/C 段/目录/**SSL 证书**/线索/目标与配置/运行日志）+ 页签内筛选框
│   │                      #   （「线索」＝intel 情报订阅 + heuristic 启发式候选两类共用，**不是漏洞结论**；
│   │                      #     「SSL 证书」＝cert 阶段产物；页签按数据源实有出现，没有产物时说明原因）
├── scanner/
│   ├── runner.py          # StageContext / PipelineRunner / run_task / sync_pocs（协作式取消：request_stop/is_stopped）
│   ├── stages/            # base + subdomain/takeover/portscan/probe/**cert**/screenshot/osint/jsmine/dirscan/vulnscan/intel/heuristic（12 个）
│   ├── pocs/engine.py     # YAML POC 引擎（nuclei 兼容子集）
│   ├── pocs/pocs/*.yaml   # 内置 7 个示例 POC
│   ├── owasp/checks.py    # 14 项启发式检查（装饰器 @check 注册进 CHECKS）+ 分级/分类门控
│   │                      #   （默认执行 7 项 —— 其余是 info/low 级，被 skip_severities 整级跳过；
│   │                      #     a10-ssrf-callback 虽是 high，但另有 ssrf.enabled 总开关、默认关）
│   ├── evasion.py         # 动态免杀：UA 池/浏览器化头/WAF 指纹/payload 变形
│   ├── wildcard.py        # 泛解析识别与过滤（纯 DNS 查询）
│   ├── passive.py         # 免 key 多来源被动子域名收集
│   ├── dnsq.py            # 纯标准库 DNS 客户端（A/CNAME/TXT/MX/NS…，UDP+TCP 回退，异常不外抛）
│   ├── cdn.py             # CDN 判定：读 config/dicts/cdn_cname.txt 按 CNAME 后缀匹配厂商（只读、无请求）
│   ├── takeover.py        # 子域接管指纹库（41 条第三方服务 suffix）+ detect()
│   ├── portscan.py        # 端口/服务扫描（TOP 表 + **fscan** + nmap 适配 + 内置 TCP connect 兜底 + 被动 banner；
│   │                      #   `engine=auto` 顺序 fscan→nmap→内置；parse_ports(max_span) 防手滑全端口，见 §7）
│   ├── jsmine.py          # JS 资产挖掘（域名/接口 URL/疑似凭据；17 条凭据规则 + 两级降噪）
│   ├── blacklist.py       # 用户黑名单（config/blacklist.txt；load/matches/filter_pairs/filter_domains，每次重读不缓存）
│   ├── auth.py            # 任务级登录态请求头（parse_headers/mask_value/summary/inject/from_task_options）；
│   │                      #   **只发目标侧**（http_request 的 auth=False 是默认值），日志/页面/报告一律掩码，见 §7
│   ├── iprecon.py         # IP 反查域名 + /24 C 段归纳（is_public_ip/segment_of/parse_domains，不 eval）
│   ├── fofa.py            # FOFA 反查（qbase64）：favicon(icon_hash) / cert="domain" / title="xxx" 三种；黑 ico / 通用证书 / 公共标题阈值
│   ├── shodan.py          # Shodan 反查（http.favicon.hash:<mmh3>）—— 与 fofa.py **同构照抄**，默认关，无 key 显式报错
│   ├── quake.py           # 360 Quake 反查（favicon: "<mmh3>"，POST + X-QuakeToken）—— 同上，默认关
│   ├── ctlog.py           # 证书透明度日志在线查询（crt.sh，免 key，**默认关**）：产出**证书维度**记录
│   ├── ssrf.py            # A10 SSRF 受控回连（**默认关**）：本机 HTTP 回连监听 + 每参数唯一 token
│   ├── mmh3.py            # 纯标准库 MurmurHash3 x86_32（平台 favicon 指纹用；含 SELF_TEST 向量）
│   ├── intel.py           # 漏洞情报订阅（P3-2）：CISA KEV 拉取+本地缓存+白名单式匹配 → **只产线索**（不写 vulns）
│   ├── heuristics.py      # 启发式候选发现（P3-3）：对已有数据做差分/异常聚合（**零请求**）→ 线索；阈值与规则表在此
│   ├── fingerprint.py     # 内置指纹规则表 → identify(resp) -> [tag] + fetch_favicon/favicon_md5/favicon_hash
│   ├── certs.py           # TLS 证书取证（**纯标准库** DER/ASN.1 解析，不引 cryptography）：parse_der/parse_pem/fetch/tls_ports
│   ├── db.py              # SQLite 层（tasks/subdomains/sites/ports/csegs/dirs/vulns/pocs/**leads**/**certs** + page_assets/delete_task/task_counts
│   │                      #   + OWN_SUBDOMAIN_WHERE/EXT_SUBDOMAIN_WHERE/OVERLAP_EXT_WHERE/OVERLAP_SITE_WHERE；DB_PATH 受 CTFSCANNER_DB 覆盖）
│   │                      #   复核（vulns.review/review_note/reviewed_at + set/bulk_set_vuln_review/review_counts）
│   │                      #   与 POC 置信度（pocs.confidence + poc_confidence）见 §7
│   ├── config.py          # DEFAULTS + load/save_settings + load_keys()（config/keys.yaml）+ resolve()；LOGS_DIR 受 CTFSCANNER_LOGS 覆盖
│   ├── utils.py           # run_cmd / http_request / pool_run / resolve_host / IO / base_domain() / rel_display()
│   ├── throttle.py        # **统一并发 / 限速 / 全局预算门控（F2）**：两级闸（任务级 + 进程级共享）
│   │                      #   + 令牌桶 + 任务预算；经 `settings["_throttle"]` 注入（沿用 auth.inject 的
│   │                      #   "任务专用副本、绝不原地改"）。三条出口都过它：`http_request` / `run_cmd` /
│   │                      #   `portscan` 裸 socket。预算耗尽＝**按停止处理**（见 §4/§5/§7）
│   ├── targets.py         # parse_lines → [(kind, raw)]，kind ∈ domain|url|ip|cidr|unknown（cidr 展开为多条 ip）
│   └── report.py          # 报告三格式：Markdown（generate）/ HTML（generate_html，自包含单文件+全量转义）/
│                          #   PDF（export_pdf，复用无头 Edge/Chrome 的 --print-to-pdf）；三者共用 collect() 同一份快照
│                          #   「SSL 证书」小节带**来源列**：TLS 握手（真握手） vs CT 日志（crt.sh 历史）
├── tools/import_ref_pocs.py # ast 静态解析参考项目 Python POC → config/pocs-imported/（导入项默认关闭）
├── tools/import_dir_dict.py # 外部目录字典 → 清洗 + **按技术栈拆桶** → config/dicts/dirs_{big,common,jsp,php,asp}.txt
│                          #   用法：py -3 tools/import_dir_dict.py --src <字典文件>（源路径只走参数，代码里不留绝对路径）
├── tools/import_fw_dicts.py # 从 dirs_big 派生**按框架细分**的字典（wordpress/tomcat/weblogic/spring/… 12 个桶
│                          #   + dirs_exposure）→ config/dicts/dirs_<框架>.txt；用法：py -3 tools/import_fw_dicts.py --force
├── tools/import_tlds.py    # 从 tldextract **内置快照**（`suffix_list_urls=()`，离线、绝不联网）导出公共后缀清单
│                          #   → config/dicts/tlds.txt（含 `co.uk`/`com.cn` 等多段后缀）；用法：py -3 tools/import_tlds.py --force
│                          #   tldextract 是**生成期可选依赖**，不进 requirements.txt；运行时只读生成好的 tlds.txt
├── tools/dirmap/          # dirmap 落点（**目录联接**，第三方项目不随仓库分发；.gitignore 排除，找不到就回退内置扫描）
├── config/settings.yaml   # 全局配置（GUI「策略配置」页覆盖 gui/limits/checks/subdomain/passive/evasion/takeover/portscan/jsmine/dirscan/vulnscan/**screenshot/cert**/iprecon/fofa/blacklist/**intel/heuristic** 十八段（dirscan 段含 mode/quick_max_paths/suffix_aware/big_dict/max_paths；portscan 段含 mode/full_ports/exclude_scanned；cert 段含 enabled/max_sites/timeout/tls_ports））
├── config/keys.yaml       # 第三方 API key 专用文件（gitignore；load_keys() 只读，save_settings 不写回）
├── config/blacklist.txt   # 用户黑名单（纯文本，一行一个域名、# 注释；* 前缀与裸域等价；命中即不入资产库）
├── config/dicts/          # subdomains(85) / resolvers(13) / dirs_small(55) / cdn_cname(292)
│                          #   sensitive(9)：**A01 检查的数据源**（`路径|关键字|级别|说明`，见 §7）
│                          #   dirs_shallow(206)：**浅扫专用**（dirscan.mode=quick 只用它），按价值排序、人工筛选
│                          #   js_thirdparty(287：JS 第三方域名单 = 内置 + URLFinder jsFiler + 续22 补 20 条常用库/CDN/链上浏览器)
│                          #   tlds(6423：公共后缀清单 = tldextract 内置快照，含多段后缀；tools/import_tlds.py 生成)
│                          #   目录字典按技术栈拆分：dirs_big(11882 全量) / dirs_common(10671) /
│                          #   dirs_php(933) / dirs_asp(162) / dirs_jsp(116)（tools/import_dir_dict.py 生成）
│                          #   再按**框架**细分 12 桶 + dirs_exposure（tools/import_fw_dicts.py 生成，
│                          #   运行时排在语言/通用字典**之前**，框架判不出就不吃这部分额度）
├── config/pocs-user/      # 用户上传 POC；config/pocs-imported/ 导入 POC（默认关闭）；config/nuclei-templates/ 官方模板投放点
├── tests/smoke.py         # 唯一测试：自包含靶场(127.0.0.1:8765) + 断言，见 §6
├── TODO.md                # 任务确认清单（待用户确认的排期，不是承诺，见 §9）
├── smoke_root/            # 测试靶场（含 .git/config 与 .env 两个"泄露"样本）
├── data/scanner.db        # SQLite（自动创建，gitignore）
└── logs/task_<id>_<ts>/   # 每任务工作目录（gitignore）
```

## 4. 架构与数据流（代码事实）

入口层（cli/client.py、gui/app.py）→ 编排层（runner.PipelineRunner）→ 阶段层（stages/*）→
检测层（pocs/engine.py、owasp/checks.py、fingerprint.py、evasion.py）→ 基础层（utils/config/log）→ 存储层（db.py）。
其中 `scanner/evasion.py` 是**所有 HTTP 出口的统一伪装层**（由 `utils.http_request` 调用），
`scanner/wildcard.py` 与 `scanner/passive.py` 只在 subdomain 阶段生效。

- 阶段顺序与注册：`runner.STAGE_ORDER` / `STAGE_REGISTRY`（当前 **12 个**：
  `subdomain → takeover → portscan → probe → **cert** → **screenshot** → osint → jsmine → dirscan → vulnscan
  → **intel** → **heuristic**`；
  `cert`（TLS 证书取证）与 `screenshot` 都**默认关**，都排在 `probe` 之后（要先有存活站点）；
  `screenshot` 需要本机 Edge/Chrome，浏览器路径探测见 `scanner/screenshot.py`；
  **但"默认关"指的是策略级开关** —— 建任务时勾了 `screenshot` / `cert`（或 CLI `-p screenshot` / `-p cert`）即
  **任务级点名**，GUI 落任务选项 `screenshot_on` / `cert_on`，阶段据此越过策略开关执行且不改全局策略
  （2026-09-23 续13：此前只认策略开关，用户勾了截图却被静默跳过，页面上永远没有缩略图；
  站点页签的「补截图」按钮同样落 `screenshot_on`；续14 的 `cert` 沿用同一套门控，
  并把 CLI 的 `-p` 默认值改成 `None` —— 否则 `-p screenshot`/`-p cert` 会被策略门控静默吃掉）；
  `cert` 只做**一次只读 TLS 握手**（`verify_mode=CERT_NONE`）并解析证书（CN/SAN/有效期/自签/指纹），
  **是取证不是漏洞结论** —— 自签/过期是证书属性，不等于漏洞；解析用纯标准库 ASN.1/DER（`scanner/certs.py`）；
  `dirscan` 默认开但**默认只跑浅扫**（`dirscan.mode=quick`，见 §8 的 dirscan 条目）；
  末尾两个**线索阶段默认关**，且**只写 `leads` 表**（不写 `vulns`、不计入漏洞数、不自动导 POC）：
  `intel` = CISA KEV 情报 × 本地指纹白名单式匹配（`scanner/intel.py`），
  `heuristic` = 对已收集数据做零请求的差分/异常聚合（`scanner/heuristics.py`）。
  新增阶段在此登记即可被 CLI `-p` 与 GUI 识别）。
- 阶段开关有两层：**任务级**（建任务时勾选 stages / CLI `-p`）与**策略级**
  （`settings.takeover.enabled` / `portscan.enabled` / `jsmine.enabled`，阶段内部自查后跳过）。
  `takeover` / `jsmine` / `dirscan` / `vulnscan` 默认开，
  `portscan` / `screenshot` / `cert`（都受策略级开关约束）/ `intel` / `heuristic` 默认关。
  另有**任务级「全量档」选项**：`portscan_full`（全端口 1-65535，见 §8）与 `dirscan_full`（深扫，见 §8），
  二者都是"用户点名要扫"→ **即使对应全局 `enabled=false` 也执行**，且 GUI/CLI 在勾了全量档却漏勾阶段时
  **自动补上该阶段并按 `STAGE_ORDER` 归位**（`runner` 按给定顺序执行、不排序，所以必须显式 sort）。
  **例外是 `osint`**：它自身没有 `enabled`，而是由 `iprecon.enabled` / `fofa.enabled` 两个
  子开关控制，**两者都关时整阶段直接跳过（一次请求都不发）**；`fofa` 下另有两个**子能力**：
  favicon（`icon_hash`，默认随 `fofa.enabled`）与**证书反查**（`cert_enabled`，默认跟随），
  各自有阈值排除（黑 ico / 通用证书）。第三个子能力是**标题反查**（`title_enabled`），续22 起带
  **归属相关性过滤**（`fofa.title_match`，默认 `label`：标题 token 须与候选域名某个 label **完全相等**
  才入库，挡掉"标题恰好含同一子串"的无关域名；设 `substring` 回退旧的子串匹配）；切不出 token 的标题
  （如纯中文）**fail-open 保留**。
- **黑名单在三处入库前过滤**（`subdomain` / `jsmine` / `osint`，统一走 `scanner/blacklist.py`）：
  命中即不写资产库，因此后续阶段自然不扫 —— 新增"产出域名"的阶段必须记得在入库前过一遍。
- **jsmine 的域名形态判断含公共后缀（PSL）校验**（续22）：末位必须是合法公共后缀（读
  `config/dicts/tlds.txt`，支持 `co.uk`/`com.cn` 等多段后缀），否则 `wallet.filter.withdraw`
  这类"点号连接的 JS 成员访问链"会被当成域名。清单缺失/为空时 **fail-open**：回退旧的宽松判断
  并告警一次（绝不静默丢资产）。
- **测试隔离靠两个环境变量**：`CTFSCANNER_DB`（库路径）与 `CTFSCANNER_LOGS`（任务工作目录）。
  `tests/smoke.py` 顶部把两者指到 `logs/smoke-<随机>/` 并在退出时删除 —— 跑测试**不会**污染
  真实 `data/scanner.db` 与 `logs/`。跑任何"会写资产"的脚本时请沿用这一约定（见 `docs/usage.md` FAQ）。
  两者都经 `scanner/config.py::env_path()` 归一（2026-09-23 续10）：空值回落默认、剥外层引号，
  **仅 Windows** 把 `/c/Users/x` 这类盘符式 POSIX 路径翻译成盘符形态 —— Git Bash 里
  `export CTFSCANNER_DB="$PWD/logs/x.db"` 传的是 `/c/...`，不归一就会被解析成**盘符根下的 c 目录**
  （库建到盘符根，`rel_display()` 还打印残缺路径，已实测踩过）。POSIX 系统上不做转换
  （那里 `/d/tmp` 就是普通目录）。新增"路径型"环境变量请复用 `env_path()`，不要各写一套。
- 每个阶段结果**三写**：任务目录文本产物（如 sites.txt）、SQLite、`ctx.results`（供下一阶段直接用）。
- 阶段级容错：单阶段异常不中断流水线，错误写入 `tasks.error`，任务最终仍置 `done`（docs 已声明此语义）。
- GUI：Flask 请求线程 + 每任务一个 daemon 线程；无任务队列，进程重启则运行中任务中断。
- **同任务「追加式执行」**（续25）：任务详情页的「补扫 / 复查 / 送去探测」可勾「追加到本任务」，
  把该阶段**追加进源任务**（不新建），结果累积、**跨运行去重**（同名站点/目录/端口/漏洞/子域名/
  证书不重复入库），续写同一 `log_file`、**不清 `error`**、进度重置。硬约束：**同任务并发追加必须
  拒绝**（`runner._register_stop` 是覆盖式注册，第二次追加会顶掉停止事件）；站点/IP/全端口三个
  **无源**入口**不能追加**（只保留"新建任务"）。被追加过则 `options.append_count>0`，详情页与
  导出报告显示「追加」横幅。内核在 `runner.run_task(..., append=True)`，去重在 `db.drop_existing()`。
- **统一并发 / 限速 / 全局预算门控（F2，`scanner/throttle.py`）**：`StageContext.__init__` 在注入
  登录态**之后**，用 `throttle.inject` 给 settings 副本再挂一个任务级限流器（`settings["_throttle"]`）。
  三条出口——`utils.http_request`（HTTP）、`utils.run_cmd`（外部子进程）、`portscan` 的裸 socket
  （`_probe_port`）——取"在飞名额"都走 `throttle.slot(kind)`：先**任务级闸**、再**进程级闸
  （跨任务共享，`_GLOBAL_STATE`）**、最后**令牌桶**，顺序固定以防死锁。实际并发是
  `min(阶段并发, max_inflight_per_task, max_inflight_global)`（`Throttle.effective_cap`）——
  这才是"消灭 `stages/portscan.py` 8 主机 × `full_workers`(256) = 2048 在飞 / 进程级零上限"的落点。
  **预算耗尽（`budget_total`）＝按停止处理**：`Throttle.exhausted()` → `StageContext.stopped()` 为真
  → 各阶段在循环边界干净收尾 → `PipelineRunner` 把任务标 **`stopped`（不是 `done`）** 并追加一条
  `[throttle] 请求预算耗尽…结果不完整` 的错误行（与"用户点了停止"用不同文案区分）。
  取消仍是协作式：所有等待都是 `Condition + wait(poll)` 轮询 + 入口检查，置位即抛 `StopRequested`
  并释放已持有的闸，**绝不"点了停止却卡在等锁"**。v1 覆盖缺口见 §7。

## 5. 关键不变量（改代码时务必保持）

1. **所有 HTTP 必须走 `utils.http_request`** —— 统一 UA、超时、`limits.verify_tls`（verify=None 时读配置）。
   不要直接 import requests/urllib。这也是**唯一伪装出口**：`utils._headers` → `evasion.browser_headers`
   （UA 随机化、浏览器化请求头、可选 XFF 伪装），改 HTTP 行为只在这一处生效。
   **登录态（任务级 Cookie/Token）同理只在这一处生效**：`http_request(..., auth=True)` 才附带
   `settings["_auth_headers"]`（由 `runner.StageContext` 注入的任务专用副本）。**默认 `auth=False`** ——
   新增调用点时先问一句"这个 URL 是目标侧还是第三方接口"，第三方**永远不加 `auth=True`**（见 §7 凭据红线）。
2. **外部工具优先 + 内置兜底**：调用前用 `which()`，Good 工具再用 `verify_tool()` 做版本握手
   （防止 pip 的 Python `httpx` 同名命令被误用）。
3. **非破坏性**：新增检查/POC 只允许探测类请求；POC 规范见 docs/poc-guide.md。免杀（evasion）只改变
   payload 的**编码形态**与请求伪装，不改变语义，不越过"无爆破/无 DoS/无写操作"红线。
4. **SQLite 线程安全靠"每次调用独立连接"**（db.get_conn 用完即关）——不要改成共享长连接。
5. **POC 注册表与扫描联动**：`engine.load_enabled_pocs` 只返回注册表里 `enabled=1 AND status='ok'`
   且级别未被 `skip_severities` 排除的记录，因此新增 POC 后需 `runner.sync_pocs()`
   （GUI 启动/刷新时会调用）。
6. **漏洞去重是调用方约定，数据库层没有约束兜底**：约定的去重键是 `(target, poc_id)`
   （即"每 POC 每目标最多一条"），但 `vulns` 表**没有** UNIQUE 约束（`scanner/db.py` 建表语句）、
   `db.insert_vuln` 是**裸 INSERT** —— 去重完全由**调用方**在做：
   `scanner/stages/vulnscan.py` 与 `scanner/stages/takeover.py` 各自建 `seen` 集合去重；
   `scanner/stages/jsmine.py` 则是直接插入、靠上游按主机名去重。因此新增任何写 `vulns` 的路径
   **必须自己保证去重**，不能指望数据库拦（用户已明确把"给 `vulns` 加 UNIQUE 约束"划到范围外）。
7. **分级门控（三层，`checks` 段）**：
   1. `skip_severities` 默认 `["info","low"]` —— **执行级**：这些级别连请求都不发
      （`owasp.checks.enabled_checks` + `pocs.engine.load_enabled_pocs` 同规则，helper 是
      `config.skip_severities()`）；
   2. `disabled_categories` / `disabled_checks` 命中的检查根本不执行（省请求）；
   3. `min_severity` 默认 `medium` —— **结果级**，过滤残余的低危/info 结果。
   即 `a02-no-https`、`a05-security-headers`、`a05-banner-disclosure` 这类项默认既不执行也不产出。
8. **所有对外"在飞动作"必须过统一门控（F2，`scanner/throttle.py`）**：HTTP 走 `utils.http_request`
   （已自动读 `settings["_throttle"]`）、外部子进程走 `utils.run_cmd(..., throttle=...)`、裸 socket 走
   `throttle.slot("socket")`。新增任何"会连目标 / 起进程"的调用点时，**必须显式把限流器传进去**
   （`ctx.throttle` / `settings["_throttle"]`）—— 不传就等于绕过并发 / 限速 / 预算。
   `throttle=None` 时按旧行为直通，那是给**离线工具与单测**留的口子，**不是给扫描路径用的**：
   漏接一处就会出现"点了停止仍有请求在飞"或"预算形同虚设"。
   补充（续21）：`throttle.slot()` **不可重入** —— 底层 `_Gate` 是**计数信号量**，同一线程在已持有
   名额时再 `slot()` 会**自锁**（等自己释放，永不返回）；**禁止在同线程里嵌套取名额**（需要"同一
   动作占多份"时用 `weight=` 一次取足，别嵌套）。`budget_total` 是**硬上限**：预算的"检查 + 扣减"
   在**同一临界区**内原子完成（`Throttle._reserve_budget`），并发下**不可能超发**（回归 `[6g]`）。

## 6. 如何验证改动

```powershell
py -3 tests/smoke.py        # 唯一回归门禁：自包含起靶场，断言覆盖 目标解析+CIDR/阶段注册(12 个)/POC 级别执行门/
                            # 免杀变形/mmh3 公开向量+iprecon/fofa 纯函数/响应体解码/流水线+指纹/三层门控/阶段门控(含 osint)/
                            # 非标端口候选/报告(含 C 段 IP)/停止/导出/GUI 路由(9 栏侧边栏 + /ports /csegs /dirs)与批量接口/
                            # 子域名分流+CDN 标记+站点折叠+POC 相对路径/
                            # 第十四轮新增 `[5d]`：注册域折算(base_domain) + 相对路径(rel_display) + 黑名单
                            # (含临时文件与开关失效) + 证书反查(build_cert_query/is_common_cert/search_cert 空域名) +
                            # source_label + 拓展域名重叠隐藏与 ?all=1 + 站点重叠 1↔2 条 + 黑名单/批量子域
                            # 两个 POST 接口(桩函数去重保序/阶段与 targets) + 策略页 cert/blacklist 字段与
                            # `panel collapsible`、无绝对路径、logs/smoke- 相对路径 + POST 映射
                            # 第十五轮新增 `[5e]`（8 组）：端口区间上限 vs 全端口放开 + 标题反查(语句/阈值/模板标题) +
                            # 目录(dirmap 行解析/重复长度文件不读/别名站去重/大小列/折叠 1↔3) +
                            # JS 敏感字符(AKID/JWT/PEM 命中 + 占位降噪) + /fullports 页与发起接口(桩 run_task) +
                            # FOFA 裸 IP 收口(_domain_of) + dirscan 阶段级"只扫不重复站点"(记录型 logger)
# 第十七轮(续8)新增 `[5n]`：情报订阅(intel：源地址/缓存命名安全/CVE 规整/白名单匹配
                            # 与词边界/资产文本不含标题/级别/组装线索) + 启发式(5 条规则正反例) +
                            # leads 写入侧去重 + 默认关门控不写库 + 报告「线索」附录只在非空时出现
# 第十八轮(续9)新增 `[5p]`：目录浅/深两档（默认 quick + 只吃 dirs_shallow + ≤quick_max_paths）
                            # + 档位判定（dirscan_full 强制 deep、portscan_full 不互相影响）
                            # + 补扫任务目标兜底(_sites_from_targets) + 建任务自动补阶段与顺序
                            # + POST /api/rescan（阶段/rescan_of/命名/next 防外站）
                            # + 后缀派生去重限额 + GUI 入口（portscan_full/dirscan_mode/api/rescan）
                            # 2026-09-23 续10 新增 `[5p] 3c`：端到端**真跑一次浅扫**（产物必须同时
                            #   命中 .env 与 .git/config、条数≥2、请求量 ≤ quick_max_paths + 基线）
                            #   —— 前三条是桩实现，只验"走哪一档"，补的就是"真扫出什么"
                            #   新增 `[5q]`：CTFSCANNER_DB/LOGS 路径归一化（空值与引号回落默认、
                            #   盘符式 POSIX 路径 Windows 归一 / Linux 原样、普通路径不动）
                            # 2026-09-23 续12 新增 `[5r]`：误报复核（状态枚举与非法值归一/单条与批量打标
                            #   （含混入非法 id）/三态筛选/复核计数/报告台账 + 「已判误报」附录（不计入漏洞数））
                            #   新增 `[5s]`：POC 置信度（来源分 × 内容型匹配器、只降级不升级、upsert 重算、
                            #   内置 POC 全 high、按层批量启停 + kind=diff 幂等）
                            #   重写 `[5e-0]`：fscan 2.2.1 真实输出 7 组断言（三正则解析 / 统计行交叉校验 /
                            #   数目不符或 rc≠0 → None / 0 个 → [] / 跳转目标不被误记）
                            # 2026-09-23 续14 新增 `[5u]`（sensitive.txt 签名列数据驱动 A01 + db 写锁串行化）
                            # 2026-09-23 续15 新增 `[5v]`（证书：内联夹具解析 + 127.0.0.1 真握手 + 门控零请求
                            #   + 落库/产物/页签/报告 + 清空资产 + 勾选即 cert_on）
                            #   新增 `[5w]`（报告三格式与趋势：八节 MD↔HTML 一一对应 / XSS 载荷全转义 /
                            #   自包含无外链 / 误报不计入趋势·未知级别归 other / 三格式路由 /
                            #   无浏览器时 PDF 返回 400 + 可读原因 / 仪表盘趋势面板）
                            # 2026-09-23 续17 新增 `[5x]`（登录态扫描：解析/掩码/不静默丢弃 + fail-closed
                            #   （回显靶场 + 逐行断言 4 个第三方调用点不带 auth）+ CLI -H/--cookie 与
                            #   GUI 400 + 补扫继承 + 页面只显掩码不回显明文；POC raw 解析与破坏性方法拒绝、
                            #   flow 布尔子集（短路/纯否定不报/越界与被跳过块引用标 unsupported）、
                            #   workflows 子模板与自环保护、dsl 仍显式 unsupported）
                            # 2026-09-23 续18 新增 `[5y]`（批次 4 五项）：
                            #   XSS 上下文判定表（8 上下文 / 探针定界符存活 / 全转义不报 + poc_id 不变）
                            #   + A10 SSRF 受控回连（默认关零请求 / 本机监听自证 / 外部回调不谎报 /
                            #     监听线程不泄漏）+ 布尔盲注（恒真恒假对比数字 + 页面抖动不判 + 无 SLEEP）
                            #   + Shodan/Quake（无 key 不发请求 + 查询串 + 阈值 + 裸 IP 收口 +
                            #     POST/X-QuakeToken + 配额报错）
                            #   + CT 日志（非 JSON/限流容错 + `*.x` 通配符剥离 + 默认关门控 +
                            #     第三方不带登录态）+ 新开关三方一致（DEFAULTS/settings.yaml/GUI POST）
                            #     + 证书来源列
# 2026-09-24 续20（含 -fix 与 F2）新增 `[6a]`~`[6f]`：复核修复回归（盲注全参数 / ssrf close 真 join /
                            #   ctlog 逗号切分）/ JSONL 导出（含误报行、与 MD 刻意差异）/ 错误追加不丢 /
                            #   孤儿任务对账 / CLI JSONL 行尾 `\n` 与 OpenProcess fail-safe /
                            #   **F2 统一门控**（闸门计数与取消不卡 / 令牌桶限速 / effective_cap=min(阶段,任务,全局) /
                            #   预算耗尽=按停止→任务标 `stopped` + `[throttle]` 错误行 / inject 不原地改 /
                            #   进程级闸跨任务共享 / http_request·run_cmd 耗尽时按停止不抛）
# 2026-09-24 续21 新增 `[6g]`~`[6j]`：F2 预算**原子化**（真实线程池 pool=20/100 作业，cap<budget 时
                            #   旧代码超发 21/22 → 修复后恒 == budget）/ 失败路径**退还预算**（等闸时取消：
                            #   不挂死 + 全额退还 + rejected==0）/ 混合 `max_inflight_global` 重建闸**告警**
                            #   （不静默）/ `slot()` **不可重入**（同线程嵌套会自锁、靠 stop 解开）
# 2026-09-24 续22 新增 `[6k]`：拓展域名降噪三件套 —— jsmine 加**公共后缀（PSL）校验**
                            #   （拒 `wallet.filter.withdraw` / `react.transitional.element` / `react.client.reference` / `i.test`，
                            #   多段后缀 `co.uk`/`com.cn` 仍接受；清单缺失 fail-open + 只告警一次）/ 第三方清单补 9 条
                            #   （含 `cloudflareinsights.com` 单独成行才拦得住 `static.*`）/ FOFA 标题**归属相关性**
                            #   （默认 `label` 档丢 `silviapengo.com`/`gkops.net`/`yulw.cn`、留 `pengo.*`；`substring` 档
                            #   复现宽松；中文标题 fail-open）+ 新开关 `fofa.title_match` 三方一致
# 2026-09-24 续25 新增 `[6l]`：同任务**追加式执行** —— 续写同一 log_file + 不清 error + 进度重置 /
                            #   跨运行去重（同 站点+路径·站点 不重复）/ 并发 409 硬拒绝 / 无源入口 409 /
                            #   仅勾选目标 / append_count 标记 + 导出横幅
py -3 cli/client.py --check # 外部工具可用性（dirmap 看 tools/dirmap/dirmap.py 是否存在）
py -3 tools/import_dir_dict.py  # 重新生成目录扫描大字典（源：tools/dirmap/data/dict_load/dict_mode_dict.txt）
py -3 tools/import_fw_dicts.py --force  # 从大字典派生**按框架**细分的字典（12 桶 + exposure）
py -3 cli/client.py -t http://127.0.0.1:8765/ -p probe,vulnscan --offline
py -3 run_gui.py            # 控制台 http://127.0.0.1:5000，口令 ctfscanner
# Linux 实机验收（**2026-09-23 续12 已达成**：Ubuntu 22.04.5 / Python 3.10.12）
#   python3 tests/smoke.py   → SMOKE PASS（`[5o]` 会按运行平台自报状态）
#   搬运：整树拷贝（含 config/dicts/），远端 `python3 -m pip install --user -r requirements.txt`
#   注意 `scp` 整树时别用 `tar --exclude=.git` —— libarchive 按 basename 匹配，会把
#   `smoke_root/.git/config` 一起排掉，导致 `[3] pipeline` 少一条 exposure-git-config 而假失败。
#   Windows 侧非交互 SSH：设 `SSH_ASKPASS`（**必须放在纯 ASCII 路径**，含中文会
#   `CreateProcessW failed error:2`）+ `SSH_ASKPASS_REQUIRE=force`；凭据由用户提供、不入库。
```

改动后**必须**跑 `tests/smoke.py`；GUI/模板改动还应 `run_gui.py` 亲眼确认页面。

> **弹「删除」确认是正常的，不是脚本在删你的数据**：`tests/smoke.py` 会在 `logs/` 下用
> `tempfile.mkdtemp(prefix="smoke-")` 造一个隔离沙箱（库与任务目录都指进去，见文件头 21–33 行），
> 跑完靠 `atexit` 里的 `shutil.rmtree` 自清。沙箱/杀软的 safe-delete 守卫按**每轮累计删除条目数**
> 计数（实测提示 `{"count":50,"threshold":50,"scope":"turn","targetCount":1}` —— 一个目标目录里
> 有 50 个条目），到阈值就弹确认；而 `ignore_errors=True` 把"被拦"变成**静默失败**，于是
> `logs/smoke-*` 会攒下来（本机攒到过 56 个 / 12 MB）。
> **它只删自己刚造的那一个目录**，不碰 `data/scanner.db`，也不碰 `logs/task_*`；残留本身是纯垃圾
> （`logs/` 已在 `.gitignore`），定期手删 `logs/smoke-*` 即可，不必为此改脚本。

### 6.1 修 bug 时，必须证明新断言**在旧代码下会挂**（2026-09-24 立的规矩）

> 背景：本项目出过两次"假测试"。第一次是 `[5p]` 把 `run_task` 桩掉了，只验"走哪一档"不验"真扫出什么"，
> 结果深扫漏掉 `.env` 的缺陷藏了很久；第二次是批次 4 修完 SSRF `close()` 的死代码后补的断言，
> 把修复**退回旧实现**跑，三条断言**依然全过** —— 因为 `srv.shutdown()` 本来就会阻塞到线程结束，
> 且旧写法同样把字段清成了 `None`。断言验的是"结果状态"，而死代码的问题恰恰在"代码路径没走到"。

**规矩**：凡是为某个 bug 补回归断言，交付前必须做一次**证伪**——把修复在内存/工作区里
**临时退回旧行为**，确认新断言**真的失败**；再还原，确认全过。两次观察结果都要写进报告。
退不回失败 = 这条断言没有区分度，等于没加。

**怎么退**（不改提交历史）：临时改回旧代码跑一次 smoke（跑完立刻还原，**不要提交那个版本**），
或在一次性脚本里 monkeypatch 常量/函数（脚本放 `logs/` 下、跑完删掉）。
可参考 `tests/smoke.py [6a]` 的写法：**桩注入 + 断言调用行为**（`join_calls == [2]`），
比断言"结果状态"（`not th.is_alive()`）强得多 —— 后者在新旧实现下都成立。

推论：**能被新旧实现同时满足的断言，不是回归测试**。写断言前先问"旧代码会让它挂吗"。

## 7. 已知局限 / 坑（真实存在，不是 TODO 清单）


- **XSS 上下文分析（2026-09-23 续18）把"反射回显"拆成 8 种上下文并分级**：
  `<script>` 内 JS 字符串 / JS 代码、无引号属性、标签名位置 → **high**（可直接逃逸或执行）；
  双/单引号属性 → medium（需先闭合引号）；HTML 文本节点 → medium（**证据里写明"需 `<` 未被转义"**）；
  HTML 注释内 → **降级为 low**（要先闭合 `-->`，多数场景不可利用；默认门槛 medium 下不产出，
  把 `checks.min_severity` 调到 low 才看得到）。
  判定靠两条探针：① 原 payload 是否**原样**回显；② 上下文探针（标记串 + `"'<>`）看哪些定界符
  **活着回来**（引号活着＝属性/JS 串可逃逸，尖括号活着＝文本节点能插标签）。
  **全部被转义的回显一律不报** —— 那是旧逻辑最大的误报源。
  `poc_id` 仍是 `a03-xss-reflect`（去重键 `(target, poc_id)` 不变），只是级别与证据随上下文变。
- **盲注只做布尔型，明确不做延时型**：`SLEEP()` / `BENCHMARK()` / `WAITFOR DELAY` / `pg_sleep()`
  会挂住目标数据库的连接线程（并发一上去就是事实上的 DoS，与"非破坏性"红线冲突），
  且跨公网抖动经常盖过几秒的差值。`a03-sqli-blind` 走"恒真 vs 恒假"差分（比状态码与长度），
  并**再发一次恒真做稳定性复验** —— 页面自带随机数/时间戳时恒真自己都会抖，不复验就是误报。
  **2 形态 × 5 参数 × 3 请求 = 总预算 30**；循环是**形态外层、参数内层**，预算优先保证
  5 个候选参数**都被覆盖**（参数外层时第一个参数就吃掉大半预算，加上 `_ordered()` 打乱顺序，
  等于"每次随机只测到前几个参数"—— 这个坑本轮踩过并修掉）。
  **已知覆盖缺口**：刻意放弃 `)` 与 `"` 两种上下文形态。命中必须给出**对比数字**（两次的状态码与长度）。
- **A10 SSRF 受控回连只在"目标能回访扫描机"时有效**：本机监听（`127.0.0.1`，端口 0 由系统分配）
  在扫描机位于 NAT 后 / 云主机没有公网 IP / 目标出网被出口防火墙拦掉时**一条回连都收不到**
  —— 这是**环境限制，不是缺陷**。填了 `ssrf.callback_base`（外部 OOB 服务）时本模块
  **读不到那侧的命中**，因此只注入、把 token 写进任务日志、**不伪造命中**（宁可不报）。
  **刻意不做**：不打内网地址（`127.0.0.1:8080` / `169.254.169.254` 那类属于利用，越线）、
  **不提交页面表单**（表单可能是写操作，所以表单只被用来取**字段名**，注入一律走 GET）、
  不做延时判定。监听端口用完即关（`finally` 里 `close()`）。
- **crt.sh 的三个"看起来很像"的能力别混**（`ctlog` / `passive` / `certs` / FOFA `cert=`）：
  `scanner/ctlog.py` 查公开 **CT 日志**，产出**证书维度**记录（签发者/有效期/序列号/涉及域名/
  CT 条目数，写进 `certs` 表且 `source='ct'`）；`scanner/passive.py` 的 crt.sh 只取主机名做
  **子域名收集**；`scanner/certs.py` 是对目标做**真实 TLS 握手**取线上正在用的证书；
  FOFA 的 `cert="domain"` 是拿证书去反查**共用它的其它资产**（不产出证书字段）。
  同一个域名在 CT 里往往有几十张历史证书，**CT 记录是线索与资产面补充，不等于"目标现在用的证书"**，
  所以「SSL 证书」页签与报告都有**来源列**区分。
  crt.sh 是公共免费服务：返回 HTML 限流页 / 超时 / 502 都是常态，所有失败只记一行日志继续跑。
- **Shodan / Quake 反查与 FOFA 是同构的三份代码**（`scanner/shodan.py` / `quake.py` / `fofa.py`），
  刻意**不抽公共基类**：查询语法、鉴权方式（query 串 / X-QuakeToken 头 / qbase64）、响应结构与
  配额模型各不相同，抽象只会把差异塞进一堆分支。三家共用同一个 mmh3 键（`scanner/mmh3.py`），
  `osint` 阶段内 **favicon 哈希按 (max_sites, workers) 缓存**，避免每家各拉一遍。
- POC 引擎是** nuclei 兼容子集**：支持 `http:`/`requests:`、`payloads`（list / dict + `attack`）、
  `variables` + 内置变量、`path` 列表、`redirects`、匹配器 `status/word/regex/size` + `condition`/`negative`/
  `case-insensitive` + `part: body|header|all`、`extractors`（regex/kval）；**`raw` / `flow`（布尔子集）/
  `workflows`（子模板编排）自 2026-09-23 续17 起为子集支持**。仍不支持的 `dsl`、oob 反连、
  flow 的 JS/循环/带参数引用、workflow 的 `subtemplates`/`args` 会被标 `_status=unsupported`
  （或写进 `_note`）并在 POC 管理页显示原因（不静默失效）。
- **凭据红线（2026-09-23 续17）**：登录态（`scanner/auth.py` 的任务级请求头）**只发目标侧**，
  `utils.http_request(auth=False)` 是默认值、4 个第三方调用点（crt.sh / FOFA / CISA KEV / IP 反查）
  **永不带**；日志/页面/报告只显掩码（`mask_value`）；解析非法行必须报错（CLI exit 1 / GUI 400），
  **不许静默丢弃**（少带一条 Authorization 会让"已登录扫描"变成假象）。框架**不做**登录爆破/表单提交。
- `owasp` 字段**格式是统一的**（`A01` 大写）：POC 引擎在 `engine.py` 里把 tag 的 `owasp-a01`
  规整为 `A01` 再入库，内置检查本身写 `A01`。*（本文件此前写的"POC 命中写 `owasp-a01`"与代码不符，
  已按代码更正 —— 见 `TODO.md` P1-3。）*
- **dirmap 自身代码的 5 个问题**（第十六轮已**修在本机那份外部副本**里，见下一条）：
  `saveResults()` 定义了两遍（前一个失效）、`response_storage`/`error_count` 是全局量、
  `saveResults` 每次全文件 `r+` 读取再追加（1.5 万条结果时 O(n²)，gevent 并发下还会丢写）、
  `conf.skip_size` 与 `intToSize()` 的字符串比较永远不相等、`ssl_context` 建了却没挂到 session。
- `config/dicts/sensitive.txt` **已是 A01 检查的数据源**（第十八轮续14 起）：文件格式改为
  `路径 | 特征关键字1,特征关键字2 | 级别 | 说明`，`checks.sensitive_files()` 读它、按"200 + 关键字命中"
  判定；**只有路径没有 `|` 的行＝预留位（跳过）**，文件缺失或一条可检测行都没有时回退
  `checks.SENSITIVE_FILES` 硬编码清单 —— 不带关键字就凭 200 判"文件存在"会被统一 200 的软 404 页放大。
- `db._WRITE_LOCK`（`threading.RLock`）把**所有写路径**串行化：`_exec` / `init_db` / `set_vuln_review` /
  `bulk_set_vuln_review` / `upsert_poc` 主路径。WAL 只保证"读不被写阻塞"、`busy_timeout=10000` 只保证
  "冲突时最多等 10 秒"，**都不保证写成功**；而本框架无任务队列，N 个任务线程 × `pool_run(workers=20)`
  的回填是完全可能同时打满的。新增写路径时**必须**走 `_exec` 或显式加这把锁。
- `parse_line` 对裸域名会 `strip("/")` 并小写；CIDR 会展开为多条 `("ip", …)`
  （`MAX_CIDR_ADDRESSES=256`，超过则整体丢弃并在解析阶段记日志）。
- GUI 无 CSRF/HTTPS 加固，仅限本机；「策略配置」页覆盖 gui/limits/checks/subdomain/passive/evasion/
  takeover/portscan/jsmine/dirscan/vulnscan/screenshot/cert/iprecon/fofa/**ssrf/shodan/quake/ctlog**/
  blacklist/intel/heuristic **二十一段**（dirscan 段含 mode/quick_max_paths/suffix_aware/big_dict/max_paths；portscan 段含 mode/full_ports/exclude_scanned）
  （含按级别 / 按 OWASP 分类 /
  按检查项三级开关），并且**每个"大功能"都有阶段级 enabled 总开关**（`dirscan` / `vulnscan`
  于第十轮补齐：此前这两段在 DEFAULTS 里根本不存在，无法从 GUI 关闭；
  `dirscan` 默认值于**第十八轮（续9）**由 `false` 反转为 `true`+`mode=quick`）；
  外部工具路径、字典路径与 `passive.sources` 清单要手改 settings.yaml；
  fofa 的 email/key 要手改 `config/keys.yaml`（控制台只读、不写回凭据）。
- `wildcard.py` 只用系统解析器（`socket.getaddrinfo`），**取不到 CNAME**，故无法用"通配 CNAME 黑名单"维度。
- **任务详情为 11 个页签**（潜在漏洞(默认)/站点/子域名/拓展域名/端口服务/C 段/目录/**SSL 证书**/线索/目标与配置/运行日志）：参考 ARL 界面的
  IP/文件泄露/URL信息/nuclei/指纹统计/WIH 这些页签**故意不做空占位**，因为对应的数据源
  还不存在（分别依赖爬虫数据模型、nuclei 二进制等）。理由与依赖关系见 `TODO.md` B-7。
  「SSL 证书」页签是续15 的落点（只读 TLS 握手 + 纯标准库 DER 解析，**握手不校验证书**）：
  证书的「自签 / 已过期」是**属性**，页签与报告都写明不是漏洞结论，且没有产物时会说明原因。
  「线索」页签是 P3-2/P3-3 的落点：**线索 ≠ 漏洞结论**，因此单列、单计数，不混进「潜在漏洞」。
  「拓展域名」页签与跨任务 `/extdomains` **共用同一张来源顺序表**（`EXT_SRC_TAGS`：
  JS 挖掘 → FOFA·标题 → 证书 → ICO → C 段，同类内新的在前），任务页另支持 `?esrc=` 分类过滤；
  以及三个**手动**处置（2026-09-23 续13）：纯 DNS 解析 `POST /api/domains/resolve`、
  送去探测 `POST /api/domains/scan-ext`（新任务 `probe→dirscan→vulnscan`）、
  `POST /api/blacklist/add`（此前任务页签没有此入口）。
  **为什么必须手动**：`osint`/`jsmine` 排在 `probe` **之后**，它们新挖出的域名赶不上本轮存活探测，
  天然停在"有域名、无站点、无检测"；而拓展域名里大量是 CDN/开源库/JS 命名空间碎片，
  全自动跑既越权又浪费额度 —— 这是**设计边界，不是缺陷**。
- **`osint` 的联网往返无法离线自测**：`tests/smoke.py` 只断言了 `iprecon`/`fofa`/`mmh3` 的纯函数、
  黑 ico 阈值边界与"两个子开关都关则无产出"的门控；`api.webscan.cc` 与 FOFA 的真实响应结构
  需要联网（FOFA 还需 key）才能验证 —— 首次实跑请打开开关并观察 `logs/task_*/task.log` 的 `[osint]` 行。
- `osint` 的阈值都是**保守估计值、未经真实数据校准**：黑 ico 阈值 200、通用证书阈值 200
  （`fofa.cert_threshold`）、单 IP 域名数 30（判共享主机）。都可在「策略配置 → 外部情报拓展」调整，
  不需要改代码。证书反查的"通用证书"判定尤其粗：**只按命中总数比阈值**，不做证书主体/颁发者分析。
- **`js_thirdparty.txt` 是黑名单，永远不可能穷尽**（续22）：它是"已知第三方/公共库域名"清单，
  新库/新 CDN 出现就得补；漏网的表现是「拓展域名」页出现某个开源库域名。`tlds.txt` 同理是
  **PSL 快照**，会滞后于 IANA 的 TLD 变更（重生成：`py -3 tools/import_tlds.py --force`）。
  两者缺失/为空都 **fail-open**（回退宽松判断并告警一次，绝不静默丢资产）。
- **黑名单的语义边界**：过滤发生在**入库前**，所以它**不影响已入库的历史资产**（老任务里的域名照旧可见），
  也不会因为后来把某域名加入黑名单就把既有行删掉。文件是纯文本、每次调用重读（改完立即生效，无需重启）。
- **重叠隐藏是"显示层"判据，不是删除**：`OVERLAP_EXT_WHERE`（拓展域名域名级全局）与
  `OVERLAP_SITE_WHERE`（站点 URL 级跨任务，保留 `MAX(id)` **最新一条**）只作用于 `/extdomains`、`/sites`
  两个列表页，`?all=1` 可放开；任务详情页签与报告仍显示全量。因此"站点页条数比任务详情少"是预期行为。
- 任务已支持**停止（协作式取消）/删除/重启/导出 + 批量操作**；停止粒度是"当前批次跑完即停"，
  不会强杀正在飞行的 HTTP 请求，任务终态记为 `stopped`（区别于 `failed`）。
- **追加执行的语义边界**（续25）：追加**只影响本轮跑的那些阶段**，不重跑整条流水线；跨运行去重是
  "**入库前跳过同键**"（不删已有行），所以用户已打的 `review` / `review_note` 不会被覆盖；
  续写 `log_file` 会把多轮日志拼在同一文件里（有意的 —— 便于按任务维度回溯全部运行）。
  追加**不改 `tasks.stages`**（任务对外仍声明原阶段集），进度按本轮重新计时；
  **同任务并发追加硬拒绝**（否则停止信号被覆盖），**无源入口**（站点/IP/全端口三页）不提供追加。
  导出有三档（续16）：`/tasks/<id>/export?fmt=md|html|pdf`（默认 md），
  **HTML 全量 `html.escape`**（报告里的标题/banner 来自被测目标，漏转义即反射型 XSS）、
  **PDF 复用无头 Edge/Chrome 打印**（没有浏览器时返回 400 + 可读原因 + HTML 替代链接，不静默失败）；
  仪表盘另有「漏洞趋势统计」面板（`db.vuln_trend()`：级别分布 + 最近 15 任务逐任务计数，**已判误报不计入**）。
- **改完 GUI 必须重启服务**：若 5000 已被旧进程占用，新起的 `run_gui.py`（经 `gui/app.py serve()`）
  会打印端口占用提示并以退出码 1 结束——按提示结束占用进程或改 `gui.port` 再试；
  请求还是打到旧进程（新路由 404）——很容易误判成"代码没生效"，先确认端口占用再排查。
  **实测代价**：曾有一个旧 GUI 进程（PID 18360，2026-09-21 14:09 启动）被点名却一直没人杀，
  连续两天占着 5000；服务端 `debug=False` 既不重载代码也不重载 Jinja 模板，于是"代码明明改了、
  页面却是 5 栏旧导航 + 还写着'疑似问题'"。**排查任何"页面不对"之前，先看进程启动时间**：
  `Get-CimInstance Win32_Process -Filter "Name like '%python%'" | Select ProcessId,CreationDate`。
  **本轮又踩一次（2026-09-22）**：GUI 于 17:17 重启，而我 17:20 才给 portscan 阶段加
  `full_workers/full_timeout` —— 从那个 GUI 发起的全端口任务**仍按旧参数**跑（日志写「最坏约 17 分钟」），
  因为 Python 进程早已把模块加载进内存。**结论：改完任何会被 GUI 调用的代码，都要重启 GUI 再验证。**
- **不要让子代理/自动化去点 GUI 的写操作按钮**：批量停止/重启/删除、新建任务都是真写库。
  本轮实测教训：一个被要求"只观察"的浏览器子代理点了「批量删除」并**把 `confirm()` 确认框也确认了**，
  硬删掉 63 条历史任务行；紧接着又提交了「新建扫描任务」表单，对一个**外部真实域名**跑了全 8 阶段扫描。
  派浏览器代理时必须在提示里明确写"只读浏览，禁止点击任何提交/删除类按钮"，并**限制其可操作页面**。
- **dirmap 适配的三个实测坑**（改之前先读 `stages/dirscan.py::_run_dirmap`）：
  ① 产物在 `output/<域名>/` **子目录**里（`res.txt` / `403.txt` / `404.txt` / `重复长度.txt`），
  不是早年的 `output/<域名>.txt`；② `output/` 是**持久目录**；
  ③ **只按 mtime 过滤会漏结果** —— dirmap 的 `saveResults()` 会与文件已有行去重，
  重扫同一目标且结果不变时**它不写新内容**、文件 mtime 保持旧值（实测「跑了 37 秒却解析 0 条」）。
  **最终方案：按目标定位** `output/<netloc 把 : 换成 _>/*.txt`，再按目标 netloc 过滤行，
  mtime 过滤只作兜底。结果行格式是 `[状态码][content-type][大小] URL`（大小形如 `1.23kb`），
  我们只读 `res.txt` / `403.txt`（`重复长度.txt` 按用户要求默认不展示）。
- **dirmap 是 GPL-3.0，刻意不内联**（把源码拷进仓库会让整个仓库受 GPL 约束）：
  只保留 `tools/dirmap/` 目录联接 + 外部适配器；对它的 5 处源码修复（重复定义 / 死变量 /
  O(n²) 读回+并发丢写 / `skip_size` 比较恒假 / `ssl_context` 未挂载，**588s → 43s**）记录在
  `tools/dirmap_fixes/README.md`（**该目录不含 dirmap 源码**）。
- **全端口扫描（1-65535）实测**（2026-09-22，本机回环）：`workers=256`/`timeout=0.3` → **82 秒**；
  **默认参数** `workers=64`/`timeout=1.0` → **1037 秒（17.3 分钟）**，差 12.6× —— 全端口用默认参数基本不可用，
  故新增 `portscan.full_workers`（默认 256）/ `portscan.full_timeout`（默认 0.5），**只在 full 模式生效**。
  阶段日志的耗时预估（`端口数/并发 × 单端口超时`）实测准确（预测 17 分钟 / 实测 1037 秒）。
  **校准表**（远端不可达目标 `192.0.2.1`，2048 端口外推 65535）：64/1.0 → ≈17 分钟；
  256/0.5（现默认）→ ≈2.2 分钟；512/0.3 → ≈0.7 分钟。默认不取 512 是因为 512 并发对远端目标偏激进。
  **N 个主机串行，总耗时 ≈ N × 单主机耗时**（默认下 10 主机 ≈ 22 分钟）。
  **校准表**（远端不可达目标 `192.0.2.1`，2048 端口外推 65535）：64/1.0 → ≈17 分钟；
  256/0.5（现默认）→ ≈2.2 分钟；512/0.3 → ≈0.7 分钟。默认不取 512 是因为 512 并发对远端目标偏激进。
  **N 个主机串行，总耗时 ≈ N × 单主机耗时**（默认下 10 主机 ≈ 22 分钟）。
  `nmap_scan()` 的两个超时已封顶（host ≤1800s / 进程 ≤3600s），否则全端口会算出 4.5~36 小时。
  GUI「全端口扫描」页发起的是**单次任务**（任务选项 `portscan_full`），不改全局策略 ——
  全局 `portscan.mode=full` 会让每个任务都变慢，谨慎使用。`parse_ports()` 默认 `max_span=4096` 就是防手滑的。
- **F2 统一门控 v1 的覆盖缺口（如实登记，不装作全覆盖）**（2026-09-24）：
  - **不覆盖** `scanner/certs.py` 的 TLS 握手、`scanner/dnsq.py` / `utils.resolve_host` 的 DNS 查询
    （量级远小于 portscan，且已被 `cert.max_sites` / `subdomain.max_resolve` 低量约束）；
  - **不覆盖** GUI 里任务外的独立动作（如 `/api/domains/resolve` 用的是 `load_settings()` 原始
    settings、没有 `_throttle`）；
  - **拦不住外部工具内部的连接**：我们只做"边界闸（同时起几个子进程）+ 把算好的线程数传进去"，
    `budget_total` **不约束外部工具内部发多少连接** —— 设了预算 ≠ 外部工具也被限住了；
  - **不同 `max_inflight_global` 的并发任务不共享闸**：`_GlobalState.gate_for` 在容量变化时重建闸
    （"配置改了即生效"），旧任务仍握旧闸 —— 若旧闸此刻仍有在飞请求，进程级**有效上限暂时是两者之和**
    （如 256 + 64）。重建时**会打一条 warning 明示**（不静默，回归 `[6i]`）；要真正的"全局硬上限"
    需让所有并发任务用同一个 `max_inflight_global`（**不改成"闸只建一次"、不合并两个闸**）；
  - 预算耗尽是**按停止处理**（任务标 `stopped` + `[throttle]` 错误行），但被拒的那一次调用仍可能
    让调用点报出"网络不可达"这类文案，**任务级错误行与状态才是权威**；
  - 默认值取"恰好等于现有单任务最大并发"（`max_inflight_*`=256 = `portscan.full_workers`），
    故**默认不改变既有行为**（0 = 不限也是同一目的）；要收紧再往下调。
- **拓展域名降噪（续22，`09044ee`）的能力边界（如实登记，不装作全能）**（2026-09-24）：
  - **PSL 是快照、不是实时**：`config/dicts/tlds.txt`（6423 条）由 `tools/import_tlds.py`
    **离线**从 **tldextract 5.1.3 打包的 PSL 快照**生成（包约 2024-11 安装；快照的确切日期未标注）。
    快照之后新委派的 gTLD **不在其中**，且未收录的后缀按 **fail-closed 处理（会被丢弃）**。
    清单缺失/为空时 **fail-open**（回退宽松判断 + 告警一次）—— **宁可留噪音，也不静默丢资产**。
  - **IDN / 中文域名整体不被识别**（**既有**能力缺失，非续22 引入）：`utils.is_domain()` 的
    `_DOMAIN_RE` 要求末位 label 是**纯 ASCII 字母** `^[a-z]{2,24}$`，所以 `例子.中国`、
    `foo.xn--fiqs8s` 全部被挡。**要支持 IDN 需另开一轮。**
  - **`.zip` 域名不被识别**（**既有**）：`jsmine._valid_host()` 的 `_FILE_EXT` 把 `zip`
    当文件后缀挡掉（`foo.zip` → False）。要支持需调整 `_FILE_EXT`。
  - **FOFA 标题归属过滤（`fofa.title_match`）的边界**：默认 `label` 档要求"标题某个 token
    与域名某个 label **完全相等**"，因此**连字符域名永不命中** —— `pengo-wallet.com` 的 label
    是整段 `pengo-wallet`，标题 token 被切成 `pengo`/`wallet`，永不相等 → **会被丢弃**。
    需要时用 `substring` 档放宽（能救回，但 `silvia-pengo.com` 那类也会跟着回来）。
- **fscan 适配的输出形态已用 fscan 2.2.1 实机校准**（2026-09-23 续12，Linux 实机抓取）：
  开放端口**不是**早年以为的 `[+] ip:port open`，而是这四种行形态之一 ——
  `[*] ip:port <service>` / `[*] http://ip:port` / `[+] http://ip:port code:NNN` / 老版本 `[+] ip:port open`；
  收尾固定打一行 `[*] 扫描完成，发现 N 个开放端口`（**0 个时也打**）。因此 `portscan._parse_fscan()`
  用三条**行首锚定**的正则取端口，再拿统计行的 N 做**交叉校验**：
  - 返回 `None` = 没装 / 起不来 / `rc≠0` / **解析数与统计行不符**（少了=换了格式，多了=认进了非 open 行）
    → 交回调用方回退 nmap / 内置扫描；
  - 返回 `[]` = 统计行明确写"发现 0 个" → 确实没有开放端口，**不必回退**。
  **必须行首锚定**：`[+]` 行的 title 段里会出现 `title:Redirecting to http://127.0.0.1:8081/system`，
  行中间乱搜 URL 会把**跳转目标**误记成端口。回归见 `tests/smoke.py [5e-0]`（7 组断言，内嵌真实样本）。
  *（此前的单条 `[+] ip:port open` 正则一条都匹配不上，且解析为空返回 `[]` 而不是 `None`，
  于是阶段只在 `found is None` 时才回退 → 静默漏报且不兜底；这就是本轮修掉的真缺陷。）*
- **`-nopoc` 只管 POC 模块，管不到 fscan 内置的"服务插件"**：实测它仍会输出
  `[!] Redis未授权访问: ip:port` 这类**只读**探测结论。本模块**只解析"端口开放"的事实行，
  不采信它的漏洞结论**（漏洞初筛归 vulnscan 阶段）。
- **漏洞复核（P1-1）与 POC 置信度（P1-2）是两套独立机制**（2026-09-23 续12）：
  - `vulns.review ∈ "" | confirmed | false_positive`（`db.REVIEW_STATES`，非法值经 `norm_review()`
    归一为 `""`）。**判误报的行不参与"潜在漏洞"计数与报告主表**，但会在报告文末
    「已判误报（人工复核排除）」附录里列出（保留可回溯）。批量打标走 `db.bulk_set_vuln_review` ——
    它**自带连接用 `cur.rowcount`**，**不要**改成 `_exec()`（后者返回 `lastrowid`，UPDATE 上恒为 0，
    会让 `/api/vulns/review` 一直回 `affected: 0`，前端以为一条都没改；这个坑已踩过一次）。
  - `pocs.confidence ∈ low | medium | high`，由 `db.poc_confidence(path, meta)` 算：
    来源分（`builtin`=high / `user`·`nuclei`=medium / `imported`·`other`=low）× **内容型匹配器**
    （`word`/`words`/`regex`/`size`/`length`）是否存在 → 存在则**降一级**，且**只降级不升级**。
    与 `enabled` 不同（那是用户意图，`upsert_poc` **不覆盖**），`confidence` 每次同步都重算。
    `vulnscan` 只把它当**同批候选内的排序键**（指纹命中仍绝对优先），不做过滤。
- **`dirscan` 的默认值于第十八轮（续9）反转为「开 + 只浅扫」**（第十五轮曾按用户要求默认关，
  现在用户要求"先用偏敏感信息的通用路径浅浅过一遍，看清结果再手动决定深度扫"）：
  `dirscan.enabled=true` + `dirscan.mode=quick`，只吃 `config/dicts/dirs_shallow.txt`
  （206 条，人工筛选、按价值排序，截断额度 `dirscan.quick_max_paths` 默认 150）→ **不发外部工具调用**。
  **深扫档**（`mode=deep` / 任务选项 `dirscan_full` / 「补扫」）才启用全量分层字典（12 框架桶 →
  语言栈 → 暴露面 → `dirs_big` 11882）+ dirmap 优先 + 后缀派生（`suffix_aware`），单站点上限 `max_paths`（默认 400）。
  两档都有的节流：只扫**不重复站点**（同任务内标题+长度相同的别名站跳过）。
  **补扫任务**（`POST /api/rescan`，名字 `补扫全目录-<月日>-<时分秒>`）只跑一个阶段，
  没有 probe 产物 → 用 `dirscan._sites_from_targets(ctx)` 从 `ctx.targets` 兜底，否则会"无存活站点"空跑。
  **本轮明确不做**：递归目录爬取 / 重写 dirmap 等价多语言字典引擎 / 运行时自动下载字典（见 `TODO.md`）。
- **FOFA 三种反查已于 2026-09-22 真实跑过**（key 已配）：
  `title="维保中心"` → 15 条（正常拓展）；`cert="example.com"` → **2 164 696 条** →
  被 `is_common_cert` 判为通用证书而放弃拓展（**这条真实数据就是阈值存在的意义**：
  没有它就会往资产库灌两百万条）。`title_threshold` / `cert_threshold` 默认 200 由此得到首个校准样本，
  仍建议按自己的目标继续观察。
- **FOFA 结果里大量行 `domain` 为空、只有 `host`（且可能是裸 IP）** —— 一律经
  `stages/osint.py::_domain_of()` 收口：空值 / 裸 IP / 含空格斜杠都返回空串，
  **裸 IP 绝不写进 `subdomains`**（IP 类资产归 portscan / probe）。新增 FOFA 类能力时请复用它。
- 目录结果的「重复长度」折叠**只作用于当前页**（分页条的「共 N 条」是未折叠总数）；
  任务详情页签则是一次性折叠（无分页）。
- **删除不是不可逆的了**：`db.delete_task()` 默认先调用 `backup_task()`，把该任务行与全部资产
  （sites/vulns/subdomains/dirs/csegs/ports）导出到 `data/trash/task_<id>_<时间>.json`；
  备份失败只告警、不阻断删除（GUI 的单个删除与批量删除都走 `db.delete_task`，无需额外操作）。
  即：**删除前请照常检查 `data/trash/`**，那里是"误删后唯一的救命稻草"。
- **dirmap 是 GPL-3.0，刻意不内联**（把源码拷进仓库会让整个仓库受 GPL 约束）：
  只保留 `tools/dirmap/` 目录联接 + 外部适配器；对它的 5 处源码修复记录在
  `tools/dirmap_fixes/README.md`（**该目录不含 dirmap 源码**）。
- **软 404 基线的并发重复计算已修**（2026-09-23 续11）：
  原先 `DirscanStage._builtin_scan._baseline()` 是"惰性填字典"且**没有同步**，`pool_run` 的
  20 个线程同时 miss 就各算一遍 —— 单站点 3 个基线探针实测膨胀成 **27~36 个**
  （占 dirscan 请求量约 18%）。现用 `threading.Lock` 把「查缓存 + 计算 + 回填」整体串起来：
  首个线程真算、其余阻塞在锁上，取得锁后命缓存，请求数**恒定 = 3 × 站点数**。
  （**不要**把它拆成"锁内查、锁外算"，那样等于没锁。）
  回归门禁：`tests/smoke.py [5p] 3c` 的断言由**上界** `≤ 3×workers`（60）收紧为**精确等号**
  —— 那个上界正是这个 bug 能长期藏住的原因。端到端浅扫实测：请求 **186 → 153**
  （字典 150 + 基线 3），命中 `.env` + `.git/config` 不变。
  *（AGENTS 早前记录的整轮 11 阶段数字 256/262、dirscan 177/183 是**修复前**的值，本轮未重跑；
  按新规则 dirscan 段应为 `150 + 3 × 站点数`。）*

## 8. 不要做的事

- 不要重写已可工作的模块换取"看起来更好"。
- 不要在未评估依赖成熟度时照搬 docs/roadmap.md 的功能（那是候选，不是承诺）。
- 不要改变 POC YAML 的既有语义与既有 POC 的 `id`（id 用于去重与溯源）。

## 9. 协作约定（用户明确要求）

- `todo.txt` 是用户的原始待办：**完成一项就在该条后追加 `[完成]`**，部分完成写
  `[部分完成：说明]`，未开始写 `[待办]`。首行已写明该约定。
- `TODO.md` 是本项目**待用户确认**的排期清单（P0 = 子域名扫描）。用户确认后再实施，
  不要自行把 P1/P3 拉上来做；P3 项依赖外部 API 或检测层成熟度，现阶段做只会产生噪声。
  文件末尾另有 **「参考项目借鉴清单」**（对标 `C:\Users\材料\Desktop\tools\scan\myscan_20250825`），
  含 A 采纳 / B 批判不采纳（8 条带理由）/ C 保留与间接处理标注——动手前先读，**避免重复调研或照搬有害设计**。
- 跨平台（Linux + Windows）是硬要求：路径用 `pathlib`、命令用列表 argv + `shell=False`、
  解释器用 `utils.pick_python`、文件读写显式 `encoding="utf-8"`、工具探测用 `shutil.which`。
- **换行符：仓库内文本文件以 CRLF 存储**（仓库级 `core.autocrlf=false`），**禁止提交 LF-only 的文件**。
  代价是实测过的：有一次用工具批量改写后文件变成 LF-only，提交时 `tests/smoke.py` 出现
  **2811 行纯 EOL"假变更"**（`git show --stat` 里 1490+/1321-），真正的内容改动被淹没、
  review 完全失效。**改完文件先自查再 `git add`**：

  ```powershell
  git diff --stat                      # 行数远超实际改动 → 大概率 EOL 被改写
  $b=[IO.File]::ReadAllBytes('<文件>') # 按字节数：LF 总数
  ($b | Where-Object { $_ -eq 10 }).Count
  ```

  归位办法（纯 EOL、不动内容，跨平台可靠）：
  `$t=[IO.File]::ReadAllText($p) -replace "\r\n","\n" -replace "\n","\r\n"; [IO.File]::WriteAllText($p,$t,(New-Object Text.UTF8Encoding $false))`
  *（**刻意不用** `.gitattributes text=auto eol=crlf`：它会把索引侧 EOL 全量改写，需要一次覆盖
  全仓库的迁移提交，`git blame` 的归因随之失效 —— 与 §0.1「事后分辨谁改了什么」冲突。
  宁可保留"提交前自查"这道人工闸门。）*
- **改动必须标注实施者**（用户 2026-09-22 明确要求）：提交信息末行写 `WorkBuddy · <模型名>`，
  并在 `CHANGELOG_AI.md` 的轮次标题下写明实施者。**背景**：本项目出现过两个 AI 会话同时改同一批文件
  （文档被反复覆盖），标注实施者是事后分辨「谁改了什么」的唯一可靠线索。
  例：`WorkBuddy · DeepSeek-V4.1-Flash`。
- 每次改完代码的标准动作：跑 `tests/smoke.py` → 更新 `CHANGELOG_AI.md`（最新在最上面）
  → 必要时同步本文件与 `docs/` → **git 提交**
  （`C:\Users\材料\MinGit\cmd\git.exe add -A && ... commit -m "<轮次>: <一句话>"`）。
  敏感文件靠 `.gitignore` 排除（keys.yaml / data / logs / pocs-user / nuclei-templates），
  提交前瞄一眼 `status --short` 确认无混入。