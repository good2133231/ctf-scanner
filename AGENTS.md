# AGENTS.md —— 给下一个接手 AI 的项目速览

> 本文件描述**实际代码状态**，不描述愿望。若与 docs/ 下其它文档冲突，以代码为准，并把冲突修掉。

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
- 外部工具（subfinder / puredns / httpx / dirmap）**均未安装** → 全部走内置兜底，这是当前默认运行状态。
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
│   │                      #   外壳＝左侧固定侧边栏 + 顶栏 + 内容区（8 栏：仪表盘/任务管理/子域名资产/拓展域名/站点资产/漏洞风险/POC 管理/策略配置）
│   │                      #   （原「端口服务/C 段视野/目录发现」三栏已移除，路由 /ports /csegs /dirs 仍在，只是不进侧栏）
│   │                      #   任务详情＝横向 8 个页签（潜在漏洞(默认)/站点/子域名/端口服务/C 段/目录/目标与配置/运行日志）+ 页签内筛选框
├── scanner/
│   ├── runner.py          # StageContext / PipelineRunner / run_task / sync_pocs（协作式取消：request_stop/is_stopped）
│   ├── stages/            # base + subdomain/takeover/portscan/probe/osint/jsmine/dirscan/vulnscan
│   ├── pocs/engine.py     # YAML POC 引擎（nuclei 兼容子集）
│   ├── pocs/pocs/*.yaml   # 内置 7 个示例 POC
│   ├── owasp/checks.py    # 12 项启发式检查（装饰器 @check 注册进 CHECKS）+ 分级/分类门控
│   ├── evasion.py         # 动态免杀：UA 池/浏览器化头/WAF 指纹/payload 变形
│   ├── wildcard.py        # 泛解析识别与过滤（纯 DNS 查询）
│   ├── passive.py         # 免 key 多来源被动子域名收集
│   ├── dnsq.py            # 纯标准库 DNS 客户端（A/CNAME/TXT/MX/NS…，UDP+TCP 回退，异常不外抛）
│   ├── cdn.py             # CDN 判定：读 config/dicts/cdn_cname.txt 按 CNAME 后缀匹配厂商（只读、无请求）
│   ├── takeover.py        # 子域接管指纹库（41 条第三方服务 suffix）+ detect()
│   ├── portscan.py        # 端口/服务扫描（TOP 表 + nmap 适配 + 内置 TCP connect 兜底 + 被动 banner）
│   ├── jsmine.py          # JS 资产挖掘（域名/接口 URL/疑似凭据，含第三方域黑名单与降噪）
│   ├── blacklist.py       # 用户黑名单（config/blacklist.txt；load/matches/filter_pairs/filter_domains，每次重读不缓存）
│   ├── iprecon.py         # IP 反查域名 + /24 C 段归纳（is_public_ip/segment_of/parse_domains，不 eval）
│   ├── fofa.py            # FOFA 反查（qbase64）：icon_hash 的 favicon 反查 + cert="domain" 证书反查；黑 ico / 通用证书阈值判定
│   ├── mmh3.py            # 纯标准库 MurmurHash3 x86_32（平台 favicon 指纹用；含 SELF_TEST 向量）
│   ├── fingerprint.py     # 内置指纹规则表 → identify(resp) -> [tag] + fetch_favicon/favicon_md5/favicon_hash
│   ├── db.py              # SQLite 层（tasks/subdomains/sites/ports/csegs/dirs/vulns/pocs + page_assets/delete_task/task_counts
│   │                      #   + OWN_SUBDOMAIN_WHERE/EXT_SUBDOMAIN_WHERE/OVERLAP_EXT_WHERE/OVERLAP_SITE_WHERE；DB_PATH 受 CTFSCANNER_DB 覆盖）
│   ├── config.py          # DEFAULTS + load/save_settings + load_keys()（config/keys.yaml）+ resolve()；LOGS_DIR 受 CTFSCANNER_LOGS 覆盖
│   ├── utils.py           # run_cmd / http_request / pool_run / resolve_host / IO / base_domain() / rel_display()
│   ├── targets.py         # parse_lines → [(kind, raw)]，kind ∈ domain|url|ip|cidr|unknown（cidr 展开为多条 ip）
│   └── report.py          # Markdown 报告
├── tools/import_ref_pocs.py # ast 静态解析参考项目 Python POC → config/pocs-imported/（导入项默认关闭）
├── config/settings.yaml   # 全局配置（GUI「策略配置」页覆盖 gui/limits/checks/subdomain/passive/evasion/takeover/portscan/jsmine/dirscan/vulnscan/iprecon/fofa/blacklist 十四段）
├── config/keys.yaml       # 第三方 API key 专用文件（gitignore；load_keys() 只读，save_settings 不写回）
├── config/blacklist.txt   # 用户黑名单（纯文本，一行一个域名、# 注释；* 前缀与裸域等价；命中即不入资产库）
├── config/dicts/          # subdomains(85) / resolvers(13) / dirs_small(55) / sensitive(11，暂未使用) / cdn_cname(292，CDN 厂商后缀)
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

- 阶段顺序与注册：`runner.STAGE_ORDER` / `STAGE_REGISTRY`（当前 **8 个**：
  `subdomain → takeover → portscan → probe → osint → jsmine → dirscan → vulnscan`；
  新增阶段在此登记即可被 CLI `-p` 与 GUI 识别）。
- 阶段开关有两层：**任务级**（建任务时勾选 stages / CLI `-p`）与**策略级**
  （`settings.takeover.enabled` / `portscan.enabled` / `jsmine.enabled`，阶段内部自查后跳过）。
  `takeover` / `jsmine` 默认开，`portscan` 默认关。
  **例外是 `osint`**：它自身没有 `enabled`，而是由 `iprecon.enabled` / `fofa.enabled` 两个
  子开关控制，**两者都关时整阶段直接跳过（一次请求都不发）**；`fofa` 下另有两个**子能力**：
  favicon（`icon_hash`，默认随 `fofa.enabled`）与**证书反查**（`cert_enabled`，默认跟随），
  各自有阈值排除（黑 ico / 通用证书）。
- **黑名单在三处入库前过滤**（`subdomain` / `jsmine` / `osint`，统一走 `scanner/blacklist.py`）：
  命中即不写资产库，因此后续阶段自然不扫 —— 新增"产出域名"的阶段必须记得在入库前过一遍。
- **测试隔离靠两个环境变量**：`CTFSCANNER_DB`（库路径）与 `CTFSCANNER_LOGS`（任务工作目录）。
  `tests/smoke.py` 顶部把两者指到 `logs/smoke-<随机>/` 并在退出时删除 —— 跑测试**不会**污染
  真实 `data/scanner.db` 与 `logs/`。跑任何"会写资产"的脚本时请沿用这一约定（见 `docs/usage.md` FAQ）。
- 每个阶段结果**三写**：任务目录文本产物（如 sites.txt）、SQLite、`ctx.results`（供下一阶段直接用）。
- 阶段级容错：单阶段异常不中断流水线，错误写入 `tasks.error`，任务最终仍置 `done`（docs 已声明此语义）。
- GUI：Flask 请求线程 + 每任务一个 daemon 线程；无任务队列，进程重启则运行中任务中断。

## 5. 关键不变量（改代码时务必保持）

1. **所有 HTTP 必须走 `utils.http_request`** —— 统一 UA、超时、`limits.verify_tls`（verify=None 时读配置）。
   不要直接 import requests/urllib。这也是**唯一伪装出口**：`utils._headers` → `evasion.browser_headers`
   （UA 随机化、浏览器化请求头、可选 XFF 伪装），改 HTTP 行为只在这一处生效。
2. **外部工具优先 + 内置兜底**：调用前用 `which()`，Good 工具再用 `verify_tool()` 做版本握手
   （防止 pip 的 Python `httpx` 同名命令被误用）。
3. **非破坏性**：新增检查/POC 只允许探测类请求；POC 规范见 docs/poc-guide.md。免杀（evasion）只改变
   payload 的**编码形态**与请求伪装，不改变语义，不越过"无爆破/无 DoS/无写操作"红线。
4. **SQLite 线程安全靠"每次调用独立连接"**（db.get_conn 用完即关）——不要改成共享长连接。
5. **POC 注册表与扫描联动**：`engine.load_enabled_pocs` 只返回注册表里 `enabled=1 AND status='ok'`
   且级别未被 `skip_severities` 排除的记录，因此新增 POC 后需 `runner.sync_pocs()`
   （GUI 启动/刷新时会调用）。
6. 单条漏洞去重键 = `(target, poc_id)`，即**每 POC 每目标最多一条**。
7. **分级门控（三层，`checks` 段）**：
   1. `skip_severities` 默认 `["info","low"]` —— **执行级**：这些级别连请求都不发
      （`owasp.checks.enabled_checks` + `pocs.engine.load_enabled_pocs` 同规则，helper 是
      `config.skip_severities()`）；
   2. `disabled_categories` / `disabled_checks` 命中的检查根本不执行（省请求）；
   3. `min_severity` 默认 `medium` —— **结果级**，过滤残余的低危/info 结果。
   即 `a02-no-https`、`a05-security-headers`、`a05-banner-disclosure` 这类项默认既不执行也不产出。

## 6. 如何验证改动

```powershell
py -3 tests/smoke.py        # 唯一回归门禁：自包含起靶场，断言覆盖 目标解析+CIDR/阶段注册(8 个)/POC 级别执行门/
                            # 免杀变形/mmh3 公开向量+iprecon/fofa 纯函数/响应体解码/流水线+指纹/三层门控/阶段门控(含 osint)/
                            # 非标端口候选/报告(含 C 段 IP)/停止/导出/GUI 路由(8 栏 + /ports /csegs /dirs)与批量接口/
                            # 子域名分流+CDN 标记+站点折叠+POC 相对路径/
                            # 第十四轮新增 `[5d]`：注册域折算(base_domain) + 相对路径(rel_display) + 黑名单
                            # (含临时文件与开关失效) + 证书反查(build_cert_query/is_common_cert/search_cert 空域名) +
                            # source_label + 拓展域名重叠隐藏与 ?all=1 + 站点重叠 1↔2 条 + 黑名单/批量子域
                            # 两个 POST 接口(桩函数去重保序/阶段与 targets) + 策略页 cert/blacklist 字段与
                            # `panel collapsible`、无绝对路径、logs/smoke- 相对路径 + POST 映射
py -3 cli/client.py --check # 外部工具可用性
py -3 cli/client.py -t http://127.0.0.1:8765/ -p probe,vulnscan --offline
py -3 run_gui.py            # 控制台 http://127.0.0.1:5000，口令 ctfscanner
```

改动后**必须**跑 `tests/smoke.py`；GUI/模板改动还应 `run_gui.py` 亲眼确认页面。

## 7. 已知局限 / 坑（真实存在，不是 TODO 清单）

- POC 引擎是** nuclei 兼容子集**：支持 `http:`/`requests:`、`payloads`（list / dict + `attack`）、
  `variables` + 内置变量、`path` 列表、`redirects`、匹配器 `status/word/regex/size` + `condition`/`negative`/
  `case-insensitive` + `part: body|header|all`、`extractors`（regex/kval）。**不支持 `raw`/`dsl`/`flow`/
  `workflows`**，这类模板会被标 `_status=unsupported` 并在 POC 管理页显示原因（不静默失效）。
- `owasp` 字段**格式是统一的**（`A01` 大写）：POC 引擎在 `engine.py` 里把 tag 的 `owasp-a01`
  规整为 `A01` 再入库，内置检查本身写 `A01`。*（本文件此前写的"POC 命中写 `owasp-a01`"与代码不符，
  已按代码更正 —— 见 `TODO.md` P1-3。）*
- `dirscan` 的 dirmap 适配解析其 `output/` 目录**最新 5 个文件**，可能读到上一次运行的残留。
- `config/dicts/sensitive.txt` 已存在但**未被读取**：内置敏感文件检查用 checks.py 里的硬编码清单。
- `parse_line` 对裸域名会 `strip("/")` 并小写；CIDR 会展开为多条 `("ip", …)`
  （`MAX_CIDR_ADDRESSES=256`，超过则整体丢弃并在解析阶段记日志）。
- GUI 无 CSRF/HTTPS 加固，仅限本机；「策略配置」页覆盖 gui/limits/checks/subdomain/passive/evasion/
  takeover/portscan/jsmine/dirscan/vulnscan/iprecon/fofa/blacklist 十四段（含按级别 / 按 OWASP 分类 /
  按检查项三级开关），并且**每个"大功能"都有阶段级 enabled 总开关**（`dirscan` / `vulnscan`
  于第十轮补齐：此前这两段在 DEFAULTS 里根本不存在，无法从 GUI 关闭）；
  外部工具路径、字典路径与 `passive.sources` 清单要手改 settings.yaml；
  fofa 的 email/key 要手改 `config/keys.yaml`（控制台只读、不写回凭据）。
- `wildcard.py` 只用系统解析器（`socket.getaddrinfo`），**取不到 CNAME**，故无法用"通配 CNAME 黑名单"维度。
- **任务详情为 8 个页签**（潜在漏洞(默认)/站点/子域名/端口服务/C 段/目录/目标与配置/运行日志）：参考 ARL 界面的
  IP/SSL证书/文件泄露/URL信息/nuclei/指纹统计/WIH 这些页签**故意不做空占位**，因为对应的数据源
  还不存在（分别依赖证书解析、爬虫数据模型等）。理由与依赖关系见 `TODO.md` B-7。
- **`osint` 的联网往返无法离线自测**：`tests/smoke.py` 只断言了 `iprecon`/`fofa`/`mmh3` 的纯函数、
  黑 ico 阈值边界与"两个子开关都关则无产出"的门控；`api.webscan.cc` 与 FOFA 的真实响应结构
  需要联网（FOFA 还需 key）才能验证 —— 首次实跑请打开开关并观察 `logs/task_*/task.log` 的 `[osint]` 行。
- `osint` 的阈值都是**保守估计值、未经真实数据校准**：黑 ico 阈值 200、通用证书阈值 200
  （`fofa.cert_threshold`）、单 IP 域名数 30（判共享主机）。都可在「策略配置 → 外部情报拓展」调整，
  不需要改代码。证书反查的"通用证书"判定尤其粗：**只按命中总数比阈值**，不做证书主体/颁发者分析。
- **黑名单的语义边界**：过滤发生在**入库前**，所以它**不影响已入库的历史资产**（老任务里的域名照旧可见），
  也不会因为后来把某域名加入黑名单就把既有行删掉。文件是纯文本、每次调用重读（改完立即生效，无需重启）。
- **重叠隐藏是"显示层"判据，不是删除**：`OVERLAP_EXT_WHERE`（拓展域名域名级全局）与
  `OVERLAP_SITE_WHERE`（站点 URL 级跨任务，保留 `MIN(id)` 最早一条）只作用于 `/extdomains`、`/sites`
  两个列表页，`?all=1` 可放开；任务详情页签与报告仍显示全量。因此"站点页条数比任务详情少"是预期行为。
- 任务已支持**停止（协作式取消）/删除/重启/导出 + 批量操作**；停止粒度是"当前批次跑完即停"，
  不会强杀正在飞行的 HTTP 请求，任务终态记为 `stopped`（区别于 `failed`）。
- **改完 GUI 必须重启服务**：若 5000 已被旧进程占用，新起的 `run_gui.py`（经 `gui/app.py serve()`）
  会打印端口占用提示并以退出码 1 结束——按提示结束占用进程或改 `gui.port` 再试；
  请求还是打到旧进程（新路由 404）——很容易误判成"代码没生效"，先确认端口占用再排查。
  **实测代价**：曾有一个旧 GUI 进程（PID 18360，2026-09-21 14:09 启动）被点名却一直没人杀，
  连续两天占着 5000；服务端 `debug=False` 既不重载代码也不重载 Jinja 模板，于是"代码明明改了、
  页面却是 5 栏旧导航 + 还写着'疑似问题'"。**排查任何"页面不对"之前，先看进程启动时间**：
  `Get-CimInstance Win32_Process -Filter "Name like '%python%'" | Select ProcessId,CreationDate`。
- **不要让子代理/自动化去点 GUI 的写操作按钮**：批量停止/重启/删除、新建任务都是真写库。
  本轮实测教训：一个被要求"只观察"的浏览器子代理点了「批量删除」并**把 `confirm()` 确认框也确认了**，
  硬删掉 63 条历史任务行；紧接着又提交了「新建扫描任务」表单，对一个**外部真实域名**跑了全 8 阶段扫描。
  派浏览器代理时必须在提示里明确写"只读浏览，禁止点击任何提交/删除类按钮"，并**限制其可操作页面**。
- **删除不是不可逆的了**：`db.delete_task()` 默认先调用 `backup_task()`，把该任务行与全部资产
  （sites/vulns/subdomains/dirs/csegs/ports）导出到 `data/trash/task_<id>_<时间>.json`；
  备份失败只告警、不阻断删除（GUI 的单个删除与批量删除都走 `db.delete_task`，无需额外操作）。
  即：**删除前请照常检查 `data/trash/`**，那里是"误删后唯一的救命稻草"。

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
- 每次改完代码的标准动作：跑 `tests/smoke.py` → 更新 `CHANGELOG_AI.md`（最新在最上面）
  → 必要时同步本文件与 `docs/` → **git 提交**
  （`C:\Users\材料\MinGit\cmd\git.exe add -A && ... commit -m "<轮次>: <一句话>"`）。
  敏感文件靠 `.gitignore` 排除（keys.yaml / data / logs / pocs-user / nuclei-templates），
  提交前瞄一眼 `status --short` 确认无混入。