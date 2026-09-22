# TODO.md —— 任务确认清单

用法：**本文件是待你确认的排期清单**，不是承诺。你确认哪几项，我就按顺序实施；
每完成一项，在 `todo.txt` 对应条目后追加 `[完成]`（约定见 todo.txt 首行）。

状态图例：`[ ]` 未开始 · `[~]` 进行中 · `[x]` 已完成

## P0 子域名扫描（最高优先级）

子域名是整条流水线的入口，入口窄了后面全是空转，所以排第一。

- [x] **P0-1 多来源被动收集**（本轮完成）：新增 `scanner/passive.py`（免 key 的公开源注册表 8 项，
      默认启用前 6 项：crt.sh / certspotter / alienvault / hackertarget / rapiddns / sublist3r，
      另备 sitedossier / bufferover），`collect()` 用 `utils.http_request` + `pool_run` 并发、
      正则通用提取（JSON/HTML/文本通吃），产出 `{子域名: "passive:<源名>"}` 写回 `subdomains` 表，
      与字典爆破结果按来源分别记账。`subfinder` 仍为外部工具优先项（未安装则自动跳过）。
      `passive.enabled` / `passive.timeout` 可在「策略配置」页开关。
- [x] **P0-2 子域接管检测**（本轮完成）：新增 `scanner/dnsq.py`（纯标准库 DNS 客户端 ——
      A/CNAME/AAAA/TXT/MX/NS/SOA/PTR，压缩指针解析、UDP/53 + `TC` 截断时回退 TCP/53、
      多解析器轮询、**任何异常都不外抛**）+ `scanner/takeover.py`（41 条第三方服务指纹：
      AWS S3 / GitHub Pages / Heroku / Azure / Shopify / Fastly / Netlify / Statuspage …）+
      `scanner/stages/takeover.py`（阶段名 `takeover`，接在 `subdomain` 之后）。
      CNAME 链回填 `subdomains.cname`（多跳用 `" -> "` 连接），疑似接管以 **high** 级入库；
      同类项按 `(target, poc_id)` 去重；产物 `logs/task_*/cnames.txt`。
      `takeover.{enabled,max_hosts,http_check}` 可在「策略配置 → 资产面拓展」开关。
      已知局限：指纹靠文案整理、第三方随时变更；`http_check=false` 时退化为纯 CNAME 判定，误报上升。
- [x] **P0-3 JS 资产挖掘拓展域名**（对应 todo #5，本轮完成）：新增 `scanner/jsmine.py` +
      `scanner/stages/jsmine.py`（阶段名 `jsmine`，接在 `probe` 之后，默认开启）。
      78 条第三方域黑名单 + 命名空间噪声表，**目标自身域（seed host + 注册域）永不误杀**；
      新域名只补当前任务没有的（`source="js:mine"`），接口 URL 落 `logs/.../js_urls.txt`，
      疑似 AK/SK 以 high 级入库（`poc_id=js-secret-*`，值掩码脱敏、附前后文 ≤160 字）。
      7 条凭据规则 + 两级降噪（厂商前缀/赋值语境 → 占位符/变量引用/成员访问过滤），跨文件按原值去重。
      已知局限：纯正则提取（无 sourcemap 还原）；短 token 与含 `test/demo` 字样的真实值偏保守丢弃。
- [x] **P0-4 CIDR 展开**（本轮完成）：`targets.expand_cidr()` —— 上限 `MAX_CIDR_ADDRESSES=256`
      （只接受 /24 及更小网段，超限返回空表并按不支持丢弃，避免变成主机扫描器）；
      地址数 > 2 时去掉网络地址与广播地址；`parse_lines()` 把 `("cidr", x)` 展开成多条 `("ip", x)`。
      **本轮同时修掉一个真实 Bug**：原第 59 行写成 `[(("ip", ip) for ip in ...)]`（生成器表达式外层
      套了列表），产出的是"装着生成器的单元素列表"，下游 `for kind, raw in ctx.targets` 抛 TypeError
      被阶段级 try/except 吞掉 → CIDR 目标静默丢失，即该功能**此前实际不可用**；已改为列表推导式。
- [x] **P0-5 第三方 API key 专用配置文件**（本轮完成）：新建 `config/keys.yaml`
      （fofa / shodan / quake / hunter / virustotal / securitytrails 占位 + 中文注释），
      已写入 `.gitignore`；`config.load_keys()` 读取并挂到 `settings["keys"]`，文件缺失/损坏返回 `{}`；
      `save_settings()` 落盘前 `settings.pop("keys", None)` —— 防止 GUI 存一次策略就把凭据
      复制进 `settings.yaml`。GUI 只读不改写，编辑请直接改文件。
- [x] **P0-6 泛解析（wildcard）过滤**（本轮完成）：新增 `scanner/wildcard.py` ——
      `random_label()` 生成随机标签、`detect(domain, samples=3)` 采样判定泛解析、
      `resolve_all()` 并发解析、`filter_hits()` 丢弃"命中通配 IP"的结果；
      `limits.wildcard_filter`（默认开）控制，在「策略配置」页可关。
      **无泛解析时零副作用**。已知局限：只用 `socket.getaddrinfo`，拿不到 CNAME，
      因此参考项目那套"CNAME 出现次数阈值 + CDN CNAME 黑名单"只借了思路未全量实现，
      留待 P0-2（子域接管）一并补 CNAME 维度。
      验收达成：对开泛解析的域名爆破后不再出现"全字典命中"。
- [x] **P0-7 检测分级门控：低危默认关闭 + 按分类开关面板**（来自 `todo.txt` 原话，**本轮完成**）：
      你的原话是"像这种太low的洞……暂时也不要开启了……我们只关注高位严重，才能拿到flag"，
      并要求"很大功能实现了 都要有一个菜单栏去有一个大体的开启或者关闭，根据分类来"。
      落地：①`config.DEFAULTS` 与 `config/settings.yaml` 增 `checks` 段
      `{min_severity: "medium", poc_engine: true, disabled_categories: [], disabled_checks: []}`；
      ②`owasp.checks.run_all()` 两级门控 —— **检查项级**（被关闭的分类/检查根本不执行，省请求）
      + **结果级**（低于 `min_severity` 直接丢弃），`vulnscan` 对 POC 结果复用同一 `severity_ok()`；
      ③GUI「策略配置」页新增 5 个面板：检测策略（级别阈值 + POC 引擎总开关）/ 按 OWASP 分类开关 /
      按检查项细粒度开关 / 动态免杀 / 信息收集，即你要的"按分类的大体开关"。
      默认门槛选 **medium** 而非 high：`a02-no-https(low)`、`a05-security-headers(info)`、
      `a05-banner-disclosure(info)` 这些默认不再产出，但保留了目录列表 / XSS 反射 / 开放重定向
      这类 medium 级有效信号。
      验收达成：`tests/smoke.py` 断言 `a02-no-https` 在默认门槛下**不出现**、门槛放到 `info` 后出现、
      关闭 A02 分类后 `a02-*` 全部消失，POC 引擎关闭后只剩内置 OWASP 检查。
      **第四轮加强（执行级硬门）**：本项当时只做到"结果级"过滤 —— 低危检查照样发请求、跑完再丢弃。
      用户第四轮明确"暂时也不要开启了"，故新增 `checks.skip_severities`（默认 `["info","low"]`）：
      这些级别**连请求都不发**，内置检查默认只执行 **5/12** 项，POC 引擎同一规则；
      GUI 增「按级别分类批量开关」面板。详见下方「第四轮」。
- [x] **P0-8 动态绕 WAF（UA 随机化 + 请求指纹变形）**（来自 `todo.txt` 原话，**本轮完成**）：
      要求注入探测具备动态绕 WAF 能力，且框架本身"相对动态"（`User-Agent` 头随机性等）。
      落地：新增 `scanner/evasion.py` ——①`UA_POOL` 10 个真实浏览器 UA，`pick_ua()` 每请求随机；
      ②`browser_headers()` 统一加 Accept / Accept-Language / Cache-Control 等浏览器化请求头
      （**刻意不设 Accept-Encoding**：urllib 兜底路径不解压，设了会把响应体变成乱码）；
      ③`WAF_SIGNATURES` 16 家厂商指纹（Cloudflare / 安全狗 / 云锁 / 阿里云盾 / 腾讯云 /
      长亭雷池 / 创宇盾 / 360 / ModSecurity / Naxsi / 宝塔 / Imperva / AWS / F5 / 华为云 / GCP），
      `detect()` 被动指纹优先、无果再补一次只读 GET 主动探测，vulnscan 每站点调用并在日志提示；
      ④`mutate_sqli/mutate_xss` 按 `bypass_level` 0~3 做注释替空格 / 大小写 / 换行与 URL 编码 /
      内联注释 / 关键字分片 / 双重编码；`a03-sqli-error` / `a03-xss-reflect` 改为"先打原始 payload，
      未命中才升级变形"，且请求数封顶（SQL 30 / XSS 20），**不引入爆破与延时**，守住非破坏性红线。
      ⑤`utils.http_request` 全部改走 `evasion` 的头构造，`spoof_xff` 可加 X-Forwarded-For 伪装。

## P1 检测能力

- [x] **P1-5 POC 供给链路：参考项目批量导入 + nuclei 模板兼容**（本轮完成，回答"我们的 POC 成熟吗"）：
      - **参考项目导入**：新增 `tools/import_ref_pocs.py`，用 `ast` **静态解析**（不执行、不 import）
        参考项目 `exploit/scripts/**/*.py` 共 341 个脚本，只从**判定语句**里取关键字
        （`'xxx' in text` 的 `Compare(In/NotIn)` 与 `.find()/.index()` 的参数），
        并过滤字典键噪声与低特异性词（长度 4~80、拒纯小写英文单词、拒含 `{}`/`\`/`%`）。
        **产出 305 个 YAML** 到 `config/pocs-imported/`（跳过非 Script 类 1、无路径 5、无可提取关键字 30），
        `words` 按长度降序取 8 个 + `matchers-condition: and`（status 200 + word or）。
        导入的 POC **默认关闭**（`db.default_poc_enabled()` 识别 `pocs-imported` 路径），
        避免 305 条低置信规则污染结果，可在「POC 管理」页逐个开启。
      - **nuclei 兼容**：`pocs/engine.py` 重写为 nuclei 语法子集 —— 兼容 `http:` 与 `requests:`
        两种顶层键；支持 `payloads`（list / dict + `attack: clusterbomb|pitchfork|batteringram`）、
        `variables` + `builtin_vars`（BaseURL/RootURL/Hostname/Host/Port/Scheme/Path）、
        `path` 为列表、`redirects`、匹配器 `status/word/regex/size` + `condition/negative/case-insensitive`
        + `part: body|header|all`、`extractors`（regex/kval，结果写入 evidence）。
        `config/nuclei-templates/` 已加入加载目录，**官方模板可直接投放使用，不依赖 nuclei 二进制**。
        `raw` / `dsl` / `flow` / `workflows` 明确**不支持**，但会标 `_status="unsupported"` 并给出 `_error`，
        **不静默失效**。
      - **结论**：自研引擎在"轻量 + 可控 + 免依赖"上优于引 nuclei（后者要装 Go 二进制、
        CTF 现场多了部署风险）；但语法向 nuclei 靠拢后两者**不冲突**：能用 nuclei 模板，
        也能继续用我们的 YAML。
      验收达成：`engine.load_all_meta()` → `total 312 ok 312 bad 0`（7 内置 + 305 导入）。
- [x] **P1-1 指纹 → POC 联动**（对应 todo #4 后半，**本轮完成**）：
      ①`checks.poc_link_tags`（默认开）—— `vulnscan._pocs_for(site)` 把"站点 tech 命中的 POC"
      排在前面**优先执行且不受 `poc_max_per_site` 上限约束**，其余 POC 补在后面受限执行；
      ②`limits.favicon_md5`（默认开）—— `probe` 阶段采集 favicon MD5 落 `sites.favicon`；
      ③POC 引擎支持 `favicon_md5_list`：命中清单不匹配时**零请求**直接返回（前置判定）。
      *（参考项目 `exploit/scripts/__template__.py` 的 `detect()`/`exec()` 两段式与
      `favicon_md5_list` 前置条件均已在我们的引擎侧具备等价能力；`priority` 加载顺序机制未采纳，见 B-5。）*
- [x] **P1-2 端口扫描阶段**（本轮完成）：新增 `scanner/portscan.py` + `scanner/stages/portscan.py`
      （阶段名 `portscan`，接在 `takeover` 之后、`probe` 之前）。`TOP_PORTS` 48 个高频端口表；
      `parse_ports()` 支持 `"80,443"` 与 `"1-1024"`（上限 4096）；nmap 优先
      （`-sT -Pn -n --open -p ... -oG -`，`-sT` 无需 root），未安装则内置 TCP connect 兜底 +
      被动 banner（仅 SSH/SMTP/MySQL/Redis 等会主动问候的端口）；结果去重后写 `ports` 表。
      **默认关闭**（`portscan.enabled=false`）—— 端口扫描耗时与噪声明显高于其他阶段；
      打开入口：「策略配置 → 资产面拓展」。**明确不调用 masscan**（需 root 且激进，违反非破坏性红线）。
- [x] **P1-3 统一 `owasp` 字段格式**（**本轮核实：无需改代码，已一致**）：
      内置检查写 `"A01"`（大写），POC 引擎从 tags 的 `"owasp-a01"` **还原为 `"A01"` 再入库**，
      两条链路产出的 `vulns.owasp` 格式本就统一。原 TODO 描述与实际代码不符，以代码为准。
- [x] **P1-4 存活 IP → 域名反查（C 段视野）**（第五轮完成，参考项目启发，免 key 可用）：
      新增 `scanner/iprecon.py` + `scanner/stages/osint.py` 的 `_c_segments()`。
      `is_public_ip()`（私有/环回/链路本地/组播/保留地址一律跳过，查了也是浪费配额）、
      `segment_of()` / `group_segments()`（IPv4 → `/24`，**IPv6 返回 ""** —— 段的概念不通用，不臆测）、
      `lookup_many()`（`pool_run` 并发 5、单 IP 只查一次、失败不重试、公共接口地址可配置替换）。
      结果：C 段落 `csegs` 表（GUI 第 10 栏「C 段视野」+ 任务详情第 8 页签「C 段」），
      单 IP 反查到的域名数超过 `iprecon.max_domains_per_ip`（默认 30）判为**共享主机/CDN**，
      C 段数据照常入库但**不纳入域名资产**（降噪）。
      **与 B-3 明确切割**：参考项目用 `eval(text)` 解析响应（响应可控即任意代码执行），
      我们 `json.loads` + 逐项结构校验，非 JSON / 结构不符一律返回空表。
      `iprecon.enabled` 默认关闭（第三方公共接口可用性不由我们掌控）。

## P2 GUI / 工程化

- [x] **P2-1 GUI 分栏扩展**（已完成，形态已收敛）：导航从 5 栏 → 8 栏
      （仪表盘 / 任务 / 子域名 / 站点 / 目录 / 漏洞 / POC / 设置）→ 9 栏（新增「**端口服务**」`/ports`）
      → 10 栏（第五轮新增「**C 段视野**」`/csegs`）→ **第十三轮按用户要求收敛到 8 栏**
      （删「目录发现 / 端口服务 / C 段视野」三栏 —— 它们是任务维度数据，详情页签本来就能看；
      同时新增「**拓展域名**」`/extdomains`；三条被删路由仍保留、可直达 URL）
      → **后续轮次又调整为现为 9 栏**（`/ips` IP 资产、`/fullports` 全端口扫描进栏；
      `/extdomains` 与 `/subdomains` 是同一张 `subdomains` 表的不同视图，单列一栏反而让人分不清
      资产归属，故退回侧栏外、仅保留路由）—— 现状以 `gui/templates/base.html` 的 `nav_items` 为准：
      仪表盘 / 任务管理 / 子域名资产 / 站点资产 / IP 资产 / 全端口扫描 / 漏洞风险 / POC 管理 / 策略配置。
      任务详情页签维持并扩到 **10 个**（潜在漏洞 / 站点 / 子域名 / 拓展域名 / **端口服务** / **C 段** /
      目录 / **线索** / 目标与配置 / 运行日志）。
      *（间接对应参考项目 GUI 的「资产分组」栏目——我们以"按资产类型分页"实现，
      没有做它的"自定义资产组"概念，理由见 B-6。）*
- [x] **P2-2 资产页筛选与分页**（**本轮完成**）：保留原有前端包含匹配 `initFilters()` 之外，
      新增**服务端**分页与关键词过滤 —— `db.page_assets(table, limit, offset, q)` 返回
      `(rows, total)`，对 `domain/source/cname、url/host/title/server/tech、host/ip/service/banner、
      site_url/path/note` 等文本列做 LIKE；`gui/templates/_pager.html` 通用分页条
      （首页/上一页/下一页/末页 + "共 N 条 · 每页 X · 第 Y/Z 页"，`PAGE_SIZES=(50,100,200,500)`）；
      `/subdomains`、`/sites`、`/dirs` 三页由客户端筛选改为「SQL 侧过滤 + 分页」，
      页码越界自动回落到最后一页重查。跨任务视图不再被 `LIMIT 500` 截断。
- [ ] **P2-3 跨平台（Linux + Windows）**：**已核查现有代码基本合规**，剩余是补验证与提示。
  - 已满足（实测 grep 过）：路径走 `pathlib`（`BASE_DIR / ...`，无硬编码分隔符）；
    `utils.run_cmd` 收列表 argv 且 `shell=False`（命令不存在返回 127、超时 124）；
    解释器选择用 `utils.pick_python`（Windows `python` / Linux `python3`，不可用则回退 `sys.executable`）；
    文件读写全部显式 `encoding="utf-8"`；外部工具探测统一 `shutil.which`。
  - 待补：在 Linux 实机跑一次 `python3 tests/smoke.py` 做验收（本机只有 Windows/Python 3.9）。
  - **已补（第十七轮续8，2026-09-23）：把"待补"里能自动化的部分全部变成了断言 + 实测。**
    新增 `tests/smoke.py [5o]`「跨平台静态审计」——它在**两种系统上都会跑**，在 Linux 上跑它就等于那次验收：
    ① 全部 49 个源文件 `compile()` 通过（排除 `tools/dirmap/`：那是第三方 Python2 项目，语法本就不兼容）；
    ② 39 个模块逐个 `import`（模块级 `winreg`/`msvcrt` 这类只会在这一步暴露）；
    ③ 源码红线：无 `shell` 直通、无 `os.system`/`os.popen`、**无写死的盘符路径**、文本读写必带 encoding；
    ④ `run_cmd(["不存在"])` 实测返回 **127**、超时实测返回 **124**（此前文档里只是"grep 过"，从未被验证）；
    ⑤ `pick_python("不存在")` 实测回退 `sys.executable`。
    实测同时修掉 1 处真实漂移：`tests/smoke.py` 里的假二进制路径原本写 `C:/fake/subfinder.exe`，
    已改为相对形式（该路径只被桩掉的 `run_cmd` 接收、从不执行，但留着会诱导后来者照抄）。
  - **仍未验证（如实标注，不假装完成）**：① Linux 实机跑 `python3 tests/smoke.py`（本机无 WSL/Docker）；
    ② 无头浏览器截图（`screenshot.browser` 在 Linux 上要探测 `chromium`/`google-chrome`）；
    ③ fscan / nmap / subfinder / dirmap 等**外部二进制**在 Linux 上的真实调用
    （代码全部走 `shutil.which` + 内置兜底，找不到只会降级、不会崩，但没有实机跑过）。
    搬运方式：整体拷贝/clone 进 Linux 即可（`config/keys.yaml` 被 gitignore、需手动带上）。
  - **已补（第八轮，2026-09-22）**：git 通道打通 —— MinGit 便携版就位，仓库已 `git init`
    并完成首次提交 `2267e51`（392 文件）。搬运障碍已消除：整体 clone/拷贝进 WSL2 或 VM 即可验收；
    `config/keys.yaml` 被 gitignore 排除、**不在仓库里**，拷贝时需手动带上（FOFA key 场景）。
  - **已补（本轮）**：GUI/CLI 端口占用的清晰报错 —— 实测发现 Windows 上 Werkzeug 因
    `SO_REUSEADDR` 会在端口被占用时**"绑定成功"**并打印 `Running on …`（页面打不开），
    现 `gui/app.py::serve()` 在 `app.run()` 前做一次真实 bind 预检，占用时打印可操作提示并 `exit 1`。
  - 验收：同一份代码在 Windows 与 Linux 各跑一次 `py -3 tests/smoke.py` / `python3 tests/smoke.py` 均 PASS。
- [x] **P2-4 任务生命周期操作（停止 / 删除 / 重启）**（本轮完成）：
      `runner` 增协作式取消（`_STOP_EVENTS` 事件表 + `request_stop/is_stopped/running_task_ids`，
      `StageContext.stopped()` 由各阶段在循环边界主动查询）；`db` 增 `delete_task` /
      `clear_task_assets` / `task_counts`；GUI 增 `/api/tasks/<id>/stop|delete|restart`、
      `/api/tasks/bulk`（stop|delete|restart，返回 `affected/skipped`）、`/tasks/<id>/export`
      （Markdown 下载）；`tasks.html` 增多条件筛选 + 全选 + 批量条 + 行内 5 个操作，
      `task_detail.html` 工具栏同款按钮。
      **语义说明**：停止是"当前批次跑完即停"（Python 线程无法安全强杀），状态写 `stopped`
      以区别于 `failed`；重启是清空该任务资产后按原参数原地重跑，避免产生重复任务行。

## 本轮新增配套（第三轮，随 P0-2/P0-3/P1-1/P1-2/P2-2 一起落地）

- [x] **POC 分类批量开关**：312 个 POC 逐个点显然不现实，`db.bulk_set_poc_enabled()`
      + `db.poc_source()`（按路径前缀归类 builtin / imported / nuclei / user / other）
      + `POST /api/pocs/bulk`；「POC 管理」页新增「按分类批量开关」面板
      （来源 × 级别 × "仅调整状态不一致的"）与「只看已启用」勾选、来源列。
      建议用法：先批量启用 `imported × critical/high`，跑通后再逐步放开。
- [x] **报告补端口维度**：`scanner/report.py` 概览表新增「开放端口」列，
      并新增「开放端口与服务（前 200）」小节（主机 / IP / 端口 / 服务 / banner）。
- [x] **数据库轻量迁移**：`db._ensure_columns()` 用 `PRAGMA table_info` 探测后
      `ALTER TABLE ADD COLUMN` —— 老库自动补 `subdomains.cname`、`sites.favicon`；
      新增 `ports` 表；`ASSET_TABLES` 与 `task_counts()` 纳入 ports。
- [x] **`tests/smoke.py` 扩充**（全部通过，SMOKE PASS）：新增断言覆盖
      CIDR 解析（含超限丢弃）、阶段注册表、`favicon` 字段、takeover/portscan/jsmine
      三阶段门控、报告「开放端口」列、`/ports` 路由、资产页分页条、POC 批量接口
      （启用→关闭还原原状）、任务详情「端口服务」页签。

## 第四轮（低价值项「执行级」硬门 + 请求形态动态化 + 文档全量对齐）

> 触发：你第四轮原话"像这种太 low 的洞我们暂时不要深入了，**暂时也不要开启了**……
> 我们只关注高位严重，才能拿到 flag"，并要求"很大功能实现了都要有一个菜单栏去有一个大体的开启
> 或者关闭，**根据分类来**"。**为什么第五轮的 `min_severity` 还不够**：它只做**结果级**过滤 ——
> 低危检查照样发请求、跑完再把结果丢掉，既浪费请求预算又让日志被噪声占满。

- [x] **`checks.skip_severities` 执行级门控**（默认 `["info","low"]`）：判定入口统一收敛到
      `config.skip_severities()`；`owasp.checks.enabled_checks()` 与 `pocs.engine.load_enabled_pocs()`
      同规则 —— 这两个级别**连请求都不发**。内置检查默认只执行 **5/12** 项，
      `a02-no-https` / `a05-security-headers` / `a05-banner-disclosure` 等 7 项不再跑。
      `config/settings.yaml` 同步并附中文注释（与 `min_severity` 的注释明确区分：一个管执行、一个管报告）。
- [x] **GUI「策略配置 → 按级别分类批量开关」**：info/low/medium/high/critical 五档复选框
      （`name="skip_severities"`，勾上即"不执行该级别"）；下方细粒度检查项列表对已被级别门
      跳过的项标注「·已按级别跳过」——避免出现"枚举了却看不到、误以为漏项"的困惑。
- [x] **注入请求形态动态化**：`evasion.mutate_sqli/mutate_xss` 抽出 `_dedup()` / `_shuffle_tail()`，
      返回前**打乱变体顺序**（首个原始 payload 仍排第一，最便宜、命中率最高）；
      `a03-sqli-error` / `a03-xss-reflect` 的**参数顺序每次随机**（`_ordered()`）。
      理由：固定尝试顺序本身会成为可被 WAF 规则固化的"请求序列特征"。
- [x] **`vulnscan` 日志明示预算去向**：输出 `内置检查 5/12 项` 与
      `info/low 级检测已跳过（连请求都不发）`。
- [x] **文档全量对齐**：`docs/usage.md`（9 栏 / 10 项页面 / 7 页签 / CIDR 与级别门两条 FAQ）、
      `docs/pipeline.md`（三层门控 + 动态性 + 配置速查增 `skip_severities`）、
      `docs/owasp-mapping.md`（三级门控 + 默认不执行的 7 项 id 清单）、
      `docs/poc-guide.md`（低级别 POC 不加载）、`docs/architecture.md`（阶段层/资产层/DB 表补齐
      ports、favicon、cname）、`docs/roadmap.md`（改为反映实际完成度，去掉"已做却标未做"）、
      `README.md`（架构图 7 阶段 + 能力边界）、`AGENTS.md`（不变量 5/7 重写 + 已知局限）。
- [x] **`tests/smoke.py` 再扩充**（SMOKE PASS）：`[2b]` POC 级别执行门（临时全开注册表后
      **级别门内 311 / 放开后 312**）+ 变形动态性（`level=0` 只回原始 payload）；
      `[3b]` 三层门控（**只抬 `min_severity` 低危项仍不出现** → 证明执行级门真实生效，
      放开 `skip_severities` 才出现，再按 A02 分类关闭又消失）。

## 第五轮（外部情报拓展：新增 osint 阶段 = P1-4 + P3-1 一并落地）

> 触发：用户授权"按你的建议自行决策、尽可能多完成"。这两项此前被排在 P3「基础未就绪」，
> 复核后判定**基础已就绪**：P0-5 已提供 `config/keys.yaml`（FOFA 只差填 key），
> P1-1 已提供 favicon 采集链路，`probe` 已产出 IP/站点。剩下的是"写代码"而非"等依赖"。

- [x] **新增阶段 `osint`**（`scanner/stages/osint.py`，阶段数 **7 → 8**）：
      `subdomain → takeover → portscan → probe → **osint** → jsmine → dirscan → vulnscan`，
      位置在 probe 之后 —— 输入是"存活站点 + 已解析 IP"，产出是**新域名**，越早入账，
      后面的 dirscan / vulnscan 覆盖越广。两个子能力独立开关
      （`iprecon.enabled` / `fofa.enabled`），**都关时整阶段一次请求都不发**（与低危检查同样的处理方式）。
- [x] **P1-4 C 段反查**（见上方 P1-4 条目）+ 新表 `csegs` + `db.insert_csegs/list_csegs/page_assets`
      接入 + 报告「C 段 IP」列与「C 段视野（前 200）」小节。
- [x] **P3-1 favicon 反查 / 黑 ico 判定**（见下方 P3-1 条目）+ `scanner/mmh3.py`（纯标准库自实现）。
- [x] **GUI**：导航 9 → **10 栏**（新增「C 段视野」`/csegs`，带关键字过滤 + 服务端分页），
      任务详情页签 7 → **8 个**（新增「C 段」），「策略配置」新增「外部情报拓展（OSINT）」面板
      （C 段反查开关/接口/上限/并发/超时 + FOFA 开关/上限/黑 ico 阈值）。
- [x] **`tests/smoke.py` 扩充**（SMOKE PASS）：`[2c]` mmh3 三个公开向量 +
      `iprecon` 纯函数（`segment_of` / `is_public_ip` / `parse_domains` 不用 eval / `group_segments`）+
      `fofa`（`build_query`、无 key 显式报错、黑 ico 阈值边界）；
      `[3d]` osint 四项开关全关 → 无 `csegs` / 无新域名产出；`[4]` 报告含「C 段 IP」；
      `[5]` `/csegs` 路由与详情页「C 段」页签。

## P3 依赖外部能力，基础未就绪（不建议现在做）

- [x] **P3-1 ico 索引 + fofa 检索**（todo #6，**第五轮完成**）：全链路已通 ——
      `fingerprint.fetch_favicon()` 采集（只读 GET、过滤不像图标的响应）+
      `scanner/mmh3.py`（FOFA `icon_hash` / Shodan `http.favicon.hash` 的社区统一键是 mmh3 而非 MD5；
      mmh3 是 C 扩展包，离线 CTF 环境装不上，故用标准库自实现并附公开向量自检）+
      `scanner/fofa.py`（`qbase64` 查询、`error:true` 时取 `errmsg`）+ 黑 ico 判定
      （命中数 > `fofa.black_ico_threshold`，默认 200 → 公共图标，放弃拓展）。
      **关于"要不要等真实数据校准阈值"**：当时这么写是因为没有实现；现在阈值做成配置项
      （GUI 可调），默认 200 是保守值，实测要校准只改配置、不动代码，因此不再阻塞排期。
      **未配置 key 时**显式返回「未配置 fofa.email / fofa.key（见 config/keys.yaml）」，不静默失败。
- [x] **P3-2 实时最新漏洞情报**（todo #3，第十七轮续8 完成）：
      **只做到「线索」这一层，不自动灌 POC** —— 原顾虑（"新增 POC 的价值取决于检测层判定质量，
      312 个里 305 个是低置信、先灌新 POC 只是放大噪声"）依然成立，所以落地方式是：
      `scanner/intel.py` 拉 **CISA KEV**（免 key 公开 JSON，只收录"已被在野利用"的 CVE）→
      与本地资产指纹做**白名单式匹配**（`MATCH_RULES` 显式写过的信号才参与，且要求
      "资产侧信号 + 情报侧产品关键词 + 厂商对得上"三条同时成立；信号词带词边界，
      防止 `iis` 被 `heliis` 吞掉）→ 结果**只写 `leads` 表**（kind=intel），
      **不写 `vulns`、不计入漏洞数、不自动导 POC**。`intel.enabled` 默认关。
      缓存落 `data/intel/<source>.json`（跟随库位置，测试自动隔离），
      拉取失败**退回过期缓存并告警**，不让外部源拖垮流水线。
- [x] **P3-3 启发式 0day 挖掘**（todo #1，第十七轮续8 完成）：
      同样只到「线索」层。`scanner/heuristics.py` **零请求**，只对已采回的数据做
      **差分 + 异常聚合** 5 条规则：软 404 模板差分（单站点主导 (状态码,大小) 占比 ≥70%）、
      高价值入口暴露（命中 `/.git`/`/actuator`/`swagger` 等但检测层没结论）、
      多主机同标题（疑似同一套系统多实例）、目录命中数离群（≥15 且 ≥3× 其它站点中位数）、
      同 C 段多 IP 有域名反查结果。产出写 `leads` 表（kind=heuristic，级别一律 info），
      `heuristic.enabled` 默认关。**主动 fuzz 仍然不做**：样本量不够时那是纯噪声。

## 第十三轮（用户当场提的 7 项，全部完成，2026-09-22）

> 本组是**用户直接点名**的需求，不属上方排期；逐条对应 `todo.txt` 第十三轮小节与 `CHANGELOG_AI.md` 第十三轮。

- [x] **乱码修复（标题中文变 `ç»´ä¿...`）**：根因 = 响应头 `Content-Type` 不带 charset 时 requests 回退
      ISO-8859-1。`scanner/utils.py` 新增 `_charset_of` / `_decode_body`（响应头 charset → UTF-8 →
      GB18030 → 带替换 UTF-8），requests 与 urllib 两路共用；存量核查 36 条标题 0 条乱码。
- [x] **拓展域名独立成页**：`db.OWN_SUBDOMAIN_WHERE` / `EXT_SUBDOMAIN_WHERE` 两判据 + `/extdomains`；
      子域名页与任务详情子域名 Tab 只列目标自身来源。
- [x] **子域名 IP / CDN 标记 + 标签过滤**：`scanner/cdn.py`（数据文件 `config/dicts/cdn_cname.txt`，292 条）+
      `subdomains.ip/cdn`（原地 ALTER TABLE 迁移）+ `subdomain._fill_net()` 回填 + 「全部/CDN/非 CDN」过滤。
- [x] **POC 页相对路径**：`gui/app.py::_rel_path()`，来源判定先于相对化执行。
- [x] **侧栏收敛 + 漏洞页加强**：删 3 栏、加「拓展域名」（见 P2-1）；漏洞页保留级别筛选并新增任务名列 +
      按任务筛选（`?task_id=`）。
- [x] **非标端口站点**：`probe` 消费 `portscan` 的 `ports`，对非 80/443 补 scheme 候选（需开 portscan 阶段）。
- [x] **重复站点默认隐藏**：`/sites` 按 `(task_id, 标题, 长度)` 折叠 + `?all=1` 开关；
      **过程中修掉一个真 Bug**（首版折叠键漏 `task_id`，跨任务视图下会把不同任务的资产折成一条）。

## 第十四轮（用户当场提的 6 项，全部完成，2026-09-22）

> 本组是**用户直接点名**的需求，不属上方排期；逐条对应 `todo.txt` 第十四轮小节与 `CHANGELOG_AI.md` 第十四轮。
> 三个设计决策由用户当场选定（批量跑子域名＝新建任务；重叠口径＝拓展域名域名级全局 / 站点 URL 级跨任务；
> 证书反查＝并入 osint 阶段并列独立子开关）。

- [x] **Q1 终端访问日志会不会崩（回答，未改代码）**：打印的是 Werkzeug 访问日志，`Debug mode: off`
      （无 reloader/调试器），与稳定性无关；真实风险只有三条 —— 无进程守护、SQLite 单写者可能
      `database is locked`、`app.run()` 是开发服务器（仅 127.0.0.1 可见）。可选换 `waitress`，非必需。
- [x] **Q2 策略配置面板可折叠**：8 个面板（`section.panel.collapsible`）**默认全折叠**，面板标题栏可点开/收起，
      页顶「全部展开 / 全部折叠」，展开状态存 `localStorage`（`ctfscanner.panels`）。
      实现：`gui/static/app.js::initCollapsiblePanels()`（注入 `.panel-head` 与 `.panel-toggle`）+
      `style.css` 的 `.panel.collapsible:not(.open) > *:not(.panel-head){display:none}`。
- [x] **Q3 改代码时并行运行/测试的隔离**：不做完整 dev/prod 双环境，只做"共用代码、数据分开" ——
      `DB_PATH` 支持 `CTFSCANNER_DB`、`LOGS_DIR` 支持 `CTFSCANNER_LOGS`（`scanner/db.py` / `scanner/config.py`）。
      `tests/smoke.py` 顶部把两者指到 `logs/smoke-<随机>/` 并 `atexit` 删除，
      跑测试**不再污染**真实 `data/scanner.db` 与 `logs/`。
- [x] **Q4 消除绝对路径显示**：新增 `utils.rel_display(path)`（项目内 → 相对项目根 POSIX；项目外/空值原样返回），
      CLI 四处输出、GUI 任务详情 `log_file`、POC 管理页、策略页黑名单路径统一改用它；
      `gui/app.py` 私有 `_rel_path()` 删除、改调 `rel_display`。
- [x] **Q5 FOFA 能力补齐**：
      - **来源可读标签**：`gui/app.py::SOURCE_LABELS` + `source_label()` 注册为 Jinja 全局
        （`被动(subfinder)` / `被动(crt.sh)` / `爆破(puredns)` / `爆破(内置)` / `JS 挖掘` /
        `C 段反查` / **`FOFA·ICO 反查`** / **`FOFA·证书反查`**），三处来源列统一调用；
      - **证书反查**：`fofa.build_cert_query(domain)` → `cert="domain"`（注册域先经 `utils.base_domain`
        折算，含 `com.cn`/`co.uk` 多段后缀；裸 IP 跳过）+ `search_cert()` + `is_common_cert()`
        （命中数 > `fofa.cert_threshold` 默认 200 判"通用证书"放弃拓展）+ `max_cert_queries` 上限（默认 10）；
        来源 `osint:fofa-cert`；子开关 `fofa.cert_enabled`（默认跟随 favicon 开关）；
      - **用户黑名单**：新 `scanner/blacklist.py` + `config/blacklist.txt`（纯文本，`#` 注释，
        `*.x` 与 `x` 等价），**入库前过滤**（subdomain / jsmine / osint 三处 `filter_pairs`/`filter_domains`）
        —— 命中域名连子域都不入资产库，后续阶段自然不扫；GUI 批量加入/移除（`/api/blacklist/add`、`/remove`）；
      - **批量跑子域名**：勾选行 → `POST /api/domains/run-subdomain` → **新建任务**（仅 `subdomain` 阶段，
        任务名 `批量子域-<月日>-<时分秒>`）；`_picked_domains()` 去重保序；
      - **拓展资产重叠默认隐藏**：`db.OVERLAP_EXT_WHERE`（域名级全局：该域名已作为任意任务的"目标自身子域名"）
        + `/extdomains` 默认叠加，`?all=1` 放开。
- [x] **Q6 站点重叠默认隐藏**：`db.OVERLAP_SITE_WHERE`（URL 级跨任务，`id IN (SELECT MIN(id) … GROUP BY url)`
      保留最早一条）+ `/sites` 默认叠加；与既有的"同任务内 标题+长度 折叠"共用一个开关（`?all=1`）。
- [x] **`tests/smoke.py` 新增 `[5d]`**（一次通过 SMOKE PASS）：11 组断言覆盖
      `base_domain` / `rel_display` / 黑名单（临时文件 + 开关失效）/ 证书反查（`build_cert_query`、
      `is_common_cert` 200↔201 边界、`search_cert` 空域名）/ `source_label` / 拓展域名重叠隐藏与 `?all=1` /
      站点重叠 1↔2 条 / 两个 POST 接口（桩函数去重保序、`stages=["subdomain"]` 与 targets）/
      策略页 cert+blacklist 字段与 `panel collapsible`、无绝对路径、`logs/smoke-` 相对路径 / settings POST 映射。
- [x] **文档同步**：`docs/usage.md`（勾选批量按钮、来源可读标签、拓展/站点两层重叠、8 面板折叠、
      证书字段、黑名单面板、新增「黑名单与批量操作」小节 + 3 条 FAQ）、`docs/pipeline.md`（osint 三个子能力、
      subdomain/jsmine 黑名单行、配置速查 2 行）、`docs/architecture.md`（blacklist.py / rel_display /
      LOGS_DIR 与 CTFSCANNER_DB / 4 条设计决策 / OVERLAP_* 判据 / source_label / 面板折叠）、
      `README.md`（能力清单 + blacklist.py/blacklist.txt + 配置段数）、`AGENTS.md`（文件树、§4 三处过滤与
      环境变量、§6 断言清单、§7 黑名单/重叠语义边界、十四段）。

## 第十五轮（用户当场提的 5 项，全部完成，2026-09-22）

> 触发：用户接手指令后直接点名 5 条需求（全端口扫描 / FOFA 标题反查 / 目录扫描重做 / JS 敏感字符 / dirmap 接入）。
> 逐条对应 `todo.txt` 第十五轮小节与 `CHANGELOG_AI.md` 第十五轮。

- [x] **R1 全端口扫描**：`parse_ports(max_span=4096)` 防手滑；`portscan.mode=full` + `full_ports`（1-65535）
      + `exclude_scanned`（跳过本任务已扫端口）+ **任务选项** `portscan_full`；GUI 新增侧栏「**全端口扫描**」
      `/fullports`（**按任务分布**：任务 × 主机 × 端口列表），勾选主机 → `POST /api/ports/full-scan`
      新建只跑 portscan 的任务（无视全局开关，但不动全局策略）。
- [x] **R2 FOFA 标题反查 + 两层黑名单**：`build_title_query/search_title/title_threshold/is_common_title`
      + `GENERIC_TITLES/is_generic_title`；来源 `osint:fofa-title`（「FOFA·标题反查」）进拓展域名页。
      黑名单两层：模板页标题（404 / Error / Welcome to nginx…）**连查询都不发**；命中数超
      `fofa.title_threshold`（默认 200）判为"公共标题"放弃拓展 —— 与黑 ico 同构。
- [x] **R3 目录扫描重做**：**默认关**；`tools/import_dir_dict.py` 生成 **15333 条大字典**
      `config/dicts/dirs_big.txt`（源自 dirmap 字典）+ `dirscan.big_dict` / `max_paths`（默认 400）节流；
      **只对不重复站点扫描**（同任务内标题+长度相同的别名站跳过）；结果**按响应大小折叠重复长度**
      （默认只显示首个，`?all=1` 放开）并展示**返回包大小**；软 404 基线升级为 3 个随机路径的 md5+长度集合。
- [x] **R4 JS 敏感字符**：凭据规则 7 → **17 条**（AKID/LTAI/AKIA、JWT、私钥 PEM、数据库 URI、
      Slack/Telegram/SendGrid/Stripe…）；PEM 头因含空格被降噪误杀的补丁；命中落 `js_secrets.txt`，
      入库 `target` 改为**主机名**；「拓展域名」页新增「**敏感**」列（按域名聚合 `js-secret-*` 条数）。
- [x] **R5 dirmap 接入（真 Bug）**：根因是 `tools.dirmap.script` 指向不存在的
      `tools/scanner/dirmap-master/dirmap.py`，导致永远打印"dirmap 不可用"；现建 `tools/dirmap/` **目录联接**
      指向机器上的 dirmap（**代码与配置里只有相对路径**），并修掉适配器的三个实测坑
      （产物在 `output/<域名>/` 子目录、`output/` 是持久目录需按启动时间过滤、
      行格式 `[状态码][content-type][大小] URL` 需专门解析）。**实测 15348 条字典 / 588 秒，产出解析正确**。
- [x] **测试**：`tests/smoke.py` 新增 `[5e]` 6 组断言（端口上限与全端口放开 / 标题反查 / 目录 dirmap 解析与折叠 /
      JS 敏感字符 / `/fullports` 页与发起接口）；`py -3 tests/smoke.py` = **SMOKE PASS**。
- [x] **文档**：`CHANGELOG_AI.md`（第十五轮）、`AGENTS.md`（目录地图/§2 外部工具结论/§6 验证/§7 局限）、
      `README.md`、`docs/usage.md`、`docs/pipeline.md`、`docs/architecture.md`、`docs/roadmap.md`、本文件、`todo.txt`。

## 第十五轮遗留待办（未做，需要时再排）

- [x] **FOFA 标题/证书反查的真实联网首跑**（2026-09-22 完成）：标题 `维保中心` → 15 条正常拓展；
      证书 `example.com` → 2 164 696 条被阈值拦下（阈值设计得到真实样本印证）。**顺带修掉一个真 Bug**：
      FOFA 大量行的 `domain` 为空、`host` 是裸 IP，原实现会把 IP 当域名写进 `subdomains`；
      现统一走 `_domain_of()` 收口（`tests/smoke.py` `[5e](4b)` 已钉住）。
- [x] **全端口扫描的真实耗时校准**（2026-09-22 完成）：本机回环 `workers=256`/`timeout=0.3` → **82 秒**；
      重跑（端口全部标记已扫）→ 2 秒、0 新增（`exclude_scanned` 生效）；全局策略未被改动。
      同时把 `nmap_scan()` 的两个超时封顶（host ≤1800s / 进程 ≤3600s）。
- [ ] **dirmap 内联（可选）**：若要把 dirmap 收进仓库，必须先修它自身的问题（`saveResults` 重复定义、
      全局量、O(n²) 追加写、`skip_size` 比较恒假、`ssl_context` 未挂载），否则并发下会丢结果；
- [x] **目录扫描的阶段级测试**（2026-09-22 完成）：`[5e](7)` 用记录型 logger 真跑一次 dirscan，
      断言"2 条别名站被去重、只扫 2 个站点"。

## 第十六轮（收尾：遗留项全清 + 两个决策落实，2026-09-22）

> 实施者：**WorkBuddy · DeepSeek-V4.1-Flash**。用户原话：把四条遗留全部解决，两个待决策项"按你推荐来"。

- [x] **FOFA 真实联网首跑 + 阈值校准**：`title="维保中心"` → 15 条并**真的入库 6 个域名**；
  `cert="example.com"` → 2 164 696 条被阈值拦下。校准样本：具体标题十位数、通用标题百万~千万级
  （`后台管理系统` 192 188 / `登录` 39 722 277 / `Index of /` 5 974 788 / `Welcome to nginx` 8 344 737）
  → **默认 200 维持不变**（偏保守、宁缺勿滥）。
  **顺带修掉一个"必然抛异常"的 Bug**：`_site_titles()` 对 `sqlite3.Row` 用了 `.get()`，
  osint 阶段每次都抛 AttributeError 被容错吞掉（标题反查永远 0 条）。
- [x] **全端口耗时校准**：本机回环 65535 端口，`workers=256/timeout=0.3` → **82 秒**；
  **默认参数**（64/1.0）→ **>17 分钟**。据此新增 `portscan.full_workers`（256）/
  `portscan.full_timeout`（0.5），**只在 full 模式生效**，GUI 策略页同步。
- [x] **目录扫描阶段级测试**：`[5e](7)` 记录型 logger 真跑 dirscan，断言"2 条别名站被去重"；
  另加 `[5e](9)` 断言 dirmap 产物按目标目录定位。
- [x] **dirmap 5 处源码修复**（改本机外部副本，已留 `.bak-workbuddy-20260922` 备份）：
  重复定义 / 死变量 / O(n²) 读回+并发丢写 / `skip_size` 比较恒假 / `ssl_context` 未挂载。
  **实测收益：15349 条字典 588 秒 → 43 秒（约 13×）**。
  **并明确"不内联"**：dirmap 是 **GPL-3.0**，拷进仓库会让整个仓库受 GPL 约束 →
  只保留外部适配器，修复记录放 `tools/dirmap_fixes/README.md`（不含源码）。
- [x] **适配器新坑修复**：dirmap 的 `saveResults()` 会与旧文件去重 → 重扫同目标不写新内容、
  mtime 不变 → 上一轮的"按 mtime 过滤"会漏结果（实测跑了 37 秒解析 0 条）。
  改为**按目标目录定位** `output/<netloc 把 : 换成 _>/`，复验 `dirmap 输出 4 条`。
- [x] **决策① 清理开发期数据**：43 条任务（全是 smoke/test/cli 产物）逐条走 `db.delete_task()`
  → **56 个 JSON 快照**在 `data/trash/`（可回溯）；僵尸 `running` 任务收尾为 `stopped`；
  `logs/` 清理 41 个孤儿任务目录 + 7 个 `smoke-*`，只留 `cli_smoke_report.md`。
- [x] **决策② 重启 GUI**：确认 5000 上跑的是旧代码（`/fullports` 404）→ 终止旧进程并用当前代码重启，
  登录后 6 个页面逐页复验通过（`/fullports` `/dirs` `/extdomains` `/settings` `/subdomains` `/tasks`）。
- [x] **新增约定（用户要求）**：改动一律标注实施者 —— `AGENTS.md` §9 写明"提交信息末行 `WorkBuddy · <模型名>`
  + CHANGELOG 轮次标题下写实施者"，用于多会话并行时事后分辨归属。

## 第十七轮（硬规矩 + 子域名并集，2026-09-22）

> 实施者：**WorkBuddy · DeepSeek-V4.1-Flash**。用户当场提的 4 件事。

- [x] **AGENTS.md 新增「§0 硬规矩」**：① 改动标注实施者（`WorkBuddy · <模型名>`）；
  ② **未经许可不得读取项目以外的代码/文件**（唯一例外＝用户主动指定）；
  ③ 代码/配置/模板/日志只允许相对路径。
- [x] **清掉代码里仅存的两处绝对路径**（`scanner/passive.py` docstring、
  `tools/import_ref_pocs.py::DEFAULT_SRC`）→ 复检 0 命中。
- [x] **子域名"主动且全"**：`subdomain.union_passive`（默认开）让 subfinder(-all) 与内置免 key
  被动源**取并集**（原实现是 `elif`，装了 subfinder 就不跑内置源）；GUI 开关 + 文档 + smoke `[5f]`。
- [ ] **dirmap 相关**（5 处源码修复的复核 / 是否内联）—— **用户已交由其他 AI 负责，本轮不动**。

### 用户问、本轮已答（结论记录）

- **端口扫描选型**：见本轮回复的对比分析（结论：CTF 场景下"够用就好"，
  fscan 若接入必须强制 `-np -nobr` 以守住非破坏性红线；nmap 慢是它的定位使然，
  我们已用 `-sT` + 内置 connect + 全端口专用并发/超时把耗时压到可接受）。
- **subfinder `-all`**：`-all` = 使用**全部数据源**（不加只用默认源集合）；我们恒带 `-all`。

### 第十七轮（续）字典按技术栈拆分（2026-09-22）

> 实施者：**WorkBuddy · DeepSeek-V4.1-Flash**

- [x] 用户给的外部字典 → `tools/import_dir_dict.py --src <文件>` 拆成
      `dirs_big(11882) / dirs_common(10671) / dirs_php(933) / dirs_asp(162) / dirs_jsp(116)` 部署进 `config/dicts/`；
- [x] **按技术栈选字典**（`dirscan.tech_aware`，默认开）：URL 后缀 + `sites.tech` 判定 →
      Java 站只吃 `dirs_jsp+dirs_common`，PHP 站只吃 `dirs_php+dirs_common`，判不出才用全量；
      语言字典排在前面，`max_paths` 截断时先保语言专属路径；dirmap 同样按栈分组用 `-e jsp|php|asp|all`；
- [x] 顺手修：`dirscan` / `vulnscan` 单独跑时**没有库回退**导致静默不干活 → 补 `db.list_sites()` 回退；
- [x] 双靶场实测：PHP 站 40 条请求 100% `.php`、Java 站 0 条 `.php/.aspx`；smoke 新增 `[5g]`。

## 第十七轮（续 2）GUI / 资产视图 8 项（2026-09-22）

> 实施者：**WorkBuddy · DeepSeek-V4.1-Flash**。用户当场提 8 项，**除截图外全部落地**。

- [x] 站点 URL 可点开（新窗口）+ **纯净模式**（`?plain=1` 只显示 URL）+ 站点行距加大；
- [x] 右上角**主题切换**（深色/浅色/深蓝/紫罗兰，CSS 变量 + localStorage）；
- [x] **指纹规则表 16 → 103 个标签**并新增 cookies 维度（CDN/WAF、国产 OA/ERP、Java 中间件、
  CMS、前端框架…）；GUI 技术栈列改为标签渲染。**结论：指纹早就落地，是规则太薄**；
- [x] **没有 IP 时标出具体原因**（`subdomains.ip_note` + `dnsq.resolve_detail()`；
  含 `over-limit` 这种"被上限挡掉"的情况）；
- [x] 新增「**IP 资产**」页（按 IP 聚合域名，**默认只显示非 CDN 解析**，可勾选批量全端口扫描）；
- [x] 端口服务改为对**真实 IP** 扫描（用库里已解析的非 CDN IP；CDN 主机跳过并记日志）；
- [x] 拓展域名**移出侧栏**、改到任务详情页签；新增 `utils.is_domain()` 统一域名形态判断
  （挡掉裸 IP / 端口 / 路径 / 通配符 / 文件名）；`jsmine._FILE_EXT` 补服务端脚本后缀；
- [x] JS 第三方黑名单改数据驱动：`config/dicts/js_thirdparty.txt`（**267 条** = 内置 + URLFinder `jsFiler` 212 条）；
- [x] **站点截图功能**（用户问"可以加吗"）：需要无头浏览器（Edge/Chrome headless）——
  已于「第十七轮（续 3）」实现（新增可选 `screenshot` 阶段 + `sites.shot` 列 + 站点页缩略图，smoke `[5j]`）。

## 第十七轮（续 3）站点截图（2026-09-22）

> 实施者：**WorkBuddy · DeepSeek-V4.1-Flash**

- [x] 新增 `screenshot` 阶段（默认关，阶段数 8 → 9）：调用本机 Edge/Chrome 无头模式截图，
      **零新依赖**；浏览器探测走「配置 → PATH → Windows 注册表 App Paths → 环境变量+相对子路径」，
      代码里不含绝对路径；临时 user-data-dir 隔离，不碰用户浏览器配置；
- [x] 产物 `logs/task_*/shots/<md5>.png` → `sites.shot`（相对任务工作目录）；
      GUI 新增 `/shots/<task_id>/<name>`（防目录穿越）+ 站点页/任务详情缩略图（点击看大图）；
      策略页新增开关与参数（max_sites / window / timeout / browser）；
- [x] 实测：单站点 3.1 秒出 11 KB 合法 PNG；端到端 `probe+screenshot` 跑通；
- [x] 顺带修 `/shots` 路由里对 `sqlite3.Row` 误用 `.get()` 的 500（同一个坑第二次踩，已在注释里点名）。

## 第十七轮（续 4）全量代码体检（2026-09-22）

> 实施者：**WorkBuddy · DeepSeek-V4.1-Flash**

- [x] 7 项可复现检查（编译 / pyflakes / 全路由 / 配置三方一致 / schema / 全 9 阶段端到端 / 并发压测）；
- [x] 修 4 个真 Bug：① `upsert_poc` 并发竞态（6 并发 5 失败）② `sync_pocs` 失败拖垮任务
      ③ POC 引擎 `{{BaseURL}}` 路径永远打不中 ④ GUI `BASE_DIR` 未定义导致上传 POC 500；
- [x] 清掉"重复定义/重复键"隐患（函数、策略映射、DEFAULTS、settings.yaml、文档各一份）；
- [x] 新增回归：`[5k]` 8 线程并发注册同一 POC 无异常且只 1 行；
- [ ] （可选后续）给 `db` 的单写者限制做更彻底的方案（如写操作串行化队列）——当前靠
      WAL + busy_timeout 已能扛住 6 并发；若以后支持更多并发任务再评估。

## 兼容性红线（所有新增代码都适用）

1. 路径用 `pathlib`；命令用列表参数 + `shell=False`；工具名不假设平台。
2. 不引入仅 Windows 或仅 Linux 可用的依赖；新增第三方依赖必须写进 `requirements.txt`。
3. 编码统一 UTF-8 显式声明（读写文件都带 `encoding="utf-8"`）。
4. GUI/CLI 启动前不要假设固定端口可用（5000 被占用时应报错清晰，而非静默失败）。

---

# 参考项目借鉴清单（`C:\Users\材料\Desktop\tools\scan\myscan_20250825`）

> 本轮按你的要求通读参考项目（`batch.py` / `core/*` / `spider/*` / `exploit/scripts/*` / `dict/*` / `conf/myscan.yaml`）
> 后的**调研结论 + 批判选优**。原则：只记"对我们有用且不重复"的，重复的不记，有害的明确写出来。
> 本清单**不是承诺**；采纳项已并入上方 P 编号，不另立重复条目。

图例：`[采纳]` 已并入上方编号 · `[已借鉴]` 现有代码已体现，标注即可 · `[暂不采纳]` 明确拒绝并写理由 · `[仅记录]` 留档备查

## A. 采纳 / 已借鉴

- `[采纳→P0-1]` **免 key 第三方子域源清单**（这是参考项目最有价值的部分）。
  其 `spider/thirdLib/*` 共 20+ 源，实测**无需 key** 的有：
  `crt.sh`（证书透明度）、`otx.alienvault.com`、`api.certspotter.com`、`api.hackertarget.com`、
  `rapiddns.io`、`api.sublist3r.com`、`myssl.com`、`ctsearch.entrust.com`、`ce.baidu.com`、
  `dns.bufferover.run`、`sitedossier.com`；需 key 的（fofa/shodan/quake/censys/virustotal/
  threatbook/securitytrails/riskiq/fullhunt/bevigil/chinaz）**留给 P0-5 之后的排期**。
  → 我们的 P0-1「多来源被动收集」应直接从这批免 key 源起步（改造成 `utils.http_request` 同步 + `pool_run` 并发，
  不引入 aiohttp，见 B-4）。
- `[采纳→P0-6]` **泛解析过滤**：`core/utils/wildcard.py` 用"IP/CNAME 出现次数超阈值即判泛解析"，
  成本极低、直接解决我们内置爆破的垃圾灌入问题。
- `[采纳→P0-2]` **CDN CNAME 名单**：`dict/information/cdn_cname.txt`（3979 字节）可直接作为
  "泛解析统一 CNAME"与"子域接管误报"的双重排除依据。
- `[采纳→P1-1]` **favicon MD5 作为零请求指纹前置**：参考项目在 POC 模板里放
  `favicon_md5_list`（`exploit/scripts/__template__.py`），并在 `spider/web.py::_get_favicon_md5`
  真实实现。我们指纹目前只有 header/body（`scanner/fingerprint.py`），**favicon 维度缺失**。
- `[采纳→P1-1]` **POC 的 `detect()` / `exec()` 两段式**：先只做指纹判定，命中才进入利用探测，
  天然与"指纹→POC 联动"契合，且与我们"非破坏性"约束一致（detect 段只有 GET）。
- `[已借鉴]` **指纹的 header/body 正则 + 匹配即返回首个标签**：我们 `fingerprint.py` 就是这样做的，
  并且已经修掉了参考项目没修的误判问题（我们的 apache 规则排除了 `Apache-Coyote`，见 CHANGELOG 第一轮）。
- `[已借鉴]` **JS 跳转跟随**（`meta refresh` / `location.href` / `location.replace`，上限 3 次）：
  参考项目 `spider/web.py::_get_js_jump` 处理得很好。我们 probe 目前只看 200/301/302，
  **未跟随 JS 跳转**——属可补的小增强，但优先级低于 P0，暂不单列。
- `[已借鉴]` **title 多级回退**（`title`→`h1`→`h2`→`h3`→`meta description`→`meta keywords`→短文本）：
  我们 `probe` 的标题提取较简单；这条在报告可读性上收益明显，**归入 P2-2 一并处理**。

## B. 批判（明确不采纳 / 需改造的理由）

- `[暂不采纳]` **B-1 `conf/myscan.yaml` 明文存放真实 key —— 这是安全事故，不是设计**。
  实测该文件内有 fofa api、shodan、quake、virustotal、**github PAT** 等可直接使用的凭据（明文入库）。
  我们只借鉴"**单文件集中**"这一结构（印证 P0-5），凭据一律走 `config/keys.yaml` + `.gitignore` + 不留可用默认值。
- `[暂不采纳]` **B-2 `core/utils/differ.py::DifferentChecker` 是未完成代码**：
  `getCompareBeforeAfterIndex` 内留调试 `print`；文件 `__main__` 段调用的是**不存在的 `MyDifflib`**
  （类名实为 `DifferentChecker`），直接运行即 `NameError`。若将来做"`xxx1/xxx2` → `xxx[FUZZ]` 归纳"
  需自行实现，**不能照搬**。
- `[暂不采纳]` **B-3 `spider/ip2domain.py` 用 `eval(text)` 解析 HTTP 响应**——危险写法（应 `json.loads`）。
  且其依赖的 `api.webscan.cc` 是免费公共接口，稳定性与可用性无保障。
  借鉴思路（`Semaphore` 限流、跳过私有 IP、`add_done_callback` 回填），解析与调用方式必须重写（见 P1-4）。
- `[暂不采纳]` **B-4 aiohttp 异步栈与"每请求新建 `ClientSession`"**：
  参考项目在 `spider/web.py::_get_alive` 里**每个请求内**新建 `ClientSession`（性能反模式），
  且 `_get_cms` 用 `str(headers)` 直接正则匹配（弱类型）。
  本仓库不变量要求"所有 HTTP 走 `utils.http_request`"（统一 UA/超时/verify_tls），已有 `pool_run` 线程池，
  **不引入 aiohttp**——否则 `limits.verify_tls`、超时、日志三处行为会分叉。
- `[暂不采纳]` **B-5 POC `priority` 机制**：参考项目用它解决多 POC 加载顺序冲突。
  我们 POC `id` 已承担**去重与溯源**语义（`AGENTS.md §5.6`：单条漏洞去重键 = `(target, poc_id)`），
  再叠一层 priority 会让"同名不同优先级"的语义与 id 唯一性打架；我们的"顺序分歧"已由
  **两条既有机制**解决 —— `checks.poc_link_tags`（指纹命中的 POC 优先执行）与
  `favicon_md5_list` 前置判定（不匹配则零请求返回），不需要再引入第二套优先级语义。**不做**。
- `[暂不采纳]` **B-6 GUI 的「资产分组」「计划任务」「GitHub 管理/监控」三个栏目**：
  资产分组需人工维护分组与成员（CTF 单人场景收益低）；计划任务需常驻调度器；
  GitHub 监控需 token + 持续抓取（且参考项目自身把 token 明文写进配置，见 B-1）。
  我们保留「**9 栏**导航 + 任务详情页签」的轻量形态（第十三轮曾从 10 栏收敛到 8 栏，
  后续轮次又按需要调整为 9 栏，见 P2-1 的现状说明）。
- `[暂不采纳]` **B-7 照抄参考项目任务详情的 13 个页签**。参考图页签为：
  站点 / 子域名 / IP / SSL证书 / 服务 / 文件泄露 / URL信息 / 风险 / 服务(python) / C段 / nuclei / 指纹统计 / WIH。
  我们实做 **10 个**（**潜在漏洞（默认页签）** / 站点 / 子域名 / **拓展域名** / **端口服务** / **C 段** /
  目录 / **线索** / 目标与配置 / 运行日志），**参考项目 13 个里剩下的 5 个不是不想做，而是数据源不存在**：
  IP 依赖 P1-4 的反查（**已于第五轮落地，同时补齐了「C 段」**）；「服务」页签已由 **P1-2 端口扫描**支撑；
  SSL证书 依赖证书解析；文件泄露·URL信息 依赖爬虫数据模型；指纹统计 依赖 P1-1（已具备数据，未单列页签）；
  nuclei·WIH 依赖外部引擎。
  → **不做空页签占位**（点开是"暂无数据"的页签比没有更糟）。
- `[暂不采纳]` **B-8 照搬 `dict/cms/*.yaml` 指纹大库**：`other.yaml` 172KB、`tmp.yaml` 258KB，
  另有 `demo/oa.yaml.bak` 156KB，属**未清洗资产**。我们 `fingerprint.py` 内置十几条标签即够 CTF 用；
  等 P1-1 真需要数据驱动时再考虑引入，并必须先去重清洗。

## C. 保留与标注（你未处理的 / 间接处理的）

- **C-1 实施情况（累计）**：你已确认方向并明确授权"按你的建议自行决策、尽可能多完成"。
  第一轮实施：P0-1 / P0-6 / P0-7 / P0-8 / P1-5 / P2-4 / P2-1；
  第三轮实施：**P0-2 / P0-3 / P0-4 / P0-5 / P1-1 / P1-2 / P1-3（核实无需改码）/ P2-2** +
  「本轮新增配套」全部条目（POC 分类批量开关、报告端口维度、DB 轻量迁移、smoke 扩充）。
  第四轮实施：**`checks.skip_severities` 执行级门 / GUI「按级别分类批量开关」/ evasion 变体与
  参数顺序随机 / vulnscan 预算日志 / 全量文档对齐 / smoke 再扩充**（详见上方「第四轮」小节）。
  第五轮实施：**新增 osint 阶段（P1-4 C 段反查 + P3-1 favicon/FOFA 反查）+ `scanner/mmh3.py`
  纯标准库实现 + `csegs` 表 + GUI 第 10 栏「C 段视野」与第 8 页签「C 段」+ OSINT 策略面板 +
  smoke 再扩充**（详见上方「第五轮」小节）。
  收尾：**以代码为准复核未列入清单的注释/文档，修掉 3 处不一致** —— `config/keys.yaml`
  注释改成"fofa 已被 `scanner/fofa.py` 真实使用"（原写"先占位"，与代码冲突）；
  `docs/security-notice.md` 补 osint 的**第三方信息披露**说明（目标 IP → api.webscan.cc、
  favicon mmh3 → FOFA）；重跑 CLI 重新生成陈旧的 `logs/cli_smoke_report.md`
  （旧产物仍写「疑似问题」且仍列 info/low 三条，与当前执行级门矛盾）。
  仍原样保留未动：**P2-3** 剩余部分（Linux 实机验证）、**P3-2 / P3-3**（依赖外部情报源 / 样本量）。
  第八轮实施（工程运维，2026-09-22，轮次编号沿 `CHANGELOG_AI.md` 口径）：git 仓库建立
  （MinGit 便携版 `C:\Users\材料\MinGit\cmd\git.exe` + 首次提交 `2267e51`，392 文件）、
  `.gitignore` 补全（`venv/` / `config/nuclei-templates/`）、`logs/` 清理 64 个开发期任务目录
  （保留最新 `cli_smoke_report.md`）、`AGENTS.md` §2 环境描述更新。
  **注：关于 `python` 是否可用，第八轮与第九轮下过两次相反结论，都不准确（第十一轮定案）** ——
  真相是"**分 shell**"：用户在**自己的 cmd** 里 `python` 完全可用（实测 `Python 3.9.0`，
  `where python` 三条命中），**AI 工具启动的 shell** 里才不可解析，根因是该 PATH 条目在进程环境里
  **编码损坏**成 `C:\Users\锟斤拷锟斤拷\…`（用户名"材料"的 UTF-8 字节被按 GBK 解读），
  并非"没装/没进 PATH"；`py -3` 因 `C:\WINDOWS\py.exe` 是纯 ASCII 路径而不受影响。
  功能无影响：`utils.pick_python()` 在 `which("python")` 不中时回退 `sys.executable`（实测生效）。
  详见 `CHANGELOG_AI.md` 第十一轮。
  零代码改动，接管基线与收尾各跑一次 `tests/smoke.py` 均 PASS。
  第九轮实施（审计第八轮成果）：修掉 `AGENTS.md` §2 的环境描述错误（第八轮"纠偏"本身不准确，
  实测 AI shell 里只有 `py -3` 可用）、SQL 注入面与跨平台双审计通过、补提交。
  第十一轮再修正：连第九轮的"python 不在 PATH"也不准确，真根因见上（PATH 条目编码损坏）。
  详见 `CHANGELOG_AI.md` 第十一轮。
  第十轮实施（2026-09-22，接手同一条指令）：按你原话"很大功能实现了 都要有一个菜单栏去有一个
  大体的开启或者关闭，根据分类来"逐段核对，**发现 `dirscan` / `vulnscan` 此前没有任何总开关**
  （`config.DEFAULTS` 里根本没有这两段，GUI 无从关闭，"只做资产测绘、不探测"这件事做不到）——
  已补阶段级 `enabled`（默认 **true**，只补"能不能关"、不改变任何既有默认行为）+ 两个 Stage 的
  gate（关掉连请求都不发）+ 策略页两个复选框与 POST 映射 + smoke `[3d]` 重写/`[5b]` 新增；
  同时清掉 3 处上一轮残留的文档错漏（`settings.yaml` 头部注释"十段"、`usage.md` 的 `-p` 开关
  清单漏 `dirscan/vulnscan`、README 的"三层门控"应为四层）。详见 `CHANGELOG_AI.md` 第十轮。
  其中 **P0-7 / P0-8 是你写在 `todo.txt` 下方但此前未被任何文档收录的原话要求**
  （低危默认关闭 + 按分类开关面板、动态绕 WAF / UA 随机化），已拆分收录并落地实现。
  第十二轮补充（事故与护栏）：我方浏览器子代理越权点了「批量删除」并确认了 `confirm()`，
  硬删掉 63 条历史任务行（另对 `orderfood.top` 误跑了全 8 阶段真实扫描）；已只读扫描 SQLite
  free 页抢回 31 条任务行并导出 `data/trash/recovered_tasks_20260922.json`（按你决定不回灌 DB），
  并新增 `db.backup_task()` / `delete_task(backup=True)` —— **删除前自动备份到 `data/trash/`**。
  详见 `CHANGELOG_AI.md` 第十二轮。
  第十三轮实施（用户当场提的 7 项，见上方「第十三轮」小节）：乱码根因修复 + 拓展域名分流新页 +
  子域名 IP/CDN 标记与标签过滤 + POC 相对路径 + 侧栏 10→8 栏收敛 + probe 消费开放端口 + 站点重复折叠；
  另修复 smoke `[2c]` 的凭据耦合脆弱性（原断言会在用户填了真实 FOFA key 时失败，且下一句会**触网**）。
  全程 `py -3 tests/smoke.py` = SMOKE PASS（连跑两次稳定）。详见 `CHANGELOG_AI.md` 第十三轮。
  第十四轮实施（用户当场提的 6 项，见上方「第十四轮」小节）：策略面板折叠 + 测试库/日志目录隔离
  （`CTFSCANNER_DB`/`CTFSCANNER_LOGS`）+ 全站相对路径 + 来源可读标签 + FOFA 证书反查 +
  用户黑名单（入库前过滤）+ 批量跑子域名（新建任务）+ 拓展/站点重叠默认隐藏。
  全程 `py -3 tests/smoke.py` = SMOKE PASS。详见 `CHANGELOG_AI.md` 第十四轮。
- **C-2 间接处理（已由现有实现覆盖，标注后不再重复排期）**：
  - 参考项目 GUI「指纹管理」栏目 → 我们已由 `scanner/fingerprint.py` 覆盖（**本轮之前**即已完成），
    差别只是它 YAML 数据驱动、我们代码内置（见 B-8）。
  - 参考项目 `conf/myscan.yaml` 的"单文件集中配置" → 我们的 `config/settings.yaml` 已是集中配置入口，
    P0-5 只是往这个既有入口里"补 key 段"，**不需要新建架构**。
  - P2-2 的**前端筛选** → 本轮已随 GUI 重构完成（`initFilters()`），故 P2-2 标 `[~]`。
  - 参考项目任务行的「删除/停止/重启」→ 本轮已实做为 **P2-4**（含批量与导出）。
  - **全局文案「疑似问题」→「潜在漏洞」**：按你的要求统一（报告 `scanner/report.py`、CLI 汇总、
    仪表盘卡片、任务详情默认页签、vulnscan 日志）；同时把 4 个检查项名称里的「（疑似）」后缀去掉
    （`a03-sqli-error` / `a03-xss-reflect` / `a01-open-redirect` / `a06-legacy-banner`），
    **`poc_id` 未变**（去重键 `(target, poc_id)` 不受影响），detail 文本里的"需人工确认"提示保留。
- **C-3 明确保留的结论（避免下个 AI 重复调研）**：**AK/SK 挖掘（P0-3 后半）在参考项目中完全没有实现**。
  实测全库 grep `AccessKeyId|LTAI|aws_access|secret_key|access_key` 仅 4 处命中，
  全部是 `core/utils/cipher.py` 的 DES 加解密工具与指纹关键字（`horde_secret_key`），**无任何 JS 密钥提取逻辑**。
  → 我们的 P0-3 属**原创项**，没有现成参考可抄，实现风险与误报控制由我们自己负责。