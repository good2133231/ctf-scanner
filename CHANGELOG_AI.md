# CHANGELOG_AI.md

> 供 AI 接手的变更日志：只记录**已实施**的代码/文档改动，写清「改了什么、为什么、怎么验证」。
> 最新的在最上面。倒序追加，不要删除历史条目。

## 2026-09-21 —— 第七轮：新增 osint 阶段（P1-4 C 段反查 + P3-1 favicon/FOFA 反查）

### 背景

第六轮把 P1-4 / P3-1 列为"未做"，理由是"依赖外部接口，本机无法离线验证"。复核后判定这个理由
**不成立**：依赖（`config/keys.yaml` 已就位、favicon 采集链路 P1-1 已就位、`probe` 已产出 IP/站点）
都已具备，剩下的是"写代码"而不是"等依赖"。因此本轮把这两项一并落地，作为新的 **`osint` 阶段**。

**一个必须说明的技术结论**：FOFA 的 `icon_hash` / Shodan 的 `http.favicon.hash` 用的是
**MurmurHash3 x86_32（mmh3）而不是 MD5**。我们原先只算 MD5（`fingerprint.favicon_md5`），
因此"拿 favicon 去第三方反查资产"这条路在实现上是**走不通的** —— 这是本轮的核心阻塞点。
`mmh3` 是 C 扩展包，在离线 CTF 环境装不上，故用标准库自实现并附公开已知向量自检。

### 变更（新增代码）

1. **`scanner/mmh3.py`（新）**：纯标准库 MurmurHash3 x86_32。
   `hash32(data, seed=0)` 返回**有符号** 32 位整数（与 `mmh3.hash` 一致）；
   `favicon_hash(content)` = `hash32(base64.encodebytes(content))` —— **必须是 `encodebytes`**
   （带换行）而不是 `b64encode`，否则算出来的值与平台数据对不上。
   `SELF_TEST` 收录 3 个公开向量（`b""` / `b"foo"` / `b"hello"`），smoke 断言，写错立刻暴露。
2. **`scanner/iprecon.py`（新）**：IP 反查 + C 段归纳。
   `is_public_ip()`（`ipaddress` 判定私有/环回/链路本地/组播/保留/未指定 → 跳过，省配额）、
   `segment_of()`（IPv4 → `a.b.c.0/24`；**非 IPv4 返回 ""**，IPv6 的"段"概念不同，不臆测）、
   `group_segments()`、`normalize_domain()`、`parse_domains()`、`reverse_lookup()`、`lookup_many()`。
   **与参考项目 B-3 的切割**：参考项目用 `eval(text)` 解析响应（响应可控即任意代码执行），
   我们 `json.loads` + 逐项结构校验；参考项目每请求新建 `ClientSession`（性能反模式），
   我们沿用 `utils.http_request` + `pool_run`（UA 随机化/超时/TLS 策略不分叉）。
   默认只开 5 并发、单 IP 只查一次、失败不重试。
3. **`scanner/fofa.py`（新）**：FOFA 反查客户端 + 黑 ico 判定。
   `credentials()` 读 `settings["keys"]["fofa"]`；`available()`；`build_query()` → `icon_hash="N"`；
   `search()` 用 `qbase64`（**base64 里的 `+` `/` `=` 必须 URL 编码**，否则 query 被破坏）；
   `is_black_ico(total, settings)` → 阈值 `fofa.black_ico_threshold`（默认 200）。
   **未配置 key 时返回 `([], 0, "未配置 fofa.email / fofa.key（见 config/keys.yaml）")`** ——
   显式报错而不是静默无结果。
4. **`scanner/stages/osint.py`（新）**：阶段 `osint`，位置 probe 之后、jsmine 之前（新域名胜地，
   越早入账后面 dirscan/vulnscan 覆盖越广）。两个子开关 `iprecon.enabled` / `fofa.enabled`，
   **都关时整阶段一次请求都不发**。`_collect_ips()` 汇总（目标 IP + 子域名 + 站点 host → 解析）、
   `_c_segments()`（`max_ips` 截断 → 归纳 → 落 `csegs`；单 IP 域名数 > `max_domains_per_ip`
   判为共享主机/CDN，C 段数据照常入库但**不纳入域名资产**）、
   `_fofa_assets()`（对站点并发算 `favicon_hash`，按 hash 去重后逐个查询，超阈值判"黑 ico"跳过）。
   新域名统一走 `db.insert_subdomains(..., source="osint:cseg" / "osint:fofa")`。

### 变更（修改既有代码）

5. **`scanner/fingerprint.py`**：抽出 `fetch_favicon()`（原 `favicon_md5` 的取字节部分），
   新增 `favicon_hash()`（mmh3）。**注意**：该模块原 docstring 写着"不做 mmh3，因为环境里没有
   可用的哈希库" —— 这个理由**现在已不成立**（`mmh3.py` 自带向量自检），已同步改掉那句说明。
   MD5 与 mmh3 分工保留：MD5 用于**我们自己的**零请求前置判定（`favicon_md5_list`），
   mmh3 只用于**对外部平台**提问。
6. **`scanner/db.py`**：新表 `csegs(id, task_id, segment, ip, domains, count)`；
   `ASSET_TABLES` 纳入 `csegs`；`task_counts()` 增 `"csegs"`；新增 `insert_csegs()` / `list_csegs()`；
   `_ASSET_PAGES` 增 `"csegs"`（支持 `/csegs` 的服务端分页 + 关键字过滤）。
7. **`scanner/runner.py`**：`STAGE_ORDER` **7 → 8 阶段**
   （`subdomain → takeover → portscan → probe → osint → jsmine → dirscan → vulnscan`）、
   注册 `OsintStage`、`StageContext.results` 预置 `csegs` / `osint_domains`。
8. **`scanner/config.py` + `config/settings.yaml`**：新增 `iprecon`
   （`enabled/api/max_ips/max_hosts/max_domains_per_ip/workers/timeout`）与
   `fofa`（`enabled/max_sites/max_assets/workers/black_ico_threshold`）两段，**均默认关闭**。
9. **`scanner/report.py`**：概览表加「C 段 IP」列（表头/分隔线/数据行三处同步），
   新增「C 段视野（前 200）」小节。
10. **GUI**：`gui/app.py` 新增 `/csegs` 路由（复用 `_asset_page`）、`task_detail` 传 `csegs`、
   策略 POST 接入两段（`iprecon_api` 留空回落到默认接口）；
   新增 `gui/templates/csegs.html`（沿用 ports.html 模式）；
   导航 **9 → 10 栏**（第 10 项「C 段视野」，四宫格图标避免与「子域名资产」重复）；
   任务详情页签 **7 → 8 个**（新增「C 段」）；`settings.html` 新增「外部情报拓展（OSINT）」面板。

### 变更（文档）

11. **`TODO.md`**：P1-4 / P3-1 标 `[x]` 并补实现说明；新增「## 第五轮」小节；
    修正因本轮落地而过期的计数（导航 9→10 栏、页签 7→8 个、B-6/B-7 的栏数与"缺的 6 个"→"5 个"）；
    P3-2 的理由从"POC 库仅 7 条"改为"312 条里 305 条是低置信导入，应先校准再扩张"；
    B-5 的"当前仅 7 条 POC 也无冲突场景"改为陈述两条既有顺序机制。
12. **`todo.txt`**：第 6 条（ico/fofa）`[部分完成]` → `[完成]`；新增「第五轮」实施清单与验证基线。
13. **本文件**：新增第七轮条目。

### 变更（文档收尾：指出并修正"注释与代码不符"）

收尾阶段用"以代码为准"的原则复核了**未被本轮列入清单的**文档与注释，发现并修正 3 处：

14. **`config/keys.yaml` 注释与代码冲突（已按代码更正）**：原文第 11-13 行写
    "目前框架内建被动收集源全部免 key……**下面的厂商用于将来的扩展来源，先占位**"，
    但 `fofa` 段**已被 `scanner/fofa.py::credentials()` 真实读取**、被 `gui/templates/settings.html`
    的 OSINT 面板明确指向（"需在 config/keys.yaml 填 fofa.email / fofa.key"）。
    已改为：显式标注 **fofa 已被 osint 阶段使用**，其余厂商（shodan / quake / hunter /
    virustotal / securitytrails）仍为占位、填了也无行为（已 grep 全仓确认：除 `config.load_keys()`
    的 docstring 举例与 `passive.py` 的"需 key 故不接"说明外，无任何代码消费这些段）。
15. **`docs/security-notice.md` 补一条 osint 的第三方披露说明**：新增阶段会把**目标 IP**
    提交给 `api.webscan.cc`、把 **favicon mmh3 哈希**提交给 FOFA —— 属"向第三方披露目标信息"
    的行为，此前文档未提。已加入「框架层面的克制」，注明默认全关、敏感项目应保持关闭。
16. **重新生成 `logs/cli_smoke_report.md`（陈旧产物）**：该文件是上一轮残留的运行产物，
    仍写着旧文案「疑似问题」且仍列着 info/low 三条（`a02-no-https` / `a05-security-headers` /
    `a05-banner-disclosure`）—— 与当前默认策略（执行级跳过 info/low）**不一致，会误导**。
    已起本地靶场（`py -3 -m http.server 8765 --directory smoke_root`）后用文档记载的 CLI 命令重跑：

    ```
    py -3 cli/client.py -t http://127.0.0.1:8765/ -p probe,vulnscan -n cli-smoke --offline --report logs/cli_smoke_report.md
    ```

    新产物（任务 #56）已与代码一致：概览表为 6 列（含「C 段 IP」）、文案为「潜在漏洞」、
    结果只剩 3 条 **high**；日志同时实测到用户要的那句
    `内置检查 5/12 项；info/low 级检测已跳过（连请求都不发）`。

### 验证

- `py -3 tests/smoke.py` → **SMOKE PASS**。新增/扩展断言：
  - `[1b]` 阶段表为 8 个（含 `osint`）；
  - `[2c]` **mmh3 三个公开向量全中**（`b""`→0 / `b"foo"`→-156908512 / `b"hello"`→613153351）；
    `favicon_hash(b"")==0` 且 `favicon_hash(ico)==hash32(base64.encodebytes(ico))`；
    `segment_of("1.2.3.4")=="1.2.3.0/24"`、`segment_of("::1")==""`；
    `is_public_ip` 对 `8.8.8.8` 为真、对 `10.0.0.1`/`127.0.0.1`/`192.168.1.1`/`not-an-ip` 为假；
    `parse_domains("null")==[]`、`parse_domains("<html>")==[]`、
    `parse_domains('[{"domain":"A.Example.com:8080"},"*.b.example.com"]')==["a.example.com","b.example.com"]`；
    `fofa.build_query(-12345)=='icon_hash="-12345"'`；
    **`fofa.available() is False` 且 `search()` 第三返回值非空**（无 key 显式报错）；
    黑 ico 边界（200 不算 / 201 算）；
  - `[3d]` `iprecon`/`fofa` 全关时跑 `osint` 阶段 → 无 `csegs` 落库、无 `osint_domains`，
    日志为 `[osint] 未启用（策略配置 → 外部情报拓展 可打开），跳过`；
  - `[4]` 报告含「C 段 IP」列；`[5]` `/csegs` 路由 200、详情页含「C 段」页签、C 段页含关键字表单与分页条。
- 实测输出：`[2c] favicon/osint primitives ok: mmh3 向量 3 个全中；favicon_hash(b'')=0 /
  ico=-1026017266；黑 ico 阈值 200；fofa 可用=False`。
- **CLI 端到端实跑（收尾阶段补）**：起本地靶场后跑 `probe,vulnscan`，日志出现
  `内置检查 5/12 项；info/low 级检测已跳过（连请求都不发）`，结果 **3 项全部为 high**
  （用户明确点名不看的 `a02-no-https` / `a05-security-headers` / `a05-banner-disclosure`
  **确实一条都没有**）—— 这是对"低危洞默认不开启"这条需求的**运行时证据**，
  此前只有单元级断言（`[3b]`）。

### 仍未做（诚实汇报）

- **P2-3** 剩余部分：Linux 实机验证（本机只有 Windows + Python 3.9，无法完成）。
- **P3-2** 实时漏洞情报订阅 / **P3-3** 启发式 0day 挖掘：理由见 `TODO.md`（依赖外部情报源与样本量）。
- `osint` 阶段的**联网行为无法在本机离线验证**：smoke 只断言了纯函数与门控，
  `api.webscan.cc` 与 FOFA 的真实往返需要联网 + FOFA key 才能验证。**这是本轮最大的验证缺口**，
  首次实跑请在「策略配置 → 外部情报拓展」里打开后观察 `logs/task_*/task.log` 的 `[osint]` 行。

### 已知局限

- `api.webscan.cc` 是免费公共接口，可用性与返回结构都不由我们掌控；接口地址做成配置项
  （`iprecon.api`，留空回落到默认）以便随时替换。
- 黑 ico 阈值默认 200 是**保守估计值**，未经真实数据校准；命中过多会放弃拓展（宁少勿滥）。
- 单 IP 域名数 > 30 判"共享主机"同样未经校准：CDN/虚拟主机场景可能把真实资产业务误判为共享主机。
- mmh3 自实现只做了 `x86_32`（社区平台用的就是它），未实现 `x86_128` / `x64_128`。

## 2026-09-21 —— 第六轮：低价值项「执行级」硬门 + 请求形态动态化 + 文档全量对齐

### 背景

用户第四轮明确取向："像 `a05-banner-disclosure(info)` / `a05-security-headers(info)` /
`a02-no-https(low)` 这种太 low 的洞**暂时也不要开启了**，我们打 CTF 只关注高位严重（注入/RCE）
才能拿到 flag"；"注入要有动态绕 WAF 功能，项目本身就要相对动态"；"很大功能实现了都要有一个
菜单栏去有一个大体的开启或者关闭，**根据分类来**"。

**问题诊断（为什么第五轮的 `min_severity` 还不够）**：`min_severity=medium` 只做**结果级**过滤 ——
低危检查**照样发请求**，跑完再把结果丢掉。这既浪费请求预算（每个站点 12 项检查里有 7 项白发），
又让"太 low 的洞"占满运行日志。用户要的是"不要开启"，即**执行级**开关。

### 变更（代码）

1. **`scanner/config.py`**：新增 `DEFAULT_SKIP_SEVERITIES = ["info", "low"]` 与
   `skip_severities(settings)` —— 全框架唯一的"哪些级别不执行"判定入口（容错：字符串也接受、
   缺省回落到常量）。`DEFAULTS.checks.skip_severities` 同步。
2. **`scanner/owasp/checks.py`**：
   - `enabled_checks()` 增加 `skip_severities` 维度 → 12 项内置检查默认只有 **5 项**会执行；
   - 新增 `_ordered()`：`a03-sqli-error` / `a03-xss-reflect` 的**参数顺序每次随机**；
   - `run_all()` docstring 改为"执行级 / 结果级"两级表述（原文只写了检查项级）。
3. **`scanner/pocs/engine.py`**：`load_enabled_pocs()` 增加同级过滤（`_norm_severity` 后比对），
   默认 info/low 级 POC 不再加载 —— 名单里的信息也明说了"想让低级别 POC 生效就改 severity 或放宽开关"。
4. **`scanner/evasion.py`**：抽出 `_dedup()` / `_shuffle_tail()`，`mutate_sqli` / `mutate_xss`
   返回前**打乱变体顺序**（首个原始 payload 保持第一，最便宜、命中率最高）。理由：固定尝试顺序
   本身会成为可被 WAF 规则固化的"请求序列特征"。
5. **`scanner/stages/vulnscan.py`**：日志增 `；info/low 级检测已跳过（连请求都不发）`，
   并把跳过的级别列出来 —— 让"扫描预算去哪了"一眼可见。
6. **`gui/app.py` + `gui/templates/settings.html`**：`checks.skip_severities` 接入策略页
   （`getlist`），新增「按级别分类批量开关」面板（info/low/medium/high/critical 五档），
   细粒度检查项列表对已被级别门跳过的项标「·已按级别跳过」。
7. **`config/settings.yaml`**：`checks.skip_severities: ["info", "low"]` + 中文注释说明
   "为什么低级别不执行"，与 `min_severity` 的注释区分开（一个管执行、一个管报告）。

### 变更（文档，第五轮遗留的最后一环 + 本轮同步）

8. **`docs/usage.md`**：`-p` 阶段列表改为 7 阶段；典型输出同步（`阶段 1/7`、`内置检查 5/12 项`）；
   GUI 章节 8 栏 → **9 栏**、6 页签 → **7 页签**、页面清单补齐「端口服务」与 POC 批量开关；
   策略配置小节改为 6 面板并补「按级别分类批量开关」；FAQ 两条重写（CIDR 已支持展开、低危项为何消失）。
9. **`docs/pipeline.md`**：vulnscan 门控改为**三层**（执行级 / 总开关与分类 / 结果级）+ 注入动态性说明；
   配置速查表增 `checks.skip_severities`。
10. **`docs/owasp-mapping.md`**：三级门控 + 明确列出默认不执行的 7 项 check id。
11. **`docs/poc-guide.md`**：执行模型与编写规范都补"低级别 POC 连加载都不加载"。
12. **`docs/architecture.md`**：阶段层补 takeover/portscan/jsmine，新增「资产层」（dnsq/takeover/
    portscan/jsmine）；DB 表补 `subdomains.cname`、`sites.favicon`、新表 `ports`；数据流补 CIDR 展开。
13. **`docs/roadmap.md`**：**改为反映实际完成度**（原文把已落地的端口扫描/CIDR/子域接管仍标未做）——
   按 [x]/[~]/[ ] 重新标注，并补"Linux 实机验证"与"刻意不做低危噪声项"。
14. **`README.md`**：架构图重画为 7 阶段（含资产面拓展）；能力边界更新（312 POC、默认只跑 5/12 检查）；
   特性列表补"三层门控 + 请求形态随机"。
15. **`AGENTS.md`**：不变量 5/7 重写（级别门 + POC 联动）、已知局限更新（7 页签、CIDR 已展开）、
   验证章节断言覆盖说明。
16. **`TODO.md` / `todo.txt`**：P0-7 追加"第四轮加强"说明；新增第四轮完成清单与待办；
   验证基线补第四轮数据。

### 验证

- `py -3 tests/smoke.py` → **SMOKE PASS**；新增断言：
  - `[2b]` 临时全开 POC 注册表 → 级别门内 **311** 个 / 放开后 **312** 个（差 1 个即被挡的 info/low 级模板）；
    `mutate_sqli(..., 0) == [payload]`、`mutate_sqli(..., 3)` 首个元素为原始 payload 且变体数 > 3；
  - `[3b]` 只调 `min_severity`（结果级）低危项仍不出现 → 证明执行级门真实生效；放开 `skip_severities`
    后才出现，再按 A02 分类关闭又消失；
  - `[3]` 流水线日志出现 `内置检查 5/12 项` 与 `info/low 级检测已跳过`。
- 实测数字：内置检查 **5/12** 项执行；POC 注册表全开时 **311/312**（info/low 级模板被挡）。

### 仍未做（诚实汇报）

- **P1-4** IP 反查 C 段（依赖外部 `api.webscan.cc`，本机无法离线验证）；
- **P2-3** 剩余部分：Linux 实机验证（本机只有 Windows + Python 3.9）；
- **P3-1 ~ P3-3**：启发式 0day 挖掘 / 实时漏洞情报订阅 / FOFA 反查 favicon（后者只差填 `config/keys.yaml`）。

### 已知局限

- `skip_severities` 对 POC 的影响面较小：现有 312 个 POC 里只有 1 个是 info/low 级
  （参考项目导入的模板经 `_norm_severity` 多为 medium 及以上），所以"省请求"的主要收益来自内置检查；
- 注入变形仍是"同语义编码变形"（注释/大小写/编码/分片），**不做盲注延时**，对纯逻辑型 WAF 规则无效；
- 参数顺序随机化只改变同一次扫描内的请求顺序，不改变请求总量（预算上限 `_SQLI_MAX_REQ` / `_XSS_MAX_REQ` 未变）。

## 2026-09-21 —— 第五轮：资产面拓展（子域接管 / JS 挖掘 / 端口服务）+ 配置分层 + 分页 + POC 分类批量开关

### 背景

用户第三轮延续授权"按你的建议自行决策、尽可能多完成"，目标是"**明天过来时待办已完全解决、
工程相当优美**"。本轮把上一轮留下的 P0-2 / P0-3 / P0-4 / P0-5 / P1-1 / P1-2 / P1-3 / P2-2
以及 B 组尾巴一次性做完，并补上两处工程性缺口（分页、POC 批量开关）。

### 变更（新增文件）

1. **`scanner/dnsq.py`（新）—— 纯标准库 DNS 客户端**（P0-2 前置）
   - `query(name, qtype, timeout, resolver)` 支持 A/CNAME/AAAA/TXT/MX/NS/SOA/PTR；
     `cname_chain()` 返回 `(chain, ips)`（chain 不含原始名字）。
   - 自实现报文编解码（压缩指针 + 长度前缀标签）；UDP/53，遇 `TC` 截断回退 TCP/53；
     ID 校验 + 多解析器轮询；**任何异常都不外抛**（返回 `[]` / `([], [])`）。
   - `resolvers(settings)` 读 `dicts.resolvers`，非法项过滤，缺失时回退 223.5.5.5 / 1.1.1.1 / 8.8.8.8。
2. **`scanner/takeover.py`（新）—— 子域接管指纹库**：`SERVICES` 41 条（41 个唯一 suffix），
   覆盖 AWS S3/S3-website、GitHub Pages、Heroku、Azure、Shopify、Fastly、Pantheon、Zendesk、
   Netlify、Bitbucket、Ghost、Statuspage、Ngrok 等；`match_service()` / `detect()`（HTTP 走
   `utils.http_request`，仅 GET），产出 `severity="high" / owasp="A05"` 的标准漏洞 dict。
3. **`scanner/stages/takeover.py`（新）—— 阶段 `takeover`**：数据源 `ctx.results["subdomains"]`
   （空则回退 `db.list_subdomains`），`pool_run` 并发解析 CNAME 并回填 `subdomains.cname`，
   命中项 `db.insert_vuln` 并按 `(target, poc_id)` 去重；产物 `logs/task_*/cnames.txt`。
4. **`scanner/portscan.py`（新）—— 端口扫描核心**：`TOP_PORTS` 48 项、`parse_ports()`（`"80,443"` /
   `"1-1024"`，上限 4096）、内置 `scan_host()`（`connect_ex` + 被动 banner）、
   `nmap_scan()`（`-sT -Pn -n --open -oG -`，`-sT` 免 root，正则解析 greppable 输出）。
   **明确不调用 masscan**。
5. **`scanner/stages/portscan.py`（新）—— 阶段 `portscan`**：主机来源 = 目标里的 ip/url/domain
   + `ctx.results["domains_for_probe"]`；`max_hosts` 截断；nmap 优先否则内置兜底；
   去重后 `db.insert_ports`。**默认关闭**（`portscan.enabled=false`）。
6. **`scanner/jsmine.py`（新）—— JS 资产挖掘核心**：`mine(url, settings, logger)` 返回
   `{domains, urls, secrets, js_count}`。78 条第三方域黑名单 + 命名空间噪声表，
   **目标自身域永不误杀**；7 条凭据规则 + 两级降噪；跨文件按原值去重；凭据值掩码脱敏。
   全程只读 GET。
7. **`scanner/stages/jsmine.py`（新）—— 阶段 `jsmine`**：新域名补入 `subdomains`
   （`source="js:mine"`）、接口 URL 落 `logs/.../js_urls.txt`、疑似凭据以 high 级入库
   （`poc_id=js-secret-*`）。
8. **`config/keys.yaml`（新）—— 第三方 API key 专用文件**（P0-5）：fofa / shodan / quake /
   hunter / virustotal / securitytrails 占位 + 中文注释；已加入 `.gitignore`。
9. **`gui/templates/_pager.html`（新）** 与 **`gui/templates/ports.html`（新）**：
   通用服务端分页条 / 端口服务资产页。

### 变更（修改既有文件）

10. **`scanner/runner.py`**：`STAGE_ORDER` 扩为
    `subdomain → takeover → portscan → probe → jsmine → dirscan → vulnscan`，
    `STAGE_REGISTRY` 纳入三个新 Stage；`StageContext.results` 预置 `ports` / `takeovers` 键。
11. **`scanner/targets.py`**：新增 `CIDR_RE` / `MAX_CIDR_ADDRESSES=256` / `expand_cidr()`（P0-4），
    `parse_lines()` 把 CIDR 展开为多条 IP。
    **⚠ 同时修掉一个真实 Bug**：原文第 59 行
    `items = [(("ip", ip) for ip in expand_cidr(t[1]))] if ...` —— 生成器表达式被套进列表，
    产出的是"装着生成器对象的单元素列表"。下游 `for kind, raw in ctx.targets` 会抛
    `TypeError: cannot unpack non-sequence generator`，被阶段级 try/except 吞掉 →
    **CIDR 目标静默丢失，P0-4 此前实际不可用**。已改为列表推导式；回归用例见 smoke `[1]`。
12. **`scanner/config.py`**：docstring 改为三段配置来源说明（含 keys.yaml）；`DEFAULTS` 增
    `limits.favicon_md5`、`checks.poc_link_tags` / `poc_max_per_site`、`takeover` / `portscan` / `jsmine`
    三段；新增 `KEYS_PATH` + `load_keys()`；`save_settings()` 落盘前 `settings.pop("keys", None)`
    —— **防止 GUI 存一次策略就把凭据复制进 settings.yaml**。
13. **`scanner/db.py`**：SCHEMA 增 `subdomains.cname`、`sites.favicon`、新表 `ports`；
    新增 `_ensure_columns()` 轻量迁移（`PRAGMA table_info` 探测 → `ALTER TABLE ADD COLUMN`）；
    `insert_subdomains` 支持三元组、新增 `set_subdomain_cnames()` / `insert_ports()` / `list_ports()`；
    新增分页层 `page_assets(table, limit, offset, q)`（返回 `(rows, total)`，`q` 走 LIKE）；
    新增 `poc_source()` / `bulk_set_poc_enabled()`（POC 分类批量开关）。
14. **`scanner/utils.py`**：`http_request(..., want_bytes=False)`，为 True 时结果额外带 `"content"`
    原始字节（favicon 计算需要）；`_urllib_request` 同步支持。
15. **`scanner/fingerprint.py`**：新增 `favicon_md5(base_url, settings, timeout)` —— 非 200 /
    空 / 超 512KB / 首字节像 HTML（说明是 SPA 回退页而非真图标）一律返回 `""`。
16. **`scanner/stages/probe.py`**：favicon 采集段，回填 `sites[].favicon`。
17. **`scanner/pocs/engine.py`**：`run_poc_on_target(..., site=...)` 增 `favicon_md5_list`
    零请求前置判定（不匹配直接返回 `[]`）。
18. **`scanner/stages/vulnscan.py`**：新增 `_pocs_for(site)` —— 指纹命中的 POC 优先且不受
    `poc_max_per_site` 约束，其余补后受限。
19. **`scanner/report.py`**：概览表增「开放端口」列 + 「开放端口与服务（前 200）」小节。
20. **`gui/app.py`**：`task_detail` 传 `ports`；新增 `PAGE_SIZES` / `_page_args()` / `_asset_page()`
    （页码越界回落最后一页）；`/subdomains`、`/sites`、`/dirs` 改服务端分页；新增 `/ports` 路由；
    `/pocs` 路由补 `source` 字段与分类统计；新增 `POST /api/pocs/bulk`；settings POST 增
    `favicon_md5`、`poc_link_tags`、`poc_max_per_site`、`takeover`/`portscan`/`jsmine` 三段。
21. **GUI 模板**：`base.html` 侧边栏 9 项（新增「端口服务」）；`task_detail.html` 7 页签 +
    子域名增 CNAME 列；`subdomains/sites/dirs` 改服务端 `q` 表单 + 分页条；`settings.html` 增
    「资产面拓展」面板；`pocs.html` 重写（分类批量开关 / 只看已启用 / 来源列）。
22. **`gui/static/app.js`**：`initFilters()` 增 `data-filter-enabled` 勾选过滤；新增 POC 批量开关处理。
23. **`gui/static/style.css`**：`.pager` 样式。
24. **`config/settings.yaml`**：同步 `favicon_md5` / `poc_link_tags` / `poc_max_per_site` /
    `takeover` / `portscan` / `jsmine` 六处，并注明 keys.yaml。
25. **`.gitignore`**：追加 `config/keys.yaml`。
26. **`tests/smoke.py`**：新增 8 组断言（见下）。

### 验证

- `py -3 tests/smoke.py` → **SMOKE PASS**（新增：CIDR 解析与超限丢弃、阶段注册表、
  `favicon` 字段、takeover/portscan/jsmine 三阶段门控、报告「开放端口」列、`/ports` 路由、
  资产页分页条、POC 批量接口启用→关闭还原、任务详情「端口服务」页签）。
- `engine.load_all_meta()` → `total 312 ok 312 bad 0`（7 内置 + 305 导入）。
- `load_settings()` → `takeover.enabled=True` / `portscan.enabled=False` / `jsmine.enabled=True`；
  `settings["keys"]` 六个厂商段全部解析成功。
- 子代理独立验证：`dnsq.cname_chain("www.github.com")` → `(['github.com'], ['20.205.243.166'])`；
  离线假 ctx 跑 takeover Stage → 门控跳过 / 命中入库两条路径均正确；
  jsmine 本地靶场验证 7 组全 PASS（含黑名单、凭据降噪、门控、去重、停止不入库）。

### 仍未做（诚实汇报）

- **P1-4** IP 反查 C 段：依赖外部 `api.webscan.cc`，且参考项目用 `eval()` 解析响应，
  需改成 `json.loads` 并把接口地址放进配置；网络依赖强，未在无外网环境验证。
- **P2-3** Linux 实机验证：本机仅 Windows / Python 3.9；跨平台不变量（`pathlib` / `shell=False` /
  `shutil.which` / `pick_python` / 显式 UTF-8）已就位，但未在 Linux 跑过 smoke。
- **P3-1 ~ P3-3**：启发式 0day / 实时情报 / FOFA 反查 favicon（后者只差填 `config/keys.yaml` 的 fofa key）。

### 已知局限（子代理交付时自报，已核实）

- `dnsq`：只解析 Answer 段（不合并 Authority/Additional）；无 DNSSEC/EDNS0；
  TCP 回退仅一次；未做连接复用。
- `takeover`：指纹靠文案整理，第三方文案会变；`http_check=false` 时退化为纯 CNAME 判定，
  误报明显上升；候选子域会二次查询 DNS（少量重复）。
- `jsmine`：纯正则提取（无 sourcemap 还原）；短 token 与含 `test/demo` 的真实值会被保守丢弃；
  同一任务重跑该阶段会重复写 vulns（`insert_vuln` 无去重键，属既有数据模型）。

## 2026-09-21 —— 第四轮：P0-1/P0-6/P0-7/P0-8 + P1-5 + P2-4 落地（分级门控 / 动态免杀 / 被动收集 / 泛解析 / 任务运维 / POC 兼容）

### 背景（用户本轮要求）

用户在上一轮任务中断后明确授权"**按你的建议自行决策、尽可能多完成工作**"，并给出两组需求：

- **A 组**：`a05-banner-disclosure(info)` / `a05-security-headers(info)` / `a02-no-https(low)` 这类
  "太 low 的洞"不要再开启——CTF 只关注能拿 flag 的**高位严重**（注入 / RCE 等）；
  注入要有**动态绕 WAF** 能力，框架本身也要"相对动态"（User-Agent 随机性等）；
  "很大功能实现了都要有一个菜单栏去有一个大体的开启或者关闭，**根据分类来**"。
- **B 组**：任务管理要有**批量停止 / 批量删除 / 查看**；结果页**不要写"疑似问题"，写"潜在漏洞"**；
  问"我们现在的 POC 成熟吗、有必要采用 nuclei 吗"，以及参考项目
  `C:\Users\材料\Desktop\tools\scan\myscan_20250825` 的漏洞**能否导出来并做到与 nuclei 不冲突的兼容**。

### 变更（新增文件）

1. **`scanner/evasion.py`（新）—— 动态免杀模块**（P0-8，原创项，参考项目无对应实现）
   - `UA_POOL`（10 个真实浏览器 UA）+ `pick_ua(settings)`：每请求随机取；
   - `browser_headers(settings, extra)`：统一补齐 Accept / Accept-Language / Cache-Control /
     Connection 等浏览器化头，**刻意不设 `Accept-Encoding`** —— urllib 兜底路径不解压，
     设了会把响应体变成乱码（这是实测踩过的坑，写在注释里）；
   - `WAF_SIGNATURES`：**16 家**厂商指纹（Cloudflare / 安全狗 / 云锁 / 阿里云盾 / 腾讯云 /
     长亭雷池 / 创宇盾 / 360 / ModSecurity / Naxsi / 宝塔 / Imperva / AWS / F5 / 华为云 / GCP）；
     `fingerprint_from(resp)` 提取、`detect(url, settings, logger)` 先被动指纹、无果再补一次只读 GET；
   - `mutate_sqli / mutate_xss / mutate(payload, level, kind)`：`bypass_level` 0~3 逐级升级
     （0 原始 → 1 注释替空格 + 大小写 → 2 换行编码 / URL 编码 / 内联注释 → 3 双重编码 + 关键字分片）；
   - 函数内 `from .utils import http_request` 延迟导入，**避免与 utils 循环依赖**。
2. **`scanner/wildcard.py`（新）—— 泛解析过滤**（P0-6）：`random_label()` / `detect(domain, samples=3)` /
   `resolve_all(names, workers)` / `filter_hits(resolved, wildcard_ips)`；无泛解析时零副作用。
   局限：只用 `socket.getaddrinfo`，拿不到 CNAME，故参考项目那套"CNAME 阈值 + CDN CNAME 黑名单"
   只借思路未全量实现（留待 P0-2）。
3. **`scanner/passive.py`（新）—— 免 key 多来源被动子域收集**（P0-1）：`SOURCES` 注册表 8 项
   （crt.sh / certspotter / alienvault / hackertarget / rapiddns / sublist3r / sitedossier / bufferover），
   `DEFAULT_SOURCES` 启用前 6 项；`_extract()` 用通用正则同时吃 JSON / HTML / 纯文本；
   `collect(domain, settings, logger, workers=6) -> {子域名: "passive:<源名>"}`。
   全部走 `utils.http_request`（统一 UA/超时/verify_tls），**不引入 aiohttp**（见 TODO.md B-4）。
4. **`tools/import_ref_pocs.py`（新）—— 参考项目 POC 静态导入器**（P1-5）
   - 用 `ast` 静态解析参考项目 `exploit/scripts/**/*.py`（**不执行、不 import**，341 个脚本），
     提取 `detect_path_list` / `exec_path_list` / `bug_level` / `bug_type` / `favicon_md5_list`；
   - 关键设计：**只从判定语句里取关键字**（`'xxx' in text` 的 `Compare(In/NotIn)`、
     `.find()/.index()` 的参数），并用 `_accept_keyword()` 过滤（长度 4~80、拒纯小写英文单词、
     拒含 `{}`/`\`/`%`、拒 http(s) 开头、拒 `STOPWORDS` 里的字典键噪声）；
   - 产出 `config/pocs-imported/<vendor>__<stem>.yaml`：`path` 最多 12 条、`words` 按长度降序取 8 条、
     `matchers-condition: and`（status 200 + word condition: or）。
   - **实测结果：341 → 305 个 YAML**（跳过非 Script 类 1 / 无路径 5 / 无可提取关键字 30）。
     首版曾产出 335 个但关键字噪声严重（出现 `http:` `name` `software` `url` 这类字典键），
     **改为"只从判定语句取"后重跑才干净**，故重跑覆盖是本脚本的正常用法。

### 变更（修改文件）

5. **配置层**：`scanner/config.py` DEFAULTS 增 `limits.wildcard_filter`、`checks`
   （`min_severity` / `poc_engine` / `disabled_categories` / `disabled_checks`）、
   `passive`（`enabled` / `sources` / `timeout`）、`evasion`
   （`random_ua` / `spoof_xff` / `waf_bypass` / `bypass_level` / `waf_detect`）；
   `config/settings.yaml` 整体重写为带中文注释的同结构。
6. **`scanner/utils.py`**：`_ua()` 改为优先 `evasion.pick_ua()`（失败回退固定 UA），
   新增 `_headers(settings, extra)` 走 `evasion.browser_headers()`，`http_request` 统一用它
   —— 这样"所有 HTTP 出口的一体化伪装"只在这一处生效，符合既有不变量。
7. **`scanner/owasp/checks.py`**：
   - 新增 `SEVERITY_ORDER` / `CATEGORIES`（A01~A10 中文名）/ `severity_ok()` / `enabled_checks()`；
   - `run_all(url, settings, min_severity=None)` 加**两级门控**：检查项级（被关闭的分类/检查
     **根本不执行**，省请求）+ 结果级（低于门槛直接丢弃）；
   - `_sqli_error` / `_xss_reflect` 重写为**多变体**：先打原始 payload，未命中才升级到变形变体，
     总请求数封顶（SQL 30 / XSS 20），命中变形变体时在 detail 里注明"命中 WAF 绕过变体：…"；
   - 4 个检查项的显示名去掉「（疑似）」后缀（**`poc_id` 不变**）。
8. **`scanner/stages/vulnscan.py` 整体重写**：读 `checks.min_severity` / `checks.poc_engine`
   （关闭时 `pocs = []` 并在日志写明"POC 引擎已关闭"）；每站点扫描前调 `evasion.detect()`；
   POC 结果复用 `severity_ok()` 过滤；`_scan_site` 首行 `if ctx.stopped(): return []`；
   日志改为"潜在漏洞 N 项（critical:1 / high:2），均为初筛结果，需人工确认"。
9. **`scanner/pocs/engine.py` 整体重写 —— 向 nuclei 语法靠拢**（P1-5 的核心回答）
   - 加载目录：`scanner/pocs/pocs` / `config/pocs-user` / `config/pocs-imported` / `config/nuclei-templates`；
   - 兼容 `http:` 与 `requests:`；支持 `payloads`（list / dict + `attack: clusterbomb|pitchfork|batteringram`）、
     `variables` + `builtin_vars`、`path` 列表、`redirects`、匹配器 `status/word/regex/size` +
     `condition/negative/case-insensitive` + `part: body|header|all`、`extractors`（regex/kval → evidence）；
   - `raw` / `dsl` / `flow` / `workflows` 明确不支持，但标 `_status="unsupported"` 并给 `_error`，**不静默失效**；
   - `MAX_REQUESTS_PER_POC = 10` 兜住请求量。
10. **`scanner/db.py`**：新增 `ASSET_TABLES` / `clear_task_assets()` / `delete_task()` /
    `task_counts()`；新增 `default_poc_enabled(path)` 使 **`config/pocs-imported/` 下的 POC 默认关闭**
    （`upsert_poc` 的 INSERT 由固定 `enabled=1` 改为按路径判定），避免 305 条低置信规则污染结果。
11. **`scanner/runner.py`**：新增协作式取消 `_STOP_EVENTS` / `_STOP_LOCK` / `request_stop()` /
    `is_stopped()` / `running_task_ids()`；`StageContext` 增 `stop_event` 与 `stopped()`；
    `PipelineRunner.run()` 在每阶段前后检查停止并落 `status="stopped"`（区别于 `failed`）；
    `run_task` 负责注册/注销事件、异常时按 `ctx.stopped()` 判定终态。
    `stages/{subdomain,probe,dirscan,vulnscan}.py` 各在循环边界加 `ctx.stopped()` 检查。
12. **`gui/app.py`**：新增 `_spawn()`；`/tasks` 传入 `counts` 与 `running`；
    新增 `/tasks/<id>/export`（Markdown 下载）、`/api/tasks/<id>/stop|delete|restart`、
    `/api/tasks/bulk`（stop|delete|restart，返回 `affected/skipped`）；
    `/settings` POST 扩展为写 `limits.wildcard_filter` / `checks` / `passive` / `evasion` 四段。
13. **GUI 模板**：`settings.html` 重写为 5 个面板（检测策略 / 按 OWASP 分类开关 / 按检查项开关 /
    动态免杀 / 信息收集 + 扫描限制 + 控制台）——即用户要的"**按分类的大功能开关**"；
    `tasks.html` 重写（多条件筛选 + 全选 + 批量条 + 10 列宽表 + 行内 5 个操作）；
    `task_detail.html` 重写（**6 个页签：潜在漏洞(默认) / 站点 / 子域名 / 目录 / 目标与配置 / 运行日志**，
    工具栏加停止/重启/导出/删除）。
14. **`gui/static/app.js`**：新增 `initSevFilter()` / `taskOp()` / `bindTaskOps()` / `selectedTaskIds()` /
    `initTaskTable()`（筛选 + 勾选 + 批量 + 行内操作 + 状态轮询并对按钮做 disabled 联动）；
    `initFilters()` 加 `dataset.bound` 守卫防重复绑定；DOMContentLoaded 去掉旧 `.stage` 轮询。
15. **`gui/static/style.css`**：补 `.st-stopped` / `.btn-mini` / `.ops` / `.pick` / `.evidence`
    （旧版只有 4 个状态色、没有行内小按钮与 evidence 列宽约束）。
16. **全局文案「疑似问题」→「潜在漏洞」**：`scanner/report.py`（4 处）、`cli/client.py`、
    `gui/templates/dashboard.html`（2 处）、`vulnscan` 日志。
17. **`run_gui.py` / `gui/app.py`**：新增 `serve()` 统一启动入口，并在 `app.run()` 之前做
    **端口占用预检**（`_port_free()` 真实 bind 一次）。原因是一个**实测复现的真实缺陷**：
    Windows 上 Werkzeug 对监听套接字设了 `SO_REUSEADDR`，端口已被占用时第二个实例会
    **绑定成功**并照样打印 `Running on http://127.0.0.1:5000`，但浏览器打不开页面
    ——这就是项目里记录过的"控制台静默失败"。现在改为明确报错并 `exit 1`：
    `[!] 启动失败：127.0.0.1:5000 已被占用（…）` + 处理建议。

### 验证

- `py -3 tests/smoke.py` → **SMOKE PASS**，其中新增断言：默认门槛下 `a02-no-https` **不出现**、
  门槛放到 `info` 后出现、关闭 A02 分类后 `a02-*` 全部消失、`poc_engine=False` 时只剩内置检查、
  取消信号置位后流水线落 `status=stopped`、导出接口返回"潜在漏洞"、批量 stop 计入 `skipped`、
  批量 delete 真正清库。
- `engine.load_all_meta()` → `total 312 ok 312 bad 0`（7 内置 + 305 导入）。
- 参考项目导入器：341 脚本 → 305 YAML（抽样人工核对 `360__finger.yaml`、`Weblogic__console_CVE_2019_2618.yaml`
  关键字已无字典键噪声）。
- GUI 端到端：`py -3 run_gui.py` 起服务后 `GET /login` → 200；再起第二个实例 →
  端口预检生效（打印占用提示、退出码 1，**不再出现"假启动"**）；
  `POST /settings` 带全套字段往返校验通过，且 `tools` / `dicts` 段**未被 GUI 覆盖**（测完已还原配置文件）。

### 明确未做（保持诚实，避免下个 AI 误判）

- **P0-2 ~ P0-5 / P1-1 ~ P1-4 / P2-2 服务端分页 / P2-3 Linux 实机验证 / P3-1 ~ P3-3 未动**。
- 泛解析过滤**没有**实现 CNAME 维度；被动收集**没有**接入任何需要 API key 的源（属 P0-5）。
- 导入的 305 条 POC 是"路径 + 关键字"启发式判定，**误报率天然偏高**，默认关闭是刻意的设计而非遗漏。

## 2026-09-21 —— 第三轮：参考项目调研（myscan）+ GUI 外壳重构（侧边栏/顶栏/页签）

### 背景（用户本轮要求）

① 读参考项目 `C:\Users\材料\Desktop\tools\scan\myscan_20250825`，**借鉴优秀且不重复的设计，并可批判选优**；
② 用户已确认的与尚未处理的条目**要保留**，**间接处理的要标注**；
③ 强调实用性 / 便捷性 / 可视化 / 清晰度，**框架主体设计失败可以大改**；
④ 参考其提供的两张 GUI 截图（"资产灯塔系统"）重排界面分布；
⑤ 要具备渗透思维 / 流程化思维 / 发散思维。

### 变更（代码）

1. **GUI 外壳重构：顶部横向 nav → 左侧固定侧边栏 + 顶栏**（对齐用户给的参考图）
   - `gui/templates/base.html` 重写：侧边栏 8 项（内联 SVG 图标 + active 高亮）、
     顶栏复用 `{% block title %}`（Jinja `self.title()`）、新增 `{% block actions %}`（页面级状态/按钮条）。
   - `gui/static/style.css` 重写外壳：新增 `.layout/.sidebar/.side-nav/.side-item/.sidebar-foot`、
     `.main/.topbar/.crumb`、`.toolbar`、`.filters`（grid 自适应）、`.bulkbar`、
     `button.ghost/.danger`、`.tabs/.tab/.tabpane`；**去掉 `main` 的 `max-width:1180px` 居中**
     （宽表场景下 1180px 会挤压列宽）；`@media (max-width:900px)` 侧边栏收窄到 150px。
   - **保留**全部原有组件类（badge/st-/sev-/bar/cards/panel/table/pre/login-box），下拉回归风险最小。
2. **任务详情页改为横向页签**（对齐参考图的任务详情形态）
   - `gui/templates/task_detail.html` 重写：站点 / 子域名 / 目录 / 疑似问题 / 运行日志 5 个页签
     （`data-tab` + `id="pane-xxx"`）；实时状态（`st-badge`/`st-stage`/`st-progress`）移到 `{% block actions %}`；
     每个页签内嵌 `<input data-filter="#tbl-xxx">` 前端筛选框。
   - 页签只做**已有数据源**的 5 个；参考图的另外 8 个页签（IP/SSL证书/服务/文件泄露/URL信息/
     C段/nuclei/指纹统计/WIH）**故意不做空占位**，理由与依赖关系写入 `TODO.md` B-7。
3. **前端通用筛选** `gui/static/app.js` 新增 `initTabs()` 与 `initFilters()`，
   并在 `DOMContentLoaded` 中优先调用；`initFilters` 支持任意 `<input data-filter="#tbl-x">`
   （整行文本包含匹配），已挂到任务/站点/子域名/目录/漏洞 5 张表。
4. **各页面模板标题迁移**：`dashboard/tasks/vulns/pocs/settings/subdomains/sites/dirs` 的 `<h1>`
   改为 `{% block title %}`（顶栏/浏览器标题共用），未破坏 `login.html`（独立页，不继承 base）。

### 变更（文档）

5. **`TODO.md` 新增「参考项目借鉴清单（批判选优）」**：分 A 采纳/已借鉴、B 批判（8 条明确不采纳及理由）、
   C 保留与标注三节；新增 **P0-6 泛解析过滤**、**P1-4 IP→域名反查（C 段）**、**P2-4 任务停止/删除/重启**
   三个**读参考项目发现的真实缺口**；P2-2 改为 `[~]`（前端筛选已完成、服务端分页仍缺）。
6. **`AGENTS.md` / `docs/usage.md` 同步** GUI 新形态（侧边栏 + 顶栏 + 页签 + 筛选）。
7. **收编 `todo.txt` 中此前未被任何文档记录的要求**：文件末尾那段"太low的洞不要开启 /
   只关注高位严重 / 注入要动态绕 WAF / UA 随机性 / 大功能要有按分类的开关菜单"
   （原文照留并追加状态行），拆分收录为 **P0-7 检测分级门控（低危默认关闭 + 分类开关面板）**
   与 **P0-8 动态绕 WAF / UA 随机化**。**本轮只收录，代码未动。**
8. **GUI 宽表溢出修复（视觉复验收尾）**：
   浏览器复验发现 `task_detail` 的宽表把**整个页面**撑出横向滚动条、表头被压成两行（"状/态"）。
   改动 `gui/static/style.css` 两处：`.panel, main > section` 加 `overflow-x:auto`
   （宽表在面板内滚动）、`th` 加 `white-space:nowrap`（表头不折行）。纯 CSS，无模板改动。

### 关键调研结论（省下个 AI 重复劳动）

- 参考项目 `spider/thirdLib/*` 有 **11 个免 key 子域数据源**可直接用于 P0-1
  （crt.sh / alienvault / certspotter / hackertarget / rapiddns / sublist3r / myssl / entrust /
  ce.baidu / bufferover / sitedossier）——已列进 TODO.md A 节。
- 参考项目**没有** AK/SK 挖掘逻辑（全库 grep 仅 4 处命中，且都是 DES 工具与指纹关键字）
  → 我们的 P0-3 属原创项，无现成参考。
- 参考项目 `conf/myscan.yaml` **明文存真实 key（含 github PAT）**，属安全事故，只借鉴"单文件集中"结构。
- 参考项目存在**未完成代码**：`core/utils/differ.py::DifferentChecker` 的 `__main__` 段引用了不存在的
  `MyDifflib`（类名实为 `DifferentChecker`），运行即 `NameError`；不得照搬。

### 验证

```powershell
py -3 tests/smoke.py
# → [1] targets ok / [2] pocs ok: 7 loaded / [3] pipeline ok: sites=1 tech=python vulns=6 /
#   [4] report ok / [5] gui routes ok / SMOKE PASS
# 真实 HTTP（端口 5055，登录后）：
# login page: 1 | crumb/title: ['仪表盘 - CTFScanner'] | aside: True | sideitems: 8 | active: 1
# tabs: 5 | tabpanes: 5 | pane-sites: True | filters: 4 | verify_tls field: True
# codes: [('/',200),('/tasks',200),('/subdomains',200),('/sites',200),('/dirs',200),('/vulns',200),('/pocs',200),('/settings',200)]
```

浏览器视觉复验（子代理，视口约 537px 宽 —— 比 1440px 更严苛）：

```
# PASS 登录/跳转、仪表盘、侧边栏 8 项(带图标+active 高亮)、顶栏(admin/修改口令/退出)
# PASS 任务列表、任务详情 5 页签（点击「子域名」「运行日志」实际切换成功、无 JS 报错）、资产页筛选框
# CSS 修复后：documentElement.scrollWidth == clientWidth == 537 → 无整页横向滚动条；
#             .panel 计算样式 overflow-x:auto；th 计算样式 white-space:nowrap
# 未覆盖（下轮可补）：800x600 窄屏三重复查、漏洞风险页截图
```

### 重要提醒（接手时必读）

- 本轮**仍然没有实施任何 P0 子域名扫描增强**——P0-1~P0-8 全部原样保留，等你确认排期。
- 改 GUI 的验证必须**先杀占用端口的旧进程**（见上一条目"重要提醒"，本轮再次踩到）。

## 2026-09-21 —— 第二轮：GUI 资产分栏扩展 + 任务确认清单

### 背景（用户本轮要求）

① 完成项要在 `todo.txt` 里标 `[完成]`；② 生成一份**任务确认清单**（P0 = 子域名扫描，
第三方 API key 另设专门配置文件，属"回头单独搞"）；③ 检查 GUI 并指出分栏不足；
④ 要兼容 Linux 与 Windows。

### 变更

1. **GUI 分栏 5 → 8**（用户反馈"分栏还不够多"，对齐 ARL 的资产视图）
   - `gui/templates/base.html` 导航新增：子域名 / 站点 / 目录。
   - `gui/app.py` 新增路由 `/subdomains`、`/sites`、`/dirs`（均 `@login_required`）。
   - 新增模板 `gui/templates/subdomains.html`、`sites.html`、`dirs.html`（跨任务资产视图）。
   - `scanner/db.py` 新增全局查询 `list_all_subdomains/list_all_sites/list_all_dirs(limit=500)`
     （原 `list_*` 都是按 task_id 过滤的，资产分栏需要跨任务视图）。
2. **`todo.txt` 状态标记**：首行加状态约定，并给各条打标 —— `#2 [完成]`、
   `#4 [部分完成：内置指纹已接入，指纹→POC 联动待做]`、接管提示词整体 `[完成]`，其余 `[待办]`。
3. **新增 `TODO.md` 任务确认清单**：P0 子域名扫描（多来源被动收集 / 子域接管检测 /
   JS 资产挖掘+黑名单+AKSK 降噪 / CIDR 展开 / API key 专用配置文件）；
   P1 指纹→POC 联动、端口扫描阶段、统一 `owasp` 字段格式；P2 GUI 筛选分页、跨平台；
   P3 ico+fofa、实时漏洞、启发式 0day（依赖外部能力或检测层成熟度，明确标注不建议现在做）。
4. **跨平台核查**：grep 实测现有代码已基本合规（pathlib、`shell=False` 列表 argv、
   `pick_python` 处理 Windows `python` / Linux `python3`、显式 UTF-8、`shutil.which`）；
   剩余待补为"端口占用清晰报错"与 Linux 实机验收，已写入 TODO.md P2-3。

### 验证

```powershell
py -3 tests/smoke.py            # SMOKE PASS（含新增 3 个资产路由断言）
# 真实 HTTP：起服务 → 登录 → 8 个页面全 200
# nav = 仪表盘 任务 子域名 站点 目录 漏洞 POC 设置 退出
```

### 重要提醒（接手时必读）

- **端口 5000 若已有旧 GUI 进程在跑，新代码不会生效**：本轮实测 `run_gui.py` 因端口被占用
  （当时占用进程 PID 18360）静默退出，请求全打到旧进程，导致新路由返回 404。
  改完 GUI 必须**先杀旧进程再起服务**，否则会误判"代码没生效"。
- 本轮**未**实施任何 P0 子域名扫描增强，等待你在 `TODO.md` 上确认排期。

## 2026-09-21 —— 项目接管：缺陷修复 + 指纹补全 + 测试自包含

接管环境：Python 3.9（`py -3`），外部工具全缺（走内置兜底），无 git 仓库。

### 背景 / 判断依据（先读实际代码）

- 通读 README / docs/*、scanner/*、cli、gui、tests 后确认：流水线、POC 引擎、OWASP 检查、
  CLI 与 GUI 均已可跑通，`tests/smoke.py` 在靶场在线时 **PASS**。项目是**可用的框架骨架**，
  不是半成品。
- 因此本轮**不新增路线图功能**，只做「真实缺陷修复 + 补全已有半成品 + 补测试门禁 + 交接文档」。

### 变更

1. **修复 `limits.verify_tls` 配置无效（死配置）**
   - 现象：`config/settings.yaml` 与 `config.DEFAULTS` 都声明了 `limits.verify_tls`，但
     `utils.http_request` 的 `verify` 形参硬编码默认 `False`，全代码库无人读取该配置 → 打开开关无效。
   - 改动：`utils.http_request(..., verify=None, ...)`，`verify is None` 时读
     `settings["limits"]["verify_tls"]`（默认 False）。默认行为不变（CTF 自签名证书场景仍不校验）。
   - 文件：`scanner/utils.py`；文档：`docs/pipeline.md` 配置速查补一行。

2. **补全内置指纹识别（`sites.tech` 半成品）**
   - 现象：`sites` 表有 `tech` 列，httpx 适配器会填，但**内置兜底路径恒为空字符串**，
     且任何页面都没展示该列 → 离线（当前唯一可用模式）下技术栈数据实际缺失。
   - 改动：新增 `scanner/fingerprint.py`（`SIGNATURES` 规则表 + `identify(resp) -> [tag]`，
     从响应头/正文识别 nginx/php/tomcat/python/spring/wordpress 等标签，只给标签不解析版本）；
     `stages/probe.py` 内置探测用它填充 `tech`；`gui/templates/task_detail.html` 存活站点表新增「技术栈」列。
   - 理由：直接支撑「指纹扫描」这一既定方向，且复用既有 `tech` 列与探测流程，不改架构。
   - 文件：`scanner/fingerprint.py`(新)、`scanner/stages/probe.py`、`gui/templates/task_detail.html`、
     `scanner/report.py`（报告存活站点表同步增加「技术栈」列）；
     文档：README 目录树与能力边界、`docs/pipeline.md` probe 降级说明、`docs/architecture.md` 决策表。

3. **测试门禁自包含（修复测试缺口）**
   - 现象：`tests/smoke.py` 依赖「外部先起好 127.0.0.1:8765」——服务器不在时 probe 得 0 站点，
     报 `AssertionError: []`，看起来像代码坏了（接管过程中实际踩到）。
   - 改动：`tests/smoke.py` 用 `ThreadingHTTPServer` 在后台线程自带靶场（`smoke_root/`，
     `atexit` 关闭；端口被占用则复用外部服务），并静默其请求日志；新增指纹断言
     （内置探测须识别出 `python`）。
   - 文件：`tests/smoke.py`。

4. **文档与代码漂移修正**
   - README「11 项 OWASP 启发式」→ **12 项**（`owasp/checks.py` 实际注册 12 个 @check，以代码为准）。

5. **交接文档**
   - 新增 `AGENTS.md`（项目速览、真实运行环境、架构不变量、验证方式、已知局限与坑）。
   - 新增本文件 `CHANGELOG_AI.md`。

### 验证

```powershell
py -3 tests/smoke.py
# → [1] targets ok / [2] pocs ok: 7 loaded / [3] pipeline ok: sites=1 tech=python vulns=6 /
#   [4] report ok / [5] gui routes ok / SMOKE PASS
py -3 cli/client.py -t http://127.0.0.1:8765/ -p subdomain,probe,dirscan,vulnscan --offline
# → 全阶段跑通：站点 1 / 目录 2 / 疑似问题 6
```

### 记录在案、本轮**未**修的问题（避免误以为已解决）

- POC 引擎不支持关闭重定向、无 extractor / payload 池 / 多请求串联（`docs/roadmap.md` 有候选）。
- `owasp` 字段两套格式（`owasp-a01` vs `A01`）未统一。
- `config/dicts/sensitive.txt` 仍未被读取（内置检查用硬编码清单）。
- `limits.brute_max_domains`、`tools.dirmap.python` 等配置 GUI 设置页不暴露（需手改 settings.yaml）。