# 使用手册

## CLI 客户端

```bash
python cli/client.py -f <目标文件> [选项]
python cli/client.py -t <单目标> [选项]
```

### 参数

| 参数 | 说明 |
|---|---|
| `-f, --file PATH` | 目标文件：每行一个 域名/URL/IP，`#` 开头为注释 |
| `-t, --target` | 单目标，可重复 `-t a.com -t http://b.local/` |
| `-n, --name` | 任务名（默认取文件名或 cli-task） |
| `-p, --stages` | 逗号分隔的阶段：`subdomain,takeover,portscan,probe,osint,jsmine,dirscan,vulnscan`（默认全部；`takeover`/`jsmine`/`dirscan`/`vulnscan`/`portscan`/`osint` 另受策略级开关约束，见下） |
| `--offline` | 离线模式：不调用 subfinder/puredns/httpx/dirmap，仅内置实现 |
| `--report PATH` | 扫描结束后生成 Markdown 报告 |
| `--check` | 打印外部工具可用性并退出 |

### 示例

```bash
# 完整流水线（推荐先 --check 确认外部工具）
python cli/client.py -f targets.txt -n recon-0921 --report logs/report.md

# 只做探测 + 漏洞初筛（URL 直达，跳过子域名）
python cli/client.py -t http://target.local/ -p probe,vulnscan

# 裸机演示：完全离线
python cli/client.py -f targets.txt --offline
```

### 典型输出

```
[*] 任务 #1 开始：recon-0921（阶段：subdomain,takeover,portscan,probe,osint,jsmine,dirscan,vulnscan）
===== 阶段 1/8：subdomain =====
[subdomain] subfinder 不可用，改用内置多来源被动收集 …
[passive] crt.sh → 12 个（example.com）
[passive] example.com 汇总 15 个（5/6 个源有响应）
[subdomain] puredns 不可用，回退内置 DNS 爆破（系统解析器）
[subdomain] 新增子域名 3 个，参与探测主机 4 个
...
===== 阶段 8/8：vulnscan =====
[vulnscan] 目标 2 个；级别门槛 medium；启用 POC 7 个；内置检查 5/12 项；info/low 级检测已跳过（连请求都不发）
[vulnscan] 潜在漏洞 6 项（high:2 / medium:4），均为初筛结果，需人工确认
===== 流水线完成 =====
[*] 任务 #1 结束：status=done
    子域名 3 | 站点 2 | 目录 17 | 潜在漏洞 6
    日志：logs\task_1_...\task.log
```

> `内置检查 5/12 项` 是**执行级门控**的结果：`checks.skip_severities`（默认 `["info","low"]`）
> 里的级别连请求都不发，因此 12 项内置检查里只有 5 项真正执行。

> 用 `--offline` 时不调用外部工具、也不跑被动收集（仅内置 DNS 爆破）；被动来源不可用只影响该源，不影响整轮。

## Web 控制台（GUI）

```bash
python run_gui.py          # 默认 http://127.0.0.1:5000
```

口令在 `config/settings.yaml` 的 `gui.token`（默认 `ctfscanner`）。

### 页面与操作流

界面外壳为**左侧固定侧边栏（8 栏导航）+ 顶栏（当前页名 + 退出）**；任务详情页内部为**横向页签**，
页签内表格上方都有**前端筛选框**（按整行文本实时过滤，无需回车）。

> 侧边栏只保留**资产总览级**入口（仪表盘 / 任务 / 子域名 / 拓展域名 / 站点 / 漏洞 / POC / 策略）。
> 原「端口服务」「C 段视野」「目录发现」三栏已移除 —— 它们是**任务维度**的数据，
> 在任务详情页签里本来就能看到，单开全局栏反而让人脱离上下文。
> 数据与路由都还在（`/ports`、`/csegs`、`/dirs` 可直接访问 URL），只是不再占侧边栏。

1. **仪表盘**：任务/子域名/站点/潜在漏洞/POC 总量，最近任务与最近潜在漏洞；
2. **任务管理**：
   - 「新建扫描任务」：填任务名 → 目标文本框逐行填写，或上传 .txt 目标文件（二选一或同时，自动合并）→ 勾选阶段 → 需要时可勾「离线模式」→ 提交；
   - 任务列表实时轮询状态与进度条；表头支持**多条件筛选**（任务名/目标/状态/阶段），可**全选勾选**后执行**批量停止 / 批量重启 / 批量删除**；
   - 每行提供**行内操作**：查看 / 停止 / 重启 / 导出（下载该任务 Markdown 报告）/ 删除；点击任务号进入详情；
   - 停止为**协作式取消**（当前批次跑完即停），任务终态记为 `stopped`（区别于 `failed`）；
   - **删除（单个或批量）前会自动备份**：任务行 + 其全部资产（站点/子域名/端口/C 段/目录/漏洞）
     导出为 `data/trash/task_<id>_<时间>.json`，误删可直接从该文件找回。备份失败只告警不阻断删除；
3. **任务详情**：顶部为任务名与实时状态（状态徽标/当前阶段/进度，运行中每 2 秒刷新），
   下方为 **8 个横向页签 —— 潜在漏洞（默认）/ 站点 / 子域名 / 端口服务 / C 段 / 目录 / 目标与配置 / 运行日志**，
   每个页签内可先筛选再查看（潜在漏洞的 evidence 可展开；日志页签显示尾部）；
   > 页签数量是**按数据源实有**的：IP、SSL 证书、文件泄露、nuclei、WIH 等页签要等
   > 证书解析 / 爬虫数据模型等数据源落地后才会加，不先做空占位（见 `TODO.md` B-7）。
4. **子域名资产**：**只显示目标自身**的子域名（来源为 subfinder / `passive:*` / puredns / `dns-brute`），
   每行含 CNAME 链、**解析 IP**、**CDN 标记**与来源；页顶可一键切「全部 / CDN / 非 CDN」。
   来源列显示的是**可读标签**（`被动(subfinder)` / `被动(crt.sh)` / `爆破(puredns)` / `爆破(内置)`），
   不再是 `passive:crt.sh` 这种内部写法。
   每行左侧可勾选，页面顶部两个按钮对勾选行生效：**加入黑名单**、**批量跑子域名（新建任务）**；
   JS 与外部情报带出来的关联域名**不在此页**（见下一栏）；
5. **拓展域名**：从 JS 挖掘（`js:mine`）与外部情报（`osint:cseg` C 段反查 / `osint:fofa` FOFA·ICO 反查 /
   `osint:fofa-cert` FOFA·证书反查 / `osint:fofa-title` FOFA·标题反查）带出来的**关联域名**，
   列/筛选/勾选操作同「子域名资产」（来源列带 **FOFA** 字样，一眼能看出哪些是 FOFA 找出来的）。
   末列「**敏感**」显示该域名下 JS 挖到的疑似凭据条数（`js-secret-*`，详见「漏洞风险」页）。这些域名**未必属于目标**，
   独立成页是为了避免误判资产归属。
   **按来源分类浏览与排序**（`?src=`）：页顶「来源分类」按钮组可只看某一类，默认列表也按
   **JS 挖掘 → FOFA·标题反查 → FOFA·证书反查 → FOFA·ICO 反查 → C 段反查** 的顺序排列
   （同类内新的在前），不会把几种来源夹在一起。
   **默认隐藏重叠资产**：某个域名若已作为「目标自身子域名」出现在任意任务里（域名级全局判重），
   说明它早就在资产清单里，这里不再重复列出；页顶开关「显示全部（含重叠）」可放开（`?all=1`）；
   勾选行后既能**批量加入黑名单**，也能**批量跑子域名**——后者新建任务的名称默认按当前分类生成，
   形如 `fofa标题拓展-0922-1530`（未选分类时用 `拓展域名-…`）；
6. **站点资产**：全库存活站点（跨任务，含状态/标题/技术栈/Server/favicon MD5）；
   **默认隐藏重复站点**，同一个开关管两层口径：
   - **重叠资产（跨任务）**：同一 URL 在多个任务里都探到过时，只保留**最新一次扫描**的那条 ——
     站点行带的是当次扫描的状态码/标题/长度/技术栈，留最旧那条等于一直看陈旧数据；
     反复扫同一个目标时列表也不会再被撑成 N 倍；
   - **同任务内重复**：「标题 + 响应长度」完全相同的多条视为同一虚拟主机的别名/泛解析产物，
     只留首个，被折叠的行标注「另有 N 条相同」。

   页顶开关「显示全部（含重叠）」可同时放开两层（`?all=1`）。
   注意折叠键带 `task_id`：跨任务视图下不同任务的同名同长度站点**不会**被互相折叠；
7. **全端口扫描**：**按任务分布**看端口资产（主机 × 任务视角：任务名 / 主机 / IP / 开放端口数 / 端口列表），
   勾选主机 → 点「发起全端口扫描」即可对某个 IP 补一次 `1-65535`。
   它新建一个**只跑 portscan 阶段**的任务（与「批量跑子域名」同一套做法：一任务一线程、
   可独立停止/删除），任务选项 `portscan_full` 让它**无视全局 `portscan.enabled`** 也会执行，
   并自动跳过该任务已扫过的端口 —— 因此不会把全局策略改慢。注意 6.5 万端口逐连接，
   耗时以分钟计，只对真需要补全的 IP 用；
8. **漏洞风险**：全库潜在漏洞，可按 **critical/high/medium/low/info 级别**筛选，
   列表带**任务名列**（点击直达该任务详情），页顶还可**按任务下拉过滤**（`?task_id=`）；
9. **POC 管理**：上传 YAML POC（落到 `config/pocs-user/`）、逐个启停、**按「来源 × 级别」批量开关**
   （来源分内置 / 导入（参考项目转换）/ nuclei / 用户），并有「来源」列与「只看已启用」筛选；
   语法错误的 POC 会标 `error`，含 `raw`/`dsl`/`flow`/`workflows` 等不支持特性的模板会标
   `unsupported` 并显示原因。**路径列展示相对项目根的路径**（如 `config/pocs-user/x.yaml`），
   不暴露本机绝对目录；
10. **策略配置**：由 **8 个面板**组成，**面板默认全部折叠**（一屏几百个勾选框实在难找）——
   点面板标题栏即可展开/收起，页顶有「全部展开 / 全部折叠」；展开状态记在浏览器 localStorage，
   刷新后保持。面板列表：
   - **检测策略**：最低报告级别（`min_severity`，默认 medium）+ **漏洞初筛阶段总开关**
     （`vulnscan.enabled`，默认开；取消勾选＝整个 vulnscan 阶段跳过，适合"只做资产测绘"）+
     POC 引擎总开关 + 指纹→POC 联动；
   - **按级别分类批量开关**：`skip_severities`（默认勾掉 info 与 low）—— **勾上＝该级别连请求都不发**，
     内置检查与 POC 引擎同时生效。这是"太 low 的洞暂时不开"的实现方式：它们的结论本来就会被
     `min_severity` 丢掉，不执行纯属省请求；
   - **按 OWASP 分类开关**：A01~A10 整类关闭（`disabled_categories`，被关闭的分类根本不执行）；
   - **按检查项细粒度开关**：逐个 check id 关闭（`disabled_checks`），被级别门跳过的项会标注；
   - **动态免杀**：UA 随机化 / XFF 伪装 / payload 变形开关与绕过强度（bypass_level 0~3）/ WAF 探测；
   - **外部情报拓展（OSINT）**：`iprecon`（C 段反查开关 / 接口地址 / IP 上限 / 主机上限 /
     单 IP 域名上限 / 并发 / 超时）与 `fofa`（favicon 反查开关 / 站点上限 / 资产上限 /
     并发 / 黑 ico 阈值 / **证书反查子开关 `cert_enabled`** / **通用证书阈值 `cert_threshold`** /
     **每任务最多查几个注册域 `max_cert_queries`** / **标题反查子开关 `title_enabled`** /
     **公共标题阈值 `title_threshold`** / **每任务最多查几个标题 `max_title_queries`**）—— **默认关闭**，且 iprecon 与 fofa
     都关时整个 `osint` 阶段一次请求都不发。接口地址留空即用默认的 `api.webscan.cc`；
     FOFA 的 email/key 不在这里填（见 `config/keys.yaml`）；
   - **用户黑名单**：显示黑名单文件路径（**相对路径**）、总开关与**当前条目列表**，
     可勾选条目后点「移除勾选条目」。文件是纯文本 `config/blacklist.txt`，也可直接手工编辑；
   - **资产面拓展 / 信息收集 / 扫描限制 / 控制台**：子域接管、**目录/路径发现**
     （`dirscan.enabled`，**默认关**；打开后可选大字典 `dirscan.big_dict`（15333 条）与
     单站点条数上限 `dirscan.max_paths`（默认 400））、JS 挖掘、端口服务这几类的开关与上限，
     （端口服务含**端口范围** `portscan.mode`（top / full 全端口）、`portscan.full_ports`、
     `portscan.exclude_scanned` 跳过已扫端口）
     泛解析过滤与多来源被动收集，并发/超时/证书校验/站点上限，监听地址与口令。
     子域名阶段的 **IP/CDN 回填**上限（`subdomain.max_resolve`，默认 500 个）与 DNS 超时
     （`subdomain.dns_timeout`）也在这一组；超上限的子域名仍会入资产表，只是没有 IP/CDN 两列。
     外部工具路径、字典路径与 `passive.sources` 来源清单请直接编辑 `config/settings.yaml`
     （CDN 厂商后缀名单在 `config/dicts/cdn_cname.txt` —— 找不到 CNAME 后缀就一律判为「非 CDN」）；
     **第三方 API key 写入 `config/keys.yaml`**（独立文件，控制台只读不改写）。

### 黑名单与批量操作

- **黑名单语义是"命中即不入资产库"**：写入 `config/blacklist.txt`（一行一个域名，`#` 注释，
  `*.example.com` 与 `example.com` 等价）后，命中的域名**连它的所有子域**都不会进资产表 ——
  因此后续 dirscan / vulnscan 自然也不会去扫它。文件每次调用都重读，改完立即生效；
- 批量加入的入口在「子域名资产」与「拓展域名」页：**勾选行 → 点「加入黑名单」**；
- **批量跑子域名**：同样是勾选行 → 点「批量跑子域名（新建任务）」。它会把勾选的域名
  打包成**一个新任务**（任务名默认 `批量子域-<月日>-<时分秒>`，阶段固定只有 `subdomain`），
  跑完回到该任务详情页看结果。之所以新建任务而不是在当前任务下挂子任务：现有任务模型
  （一任务一线程、独立状态与独立停止/删除）可以直接复用，挂子任务要改表结构、任务树渲染、
  状态聚合与递归停止 —— 收益只是 UI 好看一点。

### 全端口扫描 / 目录扫描 / dirmap

- **全端口扫描**：入口在侧栏「全端口扫描」页（勾选主机 → 发起），它新建一个只跑 portscan 的任务，
  不动全局策略；想让它成为默认行为才去「策略配置 → 端口范围」改成 `full`。
  自动跳过该任务已扫过的端口（`portscan.exclude_scanned`）；
- **目录扫描**：默认关闭。打开后默认用 **15333 条大字典**（`config/dicts/dirs_big.txt`），
  单站点最多扫 `dirscan.max_paths`（默认 400）条；**只对不重复站点**跑（同任务内标题+长度相同的
  别名站跳过）；结果按**响应大小**折叠重复长度（`/dirs` 页「显示全部」可放开），列表展示返回包大小。
  重新生成大字典：`py -3 tools/import_dir_dict.py`（源：`tools/dirmap/data/dict_load/dict_mode_dict.txt`）；
- **dirmap**：本机用**目录联接**把它挂到 `tools/dirmap/`（第三方项目不随仓库分发，`.gitignore` 已排除），
  `dirscan` 阶段会自动优先调用它（`tools.dirmap.script`，默认 `tools/dirmap/dirmap.py`）；
  找不到就回退内置字典扫描。它的产物在 `output/<域名>/` 下，我们只读 `res.txt` / `403.txt`
  且**只读本次运行写过的文件**（`output/` 是持久目录，否则会读到上次的残留）。

## 跨平台（Linux 部署要点）

代码层无 Windows 专属逻辑：路径全部走 `pathlib`，外部命令走 `subprocess` 列表参数 + `shutil.which`，文件读写显式 UTF-8。Linux 上只需注意：

```bash
# 依赖装在 venv 里，避免污染系统 Python
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python3 run_gui.py
```

- **工具版本**：subfinder/httpx/puredns 下载 `linux_amd64` 包；dirmap 是纯 Python，clone 即用；
- **解释器名**：多数发行版只有 `python3` 没有 `python`。dirmap 配置项若不调整，框架会自动退回当前解释器（`utils.pick_python`），无需手动改；
- **对外访问**：默认 `gui.host: 127.0.0.1` 仅本机可访问；部署在服务器上给团队用时把 settings.yaml 的 host 改 `0.0.0.0` 并改掉默认口令——但控制台无 CSRF/HTTPS 加固，务必放在内网或套反代认证，不要直接暴露公网；
- **权限**：不需要 root；工具放 `~/bin` 并加入 PATH 即可；
- **常驻运行**：测试可用 `nohup python3 run_gui.py &`，正式使用建议 systemd（`Restart=on-failure`）或 tmux。

## 常见问题

**Q：提示工具不可用？**
跑 `python cli/client.py --check`。要么把工具加入 PATH，要么在 settings.yaml 写路径；不装也能跑（内置兜底），但效果打折。

**Q：Windows 下 puredns / subfinder？**
均为 Go 程序，官方 release 有 exe；puredns 依赖 resolvers 文件，框架已自带。

**Q：控制台乱码 / 端口占用？**
端口在 settings.yaml `gui.port` 修改；控制台仅建议本机访问，不要暴露公网（无 CSRF/HTTPS 加固）。

**Q：扫内网大段 C 类？**
CIDR 已支持展开：`10.0.0.0/30` 会展开为可用主机逐条进入流水线；但**上限 256 个地址**，
超过（如 `10.0.0.0/16`）会被整体丢弃并在解析阶段提示，避免误扫整个网段。
大段扫描建议仍先用 nmap 导出存活主机列表再导入。

**Q：为什么结果里看不到"明文 HTTP""安全响应头缺失"这类项了？**
这是刻意的默认取向。`checks.skip_severities`（默认 `["info","low"]`）让这些级别**连请求都不发**，
`checks.min_severity`（默认 medium）再兜一层结果过滤 —— CTF 实战里它们拿不到 flag。
需要广谱信息收集时，在「策略配置」取消这两个级别的勾选，并把最低报告级别改成 `low`/`info`。

**Q：「C 段视野」一直是空的？**（该页已不在侧边栏，改到任务详情「C 段」页签看，或直接访问 `/csegs`）
该数据来自 `osint` 阶段的 C 段反查，而 `iprecon.enabled` **默认关闭**（走第三方公共接口
`api.webscan.cc`，可用性不由我们掌控）。打开路径：「策略配置 → 外部情报拓展」，打开后**只对新任务生效**。
另外私有地址（`10.` / `192.168.` / `127.` 等）会被直接跳过 —— 反查公共接口对它们没有意义。

**Q：favicon 反查（FOFA）怎么开？**
①把 fofa 的 email/key 填进 `config/keys.yaml`（**不是** `settings.yaml`，控制台不写回凭据）；
②「策略配置 → 外部情报拓展」打开 `fofa.enabled`。
命中数超过「黑 ico 阈值」（默认 200）的 favicon 会被判定为**公共图标**（默认页/通用框架图标）
并放弃拓展 —— 否则一次查询会把大量无关资产灌进来。
未填 key 时日志会写明「未配置 fofa.email / fofa.key（见 config/keys.yaml）」，不会静默失败。

**Q：站点标题是乱码（中文变 `????` / `Ã¤Â¸Â`）？**
已修复。根因是部分服务器返回 `Content-Type: text/html` 却**不带 `charset`**，而 requests 在缺省时
按 HTTP 规范回退到 ISO-8859-1，中文页面遂被解错码。现在 `scanner/utils.py` 统一走 `_decode_body()`：
**响应头 charset → UTF-8 → GB18030 → 带替换的 UTF-8** 依次尝试，`requests` 与 `urllib` 两条路径都生效。
若老库里有乱码标题，删掉对应任务重扫即可（框架不回填历史数据）。

**Q：为什么能扫出 `http://www.xiangce.com:9007` 这种非标端口站点？**
因为 `probe` 阶段现在会**消费 `portscan` 阶段的开放端口**：除 80/443 外，portscan 发现的其他开放端口
会补出 `https://host:port`、`http://host:port` 两种候选再探测。所以想扫全非标端口，需要**同时打开
`portscan` 阶段**（默认关，「策略配置 → 资产面拓展」）。只跑默认阶段时 probe 仍只探 80/443。

**Q：「子域名资产」和「拓展域名」有什么区别？**
前者只放**目标自身**的子域名（被动收集 / 字典爆破产出）；后者放 JS 挖掘与外部情报（C 段、favicon）
**带出来的关联域名**，这些域名不一定属于目标。分开是为了不误判资产归属。

**Q：站点页条数比实际少？**
默认**折叠重复站点**：同一任务内「标题 + 响应长度」完全相同的多条只留首个，其余标记「另有 N 条相同」。
页顶切「显示全部」（`?all=1`）即看全量。折叠键包含 `task_id`，不同任务的相同站点不会被互相折叠。

**Q：误删了任务还能找回吗？**
能。删除（单个或批量）前框架会自动把**任务行 + 全部资产**导出为
`data/trash/task_<id>_<时间>.json`，直接打开即可看到完整内容（站点/子域名/端口/C 段/目录/漏洞）。
但它是**删除那一刻**的快照，且 `data/` 不参与 git —— 别拿它当异地备份。

**Q：结果在哪？**
SQLite：`data/scanner.db`；每任务文件产物：`logs/task_<id>_<时间>/`；报告：`--report` 指定路径。

**Q：加了黑名单，为什么资产库里那些域名还在？**
黑名单是**入库前的过滤器**，不是清理工具：只影响**之后**的扫描（命中的域名不入库，因此
dirscan/vulnscan 也不会扫它）。已经入库的历史资产不会被自动删除 —— 需要的话在任务列表里删掉
对应任务（删除前会自动备份到 `data/trash/`）。

**Q：「拓展域名」/「站点资产」条数比预期少？**
两页都**默认隐藏重叠资产**：拓展域名页隐藏"已作为目标自身子域名出现过"的域名（域名级全局判重）；
站点页隐藏"更早任务已探到过的同一 URL"以及同任务内标题+长度完全相同的重复行。
页顶开关「显示全部（含重叠）」即看全量（`?all=1`）。

**Q：改代码时控制台/测试正在跑，会不会互相影响？**
数据面已经隔离，可以放心并行：
- 真实库是 `data/scanner.db`、任务产物在 `logs/task_*`；**`tests/smoke.py` 跑之前会把两者都指到
  `logs/smoke-<随机>/` 下的临时副本**（通过环境变量 `CTFSCANNER_DB` / `CTFSCANNER_LOGS`），
  跑完自动删除 —— 测试不会再往真实任务库里写数据，也不会在 `logs/` 里堆目录；
- 两个环境变量本身也可用于"开发/生产共用一份代码、数据分开"：
  例如 `CTFSCANNER_DB=D:\ctf-dev\dev.db CTFSCANNER_LOGS=D:\ctf-dev\logs python run_gui.py`；
- **代码热更新不生效**：Flask 以 `debug=False` 运行（刻意关掉 reloader），改完模板/代码必须
  重启控制台；端口被占用时启动会直接报错退出（不会"假启动"），所以先杀掉旧进程。
  另外只有一个 GUI 进程时不存在端口冲突；SQLite 是单写者，**多任务并发写**时偶发
  `database is locked` 已被超时重试兜住，但不建议同时跑几十个任务。
