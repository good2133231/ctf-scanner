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

界面外壳为**左侧固定侧边栏（10 栏导航）+ 顶栏（当前页名 + 退出）**；任务详情页内部为**横向页签**，
页签内表格上方都有**前端筛选框**（按整行文本实时过滤，无需回车）。

1. **仪表盘**：任务/子域名/站点/潜在漏洞/POC 总量，最近任务与最近潜在漏洞；
2. **任务管理**：
   - 「新建扫描任务」：填任务名 → 目标文本框逐行填写，或上传 .txt 目标文件（二选一或同时，自动合并）→ 勾选阶段 → 需要时可勾「离线模式」→ 提交；
   - 任务列表实时轮询状态与进度条；表头支持**多条件筛选**（任务名/目标/状态/阶段），可**全选勾选**后执行**批量停止 / 批量重启 / 批量删除**；
   - 每行提供**行内操作**：查看 / 停止 / 重启 / 导出（下载该任务 Markdown 报告）/ 删除；点击任务号进入详情；
   - 停止为**协作式取消**（当前批次跑完即停），任务终态记为 `stopped`（区别于 `failed`）；
3. **任务详情**：顶部为任务名与实时状态（状态徽标/当前阶段/进度，运行中每 2 秒刷新），
   下方为 **8 个横向页签 —— 潜在漏洞（默认）/ 站点 / 子域名 / 端口服务 / C 段 / 目录 / 目标与配置 / 运行日志**，
   每个页签内可先筛选再查看（潜在漏洞的 evidence 可展开；日志页签显示尾部）；
   > 页签数量是**按数据源实有**的：IP、SSL 证书、文件泄露、nuclei、WIH 等页签要等
   > 证书解析 / 爬虫数据模型等数据源落地后才会加，不先做空占位（见 `TODO.md` B-7）。
4. **子域名资产**：全库子域名资产（跨任务，含 CNAME 链与来源标记）；
5. **站点资产**：全库存活站点（跨任务，含状态/标题/技术栈/Server/favicon MD5）；
6. **端口服务**：全库端口与服务资产（跨任务；由 `portscan` 阶段产出，该阶段默认关闭）；
7. **C 段视野**：按 `/24` 归纳的 IP 视野（跨任务；由 `osint` 阶段的 C 段反查产出，该阶段默认关闭）——
   每行是一个 IP 及其反查到的域名。同段主机常属同一套业务，是找旁路的常见起点；
8. **目录发现**：全库目录发现结果（跨任务）；
9. **漏洞风险**：全库漏洞列表，按 critical/high/medium/low/info 过滤；
10. **POC 管理**：上传 YAML POC（落到 `config/pocs-user/`）、逐个启停、**按「来源 × 级别」批量开关**
   （来源分内置 / 导入（参考项目转换）/ nuclei / 用户），并有「来源」列与「只看已启用」筛选；
   语法错误的 POC 会标 `error`，含 `raw`/`dsl`/`flow`/`workflows` 等不支持特性的模板会标
   `unsupported` 并显示原因；
11. **策略配置**：由 7 个面板组成 ——
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
     并发 / 黑 ico 阈值）—— **两项默认关闭**，且**都关时整个 `osint` 阶段一次请求都不发**。
     接口地址留空即用默认的 `api.webscan.cc`；FOFA 的 email/key 不在这里填（见 `config/keys.yaml`）；
   - **资产面拓展 / 信息收集 / 扫描限制 / 控制台**：子域接管、**目录/路径发现**
     （`dirscan.enabled`，默认开；取消勾选＝整阶段跳过）、JS 挖掘、端口服务这几类的开关与上限，
     泛解析过滤与多来源被动收集，并发/超时/证书校验/站点上限，监听地址与口令。
     外部工具路径、字典路径与 `passive.sources` 来源清单请直接编辑 `config/settings.yaml`；
     **第三方 API key 写入 `config/keys.yaml`**（独立文件，控制台只读不改写）。

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

**Q：「C 段视野」一直是空的？**
该页数据来自 `osint` 阶段的 C 段反查，而 `iprecon.enabled` **默认关闭**（走第三方公共接口
`api.webscan.cc`，可用性不由我们掌控）。打开路径：「策略配置 → 外部情报拓展」，打开后**只对新任务生效**。
另外私有地址（`10.` / `192.168.` / `127.` 等）会被直接跳过 —— 反查公共接口对它们没有意义。

**Q：favicon 反查（FOFA）怎么开？**
①把 fofa 的 email/key 填进 `config/keys.yaml`（**不是** `settings.yaml`，控制台不写回凭据）；
②「策略配置 → 外部情报拓展」打开 `fofa.enabled`。
命中数超过「黑 ico 阈值」（默认 200）的 favicon 会被判定为**公共图标**（默认页/通用框架图标）
并放弃拓展 —— 否则一次查询会把大量无关资产灌进来。
未填 key 时日志会写明「未配置 fofa.email / fofa.key（见 config/keys.yaml）」，不会静默失败。

**Q：结果在哪？**
SQLite：`data/scanner.db`；每任务文件产物：`logs/task_<id>_<时间>/`；报告：`--report` 指定路径。
