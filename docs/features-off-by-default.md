# 已实现、但没有默认开启的功能

> 主理人点单：「整理『写了功能但没默认开启』的清单」（续271）。
> 本文只描述**配置事实**。判定用三档值，门禁 `[271]` 把这张表与配置钉在一起 ——
> 配置变了表没变 ⇒ 红；表里的行与配置对不上 ⇒ 红；把"默认已开"的段写进「没默认开」的表 ⇒ 红。

## 怎么读这三档

| 档 | 产地 | 含义 |
| --- | --- | --- |
| 代码默认 | `scanner/config.py` 的 `DEFAULTS` | 出厂值。干净克隆、**没有** `config/settings.yaml` 时就是它 |
| 随包 | `config/settings.yaml` | 仓库随包分发的覆盖层 |
| 生效 | `config.load_settings()` 的返回值 | 实际跑起来的那个值 |

⚠ 两件事经常被混为一谈，这里**分开成两张表**：

- **表一**：两处都是 `False` ⇒ 真·没默认开，不打开就一行产出都没有；
- **表二**：随包 `true` 而代码默认 `False` ⇒ **其实是开着的**，只是"开在文件层"。
  这么放是有意的：代码层守住"没填 key 就不该发请求"（见门禁 `[8bq]`）。

## 一、两处都关（真·没默认开，9 项）

| 功能 | 段（配置键） | 代码默认 | 随包 | 生效 | 为什么没默认开 | 怎么开 | 要什么 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| TLS 证书取证（只读握手取颁发者/有效期/CN/SAN/指纹，进「SSL 证书」页签） | `cert` | False | False | False | 可选取证：每个 https 站点多一次握手，会让探测变重 | 策略配置 → `cert.enabled`（页面开关 `cert_enabled`） | 无（纯标准库；握手**不校验证书** —— 自签名/过期正是要看的） |
| 站点截图（无头浏览器，站点页缩略图） | `screenshot` | False | False | False | 要本机 Chrome/Edge 无头模式，慢且依赖外部二进制与系统库 | 策略配置 → `screenshot.enabled`；`browser` 留空＝自动探测 | 本机浏览器（**续298 起标准安装即取一份进 `tools/browser/`**，或系统的 Chrome/Edge）+ 系统共享库（libnss3 / libgbm / libatk 等）+ 中文字体（同样默认即装） |
| 备案反查（同主体域名） | `icp` | False | False | False | 源按次计费/限流；预置的工信部源在国内托管，海外出口通常不可达 | 策略配置 → `icp.enabled` + `sources` 里给可达的源 | 可能要 `api_key`（只进 `config/keys.enc.yaml`，不落明文） |
| 360 Quake 的 favicon 反查（同源资产） | `quake` | False | False | False | 外部付费接口、要 key | 策略配置 → `quake.enabled` + `config/keys.yaml` 的 `quake.key` | key |
| Shodan 的 favicon 反查 | `shodan` | False | False | False | 同上；且"任何外部接口都不该在用户没点头时产生流量" | 策略配置 → `shodan.enabled` + `shodan.key` | key |
| A10 SSRF 受控回连（任务内起本机监听，把 `http://<回调>/<token>` 喂给候选参数） | `ssrf` | False | False | False | **只在目标能回访扫描机时才有效** —— NAT / 云主机场景大概率一条都收不到；且要在本机起监听 | 策略配置 → `ssrf.enabled` + 回调基址 | 目标侧能出网、且能访问到扫描机的端口 |
| 开发模式（把各阶段的"量"压到 1，只验流程跑不跑得通） | `dev` | False | False | False | 它不是"能力"，是自检模式；开着会让真实扫描几乎不出量 | 策略配置 → `dev.enabled` / CLI `--dev` | 无 |
| 边缘认证门（401 门） | `gui.edge_auth` | False | False | False | 它是**部署开关**不是能力 —— 只有把控制台绑到 `0.0.0.0` 时才需要；刻意不给环境变量覆盖，免得"随手一设"就变了 | 策略配置 / `config/settings.yaml` 的 `gui.edge_auth.enabled` | 无（配合 HTTPS 才有意义；**不替代登录**） |
| 报告导出（MD / JSONL / HTML；PDF 已于续297 移除） | `report` | False | False | False | 续171 主理人点单"默认关闭" | 策略配置 → 报告导出 | PDF 还要本机无头浏览器 |

## 二、随包开、代码默认关（其实是开着的，7 项）

| 功能 | 段（配置键） | 代码默认 | 随包 | 生效 | 备注 |
| --- | --- | --- | --- | --- | --- |
| CT 日志查询（crt.sh） | `ctlog` | False | True | True | 免 key，但属外部接口 ⇒ 代码层默认关 |
| FOFA favicon 反查 | `fofa` | False | True | True | 需 `fofa.email` / `fofa.key`；代码默认 False 是为了"没 key 就不发请求" |
| GitHub 泄露检索（只落元数据，绝不落文件内容） | `github` | False | True | True | 需 `github.token` |
| 启发式线索（本地差分，不发任何请求） | `heuristic` | False | True | True | 只产 `leads` 表线索，不写 `vulns` |
| 漏洞情报（CISA KEV，免 key） | `intel` | False | True | True | 只产线索，不计入漏洞数、不自动导入 POC |
| C 段反查（webscan.cc 公共接口） | `iprecon` | False | True | True | 第三方公共接口，可用性无保障 |
| 多平台公开代码检索（grepapp，免 key） | `multileak` | False | True | True | 边界与 `github` 同源 |

⚠ **"开关开着"≠"一定有产出"**：`fofa` / `github` 这两家没填凭据时，阶段会**因缺 key 跳过并说明**，
不会静默假装扫过。

## 三、不是 `enabled` 开关、但默认也不走的那几条路

| 能力 | 默认值 | 怎么打开 | 说明 |
| --- | --- | --- | --- |
| 全端口扫描（1-65535） | `portscan.mode: top`（只打 20 个常见 web 端口） | 单任务触发：任务详情「端口」页签的「全端口扫描（1-65535）」/ CLI `--portscan-full` | 续250 起全端口不再默认跑；端口扫描本身**续269 起默认开** |
| 截图失败候补轮 | `screenshot.retry_rounds`：代码默认 0 / 随包 1 | `config/settings.yaml` | 随包比代码多给一轮 |
| banner 的朴素贝叶斯服务识别 | `portscan.ml_service: false` | 策略配置 | 需 `data/ml/service_model.json`，没模型不动 |
| 漏洞级别门槛 | `checks.min_severity`：代码默认 `medium` / 随包 `high` | 策略配置 | 随包更严（只报 high 及以上） |
| subfinder / puredns / httpx | 未安装 ⇒ 内置兜底 | CLI `--update-tools` / GUI「外部工具」页 | 装了才走工具；**能力不缺**，差别在快与全 |
| dirmap / fscan / nmap | 有就用、没有就回退内置 | 同上 | 目录深扫优先 dirmap；端口优先 fscan → nmap → 内置 |

## 维护

- 这张表的**事实来源是配置本身**，不是抄来的：改了任何默认值，请同步这张表。
- 门禁 `[271]` 三条判据：① 表一/表二点名的段与配置逐条对上；② 默认**已开**的段（如
  `portscan` / `hostcollide`）不许出现在表一；③ 变异（摘掉表一里任意一行）⇒ 判据立刻红。
