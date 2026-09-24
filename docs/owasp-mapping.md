# OWASP Top 10（2021）覆盖映射

客观声明：下表是**黑盒自动化可以覆盖的部分**。凡依赖业务上下文、登录态或需要利用验证的类别，本框架不做自动判定或仅给极弱信号——这是刻意的取舍，避免把"高误报的自动结论"交给使用者。

| 类别 | 内置检查（check id） | 实现方式 | 局限 / 说明 |
|---|---|---|---|
| A01 失效的访问控制 | a01-directory-listing | 首页特征匹配目录列表 | 仅覆盖默认开启列表的场景 |
| | a01-sensitive-files | 探测 /.git/config、/.env、/.svn/entries、/WEB-INF/web.xml、/backup.sql 等，内容签名确认 | **路径与签名都来自数据文件 `config/dicts/sensitive.txt`**（`路径 \| 关键字 \| 级别 \| 说明`，可直接加条目）；签名必填，故纯 200 不误报；文件缺失/无有效行时回退内置清单 |
| | a01-open-redirect | 常见跳转参数 + 外部域，校验 3xx Location | 覆盖参数名有限，需人工确认 |
| A02 加密机制失效 | a02-no-https | 明文 HTTP 判定 | — |
| | a02-cookie-flags | Set-Cookie 缺少 HttpOnly/Secure | requests 合并重复响应头，多 Cookie 时解析为近似值 |
| A03 注入 | a03-sqli-error | 常见参数注入单引号，匹配数据库报错特征（带 payload 变形绕 WAF） | 仅报错回显型 |
| | a03-sqli-blind | **布尔型盲注**：同一参数发"恒真/恒假"两个 payload，比状态码与响应长度；恒真再发一次做稳定性复验（排除页面抖动） | 只做布尔差分；**明确不做 `SLEEP`/`BENCHMARK`/`WAITFOR` 延时型**（会挂住目标数据库连接线程＝事实上的 DoS，且跨公网抖动会盖过时间差）。每参数 3 个请求，总预算 12 |
| | a03-xss-reflect | 常见参数注入标记串 + 上下文探针，判**回显上下文**（文本节点/双引号属性/单引号属性/无引号属性/JS 字符串/JS 代码/标签名/HTML 注释）并按上下文定级 | 级别随上下文：JS 串·JS 代码·无引号属性·标签名＝high；引号属性·文本节点＝medium（文本节点要求 `<` 未被转义）；HTML 注释＝降级为 low。**全转义的回显一律不报** |
| A04 不安全设计 | — | 不自动化 | 需要业务建模，黑盒无法可靠判定 |
| A05 安全配置错误 | a05-security-headers | CSP/X-Content-Type-Options/X-Frame-Options/HSTS 缺失检查 | 信息级，非漏洞 |
| | a05-banner-disclosure | Server/X-Powered-By 带版本 | 信息级 |
| | a05-default-pages | phpinfo、server-status 等默认页 | — |
| | （另见 POC） | actuator/tomcat manager/swagger 等 | POC 库承担更多配置错误类检测 |
| A06 自带缺陷的组件 | a06-legacy-banner | 版本特征匹配（PHP5/Tomcat7/Apache2.2/Struts…） | 仅横幅层面；精确版本核查交给人工/POC |
| A07 认证与身份失败 | — | 不自动化（避免口令爆破） | 弱口令检测建议用专用工具在授权范围内进行 |
| A08 软件与数据完整性失效 | a08-missing-sri | 外部脚本缺 integrity 属性 | 信息级，仅 CDN 供应链风险信号 |
| A09 日志与监控失效 | — | 不自动化 | 属于工程流程问题，非黑盒可测 |
| A10 SSRF | a10-ssrf-callback | **受控回连**（默认关，`ssrf.enabled`）：任务内起本机 HTTP 监听，每参数唯一 token，把 `http://<回调基址>/<token>` 注入候选参数；收到该 token 的访问即判"目标服务端会发起出网请求" | 只证明"**会出网**"，**刻意不拿这个通道去打内网地址**（那是利用，越线）、不提交表单、不做延时判定。只在目标能回访扫描机时有效（NAT/云主机大概率收不到）；外部回调基址（`ssrf.callback_base`）模式下读不到命中 → 只注入不报，不伪造 |

## 与 POC 库的分工

- `scanner/owasp/checks.py`：**通用、低噪**的基线检查，对任何站点都会跑；
- `scanner/pocs/pocs/*.yaml`：**具体组件/场景**的定向检测（actuator、swagger、tomcat manager…），可由用户无限扩充。

两者结果统一写入 `vulns` 表，字段 `poc_id` 区分来源，`owasp` 字段标注类别。

## 分级门控（默认屏蔽低危噪声）

检查结果受 `checks` 段**三级门控**（GUI「策略配置」页可改）：

- **执行级 `skip_severities`**：默认 `["info","low"]`。列在这里的级别**连请求都不发**——内置检查与
  POC 引擎同规则（`config.skip_severities()` 是唯一判定入口）。因此下表里 14 项内置检查**默认只有
  7 项真正执行**，`a02-no-https`、`a02-cookie-flags`、`a05-security-headers`、`a05-banner-disclosure`、
  `a05-default-pages`、`a06-legacy-banner`、`a08-missing-sri` 这 7 项直接不跑。
  （那 7 项里的 `a10-ssrf-callback` 另有 `ssrf.enabled` 总开关且**默认关**，关着时一次请求都不发。）
- **结果级 `min_severity`**：默认 `medium`，只保留 `severity >= medium` 的结果——即使上面的执行门被
  放宽（清空 `skip_severities`），低危/info 结果仍默认不产出。CTF 实战里它们只会淹没注入/RCE 类
  的高位结果。需要广谱信息收集时，两个开关要**一起**放宽（取消勾选 info/low，并把门槛改成 `low`/`info`）。
  POC 命中结果同样受该门槛过滤（critical 恒保留）。
- **检查项级 `disabled_categories` / `disabled_checks`**：命中的 OWASP 分类（如 `["A05","A08"]`）或
  具体 check id（如 `["a01-open-redirect"]`）**根本不执行**，可省下请求；配置项见 `config/settings.yaml`。
- `checks.poc_engine` 是 POC 引擎总开关，关闭后只跑内置启发式检查。

## 误报与人工确认

- 所有检查本质是信号而非结论，统一以「潜在漏洞」展示；
- 所有 findings 都在 GUI 漏洞页展示 `detail` 与 `evidence`（响应片段），人工确认时以此为起点；
- 报告（Markdown）中固定附带"需人工验证"提示。
