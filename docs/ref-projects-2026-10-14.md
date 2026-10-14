# 参考项目调研（2026-10-14，主理人点单：四个项目完整读码）

> 委托方背景：ctf-scanner 是**不依托 AI、纯代码执行**的资产测绘与漏洞初筛框架（13 阶段流水线、
> Flask 控制台 + CLI、SQLite、POC 引擎 + OWASP 内置检查、非破坏性）。因此本调研只取
> **离开 AI 仍成立的纯工程**；AI 编排部分一律标"不借鉴"。
> 实施者：WorkBuddy · CodeBuddy。仓库快照 clone 于 `/tmp/ref-projects/`（仓库外，不入 git）。
> 精读覆盖声明：shuize 读主文件全流程 + 收集源清单 + 4 个代表模块；artex 读 README 全文 +
> agent/server/guard/evidence/report 目录清单 + guard/constraints/retester 三文件精读；
> strikeagent 读后端目录 + 2 个 SKILL 精读；7scanai 全读（体量小）。

## 总览

| 项目 | 体量 | 语言/形态 | AI 依赖 | 一句话定性 |
|---|---|---|---|---|
| ShuiZe_0x727 | 206 个 py，主文件 1654 行 | Python 单入口 + Plugins | 零 AI，纯工程 | 经典"一条龙"信息收集，插件式收集源最丰富 |
| ARTEX | Go 后端 + Next.js 前端 | Go 模块化 | 重度 AI（LLM 编排是主体） | AI 自主渗透系统；纯工程精华在 guard/约束/复测三态 |
| StrikeAgent（AtkBrain） | 123 py + 前端 + skills | Python 后端 + Claude Skills 方法论 | 重度 AI | Agent 编排 + 红队方法论 prompt 化 |
| 7scanAI | 仅 4 个 py | SKILL.md + pipeline 文档 | 100% AI | 不是可运行框架，是"给 AI 的作业指导书" |

## 一、ShuiZe_0x727（最值得借鉴的仓库）

**架构**：`ShuiZe.py`（1654 行）if/elif 大分支（domain / C段 / File / masscan 结果 / fofaTitle /
domainFile）→ `run_subdomain()` 等；每个收集源一个目录 + `run_xxx()` + `saveToExcel`；
Queue+Thread；**无阶段框架、无断点续跑、无 GUI、无请求预算**。架构成熟度低于 ctf-scanner
（我们的 runner/StageContext/协作式取消/SQLite 台账全面更强）。

**发现强度（它有我们没有的收集源）**：
- `Plugins/infoGather/subdomain/hostCollide/` —— **host 碰撞**：同 IP 绑不同 Host 头找出隐藏站点；
- `subdomain/beian2NewDomain/` —— **ICP 备案反查新域名**（`ShuiZe.py::beian2NewDomain`，返回关联公司名 → 喂给爱企查）；
- `subdomain/Aiqicha/` —— **爱企查企业架构**（自有 ICP / 投资 / 控股 / 分支四类信息）；
- `ParamSpider/` —— 动态参数链接收集（`run_ParamLinks`，>1000 条自动丢弃并明说）；
- `checkPanAnalysis()` —— 泛解析探测（ctf-scanner 已有 wildcard_filter，同功能）；
- `getSocksProxy()` —— 从 FOFA 收集可用 socks 代理（内网场景）。
- 如实记录：`ShuiZe.py::dnsZoneTransfer` 是 **pass 空壳**——声明未实现，完成度没有 README 那么满。

**强壮度**：普遍裸 `except: pass` 风格、无预算、全局变量传状态、optparse 旧库——弱于我们。
**便捷性**：docker 一键（build.sh / docker_build.sh）+ tqdm 彩色 CLI 输出（`tqdm.write` 打在进度条上方）值得学。

## 二、ARTEX（纯工程精华：guard / 约束 / 复测三态）

**架构**：`agent/` 全是 LLM 编排（planner/mainagent/prompt/compaction/blackboard/session）——
**整体不借鉴**。纯工程可取三件：

1. **`guard/guard.go`（安全边界层）**：每次工具调用过 PreToolUse/PostToolUse 钩子；
   `AuditEntry{ts,tool,action:allow|block,reason,command}` 把**每一条被拦截的动作**审计条目化；
   破坏性门控**不硬编码在 guard 里**，而是作为 DB 种子的"[内置] 拦截规则"——用户可禁用/删除但默认生效；
   另有失败归因计数（Observer/G5）。→ 对应我们：blacklist/三道闸已有拦截与日志，但拦截动作
   是日志行不是结构化审计条目——补一张结构化拦截审计是真实提升。
2. **`agent/constraints.go`（操作约束）**：allow/deny 双清单；语义表述极佳——
   "**发现约束之外的新目标/新端口/新主机，不等于获得授权：记为 out-of-scope 事实并跳过，
   不得为其派生意图或执行动作**"。这正是我们 `extdom.auto_expand_block` 三道闸的语义，
   文案范式可直接抄进 reason 文本与文档。
3. **`agent/retester.go`（漏洞复测三态）**：`reproduced / fixed / inconclusive`——
   "一次请求失败或未命中不能证明已修复；证据不足 = inconclusive 并写清阻塞原因"。
   → 我们复核台账只有 confirmed/false_positive 两态；**加「无法确认」第三态**是功能完整度的真实提升
   （复核时"试了但环境不满足"有地方落，且不会污染"已确认"的语义）。

**强壮度**：Go 类型系统 + 全模块 `_test.go`，工程化最高；但绑定 LLM，剥离 AI 剩不下运行时。
**便捷性**：docker compose 一键 + 在线 Demo（纯前端 Mock 数据，无需后端）——Demo 站形态值得学。

## 三、StrikeAgent / AtkBrain（圈层化扫描预算思想）

**架构**：`backend/atkbrain`（agents/api/engine/exec/graph/memory/llm_gateway/decoy_web/
entry_fingerprint）+ `skills/`（方法论文档）+ `tools/`（JSFinder、bypass-403 等封装）+ compose。
纯 AI Agent 驱动，主体不借鉴。

**纯工程可借鉴点**：`skills/recon-spiral/SKILL.md` 的**三圈螺旋**——
第 1 圈 top-100 端口 + dirb common.txt 小字典；第 2 圈 top-1000 + medium；第 3 圈 `-p-` 全端口 +
递归 fuzz；**升圈判据 = 连续 6 轮无高质量产出**（有增长就留在当前圈；info/service/danger 不算增长）；
禁止嵌套子代理防失控。→ 我们已有的对应物：`devmode.DEV_LIMITS`（静态限额）与
`screenshot.retry_rounds`；可借鉴的是**"按产出质量决定是否加码预算"的动态限额思想**
——这正是"多任务并发按机器规格与产出动态调整"（主理人 2026-10-14 点单）的设计参照。

## 四、7scanAI（几乎无可运行代码）

本质是 Claude/Codex skill 包：SKILL.md + `references/pipeline/{02 子域,04 端口,06 漏洞,08 利用,
full-workflow}.md` + 4 个脚本。亮点仅一个：**产物路径强制锁定表**（每个工具输出强制写
`targets/<domain>/<tool>_subdomains/<tool>.txt`，"禁止自创子目录、禁止别名，任一文件不在此表即违规"）
——与我们"logs/ 按确切文件名清理、判据唯一产地"是同一种纪律，无需引入。八阶段流程与
我们 13 阶段同构且更粗。**结论：没有可借鉴的运行时代码。**

## 借鉴汇总（按主理人要求的维度）

| 维度 | 结论 |
|---|---|
| 架构 | 四家无一优于我们的阶段编排（runner/StageContext/协作式取消）；ShuiZe 验证了"插件式收集源目录"形态（我们 stages/ 已是） |
| 功能完整度 | ShuiZe 的 4 个收集源我们没有：**host 碰撞、ICP 备案反查、爱企查企业关联、参数链接收集**（均纯工程可落地） |
| 发现强度 | 我们 POC 引擎 + 14 内置检查强于 ShuiZe（它靠外部 Nuclei）；ARTEX 复测三态是"发现之后"的补强方向 |
| 强壮度 | 我们最高（请求预算/协作式取消/断点续跑/去重口径/审计）；ShuiZe 最弱（裸 except、无预算） |
| 可迁移性 | 7scanAI 最高（纯文档）；我们 .venv 不可搬是已知项；ARTEX docker 化最好 |
| 便捷性 | ShuiZe docker 一键、ARTEX Mock Demo 站、tqdm 彩色 CLI 输出值得学 |
| **优先级** | ① 复测"无法确认"第三态（小）② host 碰撞（中）③ ICP 备案反查（中）④ 拦截动作结构化审计（小）⑤ 动态并发档（中，含基准实测） |

**明确不借鉴**：所有 LLM 编排（ARTEX agent/、StrikeAgent backend 主体、7scanAI 全部）、
ShuiZe 的裸异常风格与全局变量传状态、ARTEX 的 RoE 机制（其源码注释自述已删除待补）。
