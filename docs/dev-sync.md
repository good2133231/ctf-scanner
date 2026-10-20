# 本地 ↔ 服务器 开发同步（续237）

一句话：**GitHub 是唯一事实源；代码与 AI 记忆走 git 同步；运行态（数据库/日志/密钥）永远只在服务器上。**

## 三个角色

| 角色 | 放什么 | 说明 |
|---|---|---|
| **GitHub（main）** | 代码 + AI 记忆 + 文档 | 唯一事实源。`main` 始终是"最后通过门禁的状态" |
| **服务器（SSH 那台）** | 代码 + `.venv` + **真实数据库** `data/scanner.db` + `logs/` + 密钥 | **门禁执行者**：正式收尾的全量 SMOKE 在这里跑；GUI 4 个实例也在这里 |
| **本地电脑** | 代码副本 + AI 记忆副本 | 只做**编辑**；可以跑部分门禁，收尾门禁在服务器跑 |

**git 不跟踪**（各自机器各自有，互相同步是错的）：`data/`、`logs/`、`.venv/`、`config/keys*.yaml`、
`config/settings.json`、`config/edge_auth.yaml`。`config/settings.yaml` **被跟踪**（里面没有口令）。

## 每轮标准流程

### A. 在本地开发（新增）
> **本地一次性准备**：`git clone` 后 `python -m venv .venv`；
> **Windows** 用 `.venv\Scripts\pip install -r requirements.txt`（`bin/` 是 Linux/macOS 路径，
> 这就是"`\'.venv\' 不是内部或外部命令\'"报错的来源）；跑门禁用
> `.venv\Scripts\python tests/smoke.py`。没有 Chrome 时浏览器 E2E 组会红——留给服务器跑即可。


```
1. git pull --rebase origin main          # 开工前先拿最新（含服务器上刚完成的轮次）
1b. python tools/sync_check.py --strict   # 开工三查之一：脏区/未推送/未拉取必须全 0
2. 读一遍 AGENTS.md（协作规矩）+ todo.txt 顶部"下一轮"清单
3. 做一轮工作（轮号 = 上一轮 + 1，全局连续，不按机器分）
4. 写齐三份记忆：CHANGELOG_AI.md（本轮小节）/ todo.txt（顶部小节）/ AGENTS.md（若有新规矩）
5. 本地能跑多少跑多少：py_compile + 定向断言；**浏览器 E2E 需要本机装 Chrome，跑不了就留给服务器**
6. git add … && git commit && git push origin main
```

### B. 服务器接手（收尾门禁 + 上线）

```
1. python tools/sync_check.py --strict   # 服务器开工三查：脏区/未推送必须先清零
   （先于 pull：若服务器有未提交改动，pull --rebase 会拒绝，正好逼你先处理）
1b. git pull --rebase origin main
2. .venv/bin/python -m py_compile <本轮改过的 .py>     # 快速冒烟
3. .venv/bin/python tests/smoke.py                     # 正式收尾门禁（约 7 分钟）
   - 若本地已跑过且全绿，服务器这次是"落地复核"；红了就在服务器上继续修（沿用同一轮号）
4. 重启 GUI：四个端口直接启动即可，端口被旧进程占着会被 portguard 自动接管
   CTFSCANNER_GUI_PORT=5000/5001/5002/5011 nohup ./.venv/bin/python run_gui.py >> logs/gui-5000.log …
5. 看 logs/gui-*.log 确认：3 个 worker、无 Traceback
```

### C. 服务器开发（现状不变）

照旧：一轮 = 记忆同步 → 全量 SMOKE PASS → commit → push。本地定期 `git pull` 保持副本不落后。

## 硬规矩（本地 AI 与服务器 AI 同守）

1. **一轮只在一台机器上做**。中途必须换机器时：把记忆写完整（让接手方看得懂）、push，
   接手方 pull 后**沿用同号**继续，不允许重开一轮号；
2. **记忆先于门禁**：`[8as]` 会校验 max续(CHANGELOG) == max续(todo.txt)，先跑门禁后写记忆必红；
3. **轮号全局连续**，不按机器、不按 AI 重置；
4. **改任何"出厂值登记"型的断言要显式改**（表单计数、出厂 workers 等——它们红是故意的）；
5. **混合行尾文件**（.py/.html/.yaml 多为 CRLF，部分为 LF）编辑时保持原行尾；
   push 前用两式 numstat 自查：`git diff --numstat` vs `git diff --ignore-cr-at-eol --numstat` 逐文件相等；
6. **不把真实目标域名写进任何被跟踪的文件**（聊天里可以说，仓库里不行）；
7. **本地永远不用真实数据库**（`data/scanner.db` 只在服务器）；测试一律 `CTFSCANNER_DB=<临时文件>`。
8. **服务器收尾时工作区必须归零**：每轮结束 `git status --short` 必须为空——
   未提交的"顺手热修"就是"GitHub 没同步完、本地拉了再改坏"的唯一来源（续238 实测抓到一次）；
   体检命令：`python tools/sync_check.py --strict`。
9. **禁止裸 `git reset --hard`**：只在 `git status` 为空且 `sync_check` 显示 0 未推/0 未拉时，
   才允许用它把本地副本对齐 origin；有未提交改动时它会销毁唯一副本。

## 冲突处理

- 两边都动了同一文件 → `git pull --rebase` 报冲突时：**记忆文件以轮号大的一方为准**，
  代码合并以功能为准；解完重跑门禁再 push；
- 长时间不拉的本地副本：`git fetch origin && git log HEAD..origin/main --oneline` 先看差多少，
  落后超过 10 轮建议直接 `git reset --hard origin/main`（本地没有未推工作时的最干净解）。

## 验证同步是否成功

- 服务器：`git log --oneline -3` 应看到本地刚推的提交；重启后页面行为变化可见；
- 本地：`git log --oneline -3` 与 GitHub 网页一致即同步成功。

## 提示词

给本地 AI 的开场提示词已单独放在 **`docs/local-ai-prompt.md`**——新开会话时整段粘贴即可。
