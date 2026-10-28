# 本地 ↔ 服务器 开发同步（续237）

> **入口文档是仓库根目录的 [`本地开发.md`](../本地开发.md)**（触发语「你是本地开发」）——
> 本文是它的完整版：角色/流程在这里，摘要与三句命令在那边。两边讲同一件事，别讲漏。

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
> **本地一次性准备**：`git clone` 后 `python dev.py setup` —— Windows / Linux / macOS
> 同一条命令（`dev.py` 会建 `.venv` 并装依赖，路径差异由它吃掉；此前手写
> `.venv/bin/pip` 在 Windows 报"不是内部或外部命令"就是踩了这个）。
> 跑门禁：`python dev.py smoke`（没有 Chrome 时浏览器 E2E 组会红——留给服务器跑即可）。


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

## 服务器整机迁移（续291，2026-10-28）

> 适用：换服务器 / 重建机器。GitHub 仍是**代码与记忆**的唯一事实源；
> **运行态（数据库 / 密钥 / 工具 / 日志）永远不进 git**。下面按「必搬 / 可重建 / 验证」三段走。

### 必搬（不搬会丢数据、丢凭据或会话失效）

| 路径 | 说明 | 注意 |
|---|---|---|
| `data/scanner.db` | 真实任务 / 资产 / 漏洞库 | 停服务后做 **SQLite 一致性备份**再搬（`sqlite3 .backup`），不要直接拷运行中的 `-wal/-shm` |
| `config/keys.enc.yaml` | 第三方 API key 密文（0600） | 与口令分开搬运；口令走 `CTFSCANNER_KEYS_PASSPHRASE` 或 `~/.secrets/keys-pass`（0600） |
| `config/edge_auth.yaml` | 边缘认证口令（若启用） | 明文文件，0600；未启用可忽略 |
| `data/session.secret` | 登录会话签名密钥 | 不搬 ⇒ 所有用户重新登录（功能不受影响） |
| 仓库外 `alias-map-141.json` | AGENTS §0.5 脱敏别名表（若使用） | **绝不入库**；按 AGENTS §0.5 单独安全搬运 |
| 仓库外 git 凭据助手 | AGENTS §2 的 `credential.helper`（若使用） | 不在仓库；按 §2 口径处理，别把令牌写进仓库 |

### 可重建（不搬也能跑，只是慢 / 需联网）

- `.venv/`、`tools/`（含 scanner 二进制、fscan、dirmap、Go、浏览器）、`.cache/`：新机跑
  `./install.sh --full` 重建（需要网络；massdns 需 gcc/make，fscan 需 Go，Chrome/Go 走工作目录内组件）。
  离线或同架构可整目录搬以省时间。
- `logs/`：只是历史证据，不迁移；新机自动新建。
- `data/trash/`、`data/intel/`、`data/import-inbox/`：历史备份 / 缓存 / 导入素材，可选。
- `data/preview.db`：预览用，可重建。

### 新机步骤

```
1. git clone https://github.com/good2133231/ctf-scanner.git && cd ctf-scanner
2. python3 tools/sync_check.py --strict        # 干净克隆应为 0 脏 / 0 未推 / 0 未拉
3. ./install.sh --full                         # 标准安装 + 工作目录内运行时组件 + 编译层
   # 只要最小可用：./install.sh
   #   + python tools/setup_dirmap.py --install
   #   + python tools/build_fscan.py --fetch --wire
4. 停旧服务 → 搬「必搬」清单 → 新机 chmod 600 config/keys.enc.yaml（及其他密文）
5. 起服务（§B）：CTFSCANNER_GUI_PORT=5000 nohup ./.venv/bin/python run_gui.py >> logs/gui-5000.log 2>&1 &
6. 验证：./.venv/bin/python tests/smoke.py 看到 SMOKE PASS；登录后看
   · 旧库任务门面号（display_no 自动迁移）
   · 拓展域名加黑名单后立刻不列
   · 「外部工具」页状态；第三方源有 key 且能查
```

### 安全提醒（迁移时顺手加固）

- 当前 `config/settings.yaml` 是 `gui.host: 0.0.0.0` + `edge_auth.enabled: false`：
  控制台对网络开放、只有账号登录。新机建议二选一：
  ① 改回 `127.0.0.1` 并用反向代理 / 防火墙；② `python -m scanner.edgeauth --set` 设边缘口令后
  把 `edge_auth.enabled` 改回 `true`（fail-closed：门开而口令未设 = 一律 401）。
- 密钥文件权限一律 0600；迁移完成后删除临时明文拷贝（`--shred` 或用完即删）。

### 记忆

- 机器本地 `~/.trae-cn/memory/**` **不随 git 迁移**；仓库内 `AGENTS.md` / `todo.txt` /
  `CHANGELOG_AI.md` 是唯一事实源。
- 主理人跨机偏好已固化在 `AGENTS.md §9`（2026-10-28）；本轮迁移结论见 `CHANGELOG_AI.md` 续291。

## 提示词

给本地 AI 的开场提示词已单独放在 **`docs/local-ai-prompt.md`**——新开会话时整段粘贴即可。
