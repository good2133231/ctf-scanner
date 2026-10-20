# 本地 AI 提示词（续237）—— 新开会话时整段粘贴给本地 AI

> 用法：在本地机器上打开你的 AI 编程助手（Claude Code / Cursor 等），把下面整段粘进第一条消息。
> 它假设你已 `git pull` 到最新。粘贴后正常说需求即可（"把 X 页签加个 Y"）。
> **Windows 本机**：环境与门禁都走 `python dev.py setup` / `python dev.py smoke`
> （跨平台启动器；手写 `.venv\Scripts\…` 也行，但 `bin/` 是 Linux/macOS 路径）。

---

你在 CTFScanner 项目里工作。先按顺序读完这三份文件再动手，**任何一条与本提示冲突时以仓库内文件为准**：

1. `AGENTS.md` —— 协作硬规矩（门禁纪律、红线、记忆同步）。重点：
   - 每轮工作结束时**必须全量跑 `tests/smoke.py` 看到 `SMOKE PASS`**（本机若无 Chrome，浏览器 E2E 组交给服务器跑，其余组本地跑）；
   - 子进程一律带超时，不允许无超时 `wait()`；
   - 授权边界：目标必须是我方授权资产，不碰政府/银行/公用事业等关键设施域名。
2. `todo.txt` 顶部 —— 上一轮的"下一轮清单"与轮次号（**续N**）。
3. `docs/dev-sync.md` —— 本地↔服务器同步流程。

## 本项目的固定工作循环（每一轮）

1. **开工**：`git pull --rebase origin main`；轮号 = 记忆里最大 **续N + 1**（全局连续，不按机器/AI 重置）；
2. **动手**：改代码/模板/文档；测试加在 `tests/smoke.py` 尾部（`print("SMOKE PASS")` 之前），编号 `[N]`；
3. **记忆同步（先于门禁，顺序不能反）**：
   - `CHANGELOG_AI.md`：文件**第 6 行**插入本轮小节（`## 续N（日期，WorkBuddy · <AI名>）：标题`）；
   - `todo.txt`：文件**第 4306 行附近**插入本轮小节 + 更新"下一轮清单"（只放未做的）；
   - `AGENTS.md`：只有产生了**新规矩**才加条目（带 `(续N)` 号）；没规矩就不动它；
   - 校验：三份文件里 `续(\d+)` 的最大值必须一致（CHANGELOG 与 todo **恒等**是门禁硬断言）；
4. **自检**：`python -m py_compile` 所有改过的 .py；改过模板/测试后跑定向断言；
   收尾全量 `python tests/smoke.py`（约 7 分钟，看到 `SMOKE PASS` 才算完；本机缺 Chrome 时
   e2e 组留给服务器，其余组必须本地全绿）；
5. **行尾纪律**：仓库是混合行尾（.py 多为 CRLF、部分 LF）。push 前自查：
   `git diff --numstat` 与 `git diff --ignore-cr-at-eol --numstat` 逐文件相等——
   不相等的文件说明行尾被洗了，按 HEAD 原行尾还原；
6. **提交**：`git add <逐个点名> && git commit -m "续N：<标题>" && git push origin main`。

## 红线（违反任何一条就停下问我）

- 不把**真实扫描目标域名**写进任何被 git 跟踪的文件（聊天里可以说）；
- 不提交 `data/`、`logs/`、`config/keys*.yaml`、`config/settings.json`、`config/edge_auth.yaml`
  （它们被 .gitignore 忽略，别用 `git add -A` 强加）；
- 不碰门禁的红线断言来"让它变绿"——红了先查是不是真回归；确实是我点单要改的 UI/行为，
  就把断言改成新形状并在 commit message 里写明；
- 不重置/不清空 `logs/`（清理只走 `tools/clean_logs.py --apply <确切文件名>`）；
- 不动 `scanner/db.py` 的表结构除非我明确要求（迁移是服务器启动时自动做的）。

## 常见坑（前人踩过，别再踩）

- **改了"出厂值登记"型断言忘了登记**：表单总数、出厂 `queue.workers` 这类断言红是故意的，
  改值必须同步改断言并在 commit 里写明；
- **`replace` 类编辑工具在混合行尾文件上"报成功但内容丢失"**：每次编辑后必须重新 grep 核实；
- **模板的内联脚本依赖 app.js 同步加载**（`{% block script %}` 里直接调 `initTaskTable()`）：
  `app.js` 的 `<script>` 标签**禁止加 defer**（门禁 `[234]` 钉着）；
- **测试里的本机端口**：我服务器上跑着 GUI（5000/5001/5002/5011），本地跑门禁不冲突
  （e2e 用随机端口）；别把测试改成依赖固定端口；
- **FOFA/外部情报**：任何"看起来能从 MD5 反推 mmh3"的思路都是错的，图标哈希必须拿到字节。

## 我的服务器（参考）

- SSH 到服务器后：`cd /opt/tools/ctf/ctf-scanner`，`git pull --rebase origin main`，
  重启 GUI（四个端口直接启动，端口占用会被 portguard 自动接管），
  验证：`grep -h "已启动.*worker" logs/gui-*.log | tail -1`。
