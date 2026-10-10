---
name: ctf-scanner
description: CTFScanner 仓库（Flask 控制台 + 13 阶段资产测绘/漏洞初筛 CLI）的接手须知——硬规矩、唯一门禁命令、CRLF/LF 混排的改文件纪律、断言证伪要求、假红假绿高发区、收尾四步。在本仓库里读改任何文件、跑测试、提交或推送之前先用它。Use whenever working inside the ctf-scanner repo: before editing files, running tests/smoke.py, committing, or pushing.
---

# CTFScanner 接手须知

## Overview

本仓库是一个**只用于授权测试与 CTF** 的资产测绘 + 漏洞初筛框架（Flask 控制台 + CLI，13 个流水线阶段，
SQLite 存储，非破坏性）。它已经迭代了 140+ 轮、由多个 AI 会话接力维护，因此攒下了一批
"不看就会踩"的纪律。本 skill 只放**最容易犯错的那几条 + 去哪查全文**，刻意不抄正文
（抄一份就多一个会漂的产地，见下面第 5 条）。

## 先读这三份（顺序不能反）

1. `AGENTS.md §0` —— 硬规矩，**优先级高于该文件其余全部内容**，也高于本 skill。
2. `CHANGELOG_AI.md` 最新一节 —— 上一轮做了什么 + **实测数字**。
3. `todo.txt` 末尾「下一轮（续NN）」清单 —— 里面只该有未做的 `- [ ]`。

三份都是给"换了对话框、换了 AI、换了机器"的人看的：**没写进去的上下文对他等于不存在**。

## 十一条会把你绊倒的事

1. **门禁只有一条命令**：`./.venv/bin/python tests/smoke.py`（约 5 分钟，最后一行必须是
   `SMOKE PASS`，它在 `main()` 的末尾，所以只有全绿才会打印）。别用 `python3` ——
   系统解释器常常缺依赖，跑出来的是 ImportError 而不是测试结果。
2. **同一时刻只允许一个门禁执行者**：夹具端口（`FIXTURE_PORT` 8765）与
   `logs/devflow_baseline.json` 是共享状态。只读会话不许跑 `tests/smoke.py`，也不许跑
   `cli/run_devflow.py`（它会覆写那份基线）。
3. **仓库里 CRLF / LF 是混着的**（同一个文件里都有）。动手前普查一次这个文件：
   `Counter(l[len(l.rstrip(b'\r\n')):] for l in p.read_bytes().splitlines(keepends=True))`。
   **只要有任何一条 CRLF 行，就别用 Edit/Write 直接改** —— 续146-附3 实测：对 108LF/15CRLF 的
   混排文件做一次 5 行的局部替换，Edit 把**整份文件的 CRLF 归一化成了 LF**（`--numstat` 20/15、
   `--ignore-cr-at-eol` 5/0），不只是"新行写成 LF"那么轻。混排文件一律走 `read_bytes()` +
   沿用锚点行 EOL 的补丁脚本；`read_text()` 的通用换行也会**单独一步**洗掉 CRLF。
   整份单形态（100% LF 或 100% CRLF）才可以安全用 Edit/Write。改完必须核这一对相等：
   `git diff --numstat -- <文件>` 与 `git diff --ignore-cr-at-eol --numstat -- <文件>`。
   按行号打补丁时，**每一批之后都要重新取行号**（前一批增删过行，旧行号就偏了）。
4. **每条修 bug 的断言都要能被证伪**（`AGENTS §6.1`）：把行为改回旧样子，断言必须变红。
   退不回红的断言等于没加。写"某处必须是 0 命中 / 必须是空列表"这类断言时，
   先给判据一个**自证夹具**（造一个该被抓住的样本，确认它真被抓住），否则扫描范围漏了也是绿的。
5. **判据只能有一个产地**（`AGENTS §5.14`）。同一规则写两处，改了一处另一处立刻变假绿。
   现有产地：阶段清单 = `runner.STAGE_ORDER`（前端不认识任何阶段名）；站点状态码筛选 =
   `db.SITE_STATUS_WHERE`；域名解析筛选 = `db.RESOLVED_WHERE`；"目标 → 注册域" =
   `scanner/targets.py`（`host_of` / `hosts_of` / `root_of` / `roots_of`）；平台判定 =
   `toolmgr.host_arch()`；补法文案 = `admin_setup.NO_TTY_HINT` / `edgeauth.SET_HINT` /
   `keystore.lock_notice()`。
6. **断言钉代码形态，不要钉裸词**。本项目已经四次被"自己的说明文案绊红自己的断言"绊倒
   （页面文案里出现「深度目录补扫」、注释里出现 `site_urls`、docstring 里解释性地写了
   `base_domain(...)`、JS 注释里出现 `tbl-vulns`）。要判"某函数不再被调用"就用 AST 数
   `ast.Call` 节点，别 grep 文本。
7. **桩掉写路径的断言是假绿高发区**。`save_settings` 被 stub 时，"POST 之后少存了几个开关"
   没有任何可观测后果 —— 130+ 组门禁一组都不红（`AGENTS §6.2` 第十二起：一个打偏 7 行的补丁
   把 `evasion` 四个键与 `takeover` 两个键整段删掉、还留了个重复的 `"subdomain"` 键）。
   凡是桩掉写路径，就要按 `DEFAULTS` **逐段点名**"一个键都不许少"。
8. **安全红线**：口令 / token / PAT 绝不写进仓库里的任何文件，也绝不写进 `.git/config`、
   远端 URL 或提交信息。凭据密文口令只从 `CTFSCANNER_KEYS_PASSPHRASE`、
   `~/.secrets/keys-pass`（0600）或 TTY 取。控制台每次启动生成的**随机后台前缀刻意不落盘**
   （落盘就不叫"重启即换"了；它也不是访问控制）—— 逐请求日志 `logs/access.log` 也不例外：
   那一行记的是客户端送来的原始路径，落盘前由 `scanner/log.py::PrefixMask` 打码（`AGENTS §7`）。
   授权目标的真实标识不进被跟踪文件
   （替成 `example.com` / `*.test` 这类合成名；别名表在仓库**外**，位置见 `AGENTS §0.5`）。
   `git push --force` 永不允许；推送前必须 `git fetch` + `git pull --rebase`。
9. **别让自动化去点 GUI 的写按钮**（历史上有一次自动化误删了 63 行任务）。要造数据就写库、
   要走流程就用 test client，别驱动真实浏览器去点"删除"。
10. **展示层过滤 ≠ 删数据**。默认收起某些行（未解析域名、非 200/404 状态码）时，
    必须把**被收起的条数**报在页面上，并写明"入库一条没动"；翻页 / 切换链接要延续当前视图状态，
    且**默认态的链接不带那个参数**（写反了就是"第 2 页突然把收起的行全放出来"，
    同一个视图两页口径不一致）。
11. **讲运行期能力的话必须跟着配置走**（`AGENTS §5.19`）。启动横幅那句「访问审计仍然没有」活了
    四十几轮，而 `audit_log` 里一直有记录 —— 这种句子的害处是它会**改变读的人的行为**（以为查不到
    痕迹，就在绑了 `0.0.0.0` 的机器上放心做事）。凡"某能力开/关、留几天、记哪几类"的成句描述，
    一律从配置与注册表现取（`audit.config()` / `audit.KIND_LABELS`），别在文案里抄一份 `DEFAULTS`；
    开与关分态各写一句；回归要**改配置或改注册表再断言文案跟着变**（只断言"现在有这句"挡不住
    下一版漂掉），判据自己先自证抓得到被替掉的旧句子。`docs/` 与 `README.md` 里的同类陈述一起核。

## 目录与入口

- 仓库根只有两个启动文件：`run_gui.py`（控制台）、`run_bootstrap.py`（环境自举）；
  `install.sh` / `start.sh` 是它们在 Linux 上的薄包装（**不实现任何安装逻辑**，只调
  `run_bootstrap.py --install`）。
- 其余入口在 `cli/`：`client.py`（扫描 CLI）、`run_keys.py`（凭据口令加解密）、
  `run_users.py`（账号）、`run_node.py`（分布式执行节点）、`run_devflow.py`（13 阶段全流程自检）。
- `run_bootstrap.py` **刻意放在根、不进 `scanner/` 包** —— `tests/smoke.py [7p]` 钉着
  "scanner 包内不得引用 toolmgr"，塞进去就得给那条红线开豁免。
- `logs/` 与 `data/` 都在 `.gitignore` 里：一次性补丁脚本、沙箱库、门禁日志都放 `logs/`，
  收尾时**按确切文件名**删掉自己造的那些。
- `.venv` **不可搬移**（`pyvenv.cfg` / `bin/activate` / console script 的 shebang 里写死了绝对路径）。
  换机器 = 拷源码 + 重跑 `./install.sh`，不是拷 `.venv`。

## 收尾四步（`AGENTS §0.4`；缺一件就是这轮没做完）

1. `todo.txt`：写清本轮勾掉的与新增的待办；「下一轮（续NN）」里**只放未做的 `- [ ]`**。
2. `CHANGELOG_AI.md`：新增本轮小节，写**实测数字**（"优化了性能"这种没法被别人核对的话不算）。
3. 动了不变量就同步 `AGENTS.md`（§3 目录树 / §5 不变量 / §6.2 假红目录 / §7 局限）。
4. 这三份**一起** commit + push；提交信息末行写 `WorkBuddy · <模型名>`。
   提交信息**一律走 heredoc / `-F -`**，不要用 `-m "…"` —— 本仓消息里满是反引号、`$`、`!`，
   双引号挡不住 shell 的命令替换（实测：一串文件名被替换成空串，而 `git commit` 照样返回 0、
   现场零报警）。推之前 `git log -1 --format=%B` 回看一眼，这是唯一能发现它的动作。

有一条机器可判的：`max续(CHANGELOG_AI.md) == max续(todo.txt)`（`tests/smoke.py [8as]` 会核，
声称同步过 AGENTS 时 `max续(AGENTS.md)` 也要等于同一个数）。

## 去哪查全文（不要抄进别处）

- `AGENTS.md §6.2` —— 假红 / 假绿目录（已积累 12 起，每起都写了"为什么看着像代码坏了"）。
- `AGENTS.md §7` —— 已知局限（哪些是设计如此，不是 bug）。
- `AGENTS.md §9` —— EOL 纪律与"标准动作"。
- `AGENTS.md §10` —— 多 agent：什么能并行、什么必须串行、同文件写怎么办。
- `docs/takeover-*.md` —— 历次交接的复核报告（含"文档没记录的问题"）。
