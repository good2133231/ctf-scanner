# AGENTS.md —— 给下一个接手 AI 的项目速览

> 本文件描述**实际代码状态**，不描述愿望。若与 docs/ 下其它文档冲突，以代码为准，并把冲突修掉。
> 2026-09-23 新负责人接手后的复核报告见 [docs/takeover-2026-09-23.md](docs/takeover-2026-09-23.md)
> —— 里面有"文档没记录的问题"与下一步排期建议，接手时先看它，能省一轮重复调研。
>
> **⚡ 有一个会自动加载的 skill**：`.qoder/skills/ctf-scanner/SKILL.md`（续146 应主理人要求打包：
> 「把我们一些重要的项目须知打包成 skill，然后其他 ai 一进入项目就自动加载，就了解我们项目并且不容易犯错」）。
> 里面是本文件 §0 / §6.1 / §6.2 / §9 / §10 的**摘要 + 索引**，给"刚进项目、还没读全文"的 AI 用。
> 它**刻意不抄正文**（抄一份就多一个会漂的产地，§5.14）：与本文冲突时一律以本文为准；
> 反过来，改了 §0 / §6.1 / §6.2 / §9 / §10 就要回头核一遍 skill 里对应的摘要有没有变成假话。

## 0. 硬规矩（最高优先级，违反即视为改坏项目）

> 用户 2026-09-22 明确下达，**优先级高于本文件其它所有内容**。新接手者请先读完本节再动手。

1. **改动必须标注实施者**（本项目会同时存在多个 AI 会话）：
   提交信息末行写 `WorkBuddy · <模型名>`，并在 `CHANGELOG_AI.md` 的轮次标题下写明实施者。
   例：`WorkBuddy · DeepSeek-V4.1-Flash`。用途：事后分辨"某处是谁改的"。
2. **默认只读本项目目录；读项目外文件必须先拿到用户的逐次授权。**
   - 默认禁止：读取、扫描、遍历本项目目录以外的任何代码或文件
     （包括"顺手看一眼参考项目""去隔壁目录找找有没有现成的"）。
   - **例外＝用户当场手动批准**，只要用户说了就照读，不必再确认第二遍。形式包括：
     ① 用户直接给出路径（如"你可以读取 `C:\Users\材料\Desktop\tools\dirmap-master`"）；
     ② 用户说"可以去读 X"；③ 用户回答"是/可以"这类确认。
   - **批准是按次、按路径生效的**：上次批准 A 目录，不等于这次可以读 B；换新的外部路径要重新问。
     已批准清单（便于接手者知道哪些是"批准过的"，不构成新授权）：
     `C:\Users\材料\Desktop\tools\dirmap-master` —— 用户 2026-09-22 批准用于 dirmap 适配审查。
   - 本项目目录 = 本仓库根目录（`ctf-scanner/`）以内的内容；`tools/` 下的目录联接**指向外部**时，
     视同外部路径（同样需要批准）。
   - *注：联网检索公开文档不算"读项目外代码"，但也不要把外部仓库整份拉进来。*
3. **代码、配置、模板、日志里一律只出现相对路径**，禁止出现本机绝对路径
   （`C:\Users\...` / `/home/...` 等）。展示给用户的路径统一走
   `utils.rel_display()`（项目内相对项目根）。
   **Web 界面（GUI）是更严的一档（续61，用户新硬规矩）**：项目外的绝对路径
   **也不许回显**，一律 `rel_display(..., mask_outside=True)`（压成 `…/父/名`）——
   工具可能装在项目外（nmap 在 `Program Files`、`tools/fscan/` 是指向仓库外的目录联接）。
   整段展示的**自由文本**（日志 tail、自检 stdout、任务 `error`、工具 `note`/`reason`）
   逐字段转换挡不住，须过 `utils.scrub_paths()`；若手里已有那条**已知绝对路径**，
   用"精确替换"更稳（见 `gui/app.py::tools_page` 的 `_mask_pair`）。
   验收口径是**页面级**：登录后扫渲染出的 HTML，不得出现盘符绝对路径与项目根绝对路径（`tests/smoke.py [7y]`）。
   CLI 输出**保持原样**（用户要照抄去命令行）——故 `rel_display` 默认档 / `scrub_paths` 缺省都不压缩项目外路径。
   文档里不可避免的操作性路径（如 git 便携版位置）集中在 §2 说明，不要散落到各处。
4. **记忆同步是收尾的一部分，不是可选动作**（用户 2026-10-09 原话："我们的记忆你都要同步到 todo，
   **本地↔服务器双机开发**（续237）：GitHub 是唯一事实源，代码与记忆走 git 同步；
   **跨机同步的一票否决（续238）**：开工与 push 前必跑
   `python tools/sync_check.py --strict`（脏区/未推送非 0 即停）；服务器收尾时
   `git status --short` 必须为空；禁止裸 `git reset --hard`。
   **正式收尾门禁在服务器跑**（本地机器可以跑除 e2e 外的组）；一轮只在一台机器上做，
   中途换机必须把记忆写完整、push 后接手方**沿用同号**继续；流程与提示词见
   `docs/dev-sync.md` 与 `docs/local-ai-prompt.md`。
   以及修改完同步是硬记录，让我们换对话框，换 AI 也能接着执行"）：
   每一轮（每一个 `续NNN`）的**完成判据**不是"代码改完了"，而是四步都走完 ——
   ① `todo.txt` 写清本轮勾掉的与新增的待办（约定见 §9）；② `CHANGELOG_AI.md` 新增本轮小节
   （做了什么 + **实测数字**）；③ 动了不变量就同步本文件（§5 / §6.2 / §7）；
   ④ **这三份一起 git 提交并推送**。§9 末尾那句"标准动作"讲的是同一件事，本节把它提到硬规矩这一档：
   **代码做完而记忆没同步 ＝ 这一轮没做完**。
   为什么写到这个地步：接手的人可能在一个**全新的对话框**里、用**另一个 AI**、在**另一台机器**上，
   他能读到的只有这三份文件加提交历史 —— **没写进去的上下文对他等于不存在**。
   两条**结构**要求（本轮自己把它们撞了，所以写死）：`todo.txt` 末尾那个「下一轮（续NN）」清单里
   **只许有未做的 `- [ ]`**，本轮做完的一律留在上一节里 —— 把 `[x]` 混进"下一轮"，接手的人会照着
   已完成的清单去开工；另外改 `todo.txt` 这类流水账**必须按整行边界切**（切片点取在行尾就会把
   首行吞掉，本轮 `python3` 一把梭就吞了一行、靠 `git diff` 与肉眼复查才发现）。
   因此一轮的记忆必须凑齐三件事，缺一件下一个人就接不上：① **当前事实**（做了什么、实测数字 ——
   要能被别人核对，不是"优化了性能"这种没法判的话）；② **还没做什么**（下一轮清单 + 为什么这轮没做）；
   ③ **踩过的坑**（进 §6.2 假红目录或 §7 局限）—— 没记下来的坑会被下一个人当成"环境问题"糊弄过去，
   §6.2 那十一起全是这么攒出来的。
   反面教材本轮就在手边：`TODO.md` 与 `todo.txt` 是同一批待办的两份抄本，已经漂到
   "TODO.md 的轮次号停在 **117**，而 `todo.txt` 与 `CHANGELOG_AI.md` 都是 **139**"（两个数都能用
   下面的算法复现）。两份清单各说一套，新接手者分不清该看哪一份，照旧的那份做就会把已经完成的事重做。
   修法已落在 `TODO.md` 首节：它不再当第二份逐轮流水账，只留「分工 + 稳定工程化 backlog」。
   **机器可判的形式**（下一轮把它做成 `tests/smoke.py` 的一条断言；口径先在这里定死）：
   取"某文件里出现过的最大轮次号"一律用
   `py -3 -c "import re,pathlib as P;print(max(int(x) for x in re.findall(r'续(\d+)',P.Path('<文件>').read_text(encoding='utf-8',newline=''))))"`
   （bash / Git Bash 等价：`grep -oE '续[0-9]+' <文件> | grep -oE '[0-9]+' | sort -n | tail -1`）。
   判据：**`max续(CHANGELOG_AI.md) == max续(todo.txt)` 恒成立**；且**当那一轮的 CHANGELOG 小节里
   声称同步过本文件时**，`max续(AGENTS.md)` 必须等于同一个数（续145 之后三份都是 145）。
   写断言时三条边界要一起守住，否则造出来的就是 §6.2 那种"看着像代码坏了"的假红：
   - 只认**紧贴的** `续NNN`：早期轮次标题写作「第十八轮（续 11）」，中间有**空格**那一形必须排除
     （`TODO.md` 里有 9 处是那一形；把它们并进同一个数集，「最大号＝最新一轮」这个前提就不再成立）；
   - **后缀不参与比较**：`续96-附2` / `续113-附` / 「本条为补记」只取数字部分；
   - **预告号不算数**：`todo.txt` 里"下一轮＝续NN+1"这类前瞻句会让 todo 的 max 领先 CHANGELOG 一格，
     那是正常状态不是失败 —— 有歧义就改按**轮次标题行**取号（todo.txt 是 `== 续NN` / `## 续NN`，
     CHANGELOG 是 `## 续NN`）；两个口径不一致本身正是该报的漂移。

5. **被跟踪的文件里不得出现「我们自己的授权目标」的真实标识**（续141，用户 2026-10-09 下达：
   「如果我们代办里面出现域名请你把他改成 xxx.com，因为我们的 todo 有时也会在本地开发，我们还处于开发期」）：
   - **替什么**（三条判据，不是"看见域名就改"）：① 本机库 `data/scanner.db` 里真实资产涉及的注册域
     （可复算：库里资产注册域 × `git grep` 命中取交集）；② 记忆里明写「授权目标 / 用户提供的目标」
     的名字及其**派生名**（子域、连字符变体、同名不同 TLD、标题里的那个品牌词）；
     ③ 指向目标业务的 GitHub `owner/仓库名`。
   - **不替什么**：合成夹具（`example.com` / `evil.com` / `*.test` / `a.com`）、公开厂商与 CDN 域名
     （`cloudflare*` / `github*` / `bscscan.com`，以及通达·致远·rockoa 这类**产品指纹厂商名** ——
     它们是产品事实，改掉会把组件识别讲不清）、以及 `config/dicts/subdomains_deep.txt`
     （17.8 万条公共词表里有 3 个条目**字面上恰好含某些品牌词**，但那是**词不是域名**，
     动它等于破坏字典并让 `[8aq]` 的行数判据变红）。
   - **别名形态＝只换品牌 token、保留点号结构与 TLD**（`<品牌词>.<原 TLD> → targ1.<原 TLD>`），
     子域、连字符变体与同名不同 TLD 一起跟上；同一目标**永远同一个别名**、全文一致。
     这样 `[6k]` 那组 `_title_relevant("targ1", …)` 的"label ↔ 标题 token"关系原样成立
     （label `targ1` == token `targ1` ⇒ 保留；`silviatarg1.com` 的 label ≠ `targ1` ⇒ 仍判无关丢弃）——
     **脱敏不许改变任何断言语义**，验收判据就是门禁全绿 + 逐文件两式 numstat 相等。
   - **别名必须 ≥4 个字符、且不能是纯数字**（本轮实测踩过）：`scanner/stages/osint.py` 有一道
     「站点标题少于 4 个字符就不做标题反查」的闸，第一版别名只有 2 个字符，于是 `[6k]` 的端到端
     变成"一次查询都不发"、断言拿到空集 —— 现象长得像功能坏了，实际是**别名踩了自家门槛**；
     `_title_tokens()` 还会丢掉 `isdigit()` 的 token。放宽断言是错的修法。
   - **对照表不入库**：别名映射放在**仓库外**（本机是仓库同级的 `alias-map-141.json`，`chmod 600`）。
     把映射表提交进公开仓库＝把整件事逆向解开。表丢了可以从库里资产域名反查。
   - **已推送的历史不追改**（用户同一天选定"只往前洗"这一档）：所以这条买到的是
     "今后 clone / 代码搜索看不到"，**不是**"历史里没有了"；要真收回只有把仓库转 private（§2）。
   - **最容易把真名写回去的，正是「写这条规矩本身」与「记这一轮」那两段**（本轮两次都栽在这）：
     ① 拿真名当「脱敏前」的例子；② 点名词表里恰好撞词的那几个条目。所以收尾时**必须再跑一次**
     `git grep -iE '<别名表里全部键>'`（键从仓库外那份表读）—— 只看 diff 不算数，因为漏的那两处
     本身就是我刚为记录这件事写进去的。
   - **机器判据已落地（续218，`tests/smoke.py [218]`）**：被跟踪文件（`git ls-files`）里出现
     的任何注册域，若同时是 `data/scanner.db` 资产表（`subdomains`）里的注册域 ⇒ 判红。
     库本身 gitignore ⇒ **不依赖别名表**；机器上没有库（CI / 干净克隆）⇒ 跳过，不算失败。
     白名单三档：① 仓库公开字典（`cdn_cname.txt` / `js_thirdparty.txt`）；
     ② `takeover.SERVICES` 的 `cname_suffix`（运行时提取，覆盖 Firebase/Heroku/GitHub Pages 这类）；
     ③ 合成夹具（`*.test`、`example.com` / `evil.com` / `xxx.com`）与 AGENTS 已文档化的 jsmine
     「成员访问链」噪声。`[218]` 一上线就真抓到过一次泄漏（库内有资产的真实注册域出现在
     todo.txt），所以**别把白名单当成消音器**：命中的域先判"是不是公共厂商"，不是就该改成
     xxx.com，而不是把它塞进白名单。

6. **每轮收尾必须"全量验证 + 死锁排查"**（续219 立，主理人 2026-10-18 明说，优先级同 §0 其它各条）：
   ① **全量**：`py -3 tests/smoke.py` 跑到底、看到 `SMOKE PASS` —— **只跑改动相关的那一组不算**。
      理由不是形式主义：续218 就是靠全量才发现 dirscan 清理计数被自己的补丁改坏（`[7g]` 红），
      `[8bh]` 才发现给字典追加的行用了 LF（裸 LF 从 1 行变 5 行）。跨组影响只有全量兜得住。
   ② **死锁**：改动只要碰到**子进程 / 锁 / 等待 / 重试**，必须逐条确认"不会永久阻塞"——
      - 外部命令一律"**边等边读管道**"（`utils._do_run_cmd` 的读线程；先 `poll()` 等退出、
        退出后才读 ⇒ 子进程一写满 64KB 缓冲就互等，实测能让任务挂一小时、CPU 0%，
        判据是 `/proc/<子进程>/wchan` = `anon_pipe_write`）；
      - 新加的 `Event.wait()` / 轮询循环必须有超时或明确的退出条件；
      - 第三方工具（dirmap / fscan / nmap / 浏览器）输出量不可控，默认按"会写满"设计。
   ③ 这两条的**实测数字**要写进 CHANGELOG（跑了多久、哪几组、有没有红过），不许只写"已验证"。


## 1. 这是什么

CTFScanner：面向 **CTF / 授权渗透测试** 的资产测绘与漏洞初筛框架。参考 ARL 的任务化思路，
把「子域名收集 → 存活探测 → 目录发现 → 漏洞初筛」做成可复用的流水线，同时提供 CLI 与
Flask Web 控制台（仿 ARL）。

**法律边界（不可越过）**：仅用于自有或已书面授权的目标。检测一律非破坏性（只 GET/POST 探测，
无爆破、无写操作、无 DoS 延时）。新功能必须维持这一约束。

## 2. 运行环境（本机实际情况）

- Python 3.9。**结论要先分清是哪个 shell**：
  - 用户在**自己的 cmd** 里 `python` 完全可用（实测 `Python 3.9.0`，`where python` 三条命中：
    Python39 / Python38 / WindowsApps）；用户 PATH 里**确实有** `…\Programs\Python\Python39\`。
  - **AI 工具启动的 shell 里 `python` 不可解析**，根因不是"没装/没进 PATH"，而是**该 PATH 条目
    编码损坏**：`$env:PATH` 里它是乱码 `C:\Users\锟斤拷锟斤拷\AppData\Local\Programs\Python\Python39\`
    —— 用户名"材料"的 UTF-8 字节（`E6 9D 90 E6 96 99`）被按 GBK 解读成"锟斤拷"这种典型乱码，
    于是路径整体失效，`where python` / `Get-Command python` 找不到、`python -V` 报
    CommandNotFoundException。
  - `py -3` 之所以照常可用：`C:\WINDOWS\py.exe` 是**纯 ASCII 路径**不受影响，且 py.exe 自己查
    注册表定位版本（实测 `Python 3.9.0`）。**在 AI shell 里请一律写 `py -3`**，
    但**不要下"这台机器没有 python"的结论**（会误导你去做无意义的排查）。
  *（说明：第八轮写成"`python` / `py -3` 均在 PATH"、第九轮又反改成"`python` 不在 PATH"，
  两次都不准确 —— 真相是"用户 shell 有、AI shell 因编码损坏找不到"。第十一轮按 `$env:PATH`
  实测定位到真根因并改为此写法，请以此为准。
  功能上无影响：框架取解释器一律走 `utils.pick_python()` —— `which(configured)` 不中则回退
  `sys.executable`，实测返回 `…\Programs\Python\Python39\python.exe`。）*
- 依赖已装：flask 3.1、requests 2.22、PyYAML 6.0（见 requirements.txt）。
  **两份清单的分工（续137 立、续138 接进 CI）**：`requirements.txt` 是"我要什么"（直接依赖 +
  允许区间），`requirements.lock` 是"实测装出来的是哪些版本"（传递闭包逐条 `==`，3.9 与 3.14
  两边都验过解得开）。`.github/workflows/{smoke,quality}.yml` 四个装依赖步骤**全部吃 lock**，
  `run_bootstrap.py --install` 也优先 lock（解不开才回落 txt 并明说）。回归 `[8al]` 钉住这三条：
  lock 覆盖全部直接依赖、整份都是 `==`、CI 里不许再出现 `-r requirements.txt`。
  ⚠ 新增 job 时**照 lock 装**，别退回 txt —— 那会让"CI 每次装最新版"重新变成假红的来源。
  **续245 编码不变量**：两份清单首行必须是 `# -*- coding: utf-8 -*-`。Python 3.9 venv 自带的
  pip 20.2.3 在中文 Windows 上按 `locale`（GBK）解码 requirements 文件，而它的 `auto_decode`
  只认 BOM 与前两行 PEP 263 声明；文件里又有中文注释（续98 起）⇒ 没有这一行时 `dev.py setup`
  直接 `UnicodeDecodeError`（实测 byte 0xad）。`[245]` 复刻了这个旧解码器（先自证能复现失败）
  并钉住两份文件，别再让"加一句中文注释"把新机器的安装打红。
  **续246 代理环境坑（本地跑门禁前必做）**：AI 工具会话给每个 shell 注入
  `HTTP_PROXY`/`HTTPS_PROXY`（`http://127.0.0.1:<随机端口>` 的连接器代理，`env | grep -i proxy`
  可见），而 `requests` 的 `trust_env` 对**包括 127.0.0.1 在内的所有地址**生效 ⇒ 冒烟里
  `[5y]②` 的 SSRF 回环自证会改为过代理、间歇性 `RemoteDisconnected`/收不到回连，端到端断言
  `_v_ssrf=None` 假红（intel 的本地夹具拉取同族）。服务器/CI 没有这些变量、门禁的设计目标环境
  就是无代理 ⇒ **本地跑 `dev.py smoke` 前先注销四个变量**：
  `env -u HTTP_PROXY -u HTTPS_PROXY -u http_proxy -u https_proxy py -3 dev.py smoke`
  （Git Bash；PowerShell 逐条 `$env:HTTP_PROXY=$null`）。最快的判墙信号：`[5y]` 红在
  `_ssrf_callback` 返回 None、而把这个断言块单独抄出来跑却能通。
  **同族的还有 `PYTHONPATH`**：AI 工具会话经 `PYTHONPATH` 把 CLI shim 目录塞进**每个**
  Python 进程（里面有 `sitecustomize.py` 与 safe-delete 批量删除守卫）⇒ 冒烟自己收尾时的
  `rmtree`（组内沙箱 >50 文件、退出时整沙箱 ~300 文件）会被守卫 `SystemExit` 打死 —— 打在
  模块顶（启动清扫）就是零输出秒退，打在组内 finally 就是那一组之后的全部不跑。所以本地
  跑门禁连它一起注销：`env -u PYTHONPATH -u HTTP_PROXY -u HTTPS_PROXY -u http_proxy
  -u https_proxy py -3 dev.py smoke`（`[8an]` 的 rmtree 就是这么打死的，续217 注释里记过
  同一现象）。
- 外部工具：subfinder / puredns / httpx **均未安装** → 走内置兜底。**三个例外**：
  **fscan 可用**（续45 自编译 2.2.1 挂到 `tools/fscan/` 的**目录联接**，`settings.yaml` 的
  `tools.fscan=tools/fscan/fscan.exe`）→ 端口扫描 `engine=auto` 的**第一环命中**，实走 fscan；
  **nmap 已安装**（`C:\Program Files (x86)\Nmap\nmap`，实测 `which` 命中）→ 退为 fscan 之后的兜底；
  **dirmap 可用**：
  它的 Python 依赖（gevent 24.11 / lxml / progressbar）本机都有，且已在 `tools/dirmap/` 建了
  **目录联接**指向机器上的 dirmap 源码 —— 因此 dirscan 阶段在**深扫档**（`dirscan.mode=deep`、
  建任务勾「全目录深扫」；⚠ 续145 起结果页那几个「补扫」入口已摘掉，而深扫就是默认档）会**优先真的调用 dirmap**（第十五轮实测
  15348 条字典跑完约 588 秒、解析正确）；找不到 `tools/dirmap/dirmap.py` 时自动回退内置扫描。
  **`quick` 档不调用任何外部工具**（⚠ 续144 起默认档是 `deep`，`quick` 要显式选）：只吃 `config/dicts/dirs_shallow.txt` 的精选敏感路径。
  **续54 起有了"装它们"的入口**（此前只能手工放 PATH 或手改 `settings.yaml`）：
  `scanner/toolmgr.py` + CLI `--update-tools` + GUI 管理员侧栏「外部工具」页 —— 仍是
  **只在显式触发时才联网**（扫描期任何阶段都不会自动下载），只允许 https + 官方主机，
  落盘前必须过 SHA256（摘要**两个产地**，见下）；装完**逐行文本替换**回写 `tools.<名>`。
  平台事实（2026-09-26 查 GitHub API 实测）：subfinder、httpx 双平台产物 + checksums 齐；
  **puredns 官方只发 Linux / macOS 产物且无 checksums**，Windows 上会如实报"未提供当前平台产物"。
  **续164：puredns 改由本框架自己钉摘要** —— `TOOLS["puredns"].pin_version = "v2.1.1"` +
  `pin_sha256`（那一版四件产物各一条），并且取 release 时**按确切 tag**
  （`/releases/tags/v2.1.1`，**不跟 latest** —— 跟 latest 的话上游一发新版就没有能对上摘要的产物，
  安装脚本又回到必然非 0）。这**不是松红线**：字节必须与钉住的摘要一字不差（不符时连
  `--allow-unverified` 都越不过去 —— 那个开关只管"根本没有校验依据"那一类），
  tag 不是钉住的那一版就**连下载都不发起**。
  摘要产地（2026-10-12 实测，不是抄来的）：https 取官方 v2.1.1 的四件产物 → 本机 sha256 →
  解包跑出 `puredns version v2.1.1` 核对版本；本机 `tools/scanner/puredns`（续142 那一次
  用户显式批准 `--allow-unverified` 装的）与钉住的 Linux-amd64 产物解包出来**逐字节相同**
  （`bf9f6273…`）⇒ 这一档没有引入任何本机没在用的新字节。
  **为什么要改**：续163 在干净克隆实测 `./install.sh` ⇒ **rc=1**，唯一失败项就是它 ——
  "官方不发校验和就永远拒装"与"非 0＝有项失败"这两条契约合起来，就是每台新机器都得有人兜一次。
  本轮改完复测（同一条件：只放 513 个被跟踪文件的干净目录）⇒ **`./install.sh` rc=0**，
  清单里那行是 `[+] puredns v2.1.1 → tools/scanner/puredns（SHA256 已校验（本框架钉住的产物摘要））`。
  **升级它只有一条路**：人工核过新版四件产物的摘要后**同时**改 `pin_version` 与 `pin_sha256`
  （只改一个会在"tag 必须等于钉住的那版"这条判据上拒装，那是刻意的）。
  装上的直接后果是 `limits.brute_max_words: 0` **从此真的等于"全量"**（深字典 177,875 条整份喂进去），
  所以续139 记的"冷启动比对标少 16 台主机"那一段前提已经变了；开发模式仍把爆破四项压到 4/4/4/1
  （`devmode.DEV_LIMITS`）⇒ CI 与全流程自检不受影响。
- **环境/门禁启动走 dev.py（续240）**：`python dev.py setup`（建 venv+装依赖，一次性）、
  `python dev.py smoke`（全量门禁）、`python dev.py check`——
  **Windows/Linux 同一条命令**，路径差异（`.venv/Scripts` vs `.venv/bin`）由它收口；
  新增子命令必须带门禁（[240] 有 usage/未知命令/check 的测试）。
- **本地 AI 的第一读本是根目录 `本地开发.md`（续244）**：触发语「你是本地开发」；
  README 顶部、`docs/local-ai-prompt.md`（第 0 读本）、`docs/dev-sync.md`（指回入口）
  四处互指，改任何一份都要同步另外三份（`[244]` 门禁盯着互指关系）。
- **resolver 列表是子域名爆破的第一杠杆（续242）**：`config/dicts/resolvers.txt`
  （12,124 条，trickest 验证列表 + 国内头部置顶，全 IPv4 无注释）——puredns/massdns 靠它分摊
  并发，只有十几条必被公共 DNS 限流。**别删减到千条以下**；更新走 trickest 全量合并，
  `[242]` 钉着 ≥10000/无重复/全 IPv4。内置 socket 兜底那路仍用系统解析器（未接列表）。
- **FOFA 参与子域名收集（续243）**：subdomain 阶段在被动收集之后调
  `_fofa_subdomains()`（`domain="<注册域>"`，source=`osint:fofa`，注册域归一+同域只查一次），
  单域上限 `fofa.subdomain_max`（默认 100）**本地也截断**（size 只是请求参数）；
  没 key / 开关关 / 上游报错 ⇒ 跳过并说一句，不许炸（它是并集里的一路）。
- **纯前端框架不进动态语言字典（续243）**：`_dict_kind()` 判出 FRONTEND_ONLY
  （vue/react/angular/nextjs/nuxt…；**不收 jquery/bootstrap**）⇒ 返回 `"static"`，
  lang 层查 `dirs_static`（不存在 ⇒ 自动跳过），common/exposure 照旧；
  判定顺序 URL 后缀 → 服务端标签 → 前端标签（`vue,php` 是 PHP 站）。
- **历史 URL 走 `scanner/urlhist.py`（续248）**：gau 那类"零目标流量拿历史 URL"的能力
  **原生实现**（wayback CDX + OTX url_list），不引 Go 二进制。产出是**路径**（`to_path`，
  无 scheme 的别把 host 当路径），来源标签 `历史URL(wayback)` / `历史URL(OTX)`；
  按注册域查一次并缓存，**只并入深扫**（浅扫保住精选额度）、与字典共用 `max_paths` 额度；
  上游失败只记一行跳过。别再接第二个爆破引擎（puredns+massdns 已是最优）。
- **端口默认只打常见 web 端口（续250）**：`portscan.mode=top` + 显式 web 端口表
  （80/81/443/3000/5000/5001/7001/7002/8000-8002/8008/8080-8082/8088/8443/8888/9000/9090/9443）；
  全端口**不在建任务表单里**，只能从任务详情「端口」页签的按钮（`/api/ports/fullscan`，
  `_do_append` 追加、`portscan_full=True`、`exclude_scanned` 跳过已扫、结果落本任务）
  或侧栏「全端口扫描」页（跨任务新建）触发。
- **站点自曝入口走 `scanner/urlself.py`（续250）**：robots.txt 的 `Disallow:` + sitemap.xml
  （robots 里 `Sitemap:` 指名优先，`<sitemapindex>` 再取一层、上限 3 份）→ 路径并入 dirscan 候选
  （**只深扫**、与字典共用 `max_paths`、来源标签 `robots.txt`/`sitemap.xml`）。
  与 urlhist 同契约同纪律：失败只记一行、关掉即零请求、单站上限 `dirscan.selfurls_max`。
- **站点爬虫默认开（续249）**：`crawl.enabled` 出厂 **True**（主理人点单）。它一定会发
  GET，护栏是额度上限（max_sites/max_pages/max_links/同站判据）与策略页可关（关掉零请求，
  `[198]` 家族钉着）。页面入口（`urls` 表）与带参链接（vulnscan feed）都从这里来。
  katana 是**可选增强**（增量=JS/robots/sitemap/并发），要接就做成"装了优先用、没装退回内置"，
  别让默认路径依赖 Go 二进制。
- **git（2026-09-22 起）**：本仓库已是 git 仓库（`main` 分支，首次提交 `2267e51`）。
  git 二进制用 **MinGit 便携版**：`C:\Users\材料\MinGit\cmd\git.exe`（不在 PATH，
  choco/winget 因非管理员权限走不通，便携版是刻意选择）。仓库级 `user.name=CTFScanner`
  是占位身份，个人使用请自行改。
  **怎么推到 GitHub（认证方法，2026-10-01~02 实测；非交互环境下唯一可用的一条路）**：
  本机 `credential.helper = helper-selector`（Git Credential Manager），凭据已缓存在 Windows
  凭据管理器里（账号 `good2133231`），**不需要用户贴令牌**。但**非交互 shell 里
  `git push` 会拒绝弹窗**（`fatal: Cannot prompt because user interactivity has been disabled`），
  而 **bash 里 `printf ... | git credential fill` 会被 SIGTERM 杀掉** —— 可用做法是
  **用 PowerShell 工具执行下面这段**：
  ```powershell
  $raw = "protocol=https`nhost=github.com`n`n" | git credential-manager get 2>$null | Out-String
  $pw  = ([regex]::Match($raw, '(?m)^password=(.*)$')).Groups[1].Value.Trim()
  $b64 = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("x-access-token:$pw"))
  $env:GIT_TERMINAL_PROMPT = '0'
  git -c "http.extraheader=Authorization: Basic $b64" push origin main
  ```
  四个坑：① `git credential-manager get` **必须从 stdin 喂**这三行（否则返回空，会被误判成“没凭据”）；
  ② PowerShell 的 stdout **不会回显**，把结果写进文件再读；③ 令牌**只放请求头** ——
  绝不写进 `.git/config`、也别拼进 remote URL（`origin` 保持无令牌的
  `https://github.com/good2133231/ctf-scanner.git`）；④ **不要把 password 打印出来**。
  成功标志是 `旧sha..新sha  main -> main`。GitHub REST API（查 CI 结果等）用同一个 `$pw`，
  头换成 `Authorization: Bearer $pw`。
  **Linux 侧（这台远端机）推送的实操事实（2026-10-08 续136 实测）**：
  `credential.helper` 指向**仓库外**的 `/opt/tools/ctf/git-cred-helper.py`，它只从
  `config/keys.enc.yaml` 现场解出 GitHub 令牌，改之前口令来源**只有** `CTFSCANNER_KEYS_PASSPHRASE`
  或真 TTY —— 而 `config/settings.yaml` 把 `gui.keys_ask_passphrase` 设成了 `false`（续134），
  于是在 AI 的 shell（无 `/dev/tty`）里 `git push` **必然失败**，表现是
  `[!] 凭据未解锁…` + `could not read Username`。这不是网络问题，也不是 helper 坏了。
  本轮最终落定的形态（2026-10-08，用户选定"值不落明文"即可，接受同机兜底口令这一档）：
  推送令牌作为**新键 `github.push_token`** 存进 `config/keys.enc.yaml`（PBKDF2+AES-256-GCM），
  **不覆盖** `github.token` —— 后者是 `github_leak` 阶段做代码搜索用的**只读**令牌，把可写令牌
  交给扫描器等于白送权限；反过来用只读令牌去推则只会得到一个归因错的 403。磁盘上因此
  **不再存在任何明文 PAT**（本轮就发生过：仓库根 `test` 文件里躺着一个 `ghp_` 令牌 ——
  离被 `git add -A` 提交进公开仓库只差一次手滑；已核从未进过任何提交，值现已只存在于密文里）。
  口令兜底：`~/.secrets/keys-pass`（**600、属主必须是自己**，否则助手拒绝读、退回当场问一次），
  优先级＝环境变量 > 该文件 > `/dev/tty`。`git-cred-helper.py` 取令牌的顺序＝
  `push_token` > `token`。改完 `git push` 不再需要任何环境变量或 askpass。
  ⚠️ 诚实的边界：解密器与密文同机 ⇒ 这**不是**更强的加密，能读 `~/.secrets/keys-pass` 的人
  就能解开 `keys.enc.yaml`（§7 续98 那条原话照旧成立）。这一档买到的只有三件事：明文不落盘、
  值不进 argv/`ps`/history/`.git/config`、以及权限一被改坏就自动失效。要真正收回这一点，
  就把 `~/.secrets/keys-pass` 删掉，回到"每次推送给一次口令"。

  **多机 / 多 AI 并行时的同步纪律（2026-10-02 立，两边会话都要遵守）**：
  仓库是**公开的**（`good2133231/ctf-scanner`；不带凭据访问 GitHub API 就是 200），
  所以**拉代码一律不需要凭据** —— 另一台机器 `git clone` / `git pull` 直接就能跑。
  那一台要**推**回来时，按这个顺序选：
  ① **仓库级 Deploy key**（仓库 → Settings → Deploy keys → Add deploy key，
     勾 **Allow write access**）：只作用于这一个仓库、不过期、不在任何文件里留明文；
     缺点是**只能做 git 操作、不能调 GitHub API**（要看 CI 结果得另配）。
  ② **fine-grained PAT**：只选 `good2133231/ctf-scanner` 这一个仓库，Permissions 只勾
     `Contents: Read and write`（要看 CI 再加 `Actions: Read` + `Metadata: Read`），
     过期时间设短。既能推也能查 API。
  ⚠️ 三条红线：
   - **绝不**把令牌写进 `.git/config`、remote URL 或**仓库目录内的任何文件**
     （`git add -A` 会把它提交上去）。要落盘就放仓库外，且 `chmod 600`、用完即删；
     更干净的做法是 `GIT_ASKPASS` 临时脚本或 `credential.helper cache`。
   - **回归夹具也算「任何文件」**（续155 实测被拦）：形状与真 token 完全一致的假值
     （OpenAI `sk-proj…` / npm `npm_…` / PyPI `pypi-AgEIcHlwaS5vcmc…` / AWS `AKIA…` /
     Google `GOCSPX-…` / Azure `AccountKey=…`）会被 GitHub 的秘密扫描**直接拒绝推送**，
     而它分不出"这是我们自己编的假值"。测试要验的是**规则命中与不命中**，不是"存一串看着
     能用的 key" ⇒ 把夹具写成运行时拼串（`_fxs("sk-", "projaBcd…")`），源码里不留整串；
     改完用 AST 把夹具表抽出来单独跑一遍判据，确认拆分没把形状改坏（本轮 14 条逐个命中验过）。
   - 推之前**必须** `git fetch origin main` + `git pull --rebase`；落后就先变基再推。
   - **禁止 `git push --force`** —— 多机同时写同一分支时，强推会**静默盖掉别人的提交**。
  ③ 两个会话都在改**同一批文件**时，各自推到自己的分支（如 `linux/*`）再合并，别抢 `main`。
  ④ **SSH 钥匙的两个实操坑**（本轮真踩过）：
   - 钥匙**不是标准文件名**（如 `id_ed25519_ctf`）时，`ssh` **不会自动去试它** ——
     `ssh -T git@github.com` 会直接 `Permission denied (publickey)`。要写 `~/.ssh/config`：
     ```
     Host github.com
       HostName github.com
       User git
       IdentityFile ~/.ssh/id_ed25519_ctf
       IdentitiesOnly yes
     ```
     （`chmod 600 ~/.ssh/config`）这样 **git 和 ssh 都会用对钥匙**，不必再设 `core.sshCommand`。
   - `git config core.sshCommand` **只对 git 命令生效，对裸 `ssh -T` 无效**；
     而且不带 `--global` 时必须先 `cd` 进仓库，否则报 `fatal: not in a git directory`。
   - 排错：`ssh -Tv git@github.com` 能看清**实际拿哪把钥匙去试了**。
- **本机参考项目（操作性路径，集中在此）**：`C:\Users\材料\Desktop\tools\scan\myscan_20250825`
  —— `TODO.md` 末尾「参考项目借鉴清单」的对标对象（**非本项目依赖**，仅登记位置；§9 只做描述性引用）。

## 3. 目录地图

```
ctf-scanner/
├── install.sh / start.sh  # Linux/macOS 的一键安装与启动（续146）：**薄包装** —— 找解释器 → 调
│                          #   `run_bootstrap.py --install` → 复验 → 印出"哪些没自动化、下一步敲什么"；
│                          #   start.sh 则 **exec** `run_gui.py`。判据一份都不抄（§5.14），[8av] 钉住。
│                          #   ⚠ 必须 LF 行尾（`.gitattributes` 钉了 `*.sh text eol=lf`）：CRLF 的 shebang
│                          #     会让 bash 报 `bad interpreter: /usr/bin/env bash^M`，而从 Windows 检出后
│                          #     的症状看着像"这台机器没装 bash"，最难往行尾上想
├── run_gui.py             # Web 控制台入口（库里 0 个账号时**先跑首启动向导**建第一个管理员，续117）
├── run_bootstrap.py      # 迁移自举（续96）：按平台点清环境缺口，自动补 `.venv`(含 pip 引导) + pip 依赖 + `toolmgr.TOOLS` + 可选系统包层 `--with-system`；nmap/fscan/dirmap/massdns **只打印命令、不代跑**。放仓库根、刻意不进 `scanner/` 包（免得给 [7p] 的扫描期零下载红线开豁免）
│                          #   ⚠ 续146 起仓库根**只有上面这两个启动文件**（用户点单："根目录这些文件太乱了，
│                          #     主目录只留启动文件"），其余入口全在 `cli/` 下
├── cli/                   # 命令行入口（续146 从仓库根搬进来；搬完路径自举都要 `.parent.parent`，
│                          #   少一层的症状是"从仓库根跑就 ImportError: No module named scanner"，[8au]⑥ 钉住）
│   ├── client.py          # CLI 入口：导入目标 → run_task（阻塞）；`--check` 看外部工具，
│   │                      #   `--check-afrog-pocs [目录]`（续123）**只读**自查 afrog PoC 目录：
│   │                      #   多少条属于"只读 + info 级"会被喂给外部引擎、每条被拒的原因；
│   │                      #   不发请求、不写配置，退出码 0=查到结果（含一个可喂的都没有）/ 1=无从可查
│   ├── run_users.py       # 管理员账号的命令行入口（续117）：--status / --create-admin / --reset-password
│   │                      #   / --purge-legacy-token；口令只从 getpass 或 CTFSCANNER_ADMIN_PASSWORD 来，
│   │                      #   **任何输出都不出现口令值**，落库的只有 PBKDF2 派生值
│   ├── run_keys.py        # 凭据口令加密的管理入口（续98）：--status / --encrypt / --change / --verify；任何输出都不出现 key 值或口令
│   ├── run_node.py        # 分布式执行节点（续80）：连控制端领任务、跑完把资产增量回传
│   └── run_devflow.py     # 全流程自检（续50）：起内置靶场 → 压量 → 真跑 13 阶段 → 逐阶段 OK/SKIP/FAIL
│                          #   ⚠ 它会覆写 `logs/devflow_baseline.json`，只读 agent 不许跑（§10）
├── gui/
│   ├── app.py             # create_app()：路由 + 每任务一个后台线程；serve() 为统一启动入口；含跨任务资产页（子域名/拓展域名/站点/漏洞，另有 /ports /csegs /dirs）
│   ├── templates/ static/ # 页面与原生 JS（app.js：轮询状态/日志、建任务、POC 管理、页签、表格筛选、任务批量操作）
│   │                      #   `diff.html`＝续129 的复测视图「这次 vs 上次」：入口在任务详情页
│   │                      #   头部「与上次对比」，也可直接访问 `/diff?task=&base=`（三档文案：
│   │                      #   可比 / 不可比（给原因，不给全空表）/ 某类缺对照）
│   │                      #   外壳＝左侧固定侧边栏 + 顶栏 + 内容区（14 栏，以 base.html 的 nav_items 为准：
│   │                      #     仪表盘/任务管理/子域名资产/站点资产/IP 资产/全端口扫描/漏洞风险/POC 管理/外部工具/
│   │                      #     策略配置/账号管理/执行节点/访问审计/数据迁移；
│   │                      #     其中后 7 栏 admin_only＝只对管理员渲染（子用户不渲染且路由层 403）；
│   │                      #     dev.enabled=true 时再追加第 15 栏「开发模式」。
│   │                      #     ⚠ 改导航必须同步这四个地方的计数：本行、`docs/architecture.md`、
│   │                      #       `docs/usage.md`、README 开头那条功能清单 —— 续96 加「执行节点」时就漏了，
│   │                      #       文档一直说"12 栏"而实际是 13 栏（本轮顺手校正）
│   │                      #   新建任务表单（续118）有「全部勾上 / 全部清掉 / 恢复默认」三颗按钮：分组与
│   │                      #   默认值都写在模板的 data 属性里（`data-ck-group` / `data-ck-default`），
│   │                      #   JS 里不认任何阶段名 —— 阶段清单只有 `runner.STAGE_ORDER` 那一份；
│   │                      #   「全部勾上」刻意**不含**「离线模式」（勾它等于禁用外部工具，与『跑全』相反）
│   │                      #   （注：本节曾写「9 栏」且漏列账号管理/访问审计，2026-09-26 续54 按 base.html 实测更正）
│   │                      #   （原「端口服务/C 段视野/目录发现/拓展域名」四栏已移除，路由 /ports /csegs /dirs /extdomains
│   │                      #    仍在，只是不进侧栏；前三条是任务维度数据，/extdomains 与 /subdomains 是同一张表的不同视图）
│   │                      #   任务详情＝横向 11 个页签（潜在漏洞(默认)/站点/子域名/拓展域名/端口服务/C 段/目录/**SSL 证书**/**敏感信息**/目标与配置/运行日志）+ 页签内筛选框
│   │                      #   （「敏感信息」＝续126 `scanner/flagfind.py` 的产物、续148 由「flag 候选」改名，
│   │                      #     单独成表 `flags`，见 §5.16；表名与 `flags.*` 配置键刻意不改）
│   │                      #   （「线索」页签 2026-09-24 续24 按用户口径**移除** —— 线索只从 JSONL 导出出，见 §已知局限；
│   │                      #     「SSL 证书」＝cert 阶段产物；页签按数据源实有出现，没有产物时说明原因）
├── scanner/
│   ├── runner.py          # StageContext / PipelineRunner / run_task / sync_pocs（协作式取消：request_stop/is_stopped）
│   ├── progress.py        # CLI 前台进度条 + 「日志不刷乱进度条」（续212，P3-14①）：零依赖的 tqdm
│   │                      #   等价物，只取 `tqdm.write`「日志打在条上方」那一瓣（阶段级 Bar + write()）。
│   │                      #   三条纪律：**只在 TTY 渲染**（管道/CI/测试一个字节不多，smoke 的逐字
│   │                      #   比对回归靠这条）、**日志不许直接 print**（`write()`＝擦条→写行→重画）、
│   │                      #   **纯 ASCII 序列**（`\r`+空格回退，不碰 `\033[K` —— Windows 旧 conhost
│   │                      #   会原样印）。`log.py` 的控制台 handler（`_ConsoleHandler`）与
│   │                      #   `run_task(progress=)`（阶段边界 `pg.stage(中文名)`、finally 收条）都走它
│   ├── stages/            # base + subdomain/takeover/portscan/probe/**cert**/screenshot/osint/jsmine/dirscan/vulnscan/intel/heuristic/**github**（13 个）
│   ├── migrate.py         # 扫描数据的导出/导入（续136，跨机迁移）。**默认零凭据**：包里只有
│   │                      #   tasks + 八张资产表；账号表/凭据文件/任务登录态/`flags`（原文取值）
│   │                      #   各要一个显式旗标（`--with-users` / `--with-task-auth` / `--with-secrets`）
│   │                      #   **新 id**、running/queued→stopped 且 pid 归零、同名账号与凭据文件
│   │                      #   **一律不覆盖**；写之前先查表是否存在、写完前拍一份**不重名**的整库
│   │                      #   快照（WAL 下必须用 backup API）。`dry_run` 与真跑**共用同一条判据**
│   │                      #   （两份实现必漂，漂了比没有试算更糟）。
│   ├── diffview.py        # 跨任务差分（续129，复测视图）：target_set/comparable/pick_base/
│   │                      #   snapshot/diff/summary。三条不对齐就会骗人的口径：
│   │                      #   ①缺覆盖≠变化（按类别看两边 stages，三档各有说法，缺对照的数字
│   │                      #   不许进摘要）；②漏洞只把 false_positive 排除（与报告同口径），
│   │                      #   上次判误报这次又扫到且未复核 ⇒ 算新增并写明「复核结论过期」；
│   │                      #   ③owner 守卫在 diff() 里（不只放路由），别人的任务不是你的上一轮。
│   │                      #   取基准走 list_tasks(limit=None)：拿分页窗口找"上一轮"得到的
│   │                      #   "没有可比的"不是事实，是分页。`_g(obj, key)` 是因为
│   │                      #   `sqlite3.Row` 没有 .get()（本项目第五次栽在同一处）
│   ├── extcost.py         # 外部引擎的**流量口径**（续128）：预估（afrog=站点×只读PoC、
│   │                      #   fscan/nmap=主机×端口，两个单位**不合并**）+ 硬上限。
│   │                      #   `throttle` 只能管"我们发多少 / 起几个子进程"，管不到子进程
│   │                      #   自己发多少 —— 这里补的就是那一段。默认上限 0=不限（不改既有
│   │                      #   行为），但**预估数字始终进日志**：没有数字人就不知道该设哪。
│   │                      #   超限的处理是**降级**（afrog 不起进程、端口扫描退回内置那条
│   │                      #   真的受门控的通道），不是硬失败
│   ├── afrog.py           # 外部引擎 afrog 的适配器（续121；续149 起**默认开**）：只读闸门 classify_poc →
│                          #   把放行的 YAML 复制进任务目录（-P 指它，不指用户原目录）→ 固定 argv
│                          #   （-duc 省掉实测每次 30 秒的更新检查 / -doh 不往 CWD 落 108KB 报告 /
│                          #   -nc 洗 ANSI / -ja 才有证据；禁 -ps -default-pwd -brute*）→ 解析结果
│                          #   （**缺文件＝零命中**，rc=0 也可能是没干活）→ 级别只降不升
│   ├── pocs/engine.py     # YAML POC 引擎（nuclei 兼容子集）
│   ├── pocs/pocs/*.yaml   # 内置 7 个示例 POC
│   ├── owasp/checks.py    # 14 项启发式检查（装饰器 @check 注册进 CHECKS）+ 分级/分类门控
│   │                      #   （默认执行 7 项 —— 其余是 info/low 级，被 skip_severities 整级跳过；
│   │                      #     a10-ssrf-callback 虽是 high，但另有 ssrf.enabled 总开关、默认关）
│   ├── evasion.py         # 动态免杀：UA 池/浏览器化头/WAF 指纹/payload 变形
│   ├── wildcard.py        # 泛解析识别与过滤（纯 DNS 查询）
│   ├── passive.py         # 免 key 多来源被动子域名收集
│   ├── dnsq.py            # 纯标准库 DNS 客户端（A/CNAME/TXT/MX/NS…，UDP+TCP 回退，异常不外抛）
│   ├── cdp.py             # 最小 CDP（Chrome DevTools Protocol）客户端：**纯标准库**（RFC6455 文本帧 + call/wait_event/ev），
│   │                      #   只为截图兜底存在（续170）。`WS` 只连回环（拒非 127.0.0.1）、`ready()` 永不抛、
│   │                      #   `free_port()` 要系统分配的空闲端口 —— 浏览器调试口不许写死也不许对远端开
│   ├── cdn.py             # CDN 判定：两条判据 —— CNAME 链读 config/dicts/cdn_cname.txt 按后缀匹配厂商，解析 IP 段读 config/dicts/cdn_ips.txt（CNAME 优先、IP 兜底任播 CDN；只读、无请求）
│   ├── takeover.py        # 子域接管指纹库（41 条第三方服务 suffix）+ detect()
│   ├── portscan.py        # 端口/服务扫描（TOP 表 + **fscan** + nmap 适配 + 内置 TCP connect 兜底 + 被动 banner；
│   │                      #   `engine=auto` 顺序 fscan→nmap→内置；parse_ports(max_span) 防手滑全端口，见 §7）
│   ├── jsmine.py          # JS 资产挖掘（域名/接口 URL/疑似凭据；17 条凭据规则 + 两级降噪）
│   ├── blacklist.py       # 用户黑名单（config/blacklist.txt；load/matches/filter_pairs/filter_domains，每次重读不缓存）
│   ├── auth.py            # 任务级登录态请求头（parse_headers/mask_value/summary/inject/from_task_options）；
│   │                      #   **只发目标侧**（http_request 的 auth=False 是默认值），日志/页面/报告一律掩码，见 §7
│   ├── iprecon.py         # IP 反查域名 + /24 C 段归纳（is_public_ip/segment_of/parse_domains，不 eval）
│   ├── fofa.py            # FOFA 反查（qbase64）：favicon(icon_hash) / cert="domain" / title="xxx" 三种；黑 ico / 通用证书 / 公共标题阈值
│   ├── shodan.py          # Shodan 反查（http.favicon.hash:<mmh3>）—— 与 fofa.py **同构照抄**，默认关，无 key 显式报错
│   ├── quake.py           # 360 Quake 反查（favicon: "<mmh3>"，POST + X-QuakeToken）—— 同上，默认关
│   ├── virustotal.py     # VirusTotal **子域名**反查（续214）：`GET /v3/domains/<注册域>/subdomains`，
│   │                      #   与上面三家 favicon 反查**不同路**（那是同源推断，这是已收录的父子关系）。
│   │                      #   与 shodan.py 同构、刻意不抽公共基类；出厂关 + 没 key 零请求；
│   │                      #   免费档 4 次/分钟 ⇒ 模块自带 `min_interval` 节流、429 如实停不重试。
│   │                      #   ⚠ 读配置必须判 `is None`：**显式 0 不能被 `or DEFAULT` 吞掉**
│   │                      #     （`0 or 15.0`＝15.0 ⇒ 关不掉节流，本轮实测抓出来的）
│   ├── ctlog.py           # 证书透明度日志在线查询（crt.sh，免 key，DEFAULTS 关、**随包 settings.yaml 已开**）：产出**证书维度**记录
│   ├── ssrf.py            # A10 SSRF 受控回连（**默认关**）：本机 HTTP 回连监听 + 每参数唯一 token
│   ├── mmh3.py            # 纯标准库 MurmurHash3 x86_32（平台 favicon 指纹用；含 SELF_TEST 向量）
│   ├── intel.py           # 漏洞情报订阅（P3-2）：CISA KEV 拉取+本地缓存+白名单式匹配 → **只产线索**（不写 vulns）
│   ├── heuristics.py      # 启发式候选发现（P3-3）：对已有数据做差分/异常聚合（**零请求**）→ 线索；阈值与规则表在此
│   ├── flagfind.py        # 敏感信息 / CTF flag 候选抽取（续126 建、续148 改名，**默认开、零额外请求**）：只在**已经拿到**的
│   │                      #   正文（probe 根响应 / jsmine 页面与每个 JS / dirscan 每条命中 /
│   │                      #   vulnscan 的 POC 证据）上按 `flags.prefixes` + 可配正则抽候选，
│   │                      #   单独进 `flags` 表（**不写 vulns、不计入漏洞数**）。三条边界：
│   │                      #   ① 模块内不许有任何出网引用（AST 判据）；② 成本封顶 —— 判据是
│   │                      #   "字面锚 + str.find 在小写副本上定位 + 从原文取值"（1.56 MB 正文
│   │                      #   1.2 ms vs 同配置 (?i) 双分支 40 ms）；用户正则**只在必现字面量
│   │                      #   锚出的窗口上跑**，取不出锚就拒用并给原因（绝不整份正文扫）；
│   │                      #   ③ 改配置键名后，用户文件里的旧键**没人会删**（save_settings
│   │                      #     是合并写）⇒ 必须用断言钉住"旧键是惰性的"：新键要真的生效、
│   │                      #     残留的 `flags.max_bytes` 要真的不影响行为（[8ae] ④ 两条）
│   │                      #   ④ 只报候选：值保留原文大小写 + 带上下文，判真假日的是人
│   │                      #   （`flag{xxx}` 这类占位符同形状）—— 故刻意**不加**词边界规则
│   ├── fingerprint.py     # 指纹规则表 → identify(resp) -> [tag] + fetch_favicon/favicon_md5/favicon_hash
│   │                      #   `collect(ctx, site_url, resp)` + `flush(ctx, logger, where)`（续127）：
│   │                      #   把**已经发过**的响应（dirscan 每条命中 / jsmine 页面与每个 JS）里的
│   │                      #   组件标签攒起来、阶段末尾一次**并集**写进 `sites.tech`（内存与库同步），
│   │                      #   零额外请求；没有新增就一行都不写、也不打日志
│                          #   判定带**必现字面量前置过滤**（续122，`required_literals`/`_lit_filter`）：
│                          #   字面量不在文本里 ⇒ 这条规则一定不命中 ⇒ 跳过 re.search（实测 900KB 13x）
│                          #   规则是 `(part, 正则[, 状态码集合])`；**两个来源**：内置 SIGNATURES（103 个标签，
│                          #   一律不分状态）+ 外置 `config/dicts/fingerprints_extra.txt`（续120，带状态码门控，
│                          #   TAB 分隔，坏行进问题清单不静默；缓存按 (路径,mtime,size)，改字典不用重启）
│   ├── certs.py           # TLS 证书取证（**纯标准库** DER/ASN.1 解析，不引 cryptography）：parse_der/parse_pem/fetch/tls_ports
│   ├── toolmgr.py         # 外部工具版本管理（续54）：查 GitHub release → 按平台挑产物 → SHA256 校验 →
│   │                      #   单文件解包落盘 → 逐行回写 tools.<名>。**只在显式入口调用**（CLI/GUI），
│   │                      #   扫描期零下载；出口仅 https + 主机白名单；宁可报错也不猜（无校验和默认拒装）
│   ├── db.py              # SQLite 层（tasks/subdomains/sites/ports/csegs/dirs/vulns/pocs/**leads**/**certs**/**flags** + page_assets/delete_task/task_counts
│   │                      #   + OWN_SUBDOMAIN_WHERE/EXT_SUBDOMAIN_WHERE/OVERLAP_EXT_WHERE/OVERLAP_SITE_WHERE；DB_PATH 受 CTFSCANNER_DB 覆盖）
│   │                      #   复核（vulns.review/review_note/reviewed_at + set/bulk_set_vuln_review/review_counts）
│   │                      #   与 POC 置信度（pocs.confidence + poc_confidence）见 §7
│   ├── config.py          # DEFAULTS + load/save_settings + load_keys()（config/keys.yaml）+ resolve()；LOGS_DIR 受 CTFSCANNER_LOGS 覆盖；续109 新增 `session_secret(dir)`：会话签名密钥随机 32 字节 + 落盘 0600（`session.secret`），**绝不由 gui.token 推导**
│   ├── keystore.py        # 凭据口令加密（续98）：PBKDF2(60 万次)+AES-256-GCM 读写 config/keys.enc.yaml；解锁只在启动时由入口调一次并缓存，current() 只读缓存、绝不提示
│   ├── edgeauth.py        # 401 边缘认证门（续131 立、续132 改口径，§5.10 的**用户豁免项**）：
│   │                      #   口令**明文**写在 `config/edge_auth.yaml`（与 keys.yaml 同类、在 .gitignore
│   │                      #   里）；开关 `gui.edge_auth.enabled` 在 settings.yaml —— 分两个文件正是因为
│   │                      #   settings.yaml 被 git 跟踪而仓库公开。用户名固定 `edge`；口令文件缺失**或
│   │                      #   为空** = 一律 401（fail-closed；空 stored 必须在比较前挡掉）
│   │                      #   （续133）`serve()` 启动时走 `wizard()` 自检：口令没设就**当众提醒**，
│   │                      #   有终端则当场问着设（形状抄 admin_setup，输入与 isatty 可注入）
│   ├── webpath.py         # 后台路径随机化（续138，用户点单）：每次启动用 `secrets` 生成
│   │                      #   （续193 起开发期可被 `DEV_PIN_BASE` 写死成固定值，见 §5 续138 条）
│   │                      #   `/两层各10位`（共 20 位、字符表去掉 0o1li）前缀，再用 **WSGI 中间件**
│   │                      #   把整个控制台挂上去 —— 必须设 `SCRIPT_NAME`（不是只改 `PATH_INFO`），
│   │                      #   否则页面里的 `url_for`/`redirect` 全指回根路径。根路径与任何错误路径
│   │                      #   一律 404 **空响应体**（不重定向、不回 401：那都是在告诉探测者"这儿有后台"）。
│   │                      #   前缀**不写任何文件**、只在启动横幅打印，重启即换；`CTFSCANNER_WEB_PATH`
│   │                      #   可显式固定（空串＝挂回根路径）。⚠ **不是访问控制**（§5.10 那句话对它同样
│   │                      #   成立：真门槛是 edgeauth + users 两道），任何文案都不许把它写成"更安全"
│   │                      #   启动横幅那条完整地址的**唯一产地是 `gui/app.py::webpath_hints(base, host, port, ext_ip)`**（续153）：非回环部署时首行直接印**能点开的出口地址**、绑定值写进括注（`0.0.0.0` 是监听地址、不是可访问的主机名，复制过去用不了），`serve()` 里不许再拼第二条地址（续150 那样"地址形状"就有两处，改一处漏一处）
│   ├── users.py           # 多用户（续46）：PBKDF2 口令哈希 / check_login / validate_password / 防锁死（不能停用自己、至少留一个启用中的管理员）
│   ├── admin_setup.py      # 建"能登录控制台的人"（续117）：向导 + 命令行**共用**的判据（0 账号才动作 /
│   │                      #   非交互不代填 / 口令只进 users 表），两个入口一份规则，别各写一遍
│   ├── audit.py           # 访问审计流水（续48）：谁·何时·哪 IP·做了什么·成败；`record()` 自带口令形状擦洗，**只记元数据**
│   ├── login_guard.py     # 登录限速 / 失败锁定（续48）：独立表 `login_fails`（与审计分表）；按 IP 为主 + 按用户名兜底，
│   │                      #   被锁返回 429 + Retry-After 且**正确口令也拒**、页面不泄漏账号存在性；自救 `-m scanner.login_guard`
│   ├── captcha.py         # 登录验证码（续78）：**纯标准库**（手写 5×7 点阵字 + zlib/struct 编 PNG）；答案只存本进程内存，
│   │                      #   会话里只放不透明 token；一次性 + 大小写/易混归一 + `compare_digest`
│   ├── utils.py           # run_cmd / http_request（**线程本地复用连接**，续116）/ pool_run / resolve_host /
│   │                      #   IO（read_lines + **tail_lines 有界尾读**）/ base_domain() / rel_display()
│   ├── throttle.py        # **统一并发 / 限速 / 全局预算门控（F2）**：两级闸（任务级 + 进程级共享）
│   │                      #   + 令牌桶 + 任务预算；经 `settings["_throttle"]` 注入（沿用 auth.inject 的
│   │                      #   "任务专用副本、绝不原地改"）。三条出口都过它：`http_request` / `run_cmd` /
│   │                      #   `portscan` 裸 socket。预算耗尽＝**按停止处理**（见 §4/§5/§7）
│   ├── targets.py         # parse_lines → [(kind, raw)]，kind ∈ domain|url|ip|cidr|unknown（cidr 展开为多条 ip）
│   └── report.py          # 报告三格式：Markdown（generate）/ HTML（generate_html，自包含单文件+全量转义）/
│                          #   PDF（export_pdf，复用无头 Edge/Chrome 的 --print-to-pdf）；三者共用 collect() 同一份快照
│                          #   「SSL 证书」小节带**来源列**：TLS 握手（真握手） vs CT 日志（crt.sh 历史）
├── tools/import_ref_pocs.py # ast 静态解析参考项目 Python POC → config/pocs-imported/（导入项默认关闭）
├── tools/import_dir_dict.py # 外部目录字典 → 清洗 + **按技术栈拆桶** → config/dicts/dirs_{big,common,jsp,php,asp}.txt
│                          #   用法：py -3 tools/import_dir_dict.py --src <字典文件>（源路径只走参数，代码里不留绝对路径）
├── tools/import_fw_dicts.py # 从 dirs_big 派生**按框架细分**的字典（wordpress/tomcat/weblogic/spring/… 12 个桶
│                          #   + dirs_exposure）→ config/dicts/dirs_<框架>.txt；用法：py -3 tools/import_fw_dicts.py --force
├── tools/import_tlds.py    # 从 tldextract **内置快照**（`suffix_list_urls=()`，离线、绝不联网）导出公共后缀清单
│                          #   → config/dicts/tlds.txt（含 `co.uk`/`com.cn` 等多段后缀）；用法：py -3 tools/import_tlds.py --force
│                          #   tldextract 是**生成期可选依赖**，不进 requirements.txt；运行时只读生成好的 tlds.txt
├── tools/import_subdomain_dict.py # 深档子域名字典导入器（续139）：清洗 + 去重 + 并集写回
│                          #   config/dicts/subdomains_deep.txt（**默认写回目标**，精简档 subdomains.txt 一字不动）；
│                          #   纯离线、`--dry-run` 只看数不写文件、四种拒绝（详见 docs/pipeline.md §①）
├── tools/poc_review.py    # 导入 POC 的**按族复核**闭环（续114）：`--families` 看族分布 / `--dupes` 看
│                          #   「同指纹被抄成多种漏洞」的分组 / `--family wordpress` 出复核工作表（含每条
│                          #   实际在找什么的匹配器摘要 + 同指纹组大小 + 负样本校准命中）/ `--import <表>`
│                          #   **只搬人工写了 `ok` 的行**进 config/pocs-user/（文件头追加出处，不改模板内容、
│                          #   不覆盖同名、路径越界拒绝）。红线：机器不判定、没有"整批放开"旗标
├── tools/build_fscan.py   # 从源码自编译 fscan（续45 起；续166 加 `--fetch`/`--settings`：缺 Go 就取**仓库内**
│                          #   便携 Go、缺源码就按钉住摘要的 tag 归档取进 `tools/fscan-src/`；GOROOT/GOCACHE/
│                          #   GOMODCACHE/HOME 一律走 `toolmgr.go_env()`，一个字节都不写家目录。
│                          #   ⚠ 直跑必须有 `sys.path.insert(0, str(ROOT))`：`tools/scanner/` 那个**同名命名空间包**
│                          #     会顶掉真 `scanner` 包 ⇒ 续166 实测 `--wire` 这条路**从来没通过**（§6.2 第十九起）
├── tools/build_massdns.py # 从源码自编译 massdns（续165 加、续166 加 `--fetch`/`--settings`）：puredns 的传递依赖；
│                          #   官方只发 C 源码 ⇒ **仍需本机 gcc/make**，缺了如实报、不假装编成
├── tools/dirmap/          # dirmap 落点（**目录联接**，第三方项目不随仓库分发；.gitignore 排除，找不到就回退内置扫描）
├── tools/fscan/           # fscan 落点（同上：**目录联接**指向仓库外的自编译二进制；.gitignore 排除）
├── config/settings.yaml   # 全局配置（GUI「策略配置」页覆盖 gui/limits/checks/subdomain/passive/evasion/takeover/portscan/jsmine/dirscan/vulnscan/**screenshot/cert**/iprecon/fofa/**ssrf/shodan/quake/ctlog**/blacklist/**intel/heuristic/github/multileak/flags/afrog/queue/dev/http/tools/dicts** 三十一段（＝ DEFAULTS 全部段；dirscan 段含 mode/quick_max_paths/suffix_aware/big_dict/max_paths/**recursive_depth/recursive_max_dirs/recursive_max_paths**（递归三键，续30）；portscan 段含 mode/full_ports/exclude_scanned；cert 段含 enabled/max_sites/timeout/tls_ports））
│                          #   注：原文写「十八段」且漏列 ssrf/shodan/quake/ctlog，与 GUI 实际覆盖的段数不符，
│                          #   2026-09-24（续26）实测更正为 23 段；2026-10-12（续158）tools/dicts/http/queue/dev
│                          #   五段接上策略页后实测为 **31 段（= 全部段）**，`tests/smoke.py [8at]` 的例外名单已清空
├── config/keys.yaml       # 第三方 API key 专用文件（gitignore；load_keys() 只读，save_settings 不写回）
├── tools/calibrate_fingerprints.py # 组件指纹的**负样本校准**（续127，与 calibrate_pocs 同性质）：
│                          #   12 份内联合成响应（通用软 404 / 无厂商特征的登录页 / SPA 首页 /
│                          #   IIS·Apache 默认页 / 请求路径就是 /druid/login.html 的 Tomcat 404 …），
│                          #   逐条跑引擎自己的 identify()，报告"哪些标签被通用页打上"。
│                          #   零请求、**只报告不判分**（不自动降级/删规则）；实测外置 51 条判据
│                          #   0 命中 ⇒ 据此否掉了"给外置表加路径门控"（门控挡误报，而误报为 0）
├── tools/import_afrog_fp.py # afrog-pocs(MIT) 的 fingerprinting/ → **候选表 + 人工复核 → 追加**进
│                          #   config/dicts/fingerprints_extra.txt；`--scan`/`--table`/`--apply`/`--lint`，
│                          #   全程不发请求、不覆盖已有行、**没有"全部放行"旗标**（复核列空着＝零动作）
├── config/blacklist.txt   # 用户黑名单（纯文本，一行一个域名、# 注释；* 前缀与裸域等价；命中即不入资产库）
├── config/dicts/          # subdomains(84：精简档，永远全量参与) / subdomains_deep(177875：深档，续139 随仓库导入，来源写在文件头) / resolvers(13) / dirs_small(55) / cdn_cname(292) / cdn_ips(15) / waf_block_titles(11：WAF-CDN 拦截页标题文案，续112)
│                          #   fingerprints_extra(51 条/49 标签，续120)：**外置组件指纹**，TAB 分隔、
│                          #   每条带状态码与 `afrog-pocs(MIT)` 出处；复核结论与拒因见 docs/afrog-fp-review.tsv、许可见 NOTICE.md §3.2
│                          #   sensitive(9)：**A01 检查的数据源**（`路径|关键字|级别|说明`，见 §7）
│                          #   dirs_shallow(206)：**浅扫专用**（dirscan.mode=quick 只用它），按价值排序、人工筛选
│                          #   js_thirdparty(287：JS 第三方域名单 = 内置 + URLFinder jsFiler + 续22 补 20 条常用库/CDN/链上浏览器)
│                          #   waf_block_titles(11：厂商拦截页的**标题文案**，小写子串匹配 —— 只收专属文案，不收 403 Forbidden 这类通用词，收了就是自吃真发现)
│                          #   tlds(6423：公共后缀清单 = tldextract 内置快照，含多段后缀；tools/import_tlds.py 生成)
│                          #   目录字典按技术栈拆分：dirs_big(11882 全量) / dirs_common(10671) /
│                          #   dirs_php(933) / dirs_asp(162) / dirs_jsp(116)（tools/import_dir_dict.py 生成）
│                          #   再按**框架**细分 12 桶 + dirs_exposure（tools/import_fw_dicts.py 生成，
│                          #   运行时排在语言/通用字典**之前**，框架判不出就不吃这部分额度）
├── config/pocs-user/      # 用户上传 POC；config/pocs-imported/ 导入 POC（默认关闭）；config/nuclei-templates/ 官方模板投放点
├── tests/smoke.py         # 唯一测试：自包含靶场(127.0.0.1:8765) + 断言，见 §6
├── TODO.md                # 任务确认清单（待用户确认的排期，不是承诺，见 §9）
├── smoke_root/            # 测试靶场（含 .git/config 与 .env 两个"泄露"样本）
├── data/scanner.db        # SQLite（自动创建，gitignore）
└── logs/task_<id>_<ts>/   # 每任务工作目录（gitignore）
```

## 4. 架构与数据流（代码事实）

入口层（cli/client.py、gui/app.py）→ 编排层（runner.PipelineRunner）→ 阶段层（stages/*）→
检测层（pocs/engine.py、owasp/checks.py、fingerprint.py、evasion.py）→ 基础层（utils/config/log）→ 存储层（db.py）。
其中 `scanner/evasion.py` 是**所有 HTTP 出口的统一伪装层**（由 `utils.http_request` 调用），
`scanner/wildcard.py` 与 `scanner/passive.py` 只在 subdomain 阶段生效。

- 阶段顺序与注册：`runner.STAGE_ORDER` / `STAGE_REGISTRY`（当前 **13 个**：
  `subdomain → takeover → portscan → probe → **cert** → **screenshot** → osint → jsmine → dirscan → vulnscan
  → **intel** → **heuristic** → **github**`；
  `cert`（TLS 证书取证）与 `screenshot` 都**默认关**，都排在 `probe` 之后（要先有存活站点）；
  `screenshot` 需要本机 Edge/Chrome，浏览器路径探测见 `scanner/screenshot.py`；
  **但"默认关"指的是策略级开关** —— 建任务时勾了 `screenshot` / `cert`（或 CLI `-p screenshot` / `-p cert`）即
  **任务级点名**，GUI 落任务选项 `screenshot_on` / `cert_on`，阶段据此越过策略开关执行且不改全局策略
  （2026-09-23 续13：此前只认策略开关，用户勾了截图却被静默跳过，页面上永远没有缩略图；
  站点页签的「补截图」按钮同样落 `screenshot_on`；续14 的 `cert` 沿用同一套门控，
  并把 CLI 的 `-p` 默认值改成 `None` —— 否则 `-p screenshot`/`-p cert` 会被策略门控静默吃掉）；
  `cert` 只做**一次只读 TLS 握手**（`verify_mode=CERT_NONE`）并解析证书（CN/SAN/有效期/自签/指纹），
  **是取证不是漏洞结论** —— 自签/过期是证书属性，不等于漏洞；解析用纯标准库 ASN.1/DER（`scanner/certs.py`）；
  `dirscan` 默认开且**续144 起默认深扫**（`dirscan.mode=deep` + `recursive_depth=1`；`quick` 档仍在，需显式选，见 §8）；
  末尾三个**线索阶段：代码 DEFAULTS 关，而**随仓库分发的 `config/settings.yaml` 已把 `intel` / `heuristic` / `github` 三段打开**（续159-附，主理人选定的默认配置）⇒ `load_settings()` 是文件盖在 DEFAULTS 上 ⇒ **新克隆实际会跑这三段**，且**只写 `leads` 表**（不写 `vulns`、不计入漏洞数、不自动导 POC）：
  `intel` = CISA KEV 情报 × 本地指纹白名单式匹配（`scanner/intel.py`），
  `heuristic` = 对已收集数据做零请求的差分/异常聚合（`scanner/heuristics.py`），
  `github`（续26）= 拿目标**注册域**去 GitHub 公开代码里搜命中（`scanner/github_leak.py`）
  —— 三条硬边界：**只落仓库 / 文件路径 / 命中规则名**（绝不落文件内容，避免凭据明文入库）、
  **`auth=False`**（任务级登录态绝不发给 GitHub；GitHub 自己的 token 走 `Authorization`）、
  **随包已开（DEFAULTS 仍关）+ 没 token 零请求**（token 在 `config/keys.yaml` 的 `github.token`，代码搜索接口要求认证）。
  新增阶段在此登记即可被 CLI `-p` 与 GUI 识别）。
- 阶段开关有两层：**任务级**（建任务时勾选 stages / CLI `-p`）与**策略级**
  （`settings.takeover.enabled` / `portscan.enabled` / `jsmine.enabled`，阶段内部自查后跳过）。
  `takeover` / `jsmine` / `dirscan` / `vulnscan` 默认开，
  `portscan` / `screenshot` / `cert`（都受策略级开关约束）/ `intel` / `heuristic` / `github` 默认关（**这是 DEFAULTS 那一档**；随包分发的 settings.yaml 自续159-附起把 `intel`/`heuristic`/`github`/`ctlog`/`multileak` 改成开，而 `portscan`/`screenshot`/`cert` 仍是关 —— 说「谁默认开」之前要先看这两份并不相等）。
  另有**任务级「全量档」选项**：`portscan_full`（全端口 1-65535，见 §8）与 `dirscan_full`（深扫，见 §8），
  二者都是"用户点名要扫"→ **即使对应全局 `enabled=false` 也执行**，且 GUI/CLI 在勾了全量档却漏勾阶段时
  **自动补上该阶段并按 `STAGE_ORDER` 归位**（`runner` 按给定顺序执行、不排序，所以必须显式 sort）。
  **例外是 `osint`**：它自身没有 `enabled`，而是由 `iprecon.enabled` / `fofa.enabled` 两个
  子开关控制，**两者都关时整阶段直接跳过（一次请求都不发）**；`fofa` 下另有两个**子能力**：
  favicon（`icon_hash`，默认随 `fofa.enabled`）与**证书反查**（`cert_enabled`，默认跟随），
  各自有阈值排除（黑 ico / 通用证书）。第三个子能力是**标题反查**（`title_enabled`），续22 起带
  **归属相关性过滤**（`fofa.title_match`，默认 `label`：标题 token 须与候选域名某个 label **完全相等**
  才入库，挡掉"标题恰好含同一子串"的无关域名；设 `substring` 回退旧的子串匹配）；切不出 token 的标题
  （如纯中文）**fail-open 保留**。
- **黑名单在三处入库前过滤**（`subdomain` / `jsmine` / `osint`，统一走 `scanner/blacklist.py`）：
  命中即不写资产库，因此后续阶段自然不扫 —— 新增"产出域名"的阶段必须记得在入库前过一遍。
- **jsmine 的域名形态判断含公共后缀（PSL）校验**（续22）：末位必须是合法公共后缀（读
  `config/dicts/tlds.txt`，支持 `co.uk`/`com.cn` 等多段后缀），否则 `wallet.filter.withdraw`
  这类"点号连接的 JS 成员访问链"会被当成域名。清单缺失/为空时 **fail-open**：回退旧的宽松判断
  并告警一次（绝不静默丢资产）。
- **测试隔离靠两个环境变量**：`CTFSCANNER_DB`（库路径）与 `CTFSCANNER_LOGS`（任务工作目录）。
  `tests/smoke.py` 顶部把两者指到 `logs/smoke-<随机>/` 并在退出时删除 —— 跑测试**不会**污染
  真实 `data/scanner.db` 与 `logs/`。跑任何"会写资产"的脚本时请沿用这一约定（见 `docs/usage.md` FAQ）。
  两者都经 `scanner/config.py::env_path()` 归一（2026-09-23 续10）：空值回落默认、剥外层引号，
  **仅 Windows** 把 `/c/Users/x` 这类盘符式 POSIX 路径翻译成盘符形态 —— Git Bash 里
  `export CTFSCANNER_DB="$PWD/logs/x.db"` 传的是 `/c/...`，不归一就会被解析成**盘符根下的 c 目录**
  （库建到盘符根，`rel_display()` 还打印残缺路径，已实测踩过）。POSIX 系统上不做转换
  （那里 `/d/tmp` 就是普通目录）。新增"路径型"环境变量请复用 `env_path()`，不要各写一套。
- 每个阶段结果**三写**：任务目录文本产物（如 sites.txt）、SQLite、`ctx.results`（供下一阶段直接用）。
- 阶段级容错：单阶段异常不中断流水线，错误写入 `tasks.error`，任务最终仍置 `done`（docs 已声明此语义）。
- GUI：**请求线程与执行线程是分开的** —— `_spawn()` 不再直接起线程，只把本次运行的精确入参写进库
  （`tasks.run_payload` + `status='queued'`），由 `scanner/queue.py` 的**常驻 worker**认领执行
  （默认 `queue.workers=1` 串行；认领走 `db.claim_next_queued` 的原子 UPDATE，保证同一任务只有一个
  消费者 —— `runner._register_stop` 是覆盖式注册，重复消费会让「停止」失效）。
  进程重启后 `db.reconcile_orphan_tasks` 把"pid 已死且带运行规格"的 `running` **重新入队**接着跑，
  任务不丢；不带运行规格的行（CLI 直跑 / 老库遗留）仍标 `failed`（CLI 是前台阻塞、没有 worker 可接）。
  续49 起的事实，本行此前还写着"无任务队列"（续116 按代码更正）。
  另：续29 的详情页「续跑」是**用户手工**从断点接跑的入口，与上面这条自动对账并存、不互相替代。
- **同任务「追加式执行」**（续25）：任务详情页的「复查 / 送去探测」可勾「追加到本任务」（续145 起
  「补扫」那几个入口已摘掉，`POST /api/rescan` 接口本身还在，`追加` 语义由「复查」继承），
  把该阶段**追加进源任务**（不新建），结果累积、**跨运行去重**（同名站点/目录/端口/漏洞/子域名/
  证书不重复入库），续写同一 `log_file`、**不清 `error`**、进度重置。硬约束：**同任务并发追加必须
  拒绝**（`runner._register_stop` 是覆盖式注册，第二次追加会顶掉停止事件）；站点/IP/全端口三个
  **无源**入口**不能追加**（只保留"新建任务"）。被追加过则 `options.append_count>0`，详情页与
  导出报告显示「追加」横幅。内核在 `runner.run_task(..., append=True)`，去重在 `db.drop_existing()`。
- **统一并发 / 限速 / 全局预算门控（F2，`scanner/throttle.py`）**：`StageContext.__init__` 在注入
  登录态**之后**，用 `throttle.inject` 给 settings 副本再挂一个任务级限流器（`settings["_throttle"]`）。
  三条出口——`utils.http_request`（HTTP）、`utils.run_cmd`（外部子进程）、`portscan` 的裸 socket
  （`_probe_port`）——取"在飞名额"都走 `throttle.slot(kind)`：先**任务级闸**、再**进程级闸
  （跨任务共享，`_GLOBAL_STATE`）**、最后**令牌桶**，顺序固定以防死锁。实际并发是
  `min(阶段并发, max_inflight_per_task, max_inflight_global)`（`Throttle.effective_cap`）——
  这才是"消灭 `stages/portscan.py` 8 主机 × `full_workers`(256) = 2048 在飞 / 进程级零上限"的落点。
  **预算耗尽（`budget_total`）＝按停止处理**：`Throttle.exhausted()` → `StageContext.stopped()` 为真
  → 各阶段在循环边界干净收尾 → `PipelineRunner` 把任务标 **`stopped`（不是 `done`）** 并追加一条
  `[throttle] 请求预算耗尽…结果不完整` 的错误行（与"用户点了停止"用不同文案区分）。
  取消仍是协作式：所有等待都是 `Condition + wait(poll)` 轮询 + 入口检查，置位即抛 `StopRequested`
  并释放已持有的闸，**绝不"点了停止却卡在等锁"**。v1 覆盖缺口见 §7。

## 5. 关键不变量（改代码时务必保持）

1. **所有 HTTP 必须走 `utils.http_request`** —— 统一 UA、超时、证书校验开关（`verify=None` 时**按出口**读配置：目标侧 `limits.verify_tls`／第三方 `limits.verify_tls_external`，续42，见 §7 凭据红线）。
   不要直接 import requests/urllib。这也是**唯一伪装出口**：`utils._headers` → `evasion.browser_headers`
   （UA 随机化、浏览器化请求头、可选 XFF 伪装），改 HTTP 行为只在这一处生效。
   **登录态（任务级 Cookie/Token）同理只在这一处生效**：`http_request(..., auth=True)` 才附带
   `settings["_auth_headers"]`（由 `runner.StageContext` 注入的任务专用副本）。**默认 `auth=False`** ——
   新增调用点时先问一句"这个 URL 是目标侧还是第三方接口"，第三方**永远不加 `auth=True`**（见 §7 凭据红线）。
   **连接复用（续116）**：`_do_http` 用的是**线程本地**、**按 `verify` 分档**缓存的 `requests.Session`
   （`utils._http_session`），不是模块级 `requests.request()`（那等于每条请求重做一次 TCP/TLS 握手，
   自签 TLS 实测 50 ms/请求）。两条由此而来的约束：① **每次请求都从空 cookie jar 出发**是刻意的语义
   （"上一条路径的 Set-Cookie 不许影响下一条"），新增"要同一会话连续多跳"的用法必须显式实现，
   不能指望 Session 替你存；② 别把它改成**跨线程共享**的一个 Session —— requests 不保证 Session
   并发安全，且 `cert_reqs` 写在连接池对象上，会重演续42 修掉的出口分流。
   **`jsmine` 是唯一的"混合出口"模块**（续43）：页面自身请求按定义发往目标侧（`auth=True`），但同一页
   `<script src>` 绝对化后可能指向第三方，必须**按 URL 主机逐个判** `auth=`（`_is_self_host` 命中自家
   注册域才带），不能因为"URL 来自目标页面"就把整批脚本请求都带上登录态。
2. **外部工具优先 + 内置兜底**：调用前用 `which()`（裸名走 PATH；**带 `/` 或 `\` 的相对路径按
   项目根折算**，不按进程 CWD —— 否则从仓库外启动 GUI/CLI 会把装好的工具判成"未安装"再**静默降级**），
   Good 工具再用 `verify_tool()` 做版本握手
   （防止 pip 的 Python `httpx` 同名命令被误用）。**例外有两个：`fscan` 与 `afrog` 都不做握手**（afrog 是续119 按实测加的，理由见下面 §7 那条：它的 `-version` 在管道下不退出）—— 它的 `-h` 是
   "指定主机"而不是 help，也没有 `-version`；套默认探针会把**装好的** fscan 误报成"未通过版本
   校验"，`portscan` 随即**静默**降级到内置扫描（慢一个量级且无任何报错）。见
   `cli/client.py::check_tools()` 与 `tests/smoke.py` 的 `[7f]`。
   **afrog 是同一类坑的第二例（续119 实测，别只看"官方有没有 --version"）**：它**有** `-version`，
   shell 里秒回 `Afrog 3.5.7`；但只要 stdout 是**管道**（正是 `run_cmd` / `verify_tool` 的调用方式）
   它就**不退出、也不吐一个字节**（6 秒超时；把 stdin 换成 /dev/null 也一样）—— 配握手等于
   ①每次开「外部工具」页白等一个超时，②把**装好的**它报成"未通过版本校验"。所以 `verify=None`，
   并把 `toolmgr.status()` 的握手超时 **30s 收到 8s**（一次版本横幅不需要半分钟，而这种"存在但一被
   管道捕获就挂着"的工具已被证明存在）。回归 `[8x]` 里钉着"afrog 一次探测子进程都不许起"。
   `cli/client.py::check_tools()` 与 `tests/smoke.py` 的 `[7f]`。
   **后缀容错（续61，跨平台硬要求）**：`config/settings.yaml` 写死 `tools/fscan/fscan.exe`，
   而 Linux 产物名是无后缀的 `fscan` —— 照配置值直找必然失败并**静默降级**。故 `which()` 先按原值找、
   找不到再试 `_ext_variants()` 的"去掉/补上 `.exe`"变体，**一份配置两端通用**。
   ⚠️ 探测**必须走 `_probe()` 直探文件系统**，不能只靠 `shutil.which`：Windows 上**路径里带目录**时
   `shutil.which` 退化成"精确探这一个名字"、不补 `.exe`（`nmap` 那种**裸名**才由它按 PATHEXT 找）；
   POSIX 上 `_probe()` 另判可执行位（与 `shutil.which` 同语义）。回归钉在 `tests/smoke.py [7y]` ⑤。
3. **非破坏性**：新增检查/POC 只允许探测类请求；POC 规范见 docs/poc-guide.md。免杀（evasion）只改变
   payload 的**编码形态**与请求伪装，不改变语义，不越过"无爆破/无 DoS/无写操作"红线。
4. **SQLite 线程安全靠"每次调用独立连接"**（db.get_conn 用完即关）——不要改成共享长连接。
5. **POC 注册表与扫描联动**：`engine.load_enabled_pocs` 只返回注册表里 `enabled=1 AND status='ok'`
   且级别未被 `skip_severities` 排除的记录，因此新增 POC 后需 `runner.sync_pocs()`
   （GUI 启动/刷新时会调用）。
6. **漏洞去重是调用方约定，数据库层没有约束兜底**：约定的去重键是 `(target, poc_id)`
   （即"每 POC 每目标最多一条"），但 `vulns` 表**没有** UNIQUE 约束（`scanner/db.py` 建表语句）、
   `db.insert_vuln` 是**裸 INSERT** —— 去重完全由**调用方**在做：
   `scanner/stages/vulnscan.py` 与 `scanner/stages/takeover.py` 各自建 `seen` 集合去重；
   `scanner/stages/jsmine.py` 则是直接插入、靠上游按主机名去重。因此新增任何写 `vulns` 的路径
   **必须自己保证去重**，不能指望数据库拦（用户已明确把"给 `vulns` 加 UNIQUE 约束"划到范围外）。
7. **分级门控（三层，`checks` 段）**：
   1. `skip_severities` 默认 `["info","low"]` —— **执行级**：这些级别连请求都不发
      （`owasp.checks.enabled_checks` + `pocs.engine.load_enabled_pocs` 同规则，helper 是
      `config.skip_severities()`）；
   2. `disabled_categories` / `disabled_checks` 命中的检查根本不执行（省请求）；
   3. `min_severity` 代码默认 `medium`，**随包分发的 settings.yaml 是 `high`**（续159-附） ⇒ 新克隆的默认任务**只产出 high/critical，medium 会被结果闸丢掉**（这是主理人选定的口径，要旧的宽口径就在策略页把最低报告级别改回 medium） —— **结果级**，过滤残余的低危/info 结果。
   即 `a02-no-https`、`a05-security-headers`、`a05-banner-disclosure` 这类项默认既不执行也不产出。
   4. **被结果闸挡掉的量必须可见**（续176，用户点单）：低于 `min_severity` 的发现是"执行过、
      也命中了"，只是在入库前被丢（§0 第 10 条：被过滤 ≠ 不存在）。三个丢弃点
      （`owasp.checks.run_all` / vulnscan 的 POC 路 / afrog 路）各计数
      （`owasp.checks.SeverityBlocked`，线程安全；**判据仍只有 `severity_ok()` 一处**，
      计数器只数数、不引入第二份门槛逻辑），阶段末**覆盖写**落库 `tasks.sev_floor` +
      `tasks.sev_blocked`（追加执行时累加会重复计同一隐藏项＝虚高，本仓不接受虚高数字 ⇒
      页面只能说"最近一次 vulnscan 运行"）。出口两处：报告 MD/HTML 概览 note 行 + 任务详情页
      「潜在漏洞」页签顶部一行，**文案唯一产地是 `report.sev_blocked_note()`**（模板不拼第二份，
      Row/dict 都认、0 条不渲染、老行缺列不出话）。与 `skip_severities` 那类"根本不执行"
      分开说 —— 两件事混说就是假话。
8. **所有对外"在飞动作"必须过统一门控（F2，`scanner/throttle.py`）**：HTTP 走 `utils.http_request`
   （已自动读 `settings["_throttle"]`）、外部子进程走 `utils.run_cmd(..., throttle=...)`、裸 socket 走
   `throttle.slot("socket")`。新增任何"会连目标 / 起进程"的调用点时，**必须显式把限流器传进去**
   （`ctx.throttle` / `settings["_throttle"]`）—— 不传就等于绕过并发 / 限速 / 预算。
   `throttle=None` 时按旧行为直通，那是给**离线工具与单测**留的口子，**不是给扫描路径用的**：
   漏接一处就会出现"点了停止仍有请求在飞"或"预算形同虚设"。
   补充（续21）：`throttle.slot()` **不可重入** —— 底层 `_Gate` 是**计数信号量**，同一线程在已持有
   名额时再 `slot()` 会**自锁**（等自己释放，永不返回）；**禁止在同线程里嵌套取名额**（需要"同一
   动作占多份"时用 `weight=` 一次取足，别嵌套）。`budget_total` 是**硬上限**：预算的"检查 + 扣减"
   在**同一临界区**内原子完成（`Throttle._reserve_budget`），并发下**不可能超发**（回归 `[6g]`）。
9. **开发模式必须压掉一切真出网的第三方能力**（续97，`scanner/devmode.py::suppress_external`）：
   `dev.enabled=true` 时，`DEV_EXTERNAL_SECTIONS`（`iprecon` / `fofa` / `shodan` / `quake` /
   `ctlog` / `github` / `intel` —— 每个都会发**真实外部请求**或花**真实配额**）里当前开着的段，
   一律在**任务专用副本**上置 `enabled=False`，接在 `runner.StageContext` 的 `auth.inject` /
   `throttle.inject` 同一层。**三条边界**：`dev.enabled` 为假时原对象原样返回（零副作用）；
   绝不写回 `config/settings.yaml`（文件始终是用户的，关掉 `dev.enabled` 即恢复）；压住了必须
   在任务日志里点名（`[devmode] 开发模式已压制外部情报源：…`）—— 静默降级是本仓反复出事的地方。
   自检另有更窄的一份 `devflow._EXTERNAL_OFF`（不含 `iprecon`/`github`/`intel`，它们各有处置），
   两者口径不同**是刻意的**，别合并。回归见 `tests/smoke.py [8e]`（含 `enabled()` 恒假/恒真两向变异）。


10. **登录凭据只在 `users` 表里，配置文件里一个都不许有**（续117）：旧的 `gui.token` 引导口令
   （库里 0 个账号时能直接换管理员身份）已整支摘除 —— `config/settings.yaml` **被 git 跟踪、仓库公开**，
   "能换管理员身份的串"写在里面就等于交给每个读者。现在的路径：0 账号 → `serve()` 的首启动向导
   （`scanner/admin_setup.py::wizard()`）或 `python cli/run_users.py --create-admin`；`_session_user()` 对
   **不带 `uid` 的会话一律作废**（升级前留下的引导 Cookie 也不再认，回归 `[8v] ③` 钉的就是这一档）。
   新增任何"绕过账号的登录路"都算违反本条；页面侧也不许再出现口令输入框（`[8v] ④` 按渲染出的
   HTML 判，注释里写不写键名都不影响判据）。
   ⚠️ **唯一豁免（续131，用户 2026-10-08 明确批准）**：`scanner/edgeauth.py` 的 401 边缘认证门
   **就是一条独立于 `users` 表的登录路** —— 它存在的前提是 `config/settings.yaml` 把 `gui.host`
   改成了 `0.0.0.0`（控制台不再只听回环，于是任何能路由到 5000 的人都打得到登录页）。豁免只开到
   这一条，**本条的主体没有被削弱**：`users` 表仍是登录凭据的唯一存储。边界有四条（续132 改了
   存储口径）：口令**明文**写在 `config/edge_auth.yaml`，该文件与 `config/keys.yaml` 同在
   `.gitignore` 里 —— 开关在 `settings.yaml`、凭据在 `edge_auth.yaml`，**分两个文件正是因为前者被
   git 跟踪而仓库是公开的**（回归 `[8ai] ⑨b` 钉住"哨兵口令不得出现在任何被跟踪文件里"）；
   **关**；`config/settings.yaml` **本身也被跟踪**，续151 起它里面的 `gui.edge_auth.enabled`
   与 `DEFAULTS` 一致都是 **false**（用户诉求"clone 下来直接打开控制台"），但 `host: 0.0.0.0`
   仍写在文件里 —— `load_settings()` 是 `DEFAULTS + 该文件` 的合并，所以**直接 clone 的人拿到的是
   文件里的值**：照样绑所有网卡、但**不再有 401 门**。要开门就把文件里那项改回 `true` 并跑 `--set`。门开而口令未设 = 一律 401（fail-closed）并在
   启动横幅点名。**补口令有三条路**（续146-附2 补齐了第二条 —— 在此之前无终端的机器只剩第三条）：
   ① 有终端跑 `python -m scanner.edgeauth --set`，getpass 两次确认；② **没有终端**（容器 / systemd /
   cloud-init）用 `CTFSCANNER_EDGE_PASSWORD` 喂同一条命令 —— 口令仍走 `validate_password`（环境变量
   **不是免检通道**）、文件仍 0600、输出里不出现口令；③ 直接手写 `config/edge_auth.yaml`
   （没人给它 chmod，所以不推荐）。启动向导 `wizard()` **三条都不代填**，无终端时只提醒
   （`[8ai]` 的红线；`[8aw]⑤` 补钉了"环境变量就摆在那儿时也不填"）。这一档与另两个秘密同构：
   `admin_setup.ENV_PASSWORD` 建管理员、`keystore.ENV_PASSPHRASE` 解锁凭据密文 ——
   **只有显式命令吃环境变量，启动流程一律不吃**（`[8aw]①` 把三个常量名一起钉住，重名也算红）。另两条实操事实：明文 HTTP 下 Basic 会把口令随每个请求带出去（跨不可信链路仍需
   TLS 反代）；这道门**不是** `0.0.0.0` 的替代品 —— `gui.allowed_hosts` 不填时 Host 白名单仍会被
   放宽（`gui/app.py:520` 的 `CS_GUARD_HOST`），那一档要单独配。回归 `[8ai]` 钉住以上全部。

11. **指纹判据只有一条形状，且第三方内容必须"复核后才落地"**（续120）：
    `(part, 正则[, 状态码集合])` —— `part ∈ headers|body|cookies`，第三元素缺省＝不分状态。
    ① 内置 `SIGNATURES` 不许因为外部字典的存在被改写；同名标签**允许**在外置表再加一条判据
    （析取语义，与内置表一致），但**不许**为已有产品另造近似标签 —— `sites.tech` 里同时出现
    `jenkins` 与 `jenkins-login`，dirscan 的框架桶只认前者，后者等于白打。
    ② 外置表**现在是三份**（续197）：`fingerprint.EXTRA_FILES` = 手写那份
    `config/dicts/fingerprints_extra.txt` + 社区库转换来的 `fingerprints_hub.txt`
    （FingerprintHub / ObserverWard）+ `fingerprints_ehole.txt`（EHole 棱洞），共 2138 条规则。
    三张**同一份格式**，解析逻辑仍只有一份（多一个文件 ≠ 多一套读法）；后两张由
    `tools/import_fingerprints.py` 生成（**一次性转换器**：外部仓库源码不进本仓，重跑即重新生成）。
    分隔符**只能是 TAB**：判据本身是正则，`|` 是它的选择运算符，用 `|` 切列会把判据腰斩。
    ⚠ 三张的性质不同：手写那份**每条都带状态码门控**（这正是它存在的意义），社区库那两张**不分
    状态**（它们是"认不认得出这个组件"）⇒ 别拿同一个标签当两种判据的尺子（续197 的门禁就栽过：
    `grafana` 两张表都有，手写那份要求 200，社区那份不要求，404 上也打标签是**正常的**）。
    社区库的两个已知取舍（都写进了转换脚本）：默认只导 `metadata.verified: true` 那批
    （`--all` 才全量），以及 `GENERIC_WORDS` 黑名单 —— 不合这两道闸时，一份合成通用登录页会被
    一次打上 38 个互不相关的标签（"全中"比全不中更糟）。
    **长尾误报的清洗落点就是那张黑名单**（续199：按 `tools/calibrate_fingerprints.py` 的负样本
    逐条回捞，13 → 3；剩下 3 个是"语料自己就是它"的服务器标签，列白名单后判据收紧到**零**）。
- **POC/指纹的自动更新（`--update-pocs`，续206）**：`scanner/pocmgr.py` + `tools/update_pocs.py`，
  用法 `python tools/update_pocs.py --source nuclei [--ref vX]`。六条硬规矩照工具更新器：只 https、
  只官方主机（github / raw.githubusercontent / codeload）、落盘前过 SHA256（manifest 记着 ⇒ 重复跑
  是 no-op）、成员名防路径穿越（**先拒再剥** —— 先剥会让 `/etc/passwd` 变合法相对路径，那正是
  zip slip 想要的）、逐文件校验不过就拒收、只写本项目目录。
  `config/nuclei-templates/` **本来就在** `pocs.engine.POC_DIRS` 里 ⇒ 投放即被发现，**不用回写
  任何配置**。上游目录名会变（2026-10-16 实测 `http/fingerprints/` 已不存在，指纹类并到了
  `http/technologies/`）⇒ 取到 0 个时错误信息必须说清"目录名变了？仓库结构改了？"。
  **不做成定时任务**：拉外部仓库＝往机器里写第三方文件，必须人下命令（§2）。
- **软 404 的「没证据」不再冒充真发现（续210，借鉴 7scanAI）**：`scanner/stages/dirscan.py` 两档。
  - **T1 基线不可得**：`_baseline()` 的 3 次随机 marker 路径**全失败**时，元组里的 `ok_samples` 停在 0
    ⇒ 这一轮软 404 过滤**没有任何证据**。此时命中**照常入库**（展示层过滤 ≠ 删数据，§0 第 10 条），
    只在 `dirs.note` 追加固定 token `baseline-unverified`，并给该站点记账、轮末日志点名总量。
    「确实有 .env」与「当时没比成」长得一模一样，是 AGENTS §6.2 第十七起同族毛病。
  - **T2 语义矛盾判据**：`datafile_html_contradiction(path, text)`（纯函数，与 `is_uniform_block` /
    `block_markers()` 并排，**不在阶段循环里内联写正则**）—— 路径形如数据文件
    （`.env` / `.git/config` / `wp-config.php.bak` / `.sql`…）而响应体是 **HTML 文档** ⇒ 判软 404 模板。
    反向保证写进断言：真 `.env` 回 `text/plain` 键值正文**绝不**被挡（否则就是把 A01 真发现吃了）。
    两条判据各有适用面，不许合并（基线比对对响应不稳定的站点会失效，内容判定不依赖基线）。
- **外部字典源与「这一行来自哪份字典」（续222）**：`dirscan.dict_sources` 零入仓接第三方字典目录
  （如 dirsearch 的 `dicts/`，一个分类一个 `.txt`）。**只在深扫全层生效**（快扫 150 条精选与
  框架补充扫描不吃，避免被第三方大字典稀释）。`after` 按**层名**（fw/lang/shallow/exposure/common）
  定位 —— 层名与字典文件名是两个键空间（`dirs_exposure` ≠ `exposure`，本轮实测踩过）。
  每行命中的来源写 `dirs.dict_src`：内置层用字典文件名（`dirs_php`）、外部源用 `来源名/分类名`
  （`dirsearch/api`），**只放名字、绝不放绝对路径**（页面与报告是交付物）；策略页只读展示时
  路径仍过 `rel_display(mask_outside=True)`。
- **指纹标签的来源、主次与统计（续223 + 续224）**：`fingerprint.identify(resp, where, detail=True)` 回
  `{tag,src,origin}`；`collect()` 的桶是 `{tag: origin}`（doc/js），`flush()` 与 `sites.tech`
  同一条 UPDATE 写 `sites.tech_detail`（JSON，紧凑键 `t`）。**旧 detail 原样保留**（一次补标
  不许把老标签的 JS/内置来源洗掉），完全没有来源才落 `unknown`。页面/报告只认
  `fingerprint.tech_groups()`（主文档+内置 > … > 未知，**前 3 个主标签、其余折叠 +N**）——
  别在模板/report 里各写一份排序；**来源统计**走 `fingerprint.tech_stats()`（内置优先、只靠 JS 单独计数）——别在路由/模板里另算。
- **字典一览/预览/导出的边界（续223 + 续224）**：`scanner/dictstats.py` 只回**条数**与**最多 200 行 / 64 KB**
  （默认 100 行）；`resolve_builtin()` 只认 `settings["dicts"]` 的键，`resolve_external()` 只认
  `dirscan.dict_sources` 的下标 + 根目录下的 `.txt` 分类（`picks` 过滤、`resolve()` 后父目录
  必须仍是配置根）。**禁止**把请求参数当路径拼接 —— 预览接口不是任意文件读取，大字典也
  不许整份下发（前端扛不住）。**导出**走 `/dict_export`（单份附件 / 整源 zip；同一套 resolve，zip 限 64 类 / 32 MB）。
- **favicon 的两套指纹与页面贴图（续225）**：probe 一次 GET 走 `fingerprint.favicon_info()` →
  MD5（`sites.favicon`，POC 前置判定）与 mmh3（`sites.icon_hash`，FOFA/Shodan 提问值），
  图标本体落 `favicons/<md5>.ico`（`sites.icon_file`）。osint 优先复用 `icon_hash`（不要为每家
  平台重抓）；结论写 `sites.icon_ext`：expanded > black > empty（多平台取最有信息量的）。
  `/favicons/<task_id>/<name>` 只认 `<32hex>.ico` 且必须在该任务工作目录的 `favicons/` 下。
- **截图取图时机（续225）**：`screenshot.settle_ms`（默认 3000）→ `--virtual-time-budget`；
  jsmine 后 `ScreenshotStage.verify_after_js()` 用 H0/H1/H2/H3 多数表决（出现两次才换图，
  都不重复保留旧图并记 unstable）。复核只覆盖 `sites.shot` 同一路径；只在 screenshot 真跑过时触发。
- **邮箱的入口（续225）**：`emails` 表早已存在，任务页的「邮箱」页签走 `_ASSET_PAGES["emails"]`
  服务端分页（按 task_id 过滤）；别再只把它挂在跨任务 `/emails` 页。
- **logs/ 清理只走点名（续226）**：清单在 `docs/logs-cleanup.md`（必留确切文件名 / 可删候选前缀 /
  `task_*` 条件可删）；执行只走 `tools/clean_logs.py --apply <确切名字>`。**禁止**
  `rm -rf logs/*` / `rm -r logs` / `shutil.rmtree("logs")` / `glob(...).unlink()`；
  门禁 `[226]` 扫危险形态，并自测"通配 / 必留 / 未登记"三类拒绝。
- **Host 碰撞不再要勾（续227）**：策略 `hostcollide.enabled` 默认开 ⇒ 建任务页**不放勾选框**
  （`name="hostcollide"` 不得再出现）；要单任务强制跑用详情页那颗按钮，全局开关在策略页。
  `[219]④` / `[201]⑤` 钉住这条，别再把勾选框加回去。
- **目录结果的「来源字典」三条路都要有值（续228）**：内置扫描走 `_scan()` 的 jobs 四元组
  第四项（`dirs_php` / `dirsearch/api` / `suffix`）；外部工具 **dirmap 那条路走
  `_parse_output(src=...)`**（`dirmap:<模式>`，无 `-e` 时 `dirmap:通用字典`）——
  它用的是 dirmap 自带字典，不许写成我们的字典名（假话），也不许留空（那一列会显示 `-`）。
- **第三方情报接口必须自带节流（续229）**：FOFA 按 **key 计频率**，osint 是循环反查
  （favicon/证书/标题各一次）⇒ 不节流必然撞 **HTTP 429**；节流走 `fofa.min_interval`
  （默认 3s，`_rate_wait()` 的 `now`/`sleep` 可注入以便测试）。429 的语义是"你发太快"，
  按 `Retry-After` 退避重试一次后再判失败，**错误文案必须指到 `fofa.min_interval`**，
  不许说成"接口坏了"，也不许一遇错就 break 掉整轮反查。VirusTotal 那路早已同款。
- **进度是单调的（续230 + 续231）**：只有 `run_mode == fresh` 才能把 `progress` 归零；
  `append` / `resume`（追加到本任务、重截、Host 碰撞补跑、续跑）必须从当前进度起，
  按 `[_base, 100]` 推进 —— **归零点全仓只有两处，都要带 `run_mode` 判据**：
  ① `runner.run()` 起跑（阶段边界/被停止也要用 `_base`）；② `db.start_task_run()` 队列认领
  （它先于 runner 执行，漏了它 runner 的 `_base` 读到的已经是 0）。fresh 还要清
  `elapsed_seconds`；长阶段进度本来就不动，任务列表必须把 `current_stage` 写在百分比旁边。
- **送探默认建子任务（续232）**：拓展页「送去探测」的「追加到本任务」**默认不勾** ——
  点按钮就新建一个子任务（独立进度/结果页，任务列表「子任务」行内展开）；勾上才折叠进本任务。
- **送探范围默认「只送勾选」（续239）**：`scope` 表单默认 `picked`，空勾选 ⇒ 409 明确文案
  （**不许**静默 redirect——"点了没反应"比报错更伤人）；后端 API 缺省语义保持 `all` 兼容旧调用方。
  「子任务」面板的根 = **请求的那个任务**（`api_task_subtree` 不再上溯树根）；编号列显示
  `树内编号（#任务号）` 两套并见。送探必须留日志：父任务日志（范围/域名/新任务号）+
  runner 首行 `===== 本次目标：… =====`。
- **子任务面板行内要带进度条（续241）**：`pvSubtreeHtml` 的进度格是
  `bar + 百分比`（不是光秃秃一个数字）；编号列保持 `树内编号（#任务号）` 双编号；
  根 = 请求的那个任务。父子进度独立——父跑完就是跑完，子任务不许影响父的进度。
- **端口占用处置（续233，主理人规则）**：GUI 起动时首选端口被占 ⇒ 走
  `scanner/portguard.kill_occupiers()` **直接结束占用者、占回首选端口**（SIGTERM 等 1.5s →
  SIGKILL；`/proc` 解析占用者，无子进程）。**绝不杀**自己 / PID 1 / cmdline 读不到的进程；
  每次杀都连 PID+命令行进启动日志。开关 `gui.kill_port_on_conflict`（默认 true，策略页有
  勾选框，POST 映射必须带上）与 `CTFSCANNER_GUI_KILL_PORT=0`；杀不动/找不到占用者 ⇒
  退回续150 的"自动顺延"。只作用于 GUI 监听端口，别把这条规则带到 fixture / 队列 / 探测目标上。
- **前端资产改动必须带版本号（续234）**：`app.js` / `style.css` 的 URL 一律
  `url_for('static', filename=…, v=static_v(…))`（mtime 版本化）＋
  `SEND_FILE_MAX_AGE_DEFAULT=30 天`。直接改文件不改 URL，用户端最长 30 天拿旧缓存；
  把 max_age 调小来"修缓存"是反模式。新增**根路径公开端点**只能走
  `webpath._PUBLIC_PATHS`（当前仅 `/favicon.ico`），放行了什么在 CHANGELOG 里必须能查到。
- **老数据回填是"补抓"不是"补算"（续235）**：`icon_hash`（mmh3）必须拿到图标的**字节**才
  算得出，老任务只存了 MD5 ⇒ 回填只能重新 GET 一次（`iconbackfill.backfill_task`：幂等只补
  `icon_file=''`、单次 cap 200、顺序执行、stop 可中断、重入拒绝）。别试图从 MD5"反推"mmh3
  —— 那是密码学上的不可能。新入口必须：属主校验 + 后台线程 + 任务日志进度。
- **RCE 护栏（§1 红线落地为代码，续206）**：`pocmgr.validate_yaml()` 拒收"**请求内容**里有命令
  拼接/命令替换形态"的模板（afrog 的 `pocs/` 里真混着一条 GET 触发 `ipconfig` 的 HFS RCE）。
  两条边界写死在代码里：① 只扫**会发出去的内容**（path/raw/payloads/body），info.description /
  author / reference 一律不看；② 只认形态（`;cmd` / `|cmd` / `&&cmd` / `$(` / 反引号）——
  `/whoami` 这种**端点路径**不是执行，第一版扫整份文本把它全误杀了。
  参数路由那边的 `rce` 类别同理：**只识别不测**（`paramroute.KIND_CHECKS` 里没有 rce），
  要确认它得让目标真的执行命令，那越过 §1。
- **POC 分两档：验证型自动跑，利用型「待确认」（续207）**。
  - **验证型**（只判"漏洞在不在"）：SQL 注入报错回显、布尔盲注、XSS 反射、开放重定向… ⇒
    照常进 `config/nuclei-templates/`（在 `pocs.engine.POC_DIRS` 里）自动跑，**一个都不拦**。
  - **利用型**（会真的改动目标）：命令执行、写文件、删改数据 ⇒ 落 **`config/exp-pending/`**
    —— 该目录**刻意不在** `POC_DIRS` 里 ⇒ 引擎发现不了 ⇒ 自动扫描跑不到。这是**物理隔离**，
    不靠约定（门禁 [207] 钉着 `POC_DIRS` 里不许出现 `exp-pending`）。
  - 判据三处同源（`pocmgr` 里一个函数族）：只看**会发出去的内容**（path/raw/payloads/body）、
    只认**形态**（`;cmd` / `|cmd` / `$(` / 反引号 / 写操作），不看 description 与注释。
    `validate_yaml()` = "能不能收"（三道），`exploit_reason()` = "走哪路"。
  - 人工执行的边界写死在 GUI（`gui/templates/exp.html` + `/api/exp/run`）：
    **一次一个、没有批量**（批量执行不是"验证"）、结果**不落 vulns 表**（人工判读）、
    跑一次记一条审计、路径穿越/非 http/文件不存在一律 400/404。
    ⚠ exp **不是被扔掉，是被留下**：它可能正是你要的答案，只是不该由自动扫描替你决定。

    改它之后**必须重跑转换脚本重新生成表**，只改黑名单不重生成等于没改（门禁 [199] 两半都钉：
    黑名单里有这个词 + 生成的表里确实没有它）。
    ③ 任何"把第三方 PoC/指纹/字典搬进检测路径"的活儿，落地件必须是**人工复核过的表**
    （`docs/afrog-fp-review.tsv` 那种），工具侧不许提供 `--all-ok`；`severity != info` 一律拒
    （实测 afrog 的 fingerprinting/ 目录里混着一条 HFS RCE，它的判据和普通指纹一模一样）。
    回归见 `tests/smoke.py [8y]`（含 severity 白名单与门控两向变异）。

12. **外部引擎适配器不许把"没跑成"报成"没结果"**（续121，afrog）：它的退出码与文件都存在
    反例 —— `-P` 指错目录 **rc 仍是 0**（只有 `[ERR]` 那行），零命中时**结果文件根本不写**。
    所以判"跑成功"要同时看：硬错文本（洗过 ANSI 再判）＋结果文件是否存在＋内容能不能解析；
    任何一条不满足都必须让调用方拿到带 `!` 的说明，并把它打成 warning（"不是没扫出东西，是没跑成"）。
    另外三条要一起保持：① **默认关**（外部进程自管请求，绕过本任务的请求预算 —— 日志必须说明这一句）；
    ② 只喂逐条判过的**只读 + info** 模板，且 `-P` 指着**任务目录里那份复制**，不是用户原目录；
    ③ 结果级别**只降不升**，并再过一遍我们自己的 `min_severity`。回归 `tests/smoke.py [8z]`。

13. **`utils.which()` 对带目录的配置值必须返回绝对路径**（续121 实测的坑）：
    `shutil.which("tools/scanner/httpx")` 是按**进程 CWD** 解析并**原样返回相对串**的，
    而外部工具一律要显式换 `cwd` 起子进程（不把 `result.txt` / `reports/` 落在仓库根 —— 续45、续121）。
    相对串进了新 cwd 就是"起不来 rc=127 → 被判未安装 → 静默降级到内置实现"。
    裸名（只走 PATH）不受这条约束，别顺手一起改。

14. **面向用户的同一句提示只许有一个产地**（续124）：`keystore._prompt()` 只返回**原因**，
    结论由 `keystore.lock_notice()` 组一次，三个启动入口（GUI / CLI / 节点）都调它。
    原因：三处手写同一句话必然漂（本轮实测漂成"凭据保持锁定：… —— 凭据保持锁定（…）（…）"，
    同一句说两遍还带两种措辞）。判据不止查这一次字符，而是查**结构性事实**：全仓源码里
    "凭据保持锁定"字样只允许出现在 `scanner/keystore.py`，三个入口必须出现 `lock_notice(` ——
    新增入口手拼一遍就红。给用户看的成句提示（降级说明、预算说明、级别说明）都该按这个模子做。
   **续154 再添四个产地**：真实 IP 分档 = `cdn.ip_kind()` + `cdn.IP_RANK_SQL`（页面显示、两个
   排序、报告标注、端口扫描四处都读它 —— 此前 Python 与 SQL 各一份，实测两份**不同源**：
   SQL 那份把未解析排进"非 CDN"档）；截图失败原因 = `screenshot.classify()` + `REASON_*`
   （重试决策与落库标签同一个判断）；第三方清单 = `jsmine.thirdparty_suffixes()`，资产侧判定 =
   `jsmine.is_thirdparty()`（与 JS 侧 `_is_noise` 的分工写在 docstring 里：不认 apex、豁免
   `PLACEHOLDER_DOMAINS`）；点号后缀这条规则 = `jsmine._is_under()`（全仓该字面量恰好一处）。；**探测候选主机** = `extdom.own_hosts()`（内存 ∪ 库，own 口径 —— 续159，§6.2 第十四起）；**「这个名字在不在目标域之下」的归属比对** = `extdom.is_in_bases()`（`own_hosts` 与 `SubdomainStage.reuse_history` 共用，续160 —— 后缀判断写两遍就会一边一个口径）；**跨任务可借的历史域名** = `db.list_known_domains()`（own 口径 + 账号隔离都在 SQL 里）；**这条截图失败属于哪一档** = `screenshot.shot_bucket()`（落库的是「档｜尝试 N 次（方式 秒）｜原文」（续170 多了中间那一段），取前缀，没有前缀才回退 `classify()` —— 续161 实测 `classify("跳转未落地｜一句话")` 落「其他」，而这一档**可重试**，事后重算＝静默丢候选）；**哪些档值得再排一轮** = `screenshot.RETRYABLE_REASONS`；**候补轮数与上限** = `screenshot.retry_rounds()`（DEFAULTS 0＝关、**随包 settings.yaml 出厂写 1**（续164），夹到 `RETRYABLE_MAX_ROUNDS`；读侧那个"键不存在时的兜底"跟 DEFAULTS 同值，不跟随包文件）；**候补候选** = `db.list_shot_failures()` + `runner.shot_retry_targets()`（档名一律**不进 SQL**，写 `LIKE '超时%'` 就是第二份判据）；**这次运行的运行期选项** = `queue.run_options()`（`run_payload` 那份，页面与 worker 同源；从 `task["options"]` 读永远是 0 —— 轮次就不在那一列）；**这个工具该看哪一个 release** = `toolmgr._release_for()`（钉了 `pin_version` 就按 `/releases/tags/<tag>` 精确取，没钉才看 latest —— 续164；`install` 与 `update` 都走它，别在两处各判一次"有没有钉"）；**某工具钉了哪一版、哪些产物摘要** = `toolmgr.pin(name)`（唯一读 `TOOLS[...]["pin_version"]/["pin_sha256"]` 的地方）；**「校验」那一格与政策句** = `toolmgr.verified_label()` / `verify_policy()`（CLI、GUI「外部工具」页、run_bootstrap、模板四处共用；页面里再抄一句"必须通过 release 自带的 SHA256 校验和"就是假话，`[8bu]` ⑤ 用 AST 扫字面量钉住）；**「为什么取不到这组凭据」** = `keystore.keys_hint(what)`（三态三句：两份文件都没有 / 有密文但本进程没解锁 / 已解锁但密文里没这一组 —— 续162；旧文案在七处各写一遍「见 config/keys.yaml」，而密文存在时明文根本不读，照着补的人永远补不上）；**「怎么解锁」** = `keystore.unlock_howto()`（补法只这一处，`keys_hint` 与启动横幅都引它）；**口令来源优先级** = `keystore.unlock()` 一处（参数 > `CTFSCANNER_KEYS_PASSPHRASE` > `~/.secrets/keys-pass`（守卫见 `file_passphrase`：正好 0600 / 属主是自己 / 非空）> 提问）；**站点表的默认排序** = `db.SITE_TITLE_ORDER`（续165，跨任务 /sites 与资产页共用；它与 `gui/app.py::_site_fold_key` 必须同口径 —— 折叠键认「标题优先、3xx 退 `redirect_title`」，排序若另拼一份 CASE 就会「聚在一起但代表行不是最新那条」；模板里再手写一遍就是第二份）；**一次 HTTP 失败到底为什么** = `utils._exc_reason()` + `utils.http_last_error()`（续165：`http_request` 的返回契约一字未改、失败仍是 `None`，原因按**线程本地**存；分类只在 `_exc_reason` 一处，调用方（passive 那类只读源）不许自己 `except` 再猜一遍超时/DNS/TLS）；**「工作目录内运行时组件」的落点与缓存** = `toolmgr.LOCAL_STACK[*]['dest']` + `toolmgr.cache_path()`（续166：pip 与 Go 的缓存都从这一处取，`toolmgr.go_env()` 是「编译该带哪些环境变量」的唯一产地 —— 在 `tools/build_fscan.py` 里再手拼一份 `GOCACHE` 就是第二份，而漏一个变量的后果是「悄悄写进家目录」）；**settings.yaml「只改一个键」的唯一实现** = `toolmgr.patch_settings_kv(section, key, value)`（续167 把原先只能改 `tools.<名>` 的那份逐行替换推广成任意顶层段；`patch_settings_tool` 现在只是它的包装 —— 再写一份逐行替换就是第二产地，`[167]⑤` 钉住"只差那一行、别的段同名键不碰"）；**「取来之后该往配置里写什么」** = `LOCAL_STACK[*]["wire"]` + `toolmgr.stack_exec_path()`（续167：回写一个没人读的键＝半接线，判据要求 `wire` 指向的键必须真在 `DEFAULTS` 里）；**「这一件到底装好了没」** = `toolmgr._markers_ok()`（`extract_tree` 收尾与 `stack_present` 共用；本轮实测把「平台二选一」的 marker 写成「全部都要」，Linux 上于是永远缺 `bin/go.exe`、报成「归档形状与注册表对不上」——两处各写一份 marker 判据就是这类漂移的产地）；**「这台机器按哪个平台选品」** = `toolmgr.host_arch()`，而它的**唯一覆盖入口** = `toolmgr.platform_override()`（续168：CLI `--platform` 只设 `CTFSCANNER_TARGET_PLATFORM`；架构别名一律过 `toolmgr._ARCH_ALIASES` **同一张表**折算 —— 探测与覆盖各写一份表，实测就会把 `windows/x86_64` 这种无害写法判成「本平台没有产物」，那是**假不适用**）；**「这一件本平台该不该装」** = `toolmgr.stack_applicable()`（与 `install()` 里 `pre["asset"] is None` 那一支同口径：算不出产物、或 CFT 产物没有登记过的摘要 ⇒ **不适用**，既不进 `failed` 也不算 `ok`）；**「不适用这件事怎么说」** = `run_bootstrap.render()` 那一节（标题自带「不是失败」，抬头计数有一格 `本平台不适用 N`）—— 算成失败会让 Windows 上 `./install.sh` 恒 rc=1，藏起来则是新的静默降级（§0 第 10 条）；**「这个拓展域名有多大把握是自家资产」** = `scanner/extdom.py::confidence()`（续169：三档 `low/medium/high` 各带**依据文本**，档位门限是 `_HIGH_DISTANCE/_HIGH_RATIO/_MEDIUM_*` 那四个常量；`conf_norm` 是中文档名/英文/大小写唯一的归一处）；**「拿什么去比」** = `extdom.confirmed_bases(task_id)`（＝`own_hosts` ∪ `task_bases`，主理人说的"父域名可以是爷爷域名"—— 页面徽章与自动递归**必须读同一个集合**，各取一次就会出现"页面上写着高、递归却没带上"）；**「能不能自动扫」** = `extdom.auto_expand_block()`（黑名单 → `js_thirdparty.txt` → CDN 三道闸，**无论多像都挡**；阈值那一档刻意放在调用方 `similar_candidates`，两处各判就会有一处忘）；**「这一轮该扩几层 / 阈值哪档」** = `runner.resolve_ext_depth()` / `resolve_ext_confidence()` （任务级选项优先、退回策略配置；`is not None` 而不是 `or` —— 显式填的 1 被策略顶掉就是把 用户点的那一下吃掉）；**徽章的标记** = `gui/templates/_conf.html` 里的 `conf_badge` macro（续169，两处拓展域名页共用；在模板里各写一遍 span 就是第二产地）；**这张站点没截到的原因文本怎么拼** = `screenshot.error_text()`（续170：`档｜尝试 N 次（一次性 30s + CDP 兜底 45s）｜原文`，**第一段必须是档名** —— `shot_bucket()` 按第一个「｜」前的字取档，候补重试与页面那个"还剩几张"都读它）；**兜底失败不许把档名重判一遍** = 阶段里那唯一一次 `classify()`（续170 实测：兜底回来的文本是 `cdp: …`，再喂一次就落「其他」，而候补重试只认 `RETRYABLE_REASONS` 三档 ⇒ 「超时」洗成「其他」＝悄悄少一批重试；兜底自己的原文仍两段都留）；**这一轮每张最多试几次、分别用什么方式** = `screenshot.attempts_plan_note(settings)`（策略页与详情页共用，**由配置现算** —— 模板里写死"已先重试过一次"在续170 之后就是假话）；**兜底该挡哪些域** = `screenshot._TRACKER_HOSTS` + `shot_block_patterns()`（清单只收埋点/统计/广告，**不收 CDN/静态资源域**；自家注册域**与它的子域**双向都不挡；`block_extra` 只吃"像个域名"的条目）；**CDP 客户端与调试端口就绪探针** = `scanner/cdp.py`（探针在调用方各写一遍，本轮就漏了一个 `import urllib` 而让整条兜底路静默死掉 —— 由端到端夹具逼出来）；**「截图失败的站点」有哪些** = `db.list_shot_failures()`（续161 立、续170 多一个消费方：人工点的「重截失败的站点」也读它，且**不按原因档筛** —— 原因档那一道只用于自动候补重试，两件事别混）；**「这个凭据 / flag 值是不是已被判误报」** = `scanner/secretbl.py::matches()`（续177：整值精确比对、大小写敏感；jsmine 与 flagfind 两处消费方都调 `filter_secrets()`，不在各自阶段里各判一遍 —— 与域名级 `config/blacklist.txt` 是两回事，那个挡域名、这个挡值）；**「低相似但与非 CDN 已确认子域同 IP 的拓展域名算多大把握」** = `extdom.apply_ip_evidence()`（续179：低 ⇒ 中、**永远够不上高**、owned 行不动；`similar_candidates` 与页面徽章共用本函数，各写一遍就会出现"页面写着中、递归却没带上"）；**「IP 佐证的对照集」** = `extdom.confirmed_ip_map()`（own 口径复用 `db.OWN_SUBDOMAIN_WHERE`、"非 CDN 且已解析"复用 `cdn.ip_kind()` 的 real/multi 两档）；**「动态并发档开不开、起步几线程」** = `utils.ramp_opt()`（续179：`limits.workers_mode/workers_floor`，出厂 fixed＝现状不变；pool_run 的 ramp 只接探活一处，[179b]③ AST 钉点）；**「这次复测为什么落这一态」** = `scanner/stages/vulnscan.py::_retest_mark()`（续150 立三态、续180 补第四路：复现 / 探过且跑成 ⇒ fixed、**探过但检查执行失败 ⇒ unconfirmed**（`_scan_err` 由 `_scan_site` 记账 —— 一次请求失败不证明已修复）/ 没探到 ⇒ unconfirmed；三态取值集合只有 `db.RETEST_STATES` 一处）；**「这台机器按什么并发档跑」** = `utils.machine_tier()` + `utils.effective_workers()`（续181/续215：`limits.workers_auto` 按机器档位收、`limits.workers_profile` 按**上一轮真任务实测**（`profiling.from_row` → `suggest_workers`，只会往下收）—— 两条独立、配置永远是天花板；profile 由 `runner._profile_limits` 深拷贝注入 `limits._profile`，没有画像就不动；probe 三处只经 `effective_workers`，不许再留第二份 `limits.max_workers` 直读，[181](d)/[215] 钉点）；**「单任务吃多少资源 / 建议几个并发」** = `scanner/profiling.py::TaskProfile` + `suggest_workers()`（续215：真 `run_task` 采样墙钟/CPU/峰值 RSS；`limits.workers_profile`/`queue.workers_profile` 才会用它降档；画像键名 `rss_peak_mb` ↔ 库列 `peak_rss_mb` 由 `db.set_task_profile` 兼容）；**「扫描期拦截动作怎么记账」** = `audit.KIND_SCAN_BLOCK`（续182：vulnscan min_severity 挡条与自动拓展三道闸/阈值挡条两处 `audit.record`，actor=scanner；审计是旁路、开关照常管得住）；**「同 IP 绑 Host 碰撞怎么做」** = `scanner/hostcollide.py`（续183：plan/collide/run；只读 GET、指纹与该 IP 默认虚机比对、单 IP 预算；两层开关＝策略 `hostcollide.enabled`（出厂关）+ 任务选项 `hostcollide: true`；命中 source=`collide:<ip>` 自动归 own 口径；GUI/CLI 触发入口未做，待点单）；****「IP 重合算不算高置信度」** = `extdom.apply_ip_evidence`（续186 拍板：非 CDN 的 IP 与已确认子域重合即判 high，可进自动递归；CDN/没IP/自证不佐证）；**「与已确认资产同证书的域名算多大把握」** = `extdom.cert_shares()` + `apply_cert_evidence()`（续194：非大厂的同证书 ⇒ 判高；大厂/第三方共享证书只打 `cert_vendor` 标记、不升档；页面徽章与 `similar_candidates` 共用）；**「子任务树/整树汇聚的数据源」** = `gui/app.py::api_task_subtree` / `api_task_stats`（续196：parent_id 递归 + 24-a 编号；跨任务去重判据复用 `db.OWN_SUBDOMAIN_WHERE`，SQL 侧不重抄）；**「黑名单命中的 SQL 条件」** = `db.blacklist_clause()`（续194：与 `blacklist.matches` 同口径，[194a] 六向样本钉住）；**「送探的域名归谁的资产」** = `api_scan_ext` 落 `ext:probed`（续192 立、续195 改：进**根任务**（沿 parent_id 走到没有父任务的那个＝主域名任务）的 subdomains、自动 own 口径 —— 层数深了之后"父任务"只是上一层拓展任务，域名挂在那儿主域名任务里找不到；promote_owned 只收注册域命中的，非归属拓展域名靠这条补）；「探不到内存怎么判档」** = 只看 CPU、哨兵 mem_gb=8 只落账不参与档位判断（续184：wire19 [181](a) 断言抓出哨兵 8 落进 `mem_gb<=8` 中档判据、16 核被误判「中」的实现 bug，修实现不动断言）；**「IP 反查的源还活不活」** = `iprecon.preflight()`（续184：每个源探一次，挂了整轮跳过；全挂时换 `fallback_sources`，其首项 `ptr` 是本框架自己实现的原生 PTR、**不发 HTTP**）；**「邮箱等数据探测产物」** = `scanner/mails.py` + `emails` 表 + `/emails` 页（续184：jsmine 同一批正文顺带抽、零额外请求；筛选判据只在 `mails.is_noise` 一处；**只记录不验证**）；**「任务级并行几个」** = `queue.config()`（`queue.workers_auto` 按 `machine_tier` 收 1/2/4；`queue.workers_profile` 再按最近一次实测画像收，**保存策略后由 `queue.reconfigure(config()["workers"])` 立即生效**；缩容只打退休信号、线程跑完当前任务再退场，已退休线程**不占编制**（续216 的 3→1→3 断言钉住）；页面上的"同时运行 N 个"读 `queue.active_workers()`，拿 `config()` 冒充运行中数量会说错）；**「IP 反查每个源成没成」** = `iprecon.reverse_lookup_detail()` + `iprecon.format_source_stats()`（续173/216：五档 ok/empty/http_error/network_error/unregistered，汇总含预检跳过原因，并落工作目录 `iprecon_sources.json`）；**「无头浏览器用哪份字体配置」** = `screenshot.fontconfig_file()` + `screenshot._browser_env()`（续175/216：留空不注入；相对路径按仓库根解释；只进子进程 env，不改父进程）；**「安装末尾的凭据怎么落盘」** = `run_bootstrap.prompt_credentials()`（续216：进程内复用 `cli.run_keys.main`，临时明文 `--shred` 删除，**不新增子进程**；值只进 `keys.enc.yaml`）；**「dirmap 用哪个解释器」** = `dirscan._dirmap_python()`（续217：配置里非默认值 > `tools/python311/` 便携解释器 > 项目 `.venv` > PATH；默认值 `python`/`python3` 视为没指定）；**「dirmap 这条命令带不带 -e」** = `dirscan._dirmap_accepts_lang_arg()` + `dirscan._dirmap_argv()`（续217：有 -e 按技术栈分组；没有就只跑一轮、按 dirmap.conf，两种形态共用同一段产物解析 —— 不许在调用点再拼一份 argv）；**「dirmap 在 3.12+ 怎么起得来」** = `tools/dirmap_compat/imp.py` + `dirscan._dirmap_env()`（上游只有一句无用的 `import imp`，垫片放子进程 PYTHONPATH 最前；**不需要为此装 ≤3.11 的便携 CPython**）；**「dirmap 依赖装没装」** = `tools/setup_dirmap.py` + `dirscan._dirmap_deps_ok()`（显式 --install 才联网；缺依赖只回退内置扫描并说清补法）；**「仓库内 Go 与系统 Go 谁优先」** = `tools/build_fscan.py::find_go()`（续217：仓库内 `tools/go/bin/go` 优先，`CTFSCANNER_GO` 可显式覆盖；`go_env(with_local=...)` 与它同源）；**「chrome 三平台摘要 / macOS 可执行路径」** = `LOCAL_STACK["chrome"]["pin_sha256"]` + `stack_exec_path()`（续217：Linux/Win/mac-x64/mac-arm64 四份摘要；mac 的 .app 内路径只在 `stack_exec_path` 折算）；**「8765 夹具起不来」** = `tests/smoke.py::start_fixture()` / `_fixture_alive()`（续217：先短重试、再按 `/.git/config` 识别人家靶场；仍起不来就 SystemExit，不静默 None）；**「dirmap 按指纹跑不跑、喂哪些站点」**；**「一个站的标签怎么收口」** = `fingerprint.identify(resp, where=)` + `canonical_tags()` + `fingerprint.flush()`（续221：JS 正文不吃 body 规则；同义归一走 `fingerprint_aliases.txt`；单站上限 `fingerprint.max_tags` 默认 10，主文档优先、JS 补位，丢多少写日志；社区表的烂分支走 `fingerprint_fixes.txt` 精准剔除，**不搞"路径型一律降级"** —— 那判据实测 24 条命中里 23 条是真产品路径） = `dirscan._dirmap_targets()`（续220：无 `-e` 的 dirmap 字典是它自己 dirmap.conf 里那份**通用**字典、不分技术栈，上游 `-lcf` 自己都没实现 ⇒ **只把没认出指纹的站点喂它**，已认出栈的由内置扫描`_builtin_scan()` 按指纹选字典（框架桶 → 语言桶 → 暴露面 → 通用）；带 `-e` 的老快照原样全喂。全认出指纹 ⇒ 明说不跑 dirmap，不许静默）；**「外部命令的输出怎么读才不卡死」** = `utils._do_run_cmd()`（续218：**起读线程边等边抽干管道**。先 `poll()` 等退出、退出后才读 ⇒ 子进程一写满 64KB 管道缓冲就永久阻塞在 write 上，症状是任务挂一小时不动、CPU≈0，看 `/proc/<子进程>/wchan` 是 `anon_pipe_write` —— 别当成"工具在慢慢跑"）；**「dirmap 产物是目录还是单文件」** = `dirscan._target_dirs()` + `dirscan._parse_output(force=True)`（老版写 `output/<netloc>/res.txt`，无 `-e` 的 v1.1/master 写 `output/<netloc>.txt` —— 两种形态共用同一段行解析，谁在调用点另拼一份解析谁就会静默丢整轮结果）；**「截图候补轮先重试谁」** = `db.list_shot_failures()` 的 ORDER BY（续218：最久没试优先，靠 `shot_last_at` 毫秒戳）+ `db.set_site_shots()`（截成功顺手把旧 `shot_error` 清成空串）
；**「谁是父任务、谁是子任务」** = `tasks.parent_id` + `db.list_child_tasks()`（续185：拓展域名「送去探测」新建的任务挂在这里 —— 那是**任务层级**；「把域名追加成父任务的子域名」是**资产层**、由 `promote_too` 走 `extdom.promote_domains`，两件事别混）

（续184：wire19 [181](a) 断言抓出哨兵 8 落进 `mem_gb<=8` 中档判据、16 核被误判「中」的实现 bug，修实现不动断言）

15. **指纹前置过滤只许做减法，不许改变判定结果**（续122）：`_lit_filter` 给每条正则算"必现字面量"，
    跳过 `re.search` 的前提是**该字面量在任何一次命中里都必然出现**。四个放弃过滤的条件（宁可不提速，
    也不能漏报）：① 段处在可选重复里（`X?` / `X{0,}`，看最小次数是否 ≥1）；② 有一条分支取不出
    `_MIN_LIT` 以上的段（命中可能正走那条分支 ⇒ 整条不过滤）；③ 组内局部 `(?i:…)`（编译期 flags
    看不出、匹配期不区分大小写）；④ 文本含 `U+0130/U+0131/U+017F`（`re.I` 与 `str.lower()` 不一致的
    **全部**码点，实测枚举 BMP 得到），此时不许拿 `lower()` 的比较当"必不命中"。
    改这张表的匹配逻辑时，**对照组判据优先于计时判据**：`[8aa] ①` 是"逐字照搬旧实现跑同一批语料、
    标签集合必须一字不差"（6633 次对比），计时只作量级说明；新增的放弃条件必须自带变异证伪
    （把折叠守卫拆掉 ⇒ `ſrv-apache` 立刻漏报）。


16. **敏感信息 / flag 候选必须"零额外请求 + 单独成表 + 只报候选 + 形状表只有一份"**（续126 建，续148 接进内置凭据形状，`scanner/flagfind.py`）：
    ① 它**只吃调用方手里已有的文本**（四个出口：probe 根响应 / jsmine 页面与 JS / dirscan 每条
    命中 / vulnscan 的 POC 证据）。结构判据是 AST —— 模块里出现 `http_request` / `socket` /
    `run_cmd` 一类真实引用即判红。新增"这页没取到正文，我再抓一次"会把目录+JS 的请求量翻倍，
    而预算与限速都不是为它准备的。
    ② 成本封顶：定位一律"字面锚 + 小写副本 `str.find`"，取值一律从**原文**切（flag 大小写敏感；
    `lower()` 会改变长度的那几条例外码点走 `(?i)` 慢路，偏移仍必须回切原文验证）。
    用户自定义正则与**内置敏感信息形状**都**只在必现字面量锚出的窗口上跑**；取不出锚、
    或锚"定位不住"（短于 3 字符、或全是标点，如 `db-uri` 的 `://`）的一律**拒用并给出原因**
    —— 退回"整份正文扫一遍"等于同时放开 ReDoS 与耗时（实测通用 `word{...}` 形状在 CSS 堆的
    正文里能捞 2 万条）；而宽锚只看了前 `max_per_source` 个窗口，其余正文等于**静默没扫**。
    实测 1.09 MB 正文：只跑前缀 3.2 ms，加内置形状 5.5 ms；同样这 15 条形状整篇跑要 381.8 ms。
    ③ 写进**单独的 `flags` 表**：不并进 `vulns`（一个 flag 不是漏洞结论，进了就污染计数与
    复核台账），也不并进 `leads`（续24 起线索不进人读报告/页签，等于把 CTF 的结论藏起来）。
    新增资产表时**必须同时**进 `ASSET_TABLES`（本轮实测：该元组曾在 `db.py` 里定义两遍、
    后一份静默盖前一份，现立"全文件只许出现一次"的源码判据）与 `[8u]` 的逐表索引清单。
    ④ 跳过的量必须可见：`flags.max_chars`（单位是**字符**，续130 从 `max_bytes` 改名 ——
    `len(text)` 量的就是字符，写"字节"会让中文正文的放行量被低估约三倍）、
    `max_per_task` 挡下的候选、
    库里已有同值，都要进 `flagfind.note()`，且各阶段只报**自己的增量**（`begin()`/`note(ctx, since)`）
    —— 四行都报累计就分不清哪条是谁看的，与续124 那条"一句提示只有一个产地"同源。
    ⑤ 内置敏感信息形状的**唯一产地是 `scanner/jsmine.py::SECRET_RULES`**（15 条），`flagfind`
    只给它补成本护栏、不复制正则（`[8ba]①` 用 AST 查字符串常量：注释里提一句 `AKIA` 不误伤，
    抄一张表进去才判红）。锚点提取得靠 `fingerprint._literal_runs` 展开**必填位置上的捕获组**
    （`AKIA` 就躺在组里）—— 实测这一改动让 131 条内置指纹规则里**新拿到锚点的有 0 条**，
    所以指纹快路逐字符不变，而"命中 ⇒ 锚点必现"另用 4000 组随机样本 + 真实语料验过。
    ⑥ 表里存的是**原文取值** ⇒ 这张表**默认不进迁移包**（`migrate.SECRET_TABLES` + CLI
    `--with-secrets`）。包里必须写"没带 N 条"（`includes.secrets_skipped`），只留一个空列表的话
    读包的人分不清"目标本来没有"与"被默认档挡了"。
    回归 `tests/smoke.py [8ae]`（五向变异：值取小写副本 / 不做小写副本定位 / 抹掉超限计数 /
    收下无锚正则 / 第二处 `ASSET_TABLES`）+ `[8ba]`（三向变异：放松锚点门槛 / 桩掉形状表 /
    清空 `SECRET_TABLES`）。

17. **组件标签只能有一个产地，补标只做并集**（续127，`scanner/fingerprint.py::collect/flush`）：
    ① `sites.tech` 的唯一写路径是 `db.merge_sites_tech()`（并集、`task_id` 参与 WHERE、幂等），
    **不许**出现"用新识别的标签覆盖整列"的写法 —— probe 从根响应打上的标签是实况，
    被后面阶段的补标抹掉等于把第一手证据改成第二手。
    ② 补标的输入只能是**已经发过的响应**（dirscan 每条命中、jsmine 页面与每个 JS），
    `collect/flush` 的函数体内不许出现 `http_request` / `run_cmd` / `socket`（AST 判据）。
    想给"没正文的那两路"（httpx 档的 probe、dirmap 产物行）补数据就得真加请求 —— 那是
    另一个决定，必须单独一轮，不许在这里顺手加。
    ③ 内存与库**两处都要改**：下游（vulnscan 的 POC 优先、dirscan 的框架字典）读
    `ctx.results["sites"]`，页面与报告读库，只改一边就是"页面上有了、下一阶段当没看见"。
    ④ 判据的**收紧要有实测**。本轮实测（`tools/calibrate_fingerprints.py`，12 份通用负样本）
    显示外置 51 条判据 0 命中 ⇒ **不加**路径门控（门控挡误报，而误报为 0，加了只会挡掉真识别）；
    这个决定同时钉在三处：字典文件头注释、`[8af] ⑤` 的"仍是 6 列"断言、以及"把某条判据
    改成通用词 `login` 必须被 ≥3 份语料抓到"的变异（否则"0 命中"可能只是语料太弱）。
    ⑤ 没有新增 ⇒ 零 UPDATE、零日志；标签挂不上（站点不在本任务 sites 表里）⇒ **必须点名**。

18. **外部引擎的流量必须有预估、有上限、且默认不改行为**（续128，`scanner/extcost.py`）：
    ① 任何"起一个自管流量的外部进程"的新能力，都必须在**起之前**算出预估并打进日志
    （单位写清：HTTP 请求数 / 端口探测次数），不许只说"它自己管"。
    ② 上限默认 **0 = 不限**（F2 老规矩：默认路径永不触发拒绝）。这条不是偷懒 ——
    `portscan.engine=auto` + 全端口就是 `1 × 65535`，任何非零默认值都会悄悄把既有能力降级掉。
    ③ 超限的动作是**降级**，不是失败：端口扫描退回内置 TCP connect（那条真的走
    `throttle` 的并发/限速/预算），afrog 干脆不起进程并返回 `!` 开头的说明
    （说明里必须带键名，让人知道调哪里 —— §5.12 那条"没跑成 ≠ 没结果"继续适用）。
    ④ 预估的输入必须是**实际下发的那一份**（afrog 用 `n_staged` 而不是 `len(ok_files)`）：
    日志里的数字是人的判断依据，虚高与虚低都会把人带偏（虚高还会让人把上限调得过大＝把闸调没）。
    ⑤ 上限被触发时**不许出现第二个产地**：`afrog.run` 只返回 `!` 说明，由调用方（vulnscan）
    打成 warning；自己再喊一遍就是续124 修过的那类毛病（回归里断言"日志里没有第二份"）。
    回归 `tests/smoke.py [8ag]`（超限后 `run_cmd` 调用记录必须为空；没设上限时 fscan 必须照旧被调
    —— 后者是"不改既有行为"的证明；三个变异方向）。

19. **讲运行期能力的话必须跟着配置走，不许写死"有没有"**（续146-附3，`gui/app.py::_audit_hint`）：
    `_deploy_hints()` 那句「**访问审计仍然没有**」从续32 一路活到续146，而续48 就落了 `audit_log`、
    `gui.audit.enabled` 默认 True（本机 `data/scanner.db` 实测 23 条，kind 覆盖 account/login_fail/
    login_ok/settings/task）。这类句子的害处不是"旧了一点"，而是它会**主动改变读者的行为** ——
    人以为查不到痕迹，于是在绑了 `0.0.0.0` 的机器上放心做事。同一类毛病 `docs/security-notice.md`
    续54 已经犯过一次（当年那句"多用户与角色、访问审计、HTTPS 仍未提供"与代码不符），
    **第二次出现说明第一次只改了实例、没立规矩**。口径三条：
    ① 凡是"某能力开/关、留几天、记哪几类"的成句描述，一律**从配置与注册表现取**
       （`audit.config()` / `audit.KIND_LABELS`），不许在文案里再抄一份 `DEFAULTS` ——
       §5.14「同一句提示只许一个产地」对它同样适用，`audit.config()` 自己就兜缺项默认。
    ② 开与关**分态**各写一句：两态共用一句"中性话"等于没说，而关掉时警告必须比开着时更响
       （`gui.audit.enabled=false` 的措辞是"**不留任何动作痕迹**：谁登录过、谁改过配置、
       谁动过任务全都查不到"）。
    ③ 回归除了断言两态文案，还要**改配置或改注册表再断言文案跟着变** —— `[8ax]②` 往
       `KIND_LABELS` 里加一类 ⇒ 横幅必须多一类；只断言"现在有这句"挡不住下一版漂掉。
       判据本身要**先自证**抓得到被替掉的旧句子（`[8ax]` 开头那两条），否则它谁也没拦住。
    历史条目**不改写**：`CHANGELOG_AI.md` 里当年那句"明确没做"留原样，那是那一轮的实话。

- **截图的成败＝"这一次调用真的产出了新文件"，失败不许动已有产物**（续140，`scanner/screenshot.py::capture`）：
  判据是 `out_path` 存在、非空、**且 mtime 不早于这次调用开始**。为什么不是"存在且非空"：同一个 URL 的
  `shots/<md5>.png` 在续跑/追加执行时是同一个路径，旧写法让"浏览器这次根本没渲染成功"也报成功（旧图替新失败背书）。
  为什么也不是"先删再跑"：删掉之后这一轮失败时，库里那条上一轮写的 `sites.shot` 就指向一个不存在的文件，
  GUI 直接裂图 —— 比"报错误导"更糟。**失败什么都不许动。**
  连带口径：`screenshot.capture()` 返回三元组 `(ok, err, title)`，`want_title=True` 才加 `--dump-dom`；
  任何"拿渲染结果下结论"的判据都必须先看 `ok`，不许看 `available()`（§6.2 第九起就是这么红的）。


## 6. 如何验证改动

> **门禁提速的既定口径（续125）**：全流程自检**只**放宽限速节奏
> （`scanner/devflow.SELFCHECK_PACING` = rate 50/s、burst 20），其余压量一项不动；
> 开发模式对真实目标仍是 1 请求/秒。耗时基线 `logs/devflow_baseline.json` 里带 `pacing`，
> **口径不同就不与基线对比**（不可比的两次数比出来的结论是假的）。
> 要按组看耗时用 `python3 tests/smoke.py --timing`（默认关，开启时也不许改变 stdout 内容）。
> **刻意不做 `--only <组>`**：130+ 个组共享进程内状态，跳组会在依赖它的后续组里造成假绿。

```powershell
py -3 tests/smoke.py        # 唯一回归门禁：自包含起靶场，断言覆盖 目标解析+CIDR/阶段注册(13 个)/POC 级别执行门/
                            # 免杀变形/mmh3 公开向量+iprecon/fofa 纯函数/响应体解码/流水线+指纹/三层门控/阶段门控(含 osint)/
                            # 非标端口候选/报告(含 C 段 IP)/停止/导出/GUI 路由(侧边栏全栏 + /ports /csegs /dirs)与批量接口/
                            # 子域名分流+CDN 标记+站点折叠+POC 相对路径/
                            # 第十四轮新增 `[5d]`：注册域折算(base_domain) + 相对路径(rel_display) + 黑名单
                            # (含临时文件与开关失效) + 证书反查(build_cert_query/is_common_cert/search_cert 空域名) +
                            # source_label + 拓展域名重叠隐藏与 ?all=1 + 站点重叠 1↔2 条 + 黑名单/批量子域
                            # 两个 POST 接口(桩函数去重保序/阶段与 targets) + 策略页 cert/blacklist 字段与
                            # `panel collapsible`、无绝对路径、logs/smoke- 相对路径 + POST 映射
                            # 第十五轮新增 `[5e]`（8 组）：端口区间上限 vs 全端口放开 + 标题反查(语句/阈值/模板标题) +
                            # 目录(dirmap 行解析/重复长度文件不读/别名站去重/大小列/折叠 1↔3) +
                            # JS 敏感字符(AKID/JWT/PEM 命中 + 占位降噪) + /fullports 页与发起接口(桩 run_task) +
                            # FOFA 裸 IP 收口(_domain_of) + dirscan 阶段级"只扫不重复站点"(记录型 logger)
# 第十七轮(续8)新增 `[5n]`：情报订阅(intel：源地址/缓存命名安全/CVE 规整/白名单匹配
                            # 与词边界/资产文本不含标题/级别/组装线索) + 启发式(5 条规则正反例) +
                            # leads 写入侧去重 + 默认关门控不写库 + 策略开关渲染 +
                            # 线索出口口径（续24 翻转：页签与 MD/HTML 小节**必须不在**，JSONL 必须仍在）
# 第十八轮(续9)新增 `[5p]`：目录浅/深两档（默认 quick + 只吃 dirs_shallow + ≤quick_max_paths）
                            # + 档位判定（dirscan_full 强制 deep、portscan_full 不互相影响）
                            # + 补扫任务目标兜底(_sites_from_targets) + 建任务自动补阶段与顺序
                            # + POST /api/rescan（阶段/rescan_of/命名/next 防外站）
                            # + 后缀派生去重限额 + GUI 入口（portscan_full/dirscan_mode/api/rescan）
                            # 2026-09-23 续10 新增 `[5p] 3c`：端到端**真跑一次浅扫**（产物必须同时
                            #   命中 .env 与 .git/config、条数≥2、请求量 ≤ quick_max_paths + 基线）
                            #   —— 前三条是桩实现，只验"走哪一档"，补的就是"真扫出什么"
                            #   新增 `[5q]`：CTFSCANNER_DB/LOGS 路径归一化（空值与引号回落默认、
                            #   盘符式 POSIX 路径 Windows 归一 / Linux 原样、普通路径不动）
                            # 2026-09-23 续12 新增 `[5r]`：误报复核（状态枚举与非法值归一/单条与批量打标
                            #   （含混入非法 id）/三态筛选/复核计数/报告台账 + 「已判误报」附录（不计入漏洞数））
                            #   新增 `[5s]`：POC 置信度（来源分 × 内容型匹配器、只降级不升级、upsert 重算、
                            #   内置 POC 全 high、按层批量启停 + kind=diff 幂等）
                            #   重写 `[5e-0]`：fscan 2.2.1 真实输出 8 组断言（三正则解析 / 统计行交叉校验 /
                            #   数目不符或 rc≠0 → None / 0 个 → [] / 跳转目标不被误记 / cwd 一律显式给）
                            # 2026-09-23 续14 新增 `[5u]`（sensitive.txt 签名列数据驱动 A01 + db 写锁串行化）
                            # 2026-09-23 续15 新增 `[5v]`（证书：内联夹具解析 + 127.0.0.1 真握手 + 门控零请求
                            #   + 落库/产物/页签/报告 + 清空资产 + 勾选即 cert_on）
                            #   新增 `[5w]`（报告三格式与趋势：八节 MD↔HTML 一一对应 / XSS 载荷全转义 /
                            #   自包含无外链 / 误报不计入趋势·未知级别归 other / 三格式路由 /
                            #   无浏览器时 PDF 返回 400 + 可读原因 / 仪表盘趋势面板）
                            # 2026-09-23 续17 新增 `[5x]`（登录态扫描：解析/掩码/不静默丢弃 + fail-closed
                            #   （回显靶场 + 逐行断言 4 个第三方调用点不带 auth）+ CLI -H/--cookie 与
                            #   GUI 400 + 补扫继承 + 页面只显掩码不回显明文；POC raw 解析与破坏性方法拒绝、
                            #   flow 布尔子集（短路/纯否定不报/越界与被跳过块引用标 unsupported）、
                            #   workflows 子模板与自环保护、**块级** dsl 仍显式 unsupported；续38 起
                            #   `subtemplates`/`tags:` 条件编排由 `[6y]` 单独覆盖，续39 起 flow 的
                            #   **脚本子集**由 `[6z]` 单独覆盖）
                            # 2026-09-23 续18 新增 `[5y]`（批次 4 五项）：
                            #   XSS 上下文判定表（8 上下文 / 探针定界符存活 / 全转义不报 + poc_id 不变）
                            #   + A10 SSRF 受控回连（默认关零请求 / 本机监听自证 / 外部回调不谎报 /
                            #     监听线程不泄漏）+ 布尔盲注（恒真恒假对比数字 + 页面抖动不判 + 无 SLEEP）
                            #   + Shodan/Quake（无 key 不发请求 + 查询串 + 阈值 + 裸 IP 收口 +
                            #     POST/X-QuakeToken + 配额报错）
                            #   + CT 日志（非 JSON/限流容错 + `*.x` 通配符剥离 + 默认关门控 +
                            #     第三方不带登录态）+ 新开关三方一致（DEFAULTS/settings.yaml/GUI POST）
                            #     + 证书来源列
# 2026-09-24 续20（含 -fix 与 F2）新增 `[6a]`~`[6f]`：复核修复回归（盲注全参数 / ssrf close 真 join /
                            #   ctlog 逗号切分）/ JSONL 导出（含误报行、与 MD 刻意差异）/ 错误追加不丢 /
                            #   孤儿任务对账 / CLI JSONL 行尾 `\n` 与 OpenProcess fail-safe /
                            #   **F2 统一门控**（闸门计数与取消不卡 / 令牌桶限速 / effective_cap=min(阶段,任务,全局) /
                            #   预算耗尽=按停止→任务标 `stopped` + `[throttle]` 错误行 / inject 不原地改 /
                            #   进程级闸跨任务共享 / http_request·run_cmd 耗尽时按停止不抛）
# 2026-09-24 续21 新增 `[6g]`~`[6j]`：F2 预算**原子化**（真实线程池 pool=20/100 作业，cap<budget 时
                            #   旧代码超发 21/22 → 修复后恒 == budget）/ 失败路径**退还预算**（等闸时取消：
                            #   不挂死 + 全额退还 + rejected==0）/ 混合 `max_inflight_global` 重建闸**告警**
                            #   （不静默）/ `slot()` **不可重入**（同线程嵌套会自锁、靠 stop 解开）
# 2026-09-24 续22 新增 `[6k]`：拓展域名降噪三件套 —— jsmine 加**公共后缀（PSL）校验**
                            #   （拒 `wallet.filter.withdraw` / `react.transitional.element` / `react.client.reference` / `i.test`，
                            #   多段后缀 `co.uk`/`com.cn` 仍接受；清单缺失 fail-open + 只告警一次）/ 第三方清单补 9 条
                            #   （含 `cloudflareinsights.com` 单独成行才拦得住 `static.*`）/ FOFA 标题**归属相关性**
                            #   （默认 `label` 档丢 `silviatarg1.com`/`noise1.net`/`noise2.cn`、留 `targ1.*`；`substring` 档
                            #   复现宽松；中文标题 fail-open）+ 新开关 `fofa.title_match` 三方一致
# 2026-09-24 续25 新增 `[6l]`：同任务**追加式执行** —— 续写同一 log_file + 不清 error + 进度重置 /
                            #   跨运行去重（同 站点+路径·站点 不重复）/ 并发 409 硬拒绝 / 无源入口 409 /
                            #   仅勾选目标 / append_count 标记 + 导出横幅
# 2026-09-25 续29 新增 `[6q]`：**断点续扫** —— `resume_stages` 切片口径（断点及其之后，
                            #   空断点=`[]` 即"拒绝"而非全量）/ 被停止时**保留断点**（原实现清空 = 抹掉
                            #   最该续跑的收场）/ 沿用同一任务与日志、**不清资产**、error 按本次清空且
                            #   上次原因转存日志 / 无断点回退要明说 / GUI 拒绝无断点与运行中、
                            #   放行时 `resume=True` 且**剥掉 `append*`**（否则输入被收窄成空集）
                            #   注：`[6d]` 原 `current_stage == ""` 是空洞断言，已改为"对账保留断点"
# 2026-09-25 续30 新增 `[6r]`：**目录递归** —— 默认关零请求零读字典 / 目录型判定
                            #   （状态收口 200·301·302·403 + 剥 query/fragment + 文件型与**点目录**
                            #   `.git/config` 不递归 + 站点根之外不递归）/ 每前缀**独立**软 404 基线 /
                            #   入库 `site_url` 仍是站点根 / 目录数与每目录路径数上界（请求量 = K×(3+M)，
                            #   10 个目录只递归 3 个、每目录只打 1 条 → 恰好 12 个请求）/ `max_dirs`
                            #   是**跨层累计**（第 1 层用满则第 2 层一个都不发）/ 层数 / 同一目录重复命中
                            #   只递归一次 / 任务级 `recursive_dir` 可覆盖策略且**不原地改全局** /
                            #   GUI 勾选 + 策略页三键 + 建任务路由自动补 `dirscan_full` 与 dirscan 阶段
                            #   （此处抓到真缺陷：补阶段循环原先只读表单字段，而 `recursive_dir` 是直接写
                            #   进 options 的 → 勾了递归却连 dirscan 阶段都不跑；已改为按生效 options 判）
# 2026-09-25 续31 新增 `[6s]`：**CLI `--resume-task`**（续29 只做了 GUI 入口）—— 有断点走
                            #   `run_task(resume=True)` 且**阶段列表原样传**（切片由 run_task 内部做，
                            #   CLI 不自己切，避免两份切片逻辑漂移）/ 无断点**入口即拒绝**、不调用
                            #   run_task（不许退化成全量重跑）/ 与 -t·--offline·--recursive-dir·-n
                            #   互斥报错 / 任务不存在与运行中均拒绝 / 选项取自任务自身而非本次参数。
                            #   全程桩掉 `run_task`，零真实请求；用 `os.getpid()` 占住 pid 才能
                            #   测到"运行中拒绝"（否则 reconcile 会先把该 running 判成孤儿 failed）。
# 2026-09-25 续32 新增 `[6t]`：**本机守卫** —— `_host_of` 纯函数（`host:port` 剥端口 / IPv6 字面量
                            #   剥方括号 / 大小写与空白归一 / `0.0.0.0` **不算**回环 / 解不出返回空串不猜）
                            #   与 `_authority` 纯函数（**保留端口** / 默认端口按 scheme 归一 / IPv6 保留
                            #   方括号）/ Host 白名单（外站 Host 在 GET 与 POST 上均 403；`127.0.0.1` 与
                            #   `localhost:5000` 放行 —— 白名单比的是**主机名**）/ 写方法 Origin 与
                            #   Referer 校验（跨站、**同机异端口**、`null` 均 403；同源与默认端口放行）/
                            #   带外站 Origin 的 **GET 放行**（不误伤导航）/ 两个头都缺时放行
                            #   （curl/脚本必须能用）/ 登录响应 `Set-Cookie` 含 `HttpOnly` 与
                            #   `SameSite=Lax`。全走 test client，不占端口、零真实请求。
                            #   ⚠️ 写"同源/跨源"断言时**必须显式给出带端口的 Host** —— test client 默认
                            #   Host 是 `localhost`，端口断言会因"主机名本来就不同"而**假绿**（续32-fix
                            #   真缺陷就是这样漏掉的；该缺陷最终是**真实服务器 + 真实浏览器**复核才暴露）。
                            #   **未验**：真实浏览器的 DNS rebinding 链路与反代场景（见续32/-fix 变更记录）。
# 2026-09-25 续35 新增 `[6v]`：**任务运行时长** —— `format_duration` 口径（0 / 59 / 60 / 3599 / 3600 /
                            #   3661 / None / 负值）/ db 侧 SQL 算术（手工钉 `started_at` 后 `finish_task_run`
                            #   得 90，第二段累加得 150）/ `fresh=True` 清零 · 续跑（`fresh=False`）保留 /
                            #   无起点与时钟回拨都记 0（**不写负数**）/ `task_run_seconds` 四情形（含 `now=`
                            #   注入，避免依赖真实时钟）/ `run_duration_text` 页面文案（老任务 `-` / 已收场 /
                            #   运行中 / 被强杀尾段未计入）/ **详情页与任务列表页两处都真的渲染**（续36 补
                            #   `/tasks` 的「运行时长」列：从页面里取出该任务那一行再断言，避免整页凑巧同串）/
                            #   **真跑流水线**（桩阶段 + 真 `run_task`）的
                            #   done · stopped · 外层 except→failed 三条终态都落 `started_at`+`finished_at` /
                            #   启动对账按该行原 `updated_at` 结账（**不把停机时长算成运行时长**）。
                            #   注意：改坏实现时若只删 SQL 表达式不同步删绑定参数，报的是
                            #   `Incorrect number of bindings supplied` —— 那是绑定错、**不算有效变异**。
# 2026-09-25 续36 新增 `[6w]`：**FOFA 三路反查的阶段级桩测**（补续33 留下、`[6u]` 为省配额关掉 FOFA
                            #   后一直没盖上的两条：三个子开关各管哪一路 / 真查命中→落「拓展域名」）——
                            #   桩掉 `fofa_mod.search` / `search_cert` / `search_title` 与 `favicon_hash` 后跑**真流水线**，
                            #   按调用记录 + `subdomains` 落库断言：A) `fofa.enabled=false`（其余外部开关全关）→
                            #   整阶段跳过、一次查询都不发；B) 只开 favicon 那一路 → `cert_enabled`/`title_enabled=false`
                            #   时 cert·title **一次都不查**，命中只落 `osint:fofa` 一条、桩里的**裸 IP 行不入库**；
                            #   C) 三路全开：黑 ico（999>200）/ 通用证书**不拓展**，占位证书（`example.com`）与
                            #   模板标题（`Index of /backup`）**零请求**跳过，来源串 `osint:fofa-cert`/`fofa-title` 各就对。
                            #   防假绿：「黑 ico 不拓展」那条必须**同时**断言 `("icon", 12345)` 确实查过 —— 否则
                            #   "没落库"可能只是"压根没查"；零请求预筛用**调用记录里不出现**来钉，而不是只看日志。
                            #   补它的理由：既有覆盖只有阈值/预筛的**纯函数**级与标题·证书落库，favicon 路的
                            #   「命中→落库」接线与子开关判定此前**没有阶段级断言**（纯函数全绿、阶段里接错线照样绿）。
# 2026-09-25 续37 新增 `[6x]`：**nuclei `dsl` 表达式安全子集**（`scanner/pocs/dsl.py` 手写词法 +
                            #   递归下降，**不用 eval** —— 模板是外部输入）—— ① 命中路径：装载期把 AST 挂到
                            #   匹配器/提取器 dict 的 `_dsl_ast`（断言 7 / 4 条），端到端打本地靶场命中，
                            #   提取器只收**非布尔**结果（evidence 恰为 `200`/`9`/`hello-aaa`，`True` 不进）；
                            #   ② 合并口径：matcher 内 `condition`（默认 or）与 `negative`、`header`==`all_headers`、
                            #   `host` 变量、`dsl` 写成整串字符串、手工 POC dict（无 `_dsl_ast`）走现解析兜底；
                            #   ③ **装载期拒** 8 类越界（`.` 方法调用 / 未知函数 / 未知变量 / `+` 算术 / 链式比较 /
                            #   字符串大小比较 / 坏 regex / 空 dsl），每条都要能指认出是哪种写法，
                            #   且**提取器级**同样拦（`extractors` 字样出现在原因里）；
                            #   ④ **块级 / 顶层** `dsl` 仍拒（与 matchers 级放开严格区分）。
                            #   防假绿：反向用例（`contains(body,'NOT-THERE')`）必须**不报** —— 否则
                            #   "dsl 分支恒 True"照样全绿。
                            # 2026-09-25 续38 新增 `[6y]`：**nuclei workflow 条件编排**（语义对着
                            #   nuclei 源码 `pkg/templates/workflows.go` / `pkg/core/workflow_execute.go` /
                            #   `pkg/templates/tag_filter.go` 写，不自己发明）—— ① 父命中才下钻，父**不命中**
                            #   时子模板**零请求**（挡"无条件跑子模板"的假实现）；② 带 `subtemplates` 的步骤
                            #   父模板只当**开关**，报出来的是子模板的 `poc_id`（父结果不报）；③ 多级门控
                            #   逐层生效；④ `tags:` 是 **OR** 选择、候选集来自注册表（vulnscan 传 `registry=`），
                            #   未被选中的模板一个请求都不发；⑤ `tags` 与 `template` 同时写时 `tags` 优先；
                            #   ⑥ `template:` 指向目录会展开；⑦ 单步展开上限 `_WORKFLOW_MAX_SUBS`=40；
                            #   ⑧ `matchers:` / `args:`（**不是 nuclei 字段**）/ 裸 `subtemplates:` 子项跳过
                            #   并把原因写进 `_note`，全跳过则整份 `unsupported`；⑨ 带 subtemplates 的自环
                            #   被 `seen` 去重挡住（子模板只跑一次）。
                            # 2026-09-25 续39 新增 `[6z]`：**nuclei flow 的脚本子集**（语义对着 nuclei
                            #   源码 `pkg/tmplexec/flow/{flow_executor,flow_internal,vm}.go` 写 —— 注意 flow
                            #   实际不在 `pkg/protocols/common/flow/`；`http(N)` 是 1-based、`http()` 跑该协议
                            #   全部块、`iterate(...)` 扁平化成数组、`template` 是**对象**）——
                            #   ① `for...of iterate(...)` + `set()` + `http(1)`：钉 `_hits17` 路径序列，
                            #   证明循环**每轮真的重发**（脚本路的 `http(...)` 不缓存；缓存会把循环抹掉）；
                            #   ② C 式 `for`：`_flow_js_iters` 的静态轮次必须与运行期 while 条件同口径
                            #   （只改一处 → 请求数会多/少一轮）；
                            #   ③ `template["k"]` 读值 + `if` 门控：条件假 → **零请求**；
                            #   ④ `http()` 全跑（模板顺序）/ `http("id")` 与多参按**传入顺序**；
                            #   ⑤ 脚本没有整体真值 → 只报**第一个**正向命中（`hits[:1]`）；
                            #   ⑥ `log(...)` 实参先求值（其内请求照跑）、本引擎不打印；
                            #   ⑦ 13 条子集外写法**装载期**给原因（`while`/`Math`/`dns()`/未声明变量/
                            #   动态键/非字面量序号/`*`/`for...of [..]`/不终止的 `for`/超
                            #   `_FLOW_MAX_STEPS`/`eval`/未知函数/多余 `}`）；脚本路引用越界·被跳过块·
                            #   不存在的 id 同样判 `unsupported`（与布尔路**共用** `_bad_refs`）；
                            #   ⑧ 手工构造的 poc dict 走运行期兜底时，顺序必须**先布尔后脚本** ——
                            #   顺序错了会把 `http(1) && http(2)` 当脚本跑成一命中就报（语义漂移）；
                            #   ⑨ 布尔子集**零回归**：`_flow_script` 不得出现在布尔 flow 上、`||` 仍短路、
                            #   纯否定仍不报。
# 2026-09-28 续61 新增 `[7y]`：**Web 禁绝对路径（用户新硬规矩）+ 外部工具跨平台** ——
                            #   ① `rel_display` 两档口径（项目内两档同为相对形 / 项目外默认原样、
                            #   `mask_outside=True` 压成 `…/父/名`）；② `scrub_paths`（抹盘符路径·抹引号内
                            #   绝对路径·抹项目根前缀·**不误伤 URL** —— 漏掉否定环视时 `http://` 的 `p:/`
                            #   会被压掉，实测踩过）；③ **页面级扫 HTML**：登录后遍历 11 个页面，断言
                            #   **无盘符绝对路径、无项目根绝对路径**（前两组只能验"工具函数对"，挡不住
                            #   "某个模板/路由漏调了它" —— 续61 的真实缺陷正出在 `tools_page`）；
                            #   ④ 合成 `toolmgr.status` 行钉 `/tools` 的**双泄露点**（`path` 字段 +
                            #   `note` 里嵌的那份），并把 `rel_display` 打回旧口径证明断言有区分度；
                            #   ⑤ `which()` 后缀容错：同一份配置在 `.exe` / 无后缀两端都能解析
                            #   （相对与绝对两种形态），打桩 `_ext_variants` 为"只试原值"即红。
# 2026-09-28 续62 `[7n]` 增 **③b 功能向量覆盖**：全流程自检从「逐阶段」下沉到「逐子能力」——
                            #   ① `scanner/devflow.py::VECTORS` 列 **35 条**向量（阶段内分支：自动拓展/泛解析/
                            #   内置爆破/回填、CNAME、fscan 引擎、内置探测/端口候选/favicon、TLS、截图、
                            #   JS 挖掘、目录 模式/内置扫描/dirmap/框架/派生/递归、内置检查/POC 引擎、
                            #   情报 拉取/匹配、启发式聚合、osint 3 项、github 检索）；
                            #   ② 判据取自**本次运行的原生证据**（该阶段日志 / 外部命令 argv[0] / 请求 URL），
                            #   **不做"跑过就默认全绿"**；OK=真点到 / MISS=覆盖缺口 / **N-A=本次不该跑（必带原因）**；
                            #   ③ 自检 options 增 `auto_expand: True`（否则 subdomain 自动拓展永远 MISS）；
                            #   ⚠️ **改阶段日志文案时必须同步向量 `kw`** —— 判据与文案强耦合（判据命中不了就变 MISS）。
                            #   ④ 回归：`run_devflow.py` 报 35 向量 18 OK / **0 MISS** / 17 N-A；smoke 钉
                            #   状态合法 + N-A 必带原因 + 10 条核心主路径 OK + 缺口为 0 + 证据可复算，
                            #   并用 M6~M8 变异证明（判据恒不命中 / 抹掉阶段日志 / 去掉静态 N-A 原因）。
# 2026-09-28 续64 新增 `[7z]`：**截图必须无视不可信证书**（自签/过期 HTTPS 也能截）——
                            #   缺陷：`screenshot.capture()` 的 argv 缺 `--ignore-certificate-errors`，
                            #   浏览器遇自签/过期/私有 CA 直接 `ERR_CERT_AUTHORITY_INVALID` 拒载、
                            #   `--screenshot` 0 字节（CTF/内网常态）→ 实测同一站点加/不加 = 13512 vs 0。
                            #   ① 行为级：打桩 `shot_mod.run_cmd` 捕获 argv 断言开关在里头 + 变异证伪
                            #   （过滤 `_FLAGS` 即红）；② 端到端：真夹具自签 HTTPS 口（127.0.0.1）调
                            #   生产函数 `capture()` 断言 True + png 非空（无浏览器按 `[7x]` 口径跳过）。
# 2026-09-28 续69：`toolmgr._ALLOWED_HOSTS` 补 `release-assets.githubusercontent.com`
#   —— GitHub release 资产 302 跳转的实际目标（实测），缺它 `--update-tools` 什么都
#   下载不了（跳转后的真实 URL 会再校验一次白名单，防 302 绕过）。回归 `smoke [8b]④`。
# 2026-09-28 续68 新增 `[8b]`：**IDN 第二批**（base_domain 多段后缀 / .zip·.sh TLD / jsmine Unicode 形态）——
#   ① `base_domain` 走**最长匹配** `tlds.txt` 含点号后缀（含 punycode）→ 多段 IDN 注册域
#   各自成立（变异：`_multi_part_suffixes` 打回 ASCII-only 旧口径即红）；
#   ② `.zip`/`.sh`/`.do` 不再被 `_FILE_EXT` 误杀（变异：退回旧实现"PSL 后再拦 _FILE_EXT"即红）；
#   ②b 浏览器 argv —— **续74 修正续73**：CI Linux runner 必须加 `--no-sandbox`（否则 FATAL:
#   No usable sandbox!）与 `--disable-dev-shm-usage`（/dev/shm 过小→30s 超时，这才是续72 超时真因）；
#   二者现已加回。变异证伪改为“正向断言 `--no-sandbox`/`--disable-dev-shm-usage` 必须在 +
#   `--disable-background-networking` 必须在”（smoke `[7z](a)`）；PDF 导出（report.export_pdf）同源。
#   ③ jsmine 引号内 / 协议相对形态的 Unicode host 挖得到（变异：两条正则打回 ASCII-only 即红）。
# 2026-09-28 续65 新增 `[8]`：**IDN / 中文域名**（punycode 主链路 + 展示回解）——
                            #   缺陷：`例子.中国` 被判 `unknown` 静默丢弃（四处同口径的重复编码都只认纯
                            #   ASCII 字母 TLD；PSL `tlds.txt` 又把非 ASCII 后缀整批滤掉、`xn--` 一条都没有）。
                            #   ① 归一化收敛到 `utils.to_ascii()` 一处（ASCII 快路径/幂等/失败返回 None）+ 
                            #   `to_unicode()` 展示回解（失败原样、绝不抛）；`is_domain` TLD 段放宽为
                            #   `[a-z]{2,24}|xn--[a-z0-9-]{1,59}`；`targets.parse_line` / `iprecon.normalize_domain`
                            #   / `blacklist._norm` / `jsmine._add` 全部改走它；
                            #   ② `config/dicts/tlds.txt` 补 `xn--` 后缀（6423 → 6870，447 条）；
                            #   ③ 展示层 `idn_display`（= `to_unicode`）在 4 个模板的域名列回中文，
                            #   `value`/`href` 的真实值仍是 punycode；报告 MD/HTML 回中文、JSONL 保持 punycode；
                            #   ④ **端到端真链路**：目标 `例子.中国` 跑 `-p subdomain`（桩解析器）→ 解析目标/
                            #   产物/DB 全 punycode、任务详情页回中文。**每组都做 §6.1 变异证伪。**
py -3 cli/run_keys.py --status                        # 续98：凭据是明文还是密文、是否已解锁（只打摘要，不打值）
py -3 cli/client.py --check # 外部工具可用性（dirmap 看 tools/dirmap/dirmap.py 是否存在）
py -3 cli/client.py --check-afrog-pocs <目录>   # 只读自查 afrog PoC 目录：能喂几条、为什么拒（续123）
                            #   末尾另列「需手工安装（本框架不自动下载）」＝ nmap/fscan/dirmap（续59-3）+ massdns（续165，puredns 的传递依赖）
py -3 cli/client.py --bootstrap                           # 续96：迁移自举——按平台点清缺口（解释器/pip 依赖/外部工具/浏览器），**不联网**
py -3 run_bootstrap.py --install                            # 续99：等价入口（会先建 .venv 再用它自重跑；--no-venv 可退回当前解释器）
./install.sh                                        # 续146：Linux/macOS 一键安装（薄包装，判据全在 run_bootstrap.py）
./start.sh                                          # 续146：起控制台（等价 ./.venv/bin/python run_gui.py；改监听地址走 CTFSCANNER_GUI_HOST/PORT，run_gui.py 不解析 argv）
py -3 cli/client.py --bootstrap --install                   # 自动层＝pip 依赖 + toolmgr 的 TOOLS；「需手工」那三类只打印命令，一条都不代跑
py -3 cli/client.py --update-tools            # 续54：联网装/更新 subfinder/httpx/puredns 并回写 tools.<名>
                                              #   可选 --tool <名>（可重复）/ --allow-unverified / --no-wire / --tools-dest
                                              #   GUI 等价入口＝管理员侧栏「外部工具」页；两条路都**只在这时联网**
py -3 tools/import_dir_dict.py  # 重新生成目录扫描大字典（源：tools/dirmap/data/dict_load/dict_mode_dict.txt）
py -3 tools/import_fw_dicts.py --force  # 从大字典派生**按框架**细分的字典（12 桶 + exposure）
py -3 tools/calibrate_fingerprints.py  # 续127：组件指纹的负样本校准（**内联语料、零请求**，
                               #   默认 --json logs/fp_calibration.json）；只报告，不自动改判据。
                               #   回归 [8af]⑤ 钉住"外置表 0 命中"，语料变弱会被变异证伪抓出来
py -3 tools/calibrate_pocs.py  # 续60：本地负样本校准（起合成靶场，**零外网请求**逐条跑 POC 出报告）
                               #   默认 --src config/pocs-imported --json logs/poc_calibration.json --timeout 3
                               #   换 `--src scanner/pocs/pocs` 可跑内置那批；只报告，不自动改级别/不自动启用
py -3 tests/browser_e2e.py     # 续60：真浏览器 E2E（无头 Chrome/Edge + 手写 CDP 真点真读）
                               #   退出码 0=全过 / 1=有断言失败 / 2=找不到浏览器（跳过，不是通过）
                               #   已接进 smoke 的 `[7x]`（可降级组；`[7w]` 是有效级别口径 + 校准基线）
py -3 cli/client.py -t http://127.0.0.1:8765/ -p probe,vulnscan --offline
py -3 run_gui.py            # 入口在**启动横幅那行**（形如 http://<host>:<port>/<10位>/<10位>/，续138；
                            #   绑 0.0.0.0 且取到出口 IP 时首行换成能直接点开的公网地址、绑定值挪进括注（续153）；
                            #   续157 起由 gui.announce_egress_ip 控制要不要问第三方（默认开；关＝零外发）
                            #   直接开根路径是 404 空响应）；库里没账号时**当场向导**问你要设什么口令
py -3 cli/run_users.py --status # 续117：账号数 + 配置里有无历史残留（只报有无，不报任何值）
py -3 -m scanner.edgeauth --status                # 续132：401 边缘门配过口令没有（只报有无，绝不报值）
py -3 -m scanner.edgeauth --set                   # 写 config/edge_auth.yaml（明文、0600、gitignore）；口令经 getpass，**无终端时认 `CTFSCANNER_EDGE_PASSWORD`**（续146-附2；启动向导仍绝不代填）
                            #   建号 / 改口令：--create-admin [用户名]、--reset-password 用户名
                            #   非交互环境用 CTFSCANNER_ADMIN_PASSWORD 提供；口令只落 users 表
# 2026-10-14 续176 新增 `[176]`：**被 min_severity 挡掉的条目数说出口**（用户点单的收口项）——
#   计数三路（`owasp.checks.SeverityBlocked` + `run_all(..., blocked=)` 出参；vulnscan 的内置/POC/
#   afrog 三个丢弃点各 add()，判据仍只有 `severity_ok` 一处）；阶段末**覆盖写**落库
#   `tasks.sev_floor`/`sev_blocked`（追加执行累加会重复计同一隐藏项＝虚高，故页面只说"最近一次
#   vulnscan 运行"）；出口＝报告 MD/HTML 概览 + 详情页「潜在漏洞」页签，**文案唯一产地是
#   `report.sev_blocked_note()`**（模板不拼第二份）。变异证伪两向都钉着：摘计数 ⇒ [176a]/[176b]
#   红；只摘展示接线 ⇒ 仅 [176d] 红。
# Linux 实机验收（**2026-09-23 续12 已达成**：Ubuntu 22.04.5 / Python 3.10.12）
# Linux 实机验收（2026-10-02 续96-附2 复跑：Ubuntu / Python 3.14.4）—— smoke 131 段 PASS、devflow 18 OK / 0 MISS / 17 N-A、calibrate RC=0、CLI 实走 httpx、GUI /login 无绝对路径；browser_e2e 因无浏览器 RC=2（跳过≠通过），故截图与 PDF 在该机仍未验
#   python3 tests/smoke.py   → SMOKE PASS（`[5o]` 会按运行平台自报状态）
#   搬运：整树拷贝（含 config/dicts/），远端一条 `python3 run_bootstrap.py --install` 就绪（续99：自动建 .venv + 缺 pip 时引导 + 装依赖 + 下载带校验和的外部工具）；手工等价步骤仍是 `python3 -m venv venv && venv/bin/python -m pip install -r requirements.txt`
#   ⚠️ `smoke_root/.git/config` 是 `[3] pipeline` 必需的「泄露样本」，但 **git 拒绝跟踪任何
#   名为 `.git` 的目录下的文件** —— 它**永远不在仓库里**（此前只存在于作者本机）。
#   2026-09-28 续66 实测：用 `git archive HEAD` 出来的「干净树」跑 smoke 必然在 `[3]` 挂
#   （`AssertionError: [a01-sensitive-files, exposure-env-file]`），说明 **CI 一直是红的**。
#   现在由 `tests/smoke.py::ensure_fixture_git_config()` **运行时物化**（幂等、字节级一致），
#   于是推荐用 `git archive --format=tar HEAD | ssh … 'tar -x -C /tmp/xxx'`（约 4.5 MB，只传跟踪文件）。
#   ⚠️ 另一个坑：`[6u]` 开着 `portscan`，`probe` 会把**宿主机**上任何开放端口都当候选
#   （`https://host:port` 先试）—— 宿主若恰好有应答 TLS 的服务（实测 Ubuntu 的 CUPS 在 631），
#   就会多出站点与证书。相关断言已按「只钉靶场」改写（续66）；换机器跑前先看一眼本机开放端口。
#   Windows 侧非交互 SSH：设 `SSH_ASKPASS`（**必须放在纯 ASCII 路径**，含中文会
#   `CreateProcessW failed error:2`）+ `SSH_ASKPASS_REQUIRE=force`；凭据由用户提供、不入库。
```

改动后**必须**跑 `tests/smoke.py`；GUI/模板改动还应 `run_gui.py` 亲眼确认页面。

> **超过一分钟的命令一律后台跑**（2026-10-14 续176 立，主理人定的效率规矩）：
> `nohup ./.venv/bin/python tests/smoke.py > logs/<名字>.log 2>&1 &` 挂上就结束回合，
> 下次交互时再查（`pgrep -f tests/smoke.py` 看还在不在、`tail` 看进度、
> `grep -c '^\[' logs/<名字>.log` 数组数）。**反过来也成立：门禁跑动着的时候不要改任何
> 被跟踪文件** —— smoke 有大量断言读源码文本/AST，`[8as]` 还要核三份记忆的轮次号，
> 中途编辑会造出 §6.2 那类假红；要改就先等它跑完。
> ⚠ **不许用 `sleep N && 查状态` 轮询**（续176 当天就犯规过一次）：sleep 会阻塞整个回合，
> 还会每次弹一次 IDE 的"要不要后台运行"——等待只有两种合法形状：启动时 nohup、查询时毫秒级命令。

> **凭据红线的边界**（2026-10-14 续176 立，主理人原话"凭据红线只对我们本地自己配置生效"）：
> §5.10 / §7 那条"口令 / token / PAT 绝不进被跟踪文件"管的是**我们自己用的凭据** ——
> `config/keys.yaml` / `config/keys.enc.yaml` / `config/edge_auth.yaml` / `github.txt` /
> `~/.secrets/keys-pass` 这些**本机配置**（进了公开仓库就等于把我们的钥匙交出去）。
> 它**不管**扫描中从授权目标身上挖到的东西：靶子的 JS 里泄露的 AK/SK、页面里的 flag 是**扫描产物**，
> 按 `flags` 表（续126）与 `js_secrets`表的档位处理 —— 入库（`data/scanner.db` 被 gitignore）、
> GUI 可展开查看、默认不进迁移包、报告外发面单独核。两件事别混：把靶子的凭据也当"绝不出库"处理，
> 等于把 CTF 最该抄走的东西藏起来。

> **这台 Linux 跑门禁必须 `./.venv/bin/python tests/smoke.py`（续141 亲测踩过）**：`python3` 是系统
> 3.14 且**没装依赖**，于是 `[1]`~`[4b]` 一路绿到 `tests/smoke.py` 里的 `from gui.app import app`
> 才 `ModuleNotFoundError: No module named 'flask'` —— **崩在半路的红很容易被读成"刚那批改坏了"**
> （那一轮真正改的是 27 个文件里的字符串替换，与 GUI 导入无关）。数进程同理：
> `pgrep -f tests/smoke.py` 会把包着命令的 `bash -c` 一起算进去（§6.2 第八起），
> 要看 `/proc/<pid>/exe` 是不是真 python 才算"有没有第二个执行者"。

> **`logs/smoke-*` 是什么**：`tests/smoke.py` 会在 `logs/` 下用
> `tempfile.mkdtemp(prefix="smoke-")` 造一个隔离沙箱（库与任务目录都指进去，见文件头 30–101 行），
> 跑完靠 `atexit` 删掉。**它只碰自己刚造的那一个目录**，不碰 `data/scanner.db`、不碰 `logs/task_*`。
>
> **残留从哪来（2026-09-24 实测更正）**：以前这里写的是「safe-delete 守卫拦截 + `ignore_errors=True`
> 静默失败」，**已被实测证伪** —— 脚本单次 `shutil.rmtree` 删掉 70 个条目一次成功，守卫并不拦
> Python 的删除；且正常跑完前后 `logs/smoke-*` 数量不变（`120 → 120`）。真实原因是**被强杀的运行**
> （SIGTERM / 命令超时 / 手动中断）里 `atexit` 根本没机会执行 —— 任何「退出时清理」都挡不住 SIGKILL。
> 本机攒到过 **120 个 / 21.8 MB / 7770 个条目**。
>
> **现在的兜底（自愈）**：`smoke.py` 启动时清扫 `logs/` 下**超过 60 分钟**没被触碰过的 `smoke-*`
> 目录，删不掉时**明说**（不再用 `ignore_errors=True` 静默吞异常）。60 分钟下限是为了不误删
> **并发运行**中的另一个沙箱（运行期间会不断写它，mtime 一直是新的）。回归见 `[6o]`。
> 因此看到 `[清扫] logs/ 历史残留沙箱：删除 N 个` 是正常的自愈动作；残留也可以随时手删
> （`logs/` 已在 `.gitignore`）。

### 6.1 修 bug 时，必须证明新断言**在旧代码下会挂**（2026-09-24 立的规矩）

> 背景：本项目出过**四次**"假测试"（另有**两次"假红"**，口径见下面的 §6.2）。第一次是 `[5p]` 把 `run_task` 桩掉了，只验"走哪一档"不验"真扫出什么"，
> 结果深扫漏掉 `.env` 的缺陷藏了很久；第二次是批次 4 修完 SSRF `close()` 的死代码后补的断言，
> 把修复**退回旧实现**跑，三条断言**依然全过** —— 因为 `srv.shutdown()` 本来就会阻塞到线程结束，
> 且旧写法同样把字段清成了 `None`。断言验的是"结果状态"，而死代码的问题恰恰在"代码路径没走到"。
> 第三次（续32-fix）是 `[6w]` 里写"同源 / 跨源"却没**显式给出带端口的 Host** —— test client 默认 Host
> 是 `localhost`，端口断言因"主机名本来就不同"而假绿；该真缺陷最终靠**真实服务器 + 真实浏览器**才暴露。
> 第四次（续41）是 `tests/smoke.py` 的 `print("SMOKE PASS")` 写在**模块顶层**（在
> `if __name__ == "__main__": main()` 之前）—— 它在 `main()` 里几千条断言**一条都没跑**时就打印了，
> 于是**用例挂了照样打印 `SMOKE PASS`**，唯一真判据只剩退出码；已搬进 `main()` 末尾。

**规矩**：凡是为某个 bug 补回归断言，交付前必须做一次**证伪**——把修复在内存/工作区里
**临时退回旧行为**，确认新断言**真的失败**；再还原，确认全过。两次观察结果都要写进报告。
退不回失败 = 这条断言没有区分度，等于没加。

**怎么退**（不改提交历史）：临时改回旧代码跑一次 smoke（跑完立刻还原，**不要提交那个版本**），
或在一次性脚本里 monkeypatch 常量/函数（脚本放 `logs/` 下、跑完删掉）。
可参考 `tests/smoke.py [6a]` 的写法：**桩注入 + 断言调用行为**（`join_calls == [2]`），
比断言"结果状态"（`not th.is_alive()`）强得多 —— 后者在新旧实现下都成立。

推论：**能被新旧实现同时满足的断言，不是回归测试**。写断言前先问"旧代码会让它挂吗"。

推论三（续107 新增，本轮真踩到）：**证伪本身也会过期**。续104 给"窄屏不溢出"配的证伪是
「把 `main section{overflow-x:visible}` 注回仪表盘 @430，必须重新溢出」—— 实测当时 +71px。
续107 加了窄屏档（侧栏翻成顶部横条、主区从 265px 放宽到 345px）之后，同一条注入**不再造成溢出**，
因为那张表（min-content ~314px）在新宽度下本来就放得下 —— 承重关系随布局变了。
处理方式**不是**删掉证伪，而是把它挪到仍然承重的地方（`/tasks` @360，实测 +361px）。
所以：改布局/改宽度之后，除了跑门禁，还要回头问一句"当年那条证伪还成立吗"。
另一个同轮踩到的坑：`.panel`（特指度 0,1,0）**高于** `main section`（0,0,2），
注入只废后者会被顶回去、看起来"证伪失败"—— 废一条规则要把它的所有选择器一起废。

推论二：**"绿信号"本身也要能被证伪**。`SMOKE PASS` 打印在哪一行、退出码、日志里的"已启用/已跳过"一行，
都必须由"这一轮真的全部通过"这个事实产生；否则它只是装饰，还可能主动误导（第四次的 `SMOKE PASS` 就是
装饰 —— 续41 把它搬进 `main()` 末尾，并做了"旧位置 + 坏断言 → 仍打印 PASS / 新位置 + 同一坏断言 → 不打印"
这组双向证伪）。
推论四（续146 新增，本轮**第五次**撞同一类）：**断言别钉裸词，钉代码形态**。
已经有五次"自己写的说明文案把自己的断言绊红"：① 摘掉「深度目录补扫」入口后，断言
`"深度目录补扫" not in page` 被我自己在 gui/app.py 里写的一句注释绊红；② 断言 `"site_urls" not in src`
被同一轮的说明文字绊红；③ D 收敛折叠判据后，按**文本**搜 `base_domain(` 把 `github_leak.py` 的 docstring
（那里正是在解释"为什么不再需要那道守门"）算成了第二份实现；④ 断言 app.js 里不许出现
`querySelectorAll("#tbl-vulns`，被我自己写的注释绊红；⑤ `[8av]` 原先禁 install.sh 里出现 `get-pip`，
而脚本里那句"缺了 python3-venv 就退到用官方 get-pip.py 引导"是**正当说明**，不是第二份实现。
⑥ `[8bs]`（续161）判"候选那条 SQL 里不许抄档名"用的是 `assert 档名 not in inspect.getsource(函数)`，被同一份 docstring 里举的**反例**（`LIKE '超时%'` 为什么不许写）绊红 —— 同一个坑**第六次**。
处理方式一律是**把判据收紧到代码形态**，而不是给文案开豁免（豁免一加，判据就再也抓不到真违规）：
`site_urls` 改成认 `\bsite_urls\s*=`；"某函数不再被调用"改成用 **AST 数 `ast.Call` 节点**
（`[8au]⑤` 就是这么判 `base_domain` 的）；容器判据改成认真实调用 `btn.closest(".panel")`；
"禁第二份实现"只禁**动作**串（`pip install` / `-m venv`），不禁提到这些词的说明文字。
续161 那次的收窄方式是**只扫 AST 的字符串字面量并显式排除 docstring**，再**反向断言字面量里必须扫得到那段 SQL** —— 扫全文会把解释当实现，而收窄过头又不复核一次就会变成判据空跑（绿得没有内容）。
写这类断言前先问一句：**"我即将写下的这段解释，会不会自己命中它？"**
配套的一条：**"0 命中 / 空列表"型断言必须自带夹具**。`[8au]⑥` 判"活文件里没有指着仓库根的可抄命令"
之前，先造三条该被抓住的命令确认判据抓得到、再造三条不该被抓住的确认它不误伤，
并且断言扫描范围本身 > 100 个文件 —— 否则目录一改名，"0 命中"就成了空写（§6.1 的老规矩，
只是这类断言特别容易忘）。

### 6.2 假红：断言拿"环境值"当哨兵（续97 新增，两起都是真撞出来的）

> §6.1 讲的是断言**没有区分度**（假绿）。对称的另一半是断言**过度依赖当前环境的具体值**（假红）：
> 它在你机器上绿，换一台机器、或让用户按文档做一次正常操作，就必然红。这一类比假绿更阴险 ——
> 假绿让缺陷藏住，假红让人**不再相信回归门禁**，而且它通常被当成"环境有问题"糊弄过去。

**第一起（续97，`smoke [7p]`）**：验"回写 `settings.yaml` 不得动其它键"用的是
`assert "  httpx: httpx" in 文本` —— 拿**旧值**当哨兵。而 `_set7p` 是**真实 `config/settings.yaml`
的副本**，只要用户照项目推荐跑过一次 `--update-tools`（续96 的自举也会跑），那一行就变成
`tools/scanner/httpx`，哨兵必失效。远端 Linux 实跑 `--bootstrap --install` 当天就把 [7p] 打红。
**正确口径**：改前/改后**逐行 diff**，只允许被改的那一行不同（`[7p]` 已这么改）。 　**同族复发（续159）**：`smoke [5y]`/`[2c]` 把「ctlog / ssrf 出厂默认关」的判据写成 `enabled(settings)`，而那个 `settings` 是 `load_settings()` 的**本机**那份 —— 主理人在策略页打开 ctlog 后这条当场红，且红在 `ctlog_mod.search()` 那一步（现象是「判据真的去打 crt.sh 并拿到 429」，不是「代码坏了」；http 已被桩住，没真的耗配额）。口径同第一起：**「出厂默认」一律吃 `DEFAULTS`**，「关着不发请求」那一档**自己造**一份明确关着的配置（现文件里的 `_ct_off5` / `_ss_off5`）。**再复发（续162）**：`unlock()` 加上第三档（`~/.secrets/keys-pass`）之后，`[2c]` 那两句「无 key 时报未配置」的判据同时踩上两个环境依赖 —— ① 本机有 `config/keys.enc.yaml` 而 CI 没有；② keystore 的解锁状态是**进程全局**的，前面任何一组调过 `unlock()` 都会改它。现象是门禁红在一条从没人改过的断言上，而红出来的文本还带着真实的密文文件名。口径一样：**判据先把状态钉死再断言**（把那两条路径指到不存在的临时文件、`reset()` 一次、`finally` 还原）。这一族里「秘密文件的存在性」比路径更危险 —— 它不会在报错里告诉你「这台机器恰好有那个文件」。

**第二起（续97，`smoke [5]/[7y]/[8d]` 共 5 处）**：验"页面不得出现项目根绝对路径"用的是
`assert str(ROOT) not in html`。容器里 `ROOT=/w`（两个字符），正文里
`raw/flow/workflows` 这种巧合子串就会被判成泄露 —— `python:3.9-slim` 镜像里实测直接把 [5] 打红。
**正确口径**：泄露必须带**路径边界**，收敛到 `tests/smoke.py::leaked_root()`
（`根串之后不是单词字符`才算；`str(ROOT)` 与 `as_posix()` 两种写法都查）。

**写断言前的两句自检**：① 这条判据吃的是**桩/参数**，还是**这台机器恰好是什么**？
② 如果用户照 README 正常装一遍、或把仓库放进 `/w` 这种短路径里跑，它还绿吗？

**第三起（续136，本轮真踩）：两个 `tests/smoke.py` 并发跑必然假红。** 一个全量跑到 130+ 组、
十几分钟，另起一个（或让子代理也去"跑一遍门禁"）就会共用同一个本地靶场端口（8765）与同一批
进程内状态 —— 先结束的那个会把靶场服务关掉，另一个就报成"探测调用 1 次、站点 0 个"这种
**看起来像产品缺陷**的形状（本轮 `[8k]` 就是这么红的，单跑复验立刻绿）。规矩：**门禁只由一个
执行者跑**；要并行验证就做互不相干的静态检查，或者干脆排队。同理，证伪/变异实验也别和正式
门禁同时在一份工作区里跑。

**第四起（续138，容器里真踩）：以 root 跑门禁时，任何靠 Unix 权限位制造的"写不进去"都不成立。**
`smoke [8g]` 用 `chmod 0o500` 的目录验"会话密钥落盘失败必须明说降级"，而 **root 无视权限位** ——
`docker run` 里那条必然红，报成"密钥落盘失败却静默"（像产品缺陷，其实是环境）。
处理口径**不是** `if root: skip`（跳过 ≠ 通过，而且整组一声不吭），而是换成 root 也挡不住的形状
继续验同一条不变量：**父路径是一个普通文件**（任何 uid 都 `mkdir` 不进去），并在组结尾
**打印这次没验到哪一层**（`_note109` 直接拼进 `[8g]` 那行 ok）。
写新断言时记住：想要"写失败"就用**路径结构**而不是权限位；真要验权限位，就得同时具备非 root 的
执行条件（本机 venv 跑门禁才是那条的正解）。

⚠️ 顺带一条**清理纪律**（续138 本轮自己犯过一次，见 CHANGELOG 续138 第十节）：
`logs/` 里除了本轮的临时脚本，还躺着以前几轮的**产物与审计证据**（`*.json` / `smoke-*.txt` /
`devflow_baseline.json` 等）。清理只按**确切文件名**删，绝不在 `logs/` 里用 `rm *.json` 这种通配符；
要删先 `ls` 一眼确认每个都是本轮产的。`data/` 与 `.venv/` 同理 —— 那是用户与前人的东西。

**第五起（续138，容器里真踩）：项目根被挂成 `/app` 时，「页面不得出现绝对路径」这类断言会被
PoC 自己的 URL 路径打红。** `smoke [5]` 查 POC 页里有没有 `str(ROOT)` 后接非单词字符 —— 在
`ctfs:py39`（挂载点 `/app`）上，PoC 模板里的 `/app/login.jsp`、`/app/kibana/` 完全符合这个形状，
于是页面里一个本机路径都没有，断言却红了。根越短，"根串恰好是别人家 URL 的一段"就越是必然，
这不是巧合也不是实现问题。
处理：`leaked_root()` 对**短根**（只有一层）只认"真泄露的形状"—— 根 + `/` + **本项目确实存在的
某个顶层条目**（`logs/`、`data/`、`scanner/`…，从 `ROOT.iterdir()` 现取，不写死名单）；长根
（本机 venv、CI 的 `/home/runner/work/…`）保持原来的严格判据一字不动。两条都要：降级要**说出来**
（`ROOT_LEAK_MODE` 打进 `[5]` 那行 ok），判据要**仍有牙齿**（`/app/logs/a.log` 这类真泄露照样红，
`logs/_lrcheck.py` 那种"五种形状各断一次"的验法可以照抄）。
推广口径：任何"不许出现本机路径/本机标识"的断言，判据都得绑定到**本项目真实存在的结构**上，
而不是裸字符串边界 —— 否则换一个挂载点就红一次。

**第六起（续138，容器里真踩，而且这次是**真的弄坏了东西**）：把仓库 bind-mount 进容器跑门禁，
`smoke [8d ⑪]` 会对**宿主机的 `.venv`** 调 `ensure_venv()`。**当前解释器与那个 venv 不同时**
（宿主机 3.14、镜像 3.9），它会走到 `python -m venv <已存在目录>`，而这条命令**就地改写
`pyvenv.cfg`**（version/home 变成 3.9）并建出 `lib/python3.9/` —— 门禁去动用户的运行环境，
这已经不是假红而是破坏。
规矩：**任何"幂等 / 复用"类判据，只有在前置条件成立（这里＝那个 venv 对当前解释器可用）时才
对真实对象执行**；前置不成立就 (a) 打印"这一条本次没验到（不是通过）"，(b) 把失败档搬到
**沙箱目录**里演（同组下面那个 `_root11/mine` 用例就是干这个的，它连"不许删用户目录"一起验）。
跨版本容器跑门禁前，先确认测试不会写挂载进来的宿主文件。

**第七起（续139，自己造的假红，而且成因很低级）：同一个容器里并发两个 `smoke` 一定出假红。**
为了「赶紧重跑」，我在没确认前一个 `docker exec` 真的结束的情况下又起了一个 —— 而宿主机侧
`TaskStop`/`kill` 只掐 `docker exec` 那个**客户端**，容器里的 python **照旧在跑**。两个进程
写同一个日志文件、抢同一个 8765，先起的还在后面刷写，于是第二轮 RC=1、`grep Traceback` 却
一无所获 —— 就是本节一直说的「看着像代码坏了」。**跑前先数进程**：
`docker exec <c> sh -lc 'for d in /proc/[0-9]*; do tr "\0" " " < $d/cmdline 2>/dev/null | grep -q smoke.py && echo $d; done'`
（`ctfs:py39` 里没有 `ps`，也别指望 `pgrep`）。有残留就**重建容器**：代码是 `tar` 进去的副本、
镜像是现成的，重建 20 秒，比去猜哪个 PID 属于哪一轮便宜得多。同理，宿主机上也不许同时起
两份门禁 —— 「一个门禁执行者」这条约定本来就是为 8765 立的。


**第八起（续140，同一类毛病我又犯了一次，这次在宿主侧）：后台任务报「完成」不等于那个 python 已退出。**
为了赶进度，我在第一轮 `tests/smoke.py` 只跑到一半、任务侧还没回报结束之前就起了第二轮。症状分两段：
后起那轮跑出 `AssertionError: probe 没接入「跳转后」取证（调用次数=1，站点数=0）` —— 看着像续140
把 probe 改坏了，**实际是它的本地夹具绑不上 8765**（先起的还占着），夹具没起来、站点自然是 0；
再往后那一趟整趟 10 分钟超时。定位只花了一条命令：`ss -tlnp | grep 8765` 加
`pgrep -af tests/smoke.py`（注意后者会把包着命令的 `bash -c` 也算进去，**要挑出真在跑的那个 python**）。
这条把 §10 的"门禁执行者"界定清楚：**执行者是那个 python 进程，不是那次工具调用**；
起新一轮之前必须数过进程、看过端口，超时/被中断的那轮更要数（被掐掉的往往只是客户端）。

**第九起（续140，`本地全绿 → CI 两个 smoke job 同时红`）：判据拿错了对象 ——「找得到浏览器」不是「渲染得出来」。**
症状很好认也很好骗人：宿主 3.14 全绿、容器 3.9 全绿（容器里**没有**浏览器 ⇒ 那组按口径打印
「跳过（不是通过，环境限制）」），CI 的 `smoke`(3.9) 与 `probe-3-14`(3.14) **同时**红 ——
两个 Python 版本一起红却和版本无关，第一反应该是"环境差异"而不是"代码坏了"。
红的确实是新加的端到端那一条：它写的是 `if available(): assert 标题补到了`，
而 runner 上 Chrome 在、`--dump-dom` 那条路截不出 ⇒ 断言把**环境限制**读成了代码缺陷。
修法不是"CI 里关掉"，而是**把判据换对**：只有"这一次调用真的产出了新截图"才钉标题，
否则打印「跳过（不是通过，环境限制：浏览器在但截不出）」；并且用 `④c`
（`browser` 指到一个**存在但不是浏览器**的可执行文件）把这条降级路径变成**每台机器都跑得到**的断言，
不再依赖"恰好有没有装 Chrome"。同一条判据还顺手抓出 `capture()` 的真缺陷，见 §5/§7 与第八起下面那段。
定位手段（这台机器能用的）：`annotations` 只有"exit code 1"，看不到断言文本 ——
所以**先看本地与 CI 的差集**（版本无关、环境相关），再照差集复现；
本仓的日志下载端点要仓库管理员权限，未认证拿不到 ⇒ 别指望靠日志猜。

**第十起（续140-附2，**假绿**：门禁全绿、CI 也全绿，但一条断言其实再也没跑过）：跨组传标志要写进
`globals()`，写在 `main()` 里只是局部变量。**
为了把 CI 那 47 秒省掉，我在 `[7z]` 里设 `_SHOT_OK7Z = True`（"这台机器的浏览器真能截"），
`[8ar]` 用 `globals().get("_SHOT_OK7Z")` 读它 —— 整个 smoke 都跑在 `main()` 函数里，
那个赋值**从来没进过 globals**，于是读到的永远是 `None`：SPA 端到端在每一台机器上都走"跳过"分支，
而它打印的正是合规降级那句话，RC=0。
为什么比假红贵：假红会逼人查，假绿让所有人安心。这里唯一能看出问题的信号是**本机**
（浏览器真能截 ⇒ 该打印"补到标题 …"）也变成跳过；容器与 CI 本来就该跳过，所以"跳过"本身不可疑。
两条口径：① 跨组共享的标志一律 `globals()["名字"] = 值`（或干脆走模块级常量），
别用裸赋值；② 新写的"降级/跳过"分支必须先在**能跑通它的那台机器**上看过一次反面结果
（本机就该看到"ok"而不是"跳过"），否则等于给自己开了个静默旁路。


**第十一起（续141，由「脱敏」照出来的哨兵依赖）：断言拿「某个域名在现实中注册着」当判据。**
症状与第九起几乎一样（宿主 3.14 全绿、CI 的 `smoke`(3.9) 与 `probe-3-14`(3.14) **同时**红），
但这次与浏览器无关：`tests/smoke.py` 里 `assert _net7["gone.<别名>.pro"]["ip_note"] == "nxdomain"`
报的是 `KeyError`。根因**不在替换本身**——那一组只桩了 `dnsq.resolve_detail`，而
`extdom.resolve_extended()` 末尾还会调 `drop_absent_zones()`（续113 那条「注册域压根不存在就不是
资产」），**那一步真去查注册域的 NS**：旧目标名恰好在现实中注册着 ⇒ `exists` ⇒ 行留着 ⇒ 常年绿；
换成假别名 ⇒ NXDOMAIN ⇒ 行被删 ⇒ 红。宿主为什么绿？这台机器问 NS 得不到结论 ⇒ `unknown` ⇒
fail-open 保留 —— 所以这条断言吃的从来不是代码，是**外部世界 + 本机解析器恰好是什么**
（与第一起同类，只是这次的外部值是 DNS，不是配置文件里的路径）。
修法两条**都要**：① 把 `dnsq.zone_state` 一起桩掉；② 断言「桩真的被点到」
（`_zone_calls == ["<别名>.pro"]`）与 `dropped == 0` —— 只加桩不加第二条，"行还在"可能只是因为
生产代码根本没接 zone 判据，那就是**另一种假绿**。
推广口径两条：**调用链上每一个能落到真实 DNS / 真实 HTTP 的出口都要桩**，不能只桩第一眼看到的
那一个；以及**复现环境至少要有一次「问得到 NS」的机会**（容器 / CI），否则这类依赖只会表现成
"换台机器就红"。
顺带一条实操：容器里数进程时 `grep -q smoke.py` 会匹配到**自己那条 `sh -c`**（宿主 `pgrep -f`
同病，见第八起），要按 `/proc/*/exe` 是不是 python 来数。

**第十二起（续145，**假绿**，而且是本轮自己造的）：被 stub 掉的写出口，会让"整段配置被删掉"对门禁完全不可见。**
一个打偏 7 行的字节级补丁（行号取自**上一批补丁改动前**的文件）把 `/settings` 的 POST 映射里
`evasion` 的 `spoof_xff` / `waf_bypass` / `bypass_level` / `waf_detect` 与 `takeover` 的
`enabled` / `max_hosts` 整段顶掉，还留下一个**重复的 `"subdomain"` 键** —— Python 字典字面量的
重复键是"后者静默盖前者"，`ast.parse` 照样过、页面照样渲染、`/settings` 照样 302。
**130+ 组门禁一组都没红**：所有 `/settings` 的用例都把 `save_settings` 打桩成"捕获入参"，
于是"少存几个开关"没有任何可观测后果；要等用户在策略页点一次保存、发现免杀/接管开关莫名回到
默认值，才会浮出来。它最终是被**本轮新加的**那条 `auto_root` 断言以 `KeyError` 撞出来的 —— 
也就是说，抓到它的不是既有防线，是运气。
两条口径：① **多批补丁时，每一批的行号都要从"上一批已经改完的文件"重新取**（`grep -n` 一次，
别沿用记忆里的号）；② 凡是"写出口被 stub 掉"的用例，必须另有一条**按 `DEFAULTS` 逐段点名**的判据
（`set(DEFAULTS[段]) - set(捕获到的[段]) == ∅`），否则"保存一次就把某段的键删掉"这类损坏
对门禁是隐形的。`[8at] ②` 现在给 `evasion` / `takeover` / `subdomain` 三段上了这道锁
（例推到策略页覆盖的全部段已在待办里）。

**第十三起（续146-附4，本轮门禁自己红的就是它）：页面断言的筛选参数名两边不一致，写错了不报错、
只安静地不筛选。** `[8ay]⑥` 要判"没有数据包的那一行恰好出现一次解释"，我按几个资产页的习惯写了
`/vulns?task=<id>` —— 而 `gui/app.py::vulns()` 读的是 `request.args.get("task_id")`。
未知参数被 Flask 直接忽略，于是那一页根本没按任务筛，`count(...)` 数到的是**整个沙箱库里 99 行**
（那些行全是没有 packets 的旧结论），断言报 `实际 99 处`。
这条红**是好事**（它抓的是"我的判据建立在没生效的筛选上"），但形状很容易被误读成"页面坏了"。
两条口径：① 写页面级计数断言之前，先 `grep` 那一**条路由**读哪些参数名（`/vulns` 吃 `task_id`、
`/sites` `/subdomains` 等六个资产页吃 `task=`，这个不一致是既有的，不是本轮造的）；
② 计数断言必须**自带"筛选真的生效了"的对照**——`[8au]①` 那句
`assert "NOISE…-521" not in html, "?task= 没挡住别的任务的行 —— 那样下面每条计数都是捡来的绿"`
就是这道对照，新写页面断言时照抄它，别只数自己的行。
推广口径：**凡是"页面按 X 筛，然后数 Y 次"的断言，都要先证明 X 生效了**，否则数到的每一处
都可能来自别人的数据，绿得毫无意义（§6.1 那种"空写"的反面：**满写**——数到一堆但都不是被测对象）。

**第十四起（续159，真机报出来的严重缺陷）：断点续跑让整条流水线静默降级成「只扫目标本身」。**
症状是主理人贴的两个同目标对比：#17 站点 15 / 域名 49 / 漏洞 6，#18 **站点 0 / 域名 14 / 漏洞 0**；
而 #18 的 `subdomains` 里 `subfinder` 那 8 条与 #17 逐字相同，差额全在 `js:mine` 31→0 与
`osint:cseg` 10→6 —— 也就是说**「域名少」是站点归零的下游结果，不是收集变弱**。
根因：`runner.py:153` 每次构造 `StageContext` 都把 `ctx.results` 清成空表，而域名候选
`domains_for_probe` 的**唯一产地是内存**（`stages/subdomain.py:365`），两个消费方
`stages/portscan.py:44`、`stages/probe.py:421` 只读它。续跑（本次由进程被终止 + 启动对账自动重新
入队触发，任务日志 03:49:40→03:59:52 空档 10 分钟）时前序阶段不再跑 ⇒ portscan 主机 9→1、
probe 候选 18→2、站点 0，**而任务终态照旧 `done` / 进度 100% / `error` 空** —— 唯一可疑痕迹只有
「2 分 45 秒跑完 13 个阶段」这个数。日志里那句「此前各阶段的产物沿用库中已有数据」在实现上并
不成立，属于**文档替代码说谎**（§5.19 同族）。
为什么 130 多轮没人发现：`[6q]`（续29 那批）钉的是**切片口径 / 断点保留 / 不清资产 / GUI 拒绝无
断点**，**没有一条钉「续跑后下游还能看见前面的产物」** —— 判据整条是空的。
修法（续159 已落）：候选主机收敛到 `extdom.own_hosts()`＝内存 ∪ 库（own 口径，`js:`/`osint:` 是
别人的资产面，一个请求都不发），形状与 `jsmine` 的站点回退、`probe` 的端口回退一致；补出的条数
必须打进日志。**新写同类判据一律照 `[8bp]` 那个双向形状**：正面钉候选数，反手把回填退回"只读内存"
必须塌回旧数字，否则等于没加（§6.1）。

**第十五起（续161，本轮自己造的假结论）：变异档根本没落到文件上，"这条断言没区分度"于是是一条假结论。**
做 §6.1 要求的证伪时用 `Path.read_text()` 读进来、拿按「CRLF 形状的锚点」去找 —— 通用换行把 CRLF 归一成了 LF，锚点命中 **0 次**，而 `str.replace` 命中 0 次时**一声不吭**：现场表现是"把 `if status != \"done\"` 改成 `if False` 之后原型全绿"，看着像那条边界断言形同虚设，实际生产码一个字都没变。两处口径：
① **变异一律 `read_bytes()` + 字节锚点**，替换前先确认 `count(old) == 1`，替换后**回读**确认真的改到了；② 每一轮在 `finally` 里还原，并且**还原后再跑一次基线** —— 本轮就是中途一条 `assert count(new) == 1` 写歪（文件里本来就有别的 `return 0`）把脚本打断，仓库被留在"轮数夹取被替成 `return 0`"的变异态里，靠收尾那次 `git diff --numstat` 复核才发现。
推论：**证伪脚本自己也要能被证伪** —— "红/不红"这个结论的有效性等于"变异确实落盘了"这个前提，而后者必须是一条检查过的事实，不是假设。
**第十六起（续162，与第十四起同族：文档替代码说话，这回说的是「有一条你没实现的出路」）**
`install.sh:95` 与 §2 那段（2026-10-08 落定的口令口径）一直写着口令「只从 `CTFSCANNER_KEYS_PASSPHRASE` / `~/.secrets/keys-pass`（0600）/ TTY 取」，仓库外那个 `/opt/tools/ctf/git-cred-helper.py` 确实实现这三档 —— 而**运行期那份 `keystore.unlock()` 只有两档**（参数 / 环境变量 / TTY）。于是本机 `gui.keys_ask_passphrase=false` 的部署每次启动都锁着：`git push` 免交互能用（助手认那个文件），扫描与 GUI 却不认；而三行 `[osint] FOFA 未配置 email/key（config/keys.yaml）` 又把排查方向指到一份**密文存在时永远不会被读**的明文文件上（`load_keys()` 第 2 条口径）。主理人据此问「我记得我是把密钥加密了，它应该也要去解密获取」—— 这句话按文档读完全合理，错在文档与文案，不在提问的人。
两条口径：① 文案里凡写「可以怎样补」，那个「怎样」**必须当场走得通**（本轮把三档实现补齐，并把七处硬写的路径名换成 `keys_hint()` 现取的那句）；② 同一句承诺写在两处文档（安装说明 + 本文件）时，判据要落在**实现那一侧**：`[8bt] ②` 直接断言 `allow_prompt=False` 仍能从文件解锁 —— 这条断言在缺第三档的代码上必红，文档再漂也拦得住（§6.1）。顺带一条实测事实（**带时间戳，会过期**）：本轮动手**之前**那三份密文（现文件 + 两份备份）顶层都只有 `github`，`fofa` 从来没进过密文；同一天 11:15 才把主理人给的 `fofa`/`shodan`/`quake` 合并进去（见 §7 那条本机实况与 CHANGELOG 续162-附）。所以「解不开」与「解开了也没有」是两件事，揉成一句话报就是在骗人（这正是 `keys_hint` 必须分三态的理由）。
**第十七起（续162-附：差点把「没配上」报成「配好了」）**：`re.M` 里的 `^\s*` 会吃掉换行，把空值的段头与下一行粘成一个键，目标键静默消失。
现场：要把主理人给的凭据文件（`fofa:` 段头一行、下面缩进 `fofa_email:` / `fofa_api:`）解析成 dict，
写的是 `re.finditer(r"^\s*([A-Za-z_][\w .\-]*)\s*[:=]\s*(\S.*)$", raw, re.M)`。
`\s*` 包含 `\n`，于是匹配到 `fofa:` 这一行时冒号右边没有非空白字符，引擎就**跨过换行**把
下一行 `fofa_email: '…'` 整个当成 `fofa` 这个键的值吃掉 —— 结果 `fofa_email` / `quake_api` **在结果里根本不存在**，
而 `shodan:`（值直接写在同一行）照常命中。第一次写入因此只带进 shodan 一组，
如果我照那句"段与掩码都打印出来了"就回报「配好了」，FOFA 仍然是空的。
三条口径：① 解析**行式配置**一律**逐行 `match`**（或先 `splitlines()`），别在 MULTILINE 里用 `^\s*`；
② 从"读进来"到"落盘"之间必须有一条**完整性断言**（本轮补的是 `assert "fofa" in overlay and "quake" in overlay`，
   缺任何一组就不许写文件）—— 静默少认键的形状与"文件里本来就没有"一模一样；
③ 落盘后**回读复验**要按**来源逐字段**比（本轮 `github` 两只掩码逐字不变 + 三组新键逐字相同），
   只比"能不能解开"证明不了内容对了（§6.1 同一形）。
**第十八起（续165，**假绿**，由上一段会话留在工作树的改动造出来）：给 `toolmgr.MANUAL` 添名字，`run_bootstrap` 那个 if/elif/**else** 会把**别的工具的命令**打在它名下，而 `[8d]` 一组判据全绿。**
`_manual_row()` 只有 nmap / fscan 两条明写分支，**else 里写死的是 dirmap 的 clone + pip**。本批给 `MANUAL` 加了
`massdns`（puredns 在进程内 exec 的传递依赖）却没加分支 ⇒ `--check` / `--install` 输出 `massdns … git clone …/dirmap`，并因为 `tools/dirmap/dirmap.py` 真在盘上而把这一行标成 **ok**。为什么看着没问题：那一行**有原因、有命令、状态合法**；`[8d]` 那三条（清单不缺项 / `detail` 非空 / `auto∩MANUAL=∅`）判的是形状不是内容 —— **内容说的是别的工具**。同一批还留下第二形：新预检「缺 massdns 就跳过 puredns」让 `[8aq]` 的 `which` 桩（只认 puredns）把整条被测路关掉，那条恰好是**红**的（`puredns 仍在吃整份深字典：[]`）；同形但判据写成「日志里出现过某句」的话就会静默绿。
三条口径：① **给注册表添条目 = 必须同时给每个消费这条注册表的分支添名**，`[8d]` 现在钉「MANUAL 每一行只许提自己、不许提别的 MANUAL 成员」，把 `_manual_row` 退回旧形状它立刻红（已实测：同时踩中「没提自己」与「混进 dirmap」）；
② **兜底分支不许冒充**：通用 else 只能说「见 README 手工安装」，绝不能复用另一个工具的命令与 `found` 判据；
③ **「缺依赖就跳过」这类闸落地时，先把所有把该工具桩成「已装」的夹具过一遍**，并补一条正向判据（缺依赖 ⇒ **根本不起子进程**），否则测的是跳过、绿的是功能。
**第十九起（续166，第十六起同族但更隐蔽：文档教的命令**从来没跑通过**，而门禁全绿）**：`tools/build_fscan.py --wire` / `build_massdns.py --wire` 一律 `ImportError`。
根因不在文案：脚本直跑时 `sys.path[0]` 是**脚本所在目录**（`tools/`），而那里正好有个同名的
`tools/scanner/`（外部工具落点）⇒ `from scanner import toolmgr` 撞到那个**命名空间包**，报
`ImportError: cannot import name 'toolmgr' from 'scanner' (unknown location)`。`--wire` 是全仓唯一会走到这句的分支，而**门禁里没有任何一条真跑过这两个脚本** ⇒ 续165 我刚把
`python tools/build_massdns.py --wire` 当"出路"写进四份文档时，它已经是坏的。
同一批还挖出第二条同族事实：两个脚本都把 `/opt/tools/ctf/{fscan,massdns}-src` 当兜底源码目录 —— 既违反 §0.3（代码里不许出现本机绝对路径），又让"这台机器编得出、换一台编不出"，而默认读项目外目录还违反 §0.2。
三条口径：① **文档里给出的每条命令都要当场跑一次**（不是"看起来对"）—— 本轮起 `[166]⑧` 用**假工具链**（会写出产物的 `go`/`make`/`cc` 脚本）真跑两个入口，验的是接线（产物落点、`--wire` 写的是给定的那份 settings、**跟踪的那份一个字节没动**），不是编译速度；② 变异证伪跟着一起钉：把 `sys.path.insert` 那行摘掉，同一条命令必须红（否则 ⑧ 是空写）；③ 入口脚本的 path 自举与"不许有仓库外绝对路径兜底"都写成**判据**（AST 扫字符串常量 + 自带正反夹具），不写成注释。
**第二十起（续176-附，2026-10-14：拿"进程内轮询状态 + 网络环境"当哨兵 —— 本地门禁全绿、CI 红，同一条断言两个答案）**：`[8m]③` 端到端里 jsmine 的解析门（续171 加）走**真实 DNS**，而 `dnsq._pick_resolvers` 是**进程内轮询**挑 2 台 —— `resolvers.txt` 里 114.114.114.114/115 在部分网络不可达（rcode=-1），连续两次挑中它俩 ⇒ `_exchange` 全失败 ⇒ `reason=timeout` ⇒ "无结论放行" ⇒ `sub.mystery113.test` 被放过；CI 上挑中的是活解析器 ⇒ `nxdomain` ⇒ 被挡 ⇒ 红。为什么难定位：本地跑十次可能十次都"过"，**换一个网络就红** —— 判据的结论取决于进程状态与外部环境，与代码对错无关；而 fail-fast 之下 CI 一次只暴露一个失败，容易被误读成"别的地方也坏了"。同批还有第二形同族：`[167]⑥` 的夹具写死 `tools/browser/chrome`，而 `tools/browser/` 是 gitignore 的运行时组件 ⇒ 干净克隆/CI 上必然不存在。三条口径：① **端到端断言里凡走真实 DNS / 文件系统 / 网络的，一律桩死**，桩的返回值要贴合被测分支的**意图**（这里 mystery 的意图就是"注册域存在、自己暂时解析不到"，与 ② 的 fake 一致，不是随手 return 个空三元组）；② **夹具不许引用 gitignore 的路径**，判据要的性质（"相对配置值按项目根折算"）与文件是哪个无关，用仓库内必然存在的文件；③ 修这类 flaky 的验收是**本地绿 + CI 绿两边都拿**，只拿本地绿就等于没修（本例本地门禁在修复前也一直是"绿"的）。
14. **`SELECT DISTINCT … ORDER BY <表达式>` 在 SQLite 里算不出那个表达式**（续154，2026-10-11）。
    现象：拓展域名采集用 `SELECT DISTINCT domain FROM subdomains ORDER BY <真实 IP 档位 CASE>`，
    档位本该是 `real=0 / multi=1 / cdn=2 / 未解析=3`，实测 `app.ngrok.io`（单 IP、非 CDN）被排到
    multi 档之后。SQLite 对 DISTINCT 的 ORDER BY 表达式求值用的是"所选那一行"，与逐行分档不一致。
    为什么看着像代码坏了：判据本身没错，`cdn.ip_kind` 也没错，只有那条 SQL 的形状错 —— 而它的输出
    是"顺序有点怪"，最容易被人当成"数据本来就这样"。**处理**：需要按表达式排序去重时在 Python 里
    按产地判据算档位再排序（本轮就是这么改的），或按窗口函数（`page_assets(dedupe_domain=True)`）
    那一套走。**教训**：同一判据在 SQL 与 Python 各写一份，连"同不同源"都要靠实测，能不收进 SQL
    就别收（§5.14）。
**第二十起（续179，本轮自己造的假红）：页面区块在空态整块不渲染，断言把「页面上没有」当「渲染成 0」。**
策略页值黑名单计数行包在 `{% if sb %}` 里——名单为空时整行不渲染。断言
`re.search(r"值黑名单 (\d+) 条", …)` 拿到 None 后 `.group(1)` 当场 AttributeError，wire10 红在这里。
修法不是放宽成「必须渲染」，而是空态兼容（`int(m.group(1)) if m else 0`），正向路径仍钉死
（拉黑一条后必须出现 `N0+1`）。同族坑（同轮撞上）：共享 smoke 库里「页面上恰好只有我的数据」是错觉——
`/extdomains` 来源条数必须带 `?task=` 过滤、策略页计数用 `N0+1` 动态断言，
否则别的组留下的夹具让计数静默漂移；以及 bytes 补丁的多行锚点必须先把 `\n` 归一到区域 EOL
再 count（首跑 LF 形态在 CRLF 区域 count=0，长得像「代码坏了」的假红）。

## 7. 已知局限 / 坑（真实存在，不是 TODO 清单）

- **`massdns` 仍然要本机 gcc/make（续166）**：C 工具链没有"便携且带官方校验和"的产物 ⇒ `./install.sh --full` 只能把**源码**取进仓库（`tools/massdns-src/`，钉住摘要），编不了就如实报，`MANUAL` 那一行照旧点名它。别把"源码已就位"读成"massdns 已就位"——判据是 `_markers_ok` 认的 `tools/scanner/massdns`。
- **`fscan` 编译期必须联网取 Go 模块（续166 实测：GOMODCACHE 192 MB、GOCACHE 239 MB）**：模块摘要由 fscan 自带的 `go.sum` 校验（这一层我们不插手），但**离线机器上这一步必然失败**；本框架不做模块镜像、也不预打包 vendor 目录。便携 Go 归档本体 70,590,635 B、解包 283 MB。
- **`GOTELEMETRY=off` 挡不住 Go 的本地遥测计数（续166 实测）**：给了它与不给它，`~/.config/go/telemetry/local/*.count` 都照样建 ⇒ 真正管事的是把**配置目录本身**指走：Linux 靠 `XDG_CONFIG_HOME`，而 macOS（`~/Library/Application Support`）与 Windows（`%AppData%`）**都不认 XDG** ⇒ `toolmgr.go_env()` 连 `HOME`/`USERPROFILE`+`APPDATA`+`LOCALAPPDATA` 一起指进 `.cache/gohome`。代价：子进程看不到用户的 `~/.gitconfig`（本仓模块全走公共 proxy，实测不影响）。
- **仓库内 Chrome 不等于"裸机能截图"（续167）**：`tools/browser/chrome` 运行时要系统的 libnss3 / libgbm / libatk 等共享库，那是"装进系统"的东西、本框架不代装 ⇒ 取来只买到"在有这些库的机器上省一步"；缺库时 `screenshot.capture()` 照旧返回失败并给原因（**不假绿**）。本机实测可用（PNG 10,576 B / 0.6 s），但**没有在裸机上验过**。同轮另记一条：`screenshot.browser` 里写相对路径曾被按**进程 CWD** 判存在性（§5.13 那个坑的第四次），续167 起按项目根折算并返回绝对路径。
- **`--platform` 买的是"看清那个平台该装哪些"，不是"给那个平台备货"（续168）**：三条边界。① 产物**仍只下本平台那一份**（主理人选定），要真在另一台机器上装，就在那台上跑同一条命令；② 预览清单里每一行的「已装」吃的是**本机文件系统**，所以「按 windows/amd64 预览」时本机装着的 `puredns` 会显示 `ok` 而不是「不适用」—— 抬头那句声明就是为这一格写的，看到"预览"两行的人不许把那列当 Windows 的结论；③ **值不认识时不静默**：`platform_override()` 给 `(None, 原因)`、抬头照本机探测值并把那句原因印出来。同一轮把「官方没发该平台产物」与「本框架只核过部分平台」从**失败**改判成**不适用**（`install()` 的 `not_applicable` / `stack_applicable()`），Windows 上 `./install.sh` 从此 rc=0；而**真 Windows 仍是一台都没跑过** —— 那是算出来的表达，不是实测结论（待办照旧挂着）。
- **拓展域名的「置信度」是启发式，不是归属证明（续169）**：主理人点单要的是「`abdc.com` 索引到
  `abcd.org` 那多半是我们的」，判据落在**注册域主标签**的编辑距离与相似度比值上（差 ≤2 步且比值
  ≥0.70 判「高」）。它一定有误判：`abnd.com` 与 `abcd.org` 判高，可那完全可能是两个人各自注册的
  域名。买到的不是"判据正确"，而是三件一起成立的东西——**默认不扩**（`subdomain.ext_depth: 1`）、
  **阈值默认高**、**看错了有一键黑名单**（`POST /api/blacklist/add`，拓展域名页那颗按钮）。
  两条刻意没越过的线：① 相似域名**不写进 `subdomains` 的归属行**（`promote_owned` 的语义是
  "这是本项目自己的子域"，写进去就是造假，还会顺着 `own_hosts` 被 portscan/probe 当自家资产打）；
  ② 第三方清单 / CDN / 黑名单命中**无论哪一档都不自动扫**（闸赢过分数，`[169]③` 双向夹具钉着）。
  仍未验：IDN / punycode 的主标签比对（中文域名换 TLD 那一形状过不过得了 0.70 没人测过）；
  徽章每行按任务取一次对照集（页内按 `task_id` 去重，每任务 2 条 SQL），**没有**缓存层。
- **本机 `tools.fscan` 仍指向仓库外的目录联接（续45 主理人点单的形状，续166 刻意没动）**：`--full` 编出的产物在 `tools/scanner/fscan`（实测 28,229,792 B，用仓库内 Go 1.27.2 编），把配置改指它只是一行的事，但那是当年选定的口径 ⇒ 等主理人点头再改。`tools.massdns` 本轮**已**写成 `tools/scanner/massdns`（那是续165 新加的键，没有历史口径）。

- **碰库的 CLI 入口必须自己 `db.init_db()`，而 `users.count_users()` 吞错让这种洞看起来不存在**（续163，干净克隆实测）：`cli/run_users.py` 是全仓唯一一个碰库却没建表的入口（`client.py` / `run_node.py` / `migrate.py` / `login_guard.__main__` 都调了），于是新机器上 `CTFSCANNER_ADMIN_PASSWORD=… cli/run_users.py --create-admin` 崩 `no such table: users`。为什么长期没被发现：`--status` 读的 `count_users()` **刻意吞 `OperationalError` 返 0**（表没建＝0 个账号，正是它该有的说法），而 `--create-admin` 走的 `get_by_name()` 不吞 ⇒ 只有写路径崩。**最糟的是 `--status` 与登录页 0 账号时的指路语把人指到这条跑不通的命令上** —— 与 §6.2 第十六起同族：文案里写「可以这样补」，那个「这样」必须当场走得通。回归 `[8v] ⑦`（全新库路径子进程真跑 + 一条「入口必须建表」的源码判据，否则它会退化成「这台机器恰好有库才绿」）。
- **`dnsq` 只解码 CNAME / A / AAAA 的 rdata，其余类型一律给空串**（续163 实测）：`_parse_message` 里 `else: records.append((owner, rtype, ""))` 是有意省事的形状，代价是 **PTR / NS / MX / SOA 拿不到任何名称** —— 实测 1.1.1.1 系统解析器能给出 `one.one.one.one`，`dnsq.query('1.1.1.1.in-addr.arpa', 'PTR')` 给 `[]`。这同时解释了两件事：① 续113 的 `zone_state()` 为什么**只能看 rcode、不能看「NS 记录是否非空」**（那时以为是解析器问题，其实是这里没解码）；② 「我们自己用 DNS 做原生 IP 反查」目前做不到，要先补这一段。补的时候别顺手把`zone_state` 改成看记录非空 —— 那条判据的正确性依赖「未知服务器 / 被防火墙吃掉也返回空」，改之前先想清楚 fail-open 那一半。
- **`portscan.exclude_scanned` 只能排除「库里已记录的开放端口」**（续163 实测）：三条引擎路（fscan / nmap / 内置）都吃收窄后的 `target_ports`，但 `ports` 表里**只有开放端口** —— 全端口 65535 里 99.9% 是关闭端口、不入库，所以 #17/#18 两份日志里那条「已扫过 N 个端口，本次只扫剩余 M 个」**一次都没出现** ⇒ 断点续跑重进 portscan 时几乎等于重扫（耗时与目标侧压力都翻倍，而且这是「省重复」的开关，读日志的人会以为已经省了）。要真省得记 per-host 的「已扫范围 / 已跑完整轮」标记，而不是只记开放端口。
- **缺中文字体＝截图取证与中文报告静默作废（续103 本机实测）**：无头浏览器缺 CJK 字体时**不报错**、
  照样产出合法 PNG，只是图里每个汉字都是豆腐块；而 `[7z]` 只验"有没有出图、字节数对不对"，所以它
  **一直是绿的**。这台 Ubuntu 上 `fc-list :lang=zh` 命中 **0**（只有 DejaVu / Liberation）才发现。
  已按"扫描依赖必须进安装"处理：`run_bootstrap.SYSTEM_PACKAGES` 加入 `fonts-noto-cjk`，探测走
  `has_cjk_font()`（**零网络、零子进程** —— 只扫字体目录里的文件名，见下一条），`--bootstrap` 会点名。三条边界：
  ① 没有对等包的管理器（snap / brew / winget）**不生成命令**，但 `render()` **仍必须打印这一行**
  （旧代码只打印"有 argv 的行"，缺口会被整行吞掉 —— 已改，回归 `[8d]`）；
  ② **Windows 直接算"有"**（微软雅黑/宋体随系统自带，那边既无这些目录也无 fontconfig，报缺只是噪声）；
  ③ **不写进 Dockerfile**：镜像口径是"零多余依赖"，容器里本就没有浏览器（见 `docs/docker.md`）。
  ④ 判据是**文件名启发式**，不是 fontconfig 查询 —— 原因是本文件的源码红线「`run_bootstrap.py` 里每一处
     `subprocess.run` 都必须落在允许的四类意图内」（回归 `[8d]`）。第一版确实写的 `fc-list`，**就是被这条红线
     当场抓红的**；为一条只读探测开豁免不值当，改成扫目录。代价：字体装了却被 fontconfig 认不出时仍报"有"，
     所以它只用于清单点名，不参与任何扫描决策。
- **`main > section` 这类「直接子元素」判据在嵌套布局里会整条失效（续103）**：`style.css` 的
  「宽表在面板内滚动」原本写 `main > section{overflow-x:auto}`，而 dashboard 的两张表在
  `.grid2 > section` 里 —— 不是 `main` 的直接子元素，规则**一条都没作用到**，430px 下表格直接撑大文档
  （实测 `documentElement.scrollWidth` 438 > 430；探针里那两张表的"最近滚动容器祖先"是 `NONE`）。
  判据改成 `main section`（后代）。顺带记一条 CSS 事实：**`overflow-x != visible` 的元素，
  `min-width:auto` 的自动最小尺寸算 0** —— 所以先加的 `.grid2 > * { min-width:0 }` 在真浏览器里
  "改与不改同形"，已删（不留死代码）。回归 `tests/browser_e2e.py [9]`：三页 430px 无溢出 +
  反向证伪（把判据退回 `main > section` 必须重新溢出 71px）。
- **颜色守卫曾只认 `#hex`，函数式颜色是盲区（续103）**：`.lb-overlay{background:rgba(0,0,0,.82)}`
  就在"主题块外 0 处裸值"的绿灯下躺了很久 —— **绿灯不等于有判据**。现在守卫同时认
  `rgb()/rgba()/hsl()/hsla()/hwb()`，灯箱两处收进 `:root` 的 `--lb-bg` / `--lb-shadow`。
  **仍刻意不认**具名色与 `transparent`（误报面太大，要收那一档得先想清判据）。
  回归 `tests/smoke.py [6n-附]`（含"把守卫打回只查 hex，三条合成样本必须全不报"的证伪）。


- **dirmap 的 Python 3.12+ / `-e` 两条限制已解（续217）**：① 上游 `lib/core/option.py` 的
  `import imp` 是**未使用导入**（v1.1 与 master 全仓都没有 `imp.` 调用）；`tools/dirmap_compat/imp.py`
  空垫片由 `dirscan._dirmap_env()` 放进子进程 `PYTHONPATH` 最前面，实测 v1.1 在 Python 3.14 上
  `python dirmap.py -h` rc=0。② 上游没有 `-e`：`_dirmap_accepts_lang_arg()` 读它自己的参数定义源码，
  有就按技术栈分组、没有就只跑一轮（`lang_arg=False`，按它的 `dirmap.conf`），两种形态共用
  `_dirmap_argv()` 与同一段产物解析 —— 不再"装了却不用"，也不再逐组白跑。旧快照仍走分组路径。
  门禁 `[5p-附]` 双向钉住；`tests/smoke.py` 全局把 `tools.dirmap.script` 指到不存在的路径，
  第三方工具不影响门禁。**没有装便携 CPython**：`tools/python311/` 有就优先用（`_dirmap_python()`），
  没有也不影响。依赖由 `tools/setup_dirmap.py --install` 显式装（缺了只回退内置并说清补法）。
- **任何"全树扫描"都必须排除第三方落点 `tools/dirmap/` 与 `tools/fscan/`（续102）**：那两处由
  `.gitignore` 排除、内容随机器而变，且 dirmap 里**有 Python 2 的上游 example**
  （`thirdlib/IPy/example/confbuilder.py` 的 `print "..."`）—— 拿 `ast.parse` / `compileall`
  去扫全仓就会**崩在第三方文件上**（本轮 `[8d] ⑩` 正是在装了 dirmap 的机器上红的第一次）。
  口径与 `[5b]` 的 `_SKIP_DIRS` 一致；`.dockerignore` 也排掉了这两处，所以容器里一直是绿的
  （**"容器绿、本机红"就是这么来的**）。
- **这台远端 Linux 的解释器事实（续102，写下来省得再查）**：`/usr/bin/python` →
  `/usr/local/python3/bin/python3.10`（3.10.9，且 gevent / lxml / progressbar 已装），
  `/usr/bin/python3` → 3.14；仓库依赖装在 `.venv`（3.14）。所以 `dirmap` 反倒能在 3.10 下启动，
  而框架自己跑在 3.14 上 —— `pick_python("python")` 会选中 3.10 那个。fscan 则用 apt 的
  Go 1.26 自编译成功（27.8 MB，产物名 `fscan` 无 `.exe`，靠 `which()` 的后缀容错命中配置里写的
  `tools/fscan/fscan.exe`）。
- **dirmap 的依赖到底从哪加载（续106 实测，别再去找 `dirmap-deps`）**：`tools.dirmap.python` 配的是
  `python` → `pick_python` 命中 `/usr/bin/python`（3.10.9），而 gevent / lxml / progressbar 实测来自
  **`~/.local/lib/python3.10/site-packages`**（用户级 pip 装的），`sys.path` 里**没有** `dirmap-deps`。
  续102 为装依赖在**仓库同级目录**造的两个东西（33 MB 的依赖目录 + 一个空壳 venv）因此**从未被引用**
  —— 仓库内 grep 零命中，挪开后 dirmap 照旧 `-h` 正常、`cli --check` 仍报 `dirmap OK`，已删除。
  要复现依赖来源：`/usr/bin/python -c "import gevent; print(gevent.__file__)"`。

- **`utils.which()` 的返回值形状**随进程 CWD 变**（续101，会咬到"输出只出现相对路径"这条红线）**：
  配置写 `tools/scanner/httpx` 这类相对值时，它先 `shutil.which(相对值)`（按**进程 CWD** 找，命中就
  原样返回那个相对串），找不到才折算项目根走 `_probe(str(_BASE_DIR / alt))` —— 而后者返回的是
  `<项目根>/tools/scanner/httpx`。于是"在仓库里跑"与"从仓库外跑"给出两种形状。凡把工具路径印给用户
  的地方（CLI `--check`、`run_bootstrap.py` 的清单、GUI「外部工具」页）都必须再过一次
  `utils.rel_display()`：否则 §0 硬规矩 3「只出现相对路径」会随 CWD 漂，`smoke [8d] ⑦`
  （"自举输出不得含项目根"）也会在装了 dirmap / fscan 的 Windows 机器上莫名其妙地红。

- **snap 版浏览器在本项目里等于没装（续100 实测 Ubuntu 26.04）**：apt 源里已经没有 deb 版
  chromium，`chromium-browser` 只是指向 snap 的过渡壳。而 snap 的 confinement + 私有 /tmp 让
  它**写不到项目路径、也写不到我们看得见的 /tmp**：`--screenshot` 会汇报"已写 N 字节"但文件
  在 snap 命名空间里（外面看不见），输出到 `logs/task_*/` 直接 `No such file or directory`，
  `browser_e2e` 的 CDP 启动即退出 —— 只有 `$HOME` 下非隐藏路径可写。**装上了却不干活，比没装
  更难查**。`run_bootstrap.py::snap_confined()` 因此把这种浏览器报成 warn 并给出换非沙箱版的
  命令；本机改用 Google Chrome .deb 后 `[7x]`/`[7z]` 才第一次在 Linux 上真跑通。

- **`utils.pool_run()` 吞异常但**必须说出来**（续96 登记为"未改"，续115 收口）**：语义是「单个任务异常不影响整体」，
  旧实现把异常吞成 `None` 且日志一个字都不留 —— 阶段里一个真故障（实测：`fingerprint.identify()` 在 Python 3.14
  抛 `PatternError`）只表现成「存活站点 0 个」这种**静默降级**，排查方向被整个带偏。
  现在的形状：**返回值契约一字未改**（仍只返回非 `None` 的结果，所以各阶段"0 条按降级处理"的判定逻辑完全不受影响），
  新增的只有"说出来"：有异常被吞 ⇒ 一行 WARNING `N/M 个异常被跳过（首个 <类型>: <消息>）+ 是哪一批（`label=`）
  + 别把「0 条」当成「确实没有」`；`StopRequested`（点停止 / 预算耗尽）**单独计数按 info**，否则每次正常停止
  都会刷一片故障；调用方没给 `logger=` 时走进程级兜底 logger（`scanner.pool` → 控制台），
  所以**没有任何一条路径还是静默的**。
  ⚠️ 真正会退化的是**接线**：`pool_run` 新加参数不影响旧调用方，于是"新增一个出口忘了传 logger/label"
  不会报错，只会重新变成"日志里没有线索" —— 回归 `[8q] ⑤` 用 AST 扫 `scanner/` 与 `gui/` 里**每一个**
  `pool_run(...)` 调用点，少传就判红。排查同类问题的最短路径依旧是：在**当前解释器**上直接调那个被吞掉的函数，
  别只看阶段日志。
- **凭据加密的边界（续98 立、续162 补齐第三档并按现状改写）**：`scanner/keystore.py` 的解锁来源是四档 —— 显式参数 > `CTFSCANNER_KEYS_PASSPHRASE` > `~/.secrets/keys-pass` > TTY 提问。第三档是 2026-10-08 就写进 `install.sh` 与 §2 的**同机兜底**，此前只有仓库外的 git 助手实现、运行期没实现 ⇒ `gui.keys_ask_passphrase=false` 的部署每次启动都锁着（现象见 §6.2 第十六起）。三条边界：① `allow_prompt=false` 关的是**提问**、不是解锁，环境变量与该文件照旧生效；② 该文件的守卫必须是**正好 0600 + 属主是自己 + 非空** —— 写成 `& 0o077 == 0`（放过 0644）就把这一档买到的「权限一被改坏就自动失效」卖掉了；③ 环境变量给错时**照实失败，不偷偷回落到文件**（静默换档会让「这台机器到底靠哪句口令解开的」不可追溯，而 `serve()` 现在会把来源打成一行）。原话「口令绝不允许存在机器上」是续98 当时的口径，续136 用户已选定接受同机兜底这一档（只要值不落明文），本条按现状改写。
  ⚠️ 诚实边界照旧：解密器与密文同机 ⇒ 这**不是**更强的加密，能读 `~/.secrets/keys-pass` 的人就能解开 `keys.enc.yaml`；要收回就删掉那个文件，回到每次给一次口令（§2）。另记一条本机实况（别当成通用事实，且它会过期）：截至 2026-10-12 续162-附，本机密文里有 `fofa`(email+key)、`shodan`、`quake`、`github`(`token` 只读 PAT + `push_token` 推送令牌)，`gitlab` 仍没有。补进去的那一步是**合并而不是覆盖**（旧密文先备份到 `~/.secrets/keys.enc.yaml.bak-<时间>`，0600），`github` 两只的掩码逐字复验过没动。
- **加密本身的两条底线没变**（续98，`scanner/keystore.py`）：口令派生密钥
  （PBKDF2-HMAC-SHA256 60 万次）+ AES-256-GCM 认证加密，**改一个 bit 就解不开** ——
  所以"文件被人动过"与"口令错"报的是同一句话，不假装能区分；算法全走 `cryptography`，
  不自研任何原语。三条仍然成立的边界：① 把口令写进**仓库、`settings.yaml`、systemd unit、
  `.env` 或任何被跟踪文件**，这套加密立刻退化成混淆（能读那个文件的人就能解密密文）；
  ② 解锁后明文在进程内存里，**不防内存 dump**；③ 有密文但未解锁时 `load_keys()` 返回 `{}`
  且**绝不回落到明文文件** —— 否则"绕过口令就能用凭据"，加密形同虚设。
  旧条目里「本模块刻意不提供记住口令/免输入、无人值守只接受环境变量」那半句**已由续162 改掉**
  （现在多一档同机口令文件，见上一条），所以本条不再重复那句承诺。回归 `[8f]` 与 `[8bt]`。
- **puredns 的产物摘要是本框架自己核、自己钉的（续164）**：官方 release **不发 checksums**，
  而"必须有官方校验和才落盘"会让它在自动层里**永远**装不上（`./install.sh` 因此每台新机器都 rc=1）。
  现在 `TOOLS["puredns"]` 里写死了 `pin_version: v2.1.1` 与那一版四件产物的 SHA256，摘要产地从
  "release 里的文件"换成"本文件里那串十六进制"，**校验强度一个字没降**：字节不符拒装、
  `--allow-unverified` 也越不过"不符"（它只管"没有校验依据"），tag 不符连下载都不发起。
  三条连带事实：① 它**不跟 latest**，所以上游发新版不会改变本机装到的是什么，也不会让安装脚本变红；
  ② `check_updates` 对钉了版本的工具**不许**报 `has_update=True`（报了就是诱导人去按「更新」，
  而那一次必然走到 tag 拒装）；③ Windows 仍然装不上 —— 官方压根没发 Windows 产物，
  钉摘要变不出一个包来，页面上照实报"未提供当前平台产物"。
  ⚠️ 改这块时别在 `scanner/toolmgr.py` 里 `import inspect` —— 本模块自己就有一个 `inspect()` 函数，
  导入会被它**整名遮蔽**（实测 `AttributeError: 'function' object has no attribute 'signature'`），
  `[8bu]` 用 AST 把这条钉住了。
- **截图「候补重试」的三条边界（续161 立、续164 随包打开，设计如此不是 bug）**：① **三档分开**：代码 `DEFAULTS` 是 `0`＝关（`[8bs]` ③a 钉住"不偷改出厂行为"），**随包 `config/settings.yaml` 写的是 `1`**（续164 主理人点单"空闲再重试"），合并后的生效值才是 1；要退回"一个字都不排"就在策略页填 0。打开后也只排**只跑 `screenshot` 一个阶段**的追加运行，只打 `append_targets` 里那批 URL；默认串行队列意味着它就排在别的任务后面"空闲再试"，所以**没有**"每轮冷却 N 秒"那个键 —— 加一个只会 `sleep` 住一个 worker 换一句措辞。② 每一轮仍受 `screenshot.max_sites` 单轮上限约束：超出上限的按站点 id 排在下一轮，而上一轮仍失败的那几条会一直挡在前面（要按"最久没试优先"轮转得单独一轮）。③ 重试成功**不清**旧的 `shot_error`（`set_site_shots` 与 `set_site_shot_errors` 各写一列），所以站点行会同时留着 `shot` 和上一次的失败文本：页面靠 `shot` 优先显示、候选靠 `shot=''` 排除，两个数都不虚，但那一格文案看着怪。
- **站点截图的 `--ignore-certificate-errors` 不能省（2026-09-28 续64）**：CTF / 内网授权目标多为
  自签 / 过期 / 私有 CA 证书（与 `certs.py` 刻意 `CERT_NONE` 同一现实），无头浏览器不加这个开关
  会以 `net::ERR_CERT_AUTHORITY_INVALID` 拒绝加载、`--screenshot` 一个字节都不产出 —— 即**自签
  HTTPS 站点永远截不到图**。开关集中写在 `scanner/screenshot.py` 的模块级 `_FLAGS`（附"为什么
  不能省"注释）。它只影响**本机渲染**，不改变对目标的请求语义（仍是只读 GET），不越"非破坏性"
  红线。回归钉在 `tests/smoke.py [7z]`（含变异证伪 + 真夹具自签 HTTPS 端到端）。

- **自检的 `screenshot/shot` 向量恒为 N-A（2026-09-28 续64）**：自检截图目标是夹具**主机名**
  `https://www.devfixture.test:<port>/`，而自检的 DNS 覆盖只在**本进程**生效（`socket.getaddrinfo`
  打桩），**浏览器子进程解析不了** → NXDOMAIN（与"subfinder/httpx/nmap 不认 DNS 覆盖"同类，见
  `scanner/devflow.py` 顶部）。**截图功能的端到端覆盖在 `tests/smoke.py [7z]`**（用 `127.0.0.1`
  形态的夹具 URL 调生产函数 `capture()`）。要让自检也真跑到，得让自检的截图目标对浏览器可达
  （改成 IP 形态）—— 会牵动 probe/dirscan/vulnscan 的站点数，**属独立一轮，未做**。


- **CI 上一次性 `--headless=old --screenshot` 模式会卡死 30s 超时（2026-09-29 续75）**：续74 修对
  `No usable sandbox` 后 CI 仍红 —— `[7z](b)` 端到端自签 HTTPS 截图 `capture()` 超时。根因是
  **环境限制**而非产品缺陷：同一台 `ubuntu-latest` 上 google-chrome 存在、走 CDP 的 `browser_e2e.py`
  （`[7x]`）完整跑通 35 条断言，但 `capture()` 的一次性 `--screenshot` 模式在该容器里挂死 30s
  （流水线截图阶段对 `http://127.0.0.1:8765/` 同样软失败 `截图失败：timeout`）。
  因此 `[7z](b)` 放宽降级口径：浏览器没截出来（无浏览器 / 容器里 `--screenshot` 超时）就**跳过**
  （同流水线截图阶段、`[7x]` 口径），保留「`capture()` 返回 True 则钉 png 非空」的回归检查；
  「无视证书」仍由 `[7z](a)` 行为级断言 + 变异证伪钉死 `--ignore-certificate-errors` 在 argv。

- **XSS 上下文分析（2026-09-23 续18）把"反射回显"拆成 8 种上下文并分级**：
  `<script>` 内 JS 字符串 / JS 代码、无引号属性、标签名位置 → **high**（可直接逃逸或执行）；
  双/单引号属性 → medium（需先闭合引号）；HTML 文本节点 → medium（**证据里写明"需 `<` 未被转义"**）；
  HTML 注释内 → **降级为 low**（要先闭合 `-->`，多数场景不可利用；默认门槛 medium 下不产出，
  把 `checks.min_severity` 调到 low 才看得到）。
  判定靠两条探针：① 原 payload 是否**原样**回显；② 上下文探针（标记串 + `"'<>`）看哪些定界符
  **活着回来**（引号活着＝属性/JS 串可逃逸，尖括号活着＝文本节点能插标签）。
  **全部被转义的回显一律不报** —— 那是旧逻辑最大的误报源。
  `poc_id` 仍是 `a03-xss-reflect`（去重键 `(target, poc_id)` 不变），只是级别与证据随上下文变。
- **盲注只做布尔型，明确不做延时型**：`SLEEP()` / `BENCHMARK()` / `WAITFOR DELAY` / `pg_sleep()`
  会挂住目标数据库的连接线程（并发一上去就是事实上的 DoS，与"非破坏性"红线冲突），
  且跨公网抖动经常盖过几秒的差值。`a03-sqli-blind` 走"恒真 vs 恒假"差分（比状态码与长度），
  并**再发一次恒真做稳定性复验** —— 页面自带随机数/时间戳时恒真自己都会抖，不复验就是误报。
  **预算 34 = 2 形态 × 5 参数 × 3 发（基础）+ 4 发复验余量**（续143：复验只在"已经出现候选"时
  才付，每形态最多一个候选 × 2 发；**无信号时恰好 30 发**，有断言钉住这条）。循环仍是**形态外层、
  参数内层**，预算优先保证 5 个候选参数**都被覆盖**（参数外层时第一个参数就吃掉大半预算，
  加上 `_ordered()` 打乱顺序，等于"每次随机只测到前几个参数"—— 这个坑本轮踩过并修掉）。
  **判据是六道门，全过才报**（①②③④⑤ 续143；⑥ 续146-附4）：① 恒真/恒假差异显著；
  ② 恒真自身可复现；③ **任何一发都不是限流/过载类状态码**（`_SQLI_INCONCLUSIVE_STATUS`：
  408/429/5xx/520-524/598/599 —— 那发 429 是**我们自己连发三发**打出来的，旧判据
  "状态码变了＝最强信号"把它读成了注入）；④ **恒假也要复现**，且这一发是**交换顺序**后采的
  （先恒假再恒真 —— 差异必须跟着 payload 走，不能跟着"这是第几发"走）；⑤ 两次采样的
  **长度差方向一致**（`_len_sign`：真布尔盲注是某一侧稳定地多/少一块内容）；
  ⑥ **两侧都必须是内容页**（`_SQLI_CONTENT_STATUS` ＝ 2xx/3xx，判据 `_off_content()`）。
  门⑥ 是主理人第二轮追问追出来的：门③ 挡"这一发不可信"，**挡不到两侧都稳定回 404** 那一类 ——
  库里五台不同主机 `恒真 404/1486B ／ 恒假 404/1084B`，长度差**恒为 402B**，而两种 payload
  **本身等长**（`1 AND 1=1` / `1 AND 1=2`）⇒ 等长的输入不可能让"查询结果"多出 402 字节，
  差的是同一张 404 模板把请求路径印回正文。要命的是 ①②④⑤ 对这种形状**全部放行**
  （稳定、可复现、方向一致），所以旧实现照报 high。门⑥ 是纯计算，一次请求都不许多花
  （`[8ay]④` 钉住"全 404 时仍恰好 2 形态 × 5 参数 × 3 发"）。
  没过门的量**必须说出来**（`_note_skips`：几个参数、各自为什么）—— 否则"这站没洞"与
  "有候选但不可判定"在日志里长一个样，人只会读成前者（与续126「跳过的量必须可见」同一口径）。
  ⚠ 别再加"交换顺序后差异是否仍显著"那道门：它在 ①②④ 都成立时**逻辑上恒真**，写了就是死代码。
  **已知覆盖缺口**：刻意放弃 `)` 与 `"` 两种上下文形态。命中必须给出**对比数字**（两次的状态码与长度）
  **和 5 发的数据包**（`vulns.packets`，续143）：请求行、状态/长度、关键响应头、正文指纹
  （md5 + 前 160 字）—— **不放整份正文**（页面与报告会被撑爆），**不放 Cookie/Authorization
  的值**（凭据红线；`Set-Cookie` 只写"有"）。用户原话就是"数据包都没有"。
  ⚠ **但"这一类结论不记数据包"要页面自己说出来**（续146-附4）：`{% if v.packets %}` 在空值时
  整块不出现 ⇒ 续143 之前产的那批旧行、以及其余内置检查的行，全都读成"这工具从来不给我证据"。
  现在由 `gui/app.py::NO_PACKETS_HINT` 这一份产地补一句实话，措辞只说"目前只有布尔盲注与
  JS 疑似凭据两类会记录数据包"，**不猜这一行是哪一版产的**（§5.19：只说数据里看得见的事实）。
  空标题那一格同理走 `NO_TITLE_HINT`（原因 + 出路）。
- **A10 SSRF 受控回连只在"目标能回访扫描机"时有效**：本机监听（`127.0.0.1`，端口 0 由系统分配）
  在扫描机位于 NAT 后 / 云主机没有公网 IP / 目标出网被出口防火墙拦掉时**一条回连都收不到**
  —— 这是**环境限制，不是缺陷**。填了 `ssrf.callback_base`（外部 OOB 服务）时本模块
  **读不到那侧的命中**，因此只注入、把 token 写进任务日志、**不伪造命中**（宁可不报）。
  **刻意不做**：不打内网地址（`127.0.0.1:8080` / `169.254.169.254` 那类属于利用，越线）、
  **不提交页面表单**（表单可能是写操作，所以表单只被用来取**字段名**，注入一律走 GET）、
  不做延时判定。监听端口用完即关（`finally` 里 `close()`）。
- **crt.sh 的三个"看起来很像"的能力别混**（`ctlog` / `passive` / `certs` / FOFA `cert=`）：
  `scanner/ctlog.py` 查公开 **CT 日志**，产出**证书维度**记录（签发者/有效期/序列号/涉及域名/
  CT 条目数，写进 `certs` 表且 `source='ct'`）；`scanner/passive.py` 的 crt.sh 只取主机名做
  **子域名收集**；`scanner/certs.py` 是对目标做**真实 TLS 握手**取线上正在用的证书；
  FOFA 的 `cert="domain"` 是拿证书去反查**共用它的其它资产**（不产出证书字段）。
  同一个域名在 CT 里往往有几十张历史证书，**CT 记录是线索与资产面补充，不等于"目标现在用的证书"**，
  所以「SSL 证书」页签与报告都有**来源列**区分。
  crt.sh 是公共免费服务：返回 HTML 限流页 / 超时 / 502 都是常态，所有失败只记一行日志继续跑。
- **Shodan / Quake 反查与 FOFA 是同构的三份代码**（`scanner/shodan.py` / `quake.py` / `fofa.py`），
  刻意**不抽公共基类**：查询语法、鉴权方式（query 串 / X-QuakeToken 头 / qbase64）、响应结构与
  配额模型各不相同，抽象只会把差异塞进一堆分支。三家共用同一个 mmh3 键（`scanner/mmh3.py`），
  `osint` 阶段内 **favicon 哈希按 (max_sites, workers) 缓存**，避免每家各拉一遍。
- POC 引擎是** nuclei 兼容子集**：支持 `http:`/`requests:`、`payloads`（list / dict + `attack`）、
  `variables` + 内置变量、`path` 列表、`redirects`、匹配器 `status/word/regex/size/dsl` + `condition`/`negative`/
  `case-insensitive` + `part: body|header|all`、`extractors`（regex/kval/dsl）；**`raw` / `flow`（布尔子集）/
  `workflows`（子模板编排）自 2026-09-23 续17 起为子集支持**，**`matchers`/`extractors` 里的 `dsl`
  自 2026-09-25 续37 起为安全子集支持**（`scanner/pocs/dsl.py`，白名单封闭 + 不用 `eval`）。
  **workflow 条件编排自 2026-09-25 续38 起支持**（语义对齐 nuclei 源码，不自己发明）：`template:`
  文件**或目录**、`tags:`（OR 选择，候选集 = 注册表启用 + 级别门控；与 `template` 同写时 `tags` 优先）、
  `subtemplates:`（**父步骤命中才跑**；带 subtemplates 的步骤父模板只当开关、父结果不报）、
  深度上限 3 + 同模板单次执行只跑一次 + 单步展开上限 `_WORKFLOW_MAX_SUBS`=40（vulnscan 通过
  `registry=` 复用已加载的候选集，不再每站点重读 POC 目录）。
  **flow 的脚本子集自 2026-09-25 续39 起支持**（nuclei 那条"循环 + `set()` + 请求"的主干）：
  `scanner/pocs/engine.py` 的 `_FlowJsParser` 在**装载期**把脚本解析成 AST 并做静态校验
  （未声明变量、引用越界、循环是否终止、静态语句数上限 `_FLOW_MAX_STEPS`=200），运行期只按 AST
  解释执行 —— 与 `dsl` 同一条红线：**绝不把模板变成可执行代码**，也绝不"运行期静默不命中"。
  支持 `let/const/var`、`if/else`、`for...of iterate(...)`、C 式 `for`、`template["k"]`、
  `set()`（写模板上下文 → 后续请求的 `{{name}}`）、`log()`（实参先求值、不打印）、
  `http(N)`（1-based）/ `http("id")` / `http()`（该协议全部块）/ `http(1, 2)`（按传入顺序）。
  两条路**并存且顺序固定：先布尔、后脚本**（装载期与运行期兜底同一顺序 —— 布尔源串本身也能被
  脚本解析器解析成一条表达式语句，顺序错了就会语义漂移）；脚本路的 `http(...)` **不缓存**。
  与 nuclei 的已知差异：无 matchers 的块我们判假（nuclei 隐式真）、不做类型转换/方法调用/闭包/异常；
  **extractor 回填模板上下文已于续42 落地** —— 只认 `internal: true` 的命名提取器（nuclei 的
  `Internal` 注释就写着"设了才能在下一个请求里用"，不设的只进输出），多值命名照抄
  `name`/`name1`/`name2`（上限 `_EXTRACT_VARS_MAX`=10），回填发生在**匹配之前**（不受命中与否影响）。
  仍不支持的是**块级/顶层** `dsl`、oob 反连、
  flow 里**超出脚本子集**的真正 JS 语义（方法调用/闭包/异常/除 `+` 外的算术/`while`/`new`/
  带参数引用）、workflow 的 `args:`（**nuclei 的
  workflow 没有这个字段**），它们会被标 `_status=unsupported`
  （或写进 `_note`）并在 POC 管理页显示原因（不静默失效）；`dsl` 越界同样在**装载期**就被标掉。
  2026-09-25 续45 实测：仓内 **312 个模板全部 `_status=ok`、0 个带 `_note`**（7 个内置 + 305 个导入），
  上面这些"不支持"目前**没有任何模板卡在上面** —— 故按"不为假设需求写代码"结项，不实现；
  要重启这个话题，先拿出真的卡住的模板（而不是 roadmap 上的条目）。
  **workflow `matchers:` 与跨子模板传值已于续43 落地**：父模板照跑但结果一律不报（nuclei 的
  matchers 分支直接 `return`），只拿它的**非 `internal` 具名提取器**名字挑分支（`condition`
  and/or、名字大小写不敏感、`"a, b"` 与 `[a, b]` 等价），命中的分支才跑其 `subtemplates:`
  并继承父模板收集到的值（只向下传、同级互不回流）；与 `matchers:` 同写的普通 `subtemplates:`
  被忽略（照抄 nuclei）且把"被忽略"写进 `_note`。本引擎的匹配器**没有名字概念**，
  故 nuclei 的 `HasMatch(name)` 那一半恒不成立 —— 只写 `name:` 匹配器、没写具名提取器的模板分不出支。
- **凭据红线（2026-09-23 续17）**：登录态（`scanner/auth.py` 的任务级请求头）**只发目标侧**，
  `utils.http_request(auth=False)` 是默认值、4 个第三方调用点（crt.sh / FOFA / CISA KEV / IP 反查）
  **永不带**；日志/页面/报告只显掩码（`mask_value`）；解析非法行必须报错（CLI exit 1 / GUI 400），
  **不许静默丢弃**（少带一条 Authorization 会让"已登录扫描"变成假象）。框架**不做**登录爆破/表单提交。
- `owasp` 字段**格式是统一的**（`A01` 大写）：POC 引擎在 `engine.py` 里把 tag 的 `owasp-a01`
  规整为 `A01` 再入库，内置检查本身写 `A01`。*（本文件此前写的"POC 命中写 `owasp-a01`"与代码不符，
  已按代码更正 —— 见 `TODO.md` P1-3。）*
- **dirmap 自身代码的 7 个问题**（第十六轮 5 个 + 续45 2 个，均已**修在本机那份外部副本**里，
  见下一条）：`saveResults()` 定义了两遍（前一个失效）、`response_storage`/`error_count` 是全局量、
  `saveResults` 每次全文件 `r+` 读取再追加（1.5 万条结果时 O(n²)，gevent 并发下还会丢写）、
  `conf.skip_size` 与 `intToSize()` 的字符串比较永远不相等、`ssl_context` 建了却没挂到 session；
  续45 补的 2 条：**产物行写 `intToSize()` 的量化值**（`1.21kb` 反算 1239、真值 1234，±0.5% 误差
  让同一条路径的 dirmap 行与内置行在折叠去重时对不上 → 改写 `size_bytes` 精确字节数，内部
  `response_storage` 去重仍按量化值）、**`plugins/inspector.py` 的 auto-404 预检走裸
  `requests.get`**（绕过 `_LegacySSLAdapter`，旧版 SSL/自签名目标在基线阶段就失败 → 延迟导入
  `lib.controller.bruter.session` 复用，避开 `bruter → inspector` 循环导入）。
  另**适配器侧**（`scanner/stages/dirscan.py`）续45 补 2 条：解析时 `_strip_fragment()` 剥
  `#fragment`（fragment 从不发给服务端；不剥则开递归会拼出 `.../b#x/` 这种无效目录前缀）、
  `DirscanStage._cleanup_output()` 清掉本次扫过的 `output/<netloc>/`（`output/` 是持久目录、
  无上限；顺带解掉「残留文件让重扫写出 0 行、mtime 也不变」的隐患，只删本次扫过的目标）。
- `config/dicts/sensitive.txt` **已是 A01 检查的数据源**（第十八轮续14 起）：文件格式改为
  `路径 | 特征关键字1,特征关键字2 | 级别 | 说明`，`checks.sensitive_files()` 读它、按"200 + 关键字命中"
  判定；**只有路径没有 `|` 的行＝预留位（跳过）**，文件缺失或一条可检测行都没有时回退
  `checks.SENSITIVE_FILES` 硬编码清单 —— 不带关键字就凭 200 判"文件存在"会被统一 200 的软 404 页放大。
- `db._WRITE_LOCK`（`threading.RLock`）把**所有写路径**串行化：`_exec` / `init_db` / `set_vuln_review` /
  `bulk_set_vuln_review` / `upsert_poc` 主路径。WAL 只保证"读不被写阻塞"、`busy_timeout=10000` 只保证
  "冲突时最多等 10 秒"，**都不保证写成功**；而本框架无任务队列，N 个任务线程 × `pool_run(workers=20)`
  的回填是完全可能同时打满的。新增写路径时**必须**走 `_exec` 或显式加这把锁。
- `parse_line` 对裸域名会 `strip("/")` 并小写；CIDR 会展开为多条 `("ip", …)`
  （`MAX_CIDR_ADDRESSES=256`，超过则整体丢弃并在解析阶段记日志）。
- GUI **仅限本机使用**（单用户、无多用户/HTTPS/审计）。续32 起有两道**本机守卫**
  （`gui/app.py` 的 `_local_guard`，两个都只服务于"本机单用户"这一模型）：
  ① **Host 白名单** `_LOOPBACK_HOSTS = {127.0.0.1, localhost, ::1}` —— 挡 DNS rebinding
  （恶意域名解析到 127.0.0.1 即被浏览器视为同源，叠加上公开的默认口令 `ctfscanner` 就是完整接管）；
  只在下述**绑定回环地址**时启用。② **写方法 Origin/Referer 校验** —— POST/PUT/PATCH/DELETE
  要求其**权威段**与本次 `Host` 一致，比的是 `_authority()` 归一后的 `主机[:端口]`：
  **端口必须参与比对**（Cookie 不按端口隔离，同机另一个服务同样危险），默认端口按 scheme 归一
  （浏览器在默认端口下不写端口）。**注意别用 `_host_of()` 做这件事 —— 它丢端口**
  （续32-fix 的真缺陷就是两边都过 `_host_of`，导致"同机异端口"整类请求被静默放行）；
  `Origin: null` 不放行，两个头都缺失时放行（curl/脚本必须能用）。会话 Cookie 显式设
  `HttpOnly` + `SameSite=Lax`（不依赖浏览器默认值）。**刻意不做**逐表单 CSRF token（几十处调用点，
  漏一处就是"看起来有防护、实际有缺口"）。`serve()` 在绑非回环地址时打显式告警 —— 那种模式下
  Host 白名单自动放宽，暴露必须看得见。**注意 `_LOOPBACK_HOSTS` 刻意不含 `0.0.0.0`**（它是绑定
  地址、不是可访问的主机名）；`gui.host` 改了要**重启**才生效（守卫在 `create_app()` 算一次）。
- **发码与查码必须同源（续108）**：`gui/templates/login.html` 的 `.captcha-row` **无条件渲染**，
  `gui/app.py::login()` 的 `captcha.check(...)` 在**所有凭据分支之前** —— 当年账号口令与
  `gui.token` 引导口令走同一条门（续117 摘掉引导口令后只剩账号一条分支，这条纪律更要守住：
  将来再加任何登录方式，门必须在它之前）。这里分叉过一次：模板按"库里有没有账号"隐藏整块，
  路由却按"填了用户名才查码"，于是**零账号时输入 `admin` 永远「验证码错误」而页面上根本没有码可抄**
  （用户报的"后台不显示验证码"就是这个）；而唯一能直接换来管理员身份的引导口令反倒**完全免码**。
  改这一处**模板与路由要一起改**，回归 `[7h+]`（有账号档）与 `[7j]` ⑬（零账号档）两头都钉着。
  失败锁定 `max_fails_per_ip` 续108 由 10 收到 **5**，**三份默认值必须一起改**（`login_guard.DEFAULTS`
  / `config.DEFAULTS` / `config/settings.yaml`，`[7j]` ① 钉三方一致）；用例一律从 `_cfg48` 取阈值、
  不许把数字写进循环（§6.2）。这两段阈值**页面上改不了** —— `/settings` 的 gui 段没有它们的输入框
  （该段只有 host/port 与几个勾选项；`allowed_hosts`/`login_lockout` 等键保存时原样带回；续117 起连口令那一栏也没有了）。
  ✅ 续109 修掉其中第一条：会话签名密钥不再由 `gui.token` 推导 —— `config.session_secret()` 随机 32 字节、
     落在**库同目录**的 `session.secret`（0600；`data/` 本就在 .gitignore，`CTFSCANNER_DB` 一重定向就自动进测试沙箱），
     已存在则复用（重启不打光会话），写不了就**退回进程内随机并 warning**（绝不静默降级，更绝不退回可推导串）。
     顺带：`serve()` 的启动横幅不再打印引导口令的值。回归 `[8g]` —— 用**旧推导式密钥**签一张真存在、真启用的
     管理员 Cookie 塞进客户端，`/` 与 `/settings` 必须 302；同一条判据配**运行时变异**（把 `app.secret_key` 打回
     `f"ctfscanner::{token}"` → 同一张 Cookie 立刻被接受），否则"被拒"可能只是 Cookie 格式搓错了（§6.1）。
  ✅ 续117 把这一整支**摘掉**（比续113 的"只存派生值"更彻底）：`gui.token` / `gui.token_hash`
     都不再被任何代码读取，配置文件里没有任何登录凭据；残留键由 `cli/run_users.py --purge-legacy-token`
     显式清除（走 `config.remove_settings_keys` —— **逐行删**，`save_settings` 是合并写删不掉键，
     且它整份 `yaml.safe_dump` 会把 settings.yaml 的注释全洗掉，本轮真踩过）。下面这条留作历史。
  ✅ 续113 收掉第二条：`gui.token` 不再必须存明文 —— 「策略配置」页保存口令只写 `gui.token_hash`
     （pbkdf2 派生值），页面上也不回显。**仍留的一条**：老配置里"只有明文、还没有哈希"时登录仍认明文
     （否则一升级就把人锁在门外），每次启动打 warning 催迁移。详见下面「引导口令只存派生值」一条。
- 「策略配置」页覆盖 gui/limits/checks/subdomain/passive/evasion/
  takeover/portscan/jsmine/dirscan/vulnscan/screenshot/cert/iprecon/fofa/**ssrf/shodan/quake/ctlog**/
  blacklist/intel/heuristic/**github/multileak/flags/afrog/queue/dev/http/tools/dicts** **三十一段（= DEFAULTS 全段；续158 起 tools/dicts/http/queue/dev 也可从页面改）**（dirscan 段含 mode/quick_max_paths/suffix_aware/big_dict/max_paths/**recursive_depth/recursive_max_dirs/recursive_max_paths**（递归三键，续30）；portscan 段含 mode/full_ports/exclude_scanned）
  （含按级别 / 按 OWASP 分类 /
  按检查项三级开关），并且**每个"大功能"都有阶段级 enabled 总开关**（`dirscan` / `vulnscan`
  于第十轮补齐：此前这两段在 DEFAULTS 里根本不存在，无法从 GUI 关闭；
  `dirscan` 默认值于**第十八轮（续9）**由 `false` 反转为 `true`+`mode=quick`）；
  `passive.sources` 清单仍要手改 settings.yaml（外部工具路径与字典路径续158 起可在策略页「队列 / 开发模式 / 高级」改）；
  fofa 的 email/key 要手改 `config/keys.yaml`（控制台只读、不写回凭据）。
  （**但"装外部工具"不再需要手改**：续54 的 CLI `--update-tools` / GUI「外部工具」页会自己回写。）
- **`settings.yaml` 有两条写回路径，别混用**（续54 起因）：GUI「策略配置」保存走 `config.save_settings()`
  —— 它是 `load_settings()` + `yaml.safe_dump` **整份重写**，会抹掉 `settings.yaml` 里的**全部中文注释**
  （既有行为，本仓已知）；而"装工具只改一个键"这种操作走 `toolmgr.patch_settings_tool()` 的
  **逐行文本替换**（只动 `tools.<名>` 那一行，保注释、保行尾形态、保尾换行）。
  以后凡是要"只改一个键"的新功能请沿用后者，**不要图省事调 `save_settings()`** —— 那等于顺手删掉
  用户文件里的注释。回归钉在 `tests/smoke.py` 的 `[7p]`（`#` 计数与行数不变 + 纯 CRLF + 尾换行保留）。
- **`db.list_tasks/list_vulns` 的 `limit` 三态别搞混**（续55 定口径）：`limit=None` ＝ **不加上限（全量）**、
  正整数 ＝ 取最新 N 条、**`limit=0` ＝ 一条都不要**（`0` **不反转**成"全部"）。默认值 `200` 是
  "分页之外的合理默认"，**GUI 列表一律走分页**（`page_tasks`/`page_vulns`/`page_assets`）；
  只有**报告导出、阶段内部计算、全表映射**这类"不能漏"的调用方显式传 `limit=None`。
  同理，按名字找一个已知任务用 `db.find_task_by_name()`，**不要在 `list_tasks(limit=N)` 里线性找**
  —— 那个 N 一被超出就是**静默失效**（续55 修的 `devmode` 页就是这么坏的）。
  回归钉在 `tests/smoke.py` 的 `[7q]`（含"报告数据源不得再出现 `limit=1000`"的源码红线 + 2 条变异）。
- **站点页签的「批量打开」：第 1 个直接开、其余必须给真链接**（续56 定性质，续112 改形态）：
  `gui/static/app.js::initOpenSites()` 里 `window.open()` **一次手势只能开出一个** —— Chrome 对
  单次用户手势只放行一个弹窗，后面的同步调用一律返回 `null`（放进 `setTimeout`/`await` 之后
  连第一个都保不住）。旧实现据此提示"允许本站弹窗后重试"，但**允许了也还是只开一个**，用户的
  结论就是"批量打开有 bug"。现在的形态：第 1 个 `window.open`，其余渲染进 `#op-list`
  （模板里必须有这个容器）成真 `<a target="_blank" rel="noopener noreferrer">` —— 用户点每条
  链接各自是一次手势，浏览器就放行；另给「复制链接清单」（非安全上下文里 `navigator.clipboard`
  不可用 → 退回 `execCommand`，两条路径都要报成功/失败）。`OPEN_SITES_MAX = 20` 是防手滑上限，
  未列出/被拦的条数**如实显示**。
  **不发任何请求** —— 续145 摘掉那四个补扫入口（深度目录补扫 / 补截图 / 全端口补扫 / 深度补扫）
  之后它一度是站点表上**唯一**的批量动作；续170 按主理人点单在同排加回「重新截图（勾选站点）」与
  「重截失败的站点」（`POST /api/sites/reshoot`：在**本任务**里排一轮只跑 `screenshot` 的追加运行，
  **不新建任务**、排队等 worker），而 `POST /api/rescan` 接口仍在、GUI 上零消费方（续154 撤掉
  漏洞「复查」入口后一个按钮都不挂它）。`[8at]①` 钉"整页恰好两处 POST"，`[7s]⑤` 钉站点页签那一个。
  三个不能改的点：① 按钮**必须** `type="button"`（它旁边就是 GET 筛选表单，默认 `type=submit`
  会把勾选甩成查询参数并整页刷新丢掉勾选；补扫表单还在的年代它会**误触发真扫描**）；
  ② 拿到句柄后立刻 `w.opener = null`（反向标签劫持）；③ **读哪张表的勾选由按钮自己的
  `data-pick-from` 给出**，JS 里不许写死任何表 id —— 写死就等于"只有那一页能用"，
  续145 之前它硬编码 `#tbl-detail-sites`，把按钮搬到 `/sites` 只会**静默失灵**
  （勾选框有、全选有、点了没反应）；缺属性时要**报出来**，不许安静地什么都不做。
  回归钉在 `tests/smoke.py` 的 `[7r]`（检测器先变异证伪：喂 `<button type="submit" id="btn-open-sites">` 必须报错）
  与 `[8at] ①`（详情页 POST 表单恰好 2 个、`/sites` 的按钮接的是 `#tbl-all-sites`）。
- **GUI 的三类行为只能靠真浏览器验，`test_client` 看不出来**（续60 定口径）：
  ① 点击后 **DOM 真的变了没**（翻页/页签切换/面板折叠）；② **表单提交去了哪**（表里那些
  `type` 缺省的 `<button class="toggle">` 会不会误提交外层筛选表单）；③ **浏览器侧状态**
  （`window.open` 被调了几次、`localStorage` 有没有持久化）。这三类正是续56~59 一路攒下的
  "未验"项。落点是 `tests/browser_e2e.py`：**真实 Flask 服务进程**（不是 `test_client`）+
  真无头 Chrome/Edge，用**手写 CDP**（`socket` 写 RFC6455，**只用标准库**，不新增依赖）真点真读。
  **两条硬约束**：① 找不到浏览器 → **跳过**（退出码 2 + 打印原因，**绝不假绿**、绝不抛异常）；
  ② 临时库 / 日志 / user-data-dir / 引导脚本全落 `%TEMP%`，`try/finally` 回收，端口用系统分配。
  它接在 `tests/smoke.py [7x]` 里是**可降级**组：rc=0 记过、rc=2 记跳过（但**跳过原因不含
  "未找到可用的无头"时按失败算** —— 防止"因为别的原因垮掉却被当成跳过"），rc=1 直接红。
  ⚠️ **不要**再写"本机无头环境限制"这类话：实测本机 Chrome / Edge 都在、都能被 CDP 驱动
  （`--headless=old`；`--headless=new` 在 Windows 上拿不到 stdout，早期探针踩过）。
  ⚠️ 候选路径**不许写死盘符**（`tests/` 也在 smoke 的源码红线扫描范围内），从
  `ProgramFiles`/`ProgramFiles(x86)`/`LOCALAPPDATA` 环境变量拼装 + POSIX 常见路径。
- **报告资产小节的上限走 `CAP_*` 常量 + `report._cap_title()`**（续56 定口径）：
  这些上限（站点/目录 100，端口/C 段/证书/子域名 200）是**有意的可读性护栏**，不是丢数据；
  但**必须**在真的被截断时把总数写进小节标题（`存活站点（共 120 条，此处仅列前 100 条）`），
  没被截断就保持干净标题。**漏洞清单不设上限**（那是结论，`collect()` 里是 `limit=None`）。
  改报告小节时**不要再写 `sites[:100]` / `ports[:200]` 这类字面切片** —— `[7r]` 有源码红线盯着。
  **续59-2 补上"出口"**：光说"仅列前 M 条"读者仍不知道去哪儿要完整清单，所以
  ① 截断提示里写明`—— 完整清单请用「完整版」导出`；② 三个格式入口都带 `full=False` 形参，
  由 `report._caps(full)` 统一给出"本次生效的上限"（`full=True` → 全 `None` = 不截断），
  `generate()` / `generate_html()` 内部**用同名局部变量遮蔽模块常量** `CAP_*`，
  于是那 12 处切片与 `_cap_title` 调用**一处都不用改**，也就不存在"「完整版」漏改某一节"的风险；
  ③ 出口 = GUI `?full=1` / CLI `--full-report`（`--report-jsonl` 本来就是全量，不受影响）。
  默认上限**不许**借"完整版"之名被放松 —— 它是护栏，不是待修的 bug。`[7v]` 钉住了三路出口
  （含 `_caps` 退回旧行为即红的变异证伪）。
- **「全量渲染」要一并收掉，且筛选必须在服务端**（续59-2 定口径，与续51/53/57/59 同源）：
  去掉了三处残余 —— `/fullports`（全表 `GROUP BY`，原无分页无筛选）、`/dirs?agg=1`
  （原 `limit=5000` **截断后再聚合** → 第 5001 行起所属的组在任何一页都看不到，且聚合视图
  **没有分页条**）、`/pocs`（全量渲染 + 前端 `data-filter`，分页后只筛当前页＝更误导）。
  **两种下推口径别搞混**：`GROUP BY` 本就在 SQL 侧的（`/fullports`）→ `LIMIT/OFFSET` **直接下推**，
  且"计数"与"取行"**共用同一段聚合子句**（两边口径不许各写一遍）；聚合只能在 Python 里做的
  （`/dirs?agg=1`、`/ips`、`extdom` 分组）→ **全量取回 → 折叠/聚合 → 按组/IP 切片**，
  省内存靠"只查小列"，**不靠"少查几行"**。分页条要传 `unit`（「组」/「个 IP」）区分单位。
  筛选表单是 **GET**，必须排在 POST 表单**之前**，且**只包筛选控件**——表里那些没写 `type` 的
  `<button class="toggle">`（POC 开关）默认是 `submit`，被包进筛选表单后点一下就会变成提交表单。
  翻页/切换链接里的 `q` 必须 `quote()` 编码、且要带上 `agg`/`all` 等视图开关（漏了就"翻一页悄悄换视图"
  或"点「查询」跳回明细"）。`tests/smoke.py [7v]` 钉住了这些（含摘掉 `LIMIT` 下推即红的变异证伪）。
- **任务详情页一屏 8 个分页条，页码参数名必须各自独立**（续57 定口径）：漏洞页签 + 7 个资产页签
  （站点/子域名/拓展域名/端口/C 段/证书/目录）的分页条前缀依次是
  `vpage` / `stpage` / `sdpage` / `expage` / `ptpage` / `cspage` / `crpage` / `drpage`。
  `_pager.html` 的页码参数名由 `pager.pname` 指定（**缺省 `page` 只给其它页面用**）——
  **不要**在分页条里写死 `?page=N`：续53 的漏洞页签正是这么坏的（链接发 `?page=`、路由读 `vpage`
  → 「下一页/末页」静默失效，页码还照常显示）。同理 `pager.anchor`（如 `#sites`）不能省：
  页签是**纯前端切换**，翻页/筛选都是整页刷新，不带锚点就掉回第一个页签（配合
  `app.js::initTabs()` 读 `location.hash`）。回归钉在 `tests/smoke.py` 的 `[7s]`。
- **资产页签的筛选一律走服务端**（续57 定口径）：这 7 张表上的前端 `data-filter` 已撤掉 ——
  分页之后它只筛**当前页**，比原来更误导（同续53 撤 `[data-tfilter]` 的理由）。
  每页条数沿用 `PAGE_SIZES`；凡是"GET 筛选表单 + POST 表单"同页签的，GET **必须排在 POST 之前**
  （HTML 不允许 form 嵌套，否则按浏览器的容错拆法按钮会失灵），且 `action` 尾部带锚点。
  ⚠ 任务详情页现在恰好**两处** POST 表单：站点页签的「重新截图」（续170 加回）与拓展域名的
  「送去探测」。端口 / 目录两个页签仍然**一个都不许有**（续145 摘掉的补扫表单不许换个壳回来）——
  `[7s]⑤` 钉的就是"站点/拓展各恰好一个 + GET 先闭合 + form 标签配平 + 端口目录为零"，
  `[8at]①` 钉整页 `method="post"` 计数为 2。
  页签徽标一律显示**总数**
  （`*_pager.total`），不是本页行数。目录页签是**唯一例外**：`_fold_dirs()` 折叠是整表语义，
  只能"取全量 → 折叠 → 过滤 → 切片"，`[7s]` ⑦ 的"不得再全量读资产表"检测器给它留了口子。
- **`page_assets()` 的 `limit=None` / `columns` 两个口子**（续58 定口径）：`limit=None` = **不加上限**
  （三态口径与 `list_tasks()` / `list_vulns()` 一致：数字 / `None` / `0`）；`columns` 只在"要分组或
  去重、但不需要整行"时用，**列名必须由包内调用方给常量**（`q` 的 LIKE 白名单仍来自
  `_ASSET_PAGES`，两者互不影响 —— LIKE 的列与 SELECT 的列本来就不必相同）。
  ⚠️ 拓展域名页的**分组**视图绝不许自己截断：分组只能在 Python 里做（SQLite 没有注册域函数），
  所以省内存的手段是"分组阶段只查 `id/domain/ip` 三列"，**不是**"只拿前 N 行"。旧实现的
  `extdom.GROUP_ROW_CAP = 4000` 会让第 4001 行起所属的主域名组**在任何一页都不会出现**，
  分页条上的"共 N 个主域名"也是截断后的假数字。`tests/smoke.py [7t]` 钉住了这两条。
- **`/ips`（IP 资产）同样是"聚合先于分页"**（续59 定口径）：`db.list_subdomain_net()` 的默认值
  **必须是 `limit=None`**（不加上限），三态口径与 `list_tasks()`/`list_vulns()`/`page_assets()` 一致。
  这页的语义是"按 IP 聚合域名"，而 `subdomains.ip` 是**逗号连接的多 A 记录**、SQLite 没有 split
  函数，所以聚合只能在 Python 里做，分页也只能按**聚合后的 IP** 切 —— 与 `extdom.group_page()`
  同一套口径：**省内存靠"只查 `domain/ip/cdn` 三列"，不靠"少查几行"**。
  旧的 `limit=20000` 硬写上限在超限时**丢行 = 丢 IP**（该 IP 在任何一页都看不到），
  且没有任何提示；`tests/smoke.py [7u]` 钉住了"分页默认值不得是固定数字 + 3 页覆盖全量 + 变异即红"。
  关键字筛选走服务端（同续53/续57 的口径），`q` 为空时不能显示"还没有解析数据"（那会把
  "筛选没匹配"误导成"没有资产"）；分页条要传 `unit="个 IP"`（`pager.total` 是 IP 个数，不是行数）。
- `wildcard.py` 只用系统解析器（`socket.getaddrinfo`），**取不到 CNAME**，故无法用"通配 CNAME 黑名单"维度。
- **任务详情为 11 个页签**（潜在漏洞(默认)/站点/子域名/拓展域名/端口服务/C 段/目录/**SSL 证书**/**敏感信息**/目标与配置/运行日志）；
  跨任务对比**刻意不做成第 12 个页签**（续129）：页签是"本任务的数据"，而对比需要两个任务，
  塞进页签会让人以为"没数据"是自己这个任务的问题 —— 它是任务详情页头部的一个链接 + 独立 `/diff` 页。
  参考 ARL 界面的
  IP/文件泄露/URL信息/nuclei/指纹统计/WIH 这些页签**故意不做空占位**，因为对应的数据源
  还不存在（分别依赖爬虫数据模型、nuclei 二进制等）。理由与依赖关系见 `TODO.md` B-7。
  「SSL 证书」页签是续15 的落点（只读 TLS 握手 + 纯标准库 DER 解析，**握手不校验证书**）：
  证书的「自签 / 已过期」是**属性**，页签与报告都写明不是漏洞结论，且没有产物时会说明原因。
  **「线索」页签（及 MD/HTML 报告的小节）已于 2026-09-24（续24）按用户口径移除** ——
  `intel` / `heuristic` / `github` 三个阶段与 `leads` 表**完全不变**，只是不再进 GUI 页签与人读报告：
  线索现在只从 **JSONL 导出**出（`type=lead` 行 + `counts.leads`），沿用续20 的取舍
  「机器格式保留全部、筛选权交给下游」。这是**口径变更**不是缺陷，`tests/smoke.py` 的
  `[5n]` / `[5w]` 已把它翻成**反向断言**（页签与小节必须不在、JSONL 必须仍在）。
  「拓展域名」页签与跨任务 `/extdomains` **共用同一张来源顺序表**（`EXT_SRC_TAGS`：
  JS 挖掘 → FOFA·标题 → 证书 → ICO → C 段，同类内新的在前），任务页另支持 `?esrc=` 分类过滤；
  以及三个**手动**处置（2026-09-23 续13）：纯 DNS 解析 `POST /api/domains/resolve`、
  送去探测 `POST /api/domains/scan-ext`（新任务 `probe→dirscan→vulnscan`）、
  `POST /api/blacklist/add`（此前任务页签没有此入口）。
  **同轮补探之后仍然留着手动的理由**：`osint`/`jsmine` 排在 `probe` **之后**，它们新挖出的域名
  以前赶不上本轮存活探测、天然停在"有域名、无站点、无检测" —— 续139 的 `probe.second_pass`（二层
  遍历，由 `jsmine` **无条件**调用）补的就是这一条：同一轮就把归属本任务、且第一轮没试过的名字
  过一遍 DNS 预筛再补探成站点，**不必新建任务**（见 §7 续139 那条）。仍然留手动入口的理由换了但没消失：
  跨任务视图里的历史拓展域名、不归属本任务目标的域名、以及"要不要深扫"由人判断 —— 拓展域名里
  大量是 CDN/开源库/JS 命名空间碎片，全自动跑既越权又浪费额度；`POST /api/domains/scan-ext`
  那个「送去探测」入口照旧可用。
- **指纹补标与 flag 抽取共享同一处覆盖缺口（续127 登记）**：`sites.tech` 的补标只吃
  **有正文的响应** —— 走 httpx 时 probe 只回 title/tech 的 JSONL、dirmap 的产物行也没有正文，
  这两路的命中对补标与 flag 都没有输入。要补就得真加请求（与 §5.17② 冲突），属独立一轮。
  另外补标只挂在**本任务 sites 表里存在的站点**上：补扫任务没跑 probe 时 `flush()` 会把
  `missing` 点名出来（标签没挂上不是"没识别出来"），但这些标签目前确实无处落地。
- **flag 候选抽取的两处覆盖缺口（续126，如实登记）**：① **走 httpx 时 probe 根本没有正文**
  （它的 JSONL 只有 title/tech/status），所以这一路只能由 jsmine / dirscan 内置档 / vulnscan 证据兜到
  —— probe 会明写「httpx 档不返回正文，本阶段无输入可扫」，不会看起来像"扫过了、没有"；
  ② **dirmap 的产物行也没有正文**（`[状态码][content-type][大小] URL`），装了 dirmap 的机器上
  那一路的命中不会贡献 flag 候选（与续113 那条「没标题⇒不滤但明说」同源）。
  还有第三类是**形状本身**的局限：非 `{}` 形态的 flag（`flag:` 后不带括号、或题目自定义前后缀）
  要靠 `flags.prefixes` / `flags.patterns` 手工加，默认清单只有 `flag{` / `ctf{`。
  第四类是**内置形状有 6 条提不出可用的锚**（续148 如实登记）：cloud-access-id / telegram-bot-token /
  stripe-key / generic-credential 的字面量藏在**嵌套分支**里，`required_literals` 对嵌套分支返回
  None；github-token（锚 `gh`）与 db-uri（锚 `://`）提得出锚但锚定位不住 —— 一页里几百处，
  只看了前 `max_per_source` 个窗口就是静默漏报，所以宁可拒用。这六条**仍能在「线索」里看到**
  （jsmine 那一路在 JS 正文上是整篇匹配的，取值打码），不是把能力删了。
- **测试脚手架的 `finally` 自己会掩盖真错误（续130 实测）**：`[8ag] ③` 把 `which` 的
  原值捕获写在 `try` 里面，于是 try 内任何一步先抛时，`finally` 报的是
  `NameError: _real_which128`，真正的失败原因**整个看不见**。规矩：**要打桩就先取原值，
  再进 try**。同类问题这次是靠"四组联跑的预检脚本"暴露的 —— 单跑一组时那条路径根本走不到
  finally，所以新组的预检要连之前几组一起跑（见 `logs/_pre126.py` 的做法）。
- **`osint` 的联网往返无法离线自测**：`tests/smoke.py` 只断言了 `iprecon`/`fofa`/`mmh3` 的纯函数、
  黑 ico 阈值边界与"两个子开关都关则无产出"的门控；`api.webscan.cc` 与 FOFA 的真实响应结构
  需要联网（FOFA 还需 key）才能验证 —— 首次实跑请打开开关并观察 `logs/task_*/task.log` 的 `[osint]` 行。
- `osint` 的阈值都是**保守估计值、未经真实数据校准**：黑 ico 阈值 200、通用证书阈值 200
  （`fofa.cert_threshold`）、单 IP 域名数 30（判共享主机）。都可在「策略配置 → 外部情报拓展」调整，
  不需要改代码。证书反查的"通用证书"判定尤其粗：**只按命中总数比阈值**，不做证书主体/颁发者分析。
- **`js_thirdparty.txt` 是黑名单，永远不可能穷尽**（续22）：它是"已知第三方/公共库域名"清单，
  新库/新 CDN 出现就得补；漏网的表现是「拓展域名」页出现某个开源库域名。`tlds.txt` 同理是
  **PSL 快照**，会滞后于 IANA 的 TLD 变更（重生成：`py -3 tools/import_tlds.py --force`）。
  两者缺失/为空都 **fail-open**（回退宽松判断并告警一次，绝不静默丢资产）。
- **黑名单的语义边界**：过滤发生在**入库前**，所以它**不影响已入库的历史资产**（老任务里的域名照旧可见），
  也不会因为后来把某域名加入黑名单就把既有行删掉。文件是纯文本、每次调用重读（改完立即生效，无需重启）。
- **重叠隐藏是"显示层"判据，不是删除**：`OVERLAP_EXT_WHERE`（拓展域名域名级全局）与
  `OVERLAP_SITE_WHERE`（站点 URL 级跨任务，保留 `MAX(id)` **最新一条**）只作用于 `/extdomains`、`/sites`
  两个列表页，`?all=1` 可放开；任务详情页签与报告仍显示全量。因此"站点页条数比任务详情少"是预期行为。
- 任务已支持**停止（协作式取消）/删除/重启/续跑/导出 + 批量操作**；停止粒度是"当前批次跑完即停"，
  不会强杀正在飞行的 HTTP 请求，任务终态记为 `stopped`（区别于 `failed`）。
- **断点续扫的语义边界**（续29）：断点**复用 `tasks.current_stage`**（不是新增列）—— `PipelineRunner.run()`
  在每个阶段**开始前**写它、正常跑完才清空，所以"被停止 / 预算耗尽 / 进程被重启打断"时它就是
  最后进入的那个（可能只跑了一半的）阶段。`runner.resume_stages()` 返回该阶段**及其之后**的阶段
  （**故意重跑断点阶段**；各阶段产物按去重键入库，重跑不产生重复行）。`resume` 是
  `run_task` 的**独立参数**，**不能复用 `append=True`** —— 后者会带上 `append_targets` 的收窄语义，
  而 `append_scope()` 在"`append=True` 且 `append_targets` 为空"时返回**空集**，等于一次都不扫。
  因此两处原本会抹掉断点的代码（`PipelineRunner.run` 的 stopped 分支、`db.reconcile_orphan_tasks`）
  已改为**保留**；清理断点只由"正常跑完"与 GUI「重启」负责（重启同时清资产、从头跑）。
   续159 补一条**必须一起想的边界**：续跑时 `ctx.results` 是空的，所以下游阶段的候选**必须自己回库里读**（`extdom.own_hosts()`），否则「沿用库中已有数据」这句就只是文档愿望。另两条实况：`probe.second_pass` 挂在 jsmine 里、而 jsmine 在「无站点输入」时先 `return`（所谓「无条件调用」只在函数体内成立）；外部引擎（fscan/afrog）随父进程一起死，那一轮的半成品**不会**入库。
- **追加执行的语义边界**（续25）：追加**只影响本轮跑的那些阶段**，不重跑整条流水线；跨运行去重是
  "**入库前跳过同键**"（不删已有行），所以用户已打的 `review` / `review_note` 不会被覆盖；
  续写 `log_file` 会把多轮日志拼在同一文件里（有意的 —— 便于按任务维度回溯全部运行）。
  追加**不改 `tasks.stages`**（任务对外仍声明原阶段集），进度按本轮重新计时；
  **同任务并发追加硬拒绝**（否则停止信号被覆盖），**无源入口**（站点/IP/全端口三页）不提供追加。
  导出有三档（续16）：`/tasks/<id>/export?fmt=md|html|pdf`（默认 md），
  **HTML 全量 `html.escape`**（报告里的标题/banner 来自被测目标，漏转义即反射型 XSS）、
  **PDF 复用无头 Edge/Chrome 打印**（没有浏览器时返回 400 + 可读原因 + HTML 替代链接，不静默失败）；
  仪表盘另有「漏洞趋势统计」面板（`db.vuln_trend()`：级别分布 + 最近 15 任务逐任务计数，**已判误报不计入**）。
- **运行时长的时间口径**（续35）：`tasks.started_at` / `finished_at` / `elapsed_seconds` 由
  `db.start_task_run()` / `db.finish_task_run()` 维护，**不要拿 `created_at`/`updated_at` 推** ——
  `updated_at` 会被复查 / 误报复核等**非运行期**写入刷新（越等越长），两时间戳之间还可能夹着停机。
  续跑 / 追加是同一任务的第二、三段运行 → **累加**（读侧只认 `db.task_run_seconds()`：已累计 + 正在跑的
  这一段）；GUI「重启」会 `clear_task_assets()` 推翻结果集从头跑 → 清零（`start_task_run(fresh=True)`）。
  累加必须在**同一条 UPDATE 内用 SQL 算术**完成：先读后写两步之间无锁，会静默丢时长；`MAX(0,…)` +
  `COALESCE` 兜住"无起点 / 时钟回拨"（不写负数）。进程被强杀时对账按该行**原 `updated_at`**
  （最后已知存活时刻）结账，**不把停机时长算成运行时长**；老库行没有 `started_at` → 页面显示 `-`（不编数）。
  落点：详情页「目标与配置」的「运行时长」「开始 / 结束」两行 + CLI 摘要一行（同一口径，回归见 `[6v]`）。
- **改完 GUI 必须重启服务**：若 5000 已被旧进程占用，新起的 `run_gui.py`（经 `gui/app.py serve()`）
  会打印端口占用提示并以退出码 1 结束——按提示结束占用进程或改 `gui.port` 再试；
  请求还是打到旧进程（新路由 404）——很容易误判成"代码没生效"，先确认端口占用再排查。
  ⚠ 续145-附：那句提示**曾会说谎** —— `_port_free()` 原先是裸 bind，而 Werkzeug 真实那次带
  `SO_REUSEADDR`（`HTTPServer.allow_reuse_address = 1`），于是"旧进程刚结束、还有客户端连接没关完"
  （FIN-WAIT / TIME_WAIT 占着这个本地端口）会被判成"有人在监听"，而 `ss -tln` 明明是空的。
  已修（预检同样打 SO_REUSEADDR，回归 `[8at]⑤`：残留连接放行、真监听者仍报占用）；
  **再看到这句提示先用 `ss -tlnp | grep :5000` 核一眼有没有真监听者**，别照着提示去杀一个不存在的进程。
  **实测代价**：曾有一个旧 GUI 进程（PID 18360，2026-09-21 14:09 启动）被点名却一直没人杀，
  连续两天占着 5000；服务端 `debug=False` 既不重载代码也不重载 Jinja 模板，于是"代码明明改了、
  页面却是 5 栏旧导航 + 还写着'疑似问题'"。**排查任何"页面不对"之前，先看进程启动时间**：
  `Get-CimInstance Win32_Process -Filter "Name like '%python%'" | Select ProcessId,CreationDate`。
  **本轮又踩一次（2026-09-22）**：GUI 于 17:17 重启，而我 17:20 才给 portscan 阶段加
  `full_workers/full_timeout` —— 从那个 GUI 发起的全端口任务**仍按旧参数**跑（日志写「最坏约 17 分钟」），
  因为 Python 进程早已把模块加载进内存。**结论：改完任何会被 GUI 调用的代码，都要重启 GUI 再验证。**
- **不要让子代理/自动化去点 GUI 的写操作按钮**：批量停止/重启/删除、新建任务都是真写库。
  本轮实测教训：一个被要求"只观察"的浏览器子代理点了「批量删除」并**把 `confirm()` 确认框也确认了**，
  硬删掉 63 条历史任务行；紧接着又提交了「新建扫描任务」表单，对一个**外部真实域名**跑了全 8 阶段扫描。
  派浏览器代理时必须在提示里明确写"只读浏览，禁止点击任何提交/删除类按钮"，并**限制其可操作页面**。
- **dirmap 适配的三个实测坑**（改之前先读 `stages/dirscan.py::_run_dirmap`）：
  ① 产物在 `output/<域名>/` **子目录**里（`res.txt` / `403.txt` / `404.txt` / `重复长度.txt`），
  不是早年的 `output/<域名>.txt`；② `output/` 是**持久目录**；
  ③ **只按 mtime 过滤会漏结果** —— dirmap 的 `saveResults()` 会与文件已有行去重，
  重扫同一目标且结果不变时**它不写新内容**、文件 mtime 保持旧值（实测「跑了 37 秒却解析 0 条」）。
  **最终方案：按目标定位** `output/<netloc 把 : 换成 _>/*.txt`，再按目标 netloc 过滤行，
  mtime 过滤只作兜底。结果行格式是 `[状态码][content-type][大小] URL`，**续45 起大小是精确
  字节数**（如 `1234`）；老产物仍可能是量化值 `1.23kb`，`_size_to_int()` 两种都吃。
  解析时用 `_strip_fragment()` 剥掉 `#fragment`（dirmap 原样写 `response.url`，请求里带了就落盘）。
  我们只读 `res.txt` / `403.txt`（`重复长度.txt` 按用户要求默认不展示），解析完清掉本次扫过目标的
  `output/<netloc>/`（`_cleanup_output()`：只删本次扫过的，别人的历史产物不动，失败只告警）。
- **dirmap 是 GPL-3.0，刻意不内联**（把源码拷进仓库会让整个仓库受 GPL 约束）：
  只保留 `tools/dirmap/` 目录联结 + 外部适配器；对它的 7 处源码修复（重复定义 / 死变量 /
  O(n²) 读回+并发丢写 / `skip_size` 比较恒假 / `ssl_context` 未挂载，**588s → 43s**；
  续45 补：`intToSize` 量化值改精确字节数 / `inspector` 复用带 SSL 适配器的 session）记录在
  `tools/dirmap_fixes/README.md`（**该目录不含 dirmap 源码**）。
- **全端口扫描（1-65535）实测**（2026-09-22，本机回环）：`workers=256`/`timeout=0.3` → **82 秒**；
  **默认参数** `workers=64`/`timeout=1.0` → **1037 秒（17.3 分钟）**，差 12.6× —— 全端口用默认参数基本不可用，
  故新增 `portscan.full_workers`（默认 256）/ `portscan.full_timeout`（默认 0.5），**只在 full 模式生效**。
  阶段日志的耗时预估（`端口数/并发 × 单端口超时`）实测准确（预测 17 分钟 / 实测 1037 秒）。
  **校准表**（远端不可达目标 `192.0.2.1`，2048 端口外推 65535）：64/1.0 → ≈17 分钟；
  256/0.5（现默认）→ ≈2.2 分钟；512/0.3 → ≈0.7 分钟。默认不取 512 是因为 512 并发对远端目标偏激进。
  **N 个主机串行，总耗时 ≈ N × 单主机耗时**（默认下 10 主机 ≈ 22 分钟）。
  **校准表**（远端不可达目标 `192.0.2.1`，2048 端口外推 65535）：64/1.0 → ≈17 分钟；
  256/0.5（现默认）→ ≈2.2 分钟；512/0.3 → ≈0.7 分钟。默认不取 512 是因为 512 并发对远端目标偏激进。
  **N 个主机串行，总耗时 ≈ N × 单主机耗时**（默认下 10 主机 ≈ 22 分钟）。
  `nmap_scan()` 的两个超时已封顶（host ≤1800s / 进程 ≤3600s），否则全端口会算出 4.5~36 小时。
  GUI「全端口扫描」页发起的是**单次任务**（任务选项 `portscan_full`），不改全局策略 ——
  全局 `portscan.mode=full` 会让每个任务都变慢，谨慎使用。`parse_ports()` 默认 `max_span=4096` 就是防手滑的。
- **F2 统一门控 v1 的覆盖缺口（如实登记，不装作全覆盖）**（2026-09-24）：
  - **不覆盖** `scanner/certs.py` 的 TLS 握手、`scanner/dnsq.py` / `utils.resolve_host` 的 DNS 查询
    （量级远小于 portscan，且已被 `cert.max_sites` / `subdomain.max_resolve` 低量约束）；
  - **不覆盖** GUI 里任务外的独立动作（如 `/api/domains/resolve` 用的是 `load_settings()` 原始
    settings、没有 `_throttle`）；
  - **拦不住外部工具内部的连接**：我们只做"边界闸（同时起几个子进程）+ 把算好的线程数传进去"，
    `budget_total` **不约束外部工具内部发多少连接** —— 设了预算 ≠ 外部工具也被限住了；
  - **不同 `max_inflight_global` 的并发任务不共享闸**：`_GlobalState.gate_for` 在容量变化时重建闸
    （"配置改了即生效"），旧任务仍握旧闸 —— 若旧闸此刻仍有在飞请求，进程级**有效上限暂时是两者之和**
    （如 256 + 64）。重建时**会打一条 warning 明示**（不静默，回归 `[6i]`）；要真正的"全局硬上限"
    需让所有并发任务用同一个 `max_inflight_global`（**不改成"闸只建一次"、不合并两个闸**）；
  - 预算耗尽是**按停止处理**（任务标 `stopped` + `[throttle]` 错误行），但被拒的那一次调用仍可能
    让调用点报出"网络不可达"这类文案，**任务级错误行与状态才是权威**；
  - 默认值取"恰好等于现有单任务最大并发"（`max_inflight_*`=256 = `portscan.full_workers`），
    故**默认不改变既有行为**（0 = 不限也是同一目的）；要收紧再往下调。
- **拓展域名降噪（续22，`09044ee`）的能力边界（如实登记，不装作全能）**（2026-09-24）：
  - **PSL 是快照、不是实时**：`config/dicts/tlds.txt`（6423 条）由 `tools/import_tlds.py`
    **离线**从 **tldextract 5.1.3 打包的 PSL 快照**生成（包约 2024-11 安装；快照的确切日期未标注）。
    快照之后新委派的 gTLD **不在其中**，且未收录的后缀按 **fail-closed 处理（会被丢弃）**。
    清单缺失/为空时 **fail-open**（回退宽松判断 + 告警一次）—— **宁可留噪音，也不静默丢资产**。
  - **IDN / 中文域名**（续65 已支持主链路）：`utils.to_ascii()` 在边界把 Unicode/punycode 归一为
    ASCII，`is_domain`/`parse_line` 接受 punycode 形态，`config/dicts/tlds.txt` 已补 `xn--` 后缀
    （约 6870 条）。**多段 IDN 公共后缀已修（续68）**：`base_domain()` 的注册域折算改为
    **最长匹配** `tlds.txt` 里含点号的后缀（**含 punycode**，5415 条多段 / 287 条 punycode 多段）——
    此前 `MULTI_TLD` 只列 ASCII，`base_domain('a.教育.香港')` 会返回后缀本身 `教育.香港`，
    导致 `*.教育.香港` 全判成同一注册域；现在 `a.教育.香港` 与 `b.教育.香港` 各自成立。
    `MULTI_TLD` 仅作为 tlds.txt 缺失/为空时的兜底。单段 IDN TLD 不受影响
    （`例子.中国`→`例子.中国`、`a.b.中国`→`b.中国` 均正确）。
  - **`.zip` / `.sh` / `.do` 域名**（续68 已支持）：`_valid_host()` 的 `_FILE_EXT` 过滤只在
    PSL 缺失（fail-open）时生效 —— 能通过 PSL 校验的末位 label 是**真实公共后缀**
    （`zip` / `sh` / `do` 都是正经 TLD），不再被当"文件后缀"误杀
    （`foo.zip`/`foo.sh`/`foo.do` → True；`app.js`/`index.php` 仍 False）。
  - **jsmine 的 Unicode host**（续68 已支持）：`_QUOTED_HOST_RE` / `_PROTO_REL_RE` 的 label
    改为 Unicode 感知（`[^\W_]`），引号内与协议相对形态的中文主机能挖到（绝对 URL 续65 起已支持）。
    ⚠️ 无路径的**两段**引号内域名仍要求 ≥3 段（既有防 `backup.zip` 文件名误判的规则，对
    ASCII/IDN 一致）—— `例子.中国` 挖不到、`api.例子.中国` 能挖到。
  - **截图 / PDF 的浏览器参数（续74 修正续73 的结论；browser_e2e.py 走 CDP 且不在 CI 跑，
    其“老无 --no-sandbox”只在本地 Windows 成立，不能代表 CI Linux runner）**：GitHub 的 ubuntu
    runner **禁用非特权用户命名空间**（必须 `--no-sandbox`，否则 `FATAL: No usable sandbox!`）且
    `/dev/shm` **过小**（~64MB，必须 `--disable-dev-shm-usage`，否则 30s 超时无产物——这才是续72
    超时的真因）。最终配置（与 browser_e2e 一致）：`--headless=old` + `--ignore-certificate-errors`
    + `--no-sandbox` + `--disable-dev-shm-usage` + `--disable-background-networking`。见 `screenshot._FLAGS`
    与 `report.export_pdf` 的 argv（均只影响本机浏览器进程隔离，不改变对目标请求语义，不越非破坏性红线）。
    ⚠️ `--headless=new` 在该 runner 会**挂死**（续71 已排除），务必保持 `old`。
  - **FOFA 标题归属过滤（`fofa.title_match`）的边界**：默认 `label` 档要求"标题某个 token
    与域名某个 label **完全相等**"，因此**连字符域名永不命中** —— `targ1-wallet.com` 的 label
    是整段 `targ1-wallet`，标题 token 被切成 `targ1`/`wallet`，永不相等 → **会被丢弃**。
    需要时用 `substring` 档放宽（能救回，但 `silvia-targ1.com` 那类也会跟着回来）。
- **fscan 适配的输出形态已用 fscan 2.2.1 实机校准**（2026-09-23 续12，Linux 实机抓取）：
  开放端口**不是**早年以为的 `[+] ip:port open`，而是这四种行形态之一 ——
  `[*] ip:port <service>` / `[*] http://ip:port` / `[+] http://ip:port code:NNN` / 老版本 `[+] ip:port open`；
  收尾固定打一行 `[*] 扫描完成，发现 N 个开放端口`（**0 个时也打**）。因此 `portscan._parse_fscan()`
  用三条**行首锚定**的正则取端口，再拿统计行的 N 做**交叉校验**：
  - 返回 `None` = 没装 / 起不来 / `rc≠0` / **解析数与统计行不符**（少了=换了格式，多了=认进了非 open 行）
    → 交回调用方回退 nmap / 内置扫描；
  - 返回 `[]` = 统计行明确写"发现 0 个" → 确实没有开放端口，**不必回退**。
  **必须行首锚定**：`[+]` 行的 title 段里会出现 `title:Redirecting to http://127.0.0.1:8081/system`，
  行中间乱搜 URL 会把**跳转目标**误记成端口。回归见 `tests/smoke.py [5e-0]`（8 组断言，内嵌真实样本）。
  *（此前的单条 `[+] ip:port open` 正则一条都匹配不上，且解析为空返回 `[]` 而不是 `None`，
  于是阶段只在 `found is None` 时才回退 → 静默漏报且不兜底；这就是本轮修掉的真缺陷。）*
- **fscan 默认 `-o result.txt`，而且是按「进程 CWD」落盘的**（续45 真跑踩坑：本机自编译 2.2.1 二进制
  + 回环实跑）：`scanner/portscan.py::fscan_scan()` 原先既不传 `-o` 也不设 `cwd`，于是**每一轮端口
  扫描都往启动扫描器的那个目录丢一个 `result.txt`** —— GUI/CLI 从仓库根启动，就是往**仓库根**丢，
  而且内容是**跨轮追加**的（累积了不同目标的 IP、服务 banner 与 URL），`git add .` 会顺手带进提交。
  修法（最小改动）：`fscan_scan(..., workdir=None)` 里 `cwd = workdir or tempfile.gettempdir()`，
  两处 `run_cmd`（含"老版本不认 `-nopoc`"的那次重试）都带上；阶段调用点传 `workdir=ctx.workdir`，
  产物落在 `logs/task_<id>_<时间>/`，与 dirmap / cert / screenshot 的产物同级。
  回归钉在两处：`[5e-0]` 第 ⑧ 组（给了 workdir 用它 / 没给也不能继承进程 CWD / 重试带同一个 cwd）、
  以及同段"引擎选择"的第二遍（`which` 认得 fscan 时，**阶段**必须把 `workdir` 传下去）。
- **fscan 上位：`tools/fscan/` 目录联接 + `settings.yaml` 填相对路径**（续45，用户点单）：
  本机 fscan 是**自编译**的（预编译 exe 会被 Defender 拦，本机非管理员加不了排除项 —— 阿里云镜像
  取 Go 1.25.4 便携 zip → `shadow1ng/fscan` 检出 tag `v2.2.1`（`95cc12e`）→
  `go build -ldflags="-s -w" -trimpath`，27.2 MB）。二进制放仓库外、`tools/fscan/` 做目录联接、
  `.gitignore` 排除（仿 dirmap 先例），`tools.fscan` 填**相对路径** `tools/fscan/fscan.exe`。
  端到端真跑（从**仓库外**的 CWD 启动，专门验"相对路径按项目根解析"）：日志
  `[portscan] 内置 TOP 端口扫描：fscan`、`127.0.0.1:8899` 落库、`result.txt` 落在
  `logs/task_<id>_<时间>/`、仓库根干净。fscan 不可用时仍按 `engine=auto` 退 nmap → 内置。
- **`-nopoc` 只管 POC 模块，管不到 fscan 内置的"服务插件"**：实测它仍会输出
  `[!] Redis未授权访问: ip:port` 这类**只读**探测结论。本模块**只解析"端口开放"的事实行，
  不采信它的漏洞结论**（漏洞初筛归 vulnscan 阶段）。
- **漏洞复核（P1-1）与 POC 置信度（P1-2）是两套独立机制**（2026-09-23 续12）：
  - `vulns.review ∈ "" | confirmed | false_positive`（`db.REVIEW_STATES`，非法值经 `norm_review()`
    归一为 `""`）。**判误报的行不参与"潜在漏洞"计数与报告主表**，但会在报告文末
    「已判误报（人工复核排除）」附录里列出（保留可回溯）。批量打标走 `db.bulk_set_vuln_review` ——
    它**自带连接用 `cur.rowcount`**，**不要**改成 `_exec()`（后者返回 `lastrowid`，UPDATE 上恒为 0，
    会让 `/api/vulns/review` 一直回 `affected: 0`，前端以为一条都没改；这个坑已踩过一次）。
  - `pocs.confidence ∈ low | medium | high`，由 `db.poc_confidence(path, meta)` 算：
    来源分（`builtin`=high / `user`·`nuclei`=medium / `imported`·`other`=low）× **内容型匹配器**
    （`word`/`words`/`regex`/`size`/`length`）是否存在 → 存在则**降一级**，且**只降级不升级**。
    与 `enabled` 不同（那是用户意图，`upsert_poc` **不覆盖**），`confidence` 每次同步都重算。
    `vulnscan` 只把它当**同批候选内的排序键**（指纹命中仍绝对优先），不做过滤。
  - **POC 的「有效级别」才是判据，模板里写的 `severity` 对导入 POC 不可采信**（续60 定口径）：
    根因在导入器 —— `tools/import_ref_pocs.py` 把参考项目的 `bug_level` **原样抄**成 nuclei
    `severity`（参考项目一律标 HIGH；实测 305 条 = high 290 / medium 14 / low 1），而它们绝大多数
    是"这页像不像某某 OA"的**指纹**规则、不是漏洞证明。判据一律走
    `db.effective_poc_severity(path, meta=None, declared=None)`：**只对 `imported` 来源生效** —
    声明级别按本条 `poc_confidence()` 的上限压级（`_CONF_SEV_CAP`：high→critical / medium→medium /
    low→low），**只降不升**；非 `imported` **原样返回**（内置/用户 POC 的声明级别照信）。
    这是一条**边界**：连 `other`（路径不在 `POC_DIRS` 的四个目录里）也不压 —— 不是"放过未知来源"，
    而是 `iter_poc_files()` 只遍历 `POC_DIRS`，`other` 在**实际扫描路径上不可达**；
    要连它一起压，得同时改口径与本节 / `CHANGELOG_AI.md` / `docs/poc-guide.md` 的说明
    （`tests/smoke.py [7w]` ① 已把这条边界钉住）。
    缺失级别按 `medium`、非法值按 `info`（与 `engine._norm_severity` 同口径）。
    **四处消费点必须统一用它**：① `engine.load_enabled_pocs()` 的执行闸；
    ② `db.bulk_set_poc_enabled()` 的按级别批量开关；③ `/pocs` 的级别列与级别分布统计
    （页面额外用 `declared_severity` 显示"模板声明 X"，`title` 里写清压级原因）；
    ④ `engine._vuln_of()` 的**入库级别** —— 漏改这一处，伪造的 high 仍会落 `vulns` 表并越过
    `min_severity` 结果闸（等于"闸门拦住了不执行、一执行就带假级别"）。
    `pocs.severity` 列**存的仍是模板声明值**（原始数据不篡改，只做展示/判据的换算）。
    实测效果：305 个导入 POC 有效级别 **100% low** ⇒ 注册表全开 + 默认 `skip_severities` 时
    **进 0 条**（清了 skip 也过不了结果闸），「自动灌 POC」因此**默认完全惰性**；
    **要放开必须人工复核后把模板整理进 `config/pocs-user/`**（那算 `user` 来源、置信度 medium），
    而不是去清 `skip_severities`。回归钉在 `tests/smoke.py [7w]`（含打桩退回声明值即红的变异证伪）。
  - **本地负样本校准：`tools/calibrate_pocs.py`**（续60）：起一个**合成靶场**（通用后台样板页、
    软 404 最坏形态、**刻意不含**厂商特征串），零外网请求逐条跑完 POC 并出可重复报告
    （`--json logs/poc_calibration.json`）。默认跑 `config/pocs-imported`；
    `--src scanner/pocs/pocs` 可跑内置那批。它**只报告不判分** —— 命中数不等于误报数，
    要人工看 `hits[]` 里的 `matched` 是不是通用词（实测 305 条导入命中 3 条、内置 7 条命中 0）。
    **不要**用它去自动改 `pocs.severity` 或自动启用 POC：那是"采信机器判分"，本轮恰恰在修这个。
- **⚠ 续144 更新：默认已是「开 + 深扫 + 递归 1 层」（`mode=deep`），下面这段是续9 当时的口径**
  （`quick` 档的行为描述仍然有效，只是不再默认）。**`dirscan` 的默认值于第十八轮（续9）反转为「开 + 只浅扫」**（第十五轮曾按用户要求默认关，
  现在用户要求"先用偏敏感信息的通用路径浅浅过一遍，看清结果再手动决定深度扫"）：
  `dirscan.enabled=true` + `dirscan.mode=quick`，只吃 `config/dicts/dirs_shallow.txt`
  （206 条，人工筛选、按价值排序，截断额度 `dirscan.quick_max_paths` 默认 150）→ **不发外部工具调用**。
  **深扫档**（`mode=deep`，续144 起就是默认；或任务选项 `dirscan_full`）才启用全量分层字典（12 框架桶 →
  语言栈 → 暴露面 → `dirs_big` 11882）+ dirmap 优先 + 后缀派生（`suffix_aware`），单站点上限 `max_paths`（默认 400）。
  两档都有的节流：只扫**不重复站点**（同任务内标题+长度相同的别名站跳过）。
  **补扫任务**（`POST /api/rescan`，名字 `补扫全目录-<月日>-<时分秒>`）只跑一个阶段，
  没有 probe 产物 → 用 `dirscan._sites_from_targets(ctx)` 从 `ctx.targets` 兜底，否则会"无存活站点"空跑。
  ⚠ 续145 起 GUI 上**没有**发起它的入口了（接口保留：漏洞「复查」与 smoke 的 8 处直调还在用），
  所以这条兜底如今只由"直接打接口 / 追加执行"触发 —— 别把它当死代码删掉。
  **目录递归（续30，默认关）**：`dirscan.recursive_depth=0`；深扫时对**目录型命中**
  （status ∈ {200,301,302,403}、路径最后一段不含 `.`、**第一段不以 `.` 开头**）继续往下打，
  字典用浅扫精选那份截断到 `recursive_max_paths`（默认 40）。**三重闸**：
  层数 `recursive_depth`、每站**跨层累计**目录数 `recursive_max_dirs`（默认 5）、每目录路径数。
  限目录数不能省 —— 一层递归 `+K×(3 软404基线 + M)`，K 由"扫出多少个目录"决定、不受字典大小控制
  （K=5/M=40 时 +215 请求，比第一轮 153 还多）。软 404 基线**按基址各算一份**（子目录有自己的
  统一跳转页，复用根基线会把子目录下的真实命中整片滤掉）；入库 `site_url` **仍是站点根**
  （它是折叠/跨运行去重/启发式分组的数据身份，写成子目录会把一个站点拆成十几行）。
  递归放在 `run()` 里对两种产物（内置 / dirmap 的 `only_fw` 补充）一视同仁 ——
  挂进 `_builtin_scan` 会让"装了 dirmap 的机器反而没有递归"。任务级勾选 `recursive_dir`
  只本次生效且**自动带上 `dirscan_full`**；策略里填了更大的层数就按策略走。
  刻意**不打开** dirmap 自带的 `conf.recursive_scan` —— 2026-09-25（续44）复核源码后更正口径：
  `recursiveScan()` **是死代码**（唯一引用那段早被整块注释掉），打开它**也不会递归**，只影响
  两句控制台文案与进度条长度；递归一律走上面的三重闸，额度才可预测。
  **本轮明确不做**：重写 dirmap 等价多语言字典引擎 / 运行时自动下载字典（见 `TODO.md`）。
- **FOFA 三种反查已于 2026-09-22 真实跑过**（key 已配）：
  `title="维保中心"` → 15 条（正常拓展）；`cert="example.com"` → **2 164 696 条** →
  被 `is_common_cert` 判为通用证书而放弃拓展（**这条真实数据就是阈值存在的意义**：
  没有它就会往资产库灌两百万条）。`title_threshold` / `cert_threshold` 默认 200 由此得到首个校准样本，
  仍建议按自己的目标继续观察。
- **FOFA 结果里大量行 `domain` 为空、只有 `host`（且可能是裸 IP）** —— 一律经
  `stages/osint.py::_domain_of()` 收口：空值 / 裸 IP / 含空格斜杠都返回空串，
  **裸 IP 绝不写进 `subdomains`**（IP 类资产归 portscan / probe）。新增 FOFA 类能力时请复用它。
- 目录结果的「重复长度」折叠**只作用于当前页**（分页条的「共 N 条」是未折叠总数）；
  任务详情页签则是一次性折叠（无分页）。
- 折叠键是 `(站点, 状态码, 响应大小)`，**站点身份取 `dirs.site_url` 并把尾斜杠归一**
  （`gui/app.py::_fold_dirs`）。2026-09-24（续24）修过一个真 bug：dirmap 解析行早先
  `site_url` **恒为空串**（dirmap 的 `path` 里存的是完整 URL），于是 a) 同站点的 dirmap 行
  与内置行永不互折（"同样大小的没过滤"）、b) **不同站点**的 dirmap 行同 (状态码, 大小)
  反而被误折成一条（跨任务 `/dirs` 真丢结果）；同一空串还污染了 `heuristics.py` 里
  按 `site_url` 分组的软 404 / 目录离群两条规则。修法是**在解析侧**用
  `scanner/stages/dirscan.py::_origin_of()` 从 URL 反推站点（写入侧修，不是展示侧兜底 ——
  `site_url` 是数据身份，跨运行去重键 `("site_url","path")` 与启发式都在消费它）。
  **回归用例必须用 `_parse_output` 真解析出的行**：旧用例自己手写 `site_url` 为真 URL，
  恰好绕开了生产形态，所以一直没抓到。
- **删除不是不可逆的了**：`db.delete_task()` 默认先调用 `backup_task()`，把该任务行与全部资产
  （sites/vulns/subdomains/dirs/csegs/ports）导出到 `data/trash/task_<id>_<时间>.json`；
  备份失败只告警、不阻断删除（GUI 的单个删除与批量删除都走 `db.delete_task`，无需额外操作）。
  即：**删除前请照常检查 `data/trash/`**，那里是"误删后唯一的救命稻草"。
- **dirmap 是 GPL-3.0，刻意不内联**（把源码拷进仓库会让整个仓库受 GPL 约束）：
  只保留 `tools/dirmap/` 目录联结 + 外部适配器；对它的 7 处源码修复记录在
  `tools/dirmap_fixes/README.md`（**该目录不含 dirmap 源码**）。
- **软 404 基线的并发重复计算已修**（2026-09-23 续11）：
  原先 `DirscanStage._builtin_scan._baseline()` 是"惰性填字典"且**没有同步**，`pool_run` 的
  20 个线程同时 miss 就各算一遍 —— 单站点 3 个基线探针实测膨胀成 **27~36 个**
  （占 dirscan 请求量约 18%）。现用 `threading.Lock` 把「查缓存 + 计算 + 回填」整体串起来：
  首个线程真算、其余阻塞在锁上，取得锁后命缓存，请求数**恒定 = 3 × 站点数**。
  （**不要**把它拆成"锁内查、锁外算"，那样等于没锁。）
  回归门禁：`tests/smoke.py [5p] 3c` 的断言由**上界** `≤ 3×workers`（60）收紧为**精确等号**
  —— 那个上界正是这个 bug 能长期藏住的原因。端到端浅扫实测：请求 **186 → 153**
  （字典 150 + 基线 3），命中 `.env` + `.git/config` 不变。
  *（AGENTS 早前记录的整轮 11 阶段数字 256/262、dirscan 177/183 是**修复前**的值，本轮未重跑；
  按新规则 dirscan 段应为 `150 + 3 × 站点数`。）*
- **界面颜色一律走 CSS 变量，规则体里不许出现裸 hex**（2026-09-24 续23）：
  `gui/static/style.css` 的四套主题（`:root` 深色默认 + `html[data-theme="light"/"ocean"/"violet"]`）
  靠**层叠**切换 —— 主题块只写「与深色不同」的项。此前 `tr:hover td{background:#1a2230}` 与
  `input/pre{background:#0d1218}` 是**裸值**，切到浅色主题后成了「深底深字」：
  实测对比度 **1.06:1 / 1.25:1**，表格悬停行的 URL、筛选框与输入框文字**直接看不见**。
  现在这两处以及 `.badge` / `.st-*` / `.sev-*` / `.bar` / `button` 各态 / `.topbar` /
  `.side-item` / `.error` / `.panel-toggle` 全部改用变量（46 个变量）。
  **门禁两道，改样式后必须都过**：① `py -3 tools/check_contrast.py`（四主题 x 34 项配对
  对比度，文字 ≥ 4.5:1、UI 控件描边 ≥ 3:1，另加主题块外**裸值守卫**，全绿退出码 0）；
  ② `tests/smoke.py [6n]`（复用同一个 `gate()`，口径与命令行一致）。
  新增主题或新增颜色时：**在 `:root` 声明默认值**，只在确实要变的三套主题里覆盖，
  然后跑门禁。纯装饰的分隔线 `--line` 刻意不参与 3:1 判定（理由见该脚本模块 docstring）。

- **`config/settings.yaml` 的 `fofa.enabled` 已于 2026-09-26 由用户改为 `false`**（与
  `scanner/config.py` 的 `DEFAULTS` 对齐）—— 2026-09-25 接管盘点时它曾是 `true`（用户为校准阈值
  主动开的），当时的结论是「默认就开、会花配额」；现在**默认不再碰 FOFA**。背景仍然成立：
  ① `settings.yaml` 被 **git 跟踪**，所以新克隆会继承它写的开关态；② 默认阶段集是**全 13 阶段**
  （CLI `-p` 缺省、GUI 未勾选时 `or list(STAGE_ORDER)`），`osint` 在其中；③ `config/keys.yaml`
  里有**真实 FOFA 凭据** + GitHub token。所以**要评估外部开销就看这一项**：改回 `true` 即恢复
  「每次默认任务都真查 FOFA 并花配额」（`docs/roadmap.md` 已登记续23~27 与 github 阶段）。

- **`auth=` 按"URL 主机发往谁"判，不是按"URL 从哪来"判**（2026-09-25 续43）：`http_request(auth=True)`
  的语义是"该请求发往**目标侧**，要带任务登录态"。jsmine 是**唯一的混合出口**模块 —— 页面请求
  按定义发往目标侧（种子 URL），但页面里 `<script src>` 绝对化后常指向**第三方**（实测 targ1.pro
  首页引了 `static.cloudflareinsights.com`），原实现一律 `auth=True` 等于把任务 Cookie/Authorization
  发给 CDN/埋点厂商。改为按 URL 主机判：`jsmine._is_self_host(host, protect)`（seed 主机 + 其注册域，
  后缀带 `.` 比、大小写归一，`nottarg1.pro` 不算 `targ1.pro` 子域）命中才带。新增出口模块/调用点时，
  先想清"这条 URL 最终发往谁"，别被"它来自目标页面"骗了（见 §5、§7 凭据红线）。

- **GitHub 线索里的"公共分流名单"只标注、只降不升、绝不丢（续111）**：`github_leak` 的
  `credential` / `apikey` 规则含义是"目标域名与关键字出现在同一份文件里"，而别人的
  gfwlist / clash / surge / smartdns / proxy rules 名单**整批抄入几千个域名** —— 这类命中是常态，
  **不等于目标方的凭据泄露**（2026-10-05 实测授权目标 targ3.ai：30 条 github 线索里绝大多数是这一类，
  真正值得人工看的只有 `user-1/targ3-yunduan-` 那种命名对得上的业务仓库）。判据 =
  `listy_public_list(path)`，**只认文件路径、不认仓库名**（同名仓库可能是真业务代码）；命中就把
  level 降为 `info`（**只降不升**，与 §7 POC 置信度那条同口径）并在 `detail` 写明理由。
  **为什么不直接丢**：丢了就是"静默" —— 人工想核对"这域名到底有没有被公开抄过"反而看不到，
  而线索表本来就是给人看的。两侧代价不对称 → **容忍漏标、拒绝误标**：漏标只少一句提示（线索与
  级别都还在），误标等于把真泄露降成 info（把结论藏起来）。回归在 smoke 的 github 组，
  含双向变异（打回"从不判"与打回"一律算名单"都必须让某条断言失效）。

- **共享主机 / CDN 段的反查清单不入库，但结论必须入库入报告（续110）**：`osint` 早就算得出
  "某 IP 挂了几百个域名 = 共享主机/任播段，不纳入域名资产"（阈值 `iprecon.max_domains_per_ip`，
  默认 30），**却照样把这几百条写进 `csegs.domains`，报告「C 段视野」原样抄一遍** —— 读者会把
  别人的 `*.workers.dev` 当成本项目标的资产面（targ3.ai 实测：两个 CF 段各 500 条）。现在超阈值时
  `domains` 留空、由新列 `csegs.note` 写明"命中多少 / 为什么没列"（老库靠 `_COLUMN_PATCHES` 补列）。
  **判据只在 `_c_segments()` 一处**，MD 与 HTML 共用 `report._cseg_cell()`，模板用
  `c.domains or c.note`。**不许**退回"展示层再过滤一次"：那等于把同一判据抄到第 N 个出口。
  回归 `[8h]` ②（含"阈值放松到 1000 后必须照旧入库"的变异 —— 否则断言恒真）。

- **CDN 判定不能只认 CNAME**（2026-09-25 续43）：Cloudflare 这类**任播** CDN 常常 A 记录直接解析到
  边缘 IP、**CNAME 链为空**（实测 targ1.pro / admin.targ1.pro / app.targ1.pro 都解析到
  `172.66.40.229` / `172.66.43.27`）。只按 `cdn_cname.txt` 判会一律标成"非 CDN"，既看不出走 CDN，
  又会让 `portscan` 去打 Cloudflare 边缘节点、得出与本项目标无关的"30 个端口开放"。故 `cdn.match()`
  现在两条判据：**CNAME 优先**（厂商特征明确）→ 未命中再看 `cdn_ips.txt` 的**任播 IP 段**
  （`match(cname_chain, settings, ips)`；subdomain / extdom / GUI 解析三处都把解析 IP 传进去）。
  **续110 补上第四处、也是漏得最狠的一处：`portscan` 的兜底分支**。判据当时只认"`net` 里有没有
  这条域名"（`net` 由 `subdomains` 表回填），而**任务直接给的那个域名/URL 压根不在 `subdomains`
  表里** → 拿着 Cloudflare 边缘 IP 把 1-65535 全扫一遍。2026-10-05 对授权目标 targ3.ai 实跑抓到：
  26 个"开放端口" = CF 支持的 13 个端口 × 2 个任播 IP、banner 全空、两轮集合逐字节相同；
  同一次扫描里 `studio/www.targ3.ai`（在表里）却被正确跳过 —— **同一个动作在两处各写一遍判据**。
  现在兜底分支复用 subdomain 那一套（`dnsq.resolve_detail` + `cdn.match` 双判据），命中就跳过并
  点名；`dnsq` 解不出来时**退回系统解析器**（加判定不许把原本扫得到的主机挡掉）。
  线上复核：修完对同一目标重跑 `portscan` → 4 秒、0 个端口（原来 5.5 分钟 / 26 个）。回归 `[8h]`。

- **资产列表的「同域名一行 / 默认只看解析成功」都是显示口径，入库一条不动（续112）**：
  `targ3.ai` 与 `www.targ3.ai` 各出现两三行（来源 `js:mine` / `promote:js:mine` / `subfinder`），
  看着像两三个资产；而二十几个解析不了的 JS 碎片占满整屏（用户 2026-10-06 的两条点名问题）。
  判据集中在 **`scanner/db.py` 一处**：`SOURCE_RANK_CASE`（被动/爆破 > 目标自带 > 被动 > 归属追加 >
  JS > 外部情报）+ `RESOLVED_WHERE` + `other_sources_by_domain()`；`page_assets(dedupe_domain=True)`
  把去重下推成**与外层同一份 where/参数**的内层窗口函数子查询，所以「共 N 条」与列表、翻页同口径
  （内层外层不同源＝本项目反复踩的「共 N 条却翻不出 N 条」）。
  被去掉的来源**必须在页面上写出来**（「另见于 …」），被收起的条数**必须报出数字**（`显示未解析（N）`）
  —— 不报就等于让人以为「没有这些域名」。
  ⚠️ 这类「默认收起」的开关，翻页/切标签链接必须**延续当前视图**：第一版把条件写反了（默认收起时
  翻页却带 `nores=1`，第 2 页突然把碎片全放出来，同一个视图两页口径不一致），现在链接片段由
  `gui/app.py::_nores_state` 一处算好。第三方噪声走 `config/dicts/js_thirdparty.txt`（**写入侧**，
  续22 那条「黑名单永远穷尽不了」仍然成立）。回归 `[8i]`（含 `RESOLVED_WHERE` 打回恒真的变异）。

- **WAF/CDN 的整站拦截页不是「目录发现」：按厂商标题文案滤，且滤掉几条必须写进日志（续112-F）**：
  实测 targ3.ai 走 Cloudflare 时 `wp-config.php`、`wp-login.php`、`xmlrpc.php` 与它们的
  `.bak/.zip/.old…` 派生名**各留一行** `403 / 4910 / Attention Required! | Cloudflare` —— 几十条假发现
  铺满「目录」页签（用户：「这两个大小不也一样吗 为什么两个都显示了？」）。两条独立判据，各有适用面：
  ① `is_block_page()`：标题命中 `config/dicts/waf_block_titles.txt` 里的**厂商专属文案**（CF 页面带
     ray id，两次请求正文 md5 不同、长度相同 ⇒ 按文案判比按哈希可靠）。清单**刻意不收** `403 Forbidden`
     / `Access Denied` 这类通用词：nginx 默认 403 页标题就是它，而「敏感文件存在但被 Web 服务器拒绝」
     正是要报的发现，收了等于自吃结果。
  ② `is_uniform_block()`：随机探测路径**自己也回 403 且同内容**（md5 或长度相同）时按基线滤；
     基线里没有 403 样本 ⇒ 一律不滤（空签名返回 False —— 没有可比的东西就当没证据）。
  ③ **dirmap 那一路判不了，但不静默**（续113 登记）：dirmap 的产物行只有
     `[状态码][content-type][大小] URL`，**没有标题** ⇒ 文案判据无从下手。这里**刻意不**给 dirmap
     行"补一次请求取标题"，也**刻意不**按"同大小重复 N 次"猜（①的弯路已记过一次）；只由纯函数
     `dirmap_blind_rows()` 数出「无标题的拒答」并在日志里写明「这 N 条**未做拦截页判定**、请人工确认」。
     表现：装了 dirmap 的机器上，内置补充扫描那一路滤掉的 CF 页会照旧少掉，而 dirmap 自己写来的
     403 会留在结果里 —— 日志会说清是哪一批、为什么。
  两类条数分别攒进 `waf` / `blocked`，本轮结束按站点写一句日志：只写「目录发现 0 条」会让人以为
  站点没东西，而事实是「整站被同一张页挡掉了」，下一步要做的完全不同。
  ⚠️ 走过的弯路记下来：先试过「同站点 (状态,大小,标题) 重复 ≥N 条就整组丢掉」—— N=3 会漏掉 targ3.ai
  的两条一组，N=2 又会吃掉「/admin 与 /admin/ 回同一个后台登录页」这种真实重复。按**厂商文案**判是
  有依据的，按计数判是在猜。回归 `[8j]`（⑦⑧ 两面都钉：CF 式拦截页收掉、nginx 式真 403 原样入库；
  ⑨ 钉住 dirmap 那一路"没标题⇒不滤但明说"，含"漏掉标题条件"与"run() 没接线"两种变异都会红）。

- **链接（`urls` 表 / crawl 阶段）与目录（`dirs`）是两件事，不许合并（续198）**：
  `dirs` 是**字典猜出来的路径**（我们要证明它存在不存在），`urls` 是**页面里本来就写着的链接**
  （站点自己暴露的入口，一定存在）；`jsmine` 挖的是 **JS 文件里**的域名与接口（又是一回事）。
  判据分散在三处：收集在 `scanner/crawl.py`（`extract_links` / `same_site` / `looks_like_page`），
  `host/path/query` 的拆法只有 `db.insert_urls` 一处（**带不带参 = `query` 空不空**，这是
  "是不是注入面"的唯一判据），喂给漏洞检测的链接由 crawl 阶段算好放进
  `ctx.results["crawl_feed"]`、vulnscan 只管消费（每站 `crawl.max_feed`、总闸 `crawl.max_feed_total`）。
  三条红线在 `scanner/crawl.py` 顶部：**只发 GET**；`<form method="post">` **只记录永不提交**；
  **默认不跟外链**（`same_site`）。阶段**出厂关闭**（它一定会发请求，开关必须留在用户手里）。
- **3xx 站点补「跳转后」取证：只新增列，绝不改写那一跳的实况（续112-B）**：满屏
  `301 / 标题「301 Moved Permanently」`看不出落地页是什么（httpx 默认**不跟随**重定向）。现在
  `probe.attach_redirect_info` 只对 3xx 条目**再发一次允许跟随的请求**，把最终 url/状态/标题写进
  `sites` 的 `redirect_*` 三列；`status`/`title`/`length` 保持原样 —— 把 301 覆盖成落地页的 200
  等于谎报「这个端口直接回 200」，而 301 与 200 的安全含义不同（跳转链本身是信息）。
  落地页取不到 ⇒ 三列留空、页面原样显示那一跳（**不编数**）。
  **续197 改了"落地页没标题"这一档**：原先退回第一跳那句「301 Moved Permanently」，但那是
  **服务器默认跳转页文案**（CloudFront / nginx 的 301 页都长这样），显示在「标题」列等于拿中间件
  默认页当站点身份（主理人报的就是这个现象）⇒ 现在**跟到了就只用落地页标题**，落地页确实没有
  就留空（页面 `-`），`note` 写明「落地页无 title」。两条补强：落地取证用 `utils.page_title`
  （`<title>` 取不到再退 `og:title`/`twitter:title`/`meta name=title`，SPA 首屏常见；
  **不**兜 `<h1>` —— 那是正文标题，属"看起来像"）；截图阶段把渲染后的 `document.title` 回填
  `redirect_title`（`db.set_site_redirect_titles`，只补空值）。显示口径集中在 `utils.site_redirect`
  （`301 → 200` + 标记「跳转后」），GUI 两处与报告 MD/HTML 共用同一个函数，四种出口不会各说一套话。
  它同时吃 dict 与 `sqlite3.Row` —— **`Row` 没有 `.get()`**，这是本项目第五次栽在同一处。
- **引导口令只存派生值：不落盘、不回显、留空不改（续113）**：`config/settings.yaml` 被 git 跟踪，
  原先 `gui.token` 是明文，而「策略配置」页又把同一个字段 `value=` 回显到输入框里 —— 口令于是
  同时存在于**仓库**与**页面源码**两处。现在保存口令只写 `gui.token_hash`（`users.hash_password`
  的 pbkdf2 派生值）并把明文列清空；输入框改成 `type="password"` 且**永远不回显**；
  **留空＝不修改口令**（"清空输入框"绝不该把管理员锁在门外），此时若已有哈希就顺手清掉残留明文。
  唯一保留的兼容分支：老配置里只有明文、还没有哈希时，登录**仍然认明文**（常量时间比较）
  —— 不做"启动时自动改写用户配置文件"这种静默写盘，改为每次启动打一条催迁移的 warning。
  回归 `[8n]`：派生值验得出新口令、验不出旧口令；端到端（哈希配置下旧明文被拒）；
  落盘字典里不含任何明文；模板不再回显（源码红线：不许再把口令绑到 `value` 上）；
  以及把补丁打回"直接存明文"的变异必须让断言变红。
  ⚠️ 这条与续109 是两件事：109 切断了"会话密钥由口令推导"（伪造 Cookie），113 切断的是
  "口令本身外流"。两条都要在，缺一条另一条就白做。

- **"不是域名"的 JS 碎片按**注册域是否存在**判掉，DNS 无结论一律放行（续113）**：
  `chat.floating.open` / `network.protocol.name` / 那串欧盟国家码 `at.be.bg.hr…gb` 是 JS 里
  **点号连接的成员访问链**，不是域名。它们能活过形态闸门，是因为末位 label
  (`open` / `name` / `gb`) 恰好是合法公共后缀 —— 纯语法判据到此已经无能为力（PSL 判据本身没错，
  再放宽就会吃真资产）。真正的证据在 DNS：**宿主自己解析不到（`nxdomain`）且它的注册域查 NS
  也返回 NXDOMAIN** ⇒ 这个"域名"从没被注册过，压根不是资产。
  - 判据只此一处：`extdom.zone_is_absent()` / `filter_absent_zones()` / `drop_absent_zones()`，
    **三个调用点共用** —— jsmine 入库前拦（根本不进库）、`resolve_extended()` 解析回填后清已有行、
    以及 GUI 的 `POST /api/domains/resolve`（页面上点「解析」那条路）。第三条是本轮补的：
    该路由自己内联做解析、原先根本不经过 `extdom`，于是出现"流水线里清得掉、页面上点却清不掉"
    —— **新增入口时先问"这条路有没有接上同一处判据"**（回归 `[8m] ⑥` 用
    `inspect.getsource(app.view_functions["api_resolve_domains"])` 钉住，比全文件 grep 强）。
  - **只有 `absent` 算数**：`dnsq.zone_state()` 只看 rcode（3=absent、0=exists、其余=unknown），
    因为现成的 `dnsq.query("NS")` 把"确实没有"和"问不到"都返回空列表，拿它当证据会在
    DNS 抖动 / 内网无外网解析器时**把真资产判掉**；`unknown` 一律放行（丢资产比留噪声严重）；
  - 不用"子域名解析不到"当依据：真实的 `api.internal.example.com` 常常也没有 A 记录，
    但 `example.com` 有 NS ⇒ 必须留。所以判据落在**注册域**这一层；
  - 只清 `js:*` / `promote:js:*` 来源：`osint:*`（C 段 / FOFA / 证书反查）的域名是第三方
    数据库里的实际观测，"现在解析不到"不是"它不是资产"的证据。
  - 开关 `jsmine.drop_absent_zone`（默认开）；关掉只是让这些碎片回到库里，页面仍会默认收起
    未解析的行（续112-D 那道显示门）。
  - ⚠️ **判不掉的残余（实测，别当成漏修）**：`network.protocol.name` 与 `ui.action.click` 仍在库里 ——
    `name` / `click` 是**真注册的 gTLD**（有 NS、rcode=0），按"注册域不存在"这条判据必须放行。
    要在这一层拦住，就得允许"末位 label 是 gTLD 但整串不像主机名"的语法猜测 —— 那会连带吃掉
    `shop.zip` / `app.click` 这类真域名。**宁可留两条噪声，也不丢一条资产**（与 fail-open 同方向）。
  回归 `[8m]`（rcode→状态三向映射 + "NS 的 rdata 恒空、不能看记录是否非空" + 按注册域缓存的
  查询次数 + 开关关掉零查询 + jsmine 端到端不入库 + 只清 `js:*`/`promote:js:*` 且只清 `nxdomain` +
  把 `unknown` 也判成不存在的变异必须让断言变红 + **GUI「解析」路由的接线**）。

- **导入 POC 的放开只能走「人工逐行复核」这条道（续114）**：305 条导入项的有效级别被压到 `low`
  （§7「POC 置信度」那条），要放开某族就得把它们移进 `config/pocs-user/` —— 这句话此前**没有落点**，
  实际结果只会是"要么一直全关，要么有人手改文件全开"。现在由 `tools/poc_review.py` 承重：
  `--families` 看族分布 → `--family <关键字>` 出工作表 → 人工在「复核」栏写 `ok` → `--import` 只搬这些行。
  三条红线（回归 `[8o]` 逐条钉住，含"把只认 ok 放宽成连 no 也认"的变异）：
  ① **机器不判定**：复核栏空着 / 写 `no` / 写别的 ⇒ 一条都不动，也没有 `--all-ok` 这种旗标；
  ② **不改原始数据**：`config/pocs-imported/` 里的文件一字不动，搬进去的副本只在**文件头**追加出处
     （`# 人工复核后启用（…日期）`），且**不覆盖**同名目标（人工改过的不能被重跑盖掉）；
  ③ **不越界**：工作表的「文件」列被改成导入目录外的路径就拒绝 —— 那等于绕过全部判据往 `pocs-user/` 塞东西。
  工作表最该先看的是 **「同指纹」** 列：本轮实测 **305 条导入 POC 的匹配器只有 251 种**，
  **79 条与别人共用一字不差的判据** —— 14 条泛微 e-cology（声明成 deserialize / RCE / SQL 注入 /
  任意用户登录等**不同类型**）、7 条致远、5 条用友、**4 个 Confluence CVE** 全都只匹配
  "这是不是这个产品"。这类条目的真实含义是**产品识别**，不是漏洞证明：复核一条=复核整组，
  放开一条也不会带来额外信号。（`tools/poc_review.py --dupes` 随时可复算这个数。）

- **「外部情报源实际可用性」面板：把"跑不了"从任务日志提到配置页（续114）**：
  `gui/app.py::external_source_panel(settings)` 逐段给出「策略开关 / 需要凭据 / 凭据已配 / 现在能跑」+
  `keystore.status()`（密文与否、本进程解没解锁）。起因是本轮**真出过一次误判**：我把
  「这台 Linux 没有 GitHub 的 key」当事实报过，而 key 一直配在 `keys.enc.yaml` 里，真因是
  **发起任务那个进程环境里没有口令**（续98 只在启动时解锁一次）—— 「有密文但没解锁」与"没配 key"
  在日志里长一个样，处置动作却完全不同（补环境变量 vs 补凭据）。三条纪律：
  ① 只报**有/无**，值一律不出现在返回结构与 HTML 里（回归 `[8p]` 往配置里塞五个哨兵值再搜页面）；
  ② 取凭据必须走**各家自己的** accessor（`fofa.credentials` / `shodan.credentials` /
  `quake.credentials` / `github_leak.load_token`），不在面板里重抄一遍 `keys.<段>.字段` 路径
  （打桩成"恒有值"时断言必须变红，否则面板其实是硬编码）；
  ③ 免 key 的段（IP 反查 / crt.sh / KEV）照样列出并写明"还要能出网" —— 「有 key」≠「跑得动」。

- **资产页的「按任务筛选」与漏洞页同口径；下拉全集＝「这张表里有行的任务」（续112-E）**：
  六个跨任务资产页（站点/端口/目录/C 段/子域名/拓展域名）共用 `_task_scope()`（`?task=<id>` →
  `task_id=?`，并进调用点**已有的** where/参数链，不另开一份判据）与模板 `_taskpick.html` 一个文件；
  数据源 `db.tasks_with_asset(table, owner_id)` 沿用续55 的结论（不用 `list_tasks(limit=1000)`，
  否则老任务在下拉里根本选不到），且 `table` 只接受 `_ASSET_PAGES` 的白名单键 —— 表名要拼进 SQL，
  传别的名字直接 ValueError。两条容易漏的口径都有断言：
  ① 空值 / 非数字 / 0 一律当「不筛选」，**绝不能筛成空表**（地址栏留个空 `?task=` 就把整页资产清空，
  看着像资产没了）；② 筛一个「这张表里没有行」的任务时，下拉仍要显示当前任务
  （`#N（这张表里没有它的行）`），否则筛完看起来像回到了「全部任务」。
  回归 `[8l]`。


- **afrog 的两条实测事实（续119，都推翻了我先前的判断，记下来免得下一轮照错的做）**：
  ① 它的 `fingerprinting` 目录（130 个文件）里**没有任何 favicon / mmh3 匹配** —— `mmh3(` 零命中、
     没有一条规则请求 `/favicon.ico`；`icon_hash` 只作为文字出现在 3 个文件的 `description` 里。
     "它的指纹含 favicon 哈希"这个说法是想当然，**错**。
  ② 那个目录里**混着一条真 RCE**（`hfs-rce-cmd-exec.yaml`：GET 触发目标执行 `ipconfig`，
     CVE-2014-6287）⇒ "这一类目录都是只读识别"这个前提**不成立**，任何按需导入都必须逐条读请求语义。
     另外 21 个文件是 `type: tcp` 原始探测（我们引擎只有 http，**不可移植**）、4 个聚合文件含
     108 个命名条目（要拆开重建，不是转换）、9 个文件带 `brute` 路径清单。
- **"能装"与"会被用"是两件事（续119 加一档 `toolmgr.wired`）**：`TOOLS` 只回答"能不能自动下载并
  默认过官方 SHA256"，`wired(name)` 回答"扫描路径到底调不调用它"。混为一谈的表现是 —— 一个没人
  调用它的二进制在页面上写着"未找到（自动使用内置兜底）"，而**没有任何东西在为它兜底**（假话）。
  分档之后：`status()` 文案按档走；`run_bootstrap` 记 `kind="pending"` / `auto=False`（清单看得见、
  给一条显式命令，但 `--install` 不顺手拉 25 MB）；`cli --check` 不列它（那列语义就是"走内置兜底"）；
  「外部工具」页数量按实际算、不再写死"三个"。当前唯一的非 wired 成员是 `afrog`。回归 `[8x]`
  （含"wired 打回恒真 ⇒ 文案与自动层两条判据同时变红"的变异，且**桩掉 which/run_cmd 两个分支都测**，
  不吃本机装没装 —— §6.2）。
- **能自动下载的边界＝`toolmgr.TOOLS`；不能的进 `toolmgr.MANUAL`，两者必须不相交**（2026-09-27
  续59-3）：`TOOLS` 的语义是"**能自动下载、且默认必须过 release 自带 SHA256 才落盘**"，
  所以凡官方**没有"可下载且带官方校验和的单二进制产物"**的工具，一律**不得**塞进 `TOOLS`
  —— 塞进去等于让它们绕过那条校验红线（`tests/smoke.py [7p] ⑨` 用 `TOOLS∩MANUAL=∅` 不变式 +
  变异钉住）。**2026-09-27 实测**（查官方发布页 / GitHub API）三个只能手工装：
  `nmap`（官方发在 `nmap.org/dist`，**不在** GitHub release；Windows 只有 NSIS 安装器、
  Linux 只有源码包、macOS 只有 dmg —— 自动装＝跑系统级安装器）；`fscan`（官方**不发二进制**，
  本仓既定做法是 Go 自编译）；`dirmap`（最新 release 的 `assets` 是**空数组**、无 checksums，
  且是纯 Python 项目需 pip 依赖）。这三个由 `MANUAL` 如实展示在 GUI「外部工具」页与 `cli --check`
  末尾（含原因 + 指向 `tools/scanner/README.md`「手工安装」），**本框架不为它们发任何请求**。
  新增"要不要纳入自动安装"时，先问一句"官方有没有带校验和的单二进制产物"，没有就写进 `MANUAL`。

- **外部引擎的预算覆盖已于续128 补到"预估 + 可选硬上限"，但仍不是逐请求记账**：
  `extcost` 算的是"要不要起它、起之前预计它发多少"，`limits.external_max_*` 设了就会咬
  （afrog 不起进程 / 端口扫描退回内置）。**仍未覆盖**的是引擎内部的并发细节 ——
  afrog 的 `-c/-rl/-rlt` 由 `scanner/afrog.py::CEIL` 夹住、fscan 的线程数由我们传入，
  但"它内部究竟逐条发了多少"要真记账就得让流量走我们自己的出口（本地转发），未做，也不假装做了。
- **afrog 适配器不覆盖请求预算**（续121，客观边界）：`throttle` 管的是"我们起几个子进程 /
  发几次 HTTP"，**管不到外部进程自己发多少请求**（fscan 同理）。续149 起 afrog **默认开**
  （用户点单），但真起进程要过三条闸门（开关 + PoC 目录里有只读模板 + 本机装了二进制），
  站点数与 `-rl/-rlt/-c` 全部封顶（策略里填再大也超不过 `scanner/afrog.py::CEIL`），
  且日志里明写"不经本任务请求预算"。
  要真正纳入预算，得让它的流量走我们的出口（如本地转发），目前**没做，也不假装做了**。
- **afrog 的命中只进 `vulns` 表**（info/low 级），不反查成 `sites.tech` 标签：那需要一张
  PoC→标签 的映射表，没有表就不猜（组件识别的正路是续120 那份复核过的外置指纹表）。

- **迁移包默认零凭据，但"带不带"是三个独立开关、不是一句提示**（续136，`scanner/migrate.py`）：
  导出默认只有 `tasks` + 九张资产表。`users`/`nodes` 的口令与令牌哈希、`config/keys*.yaml`、
  `edge_auth.yaml` 要 `--with-users`；`tasks.options["auth"]`（扫目标时带的 Cookie/Authorization，
  `cli/client.py` 存进去的）要 `--with-task-auth`。**第三条是本轮实测找出来的**：只把账号表挡在
  门外，"只导任务表"照样会泄密。包默认落 `data/export/`（`.gitignore` 覆盖的唯一目录）且 `0600`
  —— 权限位不由"这次恰好没带口令"决定。`session.secret` **连 --with-users 也不带**（带了＝旧会话
  在新机器上继续有效）；`audit_log`/`login_fails` **永不进包**（审计是"那台机器上发生过的事"，
  跨机合并会把来源搅混）。新增"能带走数据"的出口时先问一句：**这份文件在别人手里等于什么**。
- **`db.import_task_assets()` 只服务"一份快照属于同一个任务"**（续136 实测的坑）：它会把每行的
  `task_id` 一律改写成传入的号、`id` 一律丢弃。多任务场景直接传整份资产的结果是 **44 条变 308 条**
  （每个任务都拿到别人的资产，页面上一条都分不出）—— 复用它必须**先按原 `task_id` 切好**。
- **`tasks.log_file` 存的是绝对路径**（`runner.py` 写 `str(log_file)`）：进任何要外发的东西都必须
  转相对形；而还原要按**本机 BASE_DIR** 做成绝对形、不能留相对 —— 消费方是 `Path(...).parent` 这类
  用法，相对路径会按**进程 CWD** 解析（从仓库外启动 GUI 就跑偏，与 §2 那条 `which()` 形状问题同源）。

- **迁移页（`/migrate`）比 CLI 少三个开关，而且导入侧按包内容拒绝**（续138，`gui/app.py`）：
  账号口令哈希、节点令牌哈希、凭据文件、任务登录态 —— 页面上**连复选框都不画**，服务端硬写 `False`；
  回归 `[8am]` 用**伪造表单字段**（`with_users=1`）打它，钉住"这是服务端写死的，不是页面没画所以不会传"。
  反方向同理：上传的包**只看 `data` 里真有什么**（不看 `includes` 的自我声明），含账号/凭据/登录态
  一律拒收并指回 CLI —— 浏览器里点一下就把"能登录别人系统的东西"落进本机 `config/`，这个界面不该有。
  导入是"预检 → 一次性确认令牌（10 分钟、用过即废）"两步，`session` 里只存路径与令牌，
  确认成功后删掉上传副本（回滚点是那份整库快照）。
- **迁移包加密：口令只有环境变量这一个来源，魔数与凭据文件分开**（续136 第三条边界，
  `scanner/migrate.py` + `scanner/keystore.py`）：`--encrypt-bundle` 需要 `CTFSCANNER_BUNDLE_PASSPHRASE`，
  没设就**在写任何文件之前**停住 —— 做"没给口令就默默导一份明文包"是最坏的一种降级（用户以为
  包是加密的，发出去的却是明文）。包用 `CTFSCANNER-BUNDLE-V1`、凭据文件用 `CTFSCANNER-KEYS-V1`，
  两个魔数**不许并成一个**：拿错文件必须在头部比对就被说破，而不是解出一团乱码再报"不是 JSON"
  （那种报错会把人引向"是不是口令错了"）。给了 `--export-scan FILE` 就照用户的文件名写、不改扩展名
  （识别本来就靠文件头）。报错与审计里都不许出现口令本身。
- **`--with-logs` 的边界是"路径归属"，不是"文件大小"**（续136）：只带 `LOGS_DIR` **之内**的日志
  （判据用 `resolve()` 后"LOGS_DIR 在不在 parents 里"，不是 `startswith` 字符串比较）；越界的整份
  跳过并计数，**不截断**（截一半的日志看起来是完整的，而人正是靠日志判断那次扫描跑了什么）。
  导入侧同一条规矩再守一遍：包里的 `log_rel` 是**输入**，必须校验它解析后仍在 `LOGS_DIR` 内
  （`_safe_log_target`），越界就 `refused` 并打警告 —— 包是别人给的，它想往本机任意位置写文件。
  包内键一律**相对 LOGS_DIR**，与 `log_file` 的相对形分开：两处必须是同一个值，否则日志
  "在包里但导不出来"（本轮实测过一次）。
- **随机后台路径买的是"找不到入口"，不是"进不来"**（续138，`scanner/webpath.py`）：三条口径不许松。
  ① 猜错前缀一律 `404` + **空响应体**，不 302、不 401 —— 重定向会把正确前缀写进 `Location`，
  401 会宣告"这儿有个后台"，两者都把本功能的收益还回去。② 前缀**绝不落盘**：`config/settings.yaml`
  被 git 跟踪、仓库公开，而"重启还能找回来"的价值远小于泄露面；用户原话就是"每次启动随机生成"。
  ③ **降级必须说出来**：`CTFSCANNER_WEB_PATH` 写了个不合格的值（`//`、`..`、大写、不带前导 `/`）时
  不许静默当成"挂根路径" —— 根路径正是本功能要消掉的那个暴露面，静默降级＝用户以为随机还在。
  现在是不合格 → 照旧随机 + 打印原因（`_web_base_for` 返回 `(前缀, 额外打印行)`）。
  ⚠ **续193 例外（主理人 2026-10-15 点单，开发期临时）**：`webpath.DEV_PIN_BASE` 非空时，
  `_web_base_for` 在随机分支**之前**返回这个固定值（形状仍两层各 10 位，横幅改口"开发期固定值"）
  ⇒ 上面 ②「绝不落盘」在开发期被**主动放弃**（值进公开仓库）。恢复随机的唯一动作＝改回 `None`；
  门禁 [8ak] 钉住「摘掉 pin 必须回随机且不等于 pin」。**开发收尾时必须改回**，届时把本例外删掉。
  ⚠ 文案红线：任何地方都不许把它描述成"更安全/别人进不来"，它不替代认证（§5.10）。
- **已知边界（续194）**：大厂证书的判定是「SAN 条数超 `ctlog.max_domains_per_cert`（默认 50）
  ∪ 名字命中第三方清单」—— `sni.cloudflaressl.com` 这类 Cloudflare 通用证书形态不在清单里，
  只靠条数上限兜；条数没超上限的共享证书仍会被当成同证书证据。要更严需专门的证书厂商清单，
  那是新数据文件、新产地，留待点单。
- **启动日志落 `LOGS_DIR/server.log`，但随机后台前缀仍然绝不落盘**（续145，`scanner/log.py`）：
  `attach_server_log()` 给 `gui` logger 与一个 `propagate=False` 的 boot logger 挂**同一个**
  `RotatingFileHandler`（2MB×3）。三条不许松：① **同一个 handler 实例** —— 两个 handler 各写
  同一个文件时滚动判定各算各的，A 刚滚出 `.1`、B 再滚一次就把它挤成 `.2`（历史被覆盖）；
  ② 按 `baseFilename` **去重** —— `serve()` 同进程可以被调多次（回归 `[7i]` 真调三次），
  不去重就是每条日志写 N 遍，而 `get_logger` 那句"有 handler 就早退"挡不住事后补挂；
  ③ 含**本次随机前缀**的行一律不写进文件（续138 的口径没松），判据是**内容**不是行号 ——
  `[8at]④` 用"往横幅额外塞一条含前缀的行"做证伪，只钉第一行就是位置假设。
  扣掉那一行必须**说出来**（文件里留一句"刻意不写进本文件"），静默少一行会让人以为日志坏了。
  另两条：横幅仍是 `print()` 的**逐字**输出（`say()` 只是多落一份），改成 logging 的带前缀格式
  会打红 `[7i]10b`（逐行恰好一次 / 无重复行）与 `[8ak]⑩`；写不出日志（父路径是文件、目录不可写）
  ⇒ **说出来 + 照常启动**，那句原因里不许带绝对路径（`OSError` 的字符串里有 ⇒ 只用 `strerror`）。
- **逐请求访问日志单独落 `LOGS_DIR/access.log`，且必须带前缀打码**（续146-附3，
  `scanner/log.py::attach_access_log`，`serve()` 调用）：`logs/server.log` 里**一条逐请求行都没有**
  （实测 69 行全是横幅），因为 `werkzeug._internal._log()` 自己往 logger 上补了一个往 stderr 喷的
  `_ColorStreamHandler` —— 那份流量从来没进过任何文件。三件事互相牵制：
  ① **静音终端与落盘是同一个动作** —— `_log()` 只在本进程**第一次**记日志时判 `has_level_handler`，
     判不过才补流式 handler；我们先挂上 INFO 级文件 handler，它就不补。为兜住"已经先记过日志再调用"
     的顺序，这里还会摘掉该 logger 上已有的**流式** handler —— 判据必须是"`StreamHandler` 且
     **非** `FileHandler`"：`RotatingFileHandler` 本身就是 `StreamHandler` 的子类，少写后半句会把
     自己的通道摘掉（现象：文件在、只是每一行少一半）。
  ② **前缀打码是硬约束不是整洁偏好** —— 它记的是客户端送来的**原始请求行**（`log_request` 用
     `self.path`），头一段就是本次随机后台前缀，直接落盘违反续138。`PrefixMask` 抹整串**也抹单层
     片段**（只抹整串时，有人探 `/第一层/` 就会把第一段原样留在文件里），并剥掉 Werkzeug 给非 200
     行加的 ANSI 码（Linux 上 `_log_add_style` 恒 True，否则文件里是 `^[[33m…^[[0m` 那种垃圾字节）。
     抹过的位置要留一个 `<前缀已脱敏>` 的形状（静默少一段会让人以为日志坏了），且抹完**仍要能看出
     打的是哪个页面** —— 否则这份日志没有价值，就会有人把它关掉。
  ③ **同进程第二次 `serve()` 换前缀时掩码集合必须跟着换** —— 按 `baseFilename` 去重只挡"重复挂"，
     挡不住"新前缀没进掩码集合"（`[8ax]⑦` 打的就是这个）。
     另两条显式动作不能省：`propagate=False`（否则任何给 root 挂过 handler 的库会把访问行喷回
     终端，"静音"就成了看运气的承诺）、`setLevel(INFO)`（不等 werkzeug 惰性设置 —— NOTSET 继承
     root 的 WARNING ⇒ `info()` 整个丢掉，现象是"日志文件是空的"）。与 `server.log` **分文件**：
     一个是"服务做了什么"、一个是"谁打过来"，混在一起两边都难读。写不出来 ⇒ 返回
     `(None, strerror)`、**不抛**、不动已有 handler，那句原因里不许带绝对路径（§0.3，续145 同口径）。
- **"缺配置"必须有一句汇总，否则后台启动等于静默残废**（续145，`gui/app.py::_boot_gaps`）：
  三个向导（`admin_setup` / `edgeauth` / `keystore`）各自都会打印原因与补法，但它们**散在十几行
  横幅里**；用户点单的原话是"完全后台执行我又怕在新机子上没有那些配置"。所以 `serve()` 末尾
  多一句 `[!] 本次启动有 N 项配置没就位：…`。它刻意**只给短名字**：补法那几句话的产地仍在
  `admin_setup.NO_TTY_HINT` / `edgeauth.SET_HINT` / `keystore.lock_notice()`，在这里再抄一遍就是
  第二个产地（§5.14）—— `[8at]④` 钉了"清单里不许出现 `run_users.py` / `--set`"。
  交互判据一个字没改（有终端才问、无终端绝不代填），边缘门**关着**时汇总里也一个字都不许提它
  （与 `[8ai]⑩` 同口径：默认配置必须安静）。
- **站点页「重新截图」＝排队，不当场截（续170 改写续145 那条"没有补的入口"）**：续145 摘掉
  「补截图」时如实登记过"渲染后标题只能在建任务时拿到、已跑完的任务没有任何补的入口"；
  续170 按主理人点单加回 `POST /api/sites/reshoot`（勾选站点 → 排一轮**只跑 `screenshot` 阶段**
  的**追加**运行），那句**不再成立** —— 已跑完的任务现在能补图，也能顺带补渲染后标题
  （那一轮照旧走 `set_site_titles`）。仍然成立的四条：① 它**排队**（一次无头浏览器要几秒到几十秒，
  压在 HTTP 线程上会把整个控制台卡住，还绕开队列、并发闸与请求预算）；② 策略级
  `screenshot.enabled` 仍默认关，单次只排 `screenshot.max_sites` 上限内的站点，超出的条数说出来；
  ③ 人工点的「重截失败的站点」**不看原因档**（人要点第二次就是"都要再看一眼"），原因档那一道
  只用于**自动**候补重试；④ 旧接口 `POST /api/rescan&stage=screenshot` 仍在、旧入口形态仍不许回来。
  判据：`[5t]` 钉双向（旧形态不在 + 新入口真渲染出来 + 勾选框接到表单上）、`[7r]/[7s]` 钉
  "站点页签恰好一个 POST 且 GET 先闭合"、`[170]⑧` 钉归属 404 / 上限读配置 / 空清单 409。
- **`serve()` 返回时必须把中间件摘掉**（续138，`gui/app.py`）：`app.wsgi_app` 是**模块级对象**，
  挂上去不摘，同进程后续任何 `gui_app.app.test_client().get("/login")` 都会 404。回归 `[7i]` 会
  **真调 `serve()`**（`app.run` 打桩成立刻返回），不摘就把后面每组刷成红、且红在哪个组取决于
  随机前缀 —— 是 §6.2 那种"看着像代码坏了"的假红。程序化调 `serve()` 的嵌入用法同理要能拿到
  一个还能用的 app。
- **前缀一变，执行节点就断**（续138）：`cli/run_node.py --controller` 必须填启动横幅那行**含前缀的
  完整地址**，而那个 404 是空响应体，现象只是"节点安静地不领任务"。所以 `NodeClient._post` 对 404
  要**把这句话写进异常**，别让人对着 `raise_for_status()` 的裸 404 猜。
- **站点存活口径是"回了真实状态码就算"，不许把 `-mc` 白名单加回去**（续139，`probe.is_alive`）：
  旧配置 `-mc 200,301,302,403,404` 会把 CDN 边缘活着、源站挂了的主机（`521`/`502`/`400`）**整行
  抹掉** —— 不是标成死站，是根本不出现在 httpx 输出里。2026-10-08 对 targ2.com 与灯塔逐条比实的数：
  灯塔记为站点而我们零入库 49 台，其中 34 台我们本来就有子域名；挑 6 台复测「带 `-mc` 0 行 / 去掉
  6 行」，98 候选全量复测「旧 argv 15 台 / 新 argv 49 台，且旧口径有的一个新口径都没丢」。
  三条连带口径：① `-nfs` 必须留着（不锁 scheme 时 httpx 的 scheme 回退会把 `http://h` 的 301 换成
  `https://h` 的落地状态，续112-B 的「跳转后」取证就没输入了）；② `-fr` 必须**不加**（跟随跳转＝用
  落地页状态覆盖第一跳，正是要避免的谎报）；③ 日志必须摊开 `2xx/3xx/4xx/5xx` 组成，否则"存活站点
  168 个"会被读成"168 个打得开的站"。回归 `[8ao]`（含"`is_alive` 换回白名单 ⇒ 521 消失"的变异）。
- **第一轮与二层必须共用同一个探测函数**（续139，`probe_candidates` / `register_sites`）：
  `jsmine` 之后新发现的域名（JS 挖的 + 库里其余没试过的）由 `probe.second_pass` 补探一轮 ——
  由 `jsmine` **无条件**调用（不在 `if new_domains:` 里面，本轮没挖到新域名也照补）。四条纪律
  缺一不可：只探 `extdom.task_bases` 归属（越界一个请求都不发）、**先过 DNS 预筛**（被动来源的
  名字一大半早就不解析，逐条上 HTTP 是纯浪费）、**预筛自身还有上限 `max(10 × limits.recrawl_max_hosts, 50)`**
  （深档上线后池子里可能躺着十万个不解析的历史噪声名字，一个都不解析时不许把整个池子查一遍）、
  补探主机数受 `limits.recrawl_max_hosts`（默认 300）。
  二轮结果**追加**进 `ctx.results["sites"]`（覆盖写法会让后面的 dirscan/vulnscan 读不到新站点：
  库里有了、内存里没有）。跳过多少、为什么跳必须逐条写进日志 —— 这一类功能最容易变成
  "看起来跑了、其实一个都没探"。回归 `[8ap]`（含"把 `is_owned` 换成恒真 ⇒ 立刻探到别人域名"的变异）。
- **目标是 URL / 子域时自动提取主域（续145，`subdomain.auto_root`，默认开）**：
  此前 `stages/subdomain.py` 的收集根**只认 `kind == "domain"`**，给一条 `https://www.a.com/x`
  的结果是**整阶段跳过**（日志只有一句"目标中无裸域名"），人只能自己把主域抠出来再填一遍 ——
  用户点单要的就是这件事。现在 URL 走 `urlparse().hostname` 取主机（归一仍是 `to_ascii` +
  `is_domain`，与 `targets.parse_line` 同一套），再折到注册域。三条边界：
  ① **折叠是追加不是替换** —— `www.a.com` 自己仍留在收集根里，替换掉等于把用户真正给的那个
  主机从探测清单里抹掉；② 折叠判据是"**两个触发条件、一处实现**"（`subdomain.auto_root` 或
  任务级 `auto_expand`），别在 `auto_expand` 分支里再写第二份；③ 折叠那行日志必须仍带
  「自动拓展」字样 —— `devflow.VECTORS` 的 `auto-expand` 就按这个 kw 判，改文案不改向量＝自检假 MISS。
  ⚠ 这是**默认值变更**（与续144 同一性质）：旧注释写的正是"这是扩大扫描面的行为，不能让既有任务
  在用户不知情的情况下变样"，本轮按用户点单翻了过来 ⇒ 被动收集与 DNS 爆破的根从 `www.a.com`
  变成 `a.com`（外部接口查询与解析量都涨）。要回旧行为：策略页取消「自动提取主域」。
  `auto_expand` 独有的那一半（把目标自带的子域按 `source="target"` 入资产表）**没有**跟着默认开。
  回归 `[7a]③`（四档开关 + URL 五形态）与 `[8at]②③`（三方一致 + 真 POST 两个方向 + 折叠只有一处实现）。
  **仍未收敛**：`extdom.task_bases` / `github_leak.target_domains` / `diffview.target_set`
  是同一个想法的另外三份实现，本轮刻意没动（各有额外判据、都在跑着的断言底下）—— 见待办。
- **词数闸门一律等距抽样、且只冲深档**（续139，`subdomain._spread`）：排序好的深字典 `[:3000]`
  拿到的全是 `0/00/000/aa…`，数字与叠字符前缀把额度占满，真正值钱的 `api`/`admin` 一条进不去；
  `words[::step]` 也不行 —— `n % step != 0` 时会把字典**尾巴**丢掉（排序后尾部是 `zz*` 那批），
  所以索引必须"两端保住"：`int(i*(n-1)/(cap-1))`，条数恰好取满 cap。更要紧的是**字典分两档**
  （`dicts.subdomains` 精简档 **84 条永远全量参与、任何闸门都不冲它** + `dicts.subdomains_deep`
  深档受抽样；深档续139 随仓库分发 **177,875 条**，不想要 `git rm config/dicts/subdomains_deep.txt`）：
  并成一份再抽样，84/177,875 ≈ 0.05% 会把人工挑的那几十条几乎全冲掉 —— 那不叫收窄，叫倒退。
  两道闸门分别管两路：`limits.brute_max_words`（puredns 那一路的深档上限，0=全量）/
  `limits.brute_fallback_max`（内置那一路的深档上限，默认 3000）；内置那一路另有独立并发
  `limits.brute_workers`（默认 64；纯 DNS 等待，实测 3000 条 @20 线程 ≈ 53 秒 ⇒ 全量 17.8 万条即使 128 线程也跑了 45 分钟仍未跑完，
  128 线程跑 45 分钟仍未跑完（全量只有 puredns 现实可行））。收窄后的词表要落盘
  （puredns 只吃一个文件）并把"放开办法"说出来；`limits.brute_dict_warn_min`（默认 1000）的语义是
  **没导入深档时**才会喊（随包带深档 ⇒ 默认安装不触发，用户自己删掉深档才喊），喊的时候指名
  组合爆破（`limits.brute_combo_max`，默认 4000 词/域名）是同一轮的另一半：逐条解剖显示灯塔独有而
  我们没有的 24 个域名里，14 个的标签在深档里（抽样没爆到）、**10 个任何字典都没有**
  （`api-contract`/`ws-spot`/`admin-oss`），只能把「精简档词 × 本任务已发现名字的首段」拼成 `a-b`
  再爆一轮；种子只用本任务自己发现的名字，来源标记 `dns-brute(combo)`。
  `tools/import_subdomain_dict.py`（默认写回目标就是深档）；开发模式/自检必须压 `brute_max_words`/
  `brute_fallback_max`/`brute_workers`/`recrawl_max_hosts` 四项（`devmode.DEV_LIMITS` 各给 4/4/4/1），
  否则用户带 17.8 万条深字典时，CI 跟着字典一起变慢。
  回归 `[8aq]`（⑥⑦⑨⑩ 四条各盯一面）。
- **任务级爆破档位 `subdomain_profile`（续246，B 批）= `brute_max_words` 闸门的任务级封装**：
  `quick` 把深档等距抽样到 `BRUTE_PROFILE_QUICK_WORDS`（1 万）条，`deep` 显式回到策略值
  （0=全量），未指定/不认识的值行为与加这个选项之前逐字节一致。**策略值更小时永远以策略为准**
  （配置是天花板：开发模式把 `brute_max_words` 压到 4 时勾「快速」不许放大回 1 万，否则 CI 与
  自检跟着字典一起慢）；精简档那 84 条任何档位全量在场。入口三处同一套口径：GUI 任务区下拉
  （与「全部勾上/清掉/恢复默认」三按钮联动）/ CLI `--subdomain-profile` / `create_app` 的
  `options["subdomain_profile"]`，且**勾了档位没勾 subdomain 阶段就自动补阶段**（“勾了就要生效”）。
  档位生效必须打日志说清“是等距抽样不是截断、要怎么放开”（用户看到“子域名少”时要能分辨是字典小
  还是自己选了快速档）。回归 `[246b]`（真跑 stage、读 puredns 落盘词表：12000→10002 / 策略 300
  更小→302 / deep+策略 0 全量 / 未知值不收窄也不打档位日志）。
- **被动源默认集（续246，A 批）**：`scanner/passive.py` 的 `DEFAULT_SOURCES` 6→8 ——
  +chaziyu（HTML）+urlscan（公开 search API，JSON），均 keyless 且 2026-10-20 实测可用；
  threatminer 接口本身 keyless 但实测整站 CF 522/超时 ⇒ **保留在 `SOURCES`、默认不启用**；
  ipv4info 在 OneForAll 参考实现里要 API key（且 `ipv4info.com` 当前无 A 记录）⇒ 不属于
  “免 key”档，不接。`[246]` 钉住源集合、URL 形态、`_extract` 对两种真实响应形状与
  “单源不可达不拖垮其它源”。
- **“要不要提问”的判据只有一个产地：`utils.is_interactive_stdin()`（续246）**：
  Windows 版 MSVCRT 的 `isatty()` 只判“是不是字符设备”，**NUL（DEVNULL/计划任务/服务）
  也返回 True** ⇒ 裸 `sys.stdin.isatty()` 分流会让非交互环境掉进 `getpass` —— Windows 的
  getpass 走 `msvcrt.getch()` 读**控制台**而不是 stdin，没有输入就永久挂住（`--create-admin`
  实测 180 秒超时）。Linux 走 `tcgetattr` 没这个坑 ⇒ Linux CI 上永远看不见。helper 在 isatty
  为真后再用 `GetConsoleMode(STD_INPUT_HANDLE)` 复核（只有真控制台才算交互；测试注入的假
  stdin 永远说了算）。`admin_setup`×2 / `keystore` / `edgeauth`×2 / `run_keys` /
  `run_bootstrap`×2 全部路由过去；`[8v]⑧` 逐文件源码断言“再无第二份裸 isatty”，
  ⑦ 的 `stdin=DEVNULL` 子进程钉端到端形状。

- **`<title>` 的提取只有一个产地，渲染后标题只补空、绝不覆盖**（续140）：正则与取法只在
  `scanner/utils.py` 的 `TITLE_RE`（`re.I | re.S`）+ `html_title()` 定义一次，probe 的内置兜底与
  「跳转后」取证（`stages/probe.py`）、dirscan 命中页的标题（`stages/dirscan.py`）、截图阶段的
  **渲染后**标题（`scanner/screenshot.py`）全部复用它。写第二份 `<title>` 正则就是亲手制造"四处口径
  不一样"——与 §5.14「面向用户的同一句提示只许有一个产地」是同一类毛病（行号按 2026-10-09 工作区实测，
  **认符号名不认行号**，那几个文件同轮在改）。
  两条配套口径：① `db.set_site_titles()` 把"不许覆盖已经拿到的标题"写在 **SQL 的 WHERE** 里
  （`AND (title IS NULL OR title='')`），而不是让调用方先查一遍 —— 判据落在唯一动这张表的地方
  才防得住并发，也防得住下一个调用方忘记判断；② `screenshot.capture(..., want_title=True)` 用
  `--dump-dom` 把渲染后的 DOM **挤进同一次浏览器调用**（再起一次进程是本模块最贵的动作，
  零额外启动是这条修法成立的前提），不传时 argv 与从前逐字节一致。
  ⚠️ 门控没变、也别记错：**截图阶段仍然默认关闭**（`screenshot.enabled`，或建任务时勾「截图」），
  所以「渲染后标题」是**开了截图才有**的东西；没开时的正确行为是 probe 入库日志把
  「多少个站点原始 HTML 里没有 `<title>`」说出来并指一条出路（续140 加的那半句），
  而不是假装标题抓到了。
  §6.1 口径的证伪：把 `html_title` 的 `re.S` 去掉 ⇒ 跨行 `<title>` 的站点必须判成**无标题**
  （SPA 外壳与缩进排版的页面上 `<title>` 常常跨行，那个 flag 不是装饰）。

- **站点列表的"同标题折叠"只看标题，不看响应长度；显示层与扫描侧两层故意不同键**（续147，
  `gui/app.py::_site_fold_key`）：旧键 `(task_id, title, length)` 折不掉真实站点的常态 —— 同一个
  SPA 挂在四五个主机上、标题一致而长度差几十字节（CDN/模板把请求路径印回正文），主理人原话
  「同样的站点底下 标题也要去重」。两条必须一起守住：
  ① **`task_id` 留在键里** —— `/sites` 是跨任务视图，不带就会因为别的任务有同名标题把本任务的
     站点折掉（实测把一个靶场的 15 条折成 1 条，资产归属直接丢失）；
  ② **`dirscan._dedup_sites` 仍按 `(标题, 长度)`** —— 那一层是"少发请求"的预算口径，长度不同
     就是内容不同，跟着放宽会**漏扫真页面**。显示层放宽、请求层不放宽是刻意的取舍，别
     "顺手统一成一处"（真要统一，先回答"少扫一页谁负责"）。
  放开入口仍只有一个：`?all=1`（页面上写「显示全部站点（含同标题与重叠）」），它同时放开
  跨任务重叠与同标题两层 —— 一句话说明两层，比给两个开关少踩"只开了一个还以为全开了"。
  配套口径没变：被收起的条数必须报（`已折叠隐藏 N 条`）并写明「入库一条没动」（续112 同口径）。
- **配色必须在首次绘制前定档，默认浅色**（续147，`gui/templates/base.html` 的首屏内联脚本）：
  以前只有 `app.js` 在页面末尾设 `html[data-theme]`，于是切功能页会先按 `:root`（深色）画一遍
  再被 JS 改成浅色 —— 主理人报的「我手动调成浅色，切换功能页他先显示深色再显示浅色」。
  三条口径：① 默认档（`light`）与存储键（`ctfscanner.theme`）**只有 base.html 那一份产地**，
  `app.js::initTheme` 只读 `window.CTF_THEME_KEY` 与首屏已设好的属性，自己不再藏一份 `"dark"`
  兜底（藏了就等于保留第二次改色）；② 赋值必须排在 `<link rel="stylesheet">` **之前**，
  这条由 `[8az]③` 按源码顺序判（`index(setAttribute…) < index(<link rel="stylesheet")`）；
  ③ "首屏"只有真浏览器能验，所以正面判据在 `tests/browser_e2e.py [11]`：空 localStorage 下
  `data-theme == light`、实测 `--bg` 取到浅色那套值、换页（`/tasks`）后仍是记忆里的那一档且
  下拉框同步。`:root` 仍是深色那套变量（改成浅色基准要把四套主题 46 个变量一一补全，
  `tools/check_contrast.py` 的层叠判据会逐条抓漏写），本轮**没动 CSS**，只动了首屏定档。

## 8. 不要做的事

- 不要重写已可工作的模块换取"看起来更好"。
- 不要在未评估依赖成熟度时照搬 docs/roadmap.md 的功能（那是候选，不是承诺）。
- 不要改变 POC YAML 的既有语义与既有 POC 的 `id`（id 用于去重与溯源）。

## 9. 协作约定（用户明确要求）

- `todo.txt` 是用户的原始待办：**完成一项就在该条后追加 `[完成]`**，部分完成写
  `[部分完成：说明]`，未开始写 `[待办]`。首行已写明该约定。
- `TODO.md` 是本项目**待用户确认**的排期清单（P0 = 子域名扫描）。用户确认后再实施，
  不要自行把 P1/P3 拉上来做；P3 项依赖外部 API 或检测层成熟度，现阶段做只会产生噪声。
  文件末尾另有 **「参考项目借鉴清单」**（对标本机一个外部参考项目，其路径见 §2 末「本机参考项目」一条），
  含 A 采纳 / B 批判不采纳（8 条带理由）/ C 保留与间接处理标注——动手前先读，**避免重复调研或照搬有害设计**。
- 跨平台（Linux + Windows）是硬要求：路径用 `pathlib`、命令用列表 argv + `shell=False`、
  解释器用 `utils.pick_python`、文件读写显式 `encoding="utf-8"`、工具探测用 `shutil.which`。 **跨 Python 版本红线（续96）**：内联全局标志（`(?i)` / `(?im)`）只能写在正则**串首** —— 写在别处 3.11 起是弃用写法、3.14 起直接抛 PatternError（本轮在远端 3.14 上就是它让 probe 静默报「存活站点 0 个」，因为 `pool_run` 把异常吞成 None）；回归＝`tests/smoke.py [8d] ⑩`（AST 扫全仓 + `SIGNATURES` 在当前解释器逐条编译）。
- **换行符：仓库里的 EOL 是「混合」的，没有统一约定**（`core.autocrlf=false`，按文件原样提交）。
  实测（2026-09-28，口径 = `git ls-files` 里的文本文件、含 2 个空文件）：**466 个里 71 个含 LF-only 行**
  （其中 54 个整份就是 LF，如 `scanner/extdom.py` / `scanner/intel.py` / `config/dicts/cdn_cname.txt`；
  混合的如 `tests/smoke.py` / `cli/client.py` / `gui/app.py`；整体 CRLF 的如 `scanner/db.py` / `scanner/utils.py`）。
  ⚠️ **这个数字会随编辑漂移**（本轮就从 69 涨到 71 —— Edit 类工具新增的行是 LF），
  **别拿它当精确指标**；规矩**不是"一律 CRLF"**，而是 **"不要改变文件原有的 EOL 形态"** ——
  判据永远是 `git diff --numstat` 与 `git diff --ignore-cr-at-eol --numstat` **逐文件一致**
  （对全 LF 文件同样成立）。
  代价是实测过的：有一次用工具批量改写后文件变成 LF-only，提交时 `tests/smoke.py` 出现
  **2811 行纯 EOL"假变更"**（`git show --stat` 里 1490+/1321-），真正的内容改动被淹没、review 完全失效。
  ⚠️ **另一个具体陷阱（2026-10-08 续126 踩、续129 又踩一次；比 Edit 更隐蔽）**：
  补丁脚本里用 `Path(p).read_text()` —— **`read_text()` 的通用换行单独一步就把 `\r\n` 读成
  `\n`**，之后哪怕你用 `write_bytes` 也救不回来（续129 就是这样把 `gui/app.py` 洗成
  3454/3394 的假变更，当时写的还是 `write_bytes`）。续126 那次是
  `read_text()` + `write_text(newline="")`，`git diff --numstat` 变成 **14060/13759**
  （真实改动 306/5）。**规矩：碰混合 EOL 的文件，从头到尾只用 `read_bytes()/write_bytes()`**，
  需要字符串处理就先 `read_bytes().decode("utf-8")` 再 `encode("utf-8")` 写回（不改行尾）。
  ⚠️ **续146-附3 实测到这条规矩的适用面比原先写的更宽**：对**混排**文件用 Edit 类工具做**局部**
  替换，结果不是"新行是 LF"这么轻 —— 它把**整份文件的 CRLF 行一并归一化成 LF**。本轮
  `docs/security-notice.md`（108 LF / 15 CRLF）只改了 5 行，改完 CRLF 归零，`git diff --numstat`
  报 20/15 而 `--ignore-cr-at-eol` 报 5/0 —— 那 15 行纯 EOL 假变更正是原来那 15 个 CRLF 行。
  判据不变（两种 numstat 逐文件必须一致），但**动作要跟着改**：只要文件里有**任何**一条 CRLF 行
  （动手前用 `Counter` 普查一次即可），就一律走 `logs/_lpatch.py` 那种 `read_bytes()` + 沿用锚点行
  EOL 的补丁脚本，别用 Edit/Write 直接改；**整份单形态**（100% LF 或 100% CRLF）才可以安全用
  Edit/Write。本轮同一批里 `scanner/log.py` / `install.sh` / `SKILL.md` 都是 100% LF，Edit 无副作用
  —— 所以差别不在"哪个工具能用"，在**动手前有没有普查过这个文件**。
  锚点用 `(old_crlf, old)` 两试的写法（本仓 `logs/_docs*.py` 都是这个形状）。
  ⚠️ 同一个脚本里的**第二个坑**：锚是**单行**时那次"两试"退化成同一条（锚里没有内部换行），
  但**替换文本**内部的换行会被无条件加上 `\r` —— 落在 LF 区里就多出一条纯 EOL 的假变更（本轮 `cli/client.py` 就这样差一行）。写完补丁脚本**必须**逐文件核两式 numstat 相等。
  已经洗坏了怎么救：**不是**全文件补 `\r\n`，而是**按行从 `HEAD` 还原原有 EOL**
  （difflib 对齐内容、等价的行沿用 HEAD 那一行的 EOL，新增行取该区段主导形态；
  可参考本轮用的 `logs/_eolfix.py`），然后核 `git diff --numstat` 与
  `git diff --ignore-cr-at-eol --numstat` 是否重新相等。
  ⚠️ **同一类工具还会洗引号（续222 实测）**：对混合 EOL 的 `tests/smoke.py` 做局部替换，
  整份重写后 **中文弯引号 `“”` 被归一成 ASCII `"`**（25 行；落在中文注释/字符串里就是语法错误，
  `py_compile` 才暴露）。救法与 EOL 同源：按 HEAD 逐行还原（只替换"归一化后逐字相等"的行），
  改完**必须** `py_compile` + 人眼过一遍 `git diff` 里的引号。结论不变：混合 EOL 文件只用
  `read_bytes()/write_bytes()` 的补丁脚本（`logs/_lpatch.py` / `logs/_eolfix.py`）。
  ⚠️ **具体陷阱（2026-09-28 续64 又踩一次）**：Edit/Write 这类工具会把**整个文件**归一成 LF，
  对**混合 EOL** 的文件尤其致命。归位办法**不是**无脑全文件 `\r\n`，而是**从 `git show HEAD:<file>`
  取原始字节、只替换目标文本、其余行的原 EOL 保留**。
  **改完文件先自查再 `git add`**：

  ```powershell
  git diff --stat                      # 行数远超实际改动 → 大概率 EOL 被改写
  $b=[IO.File]::ReadAllBytes('<文件>') # 按字节数：LF 总数
  ($b | Where-Object { $_ -eq 10 }).Count
  ```

  归位办法（纯 EOL、不动内容，跨平台可靠）——
  **注意 PowerShell 的转义符是反引号 `` ` `` 不是反斜杠**，所以下面这种写法是**错的**：
  `$t=[IO.File]::ReadAllText($p) -replace "\r\n","\n" -replace "\n","\r\n"`
  —— 它会把 4 个字符 `\` `r` `\` `n` **当字面文本插进文件**（本轮续23 实测：368 处）。
  用这个（Python，行为确定）：

  ```powershell
  py -3 -c "from pathlib import Path; p=Path(r'<文件>'); b=p.read_bytes(); b=b.replace(b'\r\n', b'\n').replace(b'\n', b'\r\n'); p.write_bytes(b)"
  ```

  自查：`LF 数 == CR 数` 且文件能正常 import/运行。
  *（**刻意不用** `.gitattributes text=auto eol=crlf`：它会把索引侧 EOL 全量改写，需要一次覆盖
  全仓库的迁移提交，`git blame` 的归因随之失效 —— 与 §0.1「事后分辨谁改了什么」冲突。
  宁可保留"提交前自查"这道人工闸门。）*
- **改动必须标注实施者**（用户 2026-09-22 明确要求）：提交信息末行写 `WorkBuddy · <模型名>`，
  并在 `CHANGELOG_AI.md` 的轮次标题下写明实施者。**背景**：本项目出现过两个 AI 会话同时改同一批文件
  （文档被反复覆盖），标注实施者是事后分辨「谁改了什么」的唯一可靠线索。
  例：`WorkBuddy · DeepSeek-V4.1-Flash`。
- 每次改完代码的标准动作：跑 `tests/smoke.py` → 更新 `CHANGELOG_AI.md`（最新在最上面）
  → 必要时同步本文件与 `docs/` → **git 提交**
  （git 二进制位置见 §2；形如 `<git可执行文件> add -A && <git可执行文件> commit -F -`）。
  ⚠ **提交信息一律走 heredoc / `-F -`，不要用 `-m "<正文>"`**（续146-附2 真踩的，而这一行原先
  写的正是 `-m "<轮次>: <一句话>"` —— 文档本身在教这个错）。本仓的提交信息里到处是反引号
  （文件名、组号 `[8as]`）、`$`、`!` 和中文引号，而 shell 的双引号**挡不住反引号的命令替换**：
  实测那一次的后果是"一整串文件名被替换成空串"，正文只剩括号和逗号，而 **`git commit` 不看消息
  内容、照样返回 0，现场零报警**，差一步就推到 origin 上了 —— 提交历史是共享状态，写坏了不能
  靠 force-push 擦（§0 那条），所以这类错只在"还没推"之前有救。
  配套两条：① 提交完**先 `git log -1 --format=%B` 回看一眼**再推，这是唯一能发现它的动作；
  ② 要就地改写（`--amend`）必须先证明它没共享 —— `status -sb` 是 `ahead N`
  **且** `git branch -r --contains <sha>` 在远端查不到，两个条件都成立才动手，否则只能追加更正。
  敏感文件靠 `.gitignore` 排除（keys.yaml / data / logs / pocs-user / nuclei-templates），
  提交前瞄一眼 `status --short` 确认无混入。

## 10. 多 agent 协作（默认动作，不是可选项）

> 用户 2026-10-09 明确要求把这件事写进项目记忆："我们能不能调用多agent执行，把多agent执行加入记忆，
> 提高我们生产效率，就算其他ai来了也会多agent执行"。所以这一节是**规矩**，不是经验分享：
> 任何接手者（换对话框 / 换 AI / 换机器）默认按"这件事能不能并行"来切任务，而不是默认一个人串行干完。
> 但**并行只在只读任务与互不相交的文件上是收益**；下面"必须独占"那一栏里并行生产的是**假红**，
> 不是发现 bug —— 本仓已经为"两个会话同时写同一批文件"付过两次代价（§9：文档被反复覆盖；
> §7：派去"只观察"的浏览器子代理点了「批量删除」，硬删掉 63 条历史任务行）。

**可以并行（放开做）**：

- **只读审阅 / 审计 agent**：找文档漂移、核对数字、找遗漏的断言与"说错了的地方"。它们的产出是
  报告 + 位置，不碰文件，天然互不冲突（§0.4 那句"TODO.md 停在 117"就是查出来的这类事实）。
- **写不同文件的写型 agent**：判据是各自动过的文件集合**不相交**（用 `git diff --name-only` 对一眼）；
  一旦相交就退回串行、一个文件一个 owner。
- **CI 里互不依赖的 job**：`.github/workflows/{smoke,quality}.yml` 的 job 本来就并行；
  新增 job 的前提是"它不读另一个 job 写的东西"（`logs/devflow_baseline.json` 那种共享基线就是读别人的）。

**必须串行（一次只有一个 owner；并行做这些等于自己造假红）**：

- **同一个文件的写**：后写覆盖前写，而且 `Edit` / `Write` 会把整个文件归一成 LF（见下面 CRLF 地雷）。
- **`tests/smoke.py` 与容器里的同一份门禁**：`FIXTURE_PORT = 8765` 是**硬编码常量**
  （`tests/smoke.py` 里 `start_fixture(port=FIXTURE_PORT)` 用它），两个 smoke 同机并发必冲突；
  容器里更隐蔽 —— 宿主侧杀掉 `docker exec` 那个**客户端**，容器里的 python **照旧在跑**。
  这正是 §6.2 **第七起**的成因，症状是"RC=1、`grep Traceback` 却一无所获"，看着像代码坏了。
  规矩：**门禁只有一个执行者**；要并行就排队，或改做互不相干的静态检查。证伪/变异实验也不许和
  正式门禁同时在一份工作区里跑。
- **`git` 写操作**（commit / push / checkout / stash）：多会话抢 `main` 时强推会**静默盖掉别人的提交**
  （§2 的三条红线之一）。
- **`logs/` 清理**：别的 agent 正往里写预检脚本与审计证据时，任何通配符删除都在删别人的证据
  （§6.2 的清理纪律本来就是为"一个执行者"写的）。
- **真扫描 / 真发请求的动作 vs 门禁**：两者都吃 `throttle` 的**进程级**闸与同一份 `logs/`，
  同时在跑会让"并发数""请求数"这类判据谁都不准（§5.8 的进程级共享闸就是这个意思）。

**只读 agent 一律不许跑那两个入口** —— 它们都会写共享基线文件，跑完就不是"只读"了：
`cli/run_devflow.py` **第 96 行**调 `devflow.save_baseline()`，覆盖 `logs/devflow_baseline.json`
（路径常量 `scanner/devflow.py::BASELINE_PATH`），而那份基线是"本轮比上一轮慢不慢"的唯一对照；
`tests/smoke.py` **第 71 行**在 `--timing` 开启时以 `"w"` 打开 `logs/smoke-timing.jsonl`
（每次跑都清掉历史，默认关 ⇒ 不开也不写）。只读 agent 的核验手段限于：读文件、
`git diff` / `--numstat`、静态 grep，以及**自己**写在 `logs/` 下的一次性脚本。

**每个 agent 的 brief 必须自带全部上下文**（agent 看不到本对话，这是硬事实，不是提醒）：
文件路径 + 行号 + 为什么改 + **哪些文件与命令禁止触碰**。§7 那条"派浏览器代理必须写明只读浏览、
禁止点击任何提交/删除类按钮"是同一条规矩的早期版本 —— 漏写那一次丢了 63 条任务行。
本轮的硬边界就是这么给的：不许跑 `tests/smoke.py` / `run_devflow.py`（端口 8765 与共享状态归门禁执行者）、
不许 `git commit/push/checkout/stash`、只许改点名的那两个文件。

**结果必须核验（"trust but verify"不是礼貌话）**：agent 汇报的是它**打算做什么**，
不一定是它**做了什么**。两条最低核验：`git diff --numstat -- <文件>` 与
`git diff --ignore-cr-at-eol --numstat -- <文件>` **逐文件相等**（不等＝EOL 被洗，真实改动被淹没），
再用 Read 看实际改动内容；汇报里的"已改好"不算证据。

**本仓的 CRLF 地雷（对多 agent 尤其致命，因为并行时每个写型 agent 各自都会踩一次）**：
`Edit` / `Write` 会把 CRLF 文件整份洗成 LF。实测代价：`tests/smoke.py` 一次只改消息文本的小脚本
让 `git diff --numstat` 变成 **14060/13759**（真实改动只有 **306/5**）；`gui/app.py` 也红过一次
**3454/3394**，那一次脚本里写的**已经是 `write_bytes`** —— `read_text()` 单独一步就足以洗掉 CRLF（§9）。
所以：**纯 CRLF 或混合行尾的文件，动手前先按字节扫一次行尾形态，一律用 `logs/_wpatch.py` 做字节级补丁**
（spec 是 `[(file, old, new, count)]` 的 JSON；它先试 CRLF 再试 LF、锚点不唯一就不写、
写完自己逐文件核两式 numstat 相等）。多个写型 agent 并行时这条要**逐 agent 在 brief 里写明**：
A 洗了 EOL，B 的 diff 就再也读不出东西了，而且 B 会以为是自己改坏的。
**`_wpatch` 搞不定的那一档：`logs/_lpatch.py`（续146 新增）**。它按**行号**替换，逐行保留该行原有的
EOL（新增行取该区段的主导形态），所以能改"CRLF 与 LF 在同一区段里交错"的地方 ——
`_wpatch` 靠"先试 CRLF 再试 LF"匹配整块锚点，遇到交错区段会静默返回 `[0, 0]`（本轮 `gui/app.py`
的 `/sites` 路由就是 25 CRLF + 6 LF 交错，实测打不进去）。用它的两条纪律：
① **每一批之后重新取行号**（前一批增删过行，旧行号就偏了 —— §6.2 第十二起那个"打偏 7 行"
   把 `evasion` 四个键整段删掉的事故就是这么来的）；② 锚点除了行号还要**核对首行前缀**，
   对不上就 `SystemExit`，绝不"差不多就写"。
   ⚠ **续146-附4 把 ② 从"嘴上规矩"做成了工具判据**：`_lpatch.py` 原先只收行号，那句话是
   文档里写着、代码里没做。本轮照一次 `sed -n '145,160p'` 的**窗口偏移**估行号（窗口第一行
   不等于文件第一行！），`gui/templates/task_detail.html` 那批补丁把
   `<p>{{ v.detail }}</p><pre>{{ v.evidence }}</pre>` **整行吃掉**，靠 `--numstat` 报 **2/3**
   才露出来。现在 `expect` 是 spec 的**必填第 5 项**（缺失或逐字不符都直接 `SystemExit` 并打印
   期望/实际）。
   ⚠ **同一轮还挖出更深一层：行号得按 `grep -n` 的口径数**。`bytes.splitlines()` 除了 `\n`
   还会在**裸 `\r`**、`\v`、`\f`、`\x1c-\x1e` 处断行，而 git 与 `grep` 只认 `\n`。
   `AGENTS.md:2400` 正好躺着一个 `\r\r\n`（CRLF 文件被"再加一次 \r\n"改出来的形状），
   于是**该文件 2400 行以后每一行，工具看到的号都比 `grep -n` 大 1** —— 补丁打在上一行上，
   而两式 numstat 照样相等（因为写回去的行尾形态没错），所以这道错**EOL 判据抓不到**。
   现在 `_lpatch.to_lines()` 只按 `\n` 切行（并在末行不带换行时保住尾巴），那个 `\r\r\n`
   也已修回 `\r\n`。
   自查就数**裸 CR 的个数**（非 0 就有漂移风险，别拿 `splitlines()` 与换行数去比 —— 那两个数
   在"文件结尾有没有换行"时本来就不等，会天天误报）：
   `python -c "b=open('AGENTS.md','rb').read(); print(sum(1 for i,c in enumerate(b) if c==13 and (i==len(b)-1 or b[i+1]!=10)))"`
   本轮实测：`AGENTS.md` 曾有 1 处（已修），`gui/app.py` / `tests/smoke.py` / `scanner/owasp/checks.py` /
   三个模板都是 0 处 —— 所以之前那几批按行号打的补丁落点没错，但这个结论是**这次才第一次查**。
- 一次要在**同一个文件**里改四处以上时，用 `logs/_apatch.py`（内容锚点版）而不是 `_lpatch.py`：
  锚点是"整段原文"，要求在文件里**恰好命中一次**（0 命中会给出半段命中的起点，多命中直接拒绝），
  所以不必逐批重取行号；EOL 归属与 numstat 复核规则与 `_lpatch.py` 完全相同。行号版留给
  "锚点本身正在被改、无法用原文定位"的场合。
   ⚠ **重写一个行区间＝逐字重打一遍，只许改自己真要改的那一行（续148 实测踩中）**：给
   `[probe]` 那句日志换文案时，把同一区间里的 `elif any(s.get("source") == "httpx" for s in _reg):`
   凭记忆写成 `elif not got_texts:` ⇒ 行尾形态全对（**两式 numstat 照样相等**），语义却坏了，
   一直跑到流水线断言报 `name 'got_texts' is not defined` 才露出来。补丁脚本的 `expect` 只核
   区间**首行**，救不了"区间里别的行被顺手改写"。唯一防线：先把 `sed -n 'A,Bp'` 的整段原样
   抄进新文本，再只动要动的那一行；打完 `git diff` 逐行数这个区间多了哪行、少了哪行。
   ⚠ **写这类补丁脚本时一个当场就会炸的坑（续146-附2 连着踩了两次）**：`b"…"` 里**不能放非 ASCII**。
   本仓的锚点和替换文本几乎全是中文，所以写成 `b"中文锚点"` 必挂 —— `SyntaxError: bytes can only contain ASCII literal characters`。
   正确写法：`"中文锚点".encode()`，或先 `old = "…"` 再 `old.encode()` 去数/替换。
   （另一半教训是配套的：`git commit -m "…"` 里的反引号会被 shell 当命令替换执行掉，见上面 §9 标准动作那条。两个都是"字符串边界没选对"，只是被吞的地方不同。）
