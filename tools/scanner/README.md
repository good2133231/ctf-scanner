# 外部工具放置区

CTFScanner 的流水线优先调用以下外部工具；全部缺失时框架仍可运行（内置兜底），但覆盖面与性能会明显下降。建议安装。

## 放置方式

**方式 0（续54 起，最省事）：一键下载/更新** —— CLI 或 GUI 都能做，装完自动把
`config/settings.yaml` 的 `tools.<名>` 改成刚装好的相对路径：

```bash
python cli/client.py --update-tools              # subfinder / httpx / puredns（可加 --tool 只装一个）
```

GUI 里是管理员侧栏的「外部工具」页。两条路都**只在显式触发时联网**（扫描期任何阶段都不会自动下载），
只允许 https + 官方主机，默认**必须通过 release 自带的 SHA256 校验和**才落盘。

迁移到**新机器**时用 `python cli/client.py --bootstrap`（续96）：它按平台一次点清「解释器 / pip 依赖 / 外部工具 / 截图用的浏览器」还缺什么；加 `--install` 才联网，且自动层只装 `requirements.txt` 与下表标「自动」的那三个。nmap / fscan / dirmap **仍然只打印命令、一条都不代跑**（逐条原因见下表与 `scanner/toolmgr.py` 的 `MANUAL`）。

否则可以手工放置，两种方式任选：

1. 放入系统 PATH：`subfinder`、`httpx`、`puredns` 等可执行文件直接加入 PATH；
2. 放到仓库内某处，并在 `config/settings.yaml` 的 `tools` 段写明路径。**装的位置必须和配置写的那一个
   一致** —— 本仓既定 `tools/fscan/` 与 `tools/dirmap/`（两个目录联接，指向仓库外的第三方产物，
   见 `.gitignore`），所以下例与 `settings.yaml` 逐字相同；换成别的路径也行，但改配置才算数：

```yaml
tools:
  subfinder: "tools/scanner/subfinder.exe"
  httpx: "tools/scanner/httpx.exe"
  puredns: "tools/scanner/puredns.exe"
  nmap: "nmap"                      # 已装进 PATH 时保持裸名即可
  fscan: "tools/fscan/fscan.exe"    # 自编译产物（Linux 上是 tools/fscan/fscan，无 .exe）
  dirmap:
    python: "python"
    script: "tools/dirmap/dirmap.py"
```

> 三条路径口径都由 `cli/client.py --check` 与 `--bootstrap` 直接读配置，**不写死**：填错的地方不会
> 报错，只会一直显示"未找到 / 缺少"并静默回退内置实现。

## afrog（外部引擎，续149 起默认开 —— 真跑要过三条闸门）

装它只需要一条命令（只有这时才联网，且默认必须过官方 SHA256）：

```bash
python cli/client.py --update-tools --tool afrog
```

它**默认开**（策略配置里已勾选），但要真起进程，三条闸门要**同时**满足：① `afrog.enabled` 开着；
② PoC 目录（默认 `config/afrog-pocs/`，随仓库带一份只读示例）里**真有只读模板**；
③ 本机装好了 afrog 二进制。缺任何一条都只写一行日志、**零请求**（没装 afrog 的机器不会因此报错）。
框架不代为下载第三方 PoC 树 —— 把模板放进 `afrog.poc_dir` 即可。放行口径是逐份 YAML 判**请求语义**，
只把 `GET/HEAD + 无请求体 + 非 tcp + 无 brute 清单 + severity ∈ ("", info")` 的模板复制进任务目录喂给它，
其余一律拒收（实测官方 `fingerprinting/` 130 个文件里放行 94、拒收 36，其中就有一条会触发目标执行
命令的 HFS RCE —— 拒掉它的判据是 severity 那一行）。

想知道自己的目录能喂进去多少条、剩下的为什么被拒：

```bash
python cli/client.py --check-afrog-pocs <你的 PoC 目录>     # 只读，不发请求、不改配置
```

两条要知道的边界：**它的请求由那个外部进程自己发，不经过本任务的请求预算**（所以站点数、并发、
全局限速都有内置封顶，填再大也超不过）；它的命中按 info/low 级入账，`min_severity` 是 medium 时
**不会出现在报告里**，只在任务日志与库里。实现见 `scanner/afrog.py`，回归见 `tests/smoke.py [8z]`。

## 工具清单与获取

「自动」＝续54 起可由 `--update-tools` / GUI「外部工具」页一键下载（**默认必须过 release 自带的
SHA256 校验和**才落盘）；「手工」＝官方没有"可下载且带官方校验和的单二进制产物"，步骤见下方
「手工安装」。

| 工具 | 用途 | 一键下载 | 平台说明 |
|---|---|---|---|
| subfinder | 被动子域名收集 | 自动 | 官方产物双平台都有（`windows_amd64.zip` / `linux_amd64.zip`）+ checksums |
| httpx | HTTP 存活探测/指纹 | 自动 | 官方产物双平台都有 + checksums；需 ≥1.x（`-json` 输出）；注意别和 pip 的 Python httpx 同名命令混淆（框架会做版本握手校验，假的自动降级） |
| puredns | DNS 字典爆破 | 自动（**Windows 无产物**） | **官方只发布 Linux / macOS 产物**（`puredns-{Linux\|macOS}-{amd64\|arm64}.tgz`），**无 Windows 包、也无 checksums**；Windows 上请自行 `go install` 或依赖内置爆破兜底（2026-09-26 查 GitHub API 实测） |
| nmap | 端口扫描（第二引擎，见下） | **手工** | 官方发布在 nmap.org/dist（**非** GitHub release）：Windows 只有安装器、Linux 只有源码包、macOS 只有 dmg |
| fscan | 端口扫描（第一引擎，见下） | **手工** | 官方不发二进制，需用 Go 从源码自编译（本仓为避免 Defender 拦截的既定做法） |
| dirmap | 目录扫描（补充） | **手工** | 纯 Python 项目，release 的 `assets` 为空数组（零二进制、零 checksums） |
| afrog | 漏洞检测（**外部引擎，续149 起默认开**） | 自动（并入 `--install` 默认层） | 官方产物七件（linux/macOS/windows × amd64/arm64 + `checksums.txt`），命名与 projectdiscovery 同规律 ⇒ `--update-tools --tool afrog` 装它、装完必须过 SHA256。装了会被 vulnscan 调用（续121 接线），但要真跑还要 PoC 目录里有只读模板；只喂"只读 + info 级"的模板（详见下） |

> 端口扫描的引擎优先级是 **fscan → nmap → 内置 TCP connect**；两者都没有时会**如实回退**，
> 不会因为"想用 fscan"就把阶段挂掉。

## 手工安装（无法自动下载；但有自动化脚本）

以下三个**不在** `--update-tools` / GUI「外部工具」页的覆盖范围内（它们没有"可下载且带官方
校验和的单二进制产物"），但都能用**一键脚本**装上：

- **nmap** → `./install.sh --with-system --yes`（交给发行版包管理器真装）；
- **fscan** → `./install.sh --with-build`（用本机 Go 从源码自编译，见下）；
- **dirmap** → 纯 Python、release 无产物；本仓已随附一份兼容快照在 `tools/dirmap/`，无需另装（见下）。

细节与逐条原因见下文与 `scanner/toolmgr.py` 的 `MANUAL`：

### nmap

官方发布页是 <https://nmap.org/dist/>，**不在** GitHub release（GitHub 上只有源码仓，无二进制资产）：

- **Windows**：官方只发安装器 `nmap-<版本>-setup.exe`（如 `nmap-7.991-setup.exe`，约 36 MB）。
  它是"装到 Program Files"的**系统级**动作，不是"解包取一个可执行文件"，所以本框架不代跑 ——
  请自己下载并安装；装完在 PATH 里能敲出 `nmap -version` 即可（`tools.nmap` 保持默认裸名 `nmap`）；
- **Linux**：用发行版包管理器最省事（`apt install nmap` / `dnf install nmap`）；官方只发源码包；
- **macOS**：官方只发 `.dmg`（需挂载），或 `brew install nmap`；
- **校验**（官方为每个产物提供摘要文件 `https://nmap.org/dist/sigs/<文件名>.digest.txt`）：

```powershell
curl.exe -LO https://nmap.org/dist/nmap-7.991-setup.exe
curl.exe -LO https://nmap.org/dist/sigs/nmap-7.991-setup.exe.digest.txt
Get-Content .\nmap-7.991-setup.exe.digest.txt        # 看官方摘要
Get-FileHash .\nmap-7.991-setup.exe -Algorithm SHA256   # 与上面对比
```

### fscan

官方不发二进制，**从源码自编译**（本仓为避免 Windows Defender 拦截的既定做法）。两种方式：

```bash
# ① 一键（需要本机有 Go；源码可从 CTFSCANNER_FSCAN_SRC / tools/fscan-src / --src 指定）
./install.sh --with-build

# ② 手动
git clone https://github.com/shadow1ng/fscan && cd fscan
git checkout v2.2.1
go build -ldflags="-s -w" -trimpath -o fscan
```

`./install.sh --with-build` 内部调 `python tools/build_fscan.py --wire`：用本机 Go 编译到
`tools/scanner/`，并把 `tools.fscan` 自动写回配置（缺 Go / 缺源码会**如实报**，不静默跳过）。
也可以自己指定源码目录：`python tools/build_fscan.py --src ./fscan --wire`。

装好后把 `tools.fscan` 填成该二进制路径（本仓既定 `tools/fscan/fscan.exe`，Linux 上是同目录的
`fscan`；`which()` 有 `.exe` 后缀容错，两端同一份配置都能找到；也可以只放进 PATH 保持裸名）。
框架调用时会强制带 `-np -nobr -nopoc`，老版本会自动去掉 `-nopoc` 重试。

### dirmap

纯 Python 项目，**release 页没有二进制产物**（`assets` 为空数组），只能取源码：

```bash
git clone https://github.com/H4ckForJob/dirmap tools/dirmap
cd tools/dirmap && python -m pip install -r requirement.txt
```

> ⚠️ 三条**实测**坑（2026-10-02 在 Linux 上装上游 master 撞出来的，不是猜的）：
> ① 清单文件名是 `requirement.txt`（**少一个 s**），按 pip 惯例猜 `requirements.txt` 会报 `No such file`；
> ② 它 `import imp`（Python 3.12 起标准库已删除）→ **上游 master 在 3.12+ 的解释器上根本起不来**，
>    而 `requirement.txt` 钉的 2020 年 `gevent` / `lxml` 也编不过（放宽版本能装上，但救不了 `imp`）；
>    需要一个 ≤3.11 的解释器，并把下面的 `tools.dirmap.python` 指过去。
> ③ 框架调用时固定传 `-e <技术栈>`（`php` / `jsp` / `asp` / `d` / `big` / `all`），而**上游 master
>    已经删掉了 `-e`**（v1.1 只认 `-t` / `-i` / `-iF` / `-lcf` / `--debug`，字典与后缀改由
>    `dirmap.conf` 配）。装了新版的表现是：dirmap 退出码 2 → 框架日志写明原因 → **回退内置扫描**
>    （不静默，但"装了却没用上"）。带 `-e` 的旧版（本仓适配审查所用的 `dirmap-master` 快照）才是
>    框架现在兼容的那一支。

`tools.dirmap` 是**两段式**配置（不是单个路径）：

```yaml
tools:
  dirmap:
    python: "python"
    script: "tools/dirmap/dirmap.py"
```

> 这段配置 GUI 改不了（「策略配置」页不暴露 `tools` 段），只能手改 `config/settings.yaml`。
> 历史上这里写过 `tools/scanner/dirmap-master/`，本仓已统一成 `tools/dirmap/` —— 两处不一致的
> 表现是"clone 完了 `--check` 仍说缺少"，因为框架只认配置里那一条。

> 目录扫描的主路径是本框架内置的「分层字典 + 12 个框架桶 + 暴露面」，dirmap 只作补充
> （见 `docs/roadmap.md`）。

## 验证

```bash
python cli/client.py --check
```

输出每项工具的可用性；未找到的工具会注明"自动使用内置兜底"，并在末尾给出 `--update-tools` 的一键
安装提示；此外会单列一行 **「需手工安装（本框架不自动下载）」**（nmap / fscan / dirmap + 各自原因），
免得用户一直等一个不会出现的"一键安装"。

## 说明（客观）

- subfinder 被动收集依赖其自身的数据源 API（无需 key 也有基础结果，配置 key 后效果更好）；
- puredns 需要可用 resolver 列表，框架自带 `config/dicts/resolvers.txt`；
- 内置兜底实现仅覆盖最小可用路径（见 docs/pipeline.md 的降级策略表），不要期望与本体等价。
