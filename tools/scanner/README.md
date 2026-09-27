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

否则可以手工放置，两种方式任选：

1. 放入系统 PATH：`subfinder`、`httpx`、`puredns` 等可执行文件直接加入 PATH；
2. 放到本目录，并在 `config/settings.yaml` 的 `tools` 段写明路径，Windows 示例：

```yaml
tools:
  subfinder: "tools/scanner/subfinder.exe"
  httpx: "tools/scanner/httpx.exe"
  puredns: "tools/scanner/puredns.exe"
  nmap: "nmap"                      # 已装进 PATH 时保持裸名即可
  fscan: "tools/scanner/fscan.exe"  # 自编译产物放这里
  dirmap:
    python: "python"
    script: "tools/scanner/dirmap-master/dirmap.py"
```

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

> 端口扫描的引擎优先级是 **fscan → nmap → 内置 TCP connect**；两者都没有时会**如实回退**，
> 不会因为"想用 fscan"就把阶段挂掉。

## 手工安装（无法自动下载）

以下三个**不在** `--update-tools` / GUI「外部工具」页的覆盖范围内，也**不会**有任何自动下载
（原因见上表与 `scanner/toolmgr.py` 的 `MANUAL`）：

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

官方不发二进制，**从源码自编译**（本仓为避免 Windows Defender 拦截的既定做法）：

```bash
git clone https://github.com/shadow1ng/fscan && cd fscan
git checkout v2.2.1
go build -ldflags="-s -w" -trimpath -o fscan
```

装好后把 `tools.fscan` 填成该二进制路径（或放进 PATH）。框架调用时会强制带
`-np -nobr -nopoc`，老版本会自动去掉 `-nopoc` 重试。

### dirmap

纯 Python 项目，**release 页没有二进制产物**（`assets` 为空数组），只能取源码：

```bash
git clone https://github.com/H4ckForJob/dirmap tools/scanner/dirmap-master
cd tools/scanner/dirmap-master && pip install -r requirements.txt
```

`tools.dirmap` 是**两段式**配置（不是单个路径）：

```yaml
tools:
  dirmap:
    python: "python"
    script: "tools/scanner/dirmap-master/dirmap.py"
```

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
