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
  dirmap:
    python: "python"
    script: "tools/scanner/dirmap-master/dirmap.py"
```

## 工具清单与获取

| 工具 | 用途 | 获取 | 平台说明 |
|---|---|---|---|
| subfinder | 被动子域名收集 | github.com/projectdiscovery/subfinder | 官方产物双平台都有（`windows_amd64.zip` / `linux_amd64.zip`）+ checksums |
| puredns | DNS 字典爆破 | github.com/d3mondev/puredns | **官方只发布 Linux / macOS 产物**（`puredns-{Linux\|macOS}-{amd64\|arm64}.tgz`），**无 Windows 包、也无 checksums**；Windows 上请自行 `go install` 或依赖内置爆破兜底（2026-09-26 查 GitHub API 实测） |
| httpx | HTTP 存活探测/指纹 | github.com/projectdiscovery/httpx | 官方产物双平台都有 + checksums；需 ≥1.x（`-json` 输出）；注意别和 pip 的 Python httpx 同名命令混淆（框架会做版本握手校验，假的自动降级） |
| dirmap | 目录扫描 | github.com/H4ckForJob/dirmap | Python 项目，`git clone` 整个目录到 `tools/scanner/dirmap-master` |

## 验证

```bash
python cli/client.py --check
```

输出每项工具的可用性；未找到的工具会注明"自动使用内置兜底"，并在末尾给出 `--update-tools` 的一键安装提示。

## 说明（客观）

- subfinder 被动收集依赖其自身的数据源 API（无需 key 也有基础结果，配置 key 后效果更好）；
- puredns 需要可用 resolver 列表，框架自带 `config/dicts/resolvers.txt`；
- 内置兜底实现仅覆盖最小可用路径（见 docs/pipeline.md 的降级策略表），不要期望与本体等价。
