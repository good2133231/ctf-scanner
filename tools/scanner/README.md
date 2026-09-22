# 外部工具放置区

CTFScanner 的流水线优先调用以下外部工具；全部缺失时框架仍可运行（内置兜底），但覆盖面与性能会明显下降。建议安装。

## 放置方式

两种方式任选：

1. 放入系统 PATH（推荐）：`subfinder`、`httpx`、`puredns` 等可执行文件直接加入 PATH；
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
| subfinder | 被动子域名收集 | github.com/projectdiscovery/subfinder | Windows 取 .exe，Linux 取 linux_amd64 |
| puredns | DNS 字典爆破 | github.com/d3mondev/puredns | Go 编写，双平台官方均有包 |
| httpx | HTTP 存活探测/指纹 | github.com/projectdiscovery/httpx | 需 ≥1.x（`-json` 输出）；注意别和 pip 的 Python httpx 同名命令混淆（框架会做版本握手校验，假的自动降级） |
| dirmap | 目录扫描 | github.com/H4ckForJob/dirmap | Python 项目，`git clone` 整个目录到 `tools/scanner/dirmap-master` |

## 验证

```bash
python cli/client.py --check
```

输出每项工具的可用性；未找到的工具会注明"自动使用内置兜底"。

## 说明（客观）

- subfinder 被动收集依赖其自身的数据源 API（无需 key 也有基础结果，配置 key 后效果更好）；
- puredns 需要可用 resolver 列表，框架自带 `config/dicts/resolvers.txt`；
- 内置兜底实现仅覆盖最小可用路径（见 docs/pipeline.md 的降级策略表），不要期望与本体等价。
