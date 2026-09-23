# POC 开发指南

## POC 存放位置

| 目录 | 说明 |
|---|---|
| `scanner/pocs/pocs/*.yaml` | 内置示例 POC，随框架分发 |
| `config/pocs-user/*.yaml` | 用户 POC：GUI「POC 管理」页上传，或手动放置 |
| `config/pocs-imported/*.yaml` | `tools/import_ref_pocs.py` 批量导入的参考项目 POC，**默认关闭**（关键字命中误报率高，需人工在 POC 管理页挑选后启用） |
| `config/nuclei-templates/*.yaml` | 官方 nuclei 模板投放点：本引擎兼容其核心子集，可直接丢进来加载 |

控制台启动时会自动扫描以上目录并写入注册表；之后可在 GUI 里启停每个 POC，也可以点「重新扫描 POC 目录」增量加载。语法错误的 POC 会标注 `error`；含 `raw`/`dsl`/`flow`/`workflows` 等不支持特性的模板会标注 `unsupported` 并显示原因（不静默失效），扫描时自动跳过。

## YAML 格式

本引擎向 nuclei 语法靠拢，字段命名与官方模板一致：

```yaml
id: exposure-git-config            # 全局唯一，建议 <类别>-<组件>-<问题> 命名
info:
  name: ".git 目录配置泄露"          # 展示名
  author: ctfscanner
  severity: high                    # critical / high / medium / low / info
  tags: [exposure, git, owasp-a01]  # owasp-aXX 标签会同步到漏洞记录的 owasp 字段
  description: "一句话说明危害与成因"
variables:                          # 可选，自定义变量（值里可引用内置变量）
  base: "{{BaseURL}}"
http:                               # 请求列表；兼容 nuclei 的 requests: 写法；任一请求命中即返回
  - method: GET
    path:                           # 字符串或列表；支持 {{变量}}
      - "/{{base}}"                # 相对路径拼在目标 URL 后
      - "/backup.sql"
    headers: {}                     # 可选，自定义请求头
    body: ""                        # 可选（POST 时使用）
    payloads:                       # 可选，path/body 中 {{payload}} 的替换
      - /db.sql
    redirects: true                 # 是否跟随重定向（默认 true）
    matchers-condition: and         # 多个匹配器的关系：and / or（默认 or）
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["[core]", "repositoryformatversion"]
        condition: and              # 单个 word 匹配器内多个关键字的关系
        part: body                  # body（默认） / header / all
        case-insensitive: true      # 默认 true
      - type: regex
        regex: ["root:x:0:0"]
        negative: false             # true 表示取反
    extractors:                     # 可选，命中内容写入 evidence 供人工确认
      - type: regex
        regex: ["root:x:0:0"]
```

`payloads` 支持 list（单一 `{{payload}}`）或 dict + `attack` 组合：
`clusterbomb`（笛卡尔积，默认）/ `pitchfork`（按序并行）/ `batteringram`（同一值填所有键）。

内置变量（可直接在 path/headers/body 中引用）：`BaseURL` / `RootURL` / `Hostname` / `Host` / `Port` / `Scheme` / `Path`。

**不支持**：`raw`（HTTP 原文请求）、`dsl` 表达式、`flow` / `workflows`（多请求串联/工作流）、oob 反连。
含这些特性的模板会被标 `unsupported`，不会静默失效。

## 匹配器与提取器语义

| type | 字段 | 判定 |
|---|---|---|
| status | `status: [200, 301]` | 响应状态码在列表中 |
| word | `words: [...]`, `condition: or/and`, `part: body/header/all`, `case-insensitive` | 关键字是否出现在对应部分 |
| regex | `regex: [...]`, `part`, `case-insensitive` | 任一正则命中即真 |
| size | `size: [1234]` | 响应体长度命中 |

- 多匹配器整体关系由 `matchers-condition` 控制（默认 `or`）；单个匹配器可用 `negative: true` 取反。
- `extractors` 支持 `type: regex` 与 `type: kval`（按 `Key: Value` 抽取响应头），命中片段写入 evidence（最多 5 条）。

## 执行模型

- 每个 POC 对每个目标**最多返回一条**漏洞记录（首个命中的请求）；
- 单 POC 单目标最多发 `MAX_REQUESTS_PER_POC = 10` 个请求，防失控（payload 组合被封顶）；
- `redirects` 默认跟随；写开放重定向类 POC 时显式设 `redirects: false` 并匹配 Location 头（参考 OWASP 检查模块的写法）；
- POC 的 HTTP 走 `utils.http_request`，与框架其余部分共享超时、UA 与免杀配置；
- POC 命中结果同样受 `checks.min_severity`（默认 medium）门槛过滤；**级别为 `info`/`low` 的 POC 连加载都不加载**
  （`checks.skip_severities` 执行级门控，见下）。

## 编写规范（务必遵守）

1. **非破坏性**：只允许 GET/POST 探测类请求，禁止删除/写操作 payload、禁止口令爆破、禁止 DoS 类延时；
2. **精确匹配**：至少组合 status + word/regex 两重条件，避免 `200 即命中` 这种高误报写法；
3. **severity 如实**：信息泄露用 high/medium，初筛信号用 medium/low，不要为了醒目虚标；
   注意默认 `checks.skip_severities = ["info","low"]`（**执行级**）：写 `low`/`info` 的 POC 在扫描时
   **根本不会被执行**（连请求都不发），命中结果还会被 `checks.min_severity`（默认 `medium`）再过滤一次。
   想让某个低级别 POC 真正生效，要么把它写 `medium` 以上，要么在「策略配置」里放宽这两个开关；
4. **id 稳定**：id 用于漏洞去重与报告溯源，发布后不要改；
5. **CTF 导向**：示例 POC 集中在"信息暴露/配置错误"类——CTF 里 flag 常藏在这些位置；针对题目可自写 POC（如匹配响应中的 `flag{` 特征）。

### 示例：CTF flag 检测 POC

```yaml
id: ctf-flag-echo
info:
  name: "响应中包含 flag 特征"
  author: you
  severity: info
  tags: [ctf]
http:
  - method: GET
    path: "/flag"
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: regex
        regex: ["flag\\{[^}]+\\}"]
```

## 与 nuclei 的关系（客观）

本引擎**主动向 nuclei 语法靠拢**（兼容 `http:`/`requests:`、`payloads` + `attack`、`variables` + 内置变量、
`path` 列表、`redirects`、`status/word/regex/size` 匹配器 + `condition`/`negative`/`case-insensitive`/`part`、
`regex`/`kval` extractors），官方模板可直接投放进 `config/nuclei-templates/` 被本引擎加载——从此不依赖 nuclei
二进制，也不与它冲突（同一份模板两边都能跑）。因此不再需要"接入 nuclei 适配器"作为前置项。

尚不支持的是 nuclei 的 `raw`/`dsl`/`flow`/`workflows`/oob，这类模板会被标 `unsupported`；若确需完整能力，
仍可另加适配器调用 nuclei 二进制，`vulns` 表结构可直接承接其 JSON 输出。另：`config/pocs-imported/` 下由
`tools/import_ref_pocs.py` 批量导入的参考项目 POC **默认关闭**，需人工在 POC 管理页挑选后启用。

## 置信度分层（P1-2）

每个 POC 在注册表里会带一个 `confidence`（`high` / `medium` / `low`），由 `db.poc_confidence(path, meta)` 推导：

- **来源分**：`scanner/pocs/pocs/` 内置 = `high`；`config/pocs-user/` 与 `config/nuclei-templates/` = `medium`；
  `config/pocs-imported/`（参考项目静态转换）与其他 = `low`；
- **内容型匹配器降级**：模板只要含 `word`/`words`/`regex`/`size`/`length` 这类匹配器，来源分**降一级**
  （纯 `status` 匹配的规则几乎必然误报）；**只降级不升级**。

它的作用是**排序**而非过滤：`vulnscan` 在同一站点的候选里按置信度排（**指纹命中的仍然绝对优先**），
所以高置信先跑、低置信后跑，预算不足时先跑的是更可能准的规则。扫不扫仍由 `skip_severities`
与 `enabled` 决定。POC 管理页可按置信度层**批量启停**。

> **"实测校准"仍是开放项**：`confidence` 只是**结构上的先验**，不等于"这条规则真的准"。
> 要放开那 305 个导入 POC，仍需在真实授权目标上把误报率跑出来 —— 这也是情报订阅（P3-2）
> 只到「线索」层、不自动灌 POC 的原因（详见 `docs/roadmap.md`）。
