# POC 开发指南

## POC 存放位置

| 目录 | 说明 |
|---|---|
| `scanner/pocs/pocs/*.yaml` | 内置示例 POC，随框架分发 |
| `config/pocs-user/*.yaml` | 用户 POC：GUI「POC 管理」页上传，或手动放置 |
| `config/pocs-imported/*.yaml` | `tools/import_ref_pocs.py` 批量导入的参考项目 POC，**默认关闭**（关键字命中误报率高，需人工在 POC 管理页挑选后启用） |
| `config/nuclei-templates/*.yaml` | 官方 nuclei 模板投放点：本引擎兼容其核心子集，可直接丢进来加载 |

控制台启动时会自动扫描以上目录并写入注册表；之后可在 GUI 里启停每个 POC，也可以点「重新扫描 POC 目录」增量加载。语法错误的 POC 会标注 `error`；`raw` / `flow` / `workflows` / `dsl` 已支持**核心子集**（见下节），超出子集的部分（**块级/顶层** `dsl`、flow 里的 JS/循环、workflow 的 `matchers:` / `args:`、oob 反连）会标注 `unsupported` 或写进 `_note` 并显示原因（不静默失效），扫描时自动跳过或跳过该子项。

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

**不支持**：**块级/顶层** `dsl`、oob 反连、flow 里的 JS/循环/带参数引用、workflow 的 `matchers:`
（按匹配器名分支）与 `args:`（**不是 nuclei 的 workflow 字段**）
（`matchers` / `extractors` 里的 `dsl` 已支持**安全子集**，见下节）。
含这些特性的模板会被标 `unsupported`（或把未实现子项写进原因/`_note`），不会静默失效。

## raw / flow / workflows（2026-09-23 起支持核心子集）

```yaml
id: example-raw-flow
info: {name: 示例, severity: medium}
flow: http(1) && !http(2)          # 布尔子集：&& / || / ! / 括号，引用 id() 或 http(N)
http:
  - raw:                           # nuclei 的 HTTP 原文
      - |
        GET /admin HTTP/1.1
        Host: {{Hostname}}
        X-Test: {{BaseURL}}

    matchers: [{type: status, status: [200]}]
  - id: second
    path: ["/login"]
    matchers: [{type: word, words: ["password"]}]
```

- **raw**：一段手写 HTTP 原文（请求行 + 头 + 空行 + body）。请求**方法白名单**与普通 `method:` 同一套：
  `GET/POST/HEAD/OPTIONS` 等只读方法可用，`PUT`/`PATCH`/`DELETE`/`TRACE`/`CONNECT` **一律拒绝执行**
  并把原因记进 `_note`/`_error`（框架红线：只做只读验证，不做状态变更）。原文里的 `Content-Length`
  会被**丢弃**（由 HTTP 客户端按最终 body 重算，变量渲染后长度不一致会导致截断/挂起）；
  `Host` 头保留（vhost 场景是模板作者的意图），但**请求真正发往的地址永远由目标 `base_url` 决定**。
- **flow**：`&&` / `||` / `!` / 括号 组成的布尔表达式，引用请求块的 `id`（`id_name()`）或 1-based 序号
  （`http(1)`）。语义同 nuclei：表达式成立才算命中。**纯否定式成立不报**（如只有 `!http(1)` —— 没有
  正向响应证据，报出来就是纯误报）。引用越界、或引用了**被跳过的块** → 装载期即标 `unsupported`
  （避免运行期静默不命中）。`||` 短路（左真不发右），`&&` 两块都发。
- **workflows**（2026-09-23 起支持，2026-09-25 续38 补齐条件编排）：workflow 文件顶层写
  `workflows:`，每个子项（语义对齐 nuclei 源码，不自己发明）：

  ```yaml
  workflows:
    - template: technologies/jira-detect.yaml     # 单个文件，或目录（`exploits/jira/`）
      subtemplates:                               # 父步骤**命中才跑**；父只当开关、结果不报
        - tags: [jira]                            # 按标签从候选集里挑（OR 语义）
        - template: exploits/jira/
    - tags: [cve, ssrf]                           # 顶层也可以是纯 tags 选择
  ```

  - `template:`：相对 workflow 文件所在目录解析，解析不到再按项目根解析（官方 workflow 常按
    模板库根写路径）；指向**目录**时展开目录下的 yaml。
  - `tags:`：从候选集里按标签挑，候选集 = 已启用且未被级别门控排除的 POC（与普通 POC 一视同仁）。
    **OR 语义**（命中任意一个标签即选中）；与 `template:` 同时写时 **`tags` 优先**（nuclei 如此）。
  - `subtemplates:`：**父步骤命中才跑**（父没命中 → 子模板一个请求都不发）；带 `subtemplates` 的
    步骤里父模板只当**开关**，父模板自己的命中结果**不报**（否则"技术栈识别"会和子模板结果一起
    冒出来）。多级嵌套同理，逐层门控。
  - 递归保护：深度上限 3、同一模板单次执行内只跑一次（自环直接挡住）、单个步骤一次最多展开
    **40** 个子模板（`tags:` 可能命中整个模板库、目录可能很大，超出部分不执行）。
  - **未实现**：`matchers:`（按匹配器名分支跑 subtemplates —— 本引擎的匹配器没有名字概念）、
    `args:`（**nuclei 的 workflow 没有这个字段**，`WorkflowTemplate` 只有 template / tags /
    matchers / subtemplates；nuclei 的变量传递靠"命名 extractor + 共享执行上下文"，本引擎未实现）。
    这两类子项会被**跳过**并把原因写进 `_note`（全部子项都被跳过 → 整份标 `unsupported`），不静默失效。
- **dsl**（2026-09-25 起支持**安全子集**，仅 `matchers` / `extractors` 里的写法）：变量 6 个 ——
  `status_code` / `content_length`（数值）、`body` / `all_headers` / `header`（后两者同值）/ `host`；
  比较 `==` `!=`（两侧都是数字按数字比）与 `>` `>=` `<` `<=`（**只允许数值**）；逻辑 `&&` `||` `!`
  与括号；函数 `contains` / `icontains` / `starts_with` / `ends_with` / `regex(pattern, input)` /
  `len` / `tolower` / `toupper`。同一 matcher 的多条表达式按 `condition`（默认 `or`）合并；
  `extractors` 里的 `type: dsl` 只把**非布尔**结果写进 evidence（布尔值本身就是"命中/不命中"）。
  **不用 `eval`**（模板是外部输入）：`scanner/pocs/dsl.py` 手写词法 + 递归下降，白名单之外的写法
  在**装载期**就被判掉 —— 整份模板标 `unsupported`，原因写明是哪一处（`matchers`/`extractors`）
  的哪个表达式越界。方法调用式（`body.contains('x')`）、算术（`+`）、`md5()` 等摘要函数、链式比较、
  拿字符串做大小比较、坏 `regex` 模式、空 `dsl` 都属这一类；刻意**不**落成"运行期恒不命中"
  （那会让人以为"模板跑过了、没洞"）。**块级 / 顶层** `dsl` 仍不支持（与上一段的 `dsl` 匹配器严格区分）。

## 匹配器与提取器语义

| type | 字段 | 判定 |
|---|---|---|
| status | `status: [200, 301]` | 响应状态码在列表中 |
| word | `words: [...]`, `condition: or/and`, `part: body/header/all`, `case-insensitive` | 关键字是否出现在对应部分 |
| regex | `regex: [...]`, `part`, `case-insensitive` | 任一正则命中即真 |
| size | `size: [1234]` | 响应体长度命中 |
| dsl | `dsl: [...]`, `condition: or/and` | 白名单表达式的求值结果（`condition` 默认 `or`，多条同时给时用 `and`） |

- 多匹配器整体关系由 `matchers-condition` 控制（默认 `or`）；单个匹配器可用 `negative: true` 取反。
- `extractors` 支持 `type: regex` 与 `type: kval`（按 `Key: Value` 抽取响应头），命中片段写入 evidence（最多 5 条）；
  `type: dsl` 只把**非布尔**结果写进 evidence（见上节）。

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

本引擎**主动向 nuclei 语法靠拢**（兼容 `http:`/`requests:`、`raw` HTTP 原文、
`payloads` + `attack`、`variables` + 内置变量、`path` 列表、`redirects`、
`status/word/regex/size/dsl` 匹配器 + `condition`/`negative`/`case-insensitive`/`part`、
`regex`/`kval`/`dsl` extractors、`flow` 布尔子集、`workflows` 子模板编排），官方模板可直接投放进
`config/nuclei-templates/` 被本引擎加载——从此不依赖 nuclei
二进制，也不与它冲突（同一份模板两边都能跑）。因此不再需要"接入 nuclei 适配器"作为前置项。

尚不支持的是 nuclei 的 oob 反连、flow 里的 JS/循环、workflow 的 `matchers:`（按匹配器名分支）
与 `args:`（**nuclei 的 workflow 里没有这个字段**），以及**块级/顶层**的 `dsl`
（`matchers`/`extractors` 里的 `dsl` 走上面的安全子集），
这类模板（或其未实现子项）会被标 `unsupported` / `_note`；若确需完整能力，
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
