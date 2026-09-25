"""POC 引擎：nuclei 风格 YAML 的简化实现（**兼容 nuclei 模板的核心子集**）。

为什么是"nuclei 子集"而不是"自创一套"（客观结论，2026-09 评估）：
- 参考项目 `myscan_20250825/exploit/scripts/**` 的 POC 是 Python 类脚本
  （继承 `BaseScript`，`detect()/exec()` 异步 aiohttp），**总数约 150 组但强耦合它自己的
  core 框架**（`AsyncFetcher` / `GlobalVariableManager` / `BugLevel` 等）。直接复用等于把
  对方整套框架搬进来，与本项目"零重依赖、外部工具优先"的定位冲突，故**不做运行时依赖**；
  但它的"检测路径 + 关键字命中"语义可以被静态提取成 YAML，见 `tools/import_ref_pocs.py`。
- nuclei 模板是社区事实标准（数千模板、持续更新、YAML 声明式、与本引擎同源）。
  因此这里**主动向 nuclei 语法靠拢**：官方模板可以直接丢进 `config/nuclei-templates/`
  被本引擎加载，从此不依赖 nuclei 二进制，也不与它冲突（同一份模板两边都能跑）。

支持的字段（完整说明见 docs/poc-guide.md）：
  id / info{name, author, severity, tags, description}
  favicon_md5_list（可选，排在 http 段之外）：零请求前置指纹，与 probe 阶段算出的
      站点 favicon MD5 比对，不匹配则整个 POC 一个请求都不发（P1-1）
  http[] 或 requests[]（两种写法等价）
    单请求项：method, path(字符串或列表), headers, body, payloads, attack,
              variables, redirects, matchers, matchers-condition, extractors
              **raw**（nuclei 的 HTTP 原文，2026-09-23 起支持，见下）
  匹配器：type: status | word | regex | size | dsl；part: body | header | all；
          condition: or|and；negative: true；case-insensitive
  dsl 匹配器（2026-09-25 起支持**安全子集**）：`dsl: [表达式, ...]` 由
      `scanner/pocs/dsl.py` 手写词法 + 递归下降求值（**绝不 eval** —— 模板是外部输入）。
      变量 6 个（status_code / content_length / body / all_headers / header / host）、
      比较 `== != > >= < <=`、逻辑 `&& || !`、函数 contains / icontains / starts_with /
      ends_with / regex / len / tolower / toupper；`condition: and` 作用于同一 matcher 的
      多条表达式。**超出子集在装载期就拒**（整份模板标 unsupported 并写明原因），
      不做"运行期恒不命中"这种静默失效。
  提取器：type: regex | kval | dsl（命中内容会写进 evidence，便于人工确认）；
          `internal: true` 的提取器值**不进 evidence**，而是回填模板上下文供后续请求
          `{{name}}` 使用（2026-09-25 续42 起）—— 语义对齐 nuclei 源码
          `pkg/operators/extractors/extractors.go` / `pkg/tmplexec/multiproto/multi.go`：
          回填**只认 `internal: true`**（不设的具名提取器在 nuclei 里同样只进输出、不当变量），
          同一名字的第 1 个值给 `{{name}}`、第 2/3 个给 `{{name1}}`/`{{name2}}`（上限
          `_EXTRACT_VARS_MAX` 个）；回填发生在**匹配之前**（nuclei 的 extractors 本就排在
          matchers 前，且 internal 值的传递不受命中与否影响），所以"第一个请求只取 csrf_token、
          后续请求带着它打"的模板在本引擎里也能跑通。
  flow（2026-09-23 起支持**布尔子集**）：`&&` / `||` / `!` 作用于请求块的 `id` 或
      `http(N)` 1-based 序号；引用能全部解析时才生效，否则整份模板标 unsupported。
      语义同 nuclei：条件成立才算命中；纯否定式成立（如只有 `!http(1)`）**不报**
      （没有正向响应证据，报出来就是纯误报）。
  flow 的**脚本子集**（2026-09-25 续39 起，`scanner/pocs/engine.py` 里 `_FlowJsParser` /
      `_run_flow_script`）：nuclei 的 flow 本来就是一段 JS，官方模板最常见的是
      `for (const v of iterate(...)) { set("v", v); http(1) }`。本引擎**不跑真 JS**，只支持
      封闭子集：`let/const/var`、`if/else`、`for...of iterate(...)`、`for (let i = 0; i < 5; i++)`
      （循环次数必须在装载期算得出来）、`set()` / `http()` / `log()` / `template["k"]`、
      `&& || !`、`== != === !== < > <= >=`、`+`。解析不了的一律**装载期**标 unsupported
      （未声明变量、引用越界、循环不终止、静态语句数超 `_FLOW_MAX_STEPS`）。
      与 nuclei 的已知差异（详见 docs/poc-guide.md）：块要有 matchers 命中才算真（nuclei 对
      无 operators 的块隐式返回 true；但 `internal: true` 提取器的回填照做，见上文）、
      不做类型转换、单值 / 多值命名最多到 `name` + 9 个序号（nuclei 无上限）。
  workflows（2026-09-23 起支持**子模板编排子集**，2026-09-25 续38 补齐条件编排）：
      workflow 文件顶层写 `workflows:`，每个子项（语义对齐 nuclei 源码
      `pkg/templates/workflows.go` / `pkg/core/workflow_execute.go`，不自己发明）：
        `template: <文件或目录>` —— 相对 workflow 文件所在目录解析，解析不到再按项目根；
        目录会展开成目录下的 yaml（nuclei 的 `- template: exploits/jira/` 就是这种写法）
        `tags: [a, b]` —— 从候选集（默认 `load_enabled_pocs`，即注册表开关 + 级别门控）
          按标签挑，**OR 语义**（命中任意一个标签即选中）；与 `template` 同时写时 `tags` 优先
        `subtemplates: [...]` —— **父步骤命中才跑**；带 subtemplates 的步骤里父模板只当
          开关，**父模板自己的结果不报**（否则 workflow 一命中就同时冒出"技术栈识别"噪声）
      递归保护：深度上限 `_WORKFLOW_MAX_DEPTH` + 同一模板单次执行内只跑一次（`seen`），
      单个步骤一次最多展开 `_WORKFLOW_MAX_SUBS` 个子模板。
      **不支持**：`matchers:`（按匹配器名分支 —— 本引擎的匹配器没有名字概念）与
      `args:`（**不是 nuclei 的 workflow 字段**，`WorkflowTemplate` 只有 template / tags /
      matchers / subtemplates；nuclei 的变量传递靠"`internal: true` 命名提取器 + 共享执行
      上下文"，而本引擎的每个子模板各自独立加载、上下文不串，**跨子模板**的传递未实现）——
      两者都把该子项跳过并写进 `_note`（不静默失效）。

**raw 的安全边界**（红线，2026-09-23）：raw 是"手写 HTTP 原文"，最容易被写成利用动作。
因此 `PUT` / `PATCH` / `DELETE` / `TRACE` / `CONNECT` 一律**拒绝执行**并把原因记进
`_note`/`_error`（框架只做只读验证，不做状态变更）；同一套方法白名单也对普通 `method:` 生效。

刻意不做：oob（反连）、**真正的 JS 语义**（方法调用/闭包/异常/除 `+` 外的算术/类型转换，
flow 只支持上面那个封闭子集）、workflow 的 `matchers:`（按匹配器名分支），以及**请求块级/顶层**
`dsl`（nuclei 的 dsl 只写在 `matchers` / `extractors` 里；块级写法仍按
不支持处理 —— 该块跳过并把原因记进 `_note`，不静默失效）。
含这些特性的模板会被标记 `unsupported` 并在 POC 管理页显示原因，而不是静默失效。
"""
import itertools
import pathlib
import re
from urllib.parse import urlparse

try:
    import yaml
except ImportError:
    yaml = None

from ..config import resolve, skip_severities
from .. import db
from ..utils import http_request
from . import dsl as dsl_mod

# POC 目录：内置 / 用户上传 / 参考项目批量导入 / 官方 nuclei 模板投放点
POC_DIRS = ["scanner/pocs/pocs", "config/pocs-user", "config/pocs-imported",
            "config/nuclei-templates"]

# 单个 POC 对单个目标的最大请求数（防止 payload 笛卡尔积把目标打爆）
MAX_REQUESTS_PER_POC = 10

# 命名提取器回填模板上下文时，同一名字最多向外暴露几个值（`name` / `name1` / …）。
# nuclei 是**全部**累积（`pkg/tmplexec/multiproto/multi.go` 里 k / k1 / k2…），这里加个上限
# 只为防"宽 regex 一页抽几千个"把上下文撑爆 —— 取前 10 个已覆盖模板的真实用法。
_EXTRACT_VARS_MAX = 10

# 仍**不支持**的是**请求块级/顶层** `dsl`：nuclei 的 dsl 写在 `matchers` / `extractors` 里，
# 那里已由 `_prepare_dsl()` + `scanner/pocs/dsl.py` 支持安全子集；块级写法按不支持处理 ——
# 该块跳过并把原因记进 `_note`（整份模板若只有它，则标 unsupported）。
_UNSUPPORTED_KEYS = ("dsl",)

# 破坏性/异常方法白名单（框架红线：只做只读验证）。`POST` 保留 —— 大量官方模板用它做
# "只读型"探测（表单提交返回详情页、JSON 接口取值），且 305 个存量 POC 一个都没用到写方法。
_DESTRUCTIVE_METHODS = ("PUT", "PATCH", "DELETE", "TRACE", "CONNECT")

# raw 请求里**丢弃**的头：requests 会自己按最终 body 重算长度；沿用原文的 Content-Length
# 在变量渲染后长度不一致时会导致请求截断或挂起（这是 raw 支持里最容易踩的坑）。
_RAW_DROP_HEADERS = ("content-length",)

# workflow 编排的递归深度上限（A→B→C 之后不再下钻）与单次执行的路径去重
_WORKFLOW_MAX_DEPTH = 3

# workflow 单个步骤一次最多展开多少个子模板：`tags:` 可能命中整个模板库、`template:` 可能
# 指向一个目录，两者都可能把单站点的请求量放大到不可控（nuclei 有 `-rate-limit` 兜着，
# 本引擎没有）。超出部分**不执行**（在 docs/poc-guide.md 里写明）。
_WORKFLOW_MAX_SUBS = 40

_SEVERITIES = ("critical", "high", "medium", "low", "info")


def _norm_severity(value):
    v = str(value or "medium").strip().lower()
    return v if v in _SEVERITIES else "info"


def _requests_of(data):
    """取请求列表，兼容 `http:` 与 nuclei 的 `requests:` 两种写法。"""
    for key in ("http", "requests"):
        blocks = data.get(key)
        if isinstance(blocks, list) and blocks:
            return blocks
    return []


# ---------- raw（HTTP 原文）解析 ----------

def _parse_raw(text):
    """把 nuclei `raw` 块的一段 HTTP 原文拆成 `(parsed, reason)`。

    原文形状（nuclei 标准，请求行 + 头 + 空行 + body）：
        GET /path HTTP/1.1
        Host: {{Hostname}}
        User-Agent: xxx

        body...

    **解析失败或方法被拒**时 `parsed is None`，`reason` 说明原因 —— 调用方必须把它
    记进 `_note`/`_error`（本引擎的一贯口径：不支持的写法要看得见，不静默失效）。
    """
    lines = str(text or "").replace("\r\n", "\n").replace("\r", "\n").split("\n")
    while lines and not lines[0].strip():      # YAML 块标量 `|` 首行常带一个空行
        lines.pop(0)
    if not lines:
        return None, "raw 请求为空"
    parts = lines[0].split()
    if len(parts) < 2 or not re.fullmatch(r"[A-Za-z]+", parts[0]):
        return None, f"raw 请求行不合法（应为「方法 路径 HTTP/1.1」）：{lines[0][:60]}"
    method = parts[0].upper()
    if method in _DESTRUCTIVE_METHODS:
        return None, (f"raw 请求方法 {method} 属破坏性方法，框架不执行"
                      f"（只做只读验证，不做状态变更）")
    headers, i = {}, 1
    while i < len(lines) and lines[i].strip():
        line = lines[i]
        if ":" not in line:
            return None, f"raw 请求头不合法：{line[:60]}"
        name, value = line.split(":", 1)
        name = name.strip()
        if name.lower() in _RAW_DROP_HEADERS:
            i += 1                              # 长度头交给 requests 按最终 body 重算
            continue
        headers[name] = value.strip()
        i += 1
    body = "\n".join(lines[i + 1:]).rstrip("\n") if i < len(lines) else ""
    return {"method": method, "path": parts[1], "headers": headers,
            "body": body or None}, ""


def _block_requests(block):
    """把一个请求块展开成未渲染的请求列表 `[(method, path, headers, body)]`。

    返回 `(items, reasons)`：`reasons` 是被拒绝项的原因（空列表表示全部可用）。
    兼容三种形态：nuclei `raw`（HTTP 原文）、`path` 字符串、`path` 列表。
    """
    raws = block.get("raw")
    if raws:
        items, reasons = [], []
        for one in (raws if isinstance(raws, list) else [raws]):
            parsed, reason = _parse_raw(one)
            if parsed:
                items.append(parsed)
            else:
                reasons.append(reason)
        return items, reasons
    method = str(block.get("method") or "GET").upper()
    if method in _DESTRUCTIVE_METHODS:
        return [], [f"请求方法 {method} 属破坏性方法，框架不执行（只做只读验证）"]
    raw_paths = block.get("path") or block.get("paths") or "/"
    paths = raw_paths if isinstance(raw_paths, list) else [raw_paths]
    headers = dict(block.get("headers") or {})
    return [{"method": method, "path": p, "headers": headers, "body": block.get("body")}
            for p in paths], []


# ---------- flow（条件编排，布尔子集）----------

class _FlowUnsupported(Exception):
    """flow（布尔子集或脚本子集）超出支持范围时抛出，消息即给用户看的原因。"""


_FLOW_ATOM_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_\-]*|\d+")


def _flow_tokens(expr):
    """把 flow 表达式切词。出现反引号/引号/`;` 等即判不支持（那通常是 JS 代码）。"""
    toks, i, text = [], 0, str(expr or "").strip()
    while i < len(text):
        ch = text[i]
        if ch.isspace():
            i += 1
        elif text.startswith("&&", i) or text.startswith("||", i):
            toks.append(text[i:i + 2])
            i += 2
        elif ch in "!()":
            toks.append(ch)
            i += 1
        elif _FLOW_ATOM_RE.match(text, i):
            m = _FLOW_ATOM_RE.match(text, i)
            toks.append(m.group(0))
            i = m.end()
        else:
            raise _FlowUnsupported(f"含不支持的字符 `{ch}`（可能是 JS 代码/字符串参数）")
    if not toks:
        raise _FlowUnsupported("表达式为空")
    return toks


def _flow_parse(toks):
    """递归下降解析 `||` < `&&` < `!` < 括号/引用，返回嵌套元组树。

    引用两种写法：`http(1)`（1-based 序号）与 `id_name()`（请求块的 `id`）。
    """
    pos = [0]

    def peek():
        return toks[pos[0]] if pos[0] < len(toks) else None

    def take():
        t = peek()
        pos[0] += 1
        return t

    def primary():
        t = peek()
        if t == "!":
            take()
            return ("not", primary())
        if t == "(":
            take()
            node = or_expr()
            if take() != ")":
                raise _FlowUnsupported("缺少右括号")
            return node
        if t is None or not (t[0].isalnum() or t[0] == "_"):
            raise _FlowUnsupported(f"不支持的记号 `{t}`")
        name = take()
        if peek() != "(":
            raise _FlowUnsupported(f"裸标识符 `{name}`（应为 id() 或 http(N)）")
        take()
        arg = ""
        if peek() != ")":                   # `id()` 是空参数，`http(1)` 才带序号
            arg = take()
            if arg is None:
                raise _FlowUnsupported(f"引用 `{name}(...)` 写法不合法")
        if take() != ")":
            raise _FlowUnsupported(f"引用 `{name}(...)` 写法不合法")
        low = name.lower()
        if low in ("http", "requests"):
            if not str(arg).isdigit():
                raise _FlowUnsupported(f"`{name}({arg})` 需为请求序号（如 http(1)）")
            return ("ref", int(arg))
        if low in ("for", "foreach", "while", "javascript", "js", "template",
                   "set", "wait"):
            raise _FlowUnsupported(f"`{name}()` 需要 JS/循环引擎，本引擎不执行")
        if str(arg) != "":
            raise _FlowUnsupported(f"`{name}({arg})` 带参数的自定义引用不支持")
        return ("ref", name)

    def and_expr():
        node = primary()
        while peek() == "&&":
            take()
            node = ("&&", node, primary())
        return node

    def or_expr():
        node = and_expr()
        while peek() == "||":
            take()
            node = ("||", node, and_expr())
        return node

    tree = or_expr()
    if pos[0] != len(toks):
        raise _FlowUnsupported(f"多余记号 `{toks[pos[0]]}`")
    return tree


def _flow_tree(expr):
    """`expr` → 解析树；超出子集返回 `(None, 原因)`。"""
    try:
        return _flow_parse(_flow_tokens(expr)), ""
    except _FlowUnsupported as e:
        return None, str(e)


def _flow_refs(node, out=None):
    """收集表达式引用到的全部块（`int` 序号 / `str` id）。"""
    out = set() if out is None else out
    if node[0] == "ref":
        out.add(node[1])
    elif node[0] == "not":
        _flow_refs(node[1], out)
    else:
        _flow_refs(node[1], out)
        _flow_refs(node[2], out)
    return out


def _flow_bad_refs(tree, blocks, ok_idx):
    """布尔子集的引用可解析性（口径见 `_bad_refs`）。"""
    return _bad_refs(_flow_refs(tree), blocks, ok_idx)


def _bad_refs(refs, blocks, ok_idx, str_as_call=True):
    """返回解析不到的引用（序号越界/该块被跳过、或本文件没有该 id）。

    `http(N)` 指的是核模板里 `http:` 列表的**第 N 块**（原始顺序），所以这里按原始下标
    判定 —— 跳过一块后序号会错位，把 `http(2)` 当成"跳过后剩下的第 2 块"就是错判。

    布尔子集与脚本子集**共用这一处判定**（两种写法引用的是同一份块表，口径必须一致）；
    `str_as_call` 只影响报错文本的写法（`a()` 还是 `http("a")`）。
    """
    ids = {str(blocks[i].get("id")) for i in ok_idx if blocks[i].get("id")}
    bad = []
    for ref in sorted(set(refs), key=str):
        if isinstance(ref, int):
            if not 1 <= ref <= len(blocks) or (ref - 1) not in ok_idx:
                bad.append(f"http({ref})")
        elif ref not in ids:
            bad.append(f"{ref}()" if str_as_call else f'http("{ref}")')
    return bad


# ---------- flow 的 JS 子集（脚本式编排，2026-09-25 续39）----------
#
# nuclei 的 `flow:` 是**一段 JS**（goja 执行，见 `pkg/tmplexec/flow/flow_executor.go`，
# 注意不在 `pkg/protocols/common/flow/`），官方模板里最常见的就是"循环 + set + 请求"：
#
#     flow: |
#       for (const user of iterate("admin", "root")) {
#         set("user", user)
#         http(1)
#       }
#
# 本引擎没有 JS 解释器，也**不允许**把模板变成可执行代码，所以只支持一个**封闭子集**：
# 装载期把脚本解析成 AST 并做静态校验（未声明变量、引用越界、循环是否终止、语句数上限），
# 运行期只按 AST 解释执行。子集之外的写法在装载期整份标 `unsupported` 并写明原因 ——
# 与 `dsl` 子集同一条红线：绝不"运行期静默不命中"。
#
# 与 nuclei 对齐的口径（逐条对着源码写，不自己发明）：
#   - `http(N)` 是 1-based（`flow_executor.go` 里 `counter++ // start index from 1`）；
#     `http("id")` 按块 id；`http()` 按模板顺序跑该协议**全部块**；`http(1, 2)` 按传入顺序；
#     文档里的 `http(0)` 是过时写法，代码里 0 号不存在（本引擎同样拒）
#   - `set(name, value)` 写进模板上下文 → 后续请求里的 `{{name}}`（`flow_internal.go`）
#   - `iterate(...)` 把参数**扁平化成数组**（`pkg/tmplexec/flow/vm.go`），不是"遍历请求块"
#   - `template` 是**对象不是函数**（`flow_executor.go`），读模板上下文的值
# 与 nuclei 的**已知差异**（写在 docs/poc-guide.md 里，不假装一致）：
#   - 本引擎"块要有 matchers 命中才算真"（`_match_response` 对空 matchers 返回 False），
#     nuclei 对**无 operators** 的块隐式返回 true；
#   - extractor 结果**不回填** `template`（nuclei 靠它把 http(1) 的提取值喂给 http(2)）；
#   - 不做真正的 JS：没有类型转换（`1 == "1"` 在 JS 里为真、这里为假）、没有方法调用、
#     没有闭包/异常/`while`/`break`/`continue`、除 `+` 之外没有算术。

# flow 脚本一次执行的语句数上限。循环次数与语句数都在**装载期算清**（本引擎不跑真 JS，
# 也就不需要"跑到一半掐断"这种会**静默半执行**的运行期兜底）。
_FLOW_MAX_STEPS = 200

# 明确点名的写法：给专门的原因，而不是笼统的"语法错误"。键是标识符写法。
_FLOW_JS_REJECT = {
    "while": "`while` 循环（只支持能静态数清的 `for`）",
    "do": "`do...while` 循环",
    "break": "`break`",
    "continue": "`continue`",
    "return": "`return`",
    "function": "`function` 定义",
    "new": "`new`（含 `new Dedupe()`）",
    "class": "`class`",
    "switch": "`switch`",
    "try": "`try`/`catch`",
    "throw": "`throw`",
    "typeof": "`typeof`",
    "delete": "`delete`",
    "await": "`await`",
    "async": "`async`",
    "eval": "`eval`（模板不是可执行代码）",
    "require": "`require`",
    "console": "`console`",
    "Math": "`Math`",
    "JSON": "`JSON`",
    "String": "`String`",
    "Number": "`Number`",
    "Array": "`Array`",
    "Object": "`Object`",
    "Date": "`Date`",
    "RegExp": "`RegExp`",
    "dns": "`dns()`：本引擎只有 http/requests 块，没有 dns 协议",
    "network": "`network()`：本引擎只有 http/requests 块，没有 network 协议",
    "file": "`file()`：本引擎只有 http/requests 块，没有 file 协议",
    "headless": "`headless()`：本引擎只有 http/requests 块，没有 headless 协议",
    "ssl": "`ssl()`：本引擎只有 http/requests 块，没有 ssl 协议",
    "websocket": "`websocket()`：本引擎只有 http/requests 块，没有 websocket 协议",
    "whois": "`whois()`：本引擎只有 http/requests 块，没有 whois 协议",
    "code": "`code()`：本引擎只有 http/requests 块，没有 code 协议",
    "javascript": "`javascript()`：本引擎只有 http/requests 块，没有 javascript 协议",
}

_FLOW_JS_TOKEN_RE = re.compile(r"""
    (?P<ws>\s+)
  | (?P<num>\d+)
  | (?P<str>"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')
  | (?P<id>[A-Za-z_$][A-Za-z0-9_$]*)
  | (?P<op>===|!==|=>|==|!=|<=|>=|&&|\|\||\+\+|--|[{}()\[\];,.=<>!+])
""", re.X)


def _flow_js_tokens(text):
    """把 flow 脚本切词；子集外的字符（反引号模板串、`*` `/` `%` 等算术）即判不支持。"""
    toks, i, text = [], 0, str(text or "")
    while i < len(text):
        m = _FLOW_JS_TOKEN_RE.match(text, i)
        if not m:
            raise _FlowUnsupported(
                f"脚本含不支持的字符 `{text[i]}`（子集里除 `+` 之外没有算术）")
        i = m.end()
        kind, val = m.lastgroup, m.group(0)
        if kind == "ws":
            continue
        if kind == "num":
            toks.append(("num", int(val)))
        elif kind == "str":
            toks.append(("str", dsl_mod._unquote(val)))   # 字符串去转义复用 dsl 那套
        elif kind == "id":
            toks.append(("id", val))
        else:
            toks.append(("op", val))
    return toks


def _flow_js_iters(start, op, bound, step):
    """C 式 `for` 的**静态**迭代次数；返回 `None` 表示这个循环不会终止（装载期就拒）。

    条件一开始就不成立 → 0 次（JS 如此），哪怕步进方向与条件相反。
    """
    if op == "<":
        return max(0, bound - start) if step > 0 else (0 if start >= bound else None)
    if op == "<=":
        return max(0, bound - start + 1) if step > 0 else (0 if start > bound else None)
    if op == ">":
        return max(0, start - bound) if step < 0 else (0 if start <= bound else None)
    return max(0, start - bound + 1) if step < 0 else (0 if start < bound else None)


def _flow_js_steps(stmts):
    """静态语句数**上界**（`if` 两支都算，循环按装载期算好的次数展开）。"""
    total = 0
    for s in stmts:
        total += 1
        if s[0] == "if":
            total += _flow_js_steps(s[2]) + _flow_js_steps(s[3])
        elif s[0] == "forof":
            total += s[4] * _flow_js_steps(s[3])
        elif s[0] == "fornum":
            total += s[7] * _flow_js_steps(s[6])
    return total


class _FlowJsParser:
    """`flow:` 脚本子集的装载期解析器（纯结构 + 静态校验，不发任何请求）。

    语法（封闭白名单）：
      语句：`let/const/var NAME = expr`（`;` 可有可无）、
            `if (expr) { ... } [else { ... } / else if ...]`、
            `for (const NAME of iterate(...)) { ... }`、
            `for (let i = 0; i < 5; i++) { ... }`（起止必须是**整数字面量**，步进 `++`/`--`）、
            表达式语句（`set(...)` / `http(1)` / `log(...)`）
      表达式：整数/字符串/`true`/`false`/`null`/`undefined`、局部变量、
            `template["key"]` / `template.key`、`&&` `||` `!`、`== != === !== < > <= >=`、
            `+`（数值相加或字符串拼接）、括号
    子集之外的写法（`while`、对象/数组字面量、`new`、`console`/`Math`、方法调用、算术、
    本引擎没有的协议块如 `dns()`）一律在装载期报错，**错误文本就是给用户看的原因**。
    """

    def __init__(self, text):
        self.toks = _flow_js_tokens(text)
        self.pos = 0
        self.refs = []              # `http(...)` 引用（装载期用 `_bad_refs` 校验）
        self.scopes = [set()]       # 已声明的局部变量（分层；本子集不做变量提升）

    # ---------- 记号工具 ----------
    def _peek(self, k=0):
        i = self.pos + k
        return self.toks[i] if i < len(self.toks) else None

    def _take(self):
        t = self._peek()
        self.pos += 1
        return t

    def _is_op(self, *vals):
        t = self._peek()
        return bool(t) and t[0] == "op" and t[1] in vals

    def _is_word(self, *words):
        t = self._peek()
        return bool(t) and t[0] == "id" and t[1] in words

    def _expect_op(self, val):
        t = self._take()
        got = t[1] if t else "脚本结束"
        if not t or t[0] != "op" or t[1] != val:
            raise _FlowUnsupported(f"缺少 `{val}`（实际是 `{got}`）")

    def _name(self, what="变量名"):
        t = self._take()
        if not t or t[0] != "id":
            raise _FlowUnsupported(f"{what}不合法（实际是 `{t[1] if t else '脚本结束'}`）")
        return t[1]

    def _declared(self, name):
        return any(name in s for s in self.scopes)

    def _end_stmt(self):
        if self._is_op(";"):
            self._take()

    # ---------- 语句 ----------
    def parse(self):
        stmts = self._stmts(top=True)
        if not stmts:
            raise _FlowUnsupported("脚本为空")
        return ("script", stmts, self.refs)

    def _stmts(self, top=False):
        out = []
        while True:
            t = self._peek()
            if t is None:
                break
            if t[0] == "op" and t[1] == "}":
                if top:
                    raise _FlowUnsupported("多了一个 `}`")
                break
            if t[0] == "op" and t[1] == ";":        # 空语句
                self._take()
                continue
            out.append(self._stmt())
        return out

    def _stmt(self):
        t = self._peek()
        if t[0] == "id" and t[1] in _FLOW_JS_REJECT:
            raise _FlowUnsupported(f"不支持 {_FLOW_JS_REJECT[t[1]]}")
        if self._is_word("let", "const", "var"):
            return self._let()
        if self._is_word("if"):
            return self._if()
        if self._is_word("for"):
            return self._for()
        node = self._expr()
        self._end_stmt()
        return ("expr", node)

    def _let(self):
        self._take()                                # let / const / var
        name = self._name()
        if self._is_op(";"):                        # `let x;`（未初始化 → 空值）
            self._take()
            self.scopes[-1].add(name)
            return ("let", name, ("null",))
        self._expect_op("=")
        val = self._expr()
        self._end_stmt()
        self.scopes[-1].add(name)
        return ("let", name, val)

    def _if(self):
        self._take()
        self._expect_op("(")
        cond = self._expr()
        self._expect_op(")")
        then = self._block()
        other = []
        if self._is_word("else"):
            self._take()
            other = [self._if()] if self._is_word("if") else self._block()
        return ("if", cond, then, other)

    def _block(self):
        self._expect_op("{")
        self.scopes.append(set())
        stmts = self._stmts()
        self._expect_op("}")
        self.scopes.pop()
        return stmts

    def _for(self):
        self._take()
        self._expect_op("(")
        if not self._is_word("let", "const", "var"):
            got = self._peek()
            raise _FlowUnsupported(
                f"`for` 的初始化必须是 `let/const/var` 声明（实际是 "
                f"`{got[1] if got else '脚本结束'}`）")
        self._take()
        name = self._name()
        if self._is_word("of"):
            self._take()
            return self._for_of(name)
        return self._for_num(name)

    def _for_of(self, name):
        if not self._is_word("iterate"):
            got = self._peek()
            raise _FlowUnsupported(
                f"`for...of` 只能遍历 `iterate(...)`（本引擎没有数组值，实际是 "
                f"`{got[1] if got else '脚本结束'}`）")
        self._take()
        args = self._args()
        self._expect_op(")")                        # `for (...)` 自己的右括号
        iters = len(args)                           # 每个参数恰好产生一个迭代值
        self.scopes.append({name})
        body = self._block()
        self.scopes.pop()
        return ("forof", name, args, body, iters)

    def _for_num(self, name):
        self._expect_op("=")
        start = self._int_literal("循环起点")
        self._expect_op(";")
        if self._name("循环条件里的变量") != name:
            raise _FlowUnsupported("`for` 的循环变量在三处必须一致")
        op = self._take()
        if not op or op[0] != "op" or op[1] not in ("<", "<=", ">", ">="):
            raise _FlowUnsupported("`for` 的条件要写成 `i < 5` / `i >= 0` 这种整数字面量比较")
        bound = self._int_literal("循环终点")
        self._expect_op(";")
        if self._name("步进里的变量") != name:
            raise _FlowUnsupported("`for` 的循环变量在三处必须一致")
        upd = self._take()
        if not upd or upd[0] != "op" or upd[1] not in ("++", "--"):
            raise _FlowUnsupported("`for` 的步进只支持 `i++` / `i--`")
        self._expect_op(")")
        step = 1 if upd[1] == "++" else -1
        iters = _flow_js_iters(start, op[1], bound, step)
        if iters is None:
            raise _FlowUnsupported(
                f"这个 `for` 不会终止（`i {op[1]} {bound}` 配 `i{upd[1]}`）—— "
                f"循环次数必须在装载期算得出来")
        self.scopes.append({name})
        body = self._block()
        self.scopes.pop()
        return ("fornum", name, start, op[1], bound, step, body, iters)

    def _int_literal(self, what):
        t = self._take()
        if not t or t[0] != "num":
            raise _FlowUnsupported(f"{what}必须是整数字面量（实际是 "
                                   f"`{t[1] if t else '脚本结束'}`）")
        return t[1]

    # ---------- 表达式 ----------
    def _expr(self):
        return self._or()

    def _or(self):
        node = self._and()
        while self._is_op("||"):
            self._take()
            node = ("bin", "||", node, self._and())
        return node

    def _and(self):
        node = self._cmp()
        while self._is_op("&&"):
            self._take()
            node = ("bin", "&&", node, self._cmp())
        return node

    def _cmp(self):
        node = self._add()
        while self._is_op("==", "!=", "===", "!==", "<", ">", "<=", ">="):
            op = self._take()[1]
            node = ("bin", op, node, self._add())
        return node

    def _add(self):
        node = self._unary()
        while self._is_op("+"):
            self._take()
            node = ("bin", "+", node, self._unary())
        return node

    def _unary(self):
        if self._is_op("!"):
            self._take()
            return ("not", self._unary())
        return self._primary()

    def _args(self):
        """解析 `(a, b, c)` 形式的实参列表（`(` 还没被吃掉）。"""
        self._expect_op("(")
        out = []
        if not self._is_op(")"):
            out.append(self._expr())
            while self._is_op(","):
                self._take()
                out.append(self._expr())
        self._expect_op(")")
        return out

    def _primary(self):
        t = self._take()
        if t is None:
            raise _FlowUnsupported("表达式意外结束")
        kind, val = t
        if kind == "num":
            return ("num", val)
        if kind == "str":
            return ("str", val)
        if kind == "op" and val == "(":
            node = self._expr()
            self._expect_op(")")
            return node
        if kind == "op" and val == "=>":
            raise _FlowUnsupported("箭头函数（`=>`）不在子集里")
        if kind != "id":
            raise _FlowUnsupported(f"不支持的写法 `{val}`")
        if val in ("true", "false"):
            return ("bool", val == "true")
        if val in ("null", "undefined"):
            return ("null",)
        if val in _FLOW_JS_REJECT:
            raise _FlowUnsupported(f"不支持 {_FLOW_JS_REJECT[val]}")
        if val == "template":
            return self._template_member()
        if self._is_op("("):
            return self._call(val)
        if not self._declared(val):
            raise _FlowUnsupported(
                f"未声明的变量 `{val}`（脚本只能读 `template[\"key\"]` 与前面声明过的局部变量）")
        return ("id", val)

    def _template_member(self):
        if self._is_op("["):
            self._take()
            key = self._take()
            if not key or key[0] != "str":
                raise _FlowUnsupported("`template[...]` 的键必须是字符串字面量（不做动态键）")
            self._expect_op("]")
            return ("tmpl", key[1])
        if self._is_op("."):
            self._take()
            return ("tmpl", self._name("`template.` 后面的键名"))
        raise _FlowUnsupported("`template` 是对象不是函数，读值要写成 `template[\"key\"]`")

    def _call(self, name):
        args = self._args()
        if name == "iterate":
            raise _FlowUnsupported("`iterate()` 只能用在 `for (... of iterate(...))` 的头部")
        if name in ("http", "requests"):
            for a in args:
                if a[0] == "num":
                    self.refs.append(a[1])
                elif a[0] == "str":
                    self.refs.append(a[1])
                else:
                    raise _FlowUnsupported(
                        "`http(...)` 的参数只能是请求序号 `http(1)` 或块 id `http(\"id\")`，"
                        "且必须是字面量（不做动态序号）")
            return ("call", "http", args)
        if name == "set":
            if len(args) != 2:
                raise _FlowUnsupported(f"`set()` 需要 2 个参数，实际 {len(args)} 个")
            if args[0][0] != "str":
                raise _FlowUnsupported("`set()` 的第一个参数必须是字符串字面量（变量名）")
            return ("call", "set", args)
        if name == "log":
            if len(args) > 1:
                raise _FlowUnsupported(f"`log()` 最多 1 个参数，实际 {len(args)} 个")
            return ("call", "log", args)
        raise _FlowUnsupported(
            f"不支持的函数 `{name}()`（脚本可调用的只有 `http` / `set` / `iterate` / `log`）")


def _flow_js_parse(flow):
    """`flow:` 源串 → `(prog, reason)`；可解析且通过静态校验时 `reason` 为空串。"""
    try:
        prog = _FlowJsParser(flow).parse()
    except _FlowUnsupported as e:
        return None, str(e)
    steps = _flow_js_steps(prog[1])
    if steps > _FLOW_MAX_STEPS:
        return None, (f"静态语句数上界 {steps} 超过上限 {_FLOW_MAX_STEPS}"
                      f"（循环次数在装载期就算清，本引擎不做“跑到一半掐断”）")
    return prog, ""


def _js_eq(a, b, strict):
    """`==` / `===`。本引擎**不做** JS 的类型转换（`1 == "1"` JS 为真、这里为假）：
    同类型按类型比，`===` 另要求类型一致，其余按文本比。"""
    if strict and type(a) is not type(b):
        return False
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a == b
    if isinstance(a, str) and isinstance(b, str):
        return a == b
    return str(a) == str(b)


def _js_cmp(op, a, b):
    """`<` `>` `<=` `>=`：两侧都是数字按数值比，否则按字符串比。"""
    num = lambda v: isinstance(v, (int, float)) and not isinstance(v, bool)
    x, y = (a, b) if num(a) and num(b) else (str(a), str(b))
    return {"<": x < y, "<=": x <= y, ">": x > y, ">=": x >= y}[op]


def _run_flow_script(prog, run_blocks, variables):
    """执行 flow 脚本子集，返回按执行顺序收集到的**正向命中**（vuln dict 列表）。

    `run_blocks(refs)` 负责真正发请求：`refs` 为 `None` 表示"该协议的全部块（按模板顺序）"，
    否则是 `http(1)` / `http("id")` 的引用列表（**按传入顺序**）；返回命中的 vuln dict 或 None。
    `variables` 就是模板上下文（`{{name}}` 的来源），`set()` 直接写它 —— nuclei 也是把整份
    上下文当 input event 交给请求的（`pkg/tmplexec/flow/flow_internal.go`）。

    这里不做运行期次数兜底：循环次数与语句数在装载期都算清了（见 `_flow_js_steps`），
    请求总量另受 `budget`（`MAX_REQUESTS_PER_POC`）约束。
    """
    ctx = {"vars": variables, "run": run_blocks, "hits": []}

    def ev(n, env):
        k = n[0]
        if k in ("num", "str"):
            return n[1]
        if k == "bool":
            return n[1]
        if k == "null":
            return None
        if k == "id":
            return env.get(n[1], "")
        if k == "tmpl":
            return ctx["vars"].get(n[1], "")
        if k == "not":
            return not dsl_mod.truthy(ev(n[1], env))
        if k == "call":
            if n[1] == "set":
                ctx["vars"][str(ev(n[2][0], env))] = ev(n[2][1], env)
                return None
            if n[1] == "log":
                # nuclei 的 `log()` 打到 stdout 仅作调试；本引擎没有引擎级日志器，这里按它的
                # 返回值语义「原样返回参数」处理，**不打印**（docs/poc-guide.md 写明）。
                return ev(n[2][0], env) if n[2] else ""
            args = [ev(a, env) for a in n[2]]
            hit = ctx["run"](args if args else None)
            if hit:
                ctx["hits"].append(hit)
            return bool(hit)
        op = n[1]                                   # ("bin", op, a, b)
        a = ev(n[2], env)
        if op == "&&":
            return dsl_mod.truthy(a) and dsl_mod.truthy(ev(n[3], env))
        if op == "||":
            return dsl_mod.truthy(a) or dsl_mod.truthy(ev(n[3], env))
        b = ev(n[3], env)
        if op in ("==", "!="):
            eq = _js_eq(a, b, False)
            return (not eq) if op == "!=" else eq
        if op in ("===", "!=="):
            eq = _js_eq(a, b, True)
            return (not eq) if op == "!==" else eq
        if op == "+":
            num = lambda v: isinstance(v, (int, float)) and not isinstance(v, bool)
            if num(a) and num(b):
                return a + b
            if a is None:
                return b
            return b if b is None else f"{a}{b}"
        return _js_cmp(op, a, b)

    def stmts(items, env):
        for s in items:
            k = s[0]
            if k == "expr":
                ev(s[1], env)
            elif k == "let":
                env[s[1]] = ev(s[2], env)
            elif k == "if":
                branch = s[2] if dsl_mod.truthy(ev(s[1], env)) else s[3]
                stmts(branch, dict(env))             # 块内声明不外泄（let/const 语义）
            elif k == "forof":
                for v in [ev(a, env) for a in s[2]]:
                    if v is None:                    # nuclei：nil 跳过（`vm.go`）
                        continue
                    inner = dict(env)
                    inner[s[1]] = v
                    stmts(s[3], inner)
            else:                                    # ("fornum", name, start, op, bound, step, body, iters)
                name, start, op, bound, step = s[1], s[2], s[3], s[4], s[5]
                i = start
                while (i < bound if op == "<" else i <= bound if op == "<="
                       else i > bound if op == ">" else i >= bound):
                    inner = dict(env)
                    inner[name] = i
                    stmts(s[6], inner)
                    i += step

    stmts(prog[1], {})
    return ctx["hits"]


def _runnable_blocks(data):
    """挑出可执行的请求块，返回 `(blocks, ok_idx, notes)`。

    `blocks` 是 `http:`/`requests:` 的**原始顺序**（`flow` 的 `http(N)` 按它编号），
    `ok_idx` 是其中可用块的下标；`notes` 是每个被跳过块的原因（供 `_note` 汇总展示）。
    """
    blocks = _requests_of(data)
    ok_idx, notes = [], []
    for i, b in enumerate(blocks):
        if not isinstance(b, dict) or any(k in b for k in _UNSUPPORTED_KEYS):
            notes.append("含请求块级 dsl 的请求块已跳过"
                         "（nuclei 的 dsl 写在 matchers / extractors 里）")
            continue
        items, reasons = _block_requests(b)
        if not items:
            notes.append(reasons[0] if reasons else "请求块为空，已跳过")
            continue
        ok_idx.append(i)
    return blocks, ok_idx, notes


def _prepare_dsl(blocks, ok_idx):
    """装载期把 `type: dsl` 的匹配器/提取器解析成 AST；任一表达式越界就返回原因（否则空串）。

    解析结果挂在各自的 dict 上（`_dsl_ast`），运行期只求值、不再解析 —— 与 `_flow` 同一思路：
    能在装载期判掉的一律判掉，运行期只允许"确定的事"。
    """
    for i in ok_idx:
        b = blocks[i]
        for holder in ("matchers", "extractors"):
            for entry in (b.get(holder) or []):
                if not isinstance(entry, dict):
                    continue
                if str(entry.get("type") or "").lower() != "dsl":
                    continue
                exprs = dsl_mod.expressions(entry)
                if not exprs:
                    return f"{holder} 里有一条 `dsl` 为空"
                asts = []
                for e in exprs:
                    node, reason = dsl_mod.parse(e)
                    if node is None:
                        # 带上 `matchers`/`extractors` 与原文：模板里可能有多处 dsl，
                        # 只说"哪个表达式错"不够 —— 用户要能直接定位到改哪一行。
                        return f"{holder} 的 `{str(e)[:60]}`：{reason}"
                    asts.append(node)
                entry["_dsl_ast"] = asts
    return ""


def _wf_tags(item):
    """取一个 workflow 子项的 `tags:`（nuclei 的 StringSlice：`"a,b"` 与 `[a, b]` 都合法）。"""
    raw = item.get("tags")
    if raw is None:
        return []
    out = []
    for v in (raw if isinstance(raw, list) else [raw]):
        for part in str(v).split(","):
            part = part.strip().lower()
            if part:
                out.append(part)
    return out


def _wf_steps(items, skipped):
    """把 `workflows:` 子项解析成步骤树（装载期，纯结构解析，不发任何请求）。

    语义对着 nuclei 源码（`pkg/templates/workflows.go::parseWorkflow` /
    `parseWorkflowTemplate`）写，不自己发明：

    - 每项必须有 `template:` 或 `tags:`；两者都空 → nuclei 直接判
      `invalid workflow with no templates or tags`。**顶层只有 `subtemplates:` 的项永远
      不生效** —— 它是挂在别的步骤下面的，不能单独当步骤；这里跳过该项并写明原因。
    - 两者**同时写时 `tags` 优先**、`template` 被忽略（nuclei 就是这么写的，照抄）。
    - `subtemplates:` 递归解析，**只在父步骤命中时才跑**。
    - `matchers:`（按匹配器名分支跑 subtemplates）不支持：本引擎的匹配器没有名字概念，
      跳过该项并把原因记进 `_note`（不静默失效）。
    - `args:` **不是 nuclei 的 workflow 字段**（`pkg/workflows/workflows.go` 的
      `WorkflowTemplate` 只有 template / tags / matchers / subtemplates）。nuclei 的变量
      传递靠"命名 extractor + 共享执行上下文"，本引擎未实现 —— 见到 `args:` 说明模板作者
      写错了字段，跳过该项并写明原因，而不是假装支持。
    """
    steps = []
    for item in items:
        if not isinstance(item, dict):
            skipped.append("非映射（不是 `键: 值`）的 workflow 子项")
            continue
        if item.get("matchers"):
            skipped.append("`matchers:`（按匹配器名分支的 subtemplates）")
            continue
        if item.get("args"):
            skipped.append("`args:`（nuclei workflow 无此字段，变量共享靠命名 extractor）")
            continue
        tags = _wf_tags(item)
        tpl = item.get("template")
        tpl = tpl.strip() if isinstance(tpl, str) else ""
        if not tags and not tpl:
            skipped.append("既无 `template:` 也无 `tags:` 的子项"
                           "（只有 `subtemplates:` 不算步骤，nuclei 判为非法）")
            continue
        steps.append({"path": "" if tags else tpl, "tags": tags,
                      "subtemplates": _wf_steps(item.get("subtemplates") or [], skipped)})
    return steps


def load_poc_file(path):
    """加载并校验单个 POC 文件，返回带 _status 标记的 dict（永不抛异常）。"""
    p = pathlib.Path(str(path))
    if yaml is None:
        return {"id": p.stem, "_status": "error", "_error": "PyYAML 未安装"}
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except Exception as e:
        return {"id": p.stem, "_status": "error", "_error": str(e)[:300]}
    if not isinstance(data, dict) or not data.get("id"):
        return {"id": p.stem, "_status": "error", "_error": "缺少 id"}
    data["_path"] = str(p)

    # nuclei **workflow** 文件：顶层只有 `workflows:`（编排若干子模板），没有 http/requests 段。
    # 支持的是 nuclei 的**结构子集**：`template:`（文件/目录）、`tags:`（按标签挑）、
    # `subtemplates:`（父步骤命中才跑）；`matchers:` / `args:` 见 `_wf_steps` 的说明。
    if isinstance(data.get("workflows"), list) and data["workflows"]:
        skipped = []
        data["_workflow"] = _wf_steps(data["workflows"], skipped)
        if not data["_workflow"]:
            data["_status"] = "unsupported"
            data["_error"] = ("workflow 子项均不可用：" + "；".join(dict.fromkeys(skipped))
                              if skipped else "workflow 子项为空")
            return data
        data["_status"] = "ok"
        if skipped:
            data["_note"] = "；".join(dict.fromkeys(skipped))
        return data

    if not _requests_of(data):
        if any(k in data for k in _UNSUPPORTED_KEYS):
            return {"id": data.get("id"), "_status": "unsupported",
                    "_error": ("顶层 dsl 不支持（nuclei 的 dsl 写在 matchers / extractors 里，"
                               "形如 `matchers: [{type: dsl, dsl: ['status_code == 200']}]`）"),
                    "_path": str(p)}
        return {"id": p.stem, "_status": "error", "_error": "缺少 http/requests 段"}
    blocks, ok_idx, notes = _runnable_blocks(data)
    if not ok_idx:
        return {"id": data.get("id"), "_status": "unsupported",
                "_error": f"全部请求块被跳过（{notes[0] if notes else '空块'}）",
                "_path": str(p)}
    # dsl：与 flow 同理，**装载期**解析并校验。运行期才发现表达式不合法，只能按不命中处理
    # —— 那正是本引擎最反对的静默失效（用户会以为"模板跑过了、没洞"）。
    dsl_err = _prepare_dsl(blocks, ok_idx)
    if dsl_err:
        return {"id": data.get("id"), "_status": "unsupported",
                "_error": f"dsl 表达式超出支持子集：{dsl_err}", "_path": str(p)}
    # flow：解析 + 引用可解析性都在**装载期**判掉。运行期才发现引用不到，只能"按不命中"
    # 处理 —— 那正是本引擎最反对的静默失效（用户会以为模板没洞）。
    # 先按**布尔子集**解析（`http(1) && http(2)` 这类，语义与续17 完全一致）；解析不了再按
    # **脚本子集**解析（`for (...) { set(...); http(1) }`，续39）。两条路都过不了才判不支持，
    # 报错文本把两个原因都带上（用户能一眼看出是"写错了"还是"用了子集外的东西"）。
    if data.get("flow"):
        tree, reason = _flow_tree(data["flow"])
        if tree is not None:
            bad = _flow_bad_refs(tree, blocks, ok_idx)
            if bad:
                data["_status"] = "unsupported"
                data["_error"] = "flow 引用了不存在/被跳过的请求块：" + "、".join(bad)
                return data
            data["_flow"] = tree
        else:
            prog, js_reason = _flow_js_parse(data["flow"])
            if prog is None:
                data["_status"] = "unsupported"
                data["_error"] = (f"flow 超出支持子集：{reason}；"
                                  f"脚本子集也不支持：{js_reason}")
                return data
            bad = _bad_refs(prog[2], blocks, ok_idx, str_as_call=False)
            if bad:
                data["_status"] = "unsupported"
                data["_error"] = "flow 引用了不存在/被跳过的请求块：" + "、".join(bad)
                return data
            data["_flow_script"] = prog
    data["_status"] = "ok"
    if notes:
        data["_note"] = "；".join(dict.fromkeys(notes))
    return data


def iter_poc_files(settings=None):
    for d in POC_DIRS:
        base = resolve(d)
        if base.is_dir():
            for f in sorted(base.glob("*.yaml")) + sorted(base.glob("*.yml")):
                yield f


def load_all_meta(settings=None):
    """加载目录内全部 POC 的元信息（含 error/unsupported 项，供注册表展示）。"""
    return [load_poc_file(f) for f in iter_poc_files(settings)]


def load_enabled_pocs(settings=None):
    """扫描用：仅返回 status=ok、注册表启用、且**级别未被 `checks.skip_severities` 排除**的 POC。

    `skip_severities`（默认 info + low）与内置检查同一套规则：这些 POC 的结论同样会被
    `min_severity` 丢掉，不执行只省请求（导入的 300+ 个 POC 里此类模板不少）。
    未知/缺失 severity 由 `_norm_severity` 归为 info，同样会被跳过 —— 想让某条 info 级
    POC 生效，把它自己写 severity 改成 medium 以上，或在策略配置里清空 skip_severities。
    """
    try:
        enabled = set(db.enabled_poc_paths())
    except Exception:
        enabled = None  # 注册表未初始化时不做过滤
    skip = skip_severities(settings)
    out = []
    for m in load_all_meta(settings):
        if m.get("_status") != "ok":
            continue
        if enabled is not None and m.get("_path") not in enabled:
            continue
        if _norm_severity((m.get("info") or {}).get("severity")) in skip:
            continue
        # 置信度分层（P1-2）：在内存里按同一套规则现算，供 vulnscan 排序用
        # （库里也存了一份，那份是给 GUI 展示/筛选用的，两者算法同源 `db.poc_confidence`）。
        m["_confidence"] = db.poc_confidence(m.get("_path") or "", m)
        out.append(m)
    return out


# ---------- 变量渲染 ----------

_VAR_RE = re.compile(r"\{\{\s*([A-Za-z0-9_.\-]+)\s*\}\}")


def builtin_vars(base_url):
    p = urlparse(base_url)
    port = p.port or (443 if p.scheme == "https" else 80)
    return {
        "BaseURL": base_url.rstrip("/"),
        "RootURL": f"{p.scheme}://{p.netloc}",
        "Hostname": p.netloc,
        "Host": p.hostname or "",
        "Port": str(port),
        "Scheme": p.scheme,
        "Path": p.path or "/",
    }


def _render(text, variables):
    if text is None:
        return None
    return _VAR_RE.sub(
        lambda m: str(variables.get(m.group(1), m.group(0))), str(text))


# ---------- payload 组合 ----------

def _join_url(base_url, path):
    """把 POC 的 `path` 拼成完整 URL（三种写法都要支持）。

    - 绝对路径 `/.env`      → `base + /.env`
    - 相对路径 `.env`       → `base + /.env`
    - **已经是完整 URL**    → 原样使用。nuclei 模板最常见的就是
      `path: - "{{BaseURL}}/admin"`，渲染后已经是 `http://host/admin`；
      原实现无条件再拼一次 base，结果请求变成 `http://host/http://host/admin`
      —— **永远打不中**（实测：同一份 POC 用 `/.env` 命中、用 `{{BaseURL}}/.env` 不命中）。
      而 README/文档明确承诺"官方 nuclei 模板可直接投放使用"，所以这里必须修。
    """
    text = str(path or "/").strip()
    if text.lower().startswith(("http://", "https://")):
        return text
    return base_url.rstrip("/") + (text if text.startswith("/") else "/" + text)


def _payload_sets(req, limit=MAX_REQUESTS_PER_POC):
    """把 `payloads` 展开成一组变量字典。支持 list 与 nuclei 的 dict + attack。"""
    pl = req.get("payloads")
    if not pl:
        return [{}]
    if isinstance(pl, list):
        return [{"payload": v} for v in pl[:limit]]
    if not isinstance(pl, dict) or not pl:
        return [{}]
    keys = list(pl.keys())
    lists = [[(k, v) for v in (pl[k] if isinstance(pl[k], list) else [pl[k]])]
             for k in keys]
    attack = str(req.get("attack") or "clusterbomb").lower()
    combos = []
    if attack == "pitchfork":
        n = min(len(l) for l in lists)
        for j in range(n):
            combos.append({lists[i][j][0]: lists[i][j][1] for i in range(len(lists))})
    elif attack == "batteringram":
        for v in lists[0]:
            combos.append({k: v[1] for k in keys})
    else:  # clusterbomb：笛卡尔积
        for combo in itertools.product(*lists):
            combos.append({k: v for k, v in combo})
    return combos[:limit] or [{}]


# ---------- 匹配器 / 提取器 ----------

def _part_text(resp, part):
    part = str(part or "body").lower()
    body = resp.get("text") or ""
    if part in ("header", "headers"):
        return "\n".join(f"{k}: {v}" for k, v in (resp.get("headers") or {}).items())
    if part == "all":
        return "\n".join(f"{k}: {v}" for k, v in (resp.get("headers") or {}).items()) + "\n" + body
    return body


def _dsl_ctx(resp):
    """dsl 求值上下文（键与 `scanner/pocs/dsl.py::VARIABLES` 一一对应，不能少也不能多名字）。"""
    headers = resp.get("headers") or {}
    htext = "\n".join(f"{k}: {v}" for k, v in headers.items())

    def _int(v):
        try:
            return int(v or 0)
        except (TypeError, ValueError):
            return 0

    return {"status_code": _int(resp.get("status")), "content_length": _int(resp.get("length")),
            "body": resp.get("text") or "", "all_headers": htext, "header": htext,
            "host": urlparse(resp.get("url") or "").netloc}


def _dsl_asts(entry):
    """取 `_dsl_ast`（装载期填的）；缺失时现解析一次（手工构造的 POC dict 会走到这里）。"""
    asts = entry.get("_dsl_ast")
    if asts is None:
        asts = [dsl_mod.parse(e)[0] for e in dsl_mod.expressions(entry)]
    return asts or []


def _match_dsl(m, resp):
    """`type: dsl` 匹配器：多条表达式按 `condition`（默认 or）合并。"""
    asts = _dsl_asts(m)
    if not asts:
        return False
    ctx = _dsl_ctx(resp)
    vals = []
    for ast in asts:
        if ast is None:              # 装载期已拦，这里只兜手工构造的 POC dict
            return False
        vals.append(dsl_mod.truthy(dsl_mod.evaluate(ast, ctx)))
    return all(vals) if str(m.get("condition") or "or").lower() == "and" else any(vals)


def _match_one(m, resp):
    t = str(m.get("type") or "").lower()
    ci = m.get("case-insensitive", True) is not False
    cond = str(m.get("condition") or "or").lower()
    ok = False
    if t == "status":
        try:
            allowed = [int(x) for x in (m.get("status") or [])]
        except (TypeError, ValueError):
            allowed = []
        ok = resp.get("status") in allowed
    elif t in ("word", "words"):
        text = _part_text(resp, m.get("part"))
        if ci:
            text = text.lower()
        words = [(str(w).lower() if ci else str(w)) for w in (m.get("words") or [])]
        ok = bool(words) and (any(w in text for w in words) if cond == "or"
                              else all(w in text for w in words))
    elif t == "regex":
        text = _part_text(resp, m.get("part"))
        ok = any(_safe_search(p, text, ci) for p in (m.get("regex") or []))
    elif t in ("size", "length"):
        try:
            sizes = [int(x) for x in (m.get("size") or m.get("sizes") or [])]
        except (TypeError, ValueError):
            sizes = []
        ok = resp.get("length") in sizes
    elif t == "dsl":
        ok = _match_dsl(m, resp)
    else:
        ok = False  # binary 等暂不支持，按不命中处理（不产生误报）
    if m.get("negative"):
        ok = not ok
    return ok


def _safe_search(pattern, text, ci=True):
    try:
        return bool(re.search(str(pattern), text, re.I if ci else 0))
    except re.error:
        return False


def _match_response(resp, matchers, condition):
    results = [_match_one(m, resp) for m in (matchers or []) if isinstance(m, dict)]
    if not results:
        return False
    return all(results) if str(condition or "or").lower() == "and" else any(results)


def _extract_items(resp, extractors):
    """执行 extractors，返回 `[(name, value, internal)]`（`name` 为 None ＝ 未命名）。

    **只负责取值，不决定用途**：evidence（给人看的证据）与模板变量回填（`{{name}}` 跨请求
    传递）都从这一份结果取 —— 避免两套匹配逻辑各判一遍（改一处忘另一处是这类引擎的老毛病）。
    """
    out = []
    for ex in extractors or []:
        if not isinstance(ex, dict):
            continue
        t = str(ex.get("type") or "").lower()
        name = str(ex.get("name") or "") or None
        internal = ex.get("internal") is True
        text = _part_text(resp, ex.get("part"))
        if t == "regex":
            for pat in (ex.get("regex") or []):
                try:
                    for m in re.finditer(str(pat), text):
                        out.append((name, m.group(0), internal))
                except re.error:
                    continue
        elif t == "kval":
            for key in (ex.get("kval") or []):
                m = re.search(rf"(?im)^{re.escape(str(key))}\s*:\s*(.+)$", text)
                if m:
                    out.append((name, f"{key}: {m.group(1).strip()}", internal))
        elif t == "dsl":
            # dsl 提取器只收**非布尔**结果：布尔值本身就是"命中/不命中"，写进 evidence
            # 没有人工确认价值（判命中的职责在 `_match_dsl`，两者分工不重叠）。
            ctx = _dsl_ctx(resp)
            for ast in _dsl_asts(ex):
                val = None if ast is None else dsl_mod.evaluate(ast, ctx)
                if isinstance(val, bool) or val is None:
                    continue
                s = str(val).strip()
                if s:
                    out.append((name, s, internal))
    return out


def _extract(resp, extractors):
    """evidence 用的文本片段：去重后取前 5 条。

    `internal: true` 的提取器在这里被挡掉（nuclei 语义：值照样能当变量用，但**不进输出**）——
    csrf token / nonce 这类字段本来就不该出现在报告与页面里。
    **带 `name` 的并不排他**：nuclei 里命名提取器同样会出现在输出中，"别显示"的开关只有
    `internal`，故这里只按 internal 过滤、不按 name 过滤。
    """
    return sorted({str(v)[:200] for _n, v, _i in _extract_items(resp, extractors)
                   if not _i})[:5]


def _extract_vars(resp, extractors):
    """命名 extractor 的回填值 `{name: 值, name1: 第2个值, ...}`，供后续请求 `{{name}}` 用。

    **只有 `internal: true` 的命名提取器才回填** —— 这是 nuclei 的语义，不是保守起见：
    `pkg/operators/extractors/extractors.go` 里 `Internal` 字段的注释就写着 "when set to true
    will allow using the value extracted in the next request"；不设 internal 的具名提取器只进
    `Result.OutputExtracts`（给人看的输出），**不会**写进模板级 templateCtx，后续块取不到。
    若在这里放宽成"具名即可回填"，就会出现"nuclei 里取不到、我们却取了"的偏差，最坏的同名
    撞车是把模板 `variables:` 的初值顶掉（本该发 admin，结果发了页面上抽出来的串）。

    多值命名也照抄 nuclei（`pkg/tmplexec/multiproto/multi.go`）：第 1 个值是 `{{name}}`，
    第 2/3 个是 `{{name1}}` / `{{name2}}`（**不是** `name2` 对应第 2 个）。值的累积顺序 =
    提取器书写顺序 → 匹配出现顺序（同一名字抽到多个候选值时，第一个通常是页面主表单那个）。

    同名覆盖规则：回填**晚于**模板 `variables:` 与内置变量，故同名的回填值生效。
    """
    out = {}
    seen = {}
    for name, val, internal in _extract_items(resp, extractors):
        if not internal or not name:
            continue
        s = str(val).strip()[:200]
        if not s:
            continue
        i = seen.get(name, 0)
        if i >= _EXTRACT_VARS_MAX:
            continue
        seen[name] = i + 1
        out[name if i == 0 else f"{name}{i}"] = s
    return out


# ---------- 执行 ----------

def _owasp_tags(info):
    return ",".join(str(t).lower().replace("owasp-", "").upper()
                    for t in (info.get("tags") or [])
                    if str(t).lower().startswith("owasp"))


def _vuln_of(poc, info, resp, method, url, base_url, extractors):
    """把一次命中包成 vuln dict（POC 结果与内置检查走同一套字段）。

    `target` 保持是**站点**（`base_url`）而不是命中的那个 URL —— 与改动前的口径一致，
    vulnscan 按 `(target, poc_id)` 去重、库里那一列也是站点，换口径会把既有记录割裂。
    """
    extracted = _extract(resp, extractors)
    if extracted:
        evidence = "\n".join(extracted)
    elif extractors and all(isinstance(ex, dict) and ex.get("internal") is True
                            for ex in extractors):
        # 提取器**全都**是 `internal: true` 时不能退回整段响应体：`internal` 的全部意义就是
        # "这个值不进输出"，而命中的那一页正文里往往正含着它（csrf token / nonce 就在页面里）
        # —— 退回正文等于把刚按约定藏起来的值从后门放出去。给一行自解释的说明。
        evidence = "(该响应的提取器均标注 internal: true —— 值只作模板变量，按约定不进输出)"
    else:
        evidence = (resp.get("text") or "")[:400]
    return {
        "poc_id": poc.get("id"),
        "name": info.get("name") or poc.get("id"),
        "severity": _norm_severity(info.get("severity")),
        "owasp": _owasp_tags(info),
        "target": base_url,
        "detail": (f"POC 命中：{info.get('name') or poc.get('id')}"
                   f"（请求 {method} {url}）。" + (info.get("description") or "")),
        "evidence": evidence,
    }


def _run_block(block, poc, info, base_url, variables, settings, timeout, limit, budget):
    """执行一个请求块（含 raw / path×payload 展开），命中返回 vuln dict，否则 None。

    `budget` 是**跨块共享**的剩余请求数（`[int]`），flow 里多个块共用一份额度 ——
    否则 `flow: http(1) && http(2)` 会把单 POC 的请求上限翻倍。

    **副作用（有意为之）**：每拿到一次响应就把 `internal: true` 的命名 extractor 值写进
    `variables`（模板上下文），因此调用方传进来的那个 dict 会被**就地更新** —— 这正是
    `{{name}}` 能跨块传递的机制，与 flow 的 `set()` 写的是同一份 dict。
    """
    items, _reasons = _block_requests(block)
    if not items:
        return None
    redirects = block.get("redirects", True) is not False
    for varset in _payload_sets(block, limit):
        if budget[0] <= 0:
            return None
        for one in items:
            if budget[0] <= 0:
                return None
            # 每个请求都重新快照一次模板上下文：`internal: true` 命名提取器的回填（见下）
            # 要让**同一个块里后面的请求**也用得上（nuclei 一个块里写多条 `path:` 就是按
            # 请求逐个取值）。payload 池变量叠在快照之上，仍是"payload 优先"。
            ctx_vars = dict(variables)
            ctx_vars.update({str(k): str(v) for k, v in varset.items()})
            # header 也要用**带 payload 的变量**渲染：nuclei 模板里常见
            # `X-Fuzz: {{payload}}` 这种写法，只渲染一次基础变量会漏掉替换。
            headers = {str(k): _render(v, ctx_vars) for k, v in one["headers"].items()}
            path = _render(one["path"], ctx_vars) or "/"
            url = _join_url(base_url, path)
            resp = http_request(url, method=one["method"], headers=headers or None,
                                data=_render(one["body"], ctx_vars),
                                timeout=timeout, settings=settings,
                                allow_redirects=redirects,
                                auth=True)          # 目标侧出口：带上任务登录态
            budget[0] -= 1
            if not resp:
                continue
            # 命名 extractor **回填模板上下文**（nuclei 的 `{{name}}` 跨请求传递就靠这个；
            # 只有 `internal: true` 的才回填，见 `_extract_vars`）。
            # 刻意放在匹配**之前**：nuclei 的 extractors 本来就排在 matchers 前面，且命中与否
            # 不影响 internal 值的传递（`pkg/operators/operators.go::Execute` 在有 DynamicValues
            # 时即使 matchers 全不命中也返回 true）。挂到命中之后，会让最常见的"第一个请求只负责
            # 取 csrf_token"模板在本引擎里**静默失效** —— 后续请求会带着字面量 `{{csrf_token}}`
            # 发出去。宁可多写变量：取错值只会让后面的匹配不中（看得见），取不到整条模板失效（看不见）。
            variables.update(_extract_vars(resp, block.get("extractors")))
            if not _match_response(resp, block.get("matchers"),
                                   block.get("matchers-condition") or "or"):
                continue
            return _vuln_of(poc, info, resp, one["method"], url, base_url,
                            block.get("extractors"))
    return None


def _wf_targets(step, base, registry, settings):
    """把一个 workflow 步骤展开成待跑的子模板列表（按 `_WORKFLOW_MAX_SUBS` 截断）。

    - `tags:` 步骤：从**候选集**里挑。nuclei 是 **OR 语义**（模板命中任意一个标签即选中，
      见 `pkg/templates/tag_filter.go::isExtraTagMatch`）。候选集默认取 `load_enabled_pocs()`，
      即"注册表启用 + 级别门控"与普通 POC 一视同仁；vulnscan 会把已经加载好的那份传进来
      （`registry=`），省掉每个站点重复读盘。
    - `template:` 步骤：先按 workflow 文件所在目录解析，再退一步按项目根解析（官方 workflow
      常按模板库根写路径）；指向目录时展开目录下的 yaml。
    """
    if step.get("tags"):
        want = set(step["tags"])
        pool = load_enabled_pocs(settings) if registry is None else registry
        subs = [p for p in pool
                if want & {str(t).lower() for t in ((p.get("info") or {}).get("tags") or [])}]
    else:
        ref = str(step.get("path") or "")
        cand = base / ref
        if not cand.exists():
            cand = resolve(ref)
        if cand.is_dir():
            subs = [load_poc_file(f) for f in
                    sorted(cand.rglob("*.yaml")) + sorted(cand.rglob("*.yml"))]
        else:
            subs = [load_poc_file(cand)]
    return [m for m in subs if m.get("_status") == "ok"][:_WORKFLOW_MAX_SUBS]


def _run_wf_step(step, base, base_url, settings, max_requests, site, depth, seen, registry):
    """跑一个 workflow 步骤，命中返回结果列表（空 = 没命中）。

    nuclei 语义（`pkg/core/workflow_execute.go::runWorkflowStep`）：**带 `subtemplates` 的
    步骤，父模板只当开关** —— 父模板自己的命中结果不报（否则"技术栈识别"这类父模板会和
    子模板的结果一起冒出来），只报子步骤的结果。所以这里先跑本步骤的子模板：没命中直接
    返回空（`subtemplates` 一个请求都不发 —— 这正是条件编排的全部意义），命中了才下钻。
    """
    child_steps = step.get("subtemplates") or []
    for sub in _wf_targets(step, base, registry, settings):
        key = str(pathlib.Path(str(sub.get("_path") or sub.get("id") or "")).resolve())
        if key in seen:                     # 同一模板单次执行内只跑一次（自环直接挡住）
            continue
        seen.add(key)
        hits = run_poc_on_target(sub, base_url, settings, max_requests, site=site,
                                 _depth=depth + 1, _seen=seen, registry=registry)
        if not hits:
            continue
        if not child_steps:
            return hits
        for cstep in child_steps:
            sub_hits = _run_wf_step(cstep, base, base_url, settings, max_requests,
                                    site, depth + 1, seen, registry)
            if sub_hits:
                return sub_hits
    return []


def _run_workflow(poc, base_url, settings, max_requests, site, depth, seen, registry=None):
    """执行 workflow 子集（结构见模块 docstring）。

    递归保护两条：① 深度上限 `_WORKFLOW_MAX_DEPTH`；② 同一次执行内**同一模板只跑一次**
    （`seen`），否则 A→B→A 这种环会把请求量放大成爆炸。语义同 nuclei：命中即停。
    """
    if depth > _WORKFLOW_MAX_DEPTH:
        return []
    base = pathlib.Path(poc.get("_path") or ".").parent
    for step in (poc.get("_workflow") or []):
        hits = _run_wf_step(step, base, base_url, settings, max_requests, site, depth,
                            seen, registry)
        if hits:
            return hits
    return []


def run_poc_on_target(poc, base_url, settings, max_requests=MAX_REQUESTS_PER_POC, site=None,
                      _depth=0, _seen=None, registry=None):
    """对单个目标执行单个 POC；命中即返回一条 vuln dict（每 POC 每目标最多一条）。

    `site` 为 probe 产出的站点信息（可含 `favicon`/`tech`），用于**零请求前置判定**：
    POC 声明了 `favicon_md5_list` 且当前站点 favicon 已知但不匹配时直接跳过，
    省掉整个 POC 的请求；站点 favicon 未知时**不**做排除（宁可多打，不漏判）。

    `registry` 是 workflow 里 `tags:` 步骤的候选集（`load_enabled_pocs` 的结果）；不传则
    在需要时懒加载。vulnscan 传的是它已经加载好的那份，避免每个站点重复读盘。

    三种形态：普通请求块（`path` × `payloads`）、`raw` 原文块、带 `flow` 的多块编排
    （见模块 docstring）。`flow` 有两条路：**布尔子集**每块只跑一次、条件成立且**有正向命中**
    才报（`||` 短路）；**脚本子集**按脚本执行、每次 `http(...)` 都真的发（不缓存，循环才有效），
    报第一个正向命中（脚本没有"整体真值"，与 nuclei"匹配即报"一致）。
    """
    timeout = int((settings or {}).get("limits", {}).get("http_timeout", 10))
    fav_list = poc.get("favicon_md5_list") or []
    if fav_list and isinstance(site, dict):
        cur = str(site.get("favicon") or "").lower()
        if cur and cur not in {str(h).lower() for h in fav_list}:
            return []
    if poc.get("_workflow"):
        return _run_workflow(poc, base_url, settings, max_requests, site, _depth,
                             _seen if _seen is not None else set(), registry)
    info = poc.get("info", {}) or {}
    variables = dict(builtin_vars(base_url))
    for k, v in (poc.get("variables") or {}).items():
        variables[str(k)] = _render(v, variables)
    blocks, ok_idx, _notes = _runnable_blocks(poc)
    if not ok_idx:
        return []
    budget = [max(0, int(max_requests))]

    def _run_at(i):
        return _run_block(blocks[i], poc, info, base_url, variables, settings, timeout,
                          max_requests, budget)

    # 装载期已把 `flow` 判成布尔子集（`_flow`）或脚本子集（`_flow_script`）之一；两个都没有
    # 说明是**手工构造的 poc dict**（测试/调用方直接拼 dict），这里按同样的顺序兜底解析。
    tree, prog = poc.get("_flow"), poc.get("_flow_script")
    if tree is None and prog is None and poc.get("flow"):
        tree, _reason = _flow_tree(poc.get("flow"))
        if tree is None:
            prog, _reason = _flow_js_parse(poc.get("flow"))
    if prog is not None:
        def _run_refs(refs):
            """跑脚本里的一次协议调用（`refs=None` = 该协议**全部块**，按模板顺序）。

            与布尔子集不同：这里**不缓存** —— 脚本里的 `http(1)` 常被放进循环、每轮配着不同的
            `set()` 值重发（nuclei 就是这么跑的），缓存等于把循环的意义抹掉。请求总量仍由
            `budget`（`MAX_REQUESTS_PER_POC`）兜着。只取第一个正向命中返回。
            """
            idxs = ok_idx if refs is None else [
                r - 1 if isinstance(r, int) else
                next((i for i in ok_idx if str(blocks[i].get("id")) == r), None)
                for r in refs]
            first = None
            for idx in idxs:
                if idx is None or budget[0] <= 0:
                    continue
                hit = _run_at(idx)
                if hit and first is None:
                    first = hit
            return first

        hits_list = _run_flow_script(prog, _run_refs, variables)
        return hits_list[:1]

    if tree is not None:
        hits = {}

        def _ref(ref):
            """按引用取块并**只跑一次**（缓存）；序号是 1-based 的原始块下标。"""
            if ref not in hits:
                idx = ref - 1 if isinstance(ref, int) else \
                    next((i for i in ok_idx if str(blocks[i].get("id")) == ref), None)
                hits[ref] = _run_at(idx) if idx is not None else None
            return hits[ref]

        def _ev(node):
            op = node[0]
            if op == "ref":
                return bool(_ref(node[1]))
            if op == "not":
                return not _ev(node[1])
            left = _ev(node[1])
            return (left and _ev(node[2])) if op == "&&" else (left or _ev(node[2]))

        if not _ev(tree):
            return []
        # 只报**正向命中**的那一块：纯否定式成立（如 `!http(1)`）没有任何响应证据，
        # 报出来就是纯误报 —— 与 `_match_one` 对未知匹配器类型的口径一致。
        for v in hits.values():
            if v:
                return [v]
        return []
    for i in ok_idx:
        if budget[0] <= 0:
            break
        hit = _run_at(i)
        if hit:
            return [hit]
    return []