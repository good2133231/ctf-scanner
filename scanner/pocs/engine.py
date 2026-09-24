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
  匹配器：type: status | word | regex | size；part: body | header | all；
          condition: or|and；negative: true；case-insensitive
  提取器：type: regex | kval（命中内容会写进 evidence，便于人工确认）
  flow（2026-09-23 起支持**布尔子集**）：`&&` / `||` / `!` 作用于请求块的 `id` 或
      `http(N)` 1-based 序号；引用能全部解析时才生效，否则整份模板标 unsupported。
      语义同 nuclei：条件成立才算命中；纯否定式成立（如只有 `!http(1)`）**不报**
      （没有正向响应证据，报出来就是纯误报）。
  workflows（2026-09-23 起支持**子模板编排子集**）：workflow 文件顶层写
      `workflows: - template: <相对路径>`，相对 workflow 文件所在目录解析；有递归保护
      （深度上限 + 同一路径单次执行内只跑一次）。`subtemplates` / `args` / workflow 级
      matchers 未实现，装载期标 `_note`（不静默失效）。

**raw 的安全边界**（红线，2026-09-23）：raw 是"手写 HTTP 原文"，最容易被写成利用动作。
因此 `PUT` / `PATCH` / `DELETE` / `TRACE` / `CONNECT` 一律**拒绝执行**并把原因记进
`_note`/`_error`（框架只做只读验证，不做状态变更）；同一套方法白名单也对普通 `method:` 生效。

刻意不做：dsl 表达式、oob（反连）、workflow 的 `subtemplates`/`args`。
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

# POC 目录：内置 / 用户上传 / 参考项目批量导入 / 官方 nuclei 模板投放点
POC_DIRS = ["scanner/pocs/pocs", "config/pocs-user", "config/pocs-imported",
            "config/nuclei-templates"]

# 单个 POC 对单个目标的最大请求数（防止 payload 笛卡尔积把目标打爆）
MAX_REQUESTS_PER_POC = 10

# 仍**不支持**的块级/顶层特性：`dsl` 是"把判定逻辑写在模板里"，等价于让模板执行任意逻辑，
# 与"引擎只认声明式匹配器"的定位冲突。含它的块被跳过并标注原因。
_UNSUPPORTED_KEYS = ("dsl",)

# 破坏性/异常方法白名单（框架红线：只做只读验证）。`POST` 保留 —— 大量官方模板用它做
# "只读型"探测（表单提交返回详情页、JSON 接口取值），且 305 个存量 POC 一个都没用到写方法。
_DESTRUCTIVE_METHODS = ("PUT", "PATCH", "DELETE", "TRACE", "CONNECT")

# raw 请求里**丢弃**的头：requests 会自己按最终 body 重算长度；沿用原文的 Content-Length
# 在变量渲染后长度不一致时会导致请求截断或挂起（这是 raw 支持里最容易踩的坑）。
_RAW_DROP_HEADERS = ("content-length",)

# workflow 编排的递归深度上限（A→B→C 之后不再下钻）与单次执行的路径去重
_WORKFLOW_MAX_DEPTH = 3

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
    """flow 表达式超出支持子集（含 JS/循环/`template()` 等）时抛出。"""


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
    """返回解析不到的引用（序号越界/该块被跳过、或本文件没有该 id）。

    `http(N)` 指的是核模板里 `http:` 列表的**第 N 块**（原始顺序），所以这里按原始下标
    判定 —— 跳过一块后序号会错位，把 `http(2)` 当成"跳过后剩下的第 2 块"就是错判。
    """
    ids = {str(blocks[i].get("id")) for i in ok_idx if blocks[i].get("id")}
    bad = []
    for ref in sorted(_flow_refs(tree), key=str):
        if isinstance(ref, int):
            if not 1 <= ref <= len(blocks) or (ref - 1) not in ok_idx:
                bad.append(f"http({ref})")
        elif ref not in ids:
            bad.append(f"{ref}()")
    return bad


def _runnable_blocks(data):
    """挑出可执行的请求块，返回 `(blocks, ok_idx, notes)`。

    `blocks` 是 `http:`/`requests:` 的**原始顺序**（`flow` 的 `http(N)` 按它编号），
    `ok_idx` 是其中可用块的下标；`notes` 是每个被跳过块的原因（供 `_note` 汇总展示）。
    """
    blocks = _requests_of(data)
    ok_idx, notes = [], []
    for i, b in enumerate(blocks):
        if not isinstance(b, dict) or any(k in b for k in _UNSUPPORTED_KEYS):
            notes.append("含 dsl 的请求块已跳过")
            continue
        items, reasons = _block_requests(b)
        if not items:
            notes.append(reasons[0] if reasons else "请求块为空，已跳过")
            continue
        ok_idx.append(i)
    return blocks, ok_idx, notes


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
    if isinstance(data.get("workflows"), list) and data["workflows"]:
        refs, skipped = [], 0
        for item in data["workflows"]:
            tpl = item.get("template") if isinstance(item, dict) else None
            if isinstance(tpl, str) and tpl.strip():
                refs.append(tpl.strip())
            else:
                skipped += 1        # subtemplates / args / workflow 级 matchers 未实现
        if not refs:
            data["_status"] = "unsupported"
            data["_error"] = ("workflow 子项均非 `template: <路径>`"
                              "（subtemplates / args 未支持）")
            return data
        data["_status"] = "ok"
        data["_templates"] = refs
        if skipped:
            data["_note"] = f"{skipped} 个 workflow 子项（subtemplates/args）已跳过"
        return data

    if not _requests_of(data):
        if any(k in data for k in _UNSUPPORTED_KEYS):
            return {"id": data.get("id"), "_status": "unsupported",
                    "_error": "dsl 类模板暂不支持（见 docs/poc-guide.md）",
                    "_path": str(p)}
        return {"id": p.stem, "_status": "error", "_error": "缺少 http/requests 段"}
    blocks, ok_idx, notes = _runnable_blocks(data)
    if not ok_idx:
        return {"id": data.get("id"), "_status": "unsupported",
                "_error": f"全部请求块被跳过（{notes[0] if notes else '空块'}）",
                "_path": str(p)}
    # flow：解析 + 引用可解析性都在**装载期**判掉。运行期才发现引用不到，只能"按不命中"
    # 处理 —— 那正是本引擎最反对的静默失效（用户会以为模板没洞）。
    if data.get("flow"):
        tree, reason = _flow_tree(data["flow"])
        if tree is None:
            data["_status"] = "unsupported"
            data["_error"] = f"flow 表达式超出支持子集：{reason}"
            return data
        bad = _flow_bad_refs(tree, blocks, ok_idx)
        if bad:
            data["_status"] = "unsupported"
            data["_error"] = "flow 引用了不存在/被跳过的请求块：" + "、".join(bad)
            return data
        data["_flow"] = tree
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
    else:
        ok = False  # binary / dsl 等暂不支持，按不命中处理（不产生误报）
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


def _extract(resp, extractors):
    """执行 extractors，返回命中的文本片段列表（用于 evidence）。"""
    out = []
    for ex in extractors or []:
        if not isinstance(ex, dict):
            continue
        t = str(ex.get("type") or "").lower()
        text = _part_text(resp, ex.get("part"))
        if t == "regex":
            for pat in (ex.get("regex") or []):
                try:
                    for m in re.finditer(str(pat), text):
                        out.append(m.group(0))
                except re.error:
                    continue
        elif t == "kval":
            for key in (ex.get("kval") or []):
                m = re.search(rf"(?im)^{re.escape(str(key))}\s*:\s*(.+)$", text)
                if m:
                    out.append(f"{key}: {m.group(1).strip()}")
    return sorted(set(str(x)[:200] for x in out))[:5]


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
    return {
        "poc_id": poc.get("id"),
        "name": info.get("name") or poc.get("id"),
        "severity": _norm_severity(info.get("severity")),
        "owasp": _owasp_tags(info),
        "target": base_url,
        "detail": (f"POC 命中：{info.get('name') or poc.get('id')}"
                   f"（请求 {method} {url}）。" + (info.get("description") or "")),
        "evidence": "\n".join(extracted) if extracted else (resp.get("text") or "")[:400],
    }


def _run_block(block, poc, info, base_url, variables, settings, timeout, limit, budget):
    """执行一个请求块（含 raw / path×payload 展开），命中返回 vuln dict，否则 None。

    `budget` 是**跨块共享**的剩余请求数（`[int]`），flow 里多个块共用一份额度 ——
    否则 `flow: http(1) && http(2)` 会把单 POC 的请求上限翻倍。
    """
    items, _reasons = _block_requests(block)
    if not items:
        return None
    redirects = block.get("redirects", True) is not False
    for varset in _payload_sets(block, limit):
        if budget[0] <= 0:
            return None
        ctx_vars = dict(variables)
        ctx_vars.update({str(k): str(v) for k, v in varset.items()})
        for one in items:
            if budget[0] <= 0:
                return None
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
            if not _match_response(resp, block.get("matchers"),
                                   block.get("matchers-condition") or "or"):
                continue
            return _vuln_of(poc, info, resp, one["method"], url, base_url,
                            block.get("extractors"))
    return None


def _run_workflow(poc, base_url, settings, max_requests, site, depth, seen):
    """执行 workflow 子集：`- template: <相对路径>`（相对 workflow 文件所在目录）。

    递归保护两条：① 深度上限 `_WORKFLOW_MAX_DEPTH`；② 同一次执行内**同一路径只跑一次**
    （`seen`），否则 A→B→A 这种环会把请求量放大成爆炸。语义同 nuclei：命中即停。
    路径先按 workflow 文件所在目录解析，再按项目根解析（模板常按项目根写路径）。
    """
    if depth > _WORKFLOW_MAX_DEPTH:
        return []
    base = pathlib.Path(poc.get("_path") or ".").parent
    for ref in (poc.get("_templates") or []):
        cand = base / ref
        if not cand.is_file():
            cand = resolve(ref)                     # 退一步：按项目根解析
        key = str(cand.resolve()) if cand.exists() else str(cand)
        if key in seen:
            continue
        seen.add(key)
        sub = load_poc_file(cand)
        if sub.get("_status") != "ok":
            continue
        hits = run_poc_on_target(sub, base_url, settings, max_requests,
                                 site=site, _depth=depth + 1, _seen=seen)
        if hits:
            return hits
    return []


def run_poc_on_target(poc, base_url, settings, max_requests=MAX_REQUESTS_PER_POC, site=None,
                      _depth=0, _seen=None):
    """对单个目标执行单个 POC；命中即返回一条 vuln dict（每 POC 每目标最多一条）。

    `site` 为 probe 产出的站点信息（可含 `favicon`/`tech`），用于**零请求前置判定**：
    POC 声明了 `favicon_md5_list` 且当前站点 favicon 已知但不匹配时直接跳过，
    省掉整个 POC 的请求；站点 favicon 未知时**不**做排除（宁可多打，不漏判）。

    三种形态：普通请求块（`path` × `payloads`）、`raw` 原文块、带 `flow` 的多块编排
    （见模块 docstring；`flow` 下每块只跑一次，条件成立且**有正向命中**才报）。
    """
    timeout = int((settings or {}).get("limits", {}).get("http_timeout", 10))
    fav_list = poc.get("favicon_md5_list") or []
    if fav_list and isinstance(site, dict):
        cur = str(site.get("favicon") or "").lower()
        if cur and cur not in {str(h).lower() for h in fav_list}:
            return []
    if poc.get("_templates"):
        return _run_workflow(poc, base_url, settings, max_requests, site, _depth,
                             _seen if _seen is not None else set())
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

    tree = poc.get("_flow")
    if tree is None and poc.get("flow"):
        tree, _reason = _flow_tree(poc.get("flow"))   # 装载期已校验，这里只兜底
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