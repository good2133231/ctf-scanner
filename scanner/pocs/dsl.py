"""nuclei `dsl` 表达式的**安全子集**求值器。

**为什么不用 `eval`**：`dsl` 是模板（外部输入）里写的表达式。用 Python 的 `eval`/`exec`
等于把任意代码执行权交给模板文件 —— 与本引擎"绝不执行模板逻辑、只认声明式匹配器"的红线
直接冲突。所以这里手写词法 + 递归下降，语法是**封闭白名单**：不在白名单里的写法在
**装载期**就被判为超出子集（`engine.load_poc_file` 把整份模板标 `unsupported` 并写明原因），
而不是运行期静默不命中 —— 后者会让人以为"模板跑过了、没洞"。

支持的语法：
- 变量（6 个，见 `VARIABLES`；值与 `engine._dsl_ctx()` 一一对应）：
  `status_code`(int) / `content_length`(int) / `body`(str) / `all_headers`(str) /
  `header`(str，与 `all_headers` 同值) / `host`(str)
- 字面量：整数 / 浮点 / 单双引号字符串（转义 `\\n` `\\r` `\\t` `\\\\` `\\'` `\\"`）
- 比较：`==` `!=`（两侧都是数字按数字比，否则按字符串比）；
  `>` `>=` `<` `<=` **只允许数值**（`status_code` / `content_length` / `len()` / 数字字面量），
  拿字符串做大小比较属于写错模板 → 装载期直接判不支持，不给"恒 False"这种静默语义
- 逻辑：`&&` `||` `!` 与括号（`&&` 紧于 `||`，与 nuclei 一致）
- 函数（见 `FUNCTIONS`）：`contains` / `icontains` / `starts_with` / `ends_with` /
  `regex` / `len` / `tolower` / `toupper`

**明确不做**：方法调用式（`body.contains('x')`）、算术（`+ - * /`）、`md5`/`base64` 等
摘要函数、模板间变量、循环与 JS —— 用到的模板会被标 `unsupported`，
在「POC 管理」页能直接看到原因（不静默失效）。
"""
import re

# 变量白名单。**必须**与 `engine._dsl_ctx()` 返回的键完全一致 —— 少了谁，
# 模板里引用它就会在装载期被拒（这是刻意的：宁可拒，也不要运行期 KeyError 被吞成"不命中"）。
VARIABLES = ("status_code", "content_length", "body", "all_headers", "header", "host")

# 数值型变量（唯一允许参与大小比较的变量）
_NUM_VARS = ("status_code", "content_length")

# 函数白名单：名称 → 参数个数
FUNCTIONS = {
    "contains": 2, "icontains": 2, "starts_with": 2, "ends_with": 2,
    "regex": 2, "len": 1, "tolower": 1, "toupper": 1,
}

_CMP_OPS = ("==", "!=", ">=", "<=", ">", "<")

_TOKEN_RE = re.compile(r"""
    (?P<ws>\s+)
  | (?P<num>\d+\.\d+|\d+)
  | (?P<str>"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')
  | (?P<id>[A-Za-z_][A-Za-z0-9_]*)
  | (?P<op>==|!=|>=|<=|&&|\|\||[<>!(),])
""", re.X)

_ESCAPES = {"n": "\n", "r": "\r", "t": "\t", "\\": "\\", "'": "'", '"': '"'}


class DslUnsupported(Exception):
    """表达式超出安全子集（装载期判掉，不静默失效）。"""


def _unquote(raw):
    quote, body = raw[0], raw[1:-1]
    if "\\" not in body:
        return body
    out, i = [], 0
    while i < len(body):
        ch = body[i]
        if ch == "\\" and i + 1 < len(body):
            nxt = body[i + 1]
            out.append(_ESCAPES.get(nxt, "\\" + nxt))
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _tokens(text):
    text = str(text or "")
    toks, i = [], 0
    while i < len(text):
        m = _TOKEN_RE.match(text, i)
        if not m:
            raise DslUnsupported(
                f"含不支持的字符 `{text[i]}`（只支持变量 / 字面量 / 比较 / `&&` `||` `!` / "
                f"括号 / 白名单函数）")
        i = m.end()
        kind, val = m.lastgroup, m.group(0)
        if kind == "ws":
            continue
        if kind == "num":
            toks.append(("num", float(val) if "." in val else int(val)))
        elif kind == "str":
            toks.append(("str", _unquote(val)))
        elif kind == "id":
            toks.append(("id", val))
        else:
            toks.append(("op", val))
    if not toks:
        raise DslUnsupported("表达式为空")
    return toks


def _is_numeric(node):
    """该子表达式是否**一定**是数值（大小比较的前置条件）。"""
    if node[0] == "num":
        return True
    if node[0] == "var":
        return node[1] in _NUM_VARS
    if node[0] == "call":
        return node[1] == "len"
    return False


def _parse(toks):
    """递归下降：`||` < `&&` < `!` < 比较 < 括号/字面量/变量/函数调用。"""
    pos = [0]

    def peek():
        return toks[pos[0]] if pos[0] < len(toks) else None

    def take():
        t = peek()
        pos[0] += 1
        return t

    def expect(op):
        t = take()
        got = t[1] if t else "表达式结束"
        if not t or t[0] != "op" or t[1] != op:
            raise DslUnsupported(f"缺少 `{op}`（实际是 `{got}`）")

    def primary():
        t = take()
        if t is None:
            raise DslUnsupported("表达式意外结束")
        if t[0] == "num":
            return ("num", t[1])
        if t[0] == "str":
            return ("str", t[1])
        if t[0] == "op" and t[1] == "(":
            node = or_expr()
            expect(")")
            return node
        if t[0] != "id":
            raise DslUnsupported(f"不支持的记号 `{t[1]}`")
        name = t[1]
        if peek() == ("op", "("):
            take()
            args = []
            if peek() != ("op", ")"):
                args.append(or_expr())
                while peek() == ("op", ","):
                    take()
                    args.append(or_expr())
            expect(")")
            low = name.lower()
            if low not in FUNCTIONS:
                raise DslUnsupported(
                    f"不支持的函数 `{name}()`（白名单：{' / '.join(sorted(FUNCTIONS))}）")
            if len(args) != FUNCTIONS[low]:
                raise DslUnsupported(
                    f"`{name}()` 需要 {FUNCTIONS[low]} 个参数，实际 {len(args)} 个")
            if low == "regex" and args[0][0] == "str":
                try:
                    re.compile(args[0][1])
                except re.error as e:
                    raise DslUnsupported(f"`regex()` 的模式不合法：{e}")
            return ("call", low, args)
        if name in FUNCTIONS:
            raise DslUnsupported(f"`{name}` 是函数，要写成 `{name}(...)`")
        if name not in VARIABLES:
            raise DslUnsupported(
                f"不支持的变量 `{name}`（白名单：{' / '.join(VARIABLES)}）")
        return ("var", name)

    def comparison():
        left = primary()
        t = peek()
        if not (t and t[0] == "op" and t[1] in _CMP_OPS):
            return left
        take()
        right = primary()
        nxt = peek()
        if nxt and nxt[0] == "op" and nxt[1] in _CMP_OPS:
            raise DslUnsupported("不支持链式比较（`a == b == c` 请写成 `a == b && b == c`）")
        if t[1] in (">", ">=", "<", "<=") and not (_is_numeric(left) and _is_numeric(right)):
            raise DslUnsupported(
                f"`{t[1]}` 只允许数值比较（数值来源：`status_code` / `content_length` / "
                f"`len(...)` / 数字字面量）")
        return (t[1], left, right)

    def unary():
        if peek() == ("op", "!"):
            take()
            return ("!", unary())
        return comparison()

    def and_expr():
        node = unary()
        while peek() == ("op", "&&"):
            take()
            node = ("&&", node, unary())
        return node

    def or_expr():
        node = and_expr()
        while peek() == ("op", "||"):
            take()
            node = ("||", node, and_expr())
        return node

    tree = or_expr()
    if pos[0] != len(toks):
        raise DslUnsupported(f"多余记号 `{toks[pos[0]][1]}`")
    return tree


def parse(expr):
    """源串 → `(node, reason)`：可解析时 `reason` 为空串，否则 `node` 为 None。"""
    try:
        return _parse(_tokens(expr)), ""
    except DslUnsupported as e:
        return None, str(e)


def expressions(matcher):
    """取匹配器/提取器里的 `dsl` 表达式列表（兼容字符串与列表两种写法）。"""
    raw = matcher.get("dsl")
    if isinstance(raw, str):
        return [x.strip() for x in raw.splitlines() if x.strip()]
    if isinstance(raw, (list, tuple)):
        return [str(x).strip() for x in raw if str(x).strip()]
    return []


def truthy(value):
    """条件位上的真值口径：bool 原样；数字非 0；字符串非空；None 为假。"""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if value is None:
        return False
    return str(value) != ""


def _compare(op, a, b):
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        x, y = a, b
    else:
        x, y = str(a), str(b)
    if op == "==":
        return x == y
    if op == "!=":
        return x != y
    # 大小比较在装载期已限定为数值子表达式，这里再兜一层（手工构造的 AST 也不至于抛）
    if not (isinstance(x, (int, float)) and isinstance(y, (int, float))):
        return False
    return {">": x > y, ">=": x >= y, "<": x < y, "<=": x <= y}[op]


def _call(name, args):
    text = [str(a) for a in args]
    if name == "contains":
        return text[1] in text[0]
    if name == "icontains":
        return text[1].lower() in text[0].lower()
    if name == "starts_with":
        return text[0].startswith(text[1])
    if name == "ends_with":
        return text[0].endswith(text[1])
    if name == "regex":
        try:
            return bool(re.search(text[0], text[1]))
        except re.error:
            return False
    if name == "len":
        return len(text[0])
    if name == "tolower":
        return text[0].lower()
    if name == "toupper":
        return text[0].upper()
    return False


def evaluate(node, ctx):
    """求出表达式的值（bool / 数字 / 字符串）。未知节点类型一律 False（不抛）。"""
    if node[0] in ("num", "str"):
        return node[1]
    if node[0] == "var":
        return ctx.get(node[1], "")
    if node[0] == "!":
        return not truthy(evaluate(node[1], ctx))
    if node[0] == "&&":
        return truthy(evaluate(node[1], ctx)) and truthy(evaluate(node[2], ctx))
    if node[0] == "||":
        return truthy(evaluate(node[1], ctx)) or truthy(evaluate(node[2], ctx))
    if node[0] == "call":
        return _call(node[1], [evaluate(a, ctx) for a in node[2]])
    if node[0] in _CMP_OPS:
        return _compare(node[0], evaluate(node[1], ctx), evaluate(node[2], ctx))
    return False
