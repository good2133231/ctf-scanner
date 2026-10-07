# -*- coding: utf-8 -*-
r"""把 afrog-pocs 的 `fingerprinting/` 变成**可人工复核的候选表**（续120，A 步）。

为什么不是"一个导入脚本直接灌进 fingerprint.py"：
本项目已经为同样的省事付过一次学费 —— 305 条导入 POC 的匹配器塌成 251 种、79 条共用一字不差
的判据，最后只能靠 `tools/poc_review.py` 按族人工复核（AGENTS §7）。afrog 的指纹目录看着"只是
识别"，实际同样不能盲搬，四条实测理由（数字来自 `--scan` 对 130 个真实文件的分类）：

1. **判据强度不同**：afrog 的表达式几乎都带 `response.status == 200 &&`，而我们
   `scanner/fingerprint.py` 的 `(part, 正则)` 原本**没有状态码门控** —— 直接把关键字搬过来，
   一个回了 404 却把产品名写进页面的目标就会被打上该产品的标签（等于自制造误报）。
   所以状态码保留成一列，写进 `config/dicts/fingerprints_extra.txt` 由引擎执行。
2. **目录里混着漏洞 PoC**：实测 `hfs-rce-cmd-exec.yaml`（severity=critical）是 GET 触发目标
   执行 `ipconfig`（CVE-2014-6287），判据 `body.bcontains(b"Windows IP")` 长得**和指纹一模一样**。
   ⇒ "这个目录都是只读识别"这个前提不成立，必须按 `info` 级白名单放行，其余一律拒。
3. **一批根本不可移植**：`type: tcp` 的 21 个、4 个聚合文件里的上百个命名条目
   （`"网宿" != "" && ...` 这种一条目一名）、`banner.` / `response.raw.` / `headers["server"]` /
   `bmatches` / `length()` 等我们没有的判据位置，以及 `A && B` 的**合取**判据
   （我们的规则表是**析取**的：任一规则命中即打标签，表达不了"两个都得在"）。
4. **表达式是 DSL，不是几个正则能抽干净的**：早期版本用 `response\.body\.bcontains\(\s*b"(...)"\)`
   这类正则去抽关键字，在真语料上翻车两次 —— ① 字符类 `[^\\]` 不排除引号，贪婪匹配跨过 `"` 把
   `|| response.body.ibcontains(b"...` 整段吞进关键字；② `path: /login` 是**字符串**不是列表，
   `for p in path` 逐字符迭代。⇒ 现在**先分词再递归下降解析**，解析不出来的形态一律进"拒绝/需人工"，
   不猜着翻。

三条红线照抄 `poc_review.py`（那三条已经被 `[8o]` 钉过）：
① 机器不判定 —— 复核列空着 / 写 `no` / 写别的，一律零动作，没有 `--all-ok` 这种旗标；
② 不改原始数据 —— 对 `config/dicts/fingerprints_extra.txt` 只**追加**：既不修改也不删除已有行，
   同一 `(标签, 位置, 判据)` 重复出现也只留一条。**同名标签允许再加一条判据**（引擎的规则表是
   析取，一个标签多条判据本来就合法），这不是"覆盖"；
③ 不越界 —— 全程**不发一个请求**（只读本地 YAML），唯一写盘目标是
   `config/dicts/fingerprints_extra.txt`（`--src` 与复核表只**读**，且都走参数、代码里不留绝对路径）。

用法：
    py -3 tools/import_afrog_fp.py --scan   --src <本地 afrog-pocs/fingerprinting 目录>
    py -3 tools/import_afrog_fp.py --table  --src <…> --out logs/afrog_fp.tsv
    py -3 tools/import_afrog_fp.py --apply  logs/afrog_fp.tsv   # 只搬复核列写了 ok 的行
    py -3 tools/import_afrog_fp.py --lint                        # 校验字典本身能不能被引擎读到
"""
import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

EXTRA_DICT = "config/dicts/fingerprints_extra.txt"
SEP = "\t"
TABLE_COLS = ["候选tag", "匹配位置", "判据", "状态码", "请求路径", "来源文件", "复核", "备注"]

# ---------- 只读性判定（决定"这条能不能连目标发"）----------
_WRITE_METHODS = {"PUT", "PATCH", "DELETE", "TRACE", "CONNECT"}
# 放行名单**写成数据**，好让回归能把它打坏来验证判据有区分度（§6.1）：
# 实测 fingerprinting/ 目录里混着 severity=critical 的 RCE（hfs-rce-cmd-exec），
# 它的判据 `body.bcontains(b"Windows IP")` 长得和指纹一模一样 —— 拦住它的就是这一行。
OK_SEVERITIES = ("", "info")
# 复核列里代表"放行"的那个值。空值/别的值一律不动 —— 没有 `--all-ok` 这种旗标。
VERDICT_OK = "ok"
# afrog 的判据位置 -> 我们的 parts（见 fingerprint.identify 的 parts 字典）
_PART_MAP = {"body": "body", "raw_header": "headers"}


class Manual(Exception):
    """表达式落在可机械映射的子集之外 —— 带**人话**原因，不静默丢弃。"""


def _load_yaml():
    try:
        import yaml
    except ImportError:
        raise SystemExit("[!] 需要 PyYAML（requirements.txt 里已有）")
    return yaml


# --------------------------------------------------------------------------
# 表达式分词 + 递归下降（afrog 的 expression 是一门小 DSL，不是几个正则）
# --------------------------------------------------------------------------
_TOK = re.compile(r"""
      (?P<space>\s+)
    | (?P<op>&&|\|\||==|!=|>=|<=|\+|~|\(|\)|\[|\]|,|!|\.)
    | (?P<bdq>b"(?:[^"\\]|\\.)*") | (?P<bsq>b'(?:[^'\\]|\\.)*')
    | (?P<dq>"(?:[^"\\]|\\.)*")   | (?P<sq>'(?:[^'\\]|\\.)*')
    | (?P<num>\d+)
    | (?P<word>[A-Za-z_][A-Za-z0-9_]*)
""", re.X)
_SAFE_ESC = {'"': '"', "'": "'", "\\": "\\", "n": "\n", "t": "\t", "r": "\r"}


def _tokens(s):
    out, i = [], 0
    while i < len(s):
        m = _TOK.match(s, i)
        if not m:
            raise Manual(f"表达式里有无法识别的字符 {s[i]!r}")
        i = m.end()
        if m.lastgroup != "space":
            out.append((m.lastgroup, m.group()))
    return out


def _strval(tok):
    """把 `b"..."` / `'...'` 字面量还原成 str；出现无法确定的转义就拒绝。"""
    t = tok[1:] if tok[0] == "b" else tok
    body = t[1:-1]
    if "\\" in body:
        parts, j = [], 0
        while j < len(body):
            ch = body[j]
            if ch != "\\":
                parts.append(ch)
                j += 1
                continue
            if j + 1 >= len(body) or body[j + 1] not in _SAFE_ESC:
                raise Manual("字符串里有无法确定的转义（\\x.. / \\u.. 之类）")
            parts.append(_SAFE_ESC[body[j + 1]])
            j += 2
        return "".join(parts)
    return body


class _P:
    """文法：or := and ('||' and)* | and := cmp ('&&' cmp)* | cmp := un [op un] |
    un := '!' un | prim | prim := '(' or ')' | chain ['(' args ')'] | str | num"""

    def __init__(self, toks):
        self.t, self.i = toks, 0

    def _peek(self):
        return self.t[self.i][1] if self.i < len(self.t) else None

    def _eat(self, v):
        if self._peek() != v:
            raise Manual(f"表达式语法：期望 {v}，实为 {self._peek()!r}")
        self.i += 1

    def orx(self):
        parts = [self.andx()]
        while self._peek() == "||":
            self._eat("||")
            parts.append(self.andx())
        return ("or", parts) if len(parts) > 1 else parts[0]

    def andx(self):
        parts = [self.cmpx()]
        while self._peek() == "&&":
            self._eat("&&")
            parts.append(self.cmpx())
        return ("and", parts) if len(parts) > 1 else parts[0]

    def cmpx(self):
        left = self.unx()
        if self._peek() in ("==", "!=", ">=", "<="):
            op = self._peek()
            self.i += 1
            return ("cmp", op, left, self.unx())
        return left

    def unx(self):
        if self._peek() == "!":
            self._eat("!")
            return ("not", self.unx())
        return self.prim()

    def chain(self):
        names, bracket = [], False
        k, v = self.t[self.i]
        if k != "word":
            raise Manual("表达式以非标识符开头")
        self.i += 1
        names.append(v)
        while True:
            if self._peek() == ".":
                self._eat(".")
                nk, nv = self.t[self.i]
                if nk != "word":
                    raise Manual("点号后面不是标识符")
                self.i += 1
                names.append(nv)
            elif self._peek() == "[":
                self._eat("[")
                sk, sv = self.t[self.i]
                if sk not in ("dq", "sq"):
                    raise Manual("方括号里不是字符串常量")
                self.i += 1
                names.append(sv[1:-1])
                bracket = True
                self._eat("]")
            else:
                return names, bracket

    def prim(self):
        k, v = (self.t[self.i] if self.i < len(self.t) else (None, None))
        if v == "(":
            self._eat("(")
            n = self.orx()
            self._eat(")")
            return n
        if k == "word":
            names, bracket = self.chain()
            if self._peek() == "(":
                self._eat("(")
                args = []
                while self._peek() != ")":
                    ak, av = self.t[self.i]
                    if ak in ("dq", "sq", "bdq", "bsq"):
                        args.append(("str", _strval(av)))
                    elif ak == "num":
                        args.append(("num", int(av)))
                    else:
                        raise Manual(f"函数参数位置出现 {av!r}")
                    self.i += 1
                    if self._peek() == ",":
                        self._eat(",")
                self._eat(")")
                return ("call", names, args, bracket)
            return ("ref", names, bracket)
        if k in ("dq", "sq", "bdq", "bsq"):
            self.i += 1
            node = ("str", _strval(v))
            if self._peek() == ".":
                raise Manual("判据以字符串常量为接收者调用方法（形如 字符串.bmatches(响应)）—— 那是正则，不是关键字命中")
            return node
        if k == "num":
            self.i += 1
            node = ("num", int(v))
            if self._peek() == ".":
                raise Manual("判据以数字为接收者调用方法，语义不明")
            return node
        raise Manual(f"表达式语法：意外的 {v!r}")


def parse_expr(s):
    p = _P(_tokens(s))
    node = p.orx()
    if p.i != len(p.t):
        raise Manual(f"表达式结尾有残留 {p._peek()!r}")
    return node


# --------------------------------------------------------------------------
# 形状判定：只接受 `status(可选) && 若干 (part 含 关键字) 的析取`
# --------------------------------------------------------------------------
def _flat(node, kind):
    return node[1] if node[0] == kind else [node]


def _why_call(node):
    """给"翻不动"的原子一个具体原因（而不是笼统的"不支持"）。"""
    kind = node[0]
    if kind == "not":
        return "带取反（!）—— 我们的规则表没有「排除」位置"
    if kind == "cmp":
        l, r = node[2], node[3]
        if l[0] == "str" or r[0] == "str":
            return "命名条目前缀（`\"名字\" != \"\"`）：一个文件里塞了多条具名规则，要拆开重建"
        return "比较判据（长度/状态之类），不是关键字命中"
    if kind == "ref":
        return "裸引用（没有函数调用），语义不明"
    if kind == "str":
        return "字符串常量参与判定，语义不明"
    if kind in ("and", "or"):
        return ("合取嵌在析取里（`A || (B && C)`）—— 我们的规则表是析取的，表达不了「两个都得在」")
    if kind != "call":
        return "表达式形态不在可机械映射的子集里"
    names, bracket = node[1], node[3]
    if bracket:
        return "按单个响应头字段判定（headers[\"x\"]）—— 我们的 headers 位置是拼接串，口径不同"
    fn = names[-1]
    if names[0] == "banner" or "banner" in names:
        return "tcp banner 判据（我们引擎只有 http）"
    if names[0] == "response" and "raw" in names:
        return "response.raw（含状态行的整包）—— 我们没有这个判据位置"
    if names[0] == "resp":
        return "用了 resp. 简写 —— 只认 response.，不猜它是否等价"
    if fn in ("bmatches", "bsubmatch", "matches", "regex"):
        return "正则/捕获类判据，不是关键字命中"
    if fn in ("bsize", "size", "length"):
        return "响应长度判据"
    return f"函数 {fn} 不在可机械映射的子集里"


def _atom(node):
    """-> (part, 大小写无关?, 关键字)。不合形状就抛 Manual(原因)。"""
    if node[0] != "call":
        raise Manual(_why_call(node))
    names, args, bracket = node[1], node[2], node[3]
    if bracket:
        raise Manual(_why_call(node))
    if len(names) != 3 or names[0] != "response" or names[2] not in ("bcontains", "ibcontains"):
        raise Manual(_why_call(node))
    part = _PART_MAP.get(names[1])
    if not part:
        raise Manual(_why_call(node))
    if len(args) != 1 or args[0][0] != "str" or not args[0][1]:
        raise Manual("关键字为空或参数不止一个")
    word = args[0][1]
    if "{{" in word or "}}" in word:
        raise Manual("关键字里有 afrog 变量占位符（双花括号那类）—— 我们不做变量代入，"
                    "照搬进去只会得到一条永远匹配不上的判据")
    return part, names[2] == "ibcontains", word


def _status_cmp(node):
    """是 `response.status == NNN` 吗？返回状态码或 None。"""
    if node[0] != "cmp" or node[1] != "==":
        return None
    l, r = node[2], node[3]
    if l[0] != "ref" or l[2] or l[1] != ["response", "status"]:
        return None
    if r[0] != "num":
        return None
    return r[1]


def shape(expr):
    """-> (状态码集合, [(part, ci?, 关键字), …])；不合形状抛 Manual。"""
    node = parse_expr(expr)
    terms = _flat(node, "and")
    sts, rest = [], []
    for t in terms:
        s = _status_cmp(t)
        (sts if s is not None else rest).append(s if s is not None else t)
    if not rest:
        raise Manual("只有状态码，没有任何内容判据")
    # 先排"命名条目前缀"（聚合文件里 `"产品名" != "" && …` 那种），否则它会退化成人话不清的"合取"
    for t in rest:
        if t[0] == "cmp" and (t[2][0] == "str" or t[3][0] == "str"):
            raise Manual(_why_call(t))
    if len(rest) > 1:
        raise Manual("合取判据（A && B）—— 我们的规则表是析取的，表达不了「两个都得在」")
    alts = _flat(rest[0], "or")
    atoms = [_atom(a) for a in alts]
    return sorted(set(sts)), atoms


# --------------------------------------------------------------------------
# 单个 YAML -> 行
# --------------------------------------------------------------------------
def rule_refs(doc):
    """顶层 `expression` 才决定哪些 rule 真会执行 —— 只接受 `rN()` / `rN() || rM()`。

    实测 130 个指纹文件：101 个 `r0()`、26 个 `r0() || r1()`、3 个三个 `rN()` 的析取，
    **没有一个是合取**。但"测出来如此"不等于"设计上如此"，合取照样拒绝。
    """
    expr = doc.get("expression")
    if not isinstance(expr, str) or not expr.strip():
        raise Manual("没有顶层 expression（哪些 rule 真会执行，无从确定）")
    terms = _flat(parse_expr(expr), "or")
    names = []
    for t in terms:
        if t[0] != "call" or t[3] or t[2]:
            raise Manual("顶层 expression 不是纯 rule 引用（`rN()` 形式）—— 不猜它的组合关系")
        n = "+".join(t[1])
        if n in names:
            raise Manual("顶层 expression 里同一个 rule 被引用两次")
        names.append(n)
    return names


def _rules_of(doc):
    rules = doc.get("rules")
    if not isinstance(rules, dict):
        raise Manual("rules 不是以规则名为键的映射")
    return rules


def request_kinds(doc, names):
    """被引用 rule 的请求 `(method, path, 是否有body, 是否tcp, 是否brute)`。"""
    out = []
    for r in (_rules_of(doc)[n] for n in names):
        if not isinstance(r, dict):
            continue
        req = r.get("request") or {}
        if req.get("type") == "tcp" or req.get("steps") or r.get("expression", "").find("banner") >= 0:
            out.append(("TCP", "", False, True, False))
            continue
        method = str(req.get("method") or "GET").upper()
        body = bool(str(req.get("body") or "").strip())
        brute = bool(r.get("brute"))
        paths = req.get("path")
        if isinstance(paths, str):          # 真语料里 path 既能是列表也能是**字符串**
            paths = [paths]
        for path in (paths or [""]):
            out.append((method, str(path), body, False, brute))
    return out


def expressions_of(doc, names):
    out = []
    rules = _rules_of(doc)
    for n in names:
        if n not in rules:
            raise Manual(f"顶层 expression 引用了不存在的 rule {n}")
        r = rules[n]
        if not isinstance(r, dict):
            raise Manual(f"rule {n} 不是映射")
        got = False
        if isinstance(r.get("expression"), str):
            out.append(r["expression"])
            got = True
        ex = r.get("expressions")
        if isinstance(ex, list):
            out.extend(str(x) for x in ex)
            got = True
        if not got:
            raise Manual(f"rule {n} 没有表达式")
    return out


def build_entries(doc):
    """一份文档 -> `(行列表, 拒绝原因)`；行 = dict(part, pattern, statuses, path, note)。

    刻意**只翻最主干的一种形状**：`status == NNN && (body 含 A || body 含 B …)`。
    多个 rule 的"或"关系**不靠假设**：它来自顶层 `expression` 的实测形状（见 `rule_refs`），
    合取一律拒绝。
    """
    try:
        names = rule_refs(doc)
        kinds = request_kinds(doc, names)
    except Manual as e:
        return None, str(e)
    if not kinds:
        return None, "没有 request 块"
    for method, _p, body, tcp, brute in kinds:
        if tcp:
            return None, "type:tcp 原始探测（我们引擎只有 http）"
        if method in _WRITE_METHODS:
            return None, f"非只读方法 {method}"
        if method == "POST" and body:
            return None, "POST 带请求体（可能不是纯探测）"
        if brute:
            return None, "带 brute 路径清单（一次命中多路径，与我们的单请求语义不同）"
    info = doc.get("info") or {}
    sev = str(info.get("severity") or "").lower()
    if sev not in OK_SEVERITIES:
        return None, f"severity={sev}（这一条不是识别而是漏洞判定，绝不进指纹表）"
    paths = sorted({p for _m, p, _b, _t, _r in kinds if p})
    rows = {}
    try:
        exprs = expressions_of(doc, names)
    except Manual as e:
        return None, str(e)
    for expr in exprs:
        try:
            sts, atoms = shape(expr)
        except Manual as e:
            return None, str(e)
        for part, ci, word in atoms:
            key = (part, ci, tuple(sts))
            rows.setdefault(key, []).append(word)
    if not rows:
        return None, "没有可映射的判据"
    path_note = ("请求路径 " + ",".join(paths) + " 未表达（我们按响应内容打标签）；"
                 if paths and paths != ["/"] else "")
    out = []
    for (part, ci, sts), words in rows.items():
        pat = ("(?i)" if ci else "") + "|".join(re.escape(w) for w in dict.fromkeys(words))
        try:
            compiled = re.compile(pat)
        except re.error as e:
            return None, f"生成的正则编译失败：{e}"
        # 自检：判据必须能命中它自己的关键字，否则这行就是生成坏了（大小写/转义写歪）
        probe = "\n".join(words) if not ci else ("\n".join(words) + "\n" + "\n".join(words).upper())
        if not compiled.search(probe):
            return None, "自检失败：生成的判据命中不了自己的关键字"
        out.append({"part": part, "pattern": pat, "statuses": ",".join(str(s) for s in (sts or [])),
                    "path": ",".join(paths) or "/", "nwords": len(words),
                    "note": (path_note + ("大小写不敏感；" if ci else "") +
                             ("非 ASCII 关键字，需确认响应编码；"
                              if any(ord(c) > 127 for w in words for c in w) else "")).rstrip("；")})
    return out, ""


def build_rows(src):
    yaml = _load_yaml()
    rows = []
    for p in sorted(Path(src).rglob("*.yaml")):
        try:
            doc = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        except Exception as e:
            rows.append({"skip": "refuse", "why": f"YAML 解析失败 {type(e).__name__}",
                         "file": p.name, "tag": p.stem, "name": p.stem})
            continue
        if not isinstance(doc, dict) or "rules" not in doc:
            continue
        tag = str(doc.get("id") or p.stem).strip().lower().replace(" ", "-")
        name = str((doc.get("info") or {}).get("name") or tag)
        entries, why = build_entries(doc)
        rel = p.relative_to(Path(src)).as_posix() if p.is_relative_to(Path(src)) else p.name
        if entries is None:
            rows.append({"skip": "refuse", "why": why, "file": rel, "tag": tag, "name": name})
            continue
        for e in entries:
            rows.append(dict(e, skip="", tag=tag, file=rel, name=name))
    return rows


def render_table(rows):
    lines = [SEP.join(TABLE_COLS)]
    for r in rows:
        if r.get("skip"):
            continue
        lines.append(SEP.join([r["tag"], r["part"], r["pattern"], r["statuses"], r["path"],
                               r["file"], "", f"afrog-pocs(MIT): {r['name']}；{r['note']}"]))
    return "\n".join(lines) + "\n"


HEADER_LINES = [
    "# 外置指纹表（引擎按行读取：scanner/fingerprint.py）",
    "#",
    "# 格式（TAB 分隔，后两段可省）：",
    "#     标签 <TAB> 位置 <TAB> 正则 <TAB> 状态码 <TAB> 来源 <TAB> 说明",
    "#   - 位置：headers | body（见 fingerprint.identify 的 parts）；",
    "#   - 状态码：逗号分隔，`*` 或留空 = 不分状态；只有响应状态在清单里时才打标签；",
    "#   - 同一标签可以多行，**任一行命中即打标签**（析取，与内置 SIGNATURES 一致）；",
    "#   - 以 `#` 开头的行与空行忽略。",
    "#",
    "#   - 同一个标签可以有多行（新增判据），但已有行**不会被改写也不会被删**；",
    "#",
    "# 来源：条目由 tools/import_afrog_fp.py 从 afrog-pocs（MIT）的 fingerprinting/ 目录里",
    "# 逐条人工复核后追加（`--apply` 只搬复核列写了 ok 的行），许可与出处见 NOTICE.md；",
    "# 复核结论与全部拒搬理由见 docs/afrog-fp-review.tsv。",
]


def apply_table(text):
    """只把复核列写了 `ok` 的行追加进外置字典；返回 `(写入条数, 跳过说明列表)`。"""
    out = ROOT / EXTRA_DICT
    existing = out.read_text(encoding="utf-8").splitlines() if out.exists() else []
    # 去重键是**整条判据**，不是标签：`jenkins` 这个标签本来就可以既有响应头判据又有正文判据
    have = {tuple(ln.split(SEP)[:3]) for ln in existing if ln.strip() and not ln.startswith("#")}
    added, notes, keep = 0, [], []
    for ln in text.splitlines():
        cols = ln.split(SEP)
        if len(cols) < 6 or cols[0] == TABLE_COLS[0]:
            continue
        tag, part, pat, sts, path, src = cols[:6]
        verdict = cols[6].strip().lower() if len(cols) > 6 else ""
        note = cols[7] if len(cols) > 7 else ""
        if verdict != VERDICT_OK:
            notes.append(f"{tag}：复核列不是 ok（值为 {verdict or '空'}）→ 不动")
            continue
        if part not in ("headers", "body"):
            notes.append(f"{tag}：位置 {part} 不是引擎支持的判据位置 → 不动")
            continue
        if (tag, part, pat) in have:
            notes.append(f"{tag}：字典里已有这一条判据 → 不重复追加")
            continue
        if not sts.strip():
            # 外置表存在的意义就是门控：不分状态必须由复核人**显式**在该列写 `*`，不能留空混过去
            notes.append(f"{tag}：状态码列为空 → 不动（要不分状态请显式写 *）")
            continue
        try:
            re.compile(pat)
        except re.error as e:
            notes.append(f"{tag}：判据编译失败（{e}）→ 不动")
            continue
        if not path.strip():
            path = "/"
        keep.append(SEP.join([tag, part, pat, sts.strip(), src, note]))
        have.add((tag, part, pat))
        added += 1
    if keep:
        # newline="\r\n" 会把写出去的每个 `\n` 翻译成 `\r\n`，所以这里**只写 \n**；
        # 两处都写 \r\n 会得到 `\r\r\n`（本工具第一版就是这么把字典写坏的）
        new_file = not out.exists()
        with out.open("a", encoding="utf-8", newline="\r\n") as fh:
            if new_file:
                fh.write("\n".join(HEADER_LINES) + "\n")
            for row in keep:
                fh.write(row + "\n")
    return added, notes


def lint():
    """把字典交给引擎自己读，返回 `(标签数, 问题列表)` —— 校验的是**消费方**的口径。"""
    from scanner import fingerprint as fp
    rules, issues = fp.load_extra()
    tags = {t for t, _r in rules.items()}
    return len(tags), issues


def main(argv=None):
    ap = argparse.ArgumentParser(description="afrog-pocs 指纹的按需导入（机器不判定）")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--scan", action="store_true", help="只统计各类条数（不发任何请求）")
    g.add_argument("--table", action="store_true", help="出候选工作表（复核列留空）")
    g.add_argument("--apply", metavar="TSV", help="只搬表里复核列写了 ok 的行（没有任何"
                                                                 "『全部放行』旗标）")
    g.add_argument("--lint", action="store_true", help="校验外置字典能否被引擎读到")
    ap.add_argument("--src", help="本地 afrog-pocs/fingerprinting 目录（只走参数，不留绝对路径）")
    ap.add_argument("--out", help="把候选表写到该路径（默认 stdout）")
    args = ap.parse_args(argv)

    if args.lint:
        n, issues = lint()
        print(f"[*] 字典标签 {n} 个；问题 {len(issues)} 条")
        for i in issues:
            print("    [!] " + i)
        return 1 if issues else 0
    if args.apply:
        p = Path(args.apply)
        if not p.is_absolute():
            p = ROOT / p
        if not p.exists():
            raise SystemExit(f"[!] 找不到复核表：{p.name}")
        added, notes = apply_table(p.read_text(encoding="utf-8"))
        print(f"[+] 写入 {added} 条到 {EXTRA_DICT}（只搬复核列写了 ok 的）")
        for n in notes:
            print("    [跳过] " + n)
        return 0
    if not args.src:
        raise SystemExit("[!] --scan / --table 需要 --src <本地 afrog-pocs 目录>")
    rows = build_rows(args.src)
    ok_rows = [r for r in rows if not r.get("skip")]
    refused = [(r["file"], r["why"]) for r in rows if r.get("skip")]
    if args.scan:
        files = {r["file"] for r in rows if not r.get("skip")}
        print(f"[*] 模板 {len(rows) and (len(files) + len({f for f, _ in refused}))} 个："
              f"可映射文件 {len(files)} / 拒搬 {len({f for f, _ in refused})}")
        print(f"[*] 候选行 {len(ok_rows)} 条")
        from collections import Counter
        for why, n in Counter(w for _f, w in refused).most_common():
            print(f"    {n:3d} × {why}")
        return 0
    text = render_table(rows)
    if args.out:
        (ROOT / args.out).write_text(text, encoding="utf-8")
        print(f"[+] 候选表已写到 {args.out}（可映射 {len(ok_rows)} 条；复核列写 ok 再 --apply）")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
