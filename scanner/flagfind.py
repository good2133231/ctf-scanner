"""CTF flag 候选抽取：在**已经拿到的**响应正文里按可配前缀/正则找 flag 形态串。

为什么值得单独成一张表（而不是塞进 `vulns` 或 `leads`）：flag 是 CTF 的**结论**，
既不是"漏洞"（一个 `flag{...}` 不代表目标有漏洞），也不是"线索"（它不需要人工再决定
要不要看，就是要直接抄走的东西）。混进 `vulns` 会让人以为"这站有个高危漏洞"，
混进 `leads` 又会被续24 的"页签移除"口径藏起来 —— 两边都误导，所以单独一表一条路。

三条承重边界，改这个模块前请先读完：

1. **零额外请求**。本模块只吃调用方手里已有的文本，自己不发起任何请求 —— 所以它的
   成本上限就是"已经扫过的那些正文"。判据（AST 级）在 `tests/smoke.py [8ae]`：
   模块源码里不许出现 `http_request` / `urlopen` / `socket` / `run_cmd`。
   新增"这页没取到正文，我再抓一次"的写法会立刻判红 —— 那等于把「目录发现 + JS 挖掘」
   的请求量翻倍，而预算与限速都不是为它准备的。
2. **成本必须封顶**。默认判据是"字面前缀 + 定界闭括号"，用 `str.find` 扫一份**小写副本**
   （封顶键 `flags.max_chars` 的单位是**字符**不是字节 —— 成本按字符走，而中文一个字符
   在 UTF-8 里是 3 字节，写成"字节"会让人以为放行量比实际小三倍）：
   实测 1.56 MB 正文：本实现 1.2 ms；同样两个前缀写成一趟全局忽略大小写的交替正则要
   40.3 ms，把各家比赛的前缀都塞进去（21 路）要 332.3 ms。而这些正文在 dirscan 里是
   **按路径逐条**过一遍的（几百到上万条），量级差就是整轮的耗时差。
   用户自定义正则**只在候选窗口上跑**（先取该正则的"必现字面量"当锚，见
   `scanner/fingerprint.py::required_literals`），取不出字面量的正则**直接拒用并说明原因**，
   绝不退回"在整份正文上扫" —— 那一条口子同时放开了 ReDoS 与耗时。
3. **只报候选、大小写原样**。抽到的串按**原文**保留（flag 大小写敏感，被小写化的只是
   用于定位的那份副本），并在 `context` 里带上前后文，因为同一形状经常是**占位符**
   （JS 里的 `flag{xxx}`、模板里的 `ctf{...}`）。判"是不是真 flag"是人做的事。
   误报的代价是多看一眼，漏报的代价是丢一道题 —— 所以本模块**刻意不加**"前缀前面
   必须是词边界"这类看着更聪明的规则（`.ctf{` 这种 CSS 类名会进候选，是有意的）。
"""
import re
import threading

# 默认前缀：不带括号时自动按 `前缀{` 处理（`normalize_prefixes`）。
# 刻意只放两个最常见的族 —— 清单越长 `str.find` 的趟数越多，而任何 `xxx{` 形态
# 都能由用户在策略页自己加，没必要把各家比赛的自定义前缀抄进源码。
DEFAULT_PREFIXES = ("flag", "ctf")

# 前缀尾字符 -> 闭括号。写 `flag[` 就是方括号形态，写 `flag` 等价于 `flag{`。
_CLOSER_OF = {"{": "}", "(": ")", "[": "]", "<": ">"}

# 值体里不许出现的字符：空白、控制符、以及**任何**括号。嵌套形态一律不收
# （`flag{a{b}}` 要么是真嵌套、要么是抽取越界，两种都不该进候选表）。
_VALUE_STOPS = r"^\s\x00-\x1f\x7f{}()\[\]<>"

# 上下文取多少字符（前后各一半）——只给人看，不参与判据。
CONTEXT_MAX = 240


def _cfg(settings):
    """取生效的 flags 段：缺段/坏值都落回与 DEFAULTS 同形状的兜底，不抛。"""
    from .config import DEFAULTS
    out = dict(DEFAULTS.get("flags") or {})
    out.update({k: v for k, v in ((settings or {}).get("flags") or {}).items()
                if v is not None})
    return out


def _ints(cfg, name, default, lo=1):
    """策略页送来的是字符串，这里统一收口成 int（坏值落回默认，绝不抛）。"""
    try:
        v = int(cfg.get(name, default))
    except (TypeError, ValueError):
        return default
    return v if v >= lo else default


def normalize_prefixes(items):
    """前缀清单 -> `[(显示名, 小写搜索串, 闭括号)]`，保序去重。

    `flag` → `("flag", "flag{", "}")`；`DASCTF{` → `("DASCTF", "dasctf{", "}")`；
    `flag[` → `("flag", "flag[", "]")`。搜索串一律小写：定位用小写副本，
    取值仍从**原文**切（见模块头第 3 条边界）。
    """
    out, seen = [], set()
    for raw in (items or []):
        s = str(raw or "").strip()
        if not s:
            continue
        if s[-1] in _CLOSER_OF:
            closer = _CLOSER_OF[s[-1]]
        else:
            s, closer = s + "{", "}"
        needle = s.lower()
        if needle in seen:
            continue
        seen.add(needle)
        out.append((s.rstrip("{()[<]") or s, needle, closer))
    return out


_VALUE_RE = {}    # (闭括号, min, max) -> 值体正则
_RULES = {}       # 配置指纹 -> 规则表；"改一次策略重算一次"，不随文本增长


def _value_re(closer, min_len, max_len):
    key = (closer, min_len, max_len)
    rx = _VALUE_RE.get(key)
    if rx is None:
        # 定长上限的单一字符类 + 一个闭括号：没有嵌套量词，不存在回溯爆炸的形状。
        rx = re.compile("[" + _VALUE_STOPS + re.escape(closer) + "]"
                        + "{" + str(min_len) + "," + str(max_len) + "}"
                        + re.escape(closer))
        _VALUE_RE[key] = rx
    return rx


def compile_patterns(items):
    """用户正则 -> `(rules, rejects)`；`rules` 元素为 `(原文, 编译后, [小写锚])`。

    **取不出锚就不收**：`required_literals()` 返回 None 意味着"任何文本都可能命中"，
    只能在整份正文上跑 —— 一条手滑的「全局忽略大小写 + flag.*?}」就足以把 dirscan 的几万条响应
    各扫一遍。拒用的原因要交给调用方显示，不静默丢（这是本仓反复出事的地方）。

    锚一律小写：在小写副本上定位锚是**超集**（大小写敏感的写法必然也含该字面量的
    小写形态，忽略大小写的写法同理），多选的窗口由正则自己否掉。这样一处代码同时
    覆盖两种正则，也绕开"组内局部 `(?i:…)`"那个坑（续122 里它是放弃过滤的条件 ——
    这里用它做**超集预筛**而不是**排除**，方向不同，结论就不同）。
    """
    from .fingerprint import required_literals
    rules, rejects = [], []
    for raw in (items or []):
        s = str(raw or "").strip()
        if not s:
            continue
        try:
            rx = re.compile(s)
        except re.error as e:
            rejects.append(f"{s}（编译失败：{e}）")
            continue
        anchors = required_literals(s)
        if not anchors:
            rejects.append(f"{s}（取不出必现字面量 ⇒ 只能在整份正文上跑，为控成本拒用；"
                           f"请改成带字面量锚点的写法，或直接放进「前缀」清单）")
            continue
        rules.append((s, rx, [str(a).lower() for a in anchors]))
    return rules, rejects


def rules(settings):
    """生效规则表（按配置指纹缓存）。返回 `(前缀规则, 正则规则, 拒用说明, cfg)`。

    `prefixes: []` 按字面理解成"我只要自己的正则"，**不回落**成默认前缀 —— 回落会让用户
    清空清单之后仍然被 `flag{`/`ctf{` 收一遍，而"缺段"（老配置 / CLI 没写）才落回默认。
    """
    cfg = _cfg(settings)
    prefixes = cfg.get("prefixes")
    if prefixes is None:
        prefixes = DEFAULT_PREFIXES
    patterns = cfg.get("patterns")
    key = (tuple(prefixes or ()), tuple(patterns or ()),
           _ints(cfg, "min_len", 1), _ints(cfg, "max_len", 200, 1))
    hit = _RULES.get(key)
    if hit is None:
        min_len, max_len = key[2], max(key[3], key[2])
        pat, rejects = compile_patterns(key[1])
        hit = ([(kind, needle, closer, _value_re(closer, min_len, max_len))
                for kind, needle, closer in normalize_prefixes(key[0])],
               pat, rejects, cfg)
        _RULES[key] = hit
    return hit


def _finds(hay, needle, limit):
    """在 `hay` 里逐个定位 `needle`，最多 `limit` 个（一页刷爆的兜底）。"""
    pos, n = 0, 0
    step = max(1, len(needle))
    while n < limit:
        i = hay.find(needle, pos)
        if i < 0:
            return
        yield i
        n += 1
        pos = i + step


def _hays(text):
    """`(用于定位的小写副本, 偏移是否与原文对齐)`。

    单列成一个函数是为了**可变异**（§6.1）：整条"大写正文也收"的能力就压在这一次
    `lower()` 上，把它打回"直接在原文上找小写锚"，`FLAG{...}` 立刻找不到。
    长度不对齐的那一档（U+0130 折叠成 2 字符）由调用方改走"直接对原文做忽略大小写匹配"的慢路 ——
    宁可用那条慢路，也不给一个看着对、其实切歪的候选。
    """
    low = text.lower()
    return low, len(low) == len(text)


def scan(text, settings=None, max_hits=200):
    """在一份文本里找 flag 形态串，返回 `[(kind, value, offset)]`。

    纯函数：不查库、不发请求、不写日志。`max_hits` 是**单次调用**的上限
    （策略页的 `max_per_source`）—— 一页里出现 200 个 `flag{` 只可能是模板或混淆产物，
    继续找只是把候选表灌满。
    """
    if not text:
        return []
    pre, pat, _rej, cfg = rules(settings)
    if not pre and not pat:
        return []
    max_len = _ints(cfg, "max_len", 200)
    low, aligned = _hays(text)
    out = []

    def _push(at, rx, kind):
        """从 `at` 起试匹配值体；命中则记 **(kind, 值, 值的起点)**。

        偏移一律是"值的起点"，三档（对齐 / 非对齐 / 自定义正则）同口径 —— 因为
        `context()` 要拿它前后取文，混用"前缀起点"和"值起点"会让人看到的上下文偏左几十字。
        """
        m = rx.match(text, at)
        if not m:
            return False
        out.append((kind, m.group()[:-1], at))
        return len(out) >= max_hits

    for kind, needle, closer, rx in pre:
        if aligned:
            for i in _finds(low, needle, max_hits):
                if _push(i + len(needle), rx, kind):
                    return out
        else:
            for m in re.finditer("(?i)" + re.escape(needle), text):
                if _push(m.end(), rx, kind):
                    return out
    half = max(64, 2 * max_len)
    for _src, rx, lows in pat:
        for anchor in lows:
            if aligned:
                it = _finds(low, anchor, max_hits)
            else:
                it = (m.start() for m in re.finditer("(?i)" + re.escape(anchor), text))
            for i in it:
                a = max(0, i - half)
                b = min(len(text), i + 2 * half)
                m = rx.search(text, a, b)
                if not m or not m.group():
                    continue
                out.append(("regex", m.group(), m.start()))
                if len(out) >= max_hits:
                    return out
    return out


def context(text, start, end):
    """命中串前后各取一半，供人工判断"这是真 flag 还是模板占位符"。

    写这行时先漏过一次的正是**后半段**（`text[end:b]` 没拼进去，上下文就只剩"值以前"），
    所以判据要同时查两头（`[8ae] ④`）。
    """
    half = CONTEXT_MAX // 2
    a = max(0, start - half)
    b = min(len(text), end + half)
    return (("…" if a else "") + text[a:start] + text[start:end] + text[end:b]
            + ("…" if b < len(text) else ""))


def stats(ctx):
    """本任务的抽取计数（`StageContext` 建锁；桩对象也够用）。"""
    st = getattr(ctx, "_flag_stats", None)
    if st is None:
        st = {"texts": 0, "bytes": 0, "oversize": 0, "new": 0, "dedup": 0, "full": 0}
        ctx._flag_stats = st
        ctx._flag_lock = threading.Lock()
    return st


def harvest(ctx, url, text, where):
    """把一份**已经在手**的正文喂给 flag 判据，新候选直接入库。

    调用方：probe（根响应）/ jsmine（页面与 JS 文件）/ dirscan（每个路径的响应）/
    vulnscan（POC 命中的证据与详情）。`where` 是来源标签，进库与日志用。
    返回本次新增条数。线程安全（各阶段都在 `pool_run` 的工作线程里调）。
    """
    cfg = _cfg(ctx.settings)
    if not cfg.get("enabled", True) or not text:
        return 0
    st = stats(ctx)
    max_chars = _ints(cfg, "max_chars", 2000000, 1)
    per_source = _ints(cfg, "max_per_source", 20, 1)
    cap = _ints(cfg, "max_per_task", 200, 1)
    lock = getattr(ctx, "_flag_lock", None) or _FALLBACK_LOCK
    # 计数在锁内改：`st["texts"] += 1` 是"读-改-写"三步，dirscan 有 20 个工作线程同时在调，
    # 放到锁外就会**少报**"看过 N 份" —— 一句给人看的数字不能靠运气准。
    # 锁不覆盖 `scan()` 本身：那才是耗时的地方，串行化它等于把并发扫描改成单线程。
    with lock:
        st["texts"] += 1
        st["bytes"] += len(text)
        oversize = len(text) > max_chars
        if oversize:
            # 必须说出来：跳过 N 份正文而不说，页面就成了"扫过了、没有 flag"。
            st["oversize"] += 1
    if oversize:
        return 0
    found = scan(text, ctx.settings, max_hits=per_source)
    if not found:
        return 0
    pool = ctx.results.setdefault("flags", [])
    seen = getattr(ctx, "_flag_seen", None)
    if seen is None:
        seen = ctx._flag_seen = set()
    db_seen = getattr(ctx, "_flag_db_seen", None)
    added = 0
    with lock:
        if db_seen is None:
            from . import db
            db_seen = {str(r["value"]) for r in db.list_flags(ctx.task_id)}
            ctx._flag_db_seen = db_seen
        for kind, value, off in found:
            v = str(value).strip()
            if not v or v in seen:
                continue
            if len(pool) >= cap:
                st["full"] += 1
                break
            seen.add(v)
            if v in db_seen:
                # 跨运行去重（续25 的追加执行会第二次写同一任务）：库里已有同值就跳过
                st["dedup"] += 1
                continue
            db_seen.add(v)
            row = {"value": v, "kind": kind, "source": where, "url": str(url or ""),
                   "context": context(text, off, off + len(v))}
            from . import db
            db.insert_flag(ctx.task_id, row)
            pool.append(row)
            st["new"] += 1
            added += 1
    return added


# 桩对象（回归里手搓的 ctx）没有 `_flag_lock` 时用这把进程级锁：宁可让桩测试里的
# 抽取串行，也不给"忘建锁"留一条静默并发的路。
_FALLBACK_LOCK = threading.Lock()


def begin(ctx):
    """阶段开工时拍一份计数快照（配合 `note()` 说"这一段"的增量，不是整任务累计）。"""
    return dict(stats(ctx))


def note(ctx, since):
    """一句话统计，只报 `since` 之后的增量；没有活动就返回空串（调用方据此决定要不要打印）。

    为什么不让每个阶段各打一行"累计值"：那样 probe/jsmine/dirscan/vulnscan 四行会互相包含，
    读的人无法分辨哪一条是哪个阶段看的（本项目反复出事的就是这种"数字看着都对、其实同一份"）。
    """
    st = stats(ctx)
    d = {k: st.get(k, 0) - since.get(k, 0) for k in
         ("texts", "bytes", "oversize", "new", "dedup", "full")}
    if not d["texts"] and not d["new"]:
        return ""
    bits = [f"看过正文 {d['texts']} 份", f"新增候选 {d['new']} 条"]
    if d["dedup"]:
        bits.append(f"库里已有同值 {d['dedup']} 条未重复入库")
    if d["oversize"]:
        bits.append(f"跳过 {d['oversize']} 份超大正文（>{_cfg(ctx.settings)['max_chars']} 字符，"
                    f"是「没扫」不是「没找到」）")
    if d["full"]:
        bits.append(f"已达 max_per_task 上限，另有 {d['full']} 条未收")
    return "（" + "，".join(bits) + "）"
