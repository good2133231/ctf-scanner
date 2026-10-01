"""用户黑名单：命中的域名**不入资产库**，因此后续阶段也不会去扫它。

设计取舍：
- 存成纯文本 `config/blacklist.txt`（一行一个，`#` 注释），而不是 DB 表 ——
  用户可以手工编辑、可以进 git（不含敏感信息）、也不受"删库"影响；
- **命中即整条丢弃**（而不是"入库但标记"）：资产面越小、dirscan/vulnscan 的预算越集中，
  这也正是用户要黑名单的目的（例如把第三方域、上级单位域、无关的姊妹业务域排除掉）；
- 每次调用都重新读文件、不做缓存：用户就在 GUI 里随时增删，缓存只会带来"改了不生效"的困惑。

续89「按账号隔离」：原来只有**一份全局**文件 —— 共享服务器上，子用户加一个域名会**影响所有人**。
现在生效集合 = **全局文件**（`config/blacklist.txt`，管理员维护）∪ **本账号文件**
（`config/blacklist.d/<账号 id>.txt`，只对该账号的任务生效）。仍是纯文本、可手工编辑。
"""
from pathlib import Path

from .config import BASE_DIR
from .utils import read_lines, to_ascii


_HEADER = ("# 用户黑名单：一行一个域名（含其所有子域），命中的域名不入资产库、也不会被扫。\n"
           "# 可直接手工编辑本文件；GUI 的「子域名 / 拓展域名」页也支持批量加入。\n")
_HEADER_ACCOUNT = ("# 本账号专属黑名单（续89）：只影响**本账号**的任务，不影响别人的扫描。\n"
                   "# 一行一个域名（含其所有子域）；全局黑名单在 config/blacklist.txt。\n")


def path(settings=None):
    """黑名单文件路径（`blacklist.path` 可覆盖，相对路径按项目根解析）。"""
    raw = ((settings or {}).get("blacklist") or {}).get("path") or "config/blacklist.txt"
    p = Path(str(raw))
    return p if p.is_absolute() else (BASE_DIR / p)


def dir_path(settings=None):
    """按账号黑名单的目录（`blacklist.dir` 可覆盖，相对路径按项目根解析）。"""
    raw = ((settings or {}).get("blacklist") or {}).get("dir") or "config/blacklist.d"
    p = Path(str(raw))
    return p if p.is_absolute() else (BASE_DIR / p)


def account_path(owner_id, settings=None):
    """某账号的黑名单文件（续89）；`owner_id` 为 0 / None（= 无归属）→ 返回 None。"""
    try:
        oid = int(owner_id or 0)
    except (TypeError, ValueError):
        oid = 0
    return (dir_path(settings) / f"{oid}.txt") if oid > 0 else None


def enabled(settings=None):
    return ((settings or {}).get("blacklist") or {}).get("enabled") is not False


def load(settings=None, owner_id=None):
    """读取**全部生效条目** = 全局文件 ∪ 本账号文件（续89），保持顺序去重。

    条目已归一化（小写、去前后点、去掉 `*.` 前缀、IDN → punycode）。
    开关关闭时返回空列表 —— 调用方据此判断"当前不拦任何域名"。
    `owner_id` 为空 / 0 时只看全局文件（老任务、CLI 直跑都是这一档）。
    """
    if not enabled(settings):
        return []
    out = _read(path(settings))
    ap = account_path(owner_id, settings)
    if ap is not None and ap.exists():
        seen = set(out)
        for entry in _read(ap):
            if entry not in seen:
                seen.add(entry)
                out.append(entry)
    return out


def _read(p):
    """**无视开关**地读文件条目。`add()` 用它去重：若用 `load()`（关开关时返回空），
    去重就会失效，同一条目会被反复追加到文件里。"""
    out, seen = [], set()
    for line in read_lines(p):
        entry = _norm(line)
        if entry and entry not in seen:
            seen.add(entry)
            out.append(entry)
    return out


def matches(domain, entries):
    """域名是否命中黑名单：条目本身或其**任意子域**都算命中。

    即写入 `example.com` 会同时屏蔽 `a.example.com`、`b.a.example.com` ——
    这是刻意的（批量拉黑一个域通常就是想连它的子域一起排除）。
    """
    d = _norm(domain)
    if not d:
        return ""
    for entry in entries or []:
        if d == entry or d.endswith("." + entry):
            return entry
    return ""


def filter_pairs(pairs, settings=None, owner_id=None):
    """过滤 `[(domain, source), ...]`，返回 `(保留, 被拦)`。被拦项形如 `(domain, entry)`。

    阶段层在 `insert_subdomains()` **之前**调用它 —— 这样被拦的域名既不入资产库，
    也不会出现在后续阶段的输入里。
    """
    entries = load(settings, owner_id=owner_id)
    if not entries:
        return list(pairs), []
    kept, blocked = [], []
    for domain, source in pairs:
        hit = matches(domain, entries)
        if hit:
            blocked.append((domain, hit))
        else:
            kept.append((domain, source))
    return kept, blocked


def filter_domains(domains, settings=None, owner_id=None):
    """过滤纯域名列表，返回 `(保留, 被拦条数)`（子域名阶段用：列表里没有来源信息）。"""
    entries = load(settings, owner_id=owner_id)
    if not entries:
        return list(domains), 0
    kept = [d for d in domains if not matches(d, entries)]
    return kept, len(domains) - len(kept)


def add(domains, settings=None, owner_id=None):
    """把域名批量写入黑名单，返回**新增**条数（已存在的不重复写）。

    续89：有 `owner_id` → 写**本账号文件**（只影响自己的任务）；没有 → 写**全局文件**。
    """
    p = account_path(owner_id, settings) or path(settings)
    existing = _read(p)
    have = set(existing)
    fresh = []
    for raw in domains:
        d = _norm(raw)
        if d and d not in have:
            have.add(d)
            fresh.append(d)
    if not fresh:
        return 0
    p.parent.mkdir(parents=True, exist_ok=True)
    if not p.exists():
        p.write_text(_HEADER_ACCOUNT if account_path(owner_id, settings) else _HEADER,
                     encoding="utf-8")
    # 手工编辑过的文件**末尾常常没有换行**（编辑器保存习惯）。直接 append 会把新条目粘到
    # 最后一条上：`example.com` + `a.test` → `example.coma.test`，既丢了原条目又多出一条
    # 不存在的域名，而黑名单是"命中即丢弃"，写坏等于静默失效。故追加前先补一个换行。
    tail = p.read_text(encoding="utf-8", errors="replace") if p.exists() else ""
    with p.open("a", encoding="utf-8") as fh:
        if tail and not tail.endswith("\n"):
            fh.write("\n")
        fh.write("".join(d + "\n" for d in fresh))
    return len(fresh)


def remove(domains, settings=None, owner_id=None):
    """从黑名单移除若干条目，返回**实际删除**条数。

    续89：有 `owner_id` → 只动**本账号文件**；没有 → 动**全局文件**（与 `add` 对称）。
    """
    p = account_path(owner_id, settings) or path(settings)
    drop = {_norm(d) for d in domains}
    drop.discard("")
    if not drop or not p.exists():
        return 0
    kept, removed = [], 0
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        entry = _norm(line)
        if entry and entry in drop:
            removed += 1
            continue
        kept.append(line)
    if removed:
        p.write_text("\n".join(kept).rstrip("\n") + "\n", encoding="utf-8")
    return removed


def _norm(value):
    """归一化：小写、去空白与前后点、把 `*.example.com` 视作 `example.com`，
    再把主机名统一成 **ASCII(punycode) 形**（IDN 比较边界）。

    末尾补 `to_ascii` 的理由：文件里写 `例子.中国`、而查询是 punycode（或反过来）时，
    不归一就**永不匹配** = 用户加了黑名单却没生效（静默失效）。黑名单文件本身不动，
    存量条目靠比较侧归一兜住；`to_ascii` 失败（非法 IDNA）时退回已小写/去点的原串，
    保持"只是没匹配上"的降级语义，绝不因此丢条目。
    """
    text = str(value or "").strip().lower()
    if not text or text.startswith("#"):
        return ""
    if text.startswith("*."):
        text = text[2:]
    text = text.strip(".")
    if not text or " " in text or "/" in text:
        return ""
    return to_ascii(text) or text