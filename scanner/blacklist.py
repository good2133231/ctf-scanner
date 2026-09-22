"""用户黑名单：命中的域名**不入资产库**，因此后续阶段也不会去扫它。

设计取舍：
- 存成纯文本 `config/blacklist.txt`（一行一个，`#` 注释），而不是 DB 表 ——
  用户可以手工编辑、可以进 git（不含敏感信息）、也不受"删库"影响；
- **命中即整条丢弃**（而不是"入库但标记"）：资产面越小、dirscan/vulnscan 的预算越集中，
  这也正是用户要黑名单的目的（例如把第三方域、上级单位域、无关的姊妹业务域排除掉）；
- 每次调用都重新读文件、不做缓存：用户就在 GUI 里随时增删，缓存只会带来"改了不生效"的困惑。
"""
from pathlib import Path

from .config import BASE_DIR
from .utils import read_lines


def path(settings=None):
    """黑名单文件路径（`blacklist.path` 可覆盖，相对路径按项目根解析）。"""
    raw = ((settings or {}).get("blacklist") or {}).get("path") or "config/blacklist.txt"
    p = Path(str(raw))
    return p if p.is_absolute() else (BASE_DIR / p)


def enabled(settings=None):
    return ((settings or {}).get("blacklist") or {}).get("enabled") is not False


def load(settings=None):
    """读取全部条目（已归一化：小写、去前后点、去掉 `*.` 前缀），保持文件顺序去重。"""
    if not enabled(settings):
        return []
    out, seen = [], set()
    for line in read_lines(path(settings)):
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


def filter_pairs(pairs, settings=None):
    """过滤 `[(domain, source), ...]`，返回 `(保留, 被拦)`。被拦项形如 `(domain, entry)`。

    阶段层在 `insert_subdomains()` **之前**调用它 —— 这样被拦的域名既不入资产库，
    也不会出现在后续阶段的输入里。
    """
    entries = load(settings)
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


def filter_domains(domains, settings=None):
    """过滤纯域名列表，返回 `(保留, 被拦条数)`（子域名阶段用：列表里没有来源信息）。"""
    entries = load(settings)
    if not entries:
        return list(domains), 0
    kept = [d for d in domains if not matches(d, entries)]
    return kept, len(domains) - len(kept)


def add(domains, settings=None):
    """把域名批量写入黑名单，返回**新增**条数（已存在的不重复写）。"""
    p = path(settings)
    existing = load(settings)
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
        p.write_text("# 用户黑名单：一行一个域名（含其所有子域），命中的域名不入资产库、也不会被扫。\n"
                     "# 可直接手工编辑本文件；GUI 的「子域名 / 拓展域名」页也支持批量加入。\n",
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


def remove(domains, settings=None):
    """从黑名单移除若干条目，返回**实际删除**条数。"""
    p = path(settings)
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
    """归一化：小写、去空白与前后点、把 `*.example.com` 视作 `example.com`。"""
    text = str(value or "").strip().lower()
    if not text or text.startswith("#"):
        return ""
    if text.startswith("*."):
        text = text[2:]
    text = text.strip(".")
    if not text or " " in text or "/" in text:
        return ""
    return text