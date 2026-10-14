"""值级黑名单（续177，用户点单）：把"这个凭据值是误报"变成"下次匹配到就不显示"。

与 `scanner/blacklist.py`（**域名级**、文件制、按账号隔离）是两件事，别混：
- 那个挡的是**域名**（写资产库之前），判据是后缀匹配；
- 这个挡的是**值**（凭据 / flag 匹配之后），判据是**整值精确比对**（大小写敏感 ——
  凭据值大小写敏感，`lower()` 化会让 `AKIA` 与 `akia` 互相顶掉）。
- 那个按既有形态维持文件制；这个按主理人 2026-10-14 的要求走 **DB 表**
  （`db.secret_blacklist_*`）—— 值是要在 GUI 里逐条管理（加/看/删）的用户数据。

**判据的唯一产地**：`matches()` 就这一处。两处消费方都调 `filter_secrets()`，
不在各自阶段里各判一遍（§5.14）：`stages/jsmine.py`（JS 凭据）与
`scanner/flagfind.py`（probe / js / dir / poc 四路正文的敏感信息候选）。

**被挡掉的量必须可见**（§0 第 10 条：被收起 ≠ 存在）：`filter_secrets()` 除了返回
过关的清单，还返回挡掉几条与挡的是谁；调用方把它写进任务日志。日志里的样本**掩码**显示
（`jsmine._masked`，延迟导入避免循环依赖）—— 任务日志可能被随手贴出去，而黑名单里的值
正是"已被判为噪声"的东西，没必要原文示人。
"""
from . import db


def load(owner_id=None):
    """当前账号可见的值黑名单（管理员看全局 0 + 自己的；子账号只看自己的）。"""
    return db.list_secret_blacklist(owner_id=owner_id)


def _entry_value(e):
    """黑名单条目的值：`db` 层返回的是 `sqlite3.Row`（没有 `.get`），
    测试夹具又常传 dict —— 两种形态都要认。条目的 `value` 列 NOT NULL，不会缺键。"""
    try:
        return str(e["value"] or "")
    except Exception:
        return str((e.get("value") if hasattr(e, "get") else "") or "")


def matches(value, entries):
    """这个值是否被拉黑 → 命中的条目（空串＝没命中）。整值精确比对。"""
    v = str(value or "").strip()
    if not v:
        return ""
    for e in entries or ():
        if _entry_value(e).strip() == v:
            return e
    return ""


def filter_secrets(secrets, owner_id=None):
    """把命中值黑名单的候选挡掉 → `(过关的, 被挡的)`。

    `secrets` 是匹配阶段的产物（jsmine 的 `_find_secrets` 结果或 flagfind 的候选），
    约定每项至少带 `value`（**掩码形态**）与 `_raw`（原文，仅 jsmine 那一路有）；
    比对用 `_raw`（有它才比得出真值），没有 `_raw` 的项退回到 `value` 本身。
    被挡项原样带回（不丢字段），由调用方决定日志里怎么说。
    """
    entries = load(owner_id=owner_id)
    if not entries:
        return list(secrets or []), []
    kept, blocked = [], []
    for s in secrets or ():
        raw = s.get("_raw") if isinstance(s, dict) else None
        probe = str(raw if raw is not None else (s.get("value") if isinstance(s, dict) else s) or "")
        hit = matches(probe, entries)
        (blocked if hit else kept).append(s)
    return kept, blocked


def blocked_note(blocked, limit=3):
    """被挡候选的一句话（含掩码样本）；没有就返回空串（调用方据此决定要不要打印）。"""
    if not blocked:
        return ""
    from .jsmine import _masked          # 延迟导入：jsmine 反向依赖本模块
    samples = []
    for s in blocked[:limit]:
        raw = s.get("_raw") if isinstance(s, dict) else None
        shown = _masked(str(raw or (s.get("value") if isinstance(s, dict) else s) or ""))
        kind = str(s.get("type") or s.get("kind") or "?") if isinstance(s, dict) else "?"
        samples.append(f"{kind}:{shown}")
    more = f" 等 {len(blocked)} 条" if len(blocked) > limit else ""
    return f"值黑名单挡掉 {len(blocked)} 条（如 {'；'.join(samples)}{more}）—— 这些值已被判为误报，不再显示"


def add(value, kind="", note="", owner_id=0):
    """把一个值加进黑名单（同值重复加是 no-op，返回既有/新建条目的 id）。"""
    return db.insert_secret_blacklist(value=value, kind=kind, note=note, owner_id=owner_id)


def remove(entry_id, owner_id=None):
    """移除一条（按账号隔离：别人的条目删不动，返回受影响行数）。"""
    return db.delete_secret_blacklist(entry_id, owner_id=owner_id)
