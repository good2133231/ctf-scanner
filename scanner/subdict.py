"""续344：动态子域名字典。

主理人点单：拓展域名收尾时，本任务归属域名的子域标签如果不在随包字典里，就追加到
`data/subdomains_dynamic.txt`，并在日志里报出来；以后子域名爆破自动带上这些词。
单独成模块是为了：

1. **只写归属域名**：调用方把 `promote_owned()` 认下来的域名传进来，这里不再猜归属；
2. **不重复/不写脏**：先读精简档与深档，已有的词不加；写文件用临时文件 + `os.replace`；
3. **可审计**：列表页直接读同一份文件，用户能看到“哪些是扫描中长出来的词”。

动态词只放**前缀标签**（`a.b.base` → `a.b`），不是完整域名；子域名阶段会把它们拼回
每个目标。这样同一批目标换 TLD 也能复用。
"""
from __future__ import annotations

import os
import re
import threading
from pathlib import Path

from . import targets
from .config import resolve

_LOCK = threading.RLock()
_DEFAULT = "data/subdomains_dynamic.txt"
_MAX_DEFAULT = 5000
_LABEL_RE = re.compile(r"^(?!-)[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$")


def path(settings=None):
    """动态字典的绝对路径；`dicts.subdomains_dynamic` 可改，默认 data/。"""
    raw = str(((settings or {}).get("dicts", {}) or {}).get("subdomains_dynamic", _DEFAULT) or _DEFAULT)
    return resolve(raw)


def load(settings=None, limit=None):
    """读动态词（去注释、去空行、小写、去重，保持追加顺序）。"""
    p = path(settings)
    if not p.is_file():
        return []
    cap = limit
    if cap is None:
        cap = int((((settings or {}).get("dicts", {}) or {}).get(
            "subdomains_dynamic_max", _MAX_DEFAULT)) or _MAX_DEFAULT)
    out, seen = [], set()
    try:
        with p.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                w = line.strip().lower()
                if not w or w.startswith("#") or w in seen:
                    continue
                seen.add(w)
                out.append(w)
                if cap and len(out) >= cap:
                    break
    except OSError:
        return []
    return out


def _static_words(settings):
    """随包精简档 + 深档（读不到就当空集，不阻断拓展阶段）。"""
    words = set()
    d = (settings or {}).get("dicts", {}) or {}
    for key in ("subdomains", "subdomains_deep"):
        raw = str(d.get(key, "") or "")
        if not raw:
            continue
        p = resolve(raw)
        if not p.is_file():
            continue
        try:
            with p.open("r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    w = line.strip().lower()
                    if w and not w.startswith("#"):
                        words.add(w)
        except OSError:
            continue
    return words


def label_from_domain(domain, base):
    """`a.b.base` → `a.b`；不是 `base` 的严格子域返回空串。"""
    d = str(domain or "").strip().lower().rstrip(".")
    b = str(base or "").strip().lower().rstrip(".")
    if not d or not b or d == b or not d.endswith("." + b):
        return ""
    label = d[: -(len(b) + 1)]
    if not label or "*" in label or len(label) > 253 or not _LABEL_RE.match(label):
        return ""
    # `a..b` / `.a` / `a.` 这类拼接垃圾不写进字典
    if any(not x for x in label.split(".")):
        return ""
    return label


def add_domains(domains, settings=None, logger=None, task_id=0, bases=None):
    """把归属域名的前缀标签追加到动态字典；返回 `{added, skipped, total, path}`。

    调用方只传**归属本项目**的域名（`promote_owned()` 的产出）；`bases` 给了就
    再拦一道：只收注册域落在这些已确认基域里的名字，防止调用方传宽了。
    本函数会跳过：已在随包字典里的词、已在动态表里的词、非严格子域、非法标签。
    """
    static = _static_words(settings)
    known = set(load(settings))
    allowed = {str(b).strip().lower().rstrip(".") for b in (bases or ()) if str(b).strip()}
    candidates = []
    for d in domains or ():
        b = targets.root_of(str(d or ""))
        if not b:
            continue
        b = b.lower().rstrip(".")
        if allowed and b not in allowed:
            continue
        lab = label_from_domain(d, b)
        if lab and lab not in static and lab not in known:
            candidates.append(lab)
    # 稳定去重，保留扫描发现顺序
    seen, add = set(), []
    for w in candidates:
        if w not in seen:
            seen.add(w)
            add.append(w)
    if not add:
        return {"added": [], "skipped": len(candidates), "total": len(known), "path": str(path(settings))}

    p = path(settings)
    p.parent.mkdir(parents=True, exist_ok=True)
    with _LOCK:
        existing = load(settings)
        have = set(existing)
        added = [w for w in add if w not in have]
        if not added:
            return {"added": [], "skipped": len(candidates), "total": len(have), "path": str(p)}
        cap = int((((settings or {}).get("dicts", {}) or {}).get(
            "subdomains_dynamic_max", _MAX_DEFAULT)) or _MAX_DEFAULT)
        room = max(0, cap - len(existing)) if cap else len(added)
        added = added[:room]
        if added:
            tmp = p.with_name(p.name + ".tmp")
            with tmp.open("w", encoding="utf-8", newline="\n") as f:
                if existing:
                    f.write("\n".join(existing) + "\n")
                f.write("\n".join(added) + "\n")
            os.replace(tmp, p)
    if logger:
        sample = "、".join(added[:12])
        extra = "…" if len(added) > 12 else ""
        logger.info(f"[subdomain] 动态字典新增 {len(added)} 条"
                    f"（任务 #{task_id or '-'}，累计 {len(existing) + len(added)}）：{sample}{extra}")
        if len(added) < len(add):
            logger.info(f"[subdomain] 动态字典已到上限 {cap} 条，剩余 {len(add) - len(added)} 条未写入"
                        "（调大 dicts.subdomains_dynamic_max 可放开）")
    return {"added": added, "skipped": len(candidates) - len(added),
            "total": len(existing) + len(added), "path": str(p)}
