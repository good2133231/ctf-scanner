"""nuclei 模板**暂存区**（T13，续387）—— 外部模板先过暂存、人工点了才进生产。

两条硬约束（主理人 2026-10-22 认下的 T13）：

  ① 落点必须在 `pocs.engine.POC_DIRS` **之外** —— 暂存区的模板永远不参与扫描：
     `sync_pocs` / `load_all_meta` / `load_enabled_pocs` 一个都看不见它们；
  ② 生效**只能由人显式调用** `promote()`：本模块不提供任何自动路径，导入流程只调
     `stage()`。`promote()` 的调用点只有 GUI 路由与 CLI 命令（人点的那两处）。

与 `pocmgr.EXP_DEST`（续207）的关系：那一路按**内容**分流（利用型 → 人点了才跑），
本模块按**来源**分流（外部新导入的模板 → 人点了才进生产）。两者落点不同、判据不同，
处置口径一致：**引擎发现不了 + 人点才动**。

为什么不用 `manifest.json` 那一套：暂存清单要额外记 `status`（pending）与来源、时间，
而生产 manifest 的语义是「已落盘的内容指纹」（用来做幂等）。混在一份里会让
「哪些还没确认」数不出来。
"""
import json
import time
from pathlib import Path

from . import pocmgr
from .config import resolve

# 暂存区（相对项目根）。**不在** `pocs.engine.POC_DIRS` 里 —— `[8cm]` 门禁钉着这一条。
STAGING = "config/poc-staging"
MANIFEST = "staging.json"

# 只收这两路；`exploit` 走 `pocmgr.EXP_DEST`（续207 已有自己的分流），不在这里重复。
KINDS = ("poc", "fingerprint")
_SUB = {"poc": "pocs", "fingerprint": "fingerprints"}
_PFX = {"poc": "http/", "fingerprint": "http/technologies/"}


def staging_dir():
    return Path(resolve(STAGING))


def _manifest_path():
    return staging_dir() / MANIFEST


def load():
    """读暂存清单；缺失/坏就当空清单（与 `pocmgr.load_manifest` 同口径）。"""
    try:
        data = json.loads(_manifest_path().read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:      # noqa: BLE001 - 清单缺失/坏就当空清单
        return {}


def _save(man):
    d = staging_dir()
    d.mkdir(parents=True, exist_ok=True)
    p = _manifest_path()
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(man, indent=1, sort_keys=True, ensure_ascii=False),
                   encoding="utf-8")
    tmp.replace(p)


def _name_of(rel, kind):
    """按这一路剥前缀（与 `apply_files` 同一套，剥错会写出 `pocs/pocs/…`）。"""
    n = pocmgr._safe_member(rel)
    pfx = _PFX[kind]
    return n[len(pfx):] if n.startswith(pfx) else ""


def stage(files, source="", logger=None):
    """把模板写进暂存区；**绝不**碰生产目录。`files` = `{相对路径: 文本}`。

    返回 `{"staged", "unchanged", "skipped"}`。重复导入同一份内容就是 no-op
    （清单里已有同 sha256 且文件在场）。
    """
    base = staging_dir()
    man = load()
    stats = {"staged": 0, "unchanged": 0, "skipped": 0}
    for rel, text in (files or {}).items():
        try:
            kind, _why = pocmgr.classify(rel)
        except ValueError:
            stats["skipped"] += 1
            continue
        if kind not in KINDS:
            stats["skipped"] += 1
            continue
        name = _name_of(rel, kind)
        if not name:
            stats["skipped"] += 1
            continue
        target = base / _SUB[kind] / name
        digest = pocmgr.sha256_text(text)
        key = target.relative_to(base).as_posix()
        if man.get(key, {}).get("sha256") == digest and target.exists():
            stats["unchanged"] += 1
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_suffix(target.suffix + ".tmp")
        tmp.write_text(text, encoding="utf-8")
        tmp.replace(target)
        man[key] = {"sha256": digest, "kind": kind, "source": str(source),
                    "at": time.strftime("%Y-%m-%d %H:%M:%S"), "status": "pending"}
        stats["staged"] += 1
    _save(man)
    if logger:
        logger.info(f"[poc-staging] 新增 {stats['staged']} 个待确认模板"
                    f"（无变化 {stats['unchanged']}；暂存区不在 POC_DIRS，一个都不会被扫描）")
    return stats


def _tags_of(key):
    """读暂存模板的 `info.tags`（**只读**，不执行、不加载进引擎）。"""
    try:
        import yaml
    except ImportError:
        return set()
    try:
        d = yaml.safe_load((staging_dir() / key).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError, TypeError, yaml.YAMLError):
        return set()
    info = (d or {}).get("info") or {}
    return {str(t).strip().lower() for t in (info.get("tags") or []) if str(t).strip()}


def tech_hits(techs):
    """暂存里 `info.tags` 命中给定组件集合的条目（`[{"key", "tags"}]`）。

    给 vulnscan 做「识别到组件 → 暂存区有相关模板」的提示用（主理人「结合指纹
    自动测试」要求，直接吃 P1-1 已经算出来的 `tech` 集合，不另建匹配）。
    **只提示、不生效**：T13 硬约束②，promote 只能人点（`[8cm]` 用 AST 钉着）。
    """
    want = {str(t).strip().lower() for t in (techs or ()) if str(t).strip()}
    if not want:
        return []
    out = []
    for row in list_staged():
        hit = sorted(_tags_of(row["key"]) & want)
        if hit:
            out.append({"key": row["key"], "tags": hit})
    return out


def list_staged():
    """待确认清单（按路径排序），每项带 `key` / `kind` / `sha256` / `source` / `at`。"""
    return [dict(key=k, **v) for k, v in sorted(load().items())]


def promote(names=None, dest=None, logger=None):
    """**人工**点头后把暂存的模板搬进生产目录（`names=None` = 全部）。

    这是唯一的「出暂存区」路径：本模块没有任何自动调用者，导入流程只调 `stage()`。
    返回 `{"promoted": 条数, "written": apply_files 的统计}`。
    """
    base = staging_dir()
    man = load()
    want = None if names is None else set(names)
    planned, picked = {}, []
    for key in sorted(man):
        if want is not None and key not in want:
            continue
        meta = man[key]
        kind = meta.get("kind")
        if kind not in KINDS:
            continue
        src = base / key
        if not src.exists():
            continue
        rel = _PFX[kind] + key[len(_SUB[kind]) + 1:]
        planned.setdefault(kind, {})[rel] = src.read_text(encoding="utf-8")
        picked.append(key)
    if not planned:
        return {"promoted": 0, "written": {}}
    dest = dest or resolve(pocmgr.POC_DEST)
    written = pocmgr.apply_files(dest, planned, logger=logger,
                                 exp_dest=str(pocmgr.exp_dir(dest)))
    for key in picked:
        src = base / key
        try:
            src.unlink()
        except OSError:      # noqa: BLE001 - 文件已不在就当已清理
            pass
        man.pop(key, None)
    _save(man)
    if logger:
        logger.info(f"[poc-staging] 人工确认 {len(picked)} 个模板进生产"
                    f"（落盘 {written.get('written', 0)}）")
    return {"promoted": len(picked), "written": written}


def drop(names=None):
    """丢弃暂存（`names=None` = 全部）。只删暂存区内的文件，不碰生产目录。"""
    base = staging_dir()
    man = load()
    want = None if names is None else set(names)
    n = 0
    for key in sorted(man):
        if want is not None and key not in want:
            continue
        src = base / key
        try:
            src.unlink()
        except OSError:      # noqa: BLE001 - 文件已不在就当已清理
            pass
        man.pop(key, None)
        n += 1
    _save(man)
    return {"dropped": n}


def _main(argv=None):
    """命令行入口：查看 / 确认 / 丢弃（T13「人点」的其中一处，另一处是 GUI）。"""
    import argparse
    import sys

    ap = argparse.ArgumentParser(description="nuclei 模板暂存区（T13）：确认后才进生产")
    ap.add_argument("--list", action="store_true", help="列出待确认的模板")
    ap.add_argument("--promote", nargs="*", metavar="KEY",
                    help="确认并搬进生产（给 key 就只搬这些，不给就是全部）")
    ap.add_argument("--drop", nargs="*", metavar="KEY",
                    help="丢弃暂存（同上）")
    a = ap.parse_args(argv)
    if a.list or (a.promote is None and a.drop is None):
        rows = list_staged()
        if not rows:
            print("[poc-staging] 暂存区为空")
            return 0
        for r in rows:
            print(f"  {r['key']}  ({r['kind']}, {r['at']}, {r['sha256'][:12]}…)")
        print(f"[poc-staging] 共 {len(rows)} 个待确认；扫描器看不到它们（不在 POC_DIRS）")
        return 0
    if a.promote is not None:
        rep = promote(a.promote or None)
        print(f"[poc-staging] 已确认 {rep['promoted']} 个进生产")
        return 0
    rep = drop(a.drop or None)
    print(f"[poc-staging] 已丢弃 {rep['dropped']} 个")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
