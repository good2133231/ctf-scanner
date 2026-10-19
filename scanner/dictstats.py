#!/usr/bin/env python3
"""字典统计与**受限预览**（续223 —— 策略页「字典一览」+ 外部字典源编辑器用）。

为什么单独一个模块（§5.14 单产地）：策略页要回答"这份字典多大、里面长什么样"，
而字典文件可能很大（内置 `dirs_big` 1.2 万条、外部 dirsearch 单类上千条、公共词表
17.8 万条）。**绝不能把整份字典塞进 HTML** —— 那是几十 MB，浏览器会卡死，也把
"页面只读展示"变成了"另一次文件传输"。所以：

- `count_lines()`：分块数换行，只回**数字**（带 `(路径, mtime_ns, size)` 缓存；
  文件一改，键就变，不用手工失效）；
- `read_preview()`：最多读 64 KB / 200 行，只用于"点开看一眼"；
- `resolve_builtin()` / `resolve_external()`：**只接受配置里登记过的键**，
  不接受请求里的任意路径 —— 预览接口不许变成任意文件读取（`../` / 符号链接都挡）。

页面只渲染"名字 + 条数"，完整内容永远不随页面下发。
"""
import io
import os
import re
import threading
import time
import zipfile
from pathlib import Path

from .config import BASE_DIR, resolve

# 预览上限（页面侧还有一层 limit 夹取；这里是模块自己的硬上限）
PREVIEW_LINES = 200
PREVIEW_BYTES = 64 * 1024
COUNT_CAP = 200000                  # 超过这个数只显示 "200000+"

_cache = {}
_cache_lock = threading.Lock()
_CACHE_MAX = 256


def _cache_key(p):
    st = p.stat()
    return (str(p), int(st.st_mtime_ns), int(st.st_size))


def count_lines(path, cap=COUNT_CAP):
    """分块数行（不把整份字典读进内存），返回 `(行数, 是否被 cap 截断)`。

    计数口径与 `dirscan.read_lines()` 一致：**只数物理行**（注释/空行也算）——
    页面写"1.2 万条"是字典的规模，不是"有效路径数"；两者混在一起会让人以为
    字典缩水了（深层去重/注释是扫描期的事，不是文件本身）。
    """
    p = Path(path)
    try:
        key = _cache_key(p)
    except OSError:
        return 0, False
    with _cache_lock:
        hit = _cache.get(key)
    if hit is not None:
        return hit
    n, truncated, tail = 0, False, b""
    try:
        with open(p, "rb") as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                n += chunk.count(b"\n")
                tail = chunk[-1:]
                if n >= cap:
                    # 恰好 cap 行且已到 EOF ≠ 截断；多一个字节才算
                    truncated = bool(f.read(1)) or n > cap
                    break
        if not truncated and tail and tail != b"\n":
            n += 1                      # 最后一行没有换行也算一行
    except OSError:
        return 0, False
    if n > cap:
        n, truncated = cap, True
    val = (n, truncated)
    with _cache_lock:
        if len(_cache) > _CACHE_MAX:
            _cache.clear()              # 简单有界：字典目录不会同时有几百份在变
        _cache[key] = val
    return val


def read_preview(path, limit=PREVIEW_LINES, max_bytes=PREVIEW_BYTES):
    """读前 `limit` 行（最多 `max_bytes`），返回 `(lines, truncated)`。

    `truncated=True` 表示"后面还有"（可能是行数超限，也可能是字节超限）。
    只用于页面预览；调用方必须先把 path 过 `resolve_*`（这里不判来源）。
    """
    try:
        limit = max(1, min(int(limit), PREVIEW_LINES))
        max_bytes = max(1024, min(int(max_bytes), PREVIEW_BYTES))
    except (TypeError, ValueError):
        limit, max_bytes = PREVIEW_LINES, PREVIEW_BYTES
    p = Path(path)
    try:
        with open(p, "rb") as f:
            raw = f.read(max_bytes + 1)
    except OSError:
        return [], False
    more_bytes = len(raw) > max_bytes
    text = raw[:max_bytes].decode("utf-8", "replace")
    lines = text.splitlines()
    more_lines = len(lines) > limit
    if more_lines:
        lines = lines[:limit]
    return lines, (more_bytes or more_lines)


def _root_of(raw):
    """外部源的根目录：相对仓库根解释（与 `dirscan._external_layers()` 同口径）。"""
    d = Path(str(raw or ""))
    if not d.is_absolute():
        d = BASE_DIR / d
    try:
        return d.resolve()
    except OSError:
        return d


def external_categories(src):
    """一个外部源的分类列表（`[(cat, Path), ...]`，按名字排序；`picks` 过滤）。

    目录不存在 / 没匹配到 ⇒ 空列表（调用方负责说一句）。
    """
    root = _root_of((src or {}).get("path"))
    if not root.is_dir():
        return []
    picks = [str(x).strip() for x in ((src or {}).get("picks") or []) if str(x).strip()]
    out = []
    for f in sorted(root.glob("*.txt")):
        cat = f.stem
        if picks and cat not in picks:
            continue
        out.append((cat, f))
    return out


def resolve_builtin(settings, name):
    """按 `settings["dicts"]` 的键取内置字典；不认识/不存在 ⇒ None。"""
    dicts = (settings or {}).get("dicts") or {}
    if name not in dicts:
        return None
    p = resolve(str(dicts.get(name) or ""))
    return p if p.is_file() else None


def resolve_external(settings, idx, cat):
    """按 `dirscan.dict_sources` 的**下标 + 分类名**取外部字典；非法 ⇒ None。

    安全边界（预览接口的唯一入口）：
    - `idx` 必须是已配置的下标；`cat` 必须是该源根目录下的 `*.txt` 文件名（去后缀）；
    - `cat` 不许含路径分隔符 / `..`；最终路径 `resolve()` 后父目录必须仍是配置的根
      （挡符号链接逃逸）；
    - `picks` 非空时只认列出的分类（与扫描期一致）。
    """
    srcs = ((settings or {}).get("dirscan") or {}).get("dict_sources") or []
    try:
        idx = int(idx)
    except (TypeError, ValueError):
        return None
    if idx < 0 or idx >= len(srcs) or not isinstance(srcs[idx], dict):
        return None
    cat = str(cat or "").strip()
    if not cat or cat != Path(cat).name or "/" in cat or "\\" in cat or cat in (".", ".."):
        return None
    src = srcs[idx]
    root = _root_of(src.get("path"))
    p = (root / f"{cat}.txt").resolve()
    if p.parent != root or p.suffix.lower() != ".txt" or not p.is_file():
        return None
    picks = [str(x).strip() for x in (src.get("picks") or []) if str(x).strip()]
    if picks and cat not in picks:
        return None
    return p


EXPORT_MAX_FILES = 64
EXPORT_MAX_BYTES = 32 * 1024 * 1024


def export_zip(settings, idx):
    """把一个外部源的**全部分类**打成 zip（续224；内存内，受文件数与总大小上限保护）。

    返回 `(zip_bytes, filename)`；源不存在 / 没有分类 / 超限 ⇒ `(None, 原因)`。
    只打包 `external_categories()` 给出的文件（已过 `picks` 与根目录约束）——
    与预览同一套边界，请求参数不能指定任意路径。
    """
    srcs = ((settings or {}).get("dirscan") or {}).get("dict_sources") or []
    try:
        idx = int(idx)
    except (TypeError, ValueError):
        return None, "来源下标非法"
    if idx < 0 or idx >= len(srcs) or not isinstance(srcs[idx], dict):
        return None, "来源不存在"
    src = srcs[idx]
    name = str(src.get("name") or "").strip() or f"src{idx + 1}"
    cats = external_categories(src)
    if not cats:
        return None, "该来源没有可导出的分类"
    if len(cats) > EXPORT_MAX_FILES:
        return None, f"分类过多（{len(cats)} > {EXPORT_MAX_FILES}），请改用单份导出"
    total = 0
    for _cat, p in cats:
        try:
            total += p.stat().st_size
        except OSError:
            continue
        if total > EXPORT_MAX_BYTES:
            return None, f"总大小超过上限（{EXPORT_MAX_BYTES // (1024 * 1024)} MB）"
    buf = io.BytesIO()
    safe = re.sub(r"[^0-9A-Za-z._-]+", "_", name) or f"src{idx + 1}"
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for cat, p in cats:
            try:
                z.write(str(p), arcname=f"{cat}.txt")
            except OSError:
                continue
    return buf.getvalue(), f"dicts-{safe}.zip"


def dict_index(settings, external_limit=200):
    """策略页「字典一览」的数据：内置 + 外部，每项 `{key,name,count,truncated}`。

    **只回计数**，不回内容；外部源最多列 `external_limit` 个分类（防止有人把
    一个十万文件的目录接进来把页面撑爆）。
    """
    out = []
    dicts = (settings or {}).get("dicts") or {}
    for name in sorted(dicts):
        p = resolve_builtin(settings, name)
        if not p:
            continue
        n, trunc = count_lines(p)
        out.append({"key": f"b:{name}", "name": str(name), "count": n,
                    "truncated": trunc, "kind": "builtin"})
    srcs = ((settings or {}).get("dirscan") or {}).get("dict_sources") or []
    for i, src in enumerate(srcs):
        if not isinstance(src, dict):
            continue
        sname = str(src.get("name") or "").strip() or f"源{i + 1}"
        for cat, p in external_categories(src)[:external_limit]:
            n, trunc = count_lines(p)
            out.append({"key": f"e:{i}:{cat}", "name": f"{sname}/{cat}", "count": n,
                        "truncated": trunc, "kind": "external",
                        "src_idx": i, "src_name": sname})
    return out


def edit_rows(settings, blank=2):
    """外部字典源的**可编辑行**（策略页表单用）。

    路径规则（§0.3：页面不回显项目外绝对路径）：
    - 项目内路径 → 渲染成相对仓库根（可直接编辑）；
    - 项目外绝对路径 → **value 留空**，只给一个脱敏 placeholder（`…/父/名`）；
      提交时该行留空 = 沿用原值（想改就整条重填）。
    """
    from .utils import rel_display
    srcs = ((settings or {}).get("dirscan") or {}).get("dict_sources") or []
    rows = []
    for i, src in enumerate(srcs):
        if not isinstance(src, dict):
            continue
        raw = str(src.get("path") or "")
        value, hint = raw, ""
        disp = rel_display(raw) if raw else ""
        if raw and os.path.isabs(raw):
            if disp == raw:                 # 项目外：不回显，留空 = 沿用原值
                value, hint = "", rel_display(raw, mask_outside=True)
            else:                           # 项目内：渲染成相对仓库根
                value = disp
        rows.append({"idx": i, "name": str(src.get("name") or ""),
                     "path_value": value, "path_hint": hint,
                     "picks": ",".join(str(x) for x in (src.get("picks") or [])),
                     "after": str(src.get("after") or "common")})
    for k in range(max(0, int(blank))):
        rows.append({"idx": len(srcs) + k, "name": "", "path_value": "",
                     "path_hint": "", "picks": "", "after": "common"})
    return rows
