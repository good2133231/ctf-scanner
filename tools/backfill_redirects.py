#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""续274：给老任务的 3xx 站点补跳转信息（让续266 的显示折叠对老数据也生效）。

背景：续266 的「跳转前后同一个域名 ⇒ 折成同一个站点」是**显示时**算的，但依赖库里那行 http
站点**扫描时**存下的 `redirect_url` / `redirect_status`（续112-B 探活时补）。早于续112-B 扫的老
任务没有这些字段 ⇒ 折叠配对不上 ⇒ 显示成两行。本工具只对「还是 3xx、且还没有跳转结论」的行补发
一次跳转取证（复用 `probe.attach_redirect_info` 与扫描期同一份口径），**不整站重扫**。

用法：
    python tools/backfill_redirects.py <task_id>     补一个任务
    python tools/backfill_redirects.py --all         补所有任务
只对缺结论的 3xx 行发请求；已有结论的不重复打、不覆盖（幂等）。走网络（只读 GET 跟随跳转）。
GUI 侧同口径：任务详情 → 站点页签可见折叠（续266）；本工具是给老数据补因的命令行入口。
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scanner import db                      # noqa: E402
from scanner.config import load_settings    # noqa: E402
from scanner.stages import probe            # noqa: E402


def main(argv):
    all_mode = "--all" in argv
    ids = [a for a in argv[1:] if not a.startswith("-")]
    if not all_mode and not ids:
        print(__doc__)
        return 2
    settings = load_settings()
    if all_mode:
        _tasks = db.list_tasks()
        tids = [int(t["id"]) if not isinstance(t, (tuple, list)) else int(t[0]) for t in _tasks]
    else:
        tids = [int(ids[0])]
    total = 0
    for tid in tids:
        n = probe.backfill_site_redirects(tid, db, settings)
        if n:
            print(f"[+] 任务 #{tid}：补齐 {n} 条 3xx 站点跳转信息")
        total += n
    print(f"[=] 合计补齐 {total} 条（只对缺结论的 3xx 行发请求；已有结论的不重复打、不覆盖）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
