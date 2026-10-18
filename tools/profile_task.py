#!/usr/bin/env python3
"""单任务资源画像实测（续215-P2-12）。

**为什么需要它**：续179 的并发基准是"合成回环 HTTP"（threadpool 打 20ms 的空请求），
只能说明线程池本身的成本；这个脚本跑的是**真 `runner.run_task`**（DNS/HTTP/解析/写库
全走一遍），产出的 CPU 秒数、峰值内存与"建议并发"才是 `workers_profile` 的依据。

默认目标用 `scanner/devfixture.py` 起一个只绑 `127.0.0.1` 的临时站（不碰外网、不用真实目标），
沙箱库放在 `logs/profile-<时间>-<pid>/profile.db`（`CTFSCANNER_DB` 重定向），跑完即删；
`--keep` 保留现场。`--target` 可指向**你已获授权**的地址（脚本不会替你确认授权）。

用法：
    python tools/profile_task.py                     # 夹具 + probe,jsmine，跑 1 轮
    python tools/profile_task.py --runs 3            # 跑 3 轮看波动
    python tools/profile_task.py --stages probe,dirscan --workers 8
    python tools/profile_task.py --target http://127.0.0.1:8080/ --runs 1
"""
import argparse
import json
import os
import shutil
import sys
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))


def _sandbox():
    """建一个**本次运行专属**的库与日志目录，返回根目录（相对项目根打印时用）。"""
    root = BASE_DIR / "logs" / f"profile-{time.strftime('%Y%m%d_%H%M%S')}-{os.getpid()}"
    (root / "logs").mkdir(parents=True, exist_ok=True)
    # 必须在 import scanner.db **之前**设置：DB_PATH 是模块级常量
    os.environ["CTFSCANNER_DB"] = str(root / "profile.db")
    os.environ["CTFSCANNER_LOGS"] = str(root / "logs")
    return root


def main(argv=None):
    ap = argparse.ArgumentParser(description="CTFScanner 单任务资源画像实测")
    ap.add_argument("--target", default="", help="目标（留空 = 内置 devfixture）")
    ap.add_argument("--stages", default="probe,jsmine", help="逗号分隔的阶段（默认 probe,jsmine）")
    ap.add_argument("--runs", type=int, default=1, help="重复几轮（默认 1）")
    ap.add_argument("--workers", type=int, default=0,
                    help="覆盖 limits.max_workers（0 = 用配置值）")
    ap.add_argument("--keep", action="store_true", help="保留沙箱库与任务日志")
    args = ap.parse_args(argv)

    stages = [s.strip() for s in str(args.stages or "").split(",") if s.strip()]
    if not stages:
        print("[X] --stages 为空：至少给一个阶段（如 probe）")
        return 2

    root = _sandbox()
    from scanner import db, devfixture, profiling, runner
    from scanner.config import load_settings
    from scanner.utils import rel_display

    db.init_db()          # 沙箱库是空的：建表 + 补列（与 CLI 入口同一个动作）
    fixture = None
    target = args.target.strip()
    try:
        if not target:
            fixture, target = devfixture.start()
            print(f"[*] 夹具站：{target}（只绑 127.0.0.1，跑完即停）")
        else:
            print(f"[*] 目标：{target}（请确认已获授权）")

        settings = load_settings()
        limits = settings.setdefault("limits", {})
        configured = int(args.workers or limits.get("max_workers", 20) or 20)
        limits["max_workers"] = configured
        # 测的是**配置下的原始并发**：不要让上一轮画像把这一轮降档（否则第二轮的读数
        # 会越跑越小，量到的就不是"一条任务要多少资源"而是"降档后要多少"）。
        limits["workers_auto"] = False
        limits["workers_profile"] = False
        print(f"[*] 阶段：{','.join(stages)}｜workers={configured}｜轮数={max(1, int(args.runs))}")

        rows = []
        for i in range(max(1, int(args.runs))):
            name = f"profile-{time.strftime('%H%M%S')}-{i + 1}"
            tid = db.create_task(name, target, stages)
            t0 = time.perf_counter()
            try:
                runner.run_task(tid, name, target, stages, {"offline": True}, settings)
            except Exception as e:                     # noqa: BLE001 - 单轮失败也要如实报
                print(f"[!] 第 {i + 1} 轮 run_task 抛异常：{type(e).__name__}: {e}")
            wall = round(time.perf_counter() - t0, 2)
            task = db.get_task(tid)
            raw = db.task_profile(tid) or {}
            prof = profiling.from_row(raw)
            sug = profiling.suggest_workers(prof or {}, configured=configured) if prof else {}
            item = {
                "run": i + 1,
                "task_id": tid,
                "status": str(task["status"] if task else "?"),
                "wall_s": prof.get("wall_s") if prof else wall,
                "cpu_s": round(float(raw.get("cpu_seconds") or 0), 2),
                "cpu_ratio": round(float(raw.get("cpu_ratio") or 0), 3),
                "peak_rss_mb": round(float(raw.get("peak_rss_mb") or 0), 1),
                "suggested": sug.get("cap"),
                "bound": sug.get("bound"),
                "error": str(task["error"] or "")[:200] if task else "",
            }
            rows.append(item)
            print("[profile] " + json.dumps(item, ensure_ascii=False))

        if rows:
            import statistics
            med = statistics.median([r["cpu_ratio"] for r in rows])
            peak = max(r["peak_rss_mb"] for r in rows)
            last = rows[-1]
            print(f"\n[=] {len(rows)} 轮：CPU 占比中位数 {med:.3f} 核，峰值内存 {peak:.1f} MB；"
                  f"按最后一轮建议并发 {last['suggested']}（配置 {configured}，"
                  f"{last['bound']} 先到顶）")
        if args.keep:
            print(f"[i] 沙箱保留：{rel_display(root)}（库 + 任务日志）")
        return 0
    finally:
        if fixture is not None:
            devfixture.stop(fixture)
        if not args.keep:
            shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
