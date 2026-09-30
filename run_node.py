#!/usr/bin/env python3
"""CTFScanner **分布式执行节点**（续80）—— 与 `run_gui.py` / `run_devflow.py` 对称的独立入口。

用法（在**节点机器**上跑，不是控制端）：

    py -3 run_node.py --controller http://10.0.0.5:5000 --token ctfsn_xxx --name node-1

它会：
  ① 把**本机的** DB / 日志指到节点自己的工作目录（默认 `logs/node-<名>/`）——
     **绝不碰控制端的库**（节点是"无状态执行器"，结果靠 HTTP 回传）；
  ② 循环：领任务 → 本地跑 `runner.run_task` → 回传**资产快照 + 状态**；
  ③ 空闲按 `--idle` 轮询；Ctrl-C 退出。

为什么必须单独一个入口（不能塞进 `cli/client.py`）：`scanner.db` 在 **import 期**就读
`CTFSCANNER_DB` 定死库路径，而 `cli/client.py` 一开头就 import 了 db —— 在 `main()` 里再设
环境变量已经太晚。本文件**先设环境变量、再 import**，与 `tests/smoke.py` / `run_devflow.py`
同一个套路。

安全边界：节点拿到的只有**任务入参**（目标/阶段/选项），拿不到控制端的库、也拿不到别的任务；
回传的资产快照由控制端按**列名**合并（见 `db.import_task_assets`）。
"""
import argparse
import os
import re
import socket
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))


def _safe(name):
    """把节点名压成安全的目录名（只留字母数字与 `-_.`）。"""
    s = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(name or "")).strip("-.")
    return s or "node"


def _run_one(client, task, settings, hb_interval=20.0):
    """跑一个领到的任务并回传（异常一律收成 failed 回传，不让节点挂掉）。

    跑之前起一个**运行期心跳**线程（续81）：节点跑任务时不走空闲循环、不发心跳，控制端会按
    `nodes.ONLINE_WINDOW` 把它当掉线并**误回收**这条任务（见 `nodes.reclaim_stale`）。
    """
    from scanner import db, runner
    tid = int(task["task_id"])
    name, targets = task["name"], task["targets"]
    stages, options = task["stages"], task["options"]
    mode = str(task.get("mode") or "fresh")
    print(f"[*] 领到任务 #{tid}：{name}（阶段 {','.join(stages)}，模式 {mode}）", flush=True)
    # 在**本机库**里建一条同名任务：本地 id 无所谓，回传时按控制端的 task_id 合并
    local_tid = db.create_task(name, targets, stages, options)
    status, note, counts, assets = "done", "", {}, {}
    stop_hb = threading.Event()

    def _beat():
        while not stop_hb.wait(hb_interval):
            try:
                client.heartbeat(tid, "busy")
            except Exception:                     # noqa: BLE001 - 心跳失败不致命
                pass

    threading.Thread(target=_beat, daemon=True).start()
    try:
        ctx = runner.run_task(local_tid, name, targets, stages, options, settings,
                              append=(mode == "append"), resume=(mode == "resume"))
        results = getattr(ctx, "results", None) or {}
        counts = {k: len(v) for k, v in results.items() if isinstance(v, list)}
        assets = db.dump_task_assets(local_tid)
    except Exception as exc:                      # noqa: BLE001 - 节点绝不能被单个任务拖死
        status, note = "failed", str(exc)[:200]
        print(f"[!] 任务 #{tid} 执行异常：{exc}", flush=True)
    finally:
        stop_hb.set()
    try:
        res = client.result(tid, status, note=note, counts=counts, assets=assets)
        n = sum((res.get("imported") or {}).values()) if isinstance(res, dict) else 0
        print(f"[*] 任务 #{tid} 回传完成：{status}（资产 {n} 行）", flush=True)
    except Exception as exc:                      # noqa: BLE001
        print(f"[!] 任务 #{tid} 回传失败：{exc}", flush=True)


def main():
    ap = argparse.ArgumentParser(
        description="CTFScanner 分布式执行节点 —— 仅用于授权测试与 CTF 场景")
    ap.add_argument("--controller", required=True, help="控制端地址，如 http://10.0.0.5:5000")
    ap.add_argument("--token", required=True, help="节点令牌（控制端 `cli/client.py --node-add` 生成）")
    ap.add_argument("--name", default="", help="节点名（默认取主机名）")
    ap.add_argument("--workdir", default="", help="节点本地工作目录（默认 logs/node-<名>）")
    ap.add_argument("--insecure", action="store_true",
                    help="跳过 TLS 校验（控制端用自签证书时；默认**校验**）")
    ap.add_argument("--idle", type=float, default=3.0, help="空闲轮询间隔（秒，默认 3）")
    ap.add_argument("--once", action="store_true", help="只领一次任务就退出（调试 / 脚本化）")
    args = ap.parse_args()

    name = args.name or socket.gethostname()
    workdir = Path(args.workdir) if args.workdir else (ROOT / "logs" / f"node-{_safe(name)}")
    workdir.mkdir(parents=True, exist_ok=True)
    # **先设环境变量、再 import**（见文件头）
    os.environ["CTFSCANNER_DB"] = str(workdir / "scanner.db")
    os.environ["CTFSCANNER_LOGS"] = str(workdir)

    from scanner import db, nodes
    from scanner.config import load_settings

    db.init_db()
    settings = load_settings()
    client = nodes.NodeClient(args.controller, args.token, name=name, insecure=args.insecure)
    print(f"[*] 节点 {name} 启动：控制端 {args.controller}；本地库 {workdir}", flush=True)
    print("    Ctrl-C 退出。", flush=True)

    while True:
        try:
            task = client.claim()
        except KeyboardInterrupt:
            print("\n[*] 已退出。", flush=True)
            return
        except Exception as exc:                  # noqa: BLE001 - 控制端暂时不可达就退避重试
            print(f"[!] 领任务失败：{exc}；{args.idle}s 后重试", flush=True)
            time.sleep(args.idle)
            continue
        if not task:
            try:
                client.heartbeat(0, "idle")
            except Exception:                     # noqa: BLE001 - 心跳失败不致命
                pass
            if args.once:
                print("[*] 当前没有排队任务（--once 退出）。", flush=True)
                return
            time.sleep(args.idle)
            continue
        _run_one(client, task, settings)
        if args.once:
            return


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[*] 已退出。", flush=True)
