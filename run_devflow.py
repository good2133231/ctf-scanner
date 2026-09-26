"""全流程自检入口（续50）：起内置靶场 → 压量到最小 → 真跑全 13 阶段 → 逐阶段 OK/SKIP/FAIL。

用法：``py -3 run_devflow.py``
退出码：全部阶段非 FAIL → 0；任一 FAIL → 1（便于自动化判定）。

与 ``run_gui.py`` 对称。CLI **不需要队列**（队列是控制台的事，见 ``scanner/queue.py``），
直接前台 ``runner.run_task``。

流程：夹具（``scanner/devfixture.py``，127.0.0.1 本地静态站、零外网）→
``devmode.apply()`` 把并发 / 在飞 / 速率 / 每阶段配额统统压到 1 → 13 个阶段的策略开关全打开
（有 key 的第三方阶段**真跑**，没 key 的模块自身零请求、在报告里记为「跳过」）→ 逐阶段打印结论。

判据说明（**为什么 OK/SKIP 要分开**）：
- ``FAIL``：该阶段**抛了异常**（由阶段代理记录后原样抛出，交给 runner 的阶段级容错）；
- ``SKIP``：该阶段本次**零网络活动**（目标不匹配 / 未配 key / 无对应资产）—— 不是报错；
- ``OK``：该阶段本次有网络活动（``portscan`` / ``heuristic`` 走裸 socket / 纯本地计算，
  天然不产生 ``http_request``/``run_cmd`` 计数，故固定按 OK 处理，见 ``_NON_NET_STAGES``）。
"""
import os
import pathlib
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

# ⚠️ **必须在 `import scanner.*` 之前**把库与任务工作目录指到 logs/ 下的隔离位置 ——
# `scanner/db.py` 是**模块级**读 `CTFSCANNER_DB`，import 之后再设就晚了（会写进真实库）。
_STAMP = time.strftime("%Y%m%d_%H%M%S")
_LOGS = ROOT / "logs"
_LOGS.mkdir(exist_ok=True)
os.environ["CTFSCANNER_DB"] = str(_LOGS / f"devflow_{_STAMP}.db")
os.environ["CTFSCANNER_LOGS"] = str(_LOGS / f"devflow_{_STAMP}")

from scanner import db, devfixture, devmode, runner, utils          # noqa: E402
from scanner.config import load_settings                            # noqa: E402

# 本就不走 http_request / run_cmd 的阶段：它们**天然 0 计数**，不能据此判「跳过」。
# - portscan：走**裸 socket**（`throttle.slot("socket")` + `_probe_port`），不经 HTTP/子进程；
# - heuristic：**零请求**设计（只对已收集数据做本地聚合）。
_NON_NET_STAGES = ("portscan", "heuristic")


class _RecStage:
    """阶段代理：记录本阶段 OK/FAIL（异常仍**原样抛出**，与 runner 的容错语义一致）。

    同时把"当前阶段"写进**模块级** `_CURRENT`（不是 `threading.local()`）—— 阶段内绝大多数
    请求发生在 `pool_run` 的**工作线程**里，thread-local 在那些线程里是空的，会导致请求
    全部归不到阶段上（实测过：dirscan/vulnscan 明明发了请求却被误判成「跳过」）。
    自检是**单任务前台串行**跑，阶段之间不会重叠，故用全局标记是安全的。
    """

    def __init__(self, ctx, name, cls, results):
        self._inner = cls(ctx)
        self._name = name
        self._results = results

    def run(self):
        _CURRENT["stage"] = self._name
        try:
            self._inner.run()
            self._results[self._name] = "OK"
        except Exception as exc:      # noqa: BLE001 - 记下来后原样抛
            self._results[self._name] = f"FAIL:{type(exc).__name__}: {exc}"
            raise
        finally:
            _CURRENT["stage"] = None


# "当前正在执行的阶段"（见 `_RecStage` 的说明：用全局而非 thread-local）。
_CURRENT = {"stage": None}


def _instrument(results, net_by_stage):
    """挂"按阶段计数"：包 `http_request` / `run_cmd`，并把 `STAGE_REGISTRY` 换成代理。

    返回 `restore()`（务必在 finally 里调，恢复被替换的函数与注册表）。
    手法与 tests/smoke.py [6u] 一致：各模块是 `from ..utils import http_request`
    （把函数对象绑进自己的命名空间），只改 `utils` 对它们无效，必须逐模块替换。
    """
    orig_http, orig_cmd = utils.http_request, utils.run_cmd
    http_mods = [m for m in list(sys.modules.values())
                 if str(getattr(m, "__name__", "") or "").startswith("scanner")
                 and getattr(m, "http_request", None) is orig_http]
    cmd_mods = [m for m in list(sys.modules.values())
                if str(getattr(m, "__name__", "") or "").startswith("scanner")
                and getattr(m, "run_cmd", None) is orig_cmd]

    def _bump():
        name = _CURRENT["stage"]
        if name:
            net_by_stage[name] = net_by_stage.get(name, 0) + 1

    def counting_http(url, *a, **k):
        _bump()
        return orig_http(url, *a, **k)

    def counting_cmd(argv, *a, **k):
        _bump()
        return orig_cmd(argv, *a, **k)

    for m in http_mods:
        m.http_request = counting_http
    for m in cmd_mods:
        m.run_cmd = counting_cmd

    orig_registry = dict(runner.STAGE_REGISTRY)
    runner.STAGE_REGISTRY = {
        n: (lambda ctx, _n=n, _c=c: _RecStage(ctx, _n, _c, results))
        for n, c in orig_registry.items()}

    def restore():
        for m in http_mods:
            m.http_request = orig_http
        for m in cmd_mods:
            m.run_cmd = orig_cmd
        runner.STAGE_REGISTRY = orig_registry

    return restore


def _classify(results, net_by_stage):
    """逐阶段定级：FAIL（抛异常）/ SKIP（本次零网络活动）/ OK。"""
    rows = []
    for name in runner.STAGE_ORDER:
        raw = results.get(name)
        if raw is None:
            rows.append((name, "SKIP", "未执行（流水线提前结束？）"))
        elif str(raw).startswith("FAIL:"):
            rows.append((name, "FAIL", str(raw)[len("FAIL:"):]))
        elif net_by_stage.get(name, 0) == 0 and name not in _NON_NET_STAGES:
            rows.append((name, "SKIP", "本次零网络活动（目标不匹配 / 未配 key / 无对应资产 / 命中缓存）"))
        else:
            rows.append((name, "OK", f"{net_by_stage.get(name, 0)} 次网络活动"))
    return rows


def main():
    httpd, base = devfixture.start()
    print(f"[*] 内置靶场已启动：{base}（仅 127.0.0.1，零外网）")
    exit_code = 0
    try:
        raw = load_settings()
        settings = devmode.enable_all_stages(devmode.apply(raw))
        compressed = devmode.report(raw)
        print(f"[*] 开发模式：{len(compressed)} 项压到最小")
        for line in compressed:
            print(f"      {line}")
        print(f"[*] 预算不压（刻意）：{', '.join(devmode.DEV_KEEP)} 保持不设 —— "
              "budget_total=1 会让第 2 个请求即被拒、全流程跑不完")

        targets = base + "/"
        stages = list(runner.STAGE_ORDER)
        results, net_by_stage = {}, {}
        db.init_db()
        runner.sync_pocs(settings)
        name = "devflow-all13"
        tid = db.create_task(name, targets, stages, {})
        restore = _instrument(results, net_by_stage)
        t0 = time.time()
        try:
            runner.run_task(tid, name, targets, stages, {}, settings)
        finally:
            restore()
        elapsed = time.time() - t0

        rows = _classify(results, net_by_stage)
        total_net = sum(net_by_stage.values())
        print("\n[*] 全流程自检结果（13 个阶段）：")
        for sname, status, detail in rows:
            print(f"    {status:<4} {sname:<11} {detail}")
        task = db.get_task(tid)
        print(f"\n[*] 网络活动总数：{total_net}    总耗时：{elapsed:.1f}s    "
              f"任务终态：{task['status']}")
        print(f"[*] 任务日志：{utils.rel_display(task['log_file'])}")
        err = str(task["error"] or "").strip()
        if err:
            print(f"[*] 任务 error（非空说明有阶段抛了异常）：\n    {err}")
        fails = [n for n, s, _ in rows if s == "FAIL"]
        if fails:
            exit_code = 1
            print(f"\n[!] 自检未通过：{len(fails)} 个阶段 FAIL —— {', '.join(fails)}")
        else:
            print("\n[*] 自检通过：13 个阶段均无异常（SKIP 表示本次无对应活动，不是报错）")
    finally:
        devfixture.stop(httpd)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
