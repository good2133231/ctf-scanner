"""全流程自检入口（续50 起、续52 起复用 `scanner/devflow.py` 的核心）：
起内置靶场 → 压量到最小 → 真跑全 13 阶段 → 逐阶段 真跑 / 跳过（带原因）/ FAIL。

用法：``py -3 cli/run_devflow.py``
退出码：全部阶段非 FAIL → 0；任一 FAIL → 1（便于自动化判定）。

`cli/` 下的独立入口（续146 起仓库根只留 `run_gui.py` 与 `run_bootstrap.py`）。CLI **不需要队列**（队列是控制台的事，见 ``scanner/queue.py``），
直接前台 ``runner.run_task``。

流程与判定细节见 ``scanner/devflow.py`` 文件头。本脚本只负责：① 在 `import scanner.*` **之前**
把库与任务工作目录指到 `logs/` 下的隔离位置；② 打印报告；③ 定退出码。

⚠️ **控制台「开发模式」页的自检是 `subprocess` 调本脚本**（不把 DNS 覆盖装进长驻 web 进程）——
见 ``gui/app.py::api_devmode_selfcheck``。
"""
import os
import pathlib
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# ⚠️ **必须在 `import scanner.*` 之前**把库与任务工作目录指到 logs/ 下的隔离位置 ——
# `scanner/db.py` 是**模块级**读 `CTFSCANNER_DB`，import 之后再设就晚了（会写进真实库）。
# 库**放在本轮专属目录里**（而不是 logs/devflow_<stamp>.db）：`intel` 的情报缓存目录
# 是 `Path(db.DB_PATH).parent / "intel"`（见 scanner/intel.py），把库放进专属目录能让缓存
# 也一起被隔离 —— 否则自检会读到/覆盖真实工作区的 `logs/intel/kev.json`。
_STAMP = time.strftime("%Y%m%d_%H%M%S")
_LOGS = ROOT / "logs"
_RUN_DIR = _LOGS / f"devflow_{_STAMP}"
_RUN_DIR.mkdir(parents=True, exist_ok=True)
os.environ["CTFSCANNER_DB"] = str(_RUN_DIR / "scanner.db")
os.environ["CTFSCANNER_LOGS"] = str(_RUN_DIR)

from scanner import devmode, devflow                       # noqa: E402
from scanner.config import load_settings                   # noqa: E402


def main():
    raw = load_settings()
    print("[*] 开发模式：逐项压量到最小 + 打开全部阶段开关（只作用于本次内存副本，"
          "绝不写回 config/settings.yaml）")
    print("[*] 自检夹具：devfixture.test / www.devfixture.test（RFC 2606 保留 TLD）"
          "→ DNS 覆盖到 127.0.0.1；夹具只绑 127.0.0.1、临时端口")
    print("[*] 零外网：第三方能力（FOFA / Shodan / Quake / crt.sh）在自检副本里关掉；"
          "intel 改指本地夹具源；github 无 token 时零请求")
    # 必须说出来（不然读者会以为自检跑的就是开发模式的真实节奏）：
    # 只放宽**限速节奏**，其余压量一项不动；理由见 scanner/devflow.SELFCHECK_PACING 的注释。
    print("[*] 限速节奏为自检放宽到 %s（**只这一项**；其余并发/在飞/配额仍压到 1，"
          "开发模式对真实目标仍是 1 请求/秒）" % (
              ", ".join(f"{k}={v}" for k, v in sorted(devflow.SELFCHECK_PACING.items())),))

    res = devflow.run_selfcheck(raw)
    if res["compressed"]:
        print(f"\n[*] 本次会被压量的项（{len(res['compressed'])} 项）：")
        for line in res["compressed"]:
            print(f"      {line}")
    print(f"[*] 预算不压（刻意）：{', '.join(devmode.DEV_KEEP)} 保持不设 —— "
          "budget_total=1 会让第 2 个请求即被拒、全流程跑不完")

    print("\n[*] 全流程自检结果（13 个阶段）：")
    for sname, status, detail, category in res["rows"]:
        tag = f"{status}({category})" if category else status
        print(f"    {tag:<12} {sname:<11} {detail}")

    # 续88：阶段级耗时 + 与**基线**的对比 —— 总耗时涨了也能一眼看出"是哪一步变慢"。
    # 基线是本机产物（落在 logs/ 下、不进仓库）；不同机器 / 装没装外部工具，耗时本来就不可比。
    _ss = res.get("stage_seconds") or {}
    if _ss:
        _base = devflow.load_baseline()
        _bmap = (_base.get("stage_seconds") or {}) if _base else {}
        # 本轮的真实节奏（从**生效配置**里取，不是抄常量：常量改了这里也得跟着对）
        _eff_pace = {"limits.rate_per_sec": (res["settings"].get("limits") or {}).get("rate_per_sec"),
                     "limits.rate_burst": (res["settings"].get("limits") or {}).get("rate_burst")}
        print("\n[*] 阶段级耗时（秒，降序）：")
        for _n, _v in sorted(_ss.items(), key=lambda kv: -kv[1]):
            _b = _bmap.get(_n)
            _tag = f"基线 {float(_b):.2f}s" if isinstance(_b, (int, float)) else "无基线"
            print(f"    {_n:<11} {float(_v):>7.2f}s   （{_tag}）")
        if _base:
            _cmp_ok, _cmp_why = devflow.pacing_comparable(_base, _eff_pace)
            if not _cmp_ok:
                # 口径不同就不给结论 —— 一句"没有阶段明显变慢"如果是拿不可比的两次数拼出来的，
                # 那就是假绿；明说"本轮不对比"比给一个好看的结论有用。
                print(f"[*] 本轮不与基线对比：{_cmp_why}")
            else:
                _slower = devflow.compare_baseline(_base, _ss)
                if _slower:
                    _txt = "、".join(
                        f"{d['stage']} {d['now']:.1f}s（基线 {d['base']:.1f}s，{d['x']}x）"
                        for d in _slower)
                    print("[!] 明显变慢（超过基线 %.1f 倍）：%s" % (devflow.BASELINE_RATIO, _txt))
                else:
                    print("[*] 与基线相比，没有阶段明显变慢")
        _saved = devflow.save_baseline(_ss, elapsed=res["elapsed"], pacing=_eff_pace)
        if _saved:
            print(f"[*] 本次耗时已存为基线：{_saved}（下次自检逐阶段对比）")

    print(f"\n[*] 网络活动总数：{res['total_net']}    总耗时：{res['elapsed']:.1f}s    "
          f"任务终态：{res['task_status']}")
    print(f"[*] 任务日志：{res['log_file']}")

    # 功能向量（续62）：阶段内部的**子能力**覆盖 —— 比"阶段级 OK"更细一层。
    print("\n[*] 功能向量覆盖（阶段内的子能力，判定取自本次运行的日志/命令/URL）：")
    cur_stage = None
    for sname, key, desc, status, detail in res["vectors"]:
        if sname != cur_stage:
            cur_stage = sname
            print(f"    ---- {sname} ----")
        tip = f"  ← {detail}" if detail else ""
        print(f"      {status:<5} {key:<16} {desc}{tip}")
    print(f"[*] {devflow.summarize_vectors(res['vectors'])}")
    if res["vec_miss"]:
        _miss = [f"{s}/{k}" for s, k, _d, st, _x in res["vectors"] if st == "MISS"]
        print(f"[!] 覆盖缺口（阶段已跑但子能力未点到）：{', '.join(_miss)}")

    if res["error"]:
        print(f"[*] 任务 error（非空说明有阶段抛了异常）：\n    {res['error']}")
    if res["external"]:
        print(f"[!] 自检打到了站外（违反零外网铁律）：{res['external'][:5]}")
    print(f"\n[*] {devflow.summarize(res['rows'])}")
    if res["fail"]:
        fails = [n for n, s, _d, _c in res["rows"] if s == "FAIL"]
        print(f"[!] 自检未通过：{res['fail']} 个阶段 FAIL —— {', '.join(fails)}")
    else:
        print("[*] 自检通过：无阶段 FAIL（SKIP 表示本次无对应活动，不是报错）")
    return res["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
