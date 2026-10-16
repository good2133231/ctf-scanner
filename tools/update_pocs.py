#!/usr/bin/env python3
"""`--update-pocs` 的命令行入口（续206，主理人点单第一条）。

    用法：
        python tools/update_pocs.py --source nuclei            # 取 nuclei 的 http/fingerprints
        python tools/update_pocs.py --source nuclei --ref v9.9.9
        python tools/update_pocs.py --list                     # 看预置了哪些源

它做什么：`scanner/pocmgr.py` 取模板 → 逐条校验（**命令执行形态直接拒收**，见那里的说明）
→ 落盘 `config/nuclei-templates/`（POC 引擎的 `POC_DIRS` 里已有这一项，**不用改配置**）；
取到的是 `http/fingerprints/` 时**顺手**转成指纹表
（`config/dicts/fingerprints_nuclei.txt`，与 FingerprintHub 同一份格式、同一个转换器）。

为什么不做得更"自动"（比如定时跑）：拉外部仓库=往机器里写第三方文件，这种事必须
**人下命令**（§2 的安全边界）。所以它是 CLI 而不是守护任务；要定期更新就挂自己的 cron，
命令就是上面那行。

门禁**不跑**它（零网络）：拉取逻辑在 `scanner/pocmgr.py` 里，测试桩掉 `fetch_repo` 验其余部分。
"""
import argparse
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from scanner import pocmgr                      # noqa: E402


def main(argv=None):
    ap = argparse.ArgumentParser(description="从官方仓库更新 POC / 指纹模板")
    ap.add_argument("--source", default="nuclei", help="预置源名（--list 看全部）")
    ap.add_argument("--ref", default="", help="git ref（tag / 分支 / commit），空=默认分支")
    ap.add_argument("--dest", default="", help="落盘目录（默认 config/nuclei-templates）")
    ap.add_argument("--no-fingerprints", action="store_true",
                    help="不要把指纹类模板转成指纹表")
    ap.add_argument("--list", action="store_true", help="列出预置源后退出")
    a = ap.parse_args(argv)

    if a.list:
        for k, v in pocmgr.SOURCES.items():
            print(f"{k:14s} {v['repo']}  目录：{'、'.join(v['paths'])}")
        return 0

    print(f"[update-pocs] 源 {a.source} → {a.dest or pocmgr.POC_DEST}")
    try:
        rep = pocmgr.update(a.source, ref=a.ref, dest=a.dest or None,
                            logger=_Log())
    except Exception as e:                       # noqa: BLE001 —— CLI 要把原因说清再退
        print(f"[update-pocs] 失败：{type(e).__name__}: {e}")
        return 2

    if not rep.get("ok"):
        print(f"[update-pocs] {rep.get('error')}")
        return 2

    c = rep["counts"]
    print(f"[update-pocs] 指纹类 {c['fingerprint']} 个 / POC 类 {c['poc']} 个；"
          f"落盘 {rep['written']['written']}（{rep['written']['unchanged']} 个无变化）；"
          f"拒收 {c['rejected']} / 跳过 {c['skipped']}")
    for k, v in (rep.get("rejected") or {}).items():
        print(f"    [拒收] {k}: {v}")
    if c["fingerprint"] and not a.no_fingerprints:
        _to_fingerprints(a.dest or pocmgr.POC_DEST)
    return 0


class _Log:
    def info(self, msg):
        print(msg)


def _to_fingerprints(dest):
    """把刚落盘的指纹类模板转成指纹表（与 FingerprintHub 同一份格式、同一个转换器）。"""
    import importlib.util
    src = os.path.join(ROOT, "tools", "import_fingerprints.py")
    spec = importlib.util.spec_from_file_location("ifp_update", src)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    fp_dir = os.path.join(dest, "fingerprints")
    if not os.path.isdir(fp_dir):
        print("[update-pocs] 没有指纹类模板可转（本次只取了 POC？）")
        return
    rules, stat = mod.from_fingerprinthub(fp_dir)
    out = os.path.join(ROOT, "config", "dicts", "fingerprints_nuclei.txt")
    if rules:
        # 表的格式是 `标签<TAB>位置<TAB>判据<TAB>状态码`；社区库这两张**不带状态码门控**
        # （它们是"认不认得出这个组件"），所以第四列留空 —— 与 fingerprints_hub/ehole 一致。
        lines = [f"{t}\t{w}\t{p}\t" for (t, w, p) in rules]
        with open(out, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        print(f"[update-pocs] 指纹表已写 {out}（{len(lines)} 条）")
        print("[update-pocs] ⚠ 还要做一步：把该文件登记进 scanner/fingerprint.py 的 "
              "EXTRA_FILES（只此一处，加载逻辑仍然只有一份）")
    else:
        print(f"[update-pocs] 指纹类模板一条都没转出来（{stat}）")


if __name__ == "__main__":
    raise SystemExit(main())
