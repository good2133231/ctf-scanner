#!/usr/bin/env python3
"""VT / ICP 第三方情报源的**真机验收**（续215）。

背景：续205 落地了 ICP 备案反查（`scanner/icp.py`）、续214 落地了 VirusTotal
（`scanner/virustotal.py`），但两台机器上都没填 key —— 代码就绪 ≠ 真机能用。
这个脚本在**填完 key 之后**跑一次，把"到底通没通、为什么没通"说清楚：

- 只打印**有没有配置**，绝不打印任何 key / token 值；
- VT：有 key 才发请求（`GET /v3/domains/<domain>/subdomains?limit=1`）；
- ICP：先按 `icp.preflight` 逐源探活，再用 `icp.query` 真查一个域名；
- 没有 key 的源标 `skipped`（不是失败）；`--strict` 才把"没配 key"当失败（发版验收用）。
- 退出码：0 = 配了的源都通；1 = 配了但不通 / `--strict` 下缺 key；2 = 参数错。

用法：
    python tools/check_intel_sources.py
    python tools/check_intel_sources.py --domain example.com --json
    python tools/check_intel_sources.py --strict      # 缺 key 也算失败
"""
import argparse
import json
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))


def main(argv=None):
    ap = argparse.ArgumentParser(description="CTFScanner VT / ICP 情报源真机验收")
    ap.add_argument("--domain", default="example.com",
                    help="验收查询用的域名（默认 example.com，不要拿授权目标做连通性测试）")
    ap.add_argument("--json", action="store_true", help="输出 JSON（机器可读）")
    ap.add_argument("--strict", action="store_true", help="缺 key 也返回非 0")
    args = ap.parse_args(argv)

    from scanner import icp, keystore, virustotal as vt
    from scanner.config import load_settings

    keystore.unlock(allow_prompt=False)
    keys = keystore.current() or {}
    settings = load_settings()
    report = {"domain": args.domain, "keys": {}, "vt": {}, "icp": {}}

    vt_key = bool(str(((keys.get("virustotal") or {}).get("key") or "")).strip())
    icp_key = bool(str(((keys.get("icp") or {}).get("api_key") or "")).strip())
    report["keys"] = {"virustotal": vt_key, "icp": icp_key}

    # ---- VirusTotal ----
    if not vt.available(settings):
        report["vt"] = {"status": "skipped", "reason": keystore.keys_hint("virustotal.key")}
    else:
        subs, total, err = vt.search(args.domain, settings, limit=1)
        report["vt"] = {"status": "ok" if not err else "error",
                        "subdomains": len(subs), "total": total, "error": err}

    # ---- ICP 备案反查 ----
    ok_src, bad_src = icp.preflight(None, settings, logger=None, timeout=10)
    if not ok_src and not bad_src:
        report["icp"] = {"status": "skipped", "reason": "没有配置任何源"}
    else:
        detail = {}
        for src in ok_src:
            got = icp.query(args.domain, settings, src, timeout=10)
            detail[src["name"]] = ({
                "status": "ok" if got is not None else "error",
                "domains": len((got or {}).get("domains") or []),
                "org": (got or {}).get("org") or "",
            } if got is not None else {"status": "error", "reason": "查询无响应"})
        for name, why in (bad_src or {}).items():
            detail[name] = {"status": "unreachable", "reason": why}
        good = [v for v in detail.values() if v.get("status") == "ok"]
        report["icp"] = {"status": "ok" if good else "error", "sources": detail}

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(f"[*] 域名：{report['domain']}")
        print(f"[*] 凭据：virustotal={'已填' if vt_key else '空'}，"
              f"icp.api_key={'已填' if icp_key else '空'}（值不打印）")
        _v = report["vt"]
        print(f"[{'=' if _v['status'] == 'ok' else '!'}] VT：{_v['status']}"
              + (f"（{_v.get('reason') or _v.get('error')}）" if _v.get("reason") or _v.get("error") else "")
              + (f" 子域 {_v.get('subdomains')} 条 / total={_v.get('total')}"
                 if _v.get("status") == "ok" else ""))
        _i = report["icp"]
        if _i.get("status") == "skipped":
            print(f"[!] ICP：skipped（{_i.get('reason')}）")
        else:
            print(f"[{'=' if _i['status'] == 'ok' else '!'}] ICP：{_i['status']}")
            for name, info in (_i.get("sources") or {}).items():
                extra = info.get("reason") or (
                    f"域名 {info.get('domains')} 个" + (f"，主体 {info['org']}" if info.get("org") else ""))
                print(f"    - {name}: {info.get('status')}（{extra}）")

    failed = report["vt"].get("status") == "error" or report["icp"].get("status") == "error"
    if args.strict:
        failed = failed or not vt_key or not icp_key
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
