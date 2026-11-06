#!/usr/bin/env python3
"""用加密凭据把当前提交推到 GitHub（续347）。

凭据来源：`config/keys.enc.yaml` 的 `github.push_token`。
令牌只放进本次子进程的 `http.extraheader` 环境配置，不写 remote URL、
不进 argv，也不改 `.git/config`；输出里统一替换成 `***`。
"""
import argparse
import base64
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner import keystore  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description="解密 github.push_token 并 push HEAD")
    ap.add_argument("--remote", default="origin", help="远端名（默认 origin）")
    ap.add_argument("--branch", default="main", help="远端分支（默认 main）")
    ap.add_argument("--dry-run", action="store_true", help="只打印命令，不实际推送")
    args = ap.parse_args()

    unlocked = keystore.unlock(allow_prompt=False)
    if not unlocked.get("ok"):
        print(f"UNLOCK_FAIL {unlocked.get('reason')}")
        return 1
    token = ((keystore.current() or {}).get("github") or {}).get("push_token")
    if not token:
        print("NO_TOKEN")
        return 1

    auth = base64.b64encode(f"x-access-token:{token}".encode("utf-8")).decode("ascii")
    env = dict(os.environ)
    env.update({
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "http.https://github.com/.extraheader",
        "GIT_CONFIG_VALUE_0": f"Authorization: Basic {auth}",
    })
    cmd = ["git", "push", args.remote, f"HEAD:{args.branch}"]
    print("PUSH", " ".join(cmd), flush=True)
    if args.dry_run:
        return 0

    r = subprocess.run(cmd, cwd=str(ROOT), env=env, capture_output=True, text=True)
    msg = (r.stdout or "") + (r.stderr or "")
    print(f"RC {r.returncode}")
    print(msg.replace(token, "***")[-1200:])
    return r.returncode


if __name__ == "__main__":
    raise SystemExit(main())
