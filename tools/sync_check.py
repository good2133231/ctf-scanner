"""同步体检（续238）：一条命令回答"现在能不能安全地 pull / push / 开工"。

背景（主理人的担心）："服务器代码没 bug，GitHub 有没同步完的，本地拉取修改提交，
服务器再拉反而改坏了。" 这件事的根因只有一个：**某台机器的工作区不干净或有未推提交时
就开始跨机同步**。本工具把这三件事变成一条命令可见：

- `--strict`：工作区有未提交改动、或有**未推送提交**（领先 origin）⇒ 退出码非 0。
  开工前与 push 前各跑一次；红了先处理（提交/推送/搁置），不许带着脏区跨机同步。
- 不带 `--strict`：只打印报告（体检不拦截）。

用法：
    python tools/sync_check.py --strict          # 开工前 / push 前（默认检查当前仓库）
    python tools/sync_check.py --repo /path      # 检查别的仓库（门禁自测用）

判定口径：
- **脏**：被跟踪文件有修改/暂存（`git status --porcelain` 里非 `??` 的行）。未跟踪文件
  （`??`）不算脏——logs/ 之外的临时草稿很常见，不该拦人；提交时反正要点名 add。
- **未推送**：本地 HEAD 有 origin 没有的提交（ahead > 0）。此时本地工作建立在
  "GitHub 上还不存在的代码"上，接手方看不到；
- **未拉取**：origin 有本地没有的提交（behind > 0）——先 `git pull --rebase` 再开工。
"""
import argparse
import subprocess
import sys
from pathlib import Path


def _git(repo, *args):
    """跑一条 git 命令，返回 (rc, 去尾换行的 stdout)。git 不存在/不是仓库 ⇒ rc=128。"""
    try:
        r = subprocess.run(["git", "-C", str(repo), *args],
                           capture_output=True, text=True, timeout=30)
        return r.returncode, (r.stdout or "").strip()
    except (OSError, subprocess.TimeoutExpired):
        return 128, ""


def check(repo):
    """返回报告 dict；git 不可用/不是仓库时 `ok=False` 并带 reason。"""
    repo = Path(repo).resolve()
    rc, _ = _git(repo, "rev-parse", "--is-inside-work-tree")
    if rc != 0 or _git(repo, "rev-parse", "--is-inside-work-tree")[1] != "true":
        return {"ok": False, "reason": f"{repo} 不是 git 仓库"}
    branch = _git(repo, "rev-parse", "--abbrev-ref", "HEAD")[1] or "HEAD"
    dirty = [l for l in _git(repo, "status", "--porcelain")[1].splitlines()
             if l.strip() and not l.startswith("??")]
    stashes = _git(repo, "stash", "list")[1].count("\n") + (
        1 if _git(repo, "stash", "list")[1] else 0)
    ahead = behind = 0
    has_up = _git(repo, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}")[0] == 0
    if has_up:
        out = _git(repo, "rev-list", "--left-right", "--count", "HEAD...@{u}")[1]
        if out:
            a, b2 = out.split()
            ahead, behind = int(a or 0), int(b2 or 0)
    problems = []
    if dirty:
        problems.append(f"工作区有 {len(dirty)} 个未提交改动（{branch}）")
    if ahead:
        problems.append(f"有 {ahead} 个本地提交未推送（{branch} 领先 origin）")
    if behind:
        problems.append(f"origin 有 {behind} 个提交未拉取")
    return {"ok": not problems, "problems": problems, "branch": branch,
            "dirty": dirty, "ahead": ahead, "behind": behind, "stashes": stashes,
            "has_upstream": has_up}


def main(argv=None):
    ap = argparse.ArgumentParser(description="同步体检：能否安全 pull/push/开工")
    ap.add_argument("--repo", default=str(Path(__file__).resolve().parent.parent),
                    help="仓库路径（默认：本工具所在仓库）")
    ap.add_argument("--strict", action="store_true",
                    help="有未提交改动或未推送提交 ⇒ 退出码 1（开工/push 前的硬门）")
    a = ap.parse_args(argv)
    rep = check(a.repo)
    if not rep.get("ok") and rep.get("reason"):
        print(f"[sync] {rep['reason']}")
        return 2
    print(f"[sync] 分支 {rep['branch']}｜未提交改动 {len(rep['dirty'])}｜"
          f"未推送 {rep['ahead']}｜未拉取 {rep['behind']}｜stash {rep['stashes']}")
    for d in rep["dirty"]:
        print("   脏:", d)
    if rep["ok"]:
        print("[sync] 干净且与 origin 同步 —— 可以安全跨机同步/开工")
        return 0
    for q in rep["problems"]:
        print("   !", q)
    print("[sync] 先提交/推送/拉取，再跨机同步（git pull --rebase origin main）")
    return 1 if a.strict else 0


if __name__ == "__main__":
    sys.exit(main())
