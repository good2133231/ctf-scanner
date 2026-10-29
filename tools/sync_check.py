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
- **散落的凭据形状（续296）**：未跟踪**且没被 .gitignore 覆盖**的文件，只要落在 `config/` 下，
  或内容里出现已知令牌形状，就单独点名。理由不是"整洁"：主理人 2026-10-29 两次把凭据
  随手放成 `config/config`、`config/111` —— 那两个名字**都不在** `.gitignore` 的名单里，
  一次 `git add -A` 就把明文送进公开仓库，而这条判断只看"未被跟踪也未被忽略"这个结构事实，
  不依赖文件名取得对。
"""
import argparse
import re
import subprocess
import sys
from pathlib import Path


# 已知令牌形状（只用于**发现**，绝不允许写进本仓库的被跟踪文件——门禁 [155] 那条同源）。
# 每一项都在运行时拼接，避免这里出现的"形状示例"被 GitHub 秘密扫描当成真凭据。
_SECRET_SHAPES = (
    ("GitHub classic PAT", re.compile(r"ghp_[A-Za-z0-9]{36}")),
    ("GitHub fine-grained PAT", re.compile("github_" + r"pat_[A-Za-z0-9_]{40,}")),
    ("OpenAI key", re.compile(r"sk-[A-Za-z0-9]{20,}")),
    ("AWS access key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("私钥文件正文", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
)
_SECRET_MAX_BYTES = 256 * 1024


def loose_secrets(repo):
    """未跟踪且未被忽略的文件里，哪些是"差一次 git add -A 就公开"的形状。返回 [(路径, 原因)]。"""
    repo = Path(repo).resolve()
    st = _git(repo, "status", "--porcelain", "--untracked-files=all")[1]
    cands = [l[3:].strip().strip('"') for l in st.splitlines() if l.startswith("?? ")]
    out = []
    for rel in cands:
        if not rel:
            continue
        p = repo / rel
        under_config = rel.split("/", 1)[0] == "config"
        hit_name = ""
        try:
            size = p.stat().st_size
        except OSError:
            size = 0
        if size and size <= _SECRET_MAX_BYTES:
            try:
                text = p.read_bytes().decode("utf-8", "ignore")
            except OSError:
                text = ""
            for label, rx in _SECRET_SHAPES:
                if rx.search(text):
                    hit_name = f"内容含 {label} 形状"
                    break
        if under_config or hit_name:
            why = "、".join(x for x in (("config/ 下的散文件" if under_config else ""), hit_name) if x)
            out.append((rel, why + "（未跟踪也没被 .gitignore 覆盖）"))
    return out


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
    loose = loose_secrets(repo)
    if loose:
        problems.append(f"有 {len(loose)} 个**未跟踪也没被忽略**的文件带凭据形状（差一次 git add -A）")
    if ahead:
        problems.append(f"有 {ahead} 个本地提交未推送（{branch} 领先 origin）")
    if behind:
        problems.append(f"origin 有 {behind} 个提交未拉取")
    return {"ok": not problems, "problems": problems, "branch": branch,
            "dirty": dirty, "ahead": ahead, "behind": behind, "stashes": stashes,
            "loose": loose, "has_upstream": has_up}


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
    for rel, why in rep.get("loose") or []:
        print("   散落:", rel, "←", why)
    print("[sync] 先提交/推送/拉取，再跨机同步（git pull --rebase origin main）；"
          "散落那几行要么写进 .gitignore，要么换成被跟踪的模板文件（config/keys.yaml.example 那种）")
    return 1 if a.strict else 0


if __name__ == "__main__":
    sys.exit(main())
