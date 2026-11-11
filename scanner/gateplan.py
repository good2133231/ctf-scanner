# -*- coding: utf-8 -*-
"""门禁分档的唯一产地（续308，主理人点单：「全量门禁能不能区域验证，每次跑全量有点浪费时间」）。

**要解决的不是"少跑几组"，而是"少等几次"**：本会话实测 7 次真红里 6 次红在**我没改的那一组**
（`[8bq]` 被随包默认值翻档打红、GUI 路由被抢、E2E 的默认勾选计数、`[219]②` 钉死模板名单、
`[212]` 的 CLI 入口计数、`[218]` 的黑名单路径）——所以"提交前跑一次全量"这条（AGENTS §0.6）
不许松。能松的是**开发中每一次改动的等待**，以及**全量里那些语料型的固定成本**。

于是这里只有两件事：

1. **`tier_for()`：档位是算出来的，不是人选的。** 判据是"本轮改动有没有碰到这组的承重文件"
   （`git diff --name-only HEAD` + 未跟踪的新文件）。碰到了 ⇒ 全档；没碰到 ⇒ 降档并**必须打印**
   降档说明。拿不到 diff、不在 git 工作树、或在 CI 里 ⇒ **一律全档**（CI 的 diff 天然是空的，
   拿它当"没改东西"就是让 CI 变成弱档——那正是 §6.2 第十起"静默旁路"的形状）。
2. **`note()`：那句"本次降了哪几组、为什么"的成语文案只这一处**（§5.14）。三处各拼一遍必然漂，
   漂到最后没人相信"全量"这两个字。

刻意**不做什么**：不跳过任何一组。降档只缩"语料规模"（`[8aa]` 的随机差分段），
所有判据本体（固定语料、变异证伪、覆盖率与计数判据）两档都跑。
"""
import fnmatch
import os
import re
import subprocess
from pathlib import Path

FULL = "full"
LITE = "lite"

#: 映射表文档（组号与承重文件都写在那里，本模块是它的机器形态）
MAP_DOC = "docs/gate-map.md"

#: 承重文件被改 ⇒ 该组必须跑全档。`globs` 是相对仓库根的模式；`full_n`/`lite_n` 是语料条数。
HEAVY = (
    {
        "group": "8aa",
        "what": "指纹前置过滤的逐字符差分（随机语料段 × 3 个状态码，实测 129.3s / 占可归因 23.6%）",
        "globs": ("scanner/fingerprint.py", "config/dicts/fingerprint_aliases.txt",
                  "config/dicts/fingerprint_fixes.txt", "config/dicts/fingerprints_*.txt"),
        "full_n": 2200,
        "lite_n": 400,
    },
)

_BY_GROUP = {h["group"]: h for h in HEAVY}


def changed_paths(root=None):
    """本轮改动碰到的路径（含未跟踪的新文件）。

    返回 `(路径列表, None)` 表示"拿得到"；拿不到时返回 `([], 原因)` —— 调用方**必须**把
    "拿不到"当成全档的理由，而不是当成"什么都没改"。
    """
    base = str(Path(root) if root else Path(__file__).resolve().parent.parent)
    try:
        inside = subprocess.run(["git", "-C", base, "rev-parse", "--is-inside-work-tree"],
                                capture_output=True, text=True, timeout=20)
        if inside.returncode != 0 or inside.stdout.strip() != "true":
            return [], "不在 git 工作树里"
        out = subprocess.run(["git", "-C", base, "diff", "--name-only", "HEAD"],
                             capture_output=True, text=True, timeout=60)
        if out.returncode != 0:
            return [], "git diff 失败（没有 HEAD？比如浅克隆的空仓库）"
        paths = [p for p in out.stdout.splitlines() if p.strip()]
        untracked = subprocess.run(
            ["git", "-C", base, "ls-files", "--others", "--exclude-standard"],
            capture_output=True, text=True, timeout=60)
        if untracked.returncode == 0:
            paths += [p for p in untracked.stdout.splitlines() if p.strip()]
        return sorted(set(paths)), None
    except Exception as exc:                          # noqa: BLE001 - 超时、git 不在 PATH……一律"拿不到"
        return [], "git 调用异常：%s" % type(exc).__name__


def force_full_env(env=None):
    """CI 或显式点名 ⇒ 全档。`CTFSCANNER_GATE_TIER=full` 是人工保险丝。"""
    e = env if env is not None else os.environ
    if e.get("CI") or e.get("CTFSCANNER_GATE_TIER") == FULL:
        return True
    return False


def tier_for(group, changed=None, env=None):
    """这一组本次跑什么档：`(档位, 原因, 语料条数)`。"""
    h = _BY_GROUP.get(group)
    if h is None:
        return FULL, "不在分档清单里（这一组永远全档）", 0
    if force_full_env(env):
        why = "CI 或 CTFSCANNER_GATE_TIER=full ⇒ 强制全档" if (env or os.environ).get("CI") \
            else "显式点名 CTFSCANNER_GATE_TIER=full ⇒ 强制全档"
        return FULL, why, h["full_n"]
    if changed is None:
        return FULL, "拿不到改动清单 ⇒ 全档（不许把「没 diff」读成「没改东西」）", h["full_n"]
    hit = [p for p in changed if any(fnmatch.fnmatch(p, g) for g in h["globs"])]
    if hit:
        return FULL, "改动碰到承重文件：%s" % "、".join(hit[:3]), h["full_n"]
    return LITE, "改动没碰到承重文件（%s）" % "、".join(h["globs"]), h["lite_n"]


def corpus_n(group="8aa", changed=None, env=None):
    """语料型那一段跑多少条（`[8aa]` 的随机差分段）。"""
    return tier_for(group, changed, env)[2]


def plan(root=None, env=None):
    """(改动清单, 每组的档位行, 是否降过档)——smoke 与 `--check` 都读它，别各算一遍。"""
    changed, why_unavailable = changed_paths(root)
    rows = []
    for h in HEAVY:
        if why_unavailable:
            tier, why, n = FULL, "拿不到改动清单（%s）⇒ 全档" % why_unavailable, h["full_n"]
        else:
            tier, why, n = tier_for(h["group"], changed, env)
        rows.append({"group": h["group"], "what": h["what"], "tier": tier,
                     "why": why, "n": n, "full_n": h["full_n"], "lite_n": h["lite_n"]})
    return changed, rows, why_unavailable


def note(rows):
    """那句成语文案的唯一产地。没降档也要说一句"本次全档"，否则"降档"与"没跑"读起来一样。"""
    lite = [r for r in rows if r["tier"] == LITE]
    if not lite:
        return "[gateplan] 本次全部组跑**全档**（分档清单 %d 组，无一命中「改动碰到承重文件」那一档）" % len(rows)
    return "[gateplan] 本次降档 %d 组：%s｜其余全档" % (
        len(lite), "；".join("[%s] %d→%d 段（%s）" % (r["group"], r["full_n"], r["n"], r["why"])
                          for r in lite))

# ---------- 续311：把映射表变成可执行建议（`python dev.py gate`） ----------
# 表格是唯一产地：这里只**读** docs/gate-map.md，不另存一份映射（§5.14）。
# 解析不了的行必须报出来（problems），不许静默当成"没命中"。

def map_rows(doc=None):
    """`(rows, problems)`：从映射表解析出 `[{what, patterns, groups, ranged}]`。

    行格式固定 `| 左列 | 右列 |`：左列反引号里是路径/glob（可多个），右列 `[组号]` 是必须
    点名的组（`[6a]`~`[6g]` 这种范围写法只取两端，`ranged=True` 让调用方直接建议全量）。
    """
    path = Path(doc) if doc else Path(__file__).resolve().parent.parent / MAP_DOC
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return [], ["读不到 %s：%s" % (MAP_DOC, exc)]
    rows, problems = [], []
    for line in text.splitlines():
        s = line.strip()
        if not s.startswith("|"):
            continue
        cells = [c.strip() for c in s.strip("|").split("|")]
        if len(cells) < 2:
            continue
        left, right = cells[0], cells[1]
        if re.fullmatch(r"`?\[[A-Za-z0-9]+\]`?", left):
            continue                      # 分档表（左列只有一个组号），不是"改什么→跑哪些组"
        pats = re.findall(r"`([^`]+)`", left)
        groups = re.findall(r"\[([A-Za-z0-9]+)\]", right)
        if not pats or not groups:
            if pats or groups:
                problems.append("这一行只解析出一半：%r" % s[:80])
            continue
        if "本文件" in left:
            pats.append(MAP_DOC)
        rows.append({"what": left, "patterns": pats, "groups": groups,
                     "ranged": "~" in right})
    if not rows:
        problems.append("映射表解析出 0 行（表格格式变了？）")
    return rows, problems


def _match(path, pattern):
    """改动路径是否命中表格里的 pattern：路径 / glob / 裸文件名 / 目录 / 任意层级后缀都认。"""
    p = str(pattern or "").strip().lstrip("./")
    if not p:
        return False
    if "*" in p or "?" in p:
        return (fnmatch.fnmatch(path, p) or fnmatch.fnmatch(path, "**/" + p)
                or fnmatch.fnmatch(path, "*/" + p))
    if p.endswith("/"):
        return path.startswith(p) or ("/" + p) in ("/" + path)
    if "/" in p:
        return (path == p or path.startswith(p + "/")
                or ("/" + p) in ("/" + path))
    base = os.path.basename(path)
    return base == p or ("/" + p) in ("/" + path)


def match_changed(changed, rows=None):
    """`(命中行, 组号并集, 必须全量的理由列表)`。"""
    if rows is None:
        rows, _ = map_rows()
    hit_rows, groups, full = [], [], []
    for r in rows:
        hits = sorted({f for f in changed if any(_match(f, p) for p in r["patterns"])})
        if not hits:
            continue
        hit_rows.append({"what": r["what"], "files": hits,
                         "groups": r["groups"], "ranged": r["ranged"]})
        groups += r["groups"]
        if r["ranged"]:
            full.append("「%s」右列有范围写法（~），点名两端会漏" % r["what"])
    return hit_rows, sorted(set(groups)), full

