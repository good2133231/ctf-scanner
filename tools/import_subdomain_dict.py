#!/usr/bin/env python3
"""把一份**深的**子域名字典清洗后并进 `config/dicts/subdomains_deep.txt`（深档）。

两档字典（续139，为什么分两档见 `scanner/stages/subdomain.py` 的注释）：
  · `dicts.subdomains`      ＝ 精简档，人工挑的高价值前缀，流水线**永远全量吃**；
  · `dicts.subdomains_deep` ＝ 深档，本脚本的默认目标；没装 puredns 时受
    `limits.brute_fallback_max` 等距抽样，装了 puredns 就全量吃（`limits.brute_max_words` 0）。
把深档单独成文件而不是并进精简档，正是为了"抽样只冲掉深档、精简档一条不丢"。

为什么需要它：2026-10-08 与灯塔逐条比对 weex.com，它记为站点而我们**连域名都没生成**的主机
有 15 台，根因之一是字典规模 —— 仓库里发的是 85 行（任务 8 日志原话：
`内置 DNS 爆破：1 域名 x 84 字典`），而灯塔自带的 `/code/app/dicts/subdomains.txt` 是
**17.8 万行**。深字典要能用起来，就得有一条"清洗 + 去重 + 并集"的路，而不是手工往文件里粘
（粘进去的空行、`#`、大写、`a..b`、`*`、带 `_` 的行，puredns 会照着拼出 `* .domain` 这种垃圾查询）。

用法：
    py -3 tools/import_subdomain_dict.py --src 我的字典.txt        # 并集写回深档（默认目标）
    py -3 tools/import_subdomain_dict.py --src a.txt --src b.txt --dry-run
    py -3 tools/import_subdomain_dict.py --src big.txt --replace       # 丢掉原有内容（慎用）

纯离线：只读参数给定的**本地文件**，不发任何 DNS/HTTP 请求、不下载、不依赖第三方包。
写回前逐项计数并如实报出丢弃原因（"导入 17.8 万条"与"其中 6 千条是垃圾"是两回事）。
"""
import argparse
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEST = ROOT / "config" / "dicts" / "subdomains_deep.txt"

# 爆破前缀的合法形态：小写字母/数字/连字符，允许 `www.mail` 这种多标签（灯塔也这么用），
# 但不允许 `_`、`*`、空格、Unicode —— 这些拼出来的查询要么无效要么打错域名。
# 首尾必须是字母/数字，中间允许 `.` `-`，**不允许 `_`**：带下划线的名字是 SRV 记录
# （`_dmarc.example`）而不是可爆破的主机名，拼出来的查询要么无效要么打错域名。
# （第一版这里写成 `[a-z0-9._-]`，与上一行的"不允许 `_`"自相矛盾，深档里 17 条
# `api_portal_dev` 就是这样混进来的 —— 回归 [8aq] ① 钉住中间下划线也要判非法。）
LEGAL_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$")
MAX_LABEL = 63          # RFC 1035：单标签上限
MAX_TOTAL = 253         # RFC 1035：整名上限（这里限的是前缀本身）


def classify(raw):
    """一行原始文本 → `(清洗后的前缀, None)` 或 `(None, 丢弃原因)`。

    "注释"与"空行"也算丢弃原因：调用方要把它们和"非法字符"分开数，
    否则一份带 200 行注释的字典会被报成"200 条垃圾"。
    """
    s = str(raw).strip()
    if not s:
        return None, "空行"
    if s.startswith("#"):
        return None, "注释"
    s = s.lower()
    if s.startswith("."):
        return None, "以点开头"
    s = s.rstrip(".")
    if not s:
        return None, "空行"
    if not LEGAL_RE.match(s):
        return None, "非法字符"
    if ".." in s:
        return None, "空标签"
    if any(len(x) > MAX_LABEL for x in s.split(".")):
        return None, "标签过长"
    if len(s) > MAX_TOTAL:
        return None, "整行过长"
    return s, None


def _display(p):
    """项目根之内就显示相对路径，其余原样给出用户传的那个路径。

    两边都**先 resolve** 再比：`--dest config/x.txt`（相对路径）只 resolve 一边会抛
    `ValueError: 'config/x.txt' is not in the subpath of ...` —— 实测连 `--dry-run` 都崩。
    """
    try:
        return str(Path(p).resolve().relative_to(ROOT.resolve()))
    except (ValueError, OSError):
        return str(p)


def read_src(path):
    """读一个本地文件 → `(有效前缀列表, 计数字典)`；文件读不出来的错**原样抛**，不静默返回空。"""
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    words, stats = [], {"读入": 0, "重复": 0, "非法字符": 0, "空标签": 0, "标签过长": 0,
                        "整行过长": 0, "以点开头": 0, "注释": 0, "空行": 0, "有效": 0}
    seen = set()
    for line in text.splitlines():
        stats["读入"] += 1
        w, why = classify(line)
        if why:
            stats[why] += 1
            continue
        if w in seen:
            stats["重复"] += 1
            continue
        seen.add(w)
        stats["有效"] += 1
        words.append(w)
    return words, stats


def read_dest(dest):
    """目标文件现有内容 → `(注释行, 前缀集合)`；不存在就是 `([], set())`（首次生成）。

    `dest` 必须**用参数传进来**：早先这函数读的是模块常量 `DEST`，于是 `--dest` 指到别处时
    "并集"并的是仓库那份 84 条 —— 报"原有 84 条"、写出 584 条（回归 [8aq] ③ 实测到的正是它）。
    """
    dest = Path(dest)
    if not dest.is_file():
        return [], set()
    head, words = [], set()
    for line in dest.read_text(encoding="utf-8", errors="replace").splitlines():
        s = line.strip()
        if not s:
            continue
        if s.startswith("#"):
            head.append(s)
            continue
        w, why = classify(s)
        if w:
            words.add(w)
    return head, words


def main(argv=None):
    ap = argparse.ArgumentParser(description="清洗并导入深子域名字典（纯离线）")
    ap.add_argument("--src", action="append", default=[], metavar="文件",
                    help="要导入的字典文件，可重复给多个")
    ap.add_argument("--dest", default=str(DEST),
                    help=f"写回目标（默认 {DEST.relative_to(ROOT)}）")
    ap.add_argument("--replace", action="store_true",
                    help="丢掉目标文件里原有的前缀（默认与现有内容取并集）")
    ap.add_argument("--dry-run", action="store_true", help="只报数，不写文件")
    a = ap.parse_args(argv)

    if not a.src:
        ap.error("至少要给一个 --src（本脚本不下载任何东西：字典得是你手上那份文件）")
    dest = Path(a.dest)
    for s in a.src:
        p = Path(s)
        if not p.is_file():
            print(f"[X] 源文件不存在或不是文件：{s}", file=sys.stderr)
            return 2
        if p.resolve() == dest.resolve():
            print(f"[X] 源与目标是同一个文件：{s}", file=sys.stderr)
            return 2

    words, total = [], {"读入": 0, "重复": 0, "非法字符": 0, "空标签": 0, "标签过长": 0,
                        "整行过长": 0, "以点开头": 0, "注释": 0, "空行": 0, "有效": 0}
    for s in a.src:
        w, st = read_src(s)
        print(f"[+] {s}: 读入 {st['读入']} → 有效 {st['有效']}"
              + "".join(f"、{k} {st[k]}" for k in ("重复", "非法字符", "空标签", "标签过长",
                                                   "整行过长", "以点开头", "注释", "空行")
                        if st[k]))
        words.extend(w)
        for k in total:
            total[k] += st[k]

    head, existing = read_dest(dest)
    merged = (set() if a.replace else existing) | set(words)
    if not words:
        # 源里一个有效前缀都没有（整份都是注释/空行/非法字符）：目标**一个字都不动**，
        # 也不要把同样的内容重写一遍冒充"导入成功"。
        print("[X] 这份源清洗后一个有效前缀都没有（丢弃明细见上）—— 目标保持原样，未写入",
              file=sys.stderr)
        return 1

    new_only = len(merged) - len(existing)
    print(f"[=] 目标 {_display(dest)}: "
          f"原有 {len(existing)} 条，导入后 **{len(merged)} 条**"
          f"（本次净增 {new_only}；重复丢弃 {total['重复']}）")
    if total["非法字符"] or total["空标签"] or total["标签过长"] or total["整行过长"] \
            or total["以点开头"]:
        bad = total["非法字符"] + total["空标签"] + total["标签过长"] \
            + total["整行过长"] + total["以点开头"]
        print(f"[!] 丢弃 {bad} 行不合格内容（非法字符 {total['非法字符']}、空标签 "
              f"{total['空标签']}、标签过长 {total['标签过长']}、整行过长 {total['整行过长']}、"
              f"以点开头 {total['以点开头']}）—— 这些拼出来的是无效查询，不是漏收")

    if a.dry_run:
        print("[i] --dry-run：文件未改动")
        return 0

    stamp = "导入来源：" + "、".join(str(Path(s).name) for s in a.src)
    keep_head = [h for h in head if not h.startswith("# 导入来源：")]
    body = "\n".join(keep_head + [f"# {stamp}"]) + "\n" + "\n".join(sorted(merged)) + "\n"
    tmp = dest.with_suffix(dest.suffix + ".tmp")
    tmp.parent.mkdir(parents=True, exist_ok=True)
    # 不用 `Path.write_text(..., newline=)` —— 那个参数是 **3.10+** 才有的，本仓下限 3.9
    # （CI 与容器门禁都跑 3.9）：3.9 上直接 `TypeError: unexpected keyword argument`。
    # 要精确控制行尾，就只能退回内建的文件对象写法：显式给 encoding 与 newline 两个参数。
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(body)
    os.replace(tmp, dest)
    print(f"[+] 已写入 {len(merged)} 条。爆破规模仍受 limits.brute_max_domains / "
          "limits.brute_fallback_max 约束（内置兜底不会把整份字典硬啃下来）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
