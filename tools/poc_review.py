#!/usr/bin/env python3
"""按族复核导入 POC：把「人工判定」这一步做成**可执行、可追溯、默认不动**的一条路（续114）。

实施者：WorkBuddy · Qoder-Agent（远端 Linux）

为什么需要这个工具（不是"再写一个 POC 管理器"）
----------------------------------------------
`config/pocs-imported/` 的 305 条由 `tools/import_ref_pocs.py` 静态转换而来，绝大多数是
"这页像不像某某 OA" 的**指纹**规则而不是漏洞证明，于是 `db.effective_poc_severity()` 把它们的
有效级别一律压到 `low` ⇒ 默认**一条都不执行**（AGENTS §7「POC 置信度」那条）。要放开某族，
既定的做法是"人工复核后整理进 `config/pocs-user/`"（那算 `user` 来源、置信度 medium、
有效级别照信声明）。但那句话此前**只是句话**：没有工作表、没有搬运入口、也没有"这条是谁
什么时候按什么依据放开的"的痕迹 —— 于是实际发生的事是"要么一直全关，要么有人手改文件全开"。

本工具做的就是把那件事变成三步：**挑族 → 出工作表 → 只把标了 `ok` 的搬进去**。

三条红线（改之前先读）
--------------------
1. **机器不判定**：工具只把判据（匹配器实际在找什么字串、校准靶场有没有被它命中）摊开给人看，
   复核栏空着就是**不动**；没有 `--all-ok` / `--yes` 这类"整批放开"旗标，也不接受"我看过了"
   这种口头授权 —— 授权必须落在**逐行**的 `ok` 上。
2. **不改原始数据**：`config/pocs-imported/` 里的文件一个字都不动（与 `pocs.severity` 存声明值
   同一个道理）；搬进 `config/pocs-user/` 时只在**文件头追加**几行注释写明出处。
3. **不覆盖**：目标目录里已有同名文件就跳过并说明，避免"重跑一次把人工改过的模板盖掉"。

用法
----
    py -3 tools/poc_review.py --families                 # 有哪些族、各多少条
    py -3 tools/poc_review.py --family wordpress         # 出这一族的复核工作表（Markdown）
    py -3 tools/poc_review.py --family 禅道 --out logs/zz.md
    py -3 tools/poc_review.py --import logs/zz.md        # 只搬复核栏写了 ok 的行
"""
import argparse
import datetime
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scanner import db, runner                      # noqa: E402
from scanner.pocs import engine                     # noqa: E402

SRC_DIR_NAME = "config/pocs-imported"
DEST_DIR = ROOT / "config" / "pocs-user"
CALIB_JSON = ROOT / "logs" / "poc_calibration.json"
DEFAULT_SHEET = ROOT / "logs" / "poc_review.md"
# 复核栏认这两个词（大小写、首尾空白都不敏感）。别的都算"没判"。
OK_TOKENS = {"ok", "pass"}


def _rel(p):
    """只出现相对路径（§0 硬规矩 3）。"""
    try:
        return pathlib.Path(p).resolve().relative_to(ROOT).as_posix()
    except (ValueError, OSError):
        return str(p)


def _matcher_digest(meta):
    """把"这条规则到底在找什么"压成一行 —— 人工判"是证明还是指纹"吃的就是这一行。

    为什么不只给 matcher 数量：`status:200` 与 `word:"<title>360终端安全管理系统</title>"`
    的判别力天差地别，而数量上都是"1 个匹配器"。
    """
    out = []
    for req in (meta.get("http") or []):
        for m in (req.get("matchers") or []):
            t = str(m.get("type") or "")
            if t == "status":
                out.append("status:" + ",".join(str(s) for s in (m.get("status") or [])))
            elif t in ("word", "words"):
                ws = [str(w)[:40] for w in (m.get("words") or m.get("word") or [])][:3]
                out.append("word[" + "|".join(ws) + "]" +
                           ("（排除:" + "|".join(str(x)[:20] for x in (m.get("exclude-word") or [])) + "）"
                            if m.get("exclude-word") else ""))
            elif t == "regex":
                out.append("regex:" + " | ".join(str(r)[:48] for r in (m.get("regex") or [])[:2]))
            elif t in ("size", "length"):
                # nuclei 里 `size:` 是**列表**（"这几个长度之一"），直接 print 会把中括号带进表格，
                # 复核的人在表里看到的应该是长度本身
                raw = m.get(t) if m.get(t) is not None else m.get("size")
                val = ",".join(str(x) for x in raw) if isinstance(raw, (list, tuple)) else str(raw)
                out.append(f"{t}:{val}")
            elif m:
                out.append(t or str(m)[:24])
    return "; ".join(out)[:220] or "（无匹配器 —— 只看请求是否成功）"


def _calib_hits():
    """`tools/calibrate_pocs.py` 的负样本命中（有就读，没有就空 —— 缺报告不影响复核）。

    读的是**上次那份报告**，所以口径必须写在输出里：靶场换过就得重跑校准。
    """
    try:
        import json
        data = json.loads(CALIB_JSON.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return {str(h.get("id")): str(h.get("detail") or "")[:160] for h in (data.get("hits") or [])}


def candidates(families=None, src_dirs=None):
    """列出待复核的导入 POC（按族过滤），每条带判据所需的全部字段。"""
    hits = _calib_hits()
    dirs = [pathlib.Path(d) for d in (src_dirs or [ROOT / SRC_DIR_NAME])]
    rows = []
    for d in dirs:
        if not d.exists():
            continue
        for f in sorted(d.glob("*.y*ml")):
            meta = engine.load_poc_file(f)
            if meta.get("_status") != "ok":
                continue
            info = meta.get("info") or {}
            tags = [str(t) for t in (info.get("tags") or [])]
            idc = str(meta.get("id") or f.stem)
            hay = " ".join([idc, str(info.get("name") or ""), " ".join(tags), f.name]).lower()
            if families and not any(str(kw).lower() in hay for kw in families):
                continue
            rows.append({
                "id": idc,
                "name": str(info.get("name") or ""),
                "path": _rel(f),
                "tags": ",".join(tags),
                "declared": str(info.get("severity") or "medium"),
                "effective": str(db.effective_poc_severity(str(f), meta=meta)),
                "confidence": str(db.poc_confidence(str(f), meta)),
                "matchers": _matcher_digest(meta),
                "calib": "命中（在合成负样本上=误报证据）" if idc in hits else "-",
                "author": str(info.get("author") or ""),
            })
    return _annotate_dupes(rows)


def families(src_dirs=None):
    """按 tag 统计条数，帮人**先挑族**再出表（305 条一张表没人看得完）。"""
    rows = candidates(src_dirs=src_dirs)
    cnt = {}
    for r in rows:
        for t in (r["tags"] or "").split(","):
            if t and t not in ("imported", "ref-poc"):      # 这两个是导入器打的公共标签
                cnt[t] = cnt.get(t, 0) + 1
    return sorted(cnt.items(), key=lambda kv: (-kv[1], kv[0].lower()))


HEAD = ("| 复核 | id | 名称 | 声明 | 有效 | 置信 | tags | 匹配器（这条到底在找什么） | 负样本校准 | 同指纹 | 文件 |",
        "|---|---|---|---|---|---|---|---|---|---|---|")


def _annotate_dupes(rows):
    """给每条算「判据完全相同的条目有几条」—— 复核时最该先看的一列。

    实测（2026-10-07，`--dupes`）：305 条导入 POC 的匹配器组合只有 **251 种**，
    **79 条**与别人共用同一份判据 —— 例如 14 条泛微 e-cology（声明成 deserialize / rce /
    sql_injection / 任意用户登录 等**不同漏洞类型**）匹配器一字不差，4 个 Confluence CVE
    也共用同一份"这是不是 Confluence"的指纹。这类条目的真实含义是**产品识别**，
    不是漏洞证明：复核一条就等于复核整组，逐条看是纯浪费；而放开一条也不会带来额外信号。
    """
    cnt = {}
    for r in rows:
        cnt[r["matchers"]] = cnt.get(r["matchers"], 0) + 1
    for r in rows:
        r["dup"] = cnt[r["matchers"]]
    return rows


def dupes(src_dirs=None, min_n=2):
    """按判据分组返回 `[(条数, 匹配器摘要, [id…])]`，用来回答"这 305 条真有 305 份判据吗"。"""
    groups = {}
    for r in candidates(src_dirs=src_dirs):
        groups.setdefault(r["matchers"], []).append(r["id"])
    return sorted(((len(v), k, sorted(v)) for k, v in groups.items() if len(v) >= min_n),
                  key=lambda t: (-t[0], t[1]))[:40]


def write_sheet(rows, out, note=""):
    """出工作表。**复核栏留空** —— 空着就是"没判"，`--import` 不会碰它。"""
    lines = [
        "# 导入 POC 复核工作表",
        "",
        f"- 生成：{datetime.datetime.now():%Y-%m-%d %H:%M:%S}｜`tools/poc_review.py`｜候选 {len(rows)} 条",
        f"- 校准依据：{_rel(CALIB_JSON) if CALIB_JSON.exists() else '（没有校准报告，命中列不作数；先跑 tools/calibrate_pocs.py）'}",
        "- 怎么填：**只在看过「匹配器」那一列之后**，在「复核」栏写 `ok`（= 愿意让它进扫描），"
        "其余一律留空。要否掉就写 `no`，写别的都当没判。",
        "- **先看「同指纹」列**：>1 表示表里还有别人用的是**一字不差**的判据。实测 305 条里 79 条如此"
        "（14 条泛微、7 条致远、4 个 Confluence CVE 各共用一份产品指纹），复核一条=复核整组。",
        "- 搬进去之后会发生什么：来源变成 `user` → 置信度 medium → **有效级别照信模板声明**，"
        "于是它会真的执行（仍受 `checks.skip_severities` / `min_severity` 约束）。"
        "级别与匹配器内容**不会被工具改写**。",
    ]
    if note:
        lines.append(f"- 本次范围：{note}")
    lines += ["", *HEAD]
    for r in rows:
        lines.append("|  | `{id}` | {name} | {declared} | **{effective}** | {confidence} | {tags} | "
                     "`{matchers}` | {calib} | {dup} | `{path}` |".format(**r))
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out


def _parse_sheet(text):
    """从工作表里取出**复核栏写了 ok** 的行 → 文件路径列表。

    **按表头文字定位列**（不是写死第几列）：表是给人编辑的，人可能加列、删列、把「同指纹」挪个位置 ——
    按固定下标解析会在某一天悄悄读错列，而"读错列 = 搬错文件"是这工具最不能犯的错。
    表头找不到「复核」或「文件」两列就直接报错，不猜。
    """
    i_rev = i_file = None
    ok = []
    for line in text.splitlines():
        s = line.strip()
        if not s.startswith("|"):
            continue
        cells = [c.strip().strip("`").strip() for c in s.strip("|").split("|")]
        low = [c.lower() for c in cells]
        if "复核" in low and "文件" in low:
            i_rev, i_file = low.index("复核"), low.index("文件")
            continue
        if i_rev is None or len(cells) <= max(i_rev, i_file):
            continue
        if cells[i_rev].lower() in OK_TOKENS:
            ok.append(cells[i_file])
    if i_rev is None:
        raise SystemExit("[!] 工作表里没有「复核 / 文件」表头 —— 表可能被改坏或不是本工具出的表")
    return ok


def import_ok(sheet_path):
    """按工作表里标了 `ok` 的行，把文件搬进 `config/pocs-user/`（**不覆盖**、不改动原始文件）。"""
    try:
        text = pathlib.Path(sheet_path).read_text(encoding="utf-8")
    except OSError as e:
        print(f"[!] 读不到工作表 {sheet_path}：{e}")
        return 1
    wanted = _parse_sheet(text)
    if not wanted:
        print("[i] 复核栏没有任何 `ok` —— 一条都不搬（这正是默认该有的样子）。")
        print("    要放开某条：在它的「复核」栏写 ok，再重跑 --import。")
        return 0
    DEST_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y-%m-%d")
    moved, skipped = [], []
    for rel in wanted:
        src = (ROOT / rel).resolve()
        # 复核的是**导入目录里那一份**：工作表被改动过、路径指向别处就不搬（防把工作簿外的
        # 东西顺手塞进 user 目录，那等于绕过所有判据直接进扫描）
        if not str(src).startswith(str((ROOT / SRC_DIR_NAME).resolve())) or not src.is_file():
            skipped.append((rel, "不在导入目录内或文件不存在"))
            continue
        dest = DEST_DIR / src.name
        if dest.exists():
            skipped.append((rel, "config/pocs-user/ 已有同名文件（不覆盖）"))
            continue
        body = src.read_text(encoding="utf-8", errors="replace")
        head = (f"# 人工复核后启用（tools/poc_review.py --import，{stamp}）\n"
                f"# 出处：{_rel(src)}（原文件未改动）；本行以上为复核痕迹，模板内容照抄。\n")
        dest.write_text(head + body, encoding="utf-8")
        moved.append(rel)
    print(f"[+] 已按复核结论搬进 config/pocs-user/：{len(moved)} 条" if moved
          else "[i] 标了 ok 的行都没能搬（下面逐条写明为什么）")
    for rel in moved:
        print(f"    · {rel}")
    for rel, why in skipped:
        print(f"    × 跳过 {rel}：{why}")
    if moved:
        runner.sync_pocs()      # 注册表要立刻看见，否则页面与扫描还是旧状态
        print("[+] 已 runner.sync_pocs()：新来源算 `user`（置信度 medium），"
              "有效级别照信模板声明 —— 请确认这确实是你要的执行面")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="导入 POC 的按族复核工作表 / 复核后启用")
    ap.add_argument("--family", action="append", default=None,
                    help="按关键字筛族（可重复；匹配 id/名称/tags/文件名）")
    ap.add_argument("--families", action="store_true", help="只列各族的条数，不出表")
    ap.add_argument("--dupes", action="store_true",
                    help="按「匹配器一字不差」分组列出共用的判据（先看这个再决定要不要逐条复核）")
    ap.add_argument("--all", action="store_true", help="出全表（305 条一张表，给人工分批看）")
    ap.add_argument("--out", default=str(DEFAULT_SHEET), help="工作表落盘路径（默认 logs/poc_review.md）")
    ap.add_argument("--src", action="append", default=None, help="待复核目录（默认 config/pocs-imported）")
    ap.add_argument("--import", dest="imp", metavar="SHEET",
                    help="按工作表里标了 ok 的行，把文件搬进 config/pocs-user/")
    a = ap.parse_args(argv)

    if a.imp:
        return import_ok(a.imp)
    if a.dupes:
        gs = dupes(a.src)
        tot = len(candidates(a.src))
        share = sum(n for n, _, _ in gs)
        print(f"[i] {tot} 条导入 POC 的判据只有 {tot - share + len(gs)} 种："
              f"其中 {share} 条与别人共用**一字不差**的匹配器（列前 {len(gs)} 组）")
        for n, k, ids in gs:
            print(f"  {n:3d} 条｜{k[:100]}")
            print(f"        {'、'.join(ids[:8])}{' …' if len(ids) > 8 else ''}")
        print("    含义：这类条目的真实判据是「这是不是某个产品」，不是「某个漏洞成立」。")
        print("    复核其中一条就等于复核整组；放开其中一条也不会带来额外信号。")
        return 0
    if a.families:
        print("[i] 导入 POC 的族分布（按条数）：")
        for tag, n in families(a.src):
            print(f"    {n:4d}  {tag}")
        print("    （公共标签 imported / ref-poc 不参与统计；挑一族用 --family <名>）")
        return 0
    if not a.family and not a.all:
        print("[!] 要么 --family <关键字>，要么明确 --all。不给默认全表：")
        print("    305 条一张工作表没人会看完，看不完的表等于没判据。")
        return 2
    rows = candidates(a.family or None, a.src)
    if not rows:
        print("[!] 没有匹配的 POC（换个关键字，或先 --families 看有哪些族）")
        return 1
    note = "全部导入 POC" if a.all else "族关键字：" + ", ".join(a.family or [])
    out = write_sheet(rows, pathlib.Path(a.out), note)
    n_ok = sum(1 for r in rows if r["calib"].startswith("命中"))
    print(f"[+] 工作表已写入 {_rel(out)}：{len(rows)} 条（负样本上命中 {n_ok} 条）")
    print("    填法：只在看过「匹配器」列之后在「复核」栏写 ok；然后 --import", _rel(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
