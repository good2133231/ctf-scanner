# -*- coding: utf-8 -*-
"""afrog 外部引擎适配（续121 接入；续149 起**默认开**）：只喂它"只读 + info 级"的 PoC。

默认开的前提是三条闸门都满足才可能真起进程（开关 + `poc_dir` 有只读模板 + 本机装了 afrog），
任何一条不满足都只写一行日志、**零请求**。用户口径："默认把这个启用 并且验证功能"。

定位先说清楚：本框架的检测主力是自己那份 nuclei 兼容子集引擎（`scanner/pocs/engine.py`）。
afrog 的价值是它社区里那批"组件识别"模板 —— 但**判据**已经在续120 按条复核后搬进
`config/dicts/fingerprints_extra.txt` 了；本模块解决的是另一件事：用户自己准备了一批
afrog PoC 目录、想让外部引擎替他跑一遍。所以这里是**适配器**，不是"把 afrog 当主引擎"。

为什么要适配一个外部二进制，就得按它实测的脾气来（下面每条都是本机 v3.5.7 真跑出来的，
不是读文档抄的）：

1. **自动更新检查每次固定 +30 秒**：同一个 PoC 集，不带 `-duc` 是 `30332 ms`，带上是
   `309 ms`（差 98 倍）。这不是"首启动慢"，是**每次调用**都慢 —— 一次扫描要跑 N 次就 N×30s。
2. **默认往进程 CWD 落 HTML 报告**（实测 `<CWD>/reports/*.html`，一次一份 108 KB），`-silent` 挡不住；
   加了 `-doh` 之后**报告文件不再生成，但那个 `reports/` 空目录照建** —— 所以"挡报告"与"换 cwd"
   两件事都要做，只做一件只是碰巧没出事。
   我们的 GUI/CLI 从仓库根启动 ⇒ 不加 `-doh` 就是"每扫一次在仓库根堆一份带着别的目标
   banner 的报告"，`git add .` 顺手就提交上去（fscan 的 `result.txt` 踩过同一坑，见 portscan 注释）。
   ⇒ 既给 `-doh`，也**显式给 cwd**（两件事都要，缺一个都只是"碰巧没出事"）。
3. **stdout 里有 ANSI 转义**（实测 `-silent` 输出含 `\\x1b`）⇒ 不加 `-nc`，下面那句 `[ERR]`
   判定和写进任务日志的文本都是花的。
4. **退出码不可信**：`-P` 指向不存在的目录时 rc 仍是 **0**，只在输出里写
   `Unable to locate a valid afrog PoC YAML file.` ⇒ 只看 rc 会把"一个 PoC 都没加载"
   报成"扫过了、没有结果"（§5.2 那一类静默降级）。
5. **零命中时它根本不写结果文件**（不可达目标 / 0 个 PoC 两种情况实测都没有 JSON）⇒
   文件不存在＝没有命中，**不是**失败；反过来"有 rc=0 也有文件"才是要解析的。
6. **它自带的默认值比我们的红线松**：`-c 25`、`-rl 150` 请求/秒、`-timeout 50` 秒。
   ⇒ 这里全部按策略压低并**封顶**（`_clamp`），并刻意**不传** `-ps`（端口扫描）、
   不传 `-brute*`（它自己的爆破默认最多 5000 请求/规则，属于本框架的越界动作）。
7. **它自管请求，绕过我们的请求预算**：`throttle` 只能限"我们起几个子进程"，限不到 afrog
   内部发多少请求（与 fscan 同一个覆盖缺口）。所以日志里必须把这件事说明白，不假装纳了预算。

只读红线怎么落地：跑之前**自己逐个 YAML 过一遍**（`classify_poc`），只把
`severity ∈ ("", "info")` 且所有请求都是 GET/HEAD、无 body、非 tcp、无 brute 清单的模板
复制进任务目录（`stage`），拒掉的连同原因写进日志 —— 这样即便用户把一个含 RCE/写操作的
目录指进来，落到 afrog 手里的也只有只读那部分（实测：`fingerprinting/` 130 个文件里
21 个 tcp、若干 POST/brute，还有 1 条 HFS RCE）。
"""
import json
import re
import shutil
import tempfile
from pathlib import Path

from .config import resolve
from . import extcost
from .utils import run_cmd, which

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
# rc=0 但实际没干活的那句（实测目录不存在时只有这行错误、退出码仍是 0）
_HARD_ERR_RE = re.compile(r"Unable to locate a valid afrog PoC|panic:|fatal error", re.I)

READ_ONLY_METHODS = ("GET", "HEAD")
OK_SEVERITIES = ("", "info")
# 封顶值（不是"推荐值"）：策略里填更大的数也超不过这里，见 §6 那条"别把上限交给字符串"
CEIL = {"timeout": 30, "concurrency": 25, "rate": 50, "per_target_rate": 25,
        "max_targets": 200, "proc_timeout": 1800}
DEFAULTS = {"enabled": True, "poc_dir": "config/afrog-pocs", "max_targets": 20, "timeout": 8,
            "concurrency": 4, "rate": 10, "per_target_rate": 5, "proc_timeout": 600}

# 结果级别：**只降不升**。afrog 的 `infoseg` 是模板作者自己填的，我们不拿它当依据；
# 能进到这里的前提是"只读 + info 级 PoC"，所以高于 low 的一律按 info 记。
_CARRY_SEVERITIES = ("info", "low")


def cfg(settings):
    """把 `settings.afrog` 与默认值合并，并把每一项压进封顶（负数/空串/乱填都落回默认）。"""
    raw = (settings or {}).get("afrog") or {}
    out = dict(DEFAULTS)
    # 缺键时落回默认（而不是"缺键=关"）：默认档就在 `DEFAULTS` 一处，`settings.yaml` 只写差异。
    out["enabled"] = raw.get("enabled", DEFAULTS["enabled"]) is True
    # 空串同样落回默认目录（续149）：默认预置 `config/afrog-pocs/`，用户清空它不该变成"关"，
    # 而应由 `plan()` 如实报"目录里没有只读模板"——把语义分开，别让两个原因挤成一句话。
    out["poc_dir"] = str(raw.get("poc_dir") or DEFAULTS["poc_dir"]).strip()
    for k in ("max_targets", "timeout", "concurrency", "rate", "per_target_rate", "proc_timeout"):
        try:
            n = int(raw.get(k, DEFAULTS[k]))
        except (TypeError, ValueError):
            n = DEFAULTS[k]
        out[k] = min(n if n > 0 else DEFAULTS[k], CEIL[k])
    return out


def enabled(settings):
    return cfg(settings)["enabled"] is True


def _rules_of(doc):
    rules = doc.get("rules") or {}
    return list(rules.values()) if isinstance(rules, dict) else [rules]


def classify_poc(doc):
    """一份 afrog YAML -> `(能不能喂给 afrog, 原因)`。**只看请求语义，不看判据**。

    与 `tools/import_afrog_fp.py` 的分工：那边要把表达式翻成我们的规则（所以要解析 DSL，
    翻不动就拒），这边只回答"这条模板会不会动目标"，字段级检查足够 —— 刻意不重复那份解析器。
    """
    info = doc.get("info") or {}
    sev = str(info.get("severity") or "").strip().lower()
    if sev not in OK_SEVERITIES:
        return False, f"severity={sev or '空'}（非 info 级模板不喂给外部引擎）"
    rules = _rules_of(doc)
    if not rules:
        return False, "没有 rules 块"
    for r in rules:
        if not isinstance(r, dict):
            return False, "rule 不是映射"
        req = r.get("request") or {}
        if req.get("type") == "tcp" or req.get("steps"):
            return False, "type:tcp 或多步请求（不属于我们的只读单请求语义）"
        if r.get("brute") or req.get("raw") or str(req.get("data") or "").strip():
            return False, "带 brute 清单或原始报文数据"
        method = str(req.get("method") or "GET").upper()
        if method not in READ_ONLY_METHODS:
            return False, f"非只读方法 {method}"
        if str(req.get("body") or "").strip():
            return False, f"{method} 带请求体"
    return True, ""


def plan(poc_dir):
    """目录 -> `(放行的 YAML 列表, [(相对名, 拒因), …])`。解析失败的 YAML 也算拒（不猜）。"""
    import yaml
    root = Path(resolve(str(poc_dir)))
    if not root.is_dir():
        return [], [(str(root.name or root), "不是一个目录")]
    ok, bad = [], []
    for p in sorted(root.rglob("*.y*ml")):
        rel = p.relative_to(root).as_posix()
        try:
            doc = yaml.safe_load(p.read_text(encoding="utf-8", errors="replace")) or {}
        except Exception as e:
            bad.append((rel, f"YAML 解析失败 {type(e).__name__}"))
            continue
        if not isinstance(doc, dict):
            bad.append((rel, "顶层不是映射"))
            continue
        good, why = classify_poc(doc)
        if good:
            ok.append(p)
        else:
            bad.append((rel, why))
    return ok, bad


def stage(files, dest):
    """把放行的 YAML 复制进 `dest`（afrog 的 `-P` 要指着一个只含只读模板的目录）。

    用复制不用符号链接：Windows 上非管理员建不了软链，而这里是"给外部进程读的一批文件"，
    复制没有代价（实测 130 个 YAML ≈ 120 KB）。
    """
    d = Path(dest)
    d.mkdir(parents=True, exist_ok=True)
    n = 0
    for p in files:
        p = Path(p)
        shutil.copyfile(str(p), str(d / p.name))
        n += 1
    return d, n


def build_argv(binary, targets_file, poc_dir, out_file, c):
    """固定 argv。**每一项都有存在的理由，删掉任何一条都会打开上面某个坑**（回归 [8z] 逐条断言）。"""
    return [str(binary),
            "-T", str(targets_file),
            "-P", str(poc_dir),
            "-ja", str(out_file),          # 带 request/response，才有证据可存
            "-curated", "off",             # 不碰它的付费精选源
            "-duc",                        # 实测：省下每次 30 秒
            "-doh",                        # 实测：不挡就会往 CWD 写 reports/*.html
            "-nc", "-silent",              # 无 ANSI、只吐结果行
            "-timeout", str(c["timeout"]),
            "-c", str(c["concurrency"]),
            "-rl", str(c["rate"]),
            "-rlt", str(c["per_target_rate"])]


def parse_result(path):
    """afrog 的 JSON -> 命中列表。**文件不存在＝零命中**（实测），坏 JSON 才算失败。"""
    p = Path(path)
    if not p.exists():
        return []
    text = p.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        return []
    rows = json.loads(text)
    if isinstance(rows, dict):
        rows = [rows]
    return [r for r in rows if isinstance(r, dict) and r.get("isvul") is True]


def _evidence(row):
    """从 `pocresult[]` 里取**最后一次**请求与响应开头（它给的是原始报文文本）。"""
    res = row.get("pocresult") or []
    last = res[-1] if isinstance(res, list) and res else {}
    req = str(last.get("request") or "").split("\n", 1)[0]
    resp = _ANSI_RE.sub("", str(last.get("response") or ""))[:400]
    return (f"请求：{req}\n响应：{resp}" if req or resp else "")


def to_vulns(rows):
    """afrog 命中 -> 我们的 vuln dict（字段口径与 `pocs/engine.py` 一致，落同一张表）。"""
    out = []
    for row in rows:
        info = row.get("pocinfo") or {}
        pid = str(info.get("id") or "").strip()
        if not pid:
            continue
        declared = str(info.get("infoseg") or "").strip().lower()
        sev = declared if declared in _CARRY_SEVERITIES else "info"
        name = str(info.get("infoname") or pid)
        desc = str(info.get("infodescription") or "").strip()
        out.append({
            "poc_id": f"afrog:{pid}",
            "name": name,
            "severity": sev,
            "owasp": "",
            # `fulltarget` 才是**真正命中的那个 URL**（`target` 只是本次输入），报告里要有它
            "target": str(row.get("fulltarget") or row.get("target") or ""),
            "detail": (f"afrog 只读检测命中：{name}"
                       f"（PoC {pid}，模板作者 {info.get('infoauthor') or '?'}，"
                       f"声明级别 {declared or '未标'}）。" + desc)[:1000],
            "evidence": _evidence(row),
        })
    return out


def run(sites, settings, logger=None, workdir=None, throttle=None, binary=None):
    """跑一轮 afrog（只读子集），返回 `(vulns, 说明)`；任何失败都不抛，只写日志。

    `说明` 的前缀是**给调用方分档**用的（续149，三档别混成一个）：
      · `!` 开头 = **没跑成**（二进制起不来 / 超时 / 硬错 / 结果不是 JSON / 预算拦下）→ 调用方报 warning；
      · `~` 开头 = **按设计跳过**（未启用 / 没装二进制 / 没配或空的 PoC 目录 / 目录里没有只读模板）
        → 调用方报 info，**不当错误**（默认开之后，没装 afrog 的机器每次扫描都会走到这条，别刷警告）；
      · 其余 = 真跑了一轮（`命中 N 条` 等）。
    """
    c = cfg(settings)
    urls = []
    for s in sites or []:
        u = (s.get("url") if isinstance(s, dict) else str(s)) or ""
        u = u.strip()
        if u and u not in urls:
            urls.append(u)
    urls = urls[: c["max_targets"]]
    if not urls:
        return [], "~没有可交给 afrog 的站点"
    if not c["enabled"]:
        return [], "~afrog 未启用"
    poc_dir = c["poc_dir"]
    if not str(poc_dir).strip():
        return [], "~未配置 afrog PoC 目录（afrog.poc_dir），跳过外部引擎"
    bin_path = binary or which((settings.get("tools") or {}).get("afrog") or "afrog")
    if not bin_path:
        return [], "~未安装 afrog 二进制（外部工具页装好后会把路径写回 tools.afrog），跳过外部引擎"

    ok_files, refused = plan(poc_dir)
    if not ok_files:
        # 目录不存在＝配置错（`!`）；目录在但一条只读模板都没有＝按设计跳过（`~`）。两种原因分开报。
        if len(refused) == 1 and refused[0][1] == "不是一个目录":
            return [], f"!afrog 的 PoC 目录不存在：{poc_dir}"
        return [], f"~PoC 目录里没有只读模板（拒掉 {len(refused)} 个），跳过外部引擎"
    # 续128：**请求由 afrog 自己发，本任务的预算与限速拦不住它** —— 所以这里既把预估打出来，
    # 也在设了上限时真的不起进程。上限默认 0（不限），不改既有行为；但一旦设了就必须咬得住，
    # 否则"上限"只是一个装饰数字。
    cost = extcost.afrog(len(urls), len(ok_files), settings)
    if cost["over"]:
        return [], "!" + cost["block"]
    wd = Path(workdir) if workdir else Path(tempfile.mkdtemp(prefix="afrog-"))
    wd.mkdir(parents=True, exist_ok=True)
    staged, n_staged = stage(ok_files, wd / "afrog-pocs")
    tfile = wd / "afrog-targets.txt"
    tfile.write_text("\n".join(urls) + "\n", encoding="utf-8")
    out_file = wd / "afrog-result.json"
    if out_file.exists():
        out_file.unlink()                       # 上一轮的残留会被当成这一轮的命中
    argv = build_argv(bin_path, tfile, staged, out_file, c)
    rc, out, err = run_cmd(argv, cwd=str(wd), timeout=c["proc_timeout"], throttle=throttle)
    text = _ANSI_RE.sub("", (out or "") + (err or ""))
    if rc == 124:
        return [], f"!afrog 超时（{c['proc_timeout']} 秒）被终止"
    if rc == 127:
        return [], "!afrog 起不来（127：二进制不存在或不可执行）"
    if _HARD_ERR_RE.search(text):
        # 实测：这种失败 rc 仍是 0 —— 只看退出码就会把它报成"扫过了，没有结果"
        return [], f"!afrog 没干活：{next((ln.strip() for ln in text.splitlines() if _HARD_ERR_RE.search(ln)), '')}"
    try:
        rows = parse_result(out_file)
    except (json.JSONDecodeError, ValueError) as e:
        return [], f"!afrog 结果文件不是合法 JSON（{type(e).__name__}）"
    vulns = to_vulns(rows)
    # 实际下发用的是 `n_staged`（复制进任务目录的那份子集），预估必须用**同一个数**
    # —— 用 `len(ok_files)` 会在复制失败时让日志里的数字比真实的小，而数字是给人的判断依据。
    cost2 = extcost.afrog(len(urls), n_staged, settings)
    note = (f"afrog：{len(urls)} 站点 × {n_staged} 只读 PoC（拒收 {len(refused)} 个非只读/非 info），"
            f"命中 {len(vulns)} 条"
            + (f"；rc={rc}（它的退出码不可信，判定看结果文件）" if rc != 0 else ""))
    if logger:
        logger.info(f"[afrog] {note}")
        logger.info("[afrog] 请求由外部进程自管，**不经过本任务的请求预算**"
                    f"（全局 -rl {c['rate']}/s、单目标 -rlt {c['per_target_rate']}/s、并发 -c {c['concurrency']}）")
        # 预估数字**无论有没有设上限都要打**（续128）：这一处的下限是"如实声明"，
        # 有闸没数字是装饰，有数字没闸是唠叨。
        logger.info(f"[afrog] {cost2['line']}")
        for name, why in refused[:10]:
            logger.debug(f"[afrog] 拒收 {name}：{why}")
        if len(refused) > 10:
            logger.debug(f"[afrog] 另有 {len(refused) - 10} 个模板被拒（同上口径）")
    return vulns, note
