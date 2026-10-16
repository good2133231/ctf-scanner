#!/usr/bin/env python3
"""把**外部开源指纹库**的规则转成本项目的外置指纹表（`config/dicts/fingerprints_*.txt`）。

为什么要有这个脚本（续197，主理人点单"指纹识别可以参照 github 现有的来集合，
包括但不限于 FingerprintHub，不要我给了你你就自己偷懒不去查了，有些东西越多越好"）：

- 内置 `SIGNATURES` 是**手写**的百来条，覆盖的是服务器/CDN/语言/常见中间件这种"大类"；
  真正的**产品级**指纹（几千种 CMS / OA / 面板 / 设备后台）手写得写不过来，
  而社区库已经整理好了 —— 抄判据是正当的，抄**代码**不是。
- 因此本脚本的定位是**一次性转换器**：把外部规则**读进来、转成我们自己的表、落盘**，
  外部仓库本身**不进本仓**（不 vendor、不 git submodule、不留它的源码）。
  重跑本脚本＝重新生成那张表。

已接的源（都可以只给一部分，`--src` 指向它的规则目录即可）：
- **FingerprintHub** / ObserverWard 指纹库（`web-fingerprint/*.yaml`，nuclei 风格）；
- **EHole（棱洞）** 的 `fingerprint.json`（`fingerprint[].{name,location,keyword,method}`）；
- **Glass**（`*.json`，`{name, rule: {header|body: [...]}}` 形状，识别到才导）。

转成什么：与 `tools/import_afrog_fp.py` **同一份目标格式**（TAB 分隔）——
`标签 <TAB> 位置 <TAB> 正则 <TAB> 状态码 <TAB> 来源 <TAB> 说明`
由 `scanner/fingerprint.py::load_extra` 读取。同一份格式才不会有第二套解析逻辑。

三条硬口径（都是"宁可少导，不可误报"）：
1. **只导首页探针的判据**。我们的 `identify()` 吃的是根响应（以及 dirscan 补标通道喂回来的
   正文），把 `/login`、`/druid/index.html` 这类路径的特征打到根响应上就是自己制造误报
   —— 续127 的实测结论正是"外置表里 47/51 条因为只在这些路径出现而永不触发"。
   ⇒ 只认 `path` 为 `{{BaseURL}}/`（或 `{{BaseURL}}`）的那条探针。
2. **判据必须能 `re.compile`**。外部规则是别的引擎的方言，编译不过的一律丢掉并计数，
   **绝不**悄悄改成"能编译但语义变了"的东西。同时丢掉过短的关键词（默认 < 4 字符），
   太短的串在正文里到处都是。
3. **`and` 用前向断言表达，不拆成多条 OR**。我们的表是"同一标签的规则任一命中即算"，
   把 `condition: and` 拆成两行就等于放宽成 or —— 那会改变上游的判定强度。
   等价写法是"整条锚在开头 + 每个关键词一个前向断言"（见 `_word_regex` 的 and 分支，
   那里连"为什么必须锚定、不锚定会慢多少"都写了实测数字）。

用法：
    python3 tools/import_fingerprints.py --src /path/to/FingerprintHub/web-fingerprint \\
        --kind fingerprinthub --out config/dicts/fingerprints_hub.txt

落盘的表**默认不直接生效**（`EXTRA_FILES` 里登记才会被加载）—— 先 `--dry-run` 看统计，
再决定要不要启用。
"""
import argparse
import json
import re
import sys
from pathlib import Path

MIN_WORD = 4          # 短于此长度的关键词不导（见口径 2）
MAX_RULES = 20000     # 安全阀：一次导入的规则条数上限，防止把某个源整份糊进来


def _norm_tag(name, fallback=""):
    """标签归一：小写、非法字符统一成 `-`、去首尾连字符。

    **放行 CJK**（`\u4e00-\u9fff`）：EHole 那张表里 `cms` 大量是中文（"致远OA"、
    "iDS联网数字标牌管理系统"），只按 ASCII 过滤会把它们全洗成空标签 —— 那等于整份表白导。
    """
    t = re.sub(u"[^0-9a-zA-Z._\u4e00-\u9fff-]+", "-", str(name or fallback or "").strip().lower())
    return t.strip("-._")[:40]


def _ci(flag):
    return "i" if flag else ""


# 续197 实测：EHole 那张表把一个产品的关键词列成**数组**，里面既有特有串
# （`/seeyon/USER-DATA/IMAGES/LOGIN/login.gif`）也混着 `login`、`index.php` 这种
# **任何网页都有**的串。而"同一标签的规则任一命中即算" ⇒ 只要页面里出现 login
# 就会被打成"秦川燃气综合管理系统 / 通达OA / grafana …"——实测一份合成通用登录页
# 一次命中 37 个互不相关的标签。这种"全中"比全不中更糟：真正命中的那几个被淹没了。
# 因此过短的串（MIN_WORD）之外，还要有一道**通用词黑名单**；过滤完一条不剩 ⇒ 这条规则不导。
GENERIC_WORDS = {
    # 英文
    "login", "log in", "logon", "signin", "sign in", "logout", "index.php", "index.html",
    "index", "admin", "administrator", "password", "passwd", "username", "user", "users",
    "system", "default", "home", "main", "css", "js", "images", "image", "img", "static",
    "common", "assets", "content", "upload", "uploads", "api", "www", "http", "https",
    "title", "body", "html", "head", "script", "style", "form", "input", "button", "submit",
    # 中文
    "登录", "登陆", "系统", "管理系统", "用户名", "密码", "首页", "后台", "管理", "主页",
    "欢迎", "注册", "忘记密码", "请输入",
    # 静态资源路径片段（续197 实测：EHole 里有 `js/app` 这种，任何站点都命中）
    "js/app", "js/index", "js/main", "css/style", "css/main", "static/js", "static/css",
    "images/logo", "img/logo",
    # **服务器通用形态**（续197 实测：这批串会让"nginx 目录列表页"被打上 igenus / 齐治堡垒机 /
    # 化视私云 等一长串产品名 —— 它们的判据里塞了 autoindex / Index of 这类通用串）。
    # 认出"这是个目录列表页"有别的途径（内置表 + 页面的其它特征），不需要靠误报来换。
    "index of", "index of /", "autoindex", "directory listing", "目录列表", "列目录",
    "parent directory", "welcome to nginx", "apache2 ubuntu default page",
    "apache2 debian default page", "it works!", "iis7", "iis8.5", "iis windows server",
    # 续199（按 `tools/calibrate_fingerprints.py` 的负样本逐条回捞，清单与实测对应）：
    # 下面每一个都对应**真实观察到**的误报，不是凭感觉列的。
    #  · `login.php` —— 一个词污染 7 条规则（igenus / phpoa / 化视私云 / 电信网关 /
    #    百卓 / 碧海云盒 / 齐治堡垒机），国产后台的登录页几乎都叫这个名字；
    #  · `theme`（douphp）、`_next`（kan：任何 Next.js 站点都命中，等于没判据）、
    #    `language`（igenus）、`360.cn`（电信网关：外链不是自家特征）；
    #  · 宝塔那组"没有找到站点 / 可能原因 / CDN产品 / Web服务 / 检查端口是否正确"是
    #    **通用错误页文案**（谁家都能长这样），它真正的特征是 `bt.cn` 与"宝塔Linux面板"，
    #    去掉这些通用串后识别能力一点没少。
    "login.php", "/login", "theme", "_next", "language", "360.cn",
    "没有找到站点", "可能原因", "cdn产品", "web服务", "检查端口是否正确",
}


def _word_regex(words, case_insensitive, condition):
    """nuclei 的 word 匹配器 -> 一条 Python 正则（见口径 3）。"""
    ws = [str(w) for w in (words or []) if str(w).strip()]
    ws = [w for w in ws
          if len(w) >= MIN_WORD and w.strip().lower() not in GENERIC_WORDS]
    if not ws:
        return ""
    alts = "|".join(re.escape(w) for w in ws)
    if condition == "and":
        # 每个词都要出现：用前向断言串起来；(?s) 让 `.` 跨行（页面正文几乎都有换行）。
        #
        # ⚠ `^` **必须写**（续197 实测，代价是几十倍）：不锚定时引擎会在**每一个**位置
        # 试一遍 `(?=.*w)`，而 `.*` 每次都要扫到文本末尾 ⇒ 单条规则在 3 KB 正文上就要 40+ ms、
        # 在 100 KB 上直接卡死（4468 条规则里 456 条是 and 类，扫描一轮 9.45 s）。
        # 锚到开头后每个断言只扫一遍，成本降到 O(词数 × 正文长度)。
        return "(?%ss)^%s" % (_ci(case_insensitive),
                              "".join("(?=.*%s)" % re.escape(w) for w in ws))
    return "(?%s)(?:%s)" % (_ci(case_insensitive), alts)


def _regex_merge(regexes, case_insensitive):
    rs = [str(r) for r in (regexes or []) if str(r).strip()]
    if not rs:
        return ""
    body = "|".join("(?:%s)" % r for r in rs)
    return "(?%s)%s" % (_ci(case_insensitive), body) if len(rs) > 1 or case_insensitive else rs[0]


def _part_of(m):
    """nuclei 的 part -> 我们的位置（headers/body/cookies）。"""
    p = str(m.get("part") or "body").strip().lower()
    if p in ("header", "headers", "all"):
        return "headers"          # 'all' 也按 headers 处理：头比正文短得多，误报面小
    if p == "cookie":
        return "cookies"
    return "body"


def from_fingerprinthub(src, verified_only=True):
    """FingerprintHub / ObserverWard 的 yaml 规则 -> `[(标签, 位置, 正则), ...]`。

    `verified_only`（默认开）：只导 `info.metadata.verified: true` 的那批。
    为什么默认要这道闸（续197 实测踩出来的）：整份 3413 个文件里大量规则的判据是
    "登录""管理系统""admin" 这种通用词 —— 拿一份**合成的通用登录页**去试，不加这道闸时
    一次命中 38 个互不相关的标签（天融信 / 深信服 / 海康威视…），这种"全中"比全不中更糟：
    它会淹没真正命中的那几个。`verified: true` 是上游自己标的人工核验结论，
    用它当默认档是"宁可少导，不可误报"（口径 2 那条的同款取舍）。要全量用 `--all`。
    """
    try:
        import yaml
    except ImportError:
        print("[!] 需要 PyYAML：pip install pyyaml", file=sys.stderr)
        return [], {}
    stat = {"files": 0, "bad_yaml": 0, "matchers": 0, "skipped_path": 0,
            "favicon": 0, "negative": 0, "compile_fail": 0, "short": 0, "unverified": 0}
    out = []
    # 目录是**两层**：`web-fingerprint/<组件名>/<规则>.yaml`（一个组件可能有好几个规则文件，
    # 例如同一产品的不同固件版本），所以要递归找 —— 只看一层会一条都读不到。
    for f in sorted(Path(src).rglob("*.y*ml")):
        stat["files"] += 1
        try:
            data = yaml.safe_load(f.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            stat["bad_yaml"] += 1
            continue
        if not isinstance(data, dict):
            continue
        info = data.get("info") or {}
        if verified_only and not ((info.get("metadata") or {}).get("verified") is True):
            stat["unverified"] += 1
            continue
        tag = _norm_tag(info.get("name") or data.get("id"), f.stem)
        if not tag:
            continue
        for probe in (data.get("http") or []):
            if not isinstance(probe, dict):
                continue
            # 口径 1：只认首页探针
            paths = [str(p) for p in (probe.get("path") or [])]
            if paths and not any(p.rstrip("/").endswith("{{BaseURL}}") or
                                 p.replace("{{BaseURL}}", "").strip("/") == "" for p in paths):
                stat["skipped_path"] += 1
                continue
            for m in (probe.get("matchers") or []):
                if not isinstance(m, dict):
                    continue
                stat["matchers"] += 1
                if m.get("negative"):
                    stat["negative"] += 1
                    continue
                kind = str(m.get("type") or "").strip().lower()
                if kind == "favicon":
                    stat["favicon"] += 1
                    continue
                ci = bool(m.get("case-insensitive", False))
                cond = str(m.get("condition") or "or").strip().lower()
                if kind == "word":
                    rx = _word_regex(m.get("words"), ci, cond)
                elif kind == "regex":
                    if len(str(m.get("regex") or "")) < 0:
                        continue
                    rx = _regex_merge(m.get("regex") or [], ci)
                else:
                    continue
                if not rx:
                    stat["short"] += 1
                    continue
                try:
                    re.compile(rx)
                except re.error:
                    stat["compile_fail"] += 1
                    continue
                out.append((tag, _part_of(m), rx))
    return out, stat


def from_ehole(src):
    """EHole(棱洞) 的 fingerprint.json -> 同样的三元组。"""
    p = Path(src)
    if p.is_dir():
        # EHole 主分支里那个文件叫 `finger.json`（旧版与一些 fork 叫 fingerprint.json），
        # 两个名字都认：找不到就报 missing，不猜第三个名字。
        for name in ("finger.json", "fingerprint.json", "fingerprints.json"):
            if (p / name).exists():
                p = p / name
                break
        else:
            return [], {"missing": 1}
    if not p.exists():
        return [], {"missing": 1}
    try:
        data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except Exception as e:
        print(f"[!] EHole 规则读不出来：{e}", file=sys.stderr)
        return [], {"bad_json": 1}
    if isinstance(data, dict):
        data = data.get("fingerprint") or []
    stat = {"files": 1, "matchers": 0, "compile_fail": 0, "short": 0}
    out = []
    for item in (data or []):
        if not isinstance(item, dict):
            continue
        tag = _norm_tag(item.get("cms") or item.get("name"))
        if not tag:
            continue
        loc = str(item.get("location") or "body").strip().lower()
        # EHole 有 `location: title`（只匹配 `<title>`）。我们没有 title 这一档位置，
        # 归到 body —— 标题就在正文里，代价是正文中出现同样的字也算命中（比漏掉强）。
        where = "headers" if loc in ("header", "headers") else "body"
        kws = item.get("keyword") or []
        if isinstance(kws, str):
            kws = [kws]
        stat["matchers"] += 1
        rx = _word_regex(kws, True, "or")
        if not rx:
            stat["short"] += 1
            continue
        try:
            re.compile(rx)
        except re.error:
            stat["compile_fail"] += 1
            continue
        out.append((tag, where, rx))
    return out, stat


def from_glass(src):
    """Glass 的 *.json（`{name, rule:{header|body:[...]}}`）-> 同样的三元组。"""
    stat = {"files": 0, "matchers": 0, "compile_fail": 0, "short": 0}
    out = []
    for f in sorted(Path(src).glob("*.json")):
        stat["files"] += 1
        try:
            data = json.loads(f.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        items = data if isinstance(data, list) else [data]
        for item in items:
            if not isinstance(item, dict):
                continue
            tag = _norm_tag(item.get("name"))
            rule = item.get("rule") or {}
            if not tag or not isinstance(rule, dict):
                continue
            for key, where in (("header", "headers"), ("headers", "headers"),
                               ("body", "body")):
                for kw in (rule.get(key) or []):
                    stat["matchers"] += 1
                    rx = _word_regex([kw], True, "or")
                    if not rx:
                        stat["short"] += 1
                        continue
                    try:
                        re.compile(rx)
                    except re.error:
                        stat["compile_fail"] += 1
                        continue
                    out.append((tag, where, rx))
    return out, stat


def from_fingers(src):
    """chainreactors/fingers 的 `fingerprints/*.yaml`（续204，第三个源）。

    形状（每个条目 = 一个产品，`rule` 是可选的**多条**判据，任一命中即算）：
        - name: Wakapi
          rule:
            - regexps:
                body:    [<title>wakapi …</title>, …]     # 只看正文
            - regexps:
                regexp:  [<meta name="generator" …>, …]   # 整个响应
    映射：`regexps.body` → body、`regexps.regexp` → body（fingers 里它指整个响应，
    保守落到正文 —— 落到 headers 会把大量只出现在 body 的特征判成"看不到"）、
    `regexps.header` → headers（若该版本有）。

    选它而不选 Glass / TideFinger 的原因写在报告里：那两个的规则在 **Python 源码**里
    （Glass 的 `config/rules.py`、TideFinger 是 Python2），取规则就要**执行外部代码**，
    那是另一条安全边界，本脚本不做。fingers 的规则是**数据文件**，与另两个源同级。
    """
    try:
        import yaml
    except ImportError:
        print("[!] 需要 PyYAML：pip install pyyaml", file=sys.stderr)
        return [], {}
    stat = {"files": 0, "matchers": 0, "compile_fail": 0, "short": 0}
    out = []
    for f in sorted(Path(src).rglob("*.y*ml")):
        if f.name in ("port.yaml", "aliases.yaml"):     # 端口表/别名表不是 Web 指纹
            continue
        stat["files"] += 1
        try:
            data = yaml.safe_load(f.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        if not isinstance(data, list):
            continue
        for item in data:
            if not isinstance(item, dict):
                continue
            tag = _norm_tag(item.get("name"), f.stem)
            if not tag:
                continue
            for rule in (item.get("rule") or []):
                regs = ((rule or {}).get("regexps") or {})
                for key, where in (("body", "body"), ("regexp", "body"), ("header", "headers")):
                    for pat in (regs.get(key) or []):
                        pat = str(pat or "").strip()
                        if not pat:
                            continue
                        stat["matchers"] += 1
                        try:
                            re.compile(pat)
                        except re.error:
                            stat["compile_fail"] += 1
                            continue
                        out.append((tag, where, pat))
    return out, stat


KINDS = {"fingerprinthub": from_fingerprinthub, "ehole": from_ehole,
         "fingers": from_fingers, "glass": from_glass}


def main(argv=None):
    ap = argparse.ArgumentParser(description="把外部指纹库转成本项目的外置指纹表")
    ap.add_argument("--src", required=True, help="外部规则的目录（或 EHole 的 fingerprint.json）")
    ap.add_argument("--kind", required=True, choices=sorted(KINDS), help="源的格式")
    ap.add_argument("--out", help="输出文件（默认按 kind 放到 config/dicts/）")
    ap.add_argument("--all", action="store_true",
                    help="连**未经上游核验**的规则也导（默认只导 verified: true 的那批）")
    ap.add_argument("--dry-run", action="store_true", help="只统计不落盘")
    args = ap.parse_args(argv)

    if args.kind == "fingerprinthub":
        rules, stat = from_fingerprinthub(args.src, verified_only=not args.all)
    else:
        rules, stat = KINDS[args.kind](args.src)
    # 去重（同一标签 + 同一位置 + 同一正则）
    seen, uniq = set(), []
    for t, w, r in rules:
        k = (t, w, r)
        if k in seen:
            continue
        seen.add(k)
        uniq.append((t, w, r))
    if len(uniq) > MAX_RULES:
        print(f"[!] 规则数 {len(uniq)} 超过安全阀 {MAX_RULES}，拒绝落盘（先看看是不是指错了目录）")
        return 2
    tags = len({t for t, _, _ in uniq})
    print(f"[i] {args.kind}: 读 {stat.get('files', 0)} 个文件 / {stat.get('matchers', 0)} 个匹配器"
          f" → 导出 {len(uniq)} 条规则、覆盖 {tags} 个标签")
    print(f"[i] 丢弃：非首页路径 {stat.get('skipped_path', 0)}、favicon {stat.get('favicon', 0)}、"
          f"取反 {stat.get('negative', 0)}、过短 {stat.get('short', 0)}、"
          f"编译不过 {stat.get('compile_fail', 0)}、坏文件 {stat.get('bad_yaml', 0)}、"
          f"未验证 {stat.get('unverified', 0)}")
    if args.dry_run:
        print("[i] --dry-run：不落盘")
        return 0

    out = Path(args.out or f"config/dicts/fingerprints_{args.kind}.txt")
    out.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        f"# 自动生成：tools/import_fingerprints.py --kind {args.kind}，请勿手工编辑（重跑会覆盖）",
        f"# 来源：{args.kind}（开源社区指纹库；只转换判据，外部仓库源码不进本仓）",
        "#",
        "# 格式（TAB 分隔，后三段可省）：标签 <TAB> 位置 <TAB> 正则 <TAB> 状态码 <TAB> 来源 <TAB> 说明",
        "#   位置：headers | body | cookies；状态码留空＝不分状态。",
        f"# 共 {len(uniq)} 条规则 / {tags} 个标签；导入时的丢弃统计见脚本输出。",
        "",
    ]
    for t, w, r in uniq:
        lines.append("\t".join([t, w, r, "", args.kind, ""]))
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[+] 已写入 {out}（{len(uniq)} 条规则）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
