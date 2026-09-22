"""把参考项目（myscan_20250825）的 Python POC 静态转换成本引擎的 YAML POC。

背景与可行性结论（重要，先读）：
- 参考项目的 POC 是 Python 类脚本：`class Script(BaseScript)`，在 `__init__` 里声明
  `detect_path_list` / `exec_path_list` / `favicon_md5_list` / `bug_level` / `bug_type`，
  再用 `async def detect()/exec()` 发请求并做 `if '<关键字>' in text` 判定。
- 直接 import 它们不可行：依赖对方整条 core 链（`AsyncFetcher`、`GlobalVariableManager`、
  `BugLevel`、`core.myenums`、aiohttp…），等于搬一整套框架进来。
- **静态提取可行**：真正决定"打哪个路径、看哪个关键字、什么级别"的信息，90% 是字面量、
  用 `ast` 就能读出来。于是本脚本把它们翻译成我们引擎的 YAML（等价于 nuclei 的
  `path + word matcher` 语义），从而**零依赖复用**这 150 组针对国产 OA/设备/中间件的检测逻辑。

用法：
    py -3 tools/import_ref_pocs.py                     # 默认源为下面的 REF_SRC
    py -3 tools/import_ref_pocs.py --src <目录> --out <目录> [--limit N]

产物落在 config/pocs-imported/，且在 `db.default_poc_enabled()` 中**默认关闭**：
导入 POC 以关键字命中为主，误报率明显高于手写 POC，需要人工在 POC 管理页挑选后启用。
"""
import argparse
import ast
import pathlib
import re
import sys

DEFAULT_SRC = pathlib.Path(r"C:\Users\材料\Desktop\tools\scan\myscan_20250825\exploit\scripts")
DEFAULT_OUT = pathlib.Path(__file__).resolve().parent.parent / "config" / "pocs-imported"

# 关键字黑名单：这些字符串是调用参数/常量而非检测特征
STOPWORDS = {
    "utf-8", "utf8", "gbk", "gb2312", "text/html", "application/json", "application/xml",
    "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "http", "https", "text", "json",
    "timeout", "headers", "verify", "allow_redirects", "data", "params", "cookies",
    "True", "False", "None", "print", "info", "warning", "error", "debug",
    # 下面这些是返回值字典的键名，纯属噪声（会被"只取 in 比较"过滤）
    "name", "url", "title", "software", "type", "code", "msg", "path", "status",
    "value", "id", "key", "host", "port", "scheme", "length", "body", "header",
    "content-type", "user-agent", "accept", "referer", "location", "server",
}

LEVEL_MAP = {
    "CRITICAL": "critical", "HIGH": "high", "MIDDLE": "medium", "MEDIUM": "medium",
    "LOW": "low", "INFO": "info", "NONE": "info",
}


def _literal(node):
    """把 AST 字面量转成 Python 对象；非字面量返回 None。"""
    try:
        return ast.literal_eval(node)
    except Exception:
        return None


def _attr_name(node):
    """取出 `BugLevel.HIGH` 里的 'HIGH'。"""
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return ""


def _str_list(node):
    """取 List/Tuple 里的纯字符串元素（忽略 f-string 与变量）。"""
    out = []
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        for el in node.elts:
            if isinstance(el, ast.Constant) and isinstance(el.value, str):
                out.append(el.value)
    elif isinstance(node, ast.Constant) and isinstance(node.value, str):
        out.append(node.value)
    return out


def _str_consts(node):
    """取出节点里的纯字符串常量（常量本身 / 常量元组 / 常量列表）。"""
    out = []
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        out.append(node.value)
    elif isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        for el in node.elts:
            if isinstance(el, ast.Constant) and isinstance(el.value, str):
                out.append(el.value)
    return out


def _accept_keyword(s):
    """判断一个字符串是否适合当"检测关键字"。

    只收 4~80 字符、不含占位符/正则元字符、不在噪声黑名单里的**具体特征串**
    （如 `<title>360终端安全管理系统</title>`），避免退化成"什么都命中"。
    """
    if not (4 <= len(s) <= 80) or s in STOPWORDS:
        return False
    if s.lower() in STOPWORDS:
        return False
    if s.startswith(("http://", "https://")):
        return False
    if "{" in s or "\\" in s or "%" in s:
        return False
    # 纯小写英文单词（含 _ -）多为字典键/参数名，信息量低
    if re.fullmatch(r"[a-z][a-z0-9_\-]{3,}", s):
        return False
    return True


def keywords_from_method(node):
    """从 detect()/exec() 方法体里提取检测特征。

    只认**参与判定**的字符串，而不是方法体里出现的所有字符串：
      - `'xxx' in text` / `'xxx' not in text`（参考项目最常见的写法）
      - `text.find('xxx')` / `text.index('xxx')`
    这样能天然滤掉 `return {'name': ..., 'url': ...}` 这类字典键噪声。
    """
    kws = []
    for sub in ast.walk(node):
        if isinstance(sub, ast.Compare):
            for op, right in zip(sub.ops, sub.comparators):
                if isinstance(op, (ast.In, ast.NotIn)):
                    for s in _str_consts(sub.left) + _str_consts(right):
                        if _accept_keyword(s):
                            kws.append(s)
        elif isinstance(sub, ast.Call) and _attr_name(sub.func) in ("find", "index"):
            for arg in sub.args:
                for s in _str_consts(arg):
                    if _accept_keyword(s):
                        kws.append(s)
    return kws


def parse_script(path):
    """解析单个脚本，返回 dict 或 None（不可转换时返回 None）。"""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except SyntaxError:
        return None

    info = {"paths": [], "keywords": [], "level": "medium", "bug_type": "",
            "name": "", "favicon": [], "has_detect": False}
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        methods = {n.name: n for n in node.body if isinstance(n, (ast.FunctionDef,
                                                                 ast.AsyncFunctionDef))}
        info["has_detect"] = "detect" in methods or "exec" in methods
        for mnode in methods.values():
            for sub in ast.walk(mnode):
                if not isinstance(sub, ast.Assign):
                    continue
                for tgt in sub.targets:
                    if not (isinstance(tgt, ast.Attribute)
                            and isinstance(tgt.value, ast.Name)
                            and tgt.value.id == "self"):
                        continue
                    key, val = tgt.attr, sub.value
                    if key in ("detect_path_list", "exec_path_list", "path_list"):
                        info["paths"].extend(_str_list(val))
                    elif key == "favicon_md5_list":
                        info["favicon"].extend(_str_list(val))
                    elif key == "bug_level":
                        info["level"] = LEVEL_MAP.get(_attr_name(val).upper(), "medium")
                    elif key == "bug_type":
                        lit = _literal(val)
                        info["bug_type"] = lit if isinstance(lit, str) else _attr_name(val)
                    elif key in ("name", "poc_name"):
                        lit = _literal(val)
                        if isinstance(lit, str):
                            info["name"] = lit
        # 检测关键字：只从判定语句里取
        for mname in ("detect", "exec", "verify"):
            mnode = methods.get(mname)
            if mnode:
                info["keywords"].extend(keywords_from_method(mnode))

    if not info["has_detect"]:
        return None
    return info


def build_yaml(vendor, stem, info):
    """生成 YAML 文本（手工拼装，避免依赖 PyYAML：转换工具本身要能裸跑）。"""
    def q(s):
        return '"' + str(s).replace("\\", "\\\\").replace('"', '\\"') + '"'

    paths = sorted(dict.fromkeys(info["paths"]))[:12]
    # 关键字取"最长优先"：越长的特征串越具体、误报越低
    words = sorted(dict.fromkeys(info["keywords"]), key=lambda s: (-len(s), s))[:8]
    tags = ["imported", vendor.lower(), "ref-poc"]
    if info["bug_type"]:
        tags.append(re.sub(r"[^a-z0-9]+", "-", info["bug_type"].lower()).strip("-"))
    desc = (f"由参考项目脚本静态导入：{vendor}/{stem}"
            f"（类型 {info['bug_type'] or '未知'}）。")
    if info["favicon"]:
        desc += f" 原脚本另含 favicon 指纹 {info['favicon'][:3]}，本引擎暂不支持 favicon 匹配。"
    lines = [
        f"# 自动生成：tools/import_ref_pocs.py，请勿手工编辑（重跑会覆盖）",
        f"id: ref-{vendor.lower()}-{stem.lower()}",
        "info:",
        f"  name: {q(vendor + ' ' + stem)}",
        "  author: imported-from-myscan",
        f"  severity: {info['level']}",
        f"  tags: [{', '.join(tags)}]",
        f"  description: {q(desc)}",
        "http:",
        "  - method: GET",
        "    path:",
    ]
    lines += [f"      - {q(p if str(p).startswith('/') else '/' + str(p))}" for p in paths]
    lines += [
        "    matchers-condition: and",
        "    matchers:",
        "      - type: status",
        "        status: [200]",
        "      - type: word",
        "        part: body",
        "        condition: or",
        "        words:",
    ]
    lines += [f"          - {q(w)}" for w in words]
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser(description="导入参考项目的 Python POC 为 YAML")
    ap.add_argument("--src", default=str(DEFAULT_SRC), help="参考项目 exploit/scripts 目录")
    ap.add_argument("--out", default=str(DEFAULT_OUT), help="输出目录")
    ap.add_argument("--limit", type=int, default=0, help="最多转换多少个（0=全部）")
    args = ap.parse_args()

    src, out = pathlib.Path(args.src), pathlib.Path(args.out)
    if not src.is_dir():
        print(f"[!] 源目录不存在：{src}")
        return 2
    out.mkdir(parents=True, exist_ok=True)

    stat = {"files": 0, "converted": 0, "no_path": 0, "no_kw": 0, "skipped": 0}
    for f in sorted(src.rglob("*.py")):
        if f.name.startswith("__"):
            continue
        stat["files"] += 1
        info = parse_script(f)
        if not info:
            stat["skipped"] += 1
            continue
        if not info["paths"]:
            stat["no_path"] += 1
            continue
        if not info["keywords"]:
            stat["no_kw"] += 1
            continue
        vendor = f.parent.name if f.parent != src else "root"
        stem = re.sub(r"[^0-9A-Za-z_\-]+", "_", f.stem)[:60]
        (out / f"{vendor}__{stem}.yaml").write_text(
            build_yaml(vendor, f.stem, info), encoding="utf-8")
        stat["converted"] += 1
        if args.limit and stat["converted"] >= args.limit:
            break

    print(f"[+] 扫描脚本 {stat['files']} 个 → 生成 {stat['converted']} 个 YAML 到 {out}")
    print(f"    - 跳过（非 Script 类）：{stat['skipped']}")
    print(f"    - 无 detect/exec 路径声明：{stat['no_path']}")
    print(f"    - 无可静态提取的检测关键字：{stat['no_kw']}")
    print("    提示：导入的 POC 默认关闭，请在 GUI「POC 管理」页挑选后逐条启用。")
    return 0


if __name__ == "__main__":
    sys.exit(main())