"""把外部目录字典整理成我们自己的字典，并**按技术栈拆分**。

用法：
    py -3 tools/import_dir_dict.py --src <相对或绝对路径>      # 例：用户给的 dict_mode_dict.txt
    py -3 tools/import_dir_dict.py                            # 默认读 tools/dirmap/data/dict_load/dict_mode_dict.txt

产出（都落在 `config/dicts/`）：
    dirs_big.txt     全部条目（未知技术栈时用，兼容既有行为）
    dirs_common.txt  与语言无关的条目（目录名、无扩展名、静态文件、其它扩展名）
    dirs_jsp.txt     Java 系：.jsp/.jspx/.do/.action/.jspa/.java/.war…
    dirs_php.txt     PHP 系：.php/.php3/.php5/.phtml/.phps…
    dirs_asp.txt     ASP/.NET 系：.asp/.aspx/.ashx/.asmx/.ascx/.config…

**为什么要拆**：一个站点要么是 Java 要么是 PHP 要么是 ASP.NET，把三种语言的后缀路径
全打一遍纯属浪费（`dirscan.max_paths` 的额度会被无关后缀吃光）。
运行时由 `scanner/stages/dirscan.py::_dict_kind()` 按 `sites.tech` 判定技术栈，
只取「语言字典 + 通用字典」，未知栈才回退 `dirs_big.txt`。

清洗规则（与之前一致，都是为了让扫描"快且不重复"）：
- 去空行/首尾空白；跳过 `#` 注释行；
- 去掉开头的 `/`（拼接时再补，避免 `//`）；
- **保序去重**（字典顺序通常按命中率排过，不排序、不洗牌）；
- 丢掉明显不像路径的条目（含空白、含 `://`、超长）。

来源路径只通过 `--src` 传入 —— 代码里不出现任何绝对路径（见 `AGENTS.md` §0）。
"""
import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

DEFAULT_SRC = ROOT / "tools" / "dirmap" / "data" / "dict_load" / "dict_mode_dict.txt"
DICT_DIR = ROOT / "config" / "dicts"

MAX_LEN = 120

# 扩展名 -> 语言桶（小写、不含点）。未列出的扩展名一律进 common。
LANG_EXT = {
    "jsp": ("jsp", "jspx", "jspf", "jspa", "jsw", "jsv", "java", "war", "jar", "class",
            "do", "action", "jspx"),
    "php": ("php", "php3", "php4", "php5", "php7", "php8", "phtml", "phps", "pht", "phar"),
    "asp": ("asp", "aspx", "ashx", "asmx", "ascx", "asax", "asa", "axd", "config"),
}

# 反查表：扩展名 -> 桶名
_EXT2LANG = {ext: lang for lang, exts in LANG_EXT.items() for ext in exts}

HEADER = ("# 由 tools/import_dir_dict.py 从外部字典整理而来（源：{src}）\n"
          "# 共 {n} 条 · 实际每站点扫描条数由 dirscan.max_paths 上限控制 · 请勿手工排序\n")


def clean(lines):
    """清洗 + 保序去重，返回条目列表。"""
    out, seen = [], set()
    for raw in lines:
        item = raw.strip()
        if not item or item.startswith("#"):
            continue
        item = item.lstrip("/")
        if not item or " " in item or "\t" in item or "://" in item or len(item) > MAX_LEN:
            continue
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def lang_of(entry):
    """按最后一段扩展名判断条目属于哪个语言桶；判断不出返回 ""（进 common）。"""
    tail = entry.rsplit("/", 1)[-1]
    if "." not in tail:
        return ""
    ext = tail.rsplit(".", 1)[-1].lower()
    return _EXT2LANG.get(ext, "")


def split(entries):
    """切成 {bucket: [entries]}，bucket ∈ {"", "jsp", "php", "asp"}（保序）。"""
    buckets = {"": [], "jsp": [], "php": [], "asp": []}
    for e in entries:
        buckets[lang_of(e)].append(e)
    return buckets


def write_dict(path, entries, src_label):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(HEADER.format(src=src_label, n=len(entries))
                    + "".join(i + "\n" for i in entries), encoding="utf-8")
    return len(entries)


def main():
    ap = argparse.ArgumentParser(description="整理并拆分目录扫描字典")
    ap.add_argument("--src", default=str(DEFAULT_SRC),
                    help="源字典（默认 tools/dirmap/data/dict_load/dict_mode_dict.txt）")
    ap.add_argument("--out-dir", default=str(DICT_DIR), help="输出目录（默认 config/dicts）")
    args = ap.parse_args()

    src = Path(args.src)
    if not src.is_absolute():
        src = ROOT / src
    if not src.exists():
        print(f"[!] 源字典不存在：{src}")
        print("    用 --src 指定路径（用户主动给出即可，代码里不留绝对路径）。")
        sys.exit(1)

    entries = clean(src.read_text(encoding="utf-8", errors="replace").splitlines())
    if not entries:
        print("[!] 清洗后为空，未写出")
        sys.exit(1)

    try:
        label = src.relative_to(ROOT).as_posix()
    except ValueError:
        label = src.name          # 项目外的源：只记文件名，不写绝对路径

    out_dir = Path(args.out_dir)
    if not out_dir.is_absolute():
        out_dir = ROOT / out_dir

    buckets = split(entries)
    written = {
        "dirs_big.txt": write_dict(out_dir / "dirs_big.txt", entries, label),
        "dirs_common.txt": write_dict(out_dir / "dirs_common.txt", buckets[""], label),
        "dirs_jsp.txt": write_dict(out_dir / "dirs_jsp.txt", buckets["jsp"], label),
        "dirs_php.txt": write_dict(out_dir / "dirs_php.txt", buckets["php"], label),
        "dirs_asp.txt": write_dict(out_dir / "dirs_asp.txt", buckets["asp"], label),
    }
    print(f"[*] 源 {label}：清洗后 {len(entries)} 条")
    for name, n in written.items():
        print(f"    config/dicts/{name:<16} {n} 条")


if __name__ == "__main__":
    main()
