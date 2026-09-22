"""把外部字典整理成我们自己的目录扫描字典（`config/dicts/dirs_big.txt`）。

用法：
    py -3 tools/import_dir_dict.py                       # 默认读 tools/dirmap/data/dict_load/dict_mode_dict.txt
    py -3 tools/import_dir_dict.py --src <相对或绝对路径>

来源默认是**项目内的相对路径** `tools/dirmap`（一个指向本机 dirmap 的目录联接，
见 docs/usage.md「外部工具」）—— 代码与配置里都不出现绝对路径。

做的清洗（都是为了"扫得快且不重复"）：
- 去空行、去首尾空白；跳过 `#` 注释行（dirmap 用 `#` 注释掉暂不需要的条目）；
- 统一去掉开头的 `/`（拼接时再补，避免 `//`）；
- 保序去重（字典顺序通常按命中率排过，不排序、不洗牌）；
- 丢掉明显不像路径的条目（含空白、含 `://`、超长）。
"""
import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

DEFAULT_SRC = ROOT / "tools" / "dirmap" / "data" / "dict_load" / "dict_mode_dict.txt"
DEFAULT_DST = ROOT / "config" / "dicts" / "dirs_big.txt"

MAX_LEN = 120


def clean(lines):
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default=str(DEFAULT_SRC))
    ap.add_argument("--dst", default=str(DEFAULT_DST))
    args = ap.parse_args()

    src = Path(args.src)
    if not src.is_absolute():
        src = ROOT / src
    if not src.exists():
        print(f"[!] 源字典不存在：{src}")
        print("    把 dirmap 放到 tools/dirmap（目录联接或直接拷贝），或用 --src 指定路径。")
        sys.exit(1)

    items = clean(src.read_text(encoding="utf-8", errors="replace").splitlines())
    if not items:
        print("[!] 清洗后为空，未写出")
        sys.exit(1)

    dst = Path(args.dst)
    if not dst.is_absolute():
        dst = ROOT / dst
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(
        "# 目录扫描大字典：由 tools/import_dir_dict.py 从 dirmap 的 dict_mode_dict.txt 整理而来\n"
        f"# 来源 {src.relative_to(ROOT).as_posix() if str(src).startswith(str(ROOT)) else src.name}"
        f" · 共 {len(items)} 条 · 实际扫描条数由 dirscan.max_paths 上限控制\n"
        + "".join(i + "\n" for i in items), encoding="utf-8")
    print(f"[*] 已写出 {dst.relative_to(ROOT).as_posix()}：{len(items)} 条（源 {len(items)} 行去重后）")


if __name__ == "__main__":
    main()
