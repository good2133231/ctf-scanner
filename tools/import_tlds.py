"""从 tldextract 的**内置快照**生成公共后缀清单 `config/dicts/tlds.txt`。

背景：`scanner/jsmine.py` 从 JS 里挖域名时，此前**只做形态判断** —— 末位 label 只要是
2–24 个字母就当 TLD，于是 `wallet.filter.withdraw` / `react.transitional.element` /
`react.client.reference` / `i.test` 这类"点号连接的 JS 成员访问链"全被当成域名资产
（用户从 GUI「拓展域名」页拷来的真实数据即如此）。本脚本产出**真正的公共后缀清单**，
运行时由 jsmine 用它把"末位不是合法公共后缀"的串挡掉。

用法：
    py -3 tools/import_tlds.py            # 生成（已存在则跳过）
    py -3 tools/import_tlds.py --force    # 覆盖重建
    py -3 tools/import_tlds.py --out config/dicts/tlds.txt

**离线**：只用 tldextract 打包进 wheel 的 PSL 快照（`suffix_list_urls=()`），
**绝不联网**取 publicsuffix.org —— 本项目基调是"不扫描就不联网"。
**依赖**：`tldextract` 是**可选开发依赖**（不在 `requirements.txt`；运行时不 import 它，
`scanner/jsmine.py` 只读本脚本产出的 txt）。

产出：一行一个后缀（小写；含多段后缀如 `co.uk` / `com.cn` / `ac.uk`）；
去掉 PSL 的通配 `*.` 与例外 `!` 前缀；只保留 **ASCII** 后缀（运行时 host 判定是 ASCII 的，
IDN 后缀永远不会命中，留着徒增体积）。
"""
import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "config" / "dicts" / "tlds.txt"

# 只保留 ASCII 后缀：运行时 host 由 utils.is_domain() 判定，其 TLD 是纯字母的 ASCII。
_ASCII_SUFFIX_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*$")

HEADER = (
    "# 由 tools/import_tlds.py 从 tldextract 内置 PSL 快照生成（Public Suffix List，MPL-2.0）\n"
    "# 共 {n} 条 · 一行一个后缀（含多段，如 co.uk / com.cn）· 供 scanner/jsmine.py 校验末位公共后缀\n"
    "# 请勿手工排序；重新生成：py -3 tools/import_tlds.py --force\n"
)


def collect():
    """返回排序去重后的 ASCII 后缀列表；tldextract 不可用返回 None。"""
    try:
        import tldextract
    except ImportError:
        print("[!] 未安装 tldextract（可选开发依赖）：py -3 -m pip install tldextract")
        return None
    # suffix_list_urls=() → 只用内置快照，绝不联网。
    ext = tldextract.TLDExtract(suffix_list_urls=())
    out, seen = [], set()
    for raw in ext.tlds:
        s = str(raw or "").strip().lower()
        s = s.lstrip("*").lstrip("!").strip(".")   # 去通配 *. 与例外 ! 前缀
        if not s or s in seen or not _ASCII_SUFFIX_RE.match(s):
            continue
        seen.add(s)
        out.append(s)
    out.sort()
    return out


def main():
    ap = argparse.ArgumentParser(description="从 tldextract 内置快照生成公共后缀清单")
    ap.add_argument("--force", action="store_true", help="覆盖已存在的文件")
    ap.add_argument("--out", default=str(OUT), help="输出文件（默认 config/dicts/tlds.txt）")
    args = ap.parse_args()

    out = Path(args.out)
    if not out.is_absolute():
        out = ROOT / out
    try:
        label = out.relative_to(ROOT).as_posix()
    except ValueError:
        label = out.name
    if out.exists() and not args.force:
        print(f"[-] {label} 已存在，跳过；--force 可覆盖")
        return 0

    entries = collect()
    if entries is None:
        return 1
    if not entries:
        print("[!] 未取到任何后缀，未写出")
        return 1
    out.parent.mkdir(parents=True, exist_ok=True)
    # 统一 CRLF（与 config/dicts/ 下其它字典一致；core.autocrlf=false，行尾即所见）
    body = HEADER.format(n=len(entries)) + "\n".join(entries) + "\n"
    out.write_bytes(body.replace("\n", "\r\n").encode("utf-8"))
    print(f"[+] {label}：{len(entries)} 条后缀")
    return 0


if __name__ == "__main__":
    sys.exit(main())
