"""从全量字典派生**框架特征字典**（`config/dicts/dirs_<框架>.txt`）。

背景：`dirs_big.txt` 是 11882 条的全量字典，`dirscan.max_paths`（默认 400）会把它截断，
截断点之前的路径就是"这个站点实际会被扫到的路径"。此前只按**语言**拆了 jsp/php/asp，
但真正决定 CTF 拿分的是**框架特征路径**（`wp-login.php`、`/actuator/env`、`/nacos/`…）——
按语言拆完之后它们仍散落在 `dirs_common` 的 10671 条里，400 条的额度根本轮不到。

所以这里按**框架**再拆一层：每种框架单独成文件，运行时凭 `sites.tech` 指纹命中后
**排在最前**，保证它一定能被扫到（见 `scanner/stages/dirscan.py::_dict_paths_for`）。

用法：
    py -3 tools/import_fw_dicts.py            # 只补缺失的文件
    py -3 tools/import_fw_dicts.py --force    # 全部重新派生（覆盖手工修改，慎用）

纯离线：只读 `config/dicts/dirs_big.txt`，不联网、不依赖第三方包。
"""
import argparse
import re
import sys
from collections import OrderedDict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "config" / "dicts" / "dirs_big.txt"
OUT_DIR = ROOT / "config" / "dicts"

# 框架桶 -> 特征正则（对整行做 search）。
# 顺序即优先级：`FRAMEWORK_ORDER` 只在"一个站点同时命中多个标签"时用来挑一个，
# 实际运行时框架字典排在语言字典之前，所以这里只需要保证正则不互相污染得太厉害。
BUCKETS = OrderedDict([
    # CMS / 建站
    ("wordpress", r"(?i)wp-|wordpress|xmlrpc"),
    # 数据库管理 / 常见控制台
    ("phpmyadmin", r"(?i)phpmyadmin|(?<![a-z])pma(?![a-z])|/setup/index\.php"),
    ("druid", r"(?i)druid|weburi|sql\.html"),
    # Java 系中间件 / 框架
    ("spring", r"(?i)actuator|spring|jolokia|heapdump|/env(?![a-z])|/beans(?![a-z])|httptrace"),
    ("weblogic", r"(?i)wls-wsat|bea_wls|uddiexplorer|weblogic|/console"),
    ("tomcat", r"(?i)manager/html|host-manager|examples/|catalina"),
    ("jenkins", r"(?i)jenkins|jnlp|/computer|/script"),
    ("elastic", r"(?i)elasticsearch|_cat(?![a-z])|_cluster|_nodes"),
    # 接口文档 / 协作平台
    ("swagger", r"(?i)swagger|api-docs|openapi|v[23]/api"),
    ("confluence", r"(?i)confluence"),
    ("gitlab", r"(?i)gitlab|/users/sign_in"),
    # 通用高价值暴露面（不依赖框架，任何站点都值得先试）
    ("exposure", r"(?i)\.git|\.svn|\.env(\.|$|/)|\.ds_store|\.bak(?![a-z])|\.sql(?![a-z])"
                 r"|\.zip(?![a-z])|\.tar(?![a-z])|\.rar(?![a-z])|\.old(?![a-z])|\.swp(?![a-z])"
                 r"|backup"),
])

# 说明：**不**给 ThinkPHP / Nacos / 泛微 等建桶 —— 实测 `dirs_big.txt` 里没有它们的特征路径
# （`thinkphp`/`think_template` 命中 0 条，`nacos` 命中的全是 K8s `namespaces` 误报，`weaver` 同理）。
# 与其写出"看着像框架字典、其实是通用路径或误报"的文件，不如不建：宁缺勿错。

HEADER = (
    "# 由 tools/import_fw_dicts.py 从 config/dicts/dirs_big.txt 派生（{what}）\n"
    "# 共 {n} 条 · 运行时会排在语言字典之前，确保 max_paths 截断后仍被扫到 · 请勿手工排序\n"
)


def main():
    ap = argparse.ArgumentParser(description="派生框架特征字典")
    ap.add_argument("--force", action="store_true", help="覆盖已存在的文件")
    ap.add_argument("--src", default=str(SRC), help="源字典（默认 config/dicts/dirs_big.txt）")
    args = ap.parse_args()

    src = Path(args.src)
    if not src.is_file():
        print(f"[!] 源字典不存在：{src}")
        return 1
    lines = [x.strip() for x in src.read_text(encoding="utf-8", errors="replace").splitlines()]
    entries = [x for x in lines if x and not x.startswith("#")]
    print(f"[*] 源字典 {src.name}：{len(entries)} 条有效路径")

    rc = 0
    for name, pattern in BUCKETS.items():
        rx = re.compile(pattern)
        picked = [x for x in entries if rx.search(x)]
        dst = OUT_DIR / f"dirs_{name}.txt"
        what = "通用高价值暴露面" if name == "exposure" else f"{name} 框架特征路径"
        if dst.exists() and not args.force:
            print(f"[-] {dst.name} 已存在（{len(picked)} 条候选），跳过；--force 可覆盖")
            continue
        if not picked:
            print(f"[!] {name}：正则未命中任何路径，跳过（避免写出空字典）")
            rc = 1
            continue
        dst.write_text(HEADER.format(what=what, n=len(picked)) + "\n".join(picked) + "\n",
                       encoding="utf-8")
        print(f"[+] {dst.name}：{len(picked)} 条")
    return rc


if __name__ == "__main__":
    sys.exit(main())