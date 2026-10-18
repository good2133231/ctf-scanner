"""dirmap 的 Python 3.12+ 兼容垫片。

上游 dirmap（v1.1 与 master 实测）在 `lib/core/option.py` 里有一行 `import imp`，
但**整个仓库没有任何 `imp.` 调用**（2026-10-18 逐文件 grep 复核）。Python 3.12 起
标准库删除了 `imp`，于是这一行会让 dirmap 在 3.14 上直接 ImportError —— 看起来像
"dirmap 坏了"，其实只是无用导入。

`scanner/stages/dirscan.py` 启动 dirmap 时把本目录放在子进程 `PYTHONPATH` 最前面，
因此 `import imp` 命中这个空模块。**不要**在这里实现任何加载器：dirmap 不调用它，
实现反而会掩盖"上游哪天真的开始用 imp"这件事（那时该改的是适配器，不是垫片）。
"""
