# dirmap 适配与修复记录（本目录不含 dirmap 源码）

> 记录人：WorkBuddy · DeepSeek-V4.1-Flash（2026-09-22）

## 为什么这里没有 dirmap 的代码

dirmap 是 **GPL-3.0** 第三方项目（`LICENSE` 第 1 行即 GPLv3）。把它的源码拷进本仓库会让整个
仓库受 GPL 约束，因此**刻意不内联**（这也是 `TODO.md` 里"dirmap 内联"一项的结论：**不做**）。
本目录只放"我们对它的适配约定与修复说明"，源码保持在仓库之外。

## 我们怎么用它

- 落点：`tools/dirmap/`（**目录联接**指向本机 dirmap 源码目录；`.gitignore` 已排除该目录）。
- 配置：`config/settings.yaml` → `tools.dirmap.script`（默认 `tools/dirmap/dirmap.py`，
  **只写相对路径**，绝对路径不进代码与配置）+ `tools.dirmap.threads`。
- 找不到该文件时，`dirscan` 阶段自动回退内置字典扫描（不会报错、也不会静默失败：日志会写明）。
- 调用方式：`python dirmap.py -iF <任务目录/目标文件> -e all -t <线程>`，**cwd 固定在其项目目录**
  （dirmap 用 `os.getcwd()` 定位 `data/` 与 `output/`）。

## 适配器踩过的三个坑（已在 `scanner/stages/dirscan.py` 修掉）

1. 产物在 `output/<域名>/` **子目录**里（`res.txt` / `403.txt` / `404.txt` / `重复长度.txt`），
   不再是早年的 `output/<域名>.txt`；
2. `output/` 是**持久目录**，`output/` 里的旧结果会被下次运行读到；
3. **只按 mtime 过滤也不行**：dirmap 的 `saveResults()` 会与文件里已有的行去重，
   重扫同一目标且结果不变时**它不写新内容**，文件 mtime 保持旧值 ——
   实测表现是"dirmap 跑了 37 秒，适配器却解析出 0 条并回退内置扫描"。
   → 现在改为**按目标定位**：`output/<netloc 把 : 换成 _>/`，再按目标 netloc 过滤行，
   mtime 过滤只作为兜底。

## 我们对 dirmap 源码做的 5 处修复（改的是本机那份外部副本）

> 备份：`lib/controller/bruter.py.bak-workbuddy-20260922`（同目录）。**未内联、未提交进本仓库。**

| # | 问题 | 影响 | 修法 |
|---|---|---|---|
| 1 | `saveResults()` 被定义了**两遍**（`saveResults(domain,msg)` 与 `saveResults(file_path,msg)`） | 前一个是死代码，读代码时极易改错文件 | 删掉失效的那份 |
| 2 | `error_count = {'403': 0, '404': 0}` 全局量从未被读写 | 死变量 | 删除（`response_storage` 保留并补注释） |
| 3 | `saveResults()` 每次 `open(path,'r+')` **读回整个文件**再追加 | 1.5 万条字典下是 O(n²) 读放大；且 gevent 并发下多协程同时 r+ 会**互相覆盖丢结果** | 首次写载入已有行 → 之后只追加，并加 `threading.Lock` 串行化 |
| 4 | `if size == conf.skip_size`：左边是 `intToSize()` 的字符串（`1.23kb`），右边是配置里的 `None`/`1k` | **永远不相等**，这个开关形同虚设 | 新增 `_parse_size()` 按字节数比较 |
| 5 | 建了 `ssl_context`（SECLEVEL=1 / 不校验证书）却 mount 的是**默认** adapter | 等于白建，旧版 SSL/自签名目标仍会失败 | 新增 `_LegacySSLAdapter` 把 ssl_context 注入 urllib3 连接池 |

### 修复 #3 的实测收益

同一台机器、同一个本地靶场、同样的 15349 条字典：

| | 耗时 |
|---|---|
| 修复前 | **588 秒** |
| 修复后 | **43 秒** |

（约 13× —— 差异几乎全部来自那个 O(n²) 的读回放大。这也解释了为什么"跑一次 dirmap 要十分钟"。）

## 复现步骤

```powershell
# 1) 挂载（已建好；换机器时重建）
#    mklink /J tools\dirmap <本机 dirmap 目录>
# 2) 打补丁：见上表 5 处（备份文件就在 bruter.py 同目录）
# 3) 验证：跑一个只开 dirscan 的任务，日志应出现
#    [dirscan] dirmap 处理 N 个站点 … / [dirscan] dirmap 输出 M 条
```
