# NOTICE —— 第三方内容来源说明

> 本文件只说明**第三方内容来源与许可状态**。工具的使用边界（授权要求、非破坏性红线、
> 第三方接口的数据流向）另见 [`docs/security-notice.md`](docs/security-notice.md)。

本仓库的**框架代码**（`scanner/`、`gui/`、`cli/`、`tools/`、`tests/`）为本项目自行编写。
但 `config/` 下的部分**数据文件**派生自第三方项目，其权利归原作者所有，**不因收录进本仓库而改变**。
逐项列明如下，便于使用者自行评估。

## 1. `config/dicts/dirs_*.txt` —— 派生自 dirmap（GPL-3.0）

| 文件 | 条数 | 来源 |
|---|---|---|
| `dirs_big.txt` | 11882 | 由 `tools/import_dir_dict.py` 从外部字典整理（源：`dict_mode_dict.txt`） |
| `dirs_common.txt` / `dirs_jsp.txt` / `dirs_php.txt` / `dirs_asp.txt` | 10671 / 116 / 933 / 162 | 由 `dirs_big.txt` 按技术栈拆分 |
| `dirs_<框架>.txt`（12 个桶）+ `dirs_exposure.txt` | — | 由 `tools/import_fw_dicts.py` 从 `dirs_big.txt` 二次派生 |

`tools/import_dir_dict.py` 的默认源是 `tools/dirmap/data/dict_load/dict_mode_dict.txt`，
即 **[dirmap](https://github.com/yzddmr6/dirmap) 自带的目录字典**。dirmap 以 **GPL-3.0** 授权。

> **注意**：GPL-3.0 是**传染性**许可。本仓库**并未**整体采用 GPL-3.0，也未内联 dirmap 的代码
> （`tools/dirmap/` 是目录联接，已在 `.gitignore` 中排除，不随仓库分发）。此处收录的是
> **由该字典整理派生出的路径清单**。若你打算以其他许可再分发本仓库，请自行厘清这部分数据的许可义务。

## 2. `config/pocs-imported/` —— 派生自参考项目 myscan_20250825

305 个 YAML，由 `tools/import_ref_pocs.py` 用 `ast` **静态转换**自参考项目
`myscan_20250825` 的 Python POC（`class Script(BaseScript)` 形态），
提取其中的 `detect_path_list` / 关键字 / `bug_level` 等字面量，翻译成本引擎的
`path + word matcher` 语义（等价于 nuclei 的 YAML 写法）。

- 参考项目**不在本仓库内**（脚本默认从 `tools/ref-project/` 读取，该目录未纳入版本控制）。
- 该参考项目的许可状态**本项目未做核实**，此处仅作事实性来源标注。
- 这批 POC 在 `db.default_poc_enabled()` 中**默认关闭**（关键字命中为主，误报率高于手写 POC）。
- 其中包含部分**上传/写入类**检测项（如 `ActiveMQ__activemq_putfile.yaml`）。收录不等于背书，
  使用时请遵守 `docs/security-notice.md` 的授权与非破坏性要求。

## 3. `config/dicts/js_thirdparty.txt` —— 含 URLFinder 的过滤清单

267 条 JS 第三方域名单 = 本项目内置清单 + **[URLFinder](https://github.com/pingc0y/URLFinder)**
「含过滤规则版」`config.yaml` 中的 `jsFiler` 段。URLFinder 的许可状态本项目未做核实。

## 4. 其他数据文件（本项目自建，无第三方来源）

- `config/dicts/dirs_shallow.txt` —— 自建"浅扫精选字典"（`dirscan.mode = quick` 专用）。
- `config/dicts/sensitive.txt` —— 自建，内置检查 `a01-sensitive-files` 的数据源。
- `config/dicts/resolvers.txt` —— 公共 DNS 解析器地址（阿里 DNS 等公开信息）。
- `config/dicts/cdn_cname.txt` —— CDN 厂商 CNAME 后缀清单（公开厂商域名，事实性数据；
  本文件**无来源标注**，如你知晓其出处请补记于此）。
- `config/dicts/subdomains.txt` —— 自建子域名字典。
- `scanner/pocs/pocs/*.yaml`（7 个内置 POC）、`scanner/fingerprint.py`、
  `scanner/owasp/checks.py`、`scanner/takeover.py` 指纹库 —— 本项目自行编写。

## 5. 本仓库自身的许可

本仓库**自有代码**采用 **MIT**，见 [`LICENSE`](LICENSE)。

**上述第三方派生内容不受 MIT 覆盖**，仍适用其原始项目的许可条款。其中有一处需要使用者特别注意：

- `config/dicts/dirs_*.txt` 派生自 **dirmap（GPL-3.0）**。GPL-3.0 是**传染性**许可，
  而本仓库整体采用 MIT。本项目收录的是**由该字典整理派生出的路径清单**，且**未内联 dirmap 的任何代码**
  （`tools/dirmap/` 是目录联接，已在 `.gitignore` 中排除，不随仓库分发）。
  **MIT 与 GPL-3.0 在这部分数据上的兼容性存在讨论，本项目不作法律结论**：
  若你要再分发本仓库、或用于商业用途，请自行厘清这部分数据的许可义务；必要时可从你的副本中移除这些字典。
- `config/pocs-imported/`（305 个）与 `config/dicts/js_thirdparty.txt`（URLFinder 部分）
  的来源项目许可状态**本项目未做核实**，同理请自行评估。

## 6. 第三方工具（不随仓库分发）

`subfinder` / `puredns` / `httpx` / `dirmap` / `fscan` / `nmap` 均为**外部调用**，不包含在本仓库中。
框架对它们一律采取「**外部工具优先 + 内置兜底**」策略：找不到就降级到内置实现，不会因此崩溃。
