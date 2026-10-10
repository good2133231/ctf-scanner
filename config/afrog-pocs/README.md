# afrog 只读 PoC 目录

这里是外部引擎 **afrog** 的 PoC 目录（策略配置 → 外部引擎 afrog → `PoC 目录`，
默认就是这个路径）。框架**不代为下载** afrog 的 PoC —— 你把想跑的模板放进本目录即可。

## 框架会替你做的"只读闸门"（`scanner/afrog.py::plan`）

跑之前，本目录里的每一个 `*.yaml` / `*.yml` 都会被逐条审查，**只有同时满足**下面全部条件的
模板才会被复制进任务目录喂给 afrog；其余一律拒收，并把**拒收条数与文件名**写进任务日志：

- `info.severity` 为空或 `info`（`low`/`medium`/`high`/`critical` 一律拒收）；
- 请求方法只能是 `GET` / `HEAD`；
- 不带请求体（`request.body` 为空）；
- 不是 `type: tcp`、不是多步（`steps`）；
- 不带 `brute` 清单、不带 `request.raw`。

这条闸门挡的是"会动目标"的模板（写文件、执行命令、爆破）。**它不是判据优化** ——
命中结果仍会按本任务「最低报告级别」再筛一遍（默认 medium 时 info/low 不进报告，
只在任务日志与库里）。

## 三条闸门（缺一不可，缺了只写一行日志、**零请求**）

1. 策略配置里勾选「启用 afrog 外部引擎」；
2. 本目录里有**至少一个**通过上面只读闸门的模板；
3. 本机装好了 afrog 二进制（「外部工具」页下载，或 `python cli/client.py --update-tools --tool afrog`；
   装好后框架会把路径写回 `config/settings.yaml` 的 `tools.afrog`）。

## 文件

- `example-readonly-detect.yaml` —— 一个**占位示例**，演示只读模板的写法。它匹配的标记
  默认不会命中任何真实站点（防误报），要看效果请改成你的目标特征，或直接换成你自己的模板。
