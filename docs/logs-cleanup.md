# `logs/` 精确清理清单（续226）

> **规矩**：`logs/` 是临时工作区，但里面同时躺着**审计证据**与**数据库仍在引用的任务产物**。
> 清理只允许**逐个点名**（`python tools/clean_logs.py --apply <确切名字>`）；
> **禁止** `rm -rf logs/*`、`rm -r logs`、`shutil.rmtree("logs")`、`glob(...).unlink()` 这类通配清理。
> 门禁 `tests/smoke.py [226]` 会扫代码里的危险删除形态，并自测本工具拒绝通配/必留项。

## 必留（确切文件名，删除会被工具拒绝）

| 文件 | 为什么 |
|---|---|
| `devflow_baseline.json` | 全流程自检基线（`run_devflow` 对比用） |
| `smoke-timing.jsonl` | 门禁逐组耗时历史（提速专项的唯一对照） |
| `HANDOFF-2026-10-14-b.md` | 交接记录 |
| `HANDOFF-2026-10-14-c.md` | 交接记录 |
| `HANDOFF-2026-10-14-d.md` | 交接记录 |
| `HANDOFF-2026-10-15-a.md` | 交接记录 |
| `HANDOFF-2026-10-15-b.md` | 交接记录 |
| `access.log` / `access.log.1` / `access.log.2` / `access.log.3` | Web 访问审计（轮转文件同属证据） |
| `server.log` | GUI/服务端运行日志 |
| `scanner.db.bak-20261006-062530-112d-thirdparty` | 数据库备份（改表前快照） |
| `scanner.db.bak-20261006-094633-112g-noise` | 数据库备份 |
| `scanner.db.bak-20261006-094647-112g-noise` | 数据库备份 |
| `scanner.db.bak-20261006-120404-113-fragments` | 数据库备份 |

另外：**`tasks.log_file` 指向的 `task_*` 目录一律不删**（里面有截图 `shots/`、favicon
`favicons/`、`js_urls.txt` 等，页面与报告要读）。`tools/clean_logs.py` 会查库拒绝；
**库读不到时也拒绝**（"读不到引用"不等于"没引用"）。

## 可删候选（临时产物；仍需逐个点名）

以下按**明确前缀/确切名字**归类，工具只认这些；不在清单里的名字一律拒绝：

- `_smoke*.txt`：历次门禁输出（85 个，约 27 MB）。
- `_*.py`：一次性补丁/校验脚本（226 个，约 1.1 MB）——脚本内联在对话里，产物已入库。
- `_*.json` / `_*.txt`：一次性补丁 spec / 记录（80 个）。
- `smoke*.out`、`smoke-*` 目录：旧 smoke 的 stdout 与夹具工作目录。
- `h8am-*`、`w178b-*`、`verify*`、`scan_*.run`、`profile-*`：导入导出、校验、性能采样留下的临时目录/文件。
- `preview/`：GUI 预览产物（`access.log` / captcha 图）。
- `__pycache__/`：Python 字节码缓存。
- 非 `access.log*` / `server.log` 的 `*.log`：其它运行日志。

## 任务目录 `task_*`（条件可删）

- 只有**数据库 `tasks.log_file` 不再引用**的 `task_*` 才允许删；
- 工具会实时查 `data/scanner.db`；库不存在/读失败 ⇒ 一律拒绝；
- 删之前先确认报告/截图已导出（`shots/` 是交付物的一部分）。

## 工具

```bash
# 只看分类与示例（默认动作，不删任何东西）
python tools/clean_logs.py --list

# 显式点名删除（名字必须是 logs/ 顶层确切名字；* ? [ ] / \ .. 一律拒绝）
python tools/clean_logs.py --apply _smoke222a.txt smoke-old-dir

# 必留 / 未登记 / 被 DB 引用的任务目录 → 拒绝并返回非 0
python tools/clean_logs.py --apply devflow_baseline.json
```
