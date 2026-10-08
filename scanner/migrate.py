#!/usr/bin/env python3
"""扫描数据的导出 / 导入 —— 跨机迁移用（续136）。

红线（用户 2026-10-08 点名）：**一个"迁移文件"不许顺手变成"能登录别人系统的凭据包"**。
所以包里默认**只有任务与资产**，三类东西一律不带，各自要单独显式点名：

1. `users` 表（登录口令哈希）、`nodes` 表（节点一次性令牌哈希）→ `--with-users`；
2. `config/keys.yaml` / `config/keys.enc.yaml` / `config/edge_auth.yaml`
   （第三方接口凭据、401 边缘门口令）→ 同上（与账号表同一个开关：两者合起来才"能登录"，
   分开放两个开关只会让人只带一半、迁移完发现系统起不来，再去猜缺了什么）；
3. `tasks.options["auth"]` 与 `run_payload` 里的同名键 —— 扫目标时带的登录态请求头
   （`cli/client.py` 把 `-H/--cookie` 存进任务选项，`auth.from_task_options()` 读出来用）。
   → `--with-task-auth`。

第 3 条是本轮实测找出来的：任务表看着"只是配置"，实际里面可能躺着整串 Cookie 和 Bearer token。
只把账号表挡在门外的话，"默认导出"照样会泄密 —— 于是一条开关不算守住红线。

刻意**不带**的东西（连 `--with-users` 也不带）：
- `data/session.secret`（Flask 会话签名密钥）：带了 = 迁移完旧机器的会话在新机器上**继续有效**，
  这跟"凭据包"是同一类问题。不带，代价是迁移后重新登录一次，这是划算的。
- `audit_log` / `login_fails`：审计流水属于**那台机器上发生过的事**，不是资产。跨机一合并，
  "谁在什么时候登录失败过"这种结论就分不清来源了，而它恰恰是事后追查要看的表。
"""
import base64
import json
import os
import sqlite3
import time
from pathlib import Path

from scanner import db, keystore
from scanner.config import BASE_DIR, LOGS_DIR
from scanner.utils import scrub_paths

MAGIC = "CTFSCANNER-MIGRATION-V1"
# 包格式版本。**只在结构变化时递增**，导入侧据此拒绝读不懂的包（而不是硬塞出错的东西）。
FORMAT = 1

# 账号 / 凭据类表（默认不带，见文件头红线 1）
ACCOUNT_TABLES = ("users", "nodes")
# 凭据类文件，相对 BASE_DIR（默认不带，见文件头红线 2）
CRED_FILES = ("config/keys.yaml", "config/keys.enc.yaml", "config/edge_auth.yaml")
# 审计类表：永不进包（见文件头"刻意不带"）
NEVER_TABLES = ("audit_log", "login_fails")

# 任务状态里"声称本机有个进程在跑/在排"的两档。换机器后这个声称必然是假的。
# 三个"还没跑完"的状态：running/queued 谎称本机有进程在跑，pending 谎称"已经在排队等着自动开跑"。
# 导入的包不该留下任何一种"等机器自己动"的状态 —— 一律归一成 stopped，
# "要不要跑"这个决定明确留在人手里（用户口径：导入完就自己开扫＝用一份文件在别人机器上发起对外请求）。
_LIVE_STATUSES = ("running", "queued", "pending")

# ---- 续136 的第三条边界：迁移包本身也可以加密 ----
# 独立魔数（不是凭据文件那个）：`keys.enc.yaml` 与迁移包**互相冒充不了** —— 拿错文件会在头部比对
# 那一步就被拒，而不是解出一团乱码再报"不是合法 JSON"（那种报错会把人引向"是不是口令错了"）。
BUNDLE_MAGIC = b"CTFSCANNER-BUNDLE-V1\x00"
# 口令**只**从这个环境变量取，绝不进 argv：那会出现在 `ps`、shell history，以及任何进程都能读的
# `/proc/<pid>/cmdline` 里（AGENTS.md §2 对凭据也是同一条口径）。
ENV_BUNDLE_PASSPHRASE = "CTFSCANNER_BUNDLE_PASSPHRASE"
# `--with-logs` 的两个上限（单文件 / 总量）：`-vv` 跑全阶段的日志能到几十 MB，不设上限只会产出
# 一个"发不出去、发出去了也没人敢解"的包 —— 那等于没有这个开关。
LOG_FILE_CAP = 5 * 1024 * 1024
LOG_TOTAL_CAP = 25 * 1024 * 1024


def bundle_passphrase(passphrase=None):
    """本次的包口令：参数优先（调用方已从安全渠道拿到时），否则读环境变量；都没有就空串。

    空串＝**不加密**，这是默认。加密必须是显式的：口令落在谁手里、谁能解这个包，
    是收包的人要同意的事，不该是"顺手就发生了"。
    """
    return str(passphrase or os.environ.get(ENV_BUNDLE_PASSPHRASE) or "")


def is_encrypted_bundle(path):
    """只按头部判是不是加密迁移包；不解密、不猜。"""
    return keystore.is_encrypted(path, magic=BUNDLE_MAGIC)


def _log_inside_logs_dir(abs_path):
    """日志只许带**落在 `LOGS_DIR` 内**的那一档；不合格返回 `(None, 原因)`。

    为什么在导出侧就挡：`tasks.log_file` 是自由文本列（历史上存过别的目录、也存过相对形），
    而导入侧会按包里的相对路径在本机建文件。放越界路径进包，等于给"按别人给的路径往本机任意
    位置写文件"开门 —— `_write_cred` 明确拒绝的就是这类事，日志这边必须同口径。
    """
    if not abs_path:
        return None, "空"
    try:
        p = Path(abs_path).resolve()
        root = Path(LOGS_DIR).resolve()
    except OSError:
        return None, "路径解析失败"
    if root not in p.parents:
        return None, "不在 LOGS_DIR 内"
    return p, ""


def _read_log_bounded(p, cap=LOG_FILE_CAP):
    """读日志；超过上限或非文件返回 None（调用方计入 `logs_skipped`，**不静默截断**）。

    截断比跳过更坏：截一半的日志看起来是完整的，而人正是靠日志判断"那次扫描到底跑了什么"。
    """
    try:
        if not p.is_file() or p.stat().st_size > cap:
            return None
        return p.read_bytes()
    except OSError:
        return None


def default_dst() -> Path:
    """默认落点 `data/export/` —— 在 .gitignore 覆盖的 `data/` 底下。

    为什么不是仓库根或 `output/`：包可能含凭据（`--with-users`），而"顺手 `git add .`"
    是这个项目最容易发生的失误，`data/` 是这里唯一**结构上就进不了仓库**的目录。
    """
    return db.DB_PATH.parent / "export"


def _cols(table):
    return [r["name"] for r in db._query(f"PRAGMA table_info({table})")]


def _has(table):
    """本库到底有没有这张表。`nodes` 不在 `db.SCHEMA` 里（由 `scanner/nodes.py` 自己建），
    新装的库就没有 —— 拿它当"一定有"会让 `--with-users` 导出直接抛栈。"""
    return bool(_cols(table))


def _rows(table, where="", params=()):
    return [dict(r) for r in db._query(f"SELECT * FROM {table}{where}", params)]


def to_rel_path(val):
    """库里的路径列 → **相对项目根**的串；不在项目根之下就返回空串。

    为什么要这一层（实测）：`tasks.log_file` 存的是绝对路径（`runner.py` 写 `str(log_file)`），
    原样进包就等于把 `/home/xxx/…`、`C:\\Users\\xxx\\…` 打进一份要发给别人的文件，
    而且在对方机器上那个路径必然是死的 —— 相对形是唯一两边都有意义的写法。
    项目根之外（例如 `CTFSCANNER_LOGS` 指到别处）**宁可可空**也不带出去：
    空的后果是"这个任务的日志链接没了"（页面本来就按"文件不存在"处理），
    带了后果是"本机目录结构随包外流"。
    """
    s = str(val or "").strip()
    if not s:
        return ""
    try:
        p = Path(s)
        if not p.is_absolute():
            return p.as_posix()          # 已经是相对形，原样
        return p.resolve().relative_to(BASE_DIR.resolve()).as_posix()
    except (ValueError, OSError):
        return ""


def to_abs_path(val):
    """包里的相对路径 → 本机绝对路径（导入侧的还原，形状要与 `runner` 写进去的一致）。

    消费方是 `Path(task["log_file"]).parent` 这类用法（`gui/app.py`、`runner.py`），
    相对路径会按**进程 CWD** 解析 —— 从仓库外启动 GUI 就指到别处去了，所以库里必须是绝对形。
    """
    s = str(val or "").strip()
    if not s:
        return ""
    p = Path(s)
    if p.is_absolute():
        # 老包（本轮之前导出的）里可能是绝对路径；本机对不上就当没有，不把别人的路径当自己的。
        return s if p.exists() or BASE_DIR in p.parents else ""
    return str((BASE_DIR / p).resolve())


def _json_obj(text):
    """把库里的 JSON 列读成对象；不是合法 JSON / 空 → 原样返回（不许因为格式就悄悄改数据）。"""
    try:
        return json.loads(text or "")
    except (ValueError, TypeError):
        return None


def redact_auth(obj):
    """递归剥掉 dict/list 里所有 `auth` 键（任务登录态请求头），返回 `(新对象, 剥掉的条数)`。

    为什么按**键名递归**而不是只删顶层 `options["auth"]`：运行期选项会嵌套
    （`run_payload` 是 `{"stages":…, "options":…}`，追加执行时再套一层），只删顶层会漏。
    只认 `auth` 这一个键名 —— 它就是 `auth.from_task_options()` 读的那个键，别的名字不是凭据。
    """
    n = 0
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k == "auth" and isinstance(v, dict):
                n += len(v)
                continue
            nv, nn = redact_auth(v)
            n += nn
            out[k] = nv
        return out, n
    if isinstance(obj, list):
        items = []
        for v in obj:
            nv, nn = redact_auth(v)
            n += nn
            items.append(nv)
        return items, n
    return obj, n


def export_bundle(dst=None, task_ids=None, owner_id=None, with_users=False,
                  with_task_auth=False, passphrase=None, with_logs=False):
    """导出扫描数据成一份迁移包，返回摘要 dict（含落点路径与各项计数）。

    - `task_ids=None` = 全部任务；给了列表 = 只导那几个（导单个任务给别人复看时用）。
    - `owner_id` 非空 = 只导该用户名下的任务（多租户下"导出全部"不该是默认能发生的事）。
    - 导出**只读**，不改任何库内容。
    - `passphrase`（或环境变量 `CTFSCANNER_BUNDLE_PASSPHRASE`）非空 → 整包加密。
      默认落点因此用 `.enc` 后缀；**给了 `dst` 就照你给的名字写、不改扩展名**（`--export-scan
      mypack.json` 被悄悄改名更难解释）—— 识别加密靠文件头那 21 个字节，不靠扩展名。
      默认**不**加密：加密与否是发包的人要显式决定的事。
    - `with_logs=True` → 把任务日志一起带走（默认不带，见文件头"刻意不带"）。
    """
    if task_ids:
        marks = ",".join("?" for _ in task_ids)
        rows = _rows("tasks", f" WHERE id IN ({marks})", tuple(int(t) for t in task_ids))
    else:
        rows = _rows("tasks")
    if owner_id is not None:
        rows = [r for r in rows if int(r.get("owner_id") or 0) == int(owner_id)]
    rows.sort(key=lambda r: int(r["id"]))

    stripped = 0
    dropped_logs = 0
    tasks_out = []
    logs, logs_bytes, logs_skipped = {}, 0, 0
    pw = bundle_passphrase(passphrase)
    for r in rows:
        row = dict(r)
        if not with_task_auth:
            for col in ("options", "run_payload"):
                obj = _json_obj(row.get(col))
                if obj is None:
                    continue
                clean, n = redact_auth(obj)
                if n:
                    row[col] = json.dumps(clean, ensure_ascii=False)
                stripped += n
        # 路径列与自由文本列：包里只许出现相对路径（AGENTS.md §0.3 那条硬规矩）
        _abs_log = row.get("log_file")
        rel = to_rel_path(row.get("log_file"))
        if str(row.get("log_file") or "").strip() and not rel:
            dropped_logs += 1
        row["log_file"] = rel
        if row.get("error"):
            row["error"] = scrub_paths(row["error"])
        if with_logs and _abs_log:
            # 判据是**在不在 LOGS_DIR 内**，不是"能不能相对化成项目根相对形"：
            # 容器 / CI 会把 `CTFSCANNER_LOGS` 指到项目根之外（`docker_todo/` 那套挂载就是这样），
            # 拿 `to_rel_path()` 的结果当门会把这类合法日志整批静默丢掉。
            # 包里的键统一用**相对 LOGS_DIR** 的路径 —— 它同样不含任何本机绝对路径。
            keep, _why = _log_inside_logs_dir(_abs_log)
            if keep is None:
                logs_skipped += 1
            else:
                blob = _read_log_bounded(keep)
                if blob is None or logs_bytes + len(blob) > LOG_TOTAL_CAP:
                    logs_skipped += 1
                else:
                    # 键与 `log_rel` 必须是**同一个值**（相对 LOGS_DIR）：两处不一致时导入侧
                    # 按 `log_rel` 去 `logs` 里取内容会取不到，日志就"在包里但导不出来"。
                    key = str(keep.relative_to(Path(LOGS_DIR).resolve()))
                    logs[key] = base64.b64encode(blob).decode("ascii")
                    logs_bytes += len(blob)
                    # `log_rel` 不是 `tasks` 的列，插入时被 `writeable` 那一句自然滤掉，不入库。
                    row["log_rel"] = key
        tasks_out.append(row)

    ids = [int(r["id"]) for r in tasks_out]
    assets = {}
    for t in db.ASSET_TABLES:
        if not ids:
            assets[t] = []
            continue
        marks = ",".join("?" for _ in ids)
        assets[t] = _rows(t, f" WHERE task_id IN ({marks})", tuple(ids))

    bundle = {
        "magic": MAGIC,
        "format": FORMAT,
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "source": {
            "app_version": _app_version(),
            "sqlite_version": sqlite3.sqlite_version,
            # 只记文件名不记绝对路径：`/home/alice/…` 这种机器上的目录结构对收包的人没用，
            # 还会把"这台机器上有哪些项目"写进一个要发给别人的文件。
            "db_name": db.DB_PATH.name,
        },
        "includes": {
            "tasks": len(tasks_out),
            "assets": {t: len(v) for t, v in assets.items()},
            "accounts": bool(with_users),
            "credential_files": list(CRED_FILES) if with_users else [],
            "task_auth": bool(with_task_auth),
            "task_auth_stripped": stripped,
            "log_paths_dropped": dropped_logs,
            "logs": bool(with_logs),
            "logs_included": len(logs),
            "logs_skipped": logs_skipped,
            "logs_bytes": logs_bytes,
            "encrypted": bool(pw),
        },
        "data": {"tasks": tasks_out, "assets": assets},
    }

    if with_users:
        absent = []
        for t in ACCOUNT_TABLES:
            # 新装的库里 `nodes` 还不存在（它不在 `db.SCHEMA` 里，由 `scanner/nodes.py` 建）——
            # 当"没有这一档"处理并说出来，而不是让整个导出崩在 SQL 错误上。
            if _cols(t):
                bundle["data"][t] = _rows(t)
            else:
                absent.append(t)
        bundle["includes"]["accounts_absent"] = absent
        creds = {}
        for rel in CRED_FILES:
            p = BASE_DIR / rel
            if p.is_file():
                creds[rel] = base64.b64encode(p.read_bytes()).decode("ascii")
        bundle["data"]["credentials"] = creds
        bundle["includes"]["credential_files_present"] = sorted(creds)

    if logs:
        bundle["data"]["logs"] = logs

    if dst:
        dst = Path(dst)
    else:
        # 名字必须唯一（同 `_preflight_snapshot`）：GUI 上连点两次「导出」、或脚本一秒内跑两次
        # `--export-scan`，旧写法会因为 `strftime` 只到秒而**静默盖掉前一份包** —— 而那份可能
        # 已经发给别人了。本轮 `[8am]` 的 harness 就是这么抓出来的（断言"恰好多出一个包"变红）。
        dst = _unique_path(default_dst(), f"migration_{time.strftime('%Y%m%d_%H%M%S')}",
                           ".enc" if pw else ".json")
    # 两条分支都要建目录：`_unique_path` 只**算名字**（目录不存在时 `exists()` 自然为假），
    # 只写不建就会 FileNotFoundError —— 现象是"新装机器第一次导出就失败"。
    dst.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(bundle, ensure_ascii=False, indent=1)
    if pw:
        # 加密走 keystore 的原子落盘（同目录 .part + `os.replace` + 0600）：半途失败不许留下一个
        # "看着像包、其实是残块"的文件。明文**从不**先落盘再加密。
        keystore.write_encrypted(dst, keystore.encrypt_text(text, pw, magic=BUNDLE_MAGIC))
        bundle["encrypted"] = True
    else:
        dst.write_text(text, encoding="utf-8")
    # 0600：带凭据的包只有本人该读；不带的也一起收紧 —— 权限位不该由"这次恰好没带口令"决定。
    try:
        os.chmod(dst, 0o600)
    except OSError:
        pass

    bundle["path"] = str(dst)
    bundle["bytes"] = dst.stat().st_size
    return bundle


def _app_version():
    from scanner import __version__
    return __version__


def read_bundle(src, passphrase=None):
    """读包并校验格式，返回 dict。读不懂就抛 `ValueError`（**不硬塞**）。

    加密包（`.enc`，头部 `CTFSCANNER-BUNDLE-V1`）在这一层就解开：调用方拿到的永远是同一个
    dict，`import_bundle` 不必到处分支。口令只来自参数或环境变量 `CTFSCANNER_BUNDLE_PASSPHRASE`
    —— 缺口令时报错说清"要设哪个变量"，绝不提示"把口令写在命令行里"。
    """
    src = Path(src)
    if not src.is_file():
        raise ValueError(f"迁移包不存在：{src}")
    raw = src.read_bytes()
    encrypted = raw.startswith(BUNDLE_MAGIC)
    if encrypted:
        pw = bundle_passphrase(passphrase)
        if not pw:
            raise ValueError(
                f"这是一个**加密**迁移包（{BUNDLE_MAGIC.rstrip(chr(0).encode()).decode('ascii')}）："
                f"请先设环境变量 {ENV_BUNDLE_PASSPHRASE}（口令不要写进命令行参数 —— 那会留在 "
                "ps / shell history / 其它进程可读的 /proc/<pid>/cmdline 里）")
        text, why = keystore.decrypt_blob(raw, pw, magic=BUNDLE_MAGIC)
        if text is None:
            raise ValueError(f"加密包解不开：{why}")
    elif raw.startswith(keystore.MAGIC_KEYS):
        raise ValueError(f"这个文件是**凭据文件**（keys.enc.yaml 那一族），不是迁移包：{src}")
    else:
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError(f"迁移包不是 UTF-8 文本，也不是本程序写的密文：{src}")
    try:
        bundle = json.loads(text)
    except ValueError as e:
        raise ValueError(f"迁移包不是合法 JSON：{src}（{e}）")
    if not isinstance(bundle, dict) or bundle.get("magic") != MAGIC:
        raise ValueError(f"不是 {MAGIC} 的迁移包：{src}")
    fmt = int(bundle.get("format") or 0)
    if fmt > FORMAT:
        raise ValueError(f"迁移包格式 v{fmt} 比本程序（v{FORMAT}）新 —— 请升级后再导入，"
                         "别用旧程序读新包（它会把读不懂的字段静默丢掉，等于少导一半数据）")
    if fmt < 1:
        raise ValueError(f"迁移包缺 format 字段或为 0，来源不明 —— 拒绝导入")
    bundle["encrypted"] = encrypted
    return bundle


class ImportAborted(ValueError):
    """导入中途失败。带着快照位置一起抛 —— 半份导入最需要的就是"退回去"这条路。"""

    def __init__(self, msg, snapshot=None):
        super().__init__(msg)
        self.snapshot = snapshot


def _unique_path(d, stem, suffix):
    """同一秒里不许撞名：`Path` 覆盖写会**静默丢掉上一份**，而这两处产物都是"出事时唯一的退路"。

    导出包与导入前快照原本各写各的加后缀循环（同一个规则两份实现，改一处漏一处），
    这里收成一处 —— 判据见 `_preflight_snapshot` 与 `export_bundle` 里各自的注释。
    """
    seq, dst = 0, Path(d) / f"{stem}{suffix}"
    while dst.exists():
        seq += 1
        dst = Path(d) / f"{stem}_{seq}{suffix}"
    return dst


def _preflight_snapshot():
    """导入前给**整库**拍一张快照（sqlite 的 backup API），返回路径。

    为什么导前必备：`import_bundle` 会连写十几张表，而 `db._exec` 是**每语句一提交**的，
    中途抛错（列名对不上、磁盘满、库被锁）就是"半份导入" —— 半份导入的新任务与本机自己的
    数据混在一起，事后既分不出哪些是刚进来的，也没有一键撤回的办法。
    ⚠️ 用 `sqlite3.Connection.backup()` 而不是 copy 文件：库开的是 WAL，直接 copy 会漏掉
    `-wal` 里尚未合并的页（快照本身就不完整，出事时才发现救不回来）。
    """
    trash = db.DB_PATH.parent / "trash"
    trash.mkdir(parents=True, exist_ok=True)
    # 名字必须唯一：`backup()` 是**覆盖目标库**的，两次导入落在同一秒里就会把上一份快照
    # 静默盖掉（实测连跑两次 import 拿到的是同一个文件名），而快照正是出事时唯一的退路。
    dst = _unique_path(trash, f"preflight_import_{time.strftime('%Y%m%d_%H%M%S')}", ".db")
    src = sqlite3.connect(str(db.DB_PATH))
    dst_conn = sqlite3.connect(str(dst))
    try:
        src.backup(dst_conn)
    finally:
        dst_conn.close()
        src.close()
    return dst


def import_bundle(src, dry_run=False, passphrase=None):
    """把迁移包导入本库，返回结果摘要 dict。

    四条设计口径（都是"导入不该毁掉已有东西"的具体化）：
    1. **任务一律给新 id**：包里的 `id` 只作为映射记录。同 id 覆盖会把本机已有任务的资产
       和别人的资产混成一体（`import_task_assets` 是纯 INSERT，不去重），事后分不开。
    2. **`status=running/queued/pending` 归一为 `stopped`、`pid` 归零**：那几个状态声称"本机有个进程
       在跑"，换机器后必然是假的。更糟的是包里的 `pid` 在新机器上可能正好属于某个无关进程，
       `reconcile_orphan_tasks()` 一探测"还活着"就把它永久卡在 running（既不报失败也不让人重启）。
       不自动续跑也是刻意的：导入完就自己开扫 = 用一份文件在别人机器上发起对外请求。
    3. **凭据文件与账号只在包里有、且库里没有同名时才写**：绝不覆盖本机已有的
       `keys.yaml` / 已有账号 —— 覆盖成包里的旧凭据，本机所有第三方接口会突然换一把钥匙。
    4. **`dry_run` 与真跑共用同一条代码路径**（各判据函数吃同一个旗标），不是另写一遍
       "试算"。两份实现必然漂，漂了之后 dry-run 报"没问题"、真跑却坏掉，比没有 dry-run 更糟。
       代价是 dry-run 也会做**幂等建表**（`init_db()` / `nodes.ensure()`）—— 它保证不写的是
       **数据行**，不是 DDL；不然试算会因为在空库上跑而报"缺表"，而真跑明明建得出这张表。
    5. **包里的日志写到 `LOGS_DIR/migrated_<时间戳>/` 下，绝不覆盖同名文件**（续136 的
       `--with-logs`）：日志路径按包里的**相对形**重建，再改回本机的绝对形写进 `tasks.log_file`
       —— 消费方是 `Path(...).parent` 这类用法，留相对路径会按进程 CWD 解析（AGENTS §7 那条）。
    """
    bundle = read_bundle(src, passphrase=passphrase)
    data = bundle.get("data") or {}
    inc = bundle.get("includes") or {}
    # 新库/空库先建表：`get_conn()` 只建目录、不建表，不 init 就是"表不存在"（本轮实测踩过）。
    db.init_db()
    out = {"dry_run": bool(dry_run), "tasks": {}, "assets": {},
           "users": {"added": 0, "skipped": 0}, "nodes": {"added": 0, "skipped": 0},
           "credentials": [], "warnings": [], "snapshot": None,
           "task_auth_in_bundle": int(inc.get("task_auth_stripped") or 0)}

    # **写之前**把"本库认不认识这张表"一次查干净。放在写之后才撞见 `no such table`，
    # 就变成"半份导入 + 靠快照退回"，而本该是"一个字都没动，你先把程序跑起来建库"。
    if data.get("nodes"):
        # `nodes` 不在 `db.SCHEMA` 里（它由 `scanner/nodes.py` 自己建），新装的库根本没有这张表。
        # 包里带节点数据时先把表建出来，而不是把人挡在门外说"你先去用一次节点功能"。
        from scanner import nodes as _nodes
        _nodes.ensure()
    need = ["tasks"] + [t for t in db.ASSET_TABLES if (data.get("assets") or {}).get(t)]
    need += [t for t in ACCOUNT_TABLES if data.get(t)]
    missing = [t for t in need if not _cols(t)]
    if missing:
        raise ValueError("本库缺少迁移包要用到的表：" + ", ".join(missing)
                         + "。`db.init_db()` 建不出来的那几张（如 nodes）由各自模块建 —— "
                         "先用本项目跑一次（启动 GUI 或任一 CLI 入口）建库，再导入")

    has_users = "users" in data
    if has_users:
        out["warnings"].append("本包**含账号口令哈希**（导出时带了 --with-users）——"
                               "导入后即成为本机登录凭据，请确认这台机器是该收的人。")
    if inc.get("task_auth"):
        out["warnings"].append("本包**含任务登录态请求头**（导出时带了 --with-task-auth）。")
    if bundle.get("encrypted"):
        out["warnings"].append("本包是**加密**迁移包，已按口令在内存里解开 —— 明文没有落过盘。")
    logs = data.get("logs") or {}
    if logs:
        out["warnings"].append(
            f"本包含 {len(logs)} 个任务日志（导出时带了 --with-logs）：日志里可能有第三方接口的"
            "返回原文、目标响应体与偶发的口令痕迹，请确认这台机器是该收的人。")
    log_by_task = {int(r.get("id") or 0): str(r.get("log_rel"))
                   for r in (data.get("tasks") or [])
                   if isinstance(r, dict) and r.get("log_rel")}

    cols = _cols("tasks")
    snap = None
    if not dry_run:
        snap = _preflight_snapshot()
        out["snapshot"] = snap

    try:
        for row in data.get("tasks") or []:
            if not isinstance(row, dict):
                continue
            old_id = int(row.get("id") or 0)
            new = dict(row)
            new["pid"] = 0
            new["log_file"] = to_abs_path(new.get("log_file"))
            if str(new.get("status") or "") in _LIVE_STATUSES:
                new["status"] = "stopped"
                out["warnings"].append(f"任务 #{old_id} 状态 {row.get('status')} → stopped"
                                       "（换机器后不存在那个进程；要接着跑请手动「续跑/重启」）")
            if not has_users and int(new.get("owner_id") or 0) != 0:
                # 账号没带过来，owner_id 在这台机器上指不到任何人 → 落成 0（无归属，仅管理员可见）。
                new["owner_id"] = 0
                out["warnings"].append(f"任务 #{old_id} 的 owner_id 归零（本包不含账号表）")
            writeable = [c for c in cols if c != "id" and c in new]
            lost = [k for k in new if k not in cols and k != "id" and k != "log_rel"]
            if lost:
                # 包里有、本库没有的列 = 导出的那版程序比这边新。静默丢一列，
                # 用户看到的是"数据少了一栏"却没人说过为什么。
                out["warnings"].append(f"任务 #{old_id} 有本库不认识的列被跳过：{', '.join(lost)}"
                                       "（导出方程序版本比这边新）")
            if dry_run:
                out["tasks"][old_id] = 0
                continue
            ph = ",".join("?" for _ in writeable)
            new_id = db._exec(f"INSERT INTO tasks ({', '.join(writeable)}) VALUES ({ph})",
                               tuple(new[c] for c in writeable))
            out["tasks"][old_id] = int(new_id)

        assets = data.get("assets") or {}
        for old_id, new_id in out["tasks"].items():
            # **按行自带的 task_id 切回本任务那一档**再交给 `import_task_assets` ——
            # 它会把整份快照的 `task_id` 一律改写成传入的那个号（节点回传场景里只有
            # 一个任务，所以它本来就假定"这份快照全属于同一任务"）。直接传整份的结果
            # 是实测过的：44 条子域名 × 7 个任务 = 308 条，每个任务都拿到别人的资产，
            # 而任务详情页看起来"这个站有 44 条子域名"，一条都分不出是别人的。
            snap_rows = {t: [r for r in (assets.get(t) or [])
                             if isinstance(r, dict) and int(r.get("task_id") or 0) == old_id]
                         for t in db.ASSET_TABLES}
            if not any(snap_rows.values()):
                continue
            if dry_run:
                for t, rws in snap_rows.items():
                    out["assets"][t] = out["assets"].get(t, 0) + len(rws)
                continue
            for t, n in db.import_task_assets(new_id, snap_rows).items():
                if n:
                    out["assets"][t] = out["assets"].get(t, 0) + n

        # 包里没这一档就**一次都不碰那张表**（默认导出不含账号表，而 `nodes` 不在 `db.SCHEMA` 里，
        # 空库上连 SELECT 都会 "no such table" —— 前置校验只担保"包里有的表"）。
        if data.get("users"):
            out["users"]["added"], out["users"]["skipped"] = _merge_accounts(
                "users", data["users"], key="username", dry_run=dry_run)
        if data.get("nodes"):
            out["nodes"]["added"], out["nodes"]["skipped"] = _merge_accounts(
                "nodes", data["nodes"], key="name", dry_run=dry_run)
        for rel, blob in (data.get("credentials") or {}).items():
            out["credentials"].append(_write_cred(rel, blob, dry_run=dry_run))
        if logs:
            out["logs"] = _restore_logs(logs, log_by_task, out["tasks"], dry_run=dry_run)
            if out["logs"].get("refused"):
                out["warnings"].append(
                    f"{out['logs']['refused']} 个日志路径落在 LOGS_DIR 之外 —— 已拒绝写入"
                    "（按别人给的路径往本机任意位置写文件，`_write_cred` 同口径）")
    except sqlite3.Error as e:
        raise ImportAborted(
            f"导入在第 {len(out['tasks'])} 个任务处中断：{e} —— 已写入的行**不会自动撤回**，"
            "请先用整库快照退回再重来", snapshot=snap) from e
    return out


def _restore_logs(logs, by_task, mapping, dry_run=False):
    """把包里的日志落到 `LOGS_DIR/migrated_<时间戳>/` 下，并把 `tasks.log_file` 接回新任务。

    三条硬规矩，都是"导入不该毁掉已有东西 / 不该给包作者本机写文件的权力"的具体化：
    ① **路径解析必须仍在 LOGS_DIR 之内**（包里给 `../../etc/x` 一律 `refused`，与 `_write_cred`
       同一个口径 —— 键是相对 LOGS_DIR 的，但那只是导出侧诚实的产物，不能当输入校验用）；
    ② **同名不覆盖**：本机已有同名文件就加 `_N` 序号，覆盖等于抹掉上一次导入的现场；
    ③ 权限收到 **0600**：日志里有第三方接口返回原文与目标响应体。

    `dry_run` 只数不改：写不进去（磁盘、权限）这类错误在试算阶段暴露不出来，所以试算报的是
    "打算写几个"，真跑报的是"实际写了几个"，两者分开列出，不假装是同一个数。
    """
    root = Path(LOGS_DIR).resolve()
    base = root / f"migrated_{time.strftime('%Y%m%d_%H%M%S')}"
    res = {"dir": str(base), "would_write": 0, "written": 0, "skipped": 0, "refused": 0}
    for old_id, rel in (by_task or {}).items():
        new_id = mapping.get(old_id)
        blob = logs.get(rel)
        if blob is None:
            res["skipped"] += 1          # 任务带 log_rel 但包里没那份内容（包被改过 / 版本不符）
            continue
        if not isinstance(new_id, int):
            res["skipped"] += 1
            continue
        target = _safe_log_target(root, base, rel)
        if target is None:
            res["refused"] += 1
            continue
        if dry_run:
            res["would_write"] += 1
            continue
        try:
            raw = base64.b64decode(str(blob), validate=True)
        except Exception:
            res["skipped"] += 1
            continue
        dst = target
        seq = 0
        while dst.exists():
            seq += 1
            dst = target.with_name(f"{target.stem}_{seq}{target.suffix}")
        try:
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(raw)
            try:
                os.chmod(dst, 0o600)
            except OSError:
                pass                      # Windows 没有 POSIX 位
            db.update_task(int(new_id), log_file=str(dst))
            res["written"] += 1
        except OSError:
            res["skipped"] += 1
    return res


def _safe_log_target(root, base, rel):
    """把包给的相对路径拼进 `base`，**越出 LOGS_DIR 就返回 None**。"""
    r = str(rel or "").replace("\\", "/").strip("/")
    if not r or r.startswith("/") or ".." in Path(r).parts:
        return None
    try:
        p = (base / r).resolve()
    except OSError:
        return None
    if root not in p.parents and p != base:
        return None
    return p


def _merge_accounts(table, rows, key, dry_run=False):
    """账号表按 `key`（用户名 / 节点名）**只增不改**，返回 (新增, 跳过)。

    跳过的是"本机已有同名"——覆盖等于用包里的旧哈希顶掉本机口令，
    而迁移包是会被人传来传去的文件，这种覆盖必须不发生。
    """
    have = {str(r[key]).strip().lower() for r in _rows(table, f" WHERE {key} IS NOT NULL")}
    cols = [c for c in _cols(table) if c != "id"]
    added = skipped = 0
    for row in rows:
        if not isinstance(row, dict):
            continue
        name = str(row.get(key) or "").strip()
        if not name or name.lower() in have:
            skipped += 1
            continue
        if not dry_run:
            writeable = [c for c in cols if c in row]
            db._exec(f"INSERT INTO {table} ({', '.join(writeable)}) VALUES "
                     f"({','.join('?' for _ in writeable)})", tuple(row[c] for c in writeable))
        have.add(name.lower())
        added += 1
    return added, skipped


def _write_cred(rel, blob, dry_run=False):
    """落地一个凭据文件：目录不存在就建，**已存在就绝不覆盖**，权限收到 0600。

    `dry_run` 走的是**同一串判据**（路径越界 / base64 能不能解 / 本机有没有同名），
    只是最后一步不写盘 —— 这样"试算说会被拒"和"真跑被拒"永远是同一件事。
    """
    p = (BASE_DIR / str(rel)).resolve()
    if BASE_DIR not in p.parents:
        return {"file": str(rel), "status": "refused", "reason": "路径越出项目根"}
    try:
        raw = base64.b64decode(str(blob), validate=True)
    except Exception as e:
        return {"file": str(rel), "status": "failed", "reason": f"base64 解码失败：{e}"}
    if p.exists():
        return {"file": str(rel), "status": "skipped", "reason": "本机已有同名文件（不覆盖）"}
    if dry_run:
        return {"file": str(rel), "status": "would-write", "reason": f"{len(raw)} 字节，0600"}
    p.parent.mkdir(parents=True, exist_ok=True)
    try:
        p.write_bytes(raw)
        os.chmod(p, 0o600)
    except OSError as e:
        return {"file": str(rel), "status": "failed", "reason": str(e)}
    return {"file": str(rel), "status": "written", "reason": f"{len(raw)} 字节，0600"}
