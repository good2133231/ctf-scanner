"""分布式执行节点（续80）—— **中心控制 API + 节点轮询**。

## 为什么是这个形态（而不是"把 SQLite 换成网络数据库"）

roadmap 那条原文写的是"多个执行节点认领任务（需要先替换 SQLite）"。真要换 Postgres/MySQL：
① 要引入数据库驱动（**违背本项目"零第三方依赖"的一贯取舍**）；② 要重写整个 `db.py` 的
连接/事务/迁移；③ 还要处理"多写者"—— 而现在全框架只有一个 `db._WRITE_LOCK`（**进程内**），
跨进程写同一份 SQLite 是不安全的。

换个角度就简单了：**控制端（GUI 进程）本来就是唯一的库写入者**。那就让控制端**继续独占库**，
把"共享存储"这件事交给控制端自己 —— 节点通过 HTTP **领任务 / 报心跳 / 回传结果**，
它自己那台机器上跑扫描（写它**本地**的库），跑完把**资产快照**回传，控制端并回自己的库。
于是节点是**无状态执行器**，不需要碰控制端的数据库。

## 职责边界

- **控制端**用：`create/list_all/verify/revoke/touch/claim/finish`（`gui/app.py` 的 `/api/node/*` 调）；
- **节点端**用：`NodeClient`（HTTP 客户端，`cli/run_node.py` 调）。
- 真正的执行循环在 `cli/run_node.py`；本模块不跑流水线。

## 安全口径

- 节点令牌**只存 sha256**（明文只在创建时返回一次），与账号口令同一套思路；
- 每个 `/api/node/*` 请求都要带 `X-Node-Token`，校验失败一律 401；
- 令牌可**吊销**（`revoke` → `enabled=0`），吊销后立刻失效；
- 节点拿到的只有**任务入参**（目标/阶段/选项），**拿不到控制端的库、也拿不到别的任务**。
"""
import hashlib
import json
import secrets
import time

from . import db
from .log import get_logger

logger = get_logger("nodes")

# 在线判定窗口（秒）：心跳间隔（默认 20s）的 4 倍多一点，容忍一次丢包
ONLINE_WINDOW = 90
# 令牌前缀：便于在配置/日志里一眼认出，也方便泄漏时全仓搜索
TOKEN_PREFIX = "ctfsn_"
# 队列运行模式（与 db._QUEUE_MODES 同口径；这里复制一份避免 nodes→db 的反向依赖细节）
_QUEUE_MODES = ("fresh", "append", "resume")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS nodes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  enabled INTEGER DEFAULT 1,
  last_seen TEXT DEFAULT '',
  status TEXT DEFAULT '',
  current_task INTEGER DEFAULT 0,
  note TEXT DEFAULT '',
  created_at TEXT
);
"""


def ensure():
    """建 `nodes` 表（幂等）。控制端启动与 CLI 管理入口都会调。"""
    with db._WRITE_LOCK:
        conn = db.get_conn()
        try:
            conn.executescript(_SCHEMA)
            conn.commit()
        finally:
            conn.close()


def _hash(token):
    return hashlib.sha256(str(token or "").encode("utf-8")).hexdigest()


def create(name):
    """新建节点，返回 `(id, token)`；重名 / 空名返回 `(None, 原因)`。

    **token 明文只在这里返回一次**（库里只存 sha256，之后再也拿不回来）。
    """
    ensure()
    name = str(name or "").strip()
    if not name:
        return None, "节点名不能为空"
    if db._query("SELECT id FROM nodes WHERE name=?", (name,), one=True):
        return None, f"节点名已存在：{name}"
    token = TOKEN_PREFIX + secrets.token_urlsafe(24)
    nid = db._exec(
        "INSERT INTO nodes(name, token_hash, enabled, last_seen, status, current_task, note, created_at) "
        "VALUES(?,?,?,?,?,?,?,?)",
        (name, _hash(token), 1, "", "offline", 0, "", db._now()))
    logger.info(f"[nodes] 新建节点 #{nid}：{name}（令牌只显示一次）")
    return int(nid), token


def list_all():
    ensure()
    return db._query("SELECT * FROM nodes ORDER BY id")


def get(node_id):
    ensure()
    return db._query("SELECT * FROM nodes WHERE id=?", (int(node_id),), one=True)


def verify(token):
    """按令牌找**启用中**的节点；找不到 / 空令牌返回 None（调用方一律 401）。"""
    ensure()
    t = str(token or "").strip()
    if not t:
        return None
    return db._query("SELECT * FROM nodes WHERE token_hash=? AND enabled=1",
                     (_hash(t),), one=True)


def revoke(node_id):
    ensure()
    db._exec("UPDATE nodes SET enabled=0 WHERE id=?", (int(node_id),))
    logger.info(f"[nodes] 吊销节点 #{int(node_id)}")


def touch(node_id, status=None, current_task=None, note=None):
    """更新心跳（`last_seen=now`）；只改传进来的字段。节点掉线后仍保留最后一次状态。"""
    ensure()
    fields = {"last_seen": db._now()}
    if status is not None:
        fields["status"] = str(status)[:32]
    if current_task is not None:
        fields["current_task"] = int(current_task)
    if note is not None:
        fields["note"] = str(note)[:200]
    sets = ", ".join(f"{k}=?" for k in fields)
    db._exec(f"UPDATE nodes SET {sets} WHERE id=?", (*fields.values(), int(node_id)))


def is_online(row, now=None):
    """按 `last_seen` 判定在线（空 = 从未连过 → 离线）。"""
    ts = str((row["last_seen"] if row else "") or "")
    if not ts:
        return False
    t = db._parse_ts(ts)
    if t is None:
        return False
    return (now if now is not None else time.time()) - t <= ONLINE_WINDOW


def spec_of(row):
    """把认领到的任务行拼成节点要的执行规格（口径与 `queue._load_run_spec` 一致）。"""
    keys = row.keys()
    payload = {}
    try:
        payload = json.loads((row["run_payload"] if "run_payload" in keys else "") or "{}")
    except (TypeError, ValueError):
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    stages = payload.get("stages")
    if not isinstance(stages, list) or not stages:
        stages = [s for s in (row["stages"] or "").split(",") if s]
    options = payload.get("options")
    if not isinstance(options, dict):
        try:
            options = json.loads(row["options"] or "{}")
        except (TypeError, ValueError):
            options = {}
        if not isinstance(options, dict):
            options = {}
    mode = str(row["run_mode"] or "fresh").strip().lower() or "fresh"
    return {"task_id": int(row["id"]), "name": row["name"], "targets": row["targets"],
            "stages": [str(s) for s in stages], "options": options, "mode": mode}


def _mark_offline(node_id, note=""):
    """把节点标成离线并**清掉它的 current_task**（不碰 `last_seen` —— 那会把它又算成在线）。"""
    db._exec("UPDATE nodes SET status='offline', current_task=0, note=? WHERE id=?",
             (str(note)[:200], int(node_id)))


def reclaim_stale(now=None):
    """把**掉线节点**正在跑的任务重新入队，返回被回收的任务号列表（续81）。

    为什么要它：节点认领后任务转 `running`；节点要是死了（掉电 / 被杀 / 断网），那条任务
    就**永远停在 running**，谁也领不到。本函数在**每次认领前**跑一遍（`claim()` 调），
    把"心跳超时 + 还挂着任务"的节点名下的任务重新入队。

    ⚠️ **前提是节点在跑任务期间也发心跳**（`cli/run_node.py` 有运行期心跳线程）——
    否则一条跑很久的任务会被当成掉线而**误回收**。

    重新入队的模式规则与 `db.reconcile_orphan_tasks` 一致：
    原 `resume`→`resume`、原 `append`→`append`、原 `fresh` 且有断点→`resume`、否则 `fresh`。
    """
    now = now if now is not None else time.time()
    out = []
    for row in list_all():
        if not int(row["enabled"] or 0):
            continue
        if not str(row["last_seen"] or ""):
            continue                       # 从未连过 → 没有"它正在跑"这回事
        if is_online(row, now=now):
            continue
        tid = int(row["current_task"] or 0)
        if not tid:
            _mark_offline(int(row["id"]), "心跳超时")
            continue
        task = db.get_task(tid)
        if task and task["status"] == "running":
            mode = str(task["run_mode"] or "fresh").strip().lower()
            if mode not in _QUEUE_MODES:
                mode = "fresh"
            if mode == "fresh" and str(task["current_stage"] or "").strip():
                mode = "resume"
            db.enqueue_task(tid, mode=mode)
            out.append(tid)
            logger.warning(f"[nodes] 节点 #{row['id']} 掉线，任务 #{tid} 已重新入队（{mode}）")
        _mark_offline(int(row["id"]), f"心跳超时，已回收任务 #{tid}")
    return out


def claim(node_id):
    """节点认领下一个排队任务；没有就返回 `None`。

    **原子性复用 `db.claim_next_queued()`**（`WHERE status='queued'` 的原子 UPDATE）——
    多个节点同时来领，只有一个拿得到同一条任务。
    """
    ensure()
    try:
        reclaim_stale()                # 认领前先收掉掉线节点的任务（续81）
    except Exception as exc:           # noqa: BLE001 - 回收失败绝不能挡住认领
        logger.warning(f"[nodes] 回收掉线任务失败（不影响认领）：{exc}")
    row = db.claim_next_queued()
    if row is None:
        touch(node_id, status="idle", current_task=0)
        return None
    touch(node_id, status="busy", current_task=int(row["id"]))
    spec = spec_of(row)
    # 续83：续跑 / 追加要把**控制端已有的资产**一起下发 —— 节点本地库是空的，
    #   不灌进去的话 `resume` 找不到断点（会全量重跑）、`append` 会丢掉已采资产。
    if spec["mode"] in ("resume", "append"):
        spec["current_stage"] = str(row["current_stage"] or "")
        spec["assets"] = db.dump_task_assets(int(row["id"]))
    return spec


def finish(node_id, task_id, status="done", note="", counts=None, assets=None):
    """节点回传结果：把任务收成终态、合并资产快照，并把节点置回空闲。

    `status` 三种取值（续90）：
    - `running` → **增量上传**：只并资产、**不动终态、不把节点置空闲**（节点还在跑）；
    - `done` / `failed` → 终态（其余一律当 `failed`，避免节点乱传状态把任务挂半空）。

    为什么要增量：节点原来**只在跑完时整体回传一次** —— 掉线（掉电/被杀/断网）就意味着
    它这次已经采到的资产**全丢**（控制端只有上一次快照）。边跑边传把损失压到"最后一个周期"。
    """
    raw = str(status or "").strip().lower()
    task = db.get_task(int(task_id))
    if not task:
        return {"ok": False, "reason": "任务不存在"}
    imported = {}
    if isinstance(assets, dict) and assets:
        imported = db.import_task_assets(int(task_id), assets)
    if raw == "running":
        # 增量上传：只并资产 + 刷新心跳，**不碰终态**
        touch(node_id, status="busy", current_task=int(task_id))
        return {"ok": True, "status": "running", "imported": imported}
    st = "done" if raw == "done" else "failed"
    db.finish_task_run(int(task_id), status=st)
    if st == "failed" and note:
        db.append_task_error(int(task_id), f"[node] {note}")
    touch(node_id, status="idle", current_task=0, note=note)
    logger.info(f"[nodes] 节点 #{int(node_id)} 回传任务 #{int(task_id)}：{st}"
                f"（导入 {sum(imported.values()) if imported else 0} 行资产）")
    return {"ok": True, "status": st, "imported": imported, "counts": counts or {}}


def report_progress(task_id, stage=None, progress=None):
    """节点心跳带上来的进度 → 更新控制端任务的 `current_stage` / `progress`（续83）。

    为什么需要：节点跑任务时**写的是它自己的本地库**，控制端那条任务行的 `current_stage` /
    `progress` 一直是认领时的样子（进度条不动、断点也不准）。节点把本地进度报回来，
    控制台的进度条才反映真实进展。

    只对**确实在跑**的任务写（`running` / `queued`）—— 避免节点迟到的心跳把已完成的任务改回去。
    """
    if not task_id:
        return
    task = db.get_task(int(task_id))
    if not task or task["status"] not in ("running", "queued"):
        return
    fields = {}
    if stage is not None:
        fields["current_stage"] = str(stage)[:64]
    if progress is not None:
        try:
            fields["progress"] = max(0, min(100, int(progress)))
        except (TypeError, ValueError):
            pass
    if fields:
        db.update_task(int(task_id), **fields)


# ---------------- 节点端：HTTP 客户端（只用 requests，不碰控制端的库） ----------------

class NodeClient:
    """节点侧客户端：把控制端当"任务源 + 结果汇"。

    `insecure=True` 才跳过 TLS 校验（控制端常用自签证书；默认**校验**，避免中间人）。
    """

    def __init__(self, base, token, name="", timeout=30, insecure=False):
        self.base = str(base or "").rstrip("/")
        self.token = str(token or "")
        self.name = str(name or "")
        self.timeout = int(timeout or 30)
        self.insecure = bool(insecure)

    def _post(self, path, payload):
        import requests
        resp = requests.post(self.base + path, json=payload, timeout=self.timeout,
                             verify=not self.insecure,
                             headers={"X-Node-Token": self.token, "Content-Type": "application/json"})
        if resp.status_code == 404:
            # 续138：控制台默认挂在**每次启动随机生成**的两段路径下。`--controller` 只写到
            # `http://host:5000` 就会一路 404，而那个 404 是**空响应体**（刻意的：不给探测者任何
            # 信息）—— 于是现象只是"节点安静地不领任务"。这句话必须进异常，否则没人往这上面想。
            raise RuntimeError(
                f"控制端对 {path} 回了 404 且响应体为空。控制端开着后台路径随机化时（默认开，续138），"
                "--controller 必须填启动横幅里那行**含前缀的完整地址**"
                "（形如 http://10.0.0.5:5000/xxxxxxxxxx/yyyyyyyyyy）；前缀每次启动都换，"
                "重启过控制端就要同步改这里。")
        resp.raise_for_status()
        return resp.json()

    def heartbeat(self, task_id=0, status="idle", note="", stage=None, progress=None):
        body = {"name": self.name, "task_id": int(task_id or 0),
                "status": status, "note": note}
        if stage is not None:
            body["stage"] = stage
        if progress is not None:
            body["progress"] = progress
        return self._post("/api/node/heartbeat", body)

    def claim(self):
        """领一个任务；没有返回 None。"""
        data = self._post("/api/node/claim", {"name": self.name})
        task = (data or {}).get("task")
        return task if isinstance(task, dict) else None

    def result(self, task_id, status, note="", counts=None, assets=None):
        return self._post("/api/node/result",
                          {"name": self.name, "task_id": int(task_id), "status": status,
                           "note": note, "counts": counts or {}, "assets": assets or {}})
