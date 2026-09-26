"""访问审计流水（续48）—— 谁、何时、从哪个 IP、对什么对象做了什么、成败如何。

为什么需要它：续46 起控制台是**多用户**、续47 起能**放到服务器上**给队友用。此时"谁在什么时候
建了哪个任务 / 改了口令 / 动了策略"必须可回溯 —— 出问题时能分清"是队友误操作"还是"账号被盗用"。

设计边界（红线，见 tests/smoke.py [7j] 的凭据红线断言）：
- **只记元数据**（用户名 / 角色 / IP / 对象 / 一句话说明 / 成败），**绝不记口令、凭据、API key**：
  写入侧（各路由）只传"改了哪一块 / 动了哪个对象"，不传值；`_scrub()` 再兜底擦洗一遍
  `password=…` / `token=…` / `Bearer …` / `pbkdf2_sha256$…` 这类形状，防手滑。
- **审计失败绝不阻断主流程**：`record()` 内部 try/except，写不进去只打 warning —— 审计是"旁路记录"，
  不能因为它挂了就让管理员建不了任务（可用性优先；代价是"审计可能缺条"，表现为"没有该条"）。
- 落库走 `db._exec`（复用全库唯一的写锁与连接管理）；表由 `db.SCHEMA` 的
  `CREATE TABLE IF NOT EXISTS` 建出（老库原地补表）。
- `retention_days` 默认 30：`prune()` **只清 `audit_log` 一张表**，绝不碰任何业务数据。
"""
import re
import time

from . import db
from .log import get_logger

logger = get_logger("audit")

# ---- 事件类型（kind）----
KIND_LOGIN_OK = "login_ok"           # 登录成功
KIND_LOGIN_FAIL = "login_fail"       # 登录失败（用户名/口令错、账号停用、引导口令错）
KIND_LOGIN_BLOCKED = "login_blocked"  # 被限速拦截（未走到校验口令那一步）
KIND_LOGOUT = "logout"               # 退出登录
KIND_ACCOUNT = "account"             # 账号操作（建/改口令/停用/改角色/删除/清审计）
KIND_SETTINGS = "settings"           # 保存策略配置（只记改了哪一块，**不记值**）
KIND_POC = "poc"                     # POC 管理（上传/启停/批量/刷新）
KIND_TASK = "task"                   # 任务操作（建/停/删/重启/续跑/追加/批量）
KIND_DENIED = "denied"               # 越权访问被拒（子用户敲管理页 URL）

KINDS = (KIND_LOGIN_OK, KIND_LOGIN_FAIL, KIND_LOGIN_BLOCKED, KIND_LOGOUT,
         KIND_ACCOUNT, KIND_SETTINGS, KIND_POC, KIND_TASK, KIND_DENIED)

# 页面展示用的中文标签
KIND_LABELS = {
    KIND_LOGIN_OK: "登录成功",
    KIND_LOGIN_FAIL: "登录失败",
    KIND_LOGIN_BLOCKED: "登录被拦截",
    KIND_LOGOUT: "退出登录",
    KIND_ACCOUNT: "账号操作",
    KIND_SETTINGS: "策略配置",
    KIND_POC: "POC 管理",
    KIND_TASK: "任务操作",
    KIND_DENIED: "越权访问",
}

DEFAULT_RETENTION_DAYS = 30
MAX_DETAIL_LEN = 500
DEFAULT_LIMIT = 200
MAX_LIMIT = 1000

# 兜底擦洗：把 `<敏感键><分隔符><值>` 形状整体抹掉。正常路径下调用侧根本不传这些值，
# 这里只是"手滑也不会把凭据写进审计"的最后一道网。
_SECRET_KEY = (r"password|passwd|pwd|token|secret|api[_-]?key|apikey|"
               r"authorization|cookie|access[_-]?key|private[_-]?key")
_SCRUB_PATTERNS = (
    re.compile(r"(?i)\b(" + _SECRET_KEY + r")\b\s*[:=]\s*\S+"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{4,}"),
    re.compile(r"pbkdf2_sha256\$[^\s]+"),
)


def _now():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _scrub(text):
    """把 detail 里可能出现的凭据形状抹掉，并截断到 `MAX_DETAIL_LEN`。

    返回的一定是**文本**（None → ""）；这是"绝不把凭据写进审计"的兜底，
    与调用侧"只传键名/对象名、不传值"共同构成两道网。
    """
    s = str(text or "")
    for pat in _SCRUB_PATTERNS:
        s = pat.sub("***", s)
    return s[:MAX_DETAIL_LEN]


def config(settings):
    """读取 `gui.audit` 配置（缺项用默认；类型不对也回默认）。"""
    cfg = ((settings or {}).get("gui") or {}).get("audit")
    if not isinstance(cfg, dict):
        cfg = {}
    days = cfg.get("retention_days", DEFAULT_RETENTION_DAYS)
    try:
        days = int(days)
    except (TypeError, ValueError):
        days = DEFAULT_RETENTION_DAYS
    return {"enabled": bool(cfg.get("enabled", True)), "retention_days": max(0, days)}


def record(kind, actor, ip, target="", detail="", ok=True, actor_role="", settings=None):
    """写一条审计流水，返回是否真的落库（被开关关掉 / 写失败 → False）。

    签名与调用侧约定一致：`record(kind, actor, ip, target="", detail="", ok=True)`；
    `actor_role` 与 `settings` 是可选补充。**任何异常都被吞掉并只打 warning** ——
    审计是旁路，绝不能因为它挂了而阻断登录 / 建任务（可用性优先）。
    """
    try:
        if not config(settings)["enabled"]:
            return False
        db._exec(
            "INSERT INTO audit_log(at, kind, actor, actor_role, ip, target, detail, ok) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (_now(), str(kind or "")[:40], str(actor or "")[:64], str(actor_role or "")[:16],
             str(ip or "")[:64], str(target or "")[:200], _scrub(detail), 1 if ok else 0))
        return True
    except Exception as e:      # noqa: BLE001 - 审计失败绝不阻断主流程
        try:
            logger.warning(f"[audit] 审计写入失败（已忽略）：{e}")
        except Exception:
            pass
        return False


def query(kind=None, actor=None, ip=None, ok=None, q=None, since=None, until=None,
          limit=DEFAULT_LIMIT, offset=0):
    """按条件分页查询审计流水，返回 `(rows, total)`；`rows` 是 dict 列表（供模板直接取字段）。

    - `kind` / `actor` / `ip` 精确匹配；`ok` 三态（None=全部 / True / False）；
    - `since` / `until` 是 `'YYYY-MM-DD HH:MM:SS'` 边界（含端点，字符串可比大小）；
    - `q` 是"整行关键字"（对 actor / target / detail / ip 做 LIKE）。
    """
    where, params = [], []
    if kind:
        where.append("kind=?")
        params.append(str(kind))
    if actor:
        where.append("actor=?")
        params.append(str(actor))
    if ip:
        where.append("ip=?")
        params.append(str(ip))
    if ok is not None:
        where.append("ok=?")
        params.append(1 if ok else 0)
    if since:
        where.append("at>=?")
        params.append(str(since))
    if until:
        where.append("at<=?")
        params.append(str(until))
    if q:
        where.append("(actor LIKE ? OR target LIKE ? OR detail LIKE ? OR ip LIKE ?)")
        params.extend([f"%{q}%"] * 4)
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    limit = max(1, min(int(limit or DEFAULT_LIMIT), MAX_LIMIT))
    offset = max(0, int(offset or 0))
    try:
        total = db._query(f"SELECT COUNT(*) c FROM audit_log{clause}", tuple(params), one=True)
        rows = db._query(
            f"SELECT * FROM audit_log{clause} ORDER BY id DESC LIMIT ? OFFSET ?",
            tuple(params) + (limit, offset))
    except Exception as e:      # 表还没建（纯 CLI 场景）→ 空结果，不抛
        try:
            logger.warning(f"[audit] 审计查询失败：{e}")
        except Exception:
            pass
        return [], 0
    return [dict(r) for r in rows], int(total["c"] if total else 0)


def summary(settings=None):
    """审计概览：总数 + 各 kind 计数（`/audit` 页头部展示）。"""
    out = {"total": 0, "by_kind": {}, "retention_days": config(settings)["retention_days"]}
    try:
        for r in db._query("SELECT kind k, COUNT(*) c FROM audit_log GROUP BY kind"):
            out["by_kind"][r["k"]] = r["c"]
        out["total"] = sum(out["by_kind"].values())
    except Exception:
        pass
    return out


def prune(days=None, settings=None):
    """删掉**严格早于** `now - days 天` 的审计行，返回删除条数。**只碰 `audit_log` 一张表**。

    `days` 缺省取 `gui.audit.retention_days`。用独立连接直接 `DELETE` 以便拿 `rowcount`
    （`db._exec` 返回的是 `lastrowid`，在 DELETE 上恒为 0）。任何异常都吞掉返回 0 ——
    启动时的清理绝不能拖垮控制台。
    """
    try:
        if days is None:
            days = config(settings)["retention_days"]
        days = max(0, int(days))
        cutoff = time.strftime("%Y-%m-%d %H:%M:%S",
                               time.localtime(time.time() - days * 86400))
        with db._WRITE_LOCK:
            conn = db.get_conn()
            try:
                cur = conn.cursor()
                cur.execute("DELETE FROM audit_log WHERE at < ?", (cutoff,))
                n = cur.rowcount or 0
                conn.commit()
                return n
            finally:
                conn.close()
    except Exception as e:      # noqa: BLE001
        try:
            logger.warning(f"[audit] 清理过期审计失败（已忽略）：{e}")
        except Exception:
            pass
        return 0
