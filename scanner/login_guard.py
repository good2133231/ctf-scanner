"""登录限速 / 失败锁定（续48）—— 两级：**按 IP 为主、按用户名兜底**。

为什么要两级：
- 按 IP：挡住"一台机器对着一个账号狂试口令"（最常见）；
- 按用户名：兜住"分布式 IP 打同一个账号"（每 IP 都没到阈值，但同一账号的失败总量异常）。
  阈值刻意比 IP 宽松（默认 20 vs 10）—— 它是**兜底**，不该让一次"队友集体记错口令"就把账号锁死。

计数放在**独立的 `login_fails` 表**（不是复用 `audit_log`）：`audit_log` 是**只追加的审计流水**
（`prune()` 只按保留期清），而限速计数是**可变状态**（成功登录要清该用户名的计数、锁定要打标记）。
两种语义混在一张表里，任一侧改动都会波及另一侧；分表后审计流水保持"只追加"，限速状态可自由增删，
且 `gui.audit` 关掉不影响限速、`gui.login_lockout` 关掉也不影响审计。

模型（fail2ban 式，语义明确）：
- 每次失败落一行 `kind='fail'`（`at` = 失败时刻）；
- 若**最近 `window_seconds` 内**该键的失败数达到阈值 → 落一行 `kind='lock'`（锁标记），
  锁定从该行时刻起持续 `lockout_seconds`；
- `check()` 只看"有没有仍在有效期内的锁标记"，**只读、不写任何状态** —— 这样被拦截的请求
  不会把计数越刷越大（否则攻击者能靠持续请求让锁永不过期 / 把表撑爆）。

安全语义（红线，逐条对应 tests/smoke.py [7j]）：
- **不泄漏账号是否存在**：`check()` 只按"提交的用户名 + IP"判定，**不查库**；
  "账号存在但被锁"与"账号不存在但被锁"返回**逐字节相同**的 429 页面；
- 锁定期内**即使口令正确也拒绝**（先问 guard，再校验口令）；
- **计数不无界增长**：成功登录清该用户名计数；锁定期间不再落 `fail`；`prune()` 清过期行；
- `gui.token` 引导口令登录**同样受 IP 限速**（check 在所有分支之前）；
- guard 自身出错**绝不阻断登录**（调用侧 try/except → 放行 + warning）。

自救：管理员/队友被锁在门外时，等 `lockout_seconds` 自动过期，或命令行清除（见文件末尾 `__main__`，
也写在 docs/deploy-https.md §7）。
"""
import time
from collections import namedtuple

from . import db
from .log import get_logger

logger = get_logger("login-guard")

# `gui.login_lockout` 的默认值（**保护性开关默认开、阈值刻意宽松**，见 gui/app.py 的登录接线）。
DEFAULTS = {
    "enabled": True,
    "window_seconds": 300,      # 失败计数的时间窗（秒）
    "max_fails_per_ip": 10,     # 主判据：同一 IP 在窗口内的失败上限
    "max_fails_per_user": 20,   # 兜底判据：同一用户名在窗口内的失败上限（更宽松）
    "lockout_seconds": 900,     # 触发后的锁定时长（秒）
}

# 判定结果：locked=是否拦截；retry_after=建议的 Retry-After 秒数；reason=给审计/页面用的一句话。
Verdict = namedtuple("Verdict", "locked retry_after reason")
Verdict.__new__.__defaults__ = (False, 0, "")


def _now():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _ts(epoch):
    """epoch 秒 → `'YYYY-MM-DD HH:MM:SS'`（与全库 `_now()` 同格式，可直接字符串比大小）。"""
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(epoch)))


def _epoch(value):
    """`'YYYY-MM-DD HH:MM:SS'` → epoch 秒；解析不出返回 None（**不猜**）。"""
    try:
        return time.mktime(time.strptime(str(value or "").strip(), "%Y-%m-%d %H:%M:%S"))
    except (ValueError, TypeError, OverflowError):
        return None


def _as_epoch(now):
    """把 `now` 参数归一成 epoch 秒：None → 当前时间；数字直接当 epoch；字符串按时间戳解析。"""
    if now is None:
        return time.time()
    if isinstance(now, (int, float)):
        return float(now)
    e = _epoch(now)
    return e if e is not None else time.time()


def _int_of(value, default):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def config(settings):
    """读取 `gui.login_lockout`（缺项用默认；类型不对也回默认；负数一律归 0）。"""
    cfg = ((settings or {}).get("gui") or {}).get("login_lockout")
    if not isinstance(cfg, dict):
        cfg = {}
    out = {"enabled": bool(cfg.get("enabled", DEFAULTS["enabled"]))}
    for key in ("window_seconds", "max_fails_per_ip", "max_fails_per_user", "lockout_seconds"):
        out[key] = max(0, _int_of(cfg.get(key, DEFAULTS[key]), DEFAULTS[key]))
    return out


def norm_username(username):
    """用户名归一 —— **必须与 `users.get_by_name()` 同口径**（`str(...).strip()`、大小写敏感）。

    两处口径一旦漂移，就会出现"按用户名计数记在 A、按用户名查询查的是 B"的静默漏判
    （锁定形同虚设）。所以归一逻辑只此一处，`users.get_by_name` 用的是同一个 `.strip()`。
    """
    return str(username or "").strip()


def _active_locks(cfg, ip, username, now_ep):
    """仍在有效期内的锁标记列表 `[(原因, 解锁 epoch), ...]`（只读）。"""
    cutoff = _ts(now_ep - cfg["lockout_seconds"])
    clauses, params = [], []
    if ip:
        clauses.append("ip=?")
        params.append(ip)
    if username:
        clauses.append("username=?")
        params.append(username)
    if not clauses:
        return []
    try:
        rows = db._query(
            "SELECT at, ip, username FROM login_fails WHERE kind='lock' AND at >= ? AND ("
            + " OR ".join(clauses) + ")", tuple([cutoff] + params))
    except Exception as e:      # noqa: BLE001 - 表未建/读失败 → 视为无锁（可用性优先）
        logger.warning(f"[login-guard] 读取锁标记失败（视为无锁）：{e}")
        return []
    out = []
    for r in rows:
        at = _epoch(r["at"])
        if at is None:
            continue
        unlock = at + cfg["lockout_seconds"]
        if unlock <= now_ep:
            continue
        if ip and r["ip"] == ip:
            out.append(("IP 失败过多", unlock))
        if username and r["username"] == username:
            out.append(("该账号失败过多", unlock))
    return out


def check(ip, username, settings=None, now=None):
    """只读判定：返回 `Verdict`。**不写任何状态**（被拦截的请求不会把计数越刷越大）。"""
    cfg = config(settings)
    if not cfg["enabled"] or cfg["lockout_seconds"] <= 0:
        return Verdict(False, 0, "")
    now_ep = _as_epoch(now)
    locks = _active_locks(cfg, str(ip or ""), norm_username(username), now_ep)
    if not locks:
        return Verdict(False, 0, "")
    reason, unlock = max(locks, key=lambda x: x[1])   # 取"解锁最晚"的那条
    retry = int(max(1, min(cfg["lockout_seconds"], round(unlock - now_ep))))
    return Verdict(True, retry, reason)


def _count_fails(where, params, window_start):
    row = db._query(f"SELECT COUNT(*) c FROM login_fails WHERE kind='fail' AND at >= ? AND {where}",
                    tuple([window_start] + list(params)), one=True)
    return int(row["c"] or 0) if row else 0


def _insert_lock(ip, username, now_ep):
    db._exec("INSERT INTO login_fails(at, ip, username, kind) VALUES(?,?,?,?)",
             (_ts(now_ep), ip or "", username or "", "lock"))


def _maybe_lock(cfg, ip, username, now_ep):
    """窗口内失败数达到阈值 → 落锁标记（IP 与用户名各自独立判定）。"""
    window_start = _ts(now_ep - cfg["window_seconds"])
    if ip and cfg["max_fails_per_ip"] > 0:
        if _count_fails("ip=?", (ip,), window_start) >= cfg["max_fails_per_ip"]:
            _insert_lock(ip, "", now_ep)
    if username and cfg["max_fails_per_user"] > 0:
        if _count_fails("username=?", (username,), window_start) >= cfg["max_fails_per_user"]:
            _insert_lock("", username, now_ep)


def _prune_old(cfg, now_ep):
    """清掉 `max(window, lockout)` 之前的行 —— 保证计数表不会无界增长。"""
    keep = max(cfg["window_seconds"], cfg["lockout_seconds"])
    try:
        db._exec("DELETE FROM login_fails WHERE at < ?", (_ts(now_ep - keep),))
    except Exception:
        pass


def record_fail(ip, username, settings=None, now=None):
    """记一次失败：落 `fail` 行；若达到阈值再落 `lock` 行。**已在锁定中则不再累加**。"""
    cfg = config(settings)
    if not cfg["enabled"]:
        return
    now_ep = _as_epoch(now)
    ip, uname = str(ip or ""), norm_username(username)
    try:
        # 锁定期间不再落 fail —— 否则攻击者能靠持续请求把锁无限续期 / 把表撑大（计数无界增长）。
        if _active_locks(cfg, ip, uname, now_ep):
            return
        db._exec("INSERT INTO login_fails(at, ip, username, kind) VALUES(?,?,?,?)",
                 (_ts(now_ep), ip, uname, "fail"))
        _maybe_lock(cfg, ip, uname, now_ep)
        _prune_old(cfg, now_ep)
    except Exception as e:      # noqa: BLE001 - 计数写失败绝不阻断登录
        logger.warning(f"[login-guard] 登录失败计数写入失败（已忽略）：{e}")


def record_success(ip, username, settings=None):
    """成功登录：清掉**该用户名**的失败计数与锁标记。

    **不清 IP 计数**：IP 是主判据，一次成功不该把整台机器的失败记录抹掉（同 IP 的其它尝试仍在观察）。
    清用户名计数则是对的 —— 用户这次证明了自己记得口令，之前的"记错"不该继续累积。
    """
    cfg = config(settings)
    if not cfg["enabled"]:
        return
    uname = norm_username(username)
    if not uname:
        return
    try:
        db._exec("DELETE FROM login_fails WHERE username=?", (uname,))
    except Exception as e:      # noqa: BLE001
        logger.warning(f"[login-guard] 登录成功清理计数失败（已忽略）：{e}")


def fail_counts(ip, username, settings=None, now=None):
    """当前计数快照（窗口内失败数 + 是否锁定）—— 给测试与自查用。"""
    cfg = config(settings)
    now_ep = _as_epoch(now)
    window_start = _ts(now_ep - cfg["window_seconds"])
    try:
        ip_n = _count_fails("ip=?", (str(ip or ""),), window_start) if ip else 0
        user_n = _count_fails("username=?", (norm_username(username),), window_start) \
            if norm_username(username) else 0
    except Exception:
        ip_n = user_n = 0
    verdict = check(ip, username, settings, now=now)
    return {"ip": ip_n, "user": user_n, "locked": verdict.locked,
            "retry_after": verdict.retry_after,
            "window_seconds": cfg["window_seconds"],
            "max_fails_per_ip": cfg["max_fails_per_ip"],
            "max_fails_per_user": cfg["max_fails_per_user"]}


def clear(ip=None, username=None):
    """清除指定 IP / 用户名的全部计数与锁标记（管理员自救）。返回删除条数。

    **只碰 `login_fails` 表**：它是限速状态，不是审计流水 —— 清它不影响"谁在何时登录过"的记录。
    """
    try:
        with db._WRITE_LOCK:
            conn = db.get_conn()
            try:
                cur = conn.cursor()
                if ip and username:
                    cur.execute("DELETE FROM login_fails WHERE ip=? OR username=?",
                                (str(ip), str(username)))
                elif ip:
                    cur.execute("DELETE FROM login_fails WHERE ip=?", (str(ip),))
                elif username:
                    cur.execute("DELETE FROM login_fails WHERE username=?", (str(username),))
                else:
                    cur.execute("DELETE FROM login_fails")
                n = cur.rowcount or 0
                conn.commit()
                return n
            finally:
                conn.close()
    except Exception as e:      # noqa: BLE001
        logger.warning(f"[login-guard] 清除计数失败：{e}")
        return 0


def prune(settings=None):
    """清掉过期（`max(window, lockout)` 之前）的计数行，返回删除条数。启动时调用一次。"""
    cfg = config(settings)
    try:
        keep = max(cfg["window_seconds"], cfg["lockout_seconds"])
        with db._WRITE_LOCK:
            conn = db.get_conn()
            try:
                cur = conn.cursor()
                cur.execute("DELETE FROM login_fails WHERE at < ?", (_ts(time.time() - keep),))
                n = cur.rowcount or 0
                conn.commit()
                return n
            finally:
                conn.close()
    except Exception as e:      # noqa: BLE001
        logger.warning(f"[login-guard] 清理过期计数失败（已忽略）：{e}")
        return 0


def _status_rows():
    """当前锁标记（未过期的）与计数快照，供 `--status`。"""
    cfg = config(None)
    now_ep = time.time()
    try:
        locks = db._query("SELECT at, ip, username FROM login_fails WHERE kind='lock' "
                          "ORDER BY at DESC")
        fails = db._query("SELECT COUNT(*) c FROM login_fails WHERE kind='fail' "
                          "AND at >= ?", (_ts(now_ep - cfg["window_seconds"]),), one=True)
    except Exception:
        return [], 0
    live = []
    for r in locks:
        at = _epoch(r["at"])
        if at is None:
            continue
        unlock = at + cfg["lockout_seconds"]
        if unlock > now_ep:
            live.append((r["at"], r["ip"] or "-", r["username"] or "-", int(unlock - now_ep)))
    return live, int(fails["c"] or 0) if fails else 0


def _cli(argv=None):
    """命令行自救入口：`py -3 -m scanner.login_guard --status` / `--clear [--ip X] [--user Y]`。"""
    import argparse
    p = argparse.ArgumentParser(
        description="CTFScanner 登录限速自救（续48）：查看 / 清除失败锁定")
    p.add_argument("--status", action="store_true", help="显示当前生效的锁定与窗口内失败数")
    p.add_argument("--clear", action="store_true", help="清除锁定与失败计数（不填 --ip/--user 则全清）")
    p.add_argument("--ip", default="", help="只针对该 IP")
    p.add_argument("--user", default="", help="只针对该用户名")
    args = p.parse_args(argv)
    db.init_db()
    if args.clear:
        n = clear(ip=args.ip or None, username=args.user or None)
        print(f"[*] 已清除 {n} 条限速记录"
              + (f"（ip={args.ip}）" if args.ip else "")
              + (f"（user={args.user}）" if args.user else ""))
        return 0
    live, fails = _status_rows()
    print(f"[*] 窗口内失败数：{fails}；生效中的锁定：{len(live)}")
    for at, ip, user, remain in live:
        print(f"    - {at}  ip={ip}  user={user}  剩余 {remain}s")
    if not live:
        print("    （无）")
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())
