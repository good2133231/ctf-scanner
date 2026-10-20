"""老任务的 favicon 回填（续235，主理人点单"做这个"）。

背景：`icon_hash / icon_file / icon_ext` 三列是续225 才加的 —— **老任务**的站点只有
`favicon`（MD5），没有 mmh3 与图标本体；而数据不回填，页面上那些行永远出不了图标与
FOFA 提问值。本模块把这条补齐：对"有 favicon 但没落图标"的行**各补抓一次**图标，
算 MD5 + mmh3、把图标本体落盘到任务工作目录的 `favicons/<md5>.ico`，并更新站点行。

边界（都写死，不做配置）：
- **幂等**：只处理 `icon_file` 为空的行，重复调用自动跳过已补的；
- **上限**：单次最多 `cap`（默认 200）行 —— 这是维护动作，不该在一次里打几百个请求；
- **顺序执行**（不并发）：维护动作宁可慢一点，也不跟扫描抢出口预算；
- 任务没有 `log_file`（CLI 直跑的老行 / 已删工作目录）⇒ 整体跳过并说明 —— 图标要落盘，
  没地方落就不装样子；
- 新 MD5 与旧 `sites.favicon` 不一致 ⇒ 站点图标确实变了，一并更新（如实反映现状）。
"""
import threading

from . import db
from .fingerprint import favicon_info
from .log import get_logger
from pathlib import Path

DEFAULT_CAP = 200

_LOCK = threading.Lock()
_RUNNING = set()          # 正在回填的任务号（防同任务并发重入）


def pending_count(task_id):
    """还有多少行待补（有 favicon MD5、但没落图标）——按钮文案与进度口径用。"""
    row = db._query("SELECT COUNT(*) c FROM sites WHERE task_id=? AND favicon<>'' "
                    "AND icon_file=''", (task_id,), one=True)
    return int((dict(row) if row else {}).get("c") or 0)


def backfill_task(task_id, settings=None, logger=None, stop=None, cap=DEFAULT_CAP):
    """回填一个任务的图标。返回 `{processed, saved, empty, failed, skipped_no_dir, cap}`。

    - `processed`：本轮真正发起抓取的行数（≤ cap）；
    - `saved`：拿到图标并落库/落盘的行数；`empty`：站点没有可用的 favicon；`failed`：请求失败；
    - `stop`：协作式停止（GUI 停止信号 / 测试）；`logger` 给了就把逐条与汇总写进任务日志。
    """
    settings = settings or {}
    task = db.get_task(task_id)
    if not task:
        if logger:
            logger.warning(f"[iconbackfill] 任务 #{task_id} 不存在，跳过")
        return {"processed": 0, "saved": 0, "empty": 0, "failed": 0,
                "skipped_no_dir": 0, "cap": cap}
    rows = [dict(r) for r in db._query(
        "SELECT url, favicon FROM sites WHERE task_id=? AND favicon<>'' AND icon_file='' "
        "ORDER BY id", (task_id,))]
    logf = str(task["log_file"] or "").strip()
    if not rows or not logf:
        if logger:
            logger.info("[iconbackfill] 没有待补的行（都补过了，或本来就没有 favicon）"
                        if rows else "[iconbackfill] 本任务没有带 favicon 的站点行")
        return {"processed": 0, "saved": 0, "empty": 0, "failed": 0,
                "skipped_no_dir": 0 if rows else 0, "cap": cap}
    base = Path(logf).parent
    if not base.is_dir():
        if logger:
            logger.warning(f"[iconbackfill] 任务工作目录不在了（{base}）⇒ 图标没地方落，跳过")
        return {"processed": 0, "saved": 0, "empty": 0, "failed": 0,
                "skipped_no_dir": len(rows), "cap": cap}
    icon_dir = base / "favicons"
    out = {"processed": 0, "saved": 0, "empty": 0, "failed": 0,
           "skipped_no_dir": 0, "cap": cap}
    if logger:
        logger.info(f"[iconbackfill] 老数据回填：{len(rows)} 行待补（本次上限 {cap}）…")
    for s in rows:
        if out["processed"] >= cap:
            if logger:
                logger.info(f"[iconbackfill] 达到单次上限 {cap}，"
                            f"剩余 {len(rows) - cap} 行下轮再点一次即可（幂等）")
            break
        if stop is not None and stop():
            if logger:
                logger.warning("[iconbackfill] 已请求停止，回填中断（已补的行保留）")
            break
        url = s["url"]
        out["processed"] += 1
        md5, mmh3, data = favicon_info(url, settings)
        if not data:
            out["empty" if mmh3 == 0 and not data else "failed"] += 1
            # favicon_info 拿不到内容只有两种可能：请求失败 / 站点确实没有图标。
            # 两者在这里分不开（都返回空），按 empty 记 —— 行保持原样，下次还能再试。
            if logger:
                logger.info(f"[iconbackfill] {url} 没拿到图标（本轮跳过，行保留可重试）")
            continue
        icon_dir.mkdir(parents=True, exist_ok=True)
        f = icon_dir / f"{md5}.ico"
        if not f.exists():
            f.write_bytes(data)
        rel = f"favicons/{f.name}"
        db.set_site_icon(task_id, url, icon_hash=mmh3, icon_file=rel, favicon=md5)
        out["saved"] += 1
        if logger:
            same = "（与库内 MD5 一致）" if md5 == s["favicon"] else "（站点图标已变，MD5 一并更新）"
            logger.info(f"[iconbackfill] {url} → mmh3={mmh3} {rel} {same}")
    if logger:
        logger.info(f"[iconbackfill] 完成：补上 {out['saved']} 行"
                    f"（空 {out['empty']} / 失败 {out['failed']} / 处理 {out['processed']}）")
    return out


def launch(task_id, settings=None, inline=False):
    """后台起一个回填（GUI 按钮入口）。返回 `(started, msg)`。

    同任务重入直接拒绝（上一轮还没跑完又点，只会重复抓同一批）；`inline=True` 供门禁
    同步执行（不起线程）。
    """
    with _LOCK:
        if task_id in _RUNNING:
            return False, "该任务的图标回填已在进行中（等它跑完，或刷新页面看进度）"
        _RUNNING.add(task_id)

    def _run():
        task = db.get_task(task_id)
        workdir = Path(str(task["log_file"] or "")).parent if task else None
        logger = None
        if workdir and workdir.is_dir():
            logger = get_logger(f"task-{task_id}", workdir / "task.log")
        try:
            backfill_task(task_id, settings, logger=logger)
        except Exception as e:                                  # noqa: BLE001 - 维护动作级容错
            if logger:
                logger.warning(f"[iconbackfill] 回填异常（不影响任务本身）：{e}")
        finally:
            with _LOCK:
                _RUNNING.discard(task_id)

    if inline:
        _run()
        return True, "回填完成"
    threading.Thread(target=_run, daemon=True,
                     name=f"iconbackfill-{task_id}").start()
    return True, "已开始（进度看任务日志；站点行补上后页面刷新即可见）"
