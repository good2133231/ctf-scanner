"""跨任务差分（续129）：复测时"这次 vs 上次"到底变了什么。

为什么需要它（用户点单第 5 件）：启发式只做**任务内**差分，而复测真正要回答的是
"上周扫过一次、今天再扫，多了什么 / 少了什么"。库里其实早就存了做这件事的原料
（`vulns.review` / `review_note`、各资产表都带 `task_id`），缺的只是把它们对齐的视图。

三条判据，改动前请先读完：

1. **「上次没跑过这个阶段」≠「这次的东西全是新增」**。每个类别都先看两边任务的 `stages`：
   基准任务没跑 portscan，就没有"消失的端口"可言，只能报「不可比 + 原因」。
   把缺覆盖算成差分会直接产出**反方向**的结论（"端口全关了"），这在本仓是反复出事的那一类
   —— 别把「0 条」当成「确实没有」。
2. **漏洞口径与报告一致**：已判误报（`review=false_positive`）的行**不算存在**。
   上次人工判掉的误报这次不在清单里，是"复核结论生效了"，不是"漏洞消失了"（续12）。
3. **可比性按目标判，不按任务名**。取"最近一个更早、且目标有交集、已收场"的任务作基准；
   跨归属（`owner_id`）不串（续89 多租户口径）—— 别人的任务不是你的上一轮。
"""
from .db import get_task, list_tasks
from .targets import host_of, parse_lines, root_of

# 类别 -> (键, 显示名, 需要的阶段)。阶段名以 `runner.STAGE_ORDER` 为准；这里写的是字面量清单，
# 不 import runner（差分不该依赖编排层，而两边对不上时回归 `[8ah]` 会红）。
CATEGORIES = [
    ("subdomains", "子域名", ("subdomain", "osint", "jsmine")),
    ("sites", "存活站点", ("probe",)),
    ("tech", "组件指纹", ("probe",)),
    ("ports", "开放端口", ("portscan",)),
    ("vulns", "潜在漏洞", ("vulnscan", "takeover")),
    ("flags", "flag 候选", ("probe", "jsmine", "dirscan", "vulnscan")),
]

# 只有"已收场"的任务才有完整快照：running/queued 的资产还在长，比它会得到一堆假"消失"
FINISHED = ("done", "stopped", "failed")


def _g(obj, key, default=""):
    """`dict` 与 `sqlite3.Row` 都能取的取值方式。

    本项目的第五次同类坑（AGENTS §7「Row 没有 .get()」）：`get_task()` 给的是 dict，
    而 `list_tasks()` 给的是 Row —— 用 `.get()` 就只在页面绿、在遍历候选基准时炸。
    """
    try:
        v = obj[key]
    except (KeyError, IndexError, TypeError):
        return default
    return default if v is None else v


def target_set(task):
    """任务目标 -> 归一后的**注册域**集合（判可比性用，不比 URL 细节）。

    续146：主机名提取与注册域折算改走 `targets.host_of` / `root_of`（唯一产地）。
    **这里与其它调用方有一处刻意的不同**：IP 目标**也是身份** —— 判"两轮扫的是不是同一个
    目标"时，`10.0.0.5` 与它自己当然可比，所以 `kind == "ip"` 原样收下（`host_of` 对 ip 返回
    空串，正是把"要不要算 IP"这个业务决定留给调用方）。
    """
    out = set()
    lines = str(_g(task, "targets")).splitlines()
    for kind, raw in parse_lines(lines):   # parse_lines 吃的是**行列表**，不是整串
        if kind == "ip":
            out.add(str(raw or "").strip())
            continue
        host = host_of(kind, raw)
        if not host:
            continue
        # 归一化只走 `targets.host_of`（内部是 `utils.to_ascii`）：它失败时**原样小写**继续用，
        # 不猜也不丢 —— 判可比性用得到就比，拿不到就说拿不到。
        out.add(root_of(host) or host)
    return {d for d in out if d}


def comparable(task, base):
    """两个任务可不可比，以及为什么不可比 —— 返回 `(bool, 原因)`。"""
    if not base:
        return False, "没有更早的、已收场的同目标任务"
    if int(base["id"]) == int(task["id"]):
        return False, "基准就是本任务自己"
    a, b = target_set(task), target_set(base)
    if not a or not b:
        return False, "有一方的目标解析不出域名/IP，无法判可比性（宁可不比，也不猜）"
    if not (a & b):
        return False, (f"目标没有交集（{('、'.join(sorted(a)[:3]) or '空')} vs "
                       f"{('、'.join(sorted(b)[:3]) or '空')}）")
    if str(_g(base, "status")) not in FINISHED:
        return False, f"基准任务状态是 {base['status']}，资产还在变，比不得"
    return True, ""


def pick_base(task_id, owner_id=None):
    """取"最近一个更早、已收场、目标有交集"的任务作基准，返回 `(base|None, 原因)`。

    遍历的是 `list_tasks(limit=None)` 而不是"前 200 条"（续55 的口径）：老库里有几百个任务时，
    用 `limit=N` 去找基准会在超出 N 之后**静默找不到**，然后页面上写"没有可比的上一轮" ——
    那不是事实，那是分页。
    """
    task = get_task(task_id)
    if not task:
        return None, "任务不存在"
    why = "没有更早的已收场任务"
    for base in list_tasks(limit=None, owner_id=owner_id):
        if int(base["id"]) >= int(task_id):
            continue
        ok, why2 = comparable(task, base)
        if ok:
            return base, ""
        if str(_g(base, "status")) in FINISHED:
            why = why2 or why
    return None, why


def snapshot(task_id):
    """把一个任务的资产取成 `{类别: {键: 展示值}}`（差分只比**键**，展示值给人看）。"""
    from . import db
    out = {"subdomains": {}, "sites": {}, "tech": {}, "ports": {}, "vulns": {},
           "flags": {}}
    for r in db.list_subdomains(task_id):
        out["subdomains"][str(r["domain"])] = str(r["domain"])
    for r in db.list_sites(task_id):
        url = str(r["url"] or "")
        out["sites"][url] = url
        host = str(r["host"] or "")
        for t in [x for x in str(r["tech"] or "").split(",") if x]:
            out["tech"][f"{host}|{t}"] = f"{host} → {t}"
    for r in db.list_ports(task_id):
        out["ports"][f"{r['host']}:{r['port']}"] = f"{r['host']}:{r['port']}"
    # 与报告同口径：**已判误报的不算存在**（续12）。它既不进 added 也不进 removed ——
    # 上次人工判掉的误报今天也不在清单里，那是复核结论生效，不是"漏洞消失了"。
    for r in db.list_vulns(task_id=task_id, limit=None):
        if str(r["review"] or "") == "false_positive":
            continue
        out["vulns"][f"{r['target']}|{r['poc_id']}"] = (
            f"[{r['severity']}] {r['name']} @ {r['target']}")
    for r in db.list_flags(task_id):
        out["flags"][str(r["value"])] = str(r["value"])
    # 单独留一份"被复核口径排除"的键：差分主逻辑不看它（所以它绝不会变成新增/消失），
    # 但那一栏的**说明**要用它 —— 上次判误报的那条今天又出现且未复核，是"结论过期"，
    # 不是"新冒出来的漏洞"。不把这句话写在页面上，人就会照着 +1 去追一个早就判过的东西。
    out["_fp_excluded"] = {}
    for r in db.list_vulns(task_id=task_id, limit=None):
        if str(r["review"] or "") == "false_positive":
            out["_fp_excluded"][f"{r['target']}|{r['poc_id']}"] = str(r["name"])
    return out


def stages_of(task):
    return {s.strip() for s in str(_g(task, "stages")).split(",") if s.strip()}


def diff(task_id, base_id=None, owner_id=None):
    """本次 vs 上次：各类别的新增/消失，外加"不可比就不比"的诚实说明。返回 `(结果, 原因)`。"""
    task = get_task(task_id)
    if not task:
        return None, "任务不存在"
    # 归属守卫放在这里而不是只放路由里：CLI / 回归 / 以后新增的入口都会经过 `diff()`，
    # 只在页面挡一层等于"换个入口就能看别人的任务"（续89 多租户的老教训）。
    if owner_id is not None and int(task["owner_id"] or 0) != int(owner_id):
        return None, "任务不存在或不属于当前账号"
    base = get_task(base_id) if base_id else None
    if base is not None and owner_id is not None and int(base["owner_id"] or 0) != int(owner_id):
        return None, "基准任务不存在或不属于当前账号"
    if base is None and not base_id:
        base, why = pick_base(task_id, owner_id=owner_id)
    else:
        why = ""
    res = {"task": dict(task), "base": dict(base) if base is not None else None,
           "categories": [], "comparable": False, "why_not": why}
    if base is None:
        return res, why or "没有可比的上一轮"
    ok, why2 = comparable(task, base)
    if not ok:
        res["why_not"] = why2
        return res, why2
    cur, prev = snapshot(task["id"]), snapshot(base["id"])
    st_cur, st_prev = stages_of(task), stages_of(base)
    for key, label, need in CATEGORIES:
        ran_cur = bool(st_cur & set(need))
        ran_prev = bool(st_prev & set(need))
        added = sorted(set(cur[key]) - set(prev[key]))
        removed = sorted(set(prev[key]) - set(cur[key]))
        note = ""
        if not ran_cur and not ran_prev:
            added = removed = []
            note = "两轮都没跑相关阶段 ⇒ 这一类根本没有数据，不计新增也不计消失"
        elif not ran_prev:
            added = []
            note = (f"上一轮没跑 {'/'.join(need)} ⇒ 本次的东西只是「缺对照」，"
                    f"不算新增（对比无意义）")
        elif not ran_cur:
            removed = []
            note = (f"本次没跑 {'/'.join(need)} ⇒ 上一轮的东西不是消失了，"
                    f"是这一轮没去看")
        if key == "vulns":
            ex_prev = set(prev.get("_fp_excluded") or {})
            ex_cur = set(cur.get("_fp_excluded") or {})
            reappear = sorted(ex_prev & set(cur["vulns"]))
            bits = []
            if ex_prev or ex_cur:
                bits.append(f"复核口径：上次已判误报 {len(ex_prev)} 条、这次 {len(ex_cur)} 条"
                            f"**不计入新增与消失**（与报告同口径，续12）")
            if reappear:
                bits.append(f"其中 {len(reappear)} 条这次又出现且**未复核** ⇒ 是「复核结论过期」，"
                            f"请重判，别当成新漏洞")
            if bits:
                note = "；".join(bits) + ("。" + note if note else "")
        res["categories"].append({
            "key": key, "label": label, "cur": len(cur[key]), "prev": len(prev[key]),
            "added": added, "removed": removed, "note": note,
            "added_labels": [cur[key][k] for k in added],
            "removed_labels": [prev[key][k] for k in removed]})
    res["comparable"] = True
    return res, ""


def summary(res):
    """一句话摘要（页面顶部用，明细里不重复这套数字）。"""
    if not res:
        return "无从对比"
    if not res.get("comparable"):
        return "没有可比的上一轮：" + (res.get("why_not") or "原因未知")
    base = res["base"]
    parts = []
    for row in res["categories"]:
        if row["note"]:
            continue
        if row["added"] or row["removed"]:
            parts.append(f"{row['label']} +{len(row['added'])}/-{len(row['removed'])}")
    head = f"对比基准：#{_g(base, 'id')}（{_g(base, 'created_at')}，{_g(base, 'status')}）"
    return head + ("｜" + "，".join(parts) if parts else "｜各类别都没有变化")


def for_template(res, limit=40):
    """把明细截到可读长度，并**如实报出被截断的条数**（与报告 `CAP_*` 同一口径）。"""
    out = []
    for row in (res or {}).get("categories", []):
        r = dict(row)
        for side in ("added", "removed"):
            r[side + "_show"] = r[side + "_labels"][:limit]
            r[side + "_hidden"] = max(0, len(r[side]) - limit)
        out.append(r)
    return out
