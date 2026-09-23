"""CTFScanner Web 控制台（仿 ARL 交互形态：任务管理 / 资产列表 / 漏洞列表 / POC 管理）。

说明（客观取舍）：
- 单进程 Flask + 后台线程执行流水线，满足 CTF 单机场景；生产化改造（任务队列、鉴权体系）
  见 docs/roadmap.md；
- 默认仅监听 127.0.0.1，登录口令为 config/settings.yaml 的 gui.token（默认 ctfscanner）；
- 控制台本身没有做 CSRF 等加固，切勿部署到公网。
"""
import functools
import json
import socket
import threading
import time
from pathlib import Path
from urllib.parse import quote

from flask import (Flask, Response, abort, jsonify, redirect, send_file,
                   render_template, request, session, url_for)

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner import blacklist, db
from scanner.config import BASE_DIR, load_settings, save_settings
from scanner.log import get_logger
from scanner.owasp import checks as owasp_checks
from scanner.pocs import engine
from scanner import runner
from scanner.runner import STAGE_ORDER, run_task, sync_pocs
from scanner.utils import rel_display

logger = get_logger("gui")

# 资产来源 → 页面上的可读标签（「子域名 / 拓展域名」页的来源列用它渲染成中文标签）
# 解析失败/未解析原因 → 页面文案（子域名/拓展域名/IP 页共用）。
# 用户 2026-09-22 要求：没有 IP 时必须标出**具体原因**，不能只显示一个 "-"。
IP_NOTE_LABELS = {
    "nxdomain": "域名不存在(NXDOMAIN)",
    "no-a": "无 A 记录",
    "servfail": "DNS 故障",
    "refused": "DNS 拒绝",
    "timeout": "解析超时",
    "error": "解析异常",
    "empty": "空域名",
    "over-limit": "超出回填上限(subdomain.max_resolve)",
}


def ip_note_label(note):
    """把原因码翻译成中文；空值返回空串（表示解析正常）。"""
    text = str(note or "").strip()
    if not text:
        return ""
    return IP_NOTE_LABELS.get(text, text)


SOURCE_LABELS = {
    "subfinder": "被动(subfinder)",
    "puredns": "爆破(puredns)",
    "dns-brute(fallback)": "爆破(内置)",
    "js:mine": "JS 挖掘",
    # 两个 FOFA 来源都显式带上「FOFA」字样：用户要求一眼看出哪些资产是 FOFA 找出来的
    "osint:cseg": "C 段反查",
    "osint:fofa": "FOFA·ICO 反查",
    "osint:fofa-cert": "FOFA·证书反查",
    "osint:fofa-title": "FOFA·标题反查",
}


def source_label(source):
    """把 `source` 字段翻译成可读标签；未知来源原样返回（如 `passive:crt.sh` 归一为"被动"）。"""
    text = str(source or "").strip()
    if not text:
        return "-"
    if text in SOURCE_LABELS:
        return SOURCE_LABELS[text]
    if text.startswith("passive:"):
        return f"被动({text.split(':', 1)[1]})"
    return text


def _and_where(*parts):
    """把若干 SQL 条件用 AND 拼起来，忽略空值（避免条件为空时生成 `() AND ...`）。"""
    items = [p for p in parts if p]
    return " AND ".join(f"({p})" for p in items) if items else None


def _safe_next(target, fallback):
    """只放行**站内相对路径**的 `next` 跳转目标，其余一律回退（防开放重定向）。

    `next` 来自表单，可被构造（如 `next=https://evil.com`），直接 `redirect()` 会把
    用户带到任意外站。这里只接受以单个 `/` 开头、不含反斜杠的目标 —— 顺带挡住
    `//evil.com`（协议相对）与 `/\\evil.com`（浏览器按路径规范化当外站）两种绕过写法。
    """
    t = str(target or "").strip()
    if t.startswith("/") and not t.startswith("//") and "\\" not in t:
        return t
    return fallback


def create_app():
    settings = load_settings()
    app = Flask(__name__)
    app.secret_key = f"ctfscanner::{settings.get('gui', {}).get('token', '')}"
    # 模板里可直接调用 `source_label('osint:fofa')` → 「ICO 反查」（来源列的可读标签）
    app.jinja_env.globals["source_label"] = source_label
    app.jinja_env.globals["ip_note_label"] = ip_note_label
    db.init_db()
    sync_pocs(settings)

    # ---------- 鉴权 ----------

    def login_required(fn):
        @functools.wraps(fn)
        def wrapper(*a, **k):
            if not session.get("auth"):
                return redirect(url_for("login"))
            return fn(*a, **k)
        return wrapper

    @app.route("/login", methods=["GET", "POST"])
    def login():
        error = ""
        if request.method == "POST":
            if request.form.get("token", "") == load_settings().get("gui", {}).get("token", ""):
                session["auth"] = True
                return redirect(url_for("dashboard"))
            error = "口令错误"
        return render_template("login.html", error=error)

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    # ---------- 仪表盘 ----------

    @app.route("/")
    @login_required
    def dashboard():
        return render_template(
            "dashboard.html", stats=db.dashboard_stats(),
            tasks=db.list_tasks(limit=8), vulns=db.list_vulns(limit=8))

    # ---------- 任务 ----------

    def _spawn(task_id, name, targets, stages, options):
        """后台线程执行任务（GUI 不阻塞）。"""
        threading.Thread(target=run_task, daemon=True,
                         args=(task_id, name, targets, stages, options,
                               load_settings())).start()

    @app.route("/tasks")
    @login_required
    def tasks():
        rows = db.list_tasks(limit=200)
        # 「统计」列：站点/域名数量（对齐参考图的 站点: N / 域名: N 展示）
        counts = {t["id"]: db.task_counts(t["id"]) for t in rows}
        return render_template("tasks.html", tasks=rows, stages=STAGE_ORDER,
                               counts=counts, running=set(runner.running_task_ids()))

    @app.route("/api/tasks", methods=["POST"])
    @login_required
    def api_create_task():
        data = request.form if request.form else (request.get_json(silent=True) or {})
        name = (data.get("name") or "").strip() or time.strftime("task-%m%d-%H%M%S")
        targets = (data.get("targets") or "").strip()
        f = request.files.get("file")
        if f and f.filename:
            targets = (targets + "\n" + f.read().decode("utf-8", "replace")).strip()
        if not targets:
            return jsonify({"error": "目标为空：请填写目标或导入文件"}), 400
        stages = data.getlist("stages") if hasattr(data, "getlist") else data.get("stages", [])
        if isinstance(stages, str):
            stages = [s for s in stages.split(",") if s.strip()]
        stages = [s for s in stages if s in STAGE_ORDER] or list(STAGE_ORDER)
        offline = str(data.get("offline", "")).lower() in ("1", "true", "on")
        options = {"offline": offline}
        # 「全端口 / 全目录」是**任务级选项**（与 portscan_full 同一套语义：单任务强制全量档，
        # 不改全局策略）。用户很容易只勾了全量却忘勾对应阶段，那样勾选就等于白勾 ——
        # 这里自动把对应阶段补进来，并在响应里如实告知，避免"勾了没用"的错觉。
        auto_stages = []
        for flag, stage in (("portscan_full", "portscan"), ("dirscan_full", "dirscan")):
            if str(data.get(flag, "")).lower() not in ("1", "true", "on"):
                continue
            options[flag] = True
            if stage not in stages:
                stages.append(stage)
                auto_stages.append(stage)
        # 补进来的阶段要回到流水线既定顺序：runner 按给定顺序执行，**不做排序**
        stages.sort(key=STAGE_ORDER.index)
        task_id = db.create_task(name, targets, stages, options)
        _spawn(task_id, name, targets, stages, options)
        return jsonify({"id": task_id, "auto_stages": auto_stages})

    @app.route("/tasks/<int:task_id>")
    @login_required
    def task_detail(task_id):
        task = db.get_task(task_id)
        if not task:
            abort(404)
        # 页面只展示相对路径（日志文件路径在库里存的是绝对路径，因为要真的去读它）
        task = dict(task)
        task["log_file"] = rel_display(task.get("log_file") or "")
        # 子域名 Tab 只列目标自身的子域名；JS/情报拓展的域名单独计数并指到「拓展域名」页
        subs = [dict(r) for r in db.list_subdomains(task_id)]
        own = [r for r in subs if not (r["source"] or "").startswith(("js:", "osint:"))]
        # 拓展域名（JS 挖掘 / C 段 / FOFA）在任务详情里单列一个页签 ——
        # 用户要求它不再单独占侧栏，但任务维度仍要能看到（这些域名未必属于目标）
        ext_subs = [r for r in subs if (r["source"] or "").startswith(("js:", "osint:"))]
        # 目录结果同样默认折叠"重复长度"（同一站点下几百条同样长度的 200 基本是同一个软 404 模板）
        dirs, dirs_hidden = _fold_dirs(db.list_dirs(task_id), False)
        # 「线索」页签：intel（外部情报订阅）+ heuristic（启发式候选）两类共用一张表，
        # 两者都**不是漏洞结论**，所以单独列、单独计数，不混进 vulns
        leads = db.list_leads(task_id)
        # 「补扫」相关提示条只在"本次没做全量"时出现，避免误导：
        # 本任务带了 `dirscan_full`/`portscan_full`，或全局策略本身就是全量档 → 不提示。
        try:
            top = json.loads(task.get("options") or "{}")
        except (TypeError, ValueError):
            top = {}
        if not isinstance(top, dict):
            top = {}
        dir_full = (top.get("dirscan_full") is True
                    or str((settings.get("dirscan") or {}).get("mode") or "quick") == "deep")
        port_full = (top.get("portscan_full") is True
                     or str((settings.get("portscan") or {}).get("mode") or "top") == "full")
        return render_template(
            "task_detail.html", task=task,
            subs=own, ext_subs=ext_subs,
            sites=db.list_sites(task_id),
            ports=db.list_ports(task_id), csegs=db.list_csegs(task_id),
            dirs=dirs, dirs_hidden=dirs_hidden,
            vulns=db.list_vulns(task_id=task_id, limit=1000),
            leads=leads,
            leads_intel=sum(1 for r in leads if r["kind"] == "intel"),
            # 补扫入口：任务页对"本任务的站点/IP"直接发起新任务；rescan_of 用于反向回跳
            rescan_of=top.get("rescan_of"),
            dir_full=dir_full, port_full=port_full,
            dir_cap=int((settings.get("limits") or {}).get("dirscan_max_urls", 20) or 20),
            running=set(runner.running_task_ids()))

    @app.route("/tasks/<int:task_id>/export")
    @login_required
    def task_export(task_id):
        """导出任务 Markdown 报告（下载 .md）。"""
        task = db.get_task(task_id)
        if not task:
            abort(404)
        from scanner.report import generate
        md = generate(task_id) or ""
        fname = f"task_{task_id}_{time.strftime('%Y%m%d_%H%M%S')}.md"
        return Response(md, mimetype="text/markdown; charset=utf-8",
                        headers={"Content-Disposition": f"attachment; filename={fname}"})

    @app.route("/api/tasks/<int:task_id>/stop", methods=["POST"])
    @login_required
    def api_task_stop(task_id):
        if not db.get_task(task_id):
            return jsonify({"error": "not found"}), 404
        ok = runner.request_stop(task_id)
        return jsonify({"ok": ok, "msg": "已请求停止，当前批次跑完即停" if ok
                        else "该任务当前未在运行"})

    @app.route("/api/tasks/<int:task_id>/delete", methods=["POST"])
    @login_required
    def api_task_delete(task_id):
        if not db.get_task(task_id):
            return jsonify({"error": "not found"}), 404
        runner.request_stop(task_id)   # 先停线程，避免它继续往已删除的任务里写数据
        db.delete_task(task_id)
        return jsonify({"ok": True})

    @app.route("/api/tasks/<int:task_id>/restart", methods=["POST"])
    @login_required
    def api_task_restart(task_id):
        """原地重启：清空该任务已有资产后按原参数重跑（历史任务保持单一结果集，不产生重复行）。"""
        task = db.get_task(task_id)
        if not task:
            return jsonify({"error": "not found"}), 404
        if task["status"] == "running":
            return jsonify({"ok": False, "error": "任务正在运行，请先停止再重启"})
        stages = [s for s in (task["stages"] or "").split(",") if s in STAGE_ORDER]
        db.clear_task_assets(task_id)
        db.update_task(task_id, status="pending", progress=0, current_stage="", error="")
        _spawn(task_id, task["name"], task["targets"], stages or list(STAGE_ORDER),
               json.loads(task["options"] or "{}"))
        return jsonify({"ok": True})

    @app.route("/api/tasks/bulk", methods=["POST"])
    @login_required
    def api_tasks_bulk():
        """批量操作：stop / delete / restart。ids 可来自表单或 JSON。"""
        data = request.get_json(silent=True) or {}
        action = (data.get("action") or request.form.get("action") or "").strip()
        ids = data.get("ids") or request.form.getlist("ids")
        try:
            ids = [int(i) for i in (ids or [])]
        except (TypeError, ValueError):
            return jsonify({"error": "ids 必须是整数列表"}), 400
        if action not in ("stop", "delete", "restart"):
            return jsonify({"error": "action 必须是 stop / delete / restart"}), 400
        affected, skipped = 0, []
        for tid in ids:
            task = db.get_task(tid)
            if not task:
                skipped.append(tid)
                continue
            running = task["status"] == "running"
            if action == "stop":
                if running and runner.request_stop(tid):
                    affected += 1
                else:
                    skipped.append(tid)
            elif action == "delete":
                runner.request_stop(tid)
                db.delete_task(tid)
                affected += 1
            else:  # restart
                if running:
                    skipped.append(tid)
                    continue
                stages = [s for s in (task["stages"] or "").split(",") if s in STAGE_ORDER]
                db.clear_task_assets(tid)
                db.update_task(tid, status="pending", progress=0, current_stage="", error="")
                _spawn(tid, task["name"], task["targets"], stages or list(STAGE_ORDER),
                       json.loads(task["options"] or "{}"))
                affected += 1
        return jsonify({"ok": True, "action": action, "affected": affected,
                        "skipped": skipped})

    @app.route("/api/tasks/<int:task_id>/status")
    @login_required
    def api_task_status(task_id):
        t = db.get_task(task_id)
        if not t:
            return jsonify({"error": "not found"}), 404
        return jsonify({
            "status": t["status"], "progress": t["progress"],
            "current_stage": t["current_stage"],
            "log_tail": _tail(t["log_file"]) if t["log_file"] else [],
        })

    # ---------- POC 管理 ----------

    @app.route("/pocs")
    @login_required
    def pocs():
        # _query 返回 sqlite3.Row（只读），这里要往每行补 source 字段，故转成 dict
        rows = [dict(r) for r in db.list_pocs()]
        # 分类统计（来源 / 级别），供页面上的"按分类批量开关"展示当前分布
        stats = {"source": {}, "severity": {}, "enabled": 0, "total": len(rows)}
        for r in rows:
            src = db.poc_source(r["path"])    # 来源判定依赖原始路径，必须在相对化之前算
            r["source"] = src                 # 列表展示 / 前端筛选用
            r["path"] = rel_display(r["path"])  # 页面只展示相对路径
            stats["source"][f"{src}:on" if r["enabled"] else f"{src}:off"] = \
                stats["source"].get(f"{src}:on" if r["enabled"] else f"{src}:off", 0) + 1
            stats["severity"][r["severity"] or "-"] = stats["severity"].get(r["severity"] or "-", 0) + 1
            stats["enabled"] += int(r["enabled"] or 0)
        return render_template("pocs.html", pocs=rows, stats=stats)

    @app.route("/api/pocs/upload", methods=["POST"])
    @login_required
    def api_poc_upload():
        f = request.files.get("file")
        if not f or not f.filename.lower().endswith((".yaml", ".yml")):
            return jsonify({"error": "请上传 .yaml / .yml 文件"}), 400
        dest_dir = BASE_DIR / "config" / "pocs-user"
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / Path(f.filename).name
        f.save(str(dest))
        meta = engine.load_poc_file(dest)
        db.upsert_poc(str(dest), meta)
        return jsonify({"ok": meta.get("_status") == "ok", "id": meta.get("id"),
                        "error": meta.get("_error", "")})

    @app.route("/api/pocs/<int:pid>/toggle", methods=["POST"])
    @login_required
    def api_poc_toggle(pid):
        db.toggle_poc(pid)
        return jsonify({"ok": True})

    @app.route("/api/pocs/bulk", methods=["POST"])
    @login_required
    def api_poc_bulk():
        """按分类批量开关 POC：body={action:'enable'|'disable', severity?, source?, kind?}。"""
        data = request.get_json(silent=True) or request.form
        action = (data.get("action") or "").strip()
        if action not in ("enable", "disable"):
            return jsonify({"error": "action 必须是 enable 或 disable"}), 400
        n = db.bulk_set_poc_enabled(action == "enable",
                                    severity=(data.get("severity") or "").strip() or None,
                                    source=(data.get("source") or "").strip() or None,
                                    kind=(data.get("kind") or "").strip() or None)
        return jsonify({"ok": True, "affected": n})

    @app.route("/api/pocs/refresh", methods=["POST"])
    @login_required
    def api_poc_refresh():
        sync_pocs(load_settings())
        return jsonify({"ok": True})

    # ---------- 漏洞 ----------

    @app.route("/vulns")
    @login_required
    def vulns():
        sev = request.args.get("severity") or None
        tid = request.args.get("task_id") or ""
        try:
            tid = int(tid)
        except (TypeError, ValueError):
            tid = None
        rows = db.list_vulns(task_id=tid, severity=sev, limit=500)
        # 跨任务视图里只有 `任务 #12` 没法辨认，这里带上任务名，并支持按任务筛选。
        tasks = db.list_tasks(limit=1000)
        return render_template("vulns.html", vulns=rows, sev=sev or "",
                               task_id=tid or "", tasks=tasks,
                               task_names={t["id"]: t["name"] for t in tasks})

    # ---------- 资产分栏 ----------
    #
    # 分页策略（P2-2）：跨任务资产页原来固定 `LIMIT 500`，数据量上去后会被静默截断。
    # 现在过滤与分页都走 SQL（`db.page_assets`），关键字用 `q`、页码用 `page`、每页 `size`。

    PAGE_SIZES = (50, 100, 200, 500)

    def _page_args():
        def _int(name, default):
            try:
                return int(request.args.get(name, default) or default)
            except (TypeError, ValueError):
                return default
        size = _int("size", 100)
        return max(1, _int("page", 1)), (size if size in PAGE_SIZES else 100), \
            (request.args.get("q") or "").strip()

    def _asset_page(table, base, extra_where=None, extra_params=(), order=None):
        page, size, q = _page_args()
        rows, total = db.page_assets(table, limit=size, offset=(page - 1) * size, q=q or None,
                                     extra_where=extra_where, extra_params=extra_params,
                                     order=order)
        pages = max(1, (total + size - 1) // size)
        if page > pages:  # 页码越界（例如过滤后总页数变少）→ 回落到最后一页重查
            page = pages
            rows, total = db.page_assets(table, limit=size, offset=(page - 1) * size,
                                         q=q or None, extra_where=extra_where,
                                         extra_params=extra_params, order=order)
        # q 必须 URL 编码：关键字里带 `&` / `#` / 空格时不编码会让翻页、切标签**丢掉筛选条件**
        qs = f"&q={quote(q)}&size={size}" if q else f"&size={size}"
        pager = {"page": page, "size": size, "total": total, "pages": pages,
                 "base": base, "qs": qs}
        return rows, pager, q

    def _cdn_tag():
        """子域名/拓展域名页的 CDN 标签过滤：全部 / cdn（走 CDN）/ nocdn（直连源站）。"""
        tag = (request.args.get("tag") or "").strip().lower()
        if tag == "cdn":
            return tag, "cdn <> ''", ()
        if tag == "nocdn":
            return tag, "cdn = ''", ()
        return "", None, ()

    def _overlap_args():
        """「是否显示重叠资产」开关：默认隐藏，`?all=1` 显示全部（两个资产页口径一致）。"""
        return request.args.get("all") == "1"

    def _secret_counts():
        """每个域名命中的 JS 敏感凭据条数（供「拓展域名」页的「敏感」列）。

        敏感项已随 jsmine 阶段以 `js-secret-*` 入 vulns 表，这里只按 target（主机名）聚合条数，
        不再另建一张表 —— 数据模型不变，页面上多一列"该域名下挖到过多少敏感串"。
        """
        out = {}
        try:
            for r in db._query("SELECT target t, COUNT(*) c FROM vulns "
                               "WHERE poc_id LIKE 'js-secret-%' GROUP BY target"):
                out[r["t"]] = r["c"]
        except Exception:
            return {}
        return out

    def _fold_dirs(rows, show_all):
        """目录结果按「站点 + 状态码 + 响应大小」折叠重复，返回 `(rows, hidden)`。

        为什么按大小折叠：一个站点下动辄几百条同样长度的 `200`（软 404 模板、统一的
        重定向页），它们不是真发现 —— 与 dirmap 把这类结果单独写进「重复长度.txt」
        是同一口径。默认只留首个，`?all=1`（`/dirs`）放开。
        """
        rows = [dict(r) for r in rows]
        seen, hidden = {}, 0
        for r in rows:
            r["dup"] = 0
            key = (r.get("site_url") or "", r.get("status"), r.get("length") or -1)
            first = seen.get(key)
            if first is None:
                seen[key] = r
            else:
                first["dup"] += 1
                r["hidden_dup"] = True
                hidden += 1
        if not show_all:
            rows = [r for r in rows if not r.get("hidden_dup")]
        return rows, hidden

    @app.route("/shots/<int:task_id>/<path:name>")
    @login_required
    def shot_file(task_id, name):
        """返回任务截图（PNG）。

        安全要点：只允许读**该任务工作目录下 `shots/` 里**的文件 ——
        文件名里出现路径分隔符、或解析后不在 shots 目录内，一律 404（防目录穿越）。
        """
        task = db.get_task(task_id)
        if not task:
            abort(404)
        if "/" in name or "\\" in name or not name.lower().endswith(".png"):
            abort(404)
        # 注意：db.get_task 返回 sqlite3.Row，**没有 .get()**，必须下标取值
        base = Path(task["log_file"] or "").parent.resolve()
        target = (base / "shots" / name).resolve()
        if base not in target.parents or not target.is_file():
            abort(404)
        return send_file(str(target), mimetype="image/png")

    @app.route("/ips")
    @login_required
    def ips():
        """IP 资产页：按解析 IP 聚合域名。

        **默认只显示"非 CDN 解析"**（用户要求）：走 CDN 的域名解析出来是一堆边缘节点 IP，
        对"找到真实源站"没有帮助；`?cdn=1` 可把带 CDN 标记的也显示出来（仍单独标注厂商）。
        每行可勾选 → 直接对**真实 IP** 发起全端口扫描（复用 `/api/ports/full-scan`）。
        """
        include_cdn = request.args.get("cdn") == "1"
        agg = {}
        for r in db.list_subdomain_net():
            ip_text, cdn_label = (r["ip"] or ""), (r["cdn"] or "")
            if not ip_text:
                continue
            if cdn_label and not include_cdn:
                continue
            for ip in (x.strip() for x in ip_text.split(",")):
                if not ip:
                    continue
                item = agg.setdefault(ip, {"ip": ip, "domains": [], "cdn": cdn_label})
                if r["domain"] not in item["domains"]:
                    item["domains"].append(r["domain"])
                if cdn_label and not item["cdn"]:
                    item["cdn"] = cdn_label
        rows = sorted(agg.values(), key=lambda x: (-len(x["domains"]), x["ip"]))
        return render_template("ips.html", ips=rows, include_cdn=include_cdn)

    @app.route("/subdomains")
    @login_required
    def subdomains():
        # 只显示目标自身的子域名（被动收集 + 字典爆破）；JS/情报拓展出来的域名
        # 归到「拓展域名」页 —— 混在一起会让人误判资产归属。
        tag, where, params = _cdn_tag()
        rows, pager, q = _asset_page("subdomains", "/subdomains",
                                     extra_where=_and_where(db.OWN_SUBDOMAIN_WHERE, where),
                                     extra_params=params)
        if tag:
            pager["qs"] += f"&tag={tag}"
        return render_template("subdomains.html", subs=rows, pager=pager, q=q, tag=tag)

    # 拓展域名页的"来源分类"标签：用户要求分类浏览 + 分类排序，不要把 JS / FOFA 标题 /
    # 证书 / ICO / C 段混在一起。顺序即展示顺序（也是排序优先级）。
    EXT_SRC_TAGS = (
        ("js", "JS 挖掘", "js:mine", "js挖掘拓展"),
        ("title", "FOFA·标题反查", "osint:fofa-title", "fofa标题拓展"),
        ("cert", "FOFA·证书反查", "osint:fofa-cert", "fofa证书拓展"),
        ("ico", "FOFA·ICO 反查", "osint:fofa", "fofa-ico拓展"),
        ("cseg", "C 段反查", "osint:cseg", "c段反查拓展"),
    )
    # 分类排序表达式：按 EXT_SRC_TAGS 的顺序，未知来源排最后，同类内按 id 倒序（新的在前）。
    EXT_SRC_ORDER = "CASE source " + " ".join(
        f"WHEN '{s}' THEN {i}" for i, (_k, _l, s, _n) in enumerate(EXT_SRC_TAGS)
    ) + " ELSE 99 END, id DESC"

    @app.route("/extdomains")
    @login_required
    def extdomains():
        """拓展域名：从 JS 与外部情报（C 段 / ICO / 标题 / 证书）带出来的关联域名。

        **按来源分类展示与排序**（JS 挖掘 → FOFA·标题 → FOFA·证书 → FOFA·ICO → C 段），
        用户要求"不要夹在一起"；`?src=` 只显示某一类。
        **默认隐藏重叠资产**：某域名若已经作为"目标自身子域名"存在过（任意任务），
        说明它早就在资产清单里，这里再列一遍纯属重复；`?all=1` 可显示全部。
        """
        src = (request.args.get("src") or "").strip().lower()
        picked = next((t for t in EXT_SRC_TAGS if t[0] == src), None)
        if not picked:
            src = ""
        src_where = f"source = '{picked[2]}'" if picked else None
        scan_name = picked[3] if picked else "拓展域名"
        tag, where, params = _cdn_tag()
        show_all = _overlap_args()
        rows, pager, q = _asset_page(
            "subdomains", "/extdomains",
            extra_where=_and_where(db.EXT_SUBDOMAIN_WHERE, where, src_where,
                                   None if show_all else db.OVERLAP_EXT_WHERE),
            extra_params=params, order=EXT_SRC_ORDER)
        if tag:
            pager["qs"] += f"&tag={tag}"
        if src:
            pager["qs"] += f"&src={src}"
        if show_all:
            pager["qs"] += "&all=1"
        return render_template("extdomains.html", subs=rows, pager=pager, q=q, tag=tag,
                               show_all=show_all, secrets=_secret_counts(),
                               src=src, src_tags=EXT_SRC_TAGS, scan_name=scan_name)

    @app.route("/sites")
    @login_required
    def sites():
        show_all = _overlap_args()
        # 两层"重复"处理，都由 `?all=1` 一起放开：
        # 1) 重叠资产（跨任务）：同一 URL 在多个任务里都探到过时，只保留**最新一次扫描**的那条
        #    （`MAX(id)`）—— 站点行带的是当次扫描的 status/title/length/tech，留最旧那条意味着
        #    默认视图一直展示陈旧数据（重扫的目的正是刷新这些字段）；
        #    反复扫同一个目标时，站点列表也不会再被撑成 N 倍；
        # 2) 同任务内重复（标题 + 响应长度完全相同），多为同一台虚拟主机的别名/泛解析产物
        #    （灯塔类工具也做这层去重）。key 必须带 task_id：这是跨任务视图，若不带，
        #    A 任务的站点会因为 B 任务有同名同长度的站点而被折叠掉（实测把同一个靶场的
        #    15 条记录折成了 1 条，资产归属直接丢失）；标题为空的不参与折叠。
        # 注意：折叠只作用于**当前页**（分页条上的"共 N 条"是 SQL 的总数）。
        rows, pager, q = _asset_page(
            "sites", "/sites",
            extra_where=None if show_all else db.OVERLAP_SITE_WHERE)
        rows = [dict(r) for r in rows]
        seen, hidden = {}, 0
        for r in rows:
            r["dup"] = 0
            title = (r.get("title") or "").strip()
            if not title:
                continue
            key = (r.get("task_id"), title, r.get("length"))
            first = seen.get(key)
            if first is None:
                seen[key] = r
            else:
                first["dup"] += 1
                r["hidden_dup"] = True
                hidden += 1
        if not show_all:
            rows = [r for r in rows if not r.get("hidden_dup")]
        else:
            pager["qs"] += "&all=1"
        plain = request.args.get("plain") == "1"
        if plain:                     # 分页/筛选链接要带上，否则翻页会掉回完整模式
            pager["qs"] += "&plain=1"
        return render_template("sites.html", sites=rows, pager=pager, q=q,
                               show_all=show_all, hidden=hidden, plain=plain)

    @app.route("/ports")
    @login_required
    def ports():
        rows, pager, q = _asset_page("ports", "/ports")
        return render_template("ports.html", ports=rows, pager=pager, q=q)

    @app.route("/fullports")
    @login_required
    def fullports():
        """全端口扫描：**按任务分布**看端口资产，并可对勾选的主机发起全端口扫描。

        与 `/ports`（端口明细表）的区别：这里是"主机 × 任务"的视角 —— 一眼看出
        哪个任务在哪些主机上开了哪些端口，再决定要不要对某个 IP 补一次 1-65535 全端口。
        """
        raw_rows = db._query(
            "SELECT task_id, host, ip, COUNT(*) c, GROUP_CONCAT(port) ports "
            "FROM ports GROUP BY task_id, host, ip ORDER BY task_id DESC, host")
        names = {t["id"]: t["name"] for t in db.list_tasks(limit=1000)}
        rows = []
        for r in raw_rows:
            item = dict(r)      # sqlite3.Row 不支持赋值，先转成 dict 再加工
            item["ports"] = sorted(
                {int(p) for p in str(item.get("ports") or "").split(",")
                 if str(p).strip().isdigit()})
            item["task_name"] = names.get(item["task_id"], f"#{item['task_id']}")
            rows.append(item)
        return render_template("fullports.html", hosts=rows)

    @app.route("/api/ports/full-scan", methods=["POST"])
    @login_required
    def api_full_scan():
        """对勾选的主机发起**全端口扫描**（1-65535）。

        实现上走"新建一个只跑 portscan 的任务"（与「批量跑子域名」同一套做法）：
        任务选项 `portscan_full` 让这个任务无视全局 `portscan.enabled` 也会执行，
        并且会自动跳过本任务已经扫过的端口。
        """
        hosts, seen = [], set()
        for raw in request.form.getlist("host"):
            h = (raw or "").strip()
            if h and h not in seen:
                seen.add(h)
                hosts.append(h)
        if not hosts:
            return redirect(url_for("fullports"))
        name = (request.form.get("name") or "").strip() or \
            time.strftime("全端口-%m%d-%H%M%S")
        targets = "\n".join(hosts)
        stages = ["portscan"]
        options = {"portscan_full": True}
        task_id = db.create_task(name, targets, stages, options)
        _spawn(task_id, name, targets, stages, options)
        logger.info(f"[gui] 全端口扫描任务 #{task_id} 已创建（{len(hosts)} 个主机）")
        return redirect(url_for("task_detail", task_id=task_id))

    @app.route("/csegs")
    @login_required
    def csegs():
        rows, pager, q = _asset_page("csegs", "/csegs")
        return render_template("csegs.html", csegs=rows, pager=pager, q=q)

    @app.route("/dirs")
    @login_required
    def dirs():
        show_all = _overlap_args()
        rows, pager, q = _asset_page("dirs", "/dirs")
        # 重复长度默认隐藏：同一站点下状态码与响应大小都相同的多条只留首个，`?all=1` 放开
        rows, hidden = _fold_dirs(rows, show_all)
        if show_all:
            pager["qs"] += "&all=1"
        return render_template("dirs.html", dirs=rows, pager=pager, q=q,
                               show_all=show_all, hidden=hidden)

    # ---------- 黑名单 / 批量子域名 ----------
    #
    # 黑名单落地在 `config/blacklist.txt`（纯文本，可手工编辑），命中即"不入资产库"，
    # 因此也不会被后续阶段扫到。这里提供批量加入/移除 —— 逐个手敲域名不现实。

    def _picked_domains():
        """勾选的域名（去重保序）：跨任务资产页里同一个域名可能出现在多个任务下。"""
        seen, out = set(), []
        for raw in request.form.getlist("domain"):
            d = raw.strip()
            if d and d not in seen:
                seen.add(d)
                out.append(d)
        return out

    @app.route("/api/blacklist/add", methods=["POST"])
    @login_required
    def api_blacklist_add():
        domains = _picked_domains()
        n = blacklist.add(domains, settings)
        logger.info(f"[gui] 黑名单新增 {n} 条（提交 {len(domains)} 个）")
        return redirect(_safe_next(request.form.get("next"), url_for("subdomains")))

    @app.route("/api/blacklist/remove", methods=["POST"])
    @login_required
    def api_blacklist_remove():
        n = blacklist.remove(_picked_domains(), settings)
        logger.info(f"[gui] 黑名单移除 {n} 条")
        return redirect(url_for("settings_page"))

    @app.route("/api/domains/run-subdomain", methods=["POST"])
    @login_required
    def api_run_subdomain():
        """把勾选的域名打包成**一个新任务**，只跑 subdomain 阶段。

        为什么新建任务而不是在当前任务下挂子任务：现有任务模型（一任务一线程、独立状态与
        独立停止/删除）可以直接复用，子任务要改表结构、任务树渲染、状态聚合与递归停止，
        收益只是 UI 好看一点 —— 按用户确认的口径选"新建任务"。
        """
        domains = _picked_domains()
        if not domains:
            return redirect(_safe_next(request.form.get("next"), url_for("subdomains")))
        stages = ["subdomain"]
        # 任务名：表单可显式指定前缀（拓展域名页按来源分类给出，如 `fofa标题拓展`），
        # 统一再拼上时间戳，避免同名任务互相覆盖辨认；没给前缀时退回旧的 "批量子域-…"。
        prefix = (request.form.get("name") or "").strip()
        if prefix:
            name = f"{prefix}-{time.strftime('%m%d-%H%M%S')}"
        else:
            name = time.strftime("批量子域-%m%d-%H%M%S")
        targets = "\n".join(domains)
        task_id = db.create_task(name, targets, stages, {})
        _spawn(task_id, name, targets, stages, {})
        logger.info(f"[gui] 批量子域名任务 #{task_id} 已创建（{len(domains)} 个域名，仅 subdomain 阶段）")
        return redirect(url_for("task_detail", task_id=task_id))

    @app.route("/api/rescan", methods=["POST"])
    @login_required
    def api_rescan():
        """对勾选资产发起**补充扫描**：新建一个只跑对应阶段、走全量档的任务。

        `stage=dirscan` → 深度目录补扫（全量分层字典 + dirmap + 后缀派生）；
        `stage=portscan` → 全端口补扫（1-65535）。任务级选项 `dirscan_full` / `portscan_full`
        让这个任务无视全局开关与档位走全量，**不改全局策略**；`rescan_of` 记下发起它的原任务，
        任务详情页据此显示「由任务 #N 的补扫发起」并可回跳。

        与「批量跑子域名」「发起全端口扫描」同一套做法（一任务一线程，可独立停止/删除）。
        """
        stage = (request.form.get("stage") or "").strip().lower()
        fallback = _safe_next(request.form.get("next"), url_for("tasks"))
        if stage not in ("dirscan", "portscan"):
            return redirect(fallback)
        targets, seen = [], set()
        # 字段名沿用各页既有习惯（`target`），同时接受 `targets` 便于直接调 API
        for raw in request.form.getlist("target") + request.form.getlist("targets"):
            t = (raw or "").strip()
            if t and t not in seen:
                seen.add(t)
                targets.append(t)
        if not targets:
            return redirect(fallback)
        label = "全目录" if stage == "dirscan" else "全端口"
        name = (request.form.get("name") or "").strip() or \
            time.strftime(f"补扫{label}-%m%d-%H%M%S")
        options = {f"{stage}_full": True}
        from_task = (request.form.get("from_task") or "").strip()
        if from_task.isdigit():          # 只收任务号，避免把任意文本写进任务选项
            options["rescan_of"] = int(from_task)
        text = "\n".join(targets)
        stages = [stage]
        task_id = db.create_task(name, text, stages, options)
        _spawn(task_id, name, text, stages, options)
        logger.info(f"[gui] 补扫任务 #{task_id} 已创建（{stage} 全量档，"
                    f"{len(targets)} 个目标，来源任务 #{from_task or '-'}）")
        return redirect(url_for("task_detail", task_id=task_id))

    # ---------- 设置 ----------

    @app.route("/settings", methods=["GET", "POST"])
    @login_required
    def settings_page():
        nonlocal settings
        if request.method == "POST":
            f = request.form
            try:
                data = {
                    "gui": {"host": f.get("host", "127.0.0.1"),
                            "port": int(f.get("port", 5000) or 5000),
                            "token": f.get("token", "") or "ctfscanner"},
                    "limits": {"max_workers": int(f.get("max_workers", 20) or 20),
                               "http_timeout": int(f.get("http_timeout", 10) or 10),
                               "verify_tls": f.get("verify_tls") == "1",
                               "dirscan_max_urls": int(f.get("dirscan_max_urls", 20) or 20),
                               "vulnscan_max_urls": int(f.get("vulnscan_max_urls", 100) or 100),
                               "wildcard_filter": f.get("wildcard_filter") == "1",
                               "favicon_md5": f.get("favicon_md5") == "1"},
                    # 检测策略：级别门槛 + POC 引擎总开关 + 按 OWASP 分类/检查项/级别关闭
                    "checks": {"min_severity": f.get("min_severity", "medium"),
                               "skip_severities": f.getlist("skip_severities"),
                               "poc_engine": f.get("poc_engine") == "1",
                               "disabled_categories": f.getlist("disabled_categories"),
                               "disabled_checks": f.getlist("disabled_checks"),
                               "poc_link_tags": f.get("poc_link_tags") == "1",
                               "poc_max_per_site": int(f.get("poc_max_per_site", 80) or 80)},
                    "passive": {"enabled": f.get("passive_enabled") == "1",
                                "timeout": int(f.get("passive_timeout", 20) or 20)},
                    # 子域名收集：subfinder(-all) 与内置免 key 被动源是否取并集
                    "subdomain": {"max_resolve": int(
                                      (settings.get("subdomain") or {}).get("max_resolve", 500) or 500),
                                  "dns_timeout": float(
                                      (settings.get("subdomain") or {}).get("dns_timeout", 3) or 3),
                                  "union_passive": f.get("union_passive") == "1"},
                    "evasion": {"random_ua": f.get("random_ua") == "1",
                                "spoof_xff": f.get("spoof_xff") == "1",
                                "waf_bypass": f.get("waf_bypass") == "1",
                                "bypass_level": int(f.get("bypass_level", 2) or 0),
                                "waf_detect": f.get("waf_detect") == "1"},
                    "takeover": {"enabled": f.get("takeover_enabled") == "1",
                                 "max_hosts": int(f.get("takeover_max_hosts", 300) or 300),
                                 "http_check": f.get("takeover_http_check") == "1"},
                    # 阶段级总开关（与 takeover/portscan/jsmine 同一类）：默认开
                    # 目录扫描：默认开但只跑浅扫（用户要求"先浅浅过一遍再决定要不要深挖"）；
                    # 深扫走全量分层字典 + dirmap + 后缀派生
                    "dirscan": {"enabled": f.get("dirscan_enabled") == "1",
                                "mode": f.get("dirscan_mode", "quick"),
                                "quick_max_paths": int(
                                    f.get("dirscan_quick_max_paths", 150) or 150),
                                "suffix_aware": f.get("dirscan_suffix_aware") == "1",
                                "big_dict": f.get("dirscan_big_dict") == "1",
                                "tech_aware": f.get("dirscan_tech_aware") == "1",
                                "max_paths": int(f.get("dirscan_max_paths", 400) or 400),
                                "fw_max_paths": int(f.get("dirscan_fw_max_paths", 150) or 0)},
                    "vulnscan": {"enabled": f.get("vulnscan_enabled") == "1"},
                    # 站点截图（可选，默认关）：无头 Edge/Chrome
                    "screenshot": {"enabled": f.get("screenshot_enabled") == "1",
                                   "max_sites": int(f.get("screenshot_max_sites", 20) or 20),
                                   "window": (f.get("screenshot_window") or "1280x900").strip(),
                                   "timeout": int(f.get("screenshot_timeout", 30) or 30),
                                   "browser": (f.get("screenshot_browser") or "").strip()},
                    "portscan": {"enabled": f.get("portscan_enabled") == "1",
                                 "max_hosts": int(f.get("portscan_max_hosts", 100) or 100),
                                 "ports": f.get("portscan_ports", ""),
                                 # 全端口：top（内置 TOP 表）/ full（1-65535）
                                 "mode": "full" if f.get("portscan_mode") == "full" else "top",
                                 "full_ports": (f.get("portscan_full_ports") or "1-65535").strip(),
                                 # 全端口专用并发/超时（只在 full 模式生效）
                                 "full_workers": int(f.get("portscan_full_workers", 256) or 256),
                                 "full_timeout": float(f.get("portscan_full_timeout", 0.5) or 0.5),
                                 "exclude_scanned": f.get("portscan_exclude_scanned") == "1",
                                 "timeout": float(f.get("portscan_timeout", 1) or 1),
                                 "workers": int(f.get("portscan_workers", 64) or 64),
                                 "banner": f.get("portscan_banner") == "1",
                                 # auto / fscan / nmap / builtin（见 scanner/stages/portscan.py）
                                 "engine": (f.get("portscan_engine") or "auto").strip()},
                    "jsmine": {"enabled": f.get("jsmine_enabled") == "1",
                               "max_pages": int(f.get("jsmine_max_pages", 20) or 20),
                               "max_js": int(f.get("jsmine_max_js", 40) or 40),
                               "secrets": f.get("jsmine_secrets") == "1"},
                    # 外部情报拓展（OSINT）：C 段反查 + favicon 反查，两项默认都关
                    "iprecon": {"enabled": f.get("iprecon_enabled") == "1",
                                "api": f.get("iprecon_api", "") or
                                       "https://api.webscan.cc/?action=query&ip={ip}",
                                "max_ips": int(f.get("iprecon_max_ips", 500) or 500),
                                "max_hosts": int(f.get("iprecon_max_hosts", 200) or 200),
                                "max_domains_per_ip": int(
                                    f.get("iprecon_max_domains_per_ip", 30) or 30),
                                "workers": int(f.get("iprecon_workers", 5) or 5),
                                "timeout": float(f.get("iprecon_timeout", 10) or 10)},
                    "fofa": {"enabled": f.get("fofa_enabled") == "1",
                             "max_sites": int(f.get("fofa_max_sites", 30) or 30),
                             "max_assets": int(f.get("fofa_max_assets", 100) or 100),
                             "workers": int(f.get("fofa_workers", 5) or 5),
                             "black_ico_threshold": int(
                                 f.get("fofa_black_ico_threshold", 200) or 200),
                             # 证书反查：独立子开关 + 通用证书阈值 + 查询上限
                             "cert_enabled": f.get("fofa_cert_enabled") == "1",
                             "cert_threshold": int(f.get("fofa_cert_threshold", 200) or 200),
                             "max_cert_queries": int(
                                 f.get("fofa_max_cert_queries", 10) or 10),
                             # 标题反查：独立子开关 + 公共标题阈值 + 查询上限
                             "title_enabled": f.get("fofa_title_enabled") == "1",
                             "title_threshold": int(
                                 f.get("fofa_title_threshold", 200) or 200),
                             "max_title_queries": int(
                                 f.get("fofa_max_title_queries", 10) or 10)},
                    # 黑名单：开关可从页面改，文件路径保持原值（改路径请直接编辑 settings.yaml）
                    "blacklist": {"enabled": f.get("blacklist_enabled") == "1",
                                  "path": (settings.get("blacklist") or {}).get(
                                      "path", "config/blacklist.txt")},
                    # 情报与线索（P3-2 / P3-3）：两项都默认关，且只写 leads 表
                    "intel": {"enabled": f.get("intel_enabled") == "1",
                              "source": (f.get("intel_source") or "kev").strip(),
                              "url": (f.get("intel_url") or "").strip(),
                              "cache_hours": float(f.get("intel_cache_hours", 24) or 0),
                              "timeout": int(f.get("intel_timeout", 20) or 20),
                              "max_leads": int(f.get("intel_max_leads", 50) or 50)},
                    "heuristic": {"enabled": f.get("heuristic_enabled") == "1",
                                  "max_leads": int(f.get("heuristic_max_leads", 50) or 50)},
                }
            except ValueError:
                return render_template("settings.html", s=load_settings(), checks=owasp_checks,
                                       bl=blacklist.load(settings),
                                       bl_path=rel_display(blacklist.path(settings)),
                                       error="参数必须是整数")
            settings = save_settings(data)
            return redirect(url_for("settings_page"))
        return render_template("settings.html", s=settings, checks=owasp_checks,
                               bl=blacklist.load(settings),
                               bl_path=rel_display(blacklist.path(settings)))

    def _tail(path, n=150):
        try:
            return Path(path).read_text(encoding="utf-8", errors="replace").splitlines()[-n:]
        except OSError:
            return []

    return app


app = create_app()


def _port_free(host, port):
    """端口占用预检。

    必须自己做一次真实 bind：Windows 上 Werkzeug 对监听套接字设了 SO_REUSEADDR，
    第二个实例会**绑定成功**并照常打印 "Running on ..."，但页面其实打不开
    ——这正是之前诊断过的"控制台静默失败"（见 AGENTS.md 的经验教训）。
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, port))
        except OSError:
            return False
    return True


def serve():
    """控制台统一启动入口（run_gui.py 与 `python gui/app.py` 共用）。"""
    s = load_settings().get("gui", {})
    host, port = s.get("host", "127.0.0.1"), int(s.get("port", 5000))
    if not _port_free(host, port):
        print(f"[!] 启动失败：{host}:{port} 已被占用"
              "（上一次的控制台进程还在运行，或端口被其他服务占用）。")
        print("    处理：结束占用该端口的进程，或改 config/settings.yaml 的 gui.port 后重试。")
        raise SystemExit(1)
    print(f"[*] CTFScanner 控制台: http://{host}:{port}")
    print(f"[*] 登录口令: {s.get('token', 'ctfscanner')}（config/settings.yaml 可修改）")
    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    serve()
