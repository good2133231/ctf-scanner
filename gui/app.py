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

from flask import (Flask, Response, abort, jsonify, redirect,
                   render_template, request, session, url_for)

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner import db
from scanner.config import BASE_DIR, load_settings, save_settings
from scanner.log import get_logger
from scanner.owasp import checks as owasp_checks
from scanner.pocs import engine
from scanner import runner
from scanner.runner import STAGE_ORDER, run_task, sync_pocs

logger = get_logger("gui")


def _rel_path(path):
    """把绝对路径转成相对项目根的路径（页面上只展示相对路径，不暴露本机目录结构）。

    解析失败（不在项目内、路径不存在）时原样返回，绝不因为展示需求而抛错。
    """
    try:
        return str(Path(path).resolve().relative_to(BASE_DIR))
    except (ValueError, OSError):
        return str(path)


def _and_where(*parts):
    """把若干 SQL 条件用 AND 拼起来，忽略空值（避免条件为空时生成 `() AND ...`）。"""
    items = [p for p in parts if p]
    return " AND ".join(f"({p})" for p in items) if items else None


def create_app():
    settings = load_settings()
    app = Flask(__name__)
    app.secret_key = f"ctfscanner::{settings.get('gui', {}).get('token', '')}"
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
        task_id = db.create_task(name, targets, stages, options)
        _spawn(task_id, name, targets, stages, options)
        return jsonify({"id": task_id})

    @app.route("/tasks/<int:task_id>")
    @login_required
    def task_detail(task_id):
        task = db.get_task(task_id)
        if not task:
            abort(404)
        # 子域名 Tab 只列目标自身的子域名；JS/情报拓展的域名单独计数并指到「拓展域名」页
        subs = [dict(r) for r in db.list_subdomains(task_id)]
        own = [r for r in subs if not (r["source"] or "").startswith(("js:", "osint:"))]
        return render_template(
            "task_detail.html", task=task,
            subs=own, ext_count=len(subs) - len(own),
            sites=db.list_sites(task_id),
            ports=db.list_ports(task_id), csegs=db.list_csegs(task_id),
            dirs=db.list_dirs(task_id),
            vulns=db.list_vulns(task_id=task_id, limit=1000),
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
            r["path"] = _rel_path(r["path"])  # 页面只展示相对路径
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

    def _asset_page(table, base, extra_where=None, extra_params=()):
        page, size, q = _page_args()
        rows, total = db.page_assets(table, limit=size, offset=(page - 1) * size, q=q or None,
                                     extra_where=extra_where, extra_params=extra_params)
        pages = max(1, (total + size - 1) // size)
        if page > pages:  # 页码越界（例如过滤后总页数变少）→ 回落到最后一页重查
            page = pages
            rows, total = db.page_assets(table, limit=size, offset=(page - 1) * size,
                                         q=q or None, extra_where=extra_where,
                                         extra_params=extra_params)
        qs = f"&q={q}&size={size}" if q else f"&size={size}"
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

    @app.route("/extdomains")
    @login_required
    def extdomains():
        """拓展域名：从 JS（js:mine）与外部情报（osint:cseg / osint:fofa）带出来的域名。"""
        tag, where, params = _cdn_tag()
        rows, pager, q = _asset_page("subdomains", "/extdomains",
                                     extra_where=_and_where(db.EXT_SUBDOMAIN_WHERE, where),
                                     extra_params=params)
        if tag:
            pager["qs"] += f"&tag={tag}"
        return render_template("extdomains.html", subs=rows, pager=pager, q=q, tag=tag)

    @app.route("/sites")
    @login_required
    def sites():
        rows, pager, q = _asset_page("sites", "/sites")
        # 重复站点折叠：**同一任务内**「标题 + 响应长度」完全相同的多个 URL，多为同一台
        # 虚拟主机的别名/泛解析产物（灯塔类工具也会做这层去重）。默认只留首个出现的，其余
        # 隐藏，页面上给开关显示全部。两个要点：
        # - key 必须带 task_id：这是跨任务视图，若不带，A 任务的站点会因为 B 任务有同名同长度的
        #   站点而被折叠掉（实测把同一个靶场的 15 条记录折成了 1 条，资产归属直接丢失）；
        # - 标题为空的不参与折叠 —— 空标题站点的长度相同纯属巧合；
        # - 折叠只作用于**当前页**（分页条上的"共 N 条"仍是 SQL 的总数）。
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
        show_all = request.args.get("all") == "1"
        if not show_all:
            rows = [r for r in rows if not r.get("hidden_dup")]
        if show_all:
            pager["qs"] += "&all=1"
        return render_template("sites.html", sites=rows, pager=pager, q=q,
                               show_all=show_all, hidden=hidden)

    @app.route("/ports")
    @login_required
    def ports():
        rows, pager, q = _asset_page("ports", "/ports")
        return render_template("ports.html", ports=rows, pager=pager, q=q)

    @app.route("/csegs")
    @login_required
    def csegs():
        rows, pager, q = _asset_page("csegs", "/csegs")
        return render_template("csegs.html", csegs=rows, pager=pager, q=q)

    @app.route("/dirs")
    @login_required
    def dirs():
        rows, pager, q = _asset_page("dirs", "/dirs")
        return render_template("dirs.html", dirs=rows, pager=pager, q=q)

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
                    "evasion": {"random_ua": f.get("random_ua") == "1",
                                "spoof_xff": f.get("spoof_xff") == "1",
                                "waf_bypass": f.get("waf_bypass") == "1",
                                "bypass_level": int(f.get("bypass_level", 2) or 0),
                                "waf_detect": f.get("waf_detect") == "1"},
                    "takeover": {"enabled": f.get("takeover_enabled") == "1",
                                 "max_hosts": int(f.get("takeover_max_hosts", 300) or 300),
                                 "http_check": f.get("takeover_http_check") == "1"},
                    # 阶段级总开关（与 takeover/portscan/jsmine 同一类）：默认开
                    "dirscan": {"enabled": f.get("dirscan_enabled") == "1"},
                    "vulnscan": {"enabled": f.get("vulnscan_enabled") == "1"},
                    "portscan": {"enabled": f.get("portscan_enabled") == "1",
                                 "max_hosts": int(f.get("portscan_max_hosts", 100) or 100),
                                 "ports": f.get("portscan_ports", ""),
                                 "timeout": float(f.get("portscan_timeout", 1) or 1),
                                 "workers": int(f.get("portscan_workers", 64) or 64),
                                 "banner": f.get("portscan_banner") == "1"},
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
                                 f.get("fofa_black_ico_threshold", 200) or 200)},
                }
            except ValueError:
                return render_template("settings.html", s=load_settings(), checks=owasp_checks,
                                       error="参数必须是整数")
            settings = save_settings(data)
            return redirect(url_for("settings_page"))
        return render_template("settings.html", s=settings, checks=owasp_checks)

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
