"""冒烟测试：目标解析 + POC 引擎 + 离线流水线（probe/vulnscan）+ 指纹 + 报告 + GUI 路由。

自带本地靶场（smoke_root/，127.0.0.1:8765），无需手动起服务器；端口被占用时复用已有服务。
运行：python tests/smoke.py
"""
import atexit
import base64
import copy
import functools
import sys
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

FIXTURE_PORT = 8765


class _QuietHandler(SimpleHTTPRequestHandler):
    """靶场服务器：关闭逐请求日志，避免淹没测试输出。"""

    def log_message(self, *args):
        pass


def start_fixture(port=FIXTURE_PORT):
    """在后台线程启动内置靶场；端口被占用时返回 None（复用外部服务）。"""
    handler = functools.partial(_QuietHandler, directory=str(ROOT / "smoke_root"))
    try:
        httpd = ThreadingHTTPServer(("127.0.0.1", port), handler)
    except OSError:
        return None
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    atexit.register(httpd.shutdown)
    return httpd

from scanner import db
from scanner.config import load_settings
from scanner import evasion, fofa, iprecon, mmh3
from scanner.log import get_logger
from scanner.owasp import checks as owasp_checks
from scanner.targets import expand_cidr, parse_lines
from scanner.pocs import engine
from scanner.report import generate
from scanner.runner import (STAGE_ORDER, PipelineRunner, StageContext, run_task,
                            sync_pocs)


def main():
    start_fixture()
    db.init_db()

    # 1) 目标解析与归一化
    ts = parse_lines(["http://127.0.0.1:8765/", "# comment", "example.com",
                      "10.0.0.1", "10.0.0.1"])
    assert ("url", "http://127.0.0.1:8765") in ts and ("domain", "example.com") in ts, ts
    assert len(ts) == 3, ts
    # CIDR：/30 展开为 2 个可用主机；/16 超过 256 地址上限 → 整体丢弃（不产生目标）
    cidr = parse_lines(["10.0.0.0/30"])
    assert cidr == [("ip", "10.0.0.1"), ("ip", "10.0.0.2")], cidr
    assert not expand_cidr("10.0.0.0/16") and not parse_lines(["10.0.0.0/16"])
    print("[1] targets ok:", ts, "| cidr:", cidr)

    # 1b) 流水线阶段注册：takeover / portscan / osint / jsmine 均在顺序表与注册表中
    assert STAGE_ORDER == ["subdomain", "takeover", "portscan", "probe",
                           "osint", "jsmine", "dirscan", "vulnscan"], STAGE_ORDER
    print("[1b] stages ok:", ",".join(STAGE_ORDER))

    # 2) POC 加载与校验
    metas = engine.load_all_meta()
    bad = [m for m in metas if m.get("_status") != "ok"]
    assert metas and not bad, bad
    print(f"[2] pocs ok: {len(metas)} loaded")

    # 2b) POC 引擎的级别执行门 + 免杀变形动态性
    sync_pocs(load_settings())
    scan_pocs = engine.load_enabled_pocs(load_settings())
    assert all(engine._norm_severity((m.get("info") or {}).get("severity"))
               not in ("info", "low") for m in scan_pocs), "info/low 级 POC 不该进入扫描"
    wide = load_settings()
    wide["checks"]["skip_severities"] = []
    # 临时把注册表里所有 POC 打开，才能看出"级别执行门"真实挡掉了多少模板（跑完原样还原）
    keep_off = [r["id"] for r in db.list_pocs() if r["status"] == "ok" and not r["enabled"]]
    try:
        db.bulk_set_poc_enabled(True, only_ok=True)
        n_gate = len(engine.load_enabled_pocs(load_settings()))
        n_wide = len(engine.load_enabled_pocs(wide))
    finally:
        for pid in keep_off:
            db.toggle_poc(pid)
    assert n_wide > n_gate, (n_gate, n_wide, "info/low 级 POC 应被级别执行门挡在扫描外")
    sqli = evasion.mutate_sqli("1' union select 1,2", 3)
    assert sqli[0] == "1' union select 1,2" and len(sqli) > 3, sqli  # 原始在前 + 变形变体
    assert evasion.mutate_sqli("1' and 1=1", 0) == ["1' and 1=1"], "level=0 只回原始 payload"
    assert len(evasion.mutate_xss("<svg/onload=x>", 3)) > 3
    print(f"[2b] exec-gate + mutation ok: 全开注册表后 级别门内 {n_gate} 个 / 放开后 {n_wide} 个；"
          f"sqli 变体 {len(sqli)} 个（原始优先，其余每次随机序）")

    # 2c) favicon 平台指纹（mmh3）与外部情报模块（iprecon / fofa）的纯函数行为
    settings = load_settings()
    for data, want in mmh3.SELF_TEST:      # 公开已知向量：算法写错立刻暴露
        assert mmh3.hash32(data) == want, (data, mmh3.hash32(data), want)
    assert mmh3.favicon_hash(b"") == 0
    icon = b"\x00\x01\x02\x03ico!"
    # 社区指纹必须是 base64.encodebytes（带换行），换成 b64encode 就对不上 FOFA/Shodan 数据
    assert mmh3.favicon_hash(icon) == mmh3.hash32(base64.encodebytes(icon))
    assert iprecon.segment_of("1.2.3.4") == "1.2.3.0/24" and iprecon.segment_of("::1") == ""
    assert iprecon.is_public_ip("8.8.8.8") is True
    for private in ("10.0.0.1", "127.0.0.1", "192.168.1.1", "not-an-ip"):
        assert iprecon.is_public_ip(private) is False, private
    # 反查响应解析：绝不 eval；null / 非 JSON / 结构不符一律空表
    assert iprecon.parse_domains("null") == [] and iprecon.parse_domains("<html>") == []
    assert iprecon.parse_domains('[{"domain": "A.Example.com:8080"}, "*.b.example.com"]') == \
        ["a.example.com", "b.example.com"]
    assert iprecon.group_segments(["1.2.3.5", "1.2.3.4", "9.9.9.9", "::1"]) == \
        {"1.2.3.0/24": ["1.2.3.4", "1.2.3.5"], "9.9.9.0/24": ["9.9.9.9"]}
    assert fofa.build_query(-12345) == 'icon_hash="-12345"'
    assert fofa.available(settings) is False, "keys.yaml 未填 fofa 时应判为不可用"
    assert fofa.search(-12345, settings)[2], "无 key 时应显式报错而不是静默返回空"
    assert fofa.is_black_ico(200, settings) is False and fofa.is_black_ico(201, settings) is True
    print(f"[2c] favicon/osint primitives ok: mmh3 向量 {len(mmh3.SELF_TEST)} 个全中；"
          f"favicon_hash(b'')={mmh3.favicon_hash(b'')} / ico={mmh3.favicon_hash(icon)}；"
          f"黑 ico 阈值 {fofa.black_ico_threshold(settings)}；fofa 可用={fofa.available(settings)}")

    # 3) 离线流水线（probe + vulnscan）打本地靶场
    targets = "http://127.0.0.1:8765/"
    stages = ["probe", "vulnscan"]
    tid = db.create_task("smoke", targets, stages, {"offline": True})
    sync_pocs(settings)
    ctx = run_task(tid, "smoke", targets, stages, {"offline": True}, settings)
    sites = ctx.results["sites"]
    vulns = ctx.results["vulns"]
    assert sites and sites[0]["url"].startswith("http://127.0.0.1:8765"), sites
    # 内置探测应通过指纹模块识别出技术栈（本地靶场为 Python SimpleHTTP）
    assert "python" in (sites[0].get("tech") or ""), sites[0]
    ids = sorted(v["poc_id"] for v in vulns)
    # favicon 前置指纹：probe 阶段应回填 favicon 字段（靶场无 favicon.ico 时为空串）
    assert "favicon" in sites[0], sites[0]
    print(f"[3] pipeline ok: sites={len(sites)} tech={sites[0]['tech']} "
          f"favicon={sites[0]['favicon'] or '-'} vulns={len(vulns)} {ids}")
    # 默认门槛（checks.min_severity=medium）下：high 级 POC 命中，low/info 级内置检查被门控掉
    assert "exposure-git-config" in ids, ids
    assert "a02-no-https" not in ids and "a05-security-headers" not in ids, ids

    # 3b) 门控行为：默认 skip_severities=["info","low"] 时这两级**连执行都不执行**；
    #     放开 skip_severities 且门槛放到 info 后低危项才出现；再按 OWASP 分类关闭应重新消失
    low_ids = [v["poc_id"] for v in owasp_checks.run_all(targets, settings)]
    assert "a02-no-https" not in low_ids, low_ids
    # 执行级门控：只调 min_severity（报告级）不够，info/low 级检查根本不该跑
    floor_only = copy.deepcopy(settings)
    floor_only["checks"]["min_severity"] = "info"
    floor_ids = [v["poc_id"] for v in owasp_checks.run_all(targets, floor_only)]
    assert "a02-no-https" not in floor_ids and "a05-security-headers" not in floor_ids, floor_ids
    loose = copy.deepcopy(settings)
    loose["checks"]["min_severity"] = "info"
    loose["checks"]["skip_severities"] = []
    info_ids = [v["poc_id"] for v in owasp_checks.run_all(targets, loose)]
    assert "a02-no-https" in info_ids and "a05-security-headers" in info_ids, info_ids
    loose["checks"]["disabled_categories"] = ["A02"]
    cat_ids = [v["poc_id"] for v in owasp_checks.run_all(targets, loose)]
    assert not any(i.startswith("a02-") for i in cat_ids), cat_ids
    assert "a05-security-headers" in cat_ids, cat_ids
    print(f"[3b] gating ok: floor=medium -> {len(low_ids)} 项 / 仅抬门槛 -> "
          f"{len(floor_ids)} 项 / 放开级别门 -> {len(info_ids)} 项 / 关闭 A02 -> {len(cat_ids)} 项")

    # 3c) POC 引擎总开关：关闭后只有内置 OWASP 检查，level 门槛同时放开以观察 low 项
    st_off = copy.deepcopy(settings)
    st_off["checks"]["poc_engine"] = False
    st_off["checks"]["min_severity"] = "info"
    st_off["checks"]["skip_severities"] = []
    tid_off = db.create_task("smoke-nopoc", targets, stages, {"offline": True})
    ctx_off = run_task(tid_off, "smoke-nopoc", targets, stages, {"offline": True}, st_off)
    ids_off = sorted(v["poc_id"] for v in ctx_off.results["vulns"])
    assert "exposure-git-config" not in ids_off, ids_off
    assert "a01-sensitive-files" in ids_off and "a02-no-https" in ids_off, ids_off
    print(f"[3c] poc_engine=off ok: {ids_off}")

    # 3d) 资产面拓展阶段门控：开关全部关闭时，跑这些阶段应完全跳过且不产生任何资产/请求
    st_gate = copy.deepcopy(settings)
    for seg in ("takeover", "portscan", "jsmine"):
        st_gate[seg]["enabled"] = False
    for seg in ("iprecon", "fofa"):        # osint 的两个子开关
        st_gate[seg]["enabled"] = False
    gate_stages = ["takeover", "portscan", "osint", "jsmine"]
    tid_gate = db.create_task("smoke-gate", targets, gate_stages, {"offline": True})
    ctx_gate = run_task(tid_gate, "smoke-gate", targets, gate_stages,
                        {"offline": True}, st_gate)
    assert not ctx_gate.results["takeovers"] and not ctx_gate.results["ports"], ctx_gate.results
    assert not db.list_ports(tid_gate), db.list_ports(tid_gate)
    # osint 两项子开关都关 → 连请求都不发，C 段与新增域名均为空
    assert not ctx_gate.results["csegs"] and not db.list_csegs(tid_gate), ctx_gate.results["csegs"]
    assert not ctx_gate.results["osint_domains"], ctx_gate.results["osint_domains"]
    print("[3d] gate ok: takeover/portscan/osint/jsmine 关闭后无产出")

    # 4) Markdown 报告
    md = generate(tid)
    assert md and "潜在漏洞" in md and "疑似问题" not in md
    assert "开放端口" in md, md[:400]      # 报告概览已加入端口维度
    assert "C 段 IP" in md, md[:400]       # 概览与「C 段视野」小节（无数据时不出小节）
    print(f"[4] report ok: {len(md)} chars")

    # 4b) 协作式停止：取消信号已置位时流水线在首个阶段前退出，任务状态落为 stopped
    tid_stop = db.create_task("smoke-stop", targets, stages, {"offline": True})
    wd = ROOT / "logs" / f"task_{tid_stop}_smokestop"
    wd.mkdir(parents=True, exist_ok=True)
    ev = threading.Event()
    ev.set()
    ctx_stop = StageContext(tid_stop, "smoke-stop", parse_lines([targets]), stages,
                            {"offline": True}, settings, wd,
                            get_logger(f"task-{tid_stop}", wd / "task.log"), stop_event=ev)
    PipelineRunner(ctx_stop).run()
    assert db.get_task(tid_stop)["status"] == "stopped"
    assert not ctx_stop.results["sites"], ctx_stop.results["sites"]
    print("[4b] stop ok: status=stopped 且未产生站点")

    # 5) GUI 路由（test client，不占端口）
    from gui.app import app
    c = app.test_client()
    assert c.get("/").status_code == 302
    assert c.post("/login", data={"token": "wrong"}).status_code == 200
    assert c.post("/login", data={"token": settings["gui"]["token"]}).status_code == 302
    for path in ("/", "/tasks", f"/tasks/{tid}", "/subdomains", "/sites", "/dirs",
                 "/ports", "/csegs", "/pocs", "/vulns", "/settings",
                 f"/api/tasks/{tid}/status", f"/tasks/{tid}/export"):
        r = c.get(path)
        assert r.status_code == 200, (path, r.status_code)
    # 导出接口应回传 Markdown 报告正文
    assert "潜在漏洞" in c.get(f"/tasks/{tid}/export").get_data(as_text=True)
    # 任务列表页应有批量操作条与行内操作；详情页默认页签应为「潜在漏洞」
    tasks_html = c.get("/tasks").get_data(as_text=True)
    assert "批量停止" in tasks_html and "批量删除" in tasks_html and "data-op=\"restart\"" in tasks_html
    detail_html = c.get(f"/tasks/{tid}").get_data(as_text=True)
    assert "潜在漏洞" in detail_html and "目标与配置" in detail_html and "端口服务" in detail_html
    assert "C 段" in detail_html, "任务详情应含「C 段」页签"
    # C 段视野全局分栏：关键字过滤表单 + 服务端分页条
    cseg_html = c.get("/csegs").get_data(as_text=True)
    assert "C 段视野" in cseg_html and 'name="q"' in cseg_html and "每页" in cseg_html
    # 资产页服务端分页条 + 关键字过滤表单
    subs_html = c.get("/subdomains").get_data(as_text=True)
    assert "每页" in subs_html and "共" in subs_html and 'name="q"' in subs_html
    # POC 管理页：分类批量开关 + 来源归类
    poc_html = c.get("/pocs").get_data(as_text=True)
    assert "按分类批量开关" in poc_html and "导入（参考项目转换）" in poc_html
    # 批量接口：导入 POC 默认关闭 → 启用（仅改不一致的）应影响全部导入项，再关闭还原原状
    assert db.bulk_set_poc_enabled(False, source="imported") > 0
    r = c.post("/api/pocs/bulk", json={"action": "enable", "source": "imported", "kind": "diff"})
    n_on = r.get_json()["affected"]
    assert n_on > 0, r.get_json()
    r = c.post("/api/pocs/bulk", json={"action": "disable", "source": "imported", "kind": "diff"})
    assert r.get_json()["affected"] == n_on, r.get_json()
    assert c.post("/api/pocs/bulk", json={"action": "nope"}).status_code == 400
    # 批量接口：停止未运行的任务应计入 skipped，删除则应真正清库
    r = c.post("/api/tasks/bulk", json={"action": "stop", "ids": [tid_stop]})
    assert r.get_json()["skipped"] == [tid_stop], r.get_json()
    r = c.post("/api/tasks/bulk", json={"action": "delete", "ids": [tid_stop, 999999]})
    assert r.get_json()["affected"] == 1 and r.get_json()["skipped"] == [999999], r.get_json()
    assert db.get_task(tid_stop) is None
    print("[5] gui routes ok（含导出 / 批量停止 / 批量删除）")
    print("SMOKE PASS")


if __name__ == "__main__":
    main()
