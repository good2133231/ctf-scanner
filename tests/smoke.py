"""冒烟测试：目标解析 + POC 引擎 + 离线流水线（probe/vulnscan）+ 指纹 + 报告 + GUI 路由。

自带本地靶场（smoke_root/，127.0.0.1:8765），无需手动起服务器；端口被占用时复用已有服务。
运行：python tests/smoke.py
"""
import atexit
import base64
import copy
import functools
import os
import shutil
import sys
import tempfile
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# ---- 测试库/日志目录隔离（用户要求：跑测试不能污染真实工作区）----
# 默认库 `data/scanner.db` 是**真实任务库**，直接跑冒烟测试会往里写任务/站点/漏洞/端口
# （之前那些"计数断言不稳定"多半就是这么来的）；每任务还会在 `logs/` 下堆一个目录。
# 这里把库与任务工作目录都指到 `logs/` 下的一个临时目录（`db.DB_PATH` / `db.TRASH_DIR` /
# `config.LOGS_DIR` 都跟着环境变量走），跑完统一删除 —— `logs/` 已在 .gitignore 内。
# 这也就是"开发/生产共用一份代码、数据分开"的最小实现，不必搞两套目录。
# 注意：临时目录刻意放在项目**内部** —— `rel_display()` 只能把项目内的路径显示成相对路径，
# 放到系统临时目录反而会让页面显示出绝对路径（那就测不出"路径相对化"了）。
(ROOT / "logs").mkdir(exist_ok=True)
_TMPDIR = Path(tempfile.mkdtemp(prefix="smoke-", dir=str(ROOT / "logs")))
os.environ["CTFSCANNER_DB"] = str(_TMPDIR / "scanner.db")
os.environ["CTFSCANNER_LOGS"] = str(_TMPDIR)
atexit.register(lambda: shutil.rmtree(_TMPDIR, ignore_errors=True))

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
from scanner.config import LOGS_DIR, load_settings
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
    # FOFA 凭据来自 config/keys.yaml（本地环境文件、已 gitignore），测试**不能假设它是否已填**：
    # 用一份显式清空 keys 的副本断言"未配置"分支。之前这里直接断言 `available(settings) is False`，
    # 用户一旦填入真实 key，测试先是失败、然后会带着真 key 去发真实请求 —— 测试必须与本地凭据无关。
    no_key = copy.deepcopy(settings)
    no_key["keys"] = {"fofa": {"email": "", "key": ""}}
    assert fofa.available(no_key) is False, "未配置 email/key 时 fofa 应判为不可用"
    assert fofa.search(-12345, no_key)[2], "无 key 时应显式报错而不是静默返回空"
    assert fofa.is_black_ico(200, settings) is False and fofa.is_black_ico(201, settings) is True
    print(f"[2c] favicon/osint primitives ok: mmh3 向量 {len(mmh3.SELF_TEST)} 个全中；"
          f"favicon_hash(b'')={mmh3.favicon_hash(b'')} / ico={mmh3.favicon_hash(icon)}；"
          f"黑 ico 阈值 {fofa.black_ico_threshold(settings)}；fofa 可用={fofa.available(settings)}")

    # 2d) 响应体解码（站点标题中文乱码的根因）：响应头没声明 charset 时，requests 的 r.text 会
    #     按 ISO-8859-1 回退，UTF-8 的"维保中心"会变成"ç»´ä¿ä¸­å¿ƒ"并原样入库。
    from scanner.utils import _charset_of, _decode_body
    assert _charset_of("text/html; charset=GBK") == "GBK"
    assert _charset_of("text/html") == ""
    zh = "维保中心"
    assert _decode_body(zh.encode("utf-8"), "text/html") == zh, "无 charset 时必须按 UTF-8 解"
    assert _decode_body(zh.encode("utf-8"), "text/html; charset=utf-8") == zh
    # GB18030 兜底：中文站的"中文"用 UTF-8 解是非法字节序列，应回退到 gb18030
    assert _decode_body("中文".encode("gb18030"), "text/html") == "中文"
    assert _decode_body("中文".encode("gb18030"), "text/html; charset=gbk") == "中文"
    assert _decode_body(b"\xff\xfe\xfa", "text/html"), "严重损坏时也要返回替换字符而不是抛错"
    print("[2d] body-decode ok: 无 charset → UTF-8 / 声明优先 / GB18030 兜底")

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

    # 3d) 资产面拓展 / 检测阶段门控：开关全部关闭时，跑这些阶段应完全跳过且不产生任何资产/请求。
    #     这里刻意**开启 probe 先造出存活站点** —— 否则 dirscan/vulnscan/jsmine 会因为"无站点"
    #     而跳过，那样测出来的是"没输入"，而不是"门控生效"。
    st_gate = copy.deepcopy(settings)
    for seg in ("takeover", "portscan", "jsmine", "dirscan", "vulnscan"):
        st_gate[seg]["enabled"] = False
    for seg in ("iprecon", "fofa"):        # osint 的两个子开关
        st_gate[seg]["enabled"] = False
    gate_stages = ["probe", "takeover", "portscan", "osint", "jsmine", "dirscan", "vulnscan"]
    tid_gate = db.create_task("smoke-gate", targets, gate_stages, {"offline": True})
    ctx_gate = run_task(tid_gate, "smoke-gate", targets, gate_stages,
                        {"offline": True}, st_gate)
    assert ctx_gate.results["sites"], "probe 未产出站点，下面的门控断言会失去意义"
    assert not ctx_gate.results["takeovers"] and not ctx_gate.results["ports"], ctx_gate.results
    assert not db.list_ports(tid_gate), db.list_ports(tid_gate)
    # dirscan / vulnscan 关掉后：站点存在，但目录与漏洞都必须为空（连请求都不发）
    assert not ctx_gate.results["dirs"] and not db.list_dirs(tid_gate), ctx_gate.results["dirs"]
    assert not ctx_gate.results["vulns"] and not db.list_vulns(task_id=tid_gate)
    # osint 两项子开关都关 → 连请求都不发，C 段与新增域名均为空
    assert not ctx_gate.results["csegs"] and not db.list_csegs(tid_gate), ctx_gate.results["csegs"]
    assert not ctx_gate.results["osint_domains"], ctx_gate.results["osint_domains"]
    print("[3d] gate ok: probe 有站点，但 takeover/portscan/osint/jsmine/dirscan/vulnscan 关闭后无产出")

    # 3e) 非标端口站点：portscan 已发现的开放端口要参与 probe 候选生成。
    #     灯塔能扫出 `http://host:9007` 这类站点，靠的就是"对开放端口补做 HTTP 探测"；
    #     这里给 127.0.0.1:8765（本地靶场）造一条端口记录，目标只给裸 IP，
    #     若 probe 不消费端口记录，就不可能产出 8765 上的站点。
    tid_port = db.create_task("smoke-port", "127.0.0.1", ["probe"], {"offline": True})
    db.insert_ports(tid_port, [{"host": "127.0.0.1", "ip": "127.0.0.1", "port": FIXTURE_PORT,
                                "service": "http", "banner": ""}])
    ctx_port = run_task(tid_port, "smoke-port", "127.0.0.1", ["probe"],
                        {"offline": True}, settings)
    port_urls = [s["url"] for s in ctx_port.results["sites"]]
    assert any(f":{FIXTURE_PORT}" in u for u in port_urls), port_urls
    print(f"[3e] nonstd-port ok: 候选纳入开放端口 -> {port_urls}")

    # 4) Markdown 报告
    md = generate(tid)
    assert md and "潜在漏洞" in md and "疑似问题" not in md
    assert "开放端口" in md, md[:400]      # 报告概览已加入端口维度
    assert "C 段 IP" in md, md[:400]       # 概览与「C 段视野」小节（无数据时不出小节）
    print(f"[4] report ok: {len(md)} chars")

    # 4b) 协作式停止：取消信号已置位时流水线在首个阶段前退出，任务状态落为 stopped
    tid_stop = db.create_task("smoke-stop", targets, stages, {"offline": True})
    wd = LOGS_DIR / f"task_{tid_stop}_smokestop"
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
    # 策略配置页：新加的阶段总开关必须渲染出来，且**表单名与 app.py 读取的键一一对应**
    # （这类"名字对不上"的错最隐蔽：页面照样 200，开关却永远不生效）
    settings_html = c.get("/settings").get_data(as_text=True)
    assert 'name="dirscan_enabled"' in settings_html, "策略配置缺 dirscan 总开关"
    assert 'name="vulnscan_enabled"' in settings_html, "策略配置缺 vulnscan 总开关"
    # 用桩函数接管 save_settings：既能验证 POST→配置字典的映射，又不改动真实 config/settings.yaml
    import gui.app as gui_app
    captured = {}

    def _fake_save(d):
        captured.clear()
        captured.update(d)
        return load_settings()

    _orig_save = gui_app.save_settings
    gui_app.save_settings = _fake_save
    try:
        assert c.post("/settings", data={"min_severity": "medium", "dirscan_enabled": "1",
                                         "vulnscan_enabled": "1"}).status_code == 302
        assert captured["dirscan"]["enabled"] is True, captured.get("dirscan")
        assert captured["vulnscan"]["enabled"] is True, captured.get("vulnscan")
        # 表单里不勾选 → 必须落为关闭（而不是保持旧值 True）
        assert c.post("/settings", data={"min_severity": "medium"}).status_code == 302
        assert captured["dirscan"]["enabled"] is False, captured.get("dirscan")
        assert captured["vulnscan"]["enabled"] is False, captured.get("vulnscan")
    finally:
        gui_app.save_settings = _orig_save
    print("[5b] settings POST ok: dirscan/vulnscan 总开关的勾选与取消勾选均正确落库")
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

    # 5c) 本轮新增行为：子域名/拓展域名分流 + IP/CDN 标记与标签过滤 + 站点去重折叠 + POC 相对路径
    from scanner import cdn as cdn_mod
    assert cdn_mod.match(["x.alicdn.com"]) == "alicdn.com"
    assert cdn_mod.match(["a1.b.akamaiedge.net"]) == "akamaiedge.net"
    assert cdn_mod.match(["site.cloudflare.net"]) == "cloudflare"   # 名单里的裸词按片段匹配
    assert cdn_mod.match(["www.example.com"]) == ""
    # 侧边栏精简：端口服务 / C 段视野 / 目录发现 三项已从导航移除（路由保留，任务详情仍在用）
    nav_html = c.get("/subdomains").get_data(as_text=True)
    assert 'href="/extdomains"' in nav_html, "侧边栏缺「拓展域名」"
    for gone in ('href="/ports"', 'href="/csegs"', 'href="/dirs"'):
        assert gone not in nav_html, f"侧边栏应已移除 {gone}"
    # 分流：js/osint 来源进「拓展域名」，被动收集/爆破来源留在「子域名资产」
    db.insert_subdomains(tid, [("own-smoke.example.com", "subfinder"),
                               ("js-smoke.example.com", "js:mine"),
                               ("osint-smoke.example.com", "osint:cseg")])
    db.set_subdomain_net(tid, {"own-smoke.example.com": ("1.2.3.4", ""),
                               "js-smoke.example.com": ("5.6.7.8", "cloudflare")})
    own_html = c.get("/subdomains").get_data(as_text=True)
    assert "own-smoke.example.com" in own_html and "js-smoke.example.com" not in own_html
    assert "非 CDN" in own_html, "非 CDN 标记应渲染"
    ext_html = c.get("/extdomains").get_data(as_text=True)
    assert "js-smoke.example.com" in ext_html and "own-smoke.example.com" not in ext_html
    assert "osint-smoke.example.com" in ext_html and "5.6.7.8" in ext_html
    # CDN 标签过滤走服务端 SQL
    assert "own-smoke.example.com" not in c.get("/subdomains?tag=cdn").get_data(as_text=True)
    assert "own-smoke.example.com" in c.get("/subdomains?tag=nocdn").get_data(as_text=True)
    assert "js-smoke.example.com" in c.get("/extdomains?tag=cdn").get_data(as_text=True)
    assert "js-smoke.example.com" not in c.get("/extdomains?tag=nocdn").get_data(as_text=True)
    # 站点去重折叠：标题 + 响应长度相同的默认只留首个，?all=1 显示全部。
    # 标题带上本次任务的 id —— 折叠是按任务的，而 smoke 复用的是同一个库，
    # 用固定标题会被上一次运行留下的同名站点干扰（计数就不是 1/3 了）。
    dup_title = f"SMOKE-DUP-{tid}"
    db.insert_sites(tid, [{"url": f"http://dup{i}.smoke.test/", "host": f"dup{i}.smoke.test",
                           "port": "80", "status": 200, "title": dup_title, "length": 1234,
                           "source": "builtin"} for i in range(3)])
    folded = c.get("/sites").get_data(as_text=True)
    assert folded.count(dup_title) == 1, folded.count(dup_title)
    assert "已折叠隐藏" in folded and "另有 2 条相同" in folded
    unfolded = c.get("/sites?all=1").get_data(as_text=True)
    assert unfolded.count(dup_title) == 3, unfolded.count(dup_title)
    assert "（被折叠）" in unfolded
    # POC 页只展示相对路径（不出现本机绝对目录）
    assert str(ROOT) not in poc_html, "POC 页不应出现绝对路径"
    # 漏洞页带任务名（而不是只有一个 #id）
    vulns_html = c.get("/vulns").get_data(as_text=True)
    assert db.get_task(tid)["name"] in vulns_html, "漏洞页应显示任务名"
    print("[5c] 分流/标记/去重/相对路径 ok")

    # 5d) 第十四轮：注册域折算 + 相对路径显示 + 用户黑名单 + FOFA 证书反查 + 重叠隐藏 + 面板折叠
    from scanner import blacklist as blk
    from scanner.utils import base_domain, rel_display
    from gui.app import source_label

    # (1) 注册域折算（证书反查按注册域查，能省 FOFA 配额；多段后缀必须整段保留）
    assert base_domain("a.b.example.com") == "example.com"
    assert base_domain("example.com") == "example.com"
    assert base_domain("www.example.com.cn") == "example.com.cn", base_domain("www.example.com.cn")
    assert base_domain("x.co.uk") == "x.co.uk"

    # (2) 相对路径显示（用户要求：所有展示绝对路径的地方都改成相对路径）
    assert rel_display(ROOT / "data" / "scanner.db") == "data/scanner.db"
    assert rel_display("") == ""
    outside = "/tmp/ctfscanner-outside/elsewhere.txt"     # 项目外路径原样返回，不做臆造
    assert rel_display(outside) == outside

    # (3) 用户黑名单：命中即**整条丢弃**（含所有子域）；写临时文件，绝不碰 config/blacklist.txt
    bl_file = Path(_TMPDIR) / "blacklist.txt"
    bl_settings = copy.deepcopy(settings)
    bl_settings["blacklist"] = {"enabled": True, "path": str(bl_file)}
    assert blk.load(bl_settings) == []
    assert blk.add(["Evil.example.com", "*.Tracker.test", "evil.example.com"], bl_settings) == 2
    entries = blk.load(bl_settings)
    assert entries == ["evil.example.com", "tracker.test"], entries
    assert blk.matches("a.evil.example.com", entries) == "evil.example.com"
    assert blk.matches("sub.tracker.test", entries) == "tracker.test"
    assert blk.matches("example.com", entries) == ""
    kept, blocked = blk.filter_pairs([("ok.test", "subfinder"),
                                      ("x.evil.example.com", "osint:cseg")], bl_settings)
    assert kept == [("ok.test", "subfinder")], kept
    assert blocked == [("x.evil.example.com", "evil.example.com")], blocked
    assert blk.filter_domains(["ok.test", "y.tracker.test"], bl_settings) == (["ok.test"], 1)
    assert blk.remove(["evil.example.com"], bl_settings) == 1
    assert blk.load(bl_settings) == ["tracker.test"]
    off_bl = copy.deepcopy(bl_settings)      # 关掉开关＝整份名单临时失效（文件内容不动）
    off_bl["blacklist"]["enabled"] = False
    assert blk.load(off_bl) == [] and blk.filter_domains(["y.tracker.test"], off_bl)[1] == 0
    assert blk.load(bl_settings) == ["tracker.test"], "开关关闭不该改动文件"
    # 回归：手工编辑过的名单**末尾常常没有换行**，直接 append 会把新条目粘到最后一条上
    # （实测 `example.com` + `a.test` → `example.coma.test`，原条目丢失且黑名单静默失效）
    bl_file.write_text("# 手写\nhand.test", encoding="utf-8")      # 故意不给末尾换行
    assert blk.add(["appended.test"], bl_settings) == 1
    assert blk.load(bl_settings) == ["hand.test", "appended.test"], blk.load(bl_settings)

    # (4) 证书查询语句与"通用证书"阈值
    assert fofa.build_cert_query("orderfood.top") == 'cert="orderfood.top"'
    assert fofa.build_cert_query("orderfood.top.") == 'cert="orderfood.top"'
    assert fofa.is_common_cert(200, settings) is False and fofa.is_common_cert(201, settings) is True
    assert fofa.search_cert("", settings)[2], "空域名应显式报错"

    # (5) 来源可读标签：FOFA 找出来的资产必须一眼能认出来
    assert source_label("subfinder") == "被动(subfinder)"
    assert source_label("passive:crt.sh") == "被动(crt.sh)"
    assert source_label("osint:cseg") == "C 段反查"
    assert source_label("osint:fofa") == "FOFA·ICO 反查"
    assert source_label("osint:fofa-cert") == "FOFA·证书反查"
    assert source_label("") == "-"

    # (6) 重叠资产默认隐藏：拓展域名按**域名级全局**判重，`?all=1` 才显示
    db.insert_subdomains(tid, [("overlap-smoke.example.com", "js:mine"),
                               ("overlap-smoke.example.com", "subfinder"),
                               ("pure-ext-smoke.example.com", "osint:fofa-cert")])
    ext_default = c.get("/extdomains").get_data(as_text=True)
    assert "pure-ext-smoke.example.com" in ext_default and "FOFA·证书反查" in ext_default
    assert "overlap-smoke.example.com" not in ext_default, "与自身子域名重叠的拓展域名应默认隐藏"
    assert "显示全部（含重叠）" in ext_default, "拓展域名页应有重叠开关"
    assert "overlap-smoke.example.com" in c.get("/extdomains?all=1").get_data(as_text=True)
    assert "overlap-smoke.example.com" in c.get("/subdomains").get_data(as_text=True)

    # (7) 站点重叠：同一 URL 跨任务只留**最新**那条（`MAX(id)`），`?all=1` 一起放开。
    #     必须留最新的：站点行带的是当次扫描的 status/title/length/tech，留最旧那条等于
    #     默认视图一直展示陈旧数据（重扫的目的正是刷新这些字段）。
    ov_title = f"OVERLAP-{tid}"
    ov_new_title = f"OVERLAP-NEW-{tid}"
    ov_url = "http://overlap-smoke.test/"
    ov_row = {"url": ov_url, "host": "overlap-smoke.test", "port": "80", "status": 200,
              "title": ov_title, "length": 999, "source": "builtin"}
    db.insert_sites(tid, [dict(ov_row)])                            # 较早的任务
    db.insert_sites(tid_gate, [dict(ov_row, title=ov_new_title, status=404)])   # 较晚的任务
    sites_default = c.get("/sites").get_data(as_text=True)
    assert sites_default.count(ov_title) == 0, "默认视图不应再显示旧任务的同名站点"
    assert sites_default.count(ov_new_title) == 1, sites_default.count(ov_new_title)
    assert "显示全部（含重叠）" in sites_default
    sites_all = c.get("/sites?all=1").get_data(as_text=True)
    assert sites_all.count(ov_title) == 1 and sites_all.count(ov_new_title) == 1, "放开后两条都在"

    # (8) 黑名单批量加入接口：改成桩函数，避免往真实 config/blacklist.txt 里写测试域名
    picked = []

    def _fake_bl_add(domains, st=None):
        picked.extend(domains)
        return len(domains)

    _orig_bl_add = gui_app.blacklist.add
    try:
        gui_app.blacklist.add = _fake_bl_add
        r = c.post("/api/blacklist/add", data={"domain": ["a.smoke.test", "a.smoke.test",
                                                          "b.smoke.test"],
                                               "next": "/subdomains"})
        assert r.status_code == 302, r.status_code
        assert picked == ["a.smoke.test", "b.smoke.test"], picked   # 去重保序
        assert r.headers["Location"].endswith("/subdomains"), r.headers["Location"]
    finally:
        gui_app.blacklist.add = _orig_bl_add

    # (9) 批量跑子域名接口：新建任务 + 只含 subdomain 阶段。
    #     run_task 换桩：真跑会去打 crt.sh 之类的公共接口（测试必须离线且不依赖外网）。
    _orig_run_task = gui_app.run_task
    try:
        gui_app.run_task = lambda *a, **kw: None
        r = c.post("/api/domains/run-subdomain",
                   data={"domain": ["sub1.smoke.test", "sub1.smoke.test", "sub2.smoke.test"]})
        assert r.status_code == 302, r.status_code
        new_id = int(r.headers["Location"].rstrip("/").rsplit("/", 1)[-1])
        t = db.get_task(new_id)
        assert t and t["stages"] == "subdomain", t and t["stages"]
        assert t["targets"] == "sub1.smoke.test\nsub2.smoke.test", t["targets"]
        assert t["name"].startswith("批量子域-"), t["name"]
    finally:
        gui_app.run_task = _orig_run_task

    # (10) 策略配置页：证书反查字段 / 黑名单开关 / 可折叠面板都要真的渲染出来，
    #      且整个页面不出现本机绝对路径
    st_html = c.get("/settings").get_data(as_text=True)
    for name in ("fofa_cert_enabled", "fofa_cert_threshold", "fofa_max_cert_queries",
                 "blacklist_enabled"):
        assert f'name="{name}"' in st_html, f"策略配置缺 {name}"
    assert "panel collapsible" in st_html and 'data-panels="expand"' in st_html
    assert str(ROOT) not in st_html, "策略配置页不应出现绝对路径"
    assert str(ROOT) not in detail_html, "任务详情页不应出现绝对路径"
    assert str(LOGS_DIR) not in detail_html, "任务详情页的日志文件路径应已相对化"
    assert "logs/smoke-" in detail_html, "任务详情页应显示相对日志路径（logs/...）"

    # (11) 策略配置 POST → 配置字典的映射（桩函数，不改真实 settings.yaml）
    captured2 = {}

    def _fake_save2(d):
        captured2.clear()
        captured2.update(d)
        return load_settings()

    _orig_save2 = gui_app.save_settings
    gui_app.save_settings = _fake_save2
    try:
        assert c.post("/settings", data={"min_severity": "medium", "fofa_cert_enabled": "1",
                                         "fofa_cert_threshold": "123",
                                         "fofa_max_cert_queries": "7",
                                         "blacklist_enabled": "1"}).status_code == 302
        assert captured2["fofa"]["cert_enabled"] is True, captured2.get("fofa")
        assert captured2["fofa"]["cert_threshold"] == 123, captured2.get("fofa")
        assert captured2["fofa"]["max_cert_queries"] == 7, captured2.get("fofa")
        assert captured2["blacklist"]["enabled"] is True, captured2.get("blacklist")
        # 未勾选 → 必须落为关闭（而不是保持旧值）
        assert c.post("/settings", data={"min_severity": "medium"}).status_code == 302
        assert captured2["fofa"]["cert_enabled"] is False, captured2.get("fofa")
        assert captured2["blacklist"]["enabled"] is False, captured2.get("blacklist")
        assert captured2["blacklist"]["path"] == (settings.get("blacklist") or {}).get("path")
    finally:
        gui_app.save_settings = _orig_save2
    print("[5d] 十四轮新增 ok: 注册域折算/相对路径/黑名单/证书反查/来源标签/重叠隐藏/面板折叠")

    # 5e) 第十五轮：全端口扫描 / FOFA 标题反查 / 目录扫描（大字典·重复长度·响应大小）/ JS 敏感字符
    from scanner import jsmine as jm
    from scanner import portscan as ps
    from scanner.stages.dirscan import DirscanStage, _size_to_int

    # (1) 端口：默认区间上限要挡住"手滑写成 1-65535"；全端口入口显式放开
    assert len(ps.parse_ports("1-65535")) == len(ps.TOP_PORTS), "默认上限应挡住全端口"
    full = ps.parse_ports("1-65535", max_span=65535)
    assert len(full) == 65535 and full[0] == 1 and full[-1] == 65535, len(full)
    assert ps.parse_ports("80,443,8080") == [80, 443, 8080]

    # (2) FOFA 标题反查：语句构造 + 公共标题阈值 + 模板页标题（连查询都不发）
    assert fofa.build_title_query("维保中心") == 'title="维保中心"'
    assert fofa.is_common_title(200, settings) is False
    assert fofa.is_common_title(201, settings) is True
    assert fofa.is_generic_title("404 Not Found") and fofa.is_generic_title("Welcome to nginx")
    assert not fofa.is_generic_title("维保中心后台管理系统")
    assert fofa.search_title("", settings)[2], "空标题应显式报错而不是发请求"
    assert source_label("osint:fofa-title") == "FOFA·标题反查"

    # (3) 目录扫描：dirmap 产出解析（重复长度文件不读）+ 大小换算 + 目标站点去重
    assert _size_to_int("1.23kb") == 1259 and _size_to_int("512.00b") == 512
    d_out = Path(_TMPDIR) / "output" / "host_test"
    d_out.mkdir(parents=True, exist_ok=True)
    (d_out / "res.txt").write_text(
        "[200][text/html][1.23kb] http://h/a\n[301][text/html][0b] http://h/b\n",
        encoding="utf-8")
    (d_out / "重复长度.txt").write_text("[200][text/html][1.23kb] http://h/c\n", encoding="utf-8")
    parsed = DirscanStage._parse_output(d_out / "res.txt")
    assert [p["status"] for p in parsed] == [200, 301] and parsed[0]["length"] == 1259, parsed
    assert DirscanStage._parse_output(d_out / "重复长度.txt") == [], "重复长度默认不展示"
    dup_sites = DirscanStage._dedup_sites([
        {"url": "http://a.test/", "title": "T", "length": 10},
        {"url": "http://b.test/", "title": "T", "length": 10},   # 同标题同长度 = 别名站，跳过
        {"url": "http://c.test/", "title": "X", "length": 10},
        {"url": "http://d.test/", "title": "", "length": 10},    # 无标题的不参与折叠
    ])
    assert [s["url"] for s in dup_sites] == ["http://a.test/", "http://c.test/",
                                             "http://d.test/"], dup_sites

    # (4) 目录结果：默认只显示第一条重复长度，页面带「大小」列，`?all=1` 放开
    db.insert_dirs(tid, [{"site_url": "http://dupdir.smoke.test/",
                          "path": f"http://dupdir.smoke.test/p{i}", "status": 200,
                          "length": 777, "method": "GET", "note": "builtin"} for i in range(3)])
    dirs_html = c.get("/dirs").get_data(as_text=True)
    assert "大小" in dirs_html, "目录页应有返回包大小列"
    assert dirs_html.count("777") == 1, dirs_html.count("777")
    assert "显示全部" in dirs_html
    assert c.get("/dirs?all=1").get_data(as_text=True).count("777") == 3

    # (4b) FOFA 资产行的域名收口：真实查询里大量行 `domain` 为空、只有 IP 形式的 host，
    #      裸 IP 绝不能当域名写进 subdomains 表（实测数据见 osint.py::_domain_of 注释）
    from scanner.stages.osint import _domain_of
    assert _domain_of({"domain": "www.BeimingCloud.com", "host": "https://x"}) == "www.beimingcloud.com"
    assert _domain_of({"domain": "", "host": "https://116.63.154.0"}) == "", "裸 IP 不是域名资产"
    assert _domain_of({"domain": "", "host": "47.117.144.116:1000"}) == ""
    assert _domain_of({"domain": "", "host": "https://www.beimingcloud.com"}) == "www.beimingcloud.com"
    assert _domain_of({"domain": "", "host": ""}) == "" and _domain_of({}) == ""

    # (5) JS 敏感字符：AKID / JWT / 私钥 等新规则要命中；占位值仍要被降噪掉
    hits = jm._find_secrets(
        'var a="AKIDa1b2c3d4e5f6a7b8"; var b="eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefgh";'
        'var c="-----BEGIN PRIVATE KEY-----"; var d={"api_key":"your_api_key_here"};',
        "http://x/a.js")
    types = {h["type"] for h in hits}
    assert {"tencent-access-key", "jwt", "private-key"} <= types, types
    assert not any("your_api_key" in h["value"] for h in hits), "占位值应被降噪"

    # (7) 目录扫描阶段级行为：**只对不重复站点扫描**（同任务内标题+长度相同的别名站跳过）。
    #     用真实跑一次 dirscan 来断言，而不是只测 _dedup_sites 这个纯函数 —— 纯函数对了但没接进
    #     阶段（例如忘了用返回值）是最容易漏的错。日志用一个记录型 logger 抓。
    class _Rec:
        def __init__(self):
            self.lines = []

        def _add(self, msg, *a):
            self.lines.append(str(msg))

        info = warning = debug = _add
        error = exception = _add

    rec = _Rec()
    ds_settings = copy.deepcopy(settings)
    ds_settings["dirscan"] = {"enabled": True, "big_dict": False, "max_paths": 3}
    ds_settings["tools"]["dirmap"]["script"] = "tools/does-not-exist.py"   # 强制走内置（离线、不发外部请求）
    site_a = {"url": targets, "host": "127.0.0.1", "title": "SAME", "length": 123}
    ds_tid = db.create_task("smoke-dirscan", targets, ["dirscan"], {"offline": True})
    ds_wd = Path(_TMPDIR) / f"dirscan_{ds_tid}"
    ds_wd.mkdir(parents=True, exist_ok=True)
    ds_ctx = StageContext(ds_tid, "smoke-dirscan", parse_lines([targets]), ["dirscan"],
                          {"offline": True}, ds_settings, ds_wd, rec)
    ds_ctx.results["sites"] = [dict(site_a), dict(site_a),                      # 两条重复（别名站）
                               {"url": targets, "host": "127.0.0.1",
                                "title": "OTHER", "length": 999}]               # 一条不同
    PipelineRunner(ds_ctx).run()
    scan_line = [l for l in rec.lines if "内置扫描：" in l]
    assert scan_line and "2 站点" in scan_line[0], scan_line
    assert "3 站点" not in (scan_line[0] if scan_line else ""), scan_line

    # (6) 全端口扫描：新侧栏页 + 发起接口（run_task 用桩，真跑会去连 6.5 万个端口）
    fp_html = c.get("/fullports").get_data(as_text=True)
    assert 'href="/fullports"' in fp_html and "发起全端口扫描" in fp_html
    _orig_run3 = gui_app.run_task
    try:
        gui_app.run_task = lambda *a, **kw: None
        r = c.post("/api/ports/full-scan", data={"host": ["1.2.3.4", "1.2.3.4"]})
        assert r.status_code == 302, r.status_code
        new_id = int(r.headers["Location"].rstrip("/").rsplit("/", 1)[-1])
        t = db.get_task(new_id)
        assert t["stages"] == "portscan" and t["targets"] == "1.2.3.4", t
        assert '"portscan_full": true' in (t["options"] or ""), t["options"]
    finally:
        gui_app.run_task = _orig_run3
    print("[5e] 十五轮新增 ok: 全端口/标题反查/目录(大字典·重复长度·大小)/JS敏感字符")
    print("SMOKE PASS")


if __name__ == "__main__":
    main()
