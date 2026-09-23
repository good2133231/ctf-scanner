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

    # 1b) 流水线阶段注册：全部阶段都在顺序表与注册表中；
    # intel / heuristic（P3-2/P3-3）固定排在**最后**且默认关，只写 leads 表
    assert STAGE_ORDER == ["subdomain", "takeover", "portscan", "probe",
                           "screenshot", "osint", "jsmine", "dirscan", "vulnscan",
                           "intel", "heuristic"], STAGE_ORDER
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
    # 侧边栏精简：端口服务 / C 段视野 / 目录发现 / **拓展域名** 都已从导航移除
    # （路由全部保留、任务详情页签仍在用；拓展域名改到任务详情页签，用户 2026-09-22 要求）
    nav_html = c.get("/subdomains").get_data(as_text=True)
    for gone in ('href="/ports"', 'href="/csegs"', 'href="/dirs"', 'href="/extdomains"'):
        assert gone not in nav_html, f"侧边栏应已移除 {gone}"
    # 拓展域名改到任务详情页签：页签 + 面板都要在
    ext_detail = c.get(f"/tasks/{tid}").get_data(as_text=True)
    assert 'data-tab="ext"' in ext_detail and 'id="pane-ext"' in ext_detail, "任务详情缺「拓展域名」页签"
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

    # (6b) 拓展域名**按来源分类排序 + 分类标签**（用户要求不要把 JS / FOFA 标题 / 证书混在一起）
    db.insert_subdomains(tid, [("src-title.example.com", "osint:fofa-title")])
    ext_all = c.get("/extdomains?all=1").get_data(as_text=True)
    for label in ("JS 挖掘", "FOFA·标题反查", "FOFA·证书反查", "FOFA·ICO 反查", "C 段反查"):
        assert label in ext_all, f"拓展域名页缺来源分类标签 {label}"
    # 表内顺序 = js:mine → osint:fofa-title → osint:fofa-cert → osint:cseg
    pos_js = ext_all.index("js-smoke.example.com")
    pos_title = ext_all.index("src-title.example.com")
    pos_cert = ext_all.index("pure-ext-smoke.example.com")
    pos_cseg = ext_all.index("osint-smoke.example.com")
    assert pos_js < pos_title < pos_cert < pos_cseg, \
        f"拓展域名应按来源分类排序，(js,title,cert,cseg)=({pos_js},{pos_title},{pos_cert},{pos_cseg})"
    # `?src=` 只显示该来源一类，并把它翻译成批量扫描的默认任务名前缀
    ext_title = c.get("/extdomains?all=1&src=title").get_data(as_text=True)
    assert "src-title.example.com" in ext_title and "js-smoke.example.com" not in ext_title
    assert 'value="fofa标题拓展"' in ext_title, "批量扫描应带上按来源生成的默认任务名前缀"
    assert "src-title.example.com" not in c.get("/extdomains?all=1&src=js").get_data(as_text=True)

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

    # (1b) 续8：外部工具端口扫描接入 —— fscan 适配器（强制 -np -nobr）+ nmap/fscan 命令行压缩。
    # 命令行**长度**是硬约束：65535 个端口逐个数逗号拼出来约 38 万字符，Windows CreateProcess
    # 上限 32767，会直接 OSError 起不来（原 nmap 路径就踩了这个坑，全端口时静默回退内置）。
    assert ps.format_ports([80, 443, 8000, 8001, 8002, 8080]) == "80,443,8000-8002,8080"
    assert ps.format_ports(range(1, 65536)) == "1-65535"
    assert ps.format_ports([]) == ""
    assert set(ps._fscan_flags()) >= {"-np", "-nobr", "-nopoc"}
    assert set(ps._fscan_flags(with_nopoc=False)) >= {"-np", "-nobr"}, \
        "老版本回退路径也必须保留 -np -nobr（非破坏性红线）"

    _ps_calls = []
    _orig_run_cmd = ps.run_cmd

    def _stub_run(*a, **k):
        _ps_calls.append([str(x) for x in (a[0] if a else k.get("argv"))])
        return _stub_run.reply.pop(0)

    _stub_run.reply = []
    ps.run_cmd = _stub_run
    try:
        # fscan 输出带 ANSI 颜色码，必须剥掉才能解析；`[*]` 的 POC 行**故意不认**
        _stub_run.reply = [(0, "[+] \x1b[32m10.0.0.1:80\x1b[0m open\n"
                              "[+] 10.0.0.1:8080 open\n"
                              "[*] 10.0.0.1:80 weblogic-poc\n"
                              "[+] 10.0.0.1:8080 open\n", "")]
        got = ps.fscan_scan("h.test", "10.0.0.1", [80, 8080], binary="fscan")
        assert [r["port"] for r in got] == [80, 8080], got
        assert got[0]["service"] == "http" and got[1]["service"] == "http-alt"
        assert got[0]["host"] == "h.test" and got[0]["ip"] == "10.0.0.1"
        cmd = _ps_calls[-1]
        assert {"-np", "-nobr", "-nopoc"} <= set(cmd), cmd
        assert cmd[cmd.index("-h") + 1] == "10.0.0.1" and cmd[cmd.index("-p") + 1] == "80,8080"
        assert cmd[cmd.index("-t") + 1] == "512", cmd   # workers 缺省 64 × 8
        # 老版本不认 -nopoc：去掉它重试一次，-np -nobr 必须还在
        _before = len(_ps_calls)
        _stub_run.reply = [(1, "", "flag provided but not defined: -nopoc"),
                           (0, "[+] 10.0.0.1:443 open\n", "")]
        got = ps.fscan_scan("h.test", "10.0.0.1", [443], binary="fscan")
        assert [r["port"] for r in got] == [443]
        assert len(_ps_calls) - _before == 2, _ps_calls[_before:]
        assert "-nopoc" not in _ps_calls[-1] and {"-np", "-nobr"} <= set(_ps_calls[-1])
        # rc≠0 且不是参数问题 → 返回 None，交给上层回退 nmap/内置
        _stub_run.reply = [(1, "", "boom")]
        assert ps.fscan_scan("h.test", "10.0.0.1", [80], binary="fscan") is None
        # 认不出任何 open 行 → 空结果（宁缺勿错，不拿 [*] POC 行当开放端口）
        _stub_run.reply = [(0, "[*] 10.0.0.1:80 weblogic-poc\n", "")]
        assert ps.fscan_scan("h.test", "10.0.0.1", [80], binary="fscan") == []

        # nmap 同样要走压缩后的端口串（否则全端口在 Windows 上起不来）
        _stub_run.reply = [(0, "Host: 10.0.0.1 ()\tPorts: 80/open/tcp//http///\n", "")]
        nm = ps.nmap_scan("h.test", "10.0.0.1", list(range(1, 65536)), binary="nmap")
        assert nm and nm[0]["port"] == 80, nm
        nm_cmd = _ps_calls[-1]
        assert nm_cmd[nm_cmd.index("-p") + 1] == "1-65535", "nmap 端口参数也要压缩"
        assert sum(len(x) for x in nm_cmd) < 1000, "命令行不该被 65535 个端口撑爆"
    finally:
        ps.run_cmd = _orig_run_cmd

    # 引擎选择：钉住不存在的引擎 → 日志明说并回退内置（不允许空跑）
    from scanner.stages import portscan as _ps_stage
    _rec = []

    class _Rec2:
        info = warning = debug = staticmethod(lambda m, *a: _rec.append(str(m)))
        error = exception = staticmethod(lambda m, *a: _rec.append(str(m)))

    _eng_settings = copy.deepcopy(settings)
    _eng_settings["portscan"] = {"enabled": True, "max_hosts": 5, "ports": "80",
                                 "engine": "fscan", "banner": False}
    _eng_calls = []
    _orig_host = _ps_stage.portscan.scan_host
    _orig_fs = _ps_stage.portscan.fscan_scan
    _orig_nm = _ps_stage.portscan.nmap_scan
    _orig_which = _ps_stage.which
    _ps_stage.portscan.scan_host = lambda *a, **k: (_eng_calls.append("builtin") or [])
    _ps_stage.portscan.fscan_scan = lambda *a, **k: _eng_calls.append("fscan")
    _ps_stage.portscan.nmap_scan = lambda *a, **k: _eng_calls.append("nmap")
    _ps_stage.which = lambda name: None          # 假装啥都没装
    try:
        _eng_tid = db.create_task("smoke-eng", "10.1.1.1", ["portscan"], {})
        _eng_ctx = StageContext(_eng_tid, "smoke-eng", parse_lines(["10.1.1.1"]),
                                ["portscan"], {}, _eng_settings,
                                Path(_TMPDIR) / "eng", _Rec2())
        _ps_stage.PortscanStage(_eng_ctx).run()
        assert _eng_calls and set(_eng_calls) == {"builtin"}, _eng_calls
        assert any("指定引擎 fscan 不可用" in x for x in _rec), _rec
    finally:
        _ps_stage.portscan.scan_host = _orig_host
        _ps_stage.portscan.fscan_scan = _orig_fs
        _ps_stage.portscan.nmap_scan = _orig_nm
        _ps_stage.which = _orig_which
    print("[5e-0] fscan/nmap 适配 ok: 端口串压缩为 1-65535（命令行 <1000 字符）；"
          "fscan 强制 -np -nobr -nopoc（老版本回退仍保留 -np -nobr）")

    # (2) FOFA 标题反查：语句构造 + 公共标题阈值 + 模板页标题（连查询都不发）
    assert fofa.build_title_query("维保中心") == 'title="维保中心"'
    assert fofa.is_common_title(200, settings) is False
    assert fofa.is_common_title(201, settings) is True
    assert fofa.is_generic_title("404 Not Found") and fofa.is_generic_title("Welcome to nginx")
    assert not fofa.is_generic_title("维保中心后台管理系统")
    # 续8：按 2026-09-23 实测样本校准 —— 公共标题前移到"零请求预筛"（前缀层）
    assert fofa.is_generic_title("后台管理系统"), "实测 192188 条，应零请求跳过"
    assert fofa.is_generic_title("后台管理系统 - 登录"), "前缀变体同样是公共模板页"
    assert fofa.is_generic_title("Index of /uploads"), "Apache 目录列表页的各种子路径"
    assert fofa.is_generic_title("  INDEX OF /Uploads  "), "大小写与前后空白都应先归一化"
    assert not fofa.is_generic_title("维保中心"), "具体站点标题（实测仅 15 条）必须照查"
    assert not fofa.is_generic_title("维保中心 - 后台管理系统"), "前缀不同就不该误杀"
    assert fofa.is_generic_cert("example.com") and fofa.is_generic_cert("www.example.com")
    assert fofa.is_generic_cert("localhost") and fofa.is_generic_cert("")
    assert fofa.is_generic_cert("acme-corp.cn") is False
    assert fofa.is_generic_cert("example.test") is False, "保留后缀不在黑名单里（免得误伤自测）"
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

    # (9) dirmap 产物定位：按目标 netloc 找 `output/<host>_<port>/`（重扫时 dirmap 会跟旧文件
    #     去重、不写新内容，mtime 过滤会漏；实测"跑了 37 秒却解析 0 条"就是这个问题）
    d_root = Path(_TMPDIR) / "dirmap_out"
    (d_root / "127.0.0.1_8765").mkdir(parents=True, exist_ok=True)
    (d_root / "other.test").mkdir(parents=True, exist_ok=True)
    (d_root / "127.0.0.1_8765" / "res.txt").write_text(
        "[200][text/html][1.00kb] http://127.0.0.1:8765/admin\n", encoding="utf-8")
    (d_root / "other.test" / "res.txt").write_text(
        "[200][text/html][3.00kb] http://other.test/x\n", encoding="utf-8")
    picked = DirscanStage._target_dirs(d_root, {"127.0.0.1:8765"})
    assert [d.name for d in picked] == ["127.0.0.1_8765"], picked
    assert DirscanStage._target_dirs(d_root, {"nope.test"}) == []

    # (8) osint 阶段级：把 FOFA 查询换成桩（离线、不触网），验证标题/证书反查**真的把结果入库**。
    #     这一层必须测：曾经 `_site_titles()` 把 `sqlite3.Row` 当 dict 用（`r.get("title")`），
    #     整个 osint 阶段每次都抛 AttributeError 被阶段级容错吞掉 —— 表现是"标题反查永远 0 条"，
    #     而纯函数测试完全看不出来（真实跑一次才发现）。
    from scanner.stages import osint as osint_stage
    os_calls = []

    def _stub_title(title, settings, logger=None, size=None):
        os_calls.append(("title", title))
        return ([{"host": "https://x.test", "domain": "x.test", "ip": "1.2.3.4",
                  "port": "443", "title": title}], 15, "")

    def _stub_cert(domain, settings, logger=None, size=None):
        os_calls.append(("cert", domain))
        return ([{"host": "https://y.test", "domain": "y.test", "ip": "1.2.3.5",
                  "port": "443", "title": ""}], 20, "")

    _orig_title, _orig_cert = osint_stage.fofa_mod.search_title, osint_stage.fofa_mod.search_cert
    osint_stage.fofa_mod.search_title, osint_stage.fofa_mod.search_cert = _stub_title, _stub_cert
    try:
        os_settings = copy.deepcopy(settings)
        os_settings["iprecon"]["enabled"] = False
        os_settings["fofa"].update({"enabled": True, "cert_enabled": True,
                                    "title_enabled": True, "max_title_queries": 2,
                                    "max_cert_queries": 2})
        os_settings["keys"] = {"fofa": {"email": "stub@example.test", "key": "stub"}}
        os_tid = db.create_task("smoke-osint", targets, ["osint"], {"offline": True})
        db.insert_sites(os_tid, [{"url": targets, "host": "127.0.0.1", "port": "80",
                                  "status": 200, "title": "维保中心", "length": 100,
                                  "source": "builtin"}])
        db.insert_subdomains(os_tid, [("www.example.test", "subfinder")])  # 给证书反查一个注册域
        run_task(os_tid, "smoke-osint", targets, ["osint"], {"offline": True}, os_settings)
        got = {(r["domain"], r["source"]) for r in db.list_subdomains(os_tid)}
        assert ("x.test", "osint:fofa-title") in got, got
        assert ("y.test", "osint:fofa-cert") in got, got
        assert ("title", "维保中心") in os_calls, os_calls
        assert ("cert", "example.test") in os_calls, os_calls
    finally:
        osint_stage.fofa_mod.search_title = _orig_title
        osint_stage.fofa_mod.search_cert = _orig_cert

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

    # 5f) 第十七轮：子域名收集"主动且全" —— subfinder(-all) 与内置被动源**取并集**。
    #     原实现是 elif：装了 subfinder 就完全不跑内置源（白丢 crt.sh/alienvault 这批证书情报源）。
    #     这里把 subfinder 与被动源都换成桩，验证"两边都被调用"且 argv 里带 -all。
    from scanner.stages import subdomain as sub_stage
    calls = {"subfinder": [], "passive": []}

    def _fake_which(name):
        # 相对形式的假二进制路径：run_cmd 也被桩掉，这里只是"有个非空路径"而已；
        # 刻意不写盘符（[5o] 的跨平台审计会拒绝源码里出现写死的盘符路径）。
        return "fake-bin/subfinder" if name == "subfinder" else None

    def _fake_run_cmd(argv, cwd=None, timeout=None):
        calls["subfinder"].append(list(argv))
        return 0, "", ""

    def _fake_collect(domain, settings, logger=None, workers=6):
        calls["passive"].append(domain)
        return {f"passive-only.{domain}": "passive:stub"}

    _orig = (sub_stage.which, sub_stage.verify_tool, sub_stage.run_cmd,
             sub_stage.passive.collect)
    sub_stage.which, sub_stage.verify_tool, sub_stage.run_cmd = _fake_which, lambda b: True, _fake_run_cmd
    sub_stage.passive.collect = _fake_collect
    tid_union = None
    try:
        for union, want_passive in ((True, True), (False, False)):
            calls["subfinder"].clear(), calls["passive"].clear()
            su_settings = copy.deepcopy(settings)
            su_settings["subdomain"] = {"union_passive": union, "max_resolve": 0}
            su_settings["limits"] = dict(su_settings.get("limits") or {}, wildcard_filter=False)
            su_settings["dicts"]["subdomains"] = "config/dicts/does-not-exist.txt"  # 跳过爆破
            su_tid = db.create_task(f"smoke-subs-{union}", "example.test", ["subdomain"], {})
            su_wd = Path(_TMPDIR) / f"subs_{union}"
            su_wd.mkdir(parents=True, exist_ok=True)
            su_ctx = StageContext(su_tid, "smoke-subs", parse_lines(["example.test"]),
                                  ["subdomain"], {}, su_settings, su_wd, rec)
            PipelineRunner(su_ctx).run()
            assert calls["subfinder"], "subfinder 未被调用"
            assert "-all" in calls["subfinder"][0], calls["subfinder"][0]
            assert bool(calls["passive"]) is want_passive, (union, calls["passive"])
            if union:
                tid_union = su_tid
        # 并集那一轮：内置被动源的产出必须真的落库（source=passive:stub）
        assert ("passive-only.example.test", "passive:stub") in {
            (r["domain"], r["source"]) for r in db.list_subdomains(tid_union)}, "被动源结果应入库"
    finally:
        (sub_stage.which, sub_stage.verify_tool, sub_stage.run_cmd,
         sub_stage.passive.collect) = _orig
    print("[5f] 子域名并集 ok: subfinder 带 -all 且与内置被动源取并集（union_passive 可关）")

    # 5g) 第十七轮(2)：目录字典按技术栈拆分 + 运行时按栈选字典
    #     用户要求"确定是 java 就不要用 php asp" —— 一个站只可能是一种栈，
    #     把三种语言后缀全打一遍纯属浪费 max_paths 额度。
    from scanner.stages.dirscan import _dict_kind
    assert _dict_kind("tomcat", "http://a/") == "jsp"
    assert _dict_kind("jetty", "http://a/") == "jsp"
    assert _dict_kind("php", "http://a/") == "php"
    assert _dict_kind("wordpress,nginx", "http://a/") == "php"
    assert _dict_kind("aspnet", "http://a/") == "asp"
    assert _dict_kind("iis", "http://a/") == "asp"
    assert _dict_kind("nginx", "http://a/") == "", "判不出就该返回空（走全量字典），不能瞎猜"
    assert _dict_kind("", "http://a/index.php") == "php", "URL 后缀是最直接的判据"
    assert _dict_kind("", "http://a/login.do") == "jsp"
    assert _dict_kind("", "http://a/x.aspx?y=1") == "asp"

    # 拆出来的字典文件必须存在且非空（由 tools/import_dir_dict.py 生成）
    dict_dir = ROOT / "config" / "dicts"
    counts = {}
    for key in ("dirs_common", "dirs_jsp", "dirs_php", "dirs_asp", "dirs_big"):
        items = [x for x in (dict_dir / f"{key}.txt").read_text(
            encoding="utf-8").splitlines() if x and not x.startswith("#")]
        counts[key] = len(items)
        assert items, f"{key}.txt 为空（跑 tools/import_dir_dict.py 生成）"
    assert counts["dirs_php"] and counts["dirs_jsp"] and counts["dirs_asp"], counts

    # 语言字典必须排在通用字典**前面**：max_paths 截断时先保语言专属路径
    dstage = DirscanStage(StageContext(tid, "smoke-dicts", parse_lines([targets]),
                                       ["dirscan"], {}, settings,
                                       Path(_TMPDIR) / "dicts", rec))
    jsp_paths = dstage._load_paths("jsp", {"max_paths": 50})
    php_paths = dstage._load_paths("php", {"max_paths": 50})
    jsp_set = {x for x in (dict_dir / "dirs_jsp.txt").read_text(
        encoding="utf-8").splitlines() if x and not x.startswith("#")}
    assert len(jsp_paths) == 50 and jsp_paths[0] in jsp_set, jsp_paths[:3]
    assert set(jsp_paths[:40]) != set(php_paths[:40]), "两种栈不该拿到同一批前缀"
    assert len(dstage._load_paths("", {"max_paths": 50, "big_dict": True})) == 50
    print(f"[5g] 字典按栈拆分 ok: common/jsp/php/asp = "
          f"{counts['dirs_common']}/{counts['dirs_jsp']}/{counts['dirs_php']}/{counts['dirs_asp']}"
          f"（全量 {counts['dirs_big']}）；Java 站只吃 jsp+common")

    # 5g-2) 续8：字典再按**框架**细分（tools/import_fw_dicts.py 派生，运行时排最前）
    import importlib.util
    import scanner.stages.dirscan as _ds_mod
    from scanner.stages.dirscan import (FRAMEWORK_ORDER, FRAMEWORK_TAGS, _framework_of,
                                        _FULL_LAYERS, _FW_LAYERS)
    _spec = importlib.util.spec_from_file_location(
        "_fw_dicts", ROOT / "tools" / "import_fw_dicts.py")
    _fwgen = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_fwgen)
    assert _framework_of("wordpress,nginx", "http://a/") == "wordpress"
    assert _framework_of("springboot", "http://a/") == "spring", "同义词要归到同一个桶"
    assert _framework_of("elasticsearch", "http://a/") == "elastic"
    assert _framework_of("apache,nginx", "http://a/wp-admin/") == "wordpress", "URL 兜底判据"
    assert _framework_of("apache,nginx", "http://a/actuator/env") == "spring"
    assert _framework_of("apache,nginx", "http://a/env") == "", "判不出就返回空，不能瞎猜"
    # 多命中时取 FRAMEWORK_ORDER 里最靠前的（顺序即优先级）
    assert _framework_of("jenkins,wordpress", "http://a/") == "wordpress"
    # 桶名 ↔ 生成器的 BUCKETS 必须一一对应（少一个键 = 运行时取不到文件）
    fw_counts = {}
    for name in FRAMEWORK_ORDER:
        items = [x for x in (dict_dir / f"dirs_{name}.txt").read_text(
            encoding="utf-8").splitlines() if x and not x.startswith("#")]
        fw_counts[name] = len(items)
        assert items, f"dirs_{name}.txt 为空（跑 tools/import_fw_dicts.py --force 生成）"
    assert set(FRAMEWORK_TAGS.values()) == set(FRAMEWORK_ORDER), FRAMEWORK_TAGS
    assert set(_fwgen.BUCKETS) == set(FRAMEWORK_ORDER) | {"exposure"}, (
        f"dirscan.FRAMEWORK_ORDER 与 tools/import_fw_dicts.py 的 BUCKETS 已经对不上了："
        f"{set(_fwgen.BUCKETS) ^ (set(FRAMEWORK_ORDER) | {'exposure'})}")
    assert tuple(_fwgen.BUCKETS)[:-1] == FRAMEWORK_ORDER, (
        "生成器的桶顺序（= 正则优先级）应与 FRAMEWORK_ORDER 一致")
    exposure = [x for x in (dict_dir / "dirs_exposure.txt").read_text(
        encoding="utf-8").splitlines() if x and not x.startswith("#")]
    assert exposure, "dirs_exposure.txt 为空"
    assert any(x in exposure for x in (".git/config", ".env")), "暴露面字典缺高价值条目"

    # 框架字典必须排在**语言字典之前**（max_paths 截断时先保框架特征路径）
    wp_paths = dstage._load_paths("php", {"max_paths": 50}, fw="wordpress")
    wp_set = set(x for x in (dict_dir / "dirs_wordpress.txt").read_text(
        encoding="utf-8").splitlines() if x and not x.startswith("#"))
    assert len(wp_paths) == 50 and wp_paths[0] in wp_set, wp_paths[:3]
    assert wp_paths != php_paths, "同一站点给了框架就该拿到不同的字典前缀"
    # 保序去重：框架字典是从全量字典抽的，跨文件必然有重复条目，额度不能被重复项吃掉
    assert len(set(wp_paths)) == len(wp_paths), "字典条目没去重"
    # 同一个框架桶在多个站点上要拿到**同一批**路径（字典是纯函数，不该受站点顺序影响）
    assert dstage._load_paths("php", {"max_paths": 50}, fw="wordpress") == wp_paths
    # 框架补充扫描只要 fw + exposure 两层，不吃语言/通用字典
    fw_only = dstage._load_paths("php", {"max_paths": 50}, fw="wordpress",
                                 layers=_FW_LAYERS, limit=30)
    assert len(fw_only) == 30 and fw_only[0] in wp_set, fw_only[:3]
    assert _FULL_LAYERS[:2] == ("fw", "lang") and "common" not in _FW_LAYERS
    # 只要框架层时，判不出框架就一条都取不到（`_builtin_scan(only_fw=True)` 靠这个
    # 跳过无框架的站点 —— dirmap 自带的 default.txt 已含 .git/.env，不必重复扫）
    assert dstage._load_paths("php", {"max_paths": 50}, fw="", layers=("fw",)) == []
    exp_only = dstage._load_paths("php", {"max_paths": 50}, fw="", layers=_FW_LAYERS)
    assert len(exp_only) == 50 and exp_only[0] in set(exposure), exp_only[:3]

    # fw_max_paths=0 → 框架补充扫描必须**连请求都不发**（不能只靠截断变成 1 条）
    sent = []
    orig_req = _ds_mod.http_request
    _ds_mod.http_request = lambda *a, **kw: (sent.append(a) or None)
    try:
        assert dstage._builtin_scan([{"url": "http://wp.example.com/", "tech": "wordpress"}],
                                    {"max_paths": 400, "fw_max_paths": 0, "tech_aware": True},
                                    {}, only_fw=True) == []
        assert not sent, "fw_max_paths=0 时不该发任何请求"
        # only_fw 还要跳过判不出框架的站点（省掉无意义请求）
        assert dstage._builtin_scan([{"url": "http://plain.example.com/", "tech": "nginx"}],
                                    {"max_paths": 400, "fw_max_paths": 150},
                                    {}, only_fw=True) == []
        assert not sent, "判不出框架的站点不该进补充扫描"
        # tech_aware=False（用户主动关掉按栈选字典）时补充扫描也不该瞎猜框架
        assert dstage._builtin_scan([{"url": "http://wp.example.com/", "tech": "wordpress"}],
                                    {"max_paths": 400, "fw_max_paths": 150,
                                     "tech_aware": False}, {}, only_fw=True) == []
        assert not sent
    finally:
        _ds_mod.http_request = orig_req
    print(f"[5g-2] 框架字典 ok: {'/'.join(f'{k}:{v}' for k, v in fw_counts.items())}"
          f" + exposure:{len(exposure)}；wordpress 站首选 {wp_paths[0]}")

    # 5h) 第十七轮(3)：GUI 侧栏/新页面/解析原因 + portscan 用真实 IP
    from gui.app import ip_note_label
    nav = c.get("/subdomains").get_data(as_text=True)
    assert 'href="/ips"' in nav, "侧栏缺「IP 资产」"
    assert 'href="/extdomains"' not in nav, "拓展域名不应再占侧栏"
    for path in ("/ips", "/ips?cdn=1", "/sites?plain=1"):
        r = c.get(path)
        assert r.status_code == 200, (path, r.status_code)
    assert 'id="theme-select"' in nav, "顶栏缺主题切换"
    assert "data-theme" in (ROOT / "gui" / "static" / "style.css").read_text(encoding="utf-8")
    plain_html = c.get("/sites?plain=1").get_data(as_text=True)
    assert "tbl-plain-sites" in plain_html and "纯净模式" in plain_html
    sites_html = c.get("/sites").get_data(as_text=True)
    assert 'target="_blank"' in sites_html and 'rel="noopener noreferrer"' in sites_html
    # 没有 IP 时要标出**具体原因**（用户要求）
    db.insert_subdomains(tid, [("noip-smoke.example.com", "subfinder")])
    db.set_subdomain_net(tid, {"noip-smoke.example.com": ("", "", "timeout")})
    assert "解析超时" in c.get("/subdomains").get_data(as_text=True), "无 IP 时应标出原因"
    assert ip_note_label("over-limit") == "超出回填上限(subdomain.max_resolve)"
    assert ip_note_label("") == ""
    # IP 页默认只显示非 CDN 的解析
    db.insert_subdomains(tid, [("ip-nocdn.example.com", "subfinder"),
                               ("ip-cdn.example.com", "subfinder")])
    db.set_subdomain_net(tid, {"ip-nocdn.example.com": ("9.9.9.9", "", ""),
                               "ip-cdn.example.com": ("8.8.8.8", "cloudflare", "")})
    only_nocdn = c.get("/ips").get_data(as_text=True)
    assert "9.9.9.9" in only_nocdn and "8.8.8.8" not in only_nocdn, "默认应只显示非 CDN 解析"
    with_cdn = c.get("/ips?cdn=1").get_data(as_text=True)
    assert "8.8.8.8" in with_cdn and "cloudflare" in with_cdn
    # portscan 对真实 IP 扫描：库里有解析结果就直接用；CDN 主机跳过
    from scanner.stages import portscan as ps_stage
    ps_calls = []

    def _fake_scan_host(host, ip, ports, timeout=1.0, workers=64, banner=True, stopped=None):
        ps_calls.append((host, ip, len(ports)))
        return []

    _orig_scan = ps_stage.portscan.scan_host
    ps_stage.portscan.scan_host = _fake_scan_host
    try:
        ps_settings = copy.deepcopy(settings)
        ps_settings["portscan"] = {"enabled": True, "max_hosts": 10, "ports": "80,443",
                                   "workers": 4, "timeout": 0.2, "banner": False}
        # 本机装了 nmap（实测 PATH 里有），会把内置 connect 顶掉 —— 这里显式指向不存在的
        # 二进制，保证测的是内置路径；"用真实 IP / 跳过 CDN" 的判定在选引擎之前，两条路共用。
        ps_settings["tools"] = dict(ps_settings.get("tools") or {}, nmap="nmap-does-not-exist")
        # 本机装了 nmap（实测 PATH 里有），会把内置 connect 顶掉 —— 这里显式指向不存在的
        # 二进制，保证测的是内置路径；"用真实 IP / 跳过 CDN" 的判定在选引擎之前，两条路共用。
        ps_settings["tools"] = dict(ps_settings.get("tools") or {}, nmap="nmap-does-not-exist")
        ps_tid = db.create_task("smoke-realip", "a.test", ["portscan"], {})
        db.insert_subdomains(ps_tid, [("real.example.com", "subfinder"),
                                      ("cdn.example.com", "subfinder")])
        db.set_subdomain_net(ps_tid, {"real.example.com": ("1.2.3.4", "", ""),
                                      "cdn.example.com": ("5.6.7.8", "cloudflare", "")})
        ps_ctx = StageContext(ps_tid, "smoke-realip", parse_lines(["real.example.com"]),
                              ["portscan"], {}, ps_settings, Path(_TMPDIR) / "ps", rec)
        ps_ctx.results["domains_for_probe"] = ["real.example.com", "cdn.example.com"]
        PipelineRunner(ps_ctx).run()
        used = {(h, ip) for h, ip, _n in ps_calls}
        assert ("real.example.com", "1.2.3.4") in used, used
        assert all(h != "cdn.example.com" for h, _ip, _n in ps_calls), "CDN 主机应跳过"
    finally:
        ps_stage.portscan.scan_host = _orig_scan
    print("[5h] GUI/IP 批次 ok: IP 资产页(默认非 CDN) + 解析原因 + 主题/纯净模式/超链接 + portscan 用真实 IP")

    # 5i) 第十七轮(4)：统一的"是不是域名"判断 + JS 第三方黑名单改为数据驱动（并入 URLFinder 名单）
    from scanner.utils import is_domain
    assert is_domain("www.example.com") and is_domain("example.com.cn") and is_domain("a.b.co")
    for not_domain in ("1.2.3.4", "2001:db8::1", "localhost", "foo", "*.example.com",
                       "http://x.com/a", "a b.com", "-bad.com", "a.b", ""):
        assert not is_domain(not_domain), not_domain
    # 黑名单文件：内置清单 + URLFinder jsFiler 合并后 267 条，两边都要在
    noise = jm._noise_set()
    assert len(noise) > 200, len(noise)
    assert "cnzz.com" in noise, "内置清单应保留"
    assert "adform.net" in noise, "URLFinder jsFiler 的域名应并入"
    assert jm._valid_host("index.php") is False, "JS 语境里 .php 是文件名不是域名"
    assert jm._valid_host("www.real-site.com") is True
    print(f"[5i] 域名判断/黑名单 ok: is_domain 形态判断 + 第三方名单 {len(noise)} 条（含 URLFinder jsFiler）")

    # 5j) 第十七轮(5)：站点截图（阶段注册 + 门控 + 路由与目录穿越防护 + 缩略图渲染）
    from scanner import screenshot as shot_mod
    from scanner.runner import STAGE_REGISTRY
    assert "screenshot" in STAGE_REGISTRY, "截图阶段未注册"
    assert STAGE_ORDER.index("screenshot") == STAGE_ORDER.index("probe") + 1, "截图应紧跟 probe"
    # 浏览器探测：指定不存在的路径必须判定为不可用（而不是拿去执行）
    assert shot_mod.browser_path({"screenshot": {"browser": "no-such-browser-xyz"}}) == ""
    # 关闭时不发任何截图（默认就是关的）
    shot_ctx = StageContext(tid, "smoke-shot", parse_lines([targets]), ["screenshot"], {},
                            settings, Path(_TMPDIR) / "shot", rec)
    PipelineRunner(shot_ctx).run()
    assert any("未启用" in x for x in rec.lines if "[screenshot]" in x), rec.lines[-3:]
    # 开了但浏览器不可用 → 只告警跳过（不能抛）
    shot_settings = copy.deepcopy(settings)
    shot_settings["screenshot"] = {"enabled": True, "browser": "no-such-browser-xyz"}
    shot_ctx2 = StageContext(tid, "smoke-shot2", parse_lines([targets]), ["screenshot"], {},
                             shot_settings, Path(_TMPDIR) / "shot2", rec)
    PipelineRunner(shot_ctx2).run()
    assert any("未找到可用的无头浏览器" in x for x in rec.lines), rec.lines[-3:]
    # 截图路由：只允许该任务 shots/ 下的 png，且防目录穿越
    assert c.get(f"/shots/{tid}/nope.png").status_code == 404
    assert c.get(f"/shots/{tid}/..%2F..%2Ftask.log").status_code == 404
    # 缩略图渲染：造一个假 PNG 落到任务工作目录，写库后页面应出现 img
    task_row = db.get_task(tid)
    shots_dir = Path(task_row["log_file"]).parent / "shots"
    shots_dir.mkdir(parents=True, exist_ok=True)
    (shots_dir / "fake.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"0" * 32)
    # 用库里**实际的** site.url（probe 会去掉结尾斜杠，不能拿 targets 原样匹配）
    real_url = db.list_sites(tid)[0]["url"]
    db.set_site_shots(tid, [(real_url, "shots/fake.png")])
    assert c.get(f"/shots/{tid}/fake.png").status_code == 200, "截图路由应能取到文件"
    # 任务详情页（不受"跨任务重叠隐藏"影响）与站点页都要渲染缩略图
    assert "shot-thumb" in c.get(f"/tasks/{tid}").get_data(as_text=True), "任务详情应渲染缩略图"
    assert "shot-thumb" in c.get("/sites?all=1").get_data(as_text=True), "站点页应渲染缩略图"
    print("[5j] 站点截图 ok: 阶段注册/门控/路由/防穿越/缩略图（真实截图 3.1s 已在实机验证）")

    # 5k) 全面体检：并发注册同一个 POC 不能撞 UNIQUE(path)
    #     旧实现"先 SELECT 再 INSERT"，GUI 启动 + 多个任务线程同时 sync_pocs() 时
    #     会抛 IntegrityError（实测 6 个并发任务里 5 个失败），已改为原子 UPSERT。
    import threading as _th
    errs, ids = [], []

    def _upsert():
        try:
            ids.append(db.upsert_poc("config/pocs-imported/conc-test.yaml",
                                     {"id": "conc-test", "info": {"name": "并发测试",
                                                                  "severity": "low", "tags": []},
                                      "_status": "ok"}))
        except Exception as e:                       # pragma: no cover - 失败时记录
            errs.append(f"{type(e).__name__}: {e}")

    ts = [_th.Thread(target=_upsert) for _ in range(8)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert not errs, f"并发 upsert_poc 抛异常：{errs[:2]}"
    n_rows = db._query("SELECT COUNT(*) c FROM pocs WHERE path=?",
                       ("config/pocs-imported/conc-test.yaml",), one=True)["c"]
    assert n_rows == 1, f"同一个 path 应只有 1 行，实际 {n_rows}"
    print("[5k] 并发 POC 注册 ok: 8 线程同 path 无异常且只 1 行（原子 UPSERT + busy_timeout）")

    # (5l) 全流程体检修复：这些都是"错了也不报错、只是功能静默失效"的坑，用断言钉住
    from scanner import blacklist as bl_mod, jsmine as jsmine_mod
    # 1) JS 第三方名单文件真的生效（此前 _is_noise 遍历内置集合，267 条文件白加载）
    file_only = sorted(jsmine_mod._noise_set() - jsmine_mod._ALL_NOISE)
    assert file_only, "config/dicts/js_thirdparty.txt 未加载进第三方名单"
    assert jsmine_mod._is_noise("x." + file_only[0], set(), []) is True, \
        f"名单文件里的 {file_only[0]} 未被识别（应走 _noise_set()）"
    # 2) 黑名单开关关闭时 add() 仍能去重（此前用 load() 取 existing → 空 → 同一条反复追加）
    bl_off = {"blacklist": {"enabled": False, "path": str(_TMPDIR / "bl-off.txt")}}
    assert bl_mod.add(["dup-off.test", "dup-off.test"], bl_off) == 1
    assert bl_mod.add(["dup-off.test"], bl_off) == 0, "关闭开关时 add 未去重"
    # 3) 任务详情站点页签筛选框指向真实表格 id（此前 #tbl-sites 不存在 → 筛选静默失效）
    detail = c.get(f"/tasks/{tid}").get_data(as_text=True)
    assert 'data-filter="#tbl-detail-sites"' in detail and 'id="tbl-detail-sites"' in detail
    # 4) 策略页 union_passive 只有一份（此前复制成两份 → 取消一份关不掉）
    st_html = c.get("/settings").get_data(as_text=True)
    assert st_html.count('name="union_passive"') == 1, "settings 页 union_passive 复选框重复"
    # 5) 站点页两个显示开关可共存（此前手写链接会互相冲掉）
    both = c.get("/sites?all=1&plain=1").get_data(as_text=True)
    assert "all=1" in both and "plain=1" in both
    # 6) 关键字里的 & 会被 URL 编码进分页/切标签链接（此前原样拼接 → 翻页丢筛选）
    enc = c.get("/subdomains?q=a%26b").get_data(as_text=True)
    assert "q=a%26b" in enc, "pager.qs 未对 q 做 URL 编码"
    print("[5l] 全流程体检修复 ok: js第三方名单生效/黑名单去重/站点筛选/union_passive 唯一/开关共存/q 编码")

    # (5m) 第十七轮(续7)：低危项清理。同样是"错了不报错"型，逐条钉住。
    from scanner.report import _c
    from scanner.utils import pool_run
    from scanner.config import DEFAULTS
    from scanner import iprecon as iprecon_mod, dnsq as dnsq_mod
    from scanner import fingerprint as fp_mod
    import scanner.utils as utils_mod
    from scanner.stages.dirscan import DirscanStage as _DS
    import scanner.stages.dirscan as _ds_mod
    from gui.app import _safe_next

    # 1) 报告表格转义：`|` 会撑破表格、换行会断行；`\` 必须先转义（否则 `\|` 被二次转义）
    assert _c("a|b") == "a\\|b" and _c("a\nb") == "a b" and _c("a\rb") == "a b"
    assert _c("a\\b") == "a\\\\b" and _c(None) == "" and _c(0) == "0"
    # 2) pool_run 只丢 None：falsy 但有效的结果（0/""/[]）不该被静默吞掉
    kept = pool_run(lambda x: x, [0, "", [], "ok", None], workers=3)
    assert len(kept) == 4 and None not in kept, kept
    # 3) 开放重定向：next 只放行站内相对路径
    assert _safe_next("https://evil.com", "/tasks") == "/tasks"
    assert _safe_next("//evil.com", "/tasks") == "/tasks"
    assert _safe_next("/\\evil.com", "/tasks") == "/tasks"
    assert _safe_next("/subdomains?src=title", "/tasks") == "/subdomains?src=title"
    assert _safe_next(None, "/tasks") == "/tasks"
    # 4) favicon 的 HTML 错误页过滤要真能命中 <!doctype（此前 content[:6] 短于该字面量，永不命中）
    _orig_http = utils_mod.http_request
    try:
        utils_mod.http_request = lambda *a, **k: {
            "status": 200, "content": b"<!DOCTYPE html>\n<html><body>404</body></html>"}
        assert fp_mod.fetch_favicon("http://x.test", timeout=1) == b"", \
            "HTML 错误页未被拒（content[:64] 应能匹配 <!doctype）"
        utils_mod.http_request = lambda *a, **k: {"status": 200, "content": b"\x00\x01ICO"}
        assert fp_mod.fetch_favicon("http://x.test", timeout=1) == b"\x00\x01ICO"
    finally:
        utils_mod.http_request = _orig_http
    # 5) 反查域名不再接受 `_`（与 utils.is_domain 口径一致）
    assert "_" not in iprecon_mod._DOMAIN_OK
    # 6) FOFA 查询串要清掉引号与反斜杠（会提前闭合/转义掉闭合引号）
    assert fofa.build_cert_query('a"b\\c.com') == 'cert="abc.com"', fofa.build_cert_query('a"b\\c.com')
    assert fofa.build_title_query('x"y') == 'title="xy"'
    # 7) dnsq 尊重 dicts.resolvers 覆盖，且按**路径**缓存（不同配置互不串台）
    _r1 = _TMPDIR / "res1.txt"; _r1.write_text("10.0.0.1\n", encoding="utf-8")
    _r2 = _TMPDIR / "res2.txt"; _r2.write_text("10.0.0.2\n", encoding="utf-8")
    _s1 = {"dicts": {"resolvers": str(_r1)}}
    _s2 = {"dicts": {"resolvers": str(_r2)}}
    assert dnsq_mod._pick_resolvers(1, _s1) == ["10.0.0.1"]
    assert dnsq_mod._pick_resolvers(1, _s2) == ["10.0.0.2"]
    assert dnsq_mod._pick_resolvers(1, _s1) == ["10.0.0.1"], "按路径缓存后 s1 不该被 s2 覆盖"
    # 8) dirmap 循环内有 stopped() 检查（此前要等 dirmap 整轮跑完才响应停止）
    _stop_ev = threading.Event(); _stop_ev.set()
    _ds_stop = _DS(StageContext(tid, "smoke-stop", parse_lines([targets]), ["dirscan"], {},
                                settings, Path(_TMPDIR) / "dicts-stop", rec, stop_event=_stop_ev))
    _calls = []
    _orig_run_cmd = _ds_mod.run_cmd
    _ds_mod.run_cmd = lambda *a, **k: (_calls.append(a) or (0, "", ""))
    try:
        _rows = _ds_stop._run_dirmap(Path(_TMPDIR) / "fake" / "dirmap.py",
                                     {"": [{"url": "http://127.0.0.1:8765/"}]}, {})
    finally:
        _ds_mod.run_cmd = _orig_run_cmd
    assert _rows == [] and not _calls, f"已停止时不该再拉 dirmap：rows={_rows} calls={len(_calls)}"
    # 9) 文档漂移：docstring 的默认开关必须与 DEFAULTS 一致
    #    （takeover 默认开；dirscan 默认**开但只浅扫** —— 用户要求"先浅浅过一遍再决定深挖"）
    assert DEFAULTS["takeover"]["enabled"] is True
    assert DEFAULTS["dirscan"]["enabled"] is True
    assert DEFAULTS["dirscan"]["mode"] == "quick"
    assert "screenshot" in STAGE_ORDER
    print("[5m] 低危清理 ok: 报告转义/pool_run保falsy/开放重定向/favicon HTML过滤/域名口径/"
          "FOFA转义/dnsq路径缓存/dirmap停止检查/默认开关一致")

    # (5n) 续8：P3-2 漏洞情报订阅 + P3-3 启发式候选。两者**默认关**、**只写 leads 表**，
    #      边界（不写 vulns / 不计入漏洞数 / 不自动导 POC）必须钉死，否则下次有人顺手
    #      把它们并进 vulns，误报噪声就回来了。
    import json as _json
    from scanner import intel as intel_mod
    from scanner import heuristics as heur_mod
    from scanner.stages.intel import IntelStage
    from scanner.stages.heuristic import HeuristicStage

    # 1) 情报源地址：intel.url 优先 → 内置表 → 认不出的 source 视为未配置
    assert intel_mod.feed_url({"intel": {"url": "http://feed.test/x.json"}}) == "http://feed.test/x.json"
    assert intel_mod.feed_url({}) == intel_mod.FEEDS["kev"], "默认源应是 KEV"
    assert intel_mod.feed_url({"intel": {"source": "nope"}}) == ""
    # 缓存文件名按 source 生成，且清掉路径穿越字符（不能让配置决定往哪写文件）
    _cp = intel_mod.cache_path({"intel": {"source": "../KEV!"}})
    assert _cp.parent == intel_mod.cache_dir() and _cp.name == "kev.json", _cp
    # 2) 规整：拿不到 CVE 号的记录一律无效（CVE 号是去重与溯源的键）
    assert intel_mod.normalize_item({"product": "x"}) is None
    assert intel_mod.normalize_item("nope") is None
    _kev = {"cveID": "CVE-2020-14882", "vendorProject": "Oracle",
            "product": "Oracle WebLogic Server",
            "vulnerabilityName": "Oracle WebLogic Server RCE",
            "shortDescription": "desc", "requiredAction": "patch",
            "knownRansomwareCampaignUse": "Known", "dateAdded": "2021-11-03",
            "dueDate": "2021-11-17", "cwes": ["CWE-306"]}
    _it = intel_mod.normalize_item(_kev)
    assert _it["cve"] == "CVE-2020-14882" and _it["vendor"] == "Oracle"
    assert _it["cwes"] == "CWE-306"
    _items = intel_mod.parse_feed(_json.dumps({"vulnerabilities": [_kev, {"noCve": 1}]}))
    assert len(_items) == 1, "无效记录（无 CVE 号）应被丢掉"
    assert intel_mod.parse_feed("not json") == []
    # 3) 匹配：必须同时满足"资产信号 + 产品关键词 + 厂商对得上"；短信号有词边界
    assert intel_mod.match_item(_it, "weblogic 10.3.6 oracle") == ["weblogic"]
    assert intel_mod.match_item(_it, "grafana/8.0") == []
    assert intel_mod.match_item(_it, "") == []
    assert not intel_mod._signal_hit("heliis", "iis"), "短信号不得被别的单词吞掉"
    assert intel_mod._signal_hit("microsoft-iis/10.0", "iis")
    # 参与匹配的文本**不含标题**（标题是用户内容，纳进来只会制造误报）
    _kw = intel_mod.asset_keywords(site={"tech": "wordpress", "server": "nginx",
                                        "title": "AcmePortal"})
    assert _kw == "wordpress nginx" and "acme" not in _kw, _kw
    assert intel_mod.asset_keywords(
        port={"service": "http", "banner": "Apache-Coyote/1.1"}) == "http apache-coyote/1.1"
    # 4) 级别只用于排序：已知被勒索利用 → high，其余 medium（不是 CVSS 评分）
    assert intel_mod.level_of(_it) == "high" and intel_mod.level_of({}) == "medium"
    _lead = intel_mod.build_lead(_it, "http://a/", ["weblogic"])
    assert _lead["kind"] == "intel" and _lead["code"] == "CVE-2020-14882"
    assert "nvd.nist.gov" in _lead["url"] and "人工验证" in _lead["detail"]

    ld_tid = db.create_task("smoke-leads", targets, ["intel", "heuristic"], {"offline": True})
    # 5) 写入侧去重：(kind, code, target) 相同不重复插入；leads 属于"资产表"（重启时会被清）
    assert db.insert_leads(ld_tid, [_lead, dict(_lead)]) == 1
    assert db.insert_leads(ld_tid, [_lead]) == 0, "同一条线索不该重复入库"
    assert "leads" in db.ASSET_TABLES
    _rows = db.list_leads(ld_tid)
    assert len(_rows) == 1 and _rows[0]["kind"] == "intel"
    assert not db.list_vulns(task_id=ld_tid, limit=10), "线索绝不能写进 vulns"

    # 6) 启发式五条规则各一正例 + 关键反例
    _d_soft = [{"site_url": "http://s1/", "path": f"/x{i}", "status": 200, "length": 100}
               for i in range(10)]
    assert [x["code"] for x in heur_mod.find_leads([], _d_soft, [], [])] == ["soft404"]
    _d_entry = [{"site_url": "http://s2/", "path": "/.git/config", "status": 200, "length": 10}]
    assert [x["code"] for x in heur_mod.find_leads([], _d_entry, [], [])] == ["entry-git-dir"]
    # 检测层已经就这条路径给过结论 → 不再重复报线索
    assert heur_mod.find_leads(
        [], _d_entry, [{"target": "http://s2/", "detail": "/.git/config 可读"}], []) == []
    _s_t = [{"url": f"http://a{i}/", "host": f"a{i}", "title": "AcmePortalLogin"} for i in (1, 2, 3)]
    assert [x["code"] for x in heur_mod.find_leads(_s_t, [], [], [])] == ["same-title"]
    # 公共模板标题（后台管理系统 / Index of /）不算"同一套系统"
    assert heur_mod.find_leads(
        [{"url": "http://b1/", "host": "b1", "title": "后台管理系统"},
         {"url": "http://b2/", "host": "b2", "title": "后台管理系统"}], [], [], []) == []
    _d_out = [{"site_url": "http://big/", "path": f"/p{i}", "status": 404, "length": i}
              for i in range(20)]
    _d_out += [{"site_url": "http://small/", "path": "/q", "status": 200, "length": 1}]
    assert [x["code"] for x in heur_mod.find_leads([], _d_out, [], [])] == ["dir-outlier"]
    _cseg = [{"segment": "10.0.0.0/24", "ip": f"10.0.0.{i}", "count": 2} for i in (1, 2, 3)]
    assert [x["code"] for x in heur_mod.find_leads([], [], [], _cseg)] == ["cseg-cluster"]
    assert heur_mod.find_leads([], [], [], [{"segment": "10.0.0.0/24", "ip": "10.0.0.1",
                                             "count": 0}]) == [], "无反查结果不算聚集"
    assert heur_mod.find_leads([], [], [], []) == []

    # 7) 门控：默认关时两个阶段**连库都不写**（策略配置没打开就不该产生线索）
    _gate = copy.deepcopy(settings)
    _gate["intel"] = {"enabled": False}
    _gate["heuristic"] = {"enabled": False}
    _gctx = StageContext(ld_tid, "smoke-lead-gate", parse_lines([targets]),
                         ["intel", "heuristic"], {}, _gate,
                         Path(_TMPDIR) / "lead-gate", rec)
    IntelStage(_gctx).run()
    HeuristicStage(_gctx).run()
    assert len(db.list_leads(ld_tid)) == 1, "默认关时不该写入任何新线索"
    assert DEFAULTS["intel"]["enabled"] is False and DEFAULTS["heuristic"]["enabled"] is False
    assert STAGE_ORDER[-2:] == ["intel", "heuristic"], "两个新阶段应固定在流水线最后"

    # 8) GUI：策略配置渲染出两个开关、任务详情有「线索」页签；报告附录只在有关键线索时出现
    _shtml = c.get("/settings").get_data(as_text=True)
    assert 'name="intel_enabled"' in _shtml and 'name="heuristic_enabled"' in _shtml
    _dhtml = c.get(f"/tasks/{ld_tid}").get_data(as_text=True)
    assert 'data-tab="leads"' in _dhtml and 'id="pane-leads"' in _dhtml
    _md_lead = generate(ld_tid)
    assert "线索（非漏洞结论" in _md_lead and "CVE-2020-14882" in _md_lead
    assert "线索（非漏洞结论" not in generate(ds_tid), "无线索的任务不该多出附录小节"
    print("[5n] 情报订阅/启发式 ok: KEV 解析+白名单匹配(词边界)+只写 leads(去重)/"
          "五条启发式规则+反例/默认关门控/GUI 开关与页签/报告附录")

    # (5p) 续9：目录探测「浅扫 / 深扫」两档 + 建任务全量勾选 + 结果页补扫。
    #      用户诉求：**先浅过一遍再手动决定深挖**，且勾了全量就不该"白勾"。
    import re as _re5
    from scanner.config import DEFAULTS as _DEF, resolve as _resolve
    from scanner.stages.dirscan import _SHALLOW_LAYERS, _FULL_LAYERS, _SUFFIXES

    # 1) 默认值一致：DEFAULTS ↔ settings.yaml ↔ 文件真实存在（GUI 表单/POST 映射在第 4 条用真请求验）
    assert _DEF["dirscan"]["enabled"] is True and _DEF["dirscan"]["mode"] == "quick"
    assert _DEF["dirscan"]["quick_max_paths"] == 150
    assert _DEF["dirscan"]["suffix_aware"] is True
    assert _DEF["dicts"]["dirs_shallow"] == "config/dicts/dirs_shallow.txt"
    assert settings["dirscan"]["enabled"] is True and settings["dirscan"]["mode"] == "quick"
    assert settings["dicts"]["dirs_shallow"] == _DEF["dicts"]["dirs_shallow"]
    _shallow_file = _resolve(settings["dicts"]["dirs_shallow"])
    assert _shallow_file.exists(), "浅扫字典文件不存在（config/dicts/dirs_shallow.txt）"

    # 2) 浅扫取词：只吃 dirs_shallow，条数受 quick_max_paths 约束
    _shallow_list = [x for x in _shallow_file.read_text(encoding="utf-8").splitlines()
                     if x and not x.startswith("#")]
    assert len(_shallow_list) >= 150, len(_shallow_list)   # 默认上限 150 必须能被填满
    _sq40 = dstage._load_paths("php", {"quick_max_paths": 40},
                               layers=_SHALLOW_LAYERS, limit=40)
    assert len(_sq40) == 40 and set(_sq40) <= set(_shallow_list), _sq40[:3]
    assert _SHALLOW_LAYERS == ("shallow",), "浅扫层不该夹带框架/语言/通用字典"
    # 高价值条目必须在最前面（截断时先保它们）
    assert any(x in _shallow_list[:20] for x in (".git/config", ".env")), _shallow_list[:5]

    # 3) 档位判定：任务级 dirscan_full 压过全局 mode=quick；portscan_full 与目录档位**互不影响**。
    #    `_builtin_scan` / `_run_dirmap` 都换成桩：既不发请求也不拉 dirmap，只看"走了哪一档"。
    _q_settings = copy.deepcopy(settings)
    _q_settings["dirscan"] = dict(_q_settings.get("dirscan") or {}, mode="quick")

    def _run_dirs(opts):
        seen = []
        _bs0, _dm0 = DirscanStage._builtin_scan, DirscanStage._run_dirmap
        DirscanStage._builtin_scan = (
            lambda self, s, c, l, only_fw=False, shallow=False: (seen.append(shallow) or []))
        DirscanStage._run_dirmap = lambda self, *a, **k: []
        try:
            _cx = StageContext(tid, "smoke-dir-mode", parse_lines([targets]), ["dirscan"],
                               opts, _q_settings, Path(_TMPDIR) / "dir-mode", rec)
            _cx.results["sites"] = [{"url": targets, "tech": "", "title": "", "length": None}]
            DirscanStage(_cx).run()
        finally:
            DirscanStage._builtin_scan, DirscanStage._run_dirmap = _bs0, _dm0
        return seen

    assert _run_dirs({}) == [True], "全局 quick 档应走浅扫"
    assert _run_dirs({"dirscan_full": True}) == [False], "任务级 dirscan_full 应压过 quick 走深扫"
    assert _run_dirs({"portscan_full": True}) == [True], "端口全量选项不该改目录档位"
    # 只跑 dirscan 的补扫任务没有 probe 产物：必须能从目标兜底出站点，否则整阶段空跑
    _noactx = StageContext(tid, "smoke-dir-targets", parse_lines(["http://fallback.test/"]),
                           ["dirscan"], {}, _q_settings, Path(_TMPDIR) / "dir-fb", rec)
    # parse_lines 会去掉尾部 `/`，所以这里按归一化后的形态断言
    _fb = DirscanStage._sites_from_targets(_noactx)
    assert _fb and _fb[0]["url"] == "http://fallback.test", _fb
    assert DirscanStage._sites_from_targets(
        StageContext(tid, "smoke-dir-targets2", parse_lines(["fallback.test"]), ["dirscan"], {},
                     _q_settings, Path(_TMPDIR) / "dir-fb2", rec))[0]["url"] == "http://fallback.test"

    # 3b) **深扫必须是浅扫的超集**：精选层排在 `_FULL_LAYERS` 最前。
    #     实测过的坑：未知技术栈时深扫吃 `dirs_big` 前 400 条，而 `.env`/`.git/config`
    #     在 big 里排 560/1919 位 → 深扫 400 条只命中 `.git`，比浅扫 150 条还少。
    _ds_cfg = _q_settings.get("dirscan") or {}
    _deep_paths = dstage._load_paths("", _ds_cfg, layers=_FULL_LAYERS)
    assert _deep_paths[:len(_shallow_list[:50])] == _shallow_list[:50], \
        f"深扫必须把浅扫精选条目排在最前（否则深扫会漏掉浅扫已命中的高价值路径）：" \
        f"{_deep_paths[:3]} vs {_shallow_list[:3]}"
    assert set(_shallow_list).issubset(set(_deep_paths)), \
        f"深扫额度（{len(_deep_paths)} 条）内必须覆盖浅扫全部 {len(_shallow_list)} 条精选路径"

    # 4) 建任务：勾了全量却没勾对应阶段 → **自动补阶段** + options 落库（run_task 桩住，避免真扫）
    _orig_run4 = gui_app.run_task
    try:
        gui_app.run_task = lambda *a, **kw: None
        _j4 = c.post("/api/tasks", data={"name": "smoke-full-flags", "targets": targets,
                                        "stages": ["probe"], "portscan_full": "1",
                                        "dirscan_full": "1"}).get_json()
        _t4 = db.get_task(_j4["id"])
        assert '"portscan_full": true' in _t4["options"], _t4["options"]
        assert '"dirscan_full": true' in _t4["options"], _t4["options"]
        # 补进来的阶段按 STAGE_ORDER 归位（runner 不排序，乱序会跑错顺序）
        assert _t4["stages"].split(",") == ["portscan", "probe", "dirscan"], _t4["stages"]
        assert _j4["auto_stages"] == ["portscan", "dirscan"], _j4
        # 不勾全量时不该凭空多出选项/阶段
        _j4b = c.post("/api/tasks", data={"name": "smoke-no-full", "targets": targets,
                                         "stages": ["probe"]}).get_json()
        _t4b = db.get_task(_j4b["id"])
        assert _t4b["stages"] == "probe" and "full" not in (_t4b["options"] or ""), dict(_t4b)
        assert _j4b["auto_stages"] == [], _j4b

        # 5) 补扫端点：只跑一个阶段 + 全量档 + 记录来源任务；外站 next 必须被拒
        _before5 = len(db.list_tasks(limit=1000))
        _r5 = c.post("/api/rescan", data={"stage": "dirscan", "target": ["http://a.test/"],
                                          "from_task": str(tid), "next": "https://evil.com/x"})
        assert _r5.status_code == 302, _r5.status_code
        _id5 = int(_r5.headers["Location"].rstrip("/").rsplit("/", 1)[-1])
        _t5 = db.get_task(_id5)
        assert _t5["stages"] == "dirscan" and _t5["targets"] == "http://a.test/", dict(_t5)
        assert '"dirscan_full": true' in _t5["options"], _t5["options"]
        assert f'"rescan_of": {tid}' in _t5["options"], _t5["options"]
        assert _re5.match(r"^补扫全目录-\d{4}-\d{6}$", _t5["name"]), _t5["name"]
        # 非法 stage / 空目标 → 回站内 fallback，且**不产生任务**；外站 next 不得被放行
        _r5b = c.post("/api/rescan", data={"stage": "nope", "target": ["x"],
                                           "next": "https://evil.com/"})
        assert _r5b.status_code == 302 and _r5b.headers["Location"].startswith("/") \
            and not _r5b.headers["Location"].startswith("//"), _r5b.headers.get("Location")
        _r5c = c.post("/api/rescan", data={"stage": "portscan", "next": "/sites"})
        assert _r5c.headers["Location"] == "/sites", _r5c.headers.get("Location")
        assert len(db.list_tasks(limit=1000)) == _before5 + 1, "非法请求不该建出任务"
    finally:
        gui_app.run_task = _orig_run4

    # 6) 后缀派生（仅深扫）：只对**文件名型**路径派生，去重且受 max_paths 约束；浅扫一条都不派
    _sj = DirscanStage._suffix_jobs(
        [{"site_url": "http://a/", "path": "http://a/config.php"},
         {"site_url": "http://a/", "path": "http://a/admin/"},
         {"site_url": "http://a/", "path": "http://a/.env"}], 5)
    assert len(_sj) == 5, _sj
    assert _sj[0] == ("http://a/", "config.php" + _SUFFIXES[0]), _sj[0]
    assert all(p.endswith(tuple(_SUFFIXES)) for _, p in _sj), _sj
    assert len({p for _, p in _sj}) == len(_sj), "派生结果必须去重"
    assert all("/admin/" not in p for _, p in _sj), "目录型路径不该派生后缀"
    assert DirscanStage._suffix_jobs(
        [{"site_url": "http://a/", "path": "http://a/x.php"}], 0) == []

    _sent = []
    _orig_http6, _orig_lp6 = _ds_mod.http_request, DirscanStage._load_paths

    def _fake_http6(u, **k):
        _sent.append(u)
        if "ctfscan-none" in u:            # 软 404 基线（长度 1，与真实命中区分开）
            return {"status": 200, "length": 1, "text": "base:" + u, "content": b"b"}
        return {"status": 200, "length": 200, "text": "hit:" + u, "content": b"h"}

    _site6 = [{"url": "http://sfx.test/", "tech": "", "title": "", "length": None}]
    DirscanStage._load_paths = lambda self, kind, cfg, fw="", layers=None, limit=None: \
        ["config.php"]
    _ds_mod.http_request = _fake_http6
    try:
        _sent.clear()
        DirscanStage(dstage.ctx)._builtin_scan(_site6, {"quick_max_paths": 5, "suffix_aware": True},
                                               {}, shallow=True)
        _hits_shallow = [u for u in _sent if "ctfscan-none" not in u]
        _sent.clear()
        DirscanStage(dstage.ctx)._builtin_scan(_site6, {"max_paths": 5, "suffix_aware": True}, {})
        _hits_deep = [u for u in _sent if "ctfscan-none" not in u]
    finally:
        _ds_mod.http_request, DirscanStage._load_paths = _orig_http6, _orig_lp6
    assert _hits_shallow == ["http://sfx.test/config.php"], _hits_shallow
    assert "http://sfx.test/config.php.bak" in _hits_deep, _hits_deep
    assert len(_hits_deep) > len(_hits_shallow), "深扫应派生出备份后缀变体"
    assert len(_hits_deep) <= 1 + 5, "派生总量必须受 max_paths 约束"

    # 7) GUI 可见性：建任务勾选、策略强度下拉/额度、任务详情与站点页的补扫入口
    _tasks_html = c.get("/tasks").get_data(as_text=True)
    assert 'name="portscan_full"' in _tasks_html and 'name="dirscan_full"' in _tasks_html
    _set_html = c.get("/settings").get_data(as_text=True)
    assert 'name="dirscan_mode"' in _set_html and 'name="dirscan_quick_max_paths"' in _set_html
    assert 'name="dirscan_suffix_aware"' in _set_html
    _det_html = c.get(f"/tasks/{tid}").get_data(as_text=True)
    assert "/api/rescan" in _det_html and "深度目录补扫" in _det_html, "任务详情缺补扫入口"
    assert "/api/rescan" in c.get("/sites").get_data(as_text=True), "站点页缺补扫入口"
    print("[5p] 目录浅/深两档 + 全量勾选 + 补扫 ok: 默认浅扫 150 条/档位判定(portscan_full "
          "互不影响)/目标兜底/自动补阶段/补扫任务命名与 rescan_of/next 防跳外站/"
          "后缀派生去重限额/GUI 入口")

    # (5o) 续8：P2-3 跨平台（Linux + Windows）**可执行**验证。
    #      本机只有 Windows/Python 3.9（无 WSL/Docker），"Linux 实机跑一次 smoke"这一步
    #      在这里做不了；因此把**所有能自动化的跨平台风险点**都变成断言 ——
    #      这一节在 Linux 上跑就等于那次验收（同一份代码，无平台分支）。
    #      仍未覆盖（如实标注）：①无头浏览器截图**在 Linux 上**的探测（Windows 侧已实机验证，
    #      单站 3.1s/11036 字节合法 PNG，见 CHANGELOG 续3）；②fscan/subfinder/puredns/httpx
    #      的适配分支（本机没装这些二进制，走的是内置兜底分支）。这些都需要在 Linux 上装好
    #      对应工具才能验（代码里全部走 shutil.which + 内置兜底，找不到只会降级、不会崩）。
    import inspect as _inspect
    import re as _re
    from scanner.utils import pick_python, run_cmd

    # 1) 全部源码能被 compile（语法层不存在平台差异；顺带覆盖 CLI/tools）
    #    排除 tools/dirmap/：那是**第三方** Python2 项目（目录联接，不随仓库分发），
    #    它的语法本来就不能用 Python3 compile（print 语句），不是本项目的问题。
    _SKIP_DIRS = (ROOT / "tools" / "dirmap",)
    _py = sorted(p for _d in ("scanner", "gui", "cli", "tools", "tests")
                 for p in (ROOT / _d).rglob("*.py")
                 if not any(str(p).startswith(str(s)) for s in _SKIP_DIRS))
    assert len(_py) > 30, f"源码文件数异常：{len(_py)}"
    for _p in _py:
        compile(_p.read_text(encoding="utf-8", errors="replace"), str(_p), "exec")

    # 2) 每个模块都能 import（只有模块级 winreg/msvcrt 这类才会在这里炸）
    import importlib as _importlib
    _mods = []
    for _p in sorted((ROOT / "scanner").rglob("*.py")):
        if _p.name == "__init__.py":
            continue
        _mods.append(".".join(_p.relative_to(ROOT).with_suffix("").parts))
    _mods += ["gui.app", "cli.client"]
    for _m in _mods:
        _importlib.import_module(_m)
    assert "scanner.intel" in _mods and "scanner.heuristics" in _mods, "新模块未被遍历到"

    # 3) 源码级红线：不 shell、不 os.system、不写死盘符路径（这三类都会在 Linux 上翻车）
    #    注意：下面这些**断言文本本身**也会被扫到，所以消息里刻意不写出被禁的字面量
    #    （例如不写 "shell" 加等号加 True 的完整形式），否则测试会自己匹配自己。
    _src = {p: p.read_text(encoding="utf-8", errors="replace") for p in _py}
    for _p, _txt in _src.items():
        _rel = _p.relative_to(ROOT).as_posix()
        assert not _re.search(r"shell\s*=\s*" + "True", _txt), f"{_rel}: 子进程不得走 shell"
        assert not _re.search(r"\bos\.(system|popen)\s*\(", _txt), f"{_rel}: 不得用 os 的 shell 调用"
        assert not _re.search(r"['\"][A-Za-z]:[\\/]", _txt), f"{_rel}: 出现写死的盘符路径"
        # 文本文件读写必须显式 encoding（否则 Windows 默认 GBK、Linux 默认 UTF-8，行为就分叉了）
        assert not _re.search(r"\.(read_text|write_text)\(\s*\)", _txt), f"{_rel}: 文本读写缺 encoding"
        assert not _re.search(r"\bopen\(\s*\)", _txt), f"{_rel}: 内建 open 缺参数"
    assert "shell=False" in _inspect.getsource(run_cmd), "run_cmd 必须显式关闭 shell"

    # 4) 子进程与解释器选择在两种系统上行为一致
    _rc, _out, _err = run_cmd(["ctfscanner-no-such-binary-xyz"])
    assert _rc == 127, f"命令不存在应返回 127，实际 {_rc}"
    _rc2, _, _ = run_cmd([sys.executable, "-c", "import time; time.sleep(5)"], timeout=1)
    assert _rc2 == 124, f"超时应返回 124，实际 {_rc2}"
    assert pick_python("ctfscanner-no-such-python-xyz") == sys.executable, \
        "配置的解释器不可用时必须回退到当前解释器（Linux 上 python 常常不存在）"
    print(f"[5o] 跨平台静态审计 ok: 编译 {len(_py)} 个源文件 / import {len(_mods)} 个模块 / "
          f"无 shell 直通·盘符路径·缺 encoding；run_cmd 127/124 与 pick_python 回退"
          f"（Linux 实机验收仍需在 Linux 上跑本脚本，见 TODO.md P2-3）")
    print("SMOKE PASS")


if __name__ == "__main__":
    main()
