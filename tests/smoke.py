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

# [5v] 用的固定自签证书与配套私钥（一次性生成的**测试夹具**，不是任何生产凭据）。
# 内联而不是放文件：证书解析的断言要"零外部依赖、可离线跑"，且这类夹具一旦落盘就容易被
# 误当成真凭据管理；内联后整段测试自包含。
# 证书自造特征（断言逐条依赖这些值，改动夹具必须同步改断言）：
#   subject/issuer = CN=smoke.test.lab, O=CTFScanner Smoke, C=CN
#   serial = 0x1234ABCD（DER 里带正数补位 0x00，解析器必须剥掉）
#   notBefore 2020-01-02 03:04:05Z / notAfter 2021-02-03 04:05:06Z（已过期）
#   SAN = smoke.test.lab / *.smoke.test.lab / 10.9.9.9，签名算法 sha256WithRSA
_CERT_PEM = """-----BEGIN CERTIFICATE-----
MIIDNTCCAh2gAwIBAgIEEjSrzTANBgkqhkiG9w0BAQsFADBBMQswCQYDVQQGEwJD
TjEZMBcGA1UECgwQQ1RGU2Nhbm5lciBTbW9rZTEXMBUGA1UEAwwOc21va2UudGVz
dC5sYWIwHhcNMjAwMTAyMDMwNDA1WhcNMjEwMjAzMDQwNTA2WjBBMQswCQYDVQQG
EwJDTjEZMBcGA1UECgwQQ1RGU2Nhbm5lciBTbW9rZTEXMBUGA1UEAwwOc21va2Uu
dGVzdC5sYWIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDq9op/NHZV
ZiEMArTEhe+mPN3/4auHBnFBMd4XWL6Mkq1dTF1x48ry5VEAniWUaAXbh+FIi3h9
z2jBuMqmOlJsv1N8Cduqb0lBm6Dk2qaeDit8bexjkEGHY+duFr9lQbc404JC+nFm
y/S6e8Gnqg4WU4u2hb32Sp4DP9MSntQ1PGvrGfsafV9JmRlLLxX/bGNNm4mNcTKq
vwbqh1oSjojri21NfVpSpb++OdzL9Xpgro39YlxWqwgtpxpPW67MfMetGugrFiGO
w+d+B1r1zPERIMDsv0pHZ9ugYgKdezD6WD+nyKsSBKY4tDLcZfGpiDCCMcbX5kzb
+j370u974PxVAgMBAAGjNTAzMDEGA1UdEQQqMCiCDnNtb2tlLnRlc3QubGFighAq
LnNtb2tlLnRlc3QubGFihwQKCQkJMA0GCSqGSIb3DQEBCwUAA4IBAQDBMEJ176ho
08pY2hQoJQ6hrYYSElqrHx3QirSQwoo0/WFfxSHF8shY3l51vzKM2HCck0U1RiQ5
I1dgBrkW43gMJDHFtEeEjsWDej3yj5ZdrM9c1vRrC3jfrLcRPcZNpwv+N1kXXjM6
kbIg870QuCQY8PNQ6IgJKwoc8r7oGTgdubhrNeH6Vp/quCEqbqMVQylRvsri+0Fo
VZc3UwQjQxetkJfcfsCz3U+JNeJeBIOQfxwh1JHF6TNBQQqjG+V1sH4PfdDnIHz+
5zf3ERyE8QLF0cDwViGHaFssL1GChnMKs1fZltIaCgWS/AkFJs4y4dO6OmNsUMjy
3UcR1T7xxwgi
-----END CERTIFICATE-----
"""

_KEY_PEM = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA6vaKfzR2VWYhDAK0xIXvpjzd/+GrhwZxQTHeF1i+jJKtXUxd
cePK8uVRAJ4llGgF24fhSIt4fc9owbjKpjpSbL9TfAnbqm9JQZug5Nqmng4rfG3s
Y5BBh2Pnbha/ZUG3ONOCQvpxZsv0unvBp6oOFlOLtoW99kqeAz/TEp7UNTxr6xn7
Gn1fSZkZSy8V/2xjTZuJjXEyqr8G6odaEo6I64ttTX1aUqW/vjncy/V6YK6N/WJc
VqsILacaT1uuzHzHrRroKxYhjsPnfgda9czxESDA7L9KR2fboGICnXsw+lg/p8ir
EgSmOLQy3GXxqYgwgjHG1+ZM2/o9+9Lve+D8VQIDAQABAoIBAAOChWacwBg9++YG
nXTErcHk2Dz7ebKnvhCYGZ+pKFPuemJ1/Fqg5RHDPBQdRGWLHYXRclufHVXyUKsK
a65GXdt4xqfD1kRhyOS1Yn0dfAoNfRoKwIWebJaRe0v1hEPGo8fyJdRozjkXvMQo
kzSKjVNJSZJ61pqFxP3tu+Vj/qEFZEpTYuGwyTyzLvjwSU6gTKfyhFkFgNAptdsU
1OZdxs49t4NdopJU1jsyKUF0AyyHTzXiRzcZcxqG+nNkxBClvqwg4oYsZGtrYXly
zSoszTrJepUvRRDRAa3wofG8hrm71mBQEDv0e2fKHqbliF90/NDfrzYW/jfrEyVP
YMYYAdECgYEA/1MtFetQxc2wjTmfS3ci52MrbZZKoUYdoH3fRPskce1o3N01RQrG
GdXOqNgakpBReSCIDot5At/Sogrp/gFQv1RYWCoxhilUgS6Rj3pBGk5ID7Qk5UB7
3kbmBVNFIVWhCKn44q9yw9rGI0xJQUMU4Ot21YdVXMu34nfxSXoUrBECgYEA65WV
F35PsHx5U7/sva00RLBPY4FFwV1YlOqLPosej0soNh9ct+wm2rwKYjqtL0Lj2KD/
1CkU4W2xjqDTgnHDlyJ/bDzHq4OucG1P1Lg1fwPKg5dG6FzPBFmOJmnxUuXDg/0k
qAdhzRjpBl35aZyTy7aoporZG8GqAITCjDn/oAUCgYBavTmpr45uLdKP7imRjU6H
QzQ85wuw0xVWY0WE42gpYQFCdQ8ocVLD/btLQDn5WnbKAGi6GpEwF1FpK03LarZC
uPwIoT4meuvAWUd74Svf6HAtvIzcOJWNAk9fFx/bX+4yAQ4lqcq0ljyScNsb6XYz
FRuPeWA58WBxiMTkoxFTsQKBgAKR+DVwaFgpk31Ja8DKAfb54XPZdjRc21mMkYZW
KDgx/rdQckeDaQ0b3hUiRL9uQGQdpYzgAd1PwA8pTAVxTkv40WER7K+/WQja+HL+
q36+QNhcryZb1NpcS8O5hit8XDy1Z0/5/KQrMGekYNM5JRek34QpoaK+4ybsS98R
xustAoGBAJJ0QHYKM7evba1jiMb61999eat5ze6JMpk3nNCDJ2K92BWRvb+b18pP
F5TcJN9eTewjvwZlT1m+KAlIFPimhJWDDWGhn+yn/Cik+ygsfDp8Dd9TqXVsoD9W
EzRgvLIZT5hBD4Qifb5N+XsRSSnLpAiEGXgk7HU2To1k1jDtImgR
-----END RSA PRIVATE KEY-----
"""


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
from scanner.report import export_pdf, generate, generate_html, generate_jsonl
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
    # cert（续14 证书取证）紧跟 probe；intel / heuristic（P3-2/P3-3）固定排在**最后**
    # 且默认关，只写 leads 表
    assert STAGE_ORDER == ["subdomain", "takeover", "portscan", "probe",
                           "cert", "screenshot", "osint", "jsmine", "dirscan", "vulnscan",
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
        # ① fscan 2.2.1 **真实输出**（2026-09-23 在 Ubuntu 22.04 实机抓取，逐行原样）：
        #    开放端口的实际行形态是 `[*] ip:port <service>` / `[*] http://ip:port` /
        #    `[+] http://ip:port code:NNN`，**不是**老代码以为的 `[+] ip:port open`。
        _real = (
            "      Fscan 2.2.1 (95cc12e 2026-08-25T20:44:10Z)\n"
            "\n"
            "[*] 服务插件: webpoc, dnstcp, webtitle, mysql, redis ... 等6个\n"
            "[*] 参数自适应: Timeout=1000ms, ModuleThread=20, Retry=1, ICMPRate=0.50\n"
            "[*] \x1b[36m127.0.0.1:3306\x1b[0m                 mysql    "
            "[Product:Genetec Security Center] Banner:(N 5.7.43-log ZN ,!ZP - X)\n"
            "[*] 127.0.0.1:22                   ssh      "
            "[Product:OpenSSH ||Version:8.9p1 Ubuntu 3ubuntu0.17]\n"
            "[+] MySQL 127.0.0.1:3306 MySQL 5.7.43-log\n"
            "[*] http://127.0.0.1:888           http     [Product:nginx]\n"
            "[*] 127.0.0.1:6379                 redis    [Product:Redis key-value store]\n"
            "[*] http://127.0.0.1:8766          http     [Product:Open Lighting ...]\n"
            "[!] Redis未授权访问: 127.0.0.1:6379\n"
            "[*] http://127.0.0.1:631           http     [Product:CUPS]\n"
            "[*] http://127.0.0.1:8082          http     [Product:nginx]\n"
            "[+] http://127.0.0.1:888           code:403 len:146   title:403 Forbidden\n"
            "[+] https://127.0.0.1:631          code:200 len:2247  title:Home - CUPS 2.4.1\n"
            "[*] http://127.0.0.1:8081          http     [Product:nginx]\n"
            "[*] 扫描完成，发现 8 个开放端口\n"
            "[+] http://127.0.0.1:8082          code:200 len:9659  title:None\n"
            "[+] http://127.0.0.1:8081          code:302 len:358   "
            "title:Redirecting to http://127.0.0.1:8081/system\n"
            "[*] 扫描任务完成，耗时 3.449s，已扫描 14 个目标\n"
        )
        _ports = [22, 53, 631, 888, 3306, 6379, 8081, 8082, 8766]
        _stub_run.reply = [(0, _real, "")]
        got = ps.fscan_scan("h.test", "127.0.0.1", _ports, binary="fscan")
        assert [r["port"] for r in got] == [22, 631, 888, 3306, 6379, 8081, 8082, 8766], got
        assert got[0]["service"] == "ssh" and got[5]["service"] == "http-alt", got
        assert got[0]["host"] == "h.test" and got[0]["ip"] == "127.0.0.1"
        cmd = _ps_calls[-1]
        assert {"-np", "-nobr", "-nopoc"} <= set(cmd), cmd
        assert cmd[cmd.index("-h") + 1] == "127.0.0.1"
        _parg = cmd[cmd.index("-p") + 1]
        assert _parg.startswith("22,53,631,888,3306,6379,8081-8082") and _parg.endswith("8766"), _parg
        assert cmd[cmd.index("-t") + 1] == "512", cmd   # workers 缺省 64 × 8

        # ② 老版本 `[+] ip:port open` 形态仍要认（ANSI 颜色码也要能剥掉）
        _stub_run.reply = [(0, "[+] \x1b[32m10.0.0.1:80\x1b[0m open\n"
                              "[+] 10.0.0.1:8080 open\n"
                              "[*] 扫描完成，发现 2 个开放端口\n", "")]
        got = ps.fscan_scan("h.test", "10.0.0.1", [80, 8080], binary="fscan")
        assert [r["port"] for r in got] == [80, 8080], got
        assert got[0]["service"] == "http" and got[1]["service"] == "http-alt"

        # ③ 老版本不认 -nopoc：去掉它重试一次，-np -nobr 必须还在
        _before = len(_ps_calls)
        _stub_run.reply = [(1, "", "flag provided but not defined: -nopoc"),
                           (0, "[+] 10.0.0.1:443 open\n[*] 扫描完成，发现 1 个开放端口\n", "")]
        got = ps.fscan_scan("h.test", "10.0.0.1", [443], binary="fscan")
        assert [r["port"] for r in got] == [443]
        assert len(_ps_calls) - _before == 2, _ps_calls[_before:]
        assert "-nopoc" not in _ps_calls[-1] and {"-np", "-nobr"} <= set(_ps_calls[-1])
        # ④ rc≠0 且不是参数问题 → 返回 None，交给上层回退 nmap/内置
        _stub_run.reply = [(1, "", "boom")]
        assert ps.fscan_scan("h.test", "10.0.0.1", [80], binary="fscan") is None
        # ⑤ 统计行说 0 → 空结果（**确实没有**，不必白跑一遍 nmap）
        _stub_run.reply = [(0, "[*] 扫描完成，发现 0 个开放端口\n", "")]
        assert ps.fscan_scan("h.test", "10.0.0.1", [80], binary="fscan") == []
        # ⑥ 解析数与统计行不符 → None，绝不静默漏报（宁可白跑兜底，也不漏端口）
        _stub_run.reply = [(0, "[+] 10.0.0.1:80 open\n[*] 扫描完成，发现 2 个开放端口\n", "")]
        assert ps.fscan_scan("h.test", "10.0.0.1", [80], binary="fscan") is None
        #    没有统计行 → 无法交叉校验，同样交回兜底（老版本/未来版本换格式时安全）
        _stub_run.reply = [(0, "[*] 10.0.0.1:80 some-svc\n", "")]
        assert ps.fscan_scan("h.test", "10.0.0.1", [80], binary="fscan") is None
        # ⑦ `[+]` 行 title 里的"跳转目标 URL"不能被当成本机开放端口（正则行首锚定）
        _stub_run.reply = [(0, "[+] http://10.0.0.1:80  code:302 len:1  "
                              "title:Redirecting to http://10.0.0.9:9999/x\n"
                              "[*] 扫描完成，发现 1 个开放端口\n", "")]
        got = ps.fscan_scan("h.test", "10.0.0.1", [80], binary="fscan")
        assert [r["port"] for r in got] == [80], got

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
          "fscan 强制 -np -nobr -nopoc（老版本回退仍保留 -np -nobr）；"
          "2.2.1 真实输出 8/8 全解析 + 统计行交叉校验（数目不符即回退，杜绝静默漏报）")

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

    def _fake_run_cmd(argv, cwd=None, timeout=None, throttle=None):
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

    def _fake_scan_host(host, ip, ports, timeout=1.0, workers=64, banner=True, stopped=None,
                        throttle=None):
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
    # 截图必须排在 probe（以及后来的 cert）**之后** —— 它要拿存活站点当输入。
    # 精确顺序由 [1b] 断言，这里只守"在 probe 之后"这个不变量。
    assert STAGE_ORDER.index("screenshot") > STAGE_ORDER.index("probe"), "截图应在 probe 之后"
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
    # (续13) 任务级点名 `screenshot_on`：策略级仍是默认关，但"本次任务要截图"必须生效 ——
    # 只认策略开关时，用户在新建任务里勾了「截图」却被静默跳过，页面上永远没有缩略图。
    _n5j = len(rec.lines)
    # 策略级仍是关（默认值）、且把浏览器指到不存在的路径 —— 既证明门控放行，又不会真拉起浏览器
    _shot3_cfg = copy.deepcopy(settings)
    _shot3_cfg["screenshot"] = {"enabled": False, "browser": "no-such-browser-xyz"}
    shot_ctx3 = StageContext(tid, "smoke-shot3", parse_lines([targets]), ["screenshot"],
                            {"screenshot_on": True},
                            _shot3_cfg, Path(_TMPDIR) / "shot3", rec)
    PipelineRunner(shot_ctx3).run()
    assert not any("未启用" in x for x in rec.lines[_n5j:]), rec.lines[_n5j:]
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
    print("[5j] 站点截图 ok: 阶段注册/门控(策略关·任务级 screenshot_on 生效)/路由/防穿越/缩略图"
          "（真实截图 3.1s 已在实机验证）")

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

    # 3c) **端到端真跑一次浅扫**：钉住"浅扫真的能扫出高价值路径"。
    #     3 / 3b 把扫描实现桩掉了，只验"走了哪一档"和"取词是不是超集"；而本轮那个缺陷
    #     （深扫漏掉浅扫已命中的 .env / .git/config）恰恰**只有真跑才暴露得出来** ——
    #     取词顺序对了，软 404 基线过滤、状态门（只认 200/301/302/403）仍可能把命中吃掉。
    #     所以这里不桩 `_builtin_scan`，只对 `http_request` 做计数包装（请求真发到 8765 靶场），
    #     写法沿用 [5e](7)：记录型 logger + StageContext + PipelineRunner + dirmap 指到不存在的
    #     相对路径强制走内置 + offline（不拉任何外部工具）。
    #     靶场是 smoke 自带的 smoke_root，里面**确实有** .env 与 .git/config 两个"泄露"样本。
    _e2e_cfg = copy.deepcopy(settings)
    _e2e_cfg["dirscan"] = dict(_e2e_cfg.get("dirscan") or {}, mode="quick")
    _e2e_cfg["tools"]["dirmap"]["script"] = "tools/does-not-exist.py"
    _e2e_sent = []
    _e2e_orig_http = _ds_mod.http_request

    def _e2e_http(u, **kw):
        _e2e_sent.append(str(u))
        return _e2e_orig_http(u, **kw)          # 真发请求，只做计数

    _e2e_tid = db.create_task("smoke-dir-e2e", targets, ["dirscan"], {"offline": True})
    _e2e_wd = Path(_TMPDIR) / f"dir-e2e_{_e2e_tid}"
    _e2e_wd.mkdir(parents=True, exist_ok=True)
    _e2e_ctx = StageContext(_e2e_tid, "smoke-dir-e2e", parse_lines([targets]), ["dirscan"],
                            {"offline": True}, _e2e_cfg, _e2e_wd, rec)
    _e2e_ctx.results["sites"] = [{"url": targets, "host": "127.0.0.1", "tech": "",
                                  "title": "E2E", "length": 123}]
    _e2e_cap = int((_e2e_cfg.get("dirscan") or {}).get("quick_max_paths", 150) or 0)
    _ds_mod.http_request = _e2e_http
    try:
        PipelineRunner(_e2e_ctx).run()
    finally:
        _ds_mod.http_request = _e2e_orig_http
    _e2e_paths = [str(d.get("path") or "") for d in (_e2e_ctx.results.get("dirs") or [])]
    assert any(p.endswith("/.env") for p in _e2e_paths), f"浅扫没扫出 .env：{_e2e_paths[:20]}"
    assert any(p.endswith("/.git/config") for p in _e2e_paths), \
        f"浅扫没扫出 .git/config：{_e2e_paths[:20]}"
    assert len(_e2e_paths) >= 2, _e2e_paths
    assert db.list_dirs(_e2e_tid), "命中必须入库（否则结果页看不到）"
    # 请求量受控：字典路径 ≤ quick_max_paths；软 404 基线**每站恰好 3 个探针**。
    # 这里钉成等号（不是 ≤）—— 基线是多样本、每站只需算一次，曾经因为
    # `_builtin_scan._baseline` 的惰性字典没做同步，20 个线程同时 miss 就各算一遍，
    # 单站点 3 个探针膨胀成 27~36 个。写成上界等于把这个回归放走，所以必须是精确值。
    _e2e_probes = [u for u in _e2e_sent if "ctfscan-none" not in u]
    _e2e_base = len(_e2e_sent) - len(_e2e_probes)
    _e2e_sites = len({s["url"] for s in (_e2e_ctx.results.get("sites") or [])})
    assert 0 < len(_e2e_probes) <= _e2e_cap, (len(_e2e_probes), _e2e_cap)
    assert _e2e_base == 3 * _e2e_sites, (
        _e2e_base, _e2e_sites, "软 404 基线必须每站恰好 3 个探针（并发下不得重复计算）")
    _e2e_note = (f"端到端浅扫 {len(_e2e_paths)} 条命中（.env 与 .git/config 都在），"
                 f"请求 {len(_e2e_sent)} 个 = 字典 {len(_e2e_probes)}（≤{_e2e_cap}）"
                 f" + 软404基线 {_e2e_base}（= 3 × {_e2e_sites} 站点）")

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
    print(f"[5p-3c] {_e2e_note}")

    # (5q) 续10：环境变量路径归一化（`scanner.config.env_path`）。
    #      真实踩过的坑：Git Bash 里 `export CTFSCANNER_DB="$PWD/logs/x.db"` 传进来的是
    #      `/c/Users/...`，Windows 的 pathlib 会把它解析成"当前盘符根下的 c 目录" ——
    #      测试库被建到盘符根，`rel_display()` 还会打印出缺了盘符的残缺路径。
    #      光清一次目录只治标（多会话并行必然再踩），归一必须做在入口；
    #      **同一份断言在 Linux 上也要通过**：那里 `/d/tmp` 就是普通目录，绝不能当盘符翻译。
    from scanner.config import env_path as _env_path
    # 源码红线检查禁止出现"带引号的盘符路径"字面量，期望值一律用拼接构造
    _SEP = "\\" if os.name == "nt" else "/"
    _fallback = "logs/x.db"

    # 1) 未设置 / 空值 / 纯空白 / 只有一对引号 → 回落默认值
    assert _env_path("CTFSCANNER_SMOKE_UNSET_XYZ", _fallback) == Path(_fallback)
    for _blank in ("   ", '""', "''"):
        os.environ["CTFSCANNER_SMOKE_BLANK"] = _blank
        assert _env_path("CTFSCANNER_SMOKE_BLANK", _fallback) == Path(_fallback), _blank
    os.environ.pop("CTFSCANNER_SMOKE_BLANK", None)

    # 2) 外层成对引号要被剥掉（用户从命令行复制路径时常带引号）
    _q_path = str(ROOT / "logs" / "q.db")
    os.environ["CTFSCANNER_SMOKE_QUOTED"] = '"' + _q_path + '"'
    assert str(_env_path("CTFSCANNER_SMOKE_QUOTED", _fallback)) == _q_path, \
        _env_path("CTFSCANNER_SMOKE_QUOTED", _fallback)

    # 3) 盘符式 POSIX 路径：Windows 归一成盘符形态；**Linux 原样保留**
    os.environ["CTFSCANNER_SMOKE_DRIVE"] = "/d/tmp/x"
    _got = str(_env_path("CTFSCANNER_SMOKE_DRIVE", _fallback))
    if os.name == "nt":
        assert _got == "D:" + _SEP + "tmp" + _SEP + "x", _got
    else:
        assert _got == "/d/tmp/x", f"Linux 上 /d/... 是普通目录，不该被当成盘符：{_got}"
    # 只有盘符没有路径（`/c`）也要归一成盘符根，而不是退化成相对路径 `\c`
    os.environ["CTFSCANNER_SMOKE_DRIVE2"] = "/c"
    _got2 = str(_env_path("CTFSCANNER_SMOKE_DRIVE2", _fallback))
    if os.name == "nt":
        assert _got2 == "C:" + _SEP and Path(_got2).is_absolute(), _got2
    else:
        assert _got2 == "/c", _got2

    # 4) 非盘符式路径两种平台都不动（`/foo/bar` 不是盘符；相对路径保持相对）
    for _plain in ("/foo/bar", "logs/x.db", str(ROOT / "logs")):
        os.environ["CTFSCANNER_SMOKE_PLAIN"] = _plain
        assert str(_env_path("CTFSCANNER_SMOKE_PLAIN", _fallback)) == str(Path(_plain)), _plain

    # 5) 真实锚点：本脚本靠这两个环境变量做隔离，归一化后仍必须落在测试临时目录内
    assert str(LOGS_DIR) == str(_TMPDIR), (LOGS_DIR, _TMPDIR)
    assert str(db.DB_PATH).startswith(str(_TMPDIR)), db.DB_PATH
    _plat = "Windows 归一成盘符" if os.name == "nt" else "Linux 原样保留"
    print(f"[5q] 环境变量路径归一化 ok: 空值/引号回落默认 / 盘符式 POSIX 路径 {_plat} / "
          f"普通路径不动 / LOGS_DIR 与 DB_PATH 仍在测试临时目录（os.name={os.name}）")


    # (5r) P1-1 误报复核工作流：状态归一 / 单条与批量打标 / 台账计数 / 列表筛选 /
    #      报告"误报移出结论、单独成节"。全部是纯数据层断言（GUI 只做透传，见 [7] 路由检查）。
    _rv = db.REVIEW_STATES
    assert _rv == ("", "confirmed", "false_positive"), _rv
    # 归一：只认两种结论，其余（含 None / 大小写 / 未知值 / 空白）一律落回"待复核"
    assert db.norm_review("CONFIRMED") == "confirmed" and db.norm_review(" false_positive ") \
        == "false_positive"
    for _bad in (None, "", "x", "pending", "true", 0):
        assert db.norm_review(_bad) == "", _bad

    _rv_tid = db.create_task("smoke-review", "10.2.2.2", ["vulnscan"], {})
    for _i, _sev in enumerate(("high", "high", "medium")):
        db.insert_vuln(_rv_tid, {"target": f"http://10.2.2.2/{_i}", "name": f"rule-{_i}",
                                 "severity": _sev, "poc_id": f"p{_i}"})
    _rows = db.list_vulns(task_id=_rv_tid, limit=10)
    assert len(_rows) == 3 and all((r["review"] or "") == "" for r in _rows), _rows
    assert db.review_counts(_rv_tid) == {"pending": 3, "confirmed": 0, "false_positive": 0}

    # 单条：带备注的误报；不存在的 id 必须返回 0（不做全表兜底）
    _fp_id, _ok_id = _rows[0]["id"], _rows[1]["id"]
    assert db.set_vuln_review(_fp_id, "false_positive", "统一 404 页面，非漏洞") == 1
    assert db.set_vuln_review(_ok_id, "confirmed", "手工复现成功") == 1
    assert db.set_vuln_review(99999999, "confirmed") == 0
    # note=None 表示"只改状态、不动备注"（前端行内下拉切换走的就是这条）
    assert db.set_vuln_review(_ok_id, "") == 1
    _okrow = [r for r in db.list_vulns(task_id=_rv_tid, review="pending") if r["id"] == _ok_id][0]
    assert _okrow["review_note"] == "手工复现成功", "note=None 不该清掉已有备注"
    db.set_vuln_review(_ok_id, "confirmed")

    _c = db.review_counts(_rv_tid)
    assert _c == {"pending": 1, "confirmed": 1, "false_positive": 1}, _c
    assert len(db.list_vulns(task_id=_rv_tid, review="false_positive")) == 1
    assert len(db.list_vulns(task_id=_rv_tid, review="pending")) == 1
    assert len(db.list_vulns(task_id=_rv_tid, review="1")) == 1, '"1" 应归一为待复核'
    assert len(db.list_vulns(task_id=_rv_tid)) == 3, "review=None 必须返回全部"

    # 批量：混入非法 id 要整体忽略，合法 id 照改
    assert db.bulk_set_vuln_review([_fp_id, _ok_id, "not-an-id"], "", "退回待复核") == 2
    assert db.review_counts(_rv_tid) == {"pending": 3, "confirmed": 0, "false_positive": 0}
    assert db.bulk_set_vuln_review([], "confirmed") == 0
    assert db.bulk_set_vuln_review([_fp_id], "false_positive", "误报：WAF 拦截页") == 1

    # 报告：误报不进"潜在漏洞"与概览，但仍出现在文末专门的"已判误报"小节（可追溯）
    _md = generate(_rv_tid)
    assert _md and "## 潜在漏洞" in _md
    assert "| 0 | 0 | 0 | 0 | 0 | 2 |" in _md, "概览的潜在漏洞列应为 2（3 条里排除 1 条误报）"
    assert "人工复核台账：已确认 0 ｜ 待复核 2 ｜ 已判误报 1" in _md
    assert "（误报不计入上表，见文末附录）" in _md
    assert "## 已判误报（人工复核排除）" in _md
    _tbl = _md.split("## 潜在漏洞")[1].split("## 已判误报")[0]
    _app = _md.split("## 已判误报（人工复核排除）")[1]
    assert "rule-2" not in _tbl and "rule-0" in _tbl and "rule-1" in _tbl, _tbl
    assert "rule-2" in _app and "rule-0" not in _app, "误报小节只应列已判误报的那一条"
    assert "误报：WAF 拦截页" in _app, "判误报的理由（复核备注）必须进附录留痕"
    print("[5r] 误报复核工作流 ok: 状态归一(未知值→待复核)/单条与批量打标(note=None 保留备注，"
          "非法 id 不误伤)/台账计数与 review 三态筛选/报告误报移出结论并单独成节")


    # (5s) P1-2 POC 置信度分层：由"来源 + 匹配器结构"推导（不靠人手填）+ 批量开关按层筛选
    assert db.CONF_ORDER == ("low", "medium", "high")
    # 来源定基：内置精选=high / 用户=medium / nuclei=medium / 导入的指纹型规则=low
    assert db.poc_source("scanner/pocs/pocs/exposure-phpinfo.yaml") == "builtin"
    assert db.poc_source("config/pocs-imported/360__finger.yaml") == "imported"
    assert db.poc_source("config/nuclei-templates/x.yaml") == "nuclei"
    assert db.poc_source("config/pocs-user/mine.yaml") == "user"
    assert db.poc_source("config/whatever/x.yaml") == "other"
    # 结构降权：只判状态码（没有 word/regex/size 匹配器）的规则再降一级
    _with_word = {"http": [{"matchers": [{"type": "status", "status": [200]},
                                         {"type": "word", "words": ["phpinfo()"]}]}]}
    _only_status = {"http": [{"matchers": [{"type": "status", "status": [200]}]}]}
    assert db._has_content_matcher(_with_word) and not db._has_content_matcher(_only_status)
    assert not db._has_content_matcher({})
    assert db.poc_confidence("scanner/pocs/pocs/exposure-phpinfo.yaml", _with_word) == "high"
    assert db.poc_confidence("scanner/pocs/pocs/exposure-phpinfo.yaml", _only_status) == "medium"
    assert db.poc_confidence("config/pocs-user/mine.yaml", _only_status) == "low"
    assert db.poc_confidence("config/pocs-imported/360__finger.yaml", _only_status) == "low"
    assert db.poc_confidence("config/pocs-user/mine.yaml", _with_word) == "medium"
    # 结构分只"降级"不"升级"：导入的指纹型规则再像也不该越过 low（避免低质规则被捧成高置信）
    assert db.poc_confidence("config/pocs-imported/360__finger.yaml", _with_word) == "low"
    # meta=None（只有路径，例如从库里读老记录）→ 只按来源定级，不许崩
    assert db.poc_confidence("scanner/pocs/pocs/exposure-phpinfo.yaml") == "high"
    assert db.poc_confidence("config/pocs-imported/360__finger.yaml") == "low"

    # 7 个内置 POC 全部 **同时** 带 status + word（`matchers-condition: and`），
    # 所以按分层规则它们必须都是 high —— 这是"零误报"的实测校准依据（见 CHANGELOG 续12）
    _builtin_hi = 0
    for _p in sorted((ROOT / "scanner" / "pocs" / "pocs").glob("*.yaml")):
        _meta = engine.load_poc_file(_p)
        assert _meta.get("_status") == "ok", (_p.name, _meta.get("_error"))
        assert db.poc_confidence(str(_p.relative_to(ROOT)), _meta) == "high", _p.name
        _builtin_hi += 1
    assert _builtin_hi >= 7, f"内置 POC 数量异常：{_builtin_hi}"

    # 落库与批量筛选：confidence 每次同步按内容重算（不是用户意图，不能像 enabled 那样留存偏置）
    _cid = db.upsert_poc("config/pocs-user/conf-smoke.yaml", {
        "name": "smoke-conf", "severity": "medium", "status": "ok",
        "http": [{"matchers": [{"type": "status", "status": [200]}]}]})
    _crow = [r for r in db.list_pocs() if r["id"] == _cid][0]
    assert _crow["confidence"] == "low", _crow
    db.upsert_poc("config/pocs-user/conf-smoke.yaml", {
        "name": "smoke-conf", "severity": "medium", "status": "ok",
        "http": [{"matchers": [{"type": "status", "status": [200]},
                               {"type": "regex", "regex": ["vuln-proof"]}]}]})
    _crow = [r for r in db.list_pocs() if r["id"] == _cid][0]
    assert _crow["confidence"] == "medium", f"加了内容匹配器应升到 medium：{_crow}"
    # 批量开关按层筛选：先把 high 层全部关掉，再用 kind=diff 打开 —— 返回数必须**恰好等于**
    # high 层条数。若 confidence 过滤被忽略，这里会连 imported/nuclei 那些默认关闭的 POC
    # 一起算进来（数量明显更大），断言就会失败。（跑完把 high 层的原状态还原）
    _hi = [r for r in db.list_pocs()
           if r["status"] == "ok" and db.poc_confidence(r["path"]) == "high"]
    assert len(_hi) >= 7, f"high 层数量异常：{len(_hi)}"
    _hi_was = {r["id"]: int(r["enabled"]) for r in _hi}
    try:
        db.bulk_set_poc_enabled(False, confidence="high", only_ok=True)
        _off_hi = len([r for r in db.list_pocs() if r["status"] == "ok" and not r["enabled"]
                       and db.poc_confidence(r["path"]) == "high"])
        assert _off_hi == len(_hi), (_off_hi, len(_hi))
        assert db.bulk_set_poc_enabled(True, confidence="high", kind="diff", only_ok=True) \
            == _off_hi, "confidence 维度的批量开关必须与手工筛选结果一致"
        assert db.bulk_set_poc_enabled(True, confidence="high", kind="diff", only_ok=True) == 0, \
            "已经全开之后 diff 应为 0"
    finally:
        for _pid, _en in _hi_was.items():
            if _en == 0:
                db.toggle_poc(_pid)
    print(f"[5s] POC 置信度分层 ok: 来源定基(builtin=high/imported=low) + 只判状态码降一级；"
          f"{_builtin_hi} 个内置 POC 全为 high（status+word 结构）且 confidence 随同步重算、"
          f"批量开关按层筛选精确命中 {len(_hi)} 条")


    # (5o) 续8：P2-3 跨平台（Linux + Windows）**可执行**验证。
    #      这一节在 Linux 上跑就等于那次验收（同一份代码，无平台分支）——
    #      2026-09-23 已在 Ubuntu 22.04.5 / Python 3.10.12 实机跑通（含本节与 [5r]/[5s]）。
    #      同一台机器上另做的两项实机补验（不在本节断言内，结论记在这里）：
    #      ① 无头浏览器截图：`/snap/bin/chromium` 能出图（单站 0.9s / 11274 字节合法 PNG），
    #         但 **snap 版 chromium 有私有 /tmp**，产物路径若落在 /tmp 下会写失败
    #         （报 "Failed to write file"）—— 这是 snap 的沙箱限制，不是代码问题；
    #         项目默认把产物写进 logs/task_<id>/shots/，正常路径不受影响；
    #      ② fscan 真实调用：本文件 [5e-0] 的样本就是那次实机抓取的原文，
    #         8 个开放端口 8/8 全解析（老解析器只认 `[+] ip:port open`，一条不中）；
    #      仍未覆盖（如实标注）：subfinder/puredns/httpx 的适配分支（那台机器上没装，
    #      代码里全部走 shutil.which + 内置兜底，找不到只会降级、不会崩）。
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
    # P2-3 的验收口径就是"同一份脚本在 Linux 上跑出同样的 SMOKE PASS"，所以这里按运行平台
    # 自报状态：在 Linux 上跑＝实机验收达成；在 Windows 上跑只完成静态审计那一半。
    _p23 = ("本脚本正在 Linux 上运行 → P2-3 实机验收达成"
            "（2026-09-23 首验：Ubuntu 22.04.5 / Python 3.10.12）"
            if os.name == "posix" else
            "本机为 Windows → 本节只完成静态审计那一半；"
            "Linux 实机验收已于 2026-09-23 在 Ubuntu 22.04.5 上达成")
    print(f"[5o] 跨平台静态审计 ok: 编译 {len(_py)} 个源文件 / import {len(_mods)} 个模块 / "
          f"无 shell 直通·盘符路径·缺 encoding；run_cmd 127/124 与 pick_python 回退"
          f"（{_p23}）")

    # (5t) 续13：用户 2026-09-23 的四条 GUI 反馈逐条钉住 ——
    #   ① 拓展域名页签里 JS 挖掘与 FOFA 反查**交错**、看不出归类；
    #   ② 这些拓展域名「从来没有被检测」（probe/dirscan/vulnscan 的输入是存活站点，
    #      而 jsmine/osint 排在 probe 之后，同一任务里挖出来的域名赶不上本轮探测）；
    #   ③ 目录页签看不到命中页标题、默认排序没有"200 优先 + 大小降序"；
    #   ④ 站点页签永远没有截图产物（策略级默认关把任务级勾选静默吃掉了）。
    import gui.app as _gui
    from scanner import cdn as _cdn_mod, dnsq as _dnsq_mod

    # 1) 目录：`dirs.title` 落库 + 默认排序（200 优先 → 大小降序 → 有长度的在前）
    _dt = db.create_task("smoke-dirs-order", targets, ["dirscan"], {})
    db.insert_dirs(_dt, [
        {"path": "http://a.test/small", "status": 200, "length": 100, "title": "小页面",
         "note": "builtin"},
        {"path": "http://a.test/big", "status": 200, "length": 9000, "title": "大页面",
         "note": "builtin"},
        {"path": "http://a.test/.git", "status": 403, "length": 99999, "note": "builtin"},
        {"path": "http://a.test/nolen", "status": 200, "length": None, "title": "无长度",
         "note": "builtin"},
    ])
    _drows = [dict(r) for r in db.list_dirs(_dt)]
    assert [r["path"] for r in _drows] == ["http://a.test/big", "http://a.test/small",
                                           "http://a.test/nolen", "http://a.test/.git"], _drows
    assert {r["title"] for r in _drows} >= {"大页面", "小页面", "无长度"}, "命中页标题未落库"
    # dirmap 的解析行只有状态码/大小、没有响应体 → title 留空（不能因此写失败）
    db.insert_dirs(_dt, [{"path": "http://a.test/dm", "status": 200, "length": 7,
                          "note": "dirmap"}])
    assert db._query("SELECT title FROM dirs WHERE task_id=? AND note='dirmap'",
                     (_dt,), one=True)["title"] == "", "dirmap 行缺 title 时不应报错"

    # 2) 目录页签：标题列表头 + 精简后的「深度补扫」入口；跨任务 /dirs 同步补上标题列
    _dhtml = c.get(f"/tasks/{_dt}").get_data(as_text=True)
    assert "<th>大小</th><th>标题</th>" in _dhtml, "任务详情目录页签缺「标题」列"
    assert "深度补扫</button>" in _dhtml and "对本任务全部站点深度补扫" not in _dhtml, \
        "深度补扫入口未按要求精简"
    assert "<th>标题</th>" in c.get("/dirs").get_data(as_text=True), "跨任务 /dirs 缺标题列"

    # 3) 拓展域名：按来源分类排序（JS 挖掘不再与 FOFA 交错）+ `?esrc=` 只看一类
    _et = db.create_task("smoke-ext-sort", targets, ["probe"], {})
    db.insert_subdomains(_et, [
        ("zz-js.test", "js:mine"), ("aa-title.test", "osint:fofa-title"),
        ("bb-js.test", "js:mine"), ("cc-title.test", "osint:fofa-title"),
        ("own.test", "subfinder"),
    ])
    _ehtml = c.get(f"/tasks/{_et}").get_data(as_text=True)
    # 同类内"新的在前"（id 倒序），整体顺序 JS 挖掘 → FOFA·标题
    _pos = {d: _ehtml.index(d) for d in ("bb-js.test", "zz-js.test",
                                         "cc-title.test", "aa-title.test")}
    assert _pos["bb-js.test"] < _pos["zz-js.test"] < _pos["cc-title.test"] < _pos["aa-title.test"], \
        f"拓展域名未按来源分类排序（JS 与 FOFA 交错）：{_pos}"
    _jsonly = c.get(f"/tasks/{_et}?esrc=js").get_data(as_text=True)
    assert "bb-js.test" in _jsonly and "aa-title.test" not in _jsonly, "?esrc= 分类过滤失效"

    # 4) 拓展域名的三个手动处置：解析（纯 DNS）/ 送去探测（新建任务）/ 加黑名单
    #    桩掉解析器与任务线程：断言的是端点行为（回填哪些字段、建出什么任务），不是真去查 DNS
    _orig_resolve = _dnsq_mod.resolve_detail
    _orig_run_ext = _gui.run_task
    _suf = (_cdn_mod.suffixes(settings)[0] or ("cdn.example.test",))[0]
    try:
        _dnsq_mod.resolve_detail = lambda host, **kw: \
            (["edge." + _suf, host], ["93.184.216.34"], "") if host.endswith("js.test") \
            else ([], [], "nxdomain")
        _gui.run_task = lambda *a, **kw: None
        _r1 = c.post("/api/domains/resolve", data={
            "task_id": str(_et), "domain": ["zz-js.test", "aa-title.test"],
            "next": f"/tasks/{_et}"})
        assert _r1.status_code == 302, _r1.status_code
        _net = {r["domain"]: dict(r) for r in db.list_subdomains(_et)}
        assert _net["zz-js.test"]["ip"] == "93.184.216.34", _net["zz-js.test"]
        assert _net["zz-js.test"]["cdn"] == _suf, "CNAME 链里的 CDN 特征未被识别"
        assert _net["zz-js.test"]["cname"] == "zz-js.test", "CNAME 未回填"
        assert _net["aa-title.test"]["ip_note"] == "nxdomain", \
            "解析失败必须落原因（页面上据此显示『为什么没有 IP』）"

        _before = len(db.list_tasks(limit=1000))
        _r2 = c.post("/api/domains/scan-ext", data={
            "task_id": str(_et), "domain": ["zz-js.test"], "next": f"/tasks/{_et}"})
        _new_id = int(_r2.headers["Location"].rstrip("/").rsplit("/", 1)[-1])
        _new_t = db.get_task(_new_id)
        assert _new_t["stages"] == "probe,dirscan,vulnscan", _new_t["stages"]
        assert _new_t["targets"] == "zz-js.test", _new_t["targets"]
        assert f'"rescan_of": {_et}' in _new_t["options"], _new_t["options"]
        assert _re.match(r"^拓展探测-\d{4}-\d{6}$", _new_t["name"]), _new_t["name"]
        # 空勾选 → 只回站内 next，不建任务
        _r3 = c.post("/api/domains/scan-ext", data={"task_id": str(_et), "next": "/tasks"})
        assert _r3.headers["Location"] == "/tasks" and \
            len(db.list_tasks(limit=1000)) == _before + 1, "空勾选不该建出任务"

        # 加黑名单：任务详情页签用的也是同一个端点，next 只放行站内相对路径。
        # 这里把 `blacklist.add` 换成记录桩 —— 断言"端点把勾选域名交给了黑名单"，不去动真文件。
        from scanner import blacklist as _bl_mod
        _bl_calls = []
        _orig_bl_add = _bl_mod.add
        _bl_mod.add = lambda domains, st=None: (_bl_calls.append(list(domains)), len(domains))[1]
        try:
            _r4 = c.post("/api/blacklist/add", data={
                "domain": ["noise-ext.test"], "next": f"/tasks/{_et}"})
            assert _r4.headers["Location"] == f"/tasks/{_et}", _r4.headers.get("Location")
            assert _bl_calls == [["noise-ext.test"]], _bl_calls
            _r5 = c.post("/api/blacklist/add", data={"domain": ["x.test"],
                                                    "next": "https://evil.com/"})
            assert _r5.headers["Location"].startswith("/") and \
                not _r5.headers["Location"].startswith("//"), _r5.headers.get("Location")
        finally:
            _bl_mod.add = _orig_bl_add
    finally:
        _dnsq_mod.resolve_detail = _orig_resolve
        _gui.run_task = _orig_run_ext

    # 5) 截图：建任务勾了「截图」就落任务级选项（策略级开关不动）；补截图走 stage=screenshot
    _orig_run5 = _gui.run_task
    try:
        _gui.run_task = lambda *a, **kw: None
        _j5 = c.post("/api/tasks", data={"name": "smoke-shot-on", "targets": targets,
                                        "stages": ["probe", "screenshot"]}).get_json()
        assert '"screenshot_on": true' in db.get_task(_j5["id"])["options"], "勾选截图未落任务级选项"
        _j5b = c.post("/api/tasks", data={"name": "smoke-shot-off", "targets": targets,
                                          "stages": ["probe"]}).get_json()
        assert "screenshot_on" not in (db.get_task(_j5b["id"])["options"] or ""), \
            "没勾截图不该凭空多出选项"
        _r6 = c.post("/api/rescan", data={"stage": "screenshot", "target": ["http://a.test/"],
                                          "from_task": str(tid), "next": f"/tasks/{tid}"})
        _shot_tid = int(_r6.headers["Location"].rstrip("/").rsplit("/", 1)[-1])
        _shot_t = db.get_task(_shot_tid)
        assert _shot_t["stages"] == "screenshot", _shot_t["stages"]
        assert '"screenshot_on": true' in _shot_t["options"], _shot_t["options"]
        assert _re.match(r"^补扫站点截图-\d{4}-\d{6}$", _shot_t["name"]), _shot_t["name"]
    finally:
        _gui.run_task = _orig_run5
    # 站点页签：有站点却一张截图都没有时，必须说清原因 + 给「补截图」入口
    # （用户反馈的正是"站点截图为什么还没有完成"—— 页面上只留一片空白）
    _nt = db.create_task("smoke-shot-none", targets, ["probe"], {})
    db.insert_sites(_nt, [{"url": "http://a.test/", "host": "a.test", "status": 200,
                           "title": "A", "length": 10}])
    _shtml = c.get(f"/tasks/{_nt}").get_data(as_text=True)
    assert 'name="stage" value="screenshot"' in _shtml, "站点页签缺「补截图」按钮"
    assert "截图阶段策略级" in _shtml or "没找到可用的无头浏览器" in _shtml, \
        "没有截图产物时页面未说明原因"
    print("[5t] 续13 GUI 反馈修复 ok: 拓展域名按来源分类排序(?esrc= 过滤)/解析·送去探测·加黑名单"
          "三个手动端点(含 next 防跳外站)/目录 title 列与 200 优先·大小降序/目录文案精简/"
          "截图任务级 screenshot_on 生效 + 站点页补截图与原因提示")

    # 5u) 续14：sensitive.txt 签名列（A01 改为数据驱动）+ db 写操作串行化
    #     两条都是"静默失效"型收尾 —— 前者字典长期只当预留位、检查用硬编码清单；
    #     后者只靠 WAL + busy_timeout 兜并发写，出问题（database is locked）才暴露。
    sf = owasp_checks.sensitive_files(settings)
    sf_paths = [r[0] for r in sf]
    assert "/composer.json" in sf_paths and "/.htaccess" in sf_paths, \
        f"未从数据文件读到条目（签名列没生效？）：{sf_paths}"
    assert all(r[1] for r in sf), f"参与检测的行必须都带特征关键字：{sf}"
    assert all(r[2] in owasp_checks.SEVERITY_ORDER for r in sf), f"级别非法：{sf}"

    # 只有裸路径的字典＝预留位（一条可检测的行都没有）→ 回退内置清单，而不是"这条检查消失"
    bare = Path(_TMPDIR) / "sensitive-bare.txt"
    bare.write_text("/.git/config\n/.env\n# 只有路径的行是预留位\n", encoding="utf-8")
    st_bare = copy.deepcopy(settings)
    st_bare["dicts"]["sensitive"] = str(bare)
    assert owasp_checks.sensitive_files(st_bare) == owasp_checks.SENSITIVE_FILES, \
        "裸路径字典应回退内置清单（否则等于凭 200 裸判文件存在，误报会被软 404 页放大）"
    st_gone = copy.deepcopy(settings)          # 换机器/字典被删，也不能让 A01 整条失效
    st_gone["dicts"]["sensitive"] = str(Path(_TMPDIR) / "no-such-dict.txt")
    assert owasp_checks.sensitive_files(st_gone) == owasp_checks.SENSITIVE_FILES

    # 真打一次靶场：数据驱动之后 A01 仍要能命中 .git/config（读字典不许把检测读坏）
    a01 = [v for v in owasp_checks.run_all(targets, settings)
           if v["poc_id"] == "a01-sensitive-files"]
    _a01_txt = str(a01[0].get("target", "")) + str(a01[0].get("detail", "")) if a01 else ""
    assert a01 and ".git/config" in _a01_txt, a01

    # db 写锁：必须是**可重入**锁（`init_db` / `upsert_poc` 内部还会再调 `_exec`）
    assert isinstance(db._WRITE_LOCK, type(threading.RLock())), \
        "写锁必须可重入，否则嵌套调用会自锁死"
    w_errs, w_ids = [], []

    def _writer(i):
        try:
            t = db.create_task(f"smoke-w{i}", f"w{i}.test", ["probe"], {})
            w_ids.append(t)
            db.insert_subdomains(t, [(f"a{j}.w{i}.test", "smoke") for j in range(30)])
        except Exception as e:                            # pragma: no cover - 失败时记录
            w_errs.append(f"{type(e).__name__}: {e}")

    ws = [threading.Thread(target=_writer, args=(i,)) for i in range(12)]
    for t in ws:
        t.start()
    for t in ws:
        t.join()
    assert not w_errs, f"并发写库抛异常：{w_errs[:2]}"
    assert len(set(w_ids)) == 12 and None not in w_ids, f"并发建任务 id 异常：{sorted(w_ids)}"
    n_sub = db._query("SELECT COUNT(*) c FROM subdomains WHERE source='smoke'", (), one=True)["c"]
    assert n_sub == 12 * 30, f"并发写入丢行：期望 {12 * 30}，实际 {n_sub}"
    print(f"[5u] 续14 ok: sensitive.txt 签名列数据驱动 A01（裸路径/字典缺失回退内置清单，"
          f"靶场仍命中 .git/config）+ db 写锁串行化（12 线程 × 31 次写零异常、{n_sub} 行不丢）")

    # 5v) 续14：TLS 证书取证（cert 阶段 + certs 表 + 「SSL 证书」页签）
    #     为什么不用 `ssl.getpeercert()` 的"结构化"分支做断言：它在 CERT_NONE 下返回空 dict，
    #     而自签/过期恰恰是 CTF 里最常见的情形 —— 所以这里断言的是**自写 DER 解析**的结果。
    #     夹具是一对固定的自签证书与私钥（PEM 内联，见下），因此本段**零外部依赖、可离线跑**：
    #     ① 直接解析内联 PEM（覆盖 SAN / 序列号补位 / 自签判定 / 过期天数）；
    #     ② 起一个真的 TLS 监听端口，用 certs.fetch 真握手一次（覆盖网络路径与 SNI）。
    from scanner import certs as certs_mod
    from scanner.stages.cert import CertStage, pick_targets

    fixture = _TMPDIR / "smoke-cert"
    fixture.mkdir(parents=True, exist_ok=True)
    cert_pem = fixture / "cert.pem"
    key_pem = fixture / "key.pem"
    cert_pem.write_text(_CERT_PEM, encoding="ascii")
    key_pem.write_text(_KEY_PEM, encoding="ascii")

    parsed = certs_mod.parse_der(certs_mod.parse_pem(cert_pem.read_text(encoding="ascii")))
    assert parsed["cn"] == "smoke.test.lab", parsed
    assert parsed["subject"] == "CN=smoke.test.lab, O=CTFScanner Smoke, C=CN", parsed["subject"]
    assert parsed["not_before"] == "2020-01-02 03:04:05", parsed["not_before"]
    assert parsed["not_after"] == "2021-02-03 04:05:06", parsed["not_after"]
    # 序列号：DER 给正数补的 0x00 必须剥掉，否则与 `openssl x509 -serial` 对不上
    assert parsed["serial"] == "1234ABCD", parsed["serial"]
    assert parsed["sig_algo"] == "sha256WithRSA", parsed["sig_algo"]
    assert parsed["self_signed"] == 1 and parsed["expired"] == 1, parsed
    assert parsed["days_left"] is not None and parsed["days_left"] < 0, parsed["days_left"]
    assert parsed["san"] == ["smoke.test.lab", "*.smoke.test.lab", "10.9.9.9"], parsed["san"]
    assert parsed["sha256"] == ("C5:B1:A2:FE:D3:B3:1D:7D:D6:4B:9B:11:C4:38:D2:62:"
                               "1D:8F:71:9E:3C:75:52:3E:E1:F9:D6:7A:10:C4:22:B3"), parsed["sha256"]
    # 坏输入必须抛 ValueError（调用方统一只捕它；漏出 IndexError 会让整个阶段崩）
    for bad_der in (b"", b"\x02\x01\x01", b"\x30\x03\x30\x01"):
        try:
            certs_mod.parse_der(bad_der)
            raise AssertionError(f"坏 DER 未抛错：{bad_der!r}")
        except ValueError:
            pass

    # 真握手一次（127.0.0.1 上临时 TLS 服务；端口 0 让系统分配，避免占端口）
    import socket as _socket
    import ssl as _ssl
    _sctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
    _sctx.load_cert_chain(str(cert_pem), str(key_pem))
    _srv = _socket.socket()
    _srv.bind(("127.0.0.1", 0))
    _srv.listen(4)
    _tls_port = _srv.getsockname()[1]

    def _tls_serve():
        # 一直服务到套接字关闭为止：下面除了两次 `fetch()`，还要让 cert 阶段再握一次手，
        # 只接受固定次数的话阶段那一步会撞上"连接被拒绝"，变成假失败。
        while True:
            try:
                _conn, _ = _srv.accept()
            except OSError:                                # 套接字已关 → 收工
                return
            try:
                with _sctx.wrap_socket(_conn, server_side=True) as _s:
                    _s.recv(1)
            except Exception:                              # pragma: no cover - 收尾竞态
                pass

    threading.Thread(target=_tls_serve, daemon=True).start()
    got, err = certs_mod.fetch("127.0.0.1", _tls_port, timeout=5)
    assert err == "" and got, err
    assert (got["cn"], got["serial"]) == ("smoke.test.lab", "1234ABCD"), got
    got_sni, err_sni = certs_mod.fetch("127.0.0.1", _tls_port, timeout=5,
                                       server_hostname="smoke.test.lab")
    assert err_sni == "" and got_sni["san"] == parsed["san"], (err_sni, got_sni)
    # 明文端口 / 连不上：必须**优雅返回错误串**而不是抛异常（阶段靠它写一行日志继续跑）
    _bad, _berr = certs_mod.fetch("127.0.0.1", 1, timeout=3)
    assert _bad is None and _berr, _berr

    # 挑目标：https 无条件；非 https 只有端口命中 tls_ports 才试；同 host:port 去重
    _sites = [{"url": "https://a.test/", "host": "a.test", "port": 443},
              {"url": "http://a.test/", "host": "a.test", "port": 443},      # 同 host:port → 去重
              {"url": "http://b.test:8443/", "host": "b.test", "port": 8443},  # 命中 tls_ports
              {"url": "http://c.test:8080/", "host": "c.test", "port": 8080},  # 明文 → 不试
              {"url": "http://d.test/", "host": "", "port": 80}]              # 无 host → 跳过
    _picked = pick_targets(_sites, {443, 8443, 9443})
    assert [p[1:] for p in _picked] == [("a.test", 443), ("b.test", 8443)], _picked

    # 门控：策略级默认关（且任务级没点名）时，**一个请求都不发**
    cert_settings = copy.deepcopy(settings)
    cert_settings["cert"] = {"enabled": False, "max_sites": 5, "timeout": 3}
    cv_tid = db.create_task("smoke-cert-off", targets, ["cert"], {"offline": True})
    cv_wd = Path(_TMPDIR) / f"cert_off_{cv_tid}"
    cv_wd.mkdir(parents=True, exist_ok=True)
    cv_n0 = len(rec.lines)
    cv_ctx = StageContext(cv_tid, "smoke-cert-off", parse_lines([targets]), ["cert"],
                          {"offline": True}, cert_settings, cv_wd, rec)
    cv_ctx.results["sites"] = [dict(_sites[0])]
    CertStage(cv_ctx).run()
    assert not db.list_certs(cv_tid), "策略关且未点名时不该取证"
    assert any("未启用" in l for l in rec.lines[cv_n0:]), rec.lines[cv_n0:]

    # 阶段真跑（任务级点名 cert_on）：对真站点握手 → 落库 + 写 certs.txt + 页签/报告可见
    cv2_tid = db.create_task("smoke-cert-on", f"127.0.0.1:{_tls_port}", ["cert"],
                             {"offline": True, "cert_on": True})
    cv2_wd = Path(_TMPDIR) / f"cert_on_{cv2_tid}"
    cv2_wd.mkdir(parents=True, exist_ok=True)
    cv2_ctx = StageContext(cv2_tid, "smoke-cert-on", parse_lines([f"127.0.0.1:{_tls_port}"]),
                           ["cert"], {"offline": True, "cert_on": True}, cert_settings,
                           cv2_wd, rec)
    # 站点用 https URL，等价于 probe 探到加密站点（阶段只认 URL 前缀与端口）
    cv2_ctx.results["sites"] = [{"url": f"https://127.0.0.1:{_tls_port}/",
                                 "host": "127.0.0.1", "port": _tls_port, "status": 200}]
    CertStage(cv2_ctx).run()
    _rows = db.list_certs(cv2_tid)
    assert len(_rows) == 1 and _rows[0]["cn"] == "smoke.test.lab", [dict(r) for r in _rows]
    assert _rows[0]["source"] == "tls" and _rows[0]["expired"] == 1
    _ctxt = (cv2_wd / "certs.txt").read_text(encoding="utf-8", errors="replace")
    assert "host:port\tcn\t" in _ctxt and "smoke.test.lab" in _ctxt, _ctxt[:200]
    _srv.close()                                           # 握手到此为止，收掉夹具服务
    # 页签与报告：库里有一条证书时，任务详情要出现「SSL 证书」页签，报告要有对应小节
    _dcert = c.get(f"/tasks/{cv2_tid}").get_data(as_text=True)
    assert "SSL 证书" in _dcert and "smoke.test.lab" in _dcert, "任务详情缺「SSL 证书」页签内容"
    _rcert = generate(cv2_tid)
    assert "## TLS 证书" in _rcert and "smoke.test.lab" in _rcert, "报告缺 TLS 证书小节"
    # 没有证书时页签要**说清原因**（策略关 / 无 https 或加密端口站点 / 取了但失败）
    _nohtm = c.get(f"/tasks/{cv_tid}").get_data(as_text=True)
    assert "SSL 证书" in _nohtm and "cert 阶段默认关闭" in _nohtm, "空页签未说明原因"
    # 重启任务会清空资产 → ASSET_TABLES 必须包含 certs，否则旧证书会残留成"幽灵资产"
    assert "certs" in db.ASSET_TABLES, db.ASSET_TABLES
    db.clear_task_assets(cv2_tid)
    assert not db.list_certs(cv2_tid), "清空资产没清掉证书"
    # 排序：已过期 + 自签的必须排在正常证书**前面**（默认视图要一眼看到异常项）
    _sort_tid = db.create_task("smoke-cert-sort", "x.test", ["cert"], {})
    db.insert_certs(_sort_tid, [
        {"host": "ok.test", "port": 443, "cn": "ok.test", "not_after": "2099-01-01 00:00:00",
         "days_left": 20000, "expired": 0, "self_signed": 0, "san": [], "source": "tls"},
        {"host": "exp.test", "port": 443, "cn": "exp.test", "days_left": -5,
         "expired": 1, "self_signed": 0, "san": [], "source": "tls"},
        {"host": "self.test", "port": 443, "cn": "self.test", "days_left": 900,
         "expired": 0, "self_signed": 1, "san": [], "source": "tls"}])
    assert [r["host"] for r in db.list_certs(_sort_tid)] == \
        ["exp.test", "self.test", "ok.test"], [r["host"] for r in db.list_certs(_sort_tid)]
    # 建任务勾选 cert 阶段 → 任务级 cert_on（与 screenshot_on 同一套"勾了就有用"语义）。
    # `/api/tasks` 会真的 `_spawn` 后台线程跑流水线，这里只验"选项落没落"，所以先打桩。
    _orig_run5v = _gui.run_task
    try:
        _gui.run_task = lambda *a, **kw: None
        _j5v = c.post("/api/tasks", data={"name": "smoke-cert-pick", "targets": targets,
                                          "stages": ["probe", "cert"]}).get_json()
        assert '"cert_on": true' in (db.get_task(_j5v["id"])["options"] or ""), \
            db.get_task(_j5v["id"])["options"]
        _j5v2 = c.post("/api/tasks", data={"name": "smoke-cert-nopick", "targets": targets,
                                           "stages": ["probe"]}).get_json()
        assert "cert_on" not in (db.get_task(_j5v2["id"])["options"] or ""), \
            "没勾 cert 不该凭空多出选项"
    finally:
        _gui.run_task = _orig_run5v
    print("[5v] 续15 ok: TLS 证书取证（内联夹具解析 CN/SAN/序列号剥补位/自签/过期 + "
          "127.0.0.1 真握手与 SNI + 门控关零请求 + 落库/certs.txt/「SSL 证书」页签/报告小节 + "
          "清空资产覆盖 certs + 异常优先排序 + 勾选即 cert_on）")

    # [5w] 续16：报告三格式（MD / HTML / PDF）+ 漏洞趋势统计
    # 造一个"什么节都有"的任务：站点（标题带 XSS 载荷）/ 目录 / 端口 / C 段 / 证书 /
    # 漏洞（含已判误报）/ 线索 —— HTML 的每一节都要能被断言到，空数据只会掩盖漏渲染。
    _XSS = '<script>alert(1)</script>"onx'
    w_tid = db.create_task("smoke-report-formats", targets, ["probe"], {"offline": True})
    db.insert_sites(w_tid, [{"url": "http://w.test/", "host": "w.test", "port": 80,
                             "status": 200, "title": _XSS, "server": "nginx <b>",
                             "tech": "php", "source": "probe"}])
    db.insert_dirs(w_tid, [{"site_url": "http://w.test/", "path": "/.env", "status": 200,
                            "length": 21, "title": _XSS}])
    db.insert_ports(w_tid, [{"host": "w.test", "ip": "10.0.0.9", "port": 22,
                             "service": "ssh", "banner": "SSH-2.0 " + _XSS}])
    db.insert_csegs(w_tid, [{"segment": "10.0.0.0/24", "ip": "10.0.0.9",
                             "domains": ["a.test", "b.test"], "count": 2}])
    db.insert_certs(w_tid, [{"url": "https://w.test/", "host": "w.test", "port": 443,
                             "cn": "w.test", "issuer": "CN=w.test", "expired": 1,
                             "self_signed": 1, "days_left": -3, "san": ["w.test"],
                             "sig_algo": "sha256WithRSA", "sha256": "AA:BB", "source": "tls"}])
    db.insert_vuln(w_tid, {"target": "http://w.test/", "poc_id": "smoke-xss", "name": _XSS,
                           "severity": "high", "owasp": "A03", "evidence": _XSS})
    db.insert_vuln(w_tid, {"target": "http://w.test/", "poc_id": "smoke-fp",
                           "name": "复核掉的这条", "severity": "low"})
    _fp_id = [v["id"] for v in db.list_vulns(task_id=w_tid, limit=50)
              if v["poc_id"] == "smoke-fp"][0]
    assert db.set_vuln_review(_fp_id, "false_positive", "统一 200 的软 404") == 1
    db.insert_leads(w_tid, [{"kind": "intel", "code": "CVE-2021-44228", "title": "Log4Shell",
                             "target": "w.test", "matched": "tech:log4j",
                             "level": "high", "source": "kev"}])

    _wmd = generate(w_tid)
    _whtml = generate_html(w_tid)
    # 三个格式必须**看到同一批数据**：MD 里有的小节 HTML 里也要有（避免格式间漂移）。
    for _sec in ("潜在漏洞", "存活站点", "开放端口", "C 段视野", "TLS 证书", "目录发现", "线索",
                 "已判误报"):
        assert f"<h2>{_sec}" in _whtml, f"HTML 报告缺小节：{_sec}"
        assert _sec in _wmd, f"MD 报告缺小节：{_sec}"
    assert "漏洞趋势统计" in _whtml, "HTML 报告缺级别分布"
    assert db.vuln_trend()["by_severity"]["high"] >= 1
    # **安全断言**：目标可控的内容（标题/banner/证据）进 HTML 必须被转义 ——
    # 报告是"打开就会执行 JS"的交付物，漏一处就是反射型 XSS。
    assert "<script>alert(1)</script>" not in _whtml, "站点标题未转义（XSS）"
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in _whtml, "转义结果不是 HTML 实体"
    assert 'SSH-2.0 &lt;script&gt;' in _whtml, "banner 未转义"
    assert "&quot;onx" in _whtml, "双引号未转义（可逃出属性/文本）"
    # 自包含单文件：不引任何外部资源（离线现场也要能看）
    assert "http://" not in _whtml.split("</head>")[0], "HTML 头部引了外部资源"
    assert "<link" not in _whtml and "<script" not in _whtml, "HTML 报告不该有外链/脚本标签"

    # 趋势统计口径：**已判误报不计入**（否则复核过的噪声会在趋势里反复出现）
    _tr = db.vuln_trend()
    assert _tr["review"]["false_positive"] >= 1, _tr["review"]
    _row = [r for r in _tr["recent"] if r["task_id"] == w_tid][0]
    assert _row["high"] == 1 and _row["low"] == 0 and _row["total"] == 1, _row
    # 未知级别归 other，不静默丢
    _o_tid = db.create_task("smoke-report-other-sev", "x.test", ["probe"], {})
    db.insert_vuln(_o_tid, {"target": "x.test", "poc_id": "p", "name": "脏级别",
                            "severity": "weird"})
    assert db.vuln_trend()["by_severity"]["other"] >= 1, "未知级别没归入 other"
    db.delete_task(_o_tid, backup=False)

    # GUI 三格式路由：md 默认、html、pdf 的失败路径都要**说清原因**（无浏览器时 400 + 原因）
    _r1 = c.get(f"/tasks/{w_tid}/export")
    assert _r1.status_code == 200 and "attachment" in _r1.headers["Content-Disposition"]
    assert ".md" in _r1.headers["Content-Disposition"] and "扫描报告" in _r1.get_data(as_text=True)
    _r2 = c.get(f"/tasks/{w_tid}/export?fmt=html")
    assert _r2.status_code == 200 and "text/html" in _r2.headers["Content-Type"]
    assert ".html" in _r2.headers["Content-Disposition"]
    assert "&lt;script&gt;" in _r2.get_data(as_text=True), "路由返回的 HTML 未转义"
    # 没有浏览器时必须 400 + 可读原因（把 browser_path 打桩成"找不到"再验；
    # `export_pdf` 里是"调用时才 import"，所以打桩模块属性即可生效）
    from scanner import screenshot as shot_mod
    _orig_bp = shot_mod.browser_path
    try:
        shot_mod.browser_path = lambda *a, **kw: ""
        _r3 = c.get(f"/tasks/{w_tid}/export?fmt=pdf")
        assert _r3.status_code == 400, _r3.status_code
        _r3t = _r3.get_data(as_text=True)
        assert "未找到可用的无头浏览器" in _r3t and "fmt=html" in _r3t, _r3t[:300]
        # CLI 侧同一函数：无浏览器也要返回 (False, 原因)，不能抛异常
        _ok, _err = export_pdf(w_tid, Path(_TMPDIR) / "w.pdf", settings)
        assert _ok is False and "无头浏览器" in _err, (_ok, _err)
    finally:
        shot_mod.browser_path = _orig_bp
    _ok2, _err2 = export_pdf(999999, Path(_TMPDIR) / "nope.pdf", settings)
    assert _ok2 is False and "任务不存在" in _err2, (_ok2, _err2)
    # 仪表盘趋势面板：页面上要能看到"漏洞趋势统计"（不美化断言，只守"渲染得出来"）
    _dash = c.get("/").get_data(as_text=True)
    assert "漏洞趋势统计" in _dash and "smoke-report-formats" in _dash, "仪表盘缺趋势面板"
    assert "已判误报不计入" in _dash, "趋势面板没写口径"
    db.delete_task(w_tid, backup=False)
    print("[5w] 续16 ok: 报告三格式（MD/HTML/PDF）与漏洞趋势统计（八节齐全 + XSS 载荷全转义 + "
          "自包含无外链 + 误报不计入趋势/未知级别归 other + 三格式路由 + 无浏览器 400 说明原因 + "
          "仪表盘趋势面板）")

    # [5x] 续17：登录态扫描（任务级 Cookie/Token）+ nuclei raw / flow / workflows 子集
    from http.server import BaseHTTPRequestHandler as _BaseHTTP
    from scanner import auth as _auth
    from scanner import utils as _utils

    # 本地"活靶"：`/a` 回 hello-AAA、`/b` 回 hello-BBB，并记录收到的路径 ——
    # raw/flow 的命中与短路都靠它证（不依赖公网，也不产生真实外部请求）。
    _hits17 = []

    class _Lab17(_BaseHTTP):
        def log_message(self, *a):
            pass

        def do_GET(self):
            _hits17.append(self.path)
            body = (b"hello-AAA" if self.path.startswith("/a")
                    else b"hello-BBB" if self.path.startswith("/b") else b"root")
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    _lab17 = ThreadingHTTPServer(("127.0.0.1", 0), _Lab17)
    _base_url17 = f"http://127.0.0.1:{_lab17.server_address[1]}"
    threading.Thread(target=_lab17.serve_forever, daemon=True).start()

    # ---- ① 登录态解析 / 掩码 / 不静默丢弃 ----
    _h, _errs = _auth.parse_headers(
        "# 注释行\n\nCookie: SESSION=abcdef123456; theme=dark\n"
        "Referer: http://x.test/a:b\nAuthorization: Bearer abcdefghijklmn\n")
    assert _errs == [] and _h["Cookie"] == "SESSION=abcdef123456; theme=dark", (_h, _errs)
    assert _h["Referer"] == "http://x.test/a:b", "值里的冒号被切掉了（应按第一个冒号切分）"
    assert len(_h) == 3, _h
    _h2, _e2 = _auth.parse_headers("没有冒号的一行\nCookie: ok\nBad Name: v\nEmpty:\n")
    assert _h2 == {"Cookie": "ok"}, (_h2, _e2)          # 合法行照常收下，非法行**不丢**进 errors
    assert len(_e2) == 3 and any("第 1 行" in e for e in _e2) and any("第 3 行" in e for e in _e2), _e2
    _, _e3 = _auth.parse_headers("\n".join(f"X-{i}: v" for i in range(25)))
    assert _e3 and f"超过 {_auth.MAX_HEADERS} 条" in _e3[0], _e3
    # 掩码：只掩敏感名，保留首尾各 3 字符便于"认出来是哪一条"；短值全星号
    assert _auth.mask_value("Cookie", "abcdef123456") == "abc******456"
    assert _auth.mask_value("Cookie", "abc") == "***"
    assert _auth.mask_value("X-Trace", "abcdef") == "abcdef", "非凭据头不该被掩码"
    assert "abcdef123456" not in _auth.summary({"Cookie": "abcdef123456"}), "摘要里出现了明文凭据"
    # inject 返回**副本**（CLI/测试复用同一份 settings，原地写会把凭据带到别的任务）
    _base_st = {"limits": {}}
    _st2 = _auth.inject(_base_st, {"Cookie": "a=1"})
    assert "_auth_headers" not in _base_st and _st2["_auth_headers"] == {"Cookie": "a=1"}
    _sauth_wd = _TMPDIR / "sauth"
    _sauth_wd.mkdir(parents=True, exist_ok=True)
    _ctx_auth = StageContext(db.create_task("smoke-auth-ctx", targets, ["probe"],
                                           {"auth": {"Cookie": "S=1"}}),
                             "smoke-auth-ctx", parse_lines([targets]), ["probe"],
                             {"auth": {"Cookie": "S=1"}}, _base_st, _sauth_wd,
                             get_logger("smoke-auth-ctx", _sauth_wd / "task.log"))
    assert _ctx_auth.settings["_auth_headers"] == {"Cookie": "S=1"}
    assert "_auth_headers" not in _base_st, "StageContext 污染了调用方的 settings"

    # ---- ② 只发目标侧：第三方接口默认不带（fail-closed） ----
    # 起一个"回显 Cookie"的本地服务，同一份 settings 分别用 auth=True / 默认打一次 ——
    # 这是"目标侧带、第三方不带"最直接的证据（比读代码可靠）。
    _saw = []

    class _EchoAuth(_BaseHTTP):
        def do_GET(self):
            _saw.append(self.headers.get("Cookie") or "")
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    _asrv = ThreadingHTTPServer(("127.0.0.1", 0), _EchoAuth)
    _aport = _asrv.server_address[1]
    threading.Thread(target=_asrv.serve_forever, daemon=True).start()
    _ast = _auth.inject({}, {"Cookie": "SESSION=zz9"})
    _utils.http_request(f"http://127.0.0.1:{_aport}/a", settings=_ast)              # 默认 auth=False
    assert _saw[-1] == "", f"第三方出口默认竟带上了目标凭据：{_saw[-1]}"
    _utils.http_request(f"http://127.0.0.1:{_aport}/b", settings=_ast, auth=True)
    assert _saw[-1] == "SESSION=zz9", f"目标侧出口没带上登录态：{_saw[-1]}"
    # 第三方调用点必须保持默认（改动它们等于把目标 Cookie 发给 crt.sh/FOFA/KEV）
    for _f, _ln in (("scanner/passive.py", 55), ("scanner/intel.py", 182),
                    ("scanner/fofa.py", 238), ("scanner/iprecon.py", 114)):
        _src = (ROOT / _f).read_text(encoding="utf-8").splitlines()[_ln - 1]
        assert "auth=True" not in _src, f"{_f}:{_ln} 是第三方接口，不该带登录态：{_src.strip()}"

    # ---- ③ POC 引擎：raw 解析 + 破坏性方法拒绝 + 端到端 ----
    _ptmp = _TMPDIR / "pocs17"
    _ptmp.mkdir(parents=True, exist_ok=True)

    def _wpoc(name, text):
        p = _ptmp / name
        p.write_text(text, encoding="utf-8")
        return p

    _p_raw = _wpoc("raw.yaml", """
id: smoke-raw
info: {name: raw e2e, severity: medium}
http:
  - raw:
      - |
        GET /a HTTP/1.1
        Host: {{Hostname}}
        Content-Length: 999

    matchers:
      - type: word
        words: ["hello-AAA"]
""")
    _m_raw = engine.load_poc_file(_p_raw)
    assert _m_raw["_status"] == "ok", _m_raw
    _items, _reasons = engine._block_requests(_m_raw["http"][0])
    assert _reasons == [] and _items[0]["method"] == "GET" and _items[0]["path"] == "/a", _items
    assert _items[0]["headers"]["Host"] == "{{Hostname}}", "Host 头被吃掉了"
    assert "Content-Length" not in _items[0]["headers"], "Content-Length 应丢弃（交给 requests 重算）"
    assert engine.run_poc_on_target(_m_raw, _base_url17, {})[0]["poc_id"] == "smoke-raw"
    # 破坏性方法：raw 的 DELETE 与普通块的 method: PUT 都要被拒，且原因可见
    _m_del = engine.load_poc_file(_wpoc("raw-del.yaml", """
id: smoke-raw-del
info: {name: del, severity: high}
http:
  - raw:
      - |
        DELETE /api/user/1 HTTP/1.1
        Host: {{Hostname}}
"""))
    assert _m_del["_status"] == "unsupported" and "DELETE" in _m_del["_error"], _m_del
    _m_put = engine.load_poc_file(_wpoc("put.yaml", """
id: smoke-put
info: {name: put, severity: low}
http:
  - method: PUT
    path: ["/x"]
    matchers: [{type: status, status: [200]}]
"""))
    assert _m_put["_status"] == "unsupported" and "PUT" in _m_put["_error"], _m_put
    # dsl 仍显式 unsupported（不能被 raw 的放开顺手带成"静默跳过"）
    _m_dsl = engine.load_poc_file(_wpoc("dsl.yaml", """
id: smoke-dsl
info: {name: d, severity: medium}
http:
  - path: ["/a"]
    dsl: [status_code == 200]
    matchers: [{type: status, status: [200]}]
"""))
    assert _m_dsl["_status"] == "unsupported" and "dsl" in _m_dsl["_error"], _m_dsl

    # ---- ④ flow 布尔子集：&&/||/!/序号与 id ----
    _p_flow = _wpoc("flow.yaml", """
id: smoke-flow
info: {name: flow e2e, severity: medium}
flow: http(1) && http(2)
http:
  - id: a
    path: ["/a"]
    matchers: [{type: word, words: ["hello-AAA"]}]
  - id: b
    path: ["/b"]
    matchers: [{type: word, words: ["hello-BBB"]}]
""")
    _m_flow = engine.load_poc_file(_p_flow)
    assert _m_flow["_status"] == "ok" and _m_flow["_flow"] == ("&&", ("ref", 1), ("ref", 2)), _m_flow
    assert engine._flow_tree("a() && (b() || !c())")[0] == (
        "&&", ("ref", "a"), ("||", ("ref", "b"), ("not", ("ref", "c"))))
    # 优先级：&& 紧于 ||
    assert engine._flow_tree("a() || b() && c()")[0][0] == "||"
    assert engine._flow_tree('template("x.yaml")')[0] is None, "含参数的引用必须判不支持"
    _hits17.clear()
    assert engine.run_poc_on_target(_m_flow, _base_url17, {})[0]["poc_id"] == "smoke-flow"
    assert _hits17 == ["/a", "/b"], f"&& 两块都要跑：{_hits17}"
    # || 短路：第一块命中就不该再打第二块（省的是真实请求额度）
    _p_or = _wpoc("flow-or.yaml", """
id: smoke-flow-or
info: {name: flow or, severity: medium}
flow: http(1) || http(2)
http:
  - path: ["/a"]
    matchers: [{type: word, words: ["hello-AAA"]}]
  - path: ["/b"]
    matchers: [{type: word, words: ["hello-BBB"]}]
""")
    _hits17.clear()
    assert engine.run_poc_on_target(engine.load_poc_file(_p_or), _base_url17, {})
    assert _hits17 == ["/a"], f"|| 未短路：{_hits17}"
    # 纯否定式成立 → **不报**（没有正向响应证据，报出来就是纯误报）
    _p_neg = _wpoc("flow-neg.yaml", """
id: smoke-flow-neg
info: {name: flow neg, severity: medium}
flow: "!http(1)"
http:
  - path: ["/missing"]
    matchers: [{type: word, words: ["NOT-THERE"]}]
""")
    _m_neg = engine.load_poc_file(_p_neg)
    assert _m_neg["_status"] == "ok", _m_neg
    assert engine.run_poc_on_target(_m_neg, _base_url17, {}) == []
    # 引用越界 / 跳过块后序号错位：装载期就标 unsupported
    _m_oob = engine.load_poc_file(_wpoc("flow-oob.yaml", """
id: smoke-flow-oob
info: {name: f, severity: medium}
flow: http(1) && http(3)
http:
  - path: ["/a"]
    matchers: [{type: status, status: [200]}]
  - path: ["/b"]
    matchers: [{type: status, status: [200]}]
"""))
    assert _m_oob["_status"] == "unsupported" and "http(3)" in _m_oob["_error"], _m_oob
    # 引用**被跳过的块** → 该引用无法解析（`http(N)` 按原始块下标判定），判 unsupported
    _m_skip = engine.load_poc_file(_wpoc("flow-skip.yaml", """
id: smoke-flow-skip
info: {name: f, severity: medium}
flow: http(1) || http(2)
http:
  - method: DELETE
    path: ["/del"]
    matchers: [{type: status, status: [200]}]
  - path: ["/b"]
    matchers: [{type: word, words: ["hello-BBB"]}]
"""))
    assert _m_skip["_status"] == "unsupported" and "http(1)" in _m_skip["_error"], _m_skip
    # 引用**可执行的块**时不受"另一块被跳过"影响：应为 ok，且跳过原因必须看得见（不静默）
    _m_skip2 = engine.load_poc_file(_wpoc("flow-skip2.yaml", """
id: smoke-flow-skip2
info: {name: f, severity: medium}
flow: http(2)
http:
  - method: DELETE
    path: ["/del"]
    matchers: [{type: status, status: [200]}]
  - path: ["/b"]
    matchers: [{type: word, words: ["hello-BBB"]}]
"""))
    assert _m_skip2["_status"] == "ok" and _m_skip2["_flow"] == ("ref", 2), _m_skip2
    assert "DELETE" in (_m_skip2["_note"] or ""), _m_skip2
    _hits17.clear()
    assert engine.run_poc_on_target(_m_skip2, _base_url17, {})[0]["poc_id"] == "smoke-flow-skip2"
    assert _hits17 == ["/b"], f"被跳过的 DELETE 块不该发出请求：{_hits17}"

    # ---- ⑤ workflows 子模板编排 + 递归保护 ----
    _m_wf = engine.load_poc_file(_wpoc("wf.yaml", """
id: smoke-wf
info: {name: wf, severity: medium}
workflows:
  - template: flow.yaml
  - subtemplates: [{tags: x}]
"""))
    assert _m_wf["_status"] == "ok" and _m_wf["_templates"] == ["flow.yaml"], _m_wf
    assert "subtemplates" in (_m_wf["_note"] or ""), "未实现的子项要标出来（不静默失效）"
    _hits17.clear()
    assert engine.run_poc_on_target(_m_wf, _base_url17, {})[0]["poc_id"] == "smoke-flow"
    _m_wf0 = engine.load_poc_file(_wpoc("wf-none.yaml", """
id: smoke-wf-none
info: {name: wf, severity: medium}
workflows:
  - subtemplates: [{tags: x}]
"""))
    assert _m_wf0["_status"] == "unsupported" and "subtemplates" in _m_wf0["_error"], _m_wf0
    # 自环必须被去重挡住（否则 A→A 会无限下钻）
    _m_loop = engine.load_poc_file(_wpoc("wf-loop.yaml", """
id: smoke-wf-loop
info: {name: loop, severity: medium}
workflows:
  - template: wf-loop.yaml
"""))
    assert _m_loop["_status"] == "ok" and engine.run_poc_on_target(_m_loop, _base_url17, {}) == []

    # ---- ⑥ CLI 与 GUI 入口 ----
    _spec_cli = importlib.util.spec_from_file_location("_smoke_cli", ROOT / "cli" / "client.py")
    _cli = importlib.util.module_from_spec(_spec_cli)
    _spec_cli.loader.exec_module(_cli)
    _orig_argv, _orig_cli_run = sys.argv, _cli.run_task

    class _CliCtx:
        results = {"subdomains": [], "sites": [], "dirs": [], "vulns": [],
                   "leads_intel": [], "leads_heuristic": []}
        workdir = _TMPDIR / "cli17"
    try:
        _cli.run_task = lambda *a, **kw: _CliCtx()
        sys.argv = ["client.py", "-t", "cli17.test", "-p", "probe", "-n", "smoke-cli17",
                    "-H", "Authorization: Bearer tok17", "--cookie", "S=1"]
        _cli.main()
        _cli_t = [t for t in db.list_tasks(limit=50) if t["name"] == "smoke-cli17"][0]
        assert '"Authorization": "Bearer tok17"' in _cli_t["options"], _cli_t["options"]
        assert '"Cookie": "S=1"' in _cli_t["options"], _cli_t["options"]
        # 非法行必须**中止**（exit 1），不能带着残缺的凭据开跑
        sys.argv = ["client.py", "-t", "cli17.test", "-p", "probe", "-n", "smoke-cli17-bad",
                    "-H", "坏的没有冒号"]
        try:
            _cli.main()
            raise AssertionError("非法请求头应中止 CLI")
        except SystemExit as _se:
            assert _se.code == 1, _se.code
    finally:
        sys.argv, _cli.run_task = _orig_argv, _orig_cli_run
    # GUI 建任务：合法→落选项（掩码后上屏）；非法→400 且列出原因
    _orig_run5x = _gui.run_task
    try:
        _gui.run_task = lambda *a, **kw: None
        _ja = c.post("/api/tasks", data={"name": "smoke-auth-gui", "targets": targets,
                                        "stages": ["probe"],
                                        "auth": "Cookie: SESSION=abcdef123456"}).get_json()
        assert '"auth"' in (db.get_task(_ja["id"])["options"] or ""), \
            db.get_task(_ja["id"])["options"]
        _jb = c.post("/api/tasks", data={"name": "smoke-auth-bad", "targets": targets,
                                         "stages": ["probe"], "auth": "乱写的一行"})
        assert _jb.status_code == 400 and "第 1 行" in _jb.get_json()["error"], _jb.get_json()
        # 补扫 / 拓展域名探测要**继承**原任务登录态（否则"复查"变成未登录视角）
        c.post("/api/rescan", data={"stage": "dirscan", "target": "http://a.test/",
                                    "from_task": str(_ja["id"])})
        _jr = [t for t in db.list_tasks(limit=50) if str(t["id"]) != str(_ja["id"])
               and f'"rescan_of": {_ja["id"]}' in (t["options"] or "")]
        assert _jr and '"auth"' in _jr[0]["options"], _jr and _jr[0]["options"]
    finally:
        _gui.run_task = _orig_run5x
    # 任务详情页：显示掩码值、**不回显明文**（含「运行配置 → 选项」那一行）
    _ahtml = c.get(f"/tasks/{_ja['id']}").get_data(as_text=True)
    # 值 `SESSION=abcdef123456`（20 字符）→ 首 3 + 星号 + 末 3 = 中部 14 个星号
    assert "登录态" in _ahtml and "SES**************456" in _ahtml, \
        "任务详情没显示掩码后的登录态"
    assert "SESSION=abcdef123456" not in _ahtml, "任务详情把明文凭据回显到页面了"
    print("[5x] 续17 ok: 登录态扫描（解析/掩码/不静默丢弃 + 目标侧带·第三方 fail-closed + "
          "CLI(-H/--cookie)/GUI/补扫继承 + 页面只显示掩码）与 nuclei raw/flow/workflows 子集"
          "（raw 解析·破坏性方法拒绝·端到端命中 + flow &&/|| 短路·纯否定不报·引用越界标 unsupported "
          "+ workflow 子模板与自环保护 + dsl 仍显式 unsupported）")

    # 5y) 批次 4：① XSS 上下文分析 ② A10 SSRF 受控回连 ③ 布尔盲注 ④ Shodan/Quake 反查
    #     ⑤ CT 日志（crt.sh）。**所有外部接口一律打桩，禁止触网**（[2c] 的历史教训）。
    import json as _json5
    import re as _re5
    import urllib.parse as _up5
    from scanner import ssrf as ssrf_mod, shodan as shodan_mod, quake as quake_mod
    from scanner import ctlog as ctlog_mod
    from scanner import utils as utils_mod
    from scanner.stages import osint as osint_mod

    _MK = owasp_checks.XSS_MARKER
    _BASE_P = owasp_checks._XSS_BASE
    _CTX_P = owasp_checks._XSS_CTX_PROBE

    # ---- ① XSS 上下文判定表（纯函数，不发请求）----
    #     同一句 payload 落在不同位置 → 不同上下文 / 不同级别，这就是"上下文分析"的全部意义。
    _tbl = [
        ("<div>hello MARK</div>", _BASE_P, "text-node", "medium", True),
        ('<input value="MARK">', _BASE_P, "dquote-attr", "medium", True),
        ("<input value='MARK'>", _BASE_P, "squote-attr", "medium", True),
        ("<input value=MARK>", _BASE_P, "unquoted-attr", "high", True),
        ('<script>var a = "MARK";</script>', _BASE_P, "js-string", "high", True),
        ("<script>var a = MARK;</script>", _BASE_P, "js-code", "high", True),
        ("<!-- MARK -->", _BASE_P, "html-comment", "low", True),
        ("<MARK class=x>", _BASE_P, "tag-name", "high", True),
    ]
    for _tpl, _p, _ctx, _sev, _ok in _tbl:
        _info = owasp_checks.classify_xss(_tpl.replace("MARK", _p), _p)
        assert _info is not None, _tpl
        assert _info["context"] == _ctx, (_tpl, _info)
        assert _info["severity"] == _sev, (_tpl, _info)
        assert _info["usable"] is _ok, (_tpl, _info)
        assert _info["verbatim"] is True and _info["label"], _info
    # 上下文探针（非原样回显）：靠"哪些定界符活着"判能不能逃逸
    _p_tbl = [
        # 双引号属性里 `"` 被转义、而 `'` 活着 —— 单引号救不了双引号属性 → 不报
        ('<input value="MARK&quot;&#39;&lt;&gt;">', "dquote-attr", False),
        ('<input value="MARK&quot;&#39;&lt;&gt;">'.replace("&#39;", "'"), "dquote-attr", False),
        # 无引号属性：`"` 被转义但 `<` `>` 活着 → 任一定界符可用即可逃逸 → 报
        ('<input value=MARK&quot;\'<>>', "unquoted-attr", True),
        # 文本节点要看 `<` 有没有活着：转义了就插不进标签 → 不报
        ("<div>MARK&quot;&#39;&lt;&gt;</div>", "text-node", False),
        ("<div>MARK&quot;&#39;<></div>", "text-node", True),
    ]
    for _tpl5, _ctx, _ok in _p_tbl:
        _html = _tpl5.replace("MARK", _MK)
        _info = owasp_checks.classify_xss(_html, _CTX_P)
        assert _info is not None and _info["context"] == _ctx, (_html, _info)
        assert _info["verbatim"] is False and _info["usable"] is _ok, (_html, _info)
    assert owasp_checks.classify_xss("<div>no reflection</div>", _BASE_P) is None
    assert owasp_checks.classify_xss("", _BASE_P) is None
    # poc_id 去重键**不能变**（`(target, poc_id)` 是唯一键，改了就等于换了一种漏洞）
    assert any(m["id"] == "a03-xss-reflect" for m in owasp_checks.CHECKS)

    # 端到端：同一句回显落在不同上下文 → 检查给出不同级别（_get 打桩，不发请求）
    _orig_get5 = owasp_checks._get

    def _stub_get(text, matcher=None):
        def _f(u, s, **kw):
            return {"status": 200, "headers": {}, "text": text if (matcher is None or matcher(u))
                    else "no", "length": len(text)}
        return _f

    try:
        owasp_checks._get = _stub_get(f'<html><script>var q = "{_BASE_P}";</script></html>')
        _v_js = owasp_checks._xss_reflect(targets, settings)
        assert _v_js and _v_js["poc_id"] == "a03-xss-reflect" and _v_js["severity"] == "high", _v_js
        assert "JS 字符串" in _v_js["detail"], _v_js["detail"]
        # 文本节点维持 medium，且证据必须写明"需该上下文的定界符未被转义"这一前提
        owasp_checks._get = _stub_get(f"<div>hello {_BASE_P}</div>")
        _v_txt = owasp_checks._xss_reflect(targets, settings)
        assert _v_txt and _v_txt["severity"] == "medium", _v_txt
        assert "文本节点" in _v_txt["detail"] and "定界符未被转义" in _v_txt["detail"], _v_txt["detail"]
        # 全转义（只有被 HTML 实体化的回显）→ 一个都不该报（这是旧逻辑最大的误报源）
        owasp_checks._get = _stub_get("<div>&lt;svg/onload=" + _MK + "&gt;</div>")
        assert owasp_checks._xss_reflect(targets, settings) is None, "全转义回显不该判成 XSS"
    finally:
        owasp_checks._get = _orig_get5

    # ---- ② A10 SSRF 受控回连（默认关 + 本机监听自证 + 外部回调不谎报）----
    assert ssrf_mod.enabled(settings) is False, "ssrf 必须默认关"
    _calls5 = []
    owasp_checks._get = lambda u, s, **kw: (_calls5.append(u), None)[1]
    try:
        assert owasp_checks._ssrf_callback(targets, settings) is None
    finally:
        owasp_checks._get = _orig_get5
    assert not _calls5, "默认关时 SSRF 检查一个请求都不该发"
    assert ssrf_mod.form_field_names('<input name="q"><input type="submit" name="go">'
                                     '<input name="Url">') == ["q", "url"]
    assert ssrf_mod.token_of_path("/abc123?x=1") == "abc123" and ssrf_mod.token_of_path("") == ""
    # 本机监听真收一次回连（127.0.0.1 自环，不是外部网络）
    with ssrf_mod.CallbackListener("127.0.0.1", 0) as _lsn:
        _tok = ssrf_mod.new_token()
        _cb = ssrf_mod.payload_url(_lsn.base_url, _tok)
        assert _cb.startswith("http://127.0.0.1:") and _cb.endswith("/" + _tok)
        _r5 = utils_mod.http_request(_cb, timeout=5)
        assert _r5 and _r5.get("status") == 200, _r5
        assert _lsn.wait(3.0) >= 1
        _h5 = _lsn.hits_for(_tok)
        assert _h5 and _h5[0]["method"] == "GET" and _h5[0]["path"].startswith("/" + _tok), _h5
        assert _lsn.hits_for("nosuchtoken") == []
    assert not [t for t in threading.enumerate()
                if t.name == "ssrf-callback" and t.is_alive()], "监听线程没关（线程泄漏）"

    _ssrf_on5 = copy.deepcopy(settings)
    _ssrf_on5["ssrf"] = {"enabled": True, "callback_base": "", "host": "127.0.0.1",
                         "port": 0, "wait_seconds": 3.0, "max_params": 3}
    _seen5 = []

    def _vuln_get(u, s, **kw):
        """模拟"服务端真的按我们给的 URL 出网"：把参数里的回调地址真的访问一次。"""
        _seen5.append(u)
        m = _re5.search(r"http://127\.0\.0\.1:(\d+)/([a-f0-9]{16})", _up5.unquote(u))
        if m:
            utils_mod.http_request(f"http://127.0.0.1:{m.group(1)}/{m.group(2)}", timeout=5)
        return {"status": 200, "headers": {}, "text": "ok", "length": 2}

    owasp_checks._get = _vuln_get
    try:
        _v_ssrf = owasp_checks._ssrf_callback(targets, _ssrf_on5)
    finally:
        owasp_checks._get = _orig_get5
    assert _v_ssrf and _v_ssrf["poc_id"] == "a10-ssrf-callback" and _v_ssrf["severity"] == "high", \
        _v_ssrf
    assert "收到 GET" in _v_ssrf["evidence"] and "127.0.0.1" in _v_ssrf["evidence"], _v_ssrf
    assert _seen5, "一个参数都没注入"
    # 外部回调基址：注入照做，但**读不到命中就绝不能伪造**
    _ssrf_ext5 = copy.deepcopy(settings)
    _ssrf_ext5["ssrf"] = {"enabled": True, "callback_base": "http://oob.invalid",
                          "max_params": 2, "wait_seconds": 0.5}
    _seen6 = []
    owasp_checks._get = lambda u, s, **kw: (_seen6.append(u),
                                            {"status": 200, "headers": {}, "text": "ok",
                                             "length": 2})[1]
    try:
        _v_ext = owasp_checks._ssrf_callback(targets, _ssrf_ext5, logger=rec)
    finally:
        owasp_checks._get = _orig_get5
    assert _v_ext is None, "外部回调模式下读不到命中，绝不能伪造命中"
    assert _seen6 and all("oob.invalid" in u for u in _seen6), _seen6

    # ---- ③ 布尔型盲注（只做恒真/恒假差分，不做延时）----
    def _blind_get(u, s, **kw):
        _len = 900 if _re5.search(r"(1=2|1'='2|\(1=2|\"1\"=\"2)", u) else 1200
        return {"status": 200, "headers": {}, "text": "x" * _len, "length": _len}

    _n5 = {"i": 0}
    owasp_checks._get = _blind_get
    try:
        _v_blind = owasp_checks._sqli_blind(targets, settings)
    finally:
        owasp_checks._get = _orig_get5
    assert _v_blind and _v_blind["poc_id"] == "a03-sqli-blind" \
        and _v_blind["severity"] == "high", _v_blind
    # 命中必须给出**对比数字**，不能只写"疑似存在"
    assert "长度差 300B" in _v_blind["evidence"] and "1200B" in _v_blind["evidence"] \
        and "900B" in _v_blind["evidence"], _v_blind["evidence"]
    # 恒真恒假一致 → 不报
    owasp_checks._get = _stub_get("same page")
    try:
        assert owasp_checks._sqli_blind(targets, settings) is None, "无差异不该判盲注"
    finally:
        owasp_checks._get = _orig_get5

    def _jitter_get(u, s, **kw):
        """页面自带抖动：恒真两次都不一样 → 必须判为不稳定而不是盲注。"""
        _n5["i"] += 1
        _len = 1000 + _n5["i"] * 500
        return {"status": 200, "headers": {}, "text": "y" * _len, "length": _len}

    owasp_checks._get = _jitter_get
    try:
        assert owasp_checks._sqli_blind(targets, settings) is None, "页面抖动不该判盲注"
        assert _n5["i"] <= owasp_checks._SQLI_BLIND_MAX_REQ, f"请求预算超了：{_n5['i']}"
    finally:
        owasp_checks._get = _orig_get5
    # 明确不做延时型：payload 表里不许出现 sleep/benchmark/waitfor
    _sql_src = (ROOT / "scanner" / "owasp" / "checks.py").read_text(encoding="utf-8")
    assert "布尔型盲注" in _sql_src
    for _pair in owasp_checks._SQLI_BLIND_PAIRS:
        assert not _re5.search(r"sleep|benchmark|waitfor|pg_sleep", _pair[0] + _pair[1], _re5.I)

    # ---- ④ Shodan / Quake favicon 反查（无 key 不发请求 + 查询串 + 阈值 + 解析）----
    assert shodan_mod.build_query(-12345) == "http.favicon.hash:-12345"
    assert quake_mod.build_query(-12345) == 'favicon: "-12345"'
    assert shodan_mod.is_black_ico(200, settings) is False \
        and shodan_mod.is_black_ico(201, settings) is True
    assert quake_mod.is_black_ico(200, settings) is False \
        and quake_mod.is_black_ico(201, settings) is True

    _nokey5 = copy.deepcopy(settings)
    _nokey5["keys"] = {"shodan": {"key": ""}, "quake": {"key": ""}}
    _net5 = {"n": 0}

    def _no_http(*a, **kw):
        _net5["n"] += 1
        raise AssertionError("无 key 时绝不能发请求")

    _orig_sh5, _orig_qk5 = shodan_mod.http_request, quake_mod.http_request
    shodan_mod.http_request = quake_mod.http_request = _no_http
    try:
        assert shodan_mod.available(_nokey5) is False and quake_mod.available(_nokey5) is False
        _e_sh = shodan_mod.search(-12345, _nokey5)[2]
        _e_qk = quake_mod.search(-12345, _nokey5)[2]
    finally:
        shodan_mod.http_request, quake_mod.http_request = _orig_sh5, _orig_qk5
    assert "未配置 shodan.key（见 config/keys.yaml）" in _e_sh, _e_sh
    assert "未配置 quake.key（见 config/keys.yaml）" in _e_qk, _e_qk
    assert _net5["n"] == 0, "无 key 时一个请求都不该发"

    _key5 = copy.deepcopy(settings)
    _key5["keys"] = {"shodan": {"key": "K"}, "quake": {"key": "K"}}
    _sh_resp = {"status": 200, "headers": {}, "text": _json5.dumps({
        "total": 7,
        "matches": [{"ip_str": "1.2.3.4", "port": 443, "hostnames": ["a.example.com"],
                     "domains": ["example.com"], "http": {"title": "T"}},
                    {"ip_str": "8.8.8.8", "port": 80}],
    })}
    shodan_mod.http_request = lambda *a, **kw: _sh_resp
    try:
        _a5, _t5, _err5 = shodan_mod.search(-1, _key5)
    finally:
        shodan_mod.http_request = _orig_sh5
    assert _err5 == "" and _t5 == 7 and len(_a5) == 2, (_err5, _t5, _a5)
    assert osint_mod._domain_of(_a5[0]) == "example.com", _a5[0]
    assert osint_mod._domain_of(_a5[1]) == "", "裸 IP 绝不能变成域名资产"

    _qk_resp = {"status": 200, "headers": {}, "text": _json5.dumps({
        "code": 0, "data": [{"ip": "5.6.7.8", "port": 8080, "domain": "b.example.com",
                             "service": {"http": {"title": "Q"}}}],
        "meta": {"pagination": {"total": 3}}})}
    _qk_seen = {}

    def _qk_http(url, **kw):
        _qk_seen.update(kw)
        return _qk_resp

    quake_mod.http_request = _qk_http
    try:
        _a6, _t6, _err6 = quake_mod.search(-1, _key5)
    finally:
        quake_mod.http_request = _orig_qk5
    assert _err6 == "" and _t6 == 3 and _a6[0]["domain"] == "b.example.com", (_err6, _t6, _a6)
    assert _qk_seen.get("method") == "POST", _qk_seen          # Quake 是 POST + JSON 体
    assert (_qk_seen.get("headers") or {}).get("X-QuakeToken") == "K", _qk_seen
    # 业务失败（配额耗尽）必须显式报错而不是静默空结果
    quake_mod.http_request = lambda *a, **kw: {"status": 200, "headers": {},
                                               "text": _json5.dumps({"code": 1,
                                                                     "message": "配额不足"})}
    try:
        assert "配额不足" in quake_mod.search(-1, _key5)[2]
    finally:
        quake_mod.http_request = _orig_qk5

    # ---- ⑤ CT 日志（crt.sh）：非 JSON/限流容错 + 通配符处理 + 默认关门控 ----
    assert ctlog_mod.enabled(settings) is False, "ctlog 必须默认关"
    assert ctlog_mod.build_url("example.com") == "https://crt.sh/?q=example.com&output=json"
    _ct5 = _json5.dumps([
        {"issuer_name": "C=US, O=Let's Encrypt, CN=R3", "common_name": "a.example.com",
         "name_value": "a.example.com\n*.b.example.com", "id": "111", "serial_number": "03a1",
         "not_before": "2020-01-01T00:00:00", "not_after": "2021-01-01T00:00:00"},
        {"issuer_name": "C=US, O=Let's Encrypt, CN=R3", "common_name": "a.example.com",
         "name_value": "a.example.com", "id": "222", "serial_number": "03a1",
         "not_before": "2020-01-01T00:00:00", "not_after": "2021-01-01T00:00:00"},
    ])
    _recs5, _e5 = ctlog_mod.parse_records(_ct5, settings)
    assert _e5 == "" and len(_recs5) == 1, (_e5, _recs5)
    _r5 = _recs5[0]
    assert _r5["entry_count"] == 2, _r5                     # 同一张证书的两条日志条目
    assert _r5["wildcard"] == 1, _r5
    assert "b.example.com" in _r5["san"] and all("*" not in d for d in _r5["san"]), _r5["san"]
    assert _r5["serial"] == "03A1" and _r5["expired"] == 1 and _r5["cn"] == "a.example.com", _r5
    assert ctlog_mod.domains_of(_recs5) == ["a.example.com", "b.example.com"]
    for _bad5 in ("", "   ", "<html><body>429 Too Many Requests</body></html>", "null", "[]"):
        _rr, _ee = ctlog_mod.parse_records(_bad5, settings)
        assert _rr == [], (_bad5, _rr)
        assert _ee or _bad5 == "[]", f"坏输入必须给出原因而不是静默成功：{_bad5!r}"

    _ct_calls = []

    def _ct_http(url, **kw):
        _ct_calls.append((url, kw))
        return {"status": 429, "headers": {}, "text": "slow down", "length": 9}

    _orig_ct5 = ctlog_mod.http_request
    ctlog_mod.http_request = _ct_http
    _ct_on5 = copy.deepcopy(settings)
    _ct_on5["ctlog"] = dict(_ct_on5.get("ctlog") or {}, enabled=True)
    try:
        _rr5, _ee5 = ctlog_mod.search("example.com", _ct_on5)
    finally:
        ctlog_mod.http_request = _orig_ct5
    assert _rr5 == [] and "429" in _ee5 and "限流" in _ee5, _ee5
    assert _ct_calls and all("auth" not in kw for _, kw in _ct_calls), "第三方出口绝不能带登录态"
    # 默认关 → 一次请求都不发
    _ct_calls.clear()
    ctlog_mod.http_request = _ct_http
    try:
        _rr6, _ee6 = ctlog_mod.search("example.com", settings)
    finally:
        ctlog_mod.http_request = _orig_ct5
    assert _rr6 == [] and "ctlog.enabled=false" in _ee6 and not _ct_calls, (_ee6, _ct_calls)

    # 三个新模块：必须走 utils.http_request，且**不许带 auth=True**（凭据红线）
    for _p5 in ("scanner/shodan.py", "scanner/quake.py", "scanner/ctlog.py"):
        _src5 = (ROOT / _p5).read_text(encoding="utf-8")
        assert "http_request" in _src5, f"{_p5} 没走统一 HTTP 出口"
        assert "auth=True" not in _src5, f"{_p5} 第三方出口不该带登录态"

    # ---- ⑤b osint 阶段接线：开关打开后真的会跑，且 crt.sh 失败只记日志不挂阶段 ----
    #      （[2c] 的老教训：纯函数测过了、阶段里没接上，表现就是"永远 0 条、日志无异常"）
    _os_tid = db.create_task("smoke-osint5y", "example.test", ["osint"], {})
    _os_cfg = copy.deepcopy(settings)
    _os_cfg["shodan"] = dict(_os_cfg.get("shodan") or {}, enabled=True)
    _os_cfg["ctlog"] = dict(_os_cfg.get("ctlog") or {}, enabled=True)
    _os_cfg["keys"] = {"shodan": {"key": "K"}}
    _stage5 = osint_mod.OsintStage
    _orig_fav5, _orig_roots5 = _stage5._favicon_hashes, _stage5._root_domains
    _stage5._favicon_hashes = lambda self, cap, workers: {12345: "http://127.0.0.1:8765/"}
    _stage5._root_domains = lambda self: ["example.test"]

    def _run_osint5(ct_http):
        _cx5 = StageContext(_os_tid, "smoke-osint5y", parse_lines(["example.test"]), ["osint"],
                            {}, _os_cfg, Path(_TMPDIR) / "osint5y", rec)
        shodan_mod.http_request = lambda *a, **kw: _sh_resp
        ctlog_mod.http_request = ct_http
        try:
            _stage5(_cx5).run()
        finally:
            shodan_mod.http_request, ctlog_mod.http_request = _orig_sh5, _orig_ct5
        return _cx5

    try:
        # crt.sh 限流：阶段照跑完，只是 CT 那一路没有产出（不抛异常、不中断）
        _cx_bad = _run_osint5(lambda url, **kw: {"status": 429, "headers": {},
                                                 "text": "slow down", "length": 9})
        assert "example.com" in _cx_bad.results["osint_domains"], _cx_bad.results["osint_domains"]
        assert not any("example.test" == d for d in _cx_bad.results["osint_domains"])
        assert not db.list_certs(_os_tid), "限流时不该写出证书"
        # crt.sh 正常：证书记录落库（source=ct）+ 域名进拓展域名
        _cx_ok = _run_osint5(lambda url, **kw: {"status": 200, "headers": {},
                                                "text": _ct5, "length": len(_ct5)})
        _doms5 = _cx_ok.results["osint_domains"]
        assert "a.example.com" in _doms5 and "b.example.com" in _doms5, _doms5
        _certs5 = [dict(r) for r in db.list_certs(_os_tid)]
        assert len(_certs5) == 1 and _certs5[0]["source"] == "ct", _certs5
        assert _certs5[0]["cn"] == "a.example.com" and _certs5[0]["expired"] == 1, _certs5
        _srcs5 = {r["source"] for r in db.list_subdomains(_os_tid)}
        assert "osint:ctlog" in _srcs5 and "osint:shodan" in _srcs5, _srcs5
        assert all("*" not in r["domain"] for r in db.list_subdomains(_os_tid)), \
            "通配符绝不能写进资产库"
    finally:
        _stage5._favicon_hashes, _stage5._root_domains = _orig_fav5, _orig_roots5

    # ---- ⑥ 新开关的三方一致：DEFAULTS ↔ settings.yaml ↔ GUI 表单/POST 映射 ----
    _def5 = _DEF if "_DEF" in dir() else __import__(
        "scanner.config", fromlist=["DEFAULTS"]).DEFAULTS
    for _sec5, _keys5 in (("ssrf", ("enabled", "callback_base", "wait_seconds", "max_params")),
                          ("shodan", ("enabled", "max_sites", "max_assets",
                                      "black_ico_threshold")),
                          ("quake", ("enabled", "max_sites", "max_assets",
                                     "black_ico_threshold")),
                          ("ctlog", ("enabled", "max_domains", "max_records",
                                     "write_certs"))):
        assert _sec5 in _def5 and _sec5 in settings, f"缺配置段 {_sec5}"
        for _k5 in _keys5:
            assert _k5 in _def5[_sec5], f"DEFAULTS.{_sec5} 缺 {_k5}"
            assert _k5 in (settings.get(_sec5) or {}), f"settings.yaml.{_sec5} 缺 {_k5}"
    assert _def5["ssrf"]["enabled"] is False and _def5["shodan"]["enabled"] is False
    assert _def5["quake"]["enabled"] is False and _def5["ctlog"]["enabled"] is False
    _sh5 = c.get("/settings").get_data(as_text=True)
    for _n5b in ("ssrf_enabled", "ssrf_callback_base", "shodan_enabled",
                 "shodan_black_ico_threshold", "quake_enabled", "quake_max_sites",
                 "ctlog_enabled", "ctlog_write_certs"):
        assert f'name="{_n5b}"' in _sh5, f"策略配置缺字段 {_n5b}"
    _cap5 = {}

    def _fake_save5(d):
        _cap5.clear()
        _cap5.update(d)
        return load_settings()

    _orig_save5 = gui_app.save_settings
    gui_app.save_settings = _fake_save5
    try:
        assert c.post("/settings", data={"min_severity": "medium", "ssrf_enabled": "1",
                                         "shodan_enabled": "1", "quake_enabled": "1",
                                         "ctlog_enabled": "1",
                                         "ctlog_write_certs": "1"}).status_code == 302
        assert _cap5["ssrf"]["enabled"] is True, _cap5.get("ssrf")
        assert _cap5["shodan"]["enabled"] is True and _cap5["quake"]["enabled"] is True
        assert _cap5["ctlog"]["enabled"] is True and _cap5["ctlog"]["write_certs"] is True
        # 未勾选 → 必须落为关闭（否则 GUI 存一次策略就把配置吃掉）
        assert c.post("/settings", data={"min_severity": "medium"}).status_code == 302
        assert _cap5["ssrf"]["enabled"] is False and _cap5["shodan"]["enabled"] is False
        assert _cap5["quake"]["enabled"] is False and _cap5["ctlog"]["enabled"] is False
    finally:
        gui_app.save_settings = _orig_save5
    # 「SSL 证书」页签要能区分 TLS 握手与 CT 日志两种来源（否则两类记录会混在一起看不懂）
    _ct_tid = db.create_task("smoke-ctlog", targets, ["osint"], {})
    db.insert_certs(_ct_tid, [
        {"url": "https://a.test/", "host": "a.test", "port": 443, "cn": "a.test",
         "issuer": "CN=R3", "not_before": "", "not_after": "", "days_left": None,
         "expired": 0, "self_signed": 0, "san": ["a.test"], "serial": "1",
         "sig_algo": "sha256WithRSA", "sha256": "AA:BB", "source": "tls"},
        {"url": "", "host": "example.com", "port": 0, "cn": "example.com",
         "issuer": "CN=R3", "not_before": "2020-01-01 00:00:00",
         "not_after": "2021-01-01 00:00:00", "days_left": -1, "expired": 1,
         "self_signed": 0, "san": ["example.com", "b.example.com"], "serial": "03A1",
         "sig_algo": "", "sha256": "", "source": "ct"},
    ])
    _ch5 = c.get(f"/tasks/{_ct_tid}").get_data(as_text=True)
    assert "<th>来源</th>" in _ch5, "「SSL 证书」页签缺来源列"
    assert "TLS 握手" in _ch5 and "CT 日志" in _ch5, "页签没区分两种证书来源"
    print("[5y] 批次4 ok: XSS 上下文判定表（8 上下文定级 + 探针定界符存活判定 + 全转义不报）"
          " + A10 SSRF 受控回连（默认关零请求 / 本机监听自证 / 外部回调不谎报 / 线程不泄漏）"
          " + 布尔盲注（恒真恒假对比数字 + 抖动不判 + 无 SLEEP）"
          " + Shodan/Quake（无 key 不发请求 + 查询串 + 阈值 + 裸 IP 收口 + POST/配额报错）"
          " + CT 日志（非 JSON/限流容错 + 通配符剥离 + 默认关门控 + 第三方不带登录态）"
          " + osint 阶段接线（限流只记日志不挂阶段 / 正常时证书落库 source=ct / 裸 IP 与通配符不入库）"
          " + 新开关三方一致（DEFAULTS/settings.yaml/GUI POST）+ 证书来源列")
    # 5z) QA 独立补测（software-qa-engineer-2 复核批次 4 时补）：
    #     ① SSRF 注入途中抛异常时 finally 仍要关监听（不留 ssrf-callback 线程）
    #     ② ctlog 更多坏输入（None / 截断 JSON / name_value=null）不抛异常且不给通配符
    #     ③ classify_xss 空 / 超长输入安全
    _ssrf_on5z = copy.deepcopy(settings)
    _ssrf_on5z["ssrf"] = {"enabled": True, "callback_base": "", "host": "127.0.0.1",
                          "port": 0, "wait_seconds": 0.5, "max_params": 3}
    _orig_http5z = ssrf_mod.http_request
    ssrf_mod.http_request = lambda *a, **kw: {"status": 200, "headers": {},
                                              "text": "<input name='url'>", "length": 20}

    def _boom_get5z(u, s, **kw):
        raise RuntimeError("boom")

    owasp_checks._get = _boom_get5z
    _raised5z = False
    try:
        owasp_checks._ssrf_callback(targets, _ssrf_on5z)
    except RuntimeError:
        _raised5z = True
    finally:
        ssrf_mod.http_request = _orig_http5z
        owasp_checks._get = _orig_get5
    assert _raised5z, "异常应当向上抛出（由 run_all 兜）"
    assert not [t for t in threading.enumerate()
                if t.name == "ssrf-callback" and t.is_alive()], "异常路径下监听线程没关"

    # ② ctlog：None / 截断 JSON / name_value=null 一律不抛异常，且不给通配符
    for _bad5z in (None, '{"issuer_name": "x"', '[{"name_value": null}]'):
        try:
            _rr5z, _ee5z = ctlog_mod.parse_records(_bad5z, settings)
        except Exception as _e5z:                       # 这里就是要它不抛
            raise AssertionError(f"parse_records 对 {_bad5z!r} 抛了异常：{_e5z!r}")
        assert isinstance(_rr5z, list), (_bad5z, _rr5z)
        assert all("*" not in d for r in _rr5z for d in (r.get("san") or [])), _bad5z
    # 逗号连写的 name_value 不能被当成一个域名资产（domains_of 用 is_domain 挡掉）
    _cm5z, _ = ctlog_mod.parse_records('[{"name_value": "a.example.com,b.example.com"}]',
                                       settings)
    assert "a.example.com,b.example.com" not in ctlog_mod.domains_of(_cm5z), \
        "逗号连写值绝不能进资产库"

    # ③ classify_xss：None / 超长输入安全（返回 None 或合法 dict）
    assert owasp_checks.classify_xss(None, _BASE_P) is None
    _long5z = owasp_checks.classify_xss("a" * 200000 + _BASE_P, _BASE_P)
    assert _long5z is None or _long5z["context"], "超长输入应安全返回"
    print("[5z] QA 复核补测 ok: SSRF 异常路径 close() 不留线程 / ctlog None·截断·null 不抛异常且逗号串不入资产 / classify_xss None·超长安全")

    # 6a) QA 复核后的三处修复回归（盲注预算分配 / ssrf close 死代码 / ctlog 逗号分隔）
    #     ① 盲注预算：旧实现是"参数外层、形态内层"，第一个参数就吃掉全部预算（12），
    #        于是 5 个候选参数**只有 1 个真发过请求**；加上 `_ordered()` 打乱顺序，
    #        等于"每次随机只测 1/5"。这里让**非首位参数**（第 3 个）才有信号 ——
    #        旧实现下必然漏报，新实现（形态外层、参数内层、预算 30）必须命中。
    assert owasp_checks._SQLI_BLIND_MAX_REQ == 30, owasp_checks._SQLI_BLIND_MAX_REQ
    assert len(owasp_checks._SQLI_BLIND_PAIRS) == 2, owasp_checks._SQLI_BLIND_PAIRS

    def _param_of6(u):
        for _p in owasp_checks._SQLI_BLIND_PARAMS:
            if f"?{_p}=" in u or f"&{_p}=" in u:
                return _p
        return ""

    # (a) 全程无信号 → 跑满预算，且 **5 个候选参数一个都不能漏测**（旧实现只测到第一个）
    _blind_urls6 = []
    owasp_checks._get = lambda u, s, **kw: (_blind_urls6.append(u),
                                            {"status": 200, "headers": {},
                                             "text": "x" * 1000, "length": 1000})[1]
    try:
        assert owasp_checks._sqli_blind(targets, settings) is None
    finally:
        owasp_checks._get = _orig_get5
    assert len(_blind_urls6) == owasp_checks._SQLI_BLIND_MAX_REQ, \
        f"预算应为 2 形态 × 5 参数 × 3 请求 = 30，实际 {len(_blind_urls6)}"
    for _p6 in owasp_checks._SQLI_BLIND_PARAMS:
        assert any(_param_of6(u) == _p6 for u in _blind_urls6), f"参数 {_p6} 从没被测到"
    assert not _re5.search(r"sleep|benchmark|waitfor|pg_sleep", _blind_urls6[0], _re5.I), \
        "红线：不得引入延时型 payload"

    # (b) 只有**非首位参数**（第 3 个）对布尔条件敏感 → 必须命中它
    #     （旧实现"参数外层"时第一个参数就吃光预算，这条必然漏报）
    _blind_hit_param6 = owasp_checks._SQLI_BLIND_PARAMS[2]

    def _blind_cover6(u, s, **kw):
        if _param_of6(u) == _blind_hit_param6:
            _len = 900 if _re5.search(r"(1=2|'1'='2)", u) else 1200
        else:
            _len = 1000
        return {"status": 200, "headers": {}, "text": "x" * _len, "length": _len}

    owasp_checks._get = _blind_cover6
    try:
        _v_cover6 = owasp_checks._sqli_blind(targets, settings)
    finally:
        owasp_checks._get = _orig_get5
    assert _v_cover6 and _v_cover6["poc_id"] == "a03-sqli-blind", _v_cover6
    assert f"参数 {_blind_hit_param6} 的" in _v_cover6["detail"], \
        f"命中参数应为非首位的 {_blind_hit_param6}（旧实现只测第一个参数，必然漏报）：{_v_cover6['detail']}"
    assert "长度差 300B" in _v_cover6["evidence"], _v_cover6["evidence"]

    # ② ssrf close() 的 join 不是死代码。
    #    注意：**只靠真实监听的生命周期没有区分度** —— srv.shutdown() 本身会阻塞到
    #    serve_forever 退出、线程随之自然结束，所以旧死代码下 `not th.is_alive()` 照样
    #    成立；旧写法 `srv, self._server, self._thread = self._server, None, None` 也照样
    #    把 _server/_thread 清成 None。因此必须**桩注入、断言"调用行为"**。
    class _FakeServer6:
        def __init__(self):
            self.shutdown_calls = 0
            self.server_close_calls = 0

        def shutdown(self):
            self.shutdown_calls += 1

        def server_close(self):
            self.server_close_calls += 1

    class _FakeThread6:
        def __init__(self):
            self.join_calls = []

        def join(self, timeout=None):
            self.join_calls.append(timeout)

        def is_alive(self):
            return True

    #    (a) 桩注入：直接断言调用行为（这几条才抓得住死代码回归）
    _fs6, _ft6 = _FakeServer6(), _FakeThread6()
    _h6 = ssrf_mod.CallbackListener("127.0.0.1", 0)      # 不必真 start()
    _h6._server, _h6._thread = _fs6, _ft6
    _h6.close()
    assert _fs6.shutdown_calls == 1, f"shutdown() 应恰好调用 1 次，实际 {_fs6.shutdown_calls}"
    assert _fs6.server_close_calls == 1, \
        f"server_close() 应恰好调用 1 次，实际 {_fs6.server_close_calls}"
    assert _ft6.join_calls == [2], \
        f"join(timeout=2) 必须恰好被调用 1 次 —— 旧死代码下这里是 []：{_ft6.join_calls}"
    assert _h6._server is None and _h6._thread is None, "close() 后应清空 server/thread"

    #    (b) 边界：从未 start() 就 close() → 走 `if srv is None: return` 早退。
    #        给一个从未 start 的实例挂上假线程，断言 join **一次都没被调用** ——
    #        这证明早退发生在 join 之前（而非靠 srv 恰好没副作用蒙对）。
    _ft6b = _FakeThread6()
    _h6b = ssrf_mod.CallbackListener("127.0.0.1", 0)      # _server 默认 None
    _h6b._thread = _ft6b
    _h6b.close()                                          # 不该抛异常
    assert _ft6b.join_calls == [], f"srv 为 None 时应早退、不 join：{_ft6b.join_calls}"
    assert _h6b._server is None and _h6b._thread is None

    #    (c) 真实监听：负责验"真的没泄漏"（与桩那组职责不同，都要留）
    _lsn6 = ssrf_mod.CallbackListener("127.0.0.1", 0).start()
    _th6 = _lsn6._thread
    assert _th6 is not None and _th6.is_alive(), "监听线程没起来"
    _lsn6.close()
    assert _lsn6._thread is None and _lsn6._server is None, "close() 后应清空 server/thread"
    assert not _th6.is_alive(), "close() 必须真的 join 掉监听线程（此前是死代码）"
    assert not [t for t in threading.enumerate()
                if t.name == "ssrf-callback" and t.is_alive()], "仍有存活监听线程"
    _lsn6.close()                                         # 幂等：重复 close 不该抛异常

    # ③ ctlog：逗号连写的 name_value 要真的切开（而不是靠下游 is_domain 擦屁股）
    _cm6, _ = ctlog_mod.parse_records('[{"name_value": "a.example.com,b.example.com"}]',
                                      settings)
    assert _cm6[0]["san"] == ["a.example.com", "b.example.com"], _cm6[0]["san"]
    assert _cm6[0]["wildcard"] == 0, "逗号连写的普通串不该被当成通配符"
    _cm7, _ = ctlog_mod.parse_records('[{"name_value": "*.a.example.com,b.example.com"}]',
                                      settings)
    assert _cm7[0]["san"] == ["a.example.com", "b.example.com"], _cm7[0]["san"]
    assert _cm7[0]["wildcard"] == 1, "带 *. 的整串应剥出干净域名并标记通配符"
    assert ctlog_mod.domains_of(_cm6) == ["a.example.com", "b.example.com"]
    # 混排（换行 + 逗号 + 空白）也要正确切开
    _cm8, _ = ctlog_mod.parse_records(
        '[{"name_value": "a.example.com\\n b.example.com,c.example.com ,, "}]', settings)
    assert _cm8[0]["san"] == ["a.example.com", "b.example.com", "c.example.com"], _cm8[0]["san"]
    print("[6a] 复核修复回归 ok: 盲注覆盖全部 5 个参数（非首位参数可命中，预算 30 = 2×5×3）"
          " / ssrf close() 真 join（幂等、无线程残留）/ ctlog 逗号连写正确切分且不误标通配符")

    # 6b) 交付物 A：JSONL 结果导出（机器可读的结构化导出，F6）
    #     与 MD/HTML 的**刻意差异**：JSONL 导出 collect() 的 all_vulns（含已判误报的行），
    #     把复核状态交给下游自己筛，而不是替它静默丢数据。这条断言专门锁住该差异。
    import json as _json6
    _j_tid = db.create_task("smoke-jsonl-中文任务", targets, ["probe"], {"offline": True})
    db.insert_sites(_j_tid, [{"url": "http://j.test/", "host": "j.test", "port": 80,
                              "status": 200, "title": "中文标题·测试", "server": "nginx",
                              "tech": "php", "source": "probe"}])
    db.insert_certs(_j_tid, [{"url": "https://j.test/", "host": "j.test", "port": 443,
                              "cn": "j.test", "issuer": "CN=j.test", "expired": 1,
                              "self_signed": 1, "days_left": -3, "san": ["j.test"],
                              "sig_algo": "sha256WithRSA", "sha256": "AA:BB", "source": "tls"}])
    db.insert_vuln(_j_tid, {"target": "http://j.test/", "poc_id": "smoke-jsonl-hit",
                            "name": "中文漏洞名", "severity": "high", "owasp": "A03"})
    db.insert_vuln(_j_tid, {"target": "http://j.test/", "poc_id": "smoke-jsonl-fp",
                            "name": "复核掉的中文漏洞", "severity": "low"})
    _j_fp_id = [v["id"] for v in db.list_vulns(task_id=_j_tid, limit=50)
                if v["poc_id"] == "smoke-jsonl-fp"][0]
    assert db.set_vuln_review(_j_fp_id, "false_positive", "统一 200 的软 404") == 1

    _jl = generate_jsonl(_j_tid)
    assert _jl is not None, "真实任务的 generate_jsonl 不该返回 None"
    assert generate_jsonl(999999) is None, "不存在的 task_id 应返回 None（与 generate 一致）"
    assert _jl.endswith("\n"), "每行（含最后一行）都必须以 \\n 结尾，才是合法 JSON Lines"
    _j_lines = _jl.splitlines()
    _j_objs = [_json6.loads(ln) for ln in _j_lines]        # 每行都能 json.loads
    assert _j_objs[0]["type"] == "meta", _j_objs[0]
    assert _j_objs[0]["task_id"] == _j_tid and "counts" in _j_objs[0], _j_objs[0]
    # 中文原样还原（证明 ensure_ascii=False + UTF-8）
    _j_site = [o for o in _j_objs if o["type"] == "site"][0]
    assert _j_site["title"] == "中文标题·测试", repr(_j_site["title"])
    # 先前插入的漏洞能以 type=vuln 找到，且 poc_id / severity 正确
    _j_vulns = [o for o in _j_objs if o["type"] == "vuln"]
    _j_hit = [v for v in _j_vulns if v["poc_id"] == "smoke-jsonl-hit"]
    assert _j_hit and _j_hit[0]["severity"] == "high", _j_hit
    # **刻意差异**：已判误报的漏洞仍以 type=vuln 出现在 JSONL 里（review=false_positive），
    # 而 MD 的「潜在漏洞」结论表里**不含**它（只在文末「已判误报」附录留痕）。
    _j_fp = [v for v in _j_vulns if v["poc_id"] == "smoke-jsonl-fp"]
    assert _j_fp and _j_fp[0]["review"] == "false_positive", _j_fp

    def _md_section(md_text, title):
        """取 MD 里 `## <title>` 到下一个 `## ` 之间的片段（区分结论表与附录）。"""
        marker = f"## {title}"
        if marker not in md_text:
            return ""
        return md_text.split(marker, 1)[1].split("\n## ", 1)[0]

    _j_md = generate(_j_tid)
    assert "smoke-jsonl-fp" not in _md_section(_j_md, "潜在漏洞"), \
        "已判误报的行不该进 MD「潜在漏洞」结论表（JSONL 才保留它）"
    assert "smoke-jsonl-fp" in _md_section(_j_md, "已判误报"), \
        "MD 文末「已判误报」附录应保留该行供溯源"
    # 证书行能正常序列化（证明 sqlite3.Row → dict 转换有效，没踩 .get() 那个坑）
    _j_cert = [o for o in _j_objs if o["type"] == "cert"]
    assert _j_cert and _j_cert[0]["cn"] == "j.test", _j_cert
    # GUI 路由：fmt=jsonl 走 NDJSON mimetype + .jsonl 文件名
    _jr = c.get(f"/tasks/{_j_tid}/export?fmt=jsonl")
    assert _jr.status_code == 200, _jr.status_code
    assert "application/x-ndjson" in _jr.headers["Content-Type"], _jr.headers["Content-Type"]
    assert ".jsonl" in _jr.headers["Content-Disposition"], _jr.headers["Content-Disposition"]
    db.delete_task(_j_tid, backup=False)
    print(f"[6b] JSONL 导出 ok: {len(_j_lines)} 行合法 / 首行 meta / 中文原样 / "
          "误报行仍在（与 MD 结论表刻意差异）/ 证书行可序列化 / 路由 NDJSON")

    # 6c) 交付物 B：阶段失败的错误**追加**而非覆盖（F1 静默失败治理）
    #     先单测 append_task_error 的分隔符语义，再真跑一条"两个阶段都炸"的流水线。
    _e_tid = db.create_task("smoke-err", targets, ["probe"], {"offline": True})
    db.append_task_error(_e_tid, "第一条错误")
    assert db.get_task(_e_tid)["error"] == "第一条错误", repr(db.get_task(_e_tid)["error"])
    db.append_task_error(_e_tid, "第二条错误")
    _e_err = db.get_task(_e_tid)["error"]
    assert _e_err == "第一条错误\n第二条错误", \
        f"空 error 不该产生前导分隔符、多条应换行分隔：{_e_err!r}"
    # msg 为空 / 纯空白 → no-op（不追加空行、不产生尾随分隔符）
    db.append_task_error(_e_tid, "")
    db.append_task_error(_e_tid, "   \n ")
    assert db.get_task(_e_tid)["error"] == "第一条错误\n第二条错误", \
        repr(db.get_task(_e_tid)["error"])
    db.delete_task(_e_tid, backup=False)

    # 真跑一条两个阶段都异常的流水线（临时把两个桩阶段注册进 STAGE_REGISTRY）
    import scanner.runner as _rn6

    class _BoomA6:
        name = "smoke-boom-a"

        def __init__(self, ctx):
            self.ctx = ctx

        def run(self):
            raise RuntimeError("阶段A异常")

    class _BoomB6:
        name = "smoke-boom-b"

        def __init__(self, ctx):
            self.ctx = ctx

        def run(self):
            raise RuntimeError("阶段B异常")

    _saved_reg6 = dict(_rn6.STAGE_REGISTRY)
    _rn6.STAGE_REGISTRY["smoke-boom-a"] = _BoomA6
    _rn6.STAGE_REGISTRY["smoke-boom-b"] = _BoomB6
    try:
        _b_tid = db.create_task("smoke-两阶段失败", targets,
                                ["smoke-boom-a", "smoke-boom-b"], {"offline": True})
        run_task(_b_tid, "smoke-两阶段失败", targets,
                 ["smoke-boom-a", "smoke-boom-b"], {"offline": True}, settings)
        _b_err = db.get_task(_b_tid)["error"]
        assert "smoke-boom-a: 阶段A异常" in _b_err, \
            f"第一个阶段的错误丢失了（覆盖式写法下只剩最后一条）：{_b_err!r}"
        assert "smoke-boom-b: 阶段B异常" in _b_err, \
            f"第二个阶段的错误丢失了：{_b_err!r}"
        # 终态语义不变：阶段失败时任务仍以 done 收尾（本次只让它"可见且不丢"）
        assert db.get_task(_b_tid)["status"] == "done", db.get_task(_b_tid)["status"]
        # 循环结束后的 WARNING 汇总要落进日志
        _b_log = Path(db.get_task(_b_tid)["log_file"])
        assert _b_log.exists() and "[runner] 2 个阶段异常" in _b_log.read_text(encoding="utf-8"), \
            "缺少「N 个阶段异常」的 WARNING 汇总"
        db.delete_task(_b_tid, backup=False)
    finally:
        _rn6.STAGE_REGISTRY.clear()
        _rn6.STAGE_REGISTRY.update(_saved_reg6)
    print("[6c] 错误不丢 ok: 两阶段失败两条错误都在 / 空 error 无前导分隔符 / "
          "空 msg 为 no-op / 终态仍 done / 有 WARNING 汇总")

    # 6d) 交付物 C：启动时对孤儿 running 任务对账（用户拍板语义：标 failed、不自动续跑）
    import subprocess as _sp6
    # 拿一个"确定已死"的 pid：起一个立即退出的短命进程，等它结束后再用它的 pid
    _dead_proc = _sp6.Popen([sys.executable, "-c", "pass"])
    _dead_proc.wait()
    _dead_pid = _dead_proc.pid
    assert db._pid_alive(os.getpid()) is True, "本进程必须被判定为存活"
    assert db._pid_alive(_dead_pid) is False, "已退出的进程必须被判定为已死"
    assert db._pid_alive(0) is False and db._pid_alive(None) is False, "0/None 一律视为已死"

    _o_alive = db.create_task("smoke-orphan-alive", targets, ["probe"], {"offline": True})
    db.update_task(_o_alive, status="running", pid=os.getpid())
    _o_dead = db.create_task("smoke-orphan-dead", targets, ["probe"], {"offline": True})
    db.update_task(_o_dead, status="running", pid=_dead_pid)
    _o_zero = db.create_task("smoke-orphan-zero", targets, ["probe"], {"offline": True})
    db.update_task(_o_zero, status="running", pid=0)
    _o_done = db.create_task("smoke-orphan-done", targets, ["probe"], {"offline": True})
    db.update_task(_o_done, status="done", pid=_dead_pid)
    db.reconcile_orphan_tasks()
    # pid 指向存活进程 → 跳过（绝不能误杀可能正在跑它的进程）
    assert db.get_task(_o_alive)["status"] == "running", \
        f"存活 pid 的任务被误杀：{db.get_task(_o_alive)['status']}"
    # pid 已死 → failed + 对账标记
    assert db.get_task(_o_dead)["status"] == "failed", db.get_task(_o_dead)["status"]
    assert "进程重启" in (db.get_task(_o_dead)["error"] or ""), db.get_task(_o_dead)["error"]
    assert db.get_task(_o_dead)["current_stage"] == "", db.get_task(_o_dead)["current_stage"]
    # pid=0（老库遗留）→ failed
    assert db.get_task(_o_zero)["status"] == "failed", db.get_task(_o_zero)["status"]
    # done 的任务不受影响
    assert db.get_task(_o_done)["status"] == "done", db.get_task(_o_done)["status"]
    for _ot in (_o_alive, _o_dead, _o_zero, _o_done):
        db.delete_task(_ot, backup=False)
    print("[6d] 孤儿任务对账 ok: 存活 pid 保留 running / 死 pid 与 pid=0 标 failed 且带标记 / "
          "done 不受影响")

    # 6e) 续20 验证后修复：① CLI 导出的 JSONL 行尾必须是 \n（Windows 文本模式会把 \n 翻成 \r\n，
    #     而 generate_jsonl() 与 HTTP 路由产出的都是 \n —— 同一条导出经两条路径字节必须一致）；
    #     ② Windows OpenProcess 失败时按错误码 fail-safe 判定（权限被拒/拿不准 → 视为存活）。
    _cli_out = _TMPDIR / "cli_jsonl.jsonl"
    _orig_argv6e = sys.argv
    try:
        _cli.run_task = lambda *a, **kw: _CliCtx()
        sys.argv = ["client.py", "-t", "cli-jsonl.test", "-p", "probe",
                    "-n", "smoke-cli-jsonl", "--report-jsonl", str(_cli_out)]
        _cli.main()
    finally:
        sys.argv = _orig_argv6e
        _cli.run_task = _orig_cli_run
    assert _cli_out.exists(), "CLI 未生成 JSONL 文件"
    _cli_bytes = _cli_out.read_bytes()
    assert b"\r" not in _cli_bytes, \
        "CLI 产出的 JSONL 含 CR —— 行尾被 Windows 文本模式翻成了 \\r\\n（应为 \\n）"
    assert _cli_bytes.endswith(b"\n"), "CLI 产出的 JSONL 最后一行应以 \\n 结尾"
    # 与 generate_jsonl() 直接产出的字节**完全一致**（两条导出路径不再漂移）
    _cli_tid = [t for t in db.list_tasks(limit=80) if t["name"] == "smoke-cli-jsonl"][0]["id"]
    assert _cli_bytes == generate_jsonl(_cli_tid).encode("utf-8"), \
        "CLI 产出的 JSONL 与 generate_jsonl() 字节不一致（行尾漂移）"
    db.delete_task(_cli_tid, backup=False)

    # 加固 3：真实的"OpenProcess 权限被拒"在本机不易稳定构造，故直接单测这条**纯判定函数**
    # （有区分度，不是恒真断言：把逻辑改回"失败即已死"这条会挂）。
    assert db._win_open_alive(87) is False, "ERROR_INVALID_PARAMETER(87) 应视为已死"
    assert db._win_open_alive(5) is True, "ERROR_ACCESS_DENIED(5) 应视为存活（不误杀）"
    assert db._win_open_alive(0) is True, "拿不准的错误码应一律按存活处理（fail-safe）"
    print("[6e] 续20 修复 ok: CLI JSONL 行尾为 \\n（与 generate_jsonl 字节一致）/ "
          "OpenProcess 失败按错误码 fail-safe（5 与未知→存活、87→已死）")

    # 6f) F2：统一并发 / 限速 / 全局预算门控（scanner/throttle.py + 三条出口接线 + 停止语义）。
    #     逐条覆盖：闸门计数与取消、令牌桶、min(阶段,任务,全局) 组合、预算耗尽=按停止、
    #     inject 不原地改、进程级闸跨任务共享、http_request/run_cmd 在预算耗尽时"不抛、按停止"。
    import time as _t6f
    from scanner import throttle as _th6f
    from scanner.utils import http_request as _http6f

    # TP1) _Gate 基本计数：未满立即拿；满则阻塞；capacity<=0 视为"不限"。
    _g6f = _th6f._Gate(2)
    assert _g6f.acquire(None) and _g6f.acquire(None), "未满时应立即拿到名额"
    assert _g6f.in_flight == 2, _g6f.in_flight
    _ev6f_full = threading.Event()
    _ev6f_full.set()
    # ✱ 满 + 已置位 → 必须返回 False（不能拿到名额）—— 这条抓"等待里没检查取消"
    assert _g6f.acquire(_ev6f_full, poll=0.02) is False, "满 + 已取消 → 不该拿到名额"
    _g6f.release()
    assert _g6f.acquire(None, poll=0.02) is True, "释放后应能拿到名额"
    _g6f.release()
    _g6f.release()
    assert _g6f.in_flight == 0, "释放后计数应归零"
    _g6f_un = _th6f._Gate(0)
    for _ in range(50):
        assert _g6f_un.acquire(None) is True
    assert _g6f_un.in_flight == 0, "capacity<=0 视为不限、不计数"

    # TP2) 等待中被取消：置位后应尽快退出（不卡死）—— F2 的硬约束"绝不卡在等锁"。
    _g6f2 = _th6f._Gate(1)
    _g6f2.acquire(None)
    _ev6f2 = threading.Event()
    _t0 = _t6f.monotonic()
    threading.Timer(0.15, _ev6f2.set).start()
    _got6f = _g6f2.acquire(_ev6f2, poll=0.02)
    _el6f = _t6f.monotonic() - _t0
    # ✱ 取消后必须尽快返回 False（旧式 `cond.wait()` 无轮询会一直卡住）
    assert _got6f is False and _el6f < 2.0, f"取消后应尽快退出等待（实际 {_el6f:.2f}s）"
    _g6f2.release()

    # TP3) TokenBucket：rate<=0 不限；有速率时 N 次取用会被真的拖慢。
    _tb0 = _th6f.TokenBucket(0, 0)
    assert all(_tb0.acquire(None) for _ in range(50)), "rate<=0 应恒放行"
    _tb = _th6f.TokenBucket(50, 1)          # 50/s、突发 1（先花掉突发）
    _tb.acquire(None)
    _t0 = _t6f.monotonic()
    for _ in range(4):
        _tb.acquire(None)
    _el6f = _t6f.monotonic() - _t0
    # ✱ 限速必须真的生效（4 次 @50/s 至少 ~0.06s）；不限速的实现这里会接近 0
    assert _el6f >= 0.05, f"限速应真的拖慢（4 次 @50/s 实际 {_el6f:.3f}s）"

    # TP4) effective_cap = min(阶段并发, 任务上限, 全局上限)；三者皆 0 → 0（不限）。
    _s6f = {"limits": {"max_inflight_per_task": 32, "max_inflight_global": 16,
                       "rate_per_sec": 0, "rate_burst": 0, "budget_total": 0,
                       "budget_subprocess_weight": 1}}
    _thc = _th6f.build(_s6f, 1, threading.Event(), rec)
    # ✱ 这是"消灭 8×256"的核心：阶段要 1000，也只能拿到 min(1000,32,16)=16
    assert _thc.effective_cap(1000) == 16, _thc.effective_cap(1000)
    assert _thc.effective_cap(8) == 8, "阶段并发更小则取它"
    assert _thc.effective_cap(0) == 16, "阶段传 0（不限）仍受任务/全局约束"
    _thc_zero = _th6f.build({"limits": {"max_inflight_per_task": 0,
                                        "max_inflight_global": 0}}, 2, threading.Event(), rec)
    assert _thc_zero.effective_cap(0) == 0, "三者皆 0 → 不限（返回 0）"
    assert _thc_zero.effective_cap(7) == 7, "阶段并发是唯一的正数 → 取它"

    # TP5) build 对非法/缺失值的兜底（不能让一个手滑把门控变成"永远拒绝"或"永不生效"）。
    _thc_bad = _th6f.build({"limits": {"max_inflight_per_task": "not-a-number",
                                       "budget_total": None}}, 99, threading.Event(), rec)
    assert _thc_bad._task_cap == 256, "非法值应回退默认 256"
    assert _thc_bad.budget_total == 0, "None 应回退默认 0（不限）"

    # TP6) 预算耗尽：用满后下一次 slot 抛 BudgetExhausted，且 exhausted() 变真。
    _s6f_b = {"limits": {"max_inflight_per_task": 0, "max_inflight_global": 0,
                         "budget_total": 3, "budget_subprocess_weight": 1}}
    _thb = _th6f.build(_s6f_b, 4, threading.Event(), rec)
    assert _thb.exhausted() is False
    for _ in range(3):
        with _thb.slot("http"):
            pass
    assert _thb.snapshot() == {"granted": 3, "rejected": 0, "in_flight": 0,
                               "budget_left": 0}, _thb.snapshot()
    try:
        with _thb.slot("http"):
            pass
        raise AssertionError("预算耗尽后应抛 BudgetExhausted")
    except _th6f.BudgetExhausted:
        pass
    # ✱ 耗尽标志必须变真 —— 它是 ctx.stopped() 为真的两个来源之一（驱动干净收尾）
    assert _thb.exhausted() is True, "耗尽后 exhausted() 必须为真"
    assert _thb.snapshot()["rejected"] == 1, _thb.snapshot()

    # TP7) 子进程按权重计预算（budget_subprocess_weight），http/socket 记 1。
    _s6f_w = {"limits": {"max_inflight_per_task": 0, "max_inflight_global": 0,
                         "budget_total": 10, "budget_subprocess_weight": 4}}
    _thw = _th6f.build(_s6f_w, 5, threading.Event(), rec)
    with _thw.slot("subprocess"):
        pass
    assert _thw.snapshot()["budget_left"] == 6, "子进程一次抵 4 次请求"
    with _thw.slot("http"):
        pass
    assert _thw.snapshot()["budget_left"] == 5, "http 一次抵 1 次"
    assert _thw.snapshot()["in_flight"] == 0, "with 退出后名额必须释放（无泄漏）"

    # TP8) stop_event 已置位 → 取名额直接抛 StopRequested（不占名额、不白等）。
    _ev8 = threading.Event()
    _ev8.set()
    _th8 = _th6f.build({"limits": {}}, 6, _ev8, rec)
    try:
        with _th8.slot("http"):
            pass
        raise AssertionError("stop_event 已置位时应抛 StopRequested")
    except _th6f.StopRequested:
        pass
    assert _th8.snapshot()["in_flight"] == 0, "被取消时不该占住名额"

    # TP9) inject 绝不原地改原 settings（沿用 auth.inject 的模式：任务专用副本）。
    _orig9 = {"limits": {"max_inflight_per_task": 8}}
    _copy9 = copy.deepcopy(_orig9)
    _inj9 = _th6f.inject(_orig9, 7, threading.Event(), rec)
    assert "_throttle" in _inj9 and "_throttle" not in _orig9, "inject 不得把限流器写进原 settings"
    assert _orig9 == _copy9, "原 settings 必须原样不动"
    assert _inj9["_throttle"].task_id == 7

    # TP10) 进程级闸跨任务共享 —— 否则"N 个任务各跑各的"= 进程级上限形同虚设。
    _gA = _th6f.build({"limits": {"max_inflight_global": 5}}, 8, threading.Event(), rec)
    _gB = _th6f.build({"limits": {"max_inflight_global": 5}}, 9, threading.Event(), rec)
    # ✱ 两个任务必须引用同一个全局闸对象
    assert _gA._global_gate is _gB._global_gate, \
        "同容量的进程级闸必须跨任务共享（否则进程级上限形同虚设）"

    # TP11) 出口接线：预算耗尽时 http_request 返回 None（不抛）、run_cmd 返回 (1,'',原因)。
    _thx = _th6f.build({"limits": {"budget_total": 1}}, 10, threading.Event(), rec)
    _sx = {"_throttle": _thx, "limits": {"verify_tls": False}}
    _http6f("http://127.0.0.1:1/", settings=_sx, timeout=0.5)      # 花掉唯一的预算（连不上也记账）
    _r2 = _http6f("http://127.0.0.1:1/", settings=_sx, timeout=0.5)
    # ✱ 预算耗尽 → None（按"停止"语义），而不是把异常抛给调用点
    assert _r2 is None, "预算耗尽时 http_request 应返回 None（不是抛异常）"
    assert _thx.exhausted() is True
    _thc2 = _th6f.build({"limits": {"budget_total": 1}}, 11, threading.Event(), rec)
    run_cmd([sys.executable, "-c", "pass"], timeout=5, throttle=_thc2)   # 花掉预算
    _rc_x, _ox, _ex = run_cmd([sys.executable, "-c", "pass"], timeout=5, throttle=_thc2)
    # ✱ 预算耗尽 → (1, '', '原因')，绝不抛；原因里要能看出是 throttle
    assert _rc_x == 1 and "throttle" in _ex, f"预算耗尽时 run_cmd 应返回 (1,'',原因)：{(_rc_x, _ex)!r}"

    # TP12) 端到端停止语义：预算耗尽 → 任务标 stopped（**不是 done**）+ 追加 [throttle] 错误行。
    class _Thrift6:
        name = "smoke-thrift"

        def __init__(self, ctx):
            self.ctx = ctx

        def run(self):
            while True:
                if self.ctx.stopped():
                    break
                try:
                    with self.ctx.throttle.slot("http"):
                        pass
                except _th6f.BudgetExhausted:
                    break

    _saved6f = dict(_rn6.STAGE_REGISTRY)
    _rn6.STAGE_REGISTRY["smoke-thrift"] = _Thrift6
    try:
        _bt6f = db.create_task("smoke-budget", targets, ["smoke-thrift"], {"offline": True})
        _bs6f = copy.deepcopy(settings)
        _bs6f["limits"] = dict(_bs6f.get("limits") or {}, budget_total=2,
                               max_inflight_per_task=0, max_inflight_global=0)
        _bctx6f = StageContext(_bt6f, "smoke-budget", parse_lines(["x.test"]),
                               ["smoke-thrift"], {"offline": True}, _bs6f,
                               Path(_TMPDIR) / "budget6f", rec)
        PipelineRunner(_bctx6f).run()
        _bt6f_row = db.get_task(_bt6f)
        # ✱ 预算耗尽必须标 stopped（不是 done）—— 这是"按停止处理"的落点
        assert _bt6f_row["status"] == "stopped", \
            f"预算耗尽必须标 stopped（不是 done）：{_bt6f_row['status']}"
        # ✱ 必须追加一条明确的 [throttle] 错误行（否则事后分不清"被拒绝"与"被人为停"）
        assert "[throttle]" in (_bt6f_row["error"] or "") \
            and "预算耗尽" in (_bt6f_row["error"] or ""), \
            f"应追加预算耗尽的错误行：{_bt6f_row['error']!r}"
        assert _bctx6f.stopped() is True, "预算耗尽后 ctx.stopped() 必须为真"
        assert any("[throttle]" in x for x in rec.lines), "日志里应有 [throttle] 警告"
        db.delete_task(_bt6f, backup=False)
    finally:
        _rn6.STAGE_REGISTRY.clear()
        _rn6.STAGE_REGISTRY.update(_saved6f)

    # TP13) StageContext 注入 + stopped() 双来源（stop_event 与 exhausted 任一为真）。
    _ctx6f = StageContext(12345, "smoke-ctx6f", parse_lines(["x.test"]), ["probe"], {},
                          settings, Path(_TMPDIR) / "ctx6f", rec)
    assert _ctx6f.throttle is not None and _ctx6f.throttle is _ctx6f.settings["_throttle"], \
        "StageContext 必须把限流器注入到 settings['_throttle']"
    assert _ctx6f.stopped() is False
    _ctx6f.stop_event.set()
    # ✱ stop_event 置位 → stopped() 为真（协作式取消仍有效）
    assert _ctx6f.stopped() is True, "stop_event 置位后 stopped() 必须为真"

    print("[6f] F2 门控 ok: 闸门计数/取消不卡 / 令牌桶限速 / effective_cap=min(阶段,任务,全局) / "
          "预算耗尽=按停止(任务标 stopped + [throttle] 错误行) / inject 不原地改 / "
          "进程级闸跨任务共享 / http_request·run_cmd 耗尽时按停止不抛")

    # 6g) 预算原子化（续21 修复）：预算"检查 + 扣减"必须在**同一临界区**内完成，否则任务闸
    #     饱和时 N 个线程会读到同一个旧 `_budget_left` 全部放行 → 超发 ≈ 池大小−1。
    #     用**真实线程池**复现：pool=20 / 100 个作业 / 小任务闸（制造"多线程同时读旧值"）。
    from concurrent.futures import ThreadPoolExecutor as _TPE6g

    def _run_6g(_cap, _budget):
        _th = _th6f.build({"limits": {"max_inflight_per_task": _cap,
                                      "max_inflight_global": 0,
                                      "budget_total": _budget}},
                          100 + _cap, threading.Event(), rec)

        def _job():
            try:
                with _th.slot("http"):
                    _t6f.sleep(0.01)      # 持有一小会，逼出"闸饱和 → 多线程同读旧预算"
            except _th6f.BudgetExhausted:
                pass

        with _TPE6g(max_workers=20) as _ex:
            _futs = [_ex.submit(_job) for _ in range(100)]
            for _f in _futs:
                _f.result()
        return _th.snapshot()

    _snap6g_a = _run_6g(2, 3)
    # ✱ 修复前实测：cap=2/budget=3 → granted=21（超发 ≈ 池大小−1）；修复后必须 == 3
    assert _snap6g_a["granted"] == 3, \
        f"[6g] 预算原子化：cap=2/budget=3 应 granted==3（修复前 21），实际 {_snap6g_a}"
    _snap6g_b = _run_6g(1, 3)
    # ✱ 修复前实测：cap=1/budget=3 → granted=22；修复后必须 == 3
    #    （触发条件是 budget > cap：闸饱和时"已过检查"的线程远多于预算才会超发；
    #     budget ≤ cap 时首笔预留即耗尽预算，反而不会超发 —— 故此处取 budget=3 > cap=1。）
    assert _snap6g_b["granted"] == 3, \
        f"[6g] 预算原子化：cap=1/budget=3 应 granted==3（修复前 22），实际 {_snap6g_b}"

    # 6h) 失败路径退还预算：线程在"等闸"时被取消 → 必须**全额退还**已预留的预算，且**不能挂死**。
    #     （旧代码 5719886 上本用例**整条仍失败**，失败点就是下方的 `budget_left == 4`：旧写法在闸前
    #      **只读不扣**，budget_left 恒为 10 → 上面的等待循环跑满 3s 超时 → 断言失败。只有末尾那条
    #      **退还断言**（`budget_left == 10`）在旧代码上偶然成立（旧代码压根没扣过预算）。
    #      本用例真正守的是"闸前预留 + 失败退还"这套新逻辑 —— 去掉 `_refund_budget` 后 budget_left 停在 4 ≠ 10。）
    _ev6h = threading.Event()
    _th6h = _th6f.build({"limits": {"max_inflight_per_task": 1, "max_inflight_global": 0,
                                    "budget_total": 10}}, 200, _ev6h, rec)
    _th6h._task_gate.acquire(None)          # 占住唯一任务名额 → 后续线程会卡在步骤 2（等闸）
    _res6h = []

    def _wait6h():
        try:
            with _th6h.slot("http"):
                pass
        except _th6f.StopRequested:
            _res6h.append("stop")
        except _th6f.BudgetExhausted:
            _res6h.append("budget")

    _ths6h = [threading.Thread(target=_wait6h, daemon=True) for _ in range(6)]
    for _t in _ths6h:
        _t.start()
    _dead6h = _t6f.monotonic() + 3.0
    while _th6h.snapshot()["budget_left"] > 4 and _t6f.monotonic() < _dead6h:
        _t6f.sleep(0.01)
    # 6 个线程各预留 1 → budget_left 应到 4（确保它们确实"已预留、正等闸"）
    assert _th6h.snapshot()["budget_left"] == 4, \
        f"[6h] 6 线程应各预留 1 预算（budget_left→4）：{_th6h.snapshot()}"
    _ev6h.set()                             # 在它们等闸时请求停止
    for _t in _ths6h:
        _t.join(timeout=3.0)
    # ✱ 绝不能挂死：所有线程都要退出（旧式无轮询等待会卡住）
    assert all(not _t.is_alive() for _t in _ths6h), "[6h] 取消后线程不应挂死在等闸"
    assert _res6h == ["stop"] * 6, f"[6h] 6 个等待线程都应因取消抛 StopRequested：{_res6h}"
    _snap6h = _th6h.snapshot()
    # ✱ 全额退还：失败路径必须退还已预留预算（漏退还 → budget_left==4 ≠ 10）
    assert _snap6h["budget_left"] == 10, f"[6h] 失败路径应全额退还预算：{_snap6h}"
    # ✱ 退还 ≠ 被拒：取消不该计入 rejected（rejected 只统计"预算耗尽被拒"）
    assert _snap6h["rejected"] == 0, f"[6h] 取消不应计入 rejected：{_snap6h}"
    assert _snap6h["granted"] == 0, f"[6h] 无线程真正拿到名额：{_snap6h}"
    _th6h._task_gate.release()

    # 6i) 混合容量告警：不同 `max_inflight_global` 的并发任务不共享闸（旧闸仍在飞）→
    #     进程级有效上限暂时是两者之和。这里**必须打 warning**（不静默），且两任务仍能正常取名额。
    class _Warn6i:
        def __init__(self):
            self.warnings = []

        def warning(self, msg, *a):
            self.warnings.append(str(msg))

        def info(self, *a):
            pass

        def debug(self, *a):
            pass

        def error(self, *a):
            pass

        def exception(self, *a):
            pass

    _wl6i = _Warn6i()
    _th6i_a = _th6f.build({"limits": {"max_inflight_global": 4}}, 300, threading.Event(), _wl6i)
    assert _th6i_a._global_gate.acquire(None) is True      # 让 A 的全局闸有在飞请求
    assert _th6i_a._global_gate.in_flight > 0
    _th6i_b = _th6f.build({"limits": {"max_inflight_global": 8}}, 301, threading.Event(), _wl6i)
    # ✱ 容量变化重建闸时，旧闸仍有在飞 → 必须告警（明示"有效上限暂时是两者之和"）
    assert any(("改为" in w) or ("有效上限" in w) for w in _wl6i.warnings), \
        f"[6i] 混合容量重建闸时必须告警（不静默）：{_wl6i.warnings}"
    with _th6i_b.slot("http"):             # 两任务仍能正常取名额（告警不影响功能）
        pass
    assert _th6i_b.snapshot()["granted"] == 1, _th6i_b.snapshot()
    _th6i_a._global_gate.release()

    # 6j) slot() 不可重入：同线程嵌套取名额会自锁（`_Gate` 是计数信号量）—— 靠"停止"解开。
    _ev6j = threading.Event()
    _th6j = _th6f.build({"limits": {"max_inflight_per_task": 1, "max_inflight_global": 0,
                                    "budget_total": 0}}, 400, _ev6j, rec)
    _in6j = threading.Event()
    _done6j = []

    def _nested6j():
        with _th6j.slot("http"):           # 占住唯一名额
            _in6j.set()                    # 已进临界区 → 接下来会自锁
            try:
                with _th6j.slot("http"):   # 同线程再取 → 该自锁
                    _done6j.append("acquired")
            except _th6f.StopRequested:
                _done6j.append("stop")

    _t6j = threading.Thread(target=_nested6j, daemon=True)
    _t6j.start()
    assert _in6j.wait(3.0), "[6j] 线程应已进入临界区"
    _t6j.join(timeout=0.5)
    # ✱ 同线程嵌套应自锁（等 0.5s 仍拿不到第二名额、也没抛异常）
    assert _t6j.is_alive() and not _done6j, "[6j] 同线程嵌套 slot() 应自锁（不该拿到第二名额）"
    _ev6j.set()                            # 用"停止"把它解开（否则 smoke 会挂死）
    _t6j.join(timeout=3.0)
    assert not _t6j.is_alive(), "[6j] 置位 stop_event 后嵌套等待应被解开"
    assert _done6j == ["stop"], f"[6j] 嵌套等待应因取消抛 StopRequested：{_done6j}"

    print("[6g] F2 预算原子化 ok: 真实线程池 pool=20/100 作业，cap=2·budget=3 → granted==3"
          "（修复前 21）、cap=1·budget=3 → granted==3（修复前 22）")
    print("[6h] F2 失败路径退还预算 ok: 6 线程等闸时取消 → 全部退出(不挂死) / budget_left 全额退还(10) / "
          "rejected==0")
    print("[6i] F2 混合容量告警 ok: 不同 max_inflight_global 重建闸且旧闸在飞 → 打 warning（不静默）")
    # 6k) 续22：拓展域名降噪三件套（jsmine PSL 校验 / 第三方清单 / FOFA 标题归属相关性）。
    #     A) jsmine 加公共后缀（PSL）校验 —— 此前末位 label 只要是 2–24 个字母就当 TLD，
    #        于是 `wallet.filter.withdraw` / `react.transitional.element` / `i.test` 这类
    #        "点号连接的 JS 成员访问链"全被当成域名资产（用户从「拓展域名」页拷来的真实数据）。
    #     B) js_thirdparty.txt 补齐用户数据里的第三方域名（纯数据）。
    #     C) FOFA 标题反查加"归属相关性"过滤（默认 label 相等），挡掉"标题恰好含同一子串"的无关域名。
    from scanner import jsmine as _jm6k
    from scanner.stages import osint as _os6k

    # ---- A) PSL 校验 ----
    assert _jm6k._public_suffixes(), "公共后缀清单未加载（config/dicts/tlds.txt）"
    for _h6k in ("wallet.filter.withdraw", "react.transitional.element",
                 "react.client.reference", "i.test"):
        # ✱ 修复前（末位纯字母即当 TLD）这些全是 True —— 就是用户拷来的那批"假域名"。
        #    证伪实测（bbec7f0 旧代码）：4/4 全被接受，故 `is False` 断言在旧代码上真的失败。
        assert _jm6k._valid_host(_h6k) is False, f"[6k] PSL 应拒绝：{_h6k}"
    for _h6k in ("example.com", "a.b.example.com.cn", "foo.co.uk", "x.io",
                 "sub.target.co.jp"):
        # ✱ 真实域名（含多段后缀）必须仍被接受 —— 默认路径不受影响
        assert _jm6k._valid_host(_h6k) is True, f"[6k] 真实域名应接受：{_h6k}"
    # fail-open：清单缺失 → 回退旧的宽松判断（绝不静默丢资产）+ 只告警一次
    _sfile6k, _scache6k, _swarn6k = _jm6k._TLDS_FILE, _jm6k._tlds_cache, _jm6k._tlds_warned
    try:
        _jm6k._TLDS_FILE = "config/dicts/__no_such_tlds__.txt"
        _jm6k._tlds_cache = None
        assert _jm6k._public_suffixes() is None
        assert _jm6k._valid_host("wallet.filter.withdraw") is True, "[6k] fail-open 应回退宽松判断"
        _w6k = _Rec()
        _jm6k._tlds_warned = False
        _jm6k._warn_missing_tlds(_w6k)
        _jm6k._warn_missing_tlds(_w6k)
        assert len(_w6k.lines) == 1, "[6k] 清单缺失应恰好告警一次"
    finally:
        _jm6k._TLDS_FILE, _jm6k._tlds_cache, _jm6k._tlds_warned = _sfile6k, _scache6k, _swarn6k

    # ---- B) 第三方清单（纯数据）----
    _noise6k = _jm6k._noise_set()
    for _d6k in ("reactjs.org", "react.dev", "bscscan.com", "solscan.io",
                 "cloudflareinsights.com", "api.qrserver.com", "capacitorjs.com",
                 "debox.pro", "pong-pengo.de"):
        assert _d6k in _noise6k, f"[6k] 第三方清单缺 {_d6k}"
    # ✱ `static.cloudflareinsights.com` 结尾是 `.cloudflareinsights.com` —— `cloudflare.com` 拦不住它。
    #    证伪实测（bbec7f0 旧清单 267 条）：9/9 目标域名全缺、`_is_noise(static.cloudflareinsights.com)`
    #    为 False，故 `in _noise6k` / `is True` 断言在旧代码上真的失败。
    assert _jm6k._is_noise("static.cloudflareinsights.com", set(), []) is True, \
        "[6k] cloudflareinsights.com 必须单独成行"

    # ---- C) FOFA 标题归属相关性 ----
    for _d6k in ("pengo.money", "pengo.me", "pengo.uk", "pengo.com.vn"):
        assert _os6k._title_relevant("Pengo", _d6k, "label") is True, f"[6k] 同品牌应保留：{_d6k}"
    for _d6k in ("silviapengo.com", "pengowireline.com", "kufungapengo.com",
                 "gkops.net", "yulw.cn"):
        # ✱ 修复前不做任何过滤 → 这些"恰好含同一子串"的无关域名全被当资产入库。
        #    证伪实测（bbec7f0 旧 osint，端到端）：9/9 全入库（silviapengo.com / gkops.net /
        #    yulw.cn 都在），故"默认档应丢弃"断言在旧代码上真的失败。
        assert _os6k._title_relevant("Pengo", _d6k, "label") is False, f"[6k] 无关域名应丢弃：{_d6k}"
    assert _os6k._title_relevant("Pengo", "silviapengo.com", "substring") is True, \
        "[6k] substring 档应放宽为子串匹配（回退/对照）"
    # fail-open：标题切不出 token（纯中文）时不丢 —— 否则会误杀非拉丁标题的真实资产
    assert _os6k._title_relevant("维保中心", "x.test", "label") is True

    # C-端到端：真跑 osint 阶段，默认档丢 silviapengo.com、substring 档留下它（开关真的起作用）
    _ret6k = [{"host": "https://" + _d, "domain": _d, "ip": "1.2.3.4", "port": "443",
               "title": "Pengo"} for _d in
              ("pengo.money", "pengo.me", "pengo.uk", "pengo.com.vn", "silviapengo.com",
               "pengowireline.com", "kufungapengo.com", "gkops.net", "yulw.cn")]

    def _stub6k(title, settings, logger=None, size=None):
        return ([dict(a) for a in _ret6k], len(_ret6k), "")

    _orig6k = _os6k.fofa_mod.search_title
    _os6k.fofa_mod.search_title = _stub6k
    try:
        def _os_run6k(match):
            _s6k = copy.deepcopy(settings)
            _s6k["iprecon"]["enabled"] = False
            _s6k["fofa"].update({"enabled": True, "cert_enabled": False,
                                 "title_enabled": True, "max_title_queries": 2,
                                 "title_match": match})
            _s6k["keys"] = {"fofa": {"email": "stub@example.test", "key": "stub"}}
            _tid6k = db.create_task(f"smoke-6k-{match}", targets, ["osint"], {"offline": True})
            db.insert_sites(_tid6k, [{"url": targets, "host": "127.0.0.1", "port": "80",
                                      "status": 200, "title": "Pengo", "length": 100,
                                      "source": "builtin"}])
            run_task(_tid6k, f"smoke-6k-{match}", targets, ["osint"], {"offline": True}, _s6k)
            _dom = {r["domain"] for r in db.list_subdomains(_tid6k)}
            db.delete_task(_tid6k, backup=False)
            return _dom

        _lab6k = _os_run6k("label")
        assert "pengo.money" in _lab6k and "pengo.com.vn" in _lab6k, _lab6k
        assert "silviapengo.com" not in _lab6k, f"[6k] 默认档应丢弃 silviapengo.com：{_lab6k}"
        assert "gkops.net" not in _lab6k and "yulw.cn" not in _lab6k, _lab6k
        _sub6k = _os_run6k("substring")
        assert "silviapengo.com" in _sub6k, f"[6k] substring 档应保留 silviapengo.com：{_sub6k}"
    finally:
        _os6k.fofa_mod.search_title = _orig6k

    # 新开关三方一致：DEFAULTS ↔ settings.yaml ↔ GUI 表单/POST 映射
    from scanner.config import DEFAULTS as _DEF6K
    assert _DEF6K["fofa"].get("title_match") == "label", "DEFAULTS.fofa 缺 title_match"
    assert (settings.get("fofa") or {}).get("title_match") == "label", \
        "settings.yaml.fofa 缺 title_match"
    _sh6k = c.get("/settings").get_data(as_text=True)
    assert 'name="fofa_title_match"' in _sh6k, "策略配置缺 fofa_title_match 字段"
    _cap6k = {}

    def _fake_save6k(d):
        _cap6k.clear()
        _cap6k.update(d)
        return load_settings()

    _orig_save6k = gui_app.save_settings
    gui_app.save_settings = _fake_save6k
    try:
        assert c.post("/settings", data={"min_severity": "medium",
                                         "fofa_title_match": "substring"}).status_code == 302
        assert (_cap6k.get("fofa") or {}).get("title_match") == "substring", _cap6k.get("fofa")
        # 未提交时回退默认 label（不能把配置吃成空）
        assert c.post("/settings", data={"min_severity": "medium"}).status_code == 302
        assert (_cap6k.get("fofa") or {}).get("title_match") == "label", _cap6k.get("fofa")
    finally:
        gui_app.save_settings = _orig_save6k

    print("[6k] 续22 拓展域名降噪 ok: jsmine PSL 校验（拒 withdraw/element/reference/test，"
          "多段后缀仍接受，清单缺失 fail-open+告警）/ 第三方清单补 9 条（含 "
          "cloudflareinsights.com 拦 static.*）/ FOFA 标题归属相关性（label 挡 silviapengo.com·"
          "gkops.net，pengo.* 保留；substring 档复现宽松；中文标题 fail-open）+ 开关三方一致")

    print("SMOKE PASS")


if __name__ == "__main__":
    main()
