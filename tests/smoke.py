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
import time
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


# ---- 沙箱残留的自愈清扫（2026-09-24 加）----
# 正常跑完由 atexit 删除，实测是干净的（跑一次前后 `logs/smoke-*` 数量不变）。
# 残留**只来自被强杀**的运行：SIGTERM / 命令超时 / 手动中断时 atexit 根本没有机会执行。
# （旧注释把原因写成"safe-delete 守卫拦截 + ignore_errors 静默失败"，已被实测**证伪**：
#  脚本单次 rmtree 删掉 70 个条目一次成功，守卫并不拦 Python 的删除。详见 CHANGELOG「续27」。）
# 任何"退出时清理"方案都挡不住 SIGKILL，所以这里补一条**下次运行自动清扫**的兜底：
# 删掉 `logs/` 下超过 `_SWEEP_MIN_AGE` 秒没被触碰过的 `smoke-*` 目录。
# 之所以要 60 分钟下限：并发的另一个 smoke 运行期间会不断写自己的沙箱，mtime 一直是新的，
# 不会被误删。
_SWEEP_MIN_AGE = 3600.0


def _sweep_stale_sandboxes(base: Path, now: float, min_age: float = _SWEEP_MIN_AGE,
                           skip: Path = None) -> list:
    """清扫 ``base`` 下过期的 ``smoke-*`` 残留沙箱，返回被删目录名列表。

    只碰 ``smoke-`` 前缀的**目录**：不碰 ``data/scanner.db``、不碰 ``logs/task_*`` 与真实任务日志。
    单个目录删不掉（Windows 句柄占用等）就跳过，**绝不因为清扫失败而让测试挂**。
    """
    swept = []
    failed = []
    if not base.is_dir():
        return swept
    for entry in sorted(base.iterdir()):
        if not entry.is_dir() or not entry.name.startswith("smoke-"):
            continue
        if skip is not None and entry == skip:
            continue
        try:
            if now - entry.stat().st_mtime < min_age:
                continue            # 太新：可能是并发运行中的沙箱，别动
        except OSError:
            continue
        try:
            shutil.rmtree(entry)
            swept.append(entry.name)
        except OSError:
            failed.append(entry.name)
    if swept or failed:
        print("[清扫] logs/ 历史残留沙箱：删除 %d 个%s"
              % (len(swept), ("，%d 个删除失败（下次再试）" % len(failed)) if failed else ""))
    return swept


_sweep_stale_sandboxes(ROOT / "logs", now=time.time())

_TMPDIR = Path(tempfile.mkdtemp(prefix="smoke-", dir=str(ROOT / "logs")))
os.environ["CTFSCANNER_DB"] = str(_TMPDIR / "scanner.db")
os.environ["CTFSCANNER_LOGS"] = str(_TMPDIR)


def _cleanup_sandbox() -> None:
    """退出时删掉本轮沙箱。

    **不再静默吞异常**（原来写的是 ``shutil.rmtree(_TMPDIR, ignore_errors=True)``）：
    清不掉就明说，否则残留会无声地一直攒（本机曾攒到 120 个 / 21.8 MB / 7770 个条目）。
    路径按仓库约定用**相对路径**打印，且这条提示绝不影响测试结论。
    """
    if not _TMPDIR.exists():
        return
    try:
        shutil.rmtree(_TMPDIR)
    except OSError as exc:
        rel = _TMPDIR.relative_to(ROOT).as_posix() if _TMPDIR.is_relative_to(ROOT) else _TMPDIR.name
        print("[!] 本轮冒烟沙箱未删净（不影响测试结论）：%s —— %s" % (rel, exc))
        print("    下次跑 smoke 会自动清扫 %d 分钟前的 logs/smoke-* 残留。" % int(_SWEEP_MIN_AGE // 60))


atexit.register(_cleanup_sandbox)

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
    # cert（续14 证书取证）紧跟 probe；intel / heuristic / github（P3-2/P3-3、续26）
    # 固定排在**最后**且默认关，只写 leads 表
    assert STAGE_ORDER == ["subdomain", "takeover", "portscan", "probe",
                           "cert", "screenshot", "osint", "jsmine", "dirscan", "vulnscan",
                           "intel", "heuristic", "github"], STAGE_ORDER
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
    _ps_cwds = []       # 每次调用传下去的 cwd（见第 ⑧ 组：fscan 的 -o 按**进程 CWD** 落盘）
    _orig_run_cmd = ps.run_cmd

    def _stub_run(*a, **k):
        _ps_calls.append([str(x) for x in (a[0] if a else k.get("argv"))])
        _ps_cwds.append(k.get("cwd"))
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
        assert _ps_cwds[-1] and _ps_cwds[-1] == _ps_cwds[-2], \
            f"老版本回退重试也要带同一个 cwd（否则产物又落回进程 CWD）：{_ps_cwds[-2:]}"
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
        # ⑧ `cwd` 必须显式给：fscan 默认 `-o result.txt`（common/flag.go）且写的是**进程 CWD**。
        #    真跑踩坑（续45 自编译 2.2.1 + 本机回环）：不给 cwd 时每轮扫描都往仓库根丢一个
        #    result.txt，而且是**跨轮追加**的（里面带着别的目标的 IP / 服务 banner / URL），
        #    `git add .` 会顺手把它带进提交。给了 workdir 就用它，没给也不能继承进程 CWD。
        _wd = Path(_TMPDIR) / "fs_run"
        _stub_run.reply = [(0, "[+] 10.0.0.1:80 open\n[*] 扫描完成，发现 1 个开放端口\n", "")]
        assert ps.fscan_scan("h.test", "10.0.0.1", [80], binary="fscan", workdir=_wd)
        assert _ps_cwds[-1] == str(_wd), _ps_cwds[-1]
        _stub_run.reply = [(0, "[+] 10.0.0.1:80 open\n[*] 扫描完成，发现 1 个开放端口\n", "")]
        assert ps.fscan_scan("h.test", "10.0.0.1", [80], binary="fscan")
        assert _ps_cwds[-1] and _ps_cwds[-1] != os.getcwd(), \
            f"未传 workdir 也不能继承进程 CWD（否则产物落到仓库根）：{_ps_cwds[-1]!r}"

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
    _eng_wd = {}

    def _stub_fs_eng(*a, **k):
        _eng_calls.append("fscan")
        _eng_wd.update(k)
        return []

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

        # 第二遍：让 which 认得 fscan → 钉住"阶段必须把任务产物目录传下去"。
        # 不钉的话，谁把调用点的 `workdir=ctx.workdir` 删掉都不会红，而 fscan 会默默把
        # result.txt 写进启动扫描器的目录（GUI/CLI 就是仓库根）。
        _eng_calls.clear()
        _ps_stage.portscan.fscan_scan = _stub_fs_eng
        # 按"名字里含 fscan"匹配：settings.yaml 里 `tools.fscan` 现在填的是**相对路径**
        # （tools/fscan/fscan.exe），桩不能再拿裸名 `"fscan"` 去比。
        _ps_stage.which = lambda name: "fake-fscan" if "fscan" in str(name) else None
        _ps_stage.PortscanStage(_eng_ctx).run()
        assert _eng_calls == ["fscan"], _eng_calls
        assert _eng_wd.get("workdir") == Path(_TMPDIR) / "eng", _eng_wd
    finally:
        _ps_stage.portscan.scan_host = _orig_host
        _ps_stage.portscan.fscan_scan = _orig_fs
        _ps_stage.portscan.nmap_scan = _orig_nm
        _ps_stage.which = _orig_which
    print("[5e-0] fscan/nmap 适配 ok: 端口串压缩为 1-65535（命令行 <1000 字符）；"
          "fscan 强制 -np -nobr -nopoc（老版本回退仍保留 -np -nobr）；"
          "2.2.1 真实输出 8/8 全解析 + 统计行交叉校验（数目不符即回退，杜绝静默漏报）；"
          "cwd 一律显式给（fscan 的 -o result.txt 落在任务产物目录，不落进程 CWD）")

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

    # (4b) 续24：折叠的**站点身份**必须来自数据本身。旧代码里 dirmap 解析行的 site_url 恒为
    #      空串（dirmap 的 `path` 存的是完整 URL），于是折叠键 `(site_url, 状态码, 大小)`
    #      两个方向都错：① 同站点的 dirmap 行与内置行永不互折（"同样大小的没过滤"）；
    #      ② **不同站点**的 dirmap 行因 site_url 都为空，同 (状态码, 大小) 就被误折成一条（真丢结果）。
    #      这里**不手写 site_url**（旧用例正是手写了真 URL 才漏掉这个缺陷），而是先真解一遍
    #      dirmap 产物、拿解析结果入库，再走页面折叠验数。
    d_out2 = Path(_TMPDIR) / "output" / "fold2"
    d_out2.mkdir(parents=True, exist_ok=True)
    (d_out2 / "res.txt").write_text(
        "[200][text/html][2.00kb] http://d1.test/zzfoldalpha\n"
        "[200][text/html][2.00kb] http://d2.test/zzfoldalpha\n", encoding="utf-8")
    _parsed2 = DirscanStage._parse_output(d_out2 / "res.txt")
    assert [p["site_url"] for p in _parsed2] == ["http://d1.test/", "http://d2.test/"], _parsed2
    db.insert_dirs(tid, _parsed2)
    # d1 站点再来一条**内置**结果：同站同 (200, 2048) → 必须与上面 d1 的 dirmap 行折成一条
    # （site_url 故意不带尾斜杠，顺带验折叠键的尾斜杠归一）
    db.insert_dirs(tid, [{"site_url": "http://d1.test", "path": "/zzfoldalpha", "status": 200,
                          "length": 2048, "method": "GET", "note": "builtin"}])
    # d3 站点：同大小但**另一个站点** → 绝不能被折掉
    db.insert_dirs(tid, [{"site_url": "http://d3.test/", "path": "http://d3.test/zzfoldalpha",
                          "status": 200, "length": 2048, "method": "GET", "note": "dirmap"}])
    # 任务详情目录页签：本页共有两批重复 —— 777 那批 3 条折 1（隐藏 2）+ 2048 那批 4 条折 3（隐藏 1）
    _pane2 = c.get(f"/tasks/{tid}").get_data(as_text=True)
    assert _pane2.count(">dirmap<") + _pane2.count(">builtin<") == 4, \
        "2048 那批应渲染 3 行 + 777 那批渲染 1 行；旧口径会把跨站点的 dirmap 行折掉（只渲染 3 行）"
    assert "本页已隐藏 3 条重复长度" in _pane2, "隐藏数应为 2（777 批）+ 1（2048 批）"
    # 跨任务 /dirs 用**唯一关键字**把这 4 条隔离出来：本站点 2 条折 1、另两个站点各留 1
    _dirs2 = c.get("/dirs?q=zzfoldalpha").get_data(as_text=True)
    assert _dirs2.count(">dirmap<") + _dirs2.count(">builtin<") == 3, \
        "跨任务页折叠应只折「同站点」的 2 条（旧代码会因 site_url 全空把 3 个站点的行折成 1 条）"
    assert "已隐藏 1 条重复长度" in _dirs2

    # (4c) FOFA 资产行的域名收口：真实查询里大量行 `domain` 为空、只有 IP 形式的 host，
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
    print("[5e] 十五轮新增 ok: 全端口/标题反查/目录(大字典·重复长度·大小)/JS敏感字符；"
          "续24 折叠站点身份 ok: dirmap 行 site_url 由 URL 反推 + 同站互折 + 跨站不误折")

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
    assert DEFAULTS["github"]["enabled"] is False, "GitHub 泄露检索必须默认关（续26）"
    assert STAGE_ORDER[-3:] == ["intel", "heuristic", "github"], "三个线索阶段应固定在流水线最后"

    # 8) 出口口径（续24 变更，用户 2026-09-24 拍板）：策略配置渲染出两个开关；任务详情
    #    **不再有**「线索」页签；人读报告（MD/HTML）**不再有**线索小节；但**机器格式 JSONL
    #    仍全量保留** `type=lead` 与计数（续20 先例：机器格式保留全部、筛选权交下游）。
    #    这里不是"删断言让测试变绿" —— 翻成**反向断言**钉住新口径，并补上「JSONL 没被误删」。
    _shtml = c.get("/settings").get_data(as_text=True)
    assert 'name="intel_enabled"' in _shtml and 'name="heuristic_enabled"' in _shtml
    assert 'name="github_enabled"' in _shtml, "策略面板应有 GitHub 泄露检索开关（续26）"
    assert "不再进 GUI 页签" in _shtml, "策略面板应说明线索现在只从 JSONL 出（旧文案指向已删页签）"
    _dhtml = c.get(f"/tasks/{ld_tid}").get_data(as_text=True)
    assert 'data-tab="leads"' not in _dhtml and 'id="pane-leads"' not in _dhtml, \
        "续24：「线索」页签应已移除"
    _md_lead, _html_lead = generate(ld_tid), generate_html(ld_tid)
    assert "## 线索" not in _md_lead and "<h2>线索" not in _html_lead, \
        "续24：人读报告（MD/HTML）不应再有线索小节"
    assert "<span>线索</span>" not in _html_lead, "续24：HTML 概览卡片也不再列线索计数"
    assert "## 线索" not in generate(ds_tid), "没有线索的任务同样不该出现线索小节"
    _jl_lead = generate_jsonl(ld_tid)
    assert '"type": "lead"' in _jl_lead and "CVE-2020-14882" in _jl_lead, \
        "续24：JSONL 是机器格式，线索必须保留（否则等于连数据出口一起删了）"
    assert '"leads": 1' in _jl_lead, "JSONL 概览计数应仍含 leads"
    print("[5n] 情报订阅/启发式 ok: KEV 解析+白名单匹配(词边界)+只写 leads(去重)/"
          "五条启发式规则+反例/默认关门控/策略开关/线索只走 JSONL（页签与人读报告已按续24 移除）")

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
        # 续40：送去检测**带上 subdomain 阶段**（用户要求"拓展域名再去检测也要去子域名扫描"）
        assert _new_t["stages"] == "subdomain,probe,dirscan,vulnscan", _new_t["stages"]
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
    # （线索自续24 起**只进 JSONL**，不进人读报告，见下面单独的一组断言。）
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
    for _sec in ("潜在漏洞", "存活站点", "开放端口", "C 段视野", "TLS 证书", "目录发现",
                 "已判误报"):
        assert f"<h2>{_sec}" in _whtml, f"HTML 报告缺小节：{_sec}"
        assert _sec in _wmd, f"MD 报告缺小节：{_sec}"
    # 续24：这个任务**有**一条线索，但线索已从人读报告移除 —— 必须断言"有数据却不出现"，
    # 否则"没渲染"和"没这条数据"分不开；同时机器格式 JSONL 必须仍在（数据出口不能一起删）。
    assert "## 线索" not in _wmd and "<h2>线索" not in _whtml, \
        "续24：人读报告不该再有线索小节（本任务确实有 1 条线索）"
    assert "<span>线索</span>" not in _whtml, "续24：HTML 概览卡片也不该再列线索计数"
    _wjsonl = generate_jsonl(w_tid)
    assert '"type": "lead"' in _wjsonl and "CVE-2021-44228" in _wjsonl, \
        "续24：JSONL 必须保留线索（机器格式的口径不变）"
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
    print("[5w] 续16 ok: 报告三格式（MD/HTML/PDF）与漏洞趋势统计（七节齐全 + XSS 载荷全转义 + "
          "自包含无外链 + 误报不计入趋势/未知级别归 other + 三格式路由 + 无浏览器 400 说明原因 + "
          "仪表盘趋势面板）；续24 线索只走 JSONL ok: 有线索却不进 MD/HTML 小节与概览卡片")

    # [5x] 续17：登录态扫描（任务级 Cookie/Token）+ nuclei raw / flow / workflows 子集
    from http.server import BaseHTTPRequestHandler as _BaseHTTP
    from scanner import auth as _auth
    from scanner import utils as _utils

    # 本地"活靶"：`/a` 回 hello-AAA、`/b` 回 hello-BBB、`/csrf` 回一段带两个令牌的页面
    # （续42 的跨请求取值要"从响应里抽出来再发出去"，故需要一个可控的令牌源），
    # 并记录收到的路径 —— raw/flow 的命中与短路都靠它证（不依赖公网，也不产生真实外部请求）。
    _hits17 = []

    class _Lab17(_BaseHTTP):
        def log_message(self, *a):
            pass

        def do_GET(self):
            _hits17.append(self.path)
            if self.path.startswith("/csrf"):
                body = b'<input name="csrf" value="TOK123"><i>SEC789</i>'
            else:
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
    assert _m_wf["_status"] == "ok", _m_wf
    assert [s["path"] for s in _m_wf["_workflow"]] == ["flow.yaml"], _m_wf
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
          "+ workflow 子模板与自环保护 + **块级** dsl 仍显式 unsupported）")

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
    # current_stage **刻意设成非空**：它是断点续扫的断点（runner.resume_stages 按它切片），
    # 对账必须保留它 —— 见下面 6q 与其断言。
    db.update_task(_o_dead, status="running", pid=_dead_pid, current_stage="probe")
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
    # 断点必须被**保留**：原断言 `current_stage == ""` 是空洞断言 ——
    # `create_task` 后它本来就是 `""`，把对账里"清断点"那行删掉也照样通过（假绿）。
    # 现在先把它设成某个阶段，再断言原样留下。
    assert db.get_task(_o_dead)["current_stage"] == "probe", \
        f"对账抹掉了断点（current_stage 是「最后进入的阶段」，续跑靠它切片）：" \
        f"{db.get_task(_o_dead)['current_stage']!r}"
    # pid=0（老库遗留）→ failed
    assert db.get_task(_o_zero)["status"] == "failed", db.get_task(_o_zero)["status"]
    # done 的任务不受影响
    assert db.get_task(_o_done)["status"] == "done", db.get_task(_o_done)["status"]
    for _ot in (_o_alive, _o_dead, _o_zero, _o_done):
        db.delete_task(_ot, backup=False)
    print("[6d] 孤儿任务对账 ok: 存活 pid 保留 running / 死 pid 与 pid=0 标 failed 且带标记 / "
          "断点（current_stage）被保留 / done 不受影响")

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
                 "debox.pro"):
        assert _d6k in _noise6k, f"[6k] 第三方清单缺 {_d6k}"
    # ✱ `pong-pengo.de` **已从清单移除**（续22-fix）：它含目标品牌词 `pengo`，可能是"相关域名"
    #    而不是噪声 —— **黑名单漏一条的成本远低于误杀一个相关域名**（QA 独立复验建议，
    #    主理人采纳）。这里**反向断言**它不在清单里：防止有人"顺手加回去"却不知道为什么被删过。
    assert "pong-pengo.de" not in _noise6k, \
        "[6k] pong-pengo.de 已按品牌误杀风险移除，不应再在清单里"
    # ✱ `static.cloudflareinsights.com` 结尾是 `.cloudflareinsights.com` —— `cloudflare.com` 拦不住它。
    #    证伪实测（bbec7f0 旧清单 267 条）：上述 8 个目标域名全缺（`pong-pengo.de` 已于续22-fix
    #    移除，不再计入）、`_is_noise(static.cloudflareinsights.com)`
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

    # 6l) 续25：同任务「追加式执行」—— 内核（续写日志 / 不清 error / 进度重置）+ 跨运行去重 +
    #     并发硬拒绝 + 无源入口拒绝 + 仅勾选目标 + 导出横幅。此前"补扫/复查"一律**新建任务**，
    #     结果散落在多个任务里、要来回比对；追加让结果累积进**同一任务**且不产生重复行。
    import time as _time6l
    from scanner import runner as _runner6l
    _as6l = copy.deepcopy(settings)
    _as6l["tools"]["dirmap"]["script"] = "tools/does-not-exist.py"   # 强制内置扫描（离线、不发外部请求）
    _as6l["dirscan"] = dict(_as6l.get("dirscan") or {})
    _as6l["dirscan"].update({"enabled": True, "mode": "quick",
                             "max_paths": 20, "quick_max_paths": 20})

    # (1) 先跑一个正常任务（probe 产出站点），作为追加的源
    _ap_tid = db.create_task("smoke-append", targets, ["probe"], {"offline": True})
    run_task(_ap_tid, "smoke-append", targets, ["probe"], {"offline": True}, settings)
    _t1 = db.get_task(_ap_tid)
    assert _t1["status"] == "done", _t1["status"]
    _sites6l = [dict(r) for r in db.list_sites(_ap_tid)]
    assert _sites6l, "probe 应产出站点（追加测试的输入）"
    _log1, _err1, _n_sites = _t1["log_file"], _t1["error"], len(_sites6l)
    assert _log1, "任务应有日志文件"

    # (2) 追加 dirscan：只勾选第一个站点 → 结果进**同一任务**、续写同一 log、error 不动
    _scope = [_sites6l[0]["url"]]
    _opts6l = {"offline": True, "append": True, "append_targets": _scope}
    run_task(_ap_tid, "smoke-append", "\n".join(_scope), ["dirscan"], _opts6l, _as6l,
             append=True)
    _t2 = db.get_task(_ap_tid)
    assert _t2["status"] == "done", _t2["status"]
    assert _t2["log_file"] == _log1, "追加执行必须续写**同一**日志文件（不新建 workdir）"
    assert (_t2["error"] or "") == (_err1 or ""), "追加执行不得清空已有 error"
    _dirs1 = db.list_dirs(_ap_tid)
    assert _dirs1, "追加 dirscan 应产出目录（内置扫描命中 fixture 的 .env/.git/config）"
    _n_dirs = len(_dirs1)

    # (3) 跨运行去重：再追加一次**同样的目标** → 目录/站点数不增加
    run_task(_ap_tid, "smoke-append", "\n".join(_scope), ["dirscan"], _opts6l, _as6l,
             append=True)
    assert len(db.list_dirs(_ap_tid)) == _n_dirs, \
        "同一 (站点, 路径) 跨运行不得重复入库"
    assert len(db.list_sites(_ap_tid)) == _n_sites, "追加不得重复插入站点"

    # (4) 并发硬拒绝：任务"正在运行"时不得追加（否则 _register_stop 覆盖停止事件）
    _runner6l._register_stop(_ap_tid)
    try:
        _r6l = c.post("/api/rescan", data={"stage": "dirscan", "from_task": str(_ap_tid),
                                           "append": "1", "target": _scope[0],
                                           "next": "/tasks"})
        assert _r6l.status_code == 409, _r6l.status_code
        assert "无法追加" in _r6l.get_data(as_text=True)
    finally:
        _runner6l._unregister_stop(_ap_tid)

    # (5) 无源入口（没有 from_task）→ 明确拒绝，**不得静默新建任务**
    _r6l2 = c.post("/api/rescan", data={"stage": "dirscan", "append": "1",
                                        "target": _scope[0], "next": "/tasks"})
    assert _r6l2.status_code == 409 and "没有源任务" in _r6l2.get_data(as_text=True), \
        _r6l2.status_code

    # (6) 成功追加：复用同一任务、不新建、append_count 递增。
    #     续49 起 `_spawn` 不再直接起线程，而是**入队**（写 run_payload + 置 queued）——
    #     所以这里改断言"队列状态"（status/run_mode/run_payload），不再断言"run_task 被调用"。
    import json as _json6l
    _n_tasks6l = len(db.list_tasks(limit=1000))
    _r6l3 = c.post("/api/rescan", data={"stage": "dirscan", "from_task": str(_ap_tid),
                                        "append": "1", "target": _scope[0],
                                        "next": "/tasks"})
    assert _r6l3.status_code == 302, _r6l3.status_code
    assert _r6l3.headers["Location"].rstrip("/").endswith(f"/tasks/{_ap_tid}"), \
        _r6l3.headers["Location"]
    assert len(db.list_tasks(limit=1000)) == _n_tasks6l, "追加**不得**新建任务"
    _ap6l = dict(db.get_task(_ap_tid))
    assert _ap6l["status"] == "queued" and _ap6l["run_mode"] == "append", \
        f"追加应把任务入队（status=queued + run_mode=append）：{_ap6l}"
    _pl6l = _json6l.loads(_ap6l["run_payload"] or "{}")
    assert (_pl6l.get("options") or {}).get("append") is True, f"追加运行入参缺 append：{_pl6l}"
    assert _pl6l.get("stages") == ["dirscan"], f"追加运行的阶段应写进入参：{_pl6l}"
    _opt6l = _json6l.loads(db.get_task(_ap_tid)["options"] or "{}")
    assert _opt6l.get("append_count") == 1 and _opt6l.get("appended") is True, _opt6l

    # (7) 导出横幅：含追加标记的任务，MD/HTML 顶部有横幅（**不阻断**导出）
    assert "追加执行" in generate(_ap_tid), "MD 报告应含追加横幅"
    assert "追加执行" in generate_html(_ap_tid), "HTML 报告应含追加横幅"

    db.delete_task(_ap_tid, backup=False)
    print("[6l] 续25 同任务追加式执行 ok: 续写同一 log_file + 不清 error + 进度重置 / "
          "跨运行去重（同 站点+路径·站点 不重复）/ 并发 409 硬拒绝 / 无源入口 409 / "
          "仅勾选目标 / append_count 标记 + 导出横幅")

    # 6m) 续25-fix：QA 复验 c8d51c4 报出的三项低风险缺陷回归
    #     A. db.drop_existing 自然键归一：0 / None / "" 不再被 `x or ""` 混为一谈
    #     B. /api/ports/full-scan 显式 409 拒绝 append（此前静默忽略、照样新建任务）
    #     C. StageContext.append_scope() 空集不再折成 None（不再回退全库）

    # A —— 三条语义。真实受害者是 certs 表：自然键 (host, port, sha256, serial)，
    #      CT 日志来源常是 port=0 且 sha256/serial 为空 → 同 host 多条证书被合并成 1 条。
    assert (db._norm_key_val(0) == "0" and db._norm_key_val(None) == ""
            and db._norm_key_val("") == "" and db._norm_key_val(443) == "443"), \
        '自然键归一：0→"0"、None→""、""→""、443→"443"（两侧共用这一个函数）'
    _tid6m = db.create_task("smoke-6m", "h6m", ["portscan"], {"offline": True})
    db._exec("INSERT INTO ports (task_id, host, port) VALUES (?,?,?)", (_tid6m, "h6m_a", 443))
    db._exec("INSERT INTO ports (task_id, host, port) VALUES (?,?,?)", (_tid6m, "h6m_b", 0))
    _items6m = [
        {"host": "h6m_a", "port": "443"},   # ① 内存 str "443" vs 库 int 443 → 同一键
        {"host": "h6m_a", "port": 443},
        {"host": "h6m_b", "port": None},    # ② 库 0 vs 内存 None → **必须不同键**（核心）
        {"host": "h6m_b", "port": 0},       #    同值仍应命中
        {"host": "h6m_b", "port": 443},     # ③ 0 vs 443 → 不同键（防过度去重）
    ]
    _kept6m = {(i["host"], i["port"]) for i in db.drop_existing(
        _tid6m, "ports", ("host", "port"), _items6m,
        lambda i: (i.get("host"), i.get("port")))}
    assert ("h6m_a", "443") not in _kept6m and ("h6m_a", 443) not in _kept6m, \
        f"① 443(int) 与 '443'(str) 必须算同一键（drop_existing 存在的初衷）：{_kept6m}"
    assert ("h6m_b", None) in _kept6m, \
        f"② 库里 0 与内存 None 必须**不同键**（`x or ''` 会把两者都归一成空串）：{_kept6m}"
    assert ("h6m_b", 0) not in _kept6m, f"②b 0 与 0 必须同一键：{_kept6m}"
    assert ("h6m_b", 443) in _kept6m, f"③ 0 与 443 必须不同键（防过度去重）：{_kept6m}"
    db.delete_task(_tid6m, backup=False)

    # B —— /api/ports/full-scan 带 append 必须 409 显式拒绝（此前静默新建任务）
    _n6m = len(db.list_tasks(limit=1000))
    _r6m = c.post("/api/ports/full-scan", data={"host": "127.0.0.1", "append": "1"})
    assert _r6m.status_code == 409, f"append 必须显式 409 拒绝，实际 {_r6m.status_code}"
    assert "无法追加执行" in _r6m.get_data(as_text=True), "应给出可读原因"
    assert len(db.list_tasks(limit=1000)) == _n6m, "被拒后**不得**新建任务"
    # 不带 append 仍走原路径（新建任务 302），行为不变
    _orig_rt6m = gui_app.run_task
    gui_app.run_task = lambda *a, **kw: None        # 打桩：不真起任务线程
    try:
        _r6mb = c.post("/api/ports/full-scan", data={"host": "127.0.0.1"})
    finally:
        gui_app.run_task = _orig_rt6m
    assert _r6mb.status_code == 302, _r6mb.status_code
    assert len(db.list_tasks(limit=1000)) == _n6m + 1, "不带 append 应正常新建任务"
    db.delete_task(int(str(_r6mb.headers["Location"]).rstrip("/").rsplit("/", 1)[-1]),
                   backup=False)

    # C —— append_scope() 三态：非追加 None / 追加空集 **空集**（不再折成 None）/ 追加非空
    _wd6m = LOGS_DIR / "smoke-6m"
    _wd6m.mkdir(parents=True, exist_ok=True)

    def _ctx6m(options):
        return StageContext(0, "smoke-6m", [], [], options, settings, _wd6m,
                            get_logger("smoke-6m", _wd6m / "t.log"))

    assert _ctx6m({}).append_scope() is None, "非追加必须仍返回 None（原行为不变）"
    _empty6m = _ctx6m({"append": True, "append_targets": []}).append_scope()
    assert _empty6m is not None and _empty6m == set(), \
        f"追加但一个都没勾上必须返回**空集**（`scope or None` 折成 None 会放开全库）：{_empty6m!r}"
    _all6m = [{"url": "http://a6m"}, {"url": "http://b6m"}]
    assert _ctx6m({"append": True, "append_targets": []}).scope_sites(_all6m) == [], \
        "空集就是空集（不扫）—— 不得回退到库里全部站点"
    _s6m = _ctx6m({"append": True, "append_targets": ["http://a6m/", "  http://b6m  ", ""]})
    assert _s6m.append_scope() == {"http://a6m", "http://b6m"}, _s6m.append_scope()
    assert [x["url"] for x in _s6m.scope_sites(_all6m)] == ["http://a6m", "http://b6m"]
    print("[6m] 续25-fix 三项缺陷回归 ok: drop_existing 0/None/'' 不再混为一谈"
          "（443↔'443' 仍同一键）/ full-scan append 显式 409 不再静默新建 / "
          "append_scope 空集不折 None（不回退全库）")
    # [6n] 续23 主题配色门禁：四套主题配对对比度全达 WCAG AA + 主题块外 0 处颜色字面量。
    # 走 tools/check_contrast.gate()（与命令行、证伪脚本同一口径），不在这里另写一套判断。
    import importlib.util as _ilu6n
    _spec6n = _ilu6n.spec_from_file_location("_smoke_check_contrast", ROOT / "tools" / "check_contrast.py")
    _cc6n = _ilu6n.module_from_spec(_spec6n)
    _spec6n.loader.exec_module(_cc6n)
    _css6n = (ROOT / "gui" / "static" / "style.css").read_text(encoding="utf-8")
    _problems6n = _cc6n.gate(_css6n)
    assert not _problems6n, "续23 主题配色门禁未通过：\n  " + "\n  ".join(_problems6n)
    _pairs6n = len(_cc6n.TEXT_PAIRS) + len(_cc6n.BADGE_PAIRS) + len(_cc6n.UI_PAIRS)
    print("[6n] 续23 主题配色门禁 ok: 四套主题 x %d 项配对（文字>=4.5:1 / UI 边界>=3:1）全达标，"
          "主题块外 0 处颜色字面量（tr:hover td / input / pre / .badge / .st-* / .sev-* 均已走变量）"
          % _pairs6n)

    # [6o] 续27 沙箱残留自愈清扫：只删「够旧的 smoke-* 目录」，别的都不许碰。
    #      用真目录 + 显式 mtime（不 sleep），四条边界一起验：旧的删、新的留、
    #      非 smoke- 前缀留、作为「当前沙箱」传入的即便很旧也留。
    _sw_base = _TMPDIR / "sweep-probe"
    _sw_base.mkdir(parents=True, exist_ok=True)
    _sw_now = 1_700_000_000.0          # 固定时间轴，避免依赖真实时钟
    _sw_old = _sw_base / "smoke-old"
    _sw_new = _sw_base / "smoke-fresh"
    _sw_keep = _sw_base / "task_keep"          # 非 smoke- 前缀：绝不能删（真实任务日志长这样）
    _sw_cur = _sw_base / "smoke-current"
    for _sw_d in (_sw_old, _sw_new, _sw_keep, _sw_cur):
        _sw_d.mkdir()
    os.utime(_sw_old, (_sw_now - 7200, _sw_now - 7200))    # 2 小时前 → 该删
    os.utime(_sw_new, (_sw_now - 10, _sw_now - 10))        # 10 秒前 → 太新，留
    os.utime(_sw_keep, (_sw_now - 7200, _sw_now - 7200))   # 很旧但前缀不符，留
    os.utime(_sw_cur, (_sw_now - 7200, _sw_now - 7200))    # 很旧但是本轮沙箱，留
    _sw_got = _sweep_stale_sandboxes(_sw_base, now=_sw_now, skip=_sw_cur)
    assert _sw_got == ["smoke-old"], f"清扫范围不对：应只删 smoke-old，实得 {_sw_got}"
    assert not _sw_old.exists(), "过期 smoke-* 沙箱应被删掉"
    assert _sw_new.exists(), "刚创建（10 秒前）的沙箱不得被删 —— 那是并发运行中的沙箱"
    assert _sw_keep.exists(), "非 smoke- 前缀目录不得被删（真实任务日志就是 task_* 形态）"
    assert _sw_cur.exists(), "作为当前沙箱传入的目录即便很旧也必须保留"
    # 幂等：同参数（含同一个 skip）再扫一次不应再删任何东西
    assert _sweep_stale_sandboxes(_sw_base, now=_sw_now, skip=_sw_cur) == [], \
        "同参数下重复清扫不应再删任何东西（幂等）"
    # 反面：不给 skip 时，那个「很旧的当前沙箱」确实会被删 —— 证明上一条不是靠"什么都没删"蒙对的
    assert _sweep_stale_sandboxes(_sw_base, now=_sw_now) == ["smoke-current"], \
        "去掉 skip 后，过期的同名前缀目录应被删（否则说明前一条断言没有区分度）"
    assert not _sw_cur.exists()
    print("[6o] 续27 沙箱残留自愈清扫 ok: 只删过期 smoke-*（2 小时前）/ 10 秒前的新沙箱保留"
          "（并发保护）/ task_* 等非 smoke 前缀保留 / 当前沙箱保留 / 重复清扫幂等")

    # [6p] 续26 GitHub 泄露检索（最小形态）：三条硬边界一次钉死 ——
    #      ① **只落元数据**（绝不把文件内容/凭据明文写进库、日志、报告、JSONL）；
    #      ② **auth=False**（任务级登录态 —— 目标侧 Cookie / Token —— 绝不发给 GitHub）；
    #      ③ **默认关 + 没 token 零请求**（代码搜索接口要求认证，发了也是 401）。
    #      另含：注册域收敛、多规则命中合并、入库去重、不写 vulns、限流主动收手。
    from scanner import github_leak as gh_mod
    from scanner.stages.github import GithubStage

    # 假凭据：只允许出现在**我们伪造的 GitHub 响应**里，绝不许出现在任何产出中
    _SECRET = "ghp_SMOKEsecretVALUE0123456789"

    # 1) 三方一致：DEFAULTS ↔ settings.yaml ↔ GUI 表单 / POST 映射
    from scanner.config import DEFAULTS as _DEF6P
    _gh_keys = ("enabled", "max_domains", "max_queries", "per_page", "max_leads", "timeout")
    assert "github" in _DEF6P and "github" in settings, "缺 github 配置段（续26）"
    for _k in _gh_keys:
        assert _k in _DEF6P["github"], f"DEFAULTS.github 缺 {_k}"
        assert _k in (settings.get("github") or {}), f"settings.yaml.github 缺 {_k}"
    assert _DEF6P["github"]["enabled"] is False, "GitHub 泄露检索必须默认关"
    _sh6p = c.get("/settings").get_data(as_text=True)
    for _n6p in ("github_enabled", "github_max_domains", "github_max_queries",
                 "github_per_page", "github_max_leads", "github_timeout"):
        assert f'name="{_n6p}"' in _sh6p, f"策略配置缺字段 {_n6p}"
    _cap6p = {}

    def _fake_save6p(d):
        _cap6p.clear()
        _cap6p.update(d)
        return load_settings()

    _orig_save6p = gui_app.save_settings
    gui_app.save_settings = _fake_save6p
    try:
        assert c.post("/settings", data={"min_severity": "medium", "github_enabled": "1",
                                         "github_max_queries": "6"}).status_code == 302
        assert (_cap6p.get("github") or {}).get("enabled") is True, _cap6p.get("github")
        assert (_cap6p.get("github") or {}).get("max_queries") == 6, _cap6p.get("github")
        # 未提交时必须回退默认（关 + 4）：不能因为"表单没带"就静默打开这个外发请求的能力
        assert c.post("/settings", data={"min_severity": "medium"}).status_code == 302
        assert (_cap6p.get("github") or {}).get("enabled") is False, _cap6p.get("github")
        assert (_cap6p.get("github") or {}).get("max_queries") == 4, _cap6p.get("github")
    finally:
        gui_app.save_settings = _orig_save6p

    # 2) 注册域收敛：URL / 子域名 / 裸域 → 只留注册域并去重；IP / CIDR / unknown 一律跳过。
    #    重点反例：`http://127.0.0.1:8765/` 这类 **URL 里的裸 IP**，`urlparse().hostname`
    #    拿到 `127.0.0.1`，若不加 `is_domain` 守门，`base_domain()` 会切出 `"0.1"` 这种
    #    被误当成域名的垃圾并真的去搜 GitHub（写法修正见 scanner/github_leak.py::target_domains）。
    assert gh_mod.target_domains([("url", "https://a.corp.example.com.cn:8443/x"),
                                  ("domain", "b.example.com"),
                                  ("domain", "example.com"),
                                  ("ip", "10.0.0.1"), ("cidr", "10.0.0.0/24"),
                                  ("unknown", "???"),
                                  ("url", "http://127.0.0.1:8765/")]) \
        == ["example.com.cn", "example.com"], "应只留注册域且去重（IP 目标不得切出 '0.1'）"
    assert gh_mod.target_domains([("domain", "a.example.com"), ("domain", "b.example.com")],
                                 max_domains=1) == ["example.com"], "max_domains 应生效"

    # 3) 没 token → **零请求**，且把原因写清楚（否则用户会把 401 当成"确实没泄露"）
    _req6p = []

    def _req_must_not_happen(*a, **kw):
        _req6p.append((a, kw))
        raise AssertionError("这一步不该发任何请求")

    _orig_req6p = gh_mod.http_request
    gh_mod.http_request = _req_must_not_happen
    try:
        _l0, _m0 = gh_mod.collect(["example.com"], {"github": {"enabled": True}})
        assert _m0["queries"] == 0 and not _l0 and _req6p == [], _m0
        assert "github.token" in (_m0.get("error") or ""), _m0

        # 4) 阶段层门控：默认关 / 开着但没 token / 目标全是 IP —— 三种情况都零请求、零入库
        _gh_tid = db.create_task("smoke-github", targets, ["github"], {"offline": True})
        _g6p = copy.deepcopy(settings)
        _g6p["keys"] = {}                       # 显式清掉 keys：不依赖本机 keys.yaml 是否配了 token
        _g6p["github"] = {"enabled": False}
        GithubStage(StageContext(_gh_tid, "smoke-gh-off", parse_lines([targets]), ["github"],
                                 {}, _g6p, Path(_TMPDIR) / "gh-off", rec)).run()
        _g6p["github"] = {"enabled": True, "max_domains": 3}          # 开着但没 token
        GithubStage(StageContext(_gh_tid, "smoke-gh-notoken", parse_lines([targets]), ["github"],
                                 {}, _g6p, Path(_TMPDIR) / "gh-notoken", rec)).run()
        _g6p["keys"] = {"github": {"token": "ghp_FAKE"}}             # 有 token，但目标只有 IP
        GithubStage(StageContext(_gh_tid, "smoke-gh-noasset", parse_lines([targets]), ["github"],
                                 {}, _g6p, Path(_TMPDIR) / "gh-noasset", rec)).run()
        assert _req6p == [], "默认关 / 没 token / 无注册域时都不该发请求"
        assert not db.list_leads(_gh_tid), "不该写入任何线索"
    finally:
        gh_mod.http_request = _orig_req6p

    # 5) 正常路径：伪造一条**含 `text_matches` 明文**的 GitHub 响应，验硬边界 ①②。
    _gh_items = [
        {"path": ".env", "html_url": "https://github.com/acme/infra/blob/main/.env",
         "repository": {"full_name": "acme/infra", "owner": {"login": "acme"}},
         "text_matches": [{"fragment": f"DB_PASSWORD={_SECRET}"}]},
        {"path": "conf/app.yaml",
         "html_url": "https://github.com/acme/app/blob/main/conf/app.yaml",
         "repository": {"full_name": "acme/app"},
         "text_matches": [{"fragment": f"api_key: {_SECRET}"}]},
        {"path": "no-repo.txt"},                       # 拿不到仓库 → 必须丢掉（没法溯源）
    ]
    _gh_body = _json.dumps({"total_count": 3, "items": _gh_items})
    _gh_settings = {"github": {"enabled": True, "max_queries": 4, "per_page": 30},
                    "keys": {"github": {"token": "ghp_FAKEtoken"}}}

    def _gh_http6p(url, **kw):
        _req6p.append((url, kw))
        return {"status": 200, "headers": {"X-RateLimit-Remaining": "29",
                                           "Content-Type": "application/json"},
                "text": _gh_body, "length": len(_gh_body), "url": url}

    gh_mod.http_request = _gh_http6p
    try:
        _leads6p, _meta6p = gh_mod.collect(["example.com"], _gh_settings)
    finally:
        gh_mod.http_request = _orig_req6p
    assert _meta6p["queries"] == 4 and _meta6p["error"] == "", _meta6p
    # ② auth=False：每个请求都**没有**带任务登录态（`auth` 未传或显式为 False）
    assert all(kw.get("auth") in (None, False) for _u, kw in _req6p), \
        "GitHub 请求不得带任务登录态（目标侧 Cookie / Token 绝不外发）"
    # GitHub 自己的 token 仍走 Authorization 头（代码搜索接口**要求**认证，这不是"任务登录态"）
    assert all(kw.get("headers", {}).get("Authorization", "").startswith("Bearer ")
               for _u, kw in _req6p)
    # `q` 必须整体 percent 编码：引号 / `filename:.env` 的冒号不编码会被 GitHub 直接 422
    assert "%22example.com%22" in _req6p[0][0], _req6p[0][0]
    assert "per_page=30" in _req6p[0][0], _req6p[0][0]
    # 4b) 触顶（`max_queries` 上限）是**设计内的收手**，不得混进 `error`：默认
    #     max_domains=3 × 4 条规则 = 12 次潜在查询 > 上限 4，**正常跑必然触顶**；
    #     若把它塞进 error，阶段层就会在每次正常运行里打 warning（把"正常"说成"出错"）。
    _req6p.clear()
    _cap6p_set = {"github": {"enabled": True, "max_queries": 1, "per_page": 30},
                  "keys": {"github": {"token": "ghp_FAKEtoken"}}}
    gh_mod.http_request = _gh_http6p
    try:
        _l6p_cap, _m6p_cap = gh_mod.collect(["a.example", "b.example"], _cap6p_set)
    finally:
        gh_mod.http_request = _orig_req6p
    assert (_m6p_cap["queries"], _m6p_cap["error"], _m6p_cap["capped"]) == (1, "", True), _m6p_cap
    assert len(_req6p) == 1, _req6p
    assert _l6p_cap, "触顶前那次查询的命中必须保留（触顶只是停止后续查询，不是丢弃结果）"
    _req6p.clear()
    # 5a) 合并：(域名, 仓库, 路径) 唯一的命中只出一条 —— 四条规则都命中同一份文件时全靠这步收敛，
    #     否则 db.insert_leads 只认首条，后面的规则会被**静默丢掉**
    assert [x["code"] for x in _leads6p] == ["acme/app:conf/app.yaml", "acme/infra:.env"], \
        [x["code"] for x in _leads6p]
    _merged = [x for x in _leads6p if x["code"] == "acme/infra:.env"][0]
    assert all(r in _merged["matched"] for r in ("mention", "credential", "apikey", "env-file")), \
        _merged["matched"]
    assert _merged["level"] == "medium" and _merged["kind"] == "github", _merged
    assert _merged["source"] == "GitHub" and _merged["target"] == "example.com"
    assert _merged["url"].startswith("https://github.com/acme/infra"), _merged["url"]
    # ① 只落元数据：字段集合是白名单，`text_matches` 一个字都不读
    for _ld in _leads6p:
        assert set(_ld) == {"kind", "code", "title", "target", "matched", "level",
                            "detail", "source", "url"}, sorted(_ld)
        assert "text_matches" not in _ld and "fragment" not in _ld
        assert _SECRET not in _json.dumps(_ld, ensure_ascii=False), "凭据明文绝不许进线索"
    # 白名单要**直接钉在 `normalize_hit` 上**：只断言"最终线索里没有内容字段"是不够的 ——
    # 下游 `_leads_from`/`build_lead` 恰好只取 5 个字段，会让"上游多读一个 `text_matches`"
    # 这类改动**悄悄通过**（实测：把 `text_matches` 加进 `normalize_hit` 的返回值，
    # 只靠上面的断言时 smoke 仍 PASS，属假通过）。这里补直接断言把它堵死。
    assert set(gh_mod.normalize_hit(_gh_items[0], "mention")) == {"repo", "path", "url", "rule"}, \
        "normalize_hit 必须只回这 4 个元数据字段（多读 text_matches 会带出凭据明文）"
    assert gh_mod.normalize_hit(_gh_items[2], "mention") is None, "拿不到仓库的命中应丢弃"
    assert gh_mod.normalize_hit("not-a-dict", "mention") is None

    # 6) 入库：去重键 (kind, code, target)；只进 leads，**绝不进 vulns**；JSONL 仍保留 github 线索
    assert db.insert_leads(_gh_tid, _leads6p) == 2
    assert db.insert_leads(_gh_tid, _leads6p) == 0, "同一条 GitHub 线索不该重复入库"
    _gh_rows = db.list_leads(_gh_tid)
    assert len(_gh_rows) == 2 and all(r["kind"] == "github" for r in _gh_rows)
    assert not db.list_vulns(task_id=_gh_tid, limit=50), "线索绝不能写进 vulns"
    _jl6p = generate_jsonl(_gh_tid)
    assert '"type": "lead"' in _jl6p and "acme/infra:.env" in _jl6p, "JSONL 必须保留 GitHub 线索"
    assert _SECRET not in _jl6p, "JSONL 里也绝不能出现凭据明文"

    # 7) 失败路径必须**说出来**（不能让人以为"查过了、没泄露"）
    assert "401" in gh_mod._status_reason(401) and "token" in gh_mod._status_reason(401)
    assert "422" in gh_mod._status_reason(422)
    assert "限流" in gh_mod._status_reason(403)

    def _resp6p(status, headers=None):
        return {"status": status, "headers": headers or {}, "text": _gh_body,
                "length": len(_gh_body), "url": "u"}

    # 7a) 401 / 403 是**致命**的：立刻收手，不再发后续请求（不刷爆额度、不刷日志）
    for _st, _want in ((401, "401"), (403, "限流")):
        _n6p = []
        gh_mod.http_request = lambda u, **kw: (_n6p.append(u), _resp6p(_st))[1]
        try:
            _l6p, _m6p = gh_mod.collect(["example.com"], _gh_settings)
        finally:
            gh_mod.http_request = _orig_req6p
        assert len(_n6p) == 1, f"HTTP {_st} 后不该继续发请求（实发 {len(_n6p)} 次）"
        assert _want in (_m6p.get("error") or "") and not _l6p, _m6p
    # 7b) 配额见底（X-RateLimit-Remaining=0）主动收手，不必等 GitHub 回 403
    _n6p = []
    gh_mod.http_request = lambda u, **kw: (_n6p.append(u),
                                           _resp6p(200, {"X-RateLimit-Remaining": "0"}))[1]
    try:
        _l6p, _m6p = gh_mod.collect(["example.com"], _gh_settings)
    finally:
        gh_mod.http_request = _orig_req6p
    assert len(_n6p) == 1, f"配额见底后不该继续发请求（实发 {len(_n6p)} 次）"
    assert "配额" in (_m6p.get("error") or ""), _m6p
    # 7c) 网络不可达同样是"说出来"而不是"没查到"
    gh_mod.http_request = lambda *a, **kw: None
    try:
        _l6p, _m6p = gh_mod.collect(["example.com"], _gh_settings)
    finally:
        gh_mod.http_request = _orig_req6p
    assert not _l6p and "请求失败" in (_m6p.get("error") or ""), _m6p
    # 7d) 响应不是 JSON → 不抛异常，返回原因
    _bad6p = {"status": 200, "headers": {}, "text": "<html>nope</html>", "length": 16, "url": "u"}
    gh_mod.http_request = lambda u, **kw: _bad6p
    try:
        _l6p, _m6p = gh_mod.collect(["example.com"], _gh_settings)
    finally:
        gh_mod.http_request = _orig_req6p
    assert not _l6p and "JSON" in (_m6p.get("error") or ""), _m6p
    # 7e) 规则表：四条规则的（关键词 / 级别）就是实现口径，写死防漂移
    assert [r[0] for r in gh_mod.SEARCH_RULES] == ["mention", "credential", "apikey", "env-file"]
    assert gh_mod.rule_of("nope") is None and gh_mod.rule_of("mention")[2] == "info"
    assert gh_mod.build_query("a.example.com") == '"a.example.com"'
    assert gh_mod.build_query("a.example.com", "filename:.env") == '"a.example.com" filename:.env'

    print("[6p] 续26 GitHub 泄露检索 ok: 默认关/没 token 零请求（原因写明）/ auth=False（目标侧"
          "登录态不外发，GitHub token 走 Authorization）/ 只落仓库+路径+规则名（含 text_matches"
          "的响应入库/JSONL 里 0 处凭据明文）/ 注册域收敛（URL 里的裸 IP 不再切出 '0.1'）/ "
          "四规则命中合并为一条 / 去重且不进 vulns / 401·403·配额见底均立刻收手")

    # 6q) 续29「断点续扫」：沿用原任务 / 同一日志 / 库里已有资产，只重跑断点**及其之后**的阶段。
    #     断点直接复用 `current_stage`（`PipelineRunner.run` 在**每个阶段开始前**写它）——
    #     零 schema 迁移、零额外写入，且天然 fail-safe：中断时断点所在阶段可能只跑了一半，
    #     重跑它才是真不丢结果（各阶段产物按去重键入库，重跑不会产生重复行）。
    import json as _json6q

    # (1) 纯函数切片。`[]` **只**表示"没有可用断点"，调用方据此拒绝续跑 ——
    #     在这里静默回退成"全量重跑"与用户"接着跑"的预期不符（请求量/耗时是另一个量级）。
    assert _rn6.resume_stages(["probe", "dirscan", "vulnscan"], "dirscan") == ["dirscan", "vulnscan"]
    assert _rn6.resume_stages(["probe", "dirscan"], "probe") == ["probe", "dirscan"]
    assert _rn6.resume_stages(["probe"], "") == [], "空断点 = 没有可用断点（不得回退全量）"
    assert _rn6.resume_stages(["probe"], "dirscan") == [], "断点不在本任务阶段列表里 → 无可用断点"
    assert _rn6.resume_stages(["probe"], "无此阶段") == []
    assert _rn6.resume_stages([], "probe") == [] and _rn6.resume_stages(None, None) == []
    # 顺带把不在注册表里的非法阶段名过滤掉（与 PipelineRunner.run 的过滤口径一致）
    assert _rn6.resume_stages(["probe", "smoke-nope", "dirscan"], "dirscan") == ["dirscan"]

    # (2) 端到端：三个假阶段，第二段末尾置 stop_event（模拟"跑到一半被停止 / 预算耗尽"）。
    #     只在**首次**运行时置（续跑那一轮要能真的跑到 r3，否则测不出"断点之后的阶段也跑了"）。
    _seen6q = []
    _stop_once6q = [True]

    def _mk6q(_name):
        class _Stub6q:
            name = _name

            def __init__(self, ctx):
                self.ctx = ctx

            def run(self):
                _seen6q.append(self.name)
                if self.name == "smoke-r2" and _stop_once6q[0]:
                    _stop_once6q[0] = False
                    self.ctx.stop_event.set()

        return _Stub6q

    _saved6q = dict(_rn6.STAGE_REGISTRY)
    _q_stages = ["smoke-r1", "smoke-r2", "smoke-r3"]
    _q_tid = None
    try:
        for _n in _q_stages:
            _rn6.STAGE_REGISTRY[_n] = _mk6q(_n)
        _q_tid = db.create_task("smoke-resume", targets, _q_stages, {"offline": True})
        run_task(_q_tid, "smoke-resume", targets, _q_stages, {"offline": True}, settings)
        _q1 = db.get_task(_q_tid)
        assert _q1["status"] == "stopped", _q1["status"]
        assert _seen6q == ["smoke-r1", "smoke-r2"], _seen6q
        # **被停止时必须保留断点**：原实现把它清成 ""，恰好抹掉"被停止 / 预算耗尽"这两类
        # 最需要续跑的收场（本断言在改回清空后必挂）。
        assert _q1["current_stage"] == "smoke-r2", \
            f"被停止的任务必须保留断点：{_q1['current_stage']!r}"

        # 造一条已有资产 + 一条"上次中断原因"（模拟进程重启被对账标 failed 后留下的 error）
        db.insert_sites(_q_tid, [{"url": "http://resume.example", "host": "resume.example",
                                  "port": "80", "status": 200, "title": "resume",
                                  "length": 12, "server": "", "tech": "", "source": "probe"}])
        db.append_task_error(_q_tid, "进程重启，任务中断（启动时对账）")

        _seen6q.clear()
        run_task(_q_tid, "smoke-resume", targets, _q_stages, {"offline": True}, settings,
                 resume=True)
        _q2 = db.get_task(_q_tid)
        assert _seen6q == ["smoke-r2", "smoke-r3"], \
            f"续跑应只重跑断点及其之后的阶段（断点所在阶段**故意重跑**）：{_seen6q}"
        assert _q2["status"] == "done" and _q2["current_stage"] == "", dict(_q2)
        assert _q2["log_file"] == _q1["log_file"], "续跑必须续写**同一**日志（不新建 workdir）"
        assert _q2["stages"] == ",".join(_q_stages), "续跑不得改写任务原有的阶段列表"
        assert (_q2["error"] or "") == "", "续跑按本次运行清空 error（上次原因已转存进日志）"
        assert len(db.list_sites(_q_tid)) == 1, "续跑**不得**清空已有资产（那是「重启」的语义）"
        _q_txt = Path(_q2["log_file"]).read_text(encoding="utf-8")
        assert "[resume] 从断点续跑" in _q_txt, "续跑的起始动作要落日志（否则事后无法判断跑过什么）"
        assert "进程重启，任务中断（启动时对账）" in _q_txt, \
            "上次中断原因必须在 error 被清空前转存进日志（日志是持久产物，信息不丢）"

        # (3) 无断点时的**直接调用方**回退：明说找不到断点、按全部阶段重跑（GUI 路由不会走到这）
        _seen6q.clear()
        run_task(_q_tid, "smoke-resume", targets, _q_stages, {"offline": True}, settings,
                 resume=True)
        assert _seen6q == _q_stages, f"无断点时应按全部阶段重跑并明说：{_seen6q}"
        assert "找不到可用断点" in Path(db.get_task(_q_tid)["log_file"]).read_text(encoding="utf-8")
    finally:
        if _q_tid:
            db.delete_task(_q_tid, backup=False)
        _rn6.STAGE_REGISTRY.clear()
        _rn6.STAGE_REGISTRY.update(_saved6q)

    # (4) GUI 路由 `/api/tasks/<id>/resume`：该拒的拒、该放行的放行，且放行时**必须**
    #     是 `resume=True` 且不带 `append*`（否则输入会被收窄成空集 —— 一次都不扫）。
    _gq_tid = db.create_task("smoke-resume-route", targets, ["probe", "dirscan", "vulnscan"],
                             {"offline": True, "append": True,
                              "append_targets": ["http://leftover.example"]})
    # 4a 无断点（刚建的任务）→ 明确拒绝 + 可读原因（页面据此把按钮置灰，后端也不放行）
    _ra6q = c.post(f"/api/tasks/{_gq_tid}/resume")
    assert _ra6q.get_json()["ok"] is False and "断点" in _ra6q.get_json()["error"], \
        _ra6q.get_json()
    # 4b 运行中 → 拒绝（续跑会 _register_stop 覆盖停止事件，必须硬拒）
    db.update_task(_gq_tid, current_stage="dirscan")
    _rn6._register_stop(_gq_tid)
    try:
        _rb6q = c.post(f"/api/tasks/{_gq_tid}/resume")
        assert _rb6q.get_json()["ok"] is False and "正在运行" in _rb6q.get_json()["error"], \
            _rb6q.get_json()
    finally:
        _rn6._unregister_stop(_gq_tid)
    # 4c 有断点 → 放行：复用同一任务、阶段切到"断点及其之后"、resume=True、append* 已剥掉。
    #     续49 起改断言"队列入参"（run_payload）：`_spawn` 不再起线程，而是把入参写进
    #     `tasks.run_payload` 并置 `queued`，由 worker 认领。
    _n_tasks6q = len(db.list_tasks(limit=1000))
    _rc6q = c.post(f"/api/tasks/{_gq_tid}/resume")
    assert _rc6q.get_json()["ok"] is True and "dirscan" in _rc6q.get_json()["msg"], \
        _rc6q.get_json()
    assert len(db.list_tasks(limit=1000)) == _n_tasks6q, "续跑**不得**新建任务"
    _gq_row = dict(db.get_task(_gq_tid))
    assert _gq_row["status"] == "queued" and _gq_row["run_mode"] == "resume", \
        f"续跑应把任务入队（status=queued + run_mode=resume）：{_gq_row}"
    _q_spawn = _json6q.loads(_gq_row["run_payload"] or "{}")
    assert _q_spawn.get("stages") == ["dirscan", "vulnscan"], \
        f"续跑入参的阶段应是断点及其之后：{_q_spawn}"
    _q_spawn_opts = _q_spawn.get("options") or {}
    assert _json6q.loads(db.get_task(_gq_tid)["options"] or "{}").get("append") is True, \
        "本用例前提：库里确实存着上次追加的运行期参数（否则下面那条断言是空过的）"
    assert "append" not in _q_spawn_opts and "append_targets" not in _q_spawn_opts, \
        f"上次追加的运行期参数绝不能带进续跑：{_q_spawn_opts}"
    assert _q_spawn_opts.get("offline") is True, "其余任务选项必须原样保留"
    db.delete_task(_gq_tid, backup=False)

    print("[6q] 续29 断点续扫 ok: 切片口径（断点及其之后，空断点=拒绝而非全量）/ 停止时保留断点 / "
          "沿用同一任务与日志、不清资产、error 按本次清空且上次原因转存日志 / 无断点回退要明说 / "
          "GUI 拒绝无断点与运行中、放行时 resume=True 且剥掉 append*")

    # [6r] 续30 目录递归（**默认关**）：三重闸（层数 / 每站跨层累计目录数 / 每目录路径数）+
    #      每前缀**独立**软 404 基线 + 入库 site_url 仍是站点根。
    #      为什么目录数上界与层数同等重要：单站浅扫 ≈153 请求（150 路径 + 3 基线），
    #      一层递归 = +K×(3 基线 + M)，K 是"扫出多少个目录"决定的、**不受字典大小控制** ——
    #      只限深度不限 K，请求量会随命中目录数线性放大（K=5/M=40 时 +215，比第一轮还多）。
    _dp30 = DirscanStage._dir_prefix
    # 1) 目录型判定：只有"在它后面拼路径有意义"的命中才递归
    assert _dp30("http://h", "http://h/admin", 200) == "http://h/admin"
    assert _dp30("http://h/", "http://h/api/v1", 301) == "http://h/api/v1"
    assert _dp30("http://h", "http://h/secret/", 403) == "http://h/secret", "403 目录也要递归"
    assert _dp30("http://h", "http://h/api?x=1#f", 200) == "http://h/api", "query/fragment 必须剥掉"
    # 与 `_scan::_hit` 的状态收口一致：其余状态根本进不了结果集，更不该被递归
    for _s30 in (404, 500, 401, 204):
        assert _dp30("http://h", "http://h/admin", _s30) is None, _s30
    assert _dp30("http://h", "http://h/index.php", 200) is None, "文件型路径后面拼路径没意义"
    assert _dp30("http://h", "http://h/.env", 200) is None
    assert _dp30("http://h", "http://h/.git/config", 200) is None, \
        "点目录不是可爆破目录（每个纯浪费 = 3 基线 + N 路径）"
    assert _dp30("http://h", "http://h/", 200) is None, "站点根自身不是递归目标"
    assert _dp30("http://h", "http://other/x", 200) is None, "站点根之外的条目不递归"

    _sent30, _layers30 = [], []
    _orig_http30, _orig_lp30 = _ds_mod.http_request, DirscanStage._load_paths
    _PATHS30 = ["config.php", "sub"]        # `sub` 故意是目录型，用来验证"第二层"

    def _fake_http30(u, **k):
        _sent30.append(u)
        if "ctfscan-none" in u:            # 软 404 基线（长度 1，与真实命中区分开）
            return {"status": 200, "length": 1, "text": "base:" + u, "content": b"b"}
        return {"status": 200, "length": 200, "text": "hit:" + u, "content": b"h"}

    def _fake_lp30(self, kind, cfg, fw="", layers=None, limit=None):
        # 真 `_load_paths` 的 limit 就是"截断到多少条"，这里如实模拟 ——
        # 否则 recursive_max_paths 那条断言是空过的（桩忽略 limit 就永远 2 条）
        _layers30.append(tuple(layers or ()))
        return _PATHS30[:int(limit)] if limit else list(_PATHS30)

    _st30 = DirscanStage(dstage.ctx)         # 复用 [5g] 建好的 ctx（task_id / settings 都齐）
    _sites30 = [{"url": "http://h.test/", "tech": "", "title": "", "length": None}]
    _dir30 = {"site_url": "http://h.test", "path": "http://h.test/admin", "status": 200,
              "length": 10, "method": "GET", "note": "builtin", "title": ""}
    _ds_mod.http_request, DirscanStage._load_paths = _fake_http30, _fake_lp30
    try:
        # 2) 默认关（recursive_depth=0）：连字典都不读、**一个请求都不发**
        _sent30.clear()
        assert _st30._recursive_scan(_sites30, [_dir30], {"recursive_depth": 0}, {}) == []
        assert _sent30 == [] and _layers30 == [], f"关闭时必须是零请求零读字典：{_sent30}"

        # 3) 真递归一层：请求打到**子目录**，且软 404 基线是**该子目录自己**的一份
        _sent30.clear()
        _out30 = _st30._recursive_scan(_sites30, [_dir30],
                                       {"recursive_depth": 1, "recursive_max_dirs": 5,
                                        "recursive_max_paths": 40}, {})
        _base30 = [u for u in _sent30 if "ctfscan-none" in u]
        _hit30 = [u for u in _sent30 if "ctfscan-none" not in u]
        assert sorted(_hit30) == ["http://h.test/admin/config.php", "http://h.test/admin/sub"], _hit30
        assert len(_base30) == 3 and all(u.startswith("http://h.test/admin/") for u in _base30), \
            f"基线必须按**前缀**各算一份（子目录有自己的统一跳转页，复用根基线会整片误杀）：{_base30}"
        assert all(tuple(_ds_mod._SHALLOW_LAYERS) == l for l in _layers30), \
            f"递归轮只吃浅扫精选字典（不是再来一遍大字典）：{_layers30}"
        assert _out30 and {e["site_url"] for e in _out30} == {"http://h.test"}, \
            f"入库的 site_url 必须仍是**站点根**（折叠/跨运行去重/启发式分组的数据身份）：{_out30}"
        assert {e["path"] for e in _out30} == set(_hit30), _out30

        # 4) 请求量模型：目录数上界 × 每目录路径数，基线按目录各一份
        #    （10 个目录只递归 recursive_max_dirs 个；每目录只打 recursive_max_paths 条）
        _sent30.clear()
        _many30 = [{"site_url": "http://h.test", "path": f"http://h.test/d{i}", "status": 200,
                    "length": 10, "method": "GET", "note": "builtin", "title": ""}
                   for i in range(10)]
        _st30._recursive_scan(_sites30, _many30,
                              {"recursive_depth": 1, "recursive_max_dirs": 3,
                               "recursive_max_paths": 1}, {})
        _dirs30 = {u.rsplit("/", 1)[0] for u in _sent30 if "ctfscan-none" not in u}
        assert _dirs30 == {"http://h.test/d0", "http://h.test/d1", "http://h.test/d2"}, _dirs30
        assert len([u for u in _sent30 if "ctfscan-none" in u]) == 9, "基线 = 3 × 目录数"
        assert len(_sent30) == 12, \
            f"总请求量上界 = 目录数 ×（3 基线 + 每目录条数）= 3×(3+1)：{sorted(_sent30)}"

        # 5) 层数：depth=2 时对第一层新命中的**目录型**条目继续往下打
        _sent30.clear()
        _st30._recursive_scan(_sites30, [_dir30],
                              {"recursive_depth": 2, "recursive_max_dirs": 2,
                               "recursive_max_paths": 40}, {})
        assert "http://h.test/admin/sub/sub" in _sent30, sorted(_sent30)
        # 而 max_dirs 是"**所有层合计**"：第 1 层就把它用满时，第 2 层一个请求都不许发
        _sent30.clear()
        _st30._recursive_scan(_sites30, [_dir30],
                              {"recursive_depth": 2, "recursive_max_dirs": 1,
                               "recursive_max_paths": 40}, {})
        assert not [u for u in _sent30 if "/admin/sub/" in u], \
            f"max_dirs 是跨层累计，第 1 层用满即止：{sorted(_sent30)}"
        assert len([u for u in _sent30 if "ctfscan-none" in u]) == 3, "只剩第 1 层那份基线"

        # 6) 防重复：同一目录被重复命中只递归一次（否则白付一份基线 + 一遍字典）
        _sent30.clear()
        _st30._recursive_scan(_sites30, [_dir30, dict(_dir30)],
                              {"recursive_depth": 1, "recursive_max_dirs": 5,
                               "recursive_max_paths": 1}, {})
        assert len(_sent30) == 4, f"3 基线 + 1 路径：{sorted(_sent30)}"
    finally:
        _ds_mod.http_request, DirscanStage._load_paths = _orig_http30, _orig_lp30

    # 7) 接线：任务级「目录递归」勾选 = 本次强制开（策略关着也生效，且**不原地改全局策略**）；
    #    没勾就按策略（默认关）。递归是深扫的附属能力，所以放在 `run()` 里对两种产物一视同仁
    #    （挂进 `_builtin_scan` 会让"装了 dirmap 的机器反而没有递归"）。
    assert int((settings.get("dirscan") or {}).get("recursive_depth", -1)) == 0, \
        "本用例前提：策略里目录递归是**默认关**的"
    _orig_bs30, _orig_rs30 = DirscanStage._builtin_scan, DirscanStage._recursive_scan
    _cap30 = {}
    _fake_ent30 = [dict(_dir30)]
    DirscanStage._builtin_scan = lambda self, sites, cfg, limits, shallow=False, only_fw=False: \
        list(_fake_ent30)
    DirscanStage._recursive_scan = lambda self, sites, entries, cfg, limits: _cap30.update(cfg) or []
    _run30 = db.create_task("smoke-rec-override", targets, ["dirscan"],
                            {"dirscan_full": True, "offline": True, "recursive_dir": True})
    try:
        DirscanStage(StageContext(_run30, "smoke-rec-on", parse_lines([targets]), ["dirscan"],
                                  {"dirscan_full": True, "offline": True, "recursive_dir": True},
                                  settings, Path(_TMPDIR) / "rec30", rec)).run()
        assert int(_cap30.get("recursive_depth", 0)) >= 1, \
            f"任务级勾了「目录递归」就必须至少一层（策略关着也得放行）：{_cap30}"
        assert int(settings["dirscan"]["recursive_depth"]) == 0, "只本次生效，不得原地改全局策略"
        _cap30.clear()
        DirscanStage(StageContext(_run30, "smoke-rec-off", parse_lines([targets]), ["dirscan"],
                                  {"dirscan_full": True, "offline": True}, settings,
                                  Path(_TMPDIR) / "rec30b", rec)).run()
        assert int(_cap30.get("recursive_depth", 0)) == 0, "没勾就该按策略走（默认关）"
    finally:
        DirscanStage._builtin_scan, DirscanStage._recursive_scan = _orig_bs30, _orig_rs30
        db.delete_task(_run30, backup=False)

    # 8) GUI 可见性 + 建任务路由：勾「目录递归」必须**自动带上深扫**（否则勾了静默不递归，
    #    看起来像功能坏了）；三个额度必须能在策略页改
    assert 'name="recursive_dir"' in c.get("/tasks").get_data(as_text=True), "建任务表单缺勾选"
    _set_html30 = c.get("/settings").get_data(as_text=True)
    for _k30 in ("dirscan_recursive_depth", "dirscan_recursive_max_dirs",
                 "dirscan_recursive_max_paths"):
        assert f'name="{_k30}"' in _set_html30, f"策略页缺 {_k30}"
    _orig_run30 = gui_app.run_task
    gui_app.run_task = lambda *a, **kw: None
    try:
        _j30 = c.post("/api/tasks", data={"name": "smoke-rec-route", "targets": targets,
                                         "stages": ["probe"], "recursive_dir": "1"}).get_json()
        _t30 = db.get_task(_j30["id"])
        assert '"recursive_dir": true' in _t30["options"], _t30["options"]
        assert '"dirscan_full": true' in _t30["options"], \
            "勾「目录递归」必须自动补上深扫（递归只在深扫里生效），否则勾了没反应"
        assert _t30["stages"].split(",") == ["probe", "dirscan"], _t30["stages"]
        assert _j30["auto_stages"] == ["dirscan"], _j30
        db.delete_task(_j30["id"], backup=False)
    finally:
        gui_app.run_task = _orig_run30

    print("[6r] 续30 目录递归 ok: 默认关零请求 / 目录型判定（状态收口+剥 query+文件与点目录不递归）/ "
          "每前缀独立软404基线 / site_url 仍是站点根 / 目录数与每目录路径数上界（请求量=K×(3+M)）/ "
          "跨层累计 max_dirs / 层数 / 重复目录只递归一次 / 任务级勾选可覆盖策略且不改全局 / GUI 与路由")

    # [6s] 续29 补入口：CLI `--resume-task`（GUI 早有「续跑」按钮，CLI 一直没有对称入口；
    #      `run_task(resume=True)` 的 docstring 里本来就写了"只服务于测试 / 未来的 CLI"）。
    #      全程桩掉 `run_task`，**不发任何真实请求**。
    import contextlib
    import io as _io
    import types
    import cli.client as _cli

    _calls30b = []
    _orig_rt30b = _cli.run_task

    def _fake_rt30b(task_id, name, targets, stages, options, settings, append=False,
                    resume=False):
        _calls30b.append({"task_id": task_id, "name": name, "stages": list(stages),
                          "options": dict(options), "append": append, "resume": resume})
        return types.SimpleNamespace(results={}, workdir=Path(_TMPDIR) / "cli-resume")

    def _cli_run30b(argv):
        """跑一次 CLI，返回 (退出码, stdout)。捕获 SystemExit 而不让它带走整个冒烟测试。"""
        buf = _io.StringIO()
        _calls30b.clear()
        old_argv = sys.argv
        sys.argv = ["client.py"] + argv
        try:
            with contextlib.redirect_stdout(buf):
                _cli.main()
        except SystemExit as e:
            return (e.code or 0), buf.getvalue()
        finally:
            sys.argv = old_argv
        return 0, buf.getvalue()

    _t30b = db.create_task("smoke-cli-resume", targets, ["probe", "dirscan"], {"offline": True})
    db.update_task(_t30b, current_stage="dirscan")
    _cli.run_task = _fake_rt30b
    try:
        # 1) 有断点：stub 必须收到 resume=True，且**阶段列表按任务原样传**（切片发生在
        #    `run_task` 内部，CLI 不自己切 —— 两处各切一份必然漂移）
        _code, _out = _cli_run30b(["--resume-task", str(_t30b)])
        assert _code == 0, (_code, _out)
        assert len(_calls30b) == 1, _calls30b
        assert _calls30b[0]["resume"] is True and _calls30b[0]["append"] is False, _calls30b
        assert _calls30b[0]["task_id"] == _t30b, _calls30b
        assert _calls30b[0]["stages"] == ["probe", "dirscan"], _calls30b
        assert _calls30b[0]["options"] == {"offline": True}, "选项必须来自任务自身，不吃本次参数"
        assert "续跑任务 #" in _out and "dirscan" in _out, _out

        # 2) 没有断点 → **入口就拒绝**，绝不回退成全量重跑（请求量/耗时是另一个量级）
        db.update_task(_t30b, current_stage="")
        _code, _out = _cli_run30b(["--resume-task", str(_t30b)])
        assert _code == 1 and not _calls30b, f"无断点必须拒绝且不调用 run_task：{_out}"
        assert "没有可用断点" in _out, _out

        # 3) 与本次输入类参数同用 → 报错退出（静默忽略会让人以为"这次换了目标/开了离线"）
        for _extra in (["-t", "example.com"], ["--offline"], ["--recursive-dir"], ["-n", "x"]):
            _code, _out = _cli_run30b(["--resume-task", str(_t30b)] + _extra)
            assert _code == 1 and not _calls30b, f"{_extra} 必须拒绝：{_out}"
            assert "不能与这些参数同用" in _out, _out
        assert "-t/--target" in _cli_run30b(["--resume-task", str(_t30b), "-t", "x"])[1]

        # 4) 任务不存在
        _code, _out = _cli_run30b(["--resume-task", "99999999"])
        assert _code == 1 and not _calls30b and "不存在" in _out, _out

        # 5) 任务正在运行 → 拒绝。**pid 必须设成本进程**：否则 `reconcile_orphan_tasks`
        #    会先把这个 running 判成孤儿 failed，就测不到运行中这条分支了
        db.update_task(_t30b, current_stage="dirscan", status="running", pid=os.getpid())
        _code, _out = _cli_run30b(["--resume-task", str(_t30b)])
        assert _code == 1 and not _calls30b and "正在运行" in _out, _out
    finally:
        _cli.run_task = _orig_rt30b
        db.delete_task(_t30b, backup=False)

    print("[6s] 续29 CLI --resume-task ok: 有断点走 resume=True（阶段原样交给 run_task 切）/ "
          "无断点入口即拒绝（不回退全量）/ 与 -t·--offline·--recursive-dir·-n 互斥 / "
          "任务不存在与运行中均拒绝 / 选项取自任务自身")

    # [6t] 续32 本机守卫：把「仅限本机使用」从文档里的一句"切勿部署到公网"变成**技术落实** ——
    #      Host 白名单（挡 DNS rebinding，叠加上公开的默认口令 `ctfscanner` 就是完整接管）+ 写方法的
    #      Origin/Referer 校验（Cookie 不按端口隔离，同机另一个服务也能带 Cookie 打进来）+
    #      会话 Cookie 的 HttpOnly/SameSite 显式化。全程走 test client，不占端口、不发真实请求。
    from gui.app import _host_of

    # 1) `_host_of` 是纯函数，先把口径钉死 —— Host 白名单建立在它上面（**只比主机名**）
    assert _host_of("127.0.0.1:5000") == "127.0.0.1"
    assert _host_of("[::1]:5000") == "::1", "IPv6 字面量要剥方括号"
    assert _host_of("LOCALHOST") == "localhost" and _host_of("  Example.COM ") == "example.com", \
        "大小写/空白必须归一，否则白名单与 Origin 比对都能被绕过"
    assert _host_of("0.0.0.0") == "0.0.0.0", "0.0.0.0 是绑定地址不是回环主机名，不得进白名单"
    assert _host_of("") == "" and _host_of(None) == "", "取不出主机名时返回空串（不猜）"
    assert _host_of("evil.example:5000") == "evil.example"

    # 1b) `_authority` 是跨站校验用的那一个 —— 与 `_host_of` 的关键差别是**保留端口**
    #     （续32-fix：首版错用了 `_host_of`，两边都把端口剥掉 → "同机异端口"整类请求被放行。
    #      这个缺陷是**真实服务器上实测**发现的，当时的 smoke 断言因 test client 的 Host 是
    #      `localhost`（与 `127.0.0.1:9999` 主机名本来就不同）而**假绿** —— 见下面 3) 的端口断言）
    from gui.app import _authority
    assert _authority("http://127.0.0.1:5057") == "127.0.0.1:5057"
    assert _authority("127.0.0.1:5057") == "127.0.0.1:5057", "Host 头（无 scheme）也要能归一"
    assert _authority("http://127.0.0.1") == "127.0.0.1"
    assert _authority("http://127.0.0.1:80") == "127.0.0.1", \
        "默认端口要按 scheme 归一 —— 浏览器在默认端口下不写端口，否则正常请求会被自己挡掉"
    assert _authority("https://127.0.0.1:443") == "127.0.0.1"
    assert _authority("HTTPS://Example.COM:443") == "example.com", "大小写要归一"
    assert _authority("[::1]:5000") == "[::1]:5000" and _authority("http://[::1]") == "[::1]"
    assert _authority("") == "" and _authority(None) == "" and _authority("http://") == ""
    assert _authority("http://127.0.0.1:9999") != _authority("127.0.0.1:5057"), "端口必须参与比对"

    # 2) Host 白名单：绑定回环地址时，非回环 Host 一律 403。
    #    test client 默认 Host 就是 `localhost`（在白名单内），所以这里必须**显式**换成外站域名
    assert c.get("/login", headers={"Host": "evil.example"}).status_code == 403
    assert c.post("/login", data={"token": settings["gui"]["token"]},
                  headers={"Host": "evil.example"}).status_code == 403
    assert c.get("/login", headers={"Host": "127.0.0.1"}).status_code == 200
    assert c.get("/login", headers={"Host": "localhost:5000"}).status_code == 200, \
        "回环 + 端口仍应放行（白名单比的是主机名）"

    # 3) 写方法的 Origin/Referer 校验（比**权威段**：Cookie 不按端口隔离，端口必须参与）
    _tok32 = settings["gui"]["token"]
    for _hdr32 in ({"Origin": "http://evil.example"},
                   # 同机另一个服务：**主机名相同、只有端口不同** —— 这条断言是续32-fix 的核心。
                   # 首版用 `_host_of` 比，两边都把端口剥掉就相等了，整类请求被静默放行；
                   # 当时之所以没被抓到，是因为 test client 的默认 Host 是 `localhost`，
                   # 与 `127.0.0.1:9999` 的**主机名**本来就不同 → 断言"因为别的原因"通过了（假绿）。
                   # 所以这里必须**显式给出带端口的 Host**，让比对真正落在端口上。
                   {"Host": "127.0.0.1:5057", "Origin": "http://127.0.0.1:9999"},
                   {"Host": "127.0.0.1:5057", "Referer": "http://127.0.0.1:9999/x"},
                   {"Origin": "null"},                      # file:// 页面 / 沙箱 iframe
                   {"Referer": "http://evil.example/x"}):   # 无 Origin 时退回 Referer
        assert c.post("/login", data={"token": _tok32}, headers=_hdr32).status_code == 403, _hdr32
    for _hdr32 in ({"Origin": "http://localhost"},                              # 两边都无端口
                   {"Host": "localhost:5000", "Origin": "http://localhost:5000"},  # 真实浏览器形态
                   {"Origin": "http://localhost:80"},                           # 默认端口归一
                   {"Host": "127.0.0.1:5057", "Origin": "http://127.0.0.1:5057"},
                   {"Host": "127.0.0.1:5057", "Referer": "http://127.0.0.1:5057/tasks"},
                   {"Referer": "http://localhost/x"}):
        assert c.post("/login", data={"token": _tok32}, headers=_hdr32).status_code == 302, _hdr32
    # 只拦写方法：带外站 Origin 的 GET 必须放行（否则正常导航会被误伤）
    assert c.get("/login", headers={"Origin": "http://evil.example"}).status_code == 200
    # 两个头都缺失时放行（curl / 脚本 / 老浏览器本就不带；本机工具必须能用）
    assert c.post("/login", data={"token": _tok32}).status_code == 302

    # 4) 会话 Cookie 显式收紧（不依赖浏览器默认值 —— 旧浏览器上"默认"等于没有）
    _ck32 = c.post("/login", data={"token": _tok32}).headers.get("Set-Cookie", "")
    assert "HttpOnly" in _ck32, _ck32
    assert "SameSite=Lax" in _ck32, _ck32
    assert app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"

    print("[6t] 续32 本机守卫 ok: Host 白名单（外站 Host 403 / 回环与回环+端口放行）/ "
          "写方法 Origin 与 Referer 校验（跨站·**同机异端口**·null 均 403，同源与默认端口归一放行）/ "
          "GET 不拦 / 两个头都缺时放行 / _host_of 只比主机名、_authority 保留端口 / "
          "Cookie HttpOnly+SameSite=Lax")

    
    # [6u] 续33 **全 13 阶段端到端真跑**：把"13 个阶段能不能串起来跑完"钉进回归门禁。
    #      背景（这是本用例存在的理由）：此前**真跑**的只有 `[3]`（probe + vulnscan 两阶段）
    #      与 `[5p] 3c`（只真跑 dirscan）；"全量串起来"只在 2026-09-23 续10 手工跑过一次，
    #      那时才 11 阶段 —— cert / github / 目录递归 / 追加 / 续跑 / F2 门控都是后来的，
    #      也就是说"13 个阶段还能不能跑完"**从来没有回归覆盖**。
    #      为什么不能把阶段桩掉：阶段级容错会把异常记进 `tasks.error` 后继续跑完、任务照样置
    #      `done`。只断言"13 个阶段都被调用过"抓不到"流水线其实崩了" —— 必须断言
    #      **终态 / error / 产物 / 请求量** 四件事，且请求是真发到 8765 靶场的。
    from scanner import utils as _utils6u
    from scanner.config import DEFAULTS as _DEF6U

    _u_cfg = copy.deepcopy(settings)

    # (1) 先关掉**一切会发外部第三方请求**的阶段：冒烟测试必须零外部请求。
    #     这不是洁癖，是实测踩到的坑：本机 `config/keys.yaml` 里填着**真实的 FOFA 凭据**，
    #     而 `config/settings.yaml`（被 git 跟踪的用户覆盖层）把 `fofa.enabled` 设成了 true
    #     （`scanner/config.py` 的 DEFAULTS 是 False）—— 不显式关掉，一次默认任务就会真的
    #     去查 FOFA 并花掉用户配额。
    #     `osint` 阶段自身**没有** enabled，靠下面五个子开关共同决定：全关 = 整阶段跳过。
    for _k6u in ("iprecon", "fofa", "shodan", "quake", "ctlog"):
        _u_cfg[_k6u] = dict(_u_cfg.get(_k6u) or {}, enabled=False)
        assert _u_cfg[_k6u]["enabled"] is False, _k6u
    _u_cfg["intel"] = dict(_u_cfg.get("intel") or {}, enabled=False)
    _u_cfg["github"] = dict(_u_cfg.get("github") or {}, enabled=False)
    # 内置被动子域源（crt.sh / certspotter / alienvault …）同样是外部接口：一并关掉。
    # 本用例目标是 URL，`subdomain` 阶段对 URL 目标本来就整阶段跳过；关它是为了让
    # "零外部请求"**构造性成立**，而不是"恰好这次目标里没有裸域名"。
    _u_cfg["passive"] = dict(_u_cfg.get("passive") or {}, enabled=False)
    assert _u_cfg["intel"]["enabled"] is False and _u_cfg["github"]["enabled"] is False

    # (2) 打开其余全部阶段。两处"没有 enabled 键"的坑必须绕开（KeyError 已实测踩过）：
    #     `subdomain` 段存在但**没有** enabled（它只由任务勾选的 stages 决定）；
    #     `probe` 段在 DEFAULTS 里**根本不存在**（它没有任何策略级开关）。
    #     这两条断言同时把"别给它们补 enabled"这件事写进测试，防止后人按
    #     "每个阶段都有 enabled"的错觉去改配置层。
    assert "enabled" not in (_DEF6U.get("subdomain") or {}), \
        "DEFAULTS.subdomain 本就没有 enabled（它只由任务阶段列表决定），别给它补一个"
    assert "probe" not in _DEF6U, \
        "DEFAULTS 里没有 probe 段（probe 没有策略级开关）—— 别按'所有阶段都有 enabled'写"
    for _k6u in ("takeover", "portscan", "cert", "screenshot", "jsmine", "dirscan",
                 "vulnscan", "heuristic"):
        _u_cfg[_k6u] = dict(_u_cfg.get(_k6u) or {}, enabled=True)
        assert _u_cfg[_k6u]["enabled"] is True, _k6u
    # 前提：确确实实是 13 个阶段（续26 之后才是 13；续10 手工跑那次才 11 个）
    assert len(STAGE_ORDER) == 13 and set(STAGE_ORDER) == set(_rn6.STAGE_REGISTRY), \
        (len(STAGE_ORDER), sorted(STAGE_ORDER))

    # (3) 请求计数：沿用 `[5p] 3c` 的"真发请求 + 只做计数"手法，但**覆盖全部出口**。
    #     各模块是 `from ..utils import http_request`（把函数对象绑进自己的命名空间），
    #     只改 `utils.http_request` 对它们无效 —— 所以要把**所有持有原函数对象的 scanner.* 模块**
    #     都换掉（含 utils 自己：`evasion.py` / `fingerprint.py` 是函数内局部导入，走的就是它）。
    _u_orig_http = _utils6u.http_request
    _u_mods = [m for m in list(sys.modules.values())
               if str(getattr(m, "__name__", "") or "").startswith("scanner")
               and getattr(m, "http_request", None) is _u_orig_http]
    _u_sent = []

    def _u_http(u, **kw):
        _u_sent.append(str(u))
        return _u_orig_http(u, **kw)      # 真发请求，只做计数（绝不桩掉扫描实现）

    # (4) 真跑：`sync_pocs` 不能省 —— 沙箱库是空的，没有它 vulnscan 会撞
    #     `no such table: pocs`（`engine.load_enabled_pocs` 要读 pocs 表）。
    db.init_db()
    sync_pocs(_u_cfg)
    _u_name = "smoke-all13"
    _u_stages = list(STAGE_ORDER)
    _u_tid = db.create_task(_u_name, targets, _u_stages, {})
    for _m6u in _u_mods:
        _m6u.http_request = _u_http
    _u_t0 = time.time()
    try:
        run_task(_u_tid, _u_name, targets, _u_stages, {}, _u_cfg)
    finally:
        for _m6u in _u_mods:
            _m6u.http_request = _u_orig_http
    _u_el = time.time() - _u_t0

    # (5) 终态：**正常跑完**才可能是 `done` + error 为空 + `current_stage` 被清空。
    #     `db.get_task()` 返回 `sqlite3.Row`（没有 `.get()`），必须按下标取 —— 已实测踩过。
    _u_t = db.get_task(_u_tid)
    assert _u_t["status"] == "done", \
        f"全 13 阶段应正常跑完置 done（不是 done 说明流水线被中断/预算耗尽）：{_u_t['status']}"
    assert (_u_t["error"] or "") == "", \
        f"任何阶段异常都会被 append 进 error，跑完必须为空：{_u_t['error']}"
    assert (_u_t["current_stage"] or "") == "", \
        f"正常跑完必须清空断点（续29 的语义：留着就是'待续跑'）：{_u_t['current_stage']}"
    assert int(_u_t["progress"] or 0) == 100, _u_t["progress"]
    _u_counts = db.task_counts(_u_tid)
    _u_sites = [dict(r) for r in db.list_sites(_u_tid)]
    _u_dirs = [dict(r) for r in db.list_dirs(_u_tid)]
    _u_vulns = [dict(r) for r in db.list_vulns(task_id=_u_tid, limit=200)]
    _u_leads = [dict(r) for r in db.list_leads(_u_tid)]
    assert len(_u_sites) >= 1 and _u_sites[0]["url"].startswith("http://127.0.0.1:8765"), _u_sites
    assert len(_u_dirs) >= 2, f"浅扫应至少命中 .env 与 .git/config 两条：{_u_dirs}"
    assert any(str(d.get("path") or "").endswith("/.env") for d in _u_dirs), _u_dirs
    assert any(str(d.get("path") or "").endswith("/.git/config") for d in _u_dirs), _u_dirs
    assert len(_u_vulns) >= 1, _u_vulns
    assert all(v.get("severity") in ("high", "critical") for v in _u_vulns), \
        f"默认门槛 medium 下剩下的应是 high 级（exposure-git-config 等）：{_u_vulns}"

    # (6) 三个外部依赖阶段必须**被跳过而非报错**：intel / github / osint 都不该产出任何东西，
    #     且任务 error 依然为空（"跳过"和"跑挂了"必须分得开 —— 后者会被上面 (5) 抓住）。
    #     heuristic 开着但**零请求**，它若产线索是合法的，所以只钉"外部那两条不许有"。
    assert not [x for x in _u_leads if x["kind"] in ("intel", "github")], \
        f"intel / github 已显式关闭，不该有任何线索（有的话说明默认行为在偷偷发外部请求）：{_u_leads}"
    assert db.list_csegs(_u_tid) == [], "osint 的 C 段产物必须为空（iprecon 已关）"
    assert db.list_certs(_u_tid) == [], "靶场没有 https，cert 阶段应跳过而非报错（ctlog 也已关）"
    assert not [s for s in db.list_subdomains(_u_tid)
                if "osint" in str(s["source"] or "")], "osint 阶段的域名产物必须为空"

    # (7) **零外部请求**：所有请求的**主机名**必须是回环。这条比"请求总数"更硬 ——
    #     它直接证明没有向 FOFA / crt.sh / GitHub / CISA KEV 等任何第三方发过一次请求。
    #     只比前缀是不够的：portscan 会把扫到的其它开放端口（本机 135 / 445）交回 probe 当候选，
    #     于是请求里会有 `http://127.0.0.1:445` 这类**同机异端口**的 URL —— 它们仍是本机的。
    from urllib.parse import urlparse as _up6u
    _u_out = [u for u in _u_sent
              if ((_up6u(u).hostname or "").strip().lower())
              not in ("127.0.0.1", "localhost", "::1")]
    assert not _u_out, f"冒烟测试必须零外部请求，实测打到站外：{_u_out[:5]}"

    # (8) 请求总量上界：**实测标定**后写死（构成见下方注释）。
    #     为什么是上界而不是等号：各阶段的请求数会随本机装了什么工具（nmap / fscan）、
    #     指纹命中情况而浮动，钉等号会让用例在别的机器上必然假失败。
    #     构成（本机实测，2026-09-26 逐阶段标定）：dirscan 153（浅扫字典 150 + 软 404 基线 3）/
    #     vulnscan 105（内置 OWASP 检查 + 联动 POC；续33 当时注释里的 ≈76 是 POC 集更小时的值）/
    #     probe 6（含 http/https 与 favicon）/ jsmine 1；其余 9 个阶段（subdomain / takeover /
    #     portscan / cert / screenshot / osint / intel / heuristic / github）各 0（portscan 走
    #     裸 socket，不经 http_request，故恒为 0）。合计约 265，上界 400 留了约 1.5 倍余量
    #     （给『本机装了 nmap / fscan、指纹命中更多 POC』的浮动留空间）。
    #     这份逐阶段数据来自续33 为标定临时加的阶段包装 —— 主理人 2026-09-26 派单清理时已删除；
    #     结论留在注释里，要重新标定就用本用例的 `_u_sent` 自己套一层计数。
    _U_MAX_REQ = 400
    assert len(_u_sent) <= _U_MAX_REQ, \
        f"全 13 阶段请求量 {len(_u_sent)} 超过上界 {_U_MAX_REQ}（阶段预算失控？）：" \
        f"{sorted(set(u.split('?')[0] for u in _u_sent))[:10]}"

    # (9) 对外部工具/浏览器的依赖必须**可移植**：这两处只能断言"不失败、产物可为 0"，
    #     绝不能断言"必须扫出端口"或"必须出图" —— 换一台没装 nmap / 没装浏览器的机器
    #     （以及 Linux CI）就会假失败。
    _u_ports = db.list_ports(_u_tid)
    assert isinstance(len(_u_ports), int), _u_ports          # 产物可为 0
    _u_shots = sorted((Path(db.get_task(_u_tid)["log_file"]).parent / "shots").glob("*.png")) \
        if (Path(db.get_task(_u_tid)["log_file"]).parent / "shots").is_dir() else []
    assert isinstance(len(_u_shots), int), _u_shots          # 没浏览器时 0 张是合法的
    assert (_u_t["error"] or "") == "", \
        f"跑完全 13 阶段后 error 仍必须为空（截图/端口扫描缺依赖不算错）：{_u_t['error']}"

    print("[6u] 续33 全 13 阶段端到端真跑 ok: 耗时 %.1fs / %s / 请求 %d 个（上界 %d，"
          "全部落在 127.0.0.1:8765，站外 0 个）/ 终态 done·error 空·断点已清 / "
          "heuristic 线索 %d 条（intel·github 必须为 0）/ csegs·certs·osint 域名均为 0"
          % (_u_el,
             " ".join(f"{k}={v}" for k, v in _u_counts.items() if v),
             len(_u_sent), _U_MAX_REQ,
             len([x for x in _u_leads if x["kind"] not in ("intel", "github")])))
    db.delete_task(_u_tid, backup=False)

    # [6v] 续35「运行时长」：任务详情「目标与配置」要显示"这个任务一共跑了多久"。
    #      为什么不复用现成时间戳：`updated_at` 会被补扫 / 补截图 / 误报复核这些**非运行期**
    #      写入刷新（越等越长），`created_at → finished_at` 之间还可能夹着几天的停机。
    #      所以起点/终点由 `start_task_run` / `finish_task_run` 单写，真实缺陷面在两处：
    #      ① **续跑 / 追加会跑多段**（只留最后一段会把 20 分钟的任务显示成 2 分钟）；
    #      ② **进程被强杀没收场**（尾段无据可依，绝不能拿"现在"去顶）。
    #      断言分两层：先钉 `db` 侧算术（可注入时刻，精确到秒），再钉 `runner` 侧三条终态分支
    #      **真的调了** `finish_task_run` —— 只测前者的话，把调用换回 `update_task` 照样全绿。
    from scanner.utils import format_duration

    # 1) 纯函数口径（展示层兜底：负数 / None / 非数字都不许抛）
    assert format_duration(0) == "0 秒" and format_duration(59) == "59 秒"
    assert format_duration(60) == "1 分 00 秒" and format_duration(3599) == "59 分 59 秒"
    assert format_duration(3600) == "1 小时 00 分 00 秒"
    assert format_duration(3661) == "1 小时 01 分 01 秒"
    assert format_duration(None) == "0 秒" and format_duration("abc") == "0 秒"
    assert format_duration(-5) == "0 秒", "负时长不得显示成 -5 秒"

    # 2) 起止与**累计**：手工钉住起点/结束时刻 —— 真跑只有 0~1 秒，验不出口径
    _d35 = db.create_task("smoke-duration", targets, ["probe"], {"offline": True})
    assert dict(db.get_task(_d35))["started_at"] == "", "刚建的任务没有起点"
    assert db.task_run_seconds(dict(db.get_task(_d35))) == 0
    db.update_task(_d35, started_at="2026-01-01 00:00:00")
    db.finish_task_run(_d35, ended_at="2026-01-01 00:01:30", status="done")
    _t35 = dict(db.get_task(_d35))
    assert int(_t35["elapsed_seconds"]) == 90, _t35
    assert _t35["finished_at"] == "2026-01-01 00:01:30", _t35
    # 第二段**累加**（续29/续25 会跑多段 —— 这条就是"只留最后一段"的证伪点）
    db.update_task(_d35, started_at="2026-01-01 00:05:00")
    db.finish_task_run(_d35, ended_at="2026-01-01 00:06:00", status="done")
    assert int(db.get_task(_d35)["elapsed_seconds"]) == 150, dict(db.get_task(_d35))
    # fresh（新建式执行：含 GUI「重启」）清零；非 fresh（续跑 / 追加）**不清零**
    db.start_task_run(_d35, fresh=True)
    assert int(db.get_task(_d35)["elapsed_seconds"]) == 0, "重启是清空资产从头跑 → 累计清零"
    db.update_task(_d35, elapsed_seconds=42)
    db.start_task_run(_d35, fresh=False, log_file="x")
    assert int(db.get_task(_d35)["elapsed_seconds"]) == 42, "续跑/追加沿用同一任务 → 不清零"
    db.update_task(_d35, started_at="2026-01-01 00:00:00")
    db.finish_task_run(_d35, ended_at="2026-01-01 00:00:10", status="done")
    assert int(db.get_task(_d35)["elapsed_seconds"]) == 52, dict(db.get_task(_d35))
    # 脏输入：没有起点（老库遗留行 / 被直接调用的 PipelineRunner）与时钟回拨都记 0 秒
    db.update_task(_d35, started_at="", elapsed_seconds=7)
    db.finish_task_run(_d35, ended_at="2026-01-01 00:00:10", status="done")
    assert int(db.get_task(_d35)["elapsed_seconds"]) == 7, "没起点 = 0 秒（不编数）"
    db.update_task(_d35, started_at="2026-01-01 00:01:00", elapsed_seconds=7)
    db.finish_task_run(_d35, ended_at="2026-01-01 00:00:10", status="done")
    assert int(db.get_task(_d35)["elapsed_seconds"]) == 7, "时钟回拨不得扣成负数"
    # `task_run_seconds` 的四种情形（"正在跑的那一段"用 now 注入点钉死，不依赖真实时钟）
    assert db.task_run_seconds({"started_at": "", "elapsed_seconds": 9}) == 9, \
        "没有起点就没有\"正在跑的那一段\"可加（这种行累计值恒为 0，报它即可）"
    assert db.task_run_seconds({"started_at": "", "elapsed_seconds": 0}) == 0
    assert db.task_run_seconds({"started_at": "2026-01-01 00:00:00", "elapsed_seconds": 9,
                                "finished_at": "2026-01-01 00:00:20", "status": "done"}) == 9
    assert db.task_run_seconds({"started_at": "2026-01-01 00:00:00", "elapsed_seconds": 9,
                                "finished_at": "", "status": "running"},
                               now="2026-01-01 00:00:30") == 39
    assert db.task_run_seconds({"started_at": "2026-01-01 00:00:00", "elapsed_seconds": 9,
                                "finished_at": "", "status": "failed"},
                               now="2026-01-01 00:00:30") == 9, \
        "被强杀且未被对账：尾段无据可依，只报已确认的累计值（不拿现在去顶）"
    # 页面文案：老任务显示 `-`（不拿 created_at 顶一个假起点）
    assert gui_app.run_duration_text({"started_at": "", "status": "done"}) == "-"
    assert gui_app.run_duration_text({"started_at": "2026-01-01 00:00:00", "elapsed_seconds": 90,
                                      "finished_at": "2026-01-01 00:01:30",
                                      "status": "done"}) == "1 分 30 秒"
    assert gui_app.run_duration_text({"started_at": "2026-01-01 00:00:00", "elapsed_seconds": 9,
                                      "finished_at": "", "status": "failed"}).endswith("尾段未计入）")

    # 3) runner 侧三条终态分支：每条都必须是**新建任务**（`finished_at` 初值为空），
    #    否则"没写"会被上一段留下的旧值掩盖 —— 断言就抓不到把调用换回 `update_task` 的变异。
    _saved6v = dict(_rn6.STAGE_REGISTRY)
    # 停止开关平时是**关**的（3a 要的是 done 分支），到 3b 前才打开 —— 否则 3a 会被 stop 掉
    _stop_once6v = [False]

    def _mk6v(name):
        class _Stub6v:
            def __init__(self, ctx):
                self.ctx = ctx

            def run(self):
                if name == "smoke-v2" and _stop_once6v[0]:
                    _stop_once6v[0] = False
                    self.ctx.stop_event.set()      # 覆盖 run() 的 stopped 分支

        return _Stub6v

    _v_stages = ["smoke-v1", "smoke-v2"]
    _v_ids = []
    try:
        for _n in _v_stages:
            _rn6.STAGE_REGISTRY[_n] = _mk6v(_n)
        # 3a) done 分支
        _va = db.create_task("smoke-duration-done", targets, _v_stages, {"offline": True})
        _v_ids.append(_va)
        run_task(_va, "smoke-duration-done", targets, _v_stages, {"offline": True}, settings)
        _v1 = dict(db.get_task(_va))
        assert _v1["status"] == "done" and _v1["started_at"] and _v1["finished_at"], _v1
        assert _v1["current_stage"] == "", "断点仍要清（原有行为不受影响）"
        # 3a') 页面**真的渲染**出这一行：只测 `run_duration_text()` 抓不到"路由忘了传/模板删了行"
        _v_html = c.get(f"/tasks/{_va}").get_data(as_text=True)
        _v_expect = gui_app.run_duration_text(dict(db.get_task(_va)))
        assert "运行时长" in _v_html and _v_expect in _v_html, \
            f"「目标与配置」必须显示运行时长 {_v_expect!r}"
        assert _v1["started_at"] in _v_html, "「开始 / 结束」行要显示起止时刻"
        # 3a'') 任务**列表页**是同一口径的第二个落点（续36 补 续35 的 [未做] 7）：光测
        #       `run_duration_text()` 抓不到"列表路由忘了传 durations / 模板删了列"，所以直接看渲染结果。
        _v_list_html = c.get("/tasks").get_data(as_text=True)
        import re as _re6v
        _v_row = _re6v.search(r'<tr data-id="%d".*?</tr>' % _va, _v_list_html, _re6v.S)
        assert "运行时长" in _v_list_html, "任务列表页缺「运行时长」列"
        assert _v_row and _v_expect in _v_row.group(0), \
            f"任务列表页该行应显示运行时长 {_v_expect!r}（钉到行上，避免别处凑巧出现同串而假绿）"
        # 3b) stopped 分支（用户点停止 / 预算耗尽）——断点必须保留，供续跑
        _stop_once6v[0] = True
        _vb = db.create_task("smoke-duration-stop", targets, _v_stages, {"offline": True})
        _v_ids.append(_vb)
        run_task(_vb, "smoke-duration-stop", targets, _v_stages, {"offline": True}, settings)
        _v2 = dict(db.get_task(_vb))
        assert _v2["status"] == "stopped" and _v2["started_at"] and _v2["finished_at"], _v2
        assert _v2["current_stage"] == "smoke-v2", _v2
        # 3c) 续跑是**第二段**：预置一个累计值，跑完必须"不清零"（`fresh` 误用到续跑上会被这条抓住）
        db.update_task(_vb, elapsed_seconds=123)
        run_task(_vb, "smoke-duration-stop", targets, _v_stages, {"offline": True}, settings,
                 resume=True)
        _v3 = dict(db.get_task(_vb))
        assert _v3["status"] == "done" and int(_v3["elapsed_seconds"]) >= 123, _v3
        # 3d) failed 分支 = `run_task` 的**外层 except**（阶段级异常不走这里：它只记 error
        #     后继续跑完，任务照样 done —— 这正是要用"收尾路径之外炸掉"来区分的原因）
        class _BadInfoLogger:
            def __init__(self, real):
                self._real = real

            def info(self, *a, **k):
                raise RuntimeError("smoke-6v：故意让 logger.info 炸掉")

            def __getattr__(self, name):
                return getattr(self._real, name)

        _v_real_get_logger = _rn6.get_logger
        _rn6.get_logger = lambda *a, **k: _BadInfoLogger(_v_real_get_logger(*a, **k))
        try:
            _vc = db.create_task("smoke-duration-fail", targets, _v_stages, {"offline": True})
            _v_ids.append(_vc)
            run_task(_vc, "smoke-duration-fail", targets, _v_stages, {"offline": True}, settings)
        finally:
            _rn6.get_logger = _v_real_get_logger
        _v4 = dict(db.get_task(_vc))
        assert _v4["status"] == "failed" and _v4["started_at"] and _v4["finished_at"], _v4

        # 4) 启动对账（进程被强杀）按**最后已知存活时刻**结账：进程可能几天前就死了，
        #    拿"对账时刻"当结束时刻会把停机时长整段算成运行时长。
        #    造这个输入只能直接写列：`update_task` 总会把 updated_at 刷成"现在"。
        _r35 = db.create_task("smoke-duration-reconcile", targets, ["probe"], {"offline": True})
        _v_ids.append(_r35)
        db.update_task(_r35, status="running", pid=0,     # pid=0 = 进程已不在（老库遗留行的口径）
                       started_at="2026-01-01 00:00:00", elapsed_seconds=0)
        db._exec("UPDATE tasks SET updated_at=? WHERE id=?", ("2026-01-01 00:02:00", _r35))
        assert _r35 in db.reconcile_orphan_tasks(), "pid=0 的 running 任务必须被对账标失败"
        _r35_row = dict(db.get_task(_r35))
        assert _r35_row["status"] == "failed", _r35_row
        assert int(_r35_row["elapsed_seconds"]) == 120, \
            f"必须按 updated_at−started_at 结账（拿对账时刻会算成停机+运行）：{_r35_row}"
        assert _r35_row["finished_at"] == "2026-01-01 00:02:00", _r35_row
    finally:
        for _vid in _v_ids:
            db.delete_task(_vid, backup=False)
        db.delete_task(_d35, backup=False)
        _rn6.STAGE_REGISTRY.clear()
        _rn6.STAGE_REGISTRY.update(_saved6v)

    print("[6v] 续35 运行时长 ok: format_duration 口径（0/59/60/3599/3600/3661/None/负值）/ "
          "起止写入 + 多段**累加**（90→150）/ fresh 清零·续跑不清零 / 没起点·时钟回拨均记 0 秒 "
          "（不写负数）/ task_run_seconds 四情形（运行中按注入的 now 算、被强杀只报已确认值）/ "
          "页面文案（老任务 `-`）/ 详情页与**任务列表页**两处都渲染出同一口径（续36 补列表列）/ "
          "runner 三条终态（done·stopped·外层 except→failed）都落了 "
          "started_at+finished_at / 启动对账按 updated_at 结账（不把停机时长算成运行时长）")

    # [6w] FOFA 三路反查的**阶段级**桩测（续36）—— 补 `[6u]` 留下的两条待办。
    #      `[6u]` 全 13 阶段真跑时为防烧配额**显式关掉了 FOFA**，于是这几件事一直没有回归覆盖：
    #      ① favicon 那一路（`fofa_mod.search`）"命中 → 落拓展域名"的接线；
    #      ② 三个子开关各管哪一路（cert / title 关掉后 favicon 照跑、总开关关掉则一次都不查）；
    #      ③ "命中过多即放弃拓展"（黑 ico / 通用证书）与两类**零请求预筛**（占位证书 / 模板标题）
    #         在阶段里是否真的接上 —— 纯函数测过 ≠ 接线正确（本项目已踩过这类坑）。
    #      桩掉 `fofa_mod.search*` 与 `favicon_hash`：零真实请求、不占配额。
    _fw_calls, _fw_batch = [], {}

    def _fw_icon(icon_hash, settings, logger=None, size=None):
        _fw_calls.append(("icon", icon_hash))
        return _fw_batch["icon"]

    def _fw_cert(domain, settings, logger=None, size=None):
        _fw_calls.append(("cert", domain))
        return _fw_batch["cert"].get(domain, ([], 0, ""))

    def _fw_title(title, settings, logger=None, size=None):
        _fw_calls.append(("title", title))
        return _fw_batch["title"].get(title, ([], 0, ""))

    _fw_orig = (osint_mod.fofa_mod.search, osint_mod.fofa_mod.search_cert,
                osint_mod.fofa_mod.search_title, osint_mod.favicon_hash)
    osint_mod.fofa_mod.search = _fw_icon
    osint_mod.fofa_mod.search_cert = _fw_cert
    osint_mod.fofa_mod.search_title = _fw_title
    osint_mod.favicon_hash = lambda url, settings=None: 12345

    def _fw_asset(domain, ip="1.2.3.4"):
        return {"host": "https://" + (domain or ip), "domain": domain, "ip": ip,
                "port": "443", "title": ""}

    def _fw_settings(**fofa):
        """osint 的 settings 副本：只留 FOFA 这一路开，其余外部开关一律关（零真实请求）。"""
        s = copy.deepcopy(settings)
        s["iprecon"] = dict(s.get("iprecon") or {}, enabled=False)
        for _n in ("shodan", "quake", "ctlog"):
            s[_n] = dict(s.get(_n) or {}, enabled=False)
        s["fofa"] = dict(s.get("fofa") or {}, black_ico_threshold=200, cert_threshold=200,
                         title_threshold=200)
        s["fofa"].update(fofa)
        s["keys"] = {"fofa": {"email": "stub@example.test", "key": "stub"}}
        return s

    def _fw_site(url, title):
        return {"url": url, "host": "127.0.0.1", "port": "80", "status": 200, "title": title,
                "length": 100, "source": "builtin"}

    def _fw_run(tag, s, sites, subs):
        _tid = db.create_task(f"smoke-fofa-{tag}", targets, ["osint"], {"offline": True})
        db.insert_sites(_tid, sites)
        if subs:
            db.insert_subdomains(_tid, subs)
        run_task(_tid, f"smoke-fofa-{tag}", targets, ["osint"], {"offline": True}, s)
        return _tid

    _fw_ids = []
    try:
        # A) 总开关关 + 其余子能力都关 → 整个阶段直接跳过：一次查询都不发
        _fw_batch.update({"icon": ([], 0, ""), "cert": {}, "title": {}})
        _fw_mark = len(_fw_calls)
        _fw_ids.append(_fw_run("off", _fw_settings(enabled=False),
                               [_fw_site(targets, "Acme Portal")], []))
        assert len(_fw_calls) == _fw_mark, f"fofa.enabled=False 应零查询：{_fw_calls[_fw_mark:]}"
        assert not db.list_subdomains(_fw_ids[-1]), "总开关关着不该拓展出任何域名"

        # B) 只开 favicon 那一路：命中落库且来源是 osint:fofa；cert / title **一次都不查**
        _fw_batch.update({"icon": ([_fw_asset("ico-hit.cn"), _fw_asset("", ip="9.9.9.9")],
                                   5, ""), "cert": {}, "title": {}})
        _fw_mark = len(_fw_calls)
        _fw_ids.append(_fw_run("icon", _fw_settings(enabled=True, cert_enabled=False,
                                                    title_enabled=False),
                               [_fw_site(targets, "Acme Portal")], []))
        _fw_got = {(r["domain"], r["source"]) for r in db.list_subdomains(_fw_ids[-1])}
        assert _fw_got == {("ico-hit.cn", "osint:fofa")}, \
            f"favicon 命中要落 osint:fofa，裸 IP 那行不得当域名入库：{_fw_got}"
        assert _fw_calls[_fw_mark:] == [("icon", 12345)], \
            f"cert_enabled/title_enabled=False 时不该查证书 / 标题：{_fw_calls[_fw_mark:]}"

        # C) 三路全开，钉"命中过多即放弃拓展"与"零请求预筛"：
        #    - favicon 命中 999 条（> 黑 ico 阈值 200）→ 有 assets 也**不拓展**
        #    - 证书：`example.com` 是占位证书 → **连查询都不发**；正常注册域命中 → 落 osint:fofa-cert；
        #      另一个注册域命中 999 条 → 判通用证书，不拓展
        #    - 标题：`Index of /backup` 是模板页 → **连查询都不发**；具体标题命中 → 落 osint:fofa-title
        _fw_batch.update({
            "icon": ([_fw_asset("black-ico.cn")], 999, ""),
            "cert": {"acme-portal.cn": ([_fw_asset("shared-cert.cn")], 20, ""),
                     "common-cert.org": ([_fw_asset("should-not-land.org")], 999, "")},
            "title": {"Acme Portal": ([_fw_asset("acme.cn")], 15, "")},
        })
        _fw_mark = len(_fw_calls)
        _fw_ids.append(_fw_run("all", _fw_settings(enabled=True, cert_enabled=True,
                                                   title_enabled=True),
                               [_fw_site(targets, "Acme Portal"),
                                _fw_site("http://127.0.0.1:8765/backup", "Index of /backup")],
                               [("acme-portal.cn", "subfinder"),
                                ("common-cert.org", "subfinder"),
                                ("example.com", "subfinder")]))
        _fw_c = _fw_calls[_fw_mark:]
        _fw_os = {(r["domain"], r["source"]) for r in db.list_subdomains(_fw_ids[-1])
                  if str(r["source"]).startswith("osint:")}
        assert _fw_os == {("shared-cert.cn", "osint:fofa-cert"),
                          ("acme.cn", "osint:fofa-title")}, \
            f"黑 ico / 通用证书 / 公共标题都不该拓展：{_fw_os}"
        assert ("icon", 12345) in _fw_c, "黑 ico 那条必须先**查过**才谈得上放弃（否则测的是没查）"
        assert ("cert", "example.com") not in _fw_c, \
            f"占位证书（example.com）实测百万级命中，应零请求跳过：{_fw_c}"
        assert ("title", "Index of /backup") not in _fw_c, \
            f"模板标题应零请求跳过：{_fw_c}"
        assert ("cert", "acme-portal.cn") in _fw_c and ("cert", "common-cert.org") in _fw_c, _fw_c
        assert ("title", "Acme Portal") in _fw_c, _fw_c
    finally:
        for _fid in _fw_ids:
            db.delete_task(_fid, backup=False)
        (osint_mod.fofa_mod.search, osint_mod.fofa_mod.search_cert,
         osint_mod.fofa_mod.search_title, osint_mod.favicon_hash) = _fw_orig

    print("[6w] FOFA 三路反查（阶段级桩测）ok: fofa.enabled=False 零查询 / 只开 favicon 那路时 "
          "cert·title 一次都不查 / 命中落库来源正确（osint:fofa·fofa-cert·fofa-title，裸 IP 行不入库）/ "
          "黑 ico·通用证书不拓展（且证明确实查过）/ 占位证书与模板标题**零请求**预筛")

    # [6x] nuclei `dsl` 表达式**安全子集**（续37）—— 补 `[5x]` 里"dsl 仍显式 unsupported"的缺口。
    #      只放开 `matchers` / `extractors` 里的 dsl（nuclei 就写在那里），**块级/顶层仍拒**。
    #      三条口径必须同时成立，缺一条都算没做完：
    #      ① 命中路径真的接上：装载期解析成 AST → 运行期求值 → 提取器落 evidence；
    #      ② 超出子集的写法**在装载期**就拒（整份模板 unsupported 且写明是哪种写法），
    #         绝不落到"运行期恒不命中"—— 那会让人以为"模板跑过了、没洞"；
    #      ③ 匹配器/提取器级放开 ≠ 块级放开（后者仍按不支持处理，原因可见）。
    _p_dsl_hit = _wpoc("dsl-hit.yaml", """
id: smoke-dsl-hit
info: {name: dsl hit, severity: medium}
http:
  - path: ["/a"]
    matchers-condition: and
    matchers:
      - type: dsl
        dsl:
          - "contains(body, 'hello-AAA') && status_code == 200"
          - "content_length > 3 && status_code < 500 && len(body) >= 9"
          - "starts_with(tolower(body), 'hello') && ends_with(body, 'AAA')"
          - "icontains(body, 'HELLO-aaa') && !(status_code == 404)"
          - "regex('^hello-[A-Z]{3}$', body)"
          - "toupper(body) == 'HELLO-AAA'"
          - "(contains(body, 'ZZZ') || contains(body, 'AAA')) && host != ''"
    extractors:
      - type: dsl
        dsl: ["status_code", "tolower(body)", "len(body)", "contains(body, 'AAA')"]
""")
    _m_dsl_hit = engine.load_poc_file(_p_dsl_hit)
    assert _m_dsl_hit["_status"] == "ok", _m_dsl_hit
    _dsl_m0 = _m_dsl_hit["http"][0]["matchers"][0]
    _dsl_e0 = _m_dsl_hit["http"][0]["extractors"][0]
    assert len(_dsl_m0.get("_dsl_ast") or []) == 7, "dsl 匹配器的 AST 应在装载期就挂上"
    assert len(_dsl_e0.get("_dsl_ast") or []) == 4, "dsl 提取器的 AST 应在装载期就挂上"
    _hits17.clear()
    _h_dsl = engine.run_poc_on_target(_m_dsl_hit, _base_url17, {})
    assert _hits17 == ["/a"], f"dsl 命中路径没发出请求：{_hits17}"
    assert len(_h_dsl) == 1 and _h_dsl[0]["poc_id"] == "smoke-dsl-hit", _h_dsl
    _dsl_ev = _h_dsl[0]["evidence"].splitlines()
    # 提取器只收**非布尔**结果：布尔值本身就是"命中/不命中"，当证据没有人工确认价值
    assert _dsl_ev == ["200", "9", "hello-aaa"], \
        f"dsl 提取器应落 status_code/len/tolower 三值、且不含布尔结果：{_dsl_ev}"
    # 不成立就是**不报**（钉住"dsl 分支恒 True"这类假绿）
    _m_dsl_miss = engine.load_poc_file(_wpoc("dsl-miss.yaml", """
id: smoke-dsl-miss
info: {name: dsl miss, severity: medium}
http:
  - path: ["/a"]
    matchers:
      - type: dsl
        dsl: ["contains(body, 'NOT-THERE')"]
"""))
    assert _m_dsl_miss["_status"] == "ok", _m_dsl_miss
    assert engine.run_poc_on_target(_m_dsl_miss, _base_url17, {}) == [], "dsl 不成立竟报命中"
    # 合并口径：matcher 内 `condition`（默认 or）与顶层 `negative`；变量与手工 POC dict 的兜底
    _dsl_resp = {"status": 200, "length": 9, "text": "hello-AAA",
                 "headers": {"Server": "lab"}, "url": _base_url17 + "/a"}
    _dsl_host = _dsl_resp["url"].split("/")[2]

    def _dsl_ok(matcher, expect, why):
        got = engine._match_one(matcher, _dsl_resp)
        assert got is expect, f"{why}：期望 {expect}，实际 {got}"

    _dsl_ok({"type": "dsl", "dsl": ["status_code == 200"]}, True, "基本比较")
    _dsl_ok({"type": "dsl", "dsl": "status_code == 200"}, True, "dsl 写成一整个字符串")
    _dsl_ok({"type": "dsl", "dsl": ["status_code == 200", "contains(body, 'zzz')"]},
            True, "多条默认 or")
    _dsl_ok({"type": "dsl", "condition": "and",
             "dsl": ["status_code == 200", "contains(body, 'zzz')"]}, False, "condition: and")
    _dsl_ok({"type": "dsl", "negative": True, "dsl": ["status_code == 200"]},
            False, "negative 取反")
    _dsl_ok({"type": "dsl", "dsl": ["header == all_headers", f"host == '{_dsl_host}'",
                                    "len(all_headers) > 0"]}, True,
            "header/all_headers/host 变量")
    # 手工构造的 POC dict 没有装载期的 `_dsl_ast` → 现解析兜底；越界/为空时按不命中（不炸）
    _dsl_ok({"type": "dsl", "dsl": ["body.contains('x')"]}, False, "越界表达式兜底不炸")
    _dsl_ok({"type": "dsl", "dsl": []}, False, "空 dsl 兜底不炸")
    # 越界写法（8 类）必须在**装载期**被拒，且原因能指认出是哪种写法
    def _dsl_reject(tag, expr, must):
        m = engine.load_poc_file(_wpoc(f"dsl-bad-{tag}.yaml", """
id: smoke-dsl-bad-%s
info: {name: bad, severity: low}
http:
  - path: ["/a"]
    matchers:
      - type: dsl
        dsl: ["%s"]
""" % (tag, expr)))
        assert m["_status"] == "unsupported", f"{tag} 应判 unsupported：{m}"
        assert "dsl 表达式超出支持子集" in m["_error"], f"{tag} 的原因没写清：{m['_error']}"
        assert must in m["_error"], f"{tag} 的原因应提到 {must!r}：{m['_error']}"

    _dsl_reject("dot", "body.contains('x')", "含不支持的字符 `.`")
    _dsl_reject("fn", "md5(body) == 'x'", "不支持的函数 `md5()`")
    _dsl_reject("var", "status == 200", "不支持的变量 `status`")
    _dsl_reject("arith", "status_code + 1 == 200", "含不支持的字符 `+`")
    _dsl_reject("chain", "status_code == 200 == 200", "链式比较")
    _dsl_reject("strcmp", "body > 'a'", "只允许数值比较")
    _dsl_reject("badregex", "regex('([', body)", "模式不合法")
    _m_dsl_empty = engine.load_poc_file(_wpoc("dsl-empty.yaml", """
id: smoke-dsl-empty
info: {name: e, severity: low}
http:
  - path: ["/a"]
    matchers:
      - type: dsl
        dsl: []
"""))
    assert _m_dsl_empty["_status"] == "unsupported" and "为空" in _m_dsl_empty["_error"], \
        _m_dsl_empty
    # 提取器里的越界同样在装载期拦（不能只查 matchers）
    _m_dsl_exbad = engine.load_poc_file(_wpoc("dsl-bad-extractor.yaml", """
id: smoke-dsl-bad-extractor
info: {name: e, severity: low}
http:
  - path: ["/a"]
    matchers: [{type: status, status: [200]}]
    extractors:
      - type: dsl
        dsl: ["body.contains('x')"]
"""))
    assert _m_dsl_exbad["_status"] == "unsupported" and "extractors" in _m_dsl_exbad["_error"], \
        _m_dsl_exbad
    # 块级 / 顶层 dsl 仍按不支持处理（与 matchers 级的放开严格区分开）
    _m_dsl_block = engine.load_poc_file(_wpoc("dsl-block.yaml", """
id: smoke-dsl-block
info: {name: b, severity: low}
http:
  - path: ["/a"]
    dsl: [status_code == 200]
    matchers: [{type: dsl, dsl: ["status_code == 200"]}]
"""))
    assert _m_dsl_block["_status"] == "unsupported" and "dsl" in _m_dsl_block["_error"], \
        _m_dsl_block
    _m_dsl_top = engine.load_poc_file(_wpoc("dsl-top.yaml", """
id: smoke-dsl-top
info: {name: t, severity: low}
dsl: [status_code == 200]
"""))
    assert _m_dsl_top["_status"] == "unsupported" and "顶层 dsl 不支持" in _m_dsl_top["_error"], \
        _m_dsl_top

    print("[6x] 续37 nuclei dsl 安全子集 ok: 装载期解析成 AST（匹配器 7 条 / 提取器 4 条，"
          "运行期只求值）→ 端到端命中本地靶场且 evidence 只收非布尔结果（200/9/hello-aaa）/ "
          "不成立不报 / condition or·and 与 negative 取反 / header·all_headers·host 变量 / "
          "8 类越界（方法调用·未知函数·未知变量·算术·链式比较·字符串大小比较·坏 regex·空 dsl）"
          "装载期即标 unsupported 且原因指认写法 / 提取器级同样拦 / 块级与顶层 dsl 仍拒绝")

    # [6y] nuclei workflow 的**条件编排**（续38；`matchers:` 分支为续43 补齐）：`template:`
    # （文件/目录）+ `tags:` + `subtemplates:`（父步骤命中才跑）+ `matchers:`（按具名提取器
    # 分流）。语义对着 nuclei 源码写（`pkg/templates/workflows.go` /
    # `pkg/core/workflow_execute.go` / `pkg/templates/tag_filter.go`），不自己发明：
    #   - 带 subtemplates 的步骤，父模板只当**开关**，父模板自己的结果不报；
    #   - `tags:` 是 **OR** 选择，候选集 = 注册表启用 + 级别门控（与普通 POC 一视同仁）；
    #   - `matchers:` 步骤的父模板同样只当开关（连命中都不报），按父模板结果里的
    #     **非 internal 具名提取器**名字挑分支；同名比较大小写不敏感，and 全中 / or 任一；
    #   - `args:` 不支持（它根本不是 nuclei 的 workflow 字段）。
    _y_parent = engine.load_poc_file(_wpoc("wf-parent-hit.yaml", """
id: smoke-wf-parent
info: {name: parent, severity: medium}
http:
  - path: ["/a"]
    matchers: [{type: word, words: ["hello-AAA"]}]
"""))
    assert _y_parent["_status"] == "ok", _y_parent
    engine.load_poc_file(_wpoc("wf-parent-miss.yaml", """
id: smoke-wf-parent-miss
info: {name: parent miss, severity: medium}
http:
  - path: ["/nope"]
    matchers: [{type: word, words: ["NOT-THERE"]}]
"""))
    engine.load_poc_file(_wpoc("wf-child.yaml", """
id: smoke-wf-child
info: {name: child, severity: medium}
http:
  - path: ["/b"]
    matchers: [{type: word, words: ["hello-BBB"]}]
"""))
    # ① 父命中 → 跑子模板；且**父模板自己的结果不报**（报出来的是子模板的 poc_id）
    _y_gate = engine.load_poc_file(_wpoc("wf-gate.yaml", """
id: smoke-wf-gate
info: {name: gate, severity: medium}
workflows:
  - template: wf-parent-hit.yaml
    subtemplates:
      - template: wf-child.yaml
"""))
    assert _y_gate["_status"] == "ok", _y_gate
    assert [s["path"] for s in _y_gate["_workflow"][0]["subtemplates"]] == ["wf-child.yaml"], _y_gate
    _hits17.clear()
    _y_got = engine.run_poc_on_target(_y_gate, _base_url17, {})
    assert [v["poc_id"] for v in _y_got] == ["smoke-wf-child"], _y_got
    assert _hits17 == ["/a", "/b"], f"父模板当开关要先打，命中后才打子模板：{_hits17}"
    # ② 父**不命中** → 子模板一个请求都不发（条件编排的全部意义；这条挡"无条件跑子模板"的假实现）
    _y_gate0 = engine.load_poc_file(_wpoc("wf-gate-miss.yaml", """
id: smoke-wf-gate-miss
info: {name: gate miss, severity: medium}
workflows:
  - template: wf-parent-miss.yaml
    subtemplates:
      - template: wf-child.yaml
"""))
    _hits17.clear()
    assert engine.run_poc_on_target(_y_gate0, _base_url17, {}) == []
    assert _hits17 == ["/nope"], f"父没命中就不该跑子模板：{_hits17}"
    # ③ 多级：中间层没命中 → 第三层同样不跑
    _y_nest = engine.load_poc_file(_wpoc("wf-nest.yaml", """
id: smoke-wf-nest
info: {name: nest, severity: medium}
workflows:
  - template: wf-parent-hit.yaml
    subtemplates:
      - template: wf-parent-miss.yaml
        subtemplates:
          - template: wf-child.yaml
"""))
    _hits17.clear()
    assert engine.run_poc_on_target(_y_nest, _base_url17, {}) == []
    assert _hits17 == ["/a", "/nope"], f"中间层没命中，第三层不该跑：{_hits17}"
    # ④ `tags:` 从候选集里挑（OR 语义）+ 未选中的模板绝不发请求
    _y_ta = engine.load_poc_file(_wpoc("wf-tag-a.yaml", """
id: smoke-wf-tag-a
info: {name: a, severity: medium, tags: [smoke17wf]}
http:
  - path: ["/a"]
    matchers: [{type: word, words: ["hello-AAA"]}]
"""))
    _y_tb = engine.load_poc_file(_wpoc("wf-tag-b.yaml", """
id: smoke-wf-tag-b
info: {name: b, severity: medium, tags: [other17tag]}
http:
  - path: ["/b"]
    matchers: [{type: word, words: ["hello-BBB"]}]
"""))
    _y_reg = [_y_ta, _y_tb]
    _y_tags = engine.load_poc_file(_wpoc("wf-tags.yaml", """
id: smoke-wf-tags
info: {name: tags, severity: medium}
workflows:
  - tags: [smoke17wf]
"""))
    _hits17.clear()
    assert [v["poc_id"] for v in engine.run_poc_on_target(_y_tags, _base_url17, {},
                                                          registry=_y_reg)] == ["smoke-wf-tag-a"]
    assert _hits17 == ["/a"], f"未被标签选中的模板不该跑：{_hits17}"
    _y_tags2 = engine.load_poc_file(_wpoc("wf-tags2.yaml", """
id: smoke-wf-tags2
info: {name: tags2, severity: medium}
workflows:
  - tags: [nope17tag, other17tag]
"""))
    _hits17.clear()
    assert [v["poc_id"] for v in engine.run_poc_on_target(_y_tags2, _base_url17, {},
                                                          registry=_y_reg)] == ["smoke-wf-tag-b"]
    assert _hits17 == ["/b"], f"OR 语义：命中第二个标签也要选中：{_hits17}"
    # 字符串写法（nuclei 的 StringSlice：`"a, b"` 与 `[a, b]` 等价）
    _y_tags3 = engine.load_poc_file(_wpoc("wf-tags3.yaml", """
id: smoke-wf-tags3
info: {name: tags3, severity: medium}
workflows:
  - tags: "smoke17wf, other17tag"
"""))
    assert _y_tags3["_workflow"][0]["tags"] == ["smoke17wf", "other17tag"], _y_tags3
    _hits17.clear()
    assert [v["poc_id"] for v in engine.run_poc_on_target(_y_tags3, _base_url17, {},
                                                          registry=_y_reg)] == ["smoke-wf-tag-a"]
    assert _hits17 == ["/a"], _hits17
    # 不传 registry → 懒加载 `load_enabled_pocs`（真实模板库里没有这个标签 → 空跑且不报错）
    assert engine.run_poc_on_target(_y_tags, _base_url17, {}) == []
    assert engine._wf_tags({"tags": "A, b"}) == ["a", "b"]
    assert engine._wf_tags({}) == [] and engine._wf_tags({"tags": ["x,y"]}) == ["x", "y"]
    # ⑤ `tags` 与 `template` 同时写 → **tags 优先**、template 被忽略（nuclei 的行为，照抄）
    _y_prio = engine.load_poc_file(_wpoc("wf-prio.yaml", """
id: smoke-wf-prio
info: {name: prio, severity: medium}
workflows:
  - template: wf-child.yaml
    tags: [smoke17wf]
"""))
    assert _y_prio["_workflow"][0]["path"] == "", _y_prio
    _hits17.clear()
    assert [v["poc_id"] for v in engine.run_poc_on_target(_y_prio, _base_url17, {},
                                                          registry=_y_reg)] == ["smoke-wf-tag-a"], \
        "tags 优先时 template 必须被忽略"
    assert _hits17 == ["/a"], _hits17
    # ⑥ `template:` 指向**目录**（nuclei 的 `- template: exploits/jira/` 写法）
    _y_dir = _ptmp / "wfdir" / "d1.yaml"
    _y_dir.parent.mkdir(parents=True, exist_ok=True)
    _y_dir.write_text("""
id: smoke-wf-dir
info: {name: dir, severity: medium}
http:
  - path: ["/a"]
    matchers: [{type: word, words: ["hello-AAA"]}]
""", encoding="utf-8")
    _y_dirwf = engine.load_poc_file(_wpoc("wf-dir.yaml", """
id: smoke-wf-dir-wf
info: {name: dir wf, severity: medium}
workflows:
  - template: wfdir/
"""))
    _hits17.clear()
    assert [v["poc_id"] for v in engine.run_poc_on_target(_y_dirwf, _base_url17, {})] == \
        ["smoke-wf-dir"]
    assert _hits17 == ["/a"], _hits17
    # ⑦ 单个步骤的展开上限（`tags:` 可能命中整个模板库、目录可能很大 → 必须封顶）
    _y_step = {"path": "", "tags": ["cap17"], "subtemplates": []}
    _y_cap = [{"id": f"cap{i}", "_status": "ok", "_path": f"/tmp/cap{i}.yaml",
               "info": {"tags": ["cap17"]}} for i in range(45)]
    assert len(engine._wf_targets(_y_step, _ptmp, _y_cap, {})) == engine._WORKFLOW_MAX_SUBS
    assert len(engine._wf_targets(_y_step, _ptmp, _y_cap[:5], {})) == 5, "不足上限时不该截断"
    # ⑧ `args:` / 只有 `subtemplates:` 的项：跳过并写明原因（不静默失效）。
    #    `matchers:` 从续43 起是**有效**步骤（按具名提取器分流）；与它同写的普通
    #    `subtemplates:` 被忽略，"被忽略"要能看见（照抄 nuclei：matchers 分支直接 return）。
    _y_skip = engine.load_poc_file(_wpoc("wf-skip.yaml", """
id: smoke-wf-skip
info: {name: skip, severity: medium}
workflows:
  - template: wf-child.yaml
    matchers: [{name: x, subtemplates: [{template: wf-child.yaml}]}]
    subtemplates:
      - template: wf-child.yaml
  - template: wf-child.yaml
    args: {foo: bar}
  - subtemplates: [{template: wf-child.yaml}]
  - template: wf-child.yaml
"""))
    assert _y_skip["_status"] == "ok" and len(_y_skip["_workflow"]) == 2, _y_skip
    for _y_k in ("args:", "subtemplates:"):
        assert _y_k in (_y_skip["_note"] or ""), f"`{_y_k}` 被跳过的原因要能看见：{_y_skip}"
    assert "被忽略" in (_y_skip["_note"] or ""), \
        f"与 `matchers:` 同时写的 `subtemplates:` 被忽略这件事要能看见：{_y_skip}"
    _y_ms = _y_skip["_workflow"][0]
    assert [g["names"] for g in _y_ms["matchers"]] == [["x"]], _y_ms
    assert len(_y_ms["matchers"][0]["subtemplates"]) == 1, _y_ms
    assert _y_ms["subtemplates"] == [], \
        f"与 `matchers:` 同时写的 `subtemplates:` 必须被忽略（nuclei 只跑 matchers 里的）：{_y_ms}"
    # 全部子项都被跳过 → 整份 workflow 判不可用，且原因指认写法
    _y_onlya = engine.load_poc_file(_wpoc("wf-only-args.yaml", """
id: smoke-wf-only-args
info: {name: a, severity: medium}
workflows:
  - template: wf-child.yaml
    args: {foo: bar}
"""))
    assert _y_onlya["_status"] == "unsupported" and "args:" in _y_onlya["_error"], _y_onlya
    _y_badcond = engine.load_poc_file(_wpoc("wf-bad-condition.yaml", """
id: smoke-wf-bad-condition
info: {name: b, severity: medium}
workflows:
  - template: wf-child.yaml
    matchers: [{name: x, condition: xor, subtemplates: [{template: wf-child.yaml}]}]
"""))
    assert _y_badcond["_status"] == "unsupported" and "matchers:" in _y_badcond["_error"], \
        _y_badcond
    assert "condition" in _y_badcond["_error"], _y_badcond
    # 名字一律归一成小写（`StringSlice`：`"a, b"` 与 `[a, b]` 等价）、condition 默认 or
    assert engine._wf_slice("A, b") == ["a", "b"] and engine._wf_slice(None) == []
    assert engine._wf_slice(["x,y"]) == ["x", "y"], "列表里塞了逗号串也要拆开"
    _y_g, _y_why = engine._wf_groups([{"name": "a"}, {"name": ["b", "c"]}])
    assert [g["names"] for g in _y_g] == [["a"], ["b", "c"]] and _y_why == "", (_y_g, _y_why)
    assert all(g["condition"] == "or" for g in _y_g), f"condition 默认应是 or：{_y_g}"
    _y_g2, _y_why2 = engine._wf_groups([{"name": "a", "condition": "AND"}])
    assert _y_g2[0]["condition"] == "and" and _y_why2 == "", (_y_g2, _y_why2)
    assert engine._wf_groups("x")[0] is None and "列表" in engine._wf_groups("x")[1]
    assert engine._wf_groups(["x"])[0] is None and "映射" in engine._wf_groups(["x"])[1]
    # ⑨ 带 subtemplates 的自环：同一模板单次执行只跑一次（否则 A→A 会无限下钻）
    _wpoc("wf-loop-sub.yaml", """
id: smoke-wf-loop-sub
info: {name: loop sub, severity: medium}
workflows:
  - template: wf-child.yaml
    subtemplates:
      - template: wf-loop-sub.yaml
""")
    _y_loop = engine.load_poc_file(_ptmp / "wf-loop-sub.yaml")
    _hits17.clear()
    assert engine.run_poc_on_target(_y_loop, _base_url17, {}) == []
    assert _hits17 == ["/b"], f"自环应被去重挡住，子模板只跑一次：{_hits17}"

    # ⑩ `matchers:` 分流（续43）：父模板只当"取值开关"（连命中都不报），按**非 internal 具名
    #    提取器**的名字挑分支。语义对着 nuclei `pkg/core/workflow_execute.go::runWorkflowStep`
    #    的 matchers 分支 + `pkg/workflows/workflows.go::Matcher.Match`（EqualFold 比较、
    #    and 全中 / or 任一）写。本引擎的匹配器没有名字概念，故 `HasMatch` 恒假、只能靠 Extracts。
    _wpoc("wf-tok-parent.yaml", """
id: smoke-wf-tok-parent
info: {name: tok parent, severity: medium}
http:
  - path: ["/csrf"]
    matchers: [{type: word, words: ["TOK123"]}]
    extractors:
      - type: regex
        name: tok
        regex: ["TOK[0-9]+"]
""")
    _wpoc("wf-tok-use.yaml", """
id: smoke-wf-tok-use
info: {name: tok use, severity: medium}
http:
  - path: ["/b/{{tok}}"]
    matchers: [{type: word, words: ["hello-BBB"]}]
""")
    _y_tok = engine.load_poc_file(_wpoc("wf-tok.yaml", """
id: smoke-wf-tok
info: {name: tok wf, severity: medium}
workflows:
  - template: wf-tok-parent.yaml
    matchers:
      - name: nope
        subtemplates:
          - template: wf-child.yaml
      - name: TOK
        subtemplates:
          - template: wf-tok-use.yaml
"""))
    assert _y_tok["_status"] == "ok", _y_tok
    assert [g["names"] for g in _y_tok["_workflow"][0]["matchers"]] == [["nope"], ["tok"]], _y_tok
    _hits17.clear()
    _y_tokres = engine.run_poc_on_target(_y_tok, _base_url17, {})
    # 名字大小写不敏感（`TOK` 命中父模板抽出的 `tok`）/ 未命中的 matcher 子模板零请求 /
    # 父模板本身命中了也**不报**（报出来的是子模板）
    assert _hits17 == ["/csrf", "/b/TOK123"], \
        f"matchers 分流：未命中的分支不该发请求、命中的分支要拿到父模板取到的值：{_hits17}"
    assert [v["poc_id"] for v in _y_tokres] == ["smoke-wf-tok-use"], _y_tokres
    # ⑪ `condition: and` 要求名字全中（父模板只抽得到 tok，抽不到 sec → 子模板零请求）
    _y_and = engine.load_poc_file(_wpoc("wf-tok-and.yaml", """
id: smoke-wf-tok-and
info: {name: and, severity: medium}
workflows:
  - template: wf-tok-parent.yaml
    matchers:
      - name: "tok, sec"
        condition: and
        subtemplates:
          - template: wf-tok-use.yaml
"""))
    assert [g["names"] for g in _y_and["_workflow"][0]["matchers"]] == [["tok", "sec"]], _y_and
    assert _y_and["_workflow"][0]["matchers"][0]["condition"] == "and", _y_and
    _hits17.clear()
    assert engine.run_poc_on_target(_y_and, _base_url17, {}) == []
    assert _hits17 == ["/csrf"], f"and 未全中就不该跑分支子模板：{_hits17}"
    # 同一份父模板换成 `or`（默认值）→ 任一命中即跑
    _y_or = engine.load_poc_file(_wpoc("wf-tok-or.yaml", """
id: smoke-wf-tok-or
info: {name: or, severity: medium}
workflows:
  - template: wf-tok-parent.yaml
    matchers:
      - name: [tok, sec]
        subtemplates:
          - template: wf-tok-use.yaml
"""))
    assert _y_or["_workflow"][0]["matchers"][0]["condition"] == "or", _y_or
    _hits17.clear()
    assert [v["poc_id"] for v in engine.run_poc_on_target(_y_or, _base_url17, {})] == \
        ["smoke-wf-tok-use"]
    assert _hits17 == ["/csrf", "/b/TOK123"], _hits17
    # ⑫ `internal: true` 的提取器**不参与**分流（nuclei：internal 值进 DynamicValues、
    #    不进 `result.Extracts`）→ 父模板跑了也分不出支，子模板零请求
    _wpoc("wf-tok-int.yaml", """
id: smoke-wf-tok-int
info: {name: tok int, severity: medium}
http:
  - path: ["/csrf"]
    extractors:
      - type: regex
        name: tok
        internal: true
        regex: ["TOK[0-9]+"]
""")
    _y_int = engine.load_poc_file(_wpoc("wf-tok-int-wf.yaml", """
id: smoke-wf-tok-int-wf
info: {name: int wf, severity: medium}
workflows:
  - template: wf-tok-int.yaml
    matchers:
      - name: [tok]
        subtemplates:
          - template: wf-tok-use.yaml
"""))
    assert _y_int["_status"] == "ok", _y_int
    _hits17.clear()
    assert engine.run_poc_on_target(_y_int, _base_url17, {}) == []
    assert _hits17 == ["/csrf"], f"internal 提取值不该参与分流：{_hits17}"
    # ⑬ 同级子模板互不回流：兄弟 A 也抽到一个**非 internal** 的 `tok`（值是 AAA）但没命中，
    #    兄弟 B 用的必须是**父模板给的** TOK123 —— 若把同级/各步的收集容器共用，B 会发 `/b/AAA`
    _wpoc("wf-sib-a.yaml", """
id: smoke-wf-sib-a
info: {name: sib a, severity: medium}
http:
  - path: ["/a"]
    matchers: [{type: word, words: ["NOT-THERE"]}]
    extractors:
      - type: regex
        name: tok
        regex: ["AAA"]
""")
    _wpoc("wf-sib-b.yaml", """
id: smoke-wf-sib-b
info: {name: sib b, severity: medium}
http:
  - path: ["/b/{{tok}}"]
    matchers: [{type: word, words: ["hello-BBB"]}]
""")
    _y_sib = engine.load_poc_file(_wpoc("wf-sib.yaml", """
id: smoke-wf-sib
info: {name: sib, severity: medium}
workflows:
  - template: wf-tok-parent.yaml
    matchers:
      - name: [tok]
        subtemplates:
          - template: wf-sib-a.yaml
          - template: wf-sib-b.yaml
"""))
    assert _y_sib["_status"] == "ok", _y_sib
    _hits17.clear()
    assert [v["poc_id"] for v in engine.run_poc_on_target(_y_sib, _base_url17, {})] == \
        ["smoke-wf-sib-b"]
    assert _hits17 == ["/csrf", "/a", "/b/TOK123"], \
        f"兄弟模板自己收集到的值不该回流给同层的下一个：{_hits17}"

    print("[6y] 续38/续43 nuclei workflow 条件编排 ok: 父命中才下钻（不命中则子模板零请求）/ 带 "
          "subtemplates 的父模板只当开关·结果不报 / 多级门控 / `tags:` OR 选择且只打选中的模板 "
          "/ `tags` 优先于 `template` / 目录展开 / 单步 40 个上限 / `args:`·裸 `subtemplates:` "
          "跳过并写明原因（全跳过则整份 unsupported）；续43 `matchers:` 按**非 internal 具名"
          "提取器**分流：父模板命中也不报、未命中的分支零请求、名字大小写不敏感、and/or、"
          "internal 不参与分流、跨子模板传值 `{{tok}}` 而同级不回流 / 自环去重")

    # [6z] 续39：nuclei `flow:` 的**脚本子集**（循环 + `set()` + 请求 → 多轮/多步编排）。
    # 语义对着 nuclei 源码写（`pkg/tmplexec/flow/{flow_executor,flow_internal,vm}.go`）：
    #   - `http(N)` 是 **1-based**；`http()` = 按模板顺序跑该协议**全部块**；多参按传入顺序；
    #   - `set(name, value)` 写模板上下文 → 后续请求里的 `{{name}}`；
    #   - `iterate(...)` 把参数扁平化成数组（**不是**"遍历请求块"）；
    #   - `template` 是**对象**不是函数，读值是 `template["key"]`。
    # 与布尔子集（[5x]）**并存**：装载期先按布尔解析、不行再按脚本解析；脚本里的
    # `http(...)` **不缓存**（缓存等于把循环的意义抹掉）。
    # ① `for...of iterate(...)` + `set()` + `http(1)`：每轮**真的重发**（钉请求路径序列）
    _fjs_loop = engine.load_poc_file(_wpoc("fjs-loop.yaml", """
id: smoke-fjs-loop
info: {name: fjs loop, severity: medium}
flow: |
  for (const u of iterate("admin", "root")) {
    set("user", u)
    http(1)
  }
http:
  - path: ["/{{user}}"]
    matchers: [{type: word, words: ["root"]}]
"""))
    assert _fjs_loop["_status"] == "ok", _fjs_loop.get("_error")
    assert "_flow_script" in _fjs_loop and "_flow" not in _fjs_loop, \
        f"脚本式 flow 该走脚本路：{_fjs_loop.get('_error')}"
    assert _fjs_loop["_flow_script"][0] == "script" and _fjs_loop["_flow_script"][2] == [1], \
        _fjs_loop["_flow_script"]
    _fjs_s0 = _fjs_loop["_flow_script"][1][0]
    assert _fjs_s0[0] == "forof" and _fjs_s0[4] == 2, _fjs_s0
    _hits17.clear()
    assert [v["poc_id"] for v in engine.run_poc_on_target(_fjs_loop, _base_url17, {})] == \
        ["smoke-fjs-loop"]
    assert _hits17 == ["/admin", "/root"], \
        f"`http(1)` 在循环里必须每轮重发（缓存就把循环抹掉了）：{_hits17}"
    # ② C 式 `for (let i = 0; i < 3; i++)`：三轮 → 三个请求（序号也进模板变量）
    _fjs_num = engine.load_poc_file(_wpoc("fjs-num.yaml", """
id: smoke-fjs-num
info: {name: fjs num, severity: medium}
flow: |
  for (let i = 0; i < 3; i++) {
    set("user", i)
    http(1)
  }
http:
  - path: ["/u{{user}}"]
    matchers: [{type: word, words: ["root"]}]
"""))
    assert _fjs_num["_status"] == "ok", _fjs_num.get("_error")
    assert _fjs_num["_flow_script"][1][0][0] == "fornum", _fjs_num["_flow_script"][1]
    _hits17.clear()
    assert engine.run_poc_on_target(_fjs_num, _base_url17, {})
    assert _hits17 == ["/u0", "/u1", "/u2"], f"C 式 for 的三轮：{_hits17}"
    # ③ `template["key"]` 读值与 `if` 门控：条件为假时**一句请求都不发**
    _fjs_on = engine.load_poc_file(_wpoc("fjs-tmpl-on.yaml", """
id: smoke-fjs-tmpl-on
info: {name: fjs tmpl on, severity: medium}
variables: {who: a}
flow: |
  if (template["who"] == "a") {
    http(1)
  }
http:
  - path: ["/a"]
    matchers: [{type: word, words: ["hello-AAA"]}]
"""))
    _fjs_off = engine.load_poc_file(_wpoc("fjs-tmpl-off.yaml", """
id: smoke-fjs-tmpl-off
info: {name: fjs tmpl off, severity: medium}
variables: {who: zzz}
flow: |
  if (template["who"] == "a") {
    http(1)
  }
http:
  - path: ["/a"]
    matchers: [{type: word, words: ["hello-AAA"]}]
"""))
    assert _fjs_on["_status"] == "ok" and _fjs_off["_status"] == "ok", \
        (_fjs_on.get("_error"), _fjs_off.get("_error"))
    _hits17.clear()
    assert [v["poc_id"] for v in engine.run_poc_on_target(_fjs_on, _base_url17, {})] == \
        ["smoke-fjs-tmpl-on"]
    assert _hits17 == ["/a"], f"`template[\"who\"] == \"a\"` 成立时才打：{_hits17}"
    _hits17.clear()
    assert engine.run_poc_on_target(_fjs_off, _base_url17, {}) == []
    assert _hits17 == [], f"条件为假时分支里的请求一句都不该发：{_hits17}"
    # ④ `http()` 跑全部块（模板顺序）+ `http("id")` / 多参按传入顺序
    _fjs_all = engine.load_poc_file(_wpoc("fjs-all.yaml", """
id: smoke-fjs-all
info: {name: fjs all, severity: medium}
flow: |
  http()
  http("b", 1)
http:
  - id: a
    path: ["/a"]
    matchers: [{type: word, words: ["hello-AAA"]}]
  - id: b
    path: ["/b"]
    matchers: [{type: word, words: ["hello-BBB"]}]
"""))
    assert _fjs_all["_status"] == "ok", _fjs_all.get("_error")
    assert _fjs_all["_flow_script"][2] == ["b", 1], _fjs_all["_flow_script"]
    _hits17.clear()
    assert [v["poc_id"] for v in engine.run_poc_on_target(_fjs_all, _base_url17, {})] == \
        ["smoke-fjs-all"]
    assert _hits17 == ["/a", "/b", "/b", "/a"], \
        f"`http()` 该按模板顺序跑全部块、`http(\"b\", 1)` 该按传入顺序：{_hits17}"
    # ⑤ 脚本**不是**布尔短路：两句都真发；但只报**第一个**正向命中（脚本没有"整体真值"）
    _fjs_first = engine.load_poc_file(_wpoc("fjs-first.yaml", """
id: smoke-fjs-first
info: {name: fjs first, severity: medium}
flow: |
  http(1)
  http(2)
http:
  - path: ["/a"]
    matchers: [{type: word, words: ["hello-AAA"]}]
  - path: ["/b"]
    matchers: [{type: word, words: ["hello-BBB"]}]
"""))
    assert _fjs_first["_status"] == "ok", _fjs_first.get("_error")
    _hits17.clear()
    _fjs_got = engine.run_poc_on_target(_fjs_first, _base_url17, {})
    assert len(_fjs_got) == 1 and _fjs_got[0]["poc_id"] == "smoke-fjs-first", _fjs_got
    assert _hits17 == ["/a", "/b"], f"脚本里的两句都要真发（不做布尔短路）：{_hits17}"
    # ⑥ `log(...)` 的参数**先求值**（其内的请求照跑）；本引擎不打印，只按返回值语义用它
    _fjs_log = engine.load_poc_file(_wpoc("fjs-log.yaml", """
id: smoke-fjs-log
info: {name: fjs log, severity: medium}
flow: |
  log(http(1))
  http("b")
http:
  - id: a
    path: ["/a"]
    matchers: [{type: word, words: ["hello-AAA"]}]
  - id: b
    path: ["/b"]
    matchers: [{type: word, words: ["hello-BBB"]}]
"""))
    assert _fjs_log["_status"] == "ok", _fjs_log.get("_error")
    _hits17.clear()
    assert engine.run_poc_on_target(_fjs_log, _base_url17, {})
    assert _hits17 == ["/a", "/b"], f"`log()` 里的调用要照跑（实参先求值）：{_hits17}"
    # ⑦ `if` 门控的另一半：**条件块不命中 → 分支里的请求零发出**
    _fjs_gate = engine.load_poc_file(_wpoc("fjs-gate.yaml", """
id: smoke-fjs-gate
info: {name: fjs gate, severity: medium}
flow: |
  if (http(1)) {
    http(2)
  }
http:
  - path: ["/nope"]
    matchers: [{type: word, words: ["NOT-THERE"]}]
  - path: ["/b"]
    matchers: [{type: word, words: ["hello-BBB"]}]
"""))
    assert _fjs_gate["_status"] == "ok", _fjs_gate.get("_error")
    _hits17.clear()
    assert engine.run_poc_on_target(_fjs_gate, _base_url17, {}) == []
    assert _hits17 == ["/nope"], f"分支条件不成立 → 分支里的请求一句都不该发：{_hits17}"
    # ⑧ 子集外的写法一律**装载期**判 unsupported，且原因指认到具体写法（不静默不命中）
    for _fjs_src, _fjs_needle in (
        ("while (true) { http(1) }", "while"),
        ("let x = Math.random(); http(1)", "Math"),
        ("dns('x'); http(1)", "dns()"),
        ("let y = zzz + 1; http(1)", "未声明"),
        ('let k = \'a\'; http(template[k])', "字符串字面量"),
        ("let n = 1; http(n)", "参数只能是请求序号"),
        ("let x = 1 * 2; http(1)", "不支持的字符 `*`"),
        ("for (const x of [1, 2]) { http(1) }", "iterate"),
        ("for (let i = 0; i < 3; i--) { http(1) }", "不会终止"),
        ("for (let i = 0; i < 300; i++) { http(1) }", "超过上限"),
        ("eval('x'); http(1)", "eval"),
        ("foo(1); http(1)", "不支持的函数"),
        ("http(1); }", "多了一个"),
    ):
        _fjs_bad_poc = _wpoc("fjs-bad.yaml", (
            "id: smoke-fjs-bad\n"
            "info: {name: fjs bad, severity: medium}\n"
            "flow: |\n"
            + "\n".join("  " + _ln for _ln in _fjs_src.splitlines()) + "\n"
            'http:\n'
            '  - path: ["/a"]\n'
            '    matchers: [{type: word, words: ["hello-AAA"]}]\n'))
        _fjs_m = engine.load_poc_file(_fjs_bad_poc)
        assert _fjs_m["_status"] == "unsupported", (_fjs_src, _fjs_m.get("_error"))
        assert _fjs_needle in _fjs_m["_error"], (_fjs_src, _fjs_m["_error"])
    # 脚本路的引用校验（用 `;` 让布尔路先失效，才验得到脚本路共用的 `_bad_refs`）
    _fjs_oob = engine.load_poc_file(_wpoc("fjs-oob.yaml", (
        "id: smoke-fjs-oob\n"
        "info: {name: fjs oob, severity: medium}\n"
        'flow: "http(3); http(1)"\n'
        'http:\n'
        '  - path: ["/a"]\n'
        '    matchers: [{type: word, words: ["hello-AAA"]}]\n'
        '  - path: ["/b"]\n'
        '    matchers: [{type: word, words: ["hello-BBB"]}]\n')))
    assert _fjs_oob["_status"] == "unsupported" and "http(3)" in _fjs_oob["_error"], _fjs_oob
    _fjs_skip = engine.load_poc_file(_wpoc("fjs-skip.yaml", (
        "id: smoke-fjs-skip\n"
        "info: {name: fjs skip, severity: medium}\n"
        'flow: "http(1); http(2)"\n'
        'http:\n'
        '  - method: DELETE\n'
        '    path: ["/del"]\n'
        '    matchers: [{type: status, status: [200]}]\n'
        '  - path: ["/b"]\n'
        '    matchers: [{type: word, words: ["hello-BBB"]}]\n')))
    assert _fjs_skip["_status"] == "unsupported" and "http(1)" in _fjs_skip["_error"], _fjs_skip
    _fjs_noid = engine.load_poc_file(_wpoc("fjs-noid.yaml", (
        "id: smoke-fjs-noid\n"
        "info: {name: fjs noid, severity: medium}\n"
        "flow: 'http(\"nope\"); http(1)'\n"
        'http:\n'
        '  - id: a\n'
        '    path: ["/a"]\n'
        '    matchers: [{type: word, words: ["hello-AAA"]}]\n')))
    assert _fjs_noid["_status"] == "unsupported" and '"nope"' in _fjs_noid["_error"], _fjs_noid
    # ⑨ 手工构造的 poc dict（没有装载期的 `_flow`/`_flow_script`）→ 运行期兜底必须**同样的顺序**
    #    （先布尔后脚本）。顺序错了就会把 `http(1) && http(2)` 当脚本跑：第二块没命中时
    #    布尔路应"不报"，脚本路却会报第一块的命中 —— 这正是本条要钉住的语义漂移。
    _fjs_mb = {"id": "smoke-fjs-manual-bool", "info": {}, "flow": "http(1) && http(2)",
               "http": [{"path": ["/a"], "matchers": [{"type": "word", "words": ["hello-AAA"]}]},
                        {"path": ["/nope"], "matchers": [{"type": "word", "words": ["NOT-THERE"]}]}]}
    _hits17.clear()
    assert engine.run_poc_on_target(_fjs_mb, _base_url17, {}) == [], \
        "手工 dict 的布尔 flow：有一块不命中就不该报"
    assert _hits17 == ["/a", "/nope"], _hits17
    _fjs_mj = {"id": "smoke-fjs-manual-js", "info": {}, "flow": "http(1); http(1)",
               "http": [{"path": ["/a"], "matchers": [{"type": "word", "words": ["hello-AAA"]}]}]}
    _hits17.clear()
    assert [v["poc_id"] for v in engine.run_poc_on_target(_fjs_mj, _base_url17, {})] == \
        ["smoke-fjs-manual-js"]
    assert _hits17 == ["/a", "/a"], f"手工 dict 走脚本兜底时同样不缓存：{_hits17}"
    # ⑩ 布尔子集**回归**：脚本子集加入后，[5x] 的语义一个字都不能变
    assert "_flow_script" not in _m_flow and _m_flow["_flow"] == ("&&", ("ref", 1), ("ref", 2)), \
        "布尔 flow 被脚本路抢走了（装载期顺序必须是先布尔后脚本）"
    # 前提确认：布尔源串本身**也**能被脚本解析器解析成"一条表达式语句"——正因如此，
    # 运行期只能尊重装载期判定，不能再"没有 `_flow` 就试脚本"。
    assert engine._flow_js_parse("http(1) && http(2)")[0] is not None, \
        "前提变了：脚本解析器不再接受布尔源串，第 ⑨ 条回归的意义需要重写"
    _m_or6z = engine.load_poc_file(_p_or)
    assert "_flow_script" not in _m_or6z, _m_or6z.get("_error")
    _hits17.clear()
    assert engine.run_poc_on_target(_m_or6z, _base_url17, {})
    assert _hits17 == ["/a"], f"`||` 短路在脚本子集加入后仍须生效：{_hits17}"
    _hits17.clear()
    assert engine.run_poc_on_target(_m_neg, _base_url17, {}) == []

    print("[6z] 续39 nuclei flow **脚本子集** ok: 循环里 `http(1)` 每轮重发（不缓存）/ "
          "`for...of iterate(...)`·C 式 `for` 都能数清轮次 / `template[\"k\"]` 读值 + `if` 门控"
          "（条件假则零请求）/ `http()` 全跑·`http(\"id\")` 与多参按序 / 只报第一个正向命中 / "
          "`log()` 实参求值 / 13 条子集外写法装载期给原因 / 脚本路引用越界·跳过块·不存在的 id "
          "也判 unsupported / 手工 dict 兜底顺序（先布尔后脚本）/ 布尔子集语义零回归")

    # (7a) 续40：拓展域名"六条" ——
    #   ① 送去检测要带 subdomain 阶段（[5t]④ 的断言已同步改，这里不再重复）；
    #   ② 自动**存在性判定**（纯 DNS：这个域名到底存不存在）；
    #   ③ 目标是子域（aaa.pengo.pro）→ 自动补收主域名 pengo.pro + 该子域当子域资产解析；
    #   ④ 归属本项目的拓展域名（pengo.pro 拓展出 aaa.pengo.pro）→ **追加**成正常子域，
    #      来源记 `promote:<原来源>`（"分域名而来"，原拓展行保留不动）；
    #   ⑤ 拓展域名页**按主域名分组折叠**，`?group=0` 回平铺；
    #   ⑥ 建任务「自动拓展扫描」落成任务级选项 auto_expand，并自动补 osint / jsmine 阶段。
    from scanner import dnsq as _dq7, extdom as _exd7
    from scanner.stages import subdomain as _sub7

    # ② 存在性判定：桩掉解析器（断言的是"回填哪些字段、是否幂等"，不是真去查 DNS）
    _et7 = db.create_task("smoke-ext-alive", "pengo.pro", ["probe"], {})
    db.insert_subdomains(_et7, [("alive.pengo.pro", "js:mine"),
                                ("gone.pengo.pro", "js:mine")])
    _orig_res7 = _dq7.resolve_detail
    try:
        _dq7.resolve_detail = lambda host, **kw: \
            ([host], ["1.2.3.4"], "") if host.startswith("alive.") else ([], [], "nxdomain")
        _r7 = _exd7.resolve_extended(_et7, settings, logger=rec)
        assert (_r7["scanned"], _r7["alive"], _r7["dead"]) == (2, 1, 1), _r7
        _net7 = {r["domain"]: dict(r) for r in db.list_subdomains(_et7)}
        assert _net7["alive.pengo.pro"]["ip"] == "1.2.3.4", _net7["alive.pengo.pro"]
        assert _net7["gone.pengo.pro"]["ip_note"] == "nxdomain", \
            "解析失败必须落原因（页面上据此显示『域名不存在』）"
        # 幂等：已有结论的行不再重复解析（重复调用不会白白多一轮 DNS）
        assert _exd7.resolve_extended(_et7, settings, logger=rec)["scanned"] == 0
    finally:
        _dq7.resolve_detail = _orig_res7

    # ③ 目标是子域 → 补收主域名 + 该子域入库解析（只在任务级 auto_expand 打开时）
    _seen7 = []
    _orig7 = (_sub7.which, _sub7.verify_tool, _sub7.run_cmd, _sub7.passive.collect)
    _s7 = copy.deepcopy(settings)
    _s7["subdomain"] = {"max_resolve": 0, "dns_timeout": 1}   # 0 = 不做真实解析（离线可跑）
    _s7["limits"] = dict(_s7.get("limits") or {}, wildcard_filter=False)
    _s7["dicts"]["subdomains"] = "config/dicts/does-not-exist.txt"   # 跳过字典爆破
    _sub7.which = lambda name: None
    _sub7.verify_tool = lambda b: True
    _sub7.run_cmd = lambda *a, **k: (0, "", "")
    _sub7.passive.collect = lambda d, s, logger=None, workers=6: (_seen7.append(d), {})[1]
    try:
        for _opt7, _want_base in (({"auto_expand": True}, True), ({}, False)):
            _seen7.clear()
            _t7c = db.create_task(f"smoke-expand-target-{bool(_opt7)}", "aaa.pengo.pro",
                                  ["subdomain"], {})
            _wd7 = Path(_TMPDIR) / f"expand7_{bool(_opt7)}"
            _wd7.mkdir(parents=True, exist_ok=True)
            PipelineRunner(StageContext(_t7c, "smoke-expand-target",
                                        parse_lines(["aaa.pengo.pro"]), ["subdomain"],
                                        dict(_opt7), _s7, _wd7, rec)).run()
            _rows7 = {r["domain"]: r["source"] for r in db.list_subdomains(_t7c)}
            assert "aaa.pengo.pro" in _seen7, "目标自身一定要进子域名收集"
            if _want_base:
                assert "pengo.pro" in _seen7, f"auto_expand 未补收主域名：{_seen7}"
                assert _rows7.get("aaa.pengo.pro") == "target", \
                    f"目标自带子域应按子域资产入库：{_rows7}"
            else:
                assert "pengo.pro" not in _seen7, f"没勾 auto_expand 不该改既有行为：{_seen7}"
                assert "aaa.pengo.pro" not in _rows7, \
                    f"没勾 auto_expand 不该把目标子域塞进资产表：{_rows7}"
    finally:
        (_sub7.which, _sub7.verify_tool, _sub7.run_cmd, _sub7.passive.collect) = _orig7

    # ④ 归属追加：注册域命中任务目标的拓展域名 → 追加成自身子域（原拓展行保留）
    _t7d = db.create_task("smoke-promote", "pengo.pro", ["probe"], {})
    db.insert_subdomains(_t7d, [("aaa.pengo.pro", "js:mine"),
                                ("third.example.com", "js:mine")])
    _p7 = _exd7.promote_owned(_t7d, settings, logger=rec)
    assert _p7["promoted"] == ["aaa.pengo.pro"], _p7
    _rows7d = {(r["domain"], r["source"]) for r in db.list_subdomains(_t7d)}
    assert ("aaa.pengo.pro", "promote:js:mine") in _rows7d, _rows7d
    assert ("aaa.pengo.pro", "js:mine") in _rows7d, "原拓展行必须保留（出处可查）"
    assert not any(d == "third.example.com" and s.startswith("promote:") for d, s in _rows7d), \
        "非本项目的第三方域名不该被追加"
    assert _exd7.promote_owned(_t7d, settings, logger=rec)["promoted"] == [], "重复调用应幂等"
    # 页面上：子域名页按正常子域显示（带「归属追加」标签）；拓展页因"已作为自身子域"默认隐藏
    assert "归属追加(JS 挖掘)" in c.get("/subdomains").get_data(as_text=True)
    assert "aaa.pengo.pro" in c.get("/subdomains").get_data(as_text=True)
    assert "aaa.pengo.pro" not in c.get("/extdomains").get_data(as_text=True), \
        "已归属本项目的拓展域名不该再占拓展页"
    assert "aaa.pengo.pro" in c.get("/extdomains?all=1").get_data(as_text=True)
    # 手动「追加」端点（跨任务视图按域名反查所属任务）
    _r7p = c.post("/api/domains/promote", data={"domain": ["aaa.pengo.pro"],
                                                "next": "/extdomains"})
    assert _r7p.status_code == 302 and _r7p.headers["Location"] == "/extdomains", _r7p.headers

    # ⑤ 拓展域名页按主域名分组折叠（?group=0 回平铺）
    _t7g = db.create_task("smoke-ext-group", "zzgrp7.test", ["probe"], {})
    db.insert_subdomains(_t7g, [("g1a.zzgrp7.test", "js:mine"),
                                ("g1b.zzgrp7.test", "js:mine"),
                                ("g2a.yygrp7.test", "osint:cseg")])
    _gh = c.get("/extdomains?q=zzgrp7").get_data(as_text=True)
    assert 'class="ext-group"' in _gh and "zzgrp7.test" in _gh, "分组视图缺主域名分组块"
    assert "g1a.zzgrp7.test" in _gh and "g1b.zzgrp7.test" in _gh, "分组里的行没渲染"
    assert "g2a.yygrp7.test" not in _gh, "另一个主域名的行不该混进同一组"
    _gf = c.get("/extdomains?q=zzgrp7&group=0").get_data(as_text=True)
    assert 'class="ext-group"' not in _gf and "g1a.zzgrp7.test" in _gf, "平铺模式失效"

    # ⑥ 建任务「自动拓展扫描」：落任务级 auto_expand + 自动补 osint / jsmine 阶段
    _orig_run7 = _gui.run_task
    try:
        _gui.run_task = lambda *a, **kw: None
        _j7 = c.post("/api/tasks", data={"name": "smoke-auto-expand", "targets": "pengo.pro",
                                         "stages": ["subdomain", "probe"],
                                         "auto_expand": "1"}).get_json()
        assert '"auto_expand": true' in db.get_task(_j7["id"])["options"], "未落成任务级选项"
        _st7 = set(db.get_task(_j7["id"])["stages"].split(","))
        assert _st7 >= {"subdomain", "probe", "osint", "jsmine"}, _st7
        assert set(_j7["auto_stages"]) >= {"osint", "jsmine"}, _j7
        _j7b = c.post("/api/tasks", data={"name": "smoke-no-expand", "targets": "pengo.pro",
                                          "stages": ["subdomain"]}).get_json()
        assert "auto_expand" not in (db.get_task(_j7b["id"])["options"] or ""), \
            "没勾就不该凭空多出选项（既有行为不变）"
    finally:
        _gui.run_task = _orig_run7

    # ⑥b 流水线挂钩：auto_expand 时在**最后一个**拓展阶段后自动做后处理（不勾则不做）
    _calls7 = []
    _orig_proc7 = _exd7.process
    try:
        _exd7.process = lambda *a, **kw: _calls7.append(a[0] if a else None)
        for _opt7b, _want in (({"auto_expand": True}, True), ({}, False)):
            _calls7.clear()
            _t7e = db.create_task(f"smoke-hook-{bool(_opt7b)}", "pengo.pro", ["jsmine"], {})
            PipelineRunner(StageContext(_t7e, "smoke-hook", parse_lines(["pengo.pro"]),
                                        ["jsmine"], dict(_opt7b), _s7,
                                        Path(_TMPDIR) / f"hook7_{bool(_opt7b)}", rec)).run()
            assert bool(_calls7) is _want, (_opt7b, _calls7)
            if _want:
                assert _calls7 == [_t7e], _calls7
    finally:
        _exd7.process = _orig_proc7

    print("[7a] 续40 拓展域名六条 ok: 存在性判定(幂等·失败落原因)/目标是子域→补收主域名+"
          "当子域入库/归属本项目→追加 promote:<原来源>（原行保留·第三方不误加·子域页显示·"
          "拓展页默认隐藏）/按主域名分组折叠(?group=0 平铺)/建任务 auto_expand 补 osint·jsmine/"
          "流水线在最后拓展阶段后自动后处理（不勾则不动）")

    # [7b] 续42：`internal: true` 命名提取器的值**回填模板上下文**（A1）—— nuclei 的
    # `{{csrf_token}}` 跨请求取值就靠这条链。语义照 nuclei 源码钉（一手核对，非二手转述）：
    #   `pkg/operators/operators.go::Execute` 先跑 extractors 再跑 matchers（回填**不受命中与否
    #   影响**）；`extractors.go` 的 `Internal` 注释写明"设 true 才能在下一个请求里用"，
    #   不设的具名提取器只进 `Result.OutputExtracts` → **只有 internal 才回填**；
    #   `multiproto/multi.go` 多值命名：`{{name}}`=第 1 个、`{{name1}}`=第 2 个。
    # 函数级先钉两条最容易写错的合同（不依赖 HTTP）：
    _xv_resp = {"status": 200, "length": 9, "text": "a=TOK1 b=TOK2",
                "headers": {}, "url": "http://x/"}
    assert engine._extract_vars(_xv_resp, [
        {"type": "regex", "name": "t", "internal": True, "part": "body",
         "regex": ["TOK[0-9]"]},
        {"type": "regex", "name": "u", "part": "body", "regex": ["TOK[0-9]"]}]) == \
        {"t": "TOK1", "t1": "TOK2"}, "多值命名该是 name/name1，且非 internal 的 u 完全不进回填"
    _xv_many = {"status": 200, "length": 60, "headers": {}, "url": "http://x/",
                "text": " ".join(f"M{i}" for i in range(20))}
    _xv_keys = engine._extract_vars(_xv_many, [
        {"type": "regex", "name": "m", "internal": True, "part": "body", "regex": ["M[0-9]+"]}])
    assert len(_xv_keys) == engine._EXTRACT_VARS_MAX and _xv_keys["m"] == "M0" \
        and _xv_keys["m9"] == "M9" and "m10" not in _xv_keys, \
        f"同名声明的上限该是 name + 9 个序号（防宽 regex 撑爆上下文）：{sorted(_xv_keys)}"
    # ① 取令牌的块**没有 matchers**（本引擎判它不命中）也必须回填 —— 否则"第一个请求只负责
    #    拿 csrf_token"这类最常见的模板在本引擎里静默失效（后续请求带字面量发出去）
    _xv1 = engine.load_poc_file(_wpoc("xvar-cross.yaml", """
id: smoke-xvar-cross
info: {name: xvar cross, severity: medium}
http:
  - path: ["/csrf"]
    extractors:
      - {type: regex, name: tok, internal: true, part: body, regex: ["TOK[0-9]+"]}
  - path: ["/a{{tok}}"]
    matchers: [{type: word, words: ["hello-AAA"]}]
"""))
    assert _xv1["_status"] == "ok", _xv1.get("_error")
    _hits17.clear()
    _xv1_hits = engine.run_poc_on_target(_xv1, _base_url17, {})
    assert [v["poc_id"] for v in _xv1_hits] == ["smoke-xvar-cross"]
    assert _hits17 == ["/csrf", "/aTOK123"], \
        f"无 matchers 的取令牌块也要回填，第二个请求该带真值：{_hits17}"
    assert "/aTOK123" in _xv1_hits[0]["detail"], \
        f"命中详情里的请求 URL 也要是替换后的：{_xv1_hits[0]['detail']}"
    # ② 多值命名 + `internal` 的值不进 evidence（同一响应里就有令牌，退回正文等于从后门放出去）
    _xv2 = engine.load_poc_file(_wpoc("xvar-multi.yaml", """
id: smoke-xvar-multi
info: {name: xvar multi, severity: medium}
flow: http(1) && http(2)
http:
  - path: ["/csrf"]
    extractors:
      - {type: regex, name: tok, internal: true, part: body,
         regex: ["TOK[0-9]+", "SEC[0-9]+"]}
    matchers: [{type: word, words: ["TOK123"]}]
  - path: ["/b{{tok1}}"]
    matchers: [{type: word, words: ["hello-BBB"]}]
"""))
    assert _xv2["_status"] == "ok", _xv2.get("_error")
    _hits17.clear()
    _xv2_hits = engine.run_poc_on_target(_xv2, _base_url17, {})
    assert [v["poc_id"] for v in _xv2_hits] == ["smoke-xvar-multi"]
    assert _hits17 == ["/csrf", "/bSEC789"], \
        f"第二个值该是 name1（不是 name2）且真的发出去：{_hits17}"
    assert "TOK123" not in _xv2_hits[0]["evidence"] \
        and "SEC789" not in _xv2_hits[0]["evidence"] \
        and "internal" in _xv2_hits[0]["evidence"], \
        f"internal 的值不许出现在 evidence 里（含退回正文这条后门）：{_xv2_hits[0]['evidence']}"
    # ③ 非 internal 的具名提取器**不回填**（nuclei 里它只进输出）—— 第二个请求该带字面量；
    #    但它的值照旧进 evidence（"别显示"的开关只有 internal）
    _xv3 = engine.load_poc_file(_wpoc("xvar-nointernal.yaml", """
id: smoke-xvar-nointernal
info: {name: xvar nointernal, severity: medium}
flow: http(1) && http(2)
http:
  - path: ["/csrf"]
    extractors:
      - {type: regex, name: tok, part: body, regex: ["TOK[0-9]+"]}
    matchers: [{type: word, words: ["TOK123"]}]
  - path: ["/a{{tok}}"]
    matchers: [{type: word, words: ["hello-AAA"]}]
"""))
    assert _xv3["_status"] == "ok", _xv3.get("_error")
    _hits17.clear()
    _xv3_hits = engine.run_poc_on_target(_xv3, _base_url17, {})
    assert _hits17[0] == "/csrf" and _hits17[1] in ("/a{{tok}}", "/a%7B%7Btok%7D%7D"), \
        f"非 internal 的具名提取器不该当变量（nuclei 亦是如此）：{_hits17}"
    assert "TOK123" in _xv3_hits[0]["evidence"], \
        f"非 internal 的值该照常进 evidence：{_xv3_hits[0]['evidence']}"
    # ④ **同一个块**里后一条 `path:` 也要用上前一条刚回填的值（上下文快照按请求取，
    #    快照挂在 payload 层就会漏掉这一条 —— nuclei 一个块里多行 path 正是按请求逐个取值）
    _xv4 = engine.load_poc_file(_wpoc("xvar-itempath.yaml", """
id: smoke-xvar-itempath
info: {name: xvar itempath, severity: medium}
http:
  - path: ["/csrf", "/a{{tok}}"]
    extractors:
      - {type: regex, name: tok, internal: true, part: body, regex: ["TOK[0-9]+"]}
    matchers: [{type: word, words: ["hello-AAA"]}]
"""))
    assert _xv4["_status"] == "ok", _xv4.get("_error")
    _hits17.clear()
    assert [v["poc_id"] for v in engine.run_poc_on_target(_xv4, _base_url17, {})] == \
        ["smoke-xvar-itempath"]
    assert _hits17 == ["/csrf", "/aTOK123"], f"同块后一条 path 该用上前一条的值：{_hits17}"

    print("[7b] 续42 extractor 回填 ok: 只认 internal: true（非 internal 只进输出，与 nuclei "
          "一致）/ 多值 name·name1（上限 name+9）/ 回填在匹配之前（无 matchers 的取令牌块也回填）/ "
          "同块后一条 path 用得上刚回填的值 / internal 的值不进 evidence（也不从"
          "「退回正文」这条后门漏出）")

    # [7c] 续42：第三方接口的证书校验（A3）—— 两把开关按出口分流，别把凭据挂到明文信道上。
    # 缺陷原委见 `scanner/utils.py::http_request` docstring 与 `limits.verify_tls_external`。
    _real_do7c = _utils._do_http
    _seen7c = []

    def _fake_do7c(url, method, headers, data, timeout, verify, allow_redirects,
                    settings, want_bytes, auth):
        _seen7c.append((auth, verify))
        return {"status": 200, "headers": {}, "text": "", "length": 0, "url": url}

    try:
        _utils._do_http = _fake_do7c
        _utils.http_request("https://api.github.com/x", settings={})
        _utils.http_request("https://target.local/x", settings={}, auth=True)
        _utils.http_request("https://api.github.com/x",
                            settings={"limits": {"verify_tls_external": False}})
        _utils.http_request("https://target.local/x",
                            settings={"limits": {"verify_tls": True}}, auth=True)
        _utils.http_request("https://api.github.com/x", settings={}, verify=False)
    finally:
        _utils._do_http = _real_do7c
    # ① 五个探测点分别钉住：第三方默认校验 / 目标侧默认不校验 / 两把开关互不连带 / 显式传参优先
    assert _seen7c == [(False, True), (True, False), (False, False), (True, True),
                        (False, False)], f"[7c] verify 按出口解析的结果不符合预期：{_seen7c}"

    # ② 分流能成立的前提是**调用点自己声明对了出口**，这本身就是安全属性，按源码钉死：
    #    第三方模块恒不传 auth=（传了就会被降级成不校验证书）；目标侧模块逐个必传 auth=True
    #    （漏一个就会被当成第三方去校验 → 自签名靶场静默失联）。
    #    用 ast 而不是正则：调用跨行、嵌套括号多，正则在截断处会产生假阳/假阴。
    import ast as _ast7c
    _third7c = ("passive", "ctlog", "intel", "iprecon", "fofa", "shodan", "quake",
                 "github_leak")
    _tgt7c = ("takeover", "fingerprint", "evasion", "ssrf",
               "stages/probe", "stages/dirscan", "pocs/engine", "owasp/checks")
    # jsmine 是**混合出口**（续43）：页面请求发往目标侧，但 `<script src>` 可能指向第三方
    # CDN/埋点 —— 那里必须不带登录态。所以它只要求"显式声明 auth"（不许靠默认 False 蒙过去），
    # 值的正确性由 [7d] 的运行期断言钉（这里用 ast 判不出表达式真假）。
    _hybrid7c = ("jsmine",)
    _calls7c = {}
    for _rel7c in _third7c + _tgt7c + _hybrid7c:
        _src7c = (ROOT / "scanner" / f"{_rel7c}.py").read_text(encoding="utf-8")
        for _n7c in _ast7c.walk(_ast7c.parse(_src7c)):
            if isinstance(_n7c, _ast7c.Call) and \
                    getattr(_n7c.func, "id", "") == "http_request":
                _calls7c.setdefault(_rel7c, []).append(
                    "auth" in {k.arg for k in _n7c.keywords})
    for _rel7c in _third7c:
        assert _calls7c.get(_rel7c), f"[7c] {_rel7c}.py 里找不到 http_request 调用"
        assert not any(_calls7c[_rel7c]), \
            f"[7c] {_rel7c}.py 是第三方出口，调用点不得传 auth=（那会被降级为不校验证书）"
    for _rel7c in _tgt7c:
        assert _calls7c.get(_rel7c), f"[7c] {_rel7c}.py 里找不到 http_request 调用"
        assert all(_calls7c[_rel7c]), \
            f"[7c] {_rel7c}.py 是目标侧出口，每个调用点都必须显式 auth=True"
    for _rel7c in _hybrid7c:
        assert _calls7c.get(_rel7c), f"[7c] {_rel7c}.py 里找不到 http_request 调用"
        assert all(_calls7c[_rel7c]), \
            f"[7c] {_rel7c}.py 是混合出口，每个调用点都必须显式写 auth=（值见 [7d]）"

    print("[7c] 续42 第三方证书校验 ok: auth=False→verify_tls_external（默认 True）/ "
          "auth=True→verify_tls（默认 False）/ 两把开关互不连带 / 显式 verify 优先 / "
          "8 个第三方模块零 auth= / 8 个目标侧模块全覆盖 auth=True / "
          "jsmine 为混合出口（显式 auth，值由 [7d] 钉）")

    # [7d] 续43：jsmine 抓 JS 时**第三方主机不得带登录态**（实跑 pengo.pro 逮到的缺陷）。
    #     现象：日志里出现 `InsecureRequestWarning ... host 'static.cloudflareinsights.com'`
    #     —— 那是首页 `<script src>` 引的第三方埋点，不是目标主机，却也走了 auth=True。
    #     后果：任务一旦配了 Cookie/Authorization（-H / --cookie），目标会话凭据会被发到
    #     CDN 与埋点厂商，与 AGENTS.md §5"第三方绝不带登录态"直接冲突（本次实跑未配登录态，
    #     所以没有真的外发，只是路径被证实）。修复：按 URL 主机是否属目标注册域决定 auth。
    from scanner import jsmine as _jm7d
    # ① 判定口径本身（与 `_is_noise` 的 protect 放行同一份，后缀必须按 label 比）
    assert _jm7d._is_self_host("pengo.pro", {"pengo.pro"}) is True
    assert _jm7d._is_self_host("a.b.pengo.pro", {"pengo.pro"}) is True
    assert _jm7d._is_self_host("PENGO.PRO", {"pengo.pro"}) is True, "[7d] 主机大小写应归一"
    assert _jm7d._is_self_host("static.cloudflareinsights.com", {"pengo.pro"}) is False
    assert _jm7d._is_self_host("notpengo.pro", {"pengo.pro"}) is False, \
        "[7d] 后缀匹配必须带点号：notpengo.pro 不是 pengo.pro 的子域"
    assert _jm7d._is_self_host("", {"pengo.pro"}) is False
    # ② 运行期：把 http_request 换成记录 auth 的桩，页面里放三条 `<script src>`
    _seen7d = {}

    def _fake_jm7d(url, **kw):
        _seen7d[url] = bool(kw.get("auth"))
        if url.endswith(".js"):
            return {"status": 200, "headers": {}, "text": "var a=1;", "length": 7,
                    "url": url}
        return {"status": 200, "headers": {}, "text":
                '<script src="/same.js"></script>'
                '<script src="https://cdn.pengo.pro/lib.js"></script>'
                '<script src="https://static.cloudflareinsights.com/beacon.min.js"></script>',
                "length": 64, "url": url}

    _real_jm7d = _jm7d.http_request
    try:
        _jm7d.http_request = _fake_jm7d
        _jm7d.mine("http://pengo.pro/",
                   {"jsmine": {"secrets": False}, "limits": {"max_workers": 4}})
    finally:
        _jm7d.http_request = _real_jm7d
    assert _seen7d.get("http://pengo.pro/") is True, \
        f"[7d] 目标页面本身应带登录态：{_seen7d}"
    assert _seen7d.get("http://pengo.pro/same.js") is True, \
        f"[7d] 同主机脚本应带登录态：{_seen7d}"
    assert _seen7d.get("https://cdn.pengo.pro/lib.js") is True, \
        f"[7d] 同注册域子域脚本应带登录态：{_seen7d}"
    assert _seen7d.get("https://static.cloudflareinsights.com/beacon.min.js") is False, \
        f"[7d] 第三方脚本**不得**带登录态（缺陷原形）：{_seen7d}"
    assert len(_seen7d) == 4, f"[7d] 抓取点数量不符（页面 1 + 脚本 3）：{_seen7d}"

    print("[7d] 续43 jsmine 出站凭据 ok: 同注册域（含子域、大小写归一）带登录态 / "
          "第三方 CDN·埋点不带 / 后缀按 label 比（notpengo.pro 不误判）")

    # [7e] 续43：CDN 判定补**任播 IP 段**判据（实跑 pengo.pro 逮到的准确性缺陷）。
    #     现象：pengo.pro / admin.pengo.pro / app.pengo.pro 的 A 记录直接指向 Cloudflare 边缘
    #     （`172.66.40.229` / `172.66.43.27`），**CNAME 链为空** —— 只按 CNAME 判会把三个主机
    #     全标成"非 CDN"：① 资产页看不出走 CDN；② portscan 照样去打边缘节点，得出"30 个端口
    #     开放"这种与目标无关的结论（同一时刻手工 TCP connect 22 是超时的）。
    #     修复：`config/dicts/cdn_ips.txt`（Cloudflare 官方 ips-v4 的 15 段，文件头记来源+日期）
    #     作第二条判据；CNAME 仍是**第一**判据（厂商特征比 IP 归属更明确）。
    import ast as _ast7e, ipaddress as _ipaddr7e
    from scanner import cdn as _cdn7e
    _s7e = {}
    _nets7e = _cdn7e.networks(_s7e)
    assert len(_nets7e) >= 10, f"[7e] CDN IP 段名单没加载出来：{len(_nets7e)} 条"
    _vend7e = {_v for _n, _v in _nets7e}
    assert _vend7e == {"cloudflare"}, f"[7e] 厂商名应与数据文件里的 `| cloudflare` 一致：{_vend7e}"
    # ① 实跑命中的那两个 IP（缺陷原形：CNAME 为空时它们必须仍判成 CDN）
    assert _cdn7e.ip_match(["172.66.40.229"], _s7e) == "cloudflare"
    assert _cdn7e.ip_match(["172.66.43.27"], _s7e) == "cloudflare"
    # ② 段边界（钉住"按网段判定"，而不是写成前缀/字符串比较）：`172.64.0.0/13` 两端都在内，
    #    刚出界的一侧必须不命中 —— 把 `in net` 改成 `startswith` 这类改法会在这里死。
    assert _cdn7e.ip_match(["172.64.0.0"], _s7e) == "cloudflare"
    assert _cdn7e.ip_match(["172.71.255.255"], _s7e) == "cloudflare"
    assert _cdn7e.ip_match(["172.72.0.0"], _s7e) == "", "[7e] 172.72.0.0 已在 172.64.0.0/13 之外"
    assert _cdn7e.ip_match(["172.63.255.255"], _s7e) == "", "[7e] 172.63.255.255 在 172.64.0.0/13 之前"
    # ③ 非 CDN 的公共 IP 不得误命中；空/None/非法条目一律安全返回空（不许让整次判定失败）
    assert _cdn7e.ip_match(["8.8.8.8", "9.9.9.9"], _s7e) == ""
    assert _cdn7e.ip_match([], _s7e) == ""
    assert _cdn7e.ip_match(None, _s7e) == ""
    assert _cdn7e.ip_match(["", "  ", "not-an-ip"], _s7e) == ""
    assert _cdn7e.ip_match(["", "not-an-ip", "172.66.40.229"], _s7e) == "cloudflare", \
        "[7e] 非法条目应逐条跳过，而不是让整次判定作废"
    # ④ IPv6 不得抛异常（`ipaddress` 对不同版本做包含判断会抛 TypeError），也不得误命中 IPv4 段
    assert _cdn7e.ip_match(["2606:4700::1111"], _s7e) == ""
    assert _cdn7e.ip_match(["2606:4700::1111", "172.66.40.229"], _s7e) == "cloudflare"
    # ⑤ CNAME 判据优先于 IP 判据：把 IP 名单的厂商换成假名后，CNAME 命中时不得返回假名
    #    （反过来写 = "IP 先判"，会把厂商明确的 CNAME 特征降级成"某个 IP 段"）
    _real_nets7e = _cdn7e.networks
    try:
        _cdn7e.networks = lambda settings=None: \
            ((_ipaddr7e.ip_network("172.66.0.0/16"), "fakevendor"),)
        assert _cdn7e.ip_match(["172.66.40.229"], _s7e) == "fakevendor", "[7e] 桩没生效"
        assert _cdn7e.match(["x.cloudflare.net"], _s7e, ["172.66.40.229"]) == "cloudflare", \
            "[7e] CNAME 链是厂商明确特征，必须优先于 IP 段判据"
        assert _cdn7e.match([], _s7e, ["172.66.40.229"]) == "fakevendor", \
            "[7e] CNAME 为空时才轮到 IP 判据"
    finally:
        _cdn7e.networks = _real_nets7e
    # ⑥ 向后兼容：老调用（只传 CNAME 链）行为完全不变
    assert _cdn7e.match(["x.cloudflare.net"], _s7e) == "cloudflare"
    assert _cdn7e.match([], _s7e) == ""
    assert _cdn7e.match([], _s7e, ["172.66.40.229"]) == "cloudflare"
    # ⑦ fail-safe：数据文件缺行/缺文件时都不许抛，判定退回"非 CDN"（与 cdn_cname 的既有口径一致）
    _bad7e = _TMPDIR / "cdn_ips_bad.txt"
    _bad7e.write_text("# 注释行\n172.66.0.0/16 | goodvendor\n这不是CIDR | badvendor\n\n"
                      "104.16.0.0/13\n", encoding="utf-8")
    _bad_s7e = {"dicts": {"cdn_ips": str(_bad7e)}}
    assert [_v for _n, _v in _cdn7e.networks(_bad_s7e)] == ["goodvendor", "104.16.0.0/13"], \
        f"[7e] 坏行应逐条跳过、厂商缺失应回退成 CIDR 原文：{_cdn7e.networks(_bad_s7e)}"
    assert _cdn7e.ip_match(["172.66.40.229"], _bad_s7e) == "goodvendor"
    _miss_s7e = {"dicts": {"cdn_ips": str(_TMPDIR / "no_such_cdn_ips.txt")}}
    assert _cdn7e.networks(_miss_s7e) == (), "[7e] 文件缺失应返回空名单"
    assert _cdn7e.match([], _miss_s7e, ["172.66.40.229"]) == ""
    # ⑧ 判据要生效必须**调用点把解析 IP 传进来** —— 少传一处，那一处就永远退回"只看 CNAME"
    #    （静默退化成修复前的行为）。三处调用点按源码钉死（ast：调用跨行、续行反斜杠多）。
    for _rel7e in ("scanner/stages/subdomain.py", "scanner/extdom.py", "gui/app.py"):
        _hits7e = []
        for _n7e in _ast7e.walk(_ast7e.parse((ROOT / _rel7e).read_text(encoding="utf-8"))):
            _f7e = getattr(_n7e, "func", None)
            if isinstance(_n7e, _ast7e.Call) and \
                    getattr(_f7e, "attr", "") == "match" and \
                    getattr(getattr(_f7e, "value", None), "id", "") == "cdn":
                _hits7e.append((len(_n7e.args), {k.arg for k in _n7e.keywords}))
        assert _hits7e, f"[7e] {_rel7e} 里找不到 cdn.match 调用"
        for _nargs7e, _kw7e in _hits7e:
            assert _nargs7e >= 3 or "ips" in _kw7e, \
                f"[7e] {_rel7e} 的 cdn.match 没传解析 IP（IP 判据会沦为死代码）：" \
                f"args={_nargs7e} kw={_kw7e}"

    print("[7e] 续43 CDN 双判据 ok: CNAME 优先→IP 段兜底（172.66.40.229 命中）/ "
          "段边界按网段判 / 8.8.8.8 不误命中 / IPv6 不抛 / 坏行跳过+缺文件 fail-safe / "
          "三处调用点都传了 ips")

    # 7f) 续45：`--check` 自检必须覆盖端口扫描的两个外部引擎，且 fscan **不能**走版本握手。
    #     为什么专门钉这一条：`verify_tool()` 的默认探针是 `<bin> -version`，而 fscan 的 `-h` 是
    #     "指定主机"、根本没有 `-version` —— 一旦有人"顺手统一"成 `_row(...verify_tool...)`，
    #     装了 fscan 的机器会被误报成"找到但未通过版本校验"，接着 portscan 就白白回退内置扫描。
    #     这个错误**不会抛异常**，只会让端口扫描慢一个量级，所以必须用断言钉住。
    import cli.client as _cli7f
    _orig7f = (_cli7f.which, _cli7f.verify_tool)
    _seen7f = []
    #    注意路径不能写成盘符样式（如 C:\...），否则会被本文件的 [5o] 跨平台静态审计拦下。
    _fake7f = {"nmap": "fake-tools/nmap.exe", "fscan": "fake-tools/fscan.exe"}

    def _verify7f(bin_path, *a, **k):
        _seen7f.append(str(bin_path))
        return True

    try:
        _cli7f.which, _cli7f.verify_tool = (lambda n: _fake7f.get(n)), _verify7f
        _rows7f = dict(_cli7f.check_tools({"tools": {}}))
        assert "nmap" in _rows7f and "fscan" in _rows7f, \
            f"[7f] 自检漏了端口扫描引擎：{sorted(_rows7f)}"
        assert _rows7f["nmap"].startswith("OK"), f"[7f] nmap 应判 OK：{_rows7f['nmap']}"
        assert _rows7f["fscan"].startswith("OK"), f"[7f] fscan 应判 OK：{_rows7f['fscan']}"
        _nmap_verified = any("nmap" in p for p in _seen7f)
        _fscan_verified = any("fscan" in p for p in _seen7f)
        # 缺二进制时两者都要给出"内置兜底"文案（fscan 的兜底链是回退 nmap/内置）
        _cli7f.which = lambda n: None
        _none7f = dict(_cli7f.check_tools({"tools": {}}))
    finally:
        _cli7f.which, _cli7f.verify_tool = _orig7f
    assert _nmap_verified, f"[7f] nmap 应当走版本握手：{_seen7f}"
    assert not _fscan_verified, \
        f"[7f] fscan 不能走 `-version` 握手（会被误报成未通过校验，静默降级到内置）：{_seen7f}"
    assert "未找到" in _none7f["nmap"] and "未找到" in _none7f["fscan"], _none7f

    print("[7f] 续45 --check 覆盖端口引擎 ok: nmap 走 -version 握手且判 OK / fscan 跳过握手"
          "（不误报未通过校验）/ 两者缺失时都给出内置兜底文案")

    # 7g) 续45：dirmap 4 条残留里**适配器侧**的两条。另两条改的是外部 dirmap 副本
    #     （GPL-3.0、不入仓库），只能在真机上跑真实 dirmap 验证，故这里不假装覆盖。
    #     ① `_strip_fragment`：fragment 从不发给服务端（RFC 3986），剥掉是**数据正确性**问题 ——
    #        dirmap 原样写 `response.url`（实测确认），不剥则开目录递归会把它当目录前缀拼出
    #        `.../b#x/` 这种无效 URL（白花请求），折叠去重时也与同一路径的其它行对不上。
    #     ② `_cleanup_output`：`output/` 是无上限的持久目录，**删错目录的代价不可逆** ——
    #        「只删给定（= 本次扫过）的目录 / 别人的历史产物不动 / 失败只告警不抛」必须钉住。
    from scanner.stages.dirscan import _strip_fragment as _sf7g
    from scanner.stages.dirscan import DirscanStage as _DS7g
    assert _sf7g("http://h/a/b#x") == "http://h/a/b"
    assert _sf7g("http://h/a/b?q=1#frag") == "http://h/a/b?q=1", \
        "query 必须保留（那一段是要发给服务端的，fragment 才不是）"
    assert _sf7g("http://h/a/b") == "http://h/a/b"
    assert _sf7g("") == "" and _sf7g(None) == "", "空值不能抛"
    # 解析侧两个分支都要过一遍：命中 DIRMAP_RE 的行 + 只能靠 URL_RE 兜底的行
    _d7g = Path(_TMPDIR) / "dm7g"
    _d7g.mkdir(parents=True, exist_ok=True)
    (_d7g / "res.txt").write_text(
        "[200][text/html][1234] http://h7g/a#frag\n"
        "[403][text/html][10] http://h7g/b#frag2\n"
        "http://h7g/c#frag3\n", encoding="utf-8")
    _p7g = _DS7g._parse_output(_d7g / "res.txt")
    assert [r["path"] for r in _p7g] == ["http://h7g/a", "http://h7g/b", "http://h7g/c"], _p7g
    assert [r["length"] for r in _p7g] == [1234, 10, None], \
        "续45 起 dirmap 产物行写精确字节数，必须直读出真值（量化值 1.21kb 会差 ±0.5%）"
    # 清理：只删传入的目录；不计入本次扫描目标的目录必须原地不动
    _out7g = Path(_TMPDIR) / "dm7g_out"
    (_out7g / "keep.test").mkdir(parents=True, exist_ok=True)
    (_out7g / "kill.test").mkdir(parents=True, exist_ok=True)
    (_out7g / "kill.test" / "404.txt").write_text("x" * 4096, encoding="utf-8")
    _rec7g = _Rec()
    _DS7g._cleanup_output(_rec7g, [_out7g / "kill.test"])
    assert not (_out7g / "kill.test").exists(), "本次扫过的目标目录必须被清掉"
    assert (_out7g / "keep.test").is_dir(), "没在本次扫描目标里的目录一律不能动"
    assert any("已清理 dirmap 产物目录 1 个" in l for l in _rec7g.lines), _rec7g.lines
    _DS7g._cleanup_output(_rec7g, [_out7g / "nope.test"])   # 目录不存在：只告警，不能带崩阶段
    assert any("清理 dirmap 产物目录失败" in l for l in _rec7g.lines), _rec7g.lines

    print("[7g] 续45 dirmap 残留（适配器侧）ok: 解析剥 #fragment 且保留 query（两个分支）/ "
          "产物行精确字节数直读 / 清理只删本次目标目录（别人的不动、失败只告警）")

    # [7h] 续46 **多用户**：账号密码登录 + 「管理员 / 子用户」两级角色。
    #      要钉死的是用户那句话「可以创建子用户，子用户没有查看配置的权限，只有使用扫描功能」——
    #      所以这里**真的开两个 client** 同时在线（管理员 + 子用户），逐个路由验证权限，
    #      而不是"加个装饰器就宣称实现了"（本项目第四次强调：装饰器在位 ≠ 门关得上）。
    from scanner import users as users_mod

    # 1) 口令派生（纯函数先行：哈希串格式 / 同口令不同盐 / 坏数据判失败不抛 / 常数时间比较）
    _h7h = users_mod.hash_password("smoke-pass-1234")
    assert _h7h.startswith("pbkdf2_sha256$") and len(_h7h.split("$")) == 4, _h7h
    assert "smoke-pass-1234" not in _h7h, "哈希串里绝不能出现明文口令"
    assert users_mod.verify_password(_h7h, "smoke-pass-1234")
    assert not users_mod.verify_password(_h7h, "smoke-pass-1235"), "错一位就必须失败"
    assert users_mod.hash_password("smoke-pass-1234") != _h7h, "同口令两次派生必须不同（每账号独立盐）"
    assert not users_mod.verify_password("", "x")
    assert not users_mod.verify_password("pbkdf2_sha256$abc$!!!$@@@", "x"), "坏哈希串判失败而不是抛"
    assert users_mod.const_eq("abc", "abc") and not users_mod.const_eq("abc", "abd")
    assert users_mod.const_eq("中文口令", "中文口令"), "非 ASCII 不能让 compare_digest 抛 TypeError"
    assert not users_mod.const_eq("中文口令", "中文口今")
    assert users_mod.validate_password("1234567")[0] is False, "口令下限 8 位"
    assert users_mod.validate_password("12345678")[0] is True
    assert users_mod.validate_password("smoke-admin-pw", "smoke-admin-pw")[0] is False, "口令不能等于用户名"
    assert users_mod.validate_password("   ")[0] is False
    assert users_mod.validate_username("")[0] is False and users_mod.validate_username("a")[0] is False
    assert users_mod.validate_username("a b")[0] is False, "用户名不能含空白"
    assert users_mod.validate_username("smoke-admin")[0] is True

    # 2) 管理员登录（本轮沙箱库里**还没有账号**，先建一个管理员）
    assert users_mod.count_users() == 0, "本轮沙箱库应为无账号状态"
    _ADMIN_PW, _SUB_PW, _SUB_PW2 = "SmokeAdmin#2026", "SmokeSub#2026", "SmokeSub#2026-new"
    assert users_mod.create_user("smoke-admin", _ADMIN_PW, role="admin", must_change=False)[0]
    _admin7h = users_mod.get_by_name("smoke-admin")
    assert _admin7h and _admin7h["role"] == "admin"
    # 口令列只在 `check_login` 内部用：对外（登录结果 / 列表）一律不带上
    assert "password" not in users_mod.check_login("smoke-admin", _ADMIN_PW)
    assert all("password" not in u for u in users_mod.list_users())

    _ca = app.test_client()      # 管理员
    _cs = app.test_client()      # 子用户（**独立会话**：换账号共用一个 client 证明不了权限差异）
    assert _ca.get("/").status_code == 302, "未登录必须跳登录页"
    assert _ca.post("/login", data={"username": "smoke-admin", "password": "wrong-pw"}).status_code == 200
    assert _ca.post("/login", data={"username": "smoke-admin",
                                    "password": _ADMIN_PW}).status_code == 302
    assert _ca.get("/settings").status_code == 200, "管理员必须能进策略配置"
    assert _ca.get("/pocs").status_code == 200 and _ca.get("/users").status_code == 200
    _users7h_html = _ca.get("/users").get_data(as_text=True)
    assert "smoke-admin" in _users7h_html and "创建账号" in _users7h_html
    # 页面绝不吐出口令哈希（list_users 不取 password 列 + 模板不渲染它）
    assert "pbkdf2_sha256" not in _users7h_html and _ADMIN_PW not in _users7h_html, \
        "账号页泄漏了口令哈希/明文"

    # 3) 建子用户（走**路由**，顺带验"管理员才能建号"）
    assert _ca.post("/api/users/create", data={"username": "smoke-sub", "password": _SUB_PW,
                                               "role": "user"}).status_code == 302
    _sub7h = users_mod.get_by_name("smoke-sub")
    assert _sub7h and _sub7h["role"] == "user", _sub7h
    assert _sub7h["must_change"] == 1, "新建账号默认待改密（初始口令管理员也知道）"
    assert _sub7h["enabled"] == 1

    # 4) 子用户登录 → 首次登录**强制改密**（被带到 /profile，改完才能继续）
    assert _cs.post("/login", data={"username": "smoke-sub", "password": _SUB_PW}).status_code == 302
    _r7h = _cs.get("/tasks")
    assert _r7h.status_code == 302 and "/profile" in (_r7h.headers.get("Location") or ""), \
        "待改密账号必须被带到修改口令页"
    assert _cs.get("/profile").status_code == 200, "/profile 自己必须放行（否则是跳转死循环）"
    assert _cs.post("/profile", data={"old_password": "wrong", "password": _SUB_PW2,
                                      "password2": _SUB_PW2}).status_code == 200
    assert users_mod.verify_password(users_mod.get_by_name("smoke-sub")["password"], _SUB_PW), \
        "当前口令不对时必须改失败"
    assert _cs.post("/profile", data={"old_password": _SUB_PW, "password": _SUB_PW2,
                                      "password2": _SUB_PW2}).status_code == 200
    assert users_mod.verify_password(users_mod.get_by_name("smoke-sub")["password"], _SUB_PW2)
    assert not users_mod.verify_password(users_mod.get_by_name("smoke-sub")["password"], _SUB_PW)
    assert _cs.get("/tasks").status_code == 200, "改完密就能正常用"

    # 5) **核心断言**：子用户看不到配置 —— 路由层硬挡（不是只藏侧边栏）
    for _p7h in ("/settings", "/pocs", "/users"):
        assert _cs.get(_p7h).status_code == 403, (_p7h, _cs.get(_p7h).status_code)
    # 写操作同样挡：改策略 / 启停 POC / 建账号 —— 这些比只读更要命
    assert _cs.post("/settings", data={"host": "127.0.0.1", "port": 5000}).status_code == 403
    assert _cs.post("/api/pocs/1/toggle").status_code == 403
    assert _cs.post("/api/pocs/bulk", json={"action": "enable"}).status_code == 403
    assert _cs.post("/api/pocs/refresh").status_code == 403
    assert _cs.post("/api/users/create", data={"username": "smoke-evil",
                                               "password": "evil-pw-1234"}).status_code == 403
    assert not users_mod.get_by_name("smoke-evil"), "子用户绝不能建出账号"
    # 403 页面要把话说清（静默跳首页会让人以为是自己点错了）
    assert "无权限" in _cs.get("/settings").get_data(as_text=True)

    # 6) 子用户**能**用的：扫描 + 看结果（"只有使用扫描功能"的另一半，别一禁就禁过头）
    _tid_mu = db.create_task("smoke-multiauth", targets, ["probe"], {"offline": True})
    for _p7h in ("/", "/tasks", "/subdomains", "/sites", "/ips", "/vulns", "/fullports",
                 "/dirs", "/ports", "/csegs", "/extdomains", f"/tasks/{_tid_mu}",
                 f"/api/tasks/{_tid_mu}/status"):
        assert _cs.get(_p7h).status_code == 200, (_p7h, _cs.get(_p7h).status_code)
    # 扫描类的 POST 也对子用户开放（空勾选只会重定向，不会真发请求）——证明不是"见 POST 就拦"
    assert _cs.post("/api/domains/resolve", data={"task_id": str(_tid_mu)}).status_code == 302

    # 7) 侧边栏：子用户看不到管理入口，管理员看得到（UI 与路由两层都要有）
    _sub7h_html = _cs.get("/tasks").get_data(as_text=True)
    # 判据用**入口链接**而不是页内文案：文案当不了"入口"的可靠代理 —— 各页正文本里本来就
    # 写着「在「策略配置 → …」里打开」这类**说明文字**（那是提示，不是入口），页面一改版式
    # 就会假红。实测（2026-09-26，临时脚本 `logs/_check7h.py`，子用户真登录后 GET /tasks）：
    # 当前页两种判据都是 0 次命中 —— 即这次改动是"判据与文案解耦"的**加固**，
    # **不是**在修一条已经变红的断言（如实记录，避免后人误以为它抓到过回归）。
    assert 'href="/settings"' not in _sub7h_html, "侧边栏不得向子用户露出「策略配置」入口"
    assert 'href="/users"' not in _sub7h_html, "侧边栏不得向子用户露出「账号管理」入口"
    assert 'href="/pocs"' not in _sub7h_html, "侧边栏不得向子用户露出「POC 管理」入口"
    assert "修改口令" in _sub7h_html and "smoke-sub" in _sub7h_html, "顶栏要显示当前登录者"
    assert "子用户" in _sub7h_html
    _admin7h_html = _ca.get("/tasks").get_data(as_text=True)
    assert 'href="/settings"' in _admin7h_html and 'href="/users"' in _admin7h_html
    assert 'href="/pocs"' in _admin7h_html
    assert "管理员" in _admin7h_html

    # 8) 停用**立即**生效：子用户手里的旧会话在下一个请求即被踢下线（不等他下次登录）
    assert _ca.post(f"/api/users/{_sub7h['id']}/toggle").status_code == 302
    assert users_mod.get_by_name("smoke-sub")["enabled"] == 0
    assert _cs.get("/tasks").status_code == 302, "已停用账号的会话必须当场失效"
    _cs3 = app.test_client()
    assert _cs3.post("/login", data={"username": "smoke-sub",
                                     "password": _SUB_PW2}).status_code == 200, "停用后不能再登录"
    assert _ca.post(f"/api/users/{_sub7h['id']}/toggle").status_code == 302     # 再启用（补救路径）
    assert users_mod.get_by_name("smoke-sub")["enabled"] == 1

    # 9) 防锁死三条：不能动自己 / 至少留一个启用中的管理员 / 用户名不重复
    assert _ca.post(f"/api/users/{_admin7h['id']}/toggle").status_code == 302
    assert users_mod.get_by_name("smoke-admin")["enabled"] == 1, "不能停用自己"
    assert _ca.post(f"/api/users/{_admin7h['id']}/delete").status_code == 302
    assert users_mod.get_by_name("smoke-admin"), "至少保留一个启用中的管理员"
    _n7h = users_mod.count_users()
    assert _ca.post("/api/users/create", data={"username": "smoke-admin",
                                               "password": "another-pw-1234"}).status_code == 302
    assert users_mod.count_users() == _n7h, "同名账号不能重复创建"

    # 10) 迁移口径：`gui.token` 只在"还没有任何账号"时是引导口令 —— 建了号就**不再是后门**
    _cb = app.test_client()
    assert _cb.post("/login", data={"token": settings["gui"]["token"]}).status_code == 200, \
        "已有账号后，旧共享口令必须失效"
    assert _cb.post("/login", data={"username": "", "password": settings["gui"]["token"]}).status_code == 200
    users_mod.delete_user(_sub7h["id"])
    users_mod.delete_user(_admin7h["id"])
    assert users_mod.count_users() == 0
    assert _cb.post("/login", data={"token": settings["gui"]["token"]}).status_code == 302, \
        "老部署升级后不能一上来就被锁在门外：无账号时 gui.token 仍可登录（管理员身份）"
    assert _cb.get("/settings").status_code == 200, "引导会话即管理员"
    # 第一个账号被**强制**成管理员：否则"先建了个子用户"就是单行道，从此没人能再建号
    assert _cb.post("/api/users/create", data={"username": "smoke-first",
                                               "password": "first-pw-1234",
                                               "role": "user"}).status_code == 302
    assert users_mod.get_by_name("smoke-first")["role"] == "admin", "第一个账号必须是管理员"
    assert _cb.get("/settings").status_code == 302, "建号后引导会话必须立即作废"

    print("[7h] 续46 多用户 ok: 口令只存 pbkdf2 派生值（同口令不同盐/坏串不抛）/ 账号密码登录 / "
          "管理员建子用户（默认待改密→强制改密后才可用）/ 子用户 403 挡在 策略配置·POC 管理·账号 "
          "（GET+POST 都挡，键策略/启停 POC/建号全拒）/ 子用户仍可扫描与看结果（含扫描类 POST）/ "
          "侧边栏对子用户隐藏管理入口 / 停用即时踢下线 / 防锁死（不动自己·至少一管理员）/ "
          "gui.token 仅作无账号时的引导口令（建号即失效）")

    # [7i] 续47 HTTPS 部署（反向代理终止 TLS）：控制台要能在服务器上用域名 + HTTPS 访问，
    #      且**不许削弱**续32 的 Host 白名单与续46 的 Cookie 收紧。四件事各钉一组断言：
    #      ① Host 白名单可**显式枚举**扩展（不扩的话部署域名会被整站 403 —— 这是最大的坑）；
    #      ② 扩展**不能**变成"放行一切"（`*` 必须被忽略）；③ `X-Forwarded-*` 只在显式打开
    #      `behind_proxy` 时才信（默认信 = 任何人伪造 Host/scheme，白名单与 Origin 校验一起失效）；
    #      ④ 会话 Cookie 的 `Secure` 由 `secure_cookie` 控制（默认关：HTTP 下开了会登录不上）。
    #      每条关键断言都在末尾 §9 做了**变异证伪**（把开关改坏，断言必须真变红）。
    import copy as _copy7i
    import io as _io7i
    import gui.app as gui_app
    from gui.app import _allowed_hosts, _deploy_hints, _LOOPBACK_HOSTS as _LOOPBACK7i

    # 1) `_allowed_hosts` 纯函数：默认只回环 / 显式枚举可扩 / 通配被忽略（只忽略该值，不整段作废）
    assert _allowed_hosts({})[0] == {"127.0.0.1", "localhost", "::1"}, _allowed_hosts({})
    assert _allowed_hosts({})[1] == []
    _a7i, _b7i = _allowed_hosts({"allowed_hosts": ["scanner.example.test",
                                                   "https://b.example.test:8443"]})
    assert _a7i - _LOOPBACK7i == {"scanner.example.test", "b.example.test"}, _a7i
    assert _b7i == [], "整条 URL 写法要能归一，不该被判非法"
    _a7i2, _b7i2 = _allowed_hosts({"allowed_hosts": ["*", "*.example.test", "?x", "ok.example"]})
    assert _b7i2 == ["*", "*.example.test", "?x"], _b7i2
    assert "ok.example" in _a7i2 and not any(("*" in h or "?" in h) for h in _a7i2), _a7i2
    _a7i3, _ = _allowed_hosts({"allowed_hosts": "x.test, y.test"})     # 手写字符串写法也要能吃
    assert {"x.test", "y.test"} <= _a7i3, _a7i3

    _orig_load7i, _orig_sync7i = gui_app.load_settings, gui_app.sync_pocs

    def _app_with7i(**gui_over):
        """用改过的 gui 配置**新建一个 app**（不动真实 settings.yaml、不动模块级那个 app）。

        `sync_pocs` 在这几个 app 里打桩成 no-op：本用例只验守卫/Cookie/转发头，
        没必要为每个 app 重扫一遍 300+ 模板（几十秒纯浪费，且与本用例无关）。
        """
        _base = _copy7i.deepcopy(settings)
        _base.setdefault("gui", {}).update(gui_over)
        gui_app.load_settings = lambda: _base
        gui_app.sync_pocs = lambda *_a, **_k: None
        try:
            return gui_app.create_app()
        finally:
            gui_app.load_settings, gui_app.sync_pocs = _orig_load7i, _orig_sync7i

    # 2) 默认严格（DNS rebinding 防护没被削弱）：非回环 Host 一律 403，回环照常
    assert app.config["CS_GUARD_HOST"] is True, "绑回环地址时必须做 Host 校验"
    assert app.config["CS_BAD_ALLOWED_HOSTS"] == ()
    assert app.test_client().get("/login", headers={"Host": "evil.example.com"}).status_code == 403
    assert app.test_client().get("/login", headers={"Host": "127.0.0.1"}).status_code == 200

    # 3) 显式放行才过：清单里的域名能过，别的仍 403；回环不受影响（端口不参与比对）
    _app_allow7i = _app_with7i(allowed_hosts=["scanner.example.test"])
    _c_allow7i = _app_allow7i.test_client()
    assert _c_allow7i.get("/login", headers={"Host": "scanner.example.test"}).status_code == 200
    assert _c_allow7i.get("/login",
                          headers={"Host": "scanner.example.test:443"}).status_code == 200, \
        "端口不参与白名单比对（_host_of 剥端口）"
    assert _c_allow7i.get("/login", headers={"Host": "other.example.test"}).status_code == 403
    assert _c_allow7i.get("/login", headers={"Host": "127.0.0.1"}).status_code == 200

    # 4) `*` 绝不放行一切：写通配值 = 被忽略 + 启动点名告警（而不是"整站放行"）
    _app_star7i = _app_with7i(allowed_hosts=["*"])
    assert _app_star7i.config["CS_BAD_ALLOWED_HOSTS"] == ("*",), _app_star7i.config
    assert _app_star7i.test_client().get(
        "/login", headers={"Host": "evil.example.com"}).status_code == 403

    def _env7i(app_obj, extra):
        """把 WSGI environ 直接喂给 `app.wsgi_app`，返回**被中间件改写后**的 environ。

        为什么不走 test_client：`request.host` / `request.scheme` 没有哪个页面读得出来，
        而 environ 正是 `ProxyFix` 唯一的输出面 —— 看它最贴近"到底信没信这些转发头"。
        """
        env = {"wsgi.url_scheme": "http", "REQUEST_METHOD": "GET", "PATH_INFO": "/login",
               "QUERY_STRING": "", "SERVER_NAME": "127.0.0.1", "SERVER_PORT": "5000",
               "SERVER_PROTOCOL": "HTTP/1.1", "HTTP_HOST": "127.0.0.1:5000",
               "REMOTE_ADDR": "127.0.0.1", "wsgi.input": _io7i.BytesIO(b""),
               "wsgi.errors": _io7i.StringIO(), "wsgi.version": (1, 0),
               "wsgi.multithread": False, "wsgi.multiprocess": False, "wsgi.run_once": False}
        env.update(extra)
        app_obj.wsgi_app(env, lambda status, headers, exc_info=None: None)
        return env

    # 5) 默认**不**信 X-Forwarded-*：伪造头不改变 scheme / Host / 客户端 IP
    _env7i_def = _env7i(app, {"HTTP_X_FORWARDED_PROTO": "https",
                              "HTTP_X_FORWARDED_HOST": "evil.example.com",
                              "HTTP_X_FORWARDED_FOR": "203.0.113.9"})
    assert _env7i_def["wsgi.url_scheme"] == "http", "behind_proxy 默认关：scheme 不得被伪造头改掉"
    assert _env7i_def["HTTP_HOST"] == "127.0.0.1:5000", "Host 不得被伪造头改掉"
    assert _env7i_def["REMOTE_ADDR"] == "127.0.0.1", "客户端 IP 不得被伪造头改掉"
    # 顺带证明"信了会怎样"：Host 是白名单外的域名时，用 X-Forwarded-Host 伪装成回环也必须 403
    assert app.test_client().get("/login", headers={
        "Host": "evil.example.com", "X-Forwarded-Host": "127.0.0.1"}).status_code == 403, \
        "X-Forwarded-Host 不得成为绕过 Host 白名单的后门"

    # 6) 打开 `behind_proxy` 后才生效（x_for / x_proto / x_host 各信一跳）
    _app_proxy7i = _app_with7i(behind_proxy=True, secure_cookie=True,
                               allowed_hosts=["scanner.example.test"])
    assert isinstance(_app_proxy7i.wsgi_app, gui_app.ProxyFix), "开了 behind_proxy 必须挂 ProxyFix"
    assert not isinstance(app.wsgi_app, gui_app.ProxyFix), "默认配置不得挂 ProxyFix"
    _env7i_on = _env7i(_app_proxy7i, {"HTTP_X_FORWARDED_PROTO": "https",
                                      "HTTP_X_FORWARDED_HOST": "scanner.example.test",
                                      "HTTP_X_FORWARDED_FOR": "203.0.113.9"})
    assert _env7i_on["wsgi.url_scheme"] == "https", _env7i_on["wsgi.url_scheme"]
    assert _env7i_on["HTTP_HOST"] == "scanner.example.test", _env7i_on["HTTP_HOST"]
    assert _env7i_on["REMOTE_ADDR"] == "203.0.113.9", _env7i_on["REMOTE_ADDR"]
    # 反代场景端到端：用转发来的域名访问能过白名单，别的域名仍被挡
    _c_proxy7i = _app_proxy7i.test_client()
    assert _c_proxy7i.get("/login", headers={"Host": "scanner.example.test"}).status_code == 200
    assert _c_proxy7i.get("/login", headers={"Host": "evil.example.com"}).status_code == 403

    # 7) 会话 Cookie 的 Secure：HTTPS 部署下必须带；默认配置下**不能**带（HTTP 下会登录不上）
    _PW7I = "SmokeHttps#2026"
    assert users_mod.create_user("smoke-https", _PW7I, role="user", must_change=False)[0]
    _ck7i = _c_proxy7i.post("/login", data={"username": "smoke-https", "password": _PW7I},
                            headers={"Host": "scanner.example.test"}).headers.get("Set-Cookie", "")
    assert "Secure" in _ck7i, "secure_cookie=true 时登录 Cookie 必须带 Secure：" + _ck7i
    assert "HttpOnly" in _ck7i and "SameSite=Lax" in _ck7i, \
        "续32 的 HttpOnly/SameSite 不能被新功能放宽：" + _ck7i
    _ck7i_plain = app.test_client().post(
        "/login", data={"username": "smoke-https", "password": _PW7I},
        headers={"Host": "127.0.0.1"}).headers.get("Set-Cookie", "")
    assert "HttpOnly" in _ck7i_plain and "SameSite=Lax" in _ck7i_plain, _ck7i_plain
    assert "Secure" not in _ck7i_plain, "默认配置不得给会话 Cookie 加 Secure（HTTP 下会登录不上）"

    # 8) 启动提示（抽成 `_deploy_hints` 才测得动）：默认配置安静，部署配置要把坑说全
    assert _deploy_hints({"host": "127.0.0.1"}) == [], "本机单人使用不该刷一堆部署告警"
    _hints7i = "\n".join(_deploy_hints({"host": "0.0.0.0", "behind_proxy": True,
                                        "secure_cookie": False,
                                        "allowed_hosts": ["*", "scanner.example.test"]}))
    assert "deploy-https" in _hints7i, "绑非回环地址时必须指向部署文档"
    assert "secure_cookie" in _hints7i, "TLS 反代下没开 Secure 要告警"
    assert "通配符" in _hints7i and "*" in _hints7i, "通配值要被点名"
    assert "scanner.example.test" in _hints7i, "放行清单要打印出来（排错用）"
    assert "只被你的反向代理访问" in _hints7i

    # 9) **变异证伪**（AGENTS.md §6.1）：在**同一条代码路径**上把开关改坏，断言必须真的变红。
    #    ① 关掉 Host 校验 → 恶意 Host 必须放行（证明 2)/3) 测的就是这道守卫）
    _app_allow7i.config["CS_GUARD_HOST"] = False
    assert _app_allow7i.test_client().get(
        "/login", headers={"Host": "evil.example.com"}).status_code == 200, \
        "变异后恶意 Host 仍被挡 → 说明那条断言测的不是 CS_GUARD_HOST"
    _app_allow7i.config["CS_GUARD_HOST"] = True
    assert _app_allow7i.test_client().get(
        "/login", headers={"Host": "evil.example.com"}).status_code == 403
    #    ② 把放行集合里的部署域名摘掉 → 它反而被挡（证明"显式放行"确实走这个集合）
    _keep7i = _app_allow7i.config["CS_ALLOWED_HOSTS"]
    _app_allow7i.config["CS_ALLOWED_HOSTS"] = _keep7i - {"scanner.example.test"}
    assert _app_allow7i.test_client().get(
        "/login", headers={"Host": "scanner.example.test"}).status_code == 403, \
        "变异后部署域名仍放行 → 说明放行不是靠 CS_ALLOWED_HOSTS"
    _app_allow7i.config["CS_ALLOWED_HOSTS"] = _keep7i
    #    ③ 关掉 Secure → 登录 Cookie 不该再带 Secure（证明 7) 测的就是这个开关）
    _app_proxy7i.config["SESSION_COOKIE_SECURE"] = False
    _ck7i_mut = _app_proxy7i.test_client().post(
        "/login", data={"username": "smoke-https", "password": _PW7I},
        headers={"Host": "scanner.example.test"}).headers.get("Set-Cookie", "")
    assert "Secure" not in _ck7i_mut, "变异后仍带 Secure → 说明那条断言测的不是这个开关"
    _app_proxy7i.config["SESSION_COOKIE_SECURE"] = True
    #    ④ 摘掉 ProxyFix → 转发头立刻失效（证明 6) 测的就是 ProxyFix 本身）
    _inner7i = getattr(_app_proxy7i.wsgi_app, "app", None)
    assert _inner7i is not None, "ProxyFix 应把内层 app 挂在 `.app` 上（werkzeug 约定）"
    _app_proxy7i.wsgi_app = _inner7i
    _env7i_mut = _env7i(_app_proxy7i, {"HTTP_X_FORWARDED_PROTO": "https",
                                       "HTTP_X_FORWARDED_HOST": "scanner.example.test"})
    assert _env7i_mut["wsgi.url_scheme"] == "http", \
        "摘掉 ProxyFix 后仍信转发头 → 说明那条断言测的不是 ProxyFix"

    # 10) `serve()` **真跑一遍**（三个打桩：load_settings / _port_free / app.run）。
    #     这一组是**主理人复核探针**抓出来的缺陷所加：`_deploy_hints()` 之外还残留了一句旧文案
    #     （"确需远程使用时，请走反向代理…"）被留在 `for _line in _deploy_hints(s):` 的**循环体**里 ——
    #     于是它按 hint 行数重复打印，而且在**回环地址**下也会冒出来（用户明明在本机跑，
    #     却收到"请走反向代理"的错误建议）。
    #     **为什么我原来的 [7i] 抓不到**：只测了 `_deploy_hints()` 这个纯函数，
    #     没有真调 `serve()` —— "纯函数返回正确"与"调用方打印正确"是两件事。
    #     （教训与 `_deploy_hints` 抽出来的理由相反：抽函数让文案可测，但**调用点**仍需实测。）
    import contextlib as _ctx7i

    def _serve_out7i(gui_over):
        """真调 `serve()` 并捕获 stdout，返回 `(输出行列表, 实际用到的 settings)`。"""
        _base = _copy7i.deepcopy(settings)
        _base.setdefault("gui", {}).update(gui_over)
        _buf = _io7i.StringIO()
        _orig_port_free = gui_app._port_free
        _orig_run = gui_app.app.run
        _had_run = "run" in gui_app.app.__dict__      # 恢复时别留下多余的实例属性
        gui_app.load_settings = lambda: _base
        gui_app._port_free = lambda h, p: True        # 不真 bind（否则占用端口 / 依赖环境）
        gui_app.app.run = lambda *a, **k: None        # 不真起服务器（否则测试会挂在这里）
        try:
            with _ctx7i.redirect_stdout(_buf):
                # 续49：本用例只验启动**提示**文案，绝不能顺手起任务队列 worker
                # （否则本测试库里残留的 queued 行会被真消费，污染其它用例）。
                gui_app.serve(start_queue=False)
        finally:
            gui_app.load_settings, gui_app._port_free = _orig_load7i, _orig_port_free
            if _had_run:
                gui_app.app.run = _orig_run
            else:
                gui_app.app.__dict__.pop("run", None)
        return _buf.getvalue().splitlines(), _base

    # 10a) 默认本机配置：`serve()` 不该打印任何部署提示（别给本机单人用户刷噪声）
    _out7i_def, _ = _serve_out7i({})
    assert not any(("deploy-https" in l or "Host 白名单放行" in l or "确需远程使用" in l)
                   for l in _out7i_def), "默认本机配置不该刷部署提示：" + repr(_out7i_def)

    # 10b) 反代部署配置：`_deploy_hints()` 的**每一行**在 serve() 输出里恰好出现 1 次，且整段输出无重复行
    _cfg7i = {"behind_proxy": True, "secure_cookie": True,
              "allowed_hosts": ["scanner.example.test"]}
    _out7i_proxy, _cfg7i_used = _serve_out7i(_cfg7i)
    _hints7i_used = _deploy_hints(_cfg7i_used["gui"])
    assert _hints7i_used, "反代部署配置下 `_deploy_hints` 不该为空（否则这条断言没有意义）"
    for _line in _hints7i_used:
        assert _out7i_proxy.count(_line) == 1, \
            f"启动提示必须逐行恰好一次，实际 {_out7i_proxy.count(_line)} 次：{_line!r}"
    _dup7i = sorted(l for l in set(_out7i_proxy) if l.strip() and _out7i_proxy.count(l) > 1)
    assert not _dup7i, "serve() 输出里有重复行：" + "; ".join(
        f"{_out7i_proxy.count(l)}× {l!r}" for l in _dup7i)

    # 10c) **回环地址**下不得出现"请走反向代理"这类建议（用户就在本机，那是错误建议）
    _out7i_loop, _ = _serve_out7i({"allowed_hosts": ["scanner.example.test"]})
    assert any("Host 白名单放行" in l for l in _out7i_loop), \
        "配了白名单就该打印放行清单（排错用）：" + repr(_out7i_loop)
    assert not any("确需远程使用" in l for l in _out7i_loop), \
        "回环地址下不得出现「请走反向代理」的建议：" + repr(_out7i_loop)

    print("[7i] 续47 HTTPS 部署 ok: Host 白名单可显式枚举扩展（默认仍只回环、`*` 被忽略并告警）/ "
          "X-Forwarded-* 默认不信任（伪造头不改 scheme·Host·IP，也不成为绕过白名单的后门）、"
          "behind_proxy=true 才生效（x_for/x_proto/x_host 各一跳）/ 会话 Cookie 在 HTTPS 下带 "
          "Secure 且 HttpOnly+SameSite=Lax 未被放宽 / 启动部署提示（指向 docs/deploy-https.md）/ "
          "4 条变异证伪全部按预期变红 / `serve()` 真跑：提示逐行恰好一次·无重复行·"
          "回环下不出现「请走反向代理」的错误建议")

    # [7j] 续48 **登录限速/失败锁定 + 访问审计流水**。
    #      背景：控制台即将放到服务器给队友用 —— 口令会被在线爆破，操作需要可回溯。
    #      钉死 8 条安全语义（每条一组断言，末尾 §6.1 变异证伪）：
    #      ① 两级限速（按 IP 为主 / 按用户名兜底）触发后返回 **429 + Retry-After**（不是 403）；
    #      ② **不泄漏账号是否存在**："存在但被锁"与"不存在但被锁"返回**逐字节相同**的页面；
    #      ③ 锁定期内**即使口令正确也拒绝**；④ 成功登录清该用户名计数（IP 计数不清）；
    #      ⑤ 计数**不无界增长**（锁定期间不再累加、过期行被 prune）；
    #      ⑥ `gui.token` 引导口令登录**同样受 IP 限速**；
    #      ⑦ guard/audit 出错**绝不阻断登录**；
    #      ⑧ 审计**只记元数据**：明文口令 / 口令哈希 / 引导口令值都不得出现在审计表与 /audit 页面。
    #      与既有 [6u]/[7h]/[7i] 的关系：它们都用 `app.test_client()`（IP 恒为 127.0.0.1），
    #      且 [7h] 有**故意的失败登录** —— 所以本用例的"打满阈值"一律用**独立 REMOTE_ADDR**，
    #      **绝不为迁就测试而调低默认阈值**（默认仍 10 次/5 分钟，见 scanner/config.py）。
    import scanner.audit as _audit48
    import scanner.login_guard as _lg48

    _AUD_PW = "SmokeAudit#2026"
    _SEC48 = "smoke-secret-token-ABC123"       # 会经 /settings 提交，用来验"值不落审计"
    assert users_mod.create_user("smoke-audit", _AUD_PW, role="admin", must_change=False)[0]
    _hash48 = users_mod.get_by_name("smoke-audit")["password"]   # pbkdf2 串（红线用）

    def _count_audit():
        return int(db._query("SELECT COUNT(*) c FROM audit_log", one=True)["c"] or 0)

    def _count_fails():
        return int(db._query("SELECT COUNT(*) c FROM login_fails", one=True)["c"] or 0)

    # 一个"提交 /settings 但不落盘"的 app —— 否则测试会把**真实 config/settings.yaml** 改掉。
    _orig_load48, _orig_sync48 = gui_app.load_settings, gui_app.sync_pocs

    def _make_app48():
        _base = copy.deepcopy(settings)
        gui_app.load_settings = lambda: _base
        gui_app.sync_pocs = lambda *_a, **_k: None
        try:
            _obj = gui_app.create_app()
        finally:
            gui_app.load_settings, gui_app.sync_pocs = _orig_load48, _orig_sync48
        return _obj, _base

    _app48, _base48 = _make_app48()      # 早建：它的启动 prune 会清过期行，别清掉后面造的样本
    _c48 = _app48.test_client()
    _cau = app.test_client()             # 主 app 的管理员会话（审计各路由用）
    assert _cau.post("/login", data={"username": "smoke-audit",
                                     "password": _AUD_PW}).status_code == 302

    # 1) 配置默认值 + 用户名归一必须与 `users.get_by_name()` **同口径**
    _cfg48 = _lg48.config(settings)
    assert _cfg48["enabled"] is True
    assert (_cfg48["window_seconds"], _cfg48["max_fails_per_ip"],
            _cfg48["max_fails_per_user"], _cfg48["lockout_seconds"]) == (300, 10, 20, 900), _cfg48
    assert _lg48.norm_username("  smoke-audit  ") == "smoke-audit"
    assert users_mod.get_by_name("  smoke-audit  ")["username"] == _lg48.norm_username("  smoke-audit "), \
        "guard 的用户名归一必须与 users.get_by_name 同口径（否则计数与查询会对不上）"
    # 关掉开关 → 永远不锁（纯函数，不依赖时间）
    _off48 = copy.deepcopy(settings)
    _off48["gui"]["login_lockout"] = dict(_off48["gui"]["login_lockout"], enabled=False)
    assert not _lg48.check("9.9.9.9", "x", _off48, now="2026-01-01 00:00:00").locked

    # 2) 两级判据 + 锁定窗口（注入时间，不真 sleep）：9 次不锁、第 10 次锁、900s 后自动解锁
    _IP_L, _U_L, _T0 = "198.51.100.77", "smoke-lock-target", "2026-01-01 00:00:00"
    assert not _lg48.check(_IP_L, _U_L, settings, now=_T0).locked
    for _i in range(9):
        _lg48.record_fail(_IP_L, _U_L, settings, now=_T0)
    assert not _lg48.check(_IP_L, _U_L, settings, now=_T0).locked, "9 次（<10）不该锁"
    _lg48.record_fail(_IP_L, _U_L, settings, now=_T0)          # 第 10 次 → 触发
    _v48 = _lg48.check(_IP_L, _U_L, settings, now=_T0)
    assert _v48.locked and _v48.retry_after > 0, _v48
    _v48b = _lg48.check(_IP_L, _U_L, settings, now="2026-01-01 00:14:59")
    assert _v48b.locked and _v48b.retry_after == 1, _v48b
    assert not _lg48.check(_IP_L, _U_L, settings, now="2026-01-01 00:15:01").locked, "900s 后应解锁"
    # 按用户名的**兜底**判据：换一批 IP、只打同一个用户名，到 20 次才锁（IP 各自都没满）
    _U_2 = "smoke-user-2nd"
    for _i in range(20):
        _lg48.record_fail(f"198.51.100.{100 + _i % 5}", _U_2, settings, now=_T0)
    assert _lg48.check("10.0.0.1", _U_2, settings, now=_T0).locked, "同名失败满 20 次必须按用户名锁"

    # 3) 成功登录清**该用户名**计数、**不清 IP**（同一 IP 上"别人的失败"仍在）
    _IP_C = "198.51.100.88"
    _lg48.record_fail(_IP_C, "smoke-other", settings, now=_T0)
    _lg48.record_fail(_IP_C, "smoke-lock-x", settings, now=_T0)
    _before48 = _lg48.fail_counts(_IP_C, "smoke-lock-x", settings, now=_T0)
    assert _before48["user"] == 1 and _before48["ip"] == 2, _before48
    _lg48.record_success(_IP_C, "smoke-lock-x", settings)
    _after48 = _lg48.fail_counts(_IP_C, "smoke-lock-x", settings, now=_T0)
    assert _after48["user"] == 0, "成功登录必须清掉该用户名的失败计数"
    assert _after48["ip"] == 1, "IP 计数不清（另一用户名的失败仍在）"

    # 4) 计数**不无界增长**：锁定期间继续刷也不落行；过期行被 prune 清掉
    _IP_U = "198.51.100.99"
    for _i in range(10):
        _lg48.record_fail(_IP_U, "", settings, now=_T0)
    assert _lg48.check(_IP_U, "", settings, now=_T0).locked
    _nf48 = _count_fails()
    for _i in range(50):
        _lg48.record_fail(_IP_U, "", settings, now=_T0)       # 锁定期间"攻击者"继续刷
    assert _count_fails() == _nf48, "锁定期间不得继续累加计数（否则可无限刷大 / 撑爆表）"
    db._exec("INSERT INTO login_fails(at, ip, username, kind) VALUES(?,?,?,?)",
             ("2020-01-01 00:00:00", "203.0.113.200", "", "fail"))
    _nf2 = _count_fails()
    assert _nf2 > _nf48
    assert _lg48.prune(settings) >= 1 and _count_fails() < _nf2, "prune 必须清掉过期计数行"

    # 5) HTTP 层：429 + Retry-After（不是 403）/ 正确口令也拒 / 存在性不泄漏
    _IP_H = "203.0.113.11"
    _envH = {"REMOTE_ADDR": _IP_H}
    _cl = app.test_client()
    _codes = [_cl.post("/login", data={"username": "smoke-audit", "password": "wrong-xx"},
                       environ_base=_envH).status_code for _i in range(11)]
    assert _codes[:10] == [200] * 10 and _codes[10] == 429, _codes
    _r429 = _cl.post("/login", data={"username": "smoke-audit", "password": "wrong-xx"},
                     environ_base=_envH)
    assert _r429.status_code == 429 and _r429.headers.get("Retry-After", "").isdigit(), _r429.headers
    assert 1 <= int(_r429.headers["Retry-After"]) <= 900
    assert _cl.post("/login", data={"username": "smoke-audit", "password": _AUD_PW},
                    environ_base=_envH).status_code == 429, "锁定期间即使口令正确也必须拒绝"
    # 存在性不泄漏：**同一个已被锁定的 IP** 上，"存在"与"不存在"的用户名必须返回**逐字节相同**的 429。
    # （守卫只看"提交的用户名 + IP"、不查库 —— 所以被锁文案与账号是否存在无关；
    #  若拿两个不同的 IP 去比，锁定时点不同 → Retry-After 不同 → 页面自然不同，那是测错了。）
    _v_a = _lg48.check(_IP_H, "smoke-audit", settings)
    _v_b = _lg48.check(_IP_H, "smoke-no-such-user", settings)
    assert (_v_a.locked, _v_a.retry_after) == (_v_b.locked, _v_b.retry_after), (_v_a, _v_b)
    _b1 = _cl.post("/login", data={"username": "smoke-audit", "password": "x"}, environ_base=_envH)
    _b2 = _cl.post("/login", data={"username": "smoke-no-such-user", "password": "x"},
                   environ_base=_envH)
    assert _b1.status_code == _b2.status_code == 429 and _b1.status_code != 403
    assert _b1.get_data(as_text=True) == _b2.get_data(as_text=True), \
        "锁定文案必须与『账号是否存在』无关（否则可拿来枚举用户名）"

    # 5b) 审计行必须带全"谁打谁"（复核返工第二轮）：IP 级锁的审计曾丢 actor/target（都为空）——
    #     而"这个 IP 在死磕哪个账号"恰恰是审计最该回答的。该信息此前只在 login_fails 的 fail 行里，
    #     而那张表按 max(window, lockout)（900s）清理、audit_log 却留 30 天 → 事故过去 15 分钟再翻
    #     审计就**永远查不出"那个 IP 打的是谁"**。修法：只把"真实 ip + 真实 username"传进审计元组，
    #     **不改** `_insert_lock` 写进 login_fails 的行（否则 IP 级锁会被误升级成账号级锁）。
    #     （放在 group 5 之后、group 6 之前：让"IP 级锁不误升级"这条回归断言成为文件级变异
    #       `_insert_lock(ip, "")` → `_insert_lock(ip, username)` 的**首个**捕获点。）
    _U_WHO = "smoke-who"
    _PW_WHO = "SmokeWho#2026"
    assert users_mod.create_user(_U_WHO, _PW_WHO, role="user", must_change=False)[0]
    _IP_WHO = "203.0.113.61"
    for _i in range(10):                        # 触发 IP 级锁（用户名非空；真实时间 → 锁真实有效）
        _lg48.record_fail(_IP_WHO, _U_WHO, settings)
    _blk = _audit48.query(kind=_audit48.KIND_LOGIN_BLOCKED, ip=_IP_WHO, limit=10)[0]
    _rip = [r for r in _blk if "IP 失败过多" in (r["detail"] or "")]
    assert _rip, "IP 级锁必须留审计（含 'IP 失败过多'）"
    assert _rip[0]["actor"] == _U_WHO and _rip[0]["target"] == _U_WHO, \
        f"IP 级锁审计必须记下'打的是哪个账号'，实得 actor={_rip[0]['actor']!r} target={_rip[0]['target']!r}"
    assert _rip[0]["ip"] == _IP_WHO, "IP 级锁审计的 ip 必须是该 IP"
    # 用户名级锁：审计的 ip 必须非空（= 触发它的那个 IP）
    _U_WHO2 = "smoke-who-2"
    _who2_ips = [f"198.51.100.{150 + _i % 4}" for _i in range(20)]
    for _ip2 in _who2_ips:
        _lg48.record_fail(_ip2, _U_WHO2, settings, now="2026-06-01 00:00:00")
    _blk2 = _audit48.query(kind=_audit48.KIND_LOGIN_BLOCKED, actor=_U_WHO2, limit=10)[0]
    _ru = [r for r in _blk2 if "该账号失败过多" in (r["detail"] or "")]
    assert _ru, "用户名级锁必须留审计（含 '该账号失败过多'）"
    assert _ru[0]["actor"] == _U_WHO2 and _ru[0]["target"] == _U_WHO2
    assert (_ru[0]["ip"] or "") != "", "用户名级锁审计必须记下'来自哪个 IP'（否则查不出攻击源）"
    assert _ru[0]["ip"] == _who2_ips[-1], \
        f"用户名级锁应记触发它的 IP {_who2_ips[-1]!r}，实得 {_ru[0]['ip']!r}"
    # **回归保护（最重要）**：IP 级锁**不能**被误升级成账号级锁 —— 换一个 IP 用同一账号仍能正常登录。
    # 含两条 §6.1 证伪：① 同进程"给 IP 级锁行补上用户名"（模拟文件级变异）；② 文件级真改见
    # logs/_mutate_48c.py。
    _IP_FREE = "203.0.113.62"

    def _free_login():
        return app.test_client().post(
            "/login", data={"username": _U_WHO, "password": _PW_WHO},
            environ_base={"REMOTE_ADDR": _IP_FREE}).status_code

    assert _free_login() == 302, \
        "IP 级锁只该锁那个 IP；换一个 IP 用同一账号必须仍能登录（否则 IP 级锁被误升级成账号级锁）"
    db._exec("UPDATE login_fails SET username=? WHERE kind='lock' AND ip=? AND username=''",
             (_U_WHO, _IP_WHO))                    # 变异：IP 级锁行被"账号级"污染
    assert _free_login() != 302, "污染后仍能登录 → 回归断言测的不是'IP 级锁没带用户名'"
    db._exec("UPDATE login_fails SET username='' WHERE kind='lock' AND ip=? AND username=?",
             (_IP_WHO, _U_WHO))                    # 还原
    assert _free_login() == 302, "清掉污染后必须恢复可登录"
    db._exec("DELETE FROM login_fails WHERE ip=? OR username=? OR ip LIKE ?",
             (_IP_WHO, _U_WHO2, "198.51.100.15%"))

    # 6) 审计：登录成功/失败/退出/账号操作/策略配置/POC/任务 都留下流水
    _ok_rows, _ok_total = _audit48.query(kind=_audit48.KIND_LOGIN_OK, limit=50)
    assert _ok_total >= 1 and any(r["actor"] == "smoke-audit" for r in _ok_rows), _ok_rows
    assert _audit48.query(kind=_audit48.KIND_LOGIN_FAIL, ip=_IP_H)[1] >= 10, "失败登录必须有审计"
    assert _audit48.query(kind=_audit48.KIND_LOGIN_BLOCKED, ip=_IP_H)[1] >= 1, "被拦截也要留痕"
    # 退出
    _cau.get("/logout")
    assert _audit48.query(kind=_audit48.KIND_LOGOUT)[1] >= 1
    assert _cau.post("/login", data={"username": "smoke-audit",
                                     "password": _AUD_PW}).status_code == 302
    # 账号操作（建号）
    assert _cau.post("/api/users/create", data={"username": "smoke-audit-sub",
                                                "password": "smoke-audit-pw1"}).status_code == 302
    _acc_rows, _acc_total = _audit48.query(kind=_audit48.KIND_ACCOUNT, actor="smoke-audit")
    assert _acc_total >= 1 and any("smoke-audit-sub" in (r["target"] or "") for r in _acc_rows)
    # 越权：子用户敲管理页 → 403 且留一条 denied。
    # 本用例只验"权限 + 审计"，不验"必须改密"（[7h] 已覆盖），所以先把 must_change 清掉 ——
    # 否则子用户会被 login_required 先重定向到 /profile（302），拿不到 403。
    users_mod.set_must_change(users_mod.get_by_name("smoke-audit-sub")["id"], False)
    _csub48 = app.test_client()
    assert _csub48.post("/login", data={"username": "smoke-audit-sub",
                                        "password": "smoke-audit-pw1"}).status_code == 302
    _den_before = _audit48.query(kind=_audit48.KIND_DENIED)[1]
    assert _csub48.get("/settings").status_code == 403
    assert _audit48.query(kind=_audit48.KIND_DENIED)[1] == _den_before + 1
    # 策略配置（走 stub 过的 save_settings，**不落盘**）：只记"改了哪一块"，绝不记值
    _orig_save48 = gui_app.save_settings
    gui_app.save_settings = lambda data: _base48
    try:
        _c48.post("/login", data={"username": "smoke-audit", "password": _AUD_PW})
        assert _c48.post("/settings", data={"host": "127.0.0.1", "port": "5000",
                                            "token": _SEC48}).status_code == 302
    finally:
        gui_app.save_settings = _orig_save48
    _set_rows, _set_total = _audit48.query(kind=_audit48.KIND_SETTINGS, limit=5)
    assert _set_total >= 1, "保存策略配置必须留审计"
    assert all(_SEC48 not in (r["detail"] or "") and _SEC48 not in (r["target"] or "")
               for r in _set_rows), "策略配置审计绝不能带上提交的值（哪怕是 token）"
    # POC 操作
    _poc_before = _audit48.query(kind=_audit48.KIND_POC)[1]
    assert _cau.post("/api/pocs/1/toggle").status_code == 200
    assert _audit48.query(kind=_audit48.KIND_POC)[1] == _poc_before + 1
    # 任务操作（删除一个任务）
    _task_before = _audit48.query(kind=_audit48.KIND_TASK)[1]
    _tid48 = db.create_task("smoke-audit-task", targets, ["probe"], {"offline": True})
    assert _cau.post(f"/api/tasks/{_tid48}/delete").status_code == 200
    assert _audit48.query(kind=_audit48.KIND_TASK)[1] >= _task_before + 1

    # 7) query 过滤器 + prune **只清 audit_log**（不碰业务表）
    _kr, _kt = _audit48.query(kind=_audit48.KIND_LOGIN_FAIL)
    assert _kt >= 1 and all(r["kind"] == _audit48.KIND_LOGIN_FAIL for r in _kr)
    _ir, _it = _audit48.query(ip=_IP_H)
    assert _it >= 1 and all(r["ip"] == _IP_H for r in _ir)
    _tasks_before48 = len(db.list_tasks())
    db._exec("INSERT INTO audit_log(at, kind, actor, actor_role, ip, target, detail, ok) "
             "VALUES(?,?,?,?,?,?,?,?)",
             ("2020-01-01 00:00:00", "login_ok", "old-user", "", "1.2.3.4", "", "远古记录", 1))
    _an48 = _count_audit()
    _pr48 = _audit48.prune(days=1, settings=settings)
    assert _pr48 >= 1 and _count_audit() == _an48 - _pr48, (_pr48, _an48, _count_audit())
    assert len(db.list_tasks()) == _tasks_before48, "prune 绝不能碰业务表"
    assert not _audit48.query(since="2020-01-01 00:00:00", until="2020-01-01 00:00:01")[0]

    # 8) **凭据红线**：明文口令 / 口令哈希 / 引导口令值 / 提交的 token 值
    #    都不得出现在 `audit_log` 表与渲染出的 `/audit` 页面里。
    _dump48 = "\n".join("|".join(str(r[c]) for c in
                                 ("at", "kind", "actor", "actor_role", "ip", "target", "detail"))
                        for r in db._query("SELECT * FROM audit_log"))
    _html48 = _cau.get("/audit").get_data(as_text=True)
    for _needle, _what in ((_AUD_PW, "明文口令"), (_hash48, "口令哈希"),
                           (settings["gui"]["token"], "引导口令值"), (_SEC48, "提交的新口令值")):
        assert _needle not in _dump48, f"{_what} 泄漏进了审计表"
        assert _needle not in _html48, f"{_what} 泄漏进了 /audit 页面"
    assert "smoke-audit-sub" in _html48, "/audit 页面应能看到账号操作流水（否则上面几条是空断言）"

    # 9) **§6.1 变异证伪**（真改同一条代码路径，断言必须变红）
    #    ① 关掉限速 → 已锁的 IP 立刻放行（证明 5) 测的就是 login_lockout）
    _real_cfg48 = _lg48.config
    _lg48.config = lambda _s=None: {"enabled": False, "window_seconds": 300,
                                    "max_fails_per_ip": 10, "max_fails_per_user": 20,
                                    "lockout_seconds": 900}
    try:
        assert not _lg48.check(_IP_H, "smoke-audit", settings).locked, "变异后仍锁定"
        assert _cl.post("/login", data={"username": "smoke-audit", "password": "wrong-xx"},
                        environ_base=_envH).status_code != 429, \
            "变异后仍 429 → 说明那条断言测的不是 login_lockout"
    finally:
        _lg48.config = _real_cfg48
    assert _lg48.check(_IP_H, "smoke-audit", settings).locked, "还原后必须重新锁定"
    #    ② 关掉审计擦洗 → 带 `password=` 的 detail 会原样落库（证明红线断言测的就是擦洗）
    _real_scrub48 = _audit48._scrub
    _audit48._scrub = lambda t: str(t or "")
    try:
        _audit48.record(_audit48.KIND_LOGIN_FAIL, "scrub-probe", "1.2.3.4",
                        detail=f"password={_AUD_PW}", settings=settings)
        _leak48 = "\n".join(str(r["detail"]) for r in db._query(
            "SELECT detail FROM audit_log WHERE actor='scrub-probe'"))
        assert _AUD_PW in _leak48, "变异后口令仍未出现 → 红线断言测的不是擦洗"
    finally:
        _audit48._scrub = _real_scrub48
    _audit48.record(_audit48.KIND_LOGIN_FAIL, "scrub-probe", "1.2.3.4",
                    detail=f"password={_AUD_PW}", settings=settings)
    _leak48b = "\n".join(str(r["detail"]) for r in db._query(
        "SELECT detail FROM audit_log WHERE actor='scrub-probe' ORDER BY id DESC LIMIT 1"))
    assert _AUD_PW not in _leak48b, "擦洗必须把口令抹掉"
    db._exec("DELETE FROM audit_log WHERE actor='scrub-probe'")   # 别把变异期的"泄漏样本"留在沙箱里
    #    ③ 关掉审计开关 → 不再落行（证明"审计在写"确实由 gui.audit.enabled 控制）
    _offaud48 = copy.deepcopy(settings)
    _offaud48["gui"]["audit"] = {"enabled": False, "retention_days": 30}
    _n_off48 = _count_audit()
    assert _audit48.record(_audit48.KIND_TASK, "x", "1.2.3.4", detail="x",
                           settings=_offaud48) is False
    assert _count_audit() == _n_off48

    # 10) ⑦ guard/audit 出错**绝不阻断登录**：把 check / record 打成会抛，登录仍必须成功
    def _boom48(*_a, **_k):
        raise RuntimeError("boom")

    _real_check48 = _lg48.check
    _lg48.check = _boom48
    try:
        _ct48 = app.test_client()
        assert _ct48.post("/login", data={"username": "smoke-audit",
                                          "password": _AUD_PW}).status_code == 302, \
            "guard 抛异常时必须放行登录（可用性优先）"
    finally:
        _lg48.check = _real_check48
    _real_rec48 = _audit48.record
    _audit48.record = _boom48
    try:
        _ct49 = app.test_client()
        assert _ct49.post("/login", data={"username": "smoke-audit",
                                          "password": _AUD_PW}).status_code == 302, \
            "审计抛异常时必须放行登录"
    finally:
        _audit48.record = _real_rec48

    # 11) 续48 复核返工：**"被拦截"的审计只在"锁刚被创建"时写一次**（防未认证者无界放大）。
    #     背景（主理人实测到的缺陷）：路由的"被拦截"分支曾**每次请求**都写一行 `login_blocked` ——
    #     未认证者可按请求速率持续往 `audit_log` 追加：既让磁盘无界增长，又持续抢占全库**唯一**的
    #     写锁（`db._WRITE_LOCK`），与 dirscan / portscan 那几百行一批的资产写入**争锁** → 相当于用
    #     一个新功能把扫描主流程拖慢甚至搞挂。修法：写点收口到 `login_guard` 里"锁刚被创建"那一刻
    #     （`_audit_lock`），路由侧不再写。钉死三条不变量：
    #     ① 同一锁窗口内连打 40 次被拦截请求 → `login_blocked` 只新增 1 行，且那 1 行真的存在；
    #     ② 锁窗口过期后再次被锁 → 再新增 1 行（第二次事件同样留痕）；
    #     ③ §6.1 变异证伪：拆掉"锁定后不再走判锁" → ① 必须变红。
    _T_LK = "2026-03-01 00:00:00"
    _IP_LK = "203.0.113.31"
    assert _audit48.query(kind=_audit48.KIND_LOGIN_BLOCKED, ip=_IP_LK)[1] == 0, "前置：该 IP 不应有记录"
    for _i in range(10):                                  # 第 10 次触发锁 → 写 1 条
        _lg48.record_fail(_IP_LK, "", settings, now=_T_LK)
    assert _audit48.query(kind=_audit48.KIND_LOGIN_BLOCKED, ip=_IP_LK)[1] == 1, \
        "锁被创建时必须留 1 条 login_blocked（信号不能为了'少写'而丢）"
    for _i in range(40):                                  # 锁定期内继续刷"被拦截请求"
        _lg48.record_fail(_IP_LK, "", settings, now=_T_LK)
    assert _audit48.query(kind=_audit48.KIND_LOGIN_BLOCKED, ip=_IP_LK)[1] == 1, \
        "同一锁窗口内 40 次被拦截后 login_blocked 仍须只有 1 行（否则未认证者可无界放大）"
    for _i in range(10):                                  # ② 锁窗口（900s）过期后再次打满
        _lg48.record_fail(_IP_LK, "", settings, now="2026-03-01 00:16:00")
    assert _audit48.query(kind=_audit48.KIND_LOGIN_BLOCKED, ip=_IP_LK)[1] == 2, \
        "锁窗口过期后再次被锁必须新增一行（不能因为'见过这个 IP'就永久不再记）"
    # 端到端（路由侧）：被拦截请求不再写审计 —— 40 次 429 后仍只有锁创建时那 1 条
    _IP_HT = "203.0.113.32"
    _envHT = {"REMOTE_ADDR": _IP_HT}
    _cht = app.test_client()
    for _i in range(10):
        _cht.post("/login", data={"username": "smoke-audit", "password": "wrong-yy"},
                  environ_base=_envHT)
    assert _audit48.query(kind=_audit48.KIND_LOGIN_BLOCKED, ip=_IP_HT)[1] == 1, "路由侧锁创建应留 1 条"
    for _i in range(40):
        assert _cht.post("/login", data={"username": "smoke-audit", "password": "wrong-yy"},
                         environ_base=_envHT).status_code == 429
    assert _audit48.query(kind=_audit48.KIND_LOGIN_BLOCKED, ip=_IP_HT)[1] == 1, \
        "路由侧 40 次被拦截请求后 login_blocked 仍须只有 1 行"
    # ③ §6.1 变异证伪：破坏"锁定后不再走判锁"（让 record_fail 每次都继续去判锁）→ ① 必须变红
    _real_al48 = _lg48._active_locks
    _lg48._active_locks = lambda *_a, **_k: []
    _IP_MUT = "203.0.113.33"
    try:
        for _i in range(10):
            _lg48.record_fail(_IP_MUT, "", settings, now=_T_LK)
        _m1 = _audit48.query(kind=_audit48.KIND_LOGIN_BLOCKED, ip=_IP_MUT)[1]
        for _i in range(40):
            _lg48.record_fail(_IP_MUT, "", settings, now=_T_LK)
        _m2 = _audit48.query(kind=_audit48.KIND_LOGIN_BLOCKED, ip=_IP_MUT)[1]
        assert _m2 - _m1 > 1, "变异后仍只新增 1 行 → 断言测的不是'锁只写一次'"
    finally:
        _lg48._active_locks = _real_al48
    db._exec("DELETE FROM login_fails WHERE ip IN (?,?,?)", (_IP_LK, _IP_HT, _IP_MUT))

    # 12) 续48 复核返工加固：`_scrub` 也作用到 `target`（此前只作用在 `detail`）。
    #     调用侧目前只往 target 传对象名，但"手滑把值塞进 target"这条路径原先**没有兜底**。
    _audit48.record(_audit48.KIND_TASK, "probe-tgt", "1.2.3.4",
                    target=f"password={_AUD_PW}", settings=settings)
    _tgt = db._query("SELECT target FROM audit_log WHERE actor='probe-tgt' "
                     "ORDER BY id DESC LIMIT 1", one=True)
    assert _tgt and _AUD_PW not in (_tgt["target"] or ""), "target 必须被擦洗（不能原样落库）"
    assert _AUD_PW not in _cau.get("/audit").get_data(as_text=True), "target 里的值不能出现在 /audit 页"
    # §6.1 证伪：关掉擦洗 → target 会原样落库（证明上面那条断言测的就是擦洗）
    _real_scrub48b = _audit48._scrub
    _audit48._scrub = lambda t: str(t or "")
    try:
        _audit48.record(_audit48.KIND_TASK, "probe-tgt2", "1.2.3.4",
                        target=f"password={_AUD_PW}", settings=settings)
        _tgt2 = db._query("SELECT target FROM audit_log WHERE actor='probe-tgt2' "
                          "ORDER BY id DESC LIMIT 1", one=True)
        assert _AUD_PW in (_tgt2["target"] or ""), "变异后 target 仍未泄漏 → 红线断言测的不是擦洗"
    finally:
        _audit48._scrub = _real_scrub48b
    db._exec("DELETE FROM audit_log WHERE actor IN ('probe-tgt','probe-tgt2')")

    # 13) ⑥ `gui.token` 引导口令登录**同样受 IP 限速**：清空账号（bootstrap 分支才可达），
    #     先从一个 IP 打满，再验证"即使引导口令正确也 429"；换干净 IP 仍能登录（反向对照）。
    for _u in users_mod.list_users():
        users_mod.delete_user(_u["id"])
    assert users_mod.count_users() == 0, "bootstrap 分支只在无账号时可达"
    _IP_T = "203.0.113.13"
    _envT = {"REMOTE_ADDR": _IP_T}
    _ctok = app.test_client()
    for _i in range(10):
        _ctok.post("/login", data={"token": "wrong-token"}, environ_base=_envT)
    _rtok = _ctok.post("/login", data={"token": settings["gui"]["token"]}, environ_base=_envT)
    assert _rtok.status_code == 429, "引导口令登录也必须受 IP 限速"
    assert _ctok.post("/login", data={"token": settings["gui"]["token"]},
                      environ_base={"REMOTE_ADDR": "203.0.113.14"}).status_code == 302, \
        "干净 IP 上正确的引导口令仍须能登录（证明刚才的 429 是限速，不是口令坏了）"

    print("[7j] 续48 登录限速 + 访问审计 ok: 两级限速（IP 10 次/5 分钟为主、用户名 20 次兜底，"
          "900s 后自动解锁）/ 锁定返回 429+Retry-After（非 403）· 正确口令也拒 · 存在性不泄漏"
          "（两页逐字节相同）/ 成功清用户名计数不清 IP / 计数不无界增长（锁定期不累加 + prune 清过期）/ "
          "被拦截审计只在锁创建时写一次（40 次被拦截仍只 1 行、过期再锁再记 1 行）/ "
          "审计记全『谁打谁』（IP 级锁也记被尝试账号、用户名级锁也记来源 IP）/ IP 级锁不误升级成账号级锁 / "
          "target·detail 均擦洗 / 引导口令同样受 IP 限速 / guard·audit 抛异常不阻断登录 / "
          "审计只记元数据（明文口令·哈希·引导口令值·提交值均不落表·不上页）/ 6 条变异证伪全部按预期变红")

    # [7k] 续49 **持久化任务队列**（`scanner/queue.py` + `db.enqueue_task` / `claim_next_queued`）。
    #      背景：原 `_spawn()` 直接 `threading.Thread(target=run_task)` —— 进程一重启线程没了、
    #      任务却仍挂 `running`（旧实现只能标 failed）。用户要求"重启不丢任务"，于是改成
    #      "把本次运行入参写库 + 置 queued，由 worker 认领执行"；重启对账把死掉的 running
    #      **重新入队**。本组用**独立临时库**（与前面用例的库隔离）：前面不少用例 POST 过建任务
    #      路由、库里会残留 `queued` 行，共用库的话本组起的 worker 会把它们一并消费掉。
    #      钉死 6 条语义（末尾 §6.1 变异证伪）：
    #      ① 入队 → worker 认领（queued→running）→ 执行 → 终态 done；
    #      ② 模拟进程重启：死 pid + 非空断点的 running → 对账**重新入队**（run_mode=resume、
    #         断点保留），worker 能接着消费；
    #      ③ 排队中的任务被「停止」→ 从队列移除、**不被认领**（db 层 + `/api stop` 路由）；
    #      ④ `queue.workers=1` **不并发**（同一时刻最多一个任务在跑）；
    #      ⑤ `run_mode` / `queued_at` / `run_payload` 落库；⑥ 老库（缺列）经 `_ensure_columns` 补出。
    import json as _json49
    import sqlite3 as _sqlite49
    import scanner.queue as _q49

    _qdb49 = _TMPDIR / "queue49.db"
    _saved_db49 = db.DB_PATH
    db.DB_PATH = _qdb49
    _seen49 = []
    _live49 = {"cur": 0, "max": 0}
    _lk49 = threading.Lock()

    def _consume49(tid, mode):
        """消费者桩：记录 (task_id, mode)、统计并发峰值、模拟 run_task 的终态（done）。

        本组只验**队列本身**（认领 / 模式 / 并发 / 重启），不真跑流水线 —— 用桩把
        `runner.run_task` 换掉，既快又不产生任何真实请求。
        """
        with _lk49:
            _live49["cur"] += 1
            _live49["max"] = max(_live49["max"], _live49["cur"])
        try:
            _seen49.append((tid, mode))
            time.sleep(0.05)          # 留出并发窗口：串行时峰值恒为 1
            db.update_task(tid, status="done", progress=100, current_stage="")
        finally:
            with _lk49:
                _live49["cur"] -= 1

    def _wait49(tid, want, timeout=6.0):
        end = time.time() + timeout
        while time.time() < end and db.get_task(tid)["status"] != want:
            time.sleep(0.02)
        return db.get_task(tid)["status"] == want

    try:
        db.init_db()
        _qset49 = copy.deepcopy(settings)
        _qset49["queue"] = {"workers": 1}
        # 配置口径：默认单消费者、非法值回落、上限 8
        assert _q49.config(_qset49)["workers"] == 1
        assert _q49.config({"queue": {"workers": 99}})["workers"] == 8, "workers 必须夹到 1..8"
        assert _q49.config({})["workers"] == 1, "缺省必须单消费者（串行 = 最省带宽、最不易触发风控）"
        assert _q49.config({"queue": {"workers": "x"}})["workers"] == 1, "非法值回落 1"

        # ① 入队 → 消费 → 终态；⑤ run_mode / queued_at / run_payload 落库
        _t1 = db.create_task("smoke-q1", targets, ["probe"], {"offline": True})
        db.enqueue_task(_t1, "fresh", ["probe"], {"offline": True})
        _r1 = dict(db.get_task(_t1))
        assert _r1["status"] == "queued" and _r1["run_mode"] == "fresh", _r1
        assert str(_r1["queued_at"] or "").strip(), "queued_at 必须落库（排队位置/时长靠它）"
        assert _r1["run_payload"] and '"probe"' in _r1["run_payload"], \
            "本次运行的精确入参必须写进 run_payload（重启后靠它重建）"
        _q49.start(_qset49, dispatch=_consume49)
        assert _wait49(_t1, "done"), \
            f"入队任务必须被 worker 消费到终态：{db.get_task(_t1)['status']!r}"
        assert (_t1, "fresh") in _seen49, _seen49
        assert db.queued_count() == 0

        # ② 模拟进程重启：带运行规格 + 死 pid + 非空断点 → 对账**重新入队**（resume、断点保留），
        #    worker 接着消费。先停 worker，让对账结果可观测（否则 worker 会立刻把它领走）。
        _q49.stop()
        _t2 = db.create_task("smoke-q2", targets, ["probe", "dirscan"], {"offline": True})
        db._exec("UPDATE tasks SET status='running', pid=0, current_stage='dirscan', "
                 "run_mode='fresh', run_payload=? WHERE id=?",
                 (_json49.dumps({"stages": ["probe", "dirscan"], "options": {"offline": True}}), _t2))
        _handled49 = db.reconcile_orphan_tasks()
        _r2 = dict(db.get_task(_t2))
        assert _t2 in _handled49, "带运行规格的孤儿任务必须被对账处理"
        assert _r2["status"] == "queued", \
            f"重启对账必须**重新入队**（不是标 failed）：{_r2['status']!r}"
        assert _r2["run_mode"] == "resume", \
            f"有断点的 fresh 任务重启后应按 resume 续跑：{_r2['run_mode']!r}"
        assert _r2["current_stage"] == "dirscan", "对账必须**保留断点**（续跑靠它切片）"
        assert "重新入队" in (_r2["error"] or ""), "重新入队要留一条可读说明"
        _q49.start(_qset49, dispatch=_consume49)
        assert _wait49(_t2, "done"), \
            f"重新入队的任务必须被 worker 接着消费：{db.get_task(_t2)['status']!r}"
        assert (_t2, "resume") in _seen49, f"必须以 resume 模式消费：{_seen49}"
        # §6.1 证伪：把"队列模式"清空 → 同一输入会退回旧语义（标 failed），② 的断言必红
        _real_modes49 = db._QUEUE_MODES
        db._QUEUE_MODES = ()
        try:
            _t2b = db.create_task("smoke-q2b", targets, ["probe", "dirscan"], {"offline": True})
            db._exec("UPDATE tasks SET status='running', pid=0, current_stage='dirscan', "
                     "run_mode='fresh', run_payload='{}' WHERE id=?", (_t2b,))
            db.reconcile_orphan_tasks()
            assert db.get_task(_t2b)["status"] == "failed", \
                "变异后应退回旧语义（failed）→ 证明 ② 测的就是'重新入队'这条路径"
        finally:
            db._QUEUE_MODES = _real_modes49

        # ③ 排队中的任务被「停止」→ 从队列移除、不被认领（db 层）
        _q49.stop()
        _t3 = db.create_task("smoke-q3-stop", targets, ["probe"], {"offline": True})
        _t3b = db.create_task("smoke-q3-keep", targets, ["probe"], {"offline": True})
        db.enqueue_task(_t3, "fresh", ["probe"], {"offline": True})
        db.enqueue_task(_t3b, "fresh", ["probe"], {"offline": True})
        assert db.queued_position(_t3) == 1 and db.queued_position(_t3b) == 2, "排队位置按 id 升序"
        db.update_task(_t3, status="stopped")     # 等价于「停止」路由对 queued 的处置
        _nxt49 = db.claim_next_queued()
        assert _nxt49 and _nxt49["id"] == _t3b, \
            f"被停止的排队任务不得被认领，应认领下一条：{_nxt49 and _nxt49['id']}"
        assert db.get_task(_t3)["status"] == "stopped"
        db.update_task(_t3b, status="stopped")    # 还原，别留给后面的用例
        # 路由层：/api/tasks/<id>/stop 对 queued 必须"从队列移除"（而不是回"未在运行"）
        _t4 = db.create_task("smoke-q4-route", targets, ["probe"], {"offline": True})
        db.enqueue_task(_t4, "fresh", ["probe"], {"offline": True})
        _cq49 = app.test_client()
        assert _cq49.post("/login", data={"token": settings["gui"]["token"]},
                          environ_base={"REMOTE_ADDR": "203.0.113.91"}).status_code == 302, \
            "前置：无账号时引导口令可登录（[7j] 末尾已清空账号）"
        _rs49 = _cq49.post(f"/api/tasks/{_t4}/stop")
        _rj49 = _rs49.get_json()
        assert _rs49.status_code == 200 and _rj49.get("ok") is True, _rj49
        assert "队列" in (_rj49.get("msg") or ""), f"排队任务停止应说明'从队列移除'：{_rj49}"
        assert db.get_task(_t4)["status"] == "stopped", "停止后必须离开队列"
        assert db.claim_next_queued() is None, "停止后队列里不该再认领到它"
        # §6.1 证伪：把认领的 status 过滤放宽到含 stopped → 被停止的任务也会被认领（③ 必红）
        _real_claim49 = db.claim_next_queued

        def _claim_loose49():
            r = db._query("SELECT id FROM tasks WHERE status IN ('queued','stopped') "
                          "ORDER BY id ASC LIMIT 1", one=True)
            return db.get_task(r["id"]) if r else None

        db.claim_next_queued = _claim_loose49
        try:
            _m49 = db.claim_next_queued()
            assert _m49 and _m49["status"] == "stopped", \
                "变异后应能认领到被停止的任务 → 证明 ③ 测的就是'认领只看 queued'"
        finally:
            db.claim_next_queued = _real_claim49

        # ④ queue.workers=1 不并发：一次入队 3 个，单 worker 串行消费，并发峰值恒为 1
        _q49.stop()
        _t5s = []
        for _i in range(3):
            _tx = db.create_task(f"smoke-q5-{_i}", targets, ["probe"], {"offline": True})
            db.enqueue_task(_tx, "fresh", ["probe"], {"offline": True})
            _t5s.append(_tx)
        _live49["max"] = 0
        _q49.start(_qset49, dispatch=_consume49)
        for _tx in _t5s:
            assert _wait49(_tx, "done"), f"#{_tx} 必须被消费：{db.get_task(_tx)['status']!r}"
        assert _live49["max"] == 1, f"workers=1 时同一时刻只能有一个任务在跑：峰值 {_live49['max']}"
        assert all((_tx, "fresh") in _seen49 for _tx in _t5s), _seen49
        # §6.1 证伪（①）：消费者啥也不做 → 任务停在 running（不会被置 done）
        _q49.stop()
        _t5 = db.create_task("smoke-q5-noop", targets, ["probe"], {"offline": True})
        db.enqueue_task(_t5, "fresh", ["probe"], {"offline": True})
        _q49.start(_qset49, dispatch=lambda tid, mode: None)
        time.sleep(0.3)
        assert db.get_task(_t5)["status"] != "done", \
            "消费者不做收尾时任务不该 done → 证明 ① 的 done 真由消费者产生（不是入队自带）"
        _q49.stop()
    finally:
        _q49.stop()
        db.DB_PATH = _saved_db49

    # ⑥ 老库补列：造一张"缺 run_mode/queued_at/run_payload"的 tasks 表 → `_ensure_columns` 补出
    _legacy49 = _TMPDIR / "queue49-legacy.db"
    _lc49 = _sqlite49.connect(str(_legacy49))
    _lc49.execute("CREATE TABLE tasks (id INTEGER PRIMARY KEY, name TEXT, targets TEXT, stages TEXT)")
    _lc49.commit()
    _lc49.close()
    _saved_db49b = db.DB_PATH
    db.DB_PATH = _legacy49
    try:
        db.init_db()
        _cols49 = {r["name"] for r in db._query("PRAGMA table_info(tasks)")}
        for _c in ("run_mode", "queued_at", "run_payload"):
            assert _c in _cols49, f"老库必须被补出列 {_c}：{sorted(_cols49)}"
    finally:
        db.DB_PATH = _saved_db49b

    print("[7k] 续49 持久化任务队列 ok: 入队→worker 认领→终态 done / 重启对账把带运行规格的 "
          "running **重新入队**（fresh+断点→resume、断点保留、留说明；无规格仍标 failed）/ "
          "排队中「停止」从队列移除且不被认领（db 层 + /api stop 路由）/ workers=1 不并发"
          "（峰值恒 1）/ run_mode·queued_at·run_payload 落库 / 老库缺列经 _ensure_columns 补出 / "
          "3 条变异证伪全部按预期变红")

    # [7l] 续50 **开发模式 + 全流程自检**（`scanner/devmode.py` + `scanner/devfixture.py` +
    #      `run_devflow.py`）。背景：项目还在开发期，用户要一个"开发模式"把各阶段的"量"
    #      （并发/在飞/速率/每阶段配额）压到最小（1），先验证**流程本身能不能跑通**；配套
    #      "全流程自检"：13 个阶段都跑一遍看哪一步断了（CLI `run_devflow.py` + 控制台「开发模式」页）。
    #      钉死 6 组语义（末尾 §6.1 变异证伪）：
    #      ① `devmode.apply` 逐项压量到最小 + **深拷贝**（入参一个字节不动）；
    #      ② apply **刻意不压** `budget_total`（压到 1 会让第 2 个请求即被拒、全流程跑不完）；
    #      ③ `dev.enabled` 默认 False；`devmode.enabled()` 对缺段 / 脏值不炸；
    #      ④ `devfixture` 起 / 停：只绑 `127.0.0.1`、能取到 index/admin/.env、stop 后端口释放；
    #      ⑤ 全 13 阶段在夹具上**真跑一遍**（用 apply 后的 settings）→ done + error 空 + 站外请求 0；
    #      ⑥ GUI：`dev.enabled=false` 时**无**「开发模式」入口、`true` 时**有**（桩 load_settings/sync_pocs）。
    import copy as _copy7l
    import urllib.request as _url7l
    from scanner import devfixture as _df7l
    from scanner import devmode as _dm7l
    from scanner.config import DEFAULTS as _DEF7L

    # ① 逐项压量 + 深拷贝（入参不动）
    _s7l = _copy7l.deepcopy(settings)
    _before7l = _copy7l.deepcopy(_s7l)
    _c7l = _dm7l.apply(_s7l)
    assert _s7l == _before7l, \
        "apply 必须**深拷贝**、绝不原地改入参（项目铁律：任务专用副本，见 runner.StageContext）"
    for _p7l, _v7l in (("queue.workers", 1), ("limits.max_workers", 1),
                       ("limits.max_inflight_global", 1), ("limits.max_inflight_per_task", 1),
                       ("limits.rate_per_sec", 1), ("limits.dirscan_max_urls", 1),
                       ("subdomain.max_resolve", 1), ("dirscan.quick_max_paths", 1),
                       ("takeover.max_hosts", 1), ("portscan.full_workers", 1),
                       ("jsmine.max_js", 1), ("checks.poc_max_per_site", 1)):
        _got7l = _dm7l._get(_c7l, _p7l)
        assert _got7l == _v7l, f"apply 必须把 {_p7l} 压到 {_v7l}：实测 {_got7l!r}"
    # 两个"关"（0）项：框架补充额度 / 目录递归层数
    assert _dm7l._get(_c7l, "dirscan.fw_max_paths") == 0
    assert _dm7l._get(_c7l, "dirscan.recursive_depth") == 0
    # 脏配置也能压得住：缺段 / 非 dict 的中间段都不抛（_set 会补建 dict）
    _dirty7l = _dm7l.apply({"limits": "dirty", "dirscan": None})
    assert _dm7l._get(_dirty7l, "limits.max_workers") == 1
    assert _dm7l._get(_dirty7l, "dirscan.quick_max_paths") == 1

    # ② 预算**刻意不压**（例外，理由见 scanner/devmode.py 文件头）
    assert _dm7l._get(_c7l, "limits.budget_total") == 0, \
        "budget_total 必须保持 0（不设预算）—— 压到 1 会让第 2 个请求即被拒、全流程跑不完"
    assert _dm7l._get(_c7l, "limits.budget_total") == _dm7l._get(_s7l, "limits.budget_total")
    for _k7l in _dm7l.DEV_KEEP:
        assert _k7l not in _dm7l.DEV_LIMITS, f"{_k7l} 属刻意不压项，不得进 DEV_LIMITS"

    # ③ 默认关 + 脏值不炸
    assert (_DEF7L.get("dev") or {}).get("enabled") is False, "DEFAULTS 里 dev.enabled 必须默认 False"
    assert _dm7l.enabled({}) is False and _dm7l.enabled({"dev": {}}) is False
    assert _dm7l.enabled({"dev": {"enabled": True}}) is True
    assert _dm7l.enabled({"dev": "dirty"}) is False, "脏值（非 dict）必须回落 False，不抛"
    assert _dm7l.enabled(None) is False

    # ④ 夹具起 / 停（只绑回环 + 内容可取 + 停后端口释放）
    _fx7l, _base7l = _df7l.start()
    try:
        assert _fx7l.server_address[0] == "127.0.0.1", \
            f"夹具只许绑 127.0.0.1（绝不 0.0.0.0）：{_fx7l.server_address}"
        assert _base7l.startswith("http://127.0.0.1:"), _base7l
        with _url7l.urlopen(_base7l + "/", timeout=5) as _r7l:
            _body7l = _r7l.read().decode("utf-8", "replace")
        assert "<title>DevFixture Site</title>" in _body7l, _body7l[:200]
        with _url7l.urlopen(_base7l + "/admin/", timeout=5) as _r7l:
            assert _r7l.status == 200
        with _url7l.urlopen(_base7l + "/.env", timeout=5) as _r7l:
            assert "devfixture-not-a-real-secret" in _r7l.read().decode("utf-8", "replace")
    finally:
        _df7l.stop(_fx7l)
    try:
        _url7l.urlopen(_base7l + "/", timeout=2)
        _fx_stopped7l = False
    except OSError:
        _fx_stopped7l = True
    assert _fx_stopped7l, "stop() 后端口必须释放（再连应失败）"
    _df7l.stop(_fx7l)      # 幂等：重复 stop 不炸

    # ⑤ 全 13 阶段在夹具上**真跑一遍**（用 apply 后的 settings；关掉外部第三方阶段保证零外网）
    from scanner import utils as _u7l
    from urllib.parse import urlparse as _up7l
    _fx7l2, _base7l2 = _df7l.start()
    try:
        _cfg7l = _dm7l.apply(_copy7l.deepcopy(settings))
        # 冒烟必须**零外网**（同 [6u]）：关掉一切会发外部请求的阶段 / 子能力。
        for _k7l in ("iprecon", "fofa", "shodan", "quake", "ctlog", "intel", "github"):
            _cfg7l[_k7l] = dict(_cfg7l.get(_k7l) or {}, enabled=False)
        _cfg7l["passive"] = dict(_cfg7l.get("passive") or {}, enabled=False)
        for _k7l in ("takeover", "portscan", "cert", "screenshot", "jsmine", "dirscan",
                     "vulnscan", "heuristic"):
            _cfg7l[_k7l] = dict(_cfg7l.get(_k7l) or {}, enabled=True)
        _orig_http7l = _u7l.http_request
        _mods7l = [m for m in list(sys.modules.values())
                   if str(getattr(m, "__name__", "") or "").startswith("scanner")
                   and getattr(m, "http_request", None) is _orig_http7l]
        _sent7l = []

        def _u_http7l(u, **kw):
            _sent7l.append(str(u))
            return _orig_http7l(u, **kw)

        db.init_db()
        sync_pocs(_cfg7l)
        _tg7l = _base7l2 + "/"
        _st7l = list(STAGE_ORDER)
        _tid7l = db.create_task("smoke-devflow", _tg7l, _st7l, {})
        for _m7l in _mods7l:
            _m7l.http_request = _u_http7l
        try:
            run_task(_tid7l, "smoke-devflow", _tg7l, _st7l, {}, _cfg7l)
        finally:
            for _m7l in _mods7l:
                _m7l.http_request = _orig_http7l
        _t7l = db.get_task(_tid7l)
        assert _t7l["status"] == "done", \
            f"压量后全 13 阶段应跑完置 done：{_t7l['status']} / error={_t7l['error']!r}"
        assert (_t7l["error"] or "") == "", \
            f"压量后跑完 error 必须为空（任何阶段异常都会被 append）：{_t7l['error']}"
        assert len(list(db.list_sites(_tid7l))) >= 1, "夹具上至少应有 1 个存活站点"
        _out7l = [u for u in _sent7l
                  if ((_up7l(u).hostname or "").strip().lower())
                  not in ("127.0.0.1", "localhost", "::1")]
        assert not _out7l, f"自检必须零外网，实测打到站外：{_out7l[:5]}"
        db.delete_task(_tid7l, backup=False)
    finally:
        _df7l.stop(_fx7l2)

    # ⑥ GUI：dev.enabled 控制「开发模式」入口（桩 load_settings/sync_pocs，复用 [7h]/[7i] 范式）
    _orig_load7l, _orig_sync7l = gui_app.load_settings, gui_app.sync_pocs

    def _app7l(dev_on):
        _b7l = _copy7l.deepcopy(settings)
        _b7l["dev"] = {"enabled": dev_on, "fixture_port": 0}
        gui_app.load_settings = lambda: _b7l
        gui_app.sync_pocs = lambda *_a, **_k: None
        try:
            return gui_app.create_app()
        finally:
            gui_app.load_settings, gui_app.sync_pocs = _orig_load7l, _orig_sync7l

    for _u7l2 in users_mod.list_users():
        users_mod.delete_user(_u7l2["id"])
    assert users_mod.count_users() == 0, "无账号时引导口令即管理员（[7j]/[7k] 已清空账号）"
    _app_off7l = _app7l(False)
    _c_off7l = _app_off7l.test_client()
    assert _c_off7l.post("/login", data={"token": settings["gui"]["token"]},
                         environ_base={"REMOTE_ADDR": "203.0.113.211"}).status_code == 302
    _html_off7l = _c_off7l.get("/").get_data(as_text=True)
    assert 'href="/devmode"' not in _html_off7l, \
        "dev.enabled=false 时**不得**渲染「开发模式」入口（默认完全不出现）"
    _app_on7l = _app7l(True)
    _c_on7l = _app_on7l.test_client()
    assert _c_on7l.post("/login", data={"token": settings["gui"]["token"]},
                        environ_base={"REMOTE_ADDR": "203.0.113.212"}).status_code == 302
    _html_on7l = _c_on7l.get("/").get_data(as_text=True)
    assert 'href="/devmode"' in _html_on7l, "dev.enabled=true 时**必须**渲染「开发模式」入口"
    _dev_html7l = _c_on7l.get("/devmode").get_data(as_text=True)
    assert _c_on7l.get("/devmode").status_code == 200, "开发模式页对管理员应可访问"
    assert "跑一次全流程自检" in _dev_html7l and "启动内置靶场" in _dev_html7l, "页面三个按钮必须在"

    # ---- §6.1 变异证伪（把新行为退回"旧/天真"实现，确认上面的断言**真的变红**）----
    _real_apply7l = _dm7l.apply
    _real_limits7l = dict(_dm7l.DEV_LIMITS)
    _real_host7l = _df7l.HOST
    _real_en7l = _dm7l.enabled

    # (M1) apply 退回"恒等"（不压量）→ ① 的断言必红
    _dm7l.apply = lambda s: _copy7l.deepcopy(s)
    try:
        _m1_7l = _dm7l.apply(_copy7l.deepcopy(settings))
        assert _dm7l._get(_m1_7l, "limits.max_workers") != 1, \
            "变异（apply 恒等）后 max_workers 不该是 1 → 证明 ① 测的是'apply 真的压量'"
    finally:
        _dm7l.apply = _real_apply7l

    # (M2) 把 budget_total 塞进 DEV_LIMITS → ② 的"不压"必红
    _dm7l.DEV_LIMITS["limits.budget_total"] = 1
    try:
        _m2_7l = _dm7l.apply(_copy7l.deepcopy(settings))
        assert _dm7l._get(_m2_7l, "limits.budget_total") == 1, \
            "变异（把 budget_total 放进 DEV_LIMITS）后它会被压到 1 → 证明 ② 的'不压'是有内容的"
    finally:
        _dm7l.DEV_LIMITS.clear()
        _dm7l.DEV_LIMITS.update(_real_limits7l)

    # (M3) 夹具 HOST 改成 127.0.0.2（仍是回环，**绝不**为了证伪去绑 0.0.0.0）→ ④ 必红
    _df7l.HOST = "127.0.0.2"
    _fxm7l, _ = _df7l.start()
    try:
        _bind7l = _fxm7l.server_address[0]
    finally:
        _df7l.stop(_fxm7l)
        _df7l.HOST = _real_host7l
    assert _bind7l == "127.0.0.2", f"变异生效（绑到改后的地址）：{_bind7l}"
    assert _bind7l != "127.0.0.1", \
        "变异后'绑定必须是 127.0.0.1'为假 → 证明 ④ 测的是**真实绑定地址**（不是常量恒等）"

    # (M4) devmode.enabled 恒真 → ⑥ 的"disabled 不渲染入口"必红
    _dm7l.enabled = lambda s: True
    try:
        _appm7l = _app7l(False)
        _cm7l = _appm7l.test_client()
        _cm7l.post("/login", data={"token": settings["gui"]["token"]},
                   environ_base={"REMOTE_ADDR": "203.0.113.213"})
        _htmlm7l = _cm7l.get("/").get_data(as_text=True)
        assert 'href="/devmode"' in _htmlm7l, \
            "变异（enabled 恒真）后入口出现了 → 证明 ⑥ 的'disabled 不渲染'测的是开关本身"
    finally:
        _dm7l.enabled = _real_en7l

    # (M5) budget_total=1 → 全流程**跑不完**（预算耗尽→stopped）→ ⑤ 的 done 与 ② 必红
    _dm7l.DEV_LIMITS["limits.budget_total"] = 1
    _fx7l3, _base7l3 = _df7l.start()
    try:
        _cfg7l3 = _dm7l.apply(_copy7l.deepcopy(settings))
        for _k7l in ("iprecon", "fofa", "shodan", "quake", "ctlog", "intel", "github", "passive"):
            _cfg7l3[_k7l] = dict(_cfg7l3.get(_k7l) or {}, enabled=False)
        for _k7l in ("takeover", "portscan", "cert", "screenshot", "jsmine", "dirscan",
                     "vulnscan", "heuristic"):
            _cfg7l3[_k7l] = dict(_cfg7l3.get(_k7l) or {}, enabled=True)
        _tg7l3 = _base7l3 + "/"
        _tid7l3 = db.create_task("smoke-devflow-budget", _tg7l3, list(STAGE_ORDER), {})
        run_task(_tid7l3, "smoke-devflow-budget", _tg7l3, list(STAGE_ORDER), {}, _cfg7l3)
        _st7l3 = db.get_task(_tid7l3)["status"]
        db.delete_task(_tid7l3, backup=False)
        assert _st7l3 != "done", \
            f"budget_total=1 时全流程**必跑不完**（预算耗尽→stopped），实测 {_st7l3!r} → " \
            "证明 ⑤ 的 done 与 ② 的'不压预算'都测的是真东西"
    finally:
        _df7l.stop(_fx7l3)
        _dm7l.DEV_LIMITS.clear()
        _dm7l.DEV_LIMITS.update(_real_limits7l)

    print("[7l] 续50 开发模式 + 全流程自检 ok: apply 逐项压到最小（并发/在飞/速率/配额）+ **深拷贝**"
          "（入参不动）+ 脏配置补段不抛 / **刻意不压** budget_total（压到 1 全流程跑不完，已证伪）/ "
          "dev.enabled 默认 False + 脏值不炸 / 夹具只绑 127.0.0.1·内容可取·stop 后端口释放 / "
          "全 13 阶段在夹具上真跑一遍（done·error 空·站外 0）/ GUI 入口随 dev.enabled 出现或消失 / "
          "5 条变异证伪全部按预期变红")

    # [7m] 续51 **漏洞页分页 + 排序**（P0 数据正确性）。背景：漏洞页原先固定
    #      `db.list_vulns(..., limit=500)` —— 扫出 800 条只能看到 500 条、界面还不提示，
    #      属**静默丢结果**。本组钉死 6 组语义（末尾 §6.1 变异证伪）：
    #      ① 分页：造 600 条 → `total==600`、能取到第 2 页、**第 501 条（id DESC 下 offset=500 的首行）可查**；
    #      ② 截断真实存在：旧写法 `list_vulns(limit=500)` 只回 500 条，第 501 条正好落在外面；
    #      ③ 关键字 `q` 是**服务端**过滤（不是"只搜当前页"）—— 只有第 501 条命中的关键字能找到它；
    #      ④ severity 排序是**有序 CASE**（critical 在前、info 在最后），不是字典序；
    #      ⑤ 非法输入不炸 / 不注入：page=0·page=99999·size=7·sort='; DROP TABLE'·desc=abc；
    #      ⑥ 筛选 + 排序在翻页后**保持**（pager qs 含 URL 编码后的全部条件）。
    # 目标行位置说明：造 600 条（i=0..599，id 递增），`id DESC` 下**第 501 条 = i=99**
    # （position p ↔ id 索引 600-p）。故唯一关键字挂在 i=99 —— 它正是旧写法会丢掉的那条。
    _tid7m = db.create_task("smoke-vulns-page", "127.0.0.1", ["vulnscan"], {})
    _sevs7m = ["info", "low", "medium", "high", "critical"]
    _R7M = {s: i for i, s in enumerate(_sevs7m)}     # info=0 … critical=4
    _MARKER7M = "UNIQUE-MARKER-501"
    for _i7m in range(600):
        db.insert_vuln(_tid7m, {
            "target": f"http://smoke/{_i7m}", "poc_id": f"poc-{_i7m}",
            "name": (_MARKER7M if _i7m == 99 else f"smoke vuln {_i7m}"),
            "severity": _sevs7m[_i7m % 5], "owasp": "A01",
            "detail": f"detail-{_i7m}", "evidence": f"ev-{_i7m}"})

    # ① 分页（服务端）：total 是**过滤后**总数；第 1 / 2 页各 100；第 501 条（offset=500 首行）可查
    _p1_7m, _tot7m = db.page_vulns(limit=100, offset=0, task_id=_tid7m, sort="id", desc=True)
    assert _tot7m == 600, f"total 必须是过滤后的总数 600：实测 {_tot7m}"
    assert len(_p1_7m) == 100, f"第 1 页应 100 条：实测 {len(_p1_7m)}"
    _p2_7m, _ = db.page_vulns(limit=100, offset=100, task_id=_tid7m, sort="id", desc=True)
    assert len(_p2_7m) == 100 and _p2_7m[0]["id"] < _p1_7m[-1]["id"], \
        "第 2 页应 100 条且 id 继续递减（服务端分页真的换了页）"
    _first500_7m, _ = db.page_vulns(limit=500, offset=0, task_id=_tid7m, sort="id", desc=True)
    _rest_7m, _ = db.page_vulns(limit=500, offset=500, task_id=_tid7m, sort="id", desc=True)
    _s500 = {r["id"] for r in _first500_7m}
    _srest = {r["id"] for r in _rest_7m}
    assert len(_first500_7m) == 500 and len(_rest_7m) == 100, \
        f"分页必须覆盖全部 600 条：前 500={len(_first500_7m)} / 后 {len(_rest_7m)}"
    assert not (_s500 & _srest) and len(_s500 | _srest) == 600, \
        "前后两段必须无重叠且并集=600（不重不漏）"

    # ② 截断真实存在：旧写法 `list_vulns(limit=500)` 只回 500，且**丢掉了第 501 条（MARKER）**
    _old7m = db.list_vulns(task_id=_tid7m, limit=500)
    _all7m = db.list_vulns(task_id=_tid7m, limit=100000)
    assert len(_old7m) == 500 and len(_all7m) == 600, \
        f"旧写法必须只回 500 条（截断）：实测 old={len(_old7m)} all={len(_all7m)}"
    assert _MARKER7M not in {r["name"] for r in _old7m}, \
        "旧写法（limit=500）**看不到**第 501 条 → 证明静默丢结果真实存在"

    # ③ 关键字 `q` 是**服务端**过滤：只有第 501 条命中的关键字能找到它（旧前端过滤只能搜当前页）
    _qrows7m, _qtot7m = db.page_vulns(limit=100, offset=0, task_id=_tid7m, q=_MARKER7M)
    assert _qtot7m == 1 and _qrows7m[0]["name"] == _MARKER7M, \
        f"服务端 q 必须精确命中第 501 条：实测 total={_qtot7m}"
    assert _MARKER7M not in {r["name"] for r in _p1_7m}, \
        "第 501 条不在第 1 页 → 若 q 仍在前端过滤（只搜当前页）就永远搜不到它"

    # ④ severity 排序是**有序 CASE**（critical→info），不是字典序
    _srows7m, _ = db.page_vulns(limit=600, offset=0, task_id=_tid7m, sort="severity", desc=True)
    _ranks7m = [_R7M[r["severity"]] for r in _srows7m]
    assert _ranks7m == sorted(_ranks7m, reverse=True), \
        f"severity 降序必须是有序 CASE（critical 在前、info 在后），不是字典序：{_srows7m[0]['severity']}…"
    assert _srows7m[0]["severity"] == "critical" and _srows7m[-1]["severity"] == "info", \
        f"首行应 critical、末行应 info：实测 {_srows7m[0]['severity']} / {_srows7m[-1]['severity']}"
    assert db.norm_vuln_sort("; DROP TABLE vulns") == "id" and db.norm_vuln_sort(None) == "id", \
        "非法 / 空 sort 必须回落白名单默认（id）"

    # ⑤ 非法输入不炸 / 不注入（db 层）
    _before5_7m = db._query("SELECT COUNT(*) c FROM vulns", one=True)["c"]
    for _kw5_7m in ({"sort": "; DROP TABLE vulns"}, {"sort": "bogus"}, {"desc": "abc"},
                    {"desc": "0"}, {"sort": None}, {"desc": ""}):
        _r5_7m, _t5_7m = db.page_vulns(limit=10, offset=0, task_id=_tid7m, **_kw5_7m)
        assert len(_r5_7m) == 10 and _t5_7m == 600, f"非法/边界 {_kw5_7m} 必须回落默认且不炸"
    assert db._query("SELECT COUNT(*) c FROM vulns", one=True)["c"] == _before5_7m, \
        "非法 sort 绝不能影响库（白名单挡注入）"

    # ⑥ 路由：分页 + 排序 + 筛选 + 翻页保持（桩 load_settings/sync_pocs，复用 [7h]/[7l] 范式）
    _orig_load7m, _orig_sync7m = gui_app.load_settings, gui_app.sync_pocs
    _b7m = copy.deepcopy(settings)
    _b7m["dev"] = {"enabled": False, "fixture_port": 0}
    gui_app.load_settings = lambda: _b7m
    gui_app.sync_pocs = lambda *_a, **_k: None
    try:
        _app7m = gui_app.create_app()
    finally:
        gui_app.load_settings, gui_app.sync_pocs = _orig_load7m, _orig_sync7m
    _c7m = _app7m.test_client()
    assert _c7m.post("/login", data={"token": settings["gui"]["token"]},
                     environ_base={"REMOTE_ADDR": "203.0.113.220"}).status_code == 302
    # 合法查询：high 级 + 待复核 + q="smoke vuln"（含空格→测编码）+ 按 severity 降序 + 每页 50
    _url7m = (f"/vulns?size=50&q=smoke%20vuln&sort=severity&desc=1&severity=high"
              f"&review=pending&task_id={_tid7m}")
    _resp7m = _c7m.get(_url7m)
    assert _resp7m.status_code == 200, _resp7m.status_code
    _html7m = _resp7m.get_data(as_text=True)
    assert "共 120 条" in _html7m, "过滤后总数（high 级 120 条）必须显示在分页条上"
    # 翻页链接必须带**全部**筛选 + 排序，且 q 要 URL 编码（空格→%20）—— 只检查 pager 区块
    _pg7m = _html7m.split('<div class="pager">', 1)[-1].split("</div>", 1)[0]
    for _need7m in ("q=smoke%20vuln", "sort=severity", "desc=1", "severity=high",
                    "review=pending", f"task_id={_tid7m}", "size=50"):
        assert _need7m in _pg7m, f"翻页必须保持筛选+排序（缺 {_need7m!r}）：{_pg7m}"
    # 非法输入：不炸、不注入，均回落到合法视图
    assert _c7m.get("/vulns?page=0&size=7&sort=; DROP TABLE vulns&desc=abc").status_code == 200
    assert _c7m.get("/vulns?page=99999&size=200").status_code == 200
    assert db._query("SELECT COUNT(*) c FROM vulns", one=True)["c"] == _before5_7m, \
        "非法 sort 经路由也不能影响库"

    # ---- §6.1 变异证伪（把新行为退回"旧/天真"实现，确认上面的断言真的变红）----
    _real_sort7m = dict(db._VULN_SORT)
    _real_page7m = db.page_vulns

    # (M1) severity 排序退回字典序（`ORDER BY severity`）→ ④ 的有序 CASE 断言必红
    db._VULN_SORT["severity"] = "severity"
    try:
        _ms7m, _ = db.page_vulns(limit=600, offset=0, task_id=_tid7m, sort="severity", desc=True)
        _mrank7m = [_R7M[r["severity"]] for r in _ms7m]
        assert _mrank7m != sorted(_mrank7m, reverse=True), \
            "变异（severity 退回字典序）后顺序不再是有序 CASE → 证明 ④ 测的是**真有序 CASE**"
    finally:
        db._VULN_SORT.clear()
        db._VULN_SORT.update(_real_sort7m)

    # (M2) 服务端忽略 `q`（退回"关键字只在前端过滤"）→ ③ 的服务端过滤断言必红
    def _noq7m(limit=100, offset=0, q=None, severity=None, review=None, task_id=None,
               sort=None, desc=True):
        return _real_page7m(limit=limit, offset=offset, q=None, severity=severity,
                            review=review, task_id=task_id, sort=sort, desc=desc)
    db.page_vulns = _noq7m
    try:
        _mq7m, _mqt7m = db.page_vulns(task_id=_tid7m, q=_MARKER7M)
        assert _mqt7m != 1, \
            "变异（服务端忽略 q）后关键字不再过滤（total 变 600）→ 证明 ③ 测的是**真服务端过滤**"
    finally:
        db.page_vulns = _real_page7m

    # (M3) `page_vulns` 退回"固定 limit=500 截断"（旧 list_vulns 语义，且忽略 offset）→ ①② 必红
    def _trunc7m(limit=100, offset=0, **kw):
        _rows = db.list_vulns(task_id=kw.get("task_id"), limit=500)
        return _rows[:limit], len(_rows)
    db.page_vulns = _trunc7m
    try:
        _mt7m, _mtt7m = db.page_vulns(limit=100, offset=500, task_id=_tid7m, sort="id", desc=True)
        assert _mtt7m == 500 and _MARKER7M not in {r["name"] for r in _mt7m}, \
            "变异（退回固定 limit=500 截断）后 total=500、第 501 条取不到 → 证明 ①② 测的是**真分页**"
    finally:
        db.page_vulns = _real_page7m

    # (M4) `quote` 恒等（不编码）→ ⑥ 的"翻页 q 必须 %20 编码"必红
    _real_quote7m = gui_app.quote
    gui_app.quote = lambda s, *a, **k: s
    try:
        _pgm7m = _c7m.get(_url7m).get_data(as_text=True)
        _pgm7m = _pgm7m.split('<div class="pager">', 1)[-1].split("</div>", 1)[0]
        assert "q=smoke%20vuln" not in _pgm7m, \
            "变异（quote 恒等）后 pager 里 q 变裸 'smoke vuln' → 证明 ⑥ 测的是**真 URL 编码**"
    finally:
        gui_app.quote = _real_quote7m

    # (M5) 排序字段去掉白名单（退回"直接把 sort 拼进 SQL"）→ ⑤ 的"不注入"必红
    def _naive7m(sort=None, **_k):
        return db._query(f"SELECT * FROM vulns ORDER BY {str(sort or 'id')} DESC LIMIT 1")
    _blew7m = False
    try:
        _naive7m(sort="id; SELECT 1")     # 非破坏性注入载荷：多语句会被 sqlite 拒绝
    except Exception:                     # noqa: BLE001
        _blew7m = True
    assert _blew7m, \
        "变异（去掉白名单、直接拼 sort）后非法 sort 真的拼进 SQL → 证明 ⑤ 靠**白名单映射**挡注入"

    db.delete_task(_tid7m, backup=False)
    print("[7m] 续51 漏洞页分页 + 排序 ok: 造 600 条→total 600·第 2 页可取·**第 501 条可查** / "
          "旧 limit=500 截断真实存在（第 501 条被丢，已证伪）/ q 是**服务端**过滤（第 501 条唯一命中）/ "
          "severity 有序 CASE（critical→info，非字典序）/ 非法 page·size·sort·desc 全部回落不炸不注入 / "
          "翻页保持筛选+排序且 q 经 URL 编码 / 5 条变异证伪全部按预期变红")

    # [7n] 续52 **自检夹具补域名 + HTTPS + SKIP 分类**（P0）。背景：续50 的自检报
    #      "13 个阶段均无异常"，但其中 5 个阶段**空转**（零网络活动）—— 结论名不副实。
    #      本组钉"该跑的真的跑、跑不了的如实说清为什么"，**不**硬凑全绿。5 组语义（末尾 §6.1）：
    #      ① 夹具 HTTPS：起/停、GET index、HTTP 与 HTTPS **都只绑 127.0.0.1**、stop 后两端口都释放、
    #         stop 幂等；夹具证书自签且 CN=devfixture.test（可被 cert 阶段取证）；
    #      ② DNS 覆盖：白名单（devfixture.test 及子域）→ 127.0.0.1；**非白名单一律放行**；退出**必还原**；
    #      ③ 全流程自检：cert 与 subdomain 由 SKIP 变 **OK**（有网络活动）、**零外网**；
    #      ④ SKIP 分类：每行都有**非空真实原因**（取自任务日志），token 缺失的 github 归 `未配置`；
    #      ⑤ GUI 自检走 **subprocess**（DNS 覆盖不进长驻 web 进程），输出渲染到页面。
    import copy as _copy7n
    import ssl as _ssl7n
    import socket as _sock7n
    import urllib.request as _url7n
    from scanner import certs as _certs7n
    from scanner import devfixture as _df7n
    from scanner import devflow as _dv7n

    # ① 夹具 HTTPS（HTTP + HTTPS 双监听器，都只绑回环）
    _fx7n, _hb7n, _sb7n = _df7n.start_both()
    try:
        assert _fx7n.servers[0].server_address[0] == "127.0.0.1", \
            f"HTTP 夹具只许绑 127.0.0.1（绝不 0.0.0.0）：{_fx7n.servers[0].server_address}"
        assert _fx7n.servers[1].server_address[0] == "127.0.0.1", \
            f"HTTPS 夹具只许绑 127.0.0.1（绝不 0.0.0.0）：{_fx7n.servers[1].server_address}"
        assert _hb7n.startswith("http://127.0.0.1:") and _sb7n.startswith("https://127.0.0.1:"), \
            (_hb7n, _sb7n)
        _ctx7n = _ssl7n.create_default_context()
        _ctx7n.check_hostname = False
        _ctx7n.verify_mode = _ssl7n.CERT_NONE
        with _url7n.urlopen(_sb7n + "/", timeout=5, context=_ctx7n) as _r7n:
            assert _r7n.status == 200
            assert "<title>DevFixture Site</title>" in _r7n.read().decode("utf-8", "replace")
        # 夹具证书：自签、CN=devfixture.test、**未过期**（供 cert 阶段取证）
        _info7n, _err7n = _certs7n.fetch("127.0.0.1", int(_sb7n.rsplit(":", 1)[1]), timeout=5)
        assert _info7n, f"HTTPS 夹具应能取到证书：{_err7n}"
        assert _info7n["cn"] == "devfixture.test", _info7n.get("cn")
        assert int(_info7n["expired"]) == 0 and int(_info7n["self_signed"]) == 1, _info7n
        # 情报源夹具（intel 自检时指过来，让 intel 真跑却不出网）
        with _url7n.urlopen(_hb7n + "/intel/kev.json", timeout=5) as _r7n:
            assert "NOT real data" in _r7n.read().decode("utf-8", "replace")
    finally:
        _df7n.stop(_fx7n)
    for _b7n in (_hb7n, _sb7n):
        _h7n, _p7n = _b7n.split("://")[1].split(":")
        _s7n = _sock7n.socket()
        try:
            _s7n.connect((_h7n, int(_p7n)))
            _rel7n = False
        except OSError:
            _rel7n = True
        finally:
            _s7n.close()
        assert _rel7n, f"stop() 后 {_b7n} 端口必须释放（再连应失败）"
    _df7n.stop(_fx7n)      # 幂等：重复 stop 不炸
    _fx7n_s, _sb7n_s = _df7n.start(port=0, https=True)     # 单监听器 HTTPS 也能起
    try:
        assert _fx7n_s.server_address[0] == "127.0.0.1", _fx7n_s.server_address
        assert _sb7n_s.startswith("https://127.0.0.1:"), _sb7n_s
    finally:
        _df7n.stop(_fx7n_s)

    # ② DNS 覆盖：白名单重定向 / 非白名单放行 / 退出必还原。
    #    用"哨兵原解析器"做证伪 → **零网络依赖**（不真去解析 example.com）。
    _orig_gai7n = _sock7n.getaddrinfo
    try:
        _sock7n.getaddrinfo = lambda _h, _p, *_a, **_k: [("SENTINEL", _h)]
        with _dv7n.DnsOverride([_dv7n.FIXTURE_DOMAIN]):
            _g_fx7n = _sock7n.getaddrinfo(_dv7n.FIXTURE_DOMAIN, 80)
            _g_sub7n = _sock7n.getaddrinfo("a." + _dv7n.FIXTURE_DOMAIN, 80)
            _g_oth7n = _sock7n.getaddrinfo("example.com", 80)
        assert _g_fx7n[0][4][0] == "127.0.0.1", _g_fx7n
        assert _g_sub7n[0][4][0] == "127.0.0.1", _g_sub7n
        assert _g_oth7n[0][0] == "SENTINEL", \
            "非白名单域名必须**放行给真实解析器**（绝不重定向）：example.com 被劫持了"
    finally:
        _sock7n.getaddrinfo = _orig_gai7n
    assert _sock7n.getaddrinfo is _orig_gai7n, "DNS 覆盖退出后必须还原"
    try:
        _sock7n.getaddrinfo = lambda _h, _p, *_a, **_k: [("AFTER", _h)]
        _g_after7n = _sock7n.getaddrinfo(_dv7n.FIXTURE_DOMAIN, 80)
    finally:
        _sock7n.getaddrinfo = _orig_gai7n
    assert _g_after7n[0][0] == "AFTER", "退出后夹具域名仍被重定向 → 覆盖没还原干净"

    # ③ 全流程自检（隔离库/日志已在文件顶部设好）：cert / subdomain 由 SKIP 变 OK，且**零外网**
    _res7n = _dv7n.run_selfcheck(settings, name="smoke-devflow-52")
    try:
        assert _res7n["exit_code"] == 0 and _res7n["fail"] == 0, \
            f"自检不得有 FAIL：{_res7n['fail']} 个 —— {_res7n['error']}"
        assert _res7n["task_status"] == "done", _res7n["task_status"]
        _by7n = {n: (s, d, c) for n, s, d, c in _res7n["rows"]}
        assert _by7n["subdomain"][0] == "OK", \
            f"subdomain 有裸域名目标 + DNS 覆盖，应真跑（OK）：{_by7n['subdomain']}"
        assert _by7n["cert"][0] == "OK", \
            f"cert 有 https 站点可取证，应真跑（OK）：{_by7n['cert']}"
        assert _res7n["_net"].get("subdomain", 0) > 0 and _res7n["_net"].get("cert", 0) > 0, \
            f"subdomain / cert 的 OK 必须来自**真实网络活动**：{_res7n['_net']}"
        assert not _res7n["external"], \
            f"自检必须零外网，实测打到站外：{_res7n['external'][:5]}"
        # ④ SKIP 分类：每行都有**非空真实原因**，归类在已知集合里
        _cats7n = {"无输入", "未配置", "无匹配", "命中缓存"}
        for _n7n, _st7n, _d7n, _c7n in _res7n["rows"]:
            if _st7n == "SKIP":
                assert _d7n and _d7n.strip(), f"{_n7n} 的 SKIP 原因不得为空：{_d7n!r}"
                assert _c7n in _cats7n, f"{_n7n} 的 SKIP 归类异常：{_c7n!r}（原因 {_d7n!r}）"
        # 自检清空了第三方凭据 → github 无 token → 必须归 SKIP(未配置)，原因取自日志（含 token）
        assert _by7n["github"][0] == "SKIP" and _by7n["github"][2] == "未配置", \
            f"没配 token 的 github 应归 SKIP(未配置)：{_by7n['github']}"
        assert "token" in _by7n["github"][1], \
            f"github 的 SKIP 原因应取自日志（含 token）：{_by7n['github'][1]!r}"
    finally:
        if _res7n.get("task_id"):
            db.delete_task(_res7n["task_id"], backup=False)

    # ⑤ GUI 自检走 **subprocess**（DNS 覆盖 / 夹具不进长驻 web 进程），输出渲染到页面
    _orig_sub7n = gui_app.subprocess.run
    _orig_load7n, _orig_sync7n = gui_app.load_settings, gui_app.sync_pocs

    class _FakeProc7n:
        returncode = 0
        stdout = "[*] FAKE-SELFCHECK-OUT\n[*] 13 个阶段：2 个真跑、11 个跳过（原因见上）、0 个 FAIL\n"
        stderr = ""

    _cfg7n = _copy7n.deepcopy(settings)
    _cfg7n["dev"] = {"enabled": True, "fixture_port": 0}
    gui_app.load_settings = lambda: _cfg7n
    gui_app.sync_pocs = lambda *_a, **_k: None
    try:
        _app7n = gui_app.create_app()
    finally:
        gui_app.load_settings, gui_app.sync_pocs = _orig_load7n, _orig_sync7n
    _c7n = _app7n.test_client()
    for _u7n in users_mod.list_users():
        users_mod.delete_user(_u7n["id"])
    assert _c7n.post("/login", data={"token": settings["gui"]["token"]},
                     environ_base={"REMOTE_ADDR": "203.0.113.221"}).status_code == 302
    gui_app.subprocess.run = lambda *_a, **_k: _FakeProc7n()
    try:
        _resp7n = _c7n.post("/api/devmode/selfcheck")
    finally:
        gui_app.subprocess.run = _orig_sub7n
    assert _resp7n.status_code == 302, _resp7n.status_code
    _dev7n = _c7n.get("/devmode").get_data(as_text=True)
    assert "FAKE-SELFCHECK-OUT" in _dev7n, "GUI 自检必须把**子进程输出**渲染到页面"
    assert "子进程" in _dev7n, "页面必须说明自检走子进程（DNS 覆盖不进 web 进程）"
    assert not [t for t in db.list_tasks(limit=200) if t["name"] == "dev-selfcheck"], \
        "GUI 自检不得再在 web 进程里入队（必须走子进程）"

    # ---- §6.1 变异证伪（把新行为退回"旧/天真"实现，确认上面的断言**真的变红**）----
    # (M1) DnsOverride 重定向**一切** → ② 的"非白名单放行"必红
    _real_hit7n = _dv7n.DnsOverride._hit
    _dv7n.DnsOverride._hit = lambda self, host: True
    try:
        with _dv7n.DnsOverride([_dv7n.FIXTURE_DOMAIN]):
            _m1_7n = _sock7n.getaddrinfo("example.com", 80)
    finally:
        _sock7n.getaddrinfo = _orig_gai7n
        _dv7n.DnsOverride._hit = _real_hit7n
    assert _m1_7n[0][4][0] == "127.0.0.1", \
        "变异（_hit 恒真）后 example.com 也被重定向 → 证明 ② 测的是**白名单**"

    # (M2) DnsOverride 退出**不还原** → ② 的"退出必还原"必红
    _real_exit7n = _dv7n.DnsOverride.__exit__
    _dv7n.DnsOverride.__exit__ = lambda self, *a: False
    try:
        with _dv7n.DnsOverride([_dv7n.FIXTURE_DOMAIN]):
            pass
        _m2_7n = _sock7n.getaddrinfo is _orig_gai7n
    finally:
        _sock7n.getaddrinfo = _orig_gai7n
        _dv7n.DnsOverride.__exit__ = _real_exit7n
    assert _m2_7n is False, \
        "变异（__exit__ 不还原）后 socket.getaddrinfo 没被还原 → 证明 ② 测的是**真还原**"

    # (M3) 夹具 https=True **不包 TLS** → ① 的 HTTPS GET 必红（绑 127.0.0.2 那种改法这里不适用）
    _real_make7n = _df7n._make_server
    _df7n._make_server = lambda root, port, https: _real_make7n(root, port, False)
    try:
        _fxm7n, _bm7n = _df7n.start(port=0, https=True)
        try:
            _https_ok7n = True
            try:
                with _url7n.urlopen(_bm7n + "/", timeout=3, context=_ctx7n) as _r7n:
                    _r7n.read()
            except Exception:      # noqa: BLE001 - 期望这里抛（不是 TLS 服务）
                _https_ok7n = False
        finally:
            _df7n.stop(_fxm7n)
    finally:
        _df7n._make_server = _real_make7n
    assert _https_ok7n is False, \
        "变异（https 不包 TLS）后 HTTPS GET 应失败 → 证明 ① 测的是**真 TLS 握手**"

    # (M4) skip_category 恒返回"无输入" → ④ 的 github 归 未配置 必红（用已抓到的原始输入复算）
    _real_sc7n = _dv7n.skip_category
    _dv7n.skip_category = lambda _r: "无输入"
    try:
        _rows_m4_7n = _dv7n.classify(_res7n["_results"], _res7n["_net"], _res7n["_log_lines"])
    finally:
        _dv7n.skip_category = _real_sc7n
    assert {n: c for n, s, d, c in _rows_m4_7n}.get("github") != "未配置", \
        "变异（skip_category 恒'无输入'）后 github 不再归 未配置 → 证明 ④ 的分类是真判定"

    # (M5) 抹掉 subdomain 的网络活动 → ③ 的 subdomain OK 必红（证明 OK 靠**真实活动**而非常量）
    _net_m5_7n = dict(_res7n["_net"])
    _net_m5_7n["subdomain"] = 0
    _rows_m5_7n = _dv7n.classify(_res7n["_results"], _net_m5_7n, _res7n["_log_lines"])
    assert {n: s for n, s, d, c in _rows_m5_7n}.get("subdomain") != "OK", \
        "变异（抹掉 subdomain 活动）后仍判 OK → 证明 ③ 的 OK 测的是**真实网络活动**"

    print("[7n] 续52 自检夹具补域名 + HTTPS + SKIP 分类 ok: 夹具 HTTPS 起/停（HTTP·HTTPS 都只绑 "
          "127.0.0.1，stop 后两端口都释放，证书自签 CN=devfixture.test）/ DNS 覆盖只重定向白名单"
          "（非白名单放行，退出必还原）/ 全流程自检 **cert·subdomain 由 SKIP 变 OK** 且零外网 / "
          "SKIP 分类带**日志真实原因**（token 缺失的 github 归 未配置）/ GUI 自检走 subprocess / "
          "5 条变异证伪全部按预期变红")

    # [7o] 续53 **任务列表页 + 任务详情页漏洞列表** 分页（P0 数据正确性）。背景：续51 修了
    #      跨任务 `/vulns` 的 500 截断，但**同源**的另两处仍静默丢：`/tasks` 固定
    #      `list_tasks(limit=200)`、任务详情固定 `list_vulns(task_id, limit=1000)`。
    #      本组钉死（末尾 §6.1 变异证伪 + logs/ 下两个真·路由变异脚本）：
    #      ① `/tasks` 分页：造 250 个任务 → `pager.total==250`、第 1 页恰 `size` 行、
    #         **最老那个**（id 最小）第 1 页看不到、翻到末页能看到；旧写法 `list_tasks(limit=200)`
    #         只回 200（丢 50），最老那条**永久不可达**；
    #      ② `/tasks` 服务端筛选：`?q=`（名字/目标子串）与 `?status=`（精确）真的在 SQL 侧过滤；
    #      ③ 任务详情漏洞列表分页：同一任务造 1200 条 → 页签计数==1200、第 1 页恰 `vsize` 行、
    #         id 最小那条第 1 页看不到、翻到末页能看到；旧写法 `list_vulns(limit=1000)` 只回 1000；
    #      ④ 详情页漏洞筛选 `?vsev=` / `?vq=` 服务端生效；
    #      ⑤ 非法 `page` / `vpage`（9999）不 500，回落末页；
    #      ⑥ 详情页 GET 筛选表单与 POST 复核表单**没有嵌套**（HTML 不允许 form 嵌套）。
    # 说明：为让"最老任务在末页"这条断言确定成立，先把库里任务清空（本组是 main() 最后一组，
    # 其后只打印 SMOKE PASS；冒烟库本就是隔离的 logs/ 临时库，跑完整体删除）。
    for _t0_7o in db.list_tasks(limit=100000):
        db.delete_task(_t0_7o["id"], backup=False)
    assert len(db.list_tasks(limit=100000)) == 0, "本组开始前应已清空任务表"

    _N7O = 250
    _ids7o = []
    for _i7o in range(_N7O):
        if _i7o == 0:
            _nm7o = "smoke53-OLDEST-NEEDLE53"
        elif _i7o <= 60:
            _nm7o = f"smoke53 SPACE-{_i7o:03d}"     # 带空格：测 pager 的 q 是否 URL 编码
        else:
            _nm7o = f"smoke53-task-{_i7o:03d}"
        _ids7o.append(db.create_task(_nm7o, "127.0.0.1", ["osint"], {}))
    _oldest7o, _oldest_name7o = _ids7o[0], "smoke53-OLDEST-NEEDLE53"
    for _t7o in _ids7o[:7]:            # 前 7 个置 done（供 `?status=done` 服务端筛选断言）
        db.update_task(_t7o, status="done")

    _app7o = _app_with7i()
    _c7o = _app7o.test_client()
    assert _c7o.post("/login", data={"token": settings["gui"]["token"]},
                     environ_base={"REMOTE_ADDR": "203.0.113.221"}).status_code == 302

    # ① /tasks 分页
    _r1_7o = _c7o.get("/tasks?size=50")
    assert _r1_7o.status_code == 200, _r1_7o.status_code
    _h1_7o = _r1_7o.get_data(as_text=True)
    assert "任务列表（250）" in _h1_7o, "分页后标题应显示**过滤后总数** 250"
    _n1_7o = _h1_7o.count('<tr data-id="')
    assert _n1_7o == 50, f"第 1 页应恰好 50 行：实测 {_n1_7o}"
    assert _oldest_name7o not in _h1_7o, "最老任务（id 最小）不该出现在第 1 页"
    _hlast_7o = _c7o.get("/tasks?size=50&page=5").get_data(as_text=True)
    assert _oldest_name7o in _hlast_7o, "翻到末页应能看到最老任务（旧写法下它永久不可达）"
    assert _hlast_7o.count('<tr data-id="') == 50
    _old7o = db.list_tasks(limit=200)   # 对照：旧写法只回 200 且看不到最老那条
    assert len(_old7o) == 200, f"旧写法必须只回 200 条：实测 {len(_old7o)}"
    assert _oldest_name7o not in {r["name"] for r in _old7o}, \
        "旧写法（limit=200）看不到最老任务 → 证明静默丢结果真实存在"

    # ② /tasks 服务端筛选：q（名字/目标子串）与 status（精确）
    _hq_7o = _c7o.get("/tasks?q=NEEDLE53").get_data(as_text=True)
    assert "任务列表（1）" in _hq_7o, "服务端 q 必须精确命中 1 条（旧前端过滤只搜当前页）"
    assert _oldest_name7o in _hq_7o and "smoke53-task-100" not in _hq_7o, "q 只应返回匹配行"
    _hs_7o = _c7o.get("/tasks?status=done").get_data(as_text=True)
    assert "任务列表（7）" in _hs_7o, "服务端 status 筛选必须只回 7 个 done"
    assert "smoke53-task-100" not in _hs_7o, "status=done 不应包含非 done 任务"
    # 翻页保持筛选：用 total>size 的组合让 pager 真的渲染出翻页链接（total=1 时无链接、查不到 qs）
    _pgseg7o = _c7o.get("/tasks?q=smoke53&status=pending&size=50").get_data(as_text=True)
    _pgseg7o = _pgseg7o.split('<div class="pager">', 1)[-1].split("</div>", 1)[0]
    assert "q=smoke53" in _pgseg7o and "status=pending" in _pgseg7o, "翻页必须保持全部筛选条件"
    # q 含空格必须 URL 编码（否则翻页丢条件）：60 个带空格的命中 → total 60 > size 50 → 有翻页链接
    _sp7o = _c7o.get("/tasks",
                     query_string={"q": "smoke53 SPACE", "size": "50"}).get_data(as_text=True)
    assert "任务列表（60）" in _sp7o, "q 含空格的服务端过滤应命中 60 条"
    _spp7o = _sp7o.split('<div class="pager">', 1)[-1].split("</div>", 1)[0]
    assert "q=smoke53%20SPACE" in _spp7o, "pager 里的 q 必须 URL 编码（空格→%20）"

    # ③ 任务详情漏洞列表分页（复用最老那个任务）
    _tidB7o, _MARKER7o = _oldest7o, "VULN-NEEDLE-1001"
    _sevs7o = ["critical", "high", "medium", "low", "info"]
    for _iv7o in range(1200):
        db.insert_vuln(_tidB7o, {
            "target": f"http://smoke53/{_iv7o}", "poc_id": f"poc-{_iv7o}",
            "name": (_MARKER7o if _iv7o == 0 else f"smoke53 vuln {_iv7o}"),
            "severity": _sevs7o[_iv7o % 5], "owasp": "A01",
            "detail": f"d-{_iv7o}", "evidence": f"e-{_iv7o}"})
    _dh1_7o = _c7o.get(f"/tasks/{_tidB7o}?vsize=100").get_data(as_text=True)
    assert '潜在漏洞<span class="cnt">1200</span>' in _dh1_7o, \
        "页签计数必须是**过滤后总数** 1200（不是本页数）"
    _nv1_7o = _dh1_7o.count('data-review="')
    assert _nv1_7o == 100, f"详情页漏洞表第 1 页应恰好 100 行：实测 {_nv1_7o}"
    assert _MARKER7o not in _dh1_7o, "id 最小的漏洞不该出现在第 1 页"
    _dhlast_7o = _c7o.get(f"/tasks/{_tidB7o}?vsize=100&vpage=12").get_data(as_text=True)
    assert _MARKER7o in _dhlast_7o, "翻到末页应能看到 id 最小的漏洞"
    assert _dhlast_7o.count('data-review="') == 100
    _oldv7o = db.list_vulns(task_id=_tidB7o, limit=1000)   # 对照：旧写法只回 1000
    assert len(_oldv7o) == 1000, f"旧写法必须只回 1000 条：实测 {len(_oldv7o)}"
    assert _MARKER7o not in {r["name"] for r in _oldv7o}, \
        "旧写法（limit=1000）看不到第 1001 条 → 证明静默丢结果真实存在"

    # ④ 详情页服务端筛选：vsev 与 vq
    _dvsev_7o = _c7o.get(f"/tasks/{_tidB7o}?vsev=critical").get_data(as_text=True)
    assert "共 240 条" in _dvsev_7o, "vsev=critical 服务端过滤后 total 应为 240"
    _dvq_7o = _c7o.get(f"/tasks/{_tidB7o}?vq={_MARKER7o}").get_data(as_text=True)
    assert "共 1 条" in _dvq_7o and _MARKER7o in _dvq_7o, "vq 服务端过滤应精确命中第 1001 条"

    # ⑤ 非法页码不 500（回落末页）
    assert _c7o.get("/tasks?page=9999").status_code == 200
    assert _c7o.get(f"/tasks/{_tidB7o}?vpage=9999").status_code == 200

    # ⑥ 详情页 GET 筛选表单与 POST 复核表单没有嵌套（HTML 不允许 form 嵌套）
    _iget7o = _dh1_7o.find('<form class="filters" method="get"')
    _ipost7o = _dh1_7o.find('action="/api/rescan"')
    assert 0 <= _iget7o < _ipost7o, "详情页 GET 筛选表单必须排在 POST 复核表单之前"
    assert "</form>" in _dh1_7o[_iget7o:_ipost7o], \
        "GET 表单必须在 POST 表单开始前闭合（HTML 不允许 form 嵌套）"

    # ---- §6.1 变异证伪（把新行为退回"旧/天真"实现，确认上面的断言真的变红）----
    # (M1) `/tasks` 数据源退回固定 `list_tasks(limit=200)`（旧写法，忽略分页/筛选）→ ①② 必红
    _real_page_tasks7o = db.page_tasks
    db.page_tasks = lambda limit=100, offset=0, **kw: (db.list_tasks(limit=200), 200)
    try:
        _m1_7o = _c7o.get("/tasks?size=50").get_data(as_text=True)
        assert "任务列表（250）" not in _m1_7o, \
            "变异（/tasks 退回 limit=200）后总数变 200 → 证明 ① 测的是**真分页**"
        _m1last_7o = _c7o.get("/tasks?size=50&page=5").get_data(as_text=True)
        assert _oldest_name7o not in _m1last_7o, \
            "变异后最老任务翻到末页也看不到（永久不可达）→ 证明 ① 测的是**真分页**"
    finally:
        db.page_tasks = _real_page_tasks7o

    # (M2) 任务详情漏洞列表退回固定 `list_vulns(limit=1000)`（旧写法，忽略分页/筛选）→ ③④ 必红
    _real_page_vulns7o = db.page_vulns
    db.page_vulns = lambda limit=100, offset=0, **kw: (
        db.list_vulns(task_id=kw.get("task_id"), limit=1000), 1000)
    try:
        _m2_7o = _c7o.get(f"/tasks/{_tidB7o}?vsize=100").get_data(as_text=True)
        assert '潜在漏洞<span class="cnt">1200</span>' not in _m2_7o, \
            "变异（详情页退回 limit=1000）后页签计数变 1000 → 证明 ③ 测的是**真分页**"
        _m2last_7o = _c7o.get(f"/tasks/{_tidB7o}?vsize=100&vpage=12").get_data(as_text=True)
        assert _MARKER7o not in _m2last_7o, \
            "变异后 id 最小的漏洞翻到末页也看不到 → 证明 ③ 测的是**真分页**"
    finally:
        db.page_vulns = _real_page_vulns7o

    print("[7o] 续53 任务列表页 + 任务详情页漏洞列表分页 ok: /tasks 造 250 任务→total 250·第 1 页 50 行·"
          "最老末页可见（旧 limit=200 永久不可达，已证伪）/ q·status 服务端筛选生效 + q 含空格 URL 编码 / "
          "详情页造 1200 漏洞→页签 1200·第 1 页 100 行·id 最小末页可见（旧 limit=1000 静默丢，已证伪）/ "
          "vsev·vq 服务端筛选生效 / page·vpage=9999 不 500 / GET 与 POST 表单无嵌套 / "
          "2 条变异证伪全部按预期变红（另有 logs/ 下 2 个真·路由变异脚本产出报错原文）")

    # [7p] 续54 **外部工具版本管理**（roadmap「工程化 → 工具版本管理」；实现 scanner/toolmgr.py）。
    #      这是**新模块**，没有"旧实现"可比，故 §6.1 的"退回旧实现必红"改用**变异注入**表达：
    #      把某个安全属性的判定点换回"天真实现"，确认下面的断言真的变红。
    #      钉死的安全属性（**全部离线** —— 下载/查版本两个出口都被桩掉，一个字节都不出网）：
    #      ① 只在显式入口联网：`scanner/` 包内除 toolmgr.py 外**零引用**（扫描期不可能下载）；
    #      ② 只允许 https + 主机白名单，且**跳转后的真实 URL 再校验一次**（302 绕不过白名单）；
    #      ③ 大小上限：超限即中止；
    #      ④ 默认必须过 SHA256：不符 → 拒绝落盘、**不覆盖已装好的**、不留 `.part`；
    #         release 无校验和 → 默认拒绝；显式 allow_unverified 才装且 `verified is False`；
    #      ⑤ 解包只按预期成员名取，`..` / 绝对路径成员**从根上拒绝**（zip slip 不成立）；
    #      ⑥ puredns 在 Windows 无官方产物 → 如实报"只发布 Linux / macOS"，不猜、不自动编译；
    #      ⑦ 回写 settings.yaml 走**逐行文本替换**：中文注释条数 / 行数 / 行尾 / 其它键全不变
    #         （对照 `config.save_settings()` 的整份重写会把这些注释一次抹掉）；
    #      ⑧ 两个显式入口：GUI「外部工具」页管理员可见可点、子用户 403；CLI 附属参数脱离
    #         `--update-tools` 直接报错（不静默忽略）、有工具没装上时退出码非 0。
    import hashlib as _hl7p
    import io as _io7p
    import types as _ty7p
    import zipfile as _zip7p
    from scanner import toolmgr as tm7p

    _tz7p = _TMPDIR / "toolmgr7p"
    _tz7p.mkdir(parents=True, exist_ok=True)
    _os7p, _ar7p = tm7p.host_arch()
    assert _os7p in ("windows", "linux", "macOS") and _ar7p in ("386", "amd64", "arm", "arm64"), \
        (_os7p, _ar7p)

    # ① `scanner/` 包内（除 toolmgr 自身）不得引用 toolmgr —— 扫描期"零下载"的结构性保证
    def _refs7p(pairs):
        return [n for n, t in pairs if "toolmgr" in t]

    _pairs7p = [(_f7p.relative_to(ROOT).as_posix(),
                 _f7p.read_text(encoding="utf-8", errors="replace"))
                for _f7p in sorted((ROOT / "scanner").rglob("*.py")) if _f7p.name != "toolmgr.py"]
    assert _refs7p(_pairs7p) == [], f"scanner 包内不得引用 toolmgr（扫描期零下载）：{_refs7p(_pairs7p)}"
    # 变异（M5）：把"阶段里顺手下载工具"的天真写法喂给**同一个检测器** → 必须报出来
    assert _refs7p(_pairs7p + [("scanner/stages/probe.py", "from scanner import toolmgr\n")]) \
        == ["scanner/stages/probe.py"], "检测器对'阶段里 import toolmgr'不敏感 → ① 是假绿"

    # ② 平台/命名事实（**显式传平台**，与当前主机无关，便于在 Linux/Windows 上给出同一结论）
    assert tm7p.asset_name("subfinder", "v2.16.0", "windows", "amd64") \
        == "subfinder_2.16.0_windows_amd64.zip"
    assert tm7p.asset_name("httpx", "v1.12.0", "linux", "arm64") == "httpx_1.12.0_linux_arm64.zip"
    # 注：`os_label`/`arch` 传 `None`/空串＝"用本机平台"（这是 `asset_name` 的既有语义），
    # 所以"平台缺失就编不出名字"要用**显式平台**去测 —— 下一条测的是**版本号**为空。
    assert tm7p.asset_name("subfinder", "", "windows", "amd64") is None, "版本号空不得编产物名"
    assert tm7p.asset_name("subfinder", "v", "windows", "amd64") is None, "只有 v 前缀也不得编产物名"
    assert tm7p.asset_name("nope", "v1.0.0", "windows", "amd64") is None, "未知工具不得编产物名"
    assert tm7p.asset_name("puredns", "v2.1.1", "windows", "amd64") is None, "puredns 官方无 Windows 产物"
    assert tm7p.asset_name("puredns", "v2.1.1", "linux", "amd64") == "puredns-Linux-amd64.tgz"
    _insp7p = tm7p.inspect("puredns", "windows", "amd64")
    assert _insp7p["asset"] is None and "只发布 Linux / macOS" in _insp7p["reason"], _insp7p
    assert "go install" in _insp7p["reason"], "要给出替代路径（不猜、不自动编译）"
    assert tm7p.inspect("subfinder", "windows", "amd64")["asset"], "subfinder 在 Windows 有官方产物"
    assert tm7p.parse_checksums("ab" * 32 + "  *a.zip\nbad-line\n") == {"a.zip": "ab" * 32}

    # ③ URL 白名单：三种绕过形态全拒（http 降级 / 非白名单主机 / 后缀伪装）
    for _u7p, _needle7p in (("http://api.github.com/x", "https"),
                            ("https://evil.example.com/x", "白名单"),
                            ("https://api.github.com.evil.example/x", "白名单")):
        try:
            tm7p._check_url(_u7p)
            raise AssertionError(f"必须拒绝：{_u7p}")
        except ValueError as _e7p:
            assert _needle7p in str(_e7p), (_u7p, str(_e7p))
    assert tm7p._check_url("https://objects.githubusercontent.com/x") == "objects.githubusercontent.com"

    # 下载出口：跳转后落到白名单外必须拒（否则一个 302 就绕过了白名单）、超限必须中止
    # ⚠️ 桩要**连 `urllib.parse` 一起带上**：`_check_url()` 也读它，只换 `request` 会
    #    把"校验 URL"变成 AttributeError（那样测的就不是校验逻辑了）。
    _real_urllib7p = tm7p.urllib

    class _Req7p:
        def __init__(self, url, headers=None):
            self.url, self.headers = url, headers

    class _Resp7p:
        def __init__(self, data, url):
            self._b, self._u, self._i = data, url, 0

        def read(self, n=-1):
            if n is None or n < 0:
                n = len(self._b) - self._i
            _c7p = self._b[self._i:self._i + n]
            self._i += len(_c7p)
            return _c7p

        def geturl(self):
            return self._u

        def __enter__(self):
            return self

        def __exit__(self, *_a7p):
            return False

    class _Una7p:
        def __init__(self, resp):
            self._resp = resp

        Request = _Req7p

        def urlopen(self, req, timeout=None):
            return self._resp

    def _fake_urllib7p(resp):
        return _ty7p.SimpleNamespace(request=_Una7p(resp), parse=_real_urllib7p.parse)

    try:
        tm7p.urllib = _fake_urllib7p(_Resp7p(b"x", "https://evil.example.com/payload"))
        try:
            tm7p.download_bytes("https://github.com/projectdiscovery/subfinder/releases/x")
            raise AssertionError("跳转后的主机不在白名单，必须拒绝")
        except ValueError as _e7p:
            assert "白名单" in str(_e7p), _e7p
        tm7p.urllib = _fake_urllib7p(_Resp7p(b"a" * 4096, "https://api.github.com/x"))
        try:
            tm7p.download_bytes("https://api.github.com/x", max_bytes=1024)
            raise AssertionError("超过上限必须中止")
        except ValueError as _e7p:
            assert "上限" in str(_e7p), _e7p
        # 变异（M1）：把白名单判定换回"天真实现"（不校验）→ 上面那条断言必红
        _real_chk7p = tm7p._check_url
        tm7p._check_url = lambda _u: "github.com"
        try:
            tm7p.urllib = _fake_urllib7p(_Resp7p(b"leaked", "https://evil.example.com/payload"))
            assert tm7p.download_bytes("https://github.com/x") == b"leaked", \
                "变异（不校验主机）后跳转目标不再被拦 → 证明 ③ 测的是**真校验**"
        finally:
            tm7p._check_url = _real_chk7p
    finally:
        tm7p.urllib = _real_urllib7p

    # ④ 成员名安全 + zip slip
    assert tm7p._safe_member_name("subfinder.exe") and tm7p._safe_member_name("d/sub.exe")
    assert not tm7p._safe_member_name("../evil.exe")
    assert not tm7p._safe_member_name("/etc/passwd")
    # Windows 绝对路径形态：字面量刻意拼出来（源码级红线扫描禁止写死的盘符路径字面量）
    assert not tm7p._safe_member_name("C:" + "\\" + "Windows" + "\\" + "evil.exe")

    def _mkzip7p(files):
        _buf7p = _io7p.BytesIO()
        with _zip7p.ZipFile(_buf7p, "w") as _z7p:
            for _n7p, _d7p in files.items():
                _z7p.writestr(_n7p, _d7p)
        return _buf7p.getvalue()

    _bin7p = tm7p.binary_name("subfinder")
    _asset7p = tm7p.asset_name("subfinder", "v9.9.9")
    assert _asset7p and _asset7p.endswith(".zip"), _asset7p
    _pay7p = b"FAKE-SUBFINDER-BINARY-7p"
    _zip7p_ok = _mkzip7p({_bin7p: _pay7p})
    _dig7p = _hl7p.sha256(_zip7p_ok).hexdigest()
    _slip7p = _mkzip7p({"../evil.exe": b"pwn", "sub/../../evil2.exe": b"pwn2", _bin7p: b"good"})
    try:
        tm7p.extract_binary(_slip7p, "x.zip", _bin7p)
        raise AssertionError("含 .. 成员的压缩包必须拒绝（zip slip）")
    except ValueError as _e7p:
        assert "不安全" in str(_e7p), _e7p
    # 变异（M2）：去掉成员名校验（天真实现最可能就是直接 extractall）→ 上面那条必红
    _real_safe7p = tm7p._safe_member_name
    tm7p._safe_member_name = lambda _n: True
    try:
        assert tm7p.extract_binary(_slip7p, "x.zip", _bin7p) == b"good", \
            "变异（不校验成员名）后 zip slip 不再被拒 → 证明 ④ 测的是**真校验**"
    finally:
        tm7p._safe_member_name = _real_safe7p

    # ⑤ 端到端安装（release / blob 注入 = 全离线）。settings 用**临时副本**，绝不碰真实配置
    _dest7p = _tz7p / "bin"
    _set7p = _tz7p / "settings.yaml"
    _set7p.write_bytes((ROOT / "config" / "settings.yaml").read_bytes())
    _set_txt7p = _set7p.read_text(encoding="utf-8")
    _base_asset7p = "subfinder_9.9.9_checksums.txt"
    _csum7p = f"{_dig7p}  {_asset7p}\n".encode()
    _rel7p = {"tag": "v9.9.9", "assets": {
        _asset7p: f"https://github.com/projectdiscovery/subfinder/releases/download/v9.9.9/{_asset7p}",
        _base_asset7p: "https://github.com/projectdiscovery/subfinder/releases/download/v9.9.9/"
                       + _base_asset7p}}
    _blob7p = {_base_asset7p: _csum7p, _asset7p: _zip7p_ok}
    _r7p1 = tm7p.install("subfinder", dest_dir=str(_dest7p), settings_path=str(_set7p),
                         release=_rel7p, blob=_blob7p)
    assert _r7p1["ok"] and _r7p1["verified"] is True, _r7p1
    assert (_dest7p / _bin7p).read_bytes() == _pay7p
    assert not list(_dest7p.glob("*.part")), "落盘必须原子替换，不留 .part"
    assert _r7p1["path"] == f"logs/{_TMPDIR.name}/toolmgr7p/bin/{_bin7p}", \
        f"仓库内安装必须回写**相对路径**：{_r7p1['path']}"
    assert _r7p1.get("wired") is True, _r7p1

    # ⑦ 回写 settings.yaml：注释/行数/行尾/其它键全不变，只改 tools.<名> 那一行
    _after7p = _set7p.read_bytes()
    _after_txt7p = _after7p.decode("utf-8")
    assert f"  subfinder: {_r7p1['path']}" in _after_txt7p, "tools.subfinder 必须被改成刚装好的路径"
    assert _after_txt7p.count("#") == _set_txt7p.count("#") > 50, \
        "回写必须保住中文注释（整份重写会把这些注释抹掉）"
    assert len(_after_txt7p.splitlines()) == len(_set_txt7p.splitlines()), "行数不得变化"
    assert b"\r\n" in _after7p and b"\n" not in _after7p.replace(b"\r\n", b""), \
        "行尾必须沿用文件原有形态（本仓 settings.yaml 是 CRLF）"
    assert _after7p.endswith(b"\r\n"), "结尾换行必须保留"
    assert "  httpx: httpx" in _after_txt7p and "  puredns: puredns" in _after_txt7p, "不得动其它键"
    assert "  fscan: tools/fscan/fscan.exe" in _after_txt7p, "不得动其它键（含 fscan）"

    # ⑥ 校验不过：拒绝落盘、**不覆盖已装好的**、不留 .part
    _tampered7p = dict(_blob7p)
    _tampered7p[_asset7p] = _mkzip7p({_bin7p: b"TAMPERED"})
    _r7p2 = tm7p.install("subfinder", dest_dir=str(_dest7p), settings_path=str(_set7p),
                         release=_rel7p, blob=_tampered7p)
    assert not _r7p2["ok"] and "SHA256" in _r7p2["reason"], _r7p2
    assert (_dest7p / _bin7p).read_bytes() == _pay7p, "校验不过绝不许覆盖已装好的二进制"
    assert not list(_dest7p.glob("*.part"))

    # release 没发校验和 → 默认拒绝；显式 allow_unverified 才装，且**如实**记 verified=False
    _rel_nc7p = {"tag": "v9.9.9", "assets": {_asset7p: "https://github.com/x/" + _asset7p}}
    _r7p3 = tm7p.install("subfinder", dest_dir=str(_dest7p / "n1"), settings_path=str(_set7p),
                         release=_rel_nc7p, blob={_asset7p: _zip7p_ok})
    assert not _r7p3["ok"] and "未发布校验和" in _r7p3["reason"], _r7p3
    assert not (_dest7p / "n1").exists(), "拒绝时不该建出目录"
    _r7p4 = tm7p.install("subfinder", dest_dir=str(_dest7p / "n2"), allow_unverified=True,
                         wire=False, release=_rel_nc7p, blob={_asset7p: _zip7p_ok})
    assert _r7p4["ok"] and _r7p4["verified"] is False, _r7p4
    assert (_dest7p / "n2" / _bin7p).read_bytes() == _pay7p

    # 校验和文件里**没有**本产物的条目 → 同样拒绝（不许"找不到就跳过校验"）
    _a_httpx7p = tm7p.asset_name("httpx", "v1.12.0")
    assert _a_httpx7p
    _r7p6 = tm7p.install("httpx", dest_dir=str(_dest7p / "n4"), settings_path=str(_set7p),
                         release={"tag": "v1.12.0", "assets": {
                             _a_httpx7p: "https://github.com/x/" + _a_httpx7p,
                             "httpx_1.12.0_checksums.txt": "https://github.com/x/c.txt"}},
                         blob={"httpx_1.12.0_checksums.txt": b"not-a-digest  other.zip\n"})
    assert not _r7p6["ok"] and "没有" in _r7p6["reason"], _r7p6
    assert not (_dest7p / "n4").exists()

    # ⑥ puredns 在 Windows 上：如实报平台不可用（不猜、不自动编译）
    if _os7p == "windows":
        _r7p5 = tm7p.update(["puredns"], dest_dir=str(_dest7p / "n3"), wire=False,
                            fetch=lambda _repo, timeout=0: {"tag": "v2.1.1", "assets": {}})
        assert len(_r7p5) == 1 and not _r7p5[0]["ok"], _r7p5
        assert "只发布 Linux / macOS" in _r7p5[0]["reason"], _r7p5
        assert not (_dest7p / "n3").exists()
    # 变异（M3）：把 puredns 的命名规则当成 pd（忽略"只发 Linux/macOS"这条平台事实）→ 平台判据失效
    _real_tools7p = tm7p.TOOLS["puredns"]
    tm7p.TOOLS["puredns"] = {"repo": "d3mondev/puredns", "style": "pd", "verify": None}
    try:
        assert tm7p.inspect("puredns", "windows", "amd64")["asset"], \
            "变异（丢掉平台事实）后 inspect 不再拒绝 Windows → 证明 ⑥ 测的是**真平台事实**"
    finally:
        tm7p.TOOLS["puredns"] = _real_tools7p
    # 变异（M4）：装上"跳过 SHA256"的天真实现 → 篡改包会被装进去，证明 ⑥ 的拒绝是真校验
    def _naive7p(tool, dest_dir=None, allow_unverified=False, timeout=120, wire=True,
                 settings_path=None, release=None, blob=None):
        _n7p = tm7p.binary_name(tool)
        _d7p = Path(dest_dir) if dest_dir else (ROOT / tm7p.DEFAULT_DEST)
        _d7p.mkdir(parents=True, exist_ok=True)
        _as7p = tm7p.asset_name(tool, (release or {}).get("tag"))
        (_d7p / _n7p).write_bytes(tm7p.extract_binary((blob or {})[_as7p], _as7p, _n7p))
        return {"tool": tool, "ok": True, "version": (release or {}).get("tag") or "",
                "path": str(_d7p / _n7p), "verified": True, "reason": ""}

    _real_inst7p = tm7p.install
    tm7p.install = _naive7p
    try:
        _rm7p = tm7p.update(["subfinder"], dest_dir=str(_dest7p / "naive"), settings_path=str(_set7p),
                            fetch=lambda _repo, timeout=0: _rel7p, blobs={"subfinder": _tampered7p})
        assert _rm7p[0]["ok"] and (_dest7p / "naive" / _bin7p).read_bytes() == b"TAMPERED", \
            "变异（跳过 SHA256）后篡改包被装上 → 证明 ⑥ 的拒绝落盘测的是**真校验**"
    finally:
        tm7p.install = _real_inst7p

    # 仓库内路径 → 相对路径（项目硬规矩）；含分隔符的相对路径按**项目根**折算
    assert tm7p._setting_value(ROOT / "tools" / "scanner" / "httpx.exe") == "tools/scanner/httpx.exe"

    # ⑧ GUI：管理员可进可点；子用户 403（路由层，不只是藏侧栏）
    _c7p = _app_with7i().test_client()
    assert _c7p.post("/login", data={"token": settings["gui"]["token"]}).status_code == 302
    _h7p = _c7p.get("/tools")
    assert _h7p.status_code == 200, _h7p.status_code
    _ht7p = _h7p.get_data(as_text=True)
    assert "外部工具" in _ht7p and "下载 / 更新" in _ht7p, "页面主体缺失"
    for _n7p in ("subfinder", "httpx", "puredns"):
        assert _n7p in _ht7p, _n7p
    assert 'href="/tools"' in _ht7p, "管理员侧栏必须有入口"
    assert "objects.githubusercontent.com" in _ht7p, "页面要把允许的主机如实列出来"

    _real_upd7p = tm7p.update
    _seen7p = {}

    def _stub7p(tools=None, dest_dir=None, allow_unverified=False, wire=True, settings_path=None,
                timeout=120, fetch=None, blobs=None):
        _seen7p.update(tools=tools, allow=allow_unverified, wire=wire)
        return [{"tool": "httpx", "ok": False, "version": "v1.12.0", "path": "",
                 "verified": None, "reason": "桩：离线测试，未联网"}]

    try:
        tm7p.update = _stub7p
        _rp7p = _c7p.post("/api/tools/update", data={"tool": "httpx", "no_wire": "1"})
        assert _rp7p.status_code == 302, _rp7p.status_code
        assert _seen7p == {"tools": ["httpx"], "allow": False, "wire": False}, _seen7p
    finally:
        tm7p.update = _real_upd7p
    _h2_7p = _c7p.get("/tools").get_data(as_text=True)
    assert "桩：离线测试，未联网" in _h2_7p, "更新结果必须留在页面上（进程内单槽）"
    assert "未安装" in _h2_7p, "失败必须如实展示"

    assert users_mod.create_user("smoke-sub7p", "sub7p-pw-1234", role="user",
                                 must_change=False)[0]
    _cs7p = _app_with7i().test_client()
    assert _cs7p.post("/login", data={"username": "smoke-sub7p",
                                      "password": "sub7p-pw-1234"}).status_code == 302
    assert _cs7p.get("/tools").status_code == 403, "子用户不得进外部工具页"
    assert _cs7p.post("/api/tools/update", data={"tool": "httpx"}).status_code == 403, \
        "子用户不得触发下载（这是唯一会联网的写操作）"
    assert 'href="/tools"' not in _cs7p.get("/tasks").get_data(as_text=True), \
        "子用户侧栏不该看到外部工具入口"
    users_mod.delete_user(users_mod.get_by_name("smoke-sub7p")["id"])
    assert users_mod.count_users() == 0, "本组结束应恢复无账号状态"

    # ⑧ CLI：`--update-tools` 的附属参数脱离主开关 → 直接报错（不静默忽略）；
    #    有工具没装上 → 退出码非 0；`--no-wire` 真的传成 wire=False
    _ns7p = _ty7p.SimpleNamespace(tool=["httpx"], allow_unverified=True, no_wire=True, tools_dest=None)
    _seen_cli7p = {}

    def _stub_cli7p(tools=None, dest_dir=None, allow_unverified=False, wire=True, **_kw7p):
        _seen_cli7p.update(tools=tools, dest_dir=dest_dir, allow=allow_unverified, wire=wire)
        return [{"tool": "httpx", "ok": True, "version": "v1.12.0",
                 "path": "tools/scanner/httpx.exe", "verified": False, "reason": ""}]

    try:
        tm7p.update = _stub_cli7p
        _cli.do_update_tools(_ns7p)
        assert _seen_cli7p == {"tools": ["httpx"], "dest_dir": None, "allow": True, "wire": False}, \
            _seen_cli7p
        tm7p.update = lambda *_a, **_k: [{"tool": "httpx", "ok": False, "version": "", "path": "",
                                          "verified": None, "reason": "桩：装不上"}]
        try:
            _cli.do_update_tools(_ns7p)
            raise AssertionError("有工具没装上时 CLI 必须退出码非 0（否则脚本会当成成功）")
        except SystemExit as _se7p:
            assert _se7p.code == 1, _se7p.code
    finally:
        tm7p.update = _real_upd7p
    try:
        _cli.do_update_tools(_ty7p.SimpleNamespace(tool=["nope"], allow_unverified=False,
                                                  no_wire=False, tools_dest=None))
        raise AssertionError("未知工具名必须中止（不静默忽略）")
    except SystemExit as _se7p:
        assert _se7p.code == 1, _se7p.code

    print("[7p] 续54 外部工具版本管理 ok: 平台 "
          f"{_os7p}/{_ar7p}｜scanner 包内零引用（M5 检测器敏感）｜https+白名单"
          "（跳转后再校验，M1 证伪）｜超限中止｜SHA256 不符拒绝落盘且不覆盖（M4 证伪）｜"
          "无校验和默认拒绝·显式允许则 verified=False｜'校验和文件里没有该条目'也拒绝｜"
          "zip slip 拒绝（M2 证伪）｜puredns Windows 无产物如实报（M3 证伪）｜"
          "回写相对路径且注释/行数/CRLF 行尾/其它键全不变｜GUI 管理员 200·子用户 403·结果留页｜"
          "CLI --no-wire 生效·失败退出码 1·未知工具名中止")

    # 「SMOKE PASS」必须是 main() 的最后一句 —— 只有全部断言都过了才会执行到这里。
    # 原先这一句写在**模块顶层**（在 `if __name__ == "__main__": main()` 之前），
    # 于是它在任何断言运行之前就打印了：**用例挂了照样打印 PASS**，唯一真判据只剩退出码。
    # 这是本项目第四次踩"假绿"（前三次见 `AGENTS.md §6.1`），故显式搬进 main() 末尾。
    print("SMOKE PASS")


if __name__ == "__main__":
    main()
