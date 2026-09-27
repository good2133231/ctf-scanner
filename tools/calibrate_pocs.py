#!/usr/bin/env python3
"""本地负样本校准：把"逐条实测"从"依赖外网授权目标"变成**可重复的本地回归**（续60）。

实施者：Trae · DeepSeek-V4.1-Flash

背景（根因）
------------
`config/pocs-imported/` 里的 305 条 POC 由 `tools/import_ref_pocs.py` 从参考项目静态转换而来。
它们绝大多数是"这页像不像某某 OA/中间件"的**指纹**规则，而导入器把参考项目的 `bug_level`
原样抄成了 nuclei `severity`（实测 305 条：high 290 / medium 14 / low 1）——
**声明级别与规则实际可信度完全脱钩**（见 `scanner/db.effective_poc_severity()`）。

更具体的误报机制（静态审计得出，不是猜的）：`keywords_from_method()` 只按**字面量**收关键字，
STOPWORDS 里虽然列了 `data` / `name` / `code` / `msg` 这些通用键名，但从 `'"data"' in resp.text`
这种判定里取出来的是**带引号的 `"data"`**，与 STOPWORDS 里的 `data` 不相等 → 通用 JSON 键名
就这样漏进了 `words:` 列表，于是"随便一个返回 JSON 的页面"都可能命中。

本工具做什么
------------
起一个**本地合成靶场**：所有路径（含不存在的路径）都返回 200 + 一页"无害但常见词铺满"的后台
样板页（内嵌通用 JSON 键名、登录表单、上传/下载链接）。它**不是**任何 OA/CMS/设备，
因此 —— **任何命中都是误报**。逐条把待校准目录里的 POC 打上去，把命中的挑出来，产出可保存、
可对比的 JSON 报告。

口径与边界（别过度解读）
------------------------
- 零外网请求：靶场在 127.0.0.1，被测对象是**模板本身**，不碰任何真实资产；
- 这是**一个**合成负样本，不是完备基准：没命中 ≠ 该模板在所有真实站点上都准
  （它只说明"在这类通用页上不会乱报"）；命中的条目不必然全无价值，
  但**默认放它进扫描就是在拿误报换噪声**；
- 结论用途：① 复核 `effective_poc_severity()` 的降级是否与实测一致；
  ② 给"要不要把某条导入 POC 整理进 config/pocs-user/ 人工复核后启用"提供依据。

用法：
    py -3 tools/calibrate_pocs.py                        # 默认校准 config/pocs-imported/
    py -3 tools/calibrate_pocs.py --src scanner/pocs/pocs  # 换目录（内置 POC 应 0 命中）
    py -3 tools/calibrate_pocs.py --json logs/calib.json
"""
import argparse
import json
import pathlib
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

DEFAULT_SRC = [ROOT / "config" / "pocs-imported"]
DEFAULT_JSON = ROOT / "logs" / "poc_calibration.json"

# 合成负样本页：一页"通用后台样板"，把最容易被指纹规则误用的通用词都铺上。
# 刻意**不含**任何厂商特征串（如 "Apache APISIX Dashboard" / "phpinfo()"）：
# 含了就变成"人为制造命中"，校准结论也就没意义了。
LAB_BODY = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>后台管理</title></head><body>
<h1>系统管理后台</h1>
<form action="/login" method="post">
  <input name="username" value=""><input name="password" type="password" value="">
  <input type="hidden" name="token" value="calib-token"><button>登录</button>
</form>
<ul>
  <li><a href="/admin">管理</a></li><li><a href="/upload">上传</a></li>
  <li><a href="/download">下载</a></li><li><a href="/api">接口文档</a></li>
</ul>
<pre>{"code": 0, "msg": "success", "data": [], "total": 0, "page": 1}</pre>
<script>var cfg = {"code":0,"data":{"id":1,"name":"demo","status":"ok",
  "msg":"success","token":"calib","time":0}};</script>
<!-- 常见词：data / token / name / id / code / msg / status / index of / admin / login -->
</body></html>
""".encode("utf-8")


class _LabHandler(BaseHTTPRequestHandler):
    """所有路径（含不存在的）都回 200 + 同一页样板 —— 这就是"软 404"最坏形态。"""

    protocol_version = "HTTP/1.1"

    def _reply(self, body=True):
        payload = LAB_BODY if body else b""
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-Calibration-Lab", "harmless-synthetic-page")
        self.end_headers()
        if payload:
            self.wfile.write(payload)

    def do_GET(self):                       # noqa: N802 - BaseHTTPRequestHandler 约定
        self._reply()

    def do_HEAD(self):                      # noqa: N802
        self._reply(body=False)

    def do_POST(self):                      # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)         # 必须读完，否则 keep-alive 下会串包
        self._reply()

    def log_message(self, *a):              # 静音：一次校准几千个请求，别刷屏
        pass


def start_lab():
    """起合成靶场，返回 `(base_url, shutdown)`；端口由系统分配（避免占用冲突）。"""
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _LabHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{httpd.server_address[1]}", httpd.shutdown


def iter_files(srcs):
    """按目录收集待校准的 POC 文件（.yaml/.yml，按路径排序保证报告可复现）。"""
    out = []
    for d in srcs:
        p = pathlib.Path(d)
        if not p.is_absolute():
            p = ROOT / p
        if p.is_dir():
            out.extend(sorted(p.glob("*.yaml")) + sorted(p.glob("*.yml")))
    return out


def calibrate(srcs=None, settings=None, timeout=3, lab_url=None, on_item=None):
    """逐条把 POC 打到本地靶场，返回报告 dict。

    返回结构：`{lab, total, run, unsupported, hits:[{...}], by_source:{...}}`。
    `hits` 里的每一条都是**误报**（靶场不含任何被检测组件）。
    """
    from scanner import config
    from scanner.pocs import engine

    files = iter_files(srcs or DEFAULT_SRC)
    own_lab = lab_url is None
    if own_lab:
        lab_url, shutdown = start_lab()
    else:
        shutdown = None
    try:
        st = dict(settings or config.load_settings())
        st["limits"] = dict(st.get("limits") or {})
        st["limits"]["http_timeout"] = int(timeout)
        # 只打本地靶场：第三方出口的证书校验等设置与本次无关，保持默认即可
        report = {"lab": lab_url, "total": len(files), "run": 0,
                  "unsupported": [], "hits": [], "by_source": {}}
        for f in files:
            meta = engine.load_poc_file(f)
            if meta.get("_status") != "ok":
                report["unsupported"].append({"path": _rel(f), "error": meta.get("_error", "")})
                continue
            report["run"] += 1
            try:
                found = engine.run_poc_on_target(meta, lab_url, st, site={})
            except Exception as e:                      # 单条炸掉不该中断整轮校准
                report["unsupported"].append({"path": _rel(f), "error": f"{type(e).__name__}: {e}"})
                continue
            if not found:
                continue
            v = found[0]
            path = _rel(f)
            hit = {"path": path, "id": meta.get("id", ""),
                   "name": (meta.get("info") or {}).get("name", ""),
                   "declared_severity": (meta.get("info") or {}).get("severity", ""),
                   "effective_severity": db_effective(path, meta),
                   "confidence": db_confidence(path, meta),
                   "detail": str(v.get("detail") or "")[:200]}
            report["hits"].append(hit)
            src = _source_of(path)
            report["by_source"][src] = report["by_source"].get(src, 0) + 1
            if on_item:
                on_item(hit)
        return report
    finally:
        if shutdown:
            shutdown()


def db_effective(path, meta):
    from scanner import db
    return db.effective_poc_severity(path, meta)


def db_confidence(path, meta):
    from scanner import db
    return db.poc_confidence(path, meta)


def _source_of(path):
    from scanner import db
    return db.poc_source(path)


def _rel(p):
    """相对路径 + 统一正斜杠：报告要能跨平台逐字对比（Windows 的 `\\` 会让 diff 永远不等）。"""
    p = pathlib.Path(p)
    s = str(p.relative_to(ROOT)) if p.is_relative_to(ROOT) else str(p)
    return s.replace("\\", "/")


def render(report):
    """把报告渲染成人读文本（stdout 与 JSON 分开：文本给眼睛，JSON 给回归对比）。"""
    lines = [
        "POC 负样本校准（本地合成靶场，零外网请求）",
        f"靶场：{report['lab']}（所有路径都回 200 + 通用后台样板页）",
        f"参检：{report['total']} 条（实际执行 {report['run']} 条，"
        f"跳过 {len(report['unsupported'])} 条）",
        f"命中（= 误报）：{len(report['hits'])} 条",
    ]
    for h in report["hits"]:
        lines.append(f"  [{h['effective_severity']}/{h['confidence']}] {h['id']}"
                     f"（声明 {h['declared_severity']}） {h['path']}")
        lines.append(f"      {h['detail']}")
    if report["unsupported"]:
        lines.append("跳过的（unsupported/error，不计入命中）：")
        for u in report["unsupported"][:10]:
            lines.append(f"  {u['path']}：{u['error'][:120]}")
    if report["by_source"]:
        lines.append("按来源：" + "，".join(f"{k} {v}" for k, v in sorted(report["by_source"].items())))
    lines += [
        "口径：靶场不是任何 OA/CMS/设备，命中即误报；但这是**一个**合成负样本，"
        "没命中 ≠ 该模板在真实站点上都准，命中也不等于该模板毫无价值 —— "
        "只说明它的默认可信度撑不起它声明的级别。",
    ]
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description="POC 负样本校准（本地合成靶场）")
    ap.add_argument("--src", action="append", default=None,
                    help="待校准目录（可重复；默认 config/pocs-imported）")
    ap.add_argument("--json", default=str(DEFAULT_JSON), help="报告落盘路径")
    ap.add_argument("--timeout", type=int, default=3, help="单请求超时（秒）")
    ap.add_argument("--quiet", action="store_true", help="只打印汇总，不逐条列明细")
    args = ap.parse_args(argv)

    srcs = args.src or [str(p) for p in DEFAULT_SRC]
    print(f"[校准] 目录：{'、'.join(srcs)}")
    if args.quiet:
        report = calibrate(srcs, timeout=args.timeout)
    else:
        n = [0]

        def _tick(hit):
            n[0] += 1
            print(f"  [{n[0]}] 命中 {hit['id']}（声明 {hit['declared_severity']}"
                  f" → 有效 {hit['effective_severity']}）")

        print("[校准] 逐条打靶中…")
        report = calibrate(srcs, timeout=args.timeout, on_item=_tick)
    text = render(report)
    print(text)
    out = pathlib.Path(args.json)
    if not out.is_absolute():
        out = ROOT / out
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[校准] 报告已写入 {_rel(out)}")
    except OSError as e:
        print(f"[校准] 报告写入失败（不影响本次结论）：{e}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
