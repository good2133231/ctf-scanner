#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""组件指纹的**负样本校准**（续127，与 `tools/calibrate_pocs.py` 同性质、同一红线）。

为什么要有它：续120 从 afrog-pocs 导入的 51 条判据，误报率**从没测过** —— POC 侧有
`calibrate_pocs.py`（合成靶场、零外网、只报告不判分），指纹侧没有对应物。
"导入时逐条人工复核过"只回答"这条规则在它自己那条路径上对不对"，
不回答"**别的站**的别的页面会不会也被它打上标签" —— 后者才是把 `sites.tech` 写脏的那一路，
而 `sites.tech` 下游连着 dirscan 的框架字典选择与 vulnsec 的 POC 优先排序（错标签＝白花钱的请求）。

三条纪律（与 calibrate_pocs 一致）：
- **零请求**：语料是本文件里内联的合成响应，不联网、不起服务；
- **只报告不判分**：命中数不等于误报数，**绝不**据此自动改级别 / 自动删规则 ——
  那正是续 60 修掉过的"采信机器判分"；
- 语料必须**通用**：每个样本刻意不含任何"产品级"特征串（含了就是正样本，测不出误报）；
  但**保留**服务器/前端框架层的真实特征（`Server: nginx`、`jquery.min.js`、IIS 默认页），
  因为"打上 nginx"在这类页上是**正确**的 —— 报告把两者分开交给人判，工具不判。
  每个样本的 `noise` 一栏写明"这类页面真实长什么样、为什么算负样本"，
  这样看报告的人能判断"这条命中到底是判据太宽，还是语料太像"。

用法：python3 tools/calibrate_fingerprints.py [--json logs/fp_calibration.json]
退出码：0 = 跑完了（**包括发现命中**）；1 = 引擎/字典读不通（无从可查）。
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# ---------- 负样本文档 ----------
# 形状就是 `scanner/fingerprint.py::identify()` 吃的响应 dict。
# `path` 是"当时请求的是哪条路径"（续127 的路径门控判据要用；语料刻意覆盖
# 那些"外置表里带路径的判据所对应"的路径 —— 门控失效时它们必须在这里被抓住）。
NEGATIVES = [
    {
        "name": "通用软 404（统一跳转页）",
        "noise": "整站任意路径都回这张页；标题与正文只有通用词，是最常见的假阳性来源",
        "status": 200,
        "headers": {"Server": "nginx/1.18.0", "Content-Type": "text/html; charset=utf-8"},
        "body": "<html><head><title>404 Not Found</title></head><body>"
                "<h1>页面不存在</h1><p>请返回首页 <a href=\"/\">Home</a> 或"
                "<a href=\"/login\">登录</a></p><script src=\"/static/js/jquery.min.js\"></script>"
                "</body></html>",
        "path": "/not-any-page",
    },
    {
        "name": "通用后台登录页（无厂商特征）",
        "noise": "国产 OA/ERP 的登录页几乎都是这个骨架：用户名/密码/验证码 + Bootstrap/element-ui",
        "status": 200,
        "headers": {"Content-Type": "text/html", "Set-Cookie": "JSESSIONID=ABCD1234; Path=/"},
        "body": "<html><head><title>管理系统 - 登录</title>"
                "<link href=\"/lib/element-ui/lib/theme-chalk/index.css\" rel=\"stylesheet\">"
                "</head><body><form action=\"/login\" method=\"post\">"
                "<input name=\"username\"><input name=\"password\" type=\"password\">"
                "<input name=\"captcha\"><img src=\"/captcha.jpg\"></form>"
                "<script src=\"/static/vue.min.js\"></script></body></html>",
        "path": "/login",
    },
    {
        "name": "通用 SPA 首页（Next.js + antd）",
        "noise": "前端框架特征齐全（__NEXT_DATA__/antd/jquery），但后端组件一个都没有",
        "status": 200,
        "headers": {"Content-Type": "text/html; charset=utf-8"},
        "body": "<html><head><title>Console</title></head><body><div id=\"root\">"
                "<script id=\"__NEXT_DATA__\" type=\"application/json\">"
                "{\"props\":{\"pageProps\":{}}}</script>"
                "<link href=\"/static/css/antd.min.css\" rel=\"stylesheet\">"
                "<script src=\"/static/js/jquery-3.6.0.min.js\"></script>"
                "<script src=\"/static/js/bootstrap.min.js\"></script></div></body></html>",
        "path": "/",
    },
    {
        "name": "通用 API 错误页（JSON）",
        "noise": "FastAPI/Spring 的默认错误结构都是 code/message/detail 这类通用键",
        "status": 500,
        "headers": {"Content-Type": "application/json"},
        "body": "{\"code\":500,\"message\":\"Internal Server Error\","
                "\"detail\":\"Something went wrong\",\"timestamp\":1700000000}",
        "path": "/api/xml",
    },
    {
        "name": "IIS 默认页",
        "noise": "只写了 \"Microsoft\" 与通用图片路径，没有任何产品标识",
        "status": 200,
        "headers": {"Server": "Microsoft-IIS/10.0", "Content-Type": "text/html"},
        "body": "<html><head><title>Microsoft Internet Information Services 8</title></head>"
                "<body><h1>It works!</h1><p>This is the default web page for this server.</p>"
                "<img src=\"/iis-85.png\"></body></html>",
        "path": "/",
    },
    {
        "name": "Apache 默认页",
        "noise": "\"Apache\" 出现在 **Server 头**里（那是真的），但正文里只有 generic 词",
        "status": 200,
        "headers": {"Server": "Apache/2.4.41 (Ubuntu)", "Content-Type": "text/html"},
        "body": "<html><body><h1>It works!</h1><p>This is the default web page for this server."
                "</p></body></html>",
        "path": "/",
    },
    {
        "name": "302 到登录页",
        "noise": "任何需要登录的产品都会把 / 跳到 /login，这一跳的**正文是空的**",
        "status": 302,
        "headers": {"Location": "/login", "Content-Type": "text/html"},
        "body": "",
        "path": "/",
    },
    {
        "name": "Tomcat 默认 404",
        "noise": "报告式错误页：只有状态码与一行说明，没有任何版本以外的标识",
        "status": 404,
        "headers": {"Content-Type": "text/html;charset=ISO-8859-1"},
        "body": "<html><head><title>Apache Tomcat/7.0.47 - Error report</title></head>"
                "<body><h1>HTTP Status 404 - /druid/login.html</h1>"
                "<p><b>Description</b> The requested resource is not available.</p></body></html>",
        "path": "/druid/login.html",
    },
    {
        "name": "目录列表（nginx autoindex）",
        "noise": "Index of /：路径名可能千奇百怪，判据不能靠「标题里有 login」就下结论",
        "status": 200,
        "headers": {"Server": "nginx", "Content-Type": "text/html"},
        "body": "<html><head><title>Index of /backup</title></head>"
                "<body><h1>Index of /backup</h1><pre><a href=\"../\">../</a>"
                "<a href=\"login.php\">login.php</a>  01-Jan-2020 00:00  1234</pre></body></html>",
        "path": "/backup/",
    },
    {
        "name": "通用监控面板（自研，无产品名）",
        "noise": "标题就叫 Dashboard、正文有 metrics/status/health 这些通用词",
        "status": 200,
        "headers": {"Content-Type": "text/html"},
        "body": "<html><head><title>Dashboard</title></head><body>"
                "<h2>System Status</h2><div>metrics / health / version 1.0</div>"
                "<table><tr><td>uptime</td><td>10d</td></tr></table></body></html>",
        "path": "/dashboard.html",
    },
    {
        "name": "通用登录页（带 SSO 字样）",
        "noise": "写着「统一身份认证 / sso / cas」字样的**自研**页面（不是那几个产品本身）",
        "status": 200,
        "headers": {"Content-Type": "text/html"},
        "body": "<html><head><title>统一身份认证登录</title></head><body>"
                "<form action=\"/sso/login.action\"><input name=\"user\">"
                "<input name=\"pwd\" type=\"password\"></form></body></html>",
        "path": "/sso/login.action",
    },
    {
        "name": "admin 路径的通用 403",
        "noise": "nginx 的 default 403 页（不是 WAF 拦截页，也不是「后台存在」）",
        "status": 403,
        "headers": {"Server": "nginx/1.20.1", "Content-Type": "text/html"},
        "body": "<html><head><title>403 Forbidden</title></head><body>"
                "<center><h1>403 Forbidden</h1></center><hr><center>nginx/1.20.1</center>"
                "</body></html>",
        "path": "/admin/login/?next=/admin/",
    },
]


def run():
    """逐样本 × 逐规则跑一遍引擎自己的判定，返回 `(每样本的标签, 命中明细)`。"""
    from scanner import fingerprint as fp
    per_sample, extra_hits = [], {}
    rules, issues = fp.load_extra()
    for neg in NEGATIVES:
        resp = {"status": neg["status"], "headers": neg["headers"], "text": neg["body"],
                "url": "http://neg.local" + neg["path"]}
        tags = fp.identify(resp)
        per_sample.append({"name": neg["name"], "path": neg["path"],
                           "status": neg["status"], "tags": tags})
        for t in tags:
            extra_hits.setdefault(t, []).append(neg["name"])
    return per_sample, extra_hits, rules, issues


def main():
    ap = argparse.ArgumentParser(description="组件指纹的负样本校准（零请求、只报告）")
    ap.add_argument("--json", default="logs/fp_calibration.json", help="报告落盘路径")
    args = ap.parse_args()
    from scanner.config import LOGS_DIR
    per_sample, hits, rules, issues = run()
    print("=" * 66)
    print("指纹负样本校准（合成语料，零外部请求；命中数**不等于**误报数）")
    print("=" * 66)
    if issues:
        print(f"[!] 外置字典有 {len(issues)} 条问题（先修这个，否则统计口径不准）：")
        for it in issues[:8]:
            print("    -", it)
    ext_tags = sorted(rules)
    print(f"外置字典标签 {len(ext_tags)} 个；负样本 {len(per_sample)} 份")
    noisy = 0
    for s in per_sample:
        if s["tags"]:
            noisy += 1
            print(f"  [命中] {s['name']}（{s['status']} {s['path']}）→ "
                  f"{', '.join(s['tags'])}")
        else:
            print(f"  [干净] {s['name']}")
    print("-" * 66)
    if hits:
        # 别把这份清单直接读成"误报清单"：语料本身分层，服务器/前端框架那一层的特征是
        # **故意留着**的（Server: nginx、jquery.min.js），被打上标签是真识别；只有当某个
        # 产品级标签在"不含该产品任何特征"的页上出现，那才叫误报。分辨的仍是人。
        print(f"被语料打上的标签 {len(hits)} 个（**要人工分辨**：语料确实带了该特征＝真识别，"
              f"只有通用词却被打上产品标签才＝误报）：")
        for t, names in sorted(hits.items()):
            print(f"    {t:24s} 命中 {len(names)}/{len(per_sample)} 份："
                  f"{'、'.join(names[:4])}{'…' if len(names) > 4 else ''}")
    else:
        print("没有任何标签被通用页命中 —— 这一轮的判据在负样本上是干净的。")
    out = Path(args.json)
    if not out.is_absolute():
        out = LOGS_DIR.parent / args.json
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"samples": per_sample, "noisy_tags": hits,
                               "external_tags": len(ext_tags),
                               "dict_issues": issues}, ensure_ascii=False, indent=1),
                   encoding="utf-8")
    print(f"[+] 报告：{out.relative_to(Path.cwd()) if str(out).startswith(str(Path.cwd())) else out}"
          f"（{noisy}/{len(per_sample)} 份样本有命中）")
    print("说明：本工具**不改**任何规则、不自动降级、不自动删标签 —— 判收紧还是判放行的是人。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
