"""阶段：站点截图（可选，**默认关闭**）。

位置：`probe` 之后、`osint` 之前 —— 必须先有存活站点才能截图。
产物：`logs/task_<id>_<ts>/shots/<md5>.png`，并把相对路径写进 `sites.shot`；
GUI 的站点页 / 任务详情「站点」页签显示缩略图（点击看大图）。

开关：`screenshot.enabled`（默认关）+ `screenshot.max_sites`（默认 20）+ `screenshot.window`
+ `screenshot.timeout`；浏览器路径 `screenshot.browser`（留空则自动探测 Edge/Chrome）。

为什么默认关：截图要拉起一个无头浏览器，单站点通常 1~3 秒、内存占用明显高于纯 HTTP 探测，
而且它对"拿 flag"没有直接帮助 —— 需要看站点长相时再打开。
"""
from .base import Stage
from .. import db, screenshot
from ..utils import write_lines


class ScreenshotStage(Stage):
    name = "screenshot"
    description = "站点截图（调用本机无头 Edge/Chrome，产物进 sites.shot）"

    def run(self):
        ctx = self.ctx
        cfg = ctx.settings.get("screenshot", {}) or {}
        # 门控：策略级 `screenshot.enabled`（默认关）**或** 任务级显式点名。
        # 为什么要有任务级点名：建任务时"截图"复选框默认是**不勾**的（见 tasks.html），
        # 用户勾上它就是在说"这次我要截图"；若只认策略开关，勾了却被静默跳过，
        # 页面上就只剩一句"未启用"，看起来像功能没做完（用户 2026-09-23 的实际反馈）。
        # CLI `-p screenshot` 同样走这条（显式点名即生效），不改全局策略。
        if cfg.get("enabled") is not True and ctx.options.get("screenshot_on") is not True:
            ctx.logger.info("[screenshot] 未启用（策略配置 → 资产面拓展 可打开；"
                            "建任务时勾选「截图」也可只对本次生效），跳过")
            return
        if not screenshot.available(ctx.settings):
            ctx.logger.warning("[screenshot] 未找到可用的无头浏览器（Edge/Chrome），跳过；"
                               "可在策略配置里填 screenshot.browser")
            return
        if ctx.stopped():
            ctx.logger.warning("[screenshot] 任务已请求停止，跳过")
            return

        sites = ctx.results.get("sites") or [dict(r) for r in db.list_sites(ctx.task_id)]
        sites = ctx.scope_sites(sites)          # 续25：追加执行时限定到本次勾选（非追加原样）
        cap = int(cfg.get("max_sites", 20) or 20)
        if len(sites) > cap:
            ctx.logger.info(f"[screenshot] 站点 {len(sites)} 个超过上限 {cap}，只截前 {cap} 个")
            sites = sites[:cap]
        if not sites:
            ctx.logger.info("[screenshot] 无存活站点，跳过")
            return

        timeout = int(cfg.get("timeout", 30) or 30)
        shot_dir = ctx.workdir / "shots"
        rows, errs, ok = [], [], 0
        # 只有"原始 HTML 里没有标题"的那些站点，才值得为渲染后标题多要一次 DOM
        no_title = sum(1 for s in sites if not str(s.get("title") or "").strip())
        title_rows = []
        ctx.logger.info(f"[screenshot] 开始截图 {len(sites)} 个站点 …")
        for s in sites:
            if ctx.stopped():
                ctx.logger.warning("[screenshot] 任务已请求停止，结果不再入账")
                break
            url = s.get("url")
            if not url:
                continue
            name = screenshot.shot_name(url)
            out = shot_dir / name
            want_title = not str(s.get("title") or "").strip()
            good, err, rtitle = screenshot.capture(url, out, ctx.settings, timeout=timeout,
                                                   throttle=ctx.throttle, want_title=want_title)
            # 续151（用户点单）：失败**自动重试一次** —— 超时就把超时翻倍、3xx 就落到最终
            # URL 再截一次。只在"重试策略真的变了"时才重发（换 URL 或加超时），且**沿用原始
            # URL 的产物名**：否则重试成功的图会落到另一个文件、`sites.shot` 就对不上了。
            # 无浏览器这类"重试也没用"的原因不重试；两次都失败时**两条原因都写进去**。
            if not good and not ctx.stopped():
                _low = (err or "").lower()
                _no_browser = ("browser" in _low or "浏览器" in (err or ""))
                _final = str(s.get("redirect_url") or "").strip()
                _r_url, _r_timeout = url, timeout
                if "timeout" in _low or "timed out" in _low or "超时" in (err or ""):
                    _r_timeout = timeout * 2
                elif _final and _final.rstrip("/") != str(url).rstrip("/"):
                    _r_url = _final
                else:
                    _r_timeout = timeout * 2
                if not _no_browser and (_r_url != url or _r_timeout != timeout):
                    _why = (f"换落地页 {_final}" if _r_url != url
                            else f"超时 {timeout}→{_r_timeout}s")
                    ctx.logger.info(f"[screenshot] {url} 首次失败（{err}）→ 重试（{_why}）")
                    _g2, _e2, _r2 = screenshot.capture(
                        _r_url, out, ctx.settings, timeout=_r_timeout,
                        throttle=ctx.throttle, want_title=want_title)
                    if _g2:
                        good, err, rtitle = True, "", (_r2 or rtitle)
                        ctx.logger.info(f"[screenshot] {url} 重试成功（{_why}）")
                    else:
                        err = f"{err}（重试仍失败：{_e2}）"
            if want_title and str(rtitle or "").strip():
                # 内存里也补上：screenshot 之后还有 osint / jsmine / dirscan / vulnscan 读这批站点行
                s["title"] = rtitle
                title_rows.append((url, rtitle))
            if good:
                ok += 1
                # 库里只存**相对任务工作目录**的路径（shots/xxx.png）：
                # 既不含绝对路径，也不假设工作目录一定在项目 logs/ 下
                # （测试会用 CTFSCANNER_LOGS 把工作目录指到别处）。
                rel = f"shots/{name}"
                rows.append((url, rel))
                ctx.logger.info(f"[screenshot] {url} → {rel}")
            else:
                # 续150（用户点单）：失败**原因**要落库，不只写日志 —— 站点页那一格空着时，
                # 用户要能一眼看出是 301 没落地 / 超时 / 无浏览器 / DNS 还是别的。
                errs.append((url, err))
                ctx.logger.info(f"[screenshot] {url} 截图失败：{err}")
        if rows:
            db.set_site_shots(ctx.task_id, rows)
        if errs:
            db.set_site_shot_errors(ctx.task_id, errs)
        write_lines(ctx.workdir / "shots.txt", [f"{u}\t{r}" for u, r in rows])
        filled = db.set_site_titles(ctx.task_id, title_rows) if title_rows else 0
        if no_title:
            # 必须说出来：否则页面上那排 `-` 会被读成"我们抓坏了"（用户 2026-10-09 的一问就是它）。
            ctx.logger.info(
                f"[screenshot] 本轮 {len(sites)} 个站点里 {no_title} 个**原始 HTML 没有 <title>**"
                f"（SPA 外壳常见，不是抓取失败）；无头浏览器渲染后补到标题 {filled} 个"
                + ("，其余连渲染后也没有标题" if filled < no_title else ""))
        ctx.logger.info(f"[screenshot] 完成 {ok}/{len(sites)} 个")
