"""阶段：站点截图（可选，**默认关闭**）。

位置：`probe` 之后、`osint` 之前 —— 必须先有存活站点才能截图。
产物：`logs/task_<id>_<ts>/shots/<md5>.png`，并把相对路径写进 `sites.shot`；
GUI 的站点页 / 任务详情「站点」页签显示缩略图（点击看大图）。

开关：`screenshot.enabled`（默认关）+ `screenshot.max_sites`（默认 20）+ `screenshot.window`
+ `screenshot.timeout`；浏览器路径 `screenshot.browser`（留空则自动探测 Edge/Chrome）。

为什么默认关：截图要拉起一个无头浏览器，单站点通常 1~3 秒、内存占用明显高于纯 HTTP 探测，
而且它对"拿 flag"没有直接帮助 —— 需要看站点长相时再打开。
"""
import time

from .base import Stage
from .. import db, screenshot
from ..utils import REDIRECT_STATUS, write_lines


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
        reasons = {}
        # 只有"原始 HTML 里没有标题"的那些站点，才值得为渲染后标题多要一次 DOM
        no_title = sum(1 for s in sites if not str(s.get("title") or "").strip())
        title_rows = []
        final_title_rows = []      # 续197：3xx 站点渲染后拿到的**落地页标题**（补 redirect_title）
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
            # 续197：3xx 站点的**展示标题**取自落地页那一跳（`utils.site_redirect`），
            # 而落地页常常是 SPA 外壳 —— 首屏既没有 `<title>`，连 og:title 也可能没有，
            # 标题要等 JS 渲染完才出现（CloudFront + vue/element-ui 那一类就是这样）。
            # 所以"要不要渲染后标题"多一档：3xx 且落地页还没标题时也要，
            # 否则页面上那一格永远只能显示 `-`（主理人点单"301 应该取跳转之后的标题"）。
            _need_final = (int(s.get("status") or 0) in REDIRECT_STATUS
                           and not str(s.get("redirect_title") or "").strip())
            want_title = _need_final or not str(s.get("title") or "").strip()
            good, err, rtitle = screenshot.capture(url, out, ctx.settings, timeout=timeout,
                                                   throttle=ctx.throttle, want_title=want_title)
            attempts = [("一次性", timeout)]
            # 续151 的老形状是"当场再打一次同一条 URL、超时翻倍"。续170 把它换成**换一种截法**，
            # 两条理由都是实测的（主理人 2026-10-13：「重试可以不要那么快急着重试」+
            # 「超时你要显示重试了多少次」）：
            # ① 那份日志里 6 个超时站点各白等 30+60 秒，**一张都没救回来**（单阶段多花约 9 分钟）；
            # ② 它们超时不是因为"等得不够久"，而是页面**永远不等 load**（第三方子资源挂死），
            #    同一条路再走一遍必然还是超时 —— 能救的只有 CDP 那条（挡掉埋点域、不等 load 要图）。
            # 保留"3xx 换落地页再截一次"：那是一次**不同的导航**，不是同一件事重来。
            _reason = "" if good else screenshot.classify(err, s)
            _final = str(s.get("redirect_url") or "").strip()
            _try = _final if (_reason == screenshot.REASON_REDIRECT and _final
                              and _final.rstrip("/") != str(url).rstrip("/")) else url
            if not good and _try != url and not ctx.stopped():
                ctx.logger.info(f"[screenshot] {url} 首次失败（{_reason}：{err}）"
                                f"→ 换落地页 {_try} 再截一次")
                _g2, _e2, _r2 = screenshot.capture(_try, out, ctx.settings, timeout=timeout,
                                                   throttle=ctx.throttle, want_title=want_title)
                attempts.append(("落地页一次性", timeout))
                if _g2:
                    good, err, rtitle = True, "", (_r2 or rtitle)
                else:
                    err = _e2 or err
                    _reason = screenshot.classify(err, s)
            if (not good and _reason != screenshot.REASON_BROWSER
                    and screenshot.cdp_fallback_enabled(ctx.settings) and not ctx.stopped()):
                _wait = screenshot.fallback_wait(ctx.settings)
                _dl = time.time() + _wait
                while time.time() < _dl and not ctx.stopped():
                    time.sleep(0.5)              # 等一等再兜底，但**等得起也要停得下**
                if ctx.stopped():
                    ctx.logger.info("[screenshot] 任务已停止，这一张不再走 CDP 兜底")
                else:
                    _cw = screenshot.cdp_wait(ctx.settings)
                    _nb = len(screenshot.shot_block_patterns(_try, ctx.settings))
                    ctx.logger.info(f"[screenshot] {url} 一次性没截成（{_reason}）→ CDP 兜底："
                                    f"挡掉 {_nb} 个埋点/统计域、不等 load，{int(_cw)}s 内要一张图")
                    _g3, _e3, _r3 = screenshot.capture_cdp(_try, out, ctx.settings,
                                                            timeout=_cw, throttle=ctx.throttle,
                                                            want_title=want_title)
                    attempts.append(("CDP 兜底", _cw))
                    if _g3:
                        good, err = True, ""
                        rtitle = rtitle or _r3
                        ctx.logger.info(f"[screenshot] {url} CDP 兜底截到了"
                                        f"（共尝试 {len(attempts)} 次，前一次是 {_reason}）")
                    else:
                        # 档位**不跟着兜底重判**：档说的是"这站点为什么截不到"（超时/连不上/跳转），
                        # 它不因为我们换了第二条截取路子而改变。跟着重判会把「超时」洗成「其他」，
                        # 而候补重试只认 `RETRYABLE_REASONS` 那三档 —— 洗一次就悄悄少一批重试。
                        # 兜底自己的失败原文照样留下（人要看的正是"两条路各卡在哪"）。
                        err = f"{err}；CDP 兜底：{_e3}"
            if want_title and str(rtitle or "").strip():
                if _need_final:
                    # 这一张无论走哪条路（一次性跟跳 / 换落地页 / CDP 兜底），无头浏览器最终停在
                    # 的都是落地页 ⇒ 渲染后的 `document.title` 正是 `redirect_title` 要的那句话。
                    s["redirect_title"] = rtitle
                    final_title_rows.append((url, rtitle))
                if not str(s.get("title") or "").strip():
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
                # 续150：失败**原因**要落库，不只写日志；续154：再前置一个**原因档**，
                # 站点页那一格于是能一眼看出是 301 没落地 / 超时 / 无浏览器 / DNS 还是别的。
                # 续170：档名沿用**诊断那一次**的结论（见上面 CDP 分支的注释），这里不再重判一遍。
                reasons[_reason] = reasons.get(_reason, 0) + 1
                errs.append((url, screenshot.error_text(_reason, err, attempts)))
                ctx.logger.info(f"[screenshot] {url} 截图失败（{_reason}，尝试 {len(attempts)} 次）：{err}")
        if rows:
            db.set_site_shots(ctx.task_id, rows)
        if errs:
            db.set_site_shot_errors(ctx.task_id, errs)
            ctx.logger.info("[screenshot] 失败原因分布："
                            + "、".join(f"{k} {v}" for k, v in sorted(
                                reasons.items(), key=lambda kv: (-kv[1], kv[0])))
                            + "（逐条原因写进站点行的 shot_error，站点页那一格直接显示）")
        write_lines(ctx.workdir / "shots.txt", [f"{u}\t{r}" for u, r in rows])
        filled = db.set_site_titles(ctx.task_id, title_rows) if title_rows else 0
        filled_final = (db.set_site_redirect_titles(ctx.task_id, final_title_rows)
                        if final_title_rows else 0)
        if filled_final:
            ctx.logger.info(f"[screenshot] 另有 {filled_final} 个 3xx 站点的**落地页标题**"
                            "由渲染后补上（SPA 外壳首屏没有 <title>，页面那一格之前只能显示 -）")
        if no_title:
            # 必须说出来：否则页面上那排 `-` 会被读成"我们抓坏了"（用户 2026-10-09 的一问就是它）。
            ctx.logger.info(
                f"[screenshot] 本轮 {len(sites)} 个站点里 {no_title} 个**原始 HTML 没有 <title>**"
                f"（SPA 外壳常见，不是抓取失败）；无头浏览器渲染后补到标题 {filled} 个"
                + ("，其余连渲染后也没有标题" if filled < no_title else ""))
        ctx.logger.info(f"[screenshot] 完成 {ok}/{len(sites)} 个")
