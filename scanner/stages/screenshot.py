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
        rows, ok = [], 0
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
            good, err = screenshot.capture(url, out, ctx.settings, timeout=timeout,
                                           throttle=ctx.throttle)
            if good:
                ok += 1
                # 库里只存**相对任务工作目录**的路径（shots/xxx.png）：
                # 既不含绝对路径，也不假设工作目录一定在项目 logs/ 下
                # （测试会用 CTFSCANNER_LOGS 把工作目录指到别处）。
                rel = f"shots/{name}"
                rows.append((url, rel))
                ctx.logger.info(f"[screenshot] {url} → {rel}")
            else:
                ctx.logger.info(f"[screenshot] {url} 截图失败：{err}")
        if rows:
            db.set_site_shots(ctx.task_id, rows)
        write_lines(ctx.workdir / "shots.txt", [f"{u}\t{r}" for u, r in rows])
        ctx.logger.info(f"[screenshot] 完成 {ok}/{len(sites)} 个")
