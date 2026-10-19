"""hostcollide 阶段：同 IP 绑不同 Host 头，找出藏在背后的站点（续183 模块、续201 接线）。

判据与边界全在 `scanner/hostcollide.py`（只读 GET、按 IP 预算封顶、命中落
`collide:<ip>` 前缀 ⇒ 自动归 own 口径）。这里只做三件事：开关、日志、把它接进流水线。

开关两层（与 portscan / crawl 同形状）：策略 `hostcollide.enabled`（**出厂开**，续203 主理人点单）
+ 任务选项 `hostcollide: true` —— **只剩一个用途**：策略被关掉时给某一个任务强制开。
  ⇒ 策略默认开着时，建任务**不用勾任何东西**（续219：主理人再次明确"这个默认就做、不用勾选"）。
"""
from .. import hostcollide
from .base import Stage


class HostcollideStage(Stage):
    name = "hostcollide"
    description = "Host 碰撞（同 IP 绑不同 Host 头找隐藏站点）"

    def run(self):
        ctx = self.ctx
        cfg = ctx.settings.get("hostcollide", {}) or {}
        forced = ctx.options.get("hostcollide") is True
        if cfg.get("enabled") is not True and not forced:
            ctx.logger.info("[hostcollide] 未启用（策略配置 → Host 碰撞 可打开），跳过")
            return
        if ctx.stopped():
            ctx.logger.warning("[hostcollide] 任务已请求停止，跳过")
            return
        hostcollide.run(ctx)
