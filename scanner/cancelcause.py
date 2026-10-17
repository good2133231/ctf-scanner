"""具名取消原因（续211-P2-10，借鉴 ARTEX `agent/cancelcause.go` / `terminalreason.go`、
StrikeAgent `project_status.py:195-202` 的 `pause_reason` 枚举）。

为什么需要它：`tasks.error` 是一行自由文本，"预算耗尽 / 用户点了停止 / 阶段异常 /
worker 被杀"四种完全不同的收场共用几套句子。事后想回答"这个任务为什么没跑完"只能读日志；
想做统计（"多少任务是被预算挡的"）更是不可能。

本模块只做一件事：给取消/停止一个**具名 cause**，每条写明"接下来状态怎么变"。
判据只在 runner 收场处算一次（`cause_of()`），落进 `tasks.stop_reason` 这一列
（老库由 `_COLUMN_PATCHES` 补列，与其它列同口径）。

三条纪律：
  ① **不拼第二份句子** —— `tasks.error` 那行人话照旧写（给人看的），`stop_reason`
     是给机器判的枚举；两者不重复、不互推；
  ② **枚举封闭** —— `CAUSES` 之外的值一律归一成 `unknown`（与 `db.norm_review`
     同口径：不许把任意字符串写进库，否则又是一堆幽灵状态）；
  ③ **`stall` 落 idle 不落 error**（StrikeAgent 那条教训）：没有产出不等于出错，
     所以"跑完了但什么都没发现"不是取消原因，压根不进这张表。
"""
# 具名原因 ⇒ (人类一句话, 接下来任务状态怎么变)
# 状态只能是 done / stopped / failed / queued / running 这几种既有值（不新增状态机）。
CAUSES = {
    # 用户或 API 明确要求停止
    "user_stop": ("用户请求停止", "stopped"),
    # 请求预算耗尽（throttle）：与 user_stop 是两回事，虽然都落 stopped
    "budget_exhausted": ("请求预算耗尽", "stopped"),
    # 阶段抛异常且没有容错吞掉
    "stage_error": ("阶段执行异常", "failed"),
    # 目标侧不可用（DNS 全失败 / 连接全被拒）导致没有可扫的面
    "target_unreachable": ("目标不可达", "stopped"),
    # 进程级停止信号（SIGTERM/SIGINT，例如容器被停、screen 被关）
    "signal_terminated": ("收到终止信号", "stopped"),
    # 判不出来（保守：不许猜）
    "unknown": ("原因未明", "stopped"),
}

# 合法的 cause 名（供 GUI 下拉与 API 校验复用，不各写一份）
CAUSE_NAMES = tuple(sorted(CAUSES))


def norm(cause):
    """归一成合法 cause 名；空/未知一律落 `unknown`（封闭枚举，§5.14）。"""
    c = str(cause or "").strip().lower()
    return c if c in CAUSES else "unknown"


def cause_of(*, stopped=False, budget_exhausted=False, stage_error=False,
             target_unreachable=False, signaled=False):
    """按收场时的事实算 cause（**优先级从高到低**，先匹配先返回）。

    优先级理由（写下来免得下一个人问"为什么 signal 排在 budget 前面"）：
      ① `stage_error` 最具体（有异常对象，能指认哪个阶段），排第一；
      ② `signaled` 是进程级事件（容器被停/SIGTERM），它发生时 throttle 的预算账
         已经没有意义了，排第二；
      ③ `budget_exhausted` 与 `user_stop` 都可能为真（用户看到预算快尽了手动停）——
         这种重叠时归 `user_stop`：**人的动作**是更直接的因，预算只是背景。
    """
    if stage_error:
        return "stage_error"
    if signaled:
        return "signal_terminated"
    if stopped and budget_exhausted:
        return "budget_exhausted"
    if stopped:
        return "user_stop"
    if target_unreachable:
        return "target_unreachable"
    return "unknown"


def next_status(cause):
    """这个 cause 会让任务落到哪个状态（给 runner 与 GUI 预览用）。"""
    return CAUSES[norm(cause)][1]


def describe(cause):
    """给人看的一句话（GUI 徽章 title / 报告附录用）。"""
    return CAUSES[norm(cause)][0]
