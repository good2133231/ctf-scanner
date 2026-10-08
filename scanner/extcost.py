"""外部引擎的请求量口径（续128）：把"预估"算出来显示，把"上限"变成硬判据。

为什么单开一个模块：`scanner/throttle.py` 管的是"我们自己发多少请求 / 起几个子进程"，
**管不到外部进程自己发多少** —— afrog 一轮可以打 `站点 × PoC` 个请求，fscan 一次是
`主机 × 端口` 次探测。续121 的边界说明只做到"日志里如实声明不经本任务预算"，
既没有数字也没有闸（用户点单第 4 件指出的正是这一处）。

三条设计决定，改动前请先读完：

1. **两个数字不合并**。afrog 是 HTTP 请求，fscan/nmap 是端口探测 —— 单位不同、
   打到目标上的代价也不同（一次 TCP connect 与一次带 PoC 模板的 HTTP 请求不是一回事）。
   把它们加成一个"总请求数"是假等价，所以各配一个上限、各显示各的。
2. **默认 0 = 不限**（与 `budget_total` / `rate_per_sec` 同一条 F2 规矩：默认路径永不
   触发拒绝）。原因很实际：本机默认就是 `portscan.engine=auto` + fscan 可用，而全端口
   扫描是 `1 × 65535` —— 任何"看起来合理"的非零默认值都会顺手改变既有行为，
   那不是这一轮要做的事。**预估数字默认就打**，闸默认不咬。
3. **超限就降级，不是硬失败**。portscan 超限时退回内置 TCP connect（那条走 throttle，
   真受本任务预算与限速约束），afrog 超限时干脆不起进程 —— 两种都要在日志里写明
   "是没跑成，不是没扫出东西"（§5.12 那条外部引擎不变式）。
"""
import re

# 与 config.DEFAULTS["limits"] 里那两键同源（这里只是给"键没配"的老配置兜底）
KEY_REQ = "external_max_requests"
KEY_PROBE = "external_max_port_probes"


def _cap(settings, key):
    """取上限：非数字/负数都当"不限"（0），绝不抛 —— 策略页填错不该让扫描起不来。"""
    from .config import DEFAULTS
    raw = (settings or {}).get("limits", {}).get(key)
    if raw is None:
        raw = DEFAULTS.get("limits", {}).get(key, 0)
    try:
        v = int(raw)
    except (TypeError, ValueError):
        return 0
    return v if v > 0 else 0


def _num(n):
    return f"{int(n):,}"


def afrog(n_targets, n_pocs, settings=None):
    """afrog 的预估：`站点数 × 可喂的只读 PoC 数`（它就是按这个乘积发请求的）。

    返回 `{"requests": n, "cap": c, "over": bool, "line": 展示用一句话, "block": 拦截用一句话}`。
    `n_pocs` 必须是**已经过只读闸门的那一份**（`scanner/afrog.py::plan` 的 `ok_files`），
    拿目录里的文件总数当预估会把被拒收的 brute/POST 模板也算进去 —— 那是虚高，
    虚高的数字会让人把闸调得过大，等于把闸调没了。
    """
    req = max(0, int(n_targets)) * max(0, int(n_pocs))
    cap = _cap(settings, KEY_REQ)
    over = bool(cap) and req > cap
    line = (f"预估 {_num(req)} 次 HTTP 请求（{_num(n_targets)} 站点 × {_num(n_pocs)} 只读 PoC，"
            f"**由 afrog 自管、不经本任务请求预算**）"
            + (f"；上限 {_num(cap)}" if cap else "；未设上限"))
    block = (f"afrog 没起：预估 {_num(req)} 次请求超过上限 {_num(cap)}"
             f"（{_num(n_targets)} 站点 × {_num(n_pocs)} 只读 PoC）。"
             f"要放开就调大 limits.{KEY_REQ}（0 = 不限），"
             f"或减少站点数 —— afrog 的请求由它自己发，本任务的预算与限速都拦不住它")
    return {"requests": req, "cap": cap, "over": over, "line": line, "block": block}


def ports(n_hosts, n_ports, engine="fscan", settings=None):
    """端口探测引擎（fscan / nmap）的预估：`主机数 × 端口数`（单位是探测次数，不是请求）。

    `engine` 只用于把话说清楚（日志里要写明是哪个引擎要降级）。
    """
    probes = max(0, int(n_hosts)) * max(0, int(n_ports))
    cap = _cap(settings, KEY_PROBE)
    over = bool(cap) and probes > cap
    line = (f"预估 {_num(probes)} 次端口探测（{_num(n_hosts)} 主机 × {_num(n_ports)} 端口，"
            f"由 {engine} 自管、不经本任务预算）" + (f"；上限 {_num(cap)}" if cap else "；未设上限"))
    block = (f"{engine} 预估 {_num(probes)} 次端口探测超过上限 {_num(cap)}"
             f"（{_num(n_hosts)} 主机 × {_num(n_ports)} 端口）⇒ 本轮不用它，"
             f"改用内置 TCP connect（那条**真的**走本任务的并发/限速/预算）。"
             f"要放开就调大 limits.{KEY_PROBE}（0 = 不限）")
    return {"probes": probes, "cap": cap, "over": over, "line": line, "block": block}


def parse_afrog_note(note_text):
    """从 afrog 的说明文字里取"站点 × PoC"两个数（回归用它核对预估与实际下发的一致）。"""
    m = re.search(r"(\d+) 站点 × (\d+) 只读 PoC", note_text or "")
    return (int(m.group(1)), int(m.group(2))) if m else None
