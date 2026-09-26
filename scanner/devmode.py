"""开发模式（续50）：把各阶段的"量"（并发 / 在飞 / 速率 / 每阶段配额）压到最小（1）。

目的：项目还在开发期，先验证**流程本身能不能跑通**，不被"量"的问题（并发过高、配额过大、
外部限流）干扰。配合 `run_devflow.py`（CLI）与「开发模式」页（控制台）做**全流程自检**：
把 13 个阶段都跑一遍，看哪一步断了。

为什么是"运行时深拷贝压量"而不是"改 config/settings.yaml"：
- 用户**切回来不用改文件** —— 关掉 `dev.enabled` 即恢复原策略，配置文件始终是用户自己的；
- `config/settings.yaml` 是**用户的策略覆盖层**，被工具改写会与用户手工配置纠缠
  （本项目出过 `save_settings` 把 settings.yaml 整份覆盖的事故，见 CHANGELOG 续48）；
- 沿用项目既有铁律"**任务专用副本、绝不原地改**"（见 `runner.StageContext` 的 auth/throttle 注入）——
  `apply()` 只返回一份新 dict，入参 `settings` 一个字节都不动。

⚠️ **刻意不压的项**（写在文件头 + `DEV_KEEP` 里，防止后人"补全"）：
- `limits.budget_total` / `limits.budget_subprocess_weight` **保持原值（默认 0）**。
  `budget_total=1` 会让**第 2 个请求**就被预算拒绝 → 任务在第一个阶段就"预算耗尽"收场，
  **全流程根本跑不完**。"把量压到 1"在这里会**自相矛盾**：预算的语义是"总共允许多少请求"，
  压到 1 等于"只允许发一次请求"，与"把 13 个阶段都跑一遍"直接冲突。故预算**不设**（0=不限）。
"""
import copy

# "点路径 → 目标值"。绝大多数压到 1；少数是"关"（0）—— 见每项注释。
# 顺序即 `report()` 的展示顺序（dict 保序）。
DEV_LIMITS = {
    # ---- 队列：单消费者（串行最省带宽，见 scanner/queue.py）----
    "queue.workers": 1,
    # ---- 统一门控（F2，scanner/throttle.py）：并发 / 在飞 / 速率全压到最小 ----
    "limits.max_workers": 1,
    "limits.max_inflight_global": 1,
    "limits.max_inflight_per_task": 1,
    "limits.rate_per_sec": 1,
    "limits.rate_burst": 1,
    # ---- 每任务参与资产数上限 ----
    "limits.dirscan_max_urls": 1,
    "limits.vulnscan_max_urls": 1,
    "limits.brute_max_domains": 1,
    "subdomain.max_resolve": 1,
    # ---- 目录扫描 ----
    "dirscan.quick_max_paths": 1,
    "dirscan.max_paths": 1,
    "dirscan.fw_max_paths": 0,           # 0 = 关闭"框架补充扫描"（它只是补充额度）
    "dirscan.recursive_depth": 0,         # 0 = 关闭目录递归（层数上限）
    "dirscan.recursive_max_dirs": 1,
    "dirscan.recursive_max_paths": 1,
    # ---- 各阶段每任务上限 / 并发 ----
    "takeover.max_hosts": 1,
    "portscan.max_hosts": 1,
    "portscan.workers": 1,
    "portscan.full_workers": 1,
    "jsmine.max_pages": 1,
    "jsmine.max_js": 1,
    "screenshot.max_sites": 1,
    "cert.max_sites": 1,
    "iprecon.max_ips": 1,
    "iprecon.max_hosts": 1,
    "iprecon.workers": 1,
    # ---- 第三方平台反查（FOFA / Shodan / Quake）：每任务上限 / 取回条数 / 并发 ----
    "fofa.max_sites": 1,
    "fofa.max_assets": 1,
    "fofa.workers": 1,
    # 证书 / 标题反查是**额外的**每任务配额（不在派单显式清单里，但同属"量"）——
    # 不压的话一次自检会各发最多 10 次外部查询，与"压到最小"直接冲突，故一并压到 1。
    "fofa.max_cert_queries": 1,
    "fofa.max_title_queries": 1,
    "shodan.max_sites": 1,
    "shodan.max_assets": 1,
    "shodan.workers": 1,
    "quake.max_sites": 1,
    "quake.max_assets": 1,
    "quake.workers": 1,
    # ---- CT 日志（crt.sh）----
    "ctlog.max_domains": 1,
    "ctlog.max_records": 1,
    "ctlog.max_domains_per_cert": 1,
    # ---- 线索阶段 ----
    "intel.max_leads": 1,
    "github.max_domains": 1,
    "github.max_queries": 1,
    "github.max_leads": 1,
    "heuristic.max_leads": 1,
    # ---- 检测层 ----
    "checks.poc_max_per_site": 1,
    "ssrf.max_params": 1,
    # ---- 外部工具 ----
    "tools.dirmap.threads": 1,
}

# ⚠️ 明确**不压**的项（见文件头说明）。列在这里是为了让"没出现在 DEV_LIMITS 里"
# 看起来是**刻意**，而不是遗漏。
DEV_KEEP = ("limits.budget_total", "limits.budget_subprocess_weight")


def _split(path):
    return [p for p in str(path).split(".") if p]


def _get(settings, path):
    """按点路径读值；中途缺段或非 dict 返回 `None`（不抛）。"""
    cur = settings
    for p in _split(path):
        if not isinstance(cur, dict) or p not in cur:
            return None
        cur = cur[p]
    return cur


def _set(settings, path, value):
    """按点路径写值：中间段缺失或不是 dict 时补建一个空 dict（脏配置也能压得住）。"""
    parts = _split(path)
    cur = settings
    for p in parts[:-1]:
        nxt = cur.get(p)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[p] = nxt
        cur = nxt
    cur[parts[-1]] = value


def apply(settings):
    """返回**压量后的深拷贝**；入参 `settings` 绝不原地改（见文件头）。

    非 dict 入参（None / 脏值）按空配置处理 —— 仍能产出一份"压到最小"的配置。
    """
    out = copy.deepcopy(settings) if isinstance(settings, dict) else {}
    for path, value in DEV_LIMITS.items():
        _set(out, path, value)
    return out


# 13 个阶段里有**策略级 `enabled`** 的段（`subdomain` / `probe` 没有该键 —— 见 tests/smoke.py [6u]：
# `subdomain` 只由任务阶段列表决定、`probe` 没有任何策略开关，别按"每个阶段都有 enabled"去补）。
_ENABLE_SECTIONS = ("takeover", "portscan", "cert", "screenshot", "jsmine", "dirscan",
                    "vulnscan", "heuristic", "intel", "github",
                    "iprecon", "fofa", "shodan", "quake", "ctlog")


def enable_all_stages(settings):
    """返回**打开全部阶段策略开关**的深拷贝（全流程自检要"13 个阶段都跑一遍"）。

    有 key 的第三方阶段（FOFA / Shodan / Quake / GitHub / CT 日志 / 情报 / C 段反查）一并打开：
    有 key 就真跑，没 key 的模块自身零请求、在自检报告里记为「跳过」。
    入参 `settings` 绝不原地改（与 `apply` 同一铁律）。
    """
    out = copy.deepcopy(settings) if isinstance(settings, dict) else {}
    for key in _ENABLE_SECTIONS:
        out[key] = dict(out.get(key) or {}, enabled=True)
    return out


def enabled(settings):
    """`dev.enabled` 是否为真。缺 `dev` 段 / 脏值一律返回 `False`（不抛）。"""
    dev = (settings or {}).get("dev") if isinstance(settings, dict) else None
    if not isinstance(dev, dict):
        return False
    return bool(dev.get("enabled"))


def _fmt(value):
    return "(未设置)" if value is None else repr(value)


def report(settings):
    """返回**会被改动**的压量项清单：`"路径: 原值 → 目标值"`（供启动提示与自检报告用）。

    只列"当前值 != 目标值"的项 —— 已经是目标值的项列出来只会是噪声。
    """
    cur = settings if isinstance(settings, dict) else {}
    lines = []
    for path, value in DEV_LIMITS.items():
        old = _get(cur, path)
        if old == value:
            continue
        lines.append(f"{path}: {_fmt(old)} → {_fmt(value)}")
    return lines
