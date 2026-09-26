"""全流程自检核心（续52）：夹具域名 + DNS 覆盖 + 压量 + 逐阶段真跑/跳过/失败分类。

`run_devflow.py`（CLI）与 `tests/smoke.py [7n]` **共用本模块**，避免两处逻辑漂移 ——
本轮修的问题正是"CLI 报 13 阶段均无异常，其实 5 个阶段在空转"，如果测试另写一套判定，
两边会再次各说各话。

本模块**无 import 副作用**：不设环境变量、不起线程、不写库。调用方必须在 `import scanner.*`
**之前**把 `CTFSCANNER_DB` / `CTFSCANNER_LOGS` 指到隔离位置（`scanner/db.py` 是模块级读它们）——
`run_devflow.py` 在脚本顶部设；`tests/smoke.py` 早在文件顶部已设。

判据说明（**为什么 OK/SKIP 要分开、SKIP 还要分类**）：
- ``FAIL``：该阶段**抛了异常**（由阶段代理记录后原样抛出，交给 runner 的阶段级容错）；
- ``SKIP``：该阶段本次**零网络活动**（目标不匹配 / 未配 key / 无对应资产 / 命中缓存）——
  **不是报错**。续52 起 SKIP 还要带上**真实原因分类**（``无输入`` / ``未配置`` / ``无匹配`` /
  ``命中缓存``），原因取自**任务日志里该阶段的那一行**（而不是写死一张表）——
  否则四种原因混成一句"零网络活动"，等于没说。
- ``OK``：该阶段本次有网络活动。``portscan`` / ``heuristic`` 见 ``_NON_NET_STAGES``。

**网络活动**怎么数（续52 起扩容）：除了 ``http_request`` / ``run_cmd``，还数**系统解析器**
（``socket.getaddrinfo``）—— 因为 ``subdomain`` 的内置 DNS 爆破、``cert`` 的 TLS 握手、
``osint`` 的 IP 反查都**不走** HTTP / 子进程，只走解析器。不数解析器的话，这三个阶段即使
真跑了也会被误判成"空转"（正是续50 的老毛病）。
"""
import contextlib
import os
import socket
import sys

from . import devfixture, devmode, runner, utils

# 夹具域名：RFC 2606 保留 TLD，**永远不解析到公网**。
# 为什么用 `.test`：即使有阶段用了**不认 Python DNS 覆盖**的外部工具（subfinder / httpx /
# nmap / puredns），它们对 `devfixture.test` 也只能从公网解析器拿到 NXDOMAIN，
# **不会产生任何"打到真实主机"的外网流量**（外部工具是子进程，Python 的 socket 覆盖对它们无效）。
FIXTURE_DOMAIN = "devfixture.test"
FIXTURE_SUBDOMAIN = "www.devfixture.test"

# 本就不走 http_request / run_cmd / 系统解析器的阶段：**天然 0 计数**，不能据此判"跳过"。
# - portscan：走**裸 socket**（`throttle.slot("socket")` + `_probe_port`）；
# - heuristic：**零请求**设计（只对已收集数据做本地聚合）。
# （续52 起 portscan 一般也会因 `resolve_host` 命中解析器计数而 >0，这里保留是兜底。）
_NON_NET_STAGES = ("portscan", "heuristic")

# 自检里**必须关掉**的第三方能力：它们指向真实外部服务（FOFA / Shodan / Quake / crt.sh），
# 自检铁律是**零外网**，故在自检副本里关掉。关掉后 osint 会按"未启用/无输入"如实跳过。
# （github / intel 有别的处置：github 清空 token 后零请求；intel 改指本地夹具源，见下。）
_EXTERNAL_OFF = ("fofa", "shodan", "quake", "ctlog")

# 代理环境变量名（大小写都要管 —— `requests` 两者都认）。
_PROXY_KEYS = ("NO_PROXY", "no_proxy")


@contextlib.contextmanager
def no_proxy_env():
    """把夹具域名加进 `NO_PROXY`（**只加不删**），退出还原。

    为什么需要：本机若配了 `HTTP(S)_PROXY`，`requests` 会把发往夹具域名（`devfixture.test`）
    的请求也塞给代理 —— 实测连 `https://www.devfixture.test:<port>/` 会走代理并拿到 502，
    于是 probe 一个站点都探不到。自检铁律是"只打本机夹具、零外网"，故让夹具域名**直连**。
    `requests` 的 `should_bypass_proxies` 按**主机名**判定：`NO_PROXY` 里写 `devfixture.test`
    即可覆盖它自身与所有子域（`endswith` 匹配）。
    """
    saved = {k: os.environ.get(k) for k in _PROXY_KEYS}
    cur = saved.get("NO_PROXY") or saved.get("no_proxy") or ""
    parts = [p for p in cur.replace(" ", "").split(",") if p]
    for extra in ("127.0.0.1", "localhost", "::1", FIXTURE_DOMAIN, "." + FIXTURE_DOMAIN):
        if extra not in parts:
            parts.append(extra)
    val = ",".join(parts)
    os.environ["NO_PROXY"] = val
    os.environ["no_proxy"] = val
    try:
        yield
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


class DnsOverride:
    """作用域内的 DNS 覆盖：**只**把夹具域名重定向到 `127.0.0.1`，其余一律放行给真实解析器。

    ⚠️ **红线**：只覆盖**白名单主机名**（`FIXTURE_DOMAIN` 及其任意子域），
    **其它任何域名一律放行给真实解析器，绝不重定向**（`_hit()` 之外的走 `self._orig`）。
    `__exit__` 用 `try/finally` 语义**保证还原** —— 覆盖是进程级全局钩子，
    不还原会把同一个进程里后续所有解析都带偏。

    **为什么只覆盖 `socket.getaddrinfo` 就够**（已 grep 确认，`scanner/` 全量）：
      * `utils.resolve_host` 直接调 `socket.getaddrinfo`（`wildcard` / `portscan` / `osint` 走它）；
      * `socket.create_connection`（`certs.py::fetch` 的 TLS 握手、`dnsq.py` 的 TCP 回退）
        **内部**调 `socket.getaddrinfo`；
      * `requests` / `urllib`（`utils.http_request`）建立连接最终也落到 `socket.getaddrinfo`。
    grep 结果（2026-09-26）：`getaddrinfo` 仅 `scanner/utils.py:404`；`gethostbyname` **无**；
    `create_connection` 在 `scanner/certs.py:288` 与 `scanner/dnsq.py:236`。三处都会经
    `socket.getaddrinfo`，故覆盖一个点即全覆盖。
    ⚠️ `scanner.dnsq` 查域名走的是**自建 UDP/TCP DNS 报文**（打 `config/dicts/resolvers.txt`
    里的解析器），**不经过** getaddrinfo —— 它对夹具域名的查询会得到真实解析器的 NXDOMAIN
    （这正是 `.test` 的意义，见文件头）。
    """

    def __init__(self, domains=None, on_lookup=None):
        self.domains = tuple(domains or (FIXTURE_DOMAIN,))
        self.on_lookup = on_lookup
        self._orig = None

    def _hit(self, host):
        h = str(host or "").strip().lower().rstrip(".")
        return any(h == d or h.endswith("." + d) for d in self.domains)

    def __enter__(self):
        self._orig = socket.getaddrinfo
        orig = self._orig

        def patched(host, port, family=0, type=0, proto=0, flags=0):
            if self.on_lookup:
                self.on_lookup()
            if self._hit(host):
                # 只回一条 IPv4 回环；端口原样带出（`port=None` 时给 0）
                try:
                    p = int(port)
                except (TypeError, ValueError):
                    p = 0
                return [(socket.AF_INET, type or socket.SOCK_STREAM, proto or 6, "",
                         ("127.0.0.1", p))]
            return orig(host, port, family, type, proto, flags)

        socket.getaddrinfo = patched
        return self

    def __exit__(self, *exc):
        if self._orig is not None:
            socket.getaddrinfo = self._orig
            self._orig = None
        return False


def selfcheck_settings(settings, intel_url=None):
    """自检用配置：压量（`devmode.apply`）+ 打开全部阶段开关 + 关掉会真出网的第三方能力。

    - `intel_url` 非空时把 `intel.url` 指过去（自检指向**本地夹具**的 KEV 源，让 intel 真跑却不出网），
      并把 `intel.cache_hours` 压到 0（**强制不吃旧缓存** —— 否则本机若已有真实 KEV 缓存，
      intel 会命中缓存、零请求，自检就看不到它"真跑"的样子）；为空时把 intel 关掉。
    - **清空第三方凭据**（`keys` 置空）：`enable_all_stages` 会打开 github（它要 token 才发请求），
      而用户机器上的 `config/keys.yaml` 往往**真的配了** FOFA / GitHub 凭据 —— 不清空的话，
      一次自检会**真花掉用户配额**、并打到站外（违反"零外网"铁律）。
      清空后 github 按"未配置 token"如实跳过（`SKIP(未配置)`），与铁律一致。
    - 入参 `settings` **绝不原地改**（`apply` / `enable_all_stages` 都是深拷贝）。
    """
    out = devmode.enable_all_stages(devmode.apply(settings))
    for key in _EXTERNAL_OFF:
        out[key] = dict(out.get(key) or {}, enabled=False)
    out["keys"] = {}          # 自检不携带任何第三方凭据（见 docstring）
    if intel_url:
        out["intel"] = dict(out.get("intel") or {}, enabled=True, url=str(intel_url),
                            cache_hours=0)
    else:
        out["intel"] = dict(out.get("intel") or {}, enabled=False)
    return out


def build_targets(https_port):
    """自检目标（多行文本）：夹具域名 + 子域名 + 一个**带显式端口**的 HTTPS URL。

    - 裸域名 `devfixture.test` / 子域名 `www.devfixture.test`：让 `subdomain` 阶段有输入
      （它只认裸域名，之前目标是一个 URL，整阶段被跳过）；
    - `https://www.devfixture.test:<port>/`：让 `probe` 有**可命中的站点**、`cert` 有
      **https 站点可取证**。刻意用夹具的**真实（临时）端口**，从而**不需要绑 80/443**
      （低端口在非管理员 / Linux CI 上会 bind 失败），也不必去改 `cert.tls_ports`。
    """
    return "\n".join([FIXTURE_DOMAIN, FIXTURE_SUBDOMAIN,
                      f"https://{FIXTURE_SUBDOMAIN}:{int(https_port)}/"])


class _RecStage:
    """阶段代理：记录本阶段 OK/FAIL（异常仍**原样抛出**，与 runner 的容错语义一致）。

    同时把"当前阶段"写进**模块级** `_CURRENT`（不是 `threading.local()`）—— 阶段内绝大多数
    请求发生在 `pool_run` 的**工作线程**里，thread-local 在那些线程里是空的，会导致请求
    全部归不到阶段上（实测过：dirscan/vulnscan 明明发了请求却被误判成「跳过」）。
    自检是**单任务前台串行**跑，阶段之间不会重叠，故用全局标记是安全的。
    """

    def __init__(self, ctx, name, cls, results):
        self._inner = cls(ctx)
        self._name = name
        self._results = results

    def run(self):
        _CURRENT["stage"] = self._name
        try:
            self._inner.run()
            self._results[self._name] = "OK"
        except Exception as exc:      # noqa: BLE001 - 记下来后原样抛
            self._results[self._name] = f"FAIL:{type(exc).__name__}: {exc}"
            raise
        finally:
            _CURRENT["stage"] = None


# "当前正在执行的阶段"（见 `_RecStage` 的说明：用全局而非 thread-local）。
_CURRENT = {"stage": None}


def instrument(results, net_by_stage, domains=None, sent=None):
    """挂"按阶段计数"：包 `http_request` / `run_cmd`，装 DNS 覆盖（同时按解析计数），
    并把 `STAGE_REGISTRY` 换成代理。返回 `restore()`（务必在 finally 里调）。

    手法与 tests/smoke.py [6u] 一致：各模块是 `from ..utils import http_request`
    （把函数对象绑进自己的命名空间），只改 `utils` 对它们无效，必须逐模块替换。

    `sent` 非空时把每次 `http_request` 的 URL 追加进去（供"零外网"断言用）。
    """
    orig_http, orig_cmd = utils.http_request, utils.run_cmd
    http_mods = [m for m in list(sys.modules.values())
                 if str(getattr(m, "__name__", "") or "").startswith("scanner")
                 and getattr(m, "http_request", None) is orig_http]
    cmd_mods = [m for m in list(sys.modules.values())
                if str(getattr(m, "__name__", "") or "").startswith("scanner")
                and getattr(m, "run_cmd", None) is orig_cmd]

    def _bump():
        name = _CURRENT["stage"]
        if name:
            net_by_stage[name] = net_by_stage.get(name, 0) + 1

    def counting_http(url, *a, **k):
        _bump()
        if sent is not None:
            sent.append(str(url))
        return orig_http(url, *a, **k)

    def counting_cmd(argv, *a, **k):
        _bump()
        return orig_cmd(argv, *a, **k)

    for m in http_mods:
        m.http_request = counting_http
    for m in cmd_mods:
        m.run_cmd = counting_cmd

    orig_registry = dict(runner.STAGE_REGISTRY)
    runner.STAGE_REGISTRY = {
        n: (lambda ctx, _n=n, _c=c: _RecStage(ctx, _n, _c, results))
        for n, c in orig_registry.items()}

    # DNS 覆盖 + 解析计数：`on_lookup=_bump` 让每次系统解析都计入**当前阶段**。
    dns = DnsOverride(domains, on_lookup=_bump)
    dns.__enter__()

    def restore():
        for m in http_mods:
            m.http_request = orig_http
        for m in cmd_mods:
            m.run_cmd = orig_cmd
        runner.STAGE_REGISTRY = orig_registry
        dns.__exit__(None, None, None)

    return restore


def _skip_reason(stage, log_lines):
    """从任务日志里取该阶段**第一行** `[<stage>]` 文本作为跳过原因（取不到给占位串）。

    为什么取第一行：被跳过的阶段是**提前 return** 的，它的第一行日志就是跳过原因；
    而"跑到一半才判定无匹配"的阶段（如 intel 命中缓存），第一行也是最能说明问题的那句。
    原因取自**日志真实文本**（而不是写死一张 stage→原因 的表），改代码时报告自动跟着变。
    """
    tag = f"[{stage}]"
    for ln in log_lines or []:
        i = ln.find(tag)
        if i >= 0:
            text = ln[i + len(tag):].strip()
            return text or ln.strip()
    return "（任务日志中未找到该阶段记录）"


def skip_category(reason):
    """把跳过原因归类。原因文本来自日志，类别靠关键词判定（改文案时这里要一起看）。"""
    r = str(reason or "")
    if any(k in r for k in ("未配置", "未启用", "未开启")):
        return "未配置"
    if "缓存" in r:
        return "命中缓存"
    if any(k in r for k in ("无匹配", "无可匹配", "未命中", "命中 0")):
        return "无匹配"
    return "无输入"


def classify(results, net_by_stage, log_lines):
    """逐阶段定级，返回 `[(stage, status, detail, category), ...]`。

    status ∈ {OK, SKIP, FAIL}；SKIP 的 detail 是日志里的真实原因、category 是其归类。
    """
    rows = []
    for name in runner.STAGE_ORDER:
        raw = results.get(name)
        if raw is None:
            rows.append((name, "SKIP", "未执行（流水线提前结束？）", "无输入"))
        elif str(raw).startswith("FAIL:"):
            rows.append((name, "FAIL", str(raw)[len("FAIL:"):], ""))
        elif net_by_stage.get(name, 0) == 0 and name not in _NON_NET_STAGES:
            reason = _skip_reason(name, log_lines)
            rows.append((name, "SKIP", reason, skip_category(reason)))
        else:
            rows.append((name, "OK", f"{net_by_stage.get(name, 0)} 次网络活动", ""))
    return rows


def summarize(rows):
    """总结句（**不再**说"13 个阶段均无异常"）：真跑 / 跳过 / FAIL 各几个。"""
    ok = sum(1 for _n, s, _d, _c in rows if s == "OK")
    skip = sum(1 for _n, s, _d, _c in rows if s == "SKIP")
    fail = sum(1 for _n, s, _d, _c in rows if s == "FAIL")
    return (f"{len(rows)} 个阶段：{ok} 个真跑、{skip} 个跳过（原因见上）、"
            f"{fail} 个 FAIL")


def external_urls(sent):
    """从记录下来的 URL 里挑出**站外**的（主机名不在回环 / 夹具域名白名单内）。"""
    from urllib.parse import urlparse
    out = []
    for u in sent or []:
        host = (urlparse(str(u)).hostname or "").strip().lower()
        if host in ("127.0.0.1", "localhost", "::1"):
            continue
        if host == FIXTURE_DOMAIN or host.endswith("." + FIXTURE_DOMAIN):
            continue
        out.append(str(u))
    return out


def read_log_lines(log_file):
    """读任务日志文件的行（读不到给空表）。"""
    if not log_file:
        return []
    try:
        with open(str(log_file), "r", encoding="utf-8", errors="replace") as fh:
            return fh.read().splitlines()
    except OSError:
        return []


def run_selfcheck(settings, name="devflow-all13"):
    """跑一次全流程自检，返回结果字典（**不起/不读真实库，只写调用方已隔离的库**）。

    流程：起夹具（HTTP + HTTPS，**临时端口、只绑 127.0.0.1**）→ 用自检配置
    （压量 + 全阶段 + 关外网 + intel 指本地夹具）→ 装 DNS 覆盖与计数 → 真跑全 13 阶段 →
    逐阶段分类（原因取自任务日志）→ 停夹具。

    返回 dict：rows / total_net / elapsed / task_status / task_id / log_file / error /
    external / ok / skip / fail / exit_code（另有 `_results` / `_net` / `_log_lines` 三个
    "原始输入"，供 §6.1 变异证伪在**不重跑**的前提下对 `classify` 做反证）。
    """
    import time
    import warnings

    from . import db
    from .config import load_settings

    try:      # urllib3 对"未校验证书"的 HTTPS 会逐次告警 —— 夹具本来就是自签的，属预期噪声
        from urllib3.exceptions import InsecureRequestWarning as _IRW
    except Exception:      # noqa: BLE001 - 没有 urllib3 时（走 urllib 回退）无此告警
        _IRW = None

    settings = settings if settings is not None else load_settings()
    fx, http_base, https_base = devfixture.start_both()
    result = {"rows": [], "total_net": 0, "elapsed": 0.0, "task_status": "",
              "task_id": None, "log_file": "", "error": "", "external": [],
              "ok": 0, "skip": 0, "fail": 0, "exit_code": 0,
              "http_base": http_base, "https_base": https_base,
              "settings": None, "compressed": [],
              "_results": {}, "_net": {}, "_log_lines": []}
    try:
        with no_proxy_env(), warnings.catch_warnings():
            # 夹具是**自签**证书，probe/screenshot/dirscan/vulnscan 每次 HTTPS 都会触发
            # urllib3 的 InsecureRequestWarning —— 属预期噪声，压掉以免淹没自检报告。
            # `catch_warnings` 只临时改全局过滤状态，退出即还原（worker 线程共享同一份过滤表）。
            if _IRW is not None:
                warnings.simplefilter("ignore", _IRW)
            https_port = int(https_base.rsplit(":", 1)[1])
            eff = selfcheck_settings(settings, intel_url=http_base + "/intel/kev.json")
            result["settings"] = eff
            result["compressed"] = devmode.report(settings)
            targets = build_targets(https_port)
            stages = list(runner.STAGE_ORDER)
            # `offline=True`：跳过 subdomain / probe 里会发**外部**请求的被动源与 httpx 子进程
            # （自检铁律：零外网）。内置 DNS 爆破 / 内置探测仍照跑。
            options = {"offline": True}

            db.init_db()
            runner.sync_pocs(eff)
            tid = db.create_task(name, targets, stages, options)
            result["task_id"] = tid
            results, net_by_stage, sent = {}, {}, []
            restore = instrument(results, net_by_stage, sent=sent)
            t0 = time.time()
            try:
                runner.run_task(tid, name, targets, stages, options, eff)
            finally:
                restore()
            result["elapsed"] = time.time() - t0

            task = db.get_task(tid)
            result["task_status"] = str(task["status"] or "")
            result["log_file"] = str(task["log_file"] or "")
            result["error"] = str(task["error"] or "").strip()
            log_lines = read_log_lines(result["log_file"])
            result["_results"], result["_net"], result["_log_lines"] = results, net_by_stage, log_lines
            result["rows"] = classify(results, net_by_stage, log_lines)
            result["total_net"] = sum(net_by_stage.values())
            result["external"] = external_urls(sent)
            result["ok"] = sum(1 for _n, s, _d, _c in result["rows"] if s == "OK")
            result["skip"] = sum(1 for _n, s, _d, _c in result["rows"] if s == "SKIP")
            result["fail"] = sum(1 for _n, s, _d, _c in result["rows"] if s == "FAIL")
            result["exit_code"] = 1 if result["fail"] else 0
    finally:
        devfixture.stop(fx)
    return result
