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
import re
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


def instrument(results, net_by_stage, domains=None, sent=None,
               urls_by_stage=None, cmds_by_stage=None):
    """挂"按阶段计数"：包 `http_request` / `run_cmd`，装 DNS 覆盖（同时按解析计数），
    并把 `STAGE_REGISTRY` 换成代理。返回 `restore()`（务必在 finally 里调）。

    手法与 tests/smoke.py [6u] 一致：各模块是 `from ..utils import http_request`
    （把函数对象绑进自己的命名空间），只改 `utils` 对它们无效，必须逐模块替换。

    `sent` 非空时把每次 `http_request` 的 URL 追加进去（供"零外网"断言用）。
    `urls_by_stage` / `cmds_by_stage`（续62）非空时**另按阶段**记下 HTTP URL 与外部命令
    argv[0] —— 供"功能向量"判定（阶段内子能力靠日志/命令/URL 三种证据区分，见 `VECTORS`）。
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

    def _stage_key():
        return _CURRENT["stage"]

    def counting_http(url, *a, **k):
        _bump()
        if sent is not None:
            sent.append(str(url))
        if urls_by_stage is not None:
            name = _stage_key()
            if name:
                urls_by_stage.setdefault(name, []).append(str(url))
        return orig_http(url, *a, **k)

    def counting_cmd(argv, *a, **k):
        _bump()
        if cmds_by_stage is not None:
            name = _stage_key()
            if name:
                try:
                    a0 = argv[0] if isinstance(argv, (list, tuple)) and argv else str(argv)
                except (TypeError, IndexError):
                    a0 = ""
                cmds_by_stage.setdefault(name, []).append(str(a0))
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


# ---------- 功能向量（续62）：把覆盖从「阶段」下沉到「子能力」 ----------
#
# 背景：续52 的自检只判到**阶段**粒度 —— 阶段"有网络活动"就算 OK，可阶段内部往往有多个
# 子能力分支（如 dirscan 的"内置字典扫描 / dirmap / 框架补充 / 后缀派生 / 目录递归"），
# 只跑了其中一个就报 OK，其余没跑到也看不出来。用户要求"每个功能向量打一些，确保流程正确"，
# 故这里逐条列出**阶段内的子能力**，自检跑完后用**运行期真实证据**判定点到了没有。
#
# 字段：
#   stage/key/desc —— 所属阶段 / 向量键 / 人读描述
#   kind + kw      —— 判据：`log`=该阶段日志含 kw（可再加 `not_kw` 排除）；
#                     `regex`=该阶段日志匹配正则；`cmd`=该阶段跑过含 kw 的外部命令 argv[0]；
#                     `url`=该阶段请求过含 kw 的 URL；`nonet`=该阶段有网络活动（DNS/HTTP/子进程）。
#   tool           —— 判据依赖的外部工具；**未安装**则整条记 N-A（环境缺失，不算覆盖缺口）。
#                     `has_tool` 按**配置里的路径**（`tools.<名>`）解析，与阶段同口径。
#   na             —— 静态不可达原因（自检配置下**刻意**不跑，如 offline / 第三方关闭）。
#   na_log         —— `(关键词, 原因)`：命中该关键词说明**本次无此情形**（如浏览器截图失败、
#                     单次只跑一个引擎），记 N-A 并给出原因（**数据/环境条件**，不是覆盖缺口）。
#   optional       —— 该向量是**条件分支**（只有特定资产/数据下才触发）；未点到记 N-A，
#                     不与 `MISS` 混为一谈。**主路径**向量不设它 —— 那才是真缺口。
#
# 状态（`classify_vectors`）：OK=本次真点到；MISS=阶段跑了但这条**主路径**子能力没点到
# （**覆盖缺口**）；N-A=本次不该跑/工具没装/条件未出现（附原因，不是缺口）。
# 判据全部取自证据，不做"跑过就默认全绿"。
VECTORS = (
    # ---- subdomain ----
    # `auto_expand` 有**两个分支**都打 `自动拓展` 前缀：①目标是子域时补收主域名；
    # ②目标自带的子域按子域资产入库。自检目标里主域与子域同时给了，走的是 ②，
    # 故判据用前缀 `自动拓展`（两个分支都算这条子能力被点到），desc 写全两支。
    dict(stage="subdomain", key="auto-expand", desc="自动拓展（子域入库 / 补收主域名）",
         kind="log", kw="自动拓展"),
    dict(stage="subdomain", key="wildcard", desc="泛解析识别/过滤",
         kind="log", kw="泛解析"),
    dict(stage="subdomain", key="brute-builtin", desc="内置 DNS 爆破（系统解析器）",
         kind="log", kw="内置 DNS 爆破"),
    dict(stage="subdomain", key="resolve-backfill", desc="解析结果回填（IP/CDN）",
         kind="log", kw="回填解析结果",
         optional="本次新增子域名为 0（泛解析过滤），无可回填项"),
    dict(stage="subdomain", key="passive", desc="被动多来源收集（内置）",
         na="自检 offline=True 刻意跳过被动源（零外网铁律）"),
    dict(stage="subdomain", key="subfinder", desc="外部 subfinder 被动收集",
         na="自检 offline=True 刻意跳过被动源（零外网铁律）"),
    dict(stage="subdomain", key="puredns", desc="外部 puredns 爆破",
         na="自检 offline=True（puredns 与被动源一并跳过）"),
    # ---- takeover（需要带 CNAME 的子域，夹具无 CNAME → 条件分支）----
    dict(stage="takeover", key="cname", desc="CNAME 链解析",
         kind="log", kw="CNAME 解析", optional="本次无子域名资产（夹具无 CNAME）"),
    dict(stage="takeover", key="fingerprint", desc="子域接管指纹判定",
         kind="log", kw="接管指纹判定", optional="本次无带 CNAME 的子域名"),
    # ---- portscan（单次只跑**一个**引擎：优先级 fscan > nmap > 内置）----
    dict(stage="portscan", key="engine-fscan", desc="fscan 引擎",
         kind="cmd", kw="fscan", tool="fscan"),
    dict(stage="portscan", key="engine-nmap", desc="nmap 引擎",
         kind="cmd", kw="nmap", tool="nmap",
         optional="本次未选中 nmap（单次只跑一个引擎，优先级 fscan>nmap>内置）"),
    dict(stage="portscan", key="engine-builtin", desc="内置 TCP connect 引擎",
         kind="log", kw="扫描：内置 TCP connect",
         optional="本次未选中内置引擎（单次只跑一个引擎，优先级 fscan>nmap>内置）"),
    dict(stage="portscan", key="real-ip", desc="CDN 后取已解析真实 IP",
         kind="log", kw="已解析的真实 IP",
         optional="本次无已解析 IP 映射（前置阶段未产出）"),
    # ---- probe ----
    dict(stage="probe", key="builtin", desc="内置探测（https 优先、逐个回退 http）",
         kind="log", kw="内置探测"),
    dict(stage="probe", key="httpx", desc="httpx 子进程探测",
         na="自检 offline=True 刻意跳过 httpx 子进程"),
    dict(stage="probe", key="extra-ports", desc="纳入 portscan 开放端口候选",
         kind="log", kw="额外纳入", optional="本次 portscan 未产出开放端口候选"),
    dict(stage="probe", key="favicon", desc="favicon 指纹获取",
         kind="log", kw="favicon 指纹"),
    # ---- cert ----
    dict(stage="cert", key="tls", desc="TLS 证书取证（标准库握手）",
         kind="log", kw="→ CN="),
    # ---- screenshot ----
    dict(stage="screenshot", key="shot", desc="无头浏览器截图",
         kind="log", kw="→ shots/",
         na_log=("截图失败", "本机无头浏览器截图失败（环境问题，见阶段日志）")),
    # ---- jsmine ----
    dict(stage="jsmine", key="mine", desc="JS 域名/接口/凭据挖掘",
         kind="log", kw="挖掘 JS 资产"),
    # ---- dirscan ----
    dict(stage="dirscan", key="mode", desc="浅扫/深扫模式与技术栈分组",
         kind="log", kw="模式；技术栈分组"),
    dict(stage="dirscan", key="builtin", desc="内置字典扫描",
         kind="log", kw="内置扫描："),
    dict(stage="dirscan", key="dirmap", desc="dirmap 深扫",
         na="自检为浅扫 + offline（dirmap 只在深扫且非 offline 时跑）"),
    dict(stage="dirscan", key="fw-dict", desc="框架字典补充扫描",
         na="自检 fw_max_paths=0（框架补充扫描关闭）"),
    dict(stage="dirscan", key="suffix-derive", desc="后缀派生补扫",
         na="自检为浅扫（后缀派生只在深扫内置路径时触发）"),
    dict(stage="dirscan", key="recursive", desc="目录递归",
         na="自检 recursive_depth=0（递归关闭）"),
    # ---- vulnscan ----
    dict(stage="vulnscan", key="builtin-checks", desc="内置 OWASP 检查（有启用项）",
         kind="regex", kw=r"内置检查 [1-9]\d*/"),
    dict(stage="vulnscan", key="poc-engine", desc="POC 引擎（未关闭）",
         kind="log", kw="启用 POC", not_kw="POC 引擎已关闭"),
    # ---- intel ----
    dict(stage="intel", key="fetch", desc="情报源拉取（自检指向本地夹具 KEV）",
         kind="url", kw="/intel/kev.json"),
    dict(stage="intel", key="match", desc="情报 × 资产指纹匹配",
         kind="log", kw="命中"),
    # ---- heuristic ----
    dict(stage="heuristic", key="aggregate", desc="零请求本地聚合（产线索）",
         kind="log", kw="数据源：站点"),
    # ---- osint（第三方能力在自检副本里整体关闭）----
    dict(stage="osint", key="cseg", desc="C 段反查（iprecon）",
         na="自检关闭第三方能力（fofa/shodan/quake/ctlog）"),
    dict(stage="osint", key="fofa", desc="FOFA favicon/证书/标题反查",
         na="自检关闭第三方能力（fofa/shodan/quake/ctlog）"),
    dict(stage="osint", key="ctlog", desc="CT 日志（crt.sh）",
         na="自检关闭第三方能力（fofa/shodan/quake/ctlog）"),
    # ---- github ----
    dict(stage="github", key="search", desc="GitHub 公开代码泄露检索",
         na="自检清空第三方凭据 → 无 token，按设计零请求"),
)

_VECTOR_STATUSES = ("OK", "MISS", "N-A")

# 任务日志里的阶段分隔行（`===== 阶段 3/13：portscan =====`）—— 用来把日志**切给阶段**。
_STAGE_LINE_RE = re.compile(r"阶段\s+\d+/\d+：([a-z_]+)")


def split_log_by_stage(log_lines):
    """把任务日志按阶段切开：`{stage: 该阶段全部文本}`。

    为什么不"找 `[stage]` 前缀行"：阶段里有些行不带该前缀（阶段分隔行本身、子模块打的
    非阶段前缀日志），按分隔行切换归属才不会漏（漏了会把"没跑到"误报成覆盖缺口）。
    """
    out, cur = {}, None
    for ln in log_lines or []:
        m = _STAGE_LINE_RE.search(str(ln))
        if m:
            cur = m.group(1)
        if cur:
            out.setdefault(cur, []).append(str(ln))
    return {k: "\n".join(v) for k, v in out.items()}


class _Evidence:
    """自检一次运行的**只读证据快照**（供向量判据使用；判据绝不自己发请求/读库）。"""

    def __init__(self, results, net, urls, cmds, log_by_stage, settings=None):
        self.results = results or {}
        self.net = net or {}
        self.urls = urls or {}
        self.cmds = cmds or {}
        self.log = log_by_stage or {}
        self.settings = settings if isinstance(settings, dict) else {}
        self._tools = {}

    def stage_log(self, stage):
        return self.log.get(stage, "")

    def stage_urls(self, stage):
        return list(self.urls.get(stage) or [])

    def stage_cmds(self, stage):
        return [str(a) for a in (self.cmds.get(stage) or [])]

    def net_of(self, stage):
        return int(self.net.get(stage, 0) or 0)

    def has_tool(self, name):
        """外部工具在不在 —— 按**配置里的路径**（`tools.<名>`）解析，与阶段同口径。

        ⚠️ 不能用裸名查 PATH：`fscan` 在 `settings.yaml` 里配的是 `tools/fscan/fscan.exe`，
        裸名查 PATH 会得出"未安装"（阶段却明明跑了 fscan）—— 续62 自测踩过。
        解析走 `utils.which`（跨平台后缀容错）。结果缓存，避免重复探测。
        """
        if name not in self._tools:
            conf = (self.settings.get("tools") or {}).get(name) or name
            try:
                self._tools[name] = bool(utils.which(conf))
            except Exception:      # noqa: BLE001 - 探测异常按"没有"处理，绝不因它炸自检
                self._tools[name] = False
        return self._tools[name]


def _vector_hit(v, ev):
    """单条向量的判据求值（证据不足一律 False，由调用方决定记 MISS 还是 N-A）。"""
    kind, kw, stage = v.get("kind"), v.get("kw"), v["stage"]
    if kind == "log":
        text = ev.stage_log(stage)
        if kw not in text:
            return False
        not_kw = v.get("not_kw")
        return not (not_kw and not_kw in text)
    if kind == "regex":
        return re.search(kw, ev.stage_log(stage)) is not None
    if kind == "cmd":
        return any(kw in c for c in ev.stage_cmds(stage))
    if kind == "url":
        return any(kw in u for u in ev.stage_urls(stage))
    if kind == "nonet":
        return ev.net_of(stage) > 0
    return False


def classify_vectors(stage_rows, ev):
    """逐条判定功能向量，返回 `[(stage, key, desc, status, detail), ...]`。

    status ∈ {OK, MISS, N-A}（见 `VECTORS` 上方说明）。优先级：静态 N-A > 工具缺失 N-A >
    阶段 FAIL > 判据命中 OK > 环境/条件 N-A（`na_log` / `optional`）> 阶段跳过 N-A >
    否则 MISS（阶段跑了却连**主路径**都没点到 = 覆盖缺口）。
    """
    stage_status = {n: s for n, s, _d, _c in stage_rows}
    rows = []
    for v in VECTORS:
        stage = v["stage"]
        st = stage_status.get(stage, "")
        if v.get("na"):
            rows.append((stage, v["key"], v["desc"], "N-A", v["na"]))
            continue
        if v.get("tool") and not ev.has_tool(v["tool"]):
            rows.append((stage, v["key"], v["desc"], "N-A",
                         f"外部工具未安装：{v['tool']}"))
            continue
        if st == "FAIL":
            rows.append((stage, v["key"], v["desc"], "N-A", "阶段 FAIL，未判定"))
            continue
        if _vector_hit(v, ev):
            rows.append((stage, v["key"], v["desc"], "OK", ""))
            continue
        na_log = v.get("na_log")
        if na_log and na_log[0] in ev.stage_log(stage):
            rows.append((stage, v["key"], v["desc"], "N-A", na_log[1]))
            continue
        if v.get("optional"):
            rows.append((stage, v["key"], v["desc"], "N-A", v["optional"]))
            continue
        if st in ("", "SKIP"):
            rows.append((stage, v["key"], v["desc"], "N-A",
                         "阶段本次跳过（见阶段判定）"))
        else:
            rows.append((stage, v["key"], v["desc"], "MISS",
                         "阶段已跑，但该子能力未被点到"))
    return rows


def summarize_vectors(rows):
    """向量总结句：真点到 / 覆盖缺口 / 不可达各几条。"""
    ok = sum(1 for _s, _k, _d, st, _x in rows if st == "OK")
    miss = sum(1 for _s, _k, _d, st, _x in rows if st == "MISS")
    na = sum(1 for _s, _k, _d, st, _x in rows if st == "N-A")
    return (f"{len(rows)} 个功能向量：{ok} 个点到、{miss} 个覆盖缺口、"
            f"{na} 个本次不可达（原因见上）")


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
    续62 另加：vectors（功能向量判定）/ vec_ok / vec_miss / vec_na，以及 `_urls` /
    `_cmds` / `_log_by_stage`（向量判据的原始证据，同样供变异证伪复算）。
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
              "vectors": [], "vec_ok": 0, "vec_miss": 0, "vec_na": 0,
              "http_base": http_base, "https_base": https_base,
              "settings": None, "compressed": [],
              "_results": {}, "_net": {}, "_log_lines": [],
              "_urls": {}, "_cmds": {}, "_log_by_stage": {}}
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
            # `auto_expand=True`：目标是 `aaa.devfixture.test` 这种子域时**自动补收主域名**
            # （subdomain 阶段 0 号分支）。不开的话这条子能力在自检里永远是 MISS ——
            # 它是**任务级**选项、默认关，只有显式打开才走。
            options = {"offline": True, "auto_expand": True}

            db.init_db()
            runner.sync_pocs(eff)
            tid = db.create_task(name, targets, stages, options)
            result["task_id"] = tid
            results, net_by_stage, sent = {}, {}, []
            urls_by_stage, cmds_by_stage = {}, {}
            restore = instrument(results, net_by_stage, sent=sent,
                                 urls_by_stage=urls_by_stage,
                                 cmds_by_stage=cmds_by_stage)
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
            log_by_stage = split_log_by_stage(log_lines)
            result["_results"], result["_net"], result["_log_lines"] = results, net_by_stage, log_lines
            result["_urls"], result["_cmds"], result["_log_by_stage"] = (
                urls_by_stage, cmds_by_stage, log_by_stage)
            result["rows"] = classify(results, net_by_stage, log_lines)
            result["total_net"] = sum(net_by_stage.values())
            result["external"] = external_urls(sent)
            result["ok"] = sum(1 for _n, s, _d, _c in result["rows"] if s == "OK")
            result["skip"] = sum(1 for _n, s, _d, _c in result["rows"] if s == "SKIP")
            result["fail"] = sum(1 for _n, s, _d, _c in result["rows"] if s == "FAIL")
            result["exit_code"] = 1 if result["fail"] else 0
            # 功能向量（续62）：判据只用上面已抓到的证据，**不再发任何请求**。
            # `settings=eff` 必须传：`has_tool` 要按**配置里的路径**（`tools.<名>`）解析工具，
            # 否则裸名查 PATH 会把"装了 fscan（配在 tools/fscan/fscan.exe）"误判成未安装。
            ev = _Evidence(results, net_by_stage, urls_by_stage, cmds_by_stage, log_by_stage,
                           settings=eff)
            result["vectors"] = classify_vectors(result["rows"], ev)
            result["vec_ok"] = sum(1 for _s, _k, _d, st, _x in result["vectors"] if st == "OK")
            result["vec_miss"] = sum(1 for _s, _k, _d, st, _x in result["vectors"] if st == "MISS")
            result["vec_na"] = sum(1 for _s, _k, _d, st, _x in result["vectors"] if st == "N-A")
    finally:
        devfixture.stop(fx)
    return result
