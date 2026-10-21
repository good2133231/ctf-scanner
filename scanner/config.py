"""全局配置加载。

三段配置来源（职责分离，避免"改策略把凭据一起写回去"）：
- `config/settings.yaml`（或 settings.json）：扫描策略/限制/工具路径，GUI「策略配置」页写回；
- `config/keys.yaml`：**第三方 API key 专用文件**（用户要求"回头专门搞个文件配置"），
  只读、GUI 不碰、默认加入 .gitignore，见 `load_keys()`；
- `DEFAULTS`：以上文件缺失或损坏时的兜底值。
"""
import copy
import json
import os
import pathlib
import re
import secrets

BASE_DIR = pathlib.Path(__file__).resolve().parent.parent

# Git Bash / MSYS / WSL 里 `$PWD` 展开成 `/c/Users/...` 这种"盘符式 POSIX 路径"
# （单个字母的顶层目录 = 盘符，后面才是真正的目录）。
_DRIVE_POSIX_RE = re.compile(r"^/([A-Za-z])(?:/(.*))?$")


def _norm_drive_posix(text):
    """（仅 Windows）把 `/c/Users/x` 归一成 `C:\\Users\\x`；不是这种形态则原样返回。

    POSIX 系统（Linux/macOS）**必须原样保留**：那里 `/c/...` 就是一个普通目录，
    当成盘符翻译会把路径改坏。
    """
    if os.name != "nt":
        return text
    m = _DRIVE_POSIX_RE.match(text)
    if not m:
        return text
    rest = (m.group(2) or "").replace("/", os.sep)
    return m.group(1).upper() + ":" + os.sep + rest


def env_path(name, default):
    """读"路径型"环境变量：`CTFSCANNER_DB` / `CTFSCANNER_LOGS` 这类入口统一走这里。

    归一化只做三件必要的事，其余交给 `pathlib`：
    ① 空值 / 纯空白 → 用默认值（Git Bash 里 `export X=` 很常见，不能据此建出 `.` 这种目录）；
    ② 剥掉用户可能顺手加上的外层引号（从命令行复制路径时常带）；
    ③ **仅 Windows**：把盘符式 POSIX 路径翻译成盘符形态（见下）。

    为什么要 ③（真实踩过的坑，不是假想）：Git Bash 里写
    `export CTFSCANNER_DB="$PWD/logs/x.db"`，传进来的是 `/c/Users/...`；
    而 Windows 的 `pathlib.Path("/c/Users/...")` 会把它当成**"当前盘符根下的 c 目录"**，
    解析出 `\\c\\Users\\...` —— 结果测试库被建到盘符根（`C:\\c\\...`），
    且 `utils.rel_display()` 打印出缺了盘符的残缺路径。多会话并行时这个坑必然再踩一次，
    光清目录只治标，所以归一放在入口。

    刻意**不用 `resolve()`**：仓库里 `tools/dirmap/` 是**目录联接**（指向仓库外的第三方源码），
    resolve 会穿过联接把路径变成外部真实路径，日志与测试断言就全变了。
    """
    raw = str(os.environ.get(name) or "").strip()
    # 外层成对引号才剥（路径中间出现引号的情况不处理，交给 pathlib 原样保留）
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in ("'", '"'):
        raw = raw[1:-1].strip()
    if not raw:
        return pathlib.Path(str(default))
    return pathlib.Path(_norm_drive_posix(raw))


def gui_bind(settings):
    """GUI 监听 `(host, port)`：**环境变量优先**，其次 `gui.host` / `gui.port`，最后默认值。

    为什么需要它：容器 / 编排（Docker）里不方便改 `config/settings.yaml`，而容器内**必须**
    绑 `0.0.0.0` 才能被端口映射访问到 —— 于是给出 `CTFSCANNER_GUI_HOST` / `CTFSCANNER_GUI_PORT`。
    与 `CTFSCANNER_DB` / `CTFSCANNER_LOGS` 同一套"运行环境用环境变量覆盖"的口径。

    **只覆盖这两项**（刻意）：`gui.allowed_hosts` / `behind_proxy` / `secure_cookie` 是**安全开关**，
    必须显式写在配置里 —— 让一个"顺手设了"的环境变量把它们悄悄打开，比绑错地址危险得多。
    """
    cfg = (settings or {}).get("gui") or {}
    host = str(os.environ.get("CTFSCANNER_GUI_HOST") or "").strip() \
        or str(cfg.get("host") or "127.0.0.1").strip() or "127.0.0.1"
    raw_port = str(os.environ.get("CTFSCANNER_GUI_PORT") or "").strip() or cfg.get("port", 5000)
    try:
        port = int(raw_port)
    except (TypeError, ValueError):
        port = 5000          # 端口写成非数字时退回默认，**不因此起不来**
    return host, port


# 运行期产物目录（每任务一个子目录）。与数据库一样支持环境变量覆盖：
# 跑测试时指到临时目录，就不会在真实工作区里堆出几十个 `logs/task_*` 目录，
# 也让"开发/生产共用一份代码、数据分开"变得可行（见 tests/smoke.py 顶部）。
# 走 `env_path()` 是为了把"盘符式 POSIX 路径"在入口归一（见其注释里的踩坑说明）。
LOGS_DIR = env_path("CTFSCANNER_LOGS", BASE_DIR / "logs")

DEFAULTS = {
    "gui": {
        "host": "127.0.0.1",
        "port": 5000,
        # 续233（主理人规则）：起动时端口被占 ⇒ 直接结束占用者、占回首选端口。
        # 护栏见 scanner/portguard.py；环境变量 CTFSCANNER_GUI_KILL_PORT=0 可临时关。
        "kill_port_on_conflict": True,
        # 续117：**这一段里不再有登录凭据**。原先的 `token`（明文引导口令）与续113 补的
        # `token_hash` 整支摘掉 —— 本文件**被 git 跟踪**，"口令类的值"写进来就等于公开；
        # 而这条门只在"库里一个账号都没有"时才必要，那件事用一次交互式建号就能覆盖。
        # 现在的路径：首次启动（0 账号 + 可交互终端）→ `gui/app.py::serve()` 的向导建管理员；
        # 容器 / 只读挂载 / 忘了口令 / 被锁定 → `python cli/run_users.py --create-admin | --reset-password`。
        # 老配置里残留的值不再被任何代码读取；清除是**显式动作**：`cli/run_users.py --purge-legacy-token`。
        # ---- 部署到服务器（续47，见 docs/deploy-https.md）----
        # 三项默认值都是**最保守**的：不开任何"图省事"的口子，要用必须显式配。
        # allowed_hosts：Host 白名单的**显式**扩展（空 = 只认回环名，与续32 行为逐字节一致）。
        #   反代部署时浏览器发来的 Host 是部署域名，不填这里会**整站 403**；
        #   只接受明确枚举的域名，含 `*` / `?` 的值会被忽略（不允许"放行一切"）。
        "allowed_hosts": [],
        # 续135：true = 把**本机网卡地址**自动并入放行集合（`gui/app.py::_local_host_names`）。
        # 存在的理由就是不许再往这个被跟踪的文件里写任何机器特定的 IP。默认关：
        # 当前部署口径是"不要 Host 拦截"（`allowed_hosts: []` ⇒ 守卫放宽），不替他做这个决定。
        "allowed_hosts_auto_local": False,
        # ---- 后台路径随机化（续138，用户点单）----
        # true（默认）= 每次启动把整个控制台挂到新生成的两段随机路径下（共 20 位字符），
        # 根路径与错误路径一律 404 空响应。它**不是访问控制** —— 拿到 URL 的人照样到得了登录页，
        # 真门槛是 401 边缘门 + users 表；这里买的是"扫端口/爬根目录找不到入口"。
        # 设 false 就挂回根路径（旧行为）。页面上改不了这一项，只能手改本文件
        # （先例 = login_lockout / audit / keys_ask_passphrase）。
        # 临时指定固定前缀走环境变量 CTFSCANNER_WEB_PATH（空串＝根路径），不写进任何文件。
        # 续156（主理人点单）：控制台进程**不再把逐条 INFO 刷到终端**——常驻 GUI 一开几十
        # 个阶段，终端滚动本身成了瓶颈，而该看的地方一直是 `logs/server.log` 与每个任务的
        # `task.log`（页面上的「任务日志」面板读的就是后者）。CLI 不受这项影响：它不动开关。
        "console_logs": False,
        # 续157 #D：启动横幅要不要问第三方 https 接口取"公网出口 IP"（续150 加的那行）。
        # 开着才去问（默认开，主理人 2026-10-11 拍板"可以用第三方"）；关掉＝一个外发请求都不发，
        # 横幅首行只印绑定值。绑回环时本来就不取；取不到一律静默降级，绝不拖住启动。
        "announce_egress_ip": True,
        # 续197（主理人点单「站点不是有很多注释解释吗？我们系统设置默认关闭注释，可手动开启注释」）：
        # 页面上那些灰色小字**说明段**（class="note"）默认**不渲染出来**（CSS 隐藏，不是不输出）。
        # 两层开关：这一项是全局默认；顶栏「显示说明」写 cookie，只影响这台浏览器且优先级更高。
        "notes": False,
        "web_path_random": True,
        # behind_proxy：是否信任反向代理转发的 `X-Forwarded-Proto/Host/For`。
        #   默认关 —— 它是**请求头**，任何客户端都能伪造，无条件信任会让 Host 白名单
        #   与 Origin 校验一起失效。只有"应用只被自己的反代访问"时才该打开。
        "behind_proxy": False,
        # secure_cookie：会话 Cookie 是否加 `Secure`（只在 HTTPS 下回传）。
        #   默认关 —— 走 HTTP 时开了它浏览器根本不回传 Cookie，等于登录不上；
        #   上了 TLS 反代之后再打开，否则口令 Cookie 可能被明文带出去。
        "secure_cookie": False,
        # ---- 401 边缘认证门（用户 2026-10-08 点名，见 scanner/edgeauth.py）----
        # **默认关**：这里只写"要不要挂这道门"。口令在 `config/edge_auth.yaml` —— 明文，但该文件
        # 与 `config/keys.yaml` 同一条红线（在 .gitignore 里）：**本文件被 git 跟踪、仓库公开**，
        # 口令写进任何被跟踪文件都等于交给全世界，而且 git 历史不会忘。开关与凭据分两个文件
        # 正是为此。设成 true 而口令文件缺失**或为空** → 一律 401（fail-closed）。
        "edge_auth": {"enabled": False},
        # ---- keys.enc.yaml 的启动解锁询问（续133）----
        # **默认 true**：续98 的口径是"启动时问一次"，把默认值改成 false 会让别人家的加密凭据
        # 静默不可用。本机设 false 是因为用户明确不要这句打扰；手改键，先例 = login_lockout/audit。
        "keys_ask_passphrase": True,
        # ---- 登录限速 / 失败锁定（续48，见 scanner/login_guard.py）----
        # 保护性开关**默认开**，但阈值刻意宽松：本机/小队共用场景里，"一次记错口令"不该把
        # 队友挡在门外。两级判据：按 IP 为主（5 次/5 分钟），按用户名兜底（20 次/5 分钟），
        # 触发后锁 15 分钟。被锁时返回 429 + Retry-After（不是 403），且文案与"账号是否存在"无关。
        "login_lockout": {
            "enabled": True,
            "window_seconds": 300,      # 失败计数时间窗（秒）
            "max_fails_per_ip": 5,      # 同一 IP 在窗口内的失败上限（续108：10 → 5）
            "max_fails_per_user": 20,   # 同一用户名在窗口内的失败上限（兜底，更宽松）
            "lockout_seconds": 900,     # 触发后的锁定时长（秒）
        },
        # ---- 访问审计流水（续48，见 scanner/audit.py）----
        # 记录"谁/何时/从哪个 IP/做了什么/成败"，**只记元数据、绝不记口令与凭据**。
        # retention_days：超过该天数的审计行在启动时被清理（只清 audit_log 一张表）。
        "audit": {
            "enabled": True,
            "retention_days": 30,
        },
    },
    "queue": {
        # ---- 持久化任务队列（续49，见 scanner/queue.py）----
        # 任务不再由 GUI 直接起线程，而是入队由 worker 消费 —— 进程重启后任务不丢
        # （死掉的 running 会被对账**重新入队**，见 db.reconcile_orphan_tasks）。
        # workers：并发消费者数。**默认 1 = 串行** —— 最省目标侧带宽、最不容易触发风控/封禁；
        #   只有部署到服务器、确有多任务并行需求时才调大（上限 8）。>1 时靠
        #   `db.claim_next_queued` 的原子认领保证同一任务不被重复消费。
        "workers": 1,
        # 续184：true ＝ 再按机器规格收一道上限（小 1 / 中 2 / 大 4），配置值仍是天花板。
        "workers_auto": False,
        # 续215-P2-12：true ＝ 再用**最近一次真任务实测**（CPU 几核 / 峰值内存）收一道，
        # 只会往下收。首次运行还没有画像时原样不动；下一次**启动**队列才生效。
        "workers_profile": True,
    },

    "dev": {
        # ---- 开发模式 / 全流程自检（续50，见 scanner/devmode.py）----
        # 打开后，各阶段的"量"（并发 / 在飞 / 速率 / 每阶段配额）被**运行时压到最小（1）**，
        # 目的是先验证**流程本身能不能跑通**，不被"量"的问题干扰。压量只作用于**本次运行的内存副本**，
        # 绝不写回 config/settings.yaml（见 devmode 文件头）。默认关。
        # fixture_port：内置靶场端口，0 = 交给系统分配（避免与已占用端口冲突）。
        "enabled": False,
        "fixture_port": 0,
    },
    "limits": {
        "max_workers": 20,        # HTTP 探测 / 目录扫描 / DNS 爆破线程数
        # 动态并发档（续179，参照 recon-spiral"按产出加码"）：fixed = 整批开满 max_workers
        # （现状，默认）；ramp = 从 workers_floor 起步、每批有产出就翻倍封顶（零产出的批
        # 不升档）—— 小任务不再一上来就开满线程。基准实测数字见 CHANGELOG 续179。
        "workers_mode": "fixed",
        "workers_floor": 4,
        # 按机器规格收并发上限（续181，借鉴点⑤）：false＝只认 max_workers（现状）；
        # true＝min(max_workers, machine_tier 建议值) —— 小机器自动收敛，机器再大也不超配置。
        "workers_auto": False,
        # 续215-P2-12：true＝再按**上一轮真任务实测**（cpu_ratio / peak_rss_mb）收一道。
        # 两个开关独立：只开 profile 也能按实测收，只是不做机器档位那一道。
        # 无画像（首跑/老库）时原样不动 —— 没有证据就不降档。
        "workers_profile": True,
        "http_timeout": 10,       # 单请求超时（秒）
        "verify_tls": False,
        # 第三方接口（FOFA/Shodan/Quake/crt.sh/KEV/iprecon/api.github.com）的证书校验。
        # **与 verify_tls 刻意分开**：那一项是给**目标侧**自签名靶场降级用的；第三方是公网
        # CA 签名、且多带 API key / PAT，跟着一起降级＝把凭据挂上可被中间人读的信道（续42）。
        "verify_tls_external": True,
        "dirscan_max_urls": 20,   # 每任务最多参与目录扫描的站点数
        "vulnscan_max_urls": 100, # 每任务最多参与漏洞扫描的站点数
        "brute_max_domains": 50,  # 每任务最多参与 DNS 爆破的域名数
        # 字典爆破的词数闸门（续139，喂进深档之后必须有）。`brute_max_words` 管 puredns 那一路的
        # 深档上限、`brute_fallback_max` 管内置那一路的深档上限 —— **两道都只冲深档，
        # 精简档（`dicts.subdomains`）任何情况下全量在场**。超出即等距抽样，0=全量。
        # 想吃下深档全量请装 puredns（`cli/client.py --update-tools --tool puredns`）。
        "brute_max_words": 0,
        # 内置 DNS 爆破的并发（纯 DNS 等待，与 HTTP 的 max_workers 分开）。
        # 实测这台机器：3000 条 @20 线程 ≈ 53 秒；把闸门放到 0（全量 17.8 万条）即便
        # 128 线程也**跑了 45 分钟没跑完** ⇒ 内置那一路吃深档全量是小时级的，
        # 真要全量就得装 puredns（它自带高并发与限速）。这一档只是把 3000 条压到几十秒。
        "brute_workers": 64,
        # 组合爆破（`a-b` 两两拼，对齐灯塔 alt_dns）每域名的词数上限；0=关。
        # 深档里也没有的那批名字（`api-contract`/`ws-spot`…）只能靠拼 —— 见 `subdomain.py` 4b。
        "brute_combo_max": 4000,
        "brute_fallback_max": 3000,
        "brute_dict_warn_min": 1000,
        # 二层遍历每轮最多补探多少个主机（续139，`probe.second_pass`）；攒够就停止 DNS 预筛。
        "recrawl_max_hosts": 300,
        # 拓展域名「送去探测」全任务模式下的目标数上限（0=不限，续154）：
        # 拓展域名动辄上百个，一次点击要能扩出上百个目标的探测任务，就得有个默认的刹车。
        "ext_probe_max": 100,
        "wildcard_filter": True,  # 泛解析过滤（关闭后字典爆破会保留通配命中，噪声极大）
        "favicon_md5": True,      # probe 阶段计算 favicon MD5（零请求前置指纹，见 P1-1）
        # 统一并发 / 限速 / 全局预算门控（F2，见 scanner/throttle.py）。
        # 默认路径**永不触发拒绝**：256 恰好等于现有单任务最大并发（portscan.full_workers），
        # 单任务行为完全不变，只把"跨任务的 N×2048"夹到 256；rate / budget 默认 0 = opt-in
        # （限速会改变扫描时长语义、预算会截断合法扫描，无普适值，故默认不启用）。
        "max_inflight_global": 256,     # 进程级在飞上限（跨任务共享）；0=不限
        "max_inflight_per_task": 256,   # 单任务在飞上限；0=不限
        "rate_per_sec": 0,              # 令牌桶速率（次/秒）；0=不限速
        "rate_burst": 0,                # 令牌桶突发容量；0 → 取 max(rate_per_sec, 1)
        "budget_total": 0,              # 单任务请求总预算（HTTP/裸 socket/子进程共用）；0=不设预算
        "budget_subprocess_weight": 1,  # 每次外部工具调用消耗的预算单位
        # 外部引擎自管流量的**预估与硬上限**（续128，`scanner/extcost.py`）。上面那条预算只管
        # "我们起几个子进程"，管不到子进程自己发多少 —— afrog 一轮是 `站点 × 只读 PoC` 次 HTTP
        # 请求，fscan/nmap 一次是 `主机 × 端口` 次探测。这两个数字单位不同，刻意**不合并**成
        # 一个"总数"（把端口探测当 HTTP 请求数是假等价），所以各配一个上限。
        # 默认 0 = 不限（与 `budget_total`/`rate_per_sec` 同一条 F2 规矩：默认路径永不触发拒绝；
        # 本机默认 engine=auto + fscan 可用，任何非零默认值都会顺手改变既有行为）。
        # **预估数字无论有没有设上限都会打进日志** —— "如实声明"是这一处的下限。
        "external_max_requests": 0,      # afrog 一轮预估的 HTTP 请求数上限；0=不限
        "external_max_port_probes": 0,   # fscan/nmap 一轮预估的端口探测次数上限；0=不限
    },
    "checks": {
        # 检测分级门控：只保留 severity >= min_severity 的结果。
        # CTF 实战默认 medium（低危/info 默认关闭，避免"太 low 的洞"淹没结果）；
        # 想要广谱信息收集时改为 "low" 或 "info"。
        "min_severity": "medium",
        "skip_severities": ["info", "low"],  # 这些级别**根本不执行**（见下方 skip_severities()）
        "poc_engine": True,        # POC 引擎总开关（关闭后只跑内置 OWASP 启发式检查）
        "disabled_categories": [], # 按 OWASP 分类关闭，如 ["A05", "A08"]
        "disabled_checks": [],     # 按检查项 id 精确关闭，如 ["a01-open-redirect"]
        "poc_link_tags": True,     # 指纹→POC 联动：站点技术栈命中的 POC 优先执行（P1-1）
        "poc_max_per_site": 80,    # 每站点最多执行多少个 POC（联动命中项不受此上限约束）
        # 续151（用户点单「尝试添加机器学习扫描」）：POC 优先级排序 —— 用 `data/ml/poc_model.json`
        # （朴素贝叶斯，训练自历史的 (站点,poc)→命中/未命中）给候选打分排序。**默认关**；
        # 没模型时一行说明、维持原顺序，绝不改变"哪些 POC 会被执行"的集合。
        "poc_priority": False,
    },
    "subdomain": {
        # 子域名资产回填：给每个子域名解析出 A 记录 IP 与 CNAME 链，并按
        # `config/dicts/cdn_cname.txt` 标出 CDN 厂商（纯 DNS 只读查询，不发 HTTP）。
        # 上限控制 DNS 查询量；超出的子域名仍入资产表，只是没有 IP/CDN 这两列。
        "max_resolve": 500,
        "dns_timeout": 3,
        # 子域名收集"要主动且全"：subfinder（-all 全来源）与内置免 key 被动源
        # **取并集**（默认开）。原实现是 elif —— 装了 subfinder 就不跑内置源，
        # 会白丢 crt.sh / certspotter / alienvault 这批证书与情报源。关掉可省时间。
        "union_passive": True,
        # 目标是 URL / 子域时**自动提取注册域**当收集根（续145，用户点单："就算我扫描目标
        # 给你的是 url 地址，你也能自动提取出主域"）。默认开：此前给一条
        # `https://www.a.com/x`，subdomain 阶段会整段跳过，人只能自己把主域抠出来再填一遍。
        # 关掉＝只用目标里写的那个名字（续145 之前的行为）。
        "auto_root": True,
        # 续160：把「库里其他任务已发现过、且归属本次目标」的自家子域名也并进候选与资产。
        # 动机是实测到的上游抖动：同一目标两次跑，subfinder 一次给 8 个、一次给 7 个，
        # 少掉的那个名字会让「端口 → 站点 → 指纹 → 漏洞」整条链空掉（`ibt4` 那次的现场）。
        # 上限是防"历史越攒越多"把 DNS 与探测量放大；关掉即退回"只信本轮新发现"。
        "reuse_history": True,
        "reuse_history_max": 300,
        # 续169：拓展域名「自动递归」的两档默认（层数 + 置信度阈值）。**默认组合＝不扩**：
        # 层数 1 时 `runner._maybe_queue_next_layer` 直接早退，阈值一个字都不参与。
        # 层数 N>1 ＝ 每一层把「本轮新确认的自家域名」再追加采集一次（上限 10，见
        # `runner.EXT_DEPTH_MAX`）；阈值「高」＝ 只有像到「多半是自家另一个 TLD」那种程度的
        # 拓展域名才跟着进下一层 —— 判据与依据文本只有 `scanner/extdom.py::confidence()` 那一份。
        # 第三方 / CDN / 黑名单命中**无论多像都不自动扫**（`extdom.auto_expand_block()`）。
        "ext_depth": 1,
        "ext_min_confidence": "high",
    },
    "passive": {
        # 多来源被动子域名收集（免 API key 的公开接口，见 scanner/passive.py）
        "enabled": True,
        "sources": [],             # 留空 = 用 scanner.passive.DEFAULT_SOURCES
        "timeout": 20,             # 单个源的请求超时（秒）
    },
    "evasion": {
        # 动态免杀：UA 随机化 / 请求头伪装 / 注入 payload 变形
        "random_ua": True,         # 每个请求从内置浏览器 UA 池随机取
        "spoof_xff": False,        # 附带 X-Forwarded-For（部分 WAF 按此判定"内网"而放行）
        "waf_bypass": True,        # 注入类检查启用 payload 变形绕过
        "bypass_level": 2,         # 0=原始 1=轻量(注释/大小写) 2=进阶(编码/分片) 3=激进(多重编码)
        "waf_detect": True,        # 探测目标是否存在 WAF 并在日志中提示
    },
    "takeover": {
        # 子域接管检测（P0-2）：CNAME 指向已停用的第三方服务 → 可被他人注册接管
        "enabled": True,
        "max_hosts": 300,          # 每任务最多检查多少个子域名（DNS 查询量上限）
        "http_check": True,        # 命中可疑 CNAME 后再做一次 HTTP 判定（降低误报）
    },
    "portscan": {
        # 端口扫描（P1-2）：默认关闭 —— CTF 里它噪声与耗时都大，需要时在策略配置里打开
        "enabled": False,
        "max_hosts": 100,          # 每任务最多扫描多少个主机
        # 续250：常见 web 端口（显式列；空串仍表示"内置 TOP 48"——那是通用服务档）
        "ports": "80,81,443,3000,5000,5001,7001,7002,8000,8001,8002,8008,8080,8081,8082,8088,8443,8888,9000,9090,9443",
        # 全端口扫描：`mode="full"` 时对 `full_ports`（默认 1-65535）逐端口 connect。
        # 6.5 万次连接耗时可观，但**续144 起默认就是 full**（用户点单"全部默认开"）——
        # 于是 `full_workers` / `full_timeout` 才是全端口实际吃的那两个值，
        # `workers` / `timeout` 只在 top 档生效。想对单个 IP 补一次全端口而不改全局策略，
        # 走 GUI「全端口扫描」页（任务选项 `portscan_full` 单次触发）。
        # 续250（主理人点单）：默认只打**常见 web 端口**；full＝1-65535 改为**单任务触发**
        # （任务详情「端口」页签按钮 / CLI --portscan-full / 侧栏「全端口扫描」页）。
        "mode": "top",             # top＝内置 TOP 端口或 ports 显式列表
        "full_ports": "1-65535",
        "exclude_scanned": True,   # 跳过本任务已经扫过的端口（全端口扫描时尤其有用）
        # 全端口专用并发/超时（只在 full 模式生效，不动 TOP 模式的既有行为）。
        # 实测：65535 端口在 64 并发 × 1.0s 超时下要跑十几分钟（关闭端口得等满超时），
        # 换成 256 并发 × 0.5s 只需 ~82 秒（续197：旧注释写的 0.3 已与这里的 0.5 漂移，
        # 数字以本行为准）。想更快就继续加并发/降超时（注意目标侧压力）。
        "full_workers": 256,
        "full_timeout": 0.5,
        # 单端口连接超时（秒）—— **只在 top 档生效**（默认档是 full，走上面那个）。
        # 另有一条实测边界：引擎是 fscan 时这两个值都会被量化到整秒（`-time` 只认整秒、
        # 下限 1 秒），所以 0.5 打到 fscan 上就是 1 秒；想真吃到小数超时就钉 `engine: builtin`。
        "timeout": 1.0,
        "workers": 64,             # 并发连接数
        "banner": True,            # 连接成功后尝试读取 banner（纯被动读取）
        # 引擎选择：auto = fscan → nmap → 内置 TCP connect（谁可用/有结果用谁）；
        # 也可钉住 "fscan" / "nmap" / "builtin"。fscan 快得多（默认 600 线程，适合全端口），
        # 但输出格式随版本浮动；钉住的那个不可用时会退回内置实现并在日志里说明。
        "engine": "auto",
        # 续151 无依赖 ML（默认关）：内建服务表与关键词都没认出来时，用 banner 的字符 n-gram
        # 朴素贝叶斯补一个服务名（模型 `data/ml/service_model.json`）。没模型不动。
        "ml_service": False,
    },
    "icp": {
        # 备案反查（续205）。**默认关**，且源全部走配置 —— 加一个可达的源就是往
        # `sources` 里加一行，不改代码（{{domain}} 会被替换成要查的域名；
        # `key_header` 非空时把 api_key 按那个头名带上，值只进 keys.enc.yaml）。
        # 为什么默认关、为什么预置的是国内域名：见 scanner/icp.py 顶部说明。
        "enabled": False,
        "preflight": True,          # 开跑前每个源先探一次，不通的整轮跳过并说清
        "max_domains": 50,          # 最多查多少个域名（按次计费/限流，别全量打）
        "probe_domain": "example.com",
        "api_key": "",              # 只进 keys.enc.yaml，不落明文
        "sources": [
            {"name": "miit",
             "url": "https://hlwicpfwc.miit.gov.cn/icpproject_query/api/"
                    "icpAbbreviateInfo/queryByCondition",
             "key_header": "token"},
        ],
    },
    # 指纹识别（续221）：单站标签上限。4400+ 条规则对着一个页面跑，命中十几个是常态，
    # 全塞进 sites.tech 只会把"这个站到底是什么"淹掉（主理人报的真站：一个 Sentry 登录页
    # 被打出 20+ 个标签）。超出部分由 fingerprint.flush() 截断，**并说清丢了多少**。
    "fingerprint": {
        "max_tags": 10,
    },
    "hostcollide": {
        # Host 碰撞（续183 模块、续201 接线）：同 IP 绑不同 Host 头找隐藏站点。
        # 续203 改**默认开**（主理人点单"host 碰撞默认也要开"）：它只读 GET、
        # 请求量由下面的 max_requests 夹住，而"同 IP 不同 Host"是找旁站/隐藏后台
        # 性价比最高的一招 —— 默认关着等于这一 capability 没人用过。
        "enabled": True,
        "max_requests": 200,      # 单任务请求预算（引擎内部也会再夹一次）
        "timeout": 5,
    },
    "crawl": {
        # 站点爬虫（续198）：收集页面里**本来就写着**的链接（与 dirscan 的"猜路径"是两回事）。
        # 续249（主理人点单"默认要开"）：默认**开**。它一定会发 GET —— 护栏是额度上限
        # （max_sites / max_pages / max_links / 同站判据）与策略页随时可关，不是"拿走了开关"。
        "enabled": True,
        "max_sites": 30,           # 每任务最多爬多少个站点
        "max_links": 60,           # 每站点最多收多少条链接
        "max_pages": 8,            # 每站点最多抓多少个页面（含首页）
        "max_depth": 1,            # 最多再跟几层（0＝只看站点首页上写着的）
        "same_site": True,         # 只收同 host 的链接（外链默认不收 —— 那不是目标资产）
        "include_subdomains": False,   # 开了才收 `*.目标域` 的子域链接
        "timeout": 10,
        "workers": 8,
        # 带参链接喂给 vulnscan（注入面下钻）：每站最多喂几条。0＝不喂。
        "feed_vulnscan": True,
        "max_feed": 10,            # 每**站点**最多喂几条
        "max_feed_total": 40,      # 全任务总闸（喂得太多等于把请求量翻几倍，见 vulnscan 接线处）
    },
    "jsmine": {
        # JS 资产挖掘（P0-3）：从站点 JS 中提取域名/接口 URL/密钥，扩展资产面
        "enabled": True,
        "max_pages": 20,           # 每任务最多抓取多少个页面
        "max_js": 40,              # 每任务最多抓取多少个 JS 文件
        "secrets": True,           # 开启 AK/SK 等敏感密钥提取（带前后文过滤降噪）
        "blacklist": [],           # 额外排除的第三方域名后缀，如 ["cdn.example.com"]
        # 把"根本不是域名"的 JS 碎片挡在资产库外（续113）：`chat.floating.open`、
        # `network.protocol.name`、`at.be.bg.hr…gb` 这类**点号连接的成员访问链**，末位 label
        # 恰好是合法公共后缀，PSL 形态闸门放行；但它们的**注册域**压根没被注册
        # （`floating.open` / `protocol.name` / `no.gb` 查 NS 返回 NXDOMAIN）。
        # 判据与"只在明确 NXDOMAIN 才动手、SERVFAIL/超时无条件放行"的方向见 `extdom.zone_is_absent`；
        # 关掉它只是让这些碎片回到库里（页面仍会默认收起未解析的行），不影响任何真资产。
        "drop_absent_zone": True,
        # 二层遍历总开关（续139）：jsmine 挖出的新域名 + 库里其余子域名，先过 DNS 再补探一轮，
        # 把"只进表、没变成站点"的那批名字落成站点。关闭只影响站点数量，不影响子域名表。
        "recrawl": True,
        # ---- 拓展域名"宁缺毋滥"三道闸（2026-10-13 用户点单）----
        # 背景：JS 挖掘从第三方库 JS 里带回来的候选域名里，"能解析"≠"是资产"——
        # 实测样本：`com.text.name` / `style.font.name`（能解析但打开是域名转让页）、
        # `at.alicdn.com`（CDN 基础设施）。三道闸只对**非自有**域名动手（任务目标及其
        # 注册域无条件放行），且每一档的拒绝数量都打进任务日志（不静默丢，§0 第 10 条）。
        # **总开关**：域名解析门 —— JS 挖到的非自有域名先做一次只读解析：
        #   明确 nxdomain（域名不存在）→ 不入库；servfail / timeout 等无结论 → 放行
        #   （"解析可能会漏但不会错"，用户原话）。关掉它＝三道闸整条停用。
        "verify_resolve": True,
        # 解析结果命中 CDN 厂商（CNAME 链或 IP 段，`scanner/cdn.py` 同一份名单）→
        # 那是别人的基础设施（at.alicdn.com 这类第三方 JS 资源），不入库。
        "drop_cdn": True,
        # 停车页 / 空壳检测（`scanner/parked.py`，只读）：解析成功但首页是
        # "域名转让 / for sale / DNS resolution error" 或两端口均无响应 → 不入库。
        "parking_check": True,
        # 停车检测的域名数上限（每候选最多 https+http 两次首页 GET，超出的直接放行）
        "parking_check_max": 100,
        # 域名抽取前剥离 JS 注释（license banner 里的 OSS 主页是噪声大头）。
        # 只影响域名/URL 抽取，凭据与 flag 候选仍看原始正文。
        "strip_comments": True,
    },
    "dirscan": {
        # 目录/路径发现阶段总开关（与 takeover/portscan/jsmine 同一类"资产面拓展"）。
        # **默认开启，但只跑"浅扫"**（mode=quick）：只打 config/dicts/dirs_shallow.txt 里
        # 精选的敏感路径（约 150 条/站），请求量与噪声都可控 ——
        # 用户要求"先浅浅过一遍，看清结果后再手动决定要不要深度扫"。
        # 深度扫（全量字典 + 框架桶 + dirmap）需要显式选择：策略配置里把 mode 改成 deep，
        # 或建任务时勾「全目录」，或在结果页发起「补扫」。
        # 打开后还有两层节流：只对**不重复站点**扫描（标题+长度相同的别名站跳过），
        # 且每个站点最多扫 max_paths（深扫）/ quick_max_paths（浅扫）条。每任务站点上限见 limits.dirscan_max_urls。
        "enabled": True,
        # quick = 只吃 dirs_shallow（敏感路径精选）；deep = 全量分层字典 + dirmap。
        # 任务级选项 dirscan_full=true 可把单个任务强制成 deep（不改全局策略）。
        "mode": "deep",            # 续144：默认深扫（quick＝只吃 dirs_shallow 精选路径）
        "quick_max_paths": 150,    # 浅扫单站点上限（dirs_shallow 共约 150 条，基本全吃）
        "big_dict": True,      # 未知技术栈时用全量字典（config/dicts/dirs_big.txt）
        "tech_aware": True,    # 按 sites.tech 选字典：Java 站不吃 PHP/ASP 后缀（用户要求）
        # 续248：历史 URL（wayback CDX + OTX url_list，**零目标流量**）并入目录候选。
        # 上限是"单注册域最多取多少条"；带查询串的路径默认折叠（否则 ?id= 变体吃光额度）。
        "history_enabled": True,
        "history_max": 1000,
        "history_with_query": False,
        # 续250：站点自曝入口（robots.txt Disallow + sitemap.xml，含索引表一层）并入候选。
        "selfurls_enabled": True,
        "selfurls_max": 500,
        "max_paths": 400,      # 深扫：单站点最多扫多少条字典（框架字典优先占额度）
        # 续222：外部字典源（零入仓接第三方字典目录，如 dirsearch 的 dicts/）。
        # 每项：{name, path, picks?, after?}；标签只进**名字/分类名**，不进绝对路径。
        # 与内置层共用 max_paths 额度；目录不存在/没匹配到分类 ⇒ 跳过并写日志。
        # **只在深扫档生效**（快扫/框架补充扫描不吃外部字典，避免稀释精选路径）。
        "dict_sources": [],
        # 后缀派生（deep 专用，借鉴 dirmap 的备份文件扩展）：对命中的**文件名型**路径再派生
        # .bak/.zip/.tar.gz/.old/~/.swp/.copy/.txt 等变体，额度上限同 max_paths。浅扫不做（省请求）。
        "suffix_aware": True,
        # 框架补充扫描额度：dirmap 的 `-e` 吃不下自定义字典（只认 php/jsp/asp/d/big/all），
        # 装了 dirmap 时框架字典会变成死代码 —— dirmap 跑完后按这个额度再补一轮
        # 「框架字典 + 暴露面字典」的内置扫描。置 0 关闭补充扫描。
        "fw_max_paths": 150,
        # ---- 目录递归（续30，**默认关**）----
        # 只对**目录型**命中（路径最后一段不含 `.`）继续往下打，字典用**浅扫精选**那份
        # （`dirs_shallow`）截断到 recursive_max_paths 条；`recursive_depth` 是层数上限。
        # **为什么必须同时限目录数**：单站浅扫约 153 请求（150 路径 + 3 个软 404 基线），
        # 一层递归 = +K×(3 基线 + M)（K=递归目录数、M=每目录路径数），K=5/M=40 时 +215 请求，
        # **比第一轮还多**；只限深度不限 K 会随"命中多少个目录"线性放大。
        # 只在**深扫**（mode=deep / 任务选项 dirscan_full）里生效，浅扫保持"快而少"不变。
        "recursive_depth": 1,      # 续144：默认对目录型命中再往下一层（0＝关）
        # 每个站点在**所有递归层合计**最多递归多少个目录（不是每层各算一份）
        "recursive_max_dirs": 5,
        # 每个递归目录再打多少条浅扫精选字典（目录下只值当打高价值路径，不是再来一遍大字典）
        "recursive_max_paths": 40,
        # 续151 无依赖 ML（默认开，但对**稳定站点**完全不触发）：软 404 模板页常带随机串/
        # 时间戳，md5 与长度都对不上；基线正文不稳定时用字符 n-gram Jaccard 兜底判重。
        "ml_template": True,
        # 续151 无依赖 ML（默认开）：把**长度明显离群**的 200 命中点名到日志（只提示，不改入库）
        "ml_outlier": True,
    },
    "vulnscan": {
        # 漏洞初筛阶段总开关。默认开；关闭后整阶段跳过（连请求都不发），
        # 适合"只做资产测绘、暂不探测"的场景。细粒度门控仍在 checks 段
        # （min_severity / skip_severities / poc_engine / disabled_*）。
        "enabled": True,
    },
    "afrog": {
        # 外部引擎 afrog（续121 接入；续149 **默认开**）：让 `config/afrog-pocs/` 里的
        # "只读 + info 级" PoC 跑一轮组件识别。
        # 为什么现在敢默认开：三条闸门同时成立才可能真的起进程 —— ① 开关打开；② `poc_dir`
        # 指向一个真有只读模板的目录（默认预置 `config/afrog-pocs/`）；③ 本机装好了 afrog
        # 二进制（`tools.afrog`）。任何一条不满足都只写一行说明、**一个请求都不发**。
        # 它自管请求、绕过本任务请求预算，所以 `scanner/afrog.py` 里限速值一律封顶，
        # 且只喂"GET/HEAD 无体 + severity∈{空,info}"的模板（POST/PUT/tcp/brute 全被拒收）。
        # 分不清"没跑成"与"没扫出东西"是这仓反复栽的坑，故 afrog 跑不动时日志以 `!` 开头如实标注。
        "enabled": True,
        # PoC 目录：相对路径按**项目根**解析（同 tools.* 那一段的口径）。
        "poc_dir": "config/afrog-pocs",
        "max_targets": 20,       # 一次最多交多少个站点（封顶 200）
        "timeout": 8,            # 单请求超时（秒，封顶 30）
        "concurrency": 4,        # 它的 -c（封顶 25）
        "rate": 10,              # 全局 -rl 请求/秒（它默认 150！封顶 50）
        "per_target_rate": 5,    # 单目标 -rlt（封顶 25）
        "proc_timeout": 600,     # 整个子进程的超时（封顶 1800）
    },
    "screenshot": {
        # 站点截图（可选，**默认关闭**）：调用本机已装的 Edge/Chrome 无头模式截图，
        # 产物 logs/task_*/shots/*.png，GUI 站点页显示缩略图。不引入任何新依赖。
        # `browser` 留空＝自动探测（PATH → 标准安装位置）；探测不到可在这里填绝对路径。
        "enabled": False,
        "max_sites": 20,        # 每任务最多截多少个站点
        "window": "1280x900",   # 视口尺寸（宽x高）
        "timeout": 30,          # 单站点截图超时（秒）
        # 续225：给一次性截图加 `--virtual-time-budget`（毫秒）—— 让页面把首屏 JS/定时器
        # 跑完再落图，专治"截到一半还在加载"。0＝关（退回旧行为）。
        "settle_ms": 3000,
        # 续225：jsmine 跑完后再截一次，与首图比 md5；不同就再截一张、取出现两次的那个
        # （主理人提出的"多数表决"）。只在 screenshot 阶段真的跑过时才生效。
        "verify_after_js": True,
        # 续161「候补重试」轮数（主理人点单）：任务正常跑完后，把这一轮**没截成**、且落在
        # 「超时 / 跳转未落地 / 连不上」三档的站点，排进队列再试一轮（只跑 screenshot 阶段、
        # 只打这批 URL，等 worker 空了才执行）。代码默认 0＝关（**不偷改出厂行为**）；
        # 续164 起**随包 `config/settings.yaml` 写的是 1**，新克隆合并后生效值就是 1 ——
        # 三档（DEFAULTS / 随包文件 / 合并生效值）分开写，混成一档就是 §5.19 那类假话，
        # `[8bq]`/`[8bs]` ③a 钉住。上限 2 轮硬夹在 `screenshot.RETRYABLE_MAX_ROUNDS`。
        # 「无浏览器」「预算耗尽 / 已停止」这两类**不重试**：前者重试也没浏览器，
        # 后者是人和预算在拦，绕过它就是红线。
        "retry_rounds": 0,
        # 续170（主理人「让截图更有兼容性」+「不要那么快急着重试」）：一次性 `--screenshot`
        # 只在页面 **load 完成**时才写 PNG，而"第三方子资源挂死"的页面永远不等 load ——
        # 本机 Google Chrome 154 实测：`--virtual-time-budget` / `--timeout` / old·new headless
        # 四种组合全部 20 秒 0 字节；改走 CDP（挡掉埋点域 + 不等 load 直接要图）同一夹具截出
        # 9,636–12,584 字节（这条差别每次跑门禁都重验一遍：`[170]⑦` 起真浏览器跑同一个夹具，
        #                并反过来钉「一次性必须救不回」）。所以失败后走 CDP 兜底，
        #                而不是把同一条 URL 再打一遍。
        # `cdp_fallback`＝要不要兜底（默认开；只在一次性失败后才启动，成功路径不多起进程）
        # `cdp_wait`＝这一趟的总预算（导航 + 等 load + 要图），刻意不与 `timeout` 共用一个键
        # `fallback_wait`＝兜底前先等几秒（别急着再来一次；阶段里可被"停止"打断）
        # `block_extra`＝往默认那份埋点清单**追加**；页面自己的注册域**与它的子域**永远不会被挡
        #                （挡了就是把内容截成没有样式的空壳，比"没截到"更误导人）
        "cdp_fallback": True,
        "cdp_wait": 45,
        "fallback_wait": 10,
        "block_extra": [],
        "browser": "",
        # 续175：无头浏览器的 fontconfig 配置文件（留空＝不注入）。填相对路径按仓库根解释；
        # 典型用法是把中文字体放进 `tools/fonts/` 再指向那里的 fonts.conf —— 服务器最小镜像
        # 常常没有中文字体，截图里的中文会变成方框，这一项是给那条部署路径留的口子。
        "fontconfig": "",
    },
    "cert": {
        # TLS 证书取证（可选，**默认关闭**）：对 https 站点 / tls_ports 站点做一次 TLS
        # 握手，把颁发者、有效期、CN、SAN、指纹解析进 `certs` 表，GUI 任务详情
        # 「SSL 证书」页签展示。**纯标准库**（socket/ssl + 自写 DER 解析），无新依赖；
        # 握手**不校验证书**（verify_mode=CERT_NONE）—— 自签名/过期正是要看的东西。
        # 只做一次只读握手，不发 HTTP、不写目标、不试探密码套件（见 scanner/certs.py）。
        "enabled": False,
        "max_sites": 30,           # 每任务最多对多少个 host:port 取证
        "timeout": 8,              # 单次握手超时（秒）
        # 值得试 TLS 的端口：https:// 站点无条件试；非 https 站点只有端口命中这里才试
        # （覆盖"HTTPS 服务被 probe 记成 http://host:8443"的情况）
        "tls_ports": [443, 8443, 9443],
    },
    "iprecon": {
        # C 段反查（P1-4）：IP → 域名反查 + /24 C 段归纳。
        # **默认关闭**：走第三方公共接口（可用性无保障），且反查结果属于"发散"资产，
        # 需要时才开（GUI「策略配置 → 外部情报拓展」）。接口地址可在配置里替换。
        "enabled": False,
        "api": "https://api.webscan.cc/?action=query&ip={ip}",
        "max_ips": 500,            # 单任务最多反查多少个 IP
        "max_hosts": 200,          # 为收集 IP 最多解析多少个主机名
        "max_domains_per_ip": 30,  # 单 IP 命中域名超过该值 → 判为共享主机，不纳入域名资产
        "workers": 5,              # 并发数：公共接口，刻意保持克制
        # 续184：开跑前先探一次每个源还活不活（挂了的整轮跳过，不再逐 IP 白跑）
        "preflight": True,
        # 默认源预检全挂时的备用池：ptr 是本框架自己实现的原生 PTR（不发 HTTP）
        "fallback_sources": ["ptr", "dnsdblookup", "rapiddns", "viewdns"],
        "api_rapiddns": "https://rapiddns.io/s/{ip}?full=1",
        "api_viewdns": "https://viewdns.info/reverseip/?host={ip}&t=1",

        # 续184：开跑前先探一次每个源还活不活（挂了的整轮跳过，不再逐 IP 白跑）
        "preflight": True,
        # 默认源预检全挂时的备用池：ptr 是本框架自己实现的原生 PTR（不发 HTTP）
        "fallback_sources": ["ptr", "dnsdblookup", "rapiddns", "viewdns"],
        "api_rapiddns": "https://rapiddns.io/s/{ip}?full=1",
        "api_viewdns": "https://viewdns.info/reverseip/?host={ip}&t=1",

        "timeout": 10,             # 单次反查超时（秒）
    },
    "extquota": {
        # 外部引擎配额预检（续211-P1-4）：开跑前问一句"我还有多少次"。
        # 默认开（它自己只吃一次 HTTP 且不吃目标侧预算）；关掉它 ⇒ 回到原来的
        # "逐条失败、归因错"形态。`min_left` 低于这个数就整轮跳过该源。
        "enabled": True,
        "min_left": 1,
    },
    "fofa": {
        # favicon 反查同源资产（P3-1）：需 config/keys.yaml 填 fofa.email / fofa.key
        # 代码默认值是 False（保证"没填 key 就不该发请求"）。
        # 历史：2026-09-22 用户为校准阈值曾在 config/settings.yaml 里显式设为 true；2026-09-26 已改回
        # false，与这里一致。settings.yaml 是用户覆盖层、以它为准 —— 改这一项不会影响代码默认值。
        "enabled": False,
        "max_sites": 30,           # 每任务最多对多少个站点算 favicon 并反查
        "max_assets": 100,         # 单个 favicon 最多取回多少条资产
        "workers": 5,
        # 续229：两次 FOFA 请求的最小间隔（秒）。循环反查（每个 favicon/证书/标题一次）不节流
        # 就会撞 HTTP 429 —— 那是"发太快"，不是接口坏了。填 0 = 不节流。
        "min_interval": 3.0,
        # 续243：FOFA 也参与**子域名**收集（此前只在 osint 阶段做图标/证书/标题反查）。
        # `domain="<注册域>"` 反查；单域上限 `subdomain_max`（FOFA 单次上限 10000）。
        "subdomain_enabled": True,
        "subdomain_max": 100,
        "black_ico_threshold": 200,  # 命中数超过该值 → 判为"黑 ico"（公共图标），放弃拓展
        # 证书反查（cert="example.com"）：找"与该目标共用同一张 TLS 证书"的其它域名。
        # 独立子开关（`fofa.enabled` 关掉时它也不会跑）；命中数超过 cert_threshold
        # 说明这是一张被大量域名共用的通用证书（公共 CA / 大厂证书），放弃拓展。
        "cert_enabled": True,
        "cert_threshold": 200,
        "max_cert_queries": 10,    # 每任务最多对多少个注册域做证书反查（省配额）
        # 标题反查（title="站点标题"）：找标题相同的其它资产。黑名单两层 ——
        # ① 模板页标题（404 / Error / Welcome to nginx…）连查询都不发；
        # ② 命中数超过 title_threshold 判为"公共标题"，放弃拓展（与黑 ico 同构）。
        "title_enabled": True,
        "title_threshold": 200,
        "max_title_queries": 10,   # 每任务最多反查多少个站点标题（省配额）
        # 标题反查的**归属相关性**过滤（续22）：FOFA 会带回"标题里恰好含同一子串"的无关域名
        # （实测：标题含 "targ1" → 带回 silviatarg1.com / noise1.net / noise2.cn …）。
        #   label     = 标题 token 与域名的某个 label **完全相等**才算相关（默认，最严）
        #   substring = 只要 token 是域名的**子串**就算相关（更宽松，回退/对照用）
        "title_match": "label",
    },
    "ssrf": {
        # A10 SSRF 受控回连（**默认关**）：任务内起一个本机 HTTP 回连监听，把
        # `http://<回调基址>/<token>` 喂给候选参数，收到该 token 的访问即判定
        # "目标服务端会发起出网请求"。详见 `scanner/ssrf.py` 文件头。
        # **只在目标能回访扫描机时才有效** —— NAT / 云主机场景大概率一条都收不到。
        "enabled": False,
        # 外部可达的回调基址（自建 OOB 服务 / 反向代理）。**留空 = 用本机监听地址**。
        # 填了之后本模块读不到那侧的命中，因此只注入、不报命中（宁可不报也不谎报），
        # 注入过的 token 会写进任务日志供你在那侧核对。
        "callback_base": "",
        "host": "127.0.0.1",   # 本机监听地址
        "port": 0,             # 0 = 交给系统分配（避免与本机服务抢端口）
        "wait_seconds": 6.0,   # 注入完成后等回连的秒数（期间不再向目标发请求）
        "max_params": 12,      # 每个 URL 最多注入多少个候选参数
    },
    "shodan": {
        # Shodan favicon 反查（`http.favicon.hash:<mmh3>`，与 FOFA 同一个哈希键，
        # 见 `scanner/mmh3.py`）。需 config/keys.yaml 填 shodan.key；
        # **默认关** —— 任何外部接口都不该在用户没点头时产生流量。
        "enabled": False,
        "max_sites": 30,           # 每任务最多对多少个站点算 favicon 并反查
        "max_assets": 100,         # 单个 favicon 最多取回多少条资产
        "workers": 5,
        "black_ico_threshold": 200,  # 命中数超过该值 → 公共图标，放弃拓展
    },
    "quake": {
        # 360 Quake favicon 反查（`favicon: "<mmh3>"`）。需 config/keys.yaml 填 quake.key；
        # **默认关**。结构与 shodan 段一致（POST + X-QuakeToken 头，见 scanner/quake.py）。
        "enabled": False,
        "max_sites": 30,
        "max_assets": 100,
        "workers": 5,
        "black_ico_threshold": 200,
    },
    "virustotal": {
        # VirusTotal **子域名**反查（续214）：`GET /v3/domains/<注册域>/subdomains`。
        # 与 FOFA / Shodan / Quake 那三家 favicon 反查**不是一条路** —— 那是"同源推断"，
        # 这是"已收录的父子关系"，补的正是"这个域名下还有哪些子域"。
        # 需 config/keys.yaml 填 virustotal.key（或用口令加密的 config/keys.enc.yaml）；
        # **默认开**（2026-10-21 主理人点单：key 已配好，开关不该再挡路；免费档由节流夹住）。
        # 免费档 4 次/分钟、500 次/天 ⇒ 节流靠 `min_interval`（秒），在模块内自己兑现。
        "enabled": True,
        "max_domains": 20,       # 单任务最多查几个注册域（每个一次请求）
        "limit": 40,             # 单域名最多收多少子域（v3 硬上限 40）
        "min_interval": 15.0,    # 两次请求之间的最小间隔（免费档 4 次/分钟 ⇒ 15 秒）
    },
    "ctlog": {
        # 证书透明度（CT）日志在线查询（crt.sh，**免 key** 但属外部接口 → **默认关**）。
        # 产出**证书维度**记录（签发者 / 有效期 / 序列号 / 涉及的域名 / CT 条目数），
        # 字段口径与 `scanner/certs.py` 对齐，可直接进「SSL 证书」页签（source=ct）；
        # 顺带把这些证书覆盖的域名当作拓展域名来源。
        # 与 passive.py 的 crt.sh（只取主机名做子域收集）、certs.py（真握手取线上证书）
        # 是三件不同的事，区别写在 `scanner/ctlog.py` 文件头。
        "enabled": False,
        "max_domains": 10,         # 单任务最多查几个域名（每个域名一次请求，别把 crt.sh 打挂）
        "max_records": 50,         # 单域名最多收多少张证书记录
        "max_domains_per_cert": 50,  # 单张证书最多保留多少个域名（大证书 SAN 有几百条）
        "timeout": 25,             # 单次查询超时（crt.sh 很慢，别设太短）
        "write_certs": True,       # 是否把证书维度记录写进 certs 表（source='ct'）
    },
    "blacklist": {
        # 用户黑名单：命中的域名不入资产库，因此也不会被 dirscan/vulnscan 扫到。
        # 文件是纯文本（一行一个域名，含其所有子域），可手工编辑；GUI 支持批量加入/移除。
        "enabled": True,
        "path": "config/blacklist.txt",
    },
    "intel": {
        # 漏洞情报订阅（P3-2，**默认关**）：拉取公开情报源（默认 CISA KEV，免 key），
        # 与本次扫到的资产指纹做保守匹配，产出**线索**（leads 表 kind=intel）。
        # **不写 vulns、不计入漏洞数、不自动导入 POC** —— 情报命中只说明"这条已知被在利用的
        # CVE 与你扫到的组件可能相关"，是不是真漏洞要人工确认（见 scanner/intel.py）。
        "enabled": False,
        "source": "kev",           # 内置源名（见 scanner/intel.py::FEEDS）
        "url": "",                 # 留空用内置地址；填了则覆盖（需同结构 JSON）
        "cache_hours": 24,         # 本地缓存有效期；拉取失败会退回过期缓存并告警
        "timeout": 20,             # 拉取情报源的请求超时（秒）
        "max_leads": 50,           # 单任务最多入库多少条情报线索
    },
    "heuristic": {
        # 启发式候选发现（P3-3，**默认关**）：对**已收集的**站点/目录/漏洞/C 段数据做
        # 差分与异常聚合（软 404 模板、高价值入口无结论、同标题多主机…），产出线索
        # （leads 表 kind=heuristic）。**不发任何请求**，也不写 vulns。
        "enabled": False,
        "max_leads": 50,           # 单任务最多入库多少条线索
    },
    "github": {
        # GitHub 泄露检索（续26，**默认关**）：拿目标的注册域去 GitHub 公开代码里搜命中，
        # 产出**线索**（leads 表 kind=github）。三条硬边界见 scanner/github_leak.py 文件头：
        # ① **只落元数据**（仓库 / 文件路径 / 命中规则名），**绝不落文件内容**（避免存下凭据明文）；
        # ② 所有请求 `auth=False` —— **任务级登录态（目标侧 Cookie / Token）绝不发给 GitHub**；
        # ③ token 在 `config/keys.yaml` 的 `github.token`（代码搜索接口要求认证），
        #    没配 token 时**一次请求都不发**。**不写 vulns、不计入漏洞数、不自动导入 POC**。
        "enabled": False,
        "max_domains": 3,          # 最多对几个**注册域**检索（子域名不单独查，见 stages/github.py）
        "max_queries": 4,          # 最多发几次搜索请求（代码搜索限流约 10 次/分钟）
        "per_page": 30,            # 单次请求最多取回多少条命中（GitHub 上限 100）
        "max_leads": 30,           # 单任务最多入库多少条线索
        "timeout": 20,             # 单次请求超时（秒）
        # 续151（用户点单"relevance 阈值可配"）：
        #   weak_downgrade=false → 不做弱相关降级（旧行为：弱相关也按规则级别计）；
        #   relevance_whitelist → 仓库名/文件路径里命中任一子串即视为"相关"（不判弱），
        #     给"我确知这个仓库跟我们有关"留一个人工兜底，避免被误降到 info。
        "weak_downgrade": True,
        "relevance_whitelist": [],
    },
    "multileak": {
        # 多平台公开代码检索（续150-附 11-多平台，**默认关**）：GitHub 之外的只读检索源，
        # 默认 provider=`grepapp`（免 key 公开接口，实测可用）。产出**线索**（leads 表 kind=grepapp）。
        # 边界与 github 同源（见 scanner/multileak.py 文件头）：
        # ① **只落元数据**（仓库 / 文件路径 / 命中规则名），绝不落文件内容（命中片段可能含凭据明文）；
        # ② 所有请求 `auth=False`（任务级登录态绝不外发）；③ **默认关 + 限额**；**不写 vulns**。
        "enabled": False,
        "provider": "grepapp",     # grepapp 免 key；gitlab（续158）用 keys.gitlab.token，没配 token 零请求
        "max_domains": 3,          # 最多对几个注册域检索
        "max_queries": 4,          # 最多发几次检索请求（免 key 接口有速率限制）
        "per_page": 10,            # 单次请求最多取回多少条命中
        "max_leads": 30,           # 单任务最多入库多少条线索
        "timeout": 20,             # 单次请求超时（秒）
        # 续157：#11 弱相关降级与白名单（与 github 同口径；此前硬编码在 multileak.build_lead 里）
        "weak_downgrade": True,
        "relevance_whitelist": [],
        # 续158 H：GitLab provider 的实例根（自建 GitLab 改这一项）；gitlab 的 token 在凭据文件里（`config/keys.yaml`，或口令加密的 `config/keys.enc.yaml`）
        "gitlab_base": "https://gitlab.com",
    },
    "flags": {
        # 敏感信息 / CTF flag 候选抽取：在**已经拿到**的响应正文里按形状找值得抄走的串，
        # 单独进 `flags` 表 —— **不写 vulns、不计入漏洞数**（一个 AK 或 `flag{...}` 不是漏洞结论）。
        # 零额外请求是这块的立身之本：`scanner/flagfind.py` 自己不发任何请求，只在
        # probe / jsmine / dirscan / vulnscan 手里已有的文本上跑（判据见其文件头与 [8ae]）。
        # 表名与下面这些键仍叫 `flags`：改名会打断别人机器上已有的 settings.yaml 与库里数据。
        "enabled": True,
        "secrets": True,               # 内置敏感信息形状（各家 AK/SK、API key、JWT、私钥头）
        "prefixes": ["flag", "ctf"],   # 不带括号自动按 `前缀{`；各家自定义前缀往这里加
        "patterns": [],                # 额外正则；取不出必现字面量的**拒用并说明原因**（成本口子）
        "min_len": 1,                  # 值体最短（挡 `flag{}` 这种空壳）
        "max_len": 200,                # 值体最长（同时也是自定义正则的候选窗口尺度）
        "max_chars": 2000000,          # 单份正文超过多少**字符**就不扫（不是字节），并写"跳过 N 份"
        "max_per_source": 20,          # 单份正文最多收几条（一页刷爆候选表的兜底）
        "max_per_task": 200,           # 单任务最多入库多少条候选
    },
    "tools": {
        # 优先从 PATH 解析，也可以填绝对路径（Windows 下如 tools/scanner/httpx.exe）
        "subfinder": "subfinder",
        "puredns": "puredns",
        "httpx": "httpx",
        "nmap": "nmap",
        # afrog（续119）：能被 `--update-tools` 下载/校验/更新，但**当前没有任何阶段调用它**
        # （vulnscan 的适配器还没写，见外部工具清单 TOOLS 里的 wired 标记）。列在这里是为了让
        # 「外部工具」页与清单显示的是同一个事实，而不是"没列出来＝框架不管"。
        "afrog": "afrog",
        # fscan（可选）：填二进制名或路径（Windows 下如 tools/fscan/fscan.exe）。
        # 缺省只会在 PATH 里找；找不到就跳过它。**调用时强制 `-np -nobr -nopoc`**
        # —— 不要给它开暴力破解/POC，我们只用它的端口发现能力（见 scanner/portscan.py）。
        # 相对路径（带 `/` 或 `\`）按**项目根**解析，不按进程 CWD（见 utils.which）。
        "fscan": "fscan",
        "dirmap": {
            "python": "python",
            # dirmap 是**外部项目**（依赖 gevent/lxml/progressbar），不随本仓库分发。
            # 这里只填**相对项目根**的路径：把 dirmap 放到 `tools/dirmap/`
            # （本机是拿目录联接指向机器上的 dirmap 目录，代码里不出现任何绝对路径），
            # 找不到就自动回退内置字典扫描。
            "script": "tools/dirmap/dirmap.py",
            "threads": 30,
        },
    },
    "dicts": {
        "subdomains": "config/dicts/subdomains.txt",   # 精简档：人工挑的高价值前缀，永远全量参与
        # 深档（续139，`tools/import_subdomain_dict.py` 生成/合并）：文件不在就是"没配"，
        # 阶段会打一行 info 指路；没装 puredns 时它受 `limits.brute_fallback_max` 抽样。
        "subdomains_deep": "config/dicts/subdomains_deep.txt",
        "resolvers": "config/dicts/resolvers.txt",
        "dirs": "config/dicts/dirs_small.txt",       # 小字典（快，几十条）
        # 浅扫精选字典（dirscan.mode=quick 时**只用这一份**，约 150 条敏感路径，按价值排序）
        "dirs_shallow": "config/dicts/dirs_shallow.txt",
        "dirs_big": "config/dicts/dirs_big.txt",     # 全量（未知技术栈时用）
        # 按技术栈拆分的字典（tools/import_dir_dict.py --src <外部字典> 生成）：
        # 运行时按 sites.tech 只取「语言字典 + 通用字典」，避免把三种语言的后缀全打一遍
        "dirs_common": "config/dicts/dirs_common.txt",   # 通用路径（所有已判明语言栈的站点都吃）
        "dirs_jsp": "config/dicts/dirs_jsp.txt",     # Java 系（.jsp/.do/.action/.java…）
        "dirs_php": "config/dicts/dirs_php.txt",     # PHP 系（.php/.phtml…）
        "dirs_asp": "config/dicts/dirs_asp.txt",     # ASP/.NET 系（.asp/.aspx/.config…）
        # 框架字典（tools/import_fw_dicts.py 从全量字典按特征正则派生，**运行时排在最前**）：
        # 判出站点是 WordPress / Spring / Weblogic… 就先扫它的专属路径，
        # 免得 `dirs_common` 上万条把 `wp-login.php`、`/actuator/env` 挤出 max_paths 额度。
        "dirs_wordpress": "config/dicts/dirs_wordpress.txt",
        "dirs_phpmyadmin": "config/dicts/dirs_phpmyadmin.txt",
        "dirs_druid": "config/dicts/dirs_druid.txt",
        "dirs_spring": "config/dicts/dirs_spring.txt",
        "dirs_weblogic": "config/dicts/dirs_weblogic.txt",
        "dirs_tomcat": "config/dicts/dirs_tomcat.txt",
        "dirs_jenkins": "config/dicts/dirs_jenkins.txt",
        "dirs_elastic": "config/dicts/dirs_elastic.txt",
        "dirs_swagger": "config/dicts/dirs_swagger.txt",
        "dirs_confluence": "config/dicts/dirs_confluence.txt",
        "dirs_gitlab": "config/dicts/dirs_gitlab.txt",
        # 通用暴露面（`.git` / `.env` / 备份文件）：对**所有**站点生效，排语言字典之后、通用字典之前
        "dirs_exposure": "config/dicts/dirs_exposure.txt",
        "sensitive": "config/dicts/sensitive.txt",  # A01 检查的数据源（`路径|关键字|级别|说明`）
        "cdn_cname": "config/dicts/cdn_cname.txt",  # CDN 厂商 CNAME 后缀（子域名 CDN 标记用）
        "cdn_ips": "config/dicts/cdn_ips.txt",  # CDN 厂商任播 IP 段（CNAME 为空时兜底判定）
    },
    "http": {
        "user_agent": "Mozilla/5.0 (compatible; CTFScanner/0.1; +authorized-testing-only)",
    },
    "report": {
        # ---- 报告导出（2026-10-13 用户点单）：**默认关** ----
        # MD / JSONL / HTML / PDF 四种格式（GUI 任务详情页右上角那排按钮）共用这一个开关：
        # 关着时导出路由直接给出"为什么不能导出 + 去哪儿开"的提示页，任务页也不显示
        # 导出按钮（避免"点了才知道不行"）。报告数据本身照常在库，打开开关立即可导出。
        # CLI（`run_devflow` 等）不受这一项约束 —— 那是本机操作者的出口。
        "export_enabled": False,
    },
}


KEYS_PATH = BASE_DIR / "config" / "keys.yaml"

# `checks.skip_severities` 缺省值：info 与 low 级检测**根本不执行**。
# 依据（用户明确的检测取向）：CTF 实战只看能拿 flag 的高危项（注入/RCE/接管/未授权访问），
# 明文 HTTP、安全响应头缺失、组件版本泄露这类项即使跑了，结果也会被 `min_severity` 丢掉，
# 所以"不执行"只省 HTTP 请求、不减报告内容。要广谱信息收集时把该列表清空即可。
DEFAULT_SKIP_SEVERITIES = ["info", "low"]


def skip_severities(settings):
    """返回本次扫描**不执行**的级别集合（`checks.skip_severities`，默认 info + low）。

    同时作用于内置 OWASP 检查（`owasp.checks.enabled_checks`）与 POC 引擎
    （`pocs.engine.load_enabled_pocs`），保证"低价值项连请求都不发"。
    """
    raw = ((settings or {}).get("checks") or {}).get("skip_severities")
    if raw is None:
        raw = DEFAULT_SKIP_SEVERITIES
    if isinstance(raw, str):
        raw = [raw]
    return {str(s).strip().lower() for s in raw if str(s).strip()}


def load_keys():
    """读取第三方 API key（P0-5；续98 起支持口令加密的 `config/keys.enc.yaml`）。

    单独成文件而不是塞进 settings.yaml 的理由：GUI「策略配置」页会把 settings 整体写回，
    凭据混在里面容易被覆盖/回显；且 keys 属于"部署环境"而不是"扫描策略"。
    结构示例（顶层按厂商分组）：
        fofa: {email: "", key: ""}
        shodan: {key: ""}
        quake: {key: ""}
    文件不存在或解析失败一律返回 {}，调用方按"无此来源"处理，不影响框架可用性。

    三条口径（续98）：
    1. 有 `keys.enc.yaml` 且**已解锁** → 用内存里的明文（`keystore.current()`）。
    2. 有 `keys.enc.yaml` 但**未解锁** → 返回 `{}`，**不回落到明文文件** —— 用户既然选择了
       加密，"绕过口令就能用凭据"就是把它的安全承诺作废。外部情报源会各自如实报"无 key"。
    3. 没有密文文件 → 走原来的明文 `keys.yaml`（向后兼容，旧部署不受影响）。
    本函数被 `load_settings()` 调用，而后者会被工作线程与 GUI 每个请求反复调，
    所以这里**绝不提示口令、绝不抛异常** —— 解锁只在进程启动时由入口做一次。
    """
    from . import keystore
    data = keystore.current()
    if data:
        return data
    if keystore.ENC_KEYS_PATH.exists():
        return {}
    if not KEYS_PATH.exists():
        return {}
    try:
        import yaml
        data = yaml.safe_load(KEYS_PATH.read_text(encoding="utf-8")) or {}
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _deep_merge(base, override):
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _deep_merge(base[k], v)
        else:
            base[k] = v
    return base


def load_settings():
    settings = copy.deepcopy(DEFAULTS)
    yaml_path = BASE_DIR / "config" / "settings.yaml"
    json_path = BASE_DIR / "config" / "settings.json"
    try:
        if yaml_path.exists():
            import yaml
            data = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
            _deep_merge(settings, data)
        elif json_path.exists():
            _deep_merge(settings, json.loads(json_path.read_text(encoding="utf-8")))
    except ImportError:
        # 有 settings.yaml 但环境没装 PyYAML：退回 settings.json 读取。
        # （此前 `import yaml` 写在分支里，ImportError 会被下面的兜底吞掉 → 整份配置失效，
        #  而 `elif json_path` 永远走不到，save_settings 写出的 json 也就永远读不回来。）
        if json_path.exists():
            _deep_merge(settings, json.loads(json_path.read_text(encoding="utf-8")))
    except Exception:
        # 配置损坏时退回默认值，保证框架可用
        settings = copy.deepcopy(DEFAULTS)
    settings["keys"] = load_keys()
    return settings


def _dump(settings):
    """落盘的**唯一出口**（有 PyYAML 写 yaml，否则退回 json）。

    `keys` 段来自独立的 keys.yaml，**必须剔除**后再落盘 —— 否则 GUI 存一次策略
    就把第三方凭据复制进了 settings.yaml（正是本项目明确要避免的做法）。
    """
    settings.pop("keys", None)
    try:
        import yaml
        (BASE_DIR / "config" / "settings.yaml").write_text(
            yaml.safe_dump(settings, allow_unicode=True, sort_keys=False), encoding="utf-8")
    except ImportError:
        (BASE_DIR / "config" / "settings.json").write_text(
            json.dumps(settings, ensure_ascii=False, indent=2), encoding="utf-8")
    return settings


def save_settings(data):
    """合并写入配置（`data` 里没出现的键保持原样 —— 合并语义，不是整份覆盖）。"""
    settings = load_settings()
    _deep_merge(settings, data or {})
    return _dump(settings)


def remove_settings_keys(*paths):
    """从配置文件里**删键**（按行删）；返回真正删掉的键名列表，如 `["gui.token"]`。

    为什么不走 `save_settings`：① 它是"合并写" —— 从传入字典里去掉一个键，合并时那份从文件
    重读出来的字典里**键还在**，等于删不掉；② 更要紧的是它用 `yaml.safe_dump` 整份重写，
    而 `config/settings.yaml` 里全是解释性注释（每个默认值为什么这么定、踩过什么坑），
    一次重写**全部蒸发**。所以这里是**逐行文本删除** —— 与外部工具安装器回写 `tools.<名>`
    用同一手法：只碰目标那一行，其余字节原样。
    只支持 `("段", "键")` 两层（续117 摘掉的两个登录键是唯一需要它的地方）；键不存在就什么也不做。
    刻意**不顺手删目标键上方的注释** —— 那些注释常常同时服务相邻的键，删错了才是真破坏。
    """
    text_path = BASE_DIR / "config" / "settings.yaml"
    removed = []
    if text_path.exists():
        # `newline=""` 是**必须**的：默认的通用换行会把整份 CRLF 文件读成 LF 再写回去，
        # 于是一行删除换来 275 行纯 EOL"假变更"（本轮实测踩过 —— 与 §9 的 EOL 纪律同一件事）。
        with open(text_path, "r", encoding="utf-8", newline="") as fh:
            lines = fh.read().splitlines(keepends=True)
        for section, key in paths:
            head, i = f"{section}:", 0
            while i < len(lines) and lines[i].rstrip("\r\n") != head:
                i += 1
            if i >= len(lines):
                continue                       # 没有这一段
            j = i + 1
            target = None
            while j < len(lines):
                ln = lines[j].rstrip("\r\n")
                if ln.strip() and not ln.startswith((" ", "\t")):
                    break                      # 回到顶层 = 本段结束
                if ln.strip().startswith(f"{key}:"):
                    target = j
                    break
                j += 1
            if target is not None:
                lines.pop(target)
                removed.append(f"{section}.{key}")
        if removed:
            with open(text_path, "w", encoding="utf-8", newline="") as fh:
                fh.write("".join(lines))
        return removed
    settings = load_settings()               # 没有 yaml 文件（只有 settings.json）的那一档
    for section, key in paths:
        node = settings.get(section)
        if isinstance(node, dict) and key in node:
            node.pop(key)
            removed.append(f"{section}.{key}")
    if removed:
        _dump(settings)
    return removed


def resolve(path):
    """相对路径基于项目根目录解析。"""
    p = pathlib.Path(str(path))
    return p if p.is_absolute() else (BASE_DIR / p)


# 会话签名密钥的文件名（放在**库同目录**，见 `session_secret()` 的说明）。
SECRET_FILE = "session.secret"
_SECRET_MIN = 32          # 短于这个长度就当成"文件被截断/写坏"，重新生成


def session_secret(directory):
    """会话签名密钥（续109）：**随机 32 字节**、落盘 `<directory>/session.secret`（0600），
    **绝不由 `gui.token` 推导**。

    为什么要单独管这一件事：`app.secret_key` 原先是 `f"ctfscanner::{gui.token}"`，而
    `config/settings.yaml` 是**被 git 跟踪**的、仓库还是公开的，默认口令又写在 README 里 ——
    等于任何人都能算出这把"签名钥匙"，自己签一个 `session['role']='admin'` 的 Cookie 贴上去
    就是管理员。Flask 默认只签名不加密，**密钥就是"谁能伪造会话"的唯一门槛**，它必须是
    本机随机、不进仓库、不进任何被跟踪文件。验证码与限速（续78/续48）挡的是"在线试口令"，
    对"离线伪造会话"一点用都没有 —— 所以这一处补的是那两道门**底下**的地板。

    落点选在**库同目录**（调用方传 `db.DB_PATH.parent`）：那目录本来就在 `.gitignore` 里
    （`data/`），且 `CTFSCANNER_DB` 一重定向，密钥就自动跟着进测试沙箱 —— 不必新增环境变量，
    也不会让回归测试往真实 `data/` 里塞密钥。

    返回 `(密钥, 警告)`：目录建不了/写不了/读失败时**退回进程内随机密钥**（重启即全员重新登录，
    但依然不可伪造），并带回一句必须**明说**的警告 —— 静默降级是本仓反复出事的地方。
    已存在且够长的文件一律复用（否则每次重启都把会话打光）；太短视为写坏，重新生成。
    """
    d = pathlib.Path(str(directory or "")) or BASE_DIR
    f = d / SECRET_FILE
    try:
        if f.exists():
            text = f.read_text(encoding="utf-8").strip()
            if len(text) >= _SECRET_MIN:
                return text, ""
        d.mkdir(parents=True, exist_ok=True)
        fresh = secrets.token_hex(32)
        f.write_text(fresh + "\n", encoding="utf-8")
        try:
            os.chmod(f, 0o600)
        except OSError:      # Windows 上 chmod 语义有限：不因此放弃落盘
            pass
        return fresh, ""
    except OSError as e:      # noqa: BLE001 - 拿不到文件不等于可以不放密钥，更不能退回可推导的串
        return (secrets.token_hex(32),
                f"会话密钥没能落盘（{type(e).__name__}: {e}）：本次改用**进程内随机密钥** —— "
                "重启后所有会话失效（需重新登录），但密钥不可推导、会话不可伪造。" f"请检查该目录可否写入：{d}")
