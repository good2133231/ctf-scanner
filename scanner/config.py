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


# 运行期产物目录（每任务一个子目录）。与数据库一样支持环境变量覆盖：
# 跑测试时指到临时目录，就不会在真实工作区里堆出几十个 `logs/task_*` 目录，
# 也让"开发/生产共用一份代码、数据分开"变得可行（见 tests/smoke.py 顶部）。
# 走 `env_path()` 是为了把"盘符式 POSIX 路径"在入口归一（见其注释里的踩坑说明）。
LOGS_DIR = env_path("CTFSCANNER_LOGS", BASE_DIR / "logs")

DEFAULTS = {
    "gui": {
        "host": "127.0.0.1",
        "port": 5000,
        "token": "ctfscanner",  # 仅本地实验用途，请勿将控制台暴露公网
    },
    "limits": {
        "max_workers": 20,        # HTTP 探测 / 目录扫描 / DNS 爆破线程数
        "http_timeout": 10,       # 单请求超时（秒）
        "verify_tls": False,
        # 第三方接口（FOFA/Shodan/Quake/crt.sh/KEV/iprecon/api.github.com）的证书校验。
        # **与 verify_tls 刻意分开**：那一项是给**目标侧**自签名靶场降级用的；第三方是公网
        # CA 签名、且多带 API key / PAT，跟着一起降级＝把凭据挂上可被中间人读的信道（续42）。
        "verify_tls_external": True,
        "dirscan_max_urls": 20,   # 每任务最多参与目录扫描的站点数
        "vulnscan_max_urls": 100, # 每任务最多参与漏洞扫描的站点数
        "brute_max_domains": 50,  # 每任务最多参与 DNS 爆破的域名数
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
        "ports": "",               # 留空 = 内置 TOP 端口表；也可写 "80,443,8080" 或 "1-1024"
        # 全端口扫描：`mode="full"` 时对 `full_ports`（默认 1-65535）逐端口 connect。
        # 6.5 万次连接耗时可观，所以全局默认仍是 top；GUI「全端口扫描」页对单个 IP
        # 发起的任务用**任务选项** `portscan_full` 单次触发，不改全局策略。
        "mode": "top",             # top（内置 TOP 端口） / full（全端口）
        "full_ports": "1-65535",
        "exclude_scanned": True,   # 跳过本任务已经扫过的端口（全端口扫描时尤其有用）
        # 全端口专用并发/超时（只在 full 模式生效，不动 TOP 模式的既有行为）。
        # 实测：65535 端口在 64 并发 × 1.0s 超时下要跑十几分钟（关闭端口得等满超时），
        # 换成 256 并发 × 0.3s 只需 ~82 秒。想更快就继续加并发/降超时（注意目标侧压力）。
        "full_workers": 256,
        "full_timeout": 0.5,
        "timeout": 1.0,            # 单端口连接超时（秒）
        "workers": 64,             # 并发连接数
        "banner": True,            # 连接成功后尝试读取 banner（纯被动读取）
        # 引擎选择：auto = fscan → nmap → 内置 TCP connect（谁可用/有结果用谁）；
        # 也可钉住 "fscan" / "nmap" / "builtin"。fscan 快得多（默认 600 线程，适合全端口），
        # 但输出格式随版本浮动；钉住的那个不可用时会退回内置实现并在日志里说明。
        "engine": "auto",
    },
    "jsmine": {
        # JS 资产挖掘（P0-3）：从站点 JS 中提取域名/接口 URL/密钥，扩展资产面
        "enabled": True,
        "max_pages": 20,           # 每任务最多抓取多少个页面
        "max_js": 40,              # 每任务最多抓取多少个 JS 文件
        "secrets": True,           # 开启 AK/SK 等敏感密钥提取（带前后文过滤降噪）
        "blacklist": [],           # 额外排除的第三方域名后缀，如 ["cdn.example.com"]
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
        "mode": "quick",
        "quick_max_paths": 150,    # 浅扫单站点上限（dirs_shallow 共约 150 条，基本全吃）
        "big_dict": True,      # 未知技术栈时用全量字典（config/dicts/dirs_big.txt）
        "tech_aware": True,    # 按 sites.tech 选字典：Java 站不吃 PHP/ASP 后缀（用户要求）
        "max_paths": 400,      # 深扫：单站点最多扫多少条字典（框架字典优先占额度）
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
        "recursive_depth": 0,
        # 每个站点在**所有递归层合计**最多递归多少个目录（不是每层各算一份）
        "recursive_max_dirs": 5,
        # 每个递归目录再打多少条浅扫精选字典（目录下只值当打高价值路径，不是再来一遍大字典）
        "recursive_max_paths": 40,
    },
    "vulnscan": {
        # 漏洞初筛阶段总开关。默认开；关闭后整阶段跳过（连请求都不发），
        # 适合"只做资产测绘、暂不探测"的场景。细粒度门控仍在 checks 段
        # （min_severity / skip_severities / poc_engine / disabled_*）。
        "enabled": True,
    },
    "screenshot": {
        # 站点截图（可选，**默认关闭**）：调用本机已装的 Edge/Chrome 无头模式截图，
        # 产物 logs/task_*/shots/*.png，GUI 站点页显示缩略图。不引入任何新依赖。
        # `browser` 留空＝自动探测（PATH → 标准安装位置）；探测不到可在这里填绝对路径。
        "enabled": False,
        "max_sites": 20,        # 每任务最多截多少个站点
        "window": "1280x900",   # 视口尺寸（宽x高）
        "timeout": 30,          # 单站点截图超时（秒）
        "browser": "",
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
        "timeout": 10,             # 单次反查超时（秒）
    },
    "fofa": {
        # favicon 反查同源资产（P3-1）：需 config/keys.yaml 填 fofa.email / fofa.key
        # 代码默认值是 False（保证"没填 key 就不该发请求"），但本机 config/settings.yaml
        # 已由用户显式设为 true 以启用 FOFA 反查 —— 二者不一致**是预期内的**：
        # settings.yaml 是用户覆盖层，以它为准，不要把这里改回 true 去"对齐"。
        "enabled": False,
        "max_sites": 30,           # 每任务最多对多少个站点算 favicon 并反查
        "max_assets": 100,         # 单个 favicon 最多取回多少条资产
        "workers": 5,
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
        # （实测：标题含 "pengo" → 带回 silviapengo.com / gkops.net / yulw.cn …）。
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
    },
    "tools": {
        # 优先从 PATH 解析，也可以填绝对路径（Windows 下如 tools/scanner/httpx.exe）
        "subfinder": "subfinder",
        "puredns": "puredns",
        "httpx": "httpx",
        "nmap": "nmap",
        # fscan（可选）：填二进制名或路径（Windows 下如 tools/scanner/fscan.exe）。
        # 缺省只会在 PATH 里找；找不到就跳过它。**调用时强制 `-np -nobr -nopoc`**
        # —— 不要给它开暴力破解/POC，我们只用它的端口发现能力（见 scanner/portscan.py）。
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
        "subdomains": "config/dicts/subdomains.txt",
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
    """读取第三方 API key 专用文件 `config/keys.yaml`（P0-5）。

    单独成文件而不是塞进 settings.yaml 的理由：GUI「策略配置」页会把 settings 整体写回，
    凭据混在里面容易被覆盖/回显；且 keys 属于"部署环境"而不是"扫描策略"。
    结构示例（顶层按厂商分组）：
        fofa: {email: "", key: ""}
        shodan: {key: ""}
        quake: {key: ""}
    文件不存在或解析失败一律返回 {}，调用方按"无此来源"处理，不影响框架可用性。
    """
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


def save_settings(data):
    """合并写入配置。有 PyYAML 时写 yaml，否则退回 json。

    `keys` 段来自独立的 keys.yaml，**必须剔除**后再落盘 —— 否则 GUI 存一次策略
    就把第三方凭据复制进了 settings.yaml（正是本项目明确要避免的做法）。
    """
    settings = load_settings()
    _deep_merge(settings, data or {})
    settings.pop("keys", None)
    try:
        import yaml
        (BASE_DIR / "config" / "settings.yaml").write_text(
            yaml.safe_dump(settings, allow_unicode=True, sort_keys=False), encoding="utf-8")
    except ImportError:
        (BASE_DIR / "config" / "settings.json").write_text(
            json.dumps(settings, ensure_ascii=False, indent=2), encoding="utf-8")
    return settings


def resolve(path):
    """相对路径基于项目根目录解析。"""
    p = pathlib.Path(str(path))
    return p if p.is_absolute() else (BASE_DIR / p)
