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

BASE_DIR = pathlib.Path(__file__).resolve().parent.parent

# 运行期产物目录（每任务一个子目录）。与数据库一样支持环境变量覆盖：
# 跑测试时指到临时目录，就不会在真实工作区里堆出几十个 `logs/task_*` 目录，
# 也让"开发/生产共用一份代码、数据分开"变得可行（见 tests/smoke.py 顶部）。
LOGS_DIR = pathlib.Path(os.environ.get("CTFSCANNER_LOGS") or (BASE_DIR / "logs"))

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
        "dirscan_max_urls": 20,   # 每任务最多参与目录扫描的站点数
        "vulnscan_max_urls": 100, # 每任务最多参与漏洞扫描的站点数
        "brute_max_domains": 50,  # 每任务最多参与 DNS 爆破的域名数
        "wildcard_filter": True,  # 泛解析过滤（关闭后字典爆破会保留通配命中，噪声极大）
        "favicon_md5": True,      # probe 阶段计算 favicon MD5（零请求前置指纹，见 P1-1）
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
        "timeout": 1.0,            # 单端口连接超时（秒）
        "workers": 64,             # 并发连接数
        "banner": True,            # 连接成功后尝试读取 banner（纯被动读取）
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
        # **默认关闭**：目录爆破是整条流水线里请求量最大、噪声最多的一段（大字典 1.5 万条），
        # 而多数 CTF 拿分不靠它；需要时到「策略配置 → 资产面拓展」打开。
        # 打开后还有两层节流：只对**不重复站点**扫描（标题+长度相同的别名站跳过），
        # 且每个站点最多扫 `max_paths` 条字典。每任务站点上限另见 limits.dirscan_max_urls。
        "enabled": False,
        "big_dict": True,      # 用大字典（config/dicts/dirs_big.txt，由 dirmap 字典整理而来）
        "max_paths": 400,      # 单站点最多扫多少条字典（大字典 1.5 万条时必填此上限）
    },
    "vulnscan": {
        # 漏洞初筛阶段总开关。默认开；关闭后整阶段跳过（连请求都不发），
        # 适合"只做资产测绘、暂不探测"的场景。细粒度门控仍在 checks 段
        # （min_severity / skip_severities / poc_engine / disabled_*）。
        "enabled": True,
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
    },
    "blacklist": {
        # 用户黑名单：命中的域名不入资产库，因此也不会被 dirscan/vulnscan 扫到。
        # 文件是纯文本（一行一个域名，含其所有子域），可手工编辑；GUI 支持批量加入/移除。
        "enabled": True,
        "path": "config/blacklist.txt",
    },
    "tools": {
        # 优先从 PATH 解析，也可以填绝对路径（Windows 下如 tools/scanner/httpx.exe）
        "subfinder": "subfinder",
        "puredns": "puredns",
        "httpx": "httpx",
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
        "dirs_big": "config/dicts/dirs_big.txt",     # 大字典：由 tools/import_dir_dict.py 整理
        "sensitive": "config/dicts/sensitive.txt",  # 预留：内置检查暂用硬编码清单
        "cdn_cname": "config/dicts/cdn_cname.txt",  # CDN 厂商 CNAME 后缀（子域名 CDN 标记用）
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
