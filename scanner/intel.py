"""漏洞情报订阅（P3-2）：拉取公开漏洞情报源 → 与本地资产指纹做**保守匹配** → 只写「线索」。

边界（很重要，别把它当成漏洞结论）：
- **默认关闭**（`intel.enabled`，见「策略配置 → 情报与线索」）；
- 结果**只写 `leads` 表**（kind=`intel`）：不写 `vulns`、不进漏洞计数、不自动导入 POC。
  情报命中的语义是"这条 CVE 与你扫到的组件**可能**相关，值得人工看一眼"，
  **不是**"目标存在这个漏洞" —— 理由见 `TODO.md` P3-2 的原始顾虑：产品名是厂商自述，
  与我们的指纹标签粒度不一致，直接升级成漏洞结论就是放大误报。
- 匹配是**白名单式**的：只有 `MATCH_RULES` 里显式写过的资产信号才参与匹配（宁可漏报），
  且必须"资产侧信号命中 + 情报侧产品关键词命中 + 厂商关键词对得上"三条同时成立。

数据源：CISA KEV（Known Exploited Vulnerabilities Catalog，免 key 的公开 JSON）
—— 它只收录"已被在野利用"的 CVE，正好符合 CTF 里"优先看真被利用的洞"的取向。
`intel.url` 可换成任意同结构 JSON（字段见 `normalize_item`）。

离线可用性：拉取结果落本地缓存（`data/intel/<source>.json`，跟库位置走，测试库自动隔离），
`cache_hours` 内直接用缓存；拉取失败时**退回过期缓存并告警**，不让一个外部源拖垮整条流水线。
"""
import json
import re
import time
from pathlib import Path

from . import db
from .utils import http_request

# 情报源地址（`intel.source` 选键）。KEV 是免 key 的公开 JSON，字段见 normalize_item()。
FEEDS = {
    "kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
}

DEFAULT_CACHE_HOURS = 24

# 情报 → 资产 的匹配规则：`(资产侧信号, 情报侧厂商关键词, 情报侧产品关键词)`
#
# 资产侧信号必须**真实存在于指纹库**（`scanner/fingerprint.py::SIGNATURES` 的标签名，
# 或端口扫描/banner 里会出现的原始词），否则这条规则永远不会命中 —— 那是死代码。
# 刻意不收录"没有指纹信号"的组件（如 Exchange / SharePoint / 各类边界设备）：
# 匹配不到的东西写进来只会让下一个人以为它生效了。
MATCH_RULES = (
    # 资产侧信号           情报侧厂商关键词                   情报侧产品关键词
    ("weblogic",        ("oracle",),                    "weblogic"),
    ("websphere",       ("ibm",),                       "websphere"),
    ("tomcat",          ("apache",),                    "tomcat"),
    ("apache-coyote",   ("apache",),                    "tomcat"),   # banner 里的原始词
    ("struts2",         ("apache",),                    "struts"),
    ("apache",          ("apache",),                    "http server"),
    ("solr",            ("apache",),                    "solr"),
    ("hadoop",          ("apache",),                    "hadoop"),
    ("spring",          ("vmware", "pivotal"),          "spring"),
    ("jenkins",         ("jenkins",),                   "jenkins"),
    ("gitlab",          ("gitlab",),                    "gitlab"),
    ("grafana",         ("grafana",),                   "grafana"),
    ("zabbix",          ("zabbix",),                    "zabbix"),
    ("elasticsearch",   ("elastic",),                   "elasticsearch"),
    ("kibana",          ("elastic",),                    "kibana"),
    ("wordpress",       ("wordpress",),                 "wordpress"),
    ("drupal",          ("drupal",),                    "drupal"),
    ("joomla",          ("joomla",),                    "joomla"),
    ("phpmyadmin",      ("phpmyadmin",),                "phpmyadmin"),
    ("minio",           ("minio",),                     "minio"),
    ("iis",             ("microsoft",),                 "internet information services"),
)

# 信号词两侧的"词边界"：`-` / `.` 算边界（`microsoft-iis`、`apache.coyote` 都要能命中），
# 字母数字算"词内"（挡住 `heliis` 这种把信号当子串吞进来的误匹配）。
_SIGNAL_BOUNDARY = r"(?<![a-z0-9])%s(?![a-z0-9])"


def cache_dir():
    """情报缓存目录：跟随**库位置**（`db.DB_PATH.parent/intel`）。

    这样跑测试时（`CTFSCANNER_DB` 指到临时目录）缓存也一起被隔离，不会往真实
    `data/intel/` 里塞测试数据 —— 与 `db.TRASH_DIR` 同一口径。
    """
    return Path(db.DB_PATH).parent / "intel"


def feed_url(settings):
    """本次要拉取的情报源地址：`intel.url` 优先，留空则按 `intel.source` 取内置地址。"""
    cfg = (settings or {}).get("intel", {}) or {}
    url = str(cfg.get("url") or "").strip()
    if url:
        return url
    return FEEDS.get(str(cfg.get("source") or "kev").strip().lower(), "")


def cache_path(settings):
    """缓存文件路径：按 `source` 命名（换源不会串味）。"""
    cfg = (settings or {}).get("intel", {}) or {}
    name = str(cfg.get("source") or "kev").strip().lower() or "kev"
    name = re.sub(r"[^a-z0-9_-]", "", name) or "kev"
    return cache_dir() / f"{name}.json"


def normalize_item(raw):
    """把一条情报记录规整成统一结构（KEV 字段 → 内部字段）。

    兼容字段缺失/类型异常：拿不到 `cveID` 的记录直接判为无效（返回 None）——
    CVE 号是后面去重与溯源的键，没有它这条情报没有意义。
    """
    if not isinstance(raw, dict):
        return None
    cve = str(raw.get("cveID") or raw.get("cve") or "").strip()
    if not cve:
        return None
    return {
        "cve": cve,
        "vendor": str(raw.get("vendorProject") or "").strip(),
        "product": str(raw.get("product") or "").strip(),
        "name": str(raw.get("vulnerabilityName") or "").strip(),
        "description": str(raw.get("shortDescription") or "").strip(),
        "action": str(raw.get("requiredAction") or "").strip(),
        # KEV 的 `knownRansomwareCampaignUse` 取值是 "Known" / "Unknown"
        "ransomware": str(raw.get("knownRansomwareCampaignUse") or "").strip(),
        "added": str(raw.get("dateAdded") or "").strip(),
        "due": str(raw.get("dueDate") or "").strip(),
        "cwes": ", ".join(str(c) for c in (raw.get("cwes") or [])),
    }


def parse_feed(text):
    """解析情报源响应体 → 规整后的记录列表（解析失败返回空表，不抛异常）。"""
    try:
        data = json.loads(text or "{}")
    except (ValueError, TypeError):
        return []
    if not isinstance(data, dict):
        return []
    items = []
    for raw in (data.get("vulnerabilities") or []):
        it = normalize_item(raw)
        if it:
            items.append(it)
    return items


def _read_cache(path):
    """读本地缓存（不存在/损坏返回空表）。"""
    try:
        return parse_feed(Path(path).read_text(encoding="utf-8"))
    except OSError:
        return []


def _cache_age_hours(path, settings):
    """缓存已存在多久（小时）；不存在返回 None。"""
    try:
        return (time.time() - Path(path).stat().st_mtime) / 3600.0
    except OSError:
        return None


def load_items(settings, logger=None, force=False):
    """取回情报记录，返回 `(items, error)`。

    顺序：本地缓存未过期 → 直接用；否则拉取 → 成功则写缓存；拉取失败 → **退回过期缓存**
    并在日志里告警（`error` 仍带原因，调用方据此说明"用的是旧数据"）。
    """
    cfg = (settings or {}).get("intel", {}) or {}
    url = feed_url(settings)
    if not url:
        return [], f"未配置情报源（intel.source={cfg.get('source')!r} 不在内置表里且 intel.url 为空）"
    try:
        cache_hours = float(cfg.get("cache_hours", DEFAULT_CACHE_HOURS) or 0)
    except (TypeError, ValueError):
        cache_hours = DEFAULT_CACHE_HOURS
    try:
        timeout = int(cfg.get("timeout", 20) or 20)
    except (TypeError, ValueError):
        timeout = 20

    path = cache_path(settings)
    age = _cache_age_hours(path, settings)
    if not force and age is not None and age < cache_hours:
        items = _read_cache(path)
        if items:
            if logger:
                logger.info(f"[intel] 使用本地缓存（{age:.1f} 小时前，共 {len(items)} 条）")
            return items, ""

    resp = http_request(url, timeout=timeout, settings=settings)
    if resp and resp.get("status") == 200:
        text = resp.get("text") or ""
        items = parse_feed(text)
        if items:
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text, encoding="utf-8")
            except OSError as e:
                if logger:
                    logger.warning(f"[intel] 缓存写入失败（不影响本次结果）：{e}")
            return items, ""

    err = (f"拉取情报源失败（HTTP {resp.get('status')}）" if resp
           else "拉取情报源失败（网络不可达或超时）")
    stale = _read_cache(path)
    if stale:
        if logger:
            logger.warning(f"[intel] {err}，改用过期缓存（共 {len(stale)} 条）")
        return stale, err
    return [], err


def _signal_hit(text, signal):
    """资产指纹文本里是否出现该信号词（带词边界，避免短信号被别的单词吞掉）。"""
    return bool(re.search(_SIGNAL_BOUNDARY % re.escape(signal), text))


def match_item(item, asset_text):
    """一条情报与**单个资产**的匹配：返回命中的资产侧信号列表（空表＝不相关）。

    三条同时成立才算命中：① 资产文本里有信号词；② 情报的 product 含对应产品关键词；
    ③ 厂商关键词出现在情报的厂商或产品字段里（有的记录厂商写得很随意）。
    """
    text = str(asset_text or "").lower()
    if not text:
        return []
    product = str(item.get("product") or "").lower()
    vendor = str(item.get("vendor") or "").lower()
    if not product:
        return []
    hits = []
    for signal, vendors, prod_kw in MATCH_RULES:
        if prod_kw not in product:
            continue
        if not _signal_hit(text, signal):
            continue
        if vendors and not any(v in vendor or v in product for v in vendors):
            continue
        hits.append(signal)
    return hits


def asset_keywords(site=None, port=None):
    """把一条资产压成"参与匹配的指纹文本"（小写）。

    - 站点：技术栈标签 + Server 头。**刻意不含标题**：标题是用户内容，
      `登录` / `首页` 这类词与产品名毫无关系，纳入只会制造误报。
    - 端口：服务名 + banner（banner 里常有 `Apache-Coyote/1.1`、`Redis` 这类原始词）。
    """
    if site is not None:
        tech = str(site.get("tech") or "")
        server = str(site.get("server") or "")
        return f"{tech} {server}".strip().lower()
    if port is not None:
        service = str(port.get("service") or "")
        banner = str(port.get("banner") or "")
        return f"{service} {banner}".strip().lower()
    return ""


def level_of(item):
    """线索优先级（**不是 CVSS**）：已知被勒索软件利用 → high，其余 → medium。

    取值只用于页面排序与着色；KEV 本身不提供评分，别把这里的 high 当成"目标高危"。
    """
    return "high" if str(item.get("ransomware") or "").lower() == "known" else "medium"


def build_lead(item, target, hits):
    """把一条命中组装成 `leads` 表的一行（kind=intel）。"""
    desc = item.get("description") or ""
    action = item.get("action") or ""
    detail = (f"厂商/产品：{item.get('vendor') or '-'} / {item.get('product') or '-'}；"
              f"KEV 收录时间：{item.get('added') or '-'}"
              + (f"；修复期限：{item.get('due')}" if item.get("due") else "")
              + (f"；CWE：{item['cwes']}" if item.get("cwes") else "")
              + f"\n说明：{desc}"
              + (f"\n建议动作：{action}" if action else "")
              + "\n注意：这是**情报提醒**（该 CVE 已被在野利用，且与你扫到的组件信号相关），"
                "不代表目标存在该漏洞，需人工验证。")
    return {
        "kind": "intel",
        "code": item.get("cve") or "",
        "title": item.get("name") or item.get("cve") or "",
        "target": target or "",
        "matched": " / ".join(hits),
        "level": level_of(item),
        "detail": detail,
        "source": "CISA KEV",
        "url": f"https://nvd.nist.gov/vuln/detail/{item.get('cve')}" if item.get("cve") else "",
    }