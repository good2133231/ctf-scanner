"""内置指纹识别：httpx 不可用时，从响应头/正文提取组件标签填充 sites.tech。

定位（客观说明）：
- 只是"信号级"标签（如 nginx / php / tomcat），不解析精确版本；版本类判断仍由
  owasp 检查（a06-legacy-banner）与 POC 库承担；
- 规则表刻意保持精简、可扩展：新增一行即可支持新组件，无需改动调用方。

判定成本（续122）：一条 900 KB 的响应原先要把 131 条内置规则 + 51 条外置规则各扫一遍全文
（实测中位 560 ms/次，约 1 ms/KB —— probe 每个站点都要跑一次，多线程下等于抢 GIL）。
现在给每条规则算一个**必现字面量**前置过滤：正则要命中，那个字面量就一定在文本里，
所以"字面量不在"⇒ 这条规则一定不命中，可以直接跳过 `re.search`。实测 900 KB 降到 125 ms
（4.5x）、1 KB 降到 0.34 ms（3.2x），标签集合与旧实现**逐字符相同**（差分验证见 `[8aa]`）。
"一定必现"有三个前提，破坏其中任何一条就**放弃该规则的过滤**（宁可不提速，也不能漏报）：
① 该字面量段处在必填位置上（`X{0,}`/`X?` 里的内容不算）；② 大小写折叠与 `str.lower()` 一致
（实测枚举 BMP 后，`re.I` 与 `lower()` 只在 `U+0130/U+0131/U+017F` 三个码点上不一致 ——
文本里有这三个字符就不折叠）；③ 没有组内局部 `(?i...)` 这类"编译期标志看不出但匹配期不区分大小写"
的写法。

favicon 指纹（P1-1 / P3-1，参考项目 `_get_favicon_md5` 的启发）：
同一套源码部署的系统 favicon 完全一致，因此它是**零请求前置指纹** —— POC 里声明
`favicon_md5_list` 后，目标 favicon 不匹配就不必再发任何探测请求（见 `pocs/engine.py`）。

这里同时计算**两种**指纹，用途不同、不要混用：
- MD5（`favicon_md5`）：我们自己的 `favicon_md5_list` 前置判定用，谁也不用对上；
- mmh3（`favicon_hash`）：**对外部平台**提问用 —— FOFA `icon_hash`、Shodan `http.favicon.hash`
  都以 mmh3 为键（算法实现见 `scanner/mmh3.py`，纯标准库，无需 mmh3 包）。
先前的注释说"我们只做 MD5，不做 mmh3，因为环境里没有可用的哈希库"——
该理由已不成立（`mmh3.py` 自带已知向量自检），故补齐，否则 `fofa.py` 无从提问。
"""
import hashlib
import re
from pathlib import Path

try:                                    # 3.11+ 把 sre_parse 挪进 re._parser；3.9/3.10 还是顶层模块
    from re import _parser as _sre      # noqa
except ImportError:
    import sre_parse as _sre            # noqa

# 内联全局标志（`(?i)` / `(?im)`）**只能写在串首**：Python 3.11 起这是弃用写法、3.14 起直接
# 抛 PatternError（本项目 CI 用 3.9，故此前无人发现）。同一条规则里多余的那个一律删掉——
# 串首那个本来就作用于整条表达式，分支再写一次是冗余。回归见 `tests/smoke.py [8d]`。
# --------------------------------------------------------------------------
# 必现字面量前置过滤（续122）
# --------------------------------------------------------------------------
# 三个"宁可不提速也不能漏报"的口径都写在 identify 的文档串里，这里只是实现。
_FOLD_EXOTIC = ("\u0130", "\u0131", "\u017f")   # re.I 与 str.lower() 不一致的**全部**码点
_MIN_LIT = 2                                       # 短于此长度的字面量过滤不掉任何东西，白算
_REPEAT_OPS = tuple(getattr(_sre, n) for n in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT")
                    if hasattr(_sre, n))
_LOCAL_I_RE = re.compile(r"\(\?[a-zA-Z]*i")       # 组内局部 (?i) / (?i:…)/(?i-…)
_lit_cache = {}


def _literal_runs(seq):
    """必填位置上的"极大连续字面量段"；返回 None = 结构认不出（调用方放弃过滤）。"""
    out, cur = [], []
    for item in seq:
        op, arg = item[0], item[1]
        if op == _sre.LITERAL:
            cur.append(chr(arg))
            continue
        if cur:
            out.append("".join(cur))
            cur = []
        if op in _REPEAT_OPS and int(arg[0]) >= 1:
            # 只有"至少重复一次"的部分才是必现的；`X?` / `X{0,}` 里的内容不算（arg[0] 是最小次数）
            sub = _literal_runs(arg[2])
            if sub is None:
                return None
            out.extend(sub)
        # 其余操作符（AT/IN/ANY/断言/未知）只当作"字面量被截断"，不影响剩下这些段的必现性
    if cur:
        out.append("".join(cur))
    return out


def required_literals(pattern):
    """正则 -> `(忽略大小写?, [必须至少出现一个的字面量])`，或 None（不过滤）。

    取的是**每个分支的最长必现段**：分支之间是"或"，所以过滤条件是"这些字面量里至少有一个在文本里"；
    只要有**一个分支**挑不出够长的必现段，整条规则就不能过滤（命中可能正好走那条分支）。
    """
    try:
        top = list(_sre.parse(pattern))
    except Exception:
        return None
    alts = top[0][1][1] if (len(top) == 1 and top[0][0] == _sre.BRANCH) else [top]
    lits = []
    for alt in alts:
        runs = _literal_runs(list(alt))
        if runs is None:
            return None
        best = max(runs, key=len) if runs else ""
        if len(best) < _MIN_LIT:
            return None
        lits.append(best)
    return lits


def _lit_filter(pattern):
    """按**正则原文**缓存过滤条件（内置表是字符串、外置表是编译后的对象，都取 `.pattern`）。"""
    rx = pattern if hasattr(pattern, "pattern") else re.compile(pattern)
    key = rx.pattern
    hit = _lit_cache.get(key, False)
    if hit is not False:
        return hit
    ci = bool(rx.flags & re.IGNORECASE)
    val = None
    if _LOCAL_I_RE.search(key) and not ci:
        val = None                      # 局部 (?i) 让"编译期看不出、匹配期却不分大小写" ⇒ 放弃过滤
    else:
        lits = required_literals(key)
        if lits:
            val = (ci, [l.lower() for l in lits] if ci else lits)
    _lit_cache[key] = val
    return val


# 标签 -> [(part, 正则[, 状态码])]；part: headers | body | cookies；任一规则命中即打该标签。
# 第三元组（续120）是 `frozenset` 状态码集合，缺省 = 不分状态。内置规则**一律不分状态**
# （它们看的本来就是"响应头/正文里有没有这个特征"）；那一段是给外置表用的形状。
SIGNATURES = {
    # ---------- 服务器 / 反向代理 ----------
    "nginx": [("headers", r"(?im)^server:\s*nginx(?![\w-])")],
    "openresty": [("headers", r"(?i)openresty")],
    "tengine": [("headers", r"(?i)\btengine\b")],
    "apache": [("headers", r"(?im)^server:\s*apache(?![\w-])")],
    "iis": [("headers", r"(?im)^server:\s*microsoft-iis")],
    "caddy": [("headers", r"(?im)^server:\s*caddy")],
    "lighttpd": [("headers", r"(?i)lighttpd")],
    "gunicorn": [("headers", r"(?im)^server:\s*gunicorn")],
    "uvicorn": [("headers", r"(?im)^server:\s*uvicorn")],
    "werkzeug": [("headers", r"(?im)^server:\s*werkzeug")],
    "waitress": [("headers", r"(?im)^server:\s*waitress")],
    "jetty": [("headers", r"(?i)\bjetty\b")],
    "tomcat": [("headers", r"(?i)tomcat|apache-coyote")],
    "wildfly": [("headers", r"(?i)wildfly|jboss")],
    "weblogic": [("headers", r"(?i)weblogic")],
    "websphere": [("headers", r"(?i)websphere")],
    "resin": [("headers", r"(?i)\bresin\b")],
    # ---------- CDN / WAF / 网关（这些是"是不是真实 IP"的关键线索）----------
    "cloudflare": [("headers", r"(?im)^server:\s*cloudflare|cf-ray:|cf-cache-status")],
    "cloudfront": [("headers", r"(?i)x-amz-cf-id|^via:.*cloudfront")],
    "akamai": [("headers", r"(?i)akamaighost|x-akamai-|akamai-grn")],
    "fastly": [("headers", r"(?i)x-served-by:.*fastly|x-fastly-|fastly-io-info")],
    "varnish": [("headers", r"(?i)^x-varnish:|via:.*varnish")],
    "haproxy": [("headers", r"(?i)haproxy")],
    "envoy": [("headers", r"(?i)istio-envoy|x-envoy-")],
    "kong": [("headers", r"(?im)^server:\s*kong")],
    "traefik": [("headers", r"(?i)traefik")],
    "awselb": [("headers", r"(?i)awselb|elasticloadbalancing")],
    "safedog": [("headers", r"(?i)safedog|waf/2\.0")],
    "yunsuo": [("headers", r"(?i)yunsuo|yunsuo_session")],
    "raywaf": [("headers", r"(?i)x-df-|raywaf|chaitin")],
    "yundun": [("headers", r"(?i)yundun|aliyungf")],
    "360waf": [("headers", r"(?i)360wzws|x-safe-")],
    # ---------- 语言 / 运行时 ----------
    "php": [("headers", r"(?im)^x-powered-by:\s*php|php/[\d.]+"),
            ("cookies", r"(?i)PHPSESSID|php[\w]*session")],
    "aspnet": [("headers", r"(?i)asp\.net|x-aspnet-version|x-powered-by:\s*asp\.net"),
               ("cookies", r"(?i)ASP\.NET_SessionId|\.AspNetCore")],
    "java": [("cookies", r"(?i)JSESSIONID|rememberMe="),
             ("headers", r"(?i)x-powered-by:\s*servlet|jsessionid")],
    "python": [("headers", r"(?i)^server:\s*python|python/[\d.]+")],
    "nodejs": [("headers", r"(?i)^x-powered-by:\s*express|^server:\s*node")],
    "ruby": [("headers", r"(?i)phusion passenger|^x-powered-by:\s*phusion")],
    "golang": [("headers", r"(?i)^server:\s*go-?http|^x-powered-by:\s*go")],
    # ---------- 框架 / 中间件（Java 系）----------
    "spring": [("headers", r"(?i)x-application-context|spring"),
               ("body", r"(?i)Whitelabel Error Page|org\.springframework")],
    "struts2": [("body", r"(?i)struts\.devMode|/struts/|struts2"), ("headers", r"(?i)struts")],
    "shiro": [("cookies", r"(?i)rememberMe=")],
    "jenkins": [("headers", r"(?i)^x-jenkins:|^x-hudson:")],
    "nacos": [("body", r"(?i)nacos|console-fe"), ("headers", r"(?i)nacos")],
    "druid": [("body", r"(?i)druid\.stat|druid monitor")],
    "swagger": [("body", r"(?i)swagger-ui|swagger-resources|openapi\.json")],
    "solr": [("body", r"(?i)solr admin|solr/coreadmin")],
    "elasticsearch": [("headers", r"(?i)x-elastic-product"),
                      ("body", r'(?i)"cluster_name"\s*:|you know, for search')],
    "kibana": [("headers", r"(?i)kbn-name|kbn-version")],
    "grafana": [("headers", r"(?i)grafana"), ("body", r"(?i)grafana-app|grafana_session")],
    "zabbix": [("cookies", r"(?i)zbx_session"), ("body", r"(?i)zabbix")],
    "gitlab": [("headers", r"(?i)gitlab|_gitlab_session"), ("body", r"(?i)gitlab")],
    "harbor": [("body", r"(?i)harbor-|clarity\.js.*harbor")],
    "minio": [("headers", r"(?im)^server:\s*minio"), ("body", r"(?i)minio browser")],
    "hadoop": [("body", r"(?i)hadoop|namenode|resourcemanager")],
    "consul": [("body", r"(?i)consul by hashicorp")],
    "prometheus": [("body", r"(?i)prometheus time series|prometheus/")],
    "rabbitmq": [("headers", r"(?im)^server:\s*rabbitmq"), ("body", r"(?i)rabbitmq management")],
    # ---------- 国产 OA / ERP（CTF 高价值目标）----------
    "weaver-ecology": [("body", r"(?i)/spa/portal/|ecology|weaver.*e-cology|/wui/theme/"),
                       ("cookies", r"(?i)ecology_|weaver")],
    "weaver-eoffice": [("body", r"(?i)eoffice|e-mobile"), ("cookies", r"(?i)eoffice")],
    "seeyon": [("body", r"(?i)seeyon|/seeyon/|致远"), ("cookies", r"(?i)JSESSIONID.*seeyon|loginPage")],
    "tongda-oa": [("body", r"(?i)ispirit|/general/|通达"), ("cookies", r"(?i)OA_USER|ispirit")],
    "landray": [("body", r"(?i)landray|蓝凌|/sys/ui/")],
    "fanruan": [("body", r"(?i)finereport|/webreport/|finebi")],
    "kingdee": [("body", r"(?i)kingdee|k3cloud|/kdcloud/")],
    "yonyou": [("body", r"(?i)yonyou|用友|nccloud|/uap/")],
    "ruoyi": [("body", r"(?i)ruoyi|若依"), ("headers", r"(?i)ruoyi")],
    "jeecg": [("body", r"(?i)jeecg|jeecgboot")],
    "smartbi": [("body", r"(?i)smartbi")],
    # ---------- CMS / 建站 ----------
    "wordpress": [("body", r"(?i)wp-content|wp-includes"),
                  ("headers", r"(?i)wp-super-cache|x-pingback")],
    "drupal": [("headers", r"(?i)^x-generator:\s*drupal|x-drupal-"),
               ("body", r"(?i)sites/(default|all)/files|drupal\.js")],
    "joomla": [("body", r"(?i)/components/com_|joomla"), ("headers", r"(?i)joomla")],
    "dedecms": [("body", r"(?i)/dede/|dedecms|织梦"), ("headers", r"(?i)dedecms")],
    "discuz": [("body", r"(?i)discuz|/forum\.php|static/image/common"), ("headers", r"(?i)discuz")],
    "phpcms": [("body", r"(?i)phpcms")],
    "typecho": [("body", r"(?i)typecho")],
    "zblog": [("body", r"(?i)zblog|zb_users")],
    "thinkphp": [("headers", r"(?i)thinkphp"), ("body", r"(?i)think_template|thinkphp")],
    "laravel": [("cookies", r"(?i)laravel_session|XSRF-TOKEN"), ("body", r"(?i)laravel")],
    "yii": [("cookies", r"(?i)YII_CSRF_TOKEN"), ("body", r"(?i)yii framework")],
    "codeigniter": [("cookies", r"(?i)ci_session")],
    "symfony": [("cookies", r"(?i)sf_redirect|symfony"), ("headers", r"(?i)symfony")],
    "fastadmin": [("body", r"(?i)fastadmin")],
    "phalcon": [("headers", r"(?i)phalcon")],
    "django": [("cookies", r"(?i)csrftoken|django_language"), ("body", r"(?i)csrfmiddlewaretoken")],
    "flask": [("headers", r"(?i)^server:\s*werkzeug")],
    "rails": [("cookies", r"(?i)_rails_session|_session_id"), ("headers", r"(?i)^x-powered-by:.*phusion")],
    "fastapi": [("body", r'(?i)"detail":\s*\[\{"loc"|openapi\.json')],
    # ---------- 前端框架（判断 SPA 与前端栈）----------
    "vue": [("body", r"(?i)vue(?:\.min)?\.js|__vue__|data-v-[0-9a-f]{8}")],
    "react": [("body", r"(?i)react(?:\.production\.min)?\.js|data-reactroot|__REACT_DEVTOOLS")],
    "nextjs": [("body", r"(?i)__NEXT_DATA__|/_next/static/")],
    "nuxt": [("body", r"(?i)__NUXT__|/_nuxt/")],
    "angular": [("body", r"(?i)ng-version=|angular(?:\.min)?\.js")],
    "jquery": [("body", r"(?i)jquery(?:\.min)?\.js|jquery-[\d.]+")],
    "bootstrap": [("body", r"(?i)bootstrap(?:\.min)?\.css|bootstrap(?:\.min)?\.js")],
    "element-ui": [("body", r"(?i)element-ui|el-button|el-input__inner")],
    "layui": [("body", r"(?i)layui\.js|layui\.css|layui-btn")],
    "antd": [("body", r"(?i)antd|ant-btn|ant-design")],
    "echarts": [("body", r"(?i)echarts(?:\.min)?\.js")],
    "swagger-ui-bundle": [("body", r"(?i)swagger-ui-bundle\.js")],
    # ---------- 其它常见组件 ----------
    "phpmyadmin": [("body", r"(?i)phpmyadmin|pma_password")],
    "adminer": [("body", r"(?i)adminer")],
    "websocket": [("headers", r"(?i)^upgrade:\s*websocket")],
}

# --------------------------------------------------------------------------
# 外置指纹表（续120）：加标签不用改代码，且带**状态码门控**
# --------------------------------------------------------------------------
# 为什么非要有状态码这一列：afrog-pocs 的判据几乎全写成 `response.status == 200 && 正文含 X`，
# 而原先的 `(part, 正则)` 表达不了"只在 200 时才算"。照搬关键字的后果是实测推出来的：
# 一个回了 404 却把产品名写进 `<title>` 的目标会被打上该产品的标签 —— 自己制造误报。
# 所以外置表按行带状态码，内置 SIGNATURES 保持两元组不动。
EXTRA_FILE = "config/dicts/fingerprints_extra.txt"
_WHERE = ("headers", "body", "cookies")
_extra_cache = {"key": None, "rules": {}, "issues": []}


def _extra_path():
    from .config import resolve      # 函数内导入：不与 config 的加载顺序纠缠（同 utils 里的写法）
    return resolve(EXTRA_FILE)


def _parse_statuses(text):
    """`"200,404"` -> frozenset；`"*"`/空 -> None（不分状态）；非法 -> 错误说明串。"""
    t = (text or "").strip()
    if t in ("", "*"):
        return None
    codes = []
    for piece in t.split(","):
        if not piece.strip().isdigit() or not 100 <= int(piece.strip()) <= 599:
            return f"非法状态码 {text!r}"
        codes.append(int(piece.strip()))
    return frozenset(codes)


def load_extra(path=None):
    """读外置指纹表 -> `({标签: [(位置, 编译后的正则, 状态码集合|None)]}, [问题, …])`。

    三件事值得写明：
    - **分隔符是 TAB**。判据本身就是正则，`|` 在正则里是"或"，拿 `|` 切列会把判据腰斩
      （`tools/import_afrog_fp.py` 用 `|` 的第一版就是这么坏的）；
    - 缓存键是 `(路径, mtime_ns, 大小)`：`identify()` 每个响应都要跑一次，不能每次重读文件、
      重编正则；改完字典下一次响应即生效，不用重启；
    - 坏行**不静默**：进问题清单交给 `--lint` 与回归；命中逻辑只跳过这一条，不牵连别的行。
    """
    p = Path(path) if path else _extra_path()
    try:
        st = p.stat()
    except OSError:
        _extra_cache.update(key=None, rules={}, issues=[])
        return {}, []
    key = (str(p), st.st_mtime_ns, st.st_size)
    if _extra_cache["key"] == key:
        return _extra_cache["rules"], _extra_cache["issues"]
    rules, issues = {}, []
    text = p.read_text(encoding="utf-8", errors="replace")
    for no, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        cols = line.split("\t")
        if len(cols) < 3:
            issues.append(f"第 {no} 行不足 3 列（标签<TAB>位置<TAB>判据）：{line[:40]!r}")
            continue
        tag, where, pattern = cols[0].strip(), cols[1].strip(), cols[2]
        if not tag:
            issues.append(f"第 {no} 行标签为空")
            continue
        if where not in _WHERE:
            issues.append(f"第 {no} 行位置 {where!r} 不属于 {'/'.join(_WHERE)}")
            continue
        codes = _parse_statuses(cols[3] if len(cols) > 3 else "")
        if isinstance(codes, str):
            issues.append(f"第 {no} 行 {codes}")
            continue
        try:
            rx = re.compile(pattern)
        except re.error as e:
            issues.append(f"第 {no} 行判据编译失败（{e}）")
            continue
        rules.setdefault(tag, []).append((where, rx, codes))
    _extra_cache.update(key=key, rules=rules, issues=issues)
    return rules, issues

# favicon 体积上限：有些站点会用 404 页面或超大文件冒充 favicon，直接跳过
MAX_FAVICON = 512 * 1024


def identify(resp):
    """从 http_request 的响应 dict 中提取组件标签，返回排序去重后的列表。

    规则有两个来源：内置 `SIGNATURES` 与外置 `EXTRA_FILE`（`load_extra`，带状态码门控）。
    带第三元组的规则只在响应状态落在那个集合里时才参与判定。
    """
    if not resp:
        return []
    hdrs = resp.get("headers") or {}
    parts = {
        "headers": "\n".join(f"{k}: {v}" for k, v in hdrs.items()),
        "body": resp.get("text") or "",
        # 单独拆出 Cookie：`Set-Cookie: PHPSESSID=` / `JSESSIONID` / `ASP.NET_SessionId`
        # 是判断"这站是什么语言写的"最可靠也最省事的线索（比正文关键字准得多）。
        "cookies": "\n".join(f"{k}: {v}" for k, v in hdrs.items()
                              if k.lower() in ("set-cookie", "cookie")),
    }
    status = resp.get("status")
    # 折叠文本按需算：`isascii()` 是 O(1)（CPython 在对象上存了紧凑 ASCII 标记），
    # 只有非 ASCII 文本才需要再扫那三个例外码点
    folded = {}
    for key, val in parts.items():
        folded[key] = val.lower() if (val.isascii() or not any(c in val for c in _FOLD_EXOTIC)) else None
    tags = []
    for source in (SIGNATURES, load_extra()[0]):
        for tag, rules in source.items():
            for rule in rules:
                codes = rule[2] if len(rule) > 2 else None
                if codes is not None and status not in codes:
                    continue
                part, pattern = rule[0], rule[1]
                flt = _lit_filter(pattern)
                if flt:
                    ci, lits = flt
                    if ci:
                        hay = folded.get(part)
                        if hay is None:
                            pass                 # 折叠不安全 ⇒ 不跳过，交给正则
                        elif not any(l in hay for l in lits):
                            continue
                    elif not any(l in parts.get(part, "") for l in lits):
                        continue
                if re.search(pattern, parts.get(part, "")):
                    tags.append(tag)
                    break
    return sorted(set(tags))


def fetch_favicon(base_url, settings=None, timeout=None):
    """抓取 /favicon.ico 并返回**过滤后的原始字节**；拿不到或不像图标时返回 b""。

    只做一次 GET（非破坏性），失败静默返回空——favicon 只是"加速判定"的辅助信号，
    拿不到不影响主流程（POC 侧对空值不做前置排除，避免误杀）。
    两种指纹（md5 / mmh3）共用这一份实现，保证判定口径一致。
    """
    from .utils import http_request
    if timeout is None:
        timeout = int((settings or {}).get("limits", {}).get("http_timeout", 10))
    url = str(base_url).rstrip("/") + "/favicon.ico"
    resp = http_request(url, timeout=timeout, settings=settings, want_bytes=True, auth=True)
    if not resp or resp.get("status") != 200:
        return b""
    content = resp.get("content") or b""
    if not content or len(content) > MAX_FAVICON:
        return b""
    # 图标是二进制；若服务端把 HTML 错误页当 favicon 返回，长度特征会明显不同，
    # 这里用一句廉价判断排掉最常见的"HTML 404 页"（避免不同站点共享同一个假指纹）
    # 取够长度再判：`content[:6]` 只有 6 字节，永远匹配不上 9 字节的 `<!doctype`
    # （`<html` 能匹配），等于该分支只挡了一半。取 64 字节足够覆盖 BOM/前导空白 + 声明。
    if content[:64].lstrip().lower().startswith((b"<!doctype", b"<html")):
        return b""
    return content


def favicon_md5(base_url, settings=None, timeout=None):
    """favicon 内容 MD5；拿不到或不像图标时返回 ""（用于 favicon_md5_list 前置判定）。"""
    content = fetch_favicon(base_url, settings, timeout)
    return hashlib.md5(content).hexdigest() if content else ""


def favicon_hash(base_url, settings=None, timeout=None):
    """favicon 的 mmh3 哈希（有符号 32 位）；拿不到或不像图标时返回 0。

    仅用于向外部平台（FOFA / Shodan）提问，**不要**拿去和 `favicon_md5_list` 比对。
    """
    from .mmh3 import favicon_hash as _murmur
    content = fetch_favicon(base_url, settings, timeout)
    return _murmur(content) if content else 0