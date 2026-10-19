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
import threading
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


def _is_seq(v):
    """能不能当解析后的子序列展开。3.11 起 SubPattern 不再是 list 子类，只认 __getitem__。"""
    return hasattr(v, "__getitem__") and not isinstance(v, (str, bytes, bytearray))


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
        elif op == _sre.SUBPATTERN and _is_seq(arg[-1]):
            # 组本身在必填位置上 ⇒ 组里的字面量整条表达式也必现（AKIA/LTAI 就躺在捕获组里）。
            # 展开不了的那一档退回"截断"：只可能少提速，不可能漏报。
            sub = _literal_runs(list(arg[-1]))
            if sub is None:
                return None
            out.extend(sub)
        elif op == _sre.ASSERT and _is_seq(arg[1]) and int(arg[0] or 0) >= 1:
            # 续197：**正向**断言（`(?=…)` / `(?<=…)`，`arg[0]` 为 1 / -1 表示方向，负向那类是
            # ASSERT_NOT 不在这里）成立 ⇒ 断言里的内容必现在某处 —— 社区库的 and 规则正是
            # `^(?=.*X)(?=.*Y)` 这个形状，X 与 Y 都必现，所以它们都是合法的过滤条件。
            # 过滤用的是"任一命中即跑正则"（OR），而 and 规则要求**全部**命中 ⇒ 只会少提速，
            # 不可能漏报（都不在 ⇒ 必然不命中）。取不到就整条放弃，口径与上面各分支一致。
            sub = _literal_runs(list(arg[1]))
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
# 续197（主理人点单"参照 github 现有的指纹库来集合，越多越好"）：外置表从**一份**变**多份**
# —— 手写那张（afrog 导入 + 手工条目）之外，新加两张**社区库转换**来的表，由
# `tools/import_fingerprints.py` 生成（只转判据，外部仓库源码不进本仓）：
#   fingerprints_hub.txt   ← FingerprintHub / ObserverWard（3150 个组件标签）
#   fingerprints_ehole.txt ← EHole 棱洞（805 个）
# 三张表**同一份格式**，所以解析逻辑仍然只有一份（多一个文件 ≠ 多一套读法）。
EXTRA_FILES = [EXTRA_FILE,
               "config/dicts/fingerprints_hub.txt",
               "config/dicts/fingerprints_ehole.txt",
               # 续206：nuclei 官方 `http/fingerprints/`（由 `tools/update_pocs.py --source nuclei`
               # 拉取并转换）。**文件可以不存在**（`load_extra` 跳过缺失的表），
               # 先登记是为了"跑一次更新命令就自动生效"，不用改代码。
               "config/dicts/fingerprints_nuclei.txt",
               # 续204：chainreactors/fingers（第三个外部源；规模最小 —— 它仓库里那份
               # yaml 只是维护清单，完整规则在 Go 源码内。留着是为了证明"再加一个源"
               # 只是往这个列表里加一行 + 跑一次转换器）。
               "config/dicts/fingerprints_fingers.txt"]
_WHERE = ("headers", "body", "cookies")
_extra_cache = {"key": None, "rules": {}, "issues": []}


def _extra_path():
    from .config import resolve      # 函数内导入：不与 config 的加载顺序纠缠（同 utils 里的写法）
    return resolve(EXTRA_FILE)


def _extra_paths():
    """全部外置表的绝对路径（**不存在的文件直接跳过**，不报错 —— 表是可选项）。"""
    from .config import resolve
    return [resolve(f) for f in EXTRA_FILES]


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


def _parse_extra_text(text, source=""):
    """解析一张外置表的内容 -> `(rules, issues)`（格式说明见 `load_extra`）。"""
    rules, issues = {}, []
    _pre = f"{source}：" if source else ""
    for no, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        cols = line.split("\t")
        if len(cols) < 3:
            issues.append(f"{_pre}第 {no} 行不足 3 列（标签<TAB>位置<TAB>判据）：{line[:40]!r}")
            continue
        tag, where, pattern = cols[0].strip(), cols[1].strip(), cols[2]
        if not tag:
            issues.append(f"{_pre}第 {no} 行标签为空")
            continue
        if where not in _WHERE:
            issues.append(f"{_pre}第 {no} 行位置 {where!r} 不属于 {'/'.join(_WHERE)}")
            continue
        codes = _parse_statuses(cols[3] if len(cols) > 3 else "")
        if isinstance(codes, str):
            issues.append(f"{_pre}第 {no} 行 {codes}")
            continue
        try:
            rx = re.compile(pattern)
        except re.error as e:
            issues.append(f"{_pre}第 {no} 行判据编译失败（{e}）")
            continue
        rules.setdefault(tag, []).append((where, rx, codes))
    return rules, issues


def load_extra(path=None):
    """读外置指纹表 -> `({标签: [(位置, 编译后的正则, 状态码集合|None)]}, [问题, …])`。

    `path` 给定 = 只读那一张（lint 与回归用）；不给 = 读 `EXTRA_FILES` 里的**全部**并合并
    （续197：外置表从一份变多份；同一标签的规则跨表累加，命中口径不变）。

    三件事值得写明：
    - **分隔符是 TAB**。判据本身就是正则，`|` 在正则里是"或"，拿 `|` 切列会把判据腰斩
      （`tools/import_afrog_fp.py` 用 `|` 的第一版就是这么坏的）；
    - 缓存键是**每张表的 `(路径, mtime_ns, 大小)`**：`identify()` 每个响应都要跑一次，
      不能每次重读文件、重编正则；改完字典下一次响应即生效，不用重启；
    - 坏行**不静默**：进问题清单交给 `--lint` 与回归；命中逻辑只跳过这一条，不牵连别的行。
    """
    if path:
        p = Path(path)
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return {}, []
        return _parse_extra_text(text, p.name)
    paths = [p for p in _extra_paths() if p.exists()]
    if not paths:
        _extra_cache.update(key=None, rules={}, issues=[])
        return {}, []
    try:
        key = tuple((str(p), p.stat().st_mtime_ns, p.stat().st_size) for p in paths)
    except OSError:
        return {}, []
    if _extra_cache["key"] == key:
        return _extra_cache["rules"], _extra_cache["issues"]
    rules, issues = {}, []
    for p in paths:
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        r, i = _parse_extra_text(text, p.name)
        for tag, lst in r.items():
            rules.setdefault(tag, []).extend(lst)
        issues.extend(i)
    _extra_cache.update(key=key, rules=rules, issues=issues)
    return rules, issues

# --------------------------------------------------------------------------
# 组件标签的"补标"通道（续127）：把**已经发过**的响应喂回 identify()
# --------------------------------------------------------------------------
# 为什么要有这一段（实测出来的洞）：外置表 51 条里 **47 条的判据原本是"打了 /login、
# /druid/login.html 这类路径之后长这样"**，而全仓只有 probe 的内置探测会调 `identify()`
# （根响应）⇒ 这批规则基本永不触发，只白占判定成本。用 `tools/calibrate_fingerprints.py`
# 的负样本语料复测后得到的结论是：**它们的判据本身不宽**（12 份通用页 0 命中，命中的 10 个
# 标签全来自内置表且都是真识别），所以缺的不是"路径门控收紧"，而是"没人把响应喂进来"。
# dirscan / jsmine 本来就在发这些请求、也本来就在手里拿着正文 —— 补上这一段是**零额外请求**的。
_TECH_LOCK = threading.Lock()    # 桩 ctx（回归里手搓的）没带锁时用它，宁可串行也不留静默并发


def collect(ctx, site_url, resp, where=""):
    """把一份已在手的响应里识别出的标签**攒进 ctx**（不写库、不发请求），返回新增标签数。

    攒到阶段末尾由 `flush()` 一次合并：dirscan 一个站点要打几百条路径，逐条 UPDATE
    会把写锁踩成瓶颈；而且同一条路径的标题往往和根响应重复。
    """
    if ctx is None or not resp or not site_url:
        return 0
    tags = identify(resp)
    if not tags:
        return 0
    pend = getattr(ctx, "_tech_pending", None)
    if pend is None:
        pend = ctx._tech_pending = {}
    lock = getattr(ctx, "_tech_lock", None) or _TECH_LOCK
    src = "js" if str(where or "") == "js" else "doc"
    with lock:
        # 续221：桶按来源分。超上限截断时**主文档优先**，JS 侧的标签先丢 ——
        # 同一个产品，主文档认不出来而 JS 里有个字样，后者显然更不可信。
        bucket = pend.setdefault(str(site_url), {"doc": set(), "js": set()})
        part = bucket.setdefault(src, set())
        n = len([t for t in tags if t not in part])
        part.update(tags)
    return n


def flush(ctx, logger=None, where=""):
    """把攒下的标签并进 `sites.tech`（**内存与库两处**），并说一句可见的话。

    两处都要改的理由：`sites.tech` 的下游里，vulnscan 的 POC 优先排序与 dirscan 的框架字典
    读的是 **ctx.results["sites"]**，而页面/报告读的是**库** —— 只改一边就会出现
    "页面上标签有了、下一阶段却当没看见"这种最难查的不对称。
    没有新增就一个字段都不写、也**不打日志**（不刷噪声）。
    """
    pend = getattr(ctx, "_tech_pending", None) or {}
    if not pend:
        return 0, set()
    from . import db
    new_tags = set()
    sites = ctx.results.get("sites") or []
    by_url = {str(s.get("url")): s for s in sites}
    updates = {}
    hidden_js = hidden_over = 0
    cap = max_tags(getattr(ctx, "settings", None))
    for url, bucket in pend.items():
        doc_tags = set((bucket or {}).get("doc") or set())
        js_tags = set((bucket or {}).get("js") or set()) - doc_tags
        # 主文档优先、JS 补位；仍超上限 ⇒ 只取前 cap 个，**丢了多少必须说出来**
        ordered = sorted(doc_tags) + sorted(js_tags)
        if len(ordered) > cap:
            hidden_js += len([t for t in ordered[cap:] if t in js_tags])
            hidden_over += len(ordered) - cap
            ordered = ordered[:cap]
        new_tags |= set(ordered)
        cur = [t for t in str((by_url.get(url) or {}).get("tech") or "").split(",") if t]
        add = [t for t in ordered if t not in cur]
        if not add:
            continue
        updates[url] = sorted(set(cur) | set(ordered))
        # 内存里同步：本阶段之后的下一阶段读的就是这份快照
        if url in by_url:
            by_url[url]["tech"] = ",".join(updates[url])
    n, missing = db.merge_sites_tech(ctx.task_id, updates) if updates else (0, [])
    if logger and (n or missing):
        bits = [f"补标 {n} 个站点"] if n else ["没有新标签"]
        if new_tags:
            bits.append("新增标签：" + "、".join(sorted(new_tags)))
        if missing:
            # 必须说出来：标签无处可挂意味着这批识别结果**没进任何出口**，
            # 不写就是"扫过了、页面上却没有"那种静默。
            bits.append(f"另有 {len(missing)} 个目标不在本任务站点表里（补扫任务没跑 probe？"
                        f"标签没挂上：{'、'.join(missing[:3])}{'…' if len(missing) > 3 else ''}）")
        if hidden_over:
            # 续221：标签上限（fingerprint.max_tags）截断的也必须说出来 ——
            # "20+ 个标签"本身就是用户报的故障，静默截断只会把故障藏成"怎么少了几个"。
            bits.append(f"另有 {hidden_over} 个标签未纳入（上限 {cap}，其中 {hidden_js} 个"
                        f"来自 JS 内容、优先级低于主文档）")
        logger.info(f"[{where}] 指纹补标（吃的是本阶段已发的响应，零额外请求）：" + "，".join(bits))
    ctx._tech_pending = {}
    return n, new_tags


# favicon 体积上限：有些站点会用 404 页面或超大文件冒充 favicon，直接跳过
MAX_FAVICON = 512 * 1024


# 参与匹配的正文长度上限（见 `identify` 里的说明）：只为防"一条慢正则 × 超大正文"把
# 探测拖死，不是判定口径 —— 截断前后对真实页面的命中集合差异可以忽略。
MAX_BODY_SCAN = 128 * 1024


def all_tags():
    """**全部**能识别的组件标签（内置 + 全部外置表），排序去重。

    存在的理由（续197）：POC 与指纹要能对上号 —— POC 的 `info.tags` 里写着产品名
    （`thinkphp`、`shiro`…），指纹识别出的标签也是产品名，两边取交集就是
    "这条 POC 是打哪个组件的"。POC 页面据此分类，vulnscan 据此把相关 POC 排到前面
    （见 `stages/vulnscan.py::_pocs_for`）。标签集合只在这里算一次，别处各写一份就会漂移。
    """
    return sorted(set(SIGNATURES) | set(load_extra()[0]))


# --------------------------------------------------------------------------
# 同义归一 / 弱规则降级 / 数量收口（续221）
# --------------------------------------------------------------------------
# 起因（主理人 2026-10-19 报的一个真站）：一个 Sentry 登录页被打出 20+ 个标签
# （Cloudflare ×3、next.js/nextjs、禅道、群晖-nas、群晖-diskstation、深信服、联软…）。
# 逐条查下来是三件事叠加：① 外置社区表里有"路径型无左边界"分支（`js/app\.`），
# 连 `nextjs/app.css` 都算命中 ⇒ 打出一个完全不相干的「朗拓健康医院管理系统」；
# ② 同一产品在社区表里有多个 tag（群晖-nas / 群晖-diskstation），没有归一；
# ③ jsmine 把**JS 文件正文**也喂给全部 4400+ 条 body 规则，且没有任何数量上限。
_ALIAS_FILE = "config/dicts/fingerprint_aliases.txt"
_alias_cache = {"key": None, "map": {}}


def _canon_key(tag):
    """归一化 key：大小写、空格、点、划、下划线都不算差异（`next.js` == `nextjs`）。"""
    return re.sub(r"[\s._\-]+", "", str(tag or "")).lower()


def _load_aliases():
    """同义别名表：一行一个 canonical，后面 TAB 分隔是它的别名。

    只收"同一个产品的不同叫法"，**不收不同产品** —— 收宽了会把真信号合掉。
    文件缺失/为空 ⇒ 空表（此时只剩 `_canon_key` 那一层归一）。
    """
    from .config import resolve
    try:
        p = resolve(_ALIAS_FILE)
        key = (str(p), p.stat().st_mtime_ns if p.exists() else 0)
    except Exception:
        return {}
    if _alias_cache["key"] == key:
        return _alias_cache["map"]
    table = {}
    try:
        if p.is_file():
            for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = [x.strip() for x in line.split("\t") if x.strip()]
                if len(parts) < 2:
                    continue
                for alias in parts:
                    table.setdefault(_canon_key(alias), parts[0])
    except OSError:
        pass
    _alias_cache.update(key=key, map=table)
    return table


def canonical_tags(tags):
    """同义归一：别名表 → 规范化 key 合并 → 每组选**确定性**的一个代表。

    代表规则（同组内 `min`）：内置 `SIGNATURES` 的拼写优先，其次更短，再按小写字母序。
    必须确定性 —— 早期版本按"迭代途中比较"选代表，同一组输入因 set 迭代序不同会给出
    不同拼写（`ThinkPHP` / `thinkphp` 随机二选一），那种不可复现的展示比不归一更糟。
    """
    if not tags:
        return []
    aliases = _load_aliases()
    groups = {}
    for t in {str(x).strip() for x in tags if str(x).strip()}:
        canon = aliases.get(_canon_key(t)) or t
        groups.setdefault(_canon_key(canon), set()).add(canon)
    return sorted(min(vs, key=lambda t: (t not in SIGNATURES, len(t), t.lower(), t))
                  for vs in groups.values())


_FIX_FILE = "config/dicts/fingerprint_fixes.txt"
_fix_cache = {"key": None, "map": {}}
_fixed_cache = {"fix_key": None, "rules_key": None, "rules": None}


def _load_fixes():
    """已证实的"烂分支"剔除表：`标签<TAB>分支正则<TAB>理由`（续221）。

    为什么不用"路径型片段一律降级"那种机器判据（本轮实测后废弃）：那判据在 2430 条
    外置规则里命中 24 条，其中 23 条是**真实产品路径**（致远oa 的 N/login.gif、
    蓝凌-oa 的 e/icon.css、moodle 的 moodle.org/、weblogic 的 HTTP/1.1……），
    一刀切全降级等于把这些真产品全部漏掉。社区表的质量问题只能一条一条修，修在明处。
    文件缺失/为空 ⇒ 空表（一条都不修）。
    """
    from .config import resolve
    try:
        p = resolve(_FIX_FILE)
        key = (str(p), p.stat().st_mtime_ns if p.exists() else 0)
    except Exception:
        return {}
    if _fix_cache["key"] == key:
        return _fix_cache["map"]
    table = {}
    try:
        if p.is_file():
            for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = [x.strip() for x in line.split("\t") if x.strip()]
                if len(parts) >= 2:
                    table.setdefault(parts[0], set()).add(parts[1])
    except OSError:
        pass
    _fix_cache.update(key=key, map=table)
    return table


def _fixed_rules(rules):
    """把 fixes 表登记的烂分支替换成永不匹配的 `(?!)`，**保留同规则里的强分支**。

    为什么要替换而不是整条禁用：朗拓那条规则是"产品路径 或 js 目录下的 app 片段"二选一，
    烂的只是后半支；整条禁掉会把前半支（真实的产品路径）一起丢掉。
    替换后原规则对象不动（外置表是加载时编译的 Pattern），生成一份新的给 identify 用。
    """
    fixes = _load_fixes()
    fk = tuple(sorted((k, tuple(sorted(v))) for k, v in fixes.items()))
    if not fk:
        return rules
    if _fixed_cache["fix_key"] == fk and _fixed_cache["rules_key"] == id(rules):
        return _fixed_cache["rules"]
    out = {}
    for tag, rs in (rules or {}).items():
        bad = fixes.get(tag)
        if not bad:
            out[tag] = rs
            continue
        fixed = []
        for r in rs:
            pat = r[1]
            src = str(getattr(pat, "pattern", pat))
            flags = int(getattr(pat, "flags", 0))
            for b in bad:
                if b in src:
                    src = src.replace(b, "(?!)")
            fixed.append((r[0], re.compile(src, flags)) + tuple(r[2:]))
        out[tag] = fixed
    _fixed_cache.update(fix_key=fk, rules_key=id(rules), rules=out)
    return out


def max_tags(settings=None):
    """单站标签上限（`fingerprint.max_tags`，默认 10）。

    存在的理由：4400+ 条规则对着一个页面跑，命中十几个是常态；全塞进 `sites.tech`
    只会把"这个站到底是什么"淹掉。超出部分**不静默丢** —— 由 `flush()` 说清丢了多少。
    """
    try:
        return max(1, int(((settings or {}).get("fingerprint") or {}).get("max_tags", 10)))
    except (TypeError, ValueError):
        return 10


def identify(resp, where=""):
    """从 http_request 的响应 dict 中提取组件标签，返回**同义归一后**排序去重的列表。

    规则有两个来源：内置 `SIGNATURES` 与外置 `EXTRA_FILE`（`load_extra`，带状态码门控）。
    带第三元组的规则只在响应状态落在那个集合里时才参与判定。

    `where`（续221）：这份响应是**主文档**（""，probe / dirscan 的路径响应）还是
    **JS 文件内容**（"js"，jsmine 的补标）。两种在 body 规则上区别很大：
    - JS 正文里出现"禅道 / 群晖 / next.js"这类字样，**不能证明这个站是那个产品**
      （可能是文档、示例代码、字符串表、甚至是别人的品牌名）；真正该看的是
      **主文档引用这个 JS 的路径**（那属于主文档的 body）。
    - ⇒ `where="js"` 时 body 规则一律不参与，只认 headers / cookies。
    实测：这一刀把"Sentry 登录页被打出 20+ 个标签"里的 JS 侧噪声全部消掉，
    且不损失主文档侧的识别（JS 路径特征在主文档 body 里照样命中）。
    """
    if not resp:
        return []
    hdrs = resp.get("headers") or {}
    parts = {
        "headers": "\n".join(f"{k}: {v}" for k, v in hdrs.items()),
        # 续197：正文**只看前 MAX_BODY_SCAN**。外置表从 51 条涨到 4400+ 条之后，单条规则的
        # 成本会乘上规则数 —— 一条写坏的正则（灾难性回溯）在 1 MB 正文上能把整个探测拖死，
        # 而产品特征（标题、登录页、脚本路径）几乎**永远在前几十 KB**。
        # 截断只影响"特征恰好在 128 KB 之后"那类极端情况，换到的是"不会被一条慢规则卡死"。
        "body": (resp.get("text") or "")[:MAX_BODY_SCAN],
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
    for _src_i, source in enumerate((SIGNATURES, _fixed_rules(load_extra()[0]))):
        _extra = _src_i == 1                     # 外置社区表：规则质量参差，要降级
        for tag, rules in source.items():
            for rule in rules:
                codes = rule[2] if len(rule) > 2 else None
                if codes is not None and status not in codes:
                    continue
                part, pattern = rule[0], rule[1]
                if where == "js" and part == "body":
                    continue                      # JS 正文不参与产品判定（见文档串）
                    continue                      # 路径型无左边界分支：body 上不生效
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
    return canonical_tags(tags)


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