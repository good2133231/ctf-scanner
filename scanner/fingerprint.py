"""内置指纹识别：httpx 不可用时，从响应头/正文提取组件标签填充 sites.tech。

定位（客观说明）：
- 只是"信号级"标签（如 nginx / php / tomcat），不解析精确版本；版本类判断仍由
  owasp 检查（a06-legacy-banner）与 POC 库承担；
- 规则表刻意保持精简、可扩展：新增一行即可支持新组件，无需改动调用方。

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

# 标签 -> [(part, 正则)]；part: headers | body；任一规则命中即打该标签
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
    "cloudflare": [("headers", r"(?im)^server:\s*cloudflare|(?i)cf-ray:|cf-cache-status")],
    "cloudfront": [("headers", r"(?i)x-amz-cf-id|(?i)^via:.*cloudfront")],
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
    "php": [("headers", r"(?im)^x-powered-by:\s*php|(?i)php/[\d.]+"),
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

# favicon 体积上限：有些站点会用 404 页面或超大文件冒充 favicon，直接跳过
MAX_FAVICON = 512 * 1024


def identify(resp):
    """从 http_request 的响应 dict 中提取组件标签，返回排序去重后的列表。"""
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
    tags = []
    for tag, rules in SIGNATURES.items():
        for part, pattern in rules:
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
    resp = http_request(url, timeout=timeout, settings=settings, want_bytes=True)
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