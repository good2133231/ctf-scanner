"""子域接管（Subdomain Takeover）指纹表与判定（P0-2）。

原理：子域名通过 CNAME 指向某个第三方托管服务（S3 / Heroku / GitHub Pages …），
但该资源在服务侧**已被删除/未认领**，服务商仍保留着这条 DNS 的"空壳"应答。
此时任何人只要在服务商处注册同名资源，就能让这个子域名解析并展示到自己的内容上，
即"子域接管"。判定不需要访问目标业务逻辑，纯被动、非破坏。

两条判据（缺一不可，降低误报）：
1. CNAME 链中某个节点后缀命中 `SERVICES` 的 `cname_suffix`；
2. `takeover.http_check` 开启时，对该子域发一次只读 GET（https 失败退 http），
   响应体/响应头里命中该服务的 `needles` 特征串（服务商提供的"未认领"占位页文案）。

指纹来源：公开项目 "can-i-take-over-xyz" 的已知服务清单（凭记忆整理，**宁可少而准**）。
第三方服务随时可能改版文案，命中与否只作线索，最终仍需人工确认。

硬性约束：所有 HTTP 一律走 `scanner.utils.http_request`（统一 UA/超时/verify_tls），
只做 GET，不发任何写入请求。
"""
from . import dnsq
from .utils import http_request

# 每条：slug（稳定 poc_id 后缀）、service（展示名）、cname_suffix（CNAME 后缀匹配）、
#       needles（响应体特征，大小写不敏感，命中任一即可）、
#       header_needles（响应头特征，可空）、status（期望状态码，仅供参考，可空）
SERVICES = [
    {
        "slug": "aws-s3", "service": "AWS S3", "cname_suffix": "s3.amazonaws.com",
        "needles": ["NoSuchBucket", "The specified bucket does not exist"],
        "header_needles": [], "status": [404],
    },
    {
        "slug": "aws-s3-website", "service": "AWS S3 Website",
        "cname_suffix": "s3-website", "needles": ["NoSuchBucket"],
        "header_needles": [], "status": [404],
    },
    {
        "slug": "github-pages", "service": "GitHub Pages", "cname_suffix": "github.io",
        "needles": ["There isn't a GitHub Pages site here.",
                    "For root URLs (like http://example.com/) you must provide an index.html file"],
        "header_needles": [], "status": [404],
    },
    {
        "slug": "heroku", "service": "Heroku", "cname_suffix": "herokuapp.com",
        "needles": ["No such app", "no-such-app.html"], "header_needles": [], "status": [],
    },
    {
        "slug": "heroku-ssl", "service": "Heroku SSL", "cname_suffix": "herokussl.com",
        "needles": ["No such app"], "header_needles": [], "status": [],
    },
    {
        "slug": "heroku-dns", "service": "Heroku DNS", "cname_suffix": "herokudns.com",
        "needles": ["No such app"], "header_needles": [], "status": [],
    },
    {
        "slug": "azure-websites", "service": "Azure Web App",
        "cname_suffix": "azurewebsites.net",
        "needles": ["Error 404 - Web app not found.",
                    "Web app not found",
                    "The resource you are looking for has been removed"],
        "header_needles": [], "status": [404],
    },
    {
        "slug": "azure-trafficmanager", "service": "Azure Traffic Manager",
        "cname_suffix": "trafficmanager.net",
        "needles": ["The resource you are looking for has been removed",
                    "Web app not found"],
        "header_needles": [], "status": [404],
    },
    {
        "slug": "azure-cloudapp", "service": "Azure Cloud App",
        "cname_suffix": "cloudapp.net",
        "needles": ["The resource you are looking for has been removed",
                    "Web app not found"],
        "header_needles": [], "status": [404],
    },
    {
        "slug": "azure-cloudapp-2", "service": "Azure Cloud App (cn)",
        "cname_suffix": "cloudapp.azure.com",
        "needles": ["The resource you are looking for has been removed",
                    "Web app not found"],
        "header_needles": [], "status": [404],
    },
    {
        "slug": "shopify", "service": "Shopify", "cname_suffix": "myshopify.com",
        "needles": ["Sorry, this shop is currently unavailable.",
                    "Only one step left!"],
        "header_needles": [], "status": [],
    },
    {
        "slug": "fastly", "service": "Fastly", "cname_suffix": "fastly.net",
        "needles": ["Fastly error: unknown domain"], "header_needles": [], "status": [],
    },
    {
        "slug": "pantheon", "service": "Pantheon", "cname_suffix": "pantheonsite.io",
        "needles": ["Unrecognized domain", "The gods are wise"],
        "header_needles": [], "status": [],
    },
    {
        "slug": "tumblr", "service": "Tumblr", "cname_suffix": "domains.tumblr.com",
        "needles": ["Whatever you were looking for doesn't currently exist at this address."],
        "header_needles": [], "status": [],
    },
    {
        "slug": "zendesk", "service": "Zendesk", "cname_suffix": "zendesk.com",
        "needles": ["Help Center Closed"], "header_needles": [], "status": [],
    },
    {
        "slug": "surge", "service": "Surge.sh", "cname_suffix": "surge.sh",
        "needles": ["project not found"], "header_needles": [], "status": [],
    },
    {
        "slug": "netlify", "service": "Netlify", "cname_suffix": "netlify.app",
        "needles": ["Not Found - Request ID"], "header_needles": [], "status": [404],
    },
    {
        "slug": "netlify-com", "service": "Netlify", "cname_suffix": "netlify.com",
        "needles": ["Not Found - Request ID"], "header_needles": [], "status": [404],
    },
    {
        "slug": "bitbucket", "service": "Bitbucket", "cname_suffix": "bitbucket.io",
        "needles": ["Repository not found"], "header_needles": [], "status": [],
    },
    {
        "slug": "wordpress", "service": "WordPress.com", "cname_suffix": "wordpress.com",
        "needles": ["Do you want to register"], "header_needles": [], "status": [],
    },
    {
        "slug": "ghost", "service": "Ghost", "cname_suffix": "ghost.io",
        "needles": ["The thing you were looking for is no longer here"],
        "header_needles": [], "status": [],
    },
    {
        "slug": "readme", "service": "Readme.io", "cname_suffix": "readme.io",
        "needles": ["Project doesnt exist... yet!"], "header_needles": [], "status": [],
    },
    {
        "slug": "statuspage", "service": "Statuspage", "cname_suffix": "statuspage.io",
        "needles": ["You are being redirected"], "header_needles": [], "status": [],
    },
    {
        "slug": "unbounce", "service": "Unbounce", "cname_suffix": "unbouncepages.com",
        "needles": ["The requested URL was not found on this server"],
        "header_needles": [], "status": [404],
    },
    {
        "slug": "uservoice", "service": "UserVoice", "cname_suffix": "uservoice.com",
        "needles": ["This UserVoice subdomain is currently available!"],
        "header_needles": [], "status": [],
    },
    {
        "slug": "cargo", "service": "Cargo", "cname_suffix": "cargocollective.com",
        "needles": ["If you're moving your domain away from Cargo you must make",
                    "this configuration through your registrar's DNS control panel"],
        "header_needles": [], "status": [],
    },
    {
        "slug": "intercom", "service": "Intercom", "cname_suffix": "intercom.help",
        "needles": ["Uh oh. That page doesn't exist."], "header_needles": [], "status": [],
    },
    {
        "slug": "intercom-custom", "service": "Intercom (custom)",
        "cname_suffix": "custom.intercom.help",
        "needles": ["Uh oh. That page doesn't exist."], "header_needles": [], "status": [],
    },
    {
        "slug": "ngrok", "service": "Ngrok", "cname_suffix": "ngrok.io",
        "needles": ["ngrok.io not found", "Tunnel not found"],
        "header_needles": [], "status": [],
    },
    {
        "slug": "ngrok-free", "service": "Ngrok", "cname_suffix": "ngrok-free.app",
        "needles": ["Tunnel not found", "ngrok-free.app not found"],
        "header_needles": [], "status": [],
    },
    {
        "slug": "launchrock", "service": "Launchrock", "cname_suffix": "launchrock.com",
        "needles": ["It looks like you may have taken a wrong turn somewhere."],
        "header_needles": [], "status": [],
    },
    {
        "slug": "strikingly", "service": "Strikingly", "cname_suffix": "strikingly.com",
        "needles": ["you can claim it now at",
                    "This page is reserved for artistic purposes"],
        "header_needles": [], "status": [],
    },
    {
        "slug": "strikingly-dns", "service": "Strikingly", "cname_suffix": "strikinglydns.com",
        "needles": ["you can claim it now at"], "header_needles": [], "status": [],
    },
    {
        "slug": "webflow", "service": "Webflow", "cname_suffix": "webflow.io",
        "needles": ["The page you are looking for doesn't exist or has been moved"],
        "header_needles": [], "status": [],
    },
    {
        "slug": "squarespace", "service": "Squarespace", "cname_suffix": "squarespace.com",
        "needles": ["No Such Account"], "header_needles": [], "status": [],
    },
    {
        "slug": "desk", "service": "Desk.com", "cname_suffix": "desk.com",
        "needles": ["Sorry, We Couldn't Find That Page"], "header_needles": [], "status": [],
    },
    {
        "slug": "firebase", "service": "Firebase", "cname_suffix": "firebaseapp.com",
        "needles": ["Site Not Found"], "header_needles": [], "status": [404],
    },
    {
        "slug": "firebase-web", "service": "Firebase", "cname_suffix": "web.app",
        "needles": ["Site Not Found"], "header_needles": [], "status": [404],
    },
    {
        "slug": "tilda", "service": "Tilda", "cname_suffix": "tilda.ws",
        "needles": ["Please renew your subscription"], "header_needles": [], "status": [],
    },
    {
        "slug": "helpjuice", "service": "Helpjuice", "cname_suffix": "helpjuice.com",
        "needles": ["We could not find what you're looking for"],
        "header_needles": [], "status": [],
    },
    {
        "slug": "helpscout", "service": "Help Scout", "cname_suffix": "helpscoutdocs.com",
        "needles": ["No settings were found for this company"],
        "header_needles": [], "status": [],
    },
]

_SNIPPET_LEN = 400


def _snippet(text, needle, width=_SNIPPET_LEN):
    """截取命中特征附近的上下文作为 evidence（最长 width 字符）。"""
    text = text or ""
    idx = text.lower().find(str(needle).lower())
    if idx < 0:
        return " ".join(text.split())[:width]
    start = max(0, idx - width // 3)
    return " ".join(text[start:start + width].split())[:width]


def match_service(cnames):
    """在 CNAME 链里找命中的服务，返回 (service_dict, 命中的 cname) 或 (None, None)。

    后缀匹配：`foo.s3.amazonaws.com` 命中 `s3.amazonaws.com`；
    `s3-website-us-east-1.amazonaws.com` 这类用不含点的子串后缀同样命中。
    """
    for cname in cnames or []:
        host = str(cname or "").strip().lower().rstrip(".")
        if not host:
            continue
        for svc in SERVICES:
            suffix = svc["cname_suffix"].lower()
            if host == suffix or host.endswith("." + suffix) or \
                    ("." not in suffix and suffix in host):
                return svc, cname
    return None, None


def _http_probe(subdomain, svc, settings, timeout):
    """只读 GET 判定：https 优先、失败回退 http。命中返回证据 dict，否则 None。

    任何 HTTP 都经 `utils.http_request`（不直接用 requests/urllib），只做 GET。
    """
    for scheme in ("https", "http"):
        url = f"{scheme}://{subdomain}"
        resp = http_request(url, timeout=timeout, settings=settings)
        if not resp:
            continue
        body = resp.get("text") or ""
        headers = resp.get("headers") or {}
        hit = None
        for needle in svc.get("needles") or []:
            if needle.lower() in body.lower():
                hit = ("body", needle, body)
                break
        if hit is None:
            header_text = "\n".join(f"{k}: {v}" for k, v in headers.items())
            for needle in svc.get("header_needles") or []:
                if needle.lower() in header_text.lower():
                    hit = ("header", needle, header_text)
                    break
        if hit:
            where, needle, source = hit
            return {"scheme": scheme, "url": resp.get("url") or url,
                    "status": resp.get("status"), "needle": needle, "where": where,
                    "evidence": _snippet(source, needle)}
    return None


def detect(subdomain, settings=None, logger=None):
    """检测单个子域是否疑似可被接管。命中返回 vuln dict，否则 None。

    返回字段与项目现有漏洞一致（target/poc_id/name/severity/owasp/detail/evidence），
    可直接交给 `db.insert_vuln`。
    """
    settings = settings or {}
    cfg = settings.get("takeover", {}) or {}
    chain, _ips = dnsq.cname_chain(subdomain, settings=settings)
    if not chain:
        if logger:
            logger.debug(f"[takeover] {subdomain} 无 CNAME，跳过")
        return None
    svc, hit_cname = match_service(chain)
    if not svc:
        return None

    chain_text = " -> ".join(chain)
    if cfg.get("http_check", True) is not False:
        timeout = int((settings.get("limits", {}) or {}).get("http_timeout", 10))
        probe = _http_probe(subdomain, svc, settings, timeout)
        if not probe:
            if logger:
                logger.info(f"[takeover] {subdomain} CNAME 指向 {svc['service']}，"
                            f"但未命中未认领特征，判定为非接管")
            return None
        evidence = probe["evidence"]
        http_note = (f"HTTP 判定：{probe['url']} 返回 {probe['status']}，"
                     f"在{ '响应体' if probe['where'] == 'body' else '响应头' }"
                     f"命中特征 {probe['needle']!r}")
    else:
        evidence = f"CNAME: {subdomain} -> {chain_text}"
        http_note = "HTTP 判定已在配置中关闭（takeover.http_check=false）"

    detail = (
        f"子域 {subdomain} 的 CNAME 链指向第三方托管服务 {svc['service']}"
        f"（{hit_cname}），该服务在资源未认领时仍会保留 DNS 应答，"
        f"他人可在服务商处注册同名资源从而接管此子域（OWASP A05 安全配置错误）。"
        f"CNAME 链：{subdomain} -> {chain_text}。{http_note}。"
        f"请人工确认该 CNAME 是否确实指向已释放/未认领的资源。"
    )
    return {
        "poc_id": f"takeover-{svc['slug']}",
        "name": f"{svc['service']} 子域接管",
        "severity": "high",
        "owasp": "A05",
        "target": subdomain,
        "detail": detail,
        "evidence": (evidence or "")[:_SNIPPET_LEN],
    }