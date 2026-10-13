"""停车页 / 空壳域名判定（2026-10-13 用户点单）。

为什么需要它：JS 挖掘从第三方 JS 里带回来的候选域名，"能解析"≠"是资产" ——
用户实测样本（拓展域名页）：
- `style.font.name` → 解析到 64.190.63.111，浏览器打开却是**域名转让**页；
- `com.password.name` → 打开是 Cloudflare 的 `DNS resolution error` 报错页；
- `com.text.name` → 解析得到 IP 但 80/443 什么都没有。
这类名字留着只会把「拓展域名」页灌成噪声，所以入库前用本模块判一遍。

三条判据（全部**只读**，一个写请求都不发）：
1. **CNAME 特征**：解析链落在已知停放商域名上（sedoparking / bodis / parkingcrew …）；
2. **内容特征**：首页正文命中"for sale / 域名出售 / DNS resolution error"等停放标记；
3. **空壳判定**：HTTPS 与 HTTP 各试一次首页 GET，**两边都无响应**＝解析得到 IP 却不提供
   Web 服务 —— 对"第三方候选"而言几乎不可能是值得跟的资产（判据刻意只用在
   JS 挖掘那条路上，FOFA / C 段反查回来的是第三方数据库的真实观测，不在此列）。

取向上与 `extdom.zone_is_absent` 同一条："只在**明确**证据时动手"——
拿到正文但没命中任何标记 → `alive`（保留）；网络错误与超时不等于"停车"，
但"两端口都无响应"对候选域名本身就是明确证据（正常资产首页不会两边都不通）。
"""
from .utils import html_title, http_request

# 已知停放商 / 域名交易市场的 CNAME 片段（子串匹配，与 cdn.py 的片段规则同思路）。
# 刻意保持小而准：拿不准的宁可漏判（漏了只是多留一行噪声，错判会丢真资产）。
PARKING_CNAME = (
    "sedoparking.com",      # Sedo 停放
    "parkingcrew.net",      # ParkingCrew / hofvending
    "bodis.com",            # Bodis 停放
    "afternic.com",         # Afternic（GoDaddy 旗下交易市场）
    "dan.com",              # DAN.com 交易市场落地页
    "above.com",            # Above.com 停放
    "parklogic.com",        # ParkLogic 停放
)

# 首页正文的停放标记（小写子串匹配）。样本来源：
# - "this domain is for sale" / "buy this domain"：Bodis / Afternic / Sedo 落地页的标准文案；
# - "dns resolution error"：Cloudflare 的 1016 类报错页（`com.password.name` 实测命中）；
# - "future home of"：DreamHost / Genesis 一类"占位但未建站"页；
# - 中文："域名出售" / "域名转让"。
PARKED_MARKERS = (
    "this domain is for sale",
    "domain for sale",
    "buy this domain",
    "is for sale by the owner",
    "this webpage is parked",
    "domain is parked",
    "this domain has been parked",
    "future home of",
    "dns resolution error",
    "域名出售",
    "域名转让",
    "本域名待售",
    "收购此域名",
)

# 正文最多看多少字符：停放标记几乎都在 <title> 与首屏文案里，看前 8000 字足够，
# 也避免把整份几十 KB 的正文扫一遍（那对本判定没有增益）。
_MARK_WINDOW = 8000


def cname_hit(chain):
    """解析链是否落在已知停放商上 → 命中的片段，否则空串。"""
    for host in chain or []:
        h = str(host or "").lower().strip(".")
        if not h:
            continue
        for frag in PARKING_CNAME:
            if frag in h:
                return frag
    return ""


def content_parked(text):
    """一段 HTML 正文是否命中停放标记（title 与正文各看一遍）。

    `<title>` 的正则与提取**复用 `utils.html_title()`**（AGENTS §7：同一判据不许两处 ——
    首版在本模块又抄了一份 `_TITLE_RE`，被门禁的"多处定义"检测当场拦下）。
    """
    t = str(text or "")
    window = t[:_MARK_WINDOW].lower()
    title = html_title(t)
    if title:
        window = title.lower() + "\n" + window
    return any(k in window for k in PARKED_MARKERS)


def probe(host, settings, timeout=6):
    """对一个**可解析**的主机做首页只读 GET，判定 `(verdict, why)`。

    verdict：`alive`（有响应且无停放标记，保留）/ `parked`（命中停放特征，丢弃）/
    `dead`（HTTPS 与 HTTP 都无响应——空壳，丢弃）。`why` 是给人看的依据文本。
    刻意先 https 再 http（顺序对结果无影响，只是 https 站点少走一次失败）。
    """
    host = str(host or "").strip().strip(".")
    if not host:
        return "alive", ""
    last_err = ""
    for scheme in ("https", "http"):
        resp = http_request(f"{scheme}://{host}/", timeout=timeout,
                            settings=settings, auth=False)
        if resp is None:
            # None = 网络层失败（超时/连接拒绝/限流取消）。记下原因，换下一个 scheme；
            # 两个 scheme 都 None 才判 dead（一次失败可能是临时抖动）。
            last_err = "无响应"
            continue
        text = resp.get("text") or ""
        if content_parked(text):
            return "parked", "首页命中停放/转让标记（title 或正文）"
        return "alive", ""
    return "dead", (f"HTTPS/HTTP 首页均{last_err}（解析得到地址但不提供 Web 服务）")
