"""邮箱等「数据探测」产物：从 JS / 页面正文里抽邮箱（续184，用户 2026-10-14 点单）。

和 jsmine 挖拓展域名用的是**同一批正文**，只是正则不同、落点不同 —— 挖出来的邮箱不进
子域名/漏洞，而是进 `emails` 表，在独立的「数据探测」页里看（用户原话：「独立一个标签页
比如记录邮箱这种…其实在 js 找拓展域名时候就顺带做了，只是正则不同显示的位置不同」）。

筛选**刻意从严**（宁可少报，也不让噪声把这一页淹掉；用户：「邮箱也要严格把控做好筛选」）：
- 只认标准邮箱形态，`@` 前后不许有空白/引号/尖括号残留；
- 丢掉**资源文件名**误报：`icon@2x.png` / `bootstrap@5.1.3.min.js` / `logo@3x.webp`
  （它们的"域名"是文件后缀，是前端构建产物里最常见的假邮箱）；
- 丢掉框架与文档里写死的**占位邮箱**（`example.com` / `test.com` / `email.com` /
  `yourdomain.com` / `sentry.io` …）—— 那是样例，不是目标业务的邮箱；
- 本地部分过长（>64）或整条过长（>254）判为噪声（RFC 上限，超了多半是哈希串）；
- 域名部分纯 IP、TLD 是数字、本地部分以 `.`/`-` 开头结尾的一律不收。

**只记录、不验证**：本模块一个请求都不发（不发验证邮件、不查 MX），
"这个邮箱存不存在"不是本框架该回答的问题，页面上也这么写。
"""
import re

# 只认"干净的"邮箱：两边都不能是空白/引号/尖括号/@
EMAIL_RE = re.compile(r"(?<![A-Za-z0-9._%+-])([A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]{1,63}\.)+"
                      r"[A-Za-z]{2,24})(?![A-Za-z0-9.-])")

# 资源文件名后缀：前面带 @ 的那些是构建产物（@2x/@3x/版本号），不是邮箱
_ASSET_SUFFIX = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".bmp", ".ico",
                 ".css", ".js", ".mjs", ".map", ".woff", ".woff2", ".ttf", ".eot",
                 ".mp4", ".mp3", ".pdf", ".zip")

# 占位/公共样例域名：库与文档里写死的，不是目标业务的邮箱
_PLACEHOLDER_DOMAINS = {
    "example.com", "example.org", "example.net", "test.com", "test.net", "domain.com",
    "email.com", "yourdomain.com", "your-domain.com", "company.com", "sample.com",
    "sentry.io", "wixpress.com", "localhost", "domain.tld", "mail.com", "email.tst",
    "user.com", "name.com", "foo.com", "bar.com", "abc.com",
}


def _clean(email):
    """归一：去首尾杂字符、域名小写（本地部分按原样保留 —— 少数系统区分大小写）。"""
    e = (email or "").strip().strip("\"'<>;,()[]{}")
    if "@" not in e:
        return ""
    local, _, dom = e.rpartition("@")
    return f"{local}@{dom.lower()}"


def is_noise(email):
    """这条像不像真邮箱（True ＝ 丢掉）。判据只有这一处，页面与落库都走它。"""
    e = _clean(email)
    if not e or len(e) > 254 or e.count("@") != 1:
        return True
    local, _, dom = e.partition("@")
    if not local or len(local) > 64:
        return True
    if local.startswith((".", "-")) or local.endswith((".", "-")) or ".." in local:
        return True
    if not dom or dom.startswith((".", "-")) or dom.endswith("."):
        return True
    low = dom.lower()
    if low in _PLACEHOLDER_DOMAINS:
        return True
    # 资源文件名：`x@2x.png` / `bootstrap@5.1.3.min.js`
    if low.endswith(_ASSET_SUFFIX):
        return True
    # 域名是纯 IP（v4 形态）或 TLD 不是字母
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", low):
        return True
    if not re.fullmatch(r"[A-Za-z]{2,24}", low.rsplit(".", 1)[-1]):
        return True
    return False


def extract(text, limit=0):
    """从一段正文里抽邮箱，返回 `[{"email":…, "domain":…}]`（去重、已过筛、按域名再按名排序）。

    `limit>0` 时最多返回那么多条（**等距抽样**而不是截断前 N 条 —— 邮箱常常成簇出现在
    同一个文件里，只留前 N 条等于只留一个文件的）。
    """
    out, seen = [], set()
    for m in EMAIL_RE.finditer(text or ""):
        e = _clean(m.group(1))
        if not e or is_noise(e) or e.lower() in seen:
            continue
        seen.add(e.lower())
        out.append({"email": e, "domain": e.partition("@")[2]})
    out.sort(key=lambda d: (d["domain"], d["email"]))
    if limit and len(out) > limit:
        step = max(1, len(out) // limit)
        out = out[::step][:limit]
    return out


def harvest(store, src, text, limit=0):
    """把一份正文里抽到的邮箱并进 `store`（dict：小写邮箱 → 行）。

    **只存邮箱、不存正文** —— JS 文件动辄 MB 级，把全文攒到扫描结束再抽是白烧内存。
    同一个邮箱在多个 JS 里出现时只留**第一次**的出处（后续页面上看的是"在哪见过它"）。
    """
    for item in extract(text, limit=limit):
        k = item["email"].lower()
        if k not in store:
            item["source"] = src or ""
            store[k] = item
    return store


def save(task_id, store, settings=None, logger=None, files=0):
    """把 `harvest` 攒下的邮箱落库，返回落库条数（0 条也要说清"扫了多少份正文"）。

    上限 `mails.max_per_task`（0＝不限），超出就截断并在日志里说出口。
    """
    cfg = (settings or {}).get("mails", {}) or {}
    limit = int(cfg.get("max_per_task", 0) or 0)
    dedup = sorted(store.values(), key=lambda r: (r.get("domain", ""), r.get("email", "")))
    if limit and len(dedup) > limit:
        if logger:
            logger.info(f"[mails] 邮箱命中 {len(dedup)} 个，按 mails.max_per_task={limit} 截断"
                        f"（调大该值或设 0 即全收）")
        dedup = dedup[:limit]
    if dedup:
        from . import db
        db.insert_emails(task_id, dedup)
    if logger:
        logger.info(f"[mails] 数据探测：{files} 份正文里抽出邮箱 {len(dedup)} 个"
                    + ("" if dedup else "（这一批正文里没有过筛的邮箱，属正常）"))
    return {"found": len(dedup), "files": files}


def scan(task_id, texts, settings=None, logger=None):
    """便利入口：手上已有 `[(source, text), ...]` 时一步到位（`harvest` + `save`）。"""
    store, files = {}, 0
    for src, text in (texts or []):
        files += 1
        harvest(store, src, text)
    return save(task_id, store, settings=settings, logger=logger, files=files)
