"""证书透明度（CT）日志在线查询 —— crt.sh 的**证书维度**记录。

与项目里另外两处 crt.sh / 证书能力的区别（避免后人混淆，改动前先读）
------------------------------------------------------------------
1. `scanner/passive.py` 的 crt.sh：查 `q=%25.<域>&output=json`，**只取 `common_name` /
   `name_value` 里的主机名**做子域名收集。它关心"有哪些域名"，不关心是哪张证书。
   → 本模块关心的是**证书本身**：签发者、有效期、序列号、这张证书覆盖哪些域名、
     在 CT 日志里出现过多少个条目。两者用的是同一个接口的不同切片。
2. `scanner/certs.py` 的「SSL 证书」：对目标做一次**真实 TLS 握手**取回线上正在用的
   证书并解析 DER。它是"此刻服务端实际下发的证书"，**不联网第三方**。
   → 本模块是"公开 CT 日志里历史上出现过、与该域名相关的证书"，**不接触目标**。
   同一个域名在 CT 里往往有几十张证书（历史签发、SAN 变体、测试证书），
   所以它的产物是**线索与资产面补充**，不能当作"目标现在用的证书"。
3. `scanner/fofa.py` 的 `cert="domain"` 反查：拿证书去找**共用同一张证书的其它资产**，
   目的是拓展资产面（FOFA 自己的索引）。→ 不产出证书字段，也不免费（要 key + 配额）。

字段口径刻意与 `certs.py::parse_der()` 对齐（`issuer` / `cn` / `serial` / `not_before` /
`not_after` / `days_left` / `expired` / `san`），这样产物可以直接写进 `certs` 表
（`source='ct'`）与「SSL 证书」页签，`db.insert_certs()` 无需改动。

约束
----
- **免 key，但属外部接口 → 默认关**（`ctlog.enabled=false`）。要联网才开。
- 一律走 `utils.http_request`，且 **`auth=False`（默认）** —— crt.sh 是第三方出口，
  绝不能把任务的登录态 Cookie/Token 带出去（见 AGENTS.md §7 的凭据红线）。
- crt.sh 是出了名的不稳定：会返回 HTML 错误页、会超时、会限流（429）。
  所有异常都在这里收口成"一条日志 + 空结果"，**绝不让阶段挂掉**。
- `name_value` 里的通配符（`*.x.example.com`）必须处理：剥掉 `*.` 并单独标记，
  **绝不把 `*` 写进资产库**（`utils.is_domain()` 会挡住带 `*` 的串，所以不处理就
  等于白丢一批域名）。
"""
import json
import time
import urllib.parse

from .utils import http_request, is_domain

API = "https://crt.sh/"

# 单张证书最多保留多少个域名（CT 里某些大证书带几百个 SAN，全塞进页面/报告毫无意义）
DEFAULT_MAX_DOMAINS_PER_CERT = 50

# crt.sh 的时间戳形如 `2022-01-13T23:59:59`（也可能带小数秒与 Z）
_TS_FORMATS = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d")


# ---------- 配置 ----------

def _cfg(settings):
    return (settings or {}).get("ctlog", {}) or {}


def enabled(settings):
    """CT 日志查询是否开启。**默认关** —— 免 key 但仍是外部接口。"""
    return _cfg(settings).get("enabled") is True


def max_domains(settings):
    """单任务最多查多少个域名（每个域名一次请求，省得把 crt.sh 打挂）。"""
    try:
        return max(1, int(_cfg(settings).get("max_domains") or 10))
    except (TypeError, ValueError):
        return 10


def max_records(settings):
    """单域名最多收多少张证书记录。"""
    try:
        return max(1, int(_cfg(settings).get("max_records") or 50))
    except (TypeError, ValueError):
        return 50


def max_domains_per_cert(settings):
    try:
        return max(1, int(_cfg(settings).get("max_domains_per_cert")
                          or DEFAULT_MAX_DOMAINS_PER_CERT))
    except (TypeError, ValueError):
        return DEFAULT_MAX_DOMAINS_PER_CERT


def write_certs(settings):
    """是否把证书维度记录写进 `certs` 表（`source='ct'`）。默认写。"""
    return _cfg(settings).get("write_certs") is not False


def timeout_of(settings):
    try:
        return max(1, int(_cfg(settings).get("timeout") or 25))
    except (TypeError, ValueError):
        return 25


def build_url(domain):
    """构造查询 URL：`https://crt.sh/?q=<domain>&output=json`。

    域名来自扫描结果（外部输入），必须编码 —— 带空格/引号的串直接拼进 query 会造出
    非预期的查询，甚至把参数结构破坏掉。
    """
    return f"{API}?q={urllib.parse.quote(str(domain or '').strip(), safe='')}&output=json"


# ---------- 解析 ----------

def _norm_time(text):
    """crt.sh 时间戳 → `('YYYY-MM-DD HH:MM:SS', epoch)`；解析不了返回 `('', None)`。"""
    raw = str(text or "").strip().replace("T", " ").rstrip("Z").strip()
    raw = raw.split(".")[0] if "." in raw else raw
    if not raw:
        return "", None
    for fmt in _TS_FORMATS:
        try:
            return time.strftime("%Y-%m-%d %H:%M:%S", time.strptime(raw, fmt)), \
                   time.mktime(time.strptime(raw, fmt))
        except (ValueError, OverflowError):
            continue
    return "", None


def _split_names(raw):
    """`name_value` → 域名列表：按换行切、剥通配符、去重保序。

    通配符（`*.x.example.com`）**剥掉 `*.` 后保留**（CT 日志里它就是这么存的），
    并在记录上打 `wildcard=1` —— 剥掉 `*.` 是为了让它能进资产库，
    打标记是为了让人知道"这张证书覆盖了整段子域"。
    """
    out, seen, wildcard = [], set(), 0
    for line in str(raw or "").splitlines():
        name = line.strip().lower().strip(".")
        if name.startswith("*."):
            wildcard = 1
            name = name[2:].strip(".")
        elif "*" in name:
            continue                              # 形状奇怪的通配（如 a.*.b）→ 丢掉
        if not name or name in seen:
            continue
        seen.add(name)
        out.append(name)
    return out, wildcard


def parse_records(text, settings=None):
    """crt.sh 的 JSON 响应 → `(records, error)`；**任何坏输入都不抛异常**。

    records 按 `(签发者, 序列号)` 聚合（同一张证书在 CT 里会有多条日志条目，
    例如被多个 CA 重复记录），字段口径与 `certs.py::parse_der()` 对齐。
    """
    if not text or not str(text).strip():
        return [], "crt.sh 返回空响应"
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        head = str(text)[:60].replace("\n", " ").strip()
        return [], f"crt.sh 响应不是合法 JSON（可能是限流页：{head}…）"
    if isinstance(data, dict):
        data = [data]                             # 只有一条时 crt.sh 也会返回对象
    if not isinstance(data, list):
        return [], "crt.sh 响应结构异常（既不是数组也不是对象）"

    cap = max_domains_per_cert(settings)
    now = time.time()
    bucket = {}
    for row in data:
        if not isinstance(row, dict):
            continue
        issuer = str(row.get("issuer_name") or "").strip()
        serial = str(row.get("serial_number") or "").strip().upper()
        cn = str(row.get("common_name") or "").strip().lower().strip(".")
        if cn.startswith("*."):
            cn = cn[2:]
        names, wildcard = _split_names(row.get("name_value") or "")
        if cn and cn not in names:
            names.insert(0, cn)
        nb, _ = _norm_time(row.get("not_before"))
        na, na_t = _norm_time(row.get("not_after"))
        # 聚合键：序列号唯一标识一张证书；没有序列号时退回"签发者 + 有效期"
        key = (issuer, serial) if serial else (issuer, nb, na)
        rec = bucket.get(key)
        if rec is None:
            rec = {"issuer": issuer, "cn": cn, "serial": serial,
                   "subject": "", "sig_algo": "", "sha256": "", "self_signed": 0,
                   "not_before": nb, "not_after": na,
                   "days_left": (int((na_t - now) // 86400) if na_t else None),
                   "expired": (1 if (na_t and na_t < now) else 0),
                   "san": [], "wildcard": 0, "entry_count": 0, "log_ids": [],
                   "domain_count": 0}
            bucket[key] = rec
        rec["entry_count"] += 1
        log_id = str(row.get("id") or "").strip()
        if log_id and len(rec["log_ids"]) < 20:
            rec["log_ids"].append(log_id)
        if not rec["cn"] and cn:
            rec["cn"] = cn
        rec["wildcard"] = rec["wildcard"] or wildcard
        for n in names:
            if n not in rec["san"]:
                rec["san"].append(n)
        if not rec["not_before"] and nb:
            rec["not_before"] = nb
        if not rec["not_after"] and na:
            rec["not_after"] = na
            rec["days_left"] = (int((na_t - now) // 86400) if na_t else None)
            rec["expired"] = 1 if (na_t and na_t < now) else 0

    for rec in bucket.values():
        rec["domain_count"] = len(rec["san"])
        rec["san"] = rec["san"][:cap]
        if not rec["serial"]:
            rec["serial"] = "-".join(rec["log_ids"][:2])     # 没有序列号时给个可回溯的占位
    # 已过期的排前面（与 certs 页签"可疑优先"的口径一致），其次按条目数降序
    records = sorted(bucket.values(), key=lambda r: (-r["expired"], -r["entry_count"]))
    return records, ""


def domains_of(records, limit=0):
    """把若干证书记录里的域名摊平（去重保序）。裸 IP / 带通配符的一律不进。"""
    out, seen = [], set()
    for rec in records or []:
        for name in (rec.get("san") or []):
            name = str(name or "").strip().lower().strip(".")
            if not name or name in seen or not is_domain(name):
                continue
            seen.add(name)
            out.append(name)
            if limit and len(out) >= limit:
                return out
    return out


def search(domain, settings, logger=None):
    """查一个域名的 CT 记录，返回 `(records, error)`。

    失败一律返回 `([], "原因")`：crt.sh 是公共免费服务，超时/限流/返回 HTML 都是常态，
    这里**不抛异常**，调用方（osint 阶段）只要记一行日志继续跑。
    """
    host = str(domain or "").strip().lower().strip(".")
    if not host:
        return [], "CT 日志查询目标为空"
    if not enabled(settings):
        return [], "ctlog.enabled=false（CT 日志查询默认关）"
    resp = http_request(build_url(host), timeout=timeout_of(settings), settings=settings)
    if not resp:
        return [], "请求 crt.sh 失败（网络不可达或超时）"
    status = int(resp.get("status") or 0)
    if status in (429, 503):
        return [], f"crt.sh 返回 HTTP {status}（限流，稍后再试）"
    if status != 200:
        return [], f"crt.sh 返回 HTTP {status}"
    records, err = parse_records(resp.get("text") or "", settings)
    if err and logger:
        logger.info(f"[ctlog] {host}：{err}")
    return records[:max_records(settings)], err
