"""TLS 证书取证：握手取证书 + **纯标准库**解析出颁发者 / 有效期 / SAN。

为什么自己写 DER 解析（而不是直接用 `ssl.getpeercert()`）：`getpeercert()` 只在
**校验通过**时才返回结构化字典 —— 而 CTF / 授权测试里最常见的恰恰是自签名、过期、
域名不匹配的证书，那些场景下它只回空 dict，等于"最该看的信息看不到"。
所以这里用 `verify_mode=CERT_NONE` 握手拿 **DER 原始字节**（`binary_form=True`，
无论证书是否合法都拿得到），再自己按 X.509 结构读出需要的字段。

不引入任何第三方依赖（`cryptography` 之类一律不用）：只用 `socket` / `ssl` / `hashlib`。
只解析我们需要的部分 —— 版本、序列号、签名算法、颁发者、有效期、主体、SAN 扩展；
结构之外的字段（公钥内容、扩展里的其它项）一律跳过，不做完整 X.509 实现。

安全边界：只做**一次 TLS 握手**（只读、非破坏），不发 HTTP 请求、不写目标、不做爆破。
"""
import calendar
import hashlib
import re
import socket
import ssl
import time

# SAN 条数上限：证书里塞几百个域名的（共享证书/通配泛证书）没有展示价值，反而撑爆页面
MAX_SAN = 20

# RDN 里我们要保留的属性（其余如 emailAddress/serialNumber 略过，避免页面噪声）
_RDN_NAMES = {
    "2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L",
    "2.5.4.8": "ST", "2.5.4.10": "O", "2.5.4.11": "OU",
}

# 常见签名算法 OID → 可读名（不全，认不出的就原样显示 OID，不做臆测）
_SIG_ALGOS = {
    "1.2.840.113549.1.1.5": "sha1WithRSA",
    "1.2.840.113549.1.1.11": "sha256WithRSA",
    "1.2.840.113549.1.1.12": "sha384WithRSA",
    "1.2.840.113549.1.1.13": "sha512WithRSA",
    "1.2.840.113549.1.1.10": "RSASSA-PSS",
    "1.2.840.10045.4.1": "ecdsa-with-SHA1",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
}

_OID_SAN = "2.5.29.17"        # subjectAltName（dNSName / iPAddress）
_OID_BC = "2.5.29.19"         # basicConstraints（判断是不是 CA 自签）


# ---------- DER 基础读取 ----------

def _tlv(buf, i):
    """读一个 TLV，返回 (tag, value_bytes, 下一个字节位置)。

    越界一律抛 ValueError（**不是** IndexError）：调用方统一只捕 ValueError，
    若这里漏出 IndexError，一个"没有 SAN 扩展"的证书就会让整条解析崩掉
    （实测 150 张真实 CA 证书里 147 张栽在这上面）。
    """
    if i + 2 > len(buf):
        raise ValueError("DER 数据不足，读不到 tag/length")
    tag = buf[i]
    i += 1
    n = buf[i]
    i += 1
    if n & 0x80:                       # 长格式长度：低 7 位是长度字节数
        k = n & 0x7F
        if k == 0 or i + k > len(buf):
            raise ValueError("DER 长度字段非法")
        n = int.from_bytes(buf[i:i + k], "big")
        i += k
    if i + n > len(buf):
        raise ValueError("DER 长度越界")
    return tag, buf[i:i + n], i + n


def _children(value):
    """把一个构造类型的 value 拆成子 TLV 列表。"""
    out, i = [], 0
    while i < len(value):
        tag, val, i = _tlv(value, i)
        out.append((tag, val))
    return out


def _oid(value):
    """DER OID → 点分字符串。"""
    if not value:
        return ""
    first = value[0]
    arcs = [first // 40, first % 40]
    num = 0
    for b in value[1:]:
        num = (num << 7) | (b & 0x7F)
        if not b & 0x80:
            arcs.append(num)
            num = 0
    return ".".join(str(a) for a in arcs)


def _text(value):
    """证书里的字符串值：优先 UTF-8，退回 latin-1（DER 里也有 IA5/Printable 混用）。"""
    try:
        return value.decode("utf-8").strip()
    except UnicodeDecodeError:
        return value.decode("latin-1", "replace").strip()


def _name_parts(value):
    """Name（SEQUENCE OF RDN）→ `["CN=xx", "O=yy", ...]`（DER 存储顺序）。"""
    parts = []
    for tag, rdn in _children(value):
        if tag != 0x31:                # SET OF AttributeTypeAndValue
            continue
        for atag, atv in _children(rdn):
            if atag != 0x30:
                continue
            kv = _children(atv)
            if len(kv) < 2:
                continue
            key = _RDN_NAMES.get(_oid(kv[0][1]))
            if key:
                parts.append(f"{key}={_text(kv[1][1])}")
    return parts


def _name_str(parts):
    """RDN 列表 → `CN=xx, O=yy, C=zz` 形式。

    倒序拼接：DER 按 X.500 规定"最高位在前"（C,O,...,CN），而 RFC 4514 的字符串
    写法是反过来的 —— 人读证书习惯 `CN` 在最前面，所以这里按 RFC 4514 顺序输出。
    （个别 CA 的编码顺序不规范，此时输出会跟着它的实际顺序走，不做二次排序臆测。）
    """
    return ", ".join(reversed(parts))


def _cn_of(parts):
    """主体里的 CN（页面上最常看的字段）；没有 CN 就返回空串。"""
    for p in parts:
        if p.startswith("CN="):
            return p[3:]
    return ""


def _time(value, tag):
    """UTCTime(0x17) / GeneralizedTime(0x18) → (可读串, epoch 秒)。

    用 `calendar.timegm` 而非 `time.mktime`：证书里的时间以 `Z`（UTC）结尾，
    mktime 会按**本机时区**解释，东八区下最多差 8 小时，正好把"还剩几天"算翻一天。
    """
    s = value.decode("ascii", "replace").strip()
    m = re.match(r"^(\d{2}|\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z?$", s)
    if not m:
        return s, None
    y = int(m.group(1))
    if tag == 0x17 and y < 100:        # UTCTime 两位年：00-49 归 20xx，50-99 归 19xx
        y += 2000 if y < 50 else 1900
    try:
        t = calendar.timegm((y, int(m.group(2)), int(m.group(3)), int(m.group(4) or 0),
                             int(m.group(5) or 0), int(m.group(6) or 0), 0, 0, 0))
    except (ValueError, OverflowError):
        return s, None
    return f"{y:04d}-{m.group(2)}-{m.group(3)} {m.group(4)}:{m.group(5)}:{m.group(6) or '00'}", t


def _san(value):
    """subjectAltName 扩展值（OCTET STRING 里包着 SEQUENCE OF GeneralName）。

    没有任何一个 SAN 条目是常态（根证书、只靠 CN 的老证书），此处**必须**容错返回 []：
    调用方在证书没这个扩展时会传空字节进来。
    """
    try:
        tag, inner, _ = _tlv(value, 0)
        items = _children(inner) if tag == 0x30 else []
    except (ValueError, IndexError):
        return []
    out = []
    for tag, val in items:
        if tag == 0x82:                # dNSName
            out.append(_text(val).lower())
        elif tag == 0x87 and len(val) in (4, 16):     # iPAddress
            out.append(".".join(str(b) for b in val) if len(val) == 4 else val.hex())
    return out


def _extensions(value):
    """[3] extensions → {OID: 扩展值原始字节}（只留我们关心的两个）。"""
    out = {}
    try:
        seqs = _children(value)
        if seqs and seqs[0][0] == 0x30:
            for _t, ext in _children(seqs[0][1]):
                kv = _children(ext)
                if len(kv) < 2:
                    continue
                oid = _oid(kv[0][1])
                if oid in (_OID_SAN, _OID_BC):
                    # 末项是 extnValue(OCTET STRING)；critical BOOLEAN 在中间，直接取最后一个
                    out[oid] = kv[-1][1]
    except (ValueError, IndexError):
        pass
    return out


# ---------- 对外接口 ----------

def parse_der(der):
    """DER 证书字节 → 结构化字典（解析失败抛 ValueError，由调用方兜住）。"""
    tag, top, _ = _tlv(bytes(der), 0)
    if tag != 0x30:
        raise ValueError("不是 DER SEQUENCE（不是证书？）")
    kids = _children(top)
    if len(kids) < 3 or kids[0][0] != 0x30:
        raise ValueError("证书结构不完整")
    tbs = _children(kids[0][1])
    idx = 0
    if tbs and tbs[0][0] == 0xA0:      # [0] version
        idx = 1
    if len(tbs) < 6:
        raise ValueError("TBSCertificate 结构不完整")
    _, serial_raw = tbs[idx]
    _, issuer_raw = tbs[idx + 2]
    _, validity_raw = tbs[idx + 3]
    _, subject_raw = tbs[idx + 4]
    sig_oid = ""
    try:
        # kids[1] = signatureAlgorithm AlgorithmIdentifier；(tag,value) 里的 value 已是被剥掉
        # SEQUENCE 头的内容，所以直接对**内容**取子 TLV，第一个子项就是算法 OID。
        # （早先写成"对内容再解一层 SEQUENCE"，异常被静默吞掉 → sig_algo 恒为空串。）
        sig_oid = _oid(_children(kids[1][1])[0][1])
    except (ValueError, IndexError):
        pass
    nb, na = "", ""
    nb_t = na_t = None
    times = _children(validity_raw)
    if len(times) >= 2:
        nb, nb_t = _time(times[0][1], times[0][0])
        na, na_t = _time(times[1][1], times[1][0])
    exts = _extensions(tbs[idx + 6][1]) if len(tbs) > idx + 6 and tbs[idx + 6][0] == 0xA3 else {}
    sub_parts, iss_parts = _name_parts(subject_raw), _name_parts(issuer_raw)
    now = time.time()
    d = {
        # 序列号：DER 的 INTEGER 为保持正数会给高位补一个 0x00（如 0xDEADBEEF 编成
        # 00 DE AD BE EF），这里剥掉补位再转十六进制，与 `openssl x509 -serial` 一致
        # （实测：OpenSSL 对同一张证书输出 DEADBEEF，而不是 00DEADBEEF）。
        "serial": (serial_raw.lstrip(b"\x00") or b"\x00").hex().upper(),
        "sig_algo": _SIG_ALGOS.get(sig_oid, sig_oid),
        "issuer": _name_str(iss_parts),
        "subject": _name_str(sub_parts),
        # CN 单列一份：subject 串可能很长，表格里放不下；而"CN 与会话域名不一致/
        # SAN 里没有会话域名"正是 CTF 里最常看的信号，值得单独一列。
        "cn": _cn_of(sub_parts),
        "not_before": nb,
        "not_after": na,
        # 剩余天数：已过期给负数（页面上好一眼看出"过期了"）
        "days_left": (int((na_t - now) // 86400) if na_t else None),
        "expired": (1 if (na_t and na_t < now) else 0),
        # 自签 = 主体与颁发者是"同一组 RDN"。**按集合比，不按字符串比**：X.500 要求
        # 编码时"最高位在前"，但实际证书里 subject 与 issuer 的 RDN 顺序可以不写反
        # （同一个名字、两种排列），字符串相等会把这种自签误判为非自签（实测踩到过）。
        "self_signed": (1 if sub_parts and set(sub_parts) == set(iss_parts) else 0),
        "san": _san(exts.get(_OID_SAN, b""))[:MAX_SAN],
        "sha256": ":".join(hashlib.sha256(bytes(der)).hexdigest().upper()[i:i + 2]
                           for i in range(0, 64, 2)),
    }
    return d


def parse_pem(data):
    """PEM 文本/字节 → DER（用于解析手里已有的证书文件或响应体里的证书链）。"""
    if isinstance(data, bytes):
        data = data.decode("latin-1", "replace")
    m = re.search(r"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----", data, re.S)
    if not m:
        raise ValueError("未找到 PEM 证书块")
    import base64
    return base64.b64decode(re.sub(r"\s+", "", m.group(1)))


def fetch(host, port=443, timeout=8, server_hostname=None):
    """对 host:port 做一次 TLS 握手，返回 (结构化字典, 错误串)。

    - `verify_mode=CERT_NONE`：**刻意不校验证书** —— 自签名/过期/域名不匹配也要能把
      颁发者与有效期读出来（取证目的，不是建立可信连接）；因此它**不能**当"证书合法"的判据。
    - `server_hostname` 用于 SNI（按域名连 IP 或按 IP 连域名时都要显式给）。
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, int(port)), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=server_hostname or host) as tls:
                der = tls.getpeercert(binary_form=True)
        if not der:
            return None, "服务端未提供证书"
        return parse_der(der), ""
    except Exception as e:                          # 网络/协议/解析异常都在这里收口
        return None, f"{type(e).__name__}: {e}"


def tls_ports(settings=None):
    """哪些端口值得试 TLS（按站点 port 过滤用）。默认 443 与常见管理端口。"""
    cfg = (settings or {}).get("cert", {}) or {}
    ports = cfg.get("tls_ports") or [443, 8443, 9443]
    try:
        return {int(p) for p in ports}
    except (TypeError, ValueError):
        return {443, 8443, 9443}