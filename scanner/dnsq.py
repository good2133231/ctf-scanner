"""极简 DNS 客户端（纯标准库，UDP/53 + 截断时 TCP/53 重试）。

为什么自己构造报文：`socket.getaddrinfo` 只返回最终 IP，**拿不到 CNAME**，
而子域接管检测（P0-2）恰恰要靠 CNAME 指向哪个第三方服务来判定。
本项目不引入 dnspython 等第三方依赖（`requirements.txt` 只是"确实需要时"才加），
所以这里手写一个"够用"的查询器：只做 A / CNAME 等常见类型的**只读查询**。

实现要点与局限（写在最前，避免后来者误用）：
- 只支持 UDP/53 单次问答，`TC` 截断位置位时**尝试** TCP/53 重取完整应答，
  TCP 也失败就返回 UDP 已解析到的部分（会少记录，但不会崩）。
- 只解析**应答（Answer）段**，不合并 Authority/Additional 段的粘连记录；
  正规递归解析器（RD=1）会把 CNAME 链与最终 A 记录都放在 Answer 段，够用。
- 正确处理：名称压缩指针（0xC0）、长度前缀标签、CNAME(5)/A(1)/AAAA(28) 的 rdata。
- **任何异常都不向外抛**：解析失败一律返回空列表 / `([], [])`，让上层按"无结果"处理。
- 不做 DNSSEC 校验、不做 EDNS0、不做并发复用；每次查询一个独立 socket。

调用示例：
    dnsq.resolvers(settings)              # 配置里的 DNS 服务器（文件缺失时用内置公共 DNS）
    dnsq.query("www.example.com", "A")    # ['1.2.3.4']
    dnsq.cname_chain("a.example.com")     # (['b.example.com'], ['1.2.3.4'])
"""
import random
import socket
import struct
import threading

from .config import DEFAULTS, resolve
from .utils import read_lines

# 配置文件缺失/为空时的兜底 DNS（阿里 / Cloudflare / Google，国内外各一，连通性都不错）
DEFAULT_RESOLVERS = ("223.5.5.5", "1.1.1.1", "8.8.8.8")

# 记录类型号 -> 名称（只列常用项，query() 的 qtype 参数按名字解析）
_TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28}
_A, _CNAME, _AAAA = 1, 5, 28

_MAX_DEPTH = 8        # CNAME 链最大跳数（防环）
_UDP_BUF = 4096       # 单次 UDP 读取上限，超过会被 TC 截断并触发 TCP 重取
_TTL_WAIT = 3         # 默认超时

# 解析器列表缓存 + 轮询下标：一次任务里会有成百上千次查询，不能每次都读文件 / 只用一台 DNS。
# 缓存键是 resolvers 文件路径 —— `dicts.resolvers` 可配置，不同 settings 可能指向不同文件，
# 只缓存一份会把"当前配置"错当成"全部配置"。
_CACHE = {}
_ROTATE = {"i": 0}
_LOCK = threading.Lock()


# ---------- 解析器选择 ----------

def _is_ip(text):
    """是否是合法 IPv4/IPv6 字面量。

    配置文件里混进主机名/注释尾巴时，sendto 会先去做一次系统解析，
    白白卡住几秒；先校验可以避免这种"配置笔误拖慢整个任务"。
    """
    for fam in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(fam, str(text))
            return True
        except (OSError, ValueError):
            continue
    return False


def resolvers(settings=None):
    """返回 DNS 服务器 IP 列表。

    优先读 `dicts.resolvers`（默认 `config/dicts/resolvers.txt`，与 puredns 共用同一份）；
    文件不存在、为空或只有注释时回退内置三台公共 DNS —— 保证离线兜底不空转。
    """
    dicts = (settings or {}).get("dicts") if isinstance(settings, dict) else None
    path = (dicts or {}).get("resolvers") or DEFAULTS["dicts"]["resolvers"]
    out = []
    try:
        for line in read_lines(resolve(path)):
            line = line.strip()
            if not line or line.startswith("#") or not _is_ip(line):
                continue
            out.append(line)
    except Exception:
        out = []
    return out or list(DEFAULT_RESOLVERS)


def _default_resolvers(settings=None):
    """按 resolvers **文件路径**缓存的解析器列表。

    此前只缓存 `resolvers(None)` 一份，导致调用方传入的 `dicts.resolvers` 覆盖被无视
    （始终用默认路径那份）；现在把 settings 透传进来，缓存键换成解析后的路径，
    既尊重配置、又不至于让热路径每个域名都去读一次文件。
    """
    dicts = (settings or {}).get("dicts") if isinstance(settings, dict) else None
    path = str(resolve((dicts or {}).get("resolvers") or DEFAULTS["dicts"]["resolvers"]))
    with _LOCK:
        if path in _CACHE:
            return _CACHE[path]
    lst = resolvers(settings)
    with _LOCK:
        _CACHE[path] = lst
    return lst


def _pick_resolvers(n=1, settings=None):
    """轮询挑出 n 台解析器：避免所有查询都压在同一台 DNS 上被限流。"""
    lst = _default_resolvers(settings)
    if not lst:
        return []
    n = max(1, min(int(n), len(lst)))
    with _LOCK:
        start = _ROTATE.get("i", 0) % len(lst)
        _ROTATE["i"] = start + n
    return [lst[(start + k) % len(lst)] for k in range(n)]


# ---------- 报文编解码 ----------

def _encode_name(name):
    """把域名编成 DNS 名称格式（长度前缀标签 + 结尾 0x00）。非 ASCII 走 IDNA。"""
    out = b""
    for label in str(name).strip().rstrip(".").split("."):
        if not label:
            continue
        try:
            raw = label.encode("ascii")
        except UnicodeEncodeError:
            raw = label.encode("idna")
        if len(raw) > 63:                                # 单标签上限 63 字节，超长截断
            raw = raw[:63]
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def _read_name(data, offset):
    """解码一个 DNS 名称，返回 (name, 结束偏移)。

    压缩指针（高两位 0xC0）要顺着 offset 跳回去继续读；offset 记录的始终是
    "原始位置之后"的字节，否则多记录连读时会错位。用 seen 防指针环。
    """
    labels, seen = [], set()
    jumped = False
    next_off = offset
    while 0 <= offset < len(data):
        length = data[offset]
        if length & 0xC0 == 0xC0:                       # 压缩指针
            if offset + 1 >= len(data):
                break
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                next_off = offset + 2
                jumped = True
            if ptr in seen:
                break
            seen.add(ptr)
            offset = ptr
            continue
        if length == 0:                                 # 名称结束
            if not jumped:
                next_off = offset + 1
            break
        offset += 1
        labels.append(data[offset:offset + length].decode("ascii", "replace"))
        offset += length
        if not jumped:
            next_off = offset
    return ".".join(labels), next_off


def _build_query(name, qtype, tid):
    """构造查询报文：标准头（RD=1）+ 单个问题段。"""
    header = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    return header + _encode_name(name) + struct.pack("!HH", qtype, 1)


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _parse_message(data):
    """解析应答，返回 (tid, records, rcode, tc)。

    records 为 [(owner_lower, rtype, rdata_text), ...]，只取 Answer 段。
    长度做边界检查，任何越界都视为记录结束（宁可少读，不可越界）。
    """
    if not data or len(data) < 12:
        return None
    tid, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
    rcode = flags & 0x000F
    tc = bool(flags & 0x0200)
    off = 12
    for _ in range(qd):                                  # 跳过问题段
        _, off = _read_name(data, off)
        off += 4
    records = []
    for _ in range(an):
        owner, off = _read_name(data, off)
        if off + 10 > len(data):
            break
        rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", data[off:off + 10])
        off += 10
        end = off + rdlen
        if end > len(data):
            rdlen, end = max(0, len(data) - off), len(data)
        if rtype == _CNAME:
            # CNAME 的 rdata 本身是一个（可能被压缩的）名称
            target, _ = _read_name(data, off)
            records.append((owner.lower(), rtype, target.rstrip(".")))
        elif rtype == _A and rdlen == 4:
            records.append((owner.lower(), rtype, socket.inet_ntoa(data[off:end])))
        elif rtype == _AAAA and rdlen == 16:
            records.append((owner.lower(), rtype,
                            socket.inet_ntop(socket.AF_INET6, data[off:end])))
        else:
            records.append((owner.lower(), rtype, ""))
        off = end
    return tid, records, rcode, tc


def _udp_exchange(packet, resolver, timeout):
    fam = socket.AF_INET6 if ":" in str(resolver) else socket.AF_INET
    with socket.socket(fam, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(packet, (resolver, 53))
        data, _ = s.recvfrom(_UDP_BUF)
        return data


def _tcp_exchange(packet, resolver, timeout):
    """截断时的 TCP/53 重取：报文前加 2 字节长度前缀。"""
    with socket.create_connection((resolver, 53), timeout=timeout) as s:
        s.sendall(struct.pack("!H", len(packet)) + packet)
        head = _recv_exact(s, 2)
        if not head:
            return None
        (n,) = struct.unpack("!H", head)
        return _recv_exact(s, n)


def _exchange(name, qtype, timeout=_TTL_WAIT, resolver=None, settings=None):
    """一次问答，返回 (records, rcode, tc)。UDP 失败/ID 不符会换一台 DNS 重试。"""
    tid = random.randint(0, 0xFFFF)
    packet = _build_query(name, qtype, tid)
    servers = [resolver] if resolver else _pick_resolvers(2, settings)
    for srv in servers:
        if not srv or not _is_ip(srv):
            continue
        try:
            data = _udp_exchange(packet, srv, timeout)
        except Exception:
            continue
        parsed = _parse_message(data)
        if not parsed or parsed[0] != tid:
            continue
        _tid, records, rcode, tc = parsed
        if tc:
            # 截断：尽量用 TCP 拿完整应答；失败就返回 UDP 已解析到的部分
            try:
                tdata = _tcp_exchange(packet, srv, timeout)
                tparsed = _parse_message(tdata) if tdata else None
                if tparsed and tparsed[0] == tid and not tparsed[3]:
                    return tparsed[1], tparsed[2], False
            except Exception:
                pass
            return records, rcode, True
        return records, rcode, False
    return [], -1, False


# ---------- 对外接口 ----------

def query(name, qtype="A", timeout=3, resolver=None, settings=None):
    """查询单个名称，返回**指定类型**的 rdata 字符串列表（失败返回 []）。

    qtype 支持 "A" / "CNAME" / "AAAA" / "TXT" / "MX" / "NS" / "SOA" / "PTR"；
    A 记录返回 IP 文本，CNAME 返回目标域名（不含结尾点）。
    """
    try:
        qnum = _TYPES.get(str(qtype or "A").upper())
        host = str(name or "").strip().rstrip(".")
        if not qnum or not host:
            return []
        records, _rcode, _tc = _exchange(host, qnum, timeout=timeout or _TTL_WAIT,
                                         resolver=resolver, settings=settings)
        return [text for _owner, rtype, text in records if rtype == qnum and text]
    except Exception:
        return []


def resolve_detail(name, timeout=3, resolver=None, settings=None):
    """解析 A/CNAME 并给出**失败原因** —— 供 GUI 解释"这个域名为什么没有 IP"。

    返回 `(chain, ips, reason)`：`reason` 为空串表示解析成功。取值：
    `nxdomain`（域名不存在）/ `servfail`（DNS 故障）/ `refused`（DNS 拒绝）/
    `no-a`（有应答但没有 A 记录，例如只挂了个失效 CNAME）/ `timeout`（无应答）/
    `error`（内部异常）/ `empty`（传进来的名字为空）。

    与 `cname_chain()` 的关系：那个只返回 (chain, ips)、失败静默；这个多带一个原因码，
    因为"资产页显示一个 '-'"对排查毫无帮助（用户 2026-09-22 明确要求标出原因）。
    """
    try:
        current = str(name or "").strip().rstrip(".")
        if not current:
            return [], [], "empty"
        chain, ips, seen, cmap = [], [], {current.lower()}, {}
        rcode, got_records = 0, False
        for _ in range(_MAX_DEPTH):
            records, rcode, _tc = _exchange(current, _A, timeout=timeout or _TTL_WAIT,
                                            resolver=resolver, settings=settings)
            if records:
                got_records = True
            for owner, rtype, text in records:
                if rtype == _CNAME and text:
                    cmap.setdefault(owner, text.rstrip("."))
                elif rtype == _A and text:
                    ips.append(text)
            moved = False
            while True:
                nxt = cmap.get(current.lower())
                if not nxt or nxt.lower() in seen:
                    break
                chain.append(nxt)
                seen.add(nxt.lower())
                current = nxt
                moved = True
            if ips or not moved or not records:
                break
        if ips:
            return chain, sorted(set(ips)), ""
        if rcode == 3:
            return chain, [], "nxdomain"
        if rcode == 2:
            return chain, [], "servfail"
        if rcode == 5:
            return chain, [], "refused"
        if got_records:
            return chain, [], "no-a"
        return chain, [], "timeout"
    except Exception:
        return [], [], "error"


def cname_chain(name, timeout=3, resolver=None, settings=None):
    """返回 (cname_chain, ips)。

    chain 是 CNAME 链，**不含原始名字**（如 a.x.com → b.cdn.net 时 chain=('b.cdn.net',)）；
    ips 是链尾解析到的 A 记录。无 CNAME / 解析失败一律返回 ([], [])。
    递归解析器通常在同一个应答里给出整条链，因此多数情况下只花 1 次查询。
    """
    try:
        current = str(name or "").strip().rstrip(".")
        if not current:
            return [], []
        chain, ips, seen, cmap = [], [], {current.lower()}, {}
        for _ in range(_MAX_DEPTH):
            records, _rcode, _tc = _exchange(current, _A, timeout=timeout or _TTL_WAIT,
                                             resolver=resolver, settings=settings)
            if not records:
                break
            for owner, rtype, text in records:
                if rtype == _CNAME and text:
                    cmap.setdefault(owner, text.rstrip("."))
                elif rtype == _A and text:
                    ips.append(text)
            moved = False
            while True:                                  # 先在本次应答内把链走完
                nxt = cmap.get(current.lower())
                if not nxt or nxt.lower() in seen:
                    break
                chain.append(nxt)
                seen.add(nxt.lower())
                current = nxt
                moved = True
            if ips or not moved:
                break
            # 走到链尾但还没拿到 A：对链尾再查一次（下一轮循环）
        return chain, sorted(set(ips))
    except Exception:
        return [], []