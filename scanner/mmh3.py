"""MurmurHash3 x86_32 的纯标准库实现（无第三方依赖）。

为什么自己实现（取代"引用 mmh3 包"）：
- favicon 的社区指纹库（FOFA `icon_hash`、Shodan `http.favicon.hash`）**统一以 mmh3 为键**，
  而不是 MD5。我们原先只算 MD5，因此"拿 favicon 去第三方反查资产"这条路走不通；
- `mmh3` 是 C 扩展包，在 CTF 现场（离线靶机、受限环境）装不上就整条功能不可用。
  MurmurHash3 x86_32 算法本身很短且完全确定，用标准库实现即可，还省一个依赖。

**正确性如何保证**：下面 `SELF_TEST` 里的三个向量是 mmh3 包的公开已知取值
（`mmh3.hash(b"")` / `mmh3.hash(b"foo")` / `mmh3.hash(b"hello")`），
`tests/smoke.py` 会断言它们，实现一旦写错立刻暴露。

与 `hashlib.md5` 的分工：MD5 用于**我们自己的** `favicon_md5_list` 零请求前置判定
（见 `fingerprint.py` / `pocs/engine.py`），mmh3 只用于**对外部平台**提问。
"""
import base64

# 公开已知向量（seed=0）：(输入字节, 期望的有符号 32 位结果)
SELF_TEST = ((b"", 0), (b"foo", -156908512), (b"hello", 613153351))

_C1 = 0xCC9E2D51
_C2 = 0x1B873593
_MASK = 0xFFFFFFFF


def _rotl32(x, r):
    return ((x << r) | (x >> (32 - r))) & _MASK


def hash32(data, seed=0):
    """MurmurHash3 x86_32，返回**有符号** 32 位整数（与 `mmh3.hash` 一致）。

    `data` 必须是 bytes；字符串按 UTF-8 编码（调用方自己决定，不在这里猜编码）。
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    length = len(data)
    nblocks = length // 4
    h1 = seed & _MASK

    for i in range(nblocks):
        k1 = int.from_bytes(data[i * 4:i * 4 + 4], "little")
        k1 = (k1 * _C1) & _MASK
        k1 = _rotl32(k1, 15)
        k1 = (k1 * _C2) & _MASK
        h1 ^= k1
        h1 = _rotl32(h1, 13)
        h1 = (h1 * 5 + 0xE6546B64) & _MASK

    tail = data[nblocks * 4:]
    k1 = 0
    if len(tail) == 3:
        k1 ^= tail[2] << 16
    if len(tail) >= 2:
        k1 ^= tail[1] << 8
    if len(tail) >= 1:
        k1 ^= tail[0]
        k1 = (k1 * _C1) & _MASK
        k1 = _rotl32(k1, 15)
        k1 = (k1 * _C2) & _MASK
        h1 ^= k1

    h1 ^= length
    # fmix32（雪崩）
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & _MASK
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & _MASK
    h1 ^= h1 >> 16
    return h1 - 0x100000000 if h1 >= 0x80000000 else h1


def favicon_hash(content):
    """favicon 的社区通用哈希：`mmh3.hash(base64.encodebytes(content))`。

    注意必须是 `encodebytes`（带换行的 base64 变体）而不是 `b64encode` ——
    FOFA / Shodan 的公开取数脚本用的就是前者，换成后者算出来的值对不上平台数据。
    """
    if not content:
        return 0
    return hash32(base64.encodebytes(content))