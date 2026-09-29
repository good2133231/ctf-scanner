"""登录验证码（续78）：**纯标准库**生成 + 校验，不引入 PIL / 任何第三方依赖。

为什么自己手写：项目一贯「零第三方依赖」（`requirements.txt` 只有 flask/requests/PyYAML）。
要画验证码就得有位图字体 + PNG 编码 —— 位图字体是本文件里的 `_FONT`（5×7 点阵，手写），
PNG 用 `zlib` + `struct` 手写（`_png()`），不依赖 Pillow。

设计取舍：

1. **答案只存服务端内存，绝不进 HTML/JS/会话 cookie** —— 这点决定了不能用「SVG `<text>`」或
   「前端 canvas 画字」两种偷懒做法（答案会随页面/脚本下发，等于没验证码）。所以走**服务端渲染 PNG**，
   且答案存**本进程内存**（`_STORE`），会话里只放不透明 token（Flask 默认 session 是**签名未加密**的
   cookie，塞答案进去客户端一解就读到 —— 见下方「服务端码库」）。
2. **一次性 + 大小写不敏感 + 常量时间比较**：校验通过或失败都**立刻作废**当前码（防重放），
   比较用 `secrets.compare_digest`（防时序侧信道）。用户输入统一 `.upper()`、`O/0`、`I/1`、`S/5` 归一，
   减少「看得清却打错」的挫败。
3. **易混字符不进字母表**：默认字母表去掉 `0 O 1 I L S 5 Z 2` 这类易混项，只留 `23456789` 与
   大写字母的子集（见 `ALPHABET`），降低误输入。
4. **干扰**：随机点噪 + 若干随机斜线 + 每个字符随机纵向偏移。强度有限（**不是**抗专业 OCR 的
   验证码，目的是拦住脚本化暴力提交），够用即可 —— 真正的暴力防护靠 `login_guard` 的限速/锁定。
"""
import secrets
import struct
import threading
import time
import zlib

# 默认字母表：去掉 0/O、1/I/L、5/S、2/Z 等易混字符（见文件头第 3 点）
ALPHABET = "346789ABCDEFGHJKMNPQRTUVWXY"

# 5×7 点阵字体：每个字形 7 行、每行 5 个字符（'1'=实心，'0'=空）。
_FONT = {
    "3": ["11110", "00001", "00001", "01110", "00001", "00001", "11110"],
    "4": ["00010", "00110", "01010", "10010", "11111", "00010", "00010"],
    "6": ["01110", "10000", "10000", "11110", "10001", "10001", "01110"],
    "7": ["11111", "00001", "00010", "00100", "01000", "01000", "01000"],
    "8": ["01110", "10001", "10001", "01110", "10001", "10001", "01110"],
    "9": ["01110", "10001", "10001", "01111", "00001", "00001", "01110"],
    "A": ["01110", "10001", "10001", "11111", "10001", "10001", "10001"],
    "B": ["11110", "10001", "10001", "11110", "10001", "10001", "11110"],
    "C": ["01110", "10001", "10000", "10000", "10000", "10001", "01110"],
    "D": ["11110", "10001", "10001", "10001", "10001", "10001", "11110"],
    "E": ["11111", "10000", "10000", "11110", "10000", "10000", "11111"],
    "F": ["11111", "10000", "10000", "11110", "10000", "10000", "10000"],
    "G": ["01110", "10001", "10000", "10111", "10001", "10001", "01111"],
    "H": ["10001", "10001", "10001", "11111", "10001", "10001", "10001"],
    "J": ["00111", "00010", "00010", "00010", "00010", "10010", "01100"],
    "K": ["10001", "10010", "10100", "11000", "10100", "10010", "10001"],
    "M": ["10001", "11011", "10101", "10101", "10001", "10001", "10001"],
    "N": ["10001", "11001", "11001", "10101", "10011", "10011", "10001"],
    "P": ["11110", "10001", "10001", "11110", "10000", "10000", "10000"],
    "Q": ["01110", "10001", "10001", "10001", "10101", "10010", "01101"],
    "R": ["11110", "10001", "10001", "11110", "10100", "10010", "10001"],
    "T": ["11111", "00100", "00100", "00100", "00100", "00100", "00100"],
    "U": ["10001", "10001", "10001", "10001", "10001", "10001", "01110"],
    "V": ["10001", "10001", "10001", "10001", "10001", "01010", "00100"],
    "W": ["10001", "10001", "10001", "10101", "10101", "11011", "10001"],
    "X": ["10001", "10001", "01010", "00100", "01010", "10001", "10001"],
    "Y": ["10001", "10001", "01010", "00100", "00100", "00100", "00100"],
}

# 输入归一：把用户容易看混的字符映射回字母表里的规范字符（见文件头第 2 点）
_NORMALIZE = {"O": "0", "I": "1", "L": "1", "S": "5", "Z": "2", "B": "8", "G": "6"}


def new_code(n=4):
    """生成 n 位随机验证码（默认 4 位，取自 `ALPHABET`，用 `secrets` 保证密码学随机）。"""
    n = max(3, min(8, int(n or 4)))
    return "".join(secrets.choice(ALPHABET) for _ in range(n))


def normalize(text):
    """把用户输入归一到字母表形态：去空白、转大写、替换易混字符。"""
    s = "".join(ch for ch in str(text or "").upper() if not ch.isspace())
    return "".join(_NORMALIZE.get(ch, ch) for ch in s)


def verify(expected, submitted):
    """常量时间比较（大小写/易混归一后）。`expected` 为空一律判否（没发码就不认）。"""
    if not expected:
        return False
    return secrets.compare_digest(normalize(expected), normalize(submitted))


def _png(width, height, rows):
    """把手写的 RGB 行（每行 width*3 字节）编码成 PNG（`zlib` + `struct`，无第三方依赖）。"""
    raw = b"".join(b"\x00" + bytes(r) for r in rows)   # 每行前缀 filter=0

    def chunk(tag, data):
        body = tag + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)   # 8-bit truecolor RGB
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr)
            + chunk(b"IDAT", zlib.compress(raw, 6)) + chunk(b"IEND", b""))


def render_png(code, scale=4, pad=6, seed=None):
    """把 `code` 渲染成 PNG 字节（服务端画，答案不进页面 —— 见文件头第 1 点）。

    `seed` 仅用于测试复现（同一 seed + code → 同一张图）；生产不传（用 `secrets` 随机）。
    """
    code = str(code or "")
    rng = secrets.SystemRandom() if seed is None else __import__("random").Random(seed)
    gw, gh = 5 * scale, 7 * scale                     # 单字形像素尺寸
    step = gw + scale                                 # 字间距
    width = pad * 2 + step * len(code)
    height = gh + pad * 2
    bg, fg, noise = (245, 247, 250), (30, 40, 55), (150, 160, 175)

    # 画布：按行存 RGB
    canvas = [[list(bg) for _ in range(width)] for _ in range(height)]

    def put(x, y, color):
        if 0 <= x < width and 0 <= y < height:
            canvas[y][x] = list(color)

    for i, ch in enumerate(code):
        glyph = _FONT.get(ch.upper())
        if not glyph:
            continue
        ox = pad + i * step
        oy = pad + rng.randint(-2, 2)                  # 每字符随机纵向抖动
        for ry, line in enumerate(glyph):
            for rx, bit in enumerate(line):
                if bit != "1":
                    continue
                for dy in range(scale):
                    for dx in range(scale):
                        put(ox + rx * scale + dx, oy + ry * scale + dy, fg)

    # 干扰：随机点 + 若干斜线
    for _ in range(width * height // 25):
        put(rng.randint(0, width - 1), rng.randint(0, height - 1), noise)
    for _ in range(3):
        x0, y0 = rng.randint(0, width - 1), rng.randint(0, height - 1)
        x1, y1 = rng.randint(0, width - 1), rng.randint(0, height - 1)
        steps = max(abs(x1 - x0), abs(y1 - y0), 1)
        for s in range(steps + 1):
            put(x0 + (x1 - x0) * s // steps, y0 + (y1 - y0) * s // steps, noise)

    return _png(width, height, [b"".join(bytes(px) for px in row) for row in canvas])


# ---- 服务端码库（**答案绝不进客户端 cookie**，见文件头第 1 点）----
# Flask 默认 session 是**签名但未加密**的 cookie：内容 base64 可读。若把验证码答案塞进 session，
# 客户端解一下 cookie 就拿到答案了 —— 等于没验证码。故答案只存本进程内存，会话里只放**不透明 token**。
_STORE = {}
_STORE_LOCK = threading.Lock()
_TTL = 300.0        # 5 分钟过期
_MAX = 4096         # 兜底上限：防止异常流量把内存撑爆


def _prune(now):
    """清掉过期项；超上限时按过期时间淘汰最旧的一批（调用方需持锁）。"""
    for k in [k for k, (_c, exp) in list(_STORE.items()) if exp < now]:
        _STORE.pop(k, None)
    if len(_STORE) > _MAX:
        for k, _ in sorted(_STORE.items(), key=lambda kv: kv[1][1])[:len(_STORE) - _MAX]:
            _STORE.pop(k, None)


def issue(n=4, ttl=_TTL):
    """生成一个新验证码：返回 `(token, code)`。`token` 放进会话，`code` 只留服务端。"""
    code = new_code(n)
    token = secrets.token_urlsafe(16)
    with _STORE_LOCK:
        _prune(time.time())
        _STORE[token] = (code, time.time() + float(ttl))
    return token, code


def check(token, submitted):
    """校验并**立即作废**（一次性）：token 不存在 / 已过期 / 码不符都返回 False。"""
    if not token:
        return False
    with _STORE_LOCK:
        item = _STORE.pop(str(token), None)      # pop = 一次性，防重放
    if not item:
        return False
    code, exp = item
    if time.time() > exp:
        return False
    return verify(code, submitted)
