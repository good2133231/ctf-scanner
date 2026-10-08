#!/usr/bin/env python3
"""控制台挂载路径随机化（续138）。

用户点单原话："把我们后台路径随机化，根目录默认访问 404，两层随机字符，至少 20 位，
每次启动的时候随机生成给我们。"

**先把话说清楚（这不是认证）**：随机路径买到的只有"扫端口/爬根目录的人找不到入口"。
真门槛仍然是 401 边缘门（`scanner/edgeauth.py`）+ `users` 表那两道 —— 谁拿到 URL 谁就
到了登录页，这与"路径写在配置里"时一模一样。本模块刻意**不**假装它是访问控制。

三条实现口径：

1. **每次启动新生成，不落盘**。写进 `config/settings.yaml` 就等于进公开仓库（那文件被 git
   跟踪），写进任何本机文件则"重启后还能找回来"的收益远小于泄露面；而且用户的原话就是
   "每次启动随机生成"。要固定，用环境变量 `CTFSCANNER_WEB_PATH`（空串＝挂在根路径，
   给 e2e/CI/嵌入用法留的口子，见 `serve()`）。
2. **两层、各 10 位、共 20 位**（`/aaaaaaaaaa/bbbbbbbbbb/`）。字符表去掉了容易抄错的
   `0o1li`；两段都用 `secrets` 取，**不用 `random`**（后者可预测，那等于没随机）。
3. **前缀不对一律 404，空响应体**。不回 401、不重定向到登录页、也不在页面里留任何提示 ——
   否则"这里有个后台"本身就是泄漏（401 会告诉扫描者"猜对了路径"）。
"""
import re
import secrets
import string

# 去掉 0/o/1/i/l：这些在终端里抄一次错一次，而这条 URL 是要人手敲的
ALPHABET = "".join(c for c in string.ascii_lowercase + string.digits if c not in "0o1li")
SEG_LEN = 10          # 两层 × 10 位 ＝ 20 位随机字符（用户要求的下限）
SEGMENTS = 2

# 校验用：随机前缀必须是两段、每段都是字符表内的 10 位
_BASE_RE = re.compile(r"^/[a-z0-9]{%d}/[a-z0-9]{%d}$" % (SEG_LEN, SEG_LEN))

# 手动指定（`CTFSCANNER_WEB_PATH`）时放宽到"能用就行"的形状：小写字母或数字开头，
# 后续可含 `. _ -`，每段 1–64 位、最多 4 段。刻意不接受空段、`.`/`..`、查询串、
# 反斜杠、非 ASCII —— 这些拼进 `Location` 就是开放重定向与路径穿越的原材料。
_FIXED_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
MAX_SEGMENTS = 4


def new_base(rng=None):
    """生成本次启动的挂载前缀，形如 `/k7m2q8x3pd/5w9yt4hrcb`（无前导/尾随斜杠外的内容）。

    `rng` 只为**测试可注入**（回归要能复算"两层各 10 位、字符表、不重复"这些形状判据，
    而真随机的输出没法在断言里预定）。生产调用一律不传。
    """
    pick = (rng or secrets.SystemRandom()).choice
    segs = ["".join(pick(ALPHABET) for _ in range(SEG_LEN)) for _ in range(SEGMENTS)]
    return "/" + "/".join(segs)


def normalize(base):
    """规整挂载前缀 —— **三个态分开，不把"不合格"和"挂根路径"混成同一个返回值**。

    - 空串（或 `/`）→ 返回 `""`：挂根路径。这是**有意义的取值**（e2e / 嵌入 / 就想固定挂根的人）。
    - 合格 → 返回 `"/a/b"`（吃掉尾随斜杠）。
    - 不合格 → 抛 `ValueError`。

    为什么不能"不合格就当空串"：`CTFSCANNER_WEB_PATH=/gui/console` 这种人为指定的路径一旦
    被判不合格又静默降级成根路径，表现就是"我明明设了路径，后台怎么挂在根上"—— 而根路径正是
    本功能要消掉的那个暴露面。抛出来让调用方**必须**说清它降级成了什么（见 `gui/app.py` 的
    `_web_base_for`：不合格 → 仍用随机前缀并打印原因，而不是关掉功能）。
    """
    b = str(base or "").strip().rstrip("/")
    if not b or b == "/":
        return ""
    if not b.startswith("/"):
        raise ValueError(f"前缀必须以 / 开头，收到 {b!r}")
    segs = b[1:].split("/")
    if "" in segs:
        raise ValueError(f"前缀里有空段（连续的 /），收到 {b!r}")
    if len(segs) > MAX_SEGMENTS:
        raise ValueError(f"前缀最多 {MAX_SEGMENTS} 段，收到 {len(segs)} 段：{b!r}")
    for s in segs:
        if s in (".", ".."):
            raise ValueError(f"前缀段不能用 . / ..（路径穿越形状），收到 {b!r}")
        if not _FIXED_RE.match(s):
            raise ValueError(f"前缀段 {s!r} 不合格：只许小写字母/数字开头，"
                             "后续可含 . _ -，每段 1–64 位")
    return "/" + "/".join(segs)


def is_valid(base):
    """能不能当挂载前缀用（含"空串＝挂根路径"这个合法态）。"""
    try:
        normalize(base)
    except ValueError:
        return False
    return True


def is_random_base(base):
    """是不是 `new_base()` 承诺的那种形状：两层、各 10 位、字符表内。

    与 `is_valid()` 分工不同 —— 后者放宽到"手动指定的路径能用就行"（`/gui/console` 合法），
    所以钉"每次启动随机生成 20 位"这条承诺必须用它，不能用 `is_valid()`（那会放走一层 8 位的路径）。
    """
    return bool(_BASE_RE.match(str(base or "")))


def strip(environ, base):
    """WSGI 层剥前缀：返回改写后的 `(script_name, path_info)`，不合格返回 `None`。

    ⚠ `SCRIPT_NAME` 必须设成那个前缀 —— 这是"链接会自动带上前缀"的唯一正解：
    Flask 的 `url_for()` 与 `redirect()` 都读它。只改 `PATH_INFO` 不设 `SCRIPT_NAME`，
    页面里的链接会全部指到根路径上去 404（本轮实测踩过形状：登录后跳回 `/` 就丢前缀）。
    """
    path = environ.get("PATH_INFO", "") or "/"
    if not base:
        return environ.get("SCRIPT_NAME", ""), path
    if path == base:
        return base, "/"                                  # `/前缀` 视作进首页
    if not path.startswith(base + "/"):
        return None                                       # 根路径、别的路径：一律 404
    return base, path[len(base):] or "/"


class PrefixMiddleware:
    """把整个控制台挂在随机前缀下的 WSGI 包装。

    放在 WSGI 层而不是 Flask 层，是因为 `before_request` 里再改 `PATH_INFO` 已经太晚：
    路由早就按原路径匹配完了（会先 404），而 `url_for` 也不会知道前缀。
    """

    def __init__(self, app, base=""):
        self.app = app
        self.base = normalize(base)

    def __call__(self, environ, start_response):
        got = strip(environ, self.base)
        if got is None:
            # 空 body + 不带 Server 之外的任何信息：让"猜错路径"和"这台机器根本没跑 Flask"
            # 长得一模一样。
            start_response("404 NOT FOUND", [("Content-Type", "text/plain"),
                                            ("Content-Length", "0")])
            return [b""]
        script_name, path_info = got
        environ["SCRIPT_NAME"] = script_name
        environ["PATH_INFO"] = path_info
        return self.app(environ, start_response)
