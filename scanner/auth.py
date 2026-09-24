"""任务级**登录态请求头**：把 Cookie / Token 之类的凭据注入目标侧的 HTTP 出口。

（注意：这里说的是**被测目标的登录态**，与 GUI 登录口令 `gui.token` 完全无关。）

为什么要有这一层（实战动机）：实测型检查里有相当一部分资产**登录后才存在** ——
未登录访问 `/admin`、`/api/user/list` 拿到的是 302/401，带上登录态才是 200；
JS 里的接口与凭据、需要会话的 POC，同理。没有这个能力时，框架只能扫"匿名可见面"，
对授权范围内的业务面几乎无感。

设计边界（红线，不因"能扫到更多"而放宽）：
- 只**注入请求头**（Cookie / Authorization / 自定义头），不做登录爆破、不自动提交表单、
  不解验证码 —— 凭据由使用者在授权范围内自行取得（抓包 / 接口获取），框架只负责"带上它去扫"。
- **不静默丢弃非法行**：`parse_headers()` 返回 `(headers, errors)`，调用方必须把 errors 告知
  使用者。悄悄丢掉 `Authorization` 会让"已登录扫描"变成假象（少扫出东西还以为是没洞）。
- 只发往**目标侧**出口。第三方接口（crt.sh / FOFA / CISA KEV / IP 反查）拿到的 `settings`
  不许带凭据 —— `utils.http_request(auth=False)` 是默认值，目标侧调用点才显式 `auth=True`。
- 日志、页面、报告一律 **掩码** 显示（`mask_value`），不把凭据写进日志文件与交付物。
"""
import re

# RFC 7230 token：请求头名字符集（挡住 `Cookie: a=b\r\nX: y` 这类注入形状）
_HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+\-.^_`|~]+$")

MAX_HEADERS = 20            # 单任务上限，防"贴了一整份抓包文件进来"
MAX_VALUE_LEN = 4096

# 值需要掩码的名字（凭据类都在这里）
_SENSITIVE_HINTS = ("cookie", "authorization", "token", "auth", "session",
                    "api-key", "apikey", "secret", "password")


def is_sensitive(name):
    n = str(name or "").lower()
    return any(h in n for h in _SENSITIVE_HINTS)


def mask_value(name, value):
    """凭据类的值掩码显示（保留首尾各 3 字符便于"认出来是哪一条"）。"""
    v = str(value or "")
    if not is_sensitive(name):
        return v
    if len(v) <= 6:
        return "*" * len(v)
    return v[:3] + "*" * (len(v) - 6) + v[-3:]


def summary(headers, limit=6):
    """给日志/页面用的一行摘要：只列**名字**与掩码后的值。"""
    names = [str(k) for k in (headers or {})]
    shown = ", ".join(f"{k}={mask_value(k, headers[k])}" for k in names[:limit])
    more = f" 等 {len(names)} 条" if len(names) > limit else ""
    return shown + more


def parse_headers(text):
    """把多行 `名称: 值` 文本解析成 dict，返回 `(headers, errors)`。

    - 空行与 `#` 注释行忽略；
    - 分隔符是**第一个**冒号，值里的冒号/等号保留（`Cookie: a=b; c=d`、`Referer: http://x`）；
    - 非法行进 `errors`（带行号与原因）而不是被丢掉 —— 调用方要把它显示给使用者。

    值里不可能含 CR/LF：`splitlines()` 已按 `\\r`/`\\n` 切分，因此不存在 header 注入通道
    （不需要额外再查一遍换行）。
    """
    headers, errors = {}, []
    for i, line in enumerate((text or "").splitlines(), 1):
        raw = line.strip()
        if not raw or raw.startswith("#"):
            continue
        if ":" not in raw:
            errors.append(f"第 {i} 行缺少冒号（应为「名称: 值」）：{_clip(raw)}")
            continue
        name, value = raw.split(":", 1)
        name, value = name.strip(), value.strip()
        if not _HEADER_NAME_RE.match(name):
            errors.append(f"第 {i} 行请求头名非法：{_clip(name)}")
            continue
        if not value:
            errors.append(f"第 {i} 行请求头值为空：{_clip(name)}")
            continue
        if len(value) > MAX_VALUE_LEN:
            errors.append(f"第 {i} 行请求头值过长（上限 {MAX_VALUE_LEN} 字符）：{_clip(name)}")
            continue
        if len(headers) >= MAX_HEADERS and name not in headers:
            errors.append(f"请求头超过 {MAX_HEADERS} 条，已忽略第 {i} 行起的其余内容")
            break
        headers[name] = value
    return headers, errors


def inject(settings, headers):
    """把登录态写进**本次任务专用的 settings 副本**（不做原地修改）。

    为什么是副本：GUI 的 `settings` 是每次 `_spawn` 现加载的，但 CLI / 测试会复用同一个 dict；
    原地写会把这一个任务的凭据带到别的任务上（越权 + 误报源）。
    """
    s = dict(settings or {})
    if headers:
        s["_auth_headers"] = {str(k): str(v) for k, v in headers.items()}
    return s


def from_task_options(options):
    """从任务选项里取登录态（`{"auth": {"Cookie": "..."}}`），返回 dict（无则空）。"""
    auth = (options or {}).get("auth")
    if not isinstance(auth, dict):
        return {}
    return {str(k): str(v) for k, v in auth.items() if str(k).strip() and str(v).strip()}


def _clip(text, n=40):
    t = str(text or "")
    return t if len(t) <= n else t[:n] + "…"