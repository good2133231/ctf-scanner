"""多用户与角色（续46）：账号密码登录 + 「管理员 / 子用户」两级角色。

为什么单独成模块（不塞进 `db.py`）：口令的**派生与校验**是带安全语义的一段代码
（每账号随机盐 / 迭代次数 / 常数时间比较），与"任务与资产"的存储层混在一起容易被人顺手改坏；
但它仍然复用 `db` 的连接与写锁（`db._exec` / `db._query`），不另起一套连接管理。

面向 CTF 单机/小队的取舍（**不是**企业级 IAM，刻意不做的事写在文件末尾）：
- **零第三方依赖**（离线约束）：口令用标准库 `hashlib.pbkdf2_hmac("sha256", …)` 派生，
  盐来自 `secrets.token_bytes`（每账号独立），比较用 `hmac.compare_digest`（常数时间）；
- **绝不存明文口令、也绝不打进日志**：库里只有 `pbkdf2_sha256$<迭代>$<盐>$<哈希>`，
  本模块所有函数只记"用户名 + 结果"，不记口令本身；`list_users()` 连哈希列都不取出；
- 只有两级角色：`admin`（策略配置 / POC 管理 / 账号管理）与 `user`（子用户：只能建任务
  跑扫描、看结果）；
- 会话里放的是**身份 + 角色**（`uid` / `user` / `role`），不再是续32 那个布尔 `auth`。

刻意不做（避免"看起来有、其实没有"）：
- 不做密码找回邮箱 / 短信、不做 SSO、不做审计流水表、不做登录失败锁定与验证码
  （本机/可信网段小队共用场景，锁定的代价是把队友挡在门外；口令强度靠创建时的下限兜底）；
- 口令**不强制**复杂度字符集（CTF 现场更在意"能记住、能马上开工"），只卡长度下限与
  "不能等于用户名"；要更强请管理员在建号时自己定。
"""
import base64
import hashlib
import hmac
import re
import secrets
import sqlite3
import time

from . import db

# ---- 角色 ----

ROLE_ADMIN = "admin"          # 管理员：策略配置 / POC 管理 / 账号管理
ROLE_USER = "user"            # 子用户：只能建任务跑扫描、看结果
ROLES = (ROLE_ADMIN, ROLE_USER)

# ---- 口令派生参数 ----

SCHEME = "pbkdf2_sha256"
# 20 万次迭代：标准库的 pbkdf2_hmac 是 C 实现，单次约 0.1 秒级 —— 离线爆破的成本被抬到
# 可接受量级，而登录时的一次性开销无人能感知。**改这个值会让老口令全部失效**（迭代次数
# 存在哈希串里，校验时按串里的值算，所以其实是"新口令用新值、老口令照旧"，不会锁人）。
PBKDF2_ITERATIONS = 200000
SALT_BYTES = 16               # 128 位盐，与常见实践一致

MIN_PASSWORD_LEN = 8          # 口令长度下限（CTF 现场可接受的最低线）
MAX_PASSWORD_LEN = 128        # 上限：超长输入不是"更安全"，只是误粘贴/DoS

# 用户名：2-32 个字符，不含空白与斜杠（斜杠会搅乱路径与日志，空白会让人看不出首尾）
USERNAME_RE = re.compile(r"^[^\s/\\]{2,32}$")

# 用户名不存在时的"陪跑"哈希（防止用响应时间枚举用户名，见 `_dummy_verify`）
_DUMMY_HASH = ""


def _now():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _b64(raw):
    """bytes → base64 文本（库里存文本，避免把二进制塞进 TEXT 列）。"""
    return base64.b64encode(raw).decode("ascii")


def _unb64(text):
    """base64 文本 → bytes；坏输入抛 ValueError，由调用方转"校验失败"。"""
    return base64.b64decode(text.encode("ascii"))


def hash_password(password, iterations=PBKDF2_ITERATIONS, salt=None):
    """把口令派生成**可存储**的字符串：`pbkdf2_sha256$<迭代次数>$<盐>$<哈希>`。

    三段都存下来的理由：迭代次数与盐都是"将来可能变"的参数，写进串里才能做到
    "新口令用新参数、老口令照旧校验"（否则调参就是一次全员强制改密，且没有过渡期）。
    """
    raw_salt = salt if salt is not None else secrets.token_bytes(SALT_BYTES)
    dk = hashlib.pbkdf2_hmac("sha256", str(password or "").encode("utf-8"),
                             raw_salt, int(iterations))
    return f"{SCHEME}${int(iterations)}${_b64(raw_salt)}${_b64(dk)}"


def verify_password(stored, password):
    """校验口令。任何格式异常（不是本方案 / base64 坏 / 迭代次数不是整数）一律判**失败**而不是抛。

    为什么"坏数据判失败而不是报错"：库里这一列理论上只由本模块写，但手工改库、"从别处
    导进来"的用户行都可能出现；把异常抛到登录页上，只会把管理员挡在门外（且看不出原因）。
    """
    parts = str(stored or "").split("$")
    if len(parts) != 4 or parts[0] != SCHEME:
        return False
    try:
        iterations = int(parts[1])
        salt = _unb64(parts[2])
        expect = _unb64(parts[3])
    except (ValueError, TypeError):
        return False
    dk = hashlib.pbkdf2_hmac("sha256", str(password or "").encode("utf-8"), salt, iterations)
    return hmac.compare_digest(dk, expect)


def _dummy_verify(password):
    """用户名不存在时也**算一次同量级的哈希**再返回 False。

    不加这一下的话，"用户不存在"比"口令错"快 20 万次迭代（约 0.1 秒），
    远程就能据此枚举出真实用户名 —— 属于典型的计时侧信道。
    """
    global _DUMMY_HASH
    if not _DUMMY_HASH:
        _DUMMY_HASH = hash_password(secrets.token_hex(16))
    verify_password(_DUMMY_HASH, password)
    return False


def const_eq(left, right):
    """文本常数时间比较（先编码再比：`compare_digest` 遇到非 ASCII 的 str 会抛 TypeError）。"""
    try:
        return hmac.compare_digest(str(left or "").encode("utf-8"),
                                   str(right or "").encode("utf-8"))
    except TypeError:
        return False


def validate_username(username):
    """用户名合法性，返回 `(ok, 提示)`。"""
    name = str(username or "").strip()
    if not name:
        return False, "用户名不能为空"
    if len(name) < 2 or len(name) > 32:
        return False, "用户名需 2-32 个字符"
    if not USERNAME_RE.match(name):
        return False, "用户名不能含空白、斜杠与反斜杠"
    return True, ""


def validate_password(password, username=""):
    """口令合法性，返回 `(ok, 提示)`。只卡下限（CTF 现场可用性优先），不强制字符集。"""
    pw = str(password or "")
    if not pw.strip():
        return False, "口令不能为空或纯空白"
    if len(pw) < MIN_PASSWORD_LEN:
        return False, f"口令至少 {MIN_PASSWORD_LEN} 位"
    if len(pw) > MAX_PASSWORD_LEN:
        return False, f"口令最长 {MAX_PASSWORD_LEN} 位"
    if str(username or "").strip() and pw.lower() == str(username).strip().lower():
        return False, "口令不能与用户名相同"
    return True, ""


# ---- 库访问（表由 `db.SCHEMA` 的 `CREATE TABLE IF NOT EXISTS` 建出，老库原地补表） ----

# 列表与取单行**刻意不取 password 列**：这些结果会直接进模板/日志，
# 不进内存就不会被打印出来（"不取"比"取了再记得删"可靠）。
_USER_COLUMNS = "id, username, role, enabled, must_change, created_at, updated_at, last_login_at"


def count_users():
    """账号总数（**含**停用）。表还没建（如纯 CLI 场景）→ 0，不抛。"""
    try:
        row = db._query("SELECT COUNT(*) AS n FROM users", one=True)
    except sqlite3.OperationalError:
        return 0
    return int(row["n"] or 0) if row else 0


def count_enabled_admins():
    """启用中的管理员数量 —— 用于"至少留一个管理员"的防锁死判据。"""
    try:
        row = db._query("SELECT COUNT(*) AS n FROM users WHERE role=? AND enabled=1",
                        (ROLE_ADMIN,), one=True)
    except sqlite3.OperationalError:
        return 0
    return int(row["n"] or 0) if row else 0


def get_user(uid):
    """按 id 取账号（**含** password 列，只给 `check_login` 用；不要进模板）。"""
    row = db._query("SELECT * FROM users WHERE id=?", (int(uid),), one=True)
    return dict(row) if row else None


def get_by_name(username):
    """按用户名取账号（**含** password 列）。用户名大小写敏感 —— 登录时不猜。"""
    row = db._query("SELECT * FROM users WHERE username=?", (str(username or "").strip(),), one=True)
    return dict(row) if row else None


def list_users():
    """全部账号（不含口令哈希），按 id 升序。"""
    return [dict(r) for r in db._query(f"SELECT {_USER_COLUMNS} FROM users ORDER BY id")]


def create_user(username, password, role=ROLE_USER, must_change=True):
    """建账号，返回 `(ok, 用户名或错误提示)`。

    `must_change=True`（默认）＝ 首次登录必须改口令：管理员给队友建号时**一定知道**那个
    初始口令，不改就等于这个口令长期有效且被第二个人掌握。
    """
    ok, msg = validate_username(username)
    if not ok:
        return False, msg
    ok, msg = validate_password(password, username)
    if not ok:
        return False, msg
    name = str(username or "").strip()
    role = role if role in ROLES else ROLE_USER
    if get_by_name(name):
        return False, f"用户名「{name}」已存在"
    db._exec("INSERT INTO users(username, password, role, enabled, must_change, "
             "created_at, updated_at, last_login_at) VALUES(?,?,?,?,?,?,?,?)",
             (name, hash_password(password), role, 1, 1 if must_change else 0,
              _now(), _now(), ""))
    return True, name


def set_password(uid, password, must_change=False):
    """改口令（管理员重置 / 本人自助改密共用）。返回 `(ok, 提示)`。"""
    ok, msg = validate_password(password)
    if not ok:
        return False, msg
    db._exec("UPDATE users SET password=?, must_change=?, updated_at=? WHERE id=?",
             (hash_password(password), 1 if must_change else 0, _now(), int(uid)))
    return True, "口令已更新"


def set_enabled(uid, enabled):
    """启用 / 停用账号（停用后其现有会话在下一个请求即被踢下线，见 `gui.app._session_user`）。"""
    db._exec("UPDATE users SET enabled=?, updated_at=? WHERE id=?",
             (1 if enabled else 0, _now(), int(uid)))


def set_role(uid, role):
    """改角色；非法角色值一律降级为 `user`（不抛，也不静默当管理员）。"""
    db._exec("UPDATE users SET role=?, updated_at=? WHERE id=?",
             (role if role in ROLES else ROLE_USER, _now(), int(uid)))


def set_must_change(uid, must_change):
    db._exec("UPDATE users SET must_change=?, updated_at=? WHERE id=?",
             (1 if must_change else 0, _now(), int(uid)))


def delete_user(uid):
    db._exec("DELETE FROM users WHERE id=?", (int(uid),))


def touch_login(uid):
    """记录最近登录时刻（页面「账号」页展示；不记 IP —— 本机场景没意义，也不想存）。"""
    db._exec("UPDATE users SET last_login_at=? WHERE id=?", (_now(), int(uid)))


def check_login(username, password):
    """校验「用户名 + 口令」，通过返回账号 dict（**不含** password 列），否则 None。

    失败时**不区分**"用户名不存在 / 口令错 / 已停用"给调用方 —— 页面统一显示
    "用户名或口令错误"（停用是唯一需要另说一句的情形，由调用方按 `enabled` 判断）。
    """
    row = get_by_name(username)
    if not row:
        _dummy_verify(password)
        return None
    if not verify_password(row.get("password") or "", password):
        return None
    row.pop("password", None)
    return row
