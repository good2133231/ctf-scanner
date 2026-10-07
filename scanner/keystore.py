"""`config/keys.yaml` 的口令加密（续98）。

**要解决什么**：第三方凭据（FOFA / Shodan / Quake / GitHub PAT）原先是本机明文 YAML，
只靠 `.gitignore` 不进仓库。用户要求"配置里加密、程序里解密"，这里实现的是**口令派生密钥 +
AES-GCM 认证加密落盘**：`config/keys.enc.yaml`。

**先把话说清楚（别把这一节当装饰）**：
1. 口令**不存盘**。它要么由人在启动时输入，要么由部署环境注入 `CTFSCANNER_KEYS_PASSPHRASE`。
   一旦把口令写进仓库、settings.yaml、systemd unit 或任何本机文件，这套加密就**退化成混淆** ——
   攻击者能读的文件他也就能读密钥，安全性归零。所以本模块**刻意不提供**"把口令存起来免输入"。
2. 解锁后明文必然在进程内存里（`current()` 返回的就是明文 dict）。防的是"文件被拷走/被同步上云"，
   不防"进程内存被 dump"。
3. 密文用 AESGCM（认证加密）：改一个 bit 都会解不开，所以"文件被动过"和"口令错"是同一件事 ——
   都只报 `口令不对或文件已损坏`，不假装能区分。算法与 KDF 全部走 `cryptography`，
   **不自研任何密码学原语**。

**与并发的那条硬约束**：`config.load_settings()` 会被工作线程、GUI 每个请求、分布式节点反复调用，
所以 `load_keys()` **绝不能在这里要口令** —— 它只读 `current()`（未解锁就返回 `{}`）。
解锁只在**进程启动时**由入口显式调一次 `unlock()`（`gui.serve()` / `cli` 扫描入口 / `run_node.py`）。
非交互环境（CI、`python -c`、被强接管 stdin 的自动化）**不提示、不挂住**，直接回未解锁。
"""
import base64
import getpass
import hashlib
import os
import sys
import tempfile
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
ENC_KEYS_PATH = BASE_DIR / "config" / "keys.enc.yaml"
PLAIN_KEYS_PATH = BASE_DIR / "config" / "keys.yaml"
ENV_PASSPHRASE = "CTFSCANNER_KEYS_PASSPHRASE"

_MAGIC = b"CTFSCANNER-KEYS-V1\x00"
_SALT_LEN = 16
_NONCE_LEN = 12
_KDF_ITERS = 600_000      # PBKDF2-HMAC-SHA256；启动解一次，成本 ~0.3s 换"拷走文件解不开"
_KEY_LEN = 32

# 进程内缓存：口令只在启动时输一次，之后所有 load_settings() 复用同一份明文。
_STATE = {"unlocked": False, "data": None, "reason": "", "source": ""}


def _crypto():
    """延迟导入 `cryptography`：没装它时，**明文老路照走**，只有密文文件才会如实报错。"""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        return None
    return AESGCM


def _derive(passphrase, salt):
    return hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, _KDF_ITERS, _KEY_LEN)


def is_encrypted(path=None):
    """文件存在且带我们的魔数头 —— 只按头部判，不猜、不解密。"""
    p = Path(path if path is not None else ENC_KEYS_PATH)
    if not p.exists():
        return False
    try:
        with p.open("rb") as fh:
            return fh.read(len(_MAGIC)) == _MAGIC
    except OSError:
        return False


def encrypt_text(text, passphrase):
    """明文 YAML 文本 + 口令 → 完整密文 blob（含魔数/盐/nonce）。失败抛异常（调用方是 CLI，可以抛）。"""
    aesgcm_cls = _crypto()
    if aesgcm_cls is None:
        raise RuntimeError("未安装 cryptography，无法加密凭据文件：python -m pip install cryptography")
    if not passphrase:
        raise ValueError("口令不能为空")
    salt = os.urandom(_SALT_LEN)
    nonce = os.urandom(_NONCE_LEN)
    ct = aesgcm_cls(_derive(passphrase, salt)).encrypt(nonce, text.encode("utf-8"), _MAGIC)
    return _MAGIC + salt + nonce + ct


def decrypt_blob(blob, passphrase):
    """密文 blob + 口令 → 明文字符串；任何失败都**返回 (None, 原因)**，不抛（解锁路径不许炸）。"""
    aesgcm_cls = _crypto()
    if aesgcm_cls is None:
        return None, "未安装 cryptography（pip install cryptography），无法读取加密凭据文件"
    if not isinstance(blob, (bytes, bytearray)) or len(blob) <= len(_MAGIC) + _SALT_LEN + _NONCE_LEN:
        return None, "密文文件太短或形态不对（不是本模块写的 V1 格式）"
    if bytes(blob[:len(_MAGIC)]) != _MAGIC:
        return None, "文件头不是 CTFSCANNER-KEYS-V1（不是本模块生成的密文）"
    body = bytes(blob[len(_MAGIC):])
    salt, nonce, ct = body[:_SALT_LEN], body[_SALT_LEN:_SALT_LEN + _NONCE_LEN], body[_SALT_LEN + _NONCE_LEN:]
    try:
        plain = aesgcm_cls(_derive(passphrase, salt)).decrypt(nonce, ct, _MAGIC)
    except Exception:
        # 不区分"口令错"与"文件被改"：AESGCM 的认证标签两者都拒。报成一条，不猜。
        return None, "口令不对或文件已损坏（认证加密校验未通过）"
    try:
        return plain.decode("utf-8"), ""
    except UnicodeDecodeError:
        return None, "解密成功但内容不是 UTF-8（文件被别的程序改写过）"


def write_encrypted(dst, blob):
    """原子落盘（同目录 .part + `os.replace`），并把权限收到 600（POSIX）。"""
    dst = Path(dst)
    dst.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".keys-enc-", dir=str(dst.parent))
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(blob)
        try:
            os.chmod(tmp, 0o600)        # Windows 上没有 POSIX 位，失败只跳过（NTFS 用 ACL）
        except OSError:
            pass
        os.replace(tmp, str(dst))
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return dst


def _parse(text):
    import yaml
    data = yaml.safe_load(text) or {}
    return data if isinstance(data, dict) else {}


def _prompt(src):
    """只有**真有 TTY** 才提示。非交互（CI / 管道 / 自动化）一律直接返回未解锁 —— 绝不允许挂住。

    reason 只写**原因**，结论交给 `lock_notice()` 组一次。原因里再夹一句结论会出什么事：
    三个启动入口（GUI / CLI / 节点）各自又拼了一遍前缀与后缀，实测 GUI 启动日志长这样 ——
    `凭据保持锁定：非交互环境且未设置 …—— 凭据保持锁定（外部情报源按"无 key"…）（外部情报源将按"无 key"…）`
    同一句说了两遍，还带两种措辞（"按"与"将按"），提示文本自己变成噪音源。
    """
    if not sys.stdin.isatty():
        return None, "非交互环境且未设置 " + ENV_PASSPHRASE
    try:
        got = getpass.getpass("CTFScanner 凭据口令（config/keys.enc.yaml 解锁）：")
    except (EOFError, KeyboardInterrupt):
        return None, "输入被取消"
    if not got:
        return None, "空口令"
    return got, ""


def lock_notice(reason=None):
    """把"锁定"组成**一句**完整的话；三个启动入口共用，别再各自拼前缀后缀。"""
    r = (_STATE["reason"] if reason is None else reason) or "未输入口令"
    return f"凭据保持锁定：{r}（外部情报源按\"无 key\"如实降级，其余阶段不受影响）"


def unlock(passphrase=None, path=None):
    """启动时调一次：把密文解进进程缓存。返回 `{"ok", "reason", "source"}`，**永不抛**。

    口令来源优先级：显式参数 > `CTFSCANNER_KEYS_PASSPHRASE` > 交互提示。
    没有密文文件时：若还有明文 `keys.yaml`，保持锁定但让 `current()` 走明文老路（向后兼容），
    并在 reason 里如实写"未启用加密"。
    """
    path = Path(path if path is not None else ENC_KEYS_PATH)
    if not path.exists():
        _STATE.update(unlocked=False, data=None, source="absent",
                      reason="没有加密凭据文件（沿用明文 keys.yaml，如有）")
        return {"ok": False, "reason": _STATE["reason"], "source": "absent"}
    given = passphrase if passphrase else os.environ.get(ENV_PASSPHRASE, "")
    source = "arg" if passphrase else ("env" if given else "prompt")
    if not given:
        given, why = _prompt(source)
        if given is None:
            _STATE.update(unlocked=False, data=None, source=source, reason=why)
            return {"ok": False, "reason": why, "source": source}
    try:
        blob = path.read_bytes()
    except OSError as e:
        _STATE.update(unlocked=False, data=None, source=source, reason=f"读取密文失败：{e}")
        return {"ok": False, "reason": _STATE["reason"], "source": source}
    text, why = decrypt_blob(blob, given)
    if text is None:
        _STATE.update(unlocked=False, data=None, source=source, reason=why)
        return {"ok": False, "reason": why, "source": source}
    try:
        data = _parse(text)
    except Exception as e:
        _STATE.update(unlocked=False, data=None, source=source, reason=f"解密成功但 YAML 解析失败：{e}")
        return {"ok": False, "reason": _STATE["reason"], "source": source}
    _STATE.update(unlocked=True, data=data, source=source, reason="")
    return {"ok": True, "reason": "", "source": source}


def current():
    """给 `config.load_keys()` 用：**只读缓存，绝不提示、绝不抛**。未解锁就返回 `{}`。"""
    if _STATE["unlocked"] and isinstance(_STATE["data"], dict):
        return _STATE["data"]
    return {}


def status(path=None):
    """给 GUI/诊断用的安全摘要 —— 只有布尔与原因，不含口令、不含任何 key 值。"""
    path = Path(path if path is not None else ENC_KEYS_PATH)
    return {"encrypted": path.exists(), "unlocked": bool(_STATE["unlocked"]),
            "reason": _STATE["reason"], "source": _STATE["source"],
            "plaintext_left": PLAIN_KEYS_PATH.exists(),
            "crypto_available": _crypto() is not None}


def reset():
    """测试与"换口令后重载"用：清掉进程内明文缓存。"""
    _STATE.update(unlocked=False, data=None, reason="", source="")


def mask(value):
    """把口令/密文压成可安全打印的形状（长度 + 指纹前 8 位），**永不含原文**。"""
    if not value:
        return "(空)"
    raw = value.encode("utf-8") if isinstance(value, str) else bytes(value)
    return f"{len(raw)} 字符 / sha256:{hashlib.sha256(raw).hexdigest()[:8]}"


def b64(text):
    """CLI 里把密文交给用户的可复制形态（迁移时 scp 之外也能贴过去）。"""
    return base64.b64encode(text).decode("ascii") if isinstance(text, (bytes, bytearray)) else ""
