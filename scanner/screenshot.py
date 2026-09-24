"""站点截图：调用本机已有的无头浏览器给存活站点截图（只读 GET，非破坏性）。

设计取舍：
- **不引入新依赖**（不装 playwright/selenium）：直接用系统里已装好的
  Edge / Chrome 的 `--headless --screenshot` 能力，跨平台可用；
- **浏览器位置怎么找**（遵守 `AGENTS.md` §0：代码里不写本机绝对路径）：
  ① 先看配置 `screenshot.browser`（用户可在 settings.yaml 里填绝对路径）；
  ② 再 `shutil.which()` 探测常见命令名（`msedge` / `chrome` / `chromium` / `google-chrome`…）；
  ③ 最后用**环境变量 + 相对子路径**拼出标准安装位置（`%PROGRAMFILES%\\Microsoft\\Edge\\…` 这类），
     代码里只有相对片段，没有硬编码的盘符/用户名。
- **不碰用户的浏览器配置**：每次截图都用临时 `--user-data-dir`，跑完即删；
- 截图失败只记一行日志（截图是"锦上添花"，不该拖垮流水线）。
"""
import os
import shutil
import tempfile
from pathlib import Path

from .utils import run_cmd

# 命令名（PATH 里能找到就用）
_CMD_NAMES = ("msedge", "chrome", "chromium", "google-chrome", "chromium-browser",
              "chrome.exe", "msedge.exe")

# 标准安装位置：环境变量 + 相对子路径（**不含任何硬编码绝对路径**）
_REL_CANDIDATES = (
    ("PROGRAMFILES", r"Microsoft\Edge\Application\msedge.exe"),
    ("PROGRAMFILES(X86)", r"Microsoft\Edge\Application\msedge.exe"),
    ("PROGRAMFILES", r"Google\Chrome\Application\chrome.exe"),
    ("PROGRAMFILES(X86)", r"Google\Chrome\Application\chrome.exe"),
    ("LOCALAPPDATA", r"Google\Chrome\Application\chrome.exe"),
    ("LOCALAPPDATA", r"Microsoft\Edge\Application\msedge.exe"),
    ("PROGRAMFILES", "Microsoft/Edge/Application/msedge.exe"),
    ("PROGRAMFILES(X86)", "Microsoft/Edge/Application/msedge.exe"),
    ("PROGRAMFILES", "Google/Chrome/Application/chrome.exe"),
)


# Windows 注册表里的标准登记位置（App Paths）：系统级"这个程序装在哪"的权威来源，
# 代码里不出现任何盘符/用户名（`winreg` 是标准库，非 Windows 上直接跳过）。
_REG_KEYS = (
    (r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\msedge.exe", None),
    (r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\chrome.exe", None),
    (r"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\App Paths\\msedge.exe", None),
    (r"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\App Paths\\chrome.exe", None),
)


def _from_registry():
    try:
        import winreg  # noqa: WPS433 （仅 Windows 有）
    except ImportError:
        return ""
    for sub, _ in _REG_KEYS:
        for root in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
            try:
                with winreg.OpenKey(root, sub) as key:
                    path, _typ = winreg.QueryValueEx(key, "")
                if path and Path(str(path)).exists():
                    return str(path)
            except OSError:
                continue
    return ""


def browser_path(settings=None):
    """返回可用的无头浏览器路径；找不到返回 ""。"""
    cfg = (settings or {}).get("screenshot", {}) or {}
    configured = str(cfg.get("browser") or "").strip()
    if configured:
        return configured if Path(configured).exists() or shutil.which(configured) else ""
    for name in _CMD_NAMES:
        found = shutil.which(name)
        if found:
            return found
    found = _from_registry()
    if found:
        return found
    for env_key, rel in _REL_CANDIDATES:
        base = os.environ.get(env_key)
        if not base:
            continue
        candidate = Path(base) / rel
        if candidate.exists():
            return str(candidate)
    return ""


def available(settings=None):
    return bool(browser_path(settings))


def capture(url, out_path, settings=None, timeout=30, throttle=None):
    """给单个 URL 截图，写入 `out_path`。返回 `(ok, err)`。

    `throttle`（F2）：传入时这次子进程调用占一个 `"subprocess"` 名额（并消耗预算）。
    """
    binary = browser_path(settings)
    if not binary:
        return False, "未找到可用的无头浏览器（Edge/Chrome）；可在策略配置里填 screenshot.browser"
    cfg = (settings or {}).get("screenshot", {}) or {}
    size = str(cfg.get("window") or "1280x900").replace(" ", "")
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_profile = tempfile.mkdtemp(prefix="ctfscan-shot-")
    try:
        argv = [
            binary,
            "--headless=new",
            "--disable-gpu",
            "--hide-scrollbars",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-extensions",
            f"--user-data-dir={tmp_profile}",     # 隔离：不碰用户真实浏览器配置
            f"--window-size={size}",
            f"--screenshot={out_path}",
            str(url),
        ]
        rc, _out, err = run_cmd(argv, timeout=int(timeout or 30), throttle=throttle)
        if out_path.exists() and out_path.stat().st_size > 0:
            return True, ""
        return False, (err or f"退出码 {rc}")[:200]
    except Exception as e:                        # 兜底：截图失败绝不影响主流程
        return False, str(e)[:200]
    finally:
        shutil.rmtree(tmp_profile, ignore_errors=True)


def shot_name(url):
    """由 URL 生成稳定的截图文件名（同一 URL 多次截图会覆盖，不堆垃圾）。"""
    import hashlib
    digest = hashlib.md5(str(url).encode("utf-8", "replace")).hexdigest()[:12]
    return f"{digest}.png"
