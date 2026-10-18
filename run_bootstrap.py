"""迁移自举：换机器时一次点清"这台机器还缺什么"，能自动装的装上，不能的给命令。

用法：``python run_bootstrap.py``（等价 ``python cli/client.py --bootstrap``）
退出码：0＝缺口为零、或自动层全部补齐；1＝自动层里有项失败。

**为什么要单独一个入口**：本项目跨 Windows / Linux 两端，而"迁移后要不要动手装东西"的答案
散在三处 —— `cli --check` 只看外部工具在不在 PATH、`scanner/toolmgr.py` 只管
subfinder/httpx/puredns、`requirements.txt` 得自己记得 `pip install`；至于"这台机器该用 apt
还是 winget、fscan 要 Go 自编译、截图必须有浏览器"这些平台差异，没有任何一处汇总过。
本脚本把三者串成一次调用，并把结果按"能自动 / 只能手工"两栏如实分开。

**四条红线（沿用 `scanner/toolmgr.py` 的纪律，改本文件前先读完）**：

1. **只在显式触发时联网**：只有带 `--install` 才下载（含 `.venv` 缺 pip 时取的官方
   `get-pip.py`）；`probe()` 本身零网络（只读文件系统 + `shutil.which`）。扫描期任何阶段都不
   得调用本模块 —— 因此它**放在仓库根、刻意不进 `scanner/`
   包**：`tests/smoke.py [7p]` 钉的是"scanner 包内不得引用 toolmgr"，把本模块塞进 `scanner/`
   就得给那条红线开豁免，等于把红线削弱一次。
2. **自动层的边界＝三样**：① 建项目内 `.venv`（`python -m venv` 失败就退到 `--without-pip` +
   官方 `get-pip.py` 引导 —— Ubuntu/Debian 把 ensurepip 拆进 `python3.x-venv` 包，这是常态）；
   ② pip 装依赖：有 `requirements.lock` 且当前解释器预检装得动就吃 lock，否则回落
     `requirements.txt` —— **两种情况都会把"这次吃了哪一份"打进输出**（见 `pick_requirements_file()`）；
   ③ `toolmgr.update()`（官方产物 + **SHA256 校验过**才落盘）。摘要有两个产地：release 自带的
     checksums 文件，或本框架替某个工具人工核过、钉在 `scanner/toolmgr.py` 里的那份摘要 ——
     puredns 官方不发 checksums，走的正是第二条（续164：否则 `./install.sh` 在任何新克隆上都必然
     非 0，而"钉摘要"不是松绑，字节仍必须一字不差，且只装 `pin_version` 那一版）。
   取 get-pip 用的是**另一套同纪律但独立**的白名单（只 `https://bootstrap.pypa.io` +
   大小上限）—— 刻意不复用 `toolmgr.download_bytes`，把该主机塞进 toolmgr 的白名单等于为了
   一个安装脚本去放宽那条校验红线。
   `toolmgr.MANUAL` 的 nmap / fscan / dirmap / massdns **一条请求都不发、一条命令都不代跑**：它们要么
   要装进系统目录（apt / 安装器 / dmg，需要 root），要么要用 Go 自编译 —— 代跑就是越
   "系统级动作"的界，还会绕过那条校验和红线。这里只**按平台打印**命令，由用户复制执行。
3. **只出现相对路径**（项目硬规矩）：打印的路径一律相对项目根（`tools/scanner/…`）；
   平台口径只有 `toolmgr.host_arch()` 一处，本文件不另写一份平台分支。
4. **写回只有一条路**：装完工具仍走 `toolmgr` 的逐行替换改 `tools.<名>`；本脚本不改写
   明文 `config/keys.yaml`（只在还没有密文时**读一次**用于合并），也不整份重写
   `config/settings.yaml`。安装末尾的凭据录入把用户输入交给 `cli.run_keys.main(
   ["--encrypt", …])`（进程内调用，合并/自校验/落盘都复用那一份；不另起子进程），临时明文放
   系统临时目录、`--shred` 删掉，绝不写进仓库。
"""
import argparse
import getpass
import importlib.util
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent

# CI（.github/workflows/smoke.yml）与 Dockerfile 的口径都是 3.9：低于它直接判"跑不了"，
# 高于它只是"没在 CI 上验证过"（如实提示，不当错误）。
PY_MIN = (3, 9)
PY_CI = (3, 9)

# 一键就绪用的虚拟环境（`.gitignore` 已排除，不会脏仓库）
VENV_DIR = ".venv"
# Ubuntu/Debian 把 ensurepip 拆进 python3.x-venv 包 → 系统解释器常常 `python -m venv` 直接失败，
# 而用户的要求是"一上来就能运行"，所以这里自己引导 pip（官方 get-pip.py），不碰系统包。
GET_PIP_URL = "https://bootstrap.pypa.io/get-pip.py"
_GET_PIP_HOSTS = frozenset({"bootstrap.pypa.io"})
_MAX_PIP_BYTES = 8 * 1024 * 1024
_UA = "CTFScanner-bootstrap/0.1 (+authorized-testing-only)"
REEXEC_ENV = "CTFSCANNER_BOOTSTRAP_REEXEC"

# 依赖清单分两层（各自的分工写在文件头里）：`requirements.txt` ＝ 声明"我要什么"（开区间），
# `requirements.lock` ＝ 钉"这次实测装出来的是哪些版本"（含全部传递依赖的 `==`）。
# 自动层优先吃 lock，装不动就回落 txt —— 但**这次到底吃了哪一份一定要印出来**。
REQ_TXT = "requirements.txt"
REQ_LOCK = "requirements.lock"

# requirements.txt 里的分发名 → 可 import 的模块名（本项目只有 PyYAML 这一个不一致）
_IMPORT_ALIAS = {"pyyaml": "yaml"}

# 每平台候选包管理器，顺序＝推荐优先级；探测只 `shutil.which`，不发任何请求。
_MANAGER_CANDIDATES = {
    "linux": ("apt-get", "dnf", "yum", "pacman", "zypper", "apk", "snap"),
    "macOS": ("brew", "port"),
    "windows": ("winget", "choco", "scoop"),
}
_MANAGER_INSTALL = {
    "apt-get": "sudo apt-get install -y {pkg}",
    "dnf": "sudo dnf install -y {pkg}",
    "yum": "sudo yum install -y {pkg}",
    "pacman": "sudo pacman -S --noconfirm {pkg}",
    "zypper": "sudo zypper install -y {pkg}",
    "apk": "sudo apk add {pkg}",
    "snap": "sudo snap install {pkg}",
    "brew": "brew install {pkg}",
    "port": "sudo port install {pkg}",
    "winget": "winget install -e --id {pkg}",
    "choco": "choco install -y {pkg}",
    "scoop": "scoop install {pkg}",
}
# 同一个东西在各包管理器下的名字（不同才需要登记；nmap 只有 winget 要写包 ID）。
# 某些包在特定平台上只有某个管理器有"真包"，探测到时优先选它。
_PKG_PREFERRED = {"chromium": ("snap", "flatpak")}

_PKG_NAME = {
    "nmap": {"winget": "Insecure.Nmap"},
    "chromium": {"winget": "Google.Chrome", "choco": "googlechrome"},
    "golang": {"apt-get": "golang", "dnf": "golang", "yum": "golang", "brew": "go",
               "pacman": "go", "zypper": "go", "apk": "go", "winget": "GoLang.Go",
               "choco": "golang", "scoop": "go"},
    # 中文字体各发行版命名不一。**只有 apt 那条在本机实测过**（续103，Ubuntu 26.04），
    # 其余按各家既定命名登记、未逐一验证 —— 装不上时 `install_system_packages` 会如实落成失败项，
    # 不会假装成功。snap/brew/winget 没有对等包，所以另用 _PKG_MANAGERS 把它们挡在门外。
    "fonts-noto-cjk": {"apt-get": "fonts-noto-cjk", "dnf": "google-noto-sans-cjk-fonts",
                       "yum": "google-noto-sans-cjk-fonts", "pacman": "noto-fonts-cjk",
                       "zypper": "noto-fonts-cjk", "apk": "font-noto-cjk"},
}

# 某些包**只有部分**包管理器有对等包：登记过的才允许生成命令，其余一律返回空（不猜命令）。
_PKG_MANAGERS = {"fonts-noto-cjk": ("apt-get", "dnf", "yum", "pacman", "zypper", "apk")}


def package_managers(os_label):
    """本机可用的包管理器（只查 PATH）。"""
    return [m for m in _MANAGER_CANDIDATES.get(os_label or "", ()) if shutil.which(m)]


def platform_info():
    """`(os_label, arch, managers)` —— 平台判定只走 `toolmgr.host_arch()` 这一处。"""
    from scanner import toolmgr
    os_label, arch = toolmgr.host_arch()
    return os_label, arch, package_managers(os_label)


def _order(managers, pkg):
    """把该包"只有真包的那个管理器"提到最前（Ubuntu ≥24 的 chromium 只在 snap 里，apt 那边是
    `2:1snap1` 过渡壳 —— 按 apt 的名字生成命令会装到一个没有候选的空壳）。"""
    prio = [m for m in _PKG_PREFERRED.get(pkg, ()) if m in managers]
    return prio + [m for m in managers if m not in prio]


def pkg_cmd(pkg, managers):
    """用第一个可用包管理器生成安装命令；一个都没有时返回 `[]`（**不猜命令**）。

    `_PKG_MANAGERS` 里登记过的包，只允许对登记过的管理器生成命令 —— 没对等包的管理器
    （snap 上没有 `fonts-noto-cjk`、brew 上没有 `git` 之外的同名包那类）生成出来就是**装不上**
    的命令，宁可返回空让清单去说明"该平台未登记包名"。
    """
    allow = _PKG_MANAGERS.get(pkg)
    for mgr in _order(list(managers), pkg):
        if allow is not None and mgr not in allow:
            continue
        tmpl = _MANAGER_INSTALL.get(mgr)
        if tmpl:
            return [tmpl.format(pkg=_PKG_NAME.get(pkg, {}).get(mgr, pkg))]
    return []


def pkg_argv(pkg, managers):
    """`pkg_cmd` 的**列表形态**：给 `--with-system` 真执行用（argv + `shell=False`，永不走 shell）。"""
    cmds = pkg_cmd(pkg, managers)
    return cmds[0].split() if cmds else []


# ---------- 虚拟环境：让"一上来就能运行"成立 ----------

def venv_python(root=None, windows=None):
    """venv 里的解释器路径。`windows=None` 按本机判；显式传 True/False 供测试两端都验。"""
    root = Path(root) if root is not None else ROOT
    if windows is None:
        windows = os.name == "nt"
    return root / VENV_DIR / ("Scripts" if windows else "bin") / ("python.exe" if windows else "python")


def in_venv():
    return sys.prefix != sys.base_prefix


def _check_pip_url(url):
    """get-pip 的下载纪律与 `toolmgr` 同源：只允许 https + 固定主机；大小有上限。

    刻意不复用 `toolmgr.download_bytes` —— 它的主机白名单只有 GitHub，把 `bootstrap.pypa.io`
    塞进去等于为了一个安装脚本去放宽那条校验红线。
    """
    parts = urllib.parse.urlsplit(url)
    host = (parts.hostname or "").lower()
    if parts.scheme != "https" or host not in _GET_PIP_HOSTS:
        raise RuntimeError(f"只允许从 {'、'.join(sorted(_GET_PIP_HOSTS))} 取 get-pip.py（https）")
    return host


def _bootstrap_pip(py, venv_dir):
    """在给定解释器里引导 pip（官方 get-pip.py，用完即删）。返回 `(ok, 说明)`，不抛。"""
    try:
        got = _fetch_get_pip(venv_dir / "get-pip.py")
        try:
            run = subprocess.run([str(py), str(venv_dir / "get-pip.py")], capture_output=True, text=True)
        finally:
            (venv_dir / "get-pip.py").unlink(missing_ok=True)
    except Exception as e:
        return False, f"取 get-pip.py 失败：{e}"
    if run.returncode != 0:
        tail = ((run.stderr or run.stdout or "").strip().splitlines() or ["无输出"])[-1]
        return False, f"get-pip 引导失败：{tail[:160]}"
    return True, f"已用官方 get-pip.py 引导 pip（下载 {got} 字节）"


def _fetch_get_pip(dst):
    """取官方 get-pip.py 到 dst（边收边判上限）。返回写入的字节数。"""
    _check_pip_url(GET_PIP_URL)
    req = urllib.request.Request(GET_PIP_URL, headers={"User-Agent": _UA})
    with urllib.request.urlopen(req, timeout=120) as resp:
        data = resp.read(_MAX_PIP_BYTES + 1)
    if len(data) > _MAX_PIP_BYTES:
        raise RuntimeError(f"get-pip.py 超过 {_MAX_PIP_BYTES} 字节上限，拒绝使用")
    Path(dst).write_bytes(data)
    return len(data)


def _pip_env():
    """跑 pip 时该带的 env：把下载缓存收进仓库内（**唯一产地**是 `toolmgr.cache_path`）。

    为什么要它：pip 默认写 `~/.cache/pip`（Windows 是 `%LOCALAPPDATA%\\pip\\cache`）—— "装一个
    项目却在家目录留一坨"正是本轮要消掉的形状（Go 那侧同一口径，见 `toolmgr.go_env`）。
    `PIP_NO_INPUT=1` 一并给上：自举可能在无终端环境跑，交互式提问会挂住。
    """
    from scanner import toolmgr
    env = dict(os.environ)
    env["PIP_CACHE_DIR"] = str(toolmgr.cache_path("pip"))
    env["PIP_NO_INPUT"] = "1"
    return env


def ensure_venv(root=None):
    """把项目内 `.venv` 建起来并保证里面有 pip。**幂等**：已可用就复用，绝不重建覆盖。

    返回 `(ok, 说明)`，**任何失败都不抛** —— 自动层要如实报"这步没成"，而不是把调用方崩掉。
    `python -m venv` 失败时退到 `--without-pip` + 官方 `get-pip.py` 引导：这正是 Ubuntu/Debian
    上系统解释器的常态（ensurepip 被拆进 `python3.x-venv` 包），而用户要的是一句命令就能跑，
    不该先逼人去装系统包。
    """
    root = Path(root) if root is not None else ROOT
    venv_dir = root / VENV_DIR
    py = venv_python(root)
    pre_existed = venv_dir.exists()          # 只有"本次新建的半成品"才敢删，见下面
    if py.exists():
        if subprocess.run([str(py), "-m", "pip", "--version"],
                          capture_output=True, text=True, env=_pip_env()).returncode == 0:
            return True, f"复用 {VENV_DIR}（pip 可用）"
        ok, msg = _bootstrap_pip(py, venv_dir)
        return ok, (msg if not ok else f"{VENV_DIR} 已存在但缺 pip → {msg}")
    created = subprocess.run([sys.executable, "-m", "venv", str(venv_dir)],
                             capture_output=True, text=True)
    if created.returncode == 0:
        return True, f"已创建 {VENV_DIR}"
    # 建 venv 失败（ensurepip 缺失是常态）。**只清自己刚建的**：调用前目录就存在的话，
    # 里面可能是用户自己的东西（哪怕坏掉），删它就是破坏用户数据 —— 改成如实报并让他决定。
    if not pre_existed and (venv_dir / "pyvenv.cfg").exists():
        shutil.rmtree(venv_dir, ignore_errors=True)
    elif pre_existed:
        return False, (f"{VENV_DIR} 已存在但没有可用解释器，且 `python -m venv` 失败 —— "
                       f"不删目录（里面可能是你自己的东西），请手工检查或删掉 {VENV_DIR} 后重试")
    again = subprocess.run([sys.executable, "-m", "venv", "--without-pip", str(venv_dir)],
                           capture_output=True, text=True)
    if again.returncode != 0:
        tail = ((again.stderr or again.stdout or "").strip().splitlines() or ["无输出"])[-1]
        return False, f"创建 {VENV_DIR} 失败：{tail[:160]}"
    if not py.exists():
        return False, f"{VENV_DIR} 建好了但找不到解释器（结构非预期，不猜测路径）"
    ok, msg = _bootstrap_pip(py, venv_dir)
    return ok, (msg if ok else f"{VENV_DIR} 已建但 pip 引导失败：{msg}")


def rerun_in_venv(argv=None, root=None):
    """用 `.venv` 的解释器把本脚本**重跑一遍**（依赖才会装进 venv 而不是系统解释器）。

    返回子进程退出码；没建成 venv 或已在 venv 里 → 返回 `None` 让调用方继续就地执行。
    `REEXEC_ENV` 防递归：子进程带着它，绝不会再套一层。
    """
    if in_venv() or os.environ.get(REEXEC_ENV):
        return None
    py = venv_python(root)
    if not py.exists():
        return None
    env = dict(os.environ, **{REEXEC_ENV: "1"})
    sys.stdout.flush()          # 不 flush 的话，管道里父进程的提示会排到子进程输出之后
    run = subprocess.run([str(py), str(ROOT / "run_bootstrap.py")] + list(argv or sys.argv[1:]), env=env)
    return run.returncode


def _dist_names(text):
    """从一份 requirements 风格的**文本**里取分发名（忽略注释/空行与 marker；不比版本约束）。"""
    out = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            out.append(re.split(r"[<>=!~\[\s;]", line, maxsplit=1)[0].strip())
    return [n for n in out if n]


def _norm_dist(name):
    """分发名归一（`importlib-metadata` 与 `importlib_metadata` 是同一个包）。"""
    return (name or "").lower().replace("-", "_")


def requirement_names():
    """读 `requirements.txt` 的分发名（忽略注释/空行；只取名字，不比版本约束）。"""
    return _dist_names((ROOT / REQ_TXT).read_text(encoding="utf-8"))


def locked_names():
    """读 `requirements.lock` 的分发名；文件不存在时返回 `[]`（声明层缺席≠报错）。"""
    lock = ROOT / REQ_LOCK
    if not lock.exists():
        return []
    return _dist_names(lock.read_text(encoding="utf-8", errors="replace"))


def pick_requirements_file():
    """自动层这次吃哪一份清单：`requirements.lock`（可复现）或 `requirements.txt`（声明层）。

    选 lock 要同时满足三条：文件在、覆盖得住 `requirements.txt` 的**每一个直接依赖**、
    且**当前解释器真的装得动**（用 `pip install --dry-run` 预检，只解析不落盘）。
    任何一条不满足就回落 `requirements.txt`，并把**回落原因**原样交给调用方打印 ——
    静默换清单与静默降级是同一类毛病，所以"用了哪一份"必须是输出里的一行，不是猜的。
    返回 `(相对路径, 说明)`；路径一律相对项目根（§0 硬规矩 3）。
    """
    want = {_norm_dist(x) for x in requirement_names()}
    have = {_norm_dist(x) for x in locked_names()}
    if not have:
        return REQ_TXT, f"没有 {REQ_LOCK}（只有声明层 {REQ_TXT}）"
    miss = sorted(want - have)
    if miss:
        return REQ_TXT, f"{REQ_LOCK} 里没有这些直接依赖：{'、'.join(miss)}"
    if importlib.util.find_spec("pip") is None:
        return REQ_TXT, "当前解释器没有 pip，无从预检 lock"
    try:
        chk = subprocess.run([sys.executable, "-m", "pip", "install", "--dry-run",
                              "--disable-pip-version-check", "-r", REQ_LOCK],
                             cwd=str(ROOT), capture_output=True, text=True, env=_pip_env())
    except OSError as exc:
        # 预检本身起不来＝"没验证过"，不能当成"验证通过"，回落声明层并说清是哪一步炸的
        return REQ_TXT, f"{REQ_LOCK} 无法预检（{exc}）"
    if chk.returncode != 0:
        tail = (chk.stderr or chk.stdout or "").strip().splitlines()
        return REQ_TXT, (f"当前解释器装不动 {REQ_LOCK}（预检失败）："
                         f"{(tail[-1] if tail else f'rc={chk.returncode}')[:200]}")
    return REQ_LOCK, f"预检通过：当前解释器装得动这 {len(have)} 条精确版本"




# ---------- 系统包层（`--with-system` 才执行） ----------

# 允许自动安装的系统包白名单。信任来自**发行版/snap 自己的包签名与源**，不是我们校验 ——
# 所以这一层与 `toolmgr` 那条"官方 release + SHA256 我们自己验"是**两套信任模型**，
# 也因此刻意**不含 fscan / dirmap**：那两个要 `git clone` + `go build` / pip 装依赖，
# 等于替用户决定"跑一份第三方源码"，这种决定只能由人做（`toolmgr.MANUAL` 同一条理由）。
#
# `fonts-noto-cjk` 在这份名单里的理由（续103）：它不是"锦上添花"，而是**截图取证与中文报告
# 的硬依赖**。无头浏览器缺中文字体时**不报错、照样产出合法 PNG**，只是图里每个汉字都成豆腐块
# —— 实测本机 `fc-list :lang=zh` 命中 0，而 `[7z]` 一直是绿的（它只验"有没有出图、字节数对不对"）。
# 这类"装了工具却不干活、且没有任何失败信号"的形态，与 snap 版 chromium 是同一类坑（见 AGENTS §7），
# 所以必须进自举清单，让迁移后的机器一次装齐。
SYSTEM_PACKAGES = ("nmap", "chromium", "golang", "git", "fonts-noto-cjk")

# 每个包"装没装"的检测口径（只查 PATH / 文件系统，**零网络**）
def snap_confined(path):
    """浏览器是否 snap 版（confinement 让它写不到项目路径与真实 /tmp，截图必然 0 产物）。"""
    norm = str(path or "").replace("\\\\", "/").lower()
    return "/snap/" in norm or norm.startswith("/mnt/@snap/")


# 常见中文字体文件名里的片段（大小写不敏感，比对前去掉 `-` 与 `_`）。
# 为什么按**文件名**扫而不是问 fontconfig：本文件的源码红线是"除 pip 引导外不许起任何子进程"
# （回归 `tests/smoke.py [8d]` 逐处锁 `subprocess.run` 的意图），而 `fc-list` 就是第二个子进程 ——
# 为一条探测开豁免不值当。代价是这判据是**文件名启发式**：字体装了却被 fontconfig 认不出，
# 这里仍会报"有"。所以它只用于"自举清单点不点名"，不参与任何扫描决策。
_CJK_FONT_HINTS = ("notosanscjk", "notoserifcjk", "sourcehansans", "sourcehanserif",
                   "wenquanyi", "wqy", "uming", "ukai", "droidsansfallback",
                   "msyh", "simhei", "simsun", "pingfang", "hiragino", "cjk")

# fontconfig 的默认目录 + 用户级目录（不递归搜全盘，那既不礼貌也慢）
_FONT_DIRS = ("/usr/share/fonts", "/usr/local/share/fonts",
              "/opt/fonts", "~/.fonts", "~/.local/share/fonts",
              # 续175：仓库内字体目录（用户把字体放进来后，安装自检不再报"缺中文字体"）
              str(ROOT / "tools" / "fonts"))


def has_cjk_font():
    """系统里有没有能渲染中文的字体（**零网络、零子进程**：只看字体目录里有没有对得上的文件）。

    Windows 直接算"有" —— 微软雅黑/宋体随系统自带，那边既没有这些目录也没有 fontconfig，
    报缺只会制造噪声。
    """
    if os.name == "nt":
        return True
    for root in _FONT_DIRS:
        base = os.path.expanduser(root)
        if not os.path.isdir(base):
            continue
        for _dirpath, _dirs, files in os.walk(base):
            for fn in files:
                low = fn.lower().replace("-", "").replace("_", "")
                if any(h in low for h in _CJK_FONT_HINTS):
                    return True
    return False


def _pkg_present(pkg, settings=None):
    from scanner.utils import which
    if pkg == "chromium":
        from scanner import screenshot
        return bool(screenshot.browser_path(settings))
    if pkg == "golang":
        return bool(which("go"))
    if pkg == "fonts-noto-cjk":
        return has_cjk_font()
    return bool(which(pkg))


def system_plan(settings=None, os_label=None, managers=None):
    """系统包层的计划：每项 `{name, present, argv, cmd}`；没有可用包管理器时 argv 为空。"""
    if os_label is None or managers is None:
        os_label, _arch, managers = platform_info()
    out = []
    for pkg in SYSTEM_PACKAGES:
        out.append({"name": pkg, "present": _pkg_present(pkg, settings),
                    "argv": pkg_argv(pkg, managers) if os_label in _MANAGER_CANDIDATES else [],
                    "cmd": (pkg_cmd(pkg, managers) or [""])[0]})
    return out


def install_system_packages(plan, with_system=False, assume_yes=False, runner=None):
    """**默认什么都不做**。只有 `with_system=True` 才执行；非交互还必须有 `assume_yes=True`。

    返回 `(executed, refused, failed)`。三条硬约束（回归 `[8d] ⑫` 逐条钉）：
    1. `with_system=False` → 一次 `runner` 都不许调（"脚本里有能力"≠"默认就替你装"）；
    2. 要执行但没有 `assume_yes` 且 stdin 不是 tty → **拒绝并说明**，不挂住等输入；
    3. 执行只用**列表 argv**（`runner` 收到的是 list，永不是字符串）—— 传字符串直接拒，
       防将来有人图省事改成"走 shell"的形态（那是 `[5o]` 的源码红线：这里只许列表 argv）。
    """
    if not with_system:
        return [], [r["name"] for r in plan if not r["present"]], []
    todo = [r for r in plan if not r["present"] and r["argv"]]
    if not todo:
        return [], [], []
    if not assume_yes and not sys.stdin.isatty():
        return [], [r["name"] for r in todo], [
            {"name": "system", "reason": "非交互环境必须显式 --yes 才会执行系统包安装"}]
    if not assume_yes:
        print("[?] 将执行以下系统包安装命令（需要管理员权限；发行版/包管理器自己验签）：")
        for r in todo:
            print(f"      $ {r['cmd']}")
        if input("    确认执行？输入 y 继续，其它一律跳过：").strip().lower() != "y":
            return [], [r["name"] for r in todo], []
    run = runner or (lambda argv: subprocess.run(argv, check=False).returncode)  # install_system_package
    executed, refused, failed = [], [], []
    for r in todo:
        argv = r["argv"]
        if isinstance(argv, str) or not argv or argv != list(argv):
            failed.append({"name": r["name"], "reason": "命令不是 argv 列表，拒绝执行（绝不走 shell）"})
            continue
        print(f"[+] 执行：{r['cmd']}")
        try:
            rc = run(argv)  # install_system_package
        except Exception as e:
            failed.append({"name": r["name"], "reason": f"执行失败：{e}"})
            continue
        if rc == 0:
            executed.append(r["name"])
        else:
            failed.append({"name": r["name"], "reason": f"退出码 {rc}（权限不足？源里没这个包？）"})
    return executed, refused, failed

# ---------- 探测（零网络）----------

def _row(name, kind, auto, status, detail, cmds=()):
    return {"name": name, "kind": kind, "auto": auto, "status": status,
            "detail": detail, "cmds": list(cmds)}


def probe(settings=None):
    """本机环境清单（**一条请求都不发**）。

    每行 `{name, kind, auto, status, detail, cmds}`：`kind` ∈ `runtime` / `auto` / `pending` /
    `manual` / `browser`；`status` ∈ `ok` / `missing` / `warn`；`auto` ＝ "本脚本 `--install` 会不会动它"。
    （`pending` ＝ 在 `toolmgr.TOOLS` 里、能下载能校验，但**扫描路径还没调用它**，见 `toolmgr.wired`。
    续149 起 afrog 已接线 ⇒ `pending` 目前为空集；这一档保留是为了将来再进"能装但没接线"的工具。）
    """
    from scanner import screenshot, toolmgr
    from scanner.config import load_settings, resolve
    from scanner.utils import which

    st = settings or load_settings()
    tools_cfg = st.get("tools", {}) or {}
    os_label, arch, mgrs = platform_info()
    rows = [_row("__platform__", "runtime", False, "ok",
                 f"{os_label}/{arch}｜包管理器：{'、'.join(mgrs) or '未探测到'}")]

    ver = sys.version_info[:3]
    if ver < PY_MIN:
        rows.append(_row("python", "runtime", False, "missing",
                         f"{_dot(ver)} 低于下限 {_dot(PY_MIN)}（跑不了）"))
    else:
        rows.append(_row("python", "runtime", False, "ok",
                         _dot(ver) + ("" if ver[:2] == PY_CI[:2]
                                      else f"（CI 口径是 {_dot(PY_CI)}，本版本未在 CI 验证）")))
    has_pip = importlib.util.find_spec("pip") is not None
    rows.append(_row("pip", "runtime", False, "ok" if has_pip else "missing",
                     "可用" if has_pip else
                     "当前解释器没有 pip（Ubuntu/Debian 把 ensurepip 拆进 python3.x-venv 包）"
                     " —— 自动层会自己建 .venv 并用官方 get-pip.py 引导，不需要装系统包",
                     [] if has_pip else ["python run_bootstrap.py --install"]))
    _venv_hint = f"{VENV_DIR}/{('Scripts' if os.name == 'nt' else 'bin')}/" \
                 f"{'python.exe' if os.name == 'nt' else 'python'}"
    if in_venv():
        rows.append(_row("venv", "runtime", False, "ok", "在虚拟环境里运行", []))
    elif (ROOT / VENV_DIR).exists():
        rows.append(_row("venv", "runtime", False, "warn",
                         f"现在跑在系统解释器上，但 .venv 已就绪 —— 依赖应装进 venv 而不是系统",
                         [f"{_venv_hint} run_gui.py"]))
    else:
        rows.append(_row("venv", "runtime", False, "warn",
                         "系统解释器且没有 .venv —— 自动层会自动建（含 pip 引导）",
                         ["python run_bootstrap.py --install"]))
    for dist in requirement_names():
        mod = _IMPORT_ALIAS.get(dist.lower(), dist.lower().replace("-", "_"))
        found = importlib.util.find_spec(mod) is not None
        rows.append(_row("py:" + dist, "runtime", True, "ok" if found else "missing",
                         "已安装" if found else "未安装（`import scanner.*` 会直接失败）",
                         [] if found else ["python -m pip install -r requirements.txt"]))

    for name in toolmgr.TOOLS:
        # 续119 起：`TOOLS` 里的成员按 `wired()` 再分一档 —— "能自动下载"与"扫描会用到它"是两件事。
        # 没接入扫描路径的标 kind="pending" / auto=False：`--install` 因此**不会**顺手拉它，但清单里
        # 仍然看得见、并给出一条显式命令。续149 起 afrog 已接线 ⇒ 这一档目前为空集。
        _wired = toolmgr.wired(name)
        cur = _rel(which(tools_cfg.get(name, name)))
        insp = toolmgr.inspect(name)
        detail = f"已装 {cur}" if cur else \
            (insp["reason"] or f"未装（本平台产物：{insp['binary']}）")
        if not cur and toolmgr.pin(name)[0]:
            # 钉了版本的工具要说清"装的是哪一版、按什么校验"，否则页面上只写着"未装"，
            # 用户会以为跟另外两个一样是"跟着 latest 装"（实际是装钉住的那一版）。
            detail += f"；本框架钉在 {toolmgr.pin(name)[0]}，按人工核过的产物摘要校验"
        if not cur and not _wired:
            detail += "；框架尚未调用它"
        rows.append(_row(name, "auto" if _wired else "pending", _wired,
                         "ok" if cur else ("missing" if (insp["asset"] and _wired) else "warn"),
                         detail,
                         [] if cur else [f"python cli/client.py --update-tools --tool {name}"]))

    for name in toolmgr.MANUAL:
        rows.append(_manual_row(name, os_label, mgrs, tools_cfg, resolve))

    # 续166：**工作目录内运行时组件**（Go 便携归档 / 上游源码包）。它们既不是 `TOOLS`
    # （不回写 `tools.<名>`、扫描期不调用），也不是 `MANUAL`（`--with-stack` 就能自动取，
    # 不必用户手工做）⇒ 单独一档 `kind="stack"`、`auto=False`（默认 `--install` 不顺手拉
    # 70 MB 的 Go），并且**绝不混进"需手工"那一栏**（混进去就是骗人：它明明能自动取）。
    # `stack_status()` 只看文件系统，一条请求都不发（`[8d]③` 那条"probe 零网络"照样成立）。
    for _stk in toolmgr.stack_status():
        _na168, _why168 = toolmgr.stack_applicable(_stk["name"])
        _rows168 = ([] if _stk["present"] or not _na168
                    else ["python run_bootstrap.py --with-stack"])
        if not _na168:                       # 不适用优先于"本机有没有"（预览时那条不算数）
            _st168, _det168 = "warn", _why168 + (
                "；本机落点里有东西，但那是按本平台装的，不代表那个平台可用"
                if _stk["present"] else "")
            _rows168 = []
        elif _stk["present"]:
            _st168, _det168 = "ok", f"已就位 {_stk['dest']}（{_stk['version']}）"
        else:
            _st168 = "missing"
            _det168 = f"未取（{_stk['version']} → {_stk['dest']}）：{_stk['why']}"
        rows.append(_row(_stk["name"], "stack", False, _st168, _det168, _rows168))

    path = screenshot.browser_path(st)
    if path and snap_confined(path):
        # Ubuntu ≥24 的 apt chromium 只是 snap 过渡壳，而 snap 的 confinement 让它**写不到**
        # 项目路径与真实 /tmp（实测：`--screenshot` 报"已写 12630 字节"，文件却在 snap 的私有
        # 命名空间里，外面看不见）→ 截图与 PDF 永远 0 产物。装上了却不干活，比没装更难查。
        rows.append(_row("browser", "browser", False, "warn",
                         "只有 snap 版浏览器：confinement 让它写不到项目路径与真实 /tmp，"
                         "截图与 PDF 导出会 0 产物 —— 换非沙箱版（Google Chrome .deb）",
                         ["sudo snap remove chromium",
                          "curl -fsSL -o /tmp/chrome.deb "
                          "https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb",
                          "sudo apt install -y /tmp/chrome.deb"]))
    else:
        rows.append(_row("browser", "browser", False, "ok" if path else "missing",
                         "已找到浏览器（截图阶段与 PDF 导出可用）" if path else
                         "未找到 Edge/Chrome/Chromium：截图与 PDF 导出会如实跳过（不谎报）",
                         [] if path else (pkg_cmd("chromium", mgrs)
                                          or ["本平台没有已知包管理器：自行装 Chrome/Chromium/Edge"])))
    return rows


def _dot(ver):
    return ".".join(str(x) for x in ver)


def _rel(path):
    """配置里的路径统一显示成**相对项目根**形态（§0 硬规矩 3），反斜杠也顺手归一。

    为什么要它：`tools.fscan` / `tools.dirmap.script` 的值是用户写的，可能是 `tools\\fscan\\fscan.exe`
    这种 Windows 形态，也可能有人填了项目内的绝对路径 —— 直接印出去就同时违反"相对路径"和
    "Windows 反斜杠在跨平台日志里会割裂"两条。项目外的绝对路径 `rel_display` 会原样返回，
    这正是 CLI 口径要的（用户要拿去命令行复现）。
    """
    from scanner.utils import rel_display
    return rel_display(str(path or "").replace("\\", "/"))


def _manual_row(name, os_label, mgrs, tools_cfg, resolve):
    """`toolmgr.MANUAL` 里的每一项：按平台**只打印**命令，本脚本不执行、也不发请求。
    新增 MANUAL 名字必须在这里加一条分支（[8d] 会钉"每行只许提自己"）。"""
    from scanner import toolmgr
    from scanner.utils import which

    if name == "nmap":
        cmds = pkg_cmd("nmap", mgrs) or [
            "打开 https://nmap.org/dist/ 取本平台官方产物（Windows 只有安装器、Linux 只有源码包、"
            "macOS 只有 dmg）；摘要在 sigs/<文件名>.digest.txt"]
        found = _rel(which(tools_cfg.get("nmap", "nmap")))
        why = toolmgr.MANUAL["nmap"]
    elif name == "fscan":
        binary = "fscan.exe" if os_label == "windows" else "fscan"
        cfg = _rel(tools_cfg.get("fscan", ""))
        # 编译落点跟着**配置写的目录**走（本项目既定 `tools/fscan/`）—— 只填了裸名（走 PATH）
        # 时才回落到 toolmgr 的自动层落点 `tools/scanner/`。指错地方等于"照着自举输出装完，
        # `--check` 仍然说缺"。产物名仍按平台取（配置里那半截 `.exe` 不能带到 Linux 上）。
        dest = (f"{Path(cfg).parent.as_posix()}/{binary}" if "/" in cfg
                else f"tools/scanner/{binary}")
        cmds = ["git clone https://github.com/shadow1ng/fscan",
                "cd fscan && git checkout v2.2.1",
                'go build -ldflags="-s -w" -trimpath -o ' + dest,
                "一条命令版（续166）：python tools/build_fscan.py --fetch --wire"
                "（缺 Go / 缺源码就取进仓库、过 SHA256，缓存落 .cache/ 不写家目录）"]
        found = _rel(which(tools_cfg.get("fscan", "fscan")))
        why = toolmgr.MANUAL["fscan"]
        if not found:
            for prereq, pkg in (("go", "golang"), ("git", "git")):
                if not shutil.which(prereq):
                    cmds += pkg_cmd(pkg, mgrs) or [f"本机没有 {prereq}：fscan 自编译需要它"]
    elif name == "massdns":
        # puredns 的**传递依赖**（它在进程内 exec massdns，靠 PATH 找）。官方 release 的
        #   `assets` 是空数组（2026-10-13 查 GitHub API：最新 tag v1.1.0、零产物、零 checksums）
        #   ⇒ 只能 `make` 出 bin/massdns，本框架不为它发任何请求，只打印本仓那条自编译命令。
        found = _rel(which(tools_cfg.get("massdns", "massdns")))
        why = toolmgr.MANUAL["massdns"]
        cmds = ["一条命令版（续166）：python tools/build_massdns.py --fetch --wire"
                "（源码按确切 tag 取进仓库、摘要由本框架钉住；**仍需本机 gcc/make**）",
                "git clone https://github.com/blechschmidt/massdns && "
                "git -C massdns checkout v1.1.0",
                "python tools/build_massdns.py --src ./massdns --wire（需 gcc/make）"]
    elif name == "dirmap":
        script = _rel((tools_cfg.get("dirmap", {}) or {}).get("script", "")
                      or "tools/dirmap/dirmap.py")
        # 克隆落点同样取**配置里写的路径**（本项目既定 `tools/dirmap/`），不另写一套。
        target = Path(script).parent.as_posix() or "tools/dirmap"
        # ⚠️ 它的清单文件名是 `requirement.txt`（**少一个 s**），按 pip 惯例猜 `requirements.txt`
        #    会报"No such file"，看起来像"源码不完整"。
        cmds = [f"git clone https://github.com/H4ckForJob/dirmap {target}",
                f"python -m pip install -r {target}/requirement.txt",
                "再把 config/settings.yaml 的 tools.dirmap 两段填好（python / script）"
                "—— GUI「策略配置」页改不了 tools 段",
                "注：它 `import imp`（Python 3.12 起标准库已删）→ 需要 ≤3.11 的解释器并把 "
                "tools.dirmap.python 指过去；另外上游 master 已删掉本框架要传的 `-e` 参数，"
                "逐条实测坑见 tools/scanner/README.md「手工安装」"]
        found = _rel(resolve(script)) if resolve(script).exists() else ""
        why = toolmgr.MANUAL["dirmap"]
    else:
        # 新增 MANUAL 条目而这里没分支 ⇒ 宁可只报"见 README"，也**不许**套到上面任何一个
        #   工具的命令上（续165：massdns 落进 dirmap 的 else，`--check` 给它印了 dirmap 的
        #   clone/pip 还报"已装"）。[8d] 那条"每行只许提自己"就是钉这个的。
        found = _rel(which(tools_cfg.get(name, name)))
        why = toolmgr.MANUAL[name]
        cmds = [f"{name}：官方没有可校验的单二进制产物，步骤见 tools/scanner/README.md「手工安装」一节"]
    return _row(name, "manual", False, "ok" if found else "missing",
                (f"已装 {found}" if found else why), [] if found else cmds)


# ---------- 汇总 / 自动层 / 打印 ----------

def summarize(rows):
    """分成四堆：已就绪 / 本脚本能补（auto）/ `--with-stack` 能补（stack）/ 只能用户动手（manual）。"""
    return {"rows": rows,
            "ok": [r for r in rows if r["status"] == "ok"],
            "todo_auto": [r for r in rows if r["auto"] and r["status"] != "ok"],
            "todo_stack": [r for r in rows if r["kind"] == "stack" and r["status"] != "ok"],
            "todo_manual": [r for r in rows
                            if not r["auto"] and r["status"] != "ok" and r["kind"] != "stack"]}


def render(s, failed=(), installed=(), install=False, sys_plan=()):
    """打印报告。CLI 口径：命令可直接复制，路径原样（不遮项目外路径）。"""
    from scanner import toolmgr
    os_label, arch, mgrs = platform_info()
    # `s` 可能来自调用方自己拼的字典（门禁里就有），所以这一堆一律 `.get` 兜空。
    _stk166 = s.get("todo_stack") or []
    _ov168 = toolmgr.platform_override()[1]      # 有 --platform 覆盖时这句话说的是"按谁预览"
    _na168 = [r for r in s["rows"] if r["status"] == "warn"
              and r["kind"] in ("auto", "pending", "stack")]
    print(f"[*] 迁移自举｜平台 {os_label}/{arch}｜包管理器 {'、'.join(mgrs) or '无'}"
          + (f"｜{_ov168}" if _ov168 else ""))
    if _ov168:
        print("[!] 预览模式：下面只回答「那个平台该装哪些 / 哪些天生没有」——"
              "每一行的「已装」吃的仍是**本机**文件系统，不代表那个平台真的能用。")
    print(f"  已就绪 {len(s['ok'])}｜可自动补齐 {len(s['todo_auto'])}｜需手工 {len(s['todo_manual'])}"
          + (f"｜本平台不适用 {len(_na168)}" if _na168 else "")
          + (f"｜工作目录内可取 {len(_stk166)}" if _stk166 else "")
          + (f"｜本轮已装 {len(installed)}" if installed else "")
          + (f"｜自动层失败 {len(failed)}" if failed else ""))
    auto_title = "仍未就绪（自动层没补上）" if install else "可自动补齐（加 --install 就会装）"
    for title, items in (("需要手工安装（本框架不自动下载、也不代跑）", s["todo_manual"]),
                         ("本平台不适用（**不是失败**，也不算已就绪：官方没发该平台的可校验产物）",
                          _na168),
                         ("工作目录内运行时组件（加 --with-stack 就取；全落仓库内、不写家目录）",
                          _stk166),
                         (auto_title, s["todo_auto"])):
        if not items:
            continue
        print(f"\n—— {title} ——")
        for r in items:
            print(f"  {r['name']:<12} [{r['status']}] {r['detail']}")
            for cmd in r["cmds"]:
                print(f"      $ {cmd}")
    if failed:
        # 只有"失败 N"这个数字等于没说：哪一项、为什么失败必须逐条列出来。
        print("\n—— 自动层失败（本脚本试过了，没成）——")
        for f in failed:
            print(f"  {f['name']:<12} {f.get('reason') or '未知原因'}")
    if s["todo_manual"]:
        print("\n[i] 「需手工」那几类官方都没有\"可下载且带官方校验和的单二进制产物\"，"
              "所以框架不为它们发任何请求（逐条原因见 scanner/toolmgr.py 的 MANUAL）。")
    miss_sys = [r for r in sys_plan if not r["present"]]
    if miss_sys:
        print("\n—— 系统包层（默认**只打印**，加 --with-system 才真装；需管理员权限）——")
        for r in miss_sys:
            if r["argv"]:
                print(f"  {r['name']:<16} $ {r['cmd']}")
            else:
                # 缺但**没有登记过可用的包管理器** —— 也必须点名。
                # 只打印"有命令的那些行"会让"这台机器缺中文字体、而清单上一个字都不提"，
                # 正是本仓反复出事的那类静默降级（续103）。
                print(f"  {r['name']:<16} 本机包管理器未登记该包（不猜命令）—— 请手工安装")
        print("  （fscan / dirmap 不在这一层：要 clone + 编译第三方源码，那种决定只能人来下）")
    if not s["todo_auto"] and not s["todo_manual"]:
        print("\n[+] 环境齐了：可以直接 python cli/client.py --check 复核，再跑 tests/smoke.py。")
    print("\n[i] 装完外部工具请跑 `python tests/smoke.py` 复核（本项目的唯一回归门禁）。")
    return s


def install_auto(only=(), allow_unverified=False, dest_dir=None, wire=True):
    """自动层：pip 依赖 + `toolmgr.update`（联网只发生在这里）。返回 `(installed, failed)`。"""
    wanted = {n for n in only if n}
    rows = summarize(probe())["todo_auto"]
    installed, failed = [], []
    py_rows = [r for r in rows if r["kind"] == "runtime"]
    if py_rows and (not wanted or any(r["name"] in wanted for r in py_rows)):
        if importlib.util.find_spec("pip") is None:
            failed.append({"name": "requirements", "reason": "当前解释器没有 pip"})
            print("[!] 跳过 pip 依赖：当前解释器没有 pip（自动层装不了，见清单里的命令）")
        else:
            req_file, req_why = pick_requirements_file()
            print(f"[i] Python 依赖清单：本次用 {req_file} —— {req_why}")
            p = subprocess.run([sys.executable, "-m", "pip", "install", "-r", req_file],
                               cwd=str(ROOT), capture_output=True, text=True, env=_pip_env())
            tail = (p.stderr or p.stdout or "").strip().splitlines()
            if p.returncode == 0:
                installed.append({"tool": "requirements", "path": req_file})
                print(f"[+] Python 依赖已装好（{req_file}）")
            else:
                reason = tail[-1] if tail else f"rc={p.returncode}"
                failed.append({"name": "requirements", "reason": f"{req_file}: {reason}"})
                print(f"[!] Python 依赖安装失败（{req_file}）：{reason}")
                if req_file == REQ_LOCK:
                    # 预检过了却装失败＝多半是网络/磁盘，不是版本不可解。此时**不自动**退回
                    # requirements.txt：那会装出一套没人验过的版本组合，还把真故障藏起来。
                    print(f"[!] 没有自动退回 {REQ_TXT} —— 退回去装的是**另一套版本组合**，"
                          f"会把这次的真实故障藏掉；确认是版本不可解请把 {REQ_LOCK} 临时改名再重跑")
    tool_names = [r["name"] for r in rows if r["kind"] == "auto"]
    if wanted:
        tool_names = [n for n in tool_names if n in wanted]
    if tool_names:
        from scanner import toolmgr
        for r in toolmgr.update(tool_names, dest_dir=dest_dir,
                                allow_unverified=allow_unverified, wire=wire):
            if r.get("ok"):
                installed.append(r)
                # 校验状态那句话与 CLI / GUI 同源（`toolmgr.verified_label`），这里不另写一份；
                # `verified is None`（--only-newer 跳过的那类）就**不加括号**，别说成"已校验"。
                _lbl = toolmgr.verified_label(r)
                print(f"[+] {r['tool']} {r.get('version')} → {r.get('path')}"
                      + (f"（{_lbl}）" if _lbl else ""))
            else:
                _why = r.get("reason") or "未知原因"
                if r.get("not_applicable"):
                    # 续168：**不适用 ≠ 失败**，不排进 failed（否则 Windows 上 `./install.sh`
                    # 恒 rc=1 —— puredns 官方压根没发 Windows 产物）。但也不能静默：这一行照印，
                    # 而且复探后它会以 `status=warn` 出现在下面"本平台不适用"那一节里。
                    print(f"[=] {r['tool']} 本平台不适用：{_why}")
                else:
                    failed.append({"name": r["tool"], "reason": _why})
                    print(f"[!] {r['tool']} 未装上：{_why}")
    return installed, failed


def install_stack(only=(), allow_unverified=False, timeout=600):
    """**工作目录内运行时组件**层（`--with-stack`）：Go 便携归档 + 上游源码包。

    与自动层同一批红线，一条都没松：只走 `toolmgr` 的 https + 主机白名单 + 落盘前 SHA256
    （摘要产地如实标注：Go 来自官方 `?mode=json`，源码包来自本框架钉住的那串）；
    **一个子进程都不起** ⇒ `[8d]②` 那份"自动层只许四类意图"的名单一条都不用改。
    编译仍归 `tools/build_fscan.py` / `tools/build_massdns.py` 那两个显式入口 ——
    本函数只把"编译要吃的件"取齐，**不代跑 make / go build**（那是红线）。
    落点与缓存全在仓库内（`toolmgr.LOCAL_STACK[*]["dest"]` 与 `toolmgr.cache_path`）。
    """
    from scanner import toolmgr
    names = [n for n in only if n] or list(toolmgr.LOCAL_STACK)
    installed, failed = [], []
    for r in toolmgr.stack_update(names, allow_unverified=allow_unverified, timeout=timeout):
        if r.get("ok"):
            if r.get("already"):
                # **不计进 `installed`**：那一格印的是"本轮已装 N"，把"本来就在"的算进去
                # 就是拿旧状态冒充本轮成果（§5.19 同族）。
                print(f"[=] {r['name']} 已就位（{r.get('path')}）—— 不重下")
                continue
            installed.append(r)
            # 取来还要**真的被用上**：注册表里带了 `wire` 的条目回写对应配置键
            # （`screenshot.browser_path()` 只认配置值，不认目录本身）。写回走的是
            # "只改一个键"那条逐行替换（`patch_settings_kv`），不整份重写 settings.yaml。
            _w = (toolmgr.LOCAL_STACK.get(r["name"]) or {}).get("wire")
            if _w:
                _val = toolmgr.stack_exec_path(r["name"])
                ok, note = (toolmgr.patch_settings_kv(_w[0], _w[1], _val) if _val
                            else (False, "产物没找到可执行文件"))
                print(f"[{'+' if ok else '!'}] 回写 {_w[0]}.{_w[1]} = {_val or '(空)'}"
                      + ("" if ok else f" 失败：{note}（请手动填）"))
            lbl = toolmgr.verified_label(r)
            print(f"[+] {r['name']} {r.get('version')} → {r.get('path')}"
                  f"（{r.get('files')} 个文件、{r.get('bytes', 0) / 1048576:.1f} MB"
                  + (f"，{lbl}" if lbl else "") + "）")
        elif r.get("not_applicable"):
            print(f"[=] {r['name']} 本平台不适用：{r.get('reason')}")   # 不算失败（续168）
        else:
            failed.append({"name": r["name"], "reason": r.get("reason") or "未知原因"})
            print(f"[!] {r['name']} 未取到：{r.get('reason')}")
    return installed, failed


# 续175：安装末尾可选的凭据字段（组, 键, 人话名, 是否隐藏输入）。
# 只收 `config.load_keys()` 真正消费的组；空输入＝保留现有值，绝不把空串写进去覆盖旧 key。
_KEY_FIELDS = (
    ("fofa", "email", "FOFA 邮箱", False),
    ("fofa", "key", "FOFA API key", True),
    ("shodan", "key", "Shodan API key", True),
    ("quake", "key", "360 Quake API key", True),
    ("github", "token", "GitHub 只读 token", True),
    ("gitlab", "token", "GitLab 只读 token", True),
    ("virustotal", "key", "VirusTotal API key", True),
    ("icp", "api_key", "ICP 备案源 api_key", True),
)


def prompt_credentials(ask=None):
    """安装末尾**可选**的凭据录入（续175；只在 TTY 里问，绝不挂住 CI）。

    返回 `True` 表示走完了 `run_keys.py` 且 rc=0；`False` 表示跳过/失败/非交互。
    三条红线：① 不打印任何输入值；② 明文只进系统临时文件，交给 `run_keys --encrypt
    --shred` 后立即删除；③ 已有密文由 `run_keys` 自己合并（这里不重写加密/合并逻辑）。
    """
    if ask is None:
        ask = sys.stdin.isatty()
    if not ask:
        print("[i] 非交互环境：跳过凭据录入（事后可运行 python cli/run_keys.py --encrypt）")
        return False
    try:
        yn = input("现在录入第三方 API 凭据吗？输错/留空都只是跳过，之后可再补 [y/N]：").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print("\n[i] 已跳过凭据录入")
        return False
    if yn not in ("y", "yes", "是"):
        print("[i] 已跳过凭据录入（随时可运行 python cli/run_keys.py --encrypt 补）")
        return False

    overlay = {}
    for group, key, label, secret in _KEY_FIELDS:
        prompt = f"  {label}（留空＝不改）: "
        try:
            val = getpass.getpass(prompt) if secret else input(prompt)
        except (EOFError, KeyboardInterrupt):
            print("\n[!] 输入被取消，本轮不写任何凭据（已输入的部分也不会落盘）")
            return False
        val = str(val or "").strip()
        if val:
            overlay.setdefault(group, {})[key] = val
    if not overlay:
        print("[i] 没有输入任何值，跳过（现有凭据未动）")
        return False
    try:
        import yaml
        from scanner import keystore
        from cli.run_keys import main as _run_keys_main
    except ImportError:
        print("[!] 当前环境没有 PyYAML/cryptography，无法生成临时凭据文件；跳过（现有凭据未动）")
        return False
    # 还没有密文、但旧明文 keys.yaml 存在时，必须把它并进来：run_keys 只拿得到本函数的
    # 临时 src，不会自动去读明文；不并就会在第一次加密后把旧组"静默丢掉"（之后 load_keys
    # 只看密文）。只读明文，不写、不打印值。
    base = {}
    if not (ROOT / "config" / "keys.enc.yaml").exists():
        try:
            _old = yaml.safe_load((ROOT / "config" / "keys.yaml").read_text(encoding="utf-8"))
            if isinstance(_old, dict):
                base = _old
        except Exception:                           # noqa: BLE001 - 读不到就按没有明文处理
            base = {}
    data, _rep = keystore.merge_key_dicts(base, overlay)

    tmp_name = ""
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".yaml",
                                         prefix="ctfscan-keys-", delete=False) as fh:
            yaml.safe_dump(data, fh, allow_unicode=True, sort_keys=False)
            tmp_name = fh.name
        # 进程内复用同一条 CLI 路径（合并/自校验/覆盖策略都只有 `run_keys` 一份）——
        # 不在这里 `subprocess.call`：本文件的红线是"除 pip 引导外不起子进程"（[8d]）。
        rc = _run_keys_main(["--encrypt", "--src", tmp_name, "--shred"])
        if rc == 0:
            print("[+] 凭据已写入加密文件（值不会出现在任何输出里；下次启动解锁一次即可）")
            if (ROOT / "config" / "keys.yaml").exists():
                print("[!] 旧明文 config/keys.yaml 仍在：确认密文能解开后请手工删掉它，"
                      "否则\"加密\"只防住了密文被拷走这一半。")
            return True
        print(f"[!] 凭据录入未完成（run_keys rc={rc}），现有凭据未动")
        return False
    finally:
        if tmp_name:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass


def main(argv=None):
    ap = argparse.ArgumentParser(description="迁移自举：按平台点清并补齐环境依赖")
    ap.add_argument("--install", action="store_true",
                    help="执行自动层（pip 依赖 + toolmgr 的 TOOLS）；不加只探测，零网络")
    ap.add_argument("--only", action="append", default=[],
                    help="只自动补这几项（可重复；名字见清单，如 httpx / py:flask）")
    ap.add_argument("--allow-unverified", action="store_true",
                    help="透传 toolmgr：release 没校验和时也照装（默认拒绝）")
    ap.add_argument("--tools-dest", default=None, help="透传 toolmgr 的落点目录")
    ap.add_argument("--no-wire", action="store_true", help="透传 toolmgr：装完不写回 settings.yaml")
    ap.add_argument("--no-venv", action="store_true",
                    help="不要自动建 .venv，就用当前解释器装依赖（容器/受控环境里常用）")
    ap.add_argument("--no-keys", action="store_true",
                    help="跳过安装末尾的可选凭据录入（CI / 非交互环境本来也会自动跳过）")
    ap.add_argument("--with-system", action="store_true",
                    help="系统包层：nmap / 浏览器 / Go / git 交给**发行版包管理器**真装"
                         "（默认只打印命令不执行；fscan/dirmap 永不代跑）")
    ap.add_argument("--with-stack", action="store_true",
                    help="工作目录内运行时组件层（续166）：取 Go 便携归档与上游源码包"
                         "（过 SHA256、落 tools/ 与 .cache/，**不写家目录、不装系统包、不代跑编译**）")
    ap.add_argument("--platform", default=None, metavar="os/arch",
                    help="按**另一个平台**预览选品与清单（如 windows/amd64；只影响「该装哪些」"
                         "的判定与打印，产物仍只下本平台那一份 —— 续168）")
    ap.add_argument("--stack", action="append", default=[], metavar="NAME",
                    help="配合 --with-stack：只取这几件（可重复；名字见清单里 kind=stack 那些行）")
    ap.add_argument("--yes", action="store_true",
                    help="配合 --with-system：跳过交互确认（非交互环境没有它就**拒绝执行**）")
    args = ap.parse_args(argv)
    if args.platform:
        # 唯一的覆盖入口是环境变量（判据仍只 `toolmgr.host_arch()` 一处）；值不认识时
        # `platform_override()` 会给出一句原因，清单抬头就印出来 —— 不静默按本机跑。
        os.environ["CTFSCANNER_TARGET_PLATFORM"] = str(args.platform)

    # 一键就绪：`--install` 时先保证有个带 pip 的 .venv，再用**它**重跑本脚本 ——
    # 否则在 Ubuntu 那种"系统解释器没 pip/ensurepip"的机器上，自动层只能报"装不了"。
    if args.install and not args.no_venv and not in_venv():
        ok, msg = ensure_venv()
        print(f"[{'+' if ok else '!'}] 虚拟环境：{msg}")
        code = rerun_in_venv(sys.argv[1:])
        if code is not None:
            return code
        if not ok:
            print("[!] 退回当前解释器继续（依赖会装到系统解释器上）")

    s = summarize(probe())
    installed, failed = ([], [])
    sys_plan = system_plan()
    if args.install:
        installed, failed = install_auto(tuple(args.only), args.allow_unverified,
                                        args.tools_dest, not args.no_wire)
        s = summarize(probe())          # 复探：以"真的装上没有"为准，不按安装返回值吹
    if args.with_stack:
        got, sfailed = install_stack(tuple(args.stack), args.allow_unverified)
        installed.extend(got)
        failed.extend(sfailed)
        s = summarize(probe())          # 复探：取没取到以文件系统为准（与自动层同一口径）
    if args.with_system:
        got, refused, sfailed = install_system_packages(sys_plan, True, args.yes)
        for name in got:
            installed.append({"tool": name, "path": "(系统包管理器)"})
        failed.extend(sfailed)
        if refused:
            print("[!] 系统包层被拒绝执行：" + "、".join(refused))
        s = summarize(probe())          # 复探：装没装以文件系统为准
    render(s, failed, installed, install=args.install, sys_plan=sys_plan)
    # 续175：安装收尾再问一次凭据（可选）。放在 render 之后，用户先看到"装了什么"，
    # 再决定要不要现在填 key；非交互环境由 prompt_credentials 直接跳过，不会挂住。
    if args.install and not args.no_keys:
        prompt_credentials()
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
