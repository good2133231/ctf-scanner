#!/usr/bin/env bash
# CTFScanner 一键安装（Linux / macOS）：建 .venv → 装依赖 → 装可自动的外部工具 → 如实报告缺口。
#
# 本脚本**不实现**任何安装逻辑，只做三件事：找一个够新的解释器、调 `run_bootstrap.py --install`、
# 装完复验一次。"该装什么 / 哪些只能手工 / 校验和红线"这些判据全在 `run_bootstrap.py` 里 ——
# 在这儿再抄一份就是第二个产地，两边迟早漂（AGENTS §5.14，本项目反复栽在这上面）。
#
# 用法：
#   ./install.sh                       标准安装（.venv + pip 依赖 + subfinder/httpx/puredns/afrog；有 gcc/make 时自动编 massdns）
#   ./install.sh --full                **一条命令把环境建全**（续166）：标准安装
#                                      + 工作目录内取 Go 便携归档与上游源码包（--with-stack）
#                                      + 就地编译 fscan 与 massdns（--with-build）
#                                      全部落在仓库内（tools/ 与 .cache/），不装系统包、不写家目录
#   ./install.sh --with-stack          只取运行时组件（Go / 源码包），不编译
#   ./install.sh --with-system --yes    额外让发行版包管理器**真装** nmap / 浏览器 / Go / CJK 字体
#   ./install.sh --with-build           标准安装 + 编译 fscan 与 massdns（用本机工具链；
#                                      给了 --with-stack 才会自动取缺的 Go / 源码）
#   ./install.sh --no-venv             装到当前解释器（容器 / 受控环境里常用）
#   ./install.sh --platform windows/amd64   按**另一个平台**预览清单（续168）：只改"该装哪些/
#                                      哪些天生没有"的判定与打印，**产物仍只下本平台那一份**
# 其余参数原样透传给 run_bootstrap.py（--only / --allow-unverified / --tools-dest / --no-wire）。
#
# ⚠ 仍**依赖本机**的（续274 起 massdns 标准安装即自动编，但底层要 gcc/make，C 工具链无便携替代品）：
#   `nmap` 只有系统包；CJK 字体目前仍要系统装（截图用的浏览器自续167 起可用 --with-stack 取进
#   仓库，但它只解决"有没有浏览器"，中文能不能显示仍取决于字体）。
#   没有它们框架照跑，只是截图里中文变方块、端口扫描退回内置 TCP connect。
#
# ⚠ 本文件必须保持 **LF** 行尾（.gitattributes 已钉）：CRLF 的 shebang 会让 bash 报
#   `/usr/bin/env bash\r: bad interpreter`，从 Windows 检出后直接跑不起来。
set -euo pipefail

cd "$(dirname "$0")"

# ---- ① 找一个够新的解释器 ----
# 门槛 3.9 与 CI（.github/workflows/smoke.yml）、容器门禁同口径；权威判据是 run_bootstrap.PY_MIN，
# 这里只做一个**前置**筛选，好把"解释器太老"这句话在跑之前说清楚（否则要等它自己报）。
PY=""
for cand in python3 python; do
  command -v "$cand" >/dev/null 2>&1 || continue
  if "$cand" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' 2>/dev/null; then
    PY="$cand"
    break
  fi
  echo "[!] $cand 是 $("$cand" -V 2>&1)，本项目要 ≥3.9（CI 与容器门禁都跑 3.9）"
done
if [ -z "$PY" ]; then
  echo "[X] 没找到 ≥3.9 的 python3 / python。先装解释器（按发行版挑一条）："
  echo "      Debian/Ubuntu : sudo apt-get install -y python3 python3-venv"
  echo "      RHEL/Fedora   : sudo dnf install -y python3"
  echo "      Arch          : sudo pacman -S --noconfirm python"
  echo "      Alpine        : sudo apk add python3"
  echo "    （Ubuntu/Debian 请连 python3-venv 一起装：ensurepip 被拆在那个包里，"
  echo "      缺了它 run_bootstrap 会退到用官方 get-pip.py 引导，多一次联网。）"
  exit 1
fi
echo "[*] 用 $PY（$("$PY" -V 2>&1)）"

# ---- ② 真正的安装：联网只发生在这一层，且只有显式 --install 才下载 ----
# `--with-build` / `--full` 是**本脚本自己**的开关（不是 run_bootstrap 的）：先剔出去，免得
# run_bootstrap 报"未知参数"（本项目最忌讳"传了被静默忽略"）。`--full` 展开成
# `--with-stack`（透传给 run_bootstrap）+ `--with-build`（本脚本自己执行编译入口）。
# 其余参数原样透传。
WITH_BUILD=0
WITH_STACK=0
ARGS=()
for _a in "$@"; do
  case "$_a" in
    --with-build) WITH_BUILD=1 ;;
    --with-stack) WITH_STACK=1; ARGS+=("$_a") ;;
    --full)       WITH_BUILD=1; WITH_STACK=1; ARGS+=("--with-stack") ;;
    *)            ARGS+=("$_a") ;;
  esac
done
# 不用 `set -e` 直接吃掉它的退出码：run_bootstrap 对"pip 依赖装不上"与"可选的 subfinder 没下下来"
# 一律返回 1，而后者**不影响框架跑通**（会自动降级到内置实现）。这里把码记下来、先做完复验与
# 收尾说明，最后再如实带出去 —— 直接中断的话，用户连"接下来敲哪条命令"都看不到。
BOOT_RC=0
"$PY" run_bootstrap.py --install ${ARGS[@]+"${ARGS[@]}"} || BOOT_RC=$?

# ---- ③ 复验：装没装以"能不能 import"为准，不按上一步的退出码吹 ----
# run_bootstrap 自己也会复探一遍（它的口径是"以文件系统为准"）；这里再问一次解释器，
# 是因为 start.sh 用的就是这个 RUNPY —— 两者不一致的话，装完照样起不来。
if [ -x ".venv/bin/python" ]; then RUNPY="./.venv/bin/python"; else RUNPY="$PY"; fi
if "$RUNPY" -c 'import flask, requests, yaml' 2>/dev/null; then
  echo "[+] 依赖复验通过：$RUNPY 能 import flask / requests / yaml"
else
  echo "[X] $RUNPY 仍 import 不到 flask / requests / yaml —— 原因在上面 run_bootstrap 的输出里"
  exit 1
fi
if [ "$BOOT_RC" -ne 0 ]; then
  echo "[!] run_bootstrap 报了失败项（退出码 $BOOT_RC）：多半是**可选的**外部工具没下下来"
  echo "    （GitHub release 不可达 / 校验和对不上就拒绝落盘）。框架本身仍能跑，只是覆盖面与速度不如本体。"
fi

# ---- ④ 可选：编译层（fscan 用 Go、massdns 用 gcc/make）----
# 两家官方都不发"可校验的单二进制"，只能自编译。这一步**显式**才发生，逻辑在 tools/build_*.py
# （不塞进 run_bootstrap：那条自动层被测试钉死了"绝不代跑系统级命令"，`go build` / `make` 都在禁列）。
# `--fetch` 只在用户已经要了 `--with-stack` 时才给 —— 那等于已经同意"缺的件下进仓库"；
# 只给 `--with-build` 时保持老行为：缺 Go / 缺源码就**如实报**并印出获取命令，不擅自下 70 MB。
# ---- ④ massdns（puredns 的传递依赖）：续274 起**标准安装也自动编**（原仅 --with-build）----
# 为什么进标准层：puredns 的 bruteforce/resolve 在进程内 exec massdns，缺它每个域名退码 1 ⇒
# 只下 puredns 不编 massdns ＝ 装了也跑不了快路。检测到 gcc/make 就编（--fetch 取本框架钉住的
# 小源码包 v1.1.0，非 --with-stack 那 70MB 的 Go stack）；缺 gcc/make 则按平台尝试装工具链
# （仅交互式 TTY + 有 sudo 才试，非致命，避免 CI 里挂住），再不行如实报 + 走内置纯 Python 兜底。
_have() { command -v "$1" >/dev/null 2>&1; }
if ! _have gcc || ! _have make; then
  if [ -t 0 ] && _have sudo; then
    echo "[*] massdns：没 gcc/make，交互式安装 —— 尝试按平台装编译工具链（要输密码；装不上不影响安装）..."
    if _have apt-get; then sudo apt-get install -y build-essential || true
    elif _have dnf; then sudo dnf install -y gcc make || true
    elif _have yum; then sudo yum install -y gcc make || true
    elif _have brew; then brew install gcc make || true
    elif [ "$(uname -s 2>/dev/null || echo unknown)" = "Darwin" ]; then xcode-select --install || true
    else echo "[!] 未能识别的包管理器，跳过工具链自动安装"; fi
  else
    echo "[*] massdns：没 gcc/make（非交互或无 sudo，跳过自动装工具链）。按平台自装："
    echo "      Debian/Ubuntu: sudo apt-get install -y build-essential"
    echo "      RHEL/Fedora  : sudo dnf install -y gcc make"
    echo "      macOS        : xcode-select --install"
  fi
fi
if _have gcc && _have make; then
  echo "[*] massdns：有 gcc/make，编译 puredns 的传递依赖（--fetch 取钉住源码 v1.1.0 → make → 写回配置）"
  "$RUNPY" tools/build_massdns.py --wire --fetch \
    || echo "[!] massdns 没编成（原因见上）。框架仍能跑：puredns 被预检跳过、子域名爆破回退内置纯 Python 那路。"
else
  echo "[!] 仍无 gcc/make：massdns 跳过。框架仍能跑（子域名爆破走内置纯 Python DNS 兜底，覆盖面/速度差一档）。"
  echo "    要 puredns 快路：装好 gcc/make 后跑  python tools/build_massdns.py --fetch --wire"
fi

# ---- ⑤ 可选：编译 fscan（端口扫描引擎；要 Go，仍显式 --with-build 才编）----
if [ "$WITH_BUILD" = "1" ]; then
  FETCH=""
  if [ "$WITH_STACK" = "1" ]; then FETCH="--fetch"; fi
  echo "[*] --with-build：编译 fscan（缺 Go / 缺源码会如实报，不静默跳过）"
  # shellcheck disable=SC2086  # $FETCH 刻意不加引号：空值时不能变成"一个空参数"
  "$RUNPY" tools/build_fscan.py --wire $FETCH \
    || echo "[!] fscan 编译未完成（原因见上）。框架仍能跑：端口扫描自动回退 nmap → 内置 TCP connect。"
fi

cat <<'EOF'

=========================== 装完了，接下来 ===========================
启动控制台：  ./start.sh        （等价于 ./.venv/bin/python run_gui.py）
只探测不安装：./.venv/bin/python run_bootstrap.py     （零网络，看这台机器还缺什么）

首次启动只在**缺配置时**才交互（配置齐了就直接起，适合后台/开机自启）；缺哪几项会有一句汇总。
新机子上通常是这三项 —— 前两项启动时会问你，第三项**不会问**（它只从文件读），最容易被漏掉：
  · 第一个管理员账号与口令
      非交互环境补建：CTFSCANNER_ADMIN_PASSWORD='<口令>' ./.venv/bin/python cli/run_users.py --create-admin
      （同样是临时变量、别写进任何入库文件；口令只落 users 表的 PBKDF2 派生值）
  · 凭据密文口令（config/keys.enc.yaml，只在你配过第三方 key 时才有）
      只从 CTFSCANNER_KEYS_PASSPHRASE / ~/.secrets/keys-pass / config/keys-pass（都要求 0600）/ TTY 取，
      **绝不写进任何被 git 跟踪的文件**，也不会写进 .git/config 或远端地址。
      续292 那档 config/keys-pass 是为整机迁移加的：口令跟密文一起拷，换机器不用重敲 ——
      代价是同机可读的人照样解得开，所以它必须列在 .gitignore 里（缺那一行时程序**拒读**那个文件）。
      非交互安装要顺带填第三方 key：设 CTFSCANNER_KEYS_FOFA_EMAIL / ..._FOFA_KEY / ..._SHODAN_KEY /
      ..._QUAKE_KEY / ..._GITHUB_TOKEN / ..._GITLAB_TOKEN / ..._VIRUSTOTAL_KEY / ..._ICP_API_KEY；
      有一条就直通加密，没有就跳过。值只进密文，安装输出只报字段名，不打印值。
  · **401 边缘认证门（续151 起出厂默认关）**：仓库里 config/settings.yaml 是 gui.host: 0.0.0.0 +
      gui.edge_auth.enabled: false —— 满足"clone 下来直接打开控制台"；**代价是同一网段谁都能访问**。
      要开门：把 gui.edge_auth.enabled 改回 true 并设口令。口令文件 config/edge_auth.yaml 在
      .gitignore 里、**不随仓库分发**；**门开而口令缺失 ⇒ 对所有请求回 401**，看着像"装坏了"，
      其实是门开着没钥匙。
      有终端：./.venv/bin/python -m scanner.edgeauth --set      （顺带把文件权限设成 0600）
      没终端（容器 / systemd / cloud-init）：
        CTFSCANNER_EDGE_PASSWORD='<口令>' ./.venv/bin/python -m scanner.edgeauth --set
        —— 临时变量，别写进任何入库文件。启动向导**仍然不会代填**（那是 [8ai] 的红线），
           只有这条显式命令吃它；口令同样走 validate_password，弱口令照样拒。
      纯本机自用、不想多一道门：把 config/settings.yaml 的 gui.edge_auth.enabled 改成 false。
启动横幅会逐行进 logs/server.log（2MB×3 轮转）；控制台地址里那段**随机后台前缀刻意不落盘**
（重启即换，它不是访问控制，别存进书签）。
每个 HTTP 请求一行另进 logs/access.log（同一套轮转）：终端不再一屏一行刷请求，而文件里那段
随机前缀已打码成 <前缀已脱敏> —— 这份日志看得出谁打了哪个页面，看不出后台路径。

**本脚本刻意没做**（是 run_bootstrap.py 的红线，不是漏了）：
  · nmap：只有系统包（官方发布在 nmap.org/dist，不在 GitHub release）—— 代跑就是越"系统级动作"的界。
    上面输出里**按平台印了命令**，自己复制执行；真想让它代装系统包：./install.sh --with-system --yes
  · fscan：**要你点头**（要 Go）—— ./install.sh --with-build / --full 编译；缺 Go 则端口扫描回退 nmap → 内置 TCP connect。
  · massdns（puredns 的传递依赖）：**续274 起标准安装即自动编** —— 检测到 gcc/make 就取本框架钉住的小源码包
    （v1.1.0，过 SHA256，非 --with-stack 那 70MB 的 Go stack）编译并写回配置；缺 gcc/make 时交互式会尝试装工具链、
    非交互则打印按平台的安装命令，并明确告知"子域名爆破走内置纯 Python DNS 兜底，框架照跑"。
    要强制重编：./install.sh --full（fscan 也一起）。
  · 浏览器：**能自动，但要你点头** —— ./install.sh --full（或 --with-stack）把 Chrome for Testing
    取进 tools/browser/ 并回写 tools.screenshot.browser（续167）。Linux / Windows / macOS（x64+arm64）
    的摘要都已人工核过（续217）；Linux 在本机真机启动过，Windows/macOS 只核过归档字节与归档内版本号，
    **没在真机启动过**。运行时仍要系统共享库，缺库时截图照旧如实失败。
  · CJK 字体：站点截图 / PDF 报告里的中文要靠它，仍要系统装（没有也能跑，只是截图里中文变方块）。
    浏览器解决的是"有没有东西能渲染"，字体解决的是"中文渲染成不成字"，两件事别混。
  · 没有这些外部工具框架**仍能跑通**：会自动降级到内置实现，只是覆盖面与速度不如本体。

**换机器别拷 .venv**：venv 里写死了绝对路径（pyvenv.cfg、bin/activate、各 console script 的
shebang），换个目录或换台机器就失效 —— 症状是"拷过去跑不起来，但源码一个字没改"。
正确做法：拷**源码**（.venv 本来就在 .gitignore 里，git clone / git archive 天然不带它），
到新机器上再跑一次 ./install.sh。依赖版本由 requirements.lock 钉住，装出来的是同一批。
=====================================================================
EOF

# 与 run_bootstrap.py 同一个契约（续168 起口径收窄，别在这儿另立一套）：
#   0 ＝ 缺口为零／自动层全部补齐／**只剩"本平台不适用"**（官方压根没发该平台产物，
#       如 Windows 上的 puredns —— 清单里单开一节点名，它既不算失败也不算就绪）；
#   非 0 只有一种含义：自动层里**真的**有项失败了（下载不可达 / 摘要对不上而拒绝落盘）。
exit "$BOOT_RC"
