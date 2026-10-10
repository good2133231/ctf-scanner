#!/usr/bin/env bash
# CTFScanner 一键安装（Linux / macOS）：建 .venv → 装依赖 → 装可自动的外部工具 → 如实报告缺口。
#
# 本脚本**不实现**任何安装逻辑，只做三件事：找一个够新的解释器、调 `run_bootstrap.py --install`、
# 装完复验一次。"该装什么 / 哪些只能手工 / 校验和红线"这些判据全在 `run_bootstrap.py` 里 ——
# 在这儿再抄一份就是第二个产地，两边迟早漂（AGENTS §5.14，本项目反复栽在这上面）。
#
# 用法：
#   ./install.sh                       标准安装（.venv + pip 依赖 + subfinder/httpx/puredns）
#   ./install.sh --with-system --yes    额外让发行版包管理器**真装** nmap / 浏览器 / Go / CJK 字体
#   ./install.sh --no-venv             装到当前解释器（容器 / 受控环境里常用）
# 其余参数原样透传给 run_bootstrap.py（--only / --allow-unverified / --tools-dest / --no-wire）。
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
# 不用 `set -e` 直接吃掉它的退出码：run_bootstrap 对"pip 依赖装不上"与"可选的 subfinder 没下下来"
# 一律返回 1，而后者**不影响框架跑通**（会自动降级到内置实现）。这里把码记下来、先做完复验与
# 收尾说明，最后再如实带出去 —— 直接中断的话，用户连"接下来敲哪条命令"都看不到。
BOOT_RC=0
"$PY" run_bootstrap.py --install "$@" || BOOT_RC=$?

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
      只从 CTFSCANNER_KEYS_PASSPHRASE / ~/.secrets/keys-pass（0600）/ TTY 取，
      **绝不写进仓库里的任何文件**，也不会写进 .git/config 或远端地址。
  · **401 边缘认证门的口令**：仓库里 config/settings.yaml 出厂就是 gui.host: 0.0.0.0 +
      gui.edge_auth.enabled: true（续131 的取舍：仓库是公开的，宁可 fail-closed 也不裸奔），
      而口令文件 config/edge_auth.yaml 在 .gitignore 里、**不随仓库分发**。
      ⇒ 刚 clone 出来的控制台会对**所有**请求回 401，看着像"装坏了"，其实是门开着没钥匙。
      有终端：./.venv/bin/python -m scanner.edgeauth --set      （顺带把文件权限设成 0600）
      没终端（容器 / systemd / cloud-init）：
        CTFSCANNER_EDGE_PASSWORD='<口令>' ./.venv/bin/python -m scanner.edgeauth --set
        —— 临时变量，别写进任何入库文件。启动向导**仍然不会代填**（那是 [8ai] 的红线），
           只有这条显式命令吃它；口令同样走 validate_password，弱口令照样拒。
      纯本机自用、不想多一道门：把 config/settings.yaml 的 gui.edge_auth.enabled 改成 false。
启动横幅会逐行进 logs/server.log（2MB×3 轮转）；控制台地址里那段**随机后台前缀刻意不落盘**
（重启即换，它不是访问控制，别存进书签）。

**本脚本刻意没做**（是 run_bootstrap.py 的红线，不是漏了）：
  · nmap / fscan / dirmap：要么装进系统目录（要 root）、要么要用 Go 自编译 —— 代跑就是越
    "系统级动作"的界，还会绕过 toolmgr 那条 SHA256 校验红线。上面输出里**按平台印了命令**，
    自己复制执行；真想让它代装系统包：./install.sh --with-system --yes
  · CJK 字体与浏览器：站点截图 / PDF 报告里的中文要靠它们，同上（没有也能跑，只是截图里中文变方块）。
  · 没有这些外部工具框架**仍能跑通**：会自动降级到内置实现，只是覆盖面与速度不如本体。

**换机器别拷 .venv**：venv 里写死了绝对路径（pyvenv.cfg、bin/activate、各 console script 的
shebang），换个目录或换台机器就失效 —— 症状是"拷过去跑不起来，但源码一个字没改"。
正确做法：拷**源码**（.venv 本来就在 .gitignore 里，git clone / git archive 天然不带它），
到新机器上再跑一次 ./install.sh。依赖版本由 requirements.lock 钉住，装出来的是同一批。
=====================================================================
EOF

# 与 run_bootstrap.py 同一个契约：0＝缺口为零或自动层全部补齐；非 0＝自动层里有项失败。
# 不在这里另立一套退出码口径（那又是一个会漂的产地）。
exit "$BOOT_RC"
