#!/usr/bin/env bash
# 远程服务器一键更新：拉 GitHub 最新 main + 对齐依赖（可选跑门禁 / 重启控制台）。
#
# 给谁用：本地改代码 → push 到 GitHub 后，在**服务器**上把仓库更新到最新再启动验证。
# 用法（在仓库目录内外都能跑，脚本自己定位仓库根）：
#   bash update.sh                 # 只更新代码 + 依赖（lock 变了才装）
#   bash update.sh --smoke         # 更新后顺带跑全量门禁（服务器正式收尾口径，约 6~10 分钟）
#   bash update.sh --restart       # 更新后重启控制台（端口取 CTFSCANNER_GUI_PORT，默认 5000）
#   bash update.sh --smoke --restart
#
# 口径（AGENTS §0 硬规矩，一条都不松）：
#   - 工作区有未提交改动 ⇒ 拒绝更新（服务器上"顺手热修"是跨机事故的唯一来源）；
#   - 同步前先跑 tools/sync_check.py --strict（脏区/未推送非 0 即停）；
#   - 只 rebase，绝不做破坏性硬重置；
#   - 依赖只从 requirements.lock 装（CI 与安装都不吃 requirements.txt，回归 [8al]）；
#   - 重启只杀"本脚本自己起过、pid 文件记着"的那个进程 —— 不按名字乱杀，
#     端口被没记过的进程占着就明说，不猜。
#
# ⚠ 本文件必须保持 **LF** 行尾（.gitattributes 已钉 *.sh），理由同 start.sh。
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [ -z "$ROOT" ]; then
  echo "[X] 不在 git 仓库里 —— 请先 cd 到服务器上的 ctf-scanner 仓库目录" >&2
  exit 1
fi
cd "$ROOT"

PORT="${CTFSCANNER_GUI_PORT:-5000}"
PIDFILE="logs/gui-$PORT.pid"
DO_SMOKE=0
DO_RESTART=0
for arg in "$@"; do
  case "$arg" in
    --smoke)   DO_SMOKE=1 ;;
    --restart) DO_RESTART=1 ;;
    -h|--help) sed -n '4,14p' "$0"; exit 0 ;;
    *) echo "[X] 不认识的参数：$arg（只支持 --smoke / --restart / -h）" >&2; exit 1 ;;
  esac
done

echo "[1/5] 开工体检：工作区必须干净"
if [ -n "$(git status --short)" ]; then
  echo "[X] 有未提交改动 —— 先提交或 stash，再更新（未提交的'顺手热修'就是跨机事故源）：" >&2
  git status --short >&2
  exit 1
fi
python3 tools/sync_check.py --strict

echo "[2/5] 拉取 GitHub 最新 main（rebase，不做破坏性硬重置）"
git fetch origin main
git pull --rebase origin main

echo "[3/5] 依赖对齐（.venv 没有就建；requirements.lock 有变动才重装）"
PY="./.venv/bin/python"
if [ ! -x "$PY" ]; then
  echo "    没找到 .venv，用当前 python3 建一个…"
  python3 -m venv .venv
fi
if git diff --quiet "HEAD@{1}" HEAD -- requirements.lock 2>/dev/null; then
  echo "    requirements.lock 未变动，跳过安装（要强制重装先 touch 它，或手动 pip install -r requirements.lock）"
else
  echo "    requirements.lock 有变动，按 lock 重装依赖…"
  "$PY" -m pip install -r requirements.lock
fi

if [ "$DO_SMOKE" = "1" ]; then
  echo "[4/5] 全量门禁（服务器正式收尾口径；约 6~10 分钟，跑完见 SMOKE PASS）"
  "$PY" tests/smoke.py
else
  echo "[4/5] 跳过门禁（服务器收尾建议跑一次：bash update.sh --smoke）"
fi

if [ "$DO_RESTART" = "1" ]; then
  echo "[5/5] 重启控制台（端口 $PORT）"
  if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    OLD="$(cat "$PIDFILE")"
    echo "    停掉上次由本脚本起的进程（pid $OLD）…"
    kill "$OLD" 2>/dev/null || true
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      kill -0 "$OLD" 2>/dev/null || break
      sleep 0.5
    done
    kill -0 "$OLD" 2>/dev/null && kill -9 "$OLD" 2>/dev/null || true
  fi
  mkdir -p logs
  CTFSCANNER_GUI_PORT="$PORT" nohup "$PY" run_gui.py >> "logs/gui-$PORT.log" 2>&1 &
  echo $! > "$PIDFILE"
  OK=0
  for _ in $(seq 1 60); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then
      exec 3>&- 3<&- 2>/dev/null || true
      OK=1
      break
    fi
    sleep 0.5
  done
  if [ "$OK" = "1" ]; then
    echo "    [OK] 控制台已监听 $PORT（pid $(cat "$PIDFILE")，日志 logs/gui-$PORT.log）"
  else
    echo "    [!] 30 秒还没监听 $PORT —— 看日志排查：tail -n 50 logs/gui-$PORT.log" >&2
    exit 1
  fi
else
  echo "[5/5] 未要求重启。启动控制台（照抄即可）："
  echo "    CTFSCANNER_GUI_PORT=$PORT nohup ./.venv/bin/python run_gui.py >> logs/gui-$PORT.log 2>&1 &"
fi

echo
echo "[OK] 已更新到：$(git log --oneline -1)"
echo "     本地/远程一致口径：本地 push ↔ 服务器 pull；门禁权威在服务器跑（本机跑见 dev.py smoke）。"
