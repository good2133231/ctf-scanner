#!/usr/bin/env bash
# CTFScanner 启动控制台（Linux / macOS）。
#
# 只做两件事：挑对解释器、exec `run_gui.py`。启动时的交互（首个管理员向导、凭据密文口令）、
# 随机后台前缀、日志落盘全在 `gui/app.py::serve()` 里 —— 这里不重复实现，也不"顺手"补默认值
# （补了就是第二个产地，AGENTS §5.14）。
#
# 用法：
#   ./start.sh
#
# 改监听地址/端口**不是**命令行参数（run_gui.py 不解析 argv，传了会被静默忽略 —— 那正是本项目
# 最忌讳的"点了没反应"）。两条路，判据都在 `scanner/config.py::gui_bind()`：
#   CTFSCANNER_GUI_HOST=0.0.0.0 CTFSCANNER_GUI_PORT=5000 ./start.sh    # 环境变量优先（容器/临时）
#   或改 config/settings.yaml 的 gui.host / gui.port                    # 长期（也可在控制台策略页改）
# 注意 `gui.allowed_hosts` / `behind_proxy` / `secure_cookie` 是**安全开关**，刻意不给环境变量
# 覆盖 —— 必须显式写进配置，免得一个"顺手设了"的变量把它们悄悄打开。
#
# ⚠ 本文件必须保持 **LF** 行尾（.gitattributes 已钉），理由同 install.sh。
set -euo pipefail

cd "$(dirname "$0")"

# 优先用 install.sh 建出来的 .venv；没有就退回系统解释器 —— 但**依赖必须真在**，
# 缺了就直说"先跑 ./install.sh"，不要用半套环境把控制台起到一半再崩（那种报错最难查）。
if [ -x ".venv/bin/python" ]; then
  PY="./.venv/bin/python"
else
  PY="$(command -v python3 || command -v python || true)"
  if [ -z "$PY" ]; then
    echo "[X] 既没有 .venv 也没有 python3 —— 先跑 ./install.sh"
    exit 1
  fi
  echo "[!] 没有 .venv，退回系统解释器 $PY（依赖装在全局环境里）"
fi
if ! "$PY" -c 'import flask, requests, yaml' 2>/dev/null; then
  echo "[X] $PY 缺依赖（flask / requests / PyYAML 至少一个 import 不到）—— 先跑 ./install.sh"
  exit 1
fi

exec "$PY" run_gui.py
