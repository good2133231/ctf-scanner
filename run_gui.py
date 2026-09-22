"""启动 Web 控制台：python run_gui.py（Windows 下可用 py -3 run_gui.py）"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gui.app import serve

if __name__ == "__main__":
    serve()