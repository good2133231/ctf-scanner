"""日志：控制台 + 任务文件双通道。每个任务使用独立 logger 名，绑定独立日志文件。"""
import logging
import sys


def get_logger(name, log_file=None):
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S")
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    sh.setLevel(logging.INFO)
    logger.addHandler(sh)
    if log_file:
        fh = logging.FileHandler(str(log_file), encoding="utf-8")
        fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        fh.setLevel(logging.DEBUG)
        logger.addHandler(fh)
    return logger
