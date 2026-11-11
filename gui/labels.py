# -*- coding: utf-8 -*-
"""资产来源标签（续377：从 app.py 抽出，纯字典）。

唯一用到外部符号的是 `extdom.REVERSE_SOURCE`，这里显式 import；
`app.py` 用 `from .labels import SOURCE_LABELS` 原样暴露这个名字。
"""
from scanner import extdom

SOURCE_LABELS = {
    "subfinder": "被动(subfinder)",
    "puredns": "爆破(puredns)",
    "dns-brute(fallback)": "爆破(内置)",
    "js:mine": "JS 挖掘",
    # 两个 FOFA 来源都显式带上「FOFA」字样：用户要求一眼看出哪些资产是 FOFA 找出来的
    # 续341：C 段反查已停用，旧任务里的 osint:cseg 只是历史证据，别再让它看起来像现功能。
    "osint:cseg": "IP 反查（历史 C 段，已停用）",
    extdom.REVERSE_SOURCE: "IP 反查回写（自身）",
    "osint:reverse": "IP 反查（第三方接口）",
    "osint:fofa": "FOFA·ICO 反查",
    "osint:fofa-cert": "FOFA·证书反查",
    "osint:fofa-title": "FOFA·标题反查",
    "osint:fofa-host": "FOFA·host 反查(同IP)",
    "osint:fofa-web": "FOFA·web 端口探活",
    # 批次 4 新增的三家同源/同源类来源：都带厂商名，一眼看出是哪个平台找出来的
    "osint:shodan": "Shodan·ICO 反查",
    "osint:quake": "Quake·ICO 反查",
    "osint:ctlog": "CT 日志(crt.sh)",
    "osint:redirect": "跳转落点",
    # 自动拓展扫描（`auto_expand`）：目标是子域时，把它自己也记成一条子域名资产
    "target": "目标自带子域",
}
