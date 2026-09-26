#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CTFScanner 主题配色对比度体检（WCAG 2.1 AA）。

用法::

    py -3 tools/check_contrast.py                 # 四主题全量体检，全绿退出码 0
    py -3 tools/check_contrast.py --theme light   # 只看某一个主题
    py -3 tools/check_contrast.py --all           # 连「已知豁免」的装饰性配对一起打印

为什么要有这个脚本
------------------
``gui/static/style.css`` 里四套主题靠 CSS 自定义属性切换，有两类缺陷会静默发生：

1. **漏写变量**：某套主题少写一个变量，它就按 CSS 层叠退回 ``:root``（深色）取值 ——
   浅色主题下直接变成「深底深字」（看不见）。故本脚本**按层叠语义**把 ``:root`` 的默认值
   并入每套主题后再算对比度：真正的一级缺陷是 ``FAIL``（对比度不够），
   只有「四套都没定义」才会报 ``MISSING``。
2. **游离色值**：规则体里直接写死 hex（不走变量），那一处永远不随主题切换。
   这正是续23 的两个元凶 —— ``tr:hover td{background:#1a2230}`` 与 ``input/pre{background:#0d1218}``，
   实测浅色主题下对比度 1.06:1 / 1.25:1。故本脚本另有一道**裸值守卫**：主题变量块之外的
   任何颜色字面量都算失败。修法就是把它提升为 ``var(--x)``。

两类问题任一出现，退出码都非 0。

对比度公式（WCAG 2.1）
----------------------
先把每个 sRGB 分量线性化（``c<=0.03928 ? c/12.92 : ((c+0.055)/1.055)**2.4``），
再取相对亮度 ``L = 0.2126*R + 0.7152*G + 0.0722*B``，
对比度 ``(L_light + 0.05) / (L_dark + 0.05)``。

判定口径
--------
* 文字 / 正文 >= 4.5:1（WCAG 1.4.3 AA）。
* 必要的 UI 组件边界 >= 3:1（WCAG 1.4.11 AA）—— 本轮落到「交互控件描边 ``--border``」。
* 纯装饰性分隔线（``--line``）**不参与判定**：1.4.11 只约束「识别组件所必需」的视觉信息，
  表格/面板分隔线与卡片描边属于装饰，强行拉到 3:1 会把四套主题全改成重边框（等于重做视觉），
  超出「配色修复」的范围。它们的实测值用 ``--all`` 打印，作为「已知不达标、有意不改」的留档。
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
CSS_PATH = REPO_ROOT / "gui" / "static" / "style.css"

#: :root 是深色默认值，其余三套用 html[data-theme] 覆盖
THEMES: Tuple[str, ...] = ("dark", "light", "ocean", "violet")

TH_TEXT = 4.5   #: 正文/文字阈值（WCAG 1.4.3 AA）
TH_UI = 3.0     #: UI 组件边界阈值（WCAG 1.4.11 AA）

# --------------------------------------------------------------------------- 颜色工具


def _srgb_to_linear(channel: float) -> float:
    """把 0~1 的 sRGB 分量转成线性分量。"""
    if channel <= 0.03928:
        return channel / 12.92
    return ((channel + 0.055) / 1.055) ** 2.4


def parse_color(value: str) -> Tuple[float, float, float]:
    """把 ``#rgb`` / ``#rrggbb`` 解析成 0~255 三元组；非法输入抛 ``ValueError``。"""
    raw = value.strip().lstrip("#")
    if len(raw) == 3:
        raw = "".join(ch * 2 for ch in raw)
    if len(raw) != 6 or not re.fullmatch(r"[0-9a-fA-F]{6}", raw):
        raise ValueError("非法颜色值: %r" % value)
    return (int(raw[0:2], 16), int(raw[2:4], 16), int(raw[4:6], 16))


def luminance(value: str) -> float:
    """返回颜色的 WCAG 相对亮度（0=纯黑，1=纯白）。"""
    red, green, blue = parse_color(value)
    return (
        0.2126 * _srgb_to_linear(red / 255.0)
        + 0.7152 * _srgb_to_linear(green / 255.0)
        + 0.0722 * _srgb_to_linear(blue / 255.0)
    )


def contrast(foreground: str, background: str) -> float:
    """返回两色对比度（1~21），与传入顺序无关。"""
    light = luminance(foreground)
    dark = luminance(background)
    if light < dark:
        light, dark = dark, light
    return (light + 0.05) / (dark + 0.05)


# --------------------------------------------------------------------------- CSS 解析

_BLOCK_RE = re.compile(
    r"(?P<sel>:root|html\[data-theme=\"(?P<theme>[a-z]+)\"\])\s*\{(?P<body>[^{}]*)\}",
    re.S,
)
_DECL_RE = re.compile(r"(?P<name>--[\w-]+)\s*:\s*(?P<value>[^;]+);")
_VAR_RE = re.compile(r"^var\((?P<name>--[\w-]+)\)$")


def parse_themes(css_text: str) -> Dict[str, Dict[str, str]]:
    """解析出 ``{主题名: {变量名: 原始取值}}``，**已按 CSS 层叠语义并入 ``:root`` 默认值**。

    ``:root`` 是深色默认值，其余三套主题只写「与深色不同」的项，其余继承 ``:root``。
    所以这里先收集各主题的**显式**声明，再把 ``:root`` 的键值补进每个主题：
    这样「某主题漏写某变量」会真实地退化成深色取值（由对比度 ``FAIL`` 抓），
    而不是被误判成 ``MISSING`` —— 只有四套都没定义才算真的缺变量。
    """
    raw: Dict[str, Dict[str, str]] = {}
    for match in _BLOCK_RE.finditer(css_text):
        theme = match.group("theme") or "dark"
        if theme not in THEMES:
            continue
        declarations = {
            m.group("name"): m.group("value").strip()
            for m in _DECL_RE.finditer(match.group("body"))
        }
        raw.setdefault(theme, {}).update(declarations)

    base = raw.get("dark", {})
    themes: Dict[str, Dict[str, str]] = {}
    for theme in THEMES:
        if theme == "dark":
            themes["dark"] = dict(base)
        elif theme in raw:
            themes[theme] = dict(base, **raw[theme])   # 显式声明覆盖 :root 默认值
    return themes


# --------------------------------------------------------------------------- 裸值守卫

_COMMENT_RE = re.compile(r"/\*.*?\*/", re.S)
_ANY_BLOCK_RE = re.compile(r"(?P<sel>[^{}]*)\{(?P<body>[^{}]*)\}", re.S)
_HEX_RE = re.compile(r"#[0-9a-fA-F]{3,8}\b")


def _theme_block_spans(css_text: str) -> List[Tuple[int, int]]:
    """返回主题变量块（``:root`` 与 ``html[data-theme=...]``）的字符区间，用于排除。"""
    return [(m.start(), m.end()) for m in _BLOCK_RE.finditer(css_text)]


def find_stray_literals(css_text: str) -> List[Tuple[int, str, str]]:
    """找出主题变量块**之外**的颜色字面量，返回 ``[(行号, 选择器, 色值)]``。

    * 只扫规则体（``{...}`` 内部）—— 选择器里的 ``#id`` 天然不参与，避免误报。
    * 主题块按**字符区间**排除（不做选择器字符串比对），对 BOM / 注释 / 换行都不敏感。
    * 注释先被等长替换成空白（保留换行），注释里的 hex 不算问题。
    """
    stripped = _COMMENT_RE.sub(lambda m: "".join("\n" if c == "\n" else " " for c in m.group(0)), css_text)
    spans = _theme_block_spans(css_text)
    found: List[Tuple[int, str, str]] = []
    for block in _ANY_BLOCK_RE.finditer(stripped):
        body_start, body_end = block.start("body"), block.end("body")
        # 用「规则体区间」判归属：_ANY_BLOCK_RE 的选择器会把前置注释也算进去，
        # 只看 match.start() 会把主题块自己误判成游离规则体。
        if any(s <= body_start and body_end <= e for s, e in spans):
            continue
        selector = block.group("sel").strip().splitlines()[-1].strip()
        body = block.group("body")
        body_start_line = stripped[:body_start].count("\n") + 1
        for hit in _HEX_RE.finditer(body):
            line = body_start_line + body[: hit.start()].count("\n")
            found.append((line, selector or "(顶层规则)", hit.group(0)))
    return found


def resolve(variables: Dict[str, str], name: str, _seen: Optional[set] = None) -> Optional[str]:
    """把一个变量求值成 ``#rrggbb``；支持 ``var(--x)`` 间接引用，缺失返回 ``None``。"""
    seen = _seen or set()
    if name in seen:
        raise ValueError("变量循环引用: %s" % name)
    raw = variables.get(name)
    if raw is None:
        return None
    raw = raw.strip()
    indirect = _VAR_RE.match(raw)
    if indirect:
        return resolve(variables, indirect.group("name"), seen | {name})
    return raw


# --------------------------------------------------------------------------- 检查项

Pair = Tuple[str, str, str, float]     # (说明, 前景, 背景, 阈值)
ExemptPair = Tuple[str, str, str]      # (说明, 前景, 背景)

#: 文字类配对，阈值 4.5:1。带 ★ 的是用户在浅色主题下点名"看不见"的四个病灶。
TEXT_PAIRS: Sequence[Pair] = (
    ("正文 / 页面底",                 "--text",     "--bg",          TH_TEXT),
    ("正文 / 面板底",                 "--text",     "--panel",       TH_TEXT),
    ("次要文字 / 页面底",             "--muted",    "--bg",          TH_TEXT),
    ("次要文字 / 面板底",             "--muted",    "--panel",       TH_TEXT),
    ("链接 accent / 页面底",          "--accent",   "--bg",          TH_TEXT),
    ("链接 accent / 面板底",          "--accent",   "--panel",       TH_TEXT),
    ("★行悬停 正文 / --hover",        "--text",     "--hover",       TH_TEXT),
    ("★输入框 正文 / --input-bg",     "--text",     "--input-bg",    TH_TEXT),
    ("代码块 正文 / --code-bg",       "--text",     "--code-bg",     TH_TEXT),
    ("★错误文字 --danger / 页面底",   "--danger",   "--bg",          TH_TEXT),
    ("错误文字 --danger / 面板底",    "--danger",   "--panel",       TH_TEXT),
    ("★.badge 正文 / --chip-bg",      "--text",     "--chip-bg",     TH_TEXT),
    ("顶栏 正文 / --topbar-bg",       "--text",     "--topbar-bg",   TH_TEXT),
    ("ghost 按钮字 / --ghost-bg",     "--ghost-fg", "--ghost-bg",    TH_TEXT),
    ("ghost 悬停字 / --ghost-hover",  "--text",     "--ghost-hover", TH_TEXT),
    ("主按钮字 / --btn-bg",           "--btn-fg",   "--btn-bg",      TH_TEXT),
    ("危险按钮字 / --danger-bg",      "--danger",   "--danger-bg",   TH_TEXT),
    ("侧栏项 次要字 / --side",        "--muted",    "--side",        TH_TEXT),
    ("侧栏选中 accent / --side-active", "--accent", "--side-active", TH_TEXT),
    ("筛选框 次要字 / --input-bg",    "--muted",    "--input-bg",    TH_TEXT),
    ("技术栈标签 正文 / --soft",      "--text",     "--soft",        TH_TEXT),
)

#: 11 组徽章：任务状态 6 组（含续49 的 st-queued 排队中）+ 漏洞等级 5 组，
#: 前景/背景成对定义，全部按正文 4.5:1 判定。
BADGE_PAIRS: Sequence[Pair] = (
    ("徽章 st-running",   "--st-run-fg",  "--st-run-bg",  TH_TEXT),
    ("徽章 st-done",      "--st-done-fg", "--st-done-bg", TH_TEXT),
    ("徽章 st-failed",    "--st-fail-fg", "--st-fail-bg", TH_TEXT),
    ("徽章 st-pending",   "--st-wait-fg", "--st-wait-bg", TH_TEXT),
    ("徽章 st-stopped",   "--st-stop-fg", "--st-stop-bg", TH_TEXT),
    ("徽章 st-queued",    "--st-queue-fg", "--st-queue-bg", TH_TEXT),
    ("徽章 sev-critical", "--sev-crit-fg", "--sev-crit-bg", TH_TEXT),
    ("徽章 sev-high",     "--sev-high-fg", "--sev-high-bg", TH_TEXT),
    ("徽章 sev-medium",   "--sev-med-fg",  "--sev-med-bg",  TH_TEXT),
    ("徽章 sev-low",      "--sev-low-fg",  "--sev-low-bg",  TH_TEXT),
    ("徽章 sev-info",     "--sev-info-fg", "--sev-info-bg", TH_TEXT),
)

#: 必要的 UI 组件边界，阈值 3:1（WCAG 1.4.11）。描边两侧的底色都要能分辨出来。
UI_PAIRS: Sequence[Pair] = (
    ("交互控件描边 --border / 面板底", "--border", "--panel",    TH_UI),
    ("交互控件描边 --border / 页面底", "--border", "--bg",       TH_UI),
    ("交互控件描边 --border / 输入框底", "--border", "--input-bg", TH_UI),
)

#: 装饰性 / 由文字标签标识的配对：只留档不判定（理由见模块 docstring「判定口径」）。
EXEMPT_PAIRS: Sequence[ExemptPair] = (
    ("（装饰）分隔线 --line / 面板底",        "--line",     "--panel"),
    ("（装饰）分隔线 --line / 页面底",        "--line",     "--bg"),
    ("（装饰）侧栏底 --side / 页面底",        "--side",     "--bg"),
    ("（由文字标签标识）主按钮底 / 面板底",   "--btn-bg",   "--panel"),
    ("（由文字标签标识）ghost 底 / 面板底",   "--ghost-bg", "--panel"),
)


# --------------------------------------------------------------------------- 执行


def _eval_pair(variables: Dict[str, str], fg: str, bg: str) -> Tuple[Optional[float], Optional[str]]:
    """返回 ``(对比度, 缺失变量名)``；两者互斥，缺失时对比度为 ``None``。"""
    missing = [n for n in (fg, bg) if n.startswith("--") and resolve(variables, n) is None]
    if missing:
        return None, ",".join(missing)
    fg_value = fg if fg.startswith("#") else resolve(variables, fg)
    bg_value = bg if bg.startswith("#") else resolve(variables, bg)
    assert fg_value is not None and bg_value is not None
    return contrast(fg_value, bg_value), None


def check_theme(theme: str, variables: Dict[str, str], show_exempt: bool) -> Tuple[int, int, List[str]]:
    """检查单个主题，返回 ``(检查数, 失败数, 输出行)``。"""
    lines: List[str] = []
    checks = 0
    failures = 0
    lines.append("=" * 66)
    lines.append("主题 %s（%d 个变量）" % (theme, len(variables)))
    lines.append("=" * 66)

    for group_name, pairs in (("文字", list(TEXT_PAIRS) + list(BADGE_PAIRS)), ("UI 边界", UI_PAIRS)):
        for label, fg, bg, threshold in pairs:
            checks += 1
            ratio, missing = _eval_pair(variables, fg, bg)
            if missing is not None:
                failures += 1
                lines.append("  [MISSING] %-30s 缺变量: %s" % (label, missing))
            elif ratio < threshold:
                failures += 1
                lines.append(
                    "  [FAIL   ] %-30s %.2f:1 (需 %.1f)  %s / %s"
                    % (label, ratio, threshold, fg, bg)
                )
            else:
                lines.append("  [  ok   ] %-30s %.2f:1" % (label, ratio))
        lines.append("  ---- %s 组结束 ----" % group_name)

    if show_exempt:
        lines.append("  [留档，不判定]")
        for label, fg, bg in EXEMPT_PAIRS:
            ratio, missing = _eval_pair(variables, fg, bg)
            if missing is not None:
                lines.append("  [   -   ] %-30s 缺变量: %s" % (label, missing))
            else:
                lines.append("  [   -   ] %-30s %.2f:1" % (label, ratio))
    return checks, failures, lines


def gate(css_text: str) -> List[str]:
    """返回所有不达标项的简短描述（空列表 = 全绿）。

    这是**唯一口径**：``main()`` 的退出码、``tests/smoke.py [6n]`` 的断言、
    以及证伪脚本都调它，避免三处各写一套导致「门禁说绿、断言其实没测」。
    """
    problems: List[str] = []
    themes = parse_themes(css_text)
    for theme in THEMES:
        if theme not in themes:
            problems.append("主题 %s 在 CSS 里没有定义" % theme)
            continue
        _checks, _failures, lines = check_theme(theme, themes[theme], False)
        problems += ["%s: %s" % (theme, ln.strip()) for ln in lines if "FAIL" in ln or "MISSING" in ln]
    problems += ["裸值 %s:%d %s %s（不随主题切换，请改用 var(--x)）" % (CSS_PATH.name, ln, sel, val)
                 for ln, sel, val in find_stray_literals(css_text)]
    return problems


def main(argv: Optional[Sequence[str]] = None) -> int:
    """命令行入口：返回 0 表示全部达标，1 表示有失败项。"""
    parser = argparse.ArgumentParser(description="CTFScanner 主题配色对比度体检（WCAG AA）")
    parser.add_argument("--css", default=str(CSS_PATH), help="待检查的 CSS 路径")
    parser.add_argument("--theme", choices=list(THEMES), help="只看某个主题")
    parser.add_argument("--all", action="store_true", help="连已知豁免的装饰性配对一起打印")
    args = parser.parse_args(argv)

    css_path = Path(args.css)
    if not css_path.is_file():
        print("找不到 CSS: %s" % css_path)
        return 2
    css_text = css_path.read_text(encoding="utf-8")
    themes = parse_themes(css_text)

    want = (args.theme,) if args.theme else THEMES
    total_checks = 0
    total_failures = 0
    for theme in want:
        if theme not in themes:
            print("!! 主题 %s 在 CSS 里没有定义" % theme)
            total_failures += 1
            continue
        checks, failures, lines = check_theme(theme, themes[theme], args.all)
        total_checks += checks
        total_failures += failures
        print("\n".join(lines))

    # 裸值守卫：主题变量块之外出现颜色字面量 = 该处永远不随主题切换（续23 的元凶形态）
    strays = find_stray_literals(css_text)
    total_checks += 1
    print("")
    print("=" * 66)
    print("裸值守卫（主题块外不得出现颜色字面量）")
    print("=" * 66)
    if strays:
        total_failures += 1
        for line, selector, value in strays:
            print("  [STRAY  ] %s:%d  %s  { ... %s ... }  → 请改用 var(--x)" % (css_path.name, line, selector, value))
    else:
        print("  [  ok   ] 主题块外 0 处颜色字面量")

    print("")
    print("合计：%d 项检查，%d 项失败（文字需 >= %.1f:1，UI 边界需 >= %.1f:1，裸值需 0 处）"
          % (total_checks, total_failures, TH_TEXT, TH_UI))
    return 1 if total_failures else 0


if __name__ == "__main__":
    sys.exit(main())
