"""POC 引擎：nuclei 风格 YAML 的简化实现（**兼容 nuclei 模板的核心子集**）。

为什么是"nuclei 子集"而不是"自创一套"（客观结论，2026-09 评估）：
- 参考项目 `myscan_20250825/exploit/scripts/**` 的 POC 是 Python 类脚本
  （继承 `BaseScript`，`detect()/exec()` 异步 aiohttp），**总数约 150 组但强耦合它自己的
  core 框架**（`AsyncFetcher` / `GlobalVariableManager` / `BugLevel` 等）。直接复用等于把
  对方整套框架搬进来，与本项目"零重依赖、外部工具优先"的定位冲突，故**不做运行时依赖**；
  但它的"检测路径 + 关键字命中"语义可以被静态提取成 YAML，见 `tools/import_ref_pocs.py`。
- nuclei 模板是社区事实标准（数千模板、持续更新、YAML 声明式、与本引擎同源）。
  因此这里**主动向 nuclei 语法靠拢**：官方模板可以直接丢进 `config/nuclei-templates/`
  被本引擎加载，从此不依赖 nuclei 二进制，也不与它冲突（同一份模板两边都能跑）。

支持的字段（完整说明见 docs/poc-guide.md）：
  id / info{name, author, severity, tags, description}
  favicon_md5_list（可选，排在 http 段之外）：零请求前置指纹，与 probe 阶段算出的
      站点 favicon MD5 比对，不匹配则整个 POC 一个请求都不发（P1-1）
  http[] 或 requests[]（两种写法等价）
    单请求项：method, path(字符串或列表), headers, body, payloads, attack,
              variables, redirects, matchers, matchers-condition, extractors
  匹配器：type: status | word | regex | size；part: body | header | all；
          condition: or|and；negative: true；case-insensitive
  提取器：type: regex | kval（命中内容会写进 evidence，便于人工确认）

刻意不做：raw 请求（HTTP 原文）、dsl 表达式、workflows/flow、oob（反连）。
含这些特性的模板会被标记 `unsupported` 并在 POC 管理页显示原因，而不是静默失效。
"""
import itertools
import json
import pathlib
import re
from urllib.parse import urlparse

try:
    import yaml
except ImportError:
    yaml = None

from ..config import resolve, skip_severities
from .. import db
from ..utils import http_request

# POC 目录：内置 / 用户上传 / 参考项目批量导入 / 官方 nuclei 模板投放点
POC_DIRS = ["scanner/pocs/pocs", "config/pocs-user", "config/pocs-imported",
            "config/nuclei-templates"]

# 单个 POC 对单个目标的最大请求数（防止 payload 笛卡尔积把目标打爆）
MAX_REQUESTS_PER_POC = 10

_UNSUPPORTED_KEYS = ("raw", "dsl", "flow", "workflows")

_SEVERITIES = ("critical", "high", "medium", "low", "info")


def _norm_severity(value):
    v = str(value or "medium").strip().lower()
    return v if v in _SEVERITIES else "info"


def _requests_of(data):
    """取请求列表，兼容 `http:` 与 nuclei 的 `requests:` 两种写法。"""
    for key in ("http", "requests"):
        blocks = data.get(key)
        if isinstance(blocks, list) and blocks:
            return blocks
    return []


def load_poc_file(path):
    """加载并校验单个 POC 文件，返回带 _status 标记的 dict（永不抛异常）。"""
    p = pathlib.Path(str(path))
    if yaml is None:
        return {"id": p.stem, "_status": "error", "_error": "PyYAML 未安装"}
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except Exception as e:
        return {"id": p.stem, "_status": "error", "_error": str(e)[:300]}
    if not isinstance(data, dict) or not data.get("id"):
        return {"id": p.stem, "_status": "error", "_error": "缺少 id"}
    blocks = _requests_of(data)
    if not blocks:
        # 顶层就是 workflow / 只有 raw：明确标记为不支持，而不是让它在扫描里静默失效
        if any(k in data for k in _UNSUPPORTED_KEYS):
            return {"id": data.get("id"), "_status": "unsupported",
                    "_error": "workflow/flow/raw 类模板暂不支持（见 docs/poc-guide.md）",
                    "_path": str(p)}
        return {"id": p.stem, "_status": "error", "_error": "缺少 http/requests 段"}
    runnable = [b for b in blocks if isinstance(b, dict) and not any(
        k in b for k in _UNSUPPORTED_KEYS)]
    if not runnable:
        return {"id": data.get("id"), "_status": "unsupported",
                "_error": "全部请求块均为 raw/dsl 形式，当前引擎不支持", "_path": str(p)}
    data["_status"] = "ok"
    data["_path"] = str(p)
    if len(runnable) != len(blocks):
        data["_note"] = f"{len(blocks) - len(runnable)} 个请求块含 raw/dsl，已跳过"
    return data


def iter_poc_files(settings=None):
    for d in POC_DIRS:
        base = resolve(d)
        if base.is_dir():
            for f in sorted(base.glob("*.yaml")) + sorted(base.glob("*.yml")):
                yield f


def load_all_meta(settings=None):
    """加载目录内全部 POC 的元信息（含 error/unsupported 项，供注册表展示）。"""
    return [load_poc_file(f) for f in iter_poc_files(settings)]


def load_enabled_pocs(settings=None):
    """扫描用：仅返回 status=ok、注册表启用、且**级别未被 `checks.skip_severities` 排除**的 POC。

    `skip_severities`（默认 info + low）与内置检查同一套规则：这些 POC 的结论同样会被
    `min_severity` 丢掉，不执行只省请求（导入的 300+ 个 POC 里此类模板不少）。
    未知/缺失 severity 由 `_norm_severity` 归为 info，同样会被跳过 —— 想让某条 info 级
    POC 生效，把它自己写 severity 改成 medium 以上，或在策略配置里清空 skip_severities。
    """
    try:
        enabled = set(db.enabled_poc_paths())
    except Exception:
        enabled = None  # 注册表未初始化时不做过滤
    skip = skip_severities(settings)
    out = []
    for m in load_all_meta(settings):
        if m.get("_status") != "ok":
            continue
        if enabled is not None and m.get("_path") not in enabled:
            continue
        if _norm_severity((m.get("info") or {}).get("severity")) in skip:
            continue
        out.append(m)
    return out


# ---------- 变量渲染 ----------

_VAR_RE = re.compile(r"\{\{\s*([A-Za-z0-9_.\-]+)\s*\}\}")


def builtin_vars(base_url):
    p = urlparse(base_url)
    port = p.port or (443 if p.scheme == "https" else 80)
    return {
        "BaseURL": base_url.rstrip("/"),
        "RootURL": f"{p.scheme}://{p.netloc}",
        "Hostname": p.netloc,
        "Host": p.hostname or "",
        "Port": str(port),
        "Scheme": p.scheme,
        "Path": p.path or "/",
    }


def _render(text, variables):
    if text is None:
        return None
    return _VAR_RE.sub(
        lambda m: str(variables.get(m.group(1), m.group(0))), str(text))


# ---------- payload 组合 ----------

def _payload_sets(req, limit=MAX_REQUESTS_PER_POC):
    """把 `payloads` 展开成一组变量字典。支持 list 与 nuclei 的 dict + attack。"""
    pl = req.get("payloads")
    if not pl:
        return [{}]
    if isinstance(pl, list):
        return [{"payload": v} for v in pl[:limit]]
    if not isinstance(pl, dict) or not pl:
        return [{}]
    keys = list(pl.keys())
    lists = [[(k, v) for v in (pl[k] if isinstance(pl[k], list) else [pl[k]])]
             for k in keys]
    attack = str(req.get("attack") or "clusterbomb").lower()
    combos = []
    if attack == "pitchfork":
        n = min(len(l) for l in lists)
        for j in range(n):
            combos.append({lists[i][j][0]: lists[i][j][1] for i in range(len(lists))})
    elif attack == "batteringram":
        for v in lists[0]:
            combos.append({k: v[1] for k in keys})
    else:  # clusterbomb：笛卡尔积
        for combo in itertools.product(*lists):
            combos.append({k: v for k, v in combo})
    return combos[:limit] or [{}]


# ---------- 匹配器 / 提取器 ----------

def _part_text(resp, part):
    part = str(part or "body").lower()
    body = resp.get("text") or ""
    if part in ("header", "headers"):
        return "\n".join(f"{k}: {v}" for k, v in (resp.get("headers") or {}).items())
    if part == "all":
        return "\n".join(f"{k}: {v}" for k, v in (resp.get("headers") or {}).items()) + "\n" + body
    return body


def _match_one(m, resp):
    t = str(m.get("type") or "").lower()
    ci = m.get("case-insensitive", True) is not False
    cond = str(m.get("condition") or "or").lower()
    ok = False
    if t == "status":
        try:
            allowed = [int(x) for x in (m.get("status") or [])]
        except (TypeError, ValueError):
            allowed = []
        ok = resp.get("status") in allowed
    elif t in ("word", "words"):
        text = _part_text(resp, m.get("part"))
        if ci:
            text = text.lower()
        words = [(str(w).lower() if ci else str(w)) for w in (m.get("words") or [])]
        ok = bool(words) and (any(w in text for w in words) if cond == "or"
                              else all(w in text for w in words))
    elif t == "regex":
        text = _part_text(resp, m.get("part"))
        ok = any(_safe_search(p, text, ci) for p in (m.get("regex") or []))
    elif t in ("size", "length"):
        try:
            sizes = [int(x) for x in (m.get("size") or m.get("sizes") or [])]
        except (TypeError, ValueError):
            sizes = []
        ok = resp.get("length") in sizes
    else:
        ok = False  # binary / dsl 等暂不支持，按不命中处理（不产生误报）
    if m.get("negative"):
        ok = not ok
    return ok


def _safe_search(pattern, text, ci=True):
    try:
        return bool(re.search(str(pattern), text, re.I if ci else 0))
    except re.error:
        return False


def _match_response(resp, matchers, condition):
    results = [_match_one(m, resp) for m in (matchers or []) if isinstance(m, dict)]
    if not results:
        return False
    return all(results) if str(condition or "or").lower() == "and" else any(results)


def _extract(resp, extractors):
    """执行 extractors，返回命中的文本片段列表（用于 evidence）。"""
    out = []
    for ex in extractors or []:
        if not isinstance(ex, dict):
            continue
        t = str(ex.get("type") or "").lower()
        text = _part_text(resp, ex.get("part"))
        if t == "regex":
            for pat in (ex.get("regex") or []):
                try:
                    for m in re.finditer(str(pat), text):
                        out.append(m.group(0))
                except re.error:
                    continue
        elif t == "kval":
            for key in (ex.get("kval") or []):
                m = re.search(rf"(?im)^{re.escape(str(key))}\s*:\s*(.+)$", text)
                if m:
                    out.append(f"{key}: {m.group(1).strip()}")
    return sorted(set(str(x)[:200] for x in out))[:5]


# ---------- 执行 ----------

def run_poc_on_target(poc, base_url, settings, max_requests=MAX_REQUESTS_PER_POC, site=None):
    """对单个目标执行单个 POC；命中即返回一条 vuln dict（每 POC 每目标最多一条）。

    `site` 为 probe 产出的站点信息（可含 `favicon`/`tech`），用于**零请求前置判定**：
    POC 声明了 `favicon_md5_list` 且当前站点 favicon 已知但不匹配时直接跳过，
    省掉整个 POC 的请求；站点 favicon 未知时**不**做排除（宁可多打，不漏判）。
    """
    timeout = int((settings or {}).get("limits", {}).get("http_timeout", 10))
    fav_list = poc.get("favicon_md5_list") or []
    if fav_list and isinstance(site, dict):
        cur = str(site.get("favicon") or "").lower()
        if cur and cur not in {str(h).lower() for h in fav_list}:
            return []
    info = poc.get("info", {}) or {}
    variables = dict(builtin_vars(base_url))
    for k, v in (poc.get("variables") or {}).items():
        variables[str(k)] = _render(v, variables)
    count = 0
    for req in _requests_of(poc):
        if not isinstance(req, dict) or any(k in req for k in _UNSUPPORTED_KEYS):
            continue
        if count >= max_requests:
            break
        method = str(req.get("method") or "GET").upper()
        raw_paths = req.get("path") or req.get("paths") or "/"
        paths = raw_paths if isinstance(raw_paths, list) else [raw_paths]
        headers = {str(k): _render(v, variables)
                   for k, v in (req.get("headers") or {}).items()}
        redirects = req.get("redirects", True) is not False
        for varset in _payload_sets(req, max_requests):
            if count >= max_requests:
                break
            ctx_vars = dict(variables)
            ctx_vars.update({str(k): str(v) for k, v in varset.items()})
            for p in paths:
                if count >= max_requests:
                    break
                path = _render(p, ctx_vars) or "/"
                url = base_url.rstrip("/") + (path if str(path).startswith("/") else "/" + str(path))
                body = _render(req.get("body"), ctx_vars)
                resp = http_request(url, method=method, headers=headers or None, data=body,
                                    timeout=timeout, settings=settings,
                                    allow_redirects=redirects)
                count += 1
                if not resp:
                    continue
                if not _match_response(resp, req.get("matchers"),
                                       req.get("matchers-condition") or "or"):
                    continue
                owasp = ",".join(
                    str(t).lower().replace("owasp-", "").upper()
                    for t in (info.get("tags") or [])
                    if str(t).lower().startswith("owasp"))
                extracted = _extract(resp, req.get("extractors"))
                evidence = ("\n".join(extracted) if extracted
                            else (resp.get("text") or "")[:400])
                return [{
                    "poc_id": poc.get("id"),
                    "name": info.get("name") or poc.get("id"),
                    "severity": _norm_severity(info.get("severity")),
                    "owasp": owasp,
                    "target": base_url,
                    "detail": (f"POC 命中：{info.get('name') or poc.get('id')}"
                               f"（请求 {method} {url}）。" + (info.get("description") or "")),
                    "evidence": evidence,
                }]
    return []