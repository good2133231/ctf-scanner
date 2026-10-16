"""POC / 指纹的**自动更新**（续206，主理人点单「--update-pocs 你之前排第一的」）。

口径完全照本包下那个**外部工具二进制**的更新器（同一批硬规矩，一条不减）：
  ① 只走 **https**；② 只允许**官方主机**（`ALLOWED_HOSTS`）；③ 落盘前过 **SHA256**
     （manifest 记着，重复跑就是 no-op）；④ 成员名防**路径穿越**（`_safe_member`）；
  ⑤ 逐文件**校验**不过就拒收，不静默吞；⑥ 只写本项目目录（`config/nuclei-templates/`）。
差别只在"取什么"：工具那边取 release 资产，这边取 nuclei 模板仓库的**指定子目录**
（整仓约 9000 个模板，不能整份拉 ⇒ `git sparse-checkout` 只取要用的那几个目录）。

**为什么指纹源和 POC 源是同一件事**（主理人点单「指纹库下一个源：nuclei 官方的
http/fingerprints/，正好和 --update-pocs 是同一件事」）：nuclei 的 `http/fingerprints/`
本身就是 nuclei 风格 yaml，和 FingerprintHub 同一格式 ⇒ 拉下来后
`tools/import_fingerprints.py --kind fingerprinthub` 直接就能吃。所以 `update()`
把文件按目录分成两路：`fingerprints/` 走指纹表转换，其余（`vulnerabilities/` 等）
落进 `config/nuclei-templates/` 被 POC 引擎自动发现（`POC_DIRS` 里已有这一项，
所以**不需要**回写任何配置）。

**运行期 RCE 护栏**（续206，主理人点单「参数路由的 RCE 只识别不测，红线」）：
AGENTS §1 的红线是"检测一律非破坏性、不写操作"，而**确认**一个命令执行漏洞就得让目标
真的执行命令（afrog 的 `pocs/` 里就混着一条 `hfs-rce-cmd-exec.yaml`：GET 触发目标跑
`ipconfig`）。光在导入期人工复核不够 —— 复核是一次性的，新拉的 POC 没人复核过。
所以这里把红线**落地为代码**：`validate_yaml()` 见到命令执行形态的 POC 直接拒收并说明，
它连落盘的资格都没有（更不会被跑到）。
"""
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from .config import resolve

# 只允许的官方主机（与本包下工具更新器同一口径：多一个都要在代码里写明理由）
ALLOWED_HOSTS = {"github.com", "raw.githubusercontent.com", "codeload.github.com"}

# 预置源：只放**确认存在**的官方仓库。`paths` 是仓库内的子目录（sparse-checkout 用）。
SOURCES = {
    "nuclei": {
        "repo": "projectdiscovery/nuclei-templates",
        "ref": "",                                  # 空 = 默认分支（main）
        # 续206 实测：`http/fingerprints/` **已经不存在了**（2026-10-16 拉的时候是 0 个），
        # nuclei 把指纹类模板并到了 `http/technologies/`。所以这里写的是**现在**的目录名，
        # 并且 `fetch_repo` 取到 0 个时会把"目录名变了？仓库结构改了？"说在错误里 ——
        # 上游会改结构，这是常态，别让它在"一个模板都没取到"这种看不出原因的消息里死掉。
        "paths": ["http/technologies"],              # 指纹类模板（转指纹表）
    },
    "nuclei-vuln": {
        "repo": "projectdiscovery/nuclei-templates",
        "ref": "",
        # 漏洞类模板：整目录几万条，**默认不预置**；要用的人在配置里自己加源
        # （`pocs.sources`），并且要知道它有多大（磁盘与请求量都按这个量级涨）。
        "paths": ["http/vulnerabilities/generic"],
    },
}

POC_DEST = "config/nuclei-templates"
MANIFEST = "manifest.json"

# 命令执行形态（拒收判据）。**宁可漏一批 POC，也不让框架发出"会让目标执行命令"的请求**。
#
# ⚠ 这条判据第一版扫的是**整份 yaml 文本**，结果误杀一片（续206 实测）：Jenkins 的指纹模板
# path 里就有 `/whoami`（那是端点名，不是执行命令）、一堆模板的 description 里有反引号。
# 所以判据收窄成两条，缺一不可：
#   ① 只看**会真正发到目标上**的内容（`_request_texts`：path / raw / payloads / body …），
#      描述、注释、作者名一律不看；
#   ② 只认**命令拼接形态**（`;cmd` / `|cmd` / `&&cmd` / `$(cmd)` / `` `cmd` ``）——
#      `/whoami` 这种端点路径前面是 `/` 不是分隔符，不算执行。
_CMD_NAMES = r"(?:ipconfig|ifconfig|whoami|/bin/sh|/bin/bash|cmd\.exe|net\s+user|ls\s+-la)"
# 两种形态任一命中即拒：
#   ① 命令拼接：`;cmd` / `|cmd` / `&&cmd`（HFS 那条就是 `|cmd=ipconfig`）；
#   ② 命令替换/反引号：`$(` / `` ` `` —— **在请求内容里**几乎只可能是 shell 注入
#      （`id` 这种名字太短太通用，不能进命令表，但 `$(id)` 照样该拦，所以单独判形态）。
_CMD_SPLICE = re.compile(r"(?:[;|]\s*(?:cmd[=\s]+)?\s*" + _CMD_NAMES + r")|\$\(|`", re.I)

# **写操作**形态（续207，主理人点单"有些需要 exp 再次验证的"）：会改动目标的一律不能自动跑。
# 与命令执行同等对待 —— 都是"利用"而不是"验证"。
_WRITE_MARKS = (
    r"\brm\s+-", r"\bmv\s+", r"\bchmod\b", r"\bchown\b", r"\bmkdir\b", r"\btouch\b",
    r">\s*/", r">>\s*/", r"\bDROP\s+TABLE\b", r"\bDELETE\s+FROM\b", r"\bUPDATE\s+\w+\s+SET\b",
    r"\bINSERT\s+INTO\b", r"\bTRUNCATE\b", r"\bwget\s+", r"\bcurl\s+.*-o\b",
    r"\bshutdown\b", r"\breboot\b", r"\bkill\s+-9", r"\bformat\s+c:",
)
_WRITE_SPLICE = re.compile("|".join(_WRITE_MARKS), re.I)

# 利用型 POC 的落点：**刻意不在** `pocs.engine.POC_DIRS` 里 ⇒ 引擎永远发现不了它，
# 自动扫描因此跑不到；只有 GUI「EXP 待确认」页列得出它，人点了才跑（见 gui/app.py 的
# `/exp` 与 `/api/exp/run`）。这是"验证"与"利用"分开的物理保证，不靠约定。
EXP_DEST = "config/exp-pending"

# 会发到目标上的字段（其余是给人看的：info.description / author / reference …）
_REQUEST_KEYS = ("path", "raw", "payload", "payloads", "body", "data", "args", "headers")


def _request_texts(data):
    """把模板里**会真正发出去**的字符串收集起来（只看这些，见 `_CMD_SPLICE` 的说明）。"""
    out = []

    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if str(k) in _REQUEST_KEYS:
                    if isinstance(v, str):
                        out.append(v)
                    elif isinstance(v, (list, tuple)):
                        out.extend(str(x) for x in v)
                walk(v)
        elif isinstance(o, (list, tuple)):
            for x in o:
                walk(x)

    walk(data)
    return "\n".join(out)


def _check_url(url):
    """URL 白名单：只 https + 官方主机（与本包下工具更新器同口径）。"""
    from urllib.parse import urlsplit
    u = urlsplit(str(url or ""))
    if u.scheme != "https":
        raise ValueError(f"只走 https：{url}")
    if (u.hostname or "").lower() not in ALLOWED_HOSTS:
        raise ValueError(f"主机不在白名单 {sorted(ALLOWED_HOSTS)}：{url}")
    return url


def _safe_member(name):
    """成员名防路径穿越（zip slip 的经典形态）：拒绝绝对路径、盘符与任何 `..` 段。

    ⚠ 顺序：**先拒再剥**。写成"先把 `/` 剥掉再判"会让 `/etc/passwd` 变成合法的
    `etc/passwd` 混过去 —— 那正是 zip slip 想让我们做的事（续206 实测第一版就是这么写的）。
    """
    raw = str(name or "")
    if not raw.strip():
        raise ValueError("成员名为空")
    if raw[:1] in ("/", "\\") or re.match(r"^[A-Za-z]:", raw):
        raise ValueError(f"绝对路径/盘符成员名：{name!r}")
    n = raw.replace("\\", "/").lstrip("/")
    if any(p == ".." for p in n.split("/")):
        raise ValueError(f"成员名含 `..`（路径穿越）：{name!r}")
    return n


# nuclei 的协议块：判据（matchers / extractors）可能躺在任何一个里面
_PROTOCOL_BLOCKS = ("http", "network", "dns", "file", "code", "ssl", "websocket", "headless",
                   "smb", "ldap", "ftp", "kerberos", "mysql", "postgresql", "redis", "mongodb",
                   "mqtt", "amqp", "pop3", "smtp", "imap", "snmp", "telnet", "ssh", "rdp",
                   "vhost", "javascript")


def _has_matchers(data):
    """顶层或任一协议块里有 matchers / extractors 吗（见 `validate_yaml` 判据③）。"""
    if data.get("matchers") or data.get("extractors"):
        return True
    for key in _PROTOCOL_BLOCKS:
        for blk in (data.get(key) or []):
            if isinstance(blk, dict) and (blk.get("matchers") or blk.get("extractors")):
                return True
    return False


def validate_yaml(text, name=""):
    """单条模板能不能被我们收下：`(ok, 拒绝理由)`。

    **三道**判据（续207 从四道改成三道，原因见下）：
    ① **YAML 能解析**（且是 dict）—— 解析不了的东西没法匹配；
    ② 有 `id`（顶层或 `info.id`）与 `info.name` —— 没有 id 就没法在 manifest / 页面上指认它；
    ③ 顶层或任一协议块里有 matchers / extractors —— 没有判据的模板跑一次纯白发请求。

    **为什么原来那道"命令执行形态就拒收"被移走了**（续206 → 续207）：它的出发点是对的
    （AGENTS §1：检测非破坏性），但处置太粗 —— 直接拒收会把"利用型 POC"这个**资产**扔掉，
    而主理人要的是"留着 exp，只是别自动跑，回头手动点"。于是职责拆成两问：
      - `validate_yaml`（本函数）只回答"**能不能收**"；
      - `exploit_reason()` 回答"**该走哪路**"（验证型自动跑 / 利用型分流待人工确认）。
    两问同源（都只看会发出去的内容、都只认形态），但处置不同：拦掉 vs 保留。
    """
    try:
        import yaml
        data = yaml.safe_load(text)
    except Exception as e:                       # noqa: BLE001 —— 坏文件逐条拒，别让整批炸
        return False, f"YAML 解析失败：{e}"
    if not isinstance(data, dict):
        return False, "顶层不是 mapping"
    info = data.get("info") or {}
    # `id` 在 nuclei 里是**顶层**字段（`info` 里只有 name/author/severity/tags）——
    # 续206 实测：只查 `info.id` 会把 `http/technologies/` 下几千条全判成"缺 info.id"拒收。
    if not str(data.get("id") or info.get("id") or "").strip():
        return False, "缺 id（顶层 id 或 info.id）"
    if not str(info.get("name") or "").strip():
        return False, "缺 info.name"
    # nuclei 的判据在**协议块**里（`http[0].matchers`），顶层 `matchers` 常常没有 ——
    # 续206 实测：只查顶层会把 `http/technologies/` 下几千条全判成"无 matchers"拒收。
    if not _has_matchers(data):
        return False, "顶层与各协议块里都没有 matchers/extractors（跑它纯白发请求）"
    return True, ""


def exploit_reason(data):
    """这个模板属于**利用型**吗：返回 `''`（验证型，可自动跑）或一句理由。

    续207（主理人点单）："我们如果有一些 rce 只想命令我们仅做去验证 poc 验证他存在即可"，
    "回头可以给个列表 如何 exp 也保留着，有些需要 exp 验证我们回头再手动点击执行 exp"，
    "比如 sql 注入那种帮派就不必有"。
    ⇒ 于是 POC 分两档：
      - **验证型**（判"漏洞在不在"）：SQL 注入报错回显、布尔盲注、XSS 反射、开放重定向…
        照旧自动跑，一个都不该被拦（上面那句"sql 注入那种帮派就不必有"就是它）；
      - **利用型**（会真的改动/执行）：命令执行、写文件、删改数据 ⇒ **不自动跑**，
        落 `config/exp-pending/`（引擎的 `POC_DIRS` 里没有这个目录），只在 GUI 的
        「EXP 待确认」页里列着，人点了才跑。
    判据与 `validate_yaml` 的 RCE 护栏**同源**（都只看会发出去的内容、都只认形态），
    区别只是处置：拦掉 vs 分流保留。
    """
    req = _request_texts(data)
    m = _CMD_SPLICE.search(req)
    if m:
        return f"命令执行（请求内容命中 {m.group(0).strip()!r}）"
    m = _WRITE_SPLICE.search(req)
    if m:
        return f"写操作（请求内容命中 {m.group(0).strip()!r}）"
    return ""


def classify(relpath):
    """这个相对路径该走哪一路：`("fingerprint"|"poc"|None, 原因)`。

    `http/fingerprints/` 下的走**指纹表**（转换后进 `fingerprints_*.txt`），
    其余落 **POC 目录**。不认识的位置（仓库根下的 README、`.github/` 等）直接跳过。
    """
    n = _safe_member(relpath)
    if n.startswith("http/technologies/") and n.endswith((".yaml", ".yml")):
        return "fingerprint", ""
    if n.startswith("http/") and n.endswith((".yaml", ".yml")):
        return "poc", ""
    return None, f"不在关注范围（{n}）"


def sha256_text(text):
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def load_manifest(dest):
    p = Path(dest) / MANIFEST
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}


def plan_files(files, validate=validate_yaml):
    """把 `{相对路径: 文本}` 过一遍校验与分类，返回 `(可收, 被拒, 跳过)` 三个 dict。

    可收的按 `classify` 分两路；被拒的带理由（页面与日志都要能说清"为什么没收"）。
    """
    ok, bad, skip = {}, {}, {}
    for rel, text in (files or {}).items():
        try:
            kind, why = classify(rel)
        except ValueError as e:
            bad[rel] = str(e)
            continue
        if kind is None:
            skip[rel] = why
            continue
        good, reason = validate(text, rel)
        if not good:
            bad[rel] = reason
            continue
        if kind == "poc" or kind == "fingerprint":
            # 续207：**利用型分流**（对两路都生效 —— 第一版只对 poc 路判，结果
            # `http/technologies/` 下的 RCE 型模板被归类成 fingerprint，直接漏进指纹表）。
            # 验证型（SQL 注入报错回显 / XSS 反射 / 开放重定向…）照旧进各自目录自动跑；
            # 会真的执行命令或改动目标的那类**不进** —— 改走 exploit 路，落到引擎的
            # `POC_DIRS` 里没有的目录（见 `EXP_DEST`）。
            # 这不是"拦掉"，是"留着但不让自动跑"：exp 本身仍是资产，只是要人点头。
            why207 = exploit_reason(_load_yaml(text))
            if why207:
                ok.setdefault("exploit", {})[rel] = text
                continue
        ok.setdefault(kind, {})[rel] = text
    return ok, bad, skip


def _load_yaml(text):
    """解析 yaml 供判据用；解析不了就返回 `{}`（调用方按"无判据可看"处理）。"""
    try:
        import yaml
        d = yaml.safe_load(text)
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def apply_files(dest, planned, logger=None, exp_dest=None):
    """落盘 + 记 manifest。**只写 dest 目录内**，先写 `.tmp` 再 rename（不留下半截文件）。

    `exp_dest`（续207）：利用型那一路的落点，**刻意不给默认值等于 dest** ——
    默认必须指向 `EXP_DEST` 那个引擎发现不了的目录，调用方忘了传就等于把 EXP 混进
    自动扫描的 POC 目录里（那正是这条改动要防的事）。
    """
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    man = load_manifest(dest)
    new_man = dict(man)
    stats = {"written": 0, "unchanged": 0, "exploit": 0}
    exp_dir = Path(exp_dest) if exp_dest else dest.parent / EXP_DEST
    for kind, files in (planned or {}).items():
        if kind == "exploit":
            # 单独记一份 manifest（与自动跑的那批分开，"哪些待人工确认"一眼数得出来）
            sub = exp_dir
            exp_dir.mkdir(parents=True, exist_ok=True)
            eman = load_manifest(exp_dir)
            for rel, text in files.items():
                name = _safe_member(rel)[len("http/"):]
                if not name:
                    continue
                target = sub / name
                digest = sha256_text(text)
                rel_key = str(target.relative_to(exp_dir))
                if eman.get(rel_key) == digest and target.exists():
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                tmp = target.with_suffix(target.suffix + ".tmp")
                tmp.write_text(text, encoding="utf-8")
                tmp.replace(target)
                eman[rel_key] = digest
                stats["exploit"] += 1
            (exp_dir / MANIFEST).write_text(
                json.dumps(eman, indent=1, sort_keys=True), encoding="utf-8")
            continue
        sub = dest / ("fingerprints" if kind == "fingerprint" else "pocs")
        for rel, text in files.items():
            # 剥前缀要**按这一路剥**：指纹路剥掉 `http/fingerprints/`（只留 `grafana.yaml`），
            # POC 路剥掉 `http/`（留 `vulnerabilities/generic/sqli.yaml`）。
            # 两路用同一个剥法会把指纹写成 `fingerprints/fingerprints/…`（续206 实测第一版）。
            _pfx = "http/technologies/" if kind == "fingerprint" else "http/"
            name = _safe_member(rel)[len(_pfx):]
            if not name:
                continue
            target = sub / name
            digest = sha256_text(text)
            rel_key = str(target.relative_to(dest))
            if new_man.get(rel_key) == digest and target.exists():
                stats["unchanged"] += 1
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            tmp = target.with_suffix(target.suffix + ".tmp")
            tmp.write_text(text, encoding="utf-8")
            tmp.replace(target)
            new_man[rel_key] = digest
            stats["written"] += 1
    (dest / MANIFEST).write_text(json.dumps(new_man, indent=1, sort_keys=True),
                                 encoding="utf-8")
    if logger:
        logger.info(f"[pocmgr] 落盘 {stats['written']} 个（{stats['unchanged']} 个无变化）"
                    f"→ {dest}")
    return stats


def _git(args, cwd=None, timeout=600):
    return subprocess.run(["git"] + args, cwd=cwd, capture_output=True, text=True,
                          timeout=timeout)


def fetch_repo(source, ref="", logger=None):
    """sparse clone 指定源的 `paths`，返回 `{相对路径: 文本}`。

    整仓 ~9000 个模板 ⇒ 用 `--filter=blob:none --sparse` 只取要用的子目录
    （`git clone` 不带 sparse 会把整个仓库的对象都拉下来，几分钟起且占几个 G）。
    """
    src = SOURCES.get(source)
    if not src:
        raise ValueError(f"未知源 {source!r}（预置：{sorted(SOURCES)}）")
    url = _check_url(f"https://github.com/{src['repo']}.git")
    ref = str(ref or src.get("ref") or "").strip()
    tmp = Path(tempfile.mkdtemp(prefix="pocmgr-"))
    try:
        r = _git(["clone", "--depth", "1", "--filter=blob:none", "--no-checkout", url,
                  str(tmp)])
        if r.returncode != 0:
            raise RuntimeError(f"clone 失败：{(r.stderr or r.stdout)[:200]}")
        if ref:
            r = _git(["fetch", "--depth", "1", "origin", ref], cwd=tmp)
            if r.returncode != 0:
                raise RuntimeError(f"取 ref {ref} 失败：{(r.stderr or r.stdout)[:200]}")
            r = _git(["checkout", "FETCH_HEAD"], cwd=tmp)
        else:
            r = _git(["checkout"], cwd=tmp)
        if r.returncode != 0:
            raise RuntimeError(f"checkout 失败：{(r.stderr or r.stdout)[:200]}")
        r = _git(["sparse-checkout", "set"] + list(src["paths"]), cwd=tmp)
        if r.returncode != 0:
            raise RuntimeError(f"sparse-checkout 失败：{(r.stderr or r.stdout)[:200]}")
        r = _git(["checkout"], cwd=tmp)
        if r.returncode != 0:
            raise RuntimeError(f"sparse checkout 落地失败：{(r.stderr or r.stdout)[:200]}")
        out = {}
        for p in src["paths"]:
            base = tmp / p
            if not base.is_dir():
                continue
            for f in sorted(base.rglob("*.y*ml")):
                rel = f.relative_to(tmp).as_posix()
                out[rel] = f.read_text(encoding="utf-8", errors="replace")
        if logger:
            logger.info(f"[pocmgr] 从 {src['repo']} 取到 {len(out)} 个模板"
                        f"（目录：{'、'.join(src['paths'])}）")
        return out
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def update(source="nuclei", ref="", dest=None, logger=None, exp_dest=None):
    """跑一轮：取 → 校验分类 → 落盘。返回一份能直接念给用户听的报告。

    `exp_dest`（续207）：利用型 POC 的落点，默认 `EXP_DEST`（**不在** POC_DIRS 里 ⇒ 不自动跑）。
    """
    dest = dest or resolve(POC_DEST)
    files = fetch_repo(source, ref=ref, logger=logger)
    if not files:
        return {"ok": False, "error": "一个模板都没取到（目录名变了？仓库结构改了？）"}
    ok, bad, skip = plan_files(files)
    # `dest` 可能是调用方传的字符串（CLI 就传 str）—— `Path()` 包一层再用 `.parent`
    stats = apply_files(dest, ok, logger=logger,
                        exp_dest=exp_dest or str(Path(dest).parent / EXP_DEST))
    return {"ok": True, "source": source, "ref": ref,
            "counts": {"fingerprint": len(ok.get("fingerprint", {})),
                       "poc": len(ok.get("poc", {})),
                       "exploit": len(ok.get("exploit", {})),
                       "rejected": len(bad), "skipped": len(skip)},
            "written": stats, "rejected": dict(list(bad.items())[:20])}
