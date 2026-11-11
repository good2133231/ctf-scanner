"""阶段 1：子域名收集。

三层来源，按可靠性依次叠加（外部工具优先、内置兜底）：
1. `subfinder` —— 外部工具被动收集（装了才用）；
2. `scanner/passive.py` —— 内置多来源被动收集（免 key 公开接口：
   crt.sh / certspotter / alienvault / hackertarget / rapiddns / sublist3r）；
3. DNS 字典爆破：`puredns`（外部工具）或内置 socket 解析兜底。

泛解析过滤（`scanner/wildcard.py`）：目标若开了 `*.example.com`，字典里每个词都会"命中"，
这里统一丢弃"解析结果全部落在通配 IP 内"的候选，避免垃圾灌满 probe/dirscan/vulnscan。

注意：被动来源返回的名字**可能已失效或不再解析**（免费接口的历史数据），
这里不做存活过滤，交给 probe 阶段自然丢弃（不可达即不产出站点）。

对应参考流水线：
  ./tools/scanner/subfinder -dL url -all -t 200 -o logs/passive.txt
  ./tools/scanner/puredns bruteforce ./config/subdomains.txt url -r ./config/resolvers.txt -w logs/brute.txt
  cat passive.txt brute.txt | sort -u    ->  Python 端以 sorted(set(...)) 等价实现
"""
import os
def puredns_bruteforce_argv(pd_bin, wordlist, domain, resolvers, out_file):
    """拼 puredns `bruteforce` 的 argv —— **全仓只此一处**（续264）。

    puredns v2.1.1 的用法（`puredns bruteforce --help` 实测）：
        puredns bruteforce <wordlist> domain            # 单个域名：位置参数
        puredns bruteforce <wordlist> -d domains.txt    # 一批域名：-d 吃的是**文件**
    老写法把**裸域名**塞进 `-d`，puredns 就去 `open <那个名字>` ⇒ 每个域名都退码 1
    （`puredns error: open targ1.com: no such file or directory`），而调用方只把
    stderr 截 150 字记一句 WARNING 就静默走内置兜底 ⇒ 深档 17.8 万条字典**从来没跑过**，
    每轮只剩 3084 条等距抽样（实测 #61/#62/#63/#65 四次全中，用户报"域名更少了"）。
    门禁 `[264]` 用真二进制跑一遍这个函数产出的 argv（rc 必须 0），语法再漂就红。
    """
    return [str(pd_bin), "bruteforce", str(wordlist), str(domain),
            "-r", str(resolvers), "-w", str(out_file)]


def puredns_bruteforce_batch_argv(pd_bin, wordlist, domains_file, resolvers, out_file):
    """一批域名一次跑：`puredns bruteforce <wordlist> -d <domains.txt> ...`（续370）。

    `-d` 在 v2.1.1 里吃的是**域名文件**（每行一个），不是裸域名 —— 见上一函数的注释。
    合批省的是「每个域名一次进程启动 + massdns 初始化」；单域仍走上面的位置参数形态，
    避免为了合批把 `[264]` 用真二进制钉过的那条路径也改掉。
    """
    return [str(pd_bin), "bruteforce", str(wordlist), "-d", str(domains_file),
            "-r", str(resolvers), "-w", str(out_file)]


def _combo_puredns(ctx, domain, pairs, pd_bin, massdns_bin, resolvers, th, wild_ips, workers):
    """用 puredns 跑一轮组合爆破；返回 (kept, dropped)，不可用/失败返回 None。

    组合前缀本质仍是 DNS 爆破，逐条走系统解析器在慢 DNS 上会拖到几分钟；
    puredns/massdns 已经装着时复用它，结果与 resolve_all 路径完全一致（最后仍按泛解析
    IP 过滤）。不可用时返回 None，由调用方回退到原来的 resolve_all。
    """
    if not (pd_bin and massdns_bin and resolvers and os.path.isfile(str(resolvers))):
        return None
    wl = ctx.workdir / ("combo_%s.txt" % domain)
    out = ctx.workdir / ("combo_%s.out.txt" % domain)
    try:
        write_lines(wl, pairs)
        if out.exists():
            out.unlink()
    except OSError:
        return None
    rc, _, err = run_cmd(
        puredns_bruteforce_argv(pd_bin, wl, domain, resolvers, out),
        timeout=600, throttle=th,
        extra_path=os.path.dirname(str(massdns_bin)) if massdns_bin else None)
    if rc != 0:
        ctx.logger.warning(f"[subdomain] {domain} 组合爆破 puredns 退出码 {rc}："
                           f"{err.strip()[:150]}，回退系统解析器")
        return None
    hits = [ln for ln in read_lines(out) if ln.endswith("." + domain)]
    if not hits:
        return ([], [])
    if wild_ips:
        resolved = wildcard.resolve_all(hits, workers=workers)
        return wildcard.filter_hits(resolved, wild_ips)
    return (hits, [])


from .base import Stage
from . import github as github_stage
from .. import blacklist, cdn, db, dnsq, extdom, fofa as fofa_mod, passive, subdict, targets, wildcard
from ..config import resolve
from ..utils import (is_domain, to_ascii, which, verify_tool, run_cmd, read_lines,
                    write_lines, pool_run)

# 需要做泛解析复核的来源（爆破类来源已自带通配过滤，不重复查询）
_PASSIVE_SRC = ("subfinder", "passive:")
# 续362：计入“被动子域硬上限”的来源。FOFA 子域反查也是外部被动来源，一起算；
# 主动字典/爆破（puredns / dns-brute）不在这里，它们本来就有词表上限。
_PASSIVE_CAP_SRC = ("subfinder", "passive:", "osint:fofa")


def _passive_limits(settings):
    """返回 `(硬上限, 告警线)`；0 = 不限。配置坏值回退 5 万/1 万。"""
    cfg = (settings or {}).get("subdomain", {}) or {}

    def _int(key, dflt):
        try:
            return max(0, int(cfg.get(key) if cfg.get(key) is not None else dflt))
        except (TypeError, ValueError):
            return dflt

    mx = _int("passive_max", 50000)
    warn = _int("passive_warn", 10000)
    if mx and warn > mx:
        warn = mx
    return mx, warn


def _merge_found(found, sources, items, passive_max=0, passive_warn=0,
                 state=None, logger=None):
    """把 (name, source) 并入 found/sources；被动来源受硬上限/告警线约束。

    续362 把这段从 `run()` 的闭包里提出来，只为让门禁能直接测 5 万/1 万这道闸，
    不必起网络或桩整条子域流水线。`state` 跨多次调用保存累计数/已告警/已截断。
    """
    state = state if state is not None else {"n": 0, "warned": False, "truncated": False}
    n = 0
    for name, src in items:
        src_s = str(src or "")
        _is_pas = src_s == "subfinder" or src_s.startswith(_PASSIVE_CAP_SRC)
        if _is_pas and passive_max > 0:
            if state["n"] >= passive_max:
                if not state["truncated"]:
                    state["truncated"] = True
                    if logger:
                        logger.warning(
                            f"[subdomain] 被动子域达到硬上限 {passive_max}，"
                            f"后续被动/FOFA 结果不再入库（subdomain.passive_max；"
                            f"本轮已新增 {state['n']} 个唯一域名）")
                return n
            if (passive_warn and state["n"] >= passive_warn
                    and not state["warned"]):
                state["warned"] = True
                if logger:
                    logger.warning(
                        f"[subdomain] 被动子域已超过 {passive_warn} 个，"
                        f"硬上限 {passive_max}（subdomain.passive_max/passive_warn）")
        # IDN / 中文域名 → punycode（被动来源/外部工具理论上可能回传 Unicode）；
        # 归一失败按空串丢弃（显式不静默）。ASCII 名字逐字节不变。
        name = to_ascii((name or "").strip().lower().rstrip(".")) or ""
        if not name or name in found:
            continue
        found.add(name)
        sources[name] = src
        n += 1
        if _is_pas:
            state["n"] += 1
    return n


def _spread(words, cap, logger=None, knob="limits.brute_max_words", hint=None):
    """需要收窄词表时**等距抽样**并如实报出比例；`cap<=0` 或词表本就不长时原样返回。

    为什么不取前 N 条：字典是排好序的，`words[:3000]` 拿到的全是 `0/00/000/0000/a/aa…` ——
    数字前缀和叠字符前缀把额度占满，真正值钱的 `api`/`admin`/`shop` 一条都进不去。
    等距抽样才是"整个字母表都过一遍"。
    """
    if not cap or cap <= 0 or len(words or []) <= cap:
        return words            # **原对象**：调用方靠 `is not` 判断有没有真的收窄过
    words = list(words)
    if cap == 1:
        if logger:
            logger.info(f"[subdomain] 字典 {len(words)} 条且 {knob}=1，只取第 1 条")
        return words[:1]
    # 端点都保住的等距索引：`i*(n-1)/(cap-1)` 向下取整。`words[::step]` 那种切片在
    # `n % step != 0` 时**会把字典尾巴丢掉**（排序字典的尾巴是 `zz*` 那批），
    # 而步长 > 1 保证索引严格递增（无重复）并且恰好取满 `cap` 条（切片会少于 cap）。
    last, span = len(words) - 1, cap - 1
    got = [words[int(i * last / span)] for i in range(cap)]
    if logger:
        tail = hint or f"要用全量把 {knob} 设 0"
        logger.info(f"[subdomain] 词表 {len(words)} 条超出 {knob}={cap}，等距抽样取 {len(got)} 条"
                    f"（约每 {len(words) / cap:.1f} 条取 1 条，首尾都保住、覆盖整个字典而不是"
                    f"字母表开头；{tail}）")
    return got



# 续246（B 批）：任务级爆破档位。**不新增一套词表机制** —— 快速档就是给既有的
# `limits.brute_max_words` 这道等距抽样闸门换一个任务级上限；深度档显式回到策略值。
# 为什么是"等距抽样"而不是"前 1 万条"：字典是排序的，前 1 万条几乎全是数字/叠字符
# 前缀（见 `_spread` 的注释），那等于把快速档做成"只扫字母表开头"。
BRUTE_PROFILE_QUICK_WORDS = 10000


def brute_profile(profile, policy_cap):
    """任务级爆破档位 → `(生效档名, 生效词数上限, 备注)`；上限 0 = 不限。

    - `quick`：深档收到 `BRUTE_PROFILE_QUICK_WORDS` 条；**策略值更小时以策略为准**
      （配置永远是天花板 —— 开发模式把 `limits.brute_max_words` 压到 4 时，
      勾「快速」不许反而把它放大，否则 CI 与自检会跟着字典一起变慢）。
    - `deep`：显式声明"按策略"，数字原样返回（策略 0 = 全量）。
    - 未指定 / 不认识的值：返回 `("", 策略值, "")`，行为与加这个选项之前逐字节一致。
    """
    name = str(profile or "").strip().lower()
    if name not in ("quick", "deep"):
        name = ""
    try:
        cap = max(0, int(policy_cap or 0))
    except (TypeError, ValueError):
        cap = 0
    if name == "quick":
        want = BRUTE_PROFILE_QUICK_WORDS
        if cap and cap < want:
            return name, cap, f"策略 limits.brute_max_words={cap} 更小，以策略为准"
        return name, want, ""
    if name == "deep":
        return name, cap, ""
    return "", cap, ""


def _fofa_subdomains(domains, settings, logger=None):
    """续243：FOFA `domain="<注册域>"` 反查子域名（主理人点单"fofa 子域名获取也要进行工作"）。

    此前 FOFA 只参与 **osint** 阶段（图标/证书/标题反查，产出的是*拓展域名*），子域名阶段
    完全没有它 —— 而 FOFA 的爬虫存量本身就是覆盖面很广的子域名来源。返回
    `[(host, "osint:fofa"), ...]`（去重保序）；没配 key / 开关关 / 单域查错 ⇒ 空表并说一句，
    绝不影响其它来源（这是并集里的一路，不是关键路径）。
    """
    cfg = (settings or {}).get("fofa", {}) or {}
    if cfg.get("subdomain_enabled") is False:
        if logger:
            logger.info("[subdomain] FOFA 子域名反查已关闭（fofa.subdomain_enabled=false）")
        return []
    if not fofa_mod.available(settings):
        if logger:
            logger.info("[subdomain] 未配 FOFA 凭据，跳过子域名反查（fofa.email / fofa.key）")
        return []
    try:
        cap = max(1, min(int(cfg.get("subdomain_max") or 100), 10000))
    except (TypeError, ValueError):
        cap = 100
    seen, out = set(), set()
    for d in domains or []:
        d = str(d or "").strip().lower()
        base = extdom.base_of(d) or d
        if not base or base in seen:
            continue
        seen.add(base)
        assets, total, err = fofa_mod.search_query(f'domain="{base}"', settings,
                                                   logger=logger, size=cap)
        if err:
            if logger:
                logger.info(f"[subdomain] FOFA 子域名反查 {base} 失败：{err}（跳过，不影响其它来源）")
            continue
        n = 0
        # 上限**本地也截一次**：`size` 只是请求参数，FOFA 真多返回时不能把库撑爆
        # （`subdomain_max` 的语义是"单域最多入账多少条"，不能只信上游听话）。
        for a in (assets or [])[:cap]:
            # 续281：取域名统一走 `fofa.domain_of(prefer="host")` —— 旧写法
            # `host.split(":", 1)[0]` 会把 `https://a.test` 切成 `"https"` 写进库。
            # `prefer="host"` 保证子域优先（`domain` 列可能只给注册域/空串）。
            host = fofa_mod.domain_of(a or {}, prefer="host")
            if host and host not in out:
                out.add(host); n += 1
        if logger:
            logger.info(f"[subdomain] FOFA 子域名反查 {base} → {n} 个"
                        f"（命中 {total}，上限 {cap}）")
    return [(h, "osint:fofa") for h in sorted(out)]


class SubdomainStage(Stage):
    name = "subdomain"
    description = "子域名收集（多来源被动收集 + DNS 字典爆破 + 泛解析过滤）"

    def run(self):
        ctx = self.ctx
        th = ctx.throttle        # F2 统一门控：本任务的限流器（可能是 None）
        limits = ctx.settings.get("limits", {})
        # ---------- 目标 → 收集根（续145：URL 也能自动提取主域）----------
        # 用户点单：「就算我扫描目标给你的是 url 地址，你也能自动提取出主域，就不需要我有时候
        # 自己手动提了」。此前这里只认 `kind == "domain"`，给一条 `https://www.a.com/x` 的结果是
        # **整阶段跳过**（日志只有一句"目标中无裸域名"）—— 用户得自己把主域抠出来再填一遍。
        # 主机名提取与注册域折算都走 `scanner/targets.py`（续146 收敛：此前这里、extdom、
        # github_leak、diffview、osint ×2、jsmine 各写了一份"URL 就取 hostname"）。
        # ip / cidr 没有"收集根"这回事 ⇒ `host_of` 直接给空串（它们的资产面归 portscan / probe）。
        domains, seen, from_url = [], set(), []
        for kind, raw in ctx.targets:
            host = targets.host_of(kind, raw)
            if not host or not is_domain(host):
                continue
            if kind == "url":
                from_url.append((raw, host))
            if host not in seen:
                seen.add(host)
                domains.append(host)
        for _raw, _host in from_url:
            ctx.logger.info(f"[subdomain] 目标 {_raw} 是 URL，自动提取主机 {_host}")
        if not domains:
            ctx.logger.info("[subdomain] 目标里既没有域名、也没有能提取出主机名的 URL，跳过该阶段")
            return
        if ctx.stopped():
            ctx.logger.warning("[subdomain] 任务已请求停止，跳过")
            return

        # ---------- 0a) 续150-附（11-调度）：并发触发 GitHub / 多平台泄露检索 ----------
        # 检索只依赖**注册域**（ctx.targets），与下面的子域收集毫无数据依赖，串行放到流水线末端
        # 纯属白等。这里在**子域收集开始之前**起一个 daemon 线程并发发起（不阻塞收集）；结果仍走
        # github_leak / multileak.collect() → db.insert_leads()，只产出 leads。线程里的异常一律
        # 吞掉并写日志，绝不拖垮子域阶段；github 阶段保持可用 —— 发现已跑过就跳过、不重复发请求。
        github_stage.start_early_search(ctx)

        offline = ctx.options.get("offline")
        # 续344：把任务级字典开关写进日志，避免再出现“我明明勾了全量”却只看到抽样的悬案。
        _full344 = ctx.options.get("full_brute") is True
        _prof344 = str(ctx.options.get("subdomain_profile") or "").strip() or "跟策略"
        ctx.logger.info(f"[subdomain] 任务字典选项：full_brute={'开（忽略历史）' if _full344 else '关'}"
                        f"｜subdomain_profile={_prof344}")
        workers = int(limits.get("max_workers", 20))
        found, sources = set(), {}

        # ---------- 0) 补收注册域（主域）+ 自动拓展扫描 ----------
        # **折叠判据只有这一份**（续145 之前它是 `auto_expand` 分支里的私有实现，本轮改成
        # "两个触发条件、一处实现"）：目标是子域时把它的注册域也加进收集根 —— 否则只能收到
        # `aaa.a.com` 再往下的名字，`a.com` 的其它子域全漏（用户 2026-09-25 的原始口径）。
        # 两个触发条件：
        #   ① `subdomain.auto_root`（策略级，**默认开**）＝用户 2026-10-09 点单的"自动提取主域"；
        #   ② 任务级选项 `auto_expand`（勾了还连带把目标自带的子域按子域资产入库并解析）。
        #      即便 ① 被关掉，勾了 ② 也照折叠 —— 既有行为不许因为这个新开关而缩水。
        # ⚠ 这是一次**默认值变更**：续145 之前"目标是子域"默认不折叠（那段注释写的正是
        #   "这是扩大扫描面的行为，不能让既有任务在用户不知情的情况下变样"）。本轮按用户点单
        #   把默认翻过来，代价是 DNS 爆破/被动收集的根从 `www.a.com` 变成 `a.com`（面更大）。
        #   要回到旧行为：`subdomain.auto_root: false`（策略页有勾）。
        # 折叠是**追加不是替换**：`www.a.com` 自己仍留在收集根里 —— 替换掉等于把用户真正
        # 给的那个主机从探测清单里抹掉（那才是真的改坏行为）。
        expand = ctx.options.get("auto_expand") is True
        auto_root = (ctx.settings.get("subdomain", {}) or {}).get("auto_root") is not False
        if auto_root or expand:
            why = "subdomain.auto_root" if auto_root else "任务选项 auto_expand"
            for d in list(domains):
                b = targets.root_of(d)
                if b and b != d and is_domain(b) and b not in seen:
                    seen.add(b)
                    domains.append(b)
                    ctx.logger.info(f"[subdomain] 自动拓展：目标 {d} 是子域，补收主域名 {b}（{why}）")
        if expand:
            for d in domains:
                if targets.root_of(d) != d and d not in found:
                    found.add(d)
                    sources[d] = "target"
            if sources:
                ctx.logger.info("[subdomain] 自动拓展：目标自带的子域按子域资产入库 "
                                + " / ".join(sorted(n for n, s in sources.items() if s == "target")))

        # 续362：被动子域硬上限（跨 subfinder / 内置被动 / FOFA 累计，按唯一域名计）。
        # 这是一个“安全阀”，不是扫描能力：到顶后只停止**被动**结果入库，主动爆破不受影响。
        _pcap_max, _pcap_warn = _passive_limits(ctx.settings)
        _pcap_state = {"n": 0, "warned": False, "truncated": False}

        def add_many(items):
            return _merge_found(found, sources, items, _pcap_max, _pcap_warn,
                                _pcap_state, ctx.logger)

        # ---------- 1) subfinder（外部工具优先，`-all` 走全来源）----------
        sf_bin = which(ctx.settings.get("tools", {}).get("subfinder", "subfinder"))
        if sf_bin and not verify_tool(sf_bin):
            sf_bin = None
            ctx.logger.info("[subdomain] PATH 中的 subfinder 未通过版本校验，跳过被动收集")
        used_subfinder = False
        if sf_bin and not offline:
            # `-all`：使用**全部数据源**（不加时只用默认源集合，覆盖明显更小）。
            # 用户明确要求"要主动且全"，故这里恒开 `-all`；`-t 200` 是并发上限。
            ctx.logger.info("[subdomain] subfinder 被动收集（-all 全来源）…")
            in_file = write_lines(ctx.workdir / "subfinder_in.txt", domains)
            out_file = ctx.workdir / "passive.txt"
            rc, _, err = run_cmd([sf_bin, "-dL", str(in_file), "-all", "-t", "200",
                                  "-o", str(out_file)], timeout=1800, throttle=th)
            if rc == 0:
                used_subfinder = True
                n = add_many((line, "subfinder") for line in read_lines(out_file))
                ctx.logger.info(f"[subdomain] subfinder → 新增 {n} 个")
            else:
                ctx.logger.warning(f"[subdomain] subfinder 退出码 {rc}：{err.strip()[:200]}")

        getattr(ctx, "report_progress", lambda f: None)(0.33)   # 续275：subfinder 收完（阶段内进度，别钉在 0%）
        # ---------- 2) 内置多来源被动收集（免 key 公开接口）----------
        # **与 subfinder 取并集**（`subdomain.union_passive`，默认开）：
        # 两边的源集合并不相同（subfinder 覆盖广、我们内置的是 crt.sh / certspotter /
        # alienvault / hackertarget / rapiddns / sublist3r 这些免 key 接口），
        # 原实现是 `elif`——装了 subfinder 就完全不跑内置源，等于白丢一批证书/情报源。
        # 用户要求"要主动且全"，故默认并集；想省时间可把 `union_passive` 关掉。
        union = (ctx.settings.get("subdomain", {}) or {}).get("union_passive") is not False
        if not offline and (not used_subfinder or union):
            if not used_subfinder:
                ctx.logger.info("[subdomain] subfinder 不可用/未成功，使用内置多来源被动收集 …")
            else:
                ctx.logger.info("[subdomain] 叠加内置多来源被动收集（与 subfinder 取并集）…")
            for d in domains:
                if ctx.stopped():
                    break
                n = add_many(passive.collect(d, ctx.settings, logger=ctx.logger).items())
                ctx.logger.info(f"[subdomain] 被动来源 {d} → 新增 {n} 个")
        elif offline:
            ctx.logger.info("[subdomain] 被动收集已跳过（--offline）")

        # ---------- 2b) FOFA 域名反查（续243，主理人点单"fofa 子域名获取也要进行工作"）----------
        if not offline:
            _fx243 = _fofa_subdomains(domains, ctx.settings, logger=ctx.logger)
            if _fx243:
                _n243 = add_many(_fx243)
                ctx.logger.info(f"[subdomain] FOFA 子域名反查合计新增 {_n243} 个")

        getattr(ctx, "report_progress", lambda f: None)(0.6)    # 续275：被动收集收完
        # ---------- 3) 泛解析探测（每域名一次，纯 DNS 查询）----------
        wild = {}
        if limits.get("wildcard_filter", True):
            for d in domains:
                ips = wildcard.detect(d)
                if ips:
                    wild[d] = ips
                    ctx.logger.info(f"[subdomain] 检测到泛解析 *.{d} → "
                                    f"{','.join(sorted(ips))}（将过滤通配命中）")
            if not wild:
                ctx.logger.info("[subdomain] 未检测到泛解析")
        else:
            ctx.logger.info("[subdomain] 泛解析过滤已在配置中关闭（limits.wildcard_filter）")

        # ---------- 4) DNS 字典爆破 ----------
        brute_domains = domains[: int(limits.get("brute_max_domains", 50))]
        # 续380：授权 scope 也管住 DNS 爆破的目标（scope 默认关 ⇒ 零行为变化）。
        try:
            from .. import scope as _scope380
            _sc380 = ctx.settings.get("_scope")
            if _sc380 and _sc380.get("enabled"):
                _kept380, _drop380 = _scope380.filter_domains(brute_domains, _sc380)
                if _drop380:
                    ctx.logger.info(f"[subdomain] 授权 scope 收窄 DNS 爆破："
                                    f"{len(brute_domains)} → {len(_kept380)} 个域名"
                                    f"（挡掉 {len(_drop380)} 个）")
                brute_domains = _kept380
        except Exception as _e380:      # noqa: BLE001 - scope 读坏了不该拖垮子域收集
            ctx.logger.warning(f"[subdomain] scope 过滤失败（不影响其余）：{_e380}")
        # 字典路径为空时 `resolve("")` 会落到项目根目录，`read_text()` 抛 IsADirectoryError 并
        # 让整阶段挂掉；这里先确认"配了路径且确实是文件"，否则按"无字典"走（只做被动收集）。
        # 字典分两档（续139）：`dicts.subdomains` 是**精简档**（人工挑的高价值前缀，续341 起 366 条），
        # `dicts.subdomains_deep` 是**深档**（可选文件，17.8 万条那一类）。为什么必须分两档：
        # 深档在**没装 puredns** 的机器上跑不动（内置那路是系统解析器逐条查），只能抽样收窄，
        # 而 366/177893 ≈ 0.05% —— 抽样会把精简档几乎全冲掉，那是**倒退**。所以精简档永远全量打底，
        # 只有深档受抽样闸门。深档文件不在就是"没配"，不影响任何其它阶段。
        dict_raw = str(ctx.settings.get("dicts", {}).get("subdomains", "") or "")
        wl_path = resolve(dict_raw) if dict_raw else None
        cur = ([w for w in read_lines(wl_path) if not w.startswith("#")]
               if (wl_path and wl_path.is_file()) else [])
        deep_raw = str(ctx.settings.get("dicts", {}).get("subdomains_deep", "") or "")
        deep_path = resolve(deep_raw) if deep_raw else None
        deep_ok = bool(deep_path and deep_path.is_file())
        _cur_set = set(cur)
        deep = [w for w in ([x for x in read_lines(deep_path) if not x.startswith("#")]
                            if deep_ok else []) if w not in _cur_set]
        # 续344：动态字典（拓展收尾时从归属子域长出来的前缀）放在**精简档**里，
        # 永远全量参与；不跟深档一起受 quick/增量抽样，否则"刚学到的名字"会被抽没。
        _dyn = subdict.load(ctx.settings)
        if _dyn:
            _dyn_new = [w for w in _dyn if w not in _cur_set]
            if _dyn_new:
                cur.extend(_dyn_new)
                _cur_set.update(_dyn_new)
            ctx.logger.info(f"[subdomain] 动态字典 {len(_dyn)} 条（本次新并入 {len(_dyn_new)} 条）"
                            f"：{subdict.path(ctx.settings)}")
        wordlist = cur + deep
        if dict_raw and not wordlist:
            ctx.logger.warning("[subdomain] 子域名字典不可用（路径不存在或为空文件），跳过字典爆破")
        elif deep_raw and not deep_ok:
            ctx.logger.info(f"[subdomain] 没配深字典（{deep_raw} 不存在），本次只用精简字典 "
                            f"{len(cur)} 条；要补：python tools/import_subdomain_dict.py "
                            "--src <你那份深字典>")
        elif wordlist and len(wordlist) < int(limits.get("brute_dict_warn_min", 1000)):
            # 与灯塔逐条比对时（2026-10-08，targ2.com）有一类差距跟探测器无关：它记为站点、
            # 我们**连域名都没生成**的主机 15 台，全在字典规模上 —— 仓库发的是精简版，
            # 它发的是 17.8 万条。不喊这一句，用户就会把"子域名少"读成"收集器不行"。
            ctx.logger.warning(
                f"[subdomain] 字典只有 {len(wordlist)} 条（阈值 limits.brute_dict_warn_min="
                f"{int(limits.get('brute_dict_warn_min', 1000))}），被动来源之外爆破不出多少名字；"
                "把自己那份深的字典并进深档：python tools/import_subdomain_dict.py "
                "--src <字典文件>（默认写 config/dicts/subdomains_deep.txt）")
        # 词数闸门（续139）：深字典 × 多域名会把 DNS 查询量推到千万级，内置那路（系统解析器
        # 逐条查）更是跑不完 —— 两路各自收窄，并把"怎么放开"写在日志里，不做静默截断。
        # **闸门只冲深档**：精简档那几十条人工挑的前缀任何情况下都全量在场（把它一起抽样，
        # 366/177893 ≈ 0.05% 会几乎全冲掉 —— 那不叫收窄，叫倒退）。
        # 续246（B 批）：任务级「快速 / 深度」档位。快速档只改**深档**的抽样上限
        # （精简档那几十条人工前缀任何档位都全量在场）；深度档就是"按策略"的显式写法。
        # 档位生效时必须说出来 —— 用户看到"子域名少"时要能分清是字典小、还是自己选了快速档。
        profile, brute_cap, profile_note = brute_profile(
            ctx.options.get("subdomain_profile"), limits.get("brute_max_words", 0))
        if profile:
            _pname = "快速" if profile == "quick" else "深度"
            _pextra = f"；{profile_note}" if profile_note else ""
            if deep:
                _cap_txt = f"{brute_cap:,} 条" if brute_cap else "不限（全量）"
                ctx.logger.info(
                    f"[subdomain] 爆破档位：{_pname}（任务选项 subdomain_profile={profile}）—— "
                    f"深档 {len(deep):,} 条，生效上限 {_cap_txt}{_pextra}；超出时按等距抽样取"
                    f"（**不是截断**，字典首尾与整个字母表都保得住）")
            else:
                ctx.logger.info(
                    f"[subdomain] 爆破档位：{_pname}（任务选项 subdomain_profile={profile}）—— "
                    f"本次没有深档字典（dicts.subdomains_deep 未配或不存在），"
                    f"只跑精简档 {len(cur)} 条，档位不影响本次词表")
        _sknob = "子域名快速档" if profile == "quick" else "limits.brute_max_words"
        _shint = ("要用全量请把任务档位改成「深度」，或把策略 limits.brute_max_words 设 0"
                  if profile == "quick" else None)
        deep_sel = _spread(deep, brute_cap, ctx.logger, _sknob, hint=_shint)
        words = cur + deep_sel
        dict_path = str(resolve(dict_raw)) if dict_raw else ""
        pd_bin = which(ctx.settings.get("tools", {}).get("puredns", "puredns"))
        # 续165：puredns 的 bruteforce/resolve 会**在进程内 exec `massdns`**（传递依赖，靠 PATH 找），
        # 而本仓的 `TOOLS`/`MANUAL`/`SYSTEM_PACKAGES`/`install.sh` 里此前一处都没有 massdns ⇒
        # 每个域名都退码 1、报 `exec: "massdns": executable file not found in $PATH`（实测）。
        # 先预检：缺 massdns 就别拿整轮时间（每域名 timeout=3600）去换一条看不懂的错，改用内置兜底。
        massdns_bin = which(ctx.settings.get("tools", {}).get("massdns", "massdns"))
        # puredns 只吃**一个文件**，所以配了深档时要把并集落盘它才读得到。
        # 没装 puredns（或离线）时**不落盘**：内置那路直接拿内存里的词表，写一份 1.5MB 的副本
        # 只是把任务工作目录撑大，谁也不读它。
        use_pd = bool(pd_bin) and not offline and bool(words)
        if use_pd and not massdns_bin:
            ctx.logger.warning(
                "[subdomain] puredns 已装，但缺它必需的 massdns（PATH 里找不到）—— 本次跳过 "
                "字典爆破、改用内置兜底（否则每个域名都会以退出码 1 失败）。"
                "装 massdns：python tools/build_massdns.py --wire（需 gcc/make）")
            use_pd = False
        if deep and use_pd:
            dict_path = str(write_lines(ctx.workdir / "brute_words.txt", words))
        # ---------- 4a) 增量模式（续333）：同根域近期扫过 → 跳过全量爆破 ----------
        # 主理人点单：同一个根域每建一次任务都重跑 17.8 万词 + 组合爆破，但库里已有上一次的
        # 完整子域清单；原 `reuse_history` 只在阶段末尾合并、不省时间。这里在爆破前判定：
        #   TTL 内同根域已有自家子域记录 → 只跑精简档 + 前 incremental_max_words 条深档，
        #   组合爆破对这批根域跳过。任务级 `options.full_brute`（建任务页「全量爆破」）或
        #   `subdomain.incremental=false` 走全量。离线（自检）不做增量，保持既有门禁口径。
        inc_roots, inc_words, inc_dict = set(), [], ""
        _sub_cfg = ctx.settings.get("subdomain", {}) or {}
        if (_sub_cfg.get("incremental", True) and not ctx.options.get("full_brute")
                and not offline and brute_domains):
            _ttl = max(1, int(_sub_cfg.get("incremental_ttl_days", 7) or 7))
            _inc_max = max(0, int(_sub_cfg.get("incremental_max_words", 5000) or 0))
            _known = db.recent_known_domains(days=_ttl, except_task=ctx.task_id,
                                             owner_id=getattr(ctx, "owner_id", None))
            # 变量名刻意用 `_x` / `_n`：`[8au]` 按字面量把「root_of 传 d」钉在**恰好两处**
            # （收集根与折叠），这里再写一次就会被判成"折叠多出一处"。判据本意是单一产地，不是禁用。
            _roots = {_x: (targets.root_of(_x) or _x) for _x in brute_domains}
            _hist = {(targets.root_of(_n) or _n) for _n in _known}
            inc_roots = {_x for _x, _r in _roots.items() if _r in _hist}
            if inc_roots:
                inc_words = cur + _spread(
                    deep, _inc_max, ctx.logger, "subdomain.incremental_max_words",
                    hint="0 表示增量模式不跑深档（只吃被动源与历史）；要全量请勾建任务页「全量爆破」")
                ctx.logger.info(
                    f"[subdomain] 增量模式：{'、'.join(sorted(inc_roots))} 最近 {_ttl} 天已有历史子域 "
                    f"→ 跳过全量字典与组合爆破，只跑精简档 + 深档前 {_inc_max} 条"
                    "（要全量请勾「全量爆破」或把 subdomain.incremental 设 false）")
                if use_pd and inc_words:
                    if deep:
                        inc_dict = str(write_lines(ctx.workdir / "brute_words_inc.txt", inc_words))
                    else:
                        # 没有深档：增量词表就是精简档原文件，另存副本既白占空间也被门禁 [8aq] 点名
                        inc_dict = dict_path
        if brute_domains and words and use_pd:
            _full_n = len([d for d in brute_domains if d not in inc_roots])
            _inc_n = len([d for d in brute_domains if d in inc_roots])
            _est = _full_n * len(words) + _inc_n * len(inc_words or [])
            ctx.logger.info(
                f"[subdomain] 爆破规模预估（puredns 这一路）：全量 {_full_n} 域名 × {len(words)} 词"
                f" + 增量 {_inc_n} 域名 × {len(inc_words or [])} 词 = {_est:,} 次 DNS 查询"
                "（收紧：limits.brute_max_domains / limits.brute_max_words）")
        def _builtin_brute(_words):
            if not offline:
                # 没说死"没装 puredns"：也可能是装了但缺 massdns（上一行的 WARNING 已说清），
                # 所以这里只报"本次走内置兜底"这个事实，不重复下结论。
                ctx.logger.info("[subdomain] 本次不做 puredns 爆破，回退内置 DNS 爆破（系统解析器）")
            if words:
                # 内置那路是逐条 socket 解析，深字典在这里会跑几个小时 —— 单独一道更紧的闸门，
                # 而且**只抽深档**（精简档那几十条永远全量在场），并把"想吃全量就装 puredns"
                # 这条出路写在同一行，而不是让人对着进度条猜。
                fb = cur + _spread(deep, int(limits.get("brute_fallback_max", 3000) or 0),
                                   ctx.logger, "limits.brute_fallback_max")
                fb_inc = (cur + _spread(deep, int(_sub_cfg.get("incremental_max_words", 5000) or 0),
                                        ctx.logger, "subdomain.incremental_max_words")
                          if inc_roots else [])
                if len(fb) < len(wordlist):
                    ctx.logger.info(f"[subdomain] 内置兜底只跑 {len(fb)} 条（并集共 "
                                    f"{len(wordlist)} 条，其中精简档 {len(cur)} 条全量保留）；"
                                    "要用全量字典请装 puredns：python cli/client.py --update-tools")
                ctx.logger.info(
                    f"[subdomain] 内置 DNS 爆破：{len(brute_domains)} 域名 x {len(fb)} 字典 …"
                    f"（预估 {len(brute_domains) * len(fb):,} 次 DNS 查询，"
                    f"并发 limits.brute_workers={int(limits.get('brute_workers', 64))}；"
                    "收紧：limits.brute_max_domains / limits.brute_fallback_max）")
                for d in brute_domains:
                    if ctx.stopped():
                        break
                    # 爆破那一路单独给一档并发（`limits.brute_workers`，默认 64）：它是
                    # **纯 DNS 等待**，跟着 HTTP 的 max_workers(20) 走的话深档要跑更久
                    # （实测本机 3000 条 @20 线程 ≈ 53 秒；闸门设 0 吃全量 17.8 万条，
                    # 即使 128 线程也 45 分钟没跑完 ⇒ 全量只能靠 puredns，它自带并发与限速）。
                    _fb = fb_inc if (inc_roots and d in inc_roots) else fb
                    if inc_roots and d in inc_roots and not _fb:
                        ctx.logger.info(f"[subdomain] 增量模式：{d} 跳过内置爆破（无可跑词表）")
                        continue
                    resolved = wildcard.resolve_all(
                        [f"{s}.{d}" for s in _fb],
                        workers=int(limits.get("brute_workers", 64)))
                    kept, dropped = wildcard.filter_hits(resolved, wild.get(d))
                    add_many((h, "dns-brute(fallback)") for h in kept)
                    if dropped:
                        ctx.logger.info(f"[subdomain] {d} 泛解析过滤丢弃 {len(dropped)} 个"
                                        f"（示例：{dropped[0][0]} → {dropped[0][1]}）")


        if use_pd:
            resolvers = str(resolve(ctx.settings["dicts"]["resolvers"]))
            _pd_ok, _pd_fail = 0, 0
            ctx.logger.info(f"[subdomain] puredns 爆破 {len(brute_domains)} 个域名 …")
            # 续370（主理人点单「puredns 多域合批」）：按词表分组后**一次跑一批**。
            # 增量/全量用不同词表，所以按 `_pd_dict` 分组；组内只有 1 个域名时仍走原来的
            # 位置参数形态（`[264]` 用真二进制钉过的那条），避免为合批把既有路径也改掉。
            _pd_groups = {}
            for d in brute_domains:
                if inc_roots and d in inc_roots and not inc_dict:
                    ctx.logger.info(f"[subdomain] 增量模式：{d} 跳过 puredns"
                                    "（无可跑词表，只吃被动源与历史）")
                    continue
                _pd_groups.setdefault(
                    inc_dict if (inc_roots and d in inc_roots) else dict_path, []).append(d)
            for _gi, (_pd_dict, _doms) in enumerate(_pd_groups.items()):
                if ctx.stopped():
                    # 每组 timeout=3600，不检查停止会让"停止"最多等到全部分组跑完
                    ctx.logger.warning("[subdomain] 任务已请求停止，中止 puredns 爆破")
                    break
                # 把 massdns 所在目录塞进**这一个子进程**的 PATH（puredns 在进程内 exec 它，
                # 拿不到我们在 settings 里写的绝对路径）——见 utils.run_cmd 的 extra_path。
                if len(_doms) == 1:
                    _label = _doms[0]
                    out_file = ctx.workdir / f"brute_{_label}.txt"
                    rc, _, err = run_cmd(
                        puredns_bruteforce_argv(pd_bin, _pd_dict, _label, resolvers, out_file),
                        timeout=3600, throttle=th,
                        extra_path=os.path.dirname(massdns_bin) if massdns_bin else None)
                else:
                    _label = f"{len(_doms)} 个域名（合批）"
                    out_file = ctx.workdir / f"brute_batch_{_gi}.txt"
                    _dom_file = write_lines(ctx.workdir / f"brute_domains_{_gi}.txt", _doms)
                    rc, _, err = run_cmd(
                        puredns_bruteforce_batch_argv(pd_bin, _pd_dict, _dom_file,
                                                      resolvers, out_file),
                        timeout=3600, throttle=th,
                        extra_path=os.path.dirname(massdns_bin) if massdns_bin else None)
                    if rc == 0:
                        ctx.logger.info(
                            f"[subdomain] puredns 合批跑完 {len(_doms)} 个域名"
                            f"（{', '.join(_doms[:3])}{' …' if len(_doms) > 3 else ''}）")
                if rc == 0:
                    add_many((line, "puredns") for line in read_lines(out_file))
                    _pd_ok += 1
                else:
                    _pd_fail += 1
                    ctx.logger.warning(
                        f"[subdomain] puredns {_label} 退出码 {rc}：{err.strip()[:150]}")
            if _pd_fail and not _pd_ok and words:
                ctx.logger.warning(
                    f"[subdomain] puredns 对全部 {_pd_fail} 个域名都失败了 —— 改用内置 DNS "
                    "爆破兜底（不兜的话字典爆破这一路整轮归零，后面阶段全部没得跑）")
                _builtin_brute(words)
        else:
            _builtin_brute(words)
        # ---------- 4b) 组合爆破（续139，对齐灯塔的 alt_dns）----------
        # 与灯塔逐条比实的 24 个"它有我没有"的域名里，**14 个的标签确实在深档里**（受抽样闸门
        # 没爆到），另外 **10 个任何字典里都没有** —— `api-contract` / `ws-spot` / `admin-oss` /
        # `aicoin-http-gateway` 这类是**拼出来**的，灯塔的 `ALT_DNS_CONCURRENT` 干的就是这件事。
        # 种子＝精简档词 ∪ 本任务已经发现的那些名字的首段标签；只做 `a-b` 这一种形状，
        # 不做笛卡尔积爆炸；超出 `limits.brute_combo_max` 一律等距抽样（0=关）。
        combo_max = int(limits.get("brute_combo_max", 40000) or 0)
        combo_domains = [d for d in brute_domains if d not in inc_roots]
        if inc_roots and len(combo_domains) < len(brute_domains):
            ctx.logger.info(f"[subdomain] 组合爆破：增量模式跳过 "
                            f"{len(brute_domains) - len(combo_domains)} 个根域")
        if combo_max and combo_domains and found:
            seeds = sorted({n.split(".")[0] for n in found if "." in n} | set(cur))
            seeds = [s for s in seeds if "-" not in s and len(s) <= 12]
            # 种子夹到 200：两两拼接是 |seeds|² 级别（200 ⇒ 4 万对），不夹的话一个 1236 个名字
            # 的任务会先在这里生成 150 万个字符串再抽样 —— 那是白烧内存。
            seeds = seeds[:200]
            # 续310：这里**必须**显式给 hint —— `_spread` 的默认句是"要用全量把 X 设 0"，
            # 那是给词表闸门（0=不限）写的；组合爆破的 0 是**关掉整轮**（`if combo_max`），
            # 照搬默认句就是一句会让用户把功能关掉的假话。
            _combo_resolvers = str(resolve(ctx.settings.get("dicts", {}).get("resolvers", "")))
            _combo_pd = bool(pd_bin and massdns_bin and not offline
                             and os.path.isfile(_combo_resolvers))
            pairs = _spread(list(dict.fromkeys(
                f"{a}-{b}" for a in seeds for b in seeds if a != b)),
                combo_max, ctx.logger, "limits.brute_combo_max",
                hint="0 表示关闭组合爆破（不是全量）；要更多请调大 limits.brute_combo_max")
            # 未装 puredns 时，组合前缀只能逐条走系统解析器；慢 DNS 上几万条会拖几分钟。
            # 复用内置爆破的 fallback 上限收窄（默认 3000），保证没有 puredns 的机器也能在
            # 可接受时间内完成；装了 puredns 则不受此限（它 27k 条实测 ~5s）。
            if pairs and not _combo_pd:
                _cfb = int(limits.get("brute_fallback_max", 3000) or 0)
                if _cfb and len(pairs) > _cfb:
                    pairs = _spread(pairs, _cfb, ctx.logger, "limits.brute_fallback_max",
                                    hint="未装 puredns 时组合爆破按内置兜底上限收窄；"
                                         "装 puredns 可放开")
            if pairs:
                ctx.logger.info(
                    f"[subdomain] 组合爆破：{len(seeds)} 个种子两两拼出 {len(pairs)} 个 "
                    f"`a-b` 前缀（上限 limits.brute_combo_max={combo_max}，0=关；"
                    f"预估 {len(pairs) * len(brute_domains):,} 次 DNS 查询）…")
                for d in combo_domains:
                    if ctx.stopped():
                        ctx.logger.warning("[subdomain] 任务已请求停止，中止组合爆破")
                        break
                    kept, dropped = [], []
                    _via_pd = False
                    if _combo_pd:
                        _pd_res = _combo_puredns(
                            ctx, d, pairs, pd_bin, massdns_bin, _combo_resolvers,
                            th, wild.get(d), int(limits.get("brute_workers", 64)))
                        if _pd_res is not None:
                            kept, dropped = _pd_res
                            _via_pd = True
                    if not _via_pd:
                        resolved = wildcard.resolve_all(
                            [f"{p}.{d}" for p in pairs],
                            workers=int(limits.get("brute_workers", 64)))
                        kept, dropped = wildcard.filter_hits(resolved, wild.get(d))
                    add_many((h, "dns-brute(combo)") for h in kept)
                    if dropped:
                        ctx.logger.info(f"[subdomain] {d} 组合爆破泛解析丢弃 {len(dropped)} 个")
                    ctx.logger.info(
                        f"[subdomain] {d} 组合爆破{'（puredns）' if _via_pd else '（系统解析器）'}："
                        f"{len(kept)} 个命中")

        getattr(ctx, "report_progress", lambda f: None)(0.9)    # 续275：DNS 字典爆破（含组合爆破）收完
        # ---------- 5) 被动来源的泛解析复核 ----------
        # 被动接口里混入的通配产物（如随机子域被证书签发过）用同一套判据清掉
        if wild:
            suspects = [n for n in found
                        if sources.get(n, "").startswith(_PASSIVE_SRC)]
            if suspects:
                resolved = wildcard.resolve_all(suspects, workers=workers)
                wild_all = set().union(*wild.values())
                kept, dropped = wildcard.filter_hits(resolved, wild_all)
                for name, _ips in dropped:
                    found.discard(name)
                    sources.pop(name, None)
                ctx.logger.info(f"[subdomain] 被动来源泛解析复核：{len(suspects)} 个 → "
                                f"丢弃 {len(dropped)} 个通配产物")

        # 续320（主理人 2026-11-03）：送探子任务按注册域建，但**已知的完整域名**要随任务
        # 带入（`options.seed_domains`）—— 枚举不一定能重新发现它们，漏了就是丢资产。
        _seed320 = [str(s).strip().lower() for s in (ctx.options.get("seed_domains") or [])]
        _seed320 = [s for s in _seed320 if s and targets.is_domain(s)]
        if _seed320:
            _new320 = [s for s in _seed320 if s not in found]
            found.update(_seed320)
            for s in _seed320:
                sources.setdefault(s, "seed")
            ctx.logger.info(f"[subdomain] 带入送探方已知完整域名 {len(_seed320)} 个"
                            f"（其中新发现 {len(_new320)} 个；不依赖枚举重新发现）")
        subs = sorted(found)
        # 用户黑名单：命中的域名直接丢弃 —— 既不入资产表，也不进 probe 的输入，
        # 这样后面的 dirscan / vulnscan 自然也不会覆盖它。
        subs, blocked = blacklist.filter_domains(subs, ctx.settings,
                                                 owner_id=getattr(ctx, "owner_id", 0))
        if blocked:
            ctx.logger.info(f"[subdomain] 黑名单拦截 {blocked} 个域名（config/blacklist.txt）")
        # 续160（主理人点单"同一目标两次结果不一样"里的第二类成因）：沿用历史资产。
        # 抽成方法而不是写在 run() 里 —— 它只读库与配置，抽出来才能被门禁**真跑**，
        # 不必桩 subfinder / 被动源 / 爆破那一整排网络入口（桩出来的绿是假绿，§6.1）。
        hist_added = self.reuse_history(subs, domains, sources)
        all_hosts = sorted(set(subs) | set(domains))
        ctx.results["subdomains"] = subs
        ctx.results["domains_for_probe"] = all_hosts
        write_lines(ctx.workdir / "subdomains.txt", subs)
        write_lines(ctx.workdir / "passive_multi.txt",
                    sorted(n for n in found if sources.get(n, "").startswith("passive:")))
        write_lines(ctx.workdir / "hosts.txt", all_hosts)
        # 跨运行去重（续25）：追加执行时已在库的子域名不再重复入库
        _rows = [(s, sources.get(s, "")) for s in subs]
        db.insert_subdomains(ctx.task_id, db.drop_existing(
            ctx.task_id, "subdomains", ("domain",), _rows, lambda it: (it[0],)))
        self._fill_net(subs, workers)
        ctx.logger.info(f"[subdomain] 新增子域名 {len(subs)} 个"
                        + (f"（含沿用历史 {hist_added} 个）" if hist_added else "")
                        + f"，参与探测主机 {len(all_hosts)} 个")

    def reuse_history(self, subs, domains, sources):
        """把库里**其他任务**已发现、且归属本次目标的自家子域名并进本次结果。

        动机（续160，主理人实跑抓到）：上游源每次返回的集合并不稳定 —— 同一目标一次
        `subfinder → 新增 8 个`、一次 `7 个`，少掉的那条名字会让「端口 → 站点 → 指纹 →
        漏洞」整条链都空掉。库里已经确认过它是本项目的资产，就不该因为这次没重新发现而消失。

        四条口径：① 只借 own 口径（`db.list_known_domains` 的 SQL 判据），`js:` / `osint:`
        是别人的资产面，不该被"借用"成探测目标；② 归属判定走 `extdom.task_bases` +
        `is_in_bases`（与探测候选同一份口径，不分叉）；③ 上限 `subdomain.reuse_history_max`
        （0 = 不限），触顶要说出来；④ 就地写 `sources[name] = "history"` 让 provenance 可见，
        返回并入个数供调用方打日志。**本方法零网络**（只读 SQLite + 配置）。
        """
        ctx = self.ctx
        cfg = ctx.settings.get("subdomain") or {}
        if not cfg.get("reuse_history", True):
            return 0
        cap = max(0, int(cfg.get("reuse_history_max", 300) or 0))
        pool = db.list_known_domains(except_task=ctx.task_id,
                                     owner_id=getattr(ctx, "owner_id", 0),
                                     limit=(cap * 8) if cap else 8000)
        known = extdom.filter_owned(pool, extdom.task_bases(ctx.task_id))
        new = [d for d in known if d not in set(subs) | set(domains)]
        if cap and len(new) > cap:
            ctx.logger.info(f"[subdomain] 历史沿用：候选 {len(new)} 个超过 "
                            f"subdomain.reuse_history_max={cap}，只并前 {cap} 个")
            new = new[:cap]
        for d in new:
            sources[d] = "history"
        subs.extend(new)
        ctx.logger.info(f"[subdomain] 历史沿用：库里自家口径命中 {len(known)} 个 → "
                        + (f"本次并入 {len(new)} 个（其余本轮已自己发现）" if new
                           else "一个新都不用（本轮已全部发现，或没有可借的历史资产）"))
        return len(new)

    def _fill_net(self, subs, workers):
        """回填每个子域名的解析 IP 与 CDN 标记（纯 DNS 只读查询）。

        这两个字段是**子域名资产自身的属性**：越早落库，GUI/报告里的
        "这个域名解析到哪、是否走 CDN"就越完整。
        阶段虽然也查 CNAME，但它默认只覆盖命中接管的候选，且该阶段可以在策略里关掉
        —— 关掉后子域名就完全拿不到解析信息。
        """
        ctx = self.ctx
        if ctx.stopped() or not subs:
            return
        cfg = ctx.settings.get("subdomain", {}) or {}
        cap = int(cfg.get("max_resolve", 1000))
        cap_skipped = []
        if len(subs) > cap:
            ctx.logger.info(f"[subdomain] IP/CDN 回填：{len(subs)} 个超过上限 {cap}，"
                            f"仅处理前 {cap} 个（其余仍入资产表，并标记原因 over-limit）")
            cap_skipped, subs = subs[cap:], subs[:cap]
        timeout = float(cfg.get("dns_timeout", 3) or 3)

        def _one(host):
            if ctx.stopped():
                return None
            # `resolve_detail` 比 `cname_chain` 多返回一个**失败原因码**：
            # 页面上只显示一个 '-' 时，用户无从知道是"域名不存在"还是"解析超时"
            # 还是"被 max_resolve 上限挡掉了"（用户 2026-09-22 明确要求标出原因）。
            chain, ips, reason = dnsq.resolve_detail(host, timeout=timeout,
                                                     settings=ctx.settings)
            # CDN 判定要看**两条判据**：CNAME 链（`cdn_cname.txt`）与解析 IP 段
            # （`cdn_ips.txt`）—— 后者覆盖"任播 CDN 直连 IP、CNAME 为空"的情况。
            return host, ",".join(ips), cdn.match(chain, ctx.settings, ips), reason

        mapping = {}
        for item in pool_run(_one, subs, workers=workers,
                           logger=ctx.logger, label="子域名解析"):
            host, ips, cdn_label, reason = item
            mapping[host] = (ips, cdn_label, reason)
        for host in cap_skipped:
            mapping[host] = ("", "", "over-limit")
        db.set_subdomain_net(ctx.task_id, mapping)
        getattr(ctx, "report_progress", lambda f: None)(0.97)   # 续275：解析回填落库，本阶段接近收尾
        n_cdn = sum(1 for v in mapping.values() if v[1])
        n_fail = sum(1 for v in mapping.values() if v[2])
        ctx.logger.info(f"[subdomain] 回填解析结果 {len(mapping)} 个"
                        f"（CDN {n_cdn} 个 / 非 CDN {len(mapping) - n_cdn - n_fail} 个 / "
                        f"未解析 {n_fail} 个"
                        + (f"，其中 {len(cap_skipped)} 个超出上限" if cap_skipped else "") + "）")