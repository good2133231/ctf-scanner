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
  ./tools/scanner/puredns bruteforce ./config/subdomains.txt -d url -r ./config/resolvers.txt -w logs/brute.txt
  cat passive.txt brute.txt | sort -u    ->  Python 端以 sorted(set(...)) 等价实现
"""
from .base import Stage
from . import github as github_stage
from .. import blacklist, cdn, db, dnsq, passive, targets, wildcard
from ..config import resolve
from ..utils import (is_domain, to_ascii, which, verify_tool, run_cmd, read_lines,
                    write_lines, pool_run)

# 需要做泛解析复核的来源（爆破类来源已自带通配过滤，不重复查询）
_PASSIVE_SRC = ("subfinder", "passive:")


def _spread(words, cap, logger=None, knob="limits.brute_max_words"):
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
        logger.info(f"[subdomain] 词表 {len(words)} 条超出 {knob}={cap}，等距抽样取 {len(got)} 条"
                    f"（约每 {len(words) / cap:.1f} 条取 1 条，首尾都保住、覆盖整个字典而不是"
                    f"字母表开头；要用全量把 {knob} 设 0）")
    return got


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

        def add_many(items):
            """items: (name, source) 可迭代；同名只记首个来源。返回新增条数。"""
            n = 0
            for name, src in items:
                # IDN / 中文域名 → punycode（被动来源/外部工具理论上可能回传 Unicode）；
                # 归一失败按空串丢弃（显式不静默）。ASCII 名字逐字节不变。
                name = to_ascii((name or "").strip().lower().rstrip(".")) or ""
                if not name or name in found:
                    continue
                found.add(name)
                sources[name] = src
                n += 1
            return n

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
        # 字典路径为空时 `resolve("")` 会落到项目根目录，`read_text()` 抛 IsADirectoryError 并
        # 让整阶段挂掉；这里先确认"配了路径且确实是文件"，否则按"无字典"走（只做被动收集）。
        # 字典分两档（续139）：`dicts.subdomains` 是**精简档**（人工挑的高价值前缀，84 条），
        # `dicts.subdomains_deep` 是**深档**（可选文件，17.8 万条那一类）。为什么必须分两档：
        # 深档在**没装 puredns** 的机器上跑不动（内置那路是系统解析器逐条查），只能抽样收窄，
        # 而 84/177893 ≈ 0.05% —— 抽样会把精简档几乎全冲掉，那是**倒退**。所以精简档永远全量打底，
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
        # 84/177893 ≈ 0.05% 会几乎全冲掉 —— 那不叫收窄，叫倒退）。
        deep_sel = _spread(deep, int(limits.get("brute_max_words", 0) or 0), ctx.logger)
        words = cur + deep_sel
        dict_path = str(resolve(dict_raw)) if dict_raw else ""
        pd_bin = which(ctx.settings.get("tools", {}).get("puredns", "puredns"))
        # puredns 只吃**一个文件**，所以配了深档时要把并集落盘它才读得到。
        # 没装 puredns（或离线）时**不落盘**：内置那路直接拿内存里的词表，写一份 1.5MB 的副本
        # 只是把任务工作目录撑大，谁也不读它。
        use_pd = bool(pd_bin) and not offline and bool(words)
        if deep and use_pd:
            dict_path = str(write_lines(ctx.workdir / "brute_words.txt", words))
        if brute_domains and words and use_pd:
            ctx.logger.info(
                f"[subdomain] 爆破规模预估（puredns 这一路）：{len(brute_domains)} 域名 × "
                f"{len(words)} 词 = {len(brute_domains) * len(words):,} 次 DNS 查询"
                "（收紧：limits.brute_max_domains / limits.brute_max_words）")
        if use_pd:
            resolvers = str(resolve(ctx.settings["dicts"]["resolvers"]))
            ctx.logger.info(f"[subdomain] puredns 爆破 {len(brute_domains)} 个域名 …")
            for d in brute_domains:
                if ctx.stopped():
                    # 每个域名 timeout=3600，不检查停止会让"停止"最多等到全部域名跑完
                    ctx.logger.warning("[subdomain] 任务已请求停止，中止 puredns 爆破")
                    break
                out_file = ctx.workdir / f"brute_{d}.txt"
                rc, _, err = run_cmd([pd_bin, "bruteforce", dict_path, "-d", d,
                                      "-r", resolvers, "-w", str(out_file)], timeout=3600,
                                     throttle=th)
                if rc == 0:
                    add_many((line, "puredns") for line in read_lines(out_file))
                else:
                    ctx.logger.warning(f"[subdomain] puredns {d} 退出码 {rc}：{err.strip()[:150]}")
        else:
            if not offline:
                ctx.logger.info("[subdomain] puredns 不可用，回退内置 DNS 爆破（系统解析器）")
            if words:
                # 内置那路是逐条 socket 解析，深字典在这里会跑几个小时 —— 单独一道更紧的闸门，
                # 而且**只抽深档**（精简档那几十条永远全量在场），并把"想吃全量就装 puredns"
                # 这条出路写在同一行，而不是让人对着进度条猜。
                fb = cur + _spread(deep, int(limits.get("brute_fallback_max", 3000) or 0),
                                   ctx.logger, "limits.brute_fallback_max")
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
                    resolved = wildcard.resolve_all(
                        [f"{s}.{d}" for s in fb],
                        workers=int(limits.get("brute_workers", 64)))
                    kept, dropped = wildcard.filter_hits(resolved, wild.get(d))
                    add_many((h, "dns-brute(fallback)") for h in kept)
                    if dropped:
                        ctx.logger.info(f"[subdomain] {d} 泛解析过滤丢弃 {len(dropped)} 个"
                                        f"（示例：{dropped[0][0]} → {dropped[0][1]}）")

        # ---------- 4b) 组合爆破（续139，对齐灯塔的 alt_dns）----------
        # 与灯塔逐条比实的 24 个"它有我没有"的域名里，**14 个的标签确实在深档里**（受抽样闸门
        # 没爆到），另外 **10 个任何字典里都没有** —— `api-contract` / `ws-spot` / `admin-oss` /
        # `aicoin-http-gateway` 这类是**拼出来**的，灯塔的 `ALT_DNS_CONCURRENT` 干的就是这件事。
        # 种子＝精简档词 ∪ 本任务已经发现的那些名字的首段标签；只做 `a-b` 这一种形状，
        # 不做笛卡尔积爆炸；超出 `limits.brute_combo_max` 一律等距抽样（0=关）。
        combo_max = int(limits.get("brute_combo_max", 4000) or 0)
        if combo_max and brute_domains and found:
            seeds = sorted({n.split(".")[0] for n in found if "." in n} | set(cur))
            seeds = [s for s in seeds if "-" not in s and len(s) <= 12]
            # 种子夹到 200：两两拼接是 |seeds|² 级别（200 ⇒ 4 万对），不夹的话一个 1236 个名字
            # 的任务会先在这里生成 150 万个字符串再抽样 —— 那是白烧内存。
            seeds = seeds[:200]
            pairs = _spread(list(dict.fromkeys(
                f"{a}-{b}" for a in seeds for b in seeds if a != b)),
                combo_max, ctx.logger, "limits.brute_combo_max")
            if pairs:
                ctx.logger.info(
                    f"[subdomain] 组合爆破：{len(seeds)} 个种子两两拼出 {len(pairs)} 个 "
                    f"`a-b` 前缀（上限 limits.brute_combo_max={combo_max}，0=关；"
                    f"预估 {len(pairs) * len(brute_domains):,} 次 DNS 查询）…")
                for d in brute_domains:
                    if ctx.stopped():
                        ctx.logger.warning("[subdomain] 任务已请求停止，中止组合爆破")
                        break
                    resolved = wildcard.resolve_all(
                        [f"{p}.{d}" for p in pairs],
                        workers=int(limits.get("brute_workers", 64)))
                    kept, dropped = wildcard.filter_hits(resolved, wild.get(d))
                    add_many((h, "dns-brute(combo)") for h in kept)
                    if dropped:
                        ctx.logger.info(f"[subdomain] {d} 组合爆破泛解析丢弃 {len(dropped)} 个")

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

        subs = sorted(found)
        # 用户黑名单：命中的域名直接丢弃 —— 既不入资产表，也不进 probe 的输入，
        # 这样后面的 dirscan / vulnscan 自然也不会覆盖它。
        subs, blocked = blacklist.filter_domains(subs, ctx.settings,
                                                 owner_id=getattr(ctx, "owner_id", 0))
        if blocked:
            ctx.logger.info(f"[subdomain] 黑名单拦截 {blocked} 个域名（config/blacklist.txt）")
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
        ctx.logger.info(f"[subdomain] 新增子域名 {len(subs)} 个，参与探测主机 {len(all_hosts)} 个")

    def _fill_net(self, subs, workers):
        """回填每个子域名的解析 IP 与 CDN 标记（纯 DNS 只读查询）。

        为什么放在本阶段而不是 takeover：这两个字段是**子域名资产自身的属性**，
        越早落库，GUI/报告里的"这个域名解析到哪、是否走 CDN"就越完整。takeover
        阶段虽然也查 CNAME，但它默认只覆盖命中接管的候选，且该阶段可以在策略里关掉
        —— 关掉后子域名就完全拿不到解析信息。
        """
        ctx = self.ctx
        if ctx.stopped() or not subs:
            return
        cfg = ctx.settings.get("subdomain", {}) or {}
        cap = int(cfg.get("max_resolve", 500))
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
        n_cdn = sum(1 for v in mapping.values() if v[1])
        n_fail = sum(1 for v in mapping.values() if v[2])
        ctx.logger.info(f"[subdomain] 回填解析结果 {len(mapping)} 个"
                        f"（CDN {n_cdn} 个 / 非 CDN {len(mapping) - n_cdn - n_fail} 个 / "
                        f"未解析 {n_fail} 个"
                        + (f"，其中 {len(cap_skipped)} 个超出上限" if cap_skipped else "") + "）")