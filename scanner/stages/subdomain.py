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
from .. import blacklist, cdn, db, dnsq, passive, wildcard
from ..config import resolve
from ..utils import (base_domain, is_domain, which, verify_tool, run_cmd, read_lines,
                     write_lines, pool_run)

# 需要做泛解析复核的来源（爆破类来源已自带通配过滤，不重复查询）
_PASSIVE_SRC = ("subfinder", "passive:")


class SubdomainStage(Stage):
    name = "subdomain"
    description = "子域名收集（多来源被动收集 + DNS 字典爆破 + 泛解析过滤）"

    def run(self):
        ctx = self.ctx
        th = ctx.throttle        # F2 统一门控：本任务的限流器（可能是 None）
        limits = ctx.settings.get("limits", {})
        domains, seen = [], set()
        for kind, raw in ctx.targets:
            if kind == "domain" and raw not in seen:
                seen.add(raw)
                domains.append(raw)
        if not domains:
            ctx.logger.info("[subdomain] 目标中无裸域名，跳过该阶段")
            return
        if ctx.stopped():
            ctx.logger.warning("[subdomain] 任务已请求停止，跳过")
            return

        offline = ctx.options.get("offline")
        workers = int(limits.get("max_workers", 20))
        found, sources = set(), {}

        # ---------- 0) 自动拓展扫描（`auto_expand`）：目标是子域时补收主域名 ----------
        # 用户 2026-09-25 的口径：目标是 `aaa.pengo.pro` 时，子域名收集要**连它的主域名
        # `pengo.pro` 一起收**（否则只能收到 aaa 下面再往下的名字，pengo.pro 的其他子域全漏），
        # 而 `aaa.pengo.pro` 本身也要**当作一条子域名资产**入库并解析 —— 此前它只进
        # `hosts.txt` 参与探测，资产表里查不到（"扫过但没记账"，报告里也看不到）。
        # 只在任务级选项 `auto_expand` 打开时做：这是**扩大扫描面**的行为，
        # 不能让既有任务在用户不知情的情况下变样。
        if ctx.options.get("auto_expand") is True:
            for d in list(domains):
                b = base_domain(d)
                if b and b != d and is_domain(b) and b not in seen:
                    seen.add(b)
                    domains.append(b)
                    ctx.logger.info(f"[subdomain] 自动拓展：目标 {d} 是子域，补收主域名 {b}")
            for d in domains:
                if base_domain(d) != d and d not in found:
                    found.add(d)
                    sources[d] = "target"
            if sources:
                ctx.logger.info("[subdomain] 自动拓展：目标自带的子域按子域资产入库 "
                                + " / ".join(sorted(n for n, s in sources.items() if s == "target")))

        def add_many(items):
            """items: (name, source) 可迭代；同名只记首个来源。返回新增条数。"""
            n = 0
            for name, src in items:
                name = (name or "").strip().lower().rstrip(".")
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
        dict_raw = str(ctx.settings.get("dicts", {}).get("subdomains", "") or "")
        wl_path = resolve(dict_raw) if dict_raw else None
        wordlist = ([w for w in read_lines(wl_path) if not w.startswith("#")]
                    if (wl_path and wl_path.is_file()) else [])
        if dict_raw and not wordlist:
            ctx.logger.warning("[subdomain] 子域名字典不可用（路径不存在或为空文件），跳过字典爆破")
        pd_bin = which(ctx.settings.get("tools", {}).get("puredns", "puredns"))
        if pd_bin and not offline and wordlist:
            dict_path = str(resolve(ctx.settings["dicts"]["subdomains"]))
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
            if wordlist:
                ctx.logger.info(
                    f"[subdomain] 内置 DNS 爆破：{len(brute_domains)} 域名 x {len(wordlist)} 字典 …")
                for d in brute_domains:
                    if ctx.stopped():
                        break
                    resolved = wildcard.resolve_all(
                        [f"{s}.{d}" for s in wordlist], workers=workers)
                    kept, dropped = wildcard.filter_hits(resolved, wild.get(d))
                    add_many((h, "dns-brute(fallback)") for h in kept)
                    if dropped:
                        ctx.logger.info(f"[subdomain] {d} 泛解析过滤丢弃 {len(dropped)} 个"
                                        f"（示例：{dropped[0][0]} → {dropped[0][1]}）")

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
        subs, blocked = blacklist.filter_domains(subs, ctx.settings)
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
            return host, ",".join(ips), cdn.match(chain, ctx.settings), reason

        mapping = {}
        for item in pool_run(_one, subs, workers=workers):
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