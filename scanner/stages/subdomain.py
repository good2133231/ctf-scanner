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
from ..utils import which, verify_tool, run_cmd, read_lines, write_lines, pool_run

# 需要做泛解析复核的来源（爆破类来源已自带通配过滤，不重复查询）
_PASSIVE_SRC = ("subfinder", "passive:")


class SubdomainStage(Stage):
    name = "subdomain"
    description = "子域名收集（多来源被动收集 + DNS 字典爆破 + 泛解析过滤）"

    def run(self):
        ctx = self.ctx
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

        # ---------- 1) subfinder（外部工具优先）----------
        sf_bin = which(ctx.settings.get("tools", {}).get("subfinder", "subfinder"))
        if sf_bin and not verify_tool(sf_bin):
            sf_bin = None
            ctx.logger.info("[subdomain] PATH 中的 subfinder 未通过版本校验，跳过被动收集")
        if sf_bin and not offline:
            ctx.logger.info("[subdomain] subfinder 被动收集 …")
            in_file = write_lines(ctx.workdir / "subfinder_in.txt", domains)
            out_file = ctx.workdir / "passive.txt"
            rc, _, err = run_cmd([sf_bin, "-dL", str(in_file), "-all", "-t", "200",
                                  "-o", str(out_file)], timeout=1800)
            if rc == 0:
                n = add_many((line, "subfinder") for line in read_lines(out_file))
                ctx.logger.info(f"[subdomain] subfinder → 新增 {n} 个")
            else:
                ctx.logger.warning(f"[subdomain] subfinder 退出码 {rc}：{err.strip()[:200]}")

        # ---------- 2) 内置多来源被动收集（免 key 公开接口）----------
        elif not offline:
            ctx.logger.info("[subdomain] subfinder 不可用，改用内置多来源被动收集 …")
            for d in domains:
                if ctx.stopped():
                    break
                n = add_many(passive.collect(d, ctx.settings, logger=ctx.logger).items())
                ctx.logger.info(f"[subdomain] 被动来源 {d} → 新增 {n} 个")
        else:
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
        wordlist = [w for w in read_lines(resolve(
            ctx.settings.get("dicts", {}).get("subdomains", ""))) if not w.startswith("#")]
        pd_bin = which(ctx.settings.get("tools", {}).get("puredns", "puredns"))
        if pd_bin and not offline and wordlist:
            dict_path = str(resolve(ctx.settings["dicts"]["subdomains"]))
            resolvers = str(resolve(ctx.settings["dicts"]["resolvers"]))
            ctx.logger.info(f"[subdomain] puredns 爆破 {len(brute_domains)} 个域名 …")
            for d in brute_domains:
                out_file = ctx.workdir / f"brute_{d}.txt"
                rc, _, err = run_cmd([pd_bin, "bruteforce", dict_path, "-d", d,
                                      "-r", resolvers, "-w", str(out_file)], timeout=3600)
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
        db.insert_subdomains(ctx.task_id, [(s, sources.get(s, "")) for s in subs])
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
        if len(subs) > cap:
            ctx.logger.info(f"[subdomain] IP/CDN 回填：{len(subs)} 个超过上限 {cap}，"
                            f"仅处理前 {cap} 个（其余仍入资产表，只是没有解析信息）")
            subs = subs[:cap]
        timeout = float(cfg.get("dns_timeout", 3) or 3)

        def _one(host):
            if ctx.stopped():
                return None
            chain, ips = dnsq.cname_chain(host, timeout=timeout)
            if not ips and not chain:
                return None
            return host, ",".join(ips), cdn.match(chain, ctx.settings)

        mapping = {}
        for item in pool_run(_one, subs, workers=workers):
            host, ips, cdn_label = item
            mapping[host] = (ips, cdn_label)
        db.set_subdomain_net(ctx.task_id, mapping)
        n_cdn = sum(1 for _ip, label in mapping.values() if label)
        ctx.logger.info(f"[subdomain] 回填解析结果 {len(mapping)} 个"
                        f"（其中标记 CDN {n_cdn} 个，非 CDN {len(mapping) - n_cdn} 个）")