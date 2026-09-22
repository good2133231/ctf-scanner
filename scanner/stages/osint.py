"""阶段：外部情报拓展（P1-4 C 段反查 + P3-1 FOFA favicon 反查）。

位置：probe 之后、jsmine 之前 —— 输入是"存活站点 + 已解析 IP"，产出是**新域名**，
越早入账，后面的 dirscan / vulnscan 覆盖越广。

两个子能力各自独立开关，**默认全部关闭**（都依赖第三方公共接口，可用性不由我们掌控）：
- `iprecon.enabled`：把已知 IP（目标 IP + 站点解析 IP + 子域名 A 记录）反查成域名，
  并把 IP 归纳成 `/24` C 段落 `csegs` 表（GUI「C 段」分栏）；
- `fofa.enabled`：取站点 favicon 的 mmh3 去 FOFA 反查同源资产，
  命中数超过 `fofa.black_ico_threshold` 即判为"黑 ico"（公共图标）并放弃拓展。

两者都关时整个阶段直接跳过 —— 一次请求都不发（与低危检查的处理方式一致）。
"""
from urllib.parse import urlparse

from .base import Stage
from .. import db, iprecon
from .. import fofa as fofa_mod
from ..fingerprint import favicon_hash
from ..utils import pool_run, resolve_host


class OsintStage(Stage):
    name = "osint"
    description = "外部情报拓展（C 段反查域名 / favicon 反查同源资产）"

    def run(self):
        ctx = self.ctx
        do_ip = (ctx.settings.get("iprecon", {}) or {}).get("enabled") is True
        do_fofa = (ctx.settings.get("fofa", {}) or {}).get("enabled") is True
        if not (do_ip or do_fofa):
            ctx.logger.info("[osint] 未启用（策略配置 → 外部情报拓展 可打开），跳过")
            return
        if ctx.stopped():
            ctx.logger.warning("[osint] 任务已请求停止，跳过")
            return

        found = []
        if do_ip:
            found += self._c_segments()
        if do_fofa and not ctx.stopped():
            found += self._fofa_assets()

        if ctx.stopped():
            ctx.logger.warning("[osint] 任务已请求停止，结果不再入账")
            return

        known = {r["domain"] for r in db.list_subdomains(ctx.task_id)}
        new, seen = [], set()
        for domain, source in found:
            if not domain or domain in known or domain in seen:
                continue
            seen.add(domain)
            new.append((domain, source))
        if new:
            db.insert_subdomains(ctx.task_id, new)
        ctx.results["osint_domains"] = [d for d, _ in new]
        ctx.logger.info(f"[osint] 新增域名资产 {len(new)} 个"
                        + (f"（{' / '.join(f'{s}:{n}' for s, n in _tally(new))}）" if new else ""))

    # ---------- C 段反查 ----------

    def _collect_ips(self):
        """汇总待反查的 IP：目标里的 IP 先直接用，其余主机名做一次解析。"""
        ctx = self.ctx
        cfg = ctx.settings.get("iprecon", {}) or {}
        ips, hosts = set(), []
        for kind, raw in ctx.targets:
            if kind == "ip":
                ips.add(raw)
                continue
            host = urlparse(raw).hostname if kind == "url" else raw
            if host:
                hosts.append(host)
        for r in db.list_subdomains(ctx.task_id):
            hosts.append(r["domain"])
        for r in db.list_sites(ctx.task_id):
            hosts.append(r["host"] or "")
        hosts = [h for h in dict.fromkeys(hosts) if h]

        cap = int(cfg.get("max_hosts", 200))
        if len(hosts) > cap:
            ctx.logger.info(f"[osint] 主机名 {len(hosts)} 个超过上限 {cap}，仅解析前 {cap} 个")
            hosts = hosts[:cap]

        def _resolve(host):
            if ctx.stopped():
                return None
            return resolve_host(host, timeout=3)

        for got in pool_run(_resolve, hosts, workers=max(1, int(cfg.get("workers", 5)) * 2)):
            for ip in got or []:
                ips.add(ip)
        return sorted(ips)

    def _c_segments(self):
        ctx = self.ctx
        cfg = ctx.settings.get("iprecon", {}) or {}
        ips = self._collect_ips()
        if not ips:
            ctx.logger.info("[osint] 没有可用于 C 段反查的 IP")
            return []
        public = [ip for ip in ips if iprecon.is_public_ip(ip)]
        cap_ips = int(cfg.get("max_ips", 500))
        if len(public) > cap_ips:
            ctx.logger.info(f"[osint] 公开 IP {len(public)} 个超过上限 {cap_ips}，仅反查前 {cap_ips} 个")
            public = public[:cap_ips]
        segs = iprecon.group_segments(public)
        ctx.logger.info(f"[osint] C 段反查：IP {len(public)}/{len(ips)} 个（私有地址已跳过），"
                        f"覆盖 {len(segs)} 个 /24 C 段 …")
        if not public:
            return []

        mapping, stats = iprecon.lookup_many(public, ctx.settings,
                                             logger=ctx.logger, stop=ctx.stopped)
        if ctx.stopped():
            return []

        # C 段本身也是资产视野：即使没反查到域名，也把"段 + IP"落库（含命中数量）
        cap = max(1, int(cfg.get("max_domains_per_ip", 30)))
        rows = []
        for seg, seg_ips in segs.items():
            for ip in seg_ips:
                doms = mapping.get(ip, [])
                rows.append({"segment": seg, "ip": ip,
                             "domains": doms[:cap], "count": len(doms)})
        db.insert_csegs(ctx.task_id, rows)
        ctx.results["csegs"] = rows

        found = []
        shared = 0
        for ip, doms in mapping.items():
            if len(doms) > cap:
                # 一个 IP 挂了几十个域名 → 共享主机/CDN，继续当资产拓展只会灌噪声
                shared += 1
                continue
            found += [(d, "osint:cseg") for d in doms]
        ctx.logger.info(f"[osint] C 段 → 域名 {stats['domains']} 个 / 命中 IP {stats['hit_ips']} 个"
                        + (f"；{shared} 个 IP 命中过多（>{cap}）判为共享主机，不纳入域名资产"
                           if shared else ""))
        return found

    # ---------- FOFA favicon 反查 ----------

    def _fofa_assets(self):
        ctx = self.ctx
        cfg = ctx.settings.get("fofa", {}) or {}
        if not fofa_mod.available(ctx.settings):
            ctx.logger.info("[osint] FOFA 未配置 email/key（config/keys.yaml），跳过 favicon 反查")
            return []

        sites = [dict(r) for r in db.list_sites(ctx.task_id)]
        if not sites:
            ctx.logger.info("[osint] 无存活站点，跳过 favicon 反查")
            return []
        cap = int(cfg.get("max_sites", 30))
        if len(sites) > cap:
            ctx.logger.info(f"[osint] 站点 {len(sites)} 个超过上限 {cap}，仅取前 {cap} 个算 favicon")
            sites = sites[:cap]

        def _fav(s):
            if ctx.stopped():
                return None
            return {"url": s["url"], "hash": favicon_hash(s["url"], ctx.settings)}

        hashes = {}
        for r in pool_run(_fav, sites, workers=max(1, int(cfg.get("workers", 5)))):
            if r and r["hash"]:
                hashes.setdefault(r["hash"], r["url"])
        ctx.logger.info(f"[osint] favicon 指纹 {len(hashes)}/{len(sites)} 个站点可算（mmh3）")
        if not hashes:
            return []

        found = []
        queried = black = 0
        for icon_hash, url in hashes.items():
            if ctx.stopped():
                break
            assets, total, err = fofa_mod.search(icon_hash, ctx.settings, logger=ctx.logger)
            if err:
                ctx.logger.info(f"[osint] FOFA 反查中止：{err}")
                break
            if fofa_mod.is_black_ico(total, ctx.settings):
                black += 1
                ctx.logger.info(f"[osint] {url} 的 favicon（mmh3 {icon_hash}）命中 {total} 条，"
                                f"超过黑 ico 阈值 {fofa_mod.black_ico_threshold(ctx.settings)}，"
                                f"判为公共图标，不拓展")
                continue
            queried += 1
            ctx.logger.info(f"[osint] FOFA 反查 mmh3 {icon_hash}（{url}）→ {len(assets)} 条 / 共 {total} 条")
            for a in assets:
                domain = a.get("domain") or urlparse(a.get("host") or "").hostname or ""
                found.append((domain, "osint:fofa"))
        ctx.logger.info(f"[osint] FOFA 拓展：查询 {queried} 个 favicon，跳过黑 ico {black} 个")
        return found


def _tally(items):
    counts = {}
    for _, src in items:
        counts[src] = counts.get(src, 0) + 1
    return sorted(counts.items())