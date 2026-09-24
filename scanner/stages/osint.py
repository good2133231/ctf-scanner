"""阶段：外部情报拓展（C 段反查 + favicon 反查 + 证书反查 + 标题反查 + CT 日志）。

位置：probe 之后、jsmine 之前 —— 输入是"存活站点 + 已解析 IP"，产出是**新域名**，
越早入账，后面的 dirscan / vulnscan 覆盖越广。

子能力各自独立开关，**默认全部关闭**（都依赖第三方公共接口，可用性不由我们掌控）：
- `iprecon.enabled`：把已知 IP（目标 IP + 站点解析 IP + 子域名 A 记录）反查成域名，
  并把 IP 归纳成 `/24` 段落 `csegs` 表（任务详情「C 段」页签）；
- `fofa.enabled`：取站点 favicon 的 mmh3 去 FOFA 反查**同源资产**
  （命中数超过 `fofa.black_ico_threshold` 即判为"黑 ico"，放弃拓展）；
- `fofa.cert_enabled`：按 `cert="<注册域>"` 反查**共用同一张 TLS 证书**的域名，
  命中数超过 `fofa.cert_threshold` 判为"通用证书"（公共 CA / 大厂证书），放弃拓展；
- `fofa.title_enabled`：按 `title="<站点标题>"` 反查**标题相同**的资产。它的黑名单是两层的：
  ① 一眼就是模板页的标题（`404` / `Error` / `Welcome to nginx` …）**连查询都不发**；
  ② 查完发现命中数超过 `fofa.title_threshold`（默认 200）判为"公共标题"，放弃拓展
  —— 与"黑 ico"同构，只是判据换成标题；
- `shodan.enabled` / `quake.enabled`：**同一批 favicon 哈希**再去这两家反查
  （`scanner/shodan.py` / `scanner/quake.py`，与 fofa.py 同构、各自独立文件）；
  阈值思路完全沿用"命中过多即放弃拓展"；
- `ctlog.enabled`：查 crt.sh 的**证书透明度日志**（`scanner/ctlog.py`），产出证书维度记录
  （写进 `certs` 表，source='ct'）并把它覆盖的域名当作拓展域名来源。

产出的域名来源分别是 `osint:cseg` / `osint:fofa` / `osint:fofa-cert` / `osint:fofa-title` /
`osint:shodan` / `osint:quake` / `osint:ctlog`，都归「拓展域名」页。
全部子能力都关时整个阶段直接跳过 —— 一次请求都不发（与低危检查的处理方式一致）。

**收口不变量**：所有外部来源产出的域名一律经 `_domain_of()` 过滤，
裸 IP / 带端口 / 带路径 / 通配符**绝不写进 `subdomains`**（IP 类资产归 portscan / probe）。
"""
import ipaddress
from urllib.parse import urlparse

from .base import Stage
from .. import blacklist, db, iprecon
from .. import fofa as fofa_mod
from .. import shodan as shodan_mod
from .. import quake as quake_mod
from .. import ctlog as ctlog_mod
from ..fingerprint import favicon_hash
from ..utils import base_domain, is_domain, pool_run, resolve_host


class OsintStage(Stage):
    name = "osint"
    description = "外部情报拓展（C 段反查域名 / favicon 反查同源资产 / 证书反查）"

    def run(self):
        ctx = self.ctx
        do_ip = (ctx.settings.get("iprecon", {}) or {}).get("enabled") is True
        fofa_cfg = ctx.settings.get("fofa", {}) or {}
        do_fofa = fofa_cfg.get("enabled") is True
        do_cert = do_fofa and fofa_cfg.get("cert_enabled") is not False
        do_title = do_fofa and fofa_cfg.get("title_enabled") is not False
        do_shodan = (ctx.settings.get("shodan", {}) or {}).get("enabled") is True
        do_quake = (ctx.settings.get("quake", {}) or {}).get("enabled") is True
        do_ctlog = ctlog_mod.enabled(ctx.settings)
        if not (do_ip or do_fofa or do_shodan or do_quake or do_ctlog):
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
        if do_cert and not ctx.stopped():
            found += self._fofa_cert()
        if do_title and not ctx.stopped():
            found += self._fofa_title()
        if do_shodan and not ctx.stopped():
            found += self._platform_assets(shodan_mod, "shodan")
        if do_quake and not ctx.stopped():
            found += self._platform_assets(quake_mod, "quake")
        if do_ctlog and not ctx.stopped():
            found += self._ctlog()

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
        # 用户黑名单：命中的域名**不入库**，因此后面的 dirscan/vulnscan 也不会去扫它
        new, blocked = blacklist.filter_pairs(new, ctx.settings)
        if new:
            db.insert_subdomains(ctx.task_id, new)
        if blocked:
            ctx.logger.info(f"[osint] 黑名单拦截 {len(blocked)} 个域名"
                            + f"（如 {blocked[0][0]} ← {blocked[0][1]}）")
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
                domain = _domain_of(a)
                found.append((domain, "osint:fofa"))
        ctx.logger.info(f"[osint] FOFA 拓展：查询 {queried} 个 favicon，跳过黑 ico {black} 个")
        return found

    # ---------- FOFA 证书反查 ----------

    def _root_domains(self):
        """汇总待做证书反查的**注册域**（去重、按出现顺序）：

        目标是域名/URL 时取它的注册域；站点与子域名同样折算到注册域。
        证书是按域名签的，同一个注册域下的 `a.example.com` / `b.example.com` 证书内容常重叠，
        折到注册域能把查询次数压下来（省配额）。IP 目标直接跳过 —— 证书反查要的是域名。
        """
        ctx = self.ctx
        hosts = []
        for kind, raw in ctx.targets:
            if kind == "ip":
                continue
            host = urlparse(raw).hostname if kind == "url" else raw
            if host:
                hosts.append(host)
        for r in db.list_sites(ctx.task_id):
            hosts.append(r["host"] or "")
        for r in db.list_subdomains(ctx.task_id):
            hosts.append(r["domain"])

        roots = []
        for h in hosts:
            h = (h or "").strip().lower().strip(".")
            if not h:
                continue
            try:
                ipaddress.ip_address(h)      # 裸 IP 没有证书主体，跳过
                continue
            except ValueError:
                pass
            root = base_domain(h)
            if root and "." in root:
                roots.append(root)
        return list(dict.fromkeys(roots))

    def _fofa_cert(self):
        ctx = self.ctx
        cfg = ctx.settings.get("fofa", {}) or {}
        if not fofa_mod.available(ctx.settings):
            ctx.logger.info("[osint] FOFA 未配置 email/key（config/keys.yaml），跳过证书反查")
            return []
        roots = self._root_domains()
        if not roots:
            ctx.logger.info("[osint] 没有可用于证书反查的注册域")
            return []
        cap = max(1, int(cfg.get("max_cert_queries") or 10))
        if len(roots) > cap:
            ctx.logger.info(f"[osint] 注册域 {len(roots)} 个超过上限 {cap}，仅反查前 {cap} 个")
            roots = roots[:cap]

        found = []
        queried = common = pre = 0
        for root in roots:
            if ctx.stopped():
                break
            # 零请求预筛：占位证书（example.com / localhost …）实测命中百万级，连查询都不发
            if fofa_mod.is_generic_cert(root):
                pre += 1
                ctx.logger.info(f'[osint] 证书 cert="{root}" 属已知占位证书（如 example.com），'
                                f"跳过查询")
                continue
            assets, total, err = fofa_mod.search_cert(root, ctx.settings, logger=ctx.logger)
            if err:
                ctx.logger.info(f"[osint] 证书反查中止：{err}")
                break
            if fofa_mod.is_common_cert(total, ctx.settings):
                common += 1
                ctx.logger.info(f'[osint] 证书 cert="{root}" 命中 {total} 条，'
                                f"超过通用证书阈值 {fofa_mod.cert_threshold(ctx.settings)}，"
                                f"判为通用证书，不拓展")
                continue
            queried += 1
            ctx.logger.info(f'[osint] 证书反查 cert="{root}" → {len(assets)} 条 / 共 {total} 条')
            for a in assets:
                domain = _domain_of(a)
                found.append((domain, "osint:fofa-cert"))
        ctx.logger.info(f"[osint] 证书拓展：查询 {queried} 个注册域，跳过通用证书 {common} 个"
                        + (f"（另有 {pre} 个占位证书连查询都未发）" if pre else ""))
        return found

    # ---------- FOFA 标题反查 ----------

    def _site_titles(self):
        """待反查的站点标题（去重、保序）：短标题与模板页标题直接丢掉。

        `404` / `Error` / `Welcome to nginx` 这类通用标题一搜一大堆（"一找一大堆"的典型），
        既浪费配额又灌进无关资产 —— 所以它们是**黑名单的第一层**（连查询都不发），
        第二层才是"查完发现命中数超阈值判为公共标题"（与黑 ico 同构）。
        """
        ctx = self.ctx
        titles = []
        # 注意：`db.list_sites()` 返回的是 `sqlite3.Row`，**没有 `.get()`**。
        # 这里曾写成 `r.get("title")`，于是整个 osint 阶段每次都在这里抛 AttributeError
        # 被阶段级容错吞掉 —— 表现是"标题反查永远 0 条、日志只有一行阶段异常"。
        # 真实跑一次（2026-09-22）才暴露出来，故此处与全文件统一用下标取值。
        for r in db.list_sites(ctx.task_id):
            t = (r["title"] or "").strip()
            if len(t) < 4 or fofa_mod.is_generic_title(t):
                continue
            titles.append(t)
        return list(dict.fromkeys(titles))

    def _fofa_title(self):
        ctx = self.ctx
        cfg = ctx.settings.get("fofa", {}) or {}
        if not fofa_mod.available(ctx.settings):
            ctx.logger.info("[osint] FOFA 未配置 email/key（config/keys.yaml），跳过标题反查")
            return []
        titles = self._site_titles()
        if not titles:
            ctx.logger.info("[osint] 没有可用于标题反查的站点标题")
            return []
        cap = max(1, int(cfg.get("max_title_queries") or 10))
        if len(titles) > cap:
            ctx.logger.info(f"[osint] 站点标题 {len(titles)} 个超过上限 {cap}，仅反查前 {cap} 个")
            titles = titles[:cap]

        found = []
        queried = common = 0
        for title in titles:
            if ctx.stopped():
                break
            assets, total, err = fofa_mod.search_title(title, ctx.settings, logger=ctx.logger)
            if err:
                ctx.logger.info(f"[osint] 标题反查中止：{err}")
                break
            if fofa_mod.is_common_title(total, ctx.settings):
                common += 1
                ctx.logger.info(f'[osint] 标题 title="{title}" 命中 {total} 条，'
                                f"超过公共标题阈值 {fofa_mod.title_threshold(ctx.settings)}，"
                                f"判为公共标题，不拓展")
                continue
            queried += 1
            ctx.logger.info(f'[osint] 标题反查 title="{title}" → {len(assets)} 条 / 共 {total} 条')
            for a in assets:
                domain = _domain_of(a)
                found.append((domain, "osint:fofa-title"))
        ctx.logger.info(f"[osint] 标题拓展：查询 {queried} 个标题，跳过公共标题 {common} 个")
        return found

    # ---------- Shodan / Quake favicon 反查（与 FOFA 同构，只换客户端） ----------

    def _favicon_hashes(self, cap, workers):
        """站点 favicon 的 mmh3（**同任务内按 (cap, workers) 缓存**，多平台共用一份）。

        为什么要缓存：Shodan 与 Quake 用的**就是 FOFA 那一批哈希**（同一个 mmh3 键），
        逐个平台重算等于把每个站点的 favicon 再拉一遍，白白多出几十个请求。
        缓存按 `(cap, workers)` 分桶 —— 两家的上限可能配得不一样，取小那份会漏站点，
        取大那份会多算，所以按实际参数各存一份。
        """
        ctx = self.ctx
        cache = self.__dict__.setdefault("_fav_cache", {})
        cached = cache.get((cap, workers))
        if cached is not None:
            return cached
        sites = [dict(r) for r in db.list_sites(ctx.task_id)]
        if not sites:
            ctx.logger.info("[osint] 无存活站点，跳过 favicon 指纹计算")
            cache[(cap, workers)] = {}
            return {}
        if len(sites) > cap:
            ctx.logger.info(f"[osint] 站点 {len(sites)} 个超过上限 {cap}，仅取前 {cap} 个算 favicon")
            sites = sites[:cap]

        def _fav(s):
            if ctx.stopped():
                return None
            return {"url": s["url"], "hash": favicon_hash(s["url"], ctx.settings)}

        hashes = {}
        for r in pool_run(_fav, sites, workers=max(1, workers)):
            if r and r["hash"]:
                hashes.setdefault(r["hash"], r["url"])
        ctx.logger.info(f"[osint] favicon 指纹 {len(hashes)}/{len(sites)} 个站点可算（mmh3）")
        cache[(cap, workers)] = hashes
        return hashes

    def _platform_assets(self, mod, name):
        """按 favicon 哈希去 Shodan / Quake 反查同源资产（`osint:shodan` / `osint:quake`）。

        与 `_fofa_assets` 是同一套流程（查 → 命中过多即放弃拓展），刻意**照抄**而不是
        抽公共基类 —— 三家的字段、鉴权与配额模型各不相同，抽象只会把差异塞进分支里。
        """
        ctx = self.ctx
        cfg = ctx.settings.get(name, {}) or {}
        if not mod.available(ctx.settings):
            ctx.logger.info(f"[osint] {name} 未配置 key（config/keys.yaml），跳过 favicon 反查")
            return []
        try:
            cap = int(cfg.get("max_sites", 30))
        except (TypeError, ValueError):
            cap = 30
        hashes = self._favicon_hashes(cap, max(1, int(cfg.get("workers", 5) or 5)))
        if not hashes:
            return []

        found = []
        queried = black = 0
        for icon_hash, url in hashes.items():
            if ctx.stopped():
                break
            assets, total, err = mod.search(icon_hash, ctx.settings, logger=ctx.logger)
            if err:
                ctx.logger.info(f"[osint] {name} 反查中止：{err}")
                break
            if mod.is_black_ico(total, ctx.settings):
                black += 1
                ctx.logger.info(f"[osint] {url} 的 favicon（mmh3 {icon_hash}）在 {name} 命中 "
                                f"{total} 条，超过黑 ico 阈值 {mod.black_ico_threshold(ctx.settings)}，"
                                f"判为公共图标，不拓展")
                continue
            queried += 1
            ctx.logger.info(f"[osint] {name} 反查 mmh3 {icon_hash}（{url}）→ "
                            f"{len(assets)} 条 / 共 {total} 条")
            for a in assets:
                found.append((_domain_of(a), f"osint:{name}"))
        ctx.logger.info(f"[osint] {name} 拓展：查询 {queried} 个 favicon，跳过黑 ico {black} 个")
        return found

    # ---------- CT 日志（crt.sh） ----------

    def _ctlog(self):
        """查 crt.sh 的证书透明度日志：产出**证书维度**记录 + 它覆盖的域名。

        容错是这里的重点：crt.sh 是公共免费服务，返回 HTML 限流页 / 超时 / 502 都是常态。
        任何失败都只记一行日志并**继续跑下一个域名**，绝不让整个 osint 阶段挂掉
        （阶段级容错只兜异常，不兜"静默没结果"）。
        """
        ctx = self.ctx
        roots = self._root_domains()
        if not roots:
            ctx.logger.info("[osint] 没有可用于 CT 日志查询的注册域")
            return []
        cap = ctlog_mod.max_domains(ctx.settings)
        if len(roots) > cap:
            ctx.logger.info(f"[osint] 注册域 {len(roots)} 个超过上限 {cap}，仅查前 {cap} 个")
            roots = roots[:cap]

        found, certs = [], []
        queried = failed = 0
        for root in roots:
            if ctx.stopped():
                break
            records, err = ctlog_mod.search(root, ctx.settings, logger=ctx.logger)
            if err:
                failed += 1
                ctx.logger.info(f"[osint] CT 日志查询 {root} 失败：{err}（记一行，继续）")
                continue
            queried += 1
            n_dom = sum(len(r.get("san") or []) for r in records)
            ctx.logger.info(f"[osint] CT 日志 {root} → 证书 {len(records)} 张 / 域名 {n_dom} 个")
            for rec in records:
                if ctlog_mod.write_certs(ctx.settings):
                    row = dict(rec)
                    row.update({"url": "", "host": root, "port": 0, "source": "ct"})
                    certs.append(row)
                for d in ctlog_mod.domains_of([rec]):
                    found.append((d, "osint:ctlog"))
        if certs:
            db.insert_certs(ctx.task_id, certs)
        ctx.logger.info(f"[osint] CT 日志：查询 {queried} 个注册域，失败 {failed} 个，"
                        f"证书记录 {len(certs)} 条"
                        + ("（已写入「SSL 证书」页签，来源 ct）" if certs else ""))
        return found



def _domain_of(asset):
    """从 FOFA 资产行里取**域名**；取不到、或是裸 IP 就返回空串。

    实测（2026-09-22 真实查询）FOFA 的结果里**大量行的 `domain` 是空的**，
    只有 `host`（如 `https://116.63.154.0` / `47.117.144.116:1000`）。原实现直接
    `a["domain"] or hostname`，于是把**裸 IP 当成域名**写进了 `subdomains` 表 ——
    那会让「子域名资产」里混进一堆 IP，也会被后续 dirscan/vulnscan 当域名去处理。
    这里统一收口：只有真的像域名（含点、非 IP）才返回。
    """
    raw = str(asset.get("domain") or "").strip().lower().strip(".")
    if not raw:
        raw = (urlparse(str(asset.get("host") or "")).hostname or "").strip(".")
    # 统一走 `utils.is_domain()`：它已经把"裸 IP / 带端口 / 带路径 / 通配符"全部挡掉，
    # 比这里各写一份判断更可靠（用户要求"简单判断是不是域名"）。
    return raw if is_domain(raw) else ""


def _tally(items):
    counts = {}
    for _, src in items:
        counts[src] = counts.get(src, 0) + 1
    return sorted(counts.items())