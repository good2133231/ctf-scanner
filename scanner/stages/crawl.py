"""crawl 阶段：从存活站点的页面里收集**站点自己暴露的链接**（续198）。

产物两张脸、一个口径：
- 全部链接 → `urls` 表（页面「链接」标签页看的就是它）；
- **带参数**的那部分 → `ctx.results["crawl_feed"]`，交给 vulnscan 当**额外的漏洞检测目标**
  （主理人点单："这些我们也要智能测漏洞"）。带参链接才是注入面，无参的静态页喂给漏洞检测
  只是白花请求 —— 所以这里就筛掉，不让 vulnscan 再去判一次。

开关两层（与 portscan 同一形状）：策略 `crawl.enabled` + 任务选项 `crawl: true`。续198 出厂**关**（它一定会发请求：一个站点一页就是一次 GET）；
**续249 起默认开**（主理人点单"默认要开"）——开关仍完整保留：策略页随时可关，关掉时本阶段一个请求都不发；真正兜底的是额度上限（max_sites / max_pages / max_links / 同站判据），不是"替你决定"。
"""
from .. import crawl as crawl_mod, db
from ..utils import http_request, pool_run
from .base import Stage


class CrawlStage(Stage):
    name = "crawl"
    description = "站点爬虫（收集页面里暴露的链接，并给漏洞检测喂带参入口）"

    def run(self):
        ctx = self.ctx
        cfg = ctx.settings.get("crawl", {}) or {}
        forced = ctx.options.get("crawl") is True
        if cfg.get("enabled") is not True and not forced:
            ctx.logger.info("[crawl] 未启用（策略配置 → 站点爬虫 可打开），跳过")
            return
        if ctx.stopped():
            ctx.logger.warning("[crawl] 任务已请求停止，跳过")
            return

        sites = [str(s.get("url") or "") for s in (ctx.results.get("sites") or [])
                 if s.get("url")]
        if not sites:      # 单独跑本阶段 / 站点结果没在内存里时回退数据库
            sites = [str(r["url"] or "") for r in db.list_sites(ctx.task_id) if r["url"]]
        sites = list(dict.fromkeys(sites))
        max_sites = max(1, int(cfg.get("max_sites", 30) or 30))
        if len(sites) > max_sites:
            ctx.logger.info(f"[crawl] 站点 {len(sites)} 个，超过 max_sites={max_sites}，"
                            f"只爬前 {max_sites} 个")
            sites = sites[:max_sites]
        if not sites:
            ctx.logger.info("[crawl] 无站点输入，跳过")
            return

        timeout = int(cfg.get("timeout", 10) or 10)
        workers = max(1, int(cfg.get("workers", 8) or 8))
        ctx.logger.info(f"[crawl] 从 {len(sites)} 个站点收集链接（每站上限 "
                        f"{cfg.get('max_links', 60)} 条 / 最多 {cfg.get('max_pages', 8)} 页）…")

        def _fetch(u):
            if ctx.stopped():
                return None
            return http_request(u, timeout=timeout, settings=ctx.settings, auth=True)

        def _one(site_url):
            rows, stats = crawl_mod.crawl_site(site_url, _fetch, cfg)
            return site_url, rows, stats

        got = pool_run(_one, sites, workers=workers, logger=ctx.logger, label="爬虫")

        # 跨站点去重：同一个 URL 被两个站点（如 http 与 https 两条候选）发现时只留第一条。
        # 去重是**写方**的责任（§5.6），不指望表上的约束。
        seen, rows, totals = set(), [], {"pages": 0, "links": 0, "dup": 0, "offsite": 0,
                                         "bad": 0, "full": 0}
        for _site, _rows, _st in got or []:
            for k, v in _st.items():
                totals[k] = totals.get(k, 0) + v
            for r in _rows:
                if r["url"] in seen:
                    continue
                seen.add(r["url"])
                rows.append(r)
        if not rows:
            ctx.logger.info(f"[crawl] 抓了 {totals['pages']} 个页面，没收集到链接"
                            f"（跳过：外链 {totals['offsite']} / 重复 {totals['dup']} / "
                            f"非页面 {totals['bad']} / 超上限 {totals['full']}）")
            return

        n = db.insert_urls(ctx.task_id, rows)
        ctx.results["urls"] = rows

        # 带参链接 = 注入面，喂给 vulnscan（上限按**每个站点**算，不让一个站吃光额度）
        max_feed = max(0, int(cfg.get("max_feed", 10) or 0))
        feed = []
        if cfg.get("feed_vulnscan", True) is not False and max_feed:
            per_site = {}
            for r in rows:
                if not _has_query(r["url"]):
                    continue
                key = r.get("site_url") or r["url"]
                if per_site.get(key, 0) >= max_feed:
                    continue
                per_site[key] = per_site.get(key, 0) + 1
                feed.append(r["url"])
            ctx.results["crawl_feed"] = feed

        ctx.logger.info(f"[crawl] 抓 {totals['pages']} 页 → 链接 {len(rows)} 条（入库 {n}），"
                        f"其中带参 {sum(1 for r in rows if _has_query(r['url']))} 条"
                        + (f"，喂给漏洞检测 {len(feed)} 条（每站上限 {max_feed}）" if feed else "")
                        + f"｜跳过：外链 {totals['offsite']} / 重复 {totals['dup']} / "
                          f"非页面 {totals['bad']} / 超上限 {totals['full']}")


def _has_query(url):
    """这条 URL 带不带查询串（**唯一的"是不是注入面"判据**，别处不许再写一遍）。"""
    return "?" in str(url or "") and str(url).split("?", 1)[1].strip() != ""
