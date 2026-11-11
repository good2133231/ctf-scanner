"""阶段：外部情报拓展（IP 反查 + favicon 反查 + 证书反查 + 标题反查 + CT 日志）。

位置：probe 之后、jsmine 之前 —— 输入是"存活站点 + 已解析 IP"，产出是**新域名**，
越早入账，后面的 dirscan / vulnscan 覆盖越广。

子能力各自独立开关，**默认全部关闭**（都依赖第三方公共接口，可用性不由我们掌控）：
- `iprecon.enabled`：两路精确 IP 反查 —— `from_targets` 用目标/子域名/站点解析出的
  真实 IP 直接反查；`from_favicon` 只处理 favicon 命中的裸 IP（先探活，再 IP→域名）。
  **C 段反查已停用**（续336：同段/共享 IP 很容易把别人的资产收进来）；续338 起
  `run()` 只调用不写 C 段表的 `_ip_reverse()`，不调用 `_c_segments()`；历史 `csegs`
  仍可在任务详情「C 段」页签查看；
- `fofa.enabled`：取站点 favicon 的 mmh3 去 FOFA 反查**同源资产**
  （命中数超过 `fofa.black_ico_threshold` 即判为"黑 ico"，放弃拓展）；
- `fofa.cert_enabled`：按 `cert="<注册域>"` 反查**共用同一张 TLS 证书**的域名，
  命中数超过 `fofa.cert_threshold` 判为"通用证书"（公共 CA / 大厂证书），放弃拓展；
- `fofa.title_enabled`：按 `title="<站点标题>"` 反查**标题相同**的资产。它的黑名单是两层的：
  ① 一眼就是模板页的标题（`404` / `Error` / `Welcome to nginx` …）**连查询都不发**；
  ② 查完发现命中数超过 `fofa.title_threshold`（默认 200）判为"公共标题"，放弃拓展
  —— 与"黑 ico"同构，只是判据换成标题；
- `fofa.host_enabled`（续365）：按 `host="<注册域首段>"` 反查同名资产；**只收
  IP 与本任务子域名解析结果重合的**（不排除 CDN、多 A 任一命中即可），命中行
  以 `osint:fofa-host` 入库并判高置信；
- `shodan.enabled` / `quake.enabled`：**同一批 favicon 哈希**再去这两家反查
  （`scanner/shodan.py` / `scanner/quake.py`，与 fofa.py 同构、各自独立文件）；
  阈值思路完全沿用"命中过多即放弃拓展"；
- `ctlog.enabled`：查 crt.sh 的**证书透明度日志**（`scanner/ctlog.py`），产出证书维度记录
  （写进 `certs` 表，source='ct'）并把它覆盖的域名当作拓展域名来源。

产出的域名来源分别是 `osint:fofa` / `osint:fofa-cert` / `osint:fofa-title` /
`osint:reverse`（精确 IP 反查）/ `osint:iprecon`（favicon 命中裸 IP） /
`osint:shodan` / `osint:quake` / `osint:vt` / `osint:ctlog` / `osint:fofa-host`，都归「拓展域名」页。
历史 `osint:cseg` 是已停用的旧 C 段标签，底层同样是精确 IP 反查；新任务不再产生该来源。
全部子能力都关时整个阶段直接跳过 —— 一次请求都不发（与低危检查的处理方式一致）。

**收口不变量**：所有外部来源产出的域名一律经 `_domain_of()` 过滤，
裸 IP / 带端口 / 带路径 / 通配符**绝不写进 `subdomains`**（IP 类资产归 portscan / probe）。
"""
import json
import re


from .base import Stage
from .. import blacklist, config, db, extdom, iprecon, jsmine, targets
from .. import cdn as cdn_mod
from .. import fofa as fofa_mod
from .. import shodan as shodan_mod
from .. import quake as quake_mod
from .. import virustotal as vt_mod
from .. import ctlog as ctlog_mod
from .. import keystore
from ..fingerprint import favicon_hash
from ..utils import http_request, is_domain, pool_run, resolve_host

# ---------- FOFA 标题反查的相关性过滤 ----------

# 标题按非字母数字切 token 后，这些通用词不参与"是否相关"的判断
# （避免把 `com` / `www` / `home` 这类通用词误当品牌词）。
_TITLE_STOPWORDS = frozenset({
    "www", "http", "https", "com", "net", "org", "the", "and", "for", "you",
    "your", "our", "official", "home", "homepage", "index", "page", "site",
    "web", "welcome", "login", "sign", "account", "app", "mobile", "document",
    "untitled", "new", "error", "admin", "portal",
})
_TITLE_TOKEN_RE = re.compile(r"[a-z0-9]+")


class OsintStage(Stage):
    name = "osint"
    description = "外部情报拓展（精确 IP 反查 / favicon 反查同源资产 / 证书反查）"

    def _mark_icon(self, url, status):
        """记录一份图标的拓展结论（续225）：expanded > black > empty（多平台取最有信息量的）。

        页面据此在图标下显示「已拓展」/「三方未拓展」；空串 = 没查/无图标，不显示徽章。
        """
        rank = {"expanded": 3, "black": 2, "empty": 1}
        cur = self.__dict__.setdefault("_icon_status", {})
        if rank.get(status, 0) >= rank.get(cur.get(url, ""), 0):
            cur[url] = status

    def _note_source(self, key, label, status, count=0, detail=""):
        """续362：记录一个 OSINT 来源的结果状态（ok/empty/unknown/partial/failed/skipped/disabled）。

        存进 `tasks.options.osint_sources`，任务详情页直接展示；解决“来源失败”和
        “确实没有资产”看起来一样的问题。不自动重试。
        """
        cur = self.__dict__.setdefault("_osint_sources", {})
        cur[key] = {"key": str(key), "label": str(label), "status": str(status),
                    "count": int(count or 0), "detail": str(detail or "")[:240]}

    def _save_source_status(self):
        """把本轮来源状态合并进 options（保留其它 options 键），失败只 warning。"""
        st = list(self.__dict__.get("_osint_sources", {}).values())
        shared = sorted(str(x) for x in (self.__dict__.get("_shared_ips") or set()) if x)
        if not st and not shared:
            return
        for s in st:
            if s.get("status") == "pending":
                s["status"] = "skipped"
        ctx = self.ctx
        if st:
            ctx.logger.info("[osint] 来源状态：" + " / ".join(
                f"{s['label']}={s['status']}({s['count']})" for s in st))
        try:
            task = dict(db.get_task(ctx.task_id) or {})
            try:
                opts = json.loads(task.get("options") or "{}")
            except (TypeError, ValueError):
                opts = {}
            if not isinstance(opts, dict):
                opts = {}
            if st:
                opts["osint_sources"] = st
            # 续363：共享 IP 也落盘，供 extdom 在 VT/FOFA 拓展行上继续排除伪同源证据。
            if shared:
                opts["iprecon_shared_ips"] = shared
            else:
                opts.pop("iprecon_shared_ips", None)
            db.update_task(ctx.task_id, options=json.dumps(opts, ensure_ascii=False))
        except Exception as e:      # noqa: BLE001 - 状态展示不能把情报阶段带崩
            ctx.logger.warning(f"[osint] 来源状态写入失败（不影响扫描）：{e}")

    def _favicon_ip_domains(self, ips, skip_alive=False):
        """favicon 命中里的裸 IP：**先探活，再做 IP→域名**（续314，主理人点单）。

        为什么必须先探活：IP 反查（webscan / hackertarget / rapiddns / FOFA `ip=`）返回的
        都是**历史**解析，IP 可能早就换主了；活着的 IP 才有"它现在承载什么"的意义。
        探活只发 2 个 GET（http/https 各一次、超时 3 秒、不带登录态、不校验证书），
        失败就跳过 —— 宁可少列，也不把死 IP 的历史域名灌进拓展。

        免费源与 FOFA `ip=` **都做**（主理人点单）：免费源先跑，FOFA 有 key 再补一路；
        两路结果合并去重。入库来源统一 `osint:iprecon`，note 写明 IP 语法与「历史反查·待确认」
        —— 它与「同一张证书 / 同一图标」那种当前证据不是一回事，页面必须能分开读。

        续366：`skip_alive=True` 供 **FOFA 端口资产**那批裸 IP 复用同一条反查链路 ——
        FOFA 已经证明该 IP:port 上有服务，不再探活 80/443（那会漏掉只开 2053/2083 的资产），
        也不再受 `iprecon.enabled`（出厂默认关）限制，改由 `fofa.bare_ip_reverse` 独立控制。
        `skip_alive=False` 的行为逐字不变（门禁 [314] 直接调默认档）。
        """
        ctx = self.ctx
        if skip_alive:
            fcfg = ctx.settings.get("fofa", {}) or {}
            if fcfg.get("bare_ip_reverse") is False:
                ctx.logger.info("[osint] FOFA 裸 IP 反查已关闭（fofa.bare_ip_reverse=false）")
                return []
            if (getattr(ctx, "options", None) or {}).get("offline"):
                ctx.logger.info("[osint] 离线任务跳过 FOFA 裸 IP 反查")
                return []
            cap = int(fcfg.get("web_max", 20) or 0)
        else:
            cfg = ctx.settings.get("iprecon", {}) or {}
            if cfg.get("from_favicon", True) is False:
                ctx.logger.info("[osint] favicon 命中 IP 的反查已关闭（iprecon.from_favicon=false）")
                return []
            # 续317：总开关必须管住这条子链路 —— 续314 时它只认 from_favicon，
            # `iprecon.enabled=false`（出厂默认）时照样发真实请求（门禁 [6k] 抓到）。
            if cfg.get("enabled") is not True:
                ctx.logger.info("[osint] favicon 命中 IP 的反查跳过（iprecon.enabled 未开）")
                return []
            cap = int(cfg.get("from_favicon_max", 20) or 0)
        if cap > 0 and len(ips) > cap:
            ctx.logger.info(f"[osint] 裸 IP {len(ips)} 个超过上限 {cap}，仅处理前 {cap} 个")
            ips = list(ips)[:cap]
        out, alive_n, seen_ip = [], 0, set()
        for ip in ips:
            if ctx.stopped():
                break
            ip = str(ip or "").strip()
            if not ip or ip in seen_ip:
                continue
            seen_ip.add(ip)
            if not iprecon.is_public_ip(ip):
                continue
            if not skip_alive:
                if not self._ip_alive(ip):
                    ctx.logger.info(f"[osint] favicon 命中 IP {ip} 探活失败（80/443 无响应），跳过反查")
                    continue
                alive_n += 1
            doms = []
            try:
                doms = iprecon.reverse_lookup(ip, ctx.settings, logger=ctx.logger)
            except Exception as e:      # noqa: BLE001 - 公共反查接口，任何异常都不该影响主流程
                ctx.logger.debug(f"[osint] IP {ip} 免费源反查异常：{e}")
            via = "免费源"
            if fofa_mod.available(ctx.settings):
                assets, _total, err = fofa_mod.search_ip(ip, ctx.settings, logger=ctx.logger)
                if err:
                    ctx.logger.info(f"[osint] FOFA ip= 反查 {ip} 未成：{err}")
                elif assets:
                    doms = list(doms) + [d for d in (_domain_of(a) for a in assets) if d]
                    via = "免费源+FOFA"
            uniq = [d for d in dict.fromkeys(doms) if d]
            ctx.logger.info(f"[osint] FOFA 裸 IP {ip}{'' if skip_alive else ' 存活'}，"
                            f"{via}反查出 {len(uniq)} 个域名（历史数据，入库标「待确认」）")
            for d in uniq:
                # 续319：按「同域 / 名字相似 / 同证书 / 同证书+favicon / 待确认」分级，
                # 依据写进 note（拓展域名页的「备注」列直接看得到）。
                _tag319, _why319 = _recon_level(d, ctx)
                _note319 = f'ip="{ip}" · 历史反查（{via}）· {_tag319}'
                if skip_alive:
                    _note319 = "FOFA 裸 IP · " + _note319
                if _why319:
                    _note319 += f"（{_why319}）"
                out.append((d, "osint:iprecon", _note319))
        if ips:
            ctx.logger.info(f"[osint] FOFA 裸 IP {len(ips)} 个"
                            + ("" if skip_alive else f"：探活通过 {alive_n} 个")
                            + f"，反查域名 {len({d for d, _s, _n in out})} 个")
        return out

    def _ip_alive(self, ip):
        """IP 是否还活着：http/https 根路径各一次 GET，任一有响应即算活（续314）。

        刻意 `auth=False, verify=False`：这些 IP 来自 FOFA，**不是本任务的授权目标**，
        不带任务登录态（Cookie 泄露）；只判断"有没有响应"，证书是谁签的与探活无关。
        """
        ctx = self.ctx
        for scheme in ("http", "https"):
            if ctx.stopped():
                return False
            r = http_request(f"{scheme}://{ip}/", timeout=3, settings=ctx.settings,
                             verify=False, auth=False)
            if r is not None:
                return True
        return False

    def _flush_icon_status(self):
        st = getattr(self, "_icon_status", {})
        if st:
            db.set_site_icon_status(self.ctx.task_id, list(st.items()))

    def run(self):
        ctx = self.ctx
        self._icon_status = {}
        self._osint_sources = {}
        self._shared_ips = set()
        self._fofa_host_ips = {}
        self._bare_ips = []          # 续366：FOFA 各路攒下的裸 IP
        self._fofa_web_ports = []    # 续366：FOFA 各路攒下的 host:port 资产
        fofa_cfg = ctx.settings.get("fofa", {}) or {}
        do_fofa = fofa_cfg.get("enabled") is True
        do_host = do_fofa and fofa_cfg.get("host_enabled") is not False
        do_cert = do_fofa and fofa_cfg.get("cert_enabled") is not False
        do_title = do_fofa and fofa_cfg.get("title_enabled") is not False
        do_shodan = (ctx.settings.get("shodan", {}) or {}).get("enabled") is True
        do_quake = (ctx.settings.get("quake", {}) or {}).get("enabled") is True
        # 续214：VirusTotal **子域名**反查 —— 与前三家 favicon 反查不同路（那是同源推断、
        # 这是已收录的父子关系）。它**不进 extquota 预检**：VT 免费档是速率限制
        # （4 次/分钟、500 次/天）而不是"剩余额度"，没有可查的额度端点；那一档由模块
        # 自己的 `min_interval` 节流 + 429 如实停来兑现（塞进 preflight 只会得到假数字）。
        do_vt = (ctx.settings.get("virustotal", {}) or {}).get("enabled") is True
        do_ctlog = ctlog_mod.enabled(ctx.settings)
        # 续334（urlfinder 式）：Wayback 被动 URL 源 —— 查第三方历史索引，不碰目标站。
        # 零目标请求（CDX 是第三方），离线任务跳过；产出 source=`osint:wayback`。
        _pcfg334 = ctx.settings.get("passive_urls", {}) or {}
        do_passive = (_pcfg334.get("enabled") is not False
                      and not ctx.options.get("offline"))
        # 续338（主理人 2026-11-05）：不要 C 段，只要**目标真实 IP 的 IP 反查**。
        # 反查单位是精确 IP，不展开 /24；结果仍进拓展域名，供索引与后续高置信送探。
        _ipcfg338 = ctx.settings.get("iprecon", {}) or {}
        do_iprecon = (_ipcfg338.get("enabled") is True
                      and _ipcfg338.get("from_targets") is not False
                      and not ctx.options.get("offline"))
        # 续211-P1-4：外部引擎**配额预检**（三家按 key 计费/限流）。额度耗尽时的现状是
        # 逐条请求失败、日志刷一片归因错的失败原因（用户看到"工具坏了"，事实是"额度用完了"）。
        # 口径照 `iprecon.preflight`：**跳过必须点名**；查不到额度的一律放行
        # （"我不知道" ≠ "没额度"，§6.2 第十七起同族）；`auth=False`（§5.1 第三方不带登录态）。
        # 每轮只查一次（它自己吃一次 HTTP，但不吃目标侧请求预算）。
        if do_fofa or do_shodan or do_quake:
            from .. import extquota as _eq211
            _srcs211 = [s for s, on in (("fofa", do_fofa), ("shodan", do_shodan),
                                        ("quake", do_quake)) if on]
            _ok211, _bad211 = _eq211.preflight(_srcs211, ctx.settings,
                                               logger=ctx.logger)
            if _bad211:
                do_fofa = do_fofa and "fofa" in _ok211
                do_shodan = do_shodan and "shodan" in _ok211
                do_quake = do_quake and "quake" in _ok211
        # 续205：备案反查有**自己的**开关（icp.enabled）—— 它用的是另一套接口、另一份配额，
        # 与"外部情报拓展"那批不是一回事。默认全关时整段跳过、零请求。
        do_icp = (ctx.settings.get("icp", {}) or {}).get("enabled") is True
        # 续362：先把“启用/未启用”记下来；各来源函数后面覆盖成 ok/empty/partial/failed。
        for _k362, _l362, _on362 in (("fofa", "FOFA", do_fofa),
                                     ("shodan", "Shodan", do_shodan),
                                     ("quake", "Quake", do_quake),
                                     ("virustotal", "VirusTotal", do_vt),
                                     ("ctlog", "CT 日志", do_ctlog),
                                     ("icp", "备案反查", do_icp),
                                     ("iprecon", "IP 反查", do_iprecon),
                                     ("passive", "Wayback", do_passive)):
            self._note_source(_k362, _l362, "pending" if _on362 else "disabled")
        if not (do_fofa or do_shodan or do_quake or do_vt or do_ctlog
                or do_icp or do_passive or do_iprecon):
            ctx.logger.info("[osint] 未启用（策略配置 → 外部情报拓展 可打开），跳过")
            self._save_source_status()
            return
        if ctx.stopped():
            ctx.logger.warning("[osint] 任务已请求停止，跳过")
            self._save_source_status()
            return

        found = []
        if do_icp and not ctx.stopped():
            try:
                from .. import icp as _icp205
                _n205, _note205 = _icp205.run(ctx, logger=ctx.logger)
                if _note205:
                    ctx.logger.info(f"[osint] 备案反查：{_note205}")
                if _n205:
                    found += [str(r["domain"]) for r in db._query(
                        "SELECT domain FROM subdomains WHERE task_id=? AND source='osint:icp'",
                        (ctx.task_id,))]
                self._note_source("icp", "备案反查", "ok" if _n205 else "empty",
                                  _n205, _note205)
            except Exception as _e205:            # noqa: BLE001 —— 情报阶段不许把任务带崩
                self._note_source("icp", "备案反查", "failed", 0, str(_e205))
                ctx.logger.warning(f"[osint] 备案反查失败（不影响其余情报）：{_e205}")
        # 续336/338（主理人点单）：C 段反查停用；只保留**精确 IP 反查**。
        # `_c_segments()` 仍不调用（它写 C 段表、按 /24 归档，已判为噪声源），
        # 新增的 `_ip_reverse()` 只拿目标/资产解析出的真实 IP 去反查域名。
        if do_iprecon and not ctx.stopped():
            try:
                _ip_items362 = self._ip_reverse()
                found += _ip_items362
                self._note_source("iprecon", "IP 反查",
                                  "ok" if _ip_items362 else "empty", len(_ip_items362))
            except Exception as _e338:          # noqa: BLE001 - 情报阶段不许把任务带崩
                self._note_source("iprecon", "IP 反查", "failed", 0, str(_e338))
                ctx.logger.warning(f"[osint] IP 反查失败（不影响其余情报）：{_e338}")
        if do_fofa and not ctx.stopped():
            # 续365：host= 反查的「同 IP 佐证」优先级高于其它反查来源 —— 同一域名被
            # 多路命中时要以 osint:fofa-host 落库，置信度证据才不会在去重里丢掉。
            _fofa362 = (self._fofa_host() if do_host else []) + self._fofa_assets()
            if do_cert and not ctx.stopped():
                _fofa362 += self._fofa_cert()
            if do_title and not ctx.stopped():
                _fofa362 += self._fofa_title()
            found = _fofa362 + found
            # 续366：FOFA 四路（favicon / cert / title / host=）攒下的裸 IP 与 host:port
            # 在这里统一收口 —— 位置必须在全部查询之后，少一路都会漏资产。
            if self._bare_ips and not ctx.stopped():
                found = self._favicon_ip_domains(self._bare_ips, skip_alive=True) + found
            if self._fofa_web_ports and not ctx.stopped():
                self._fofa_web_portscan()
            self._note_source("fofa", "FOFA", "ok" if _fofa362 else "unknown", len(_fofa362),
                              "" if _fofa362 else "无返回；空结果与上游失败无法区分（详见任务日志）")
        if do_shodan and not ctx.stopped():
            _sh362 = self._platform_assets(shodan_mod, "shodan")
            found += _sh362
            self._note_source("shodan", "Shodan", "ok" if _sh362 else "unknown", len(_sh362),
                              "" if _sh362 else "无返回；空结果与上游失败无法区分（详见任务日志）")
        if do_quake and not ctx.stopped():
            _qu362 = self._platform_assets(quake_mod, "quake")
            found += _qu362
            self._note_source("quake", "Quake", "ok" if _qu362 else "unknown", len(_qu362),
                              "" if _qu362 else "无返回；空结果与上游失败无法区分（详见任务日志）")
        if do_vt and not ctx.stopped():
            found += self._vt_domains()

        if do_ctlog and not ctx.stopped():
            found += self._ctlog()

        if do_passive and not ctx.stopped():
            _pa362 = self._passive_hosts()
            found += _pa362
            self._note_source("passive", "Wayback", "ok" if _pa362 else "unknown", len(_pa362),
                              "" if _pa362 else "无返回；空结果与上游失败无法区分（详见任务日志）")

        if ctx.stopped():
            ctx.logger.warning("[osint] 任务已请求停止，结果不再入账")
            self._save_source_status()
            return

        known = {r["domain"] for r in db.list_subdomains(ctx.task_id)}
        new, seen, notes = [], set(), {}
        for item in found:
            domain, source = item[0], item[1]
            note = item[2] if len(item) > 2 else ""
            if not domain or domain in known or domain in seen:
                continue
            seen.add(domain)
            notes[domain] = note
            new.append((domain, source))
        # 用户黑名单：命中的域名**不入库**，因此后面的 dirscan/vulnscan 也不会去扫它
        new, blocked = blacklist.filter_pairs(new, ctx.settings,
                                             owner_id=getattr(ctx, "owner_id", 0))
        # 续154（用户点单）：第三方 / CDN / SaaS 清单同样要挡在**入库前**。此前这张清单只在 JS
        # 挖掘那条路上生效，FOFA / C 段 / 证书 / CT 反查回来的 `*.cloudfront.net`、
        # `*.workers.dev` 照样进「拓展域名」，那一页一半是别人的资产。归属本项目的先放行
        # （与 `jsmine._is_noise` 同一口径：自家域名哪怕长得像第三方也不当噪声）。
        _bases = extdom.task_bases(ctx.task_id)
        keep, third = [], []
        for d, s in new:
            if extdom.is_owned(d, _bases) or not jsmine.is_thirdparty(d):
                keep.append((d, s))
            else:
                third.append((d, s))
        new = keep
        if third:
            ctx.logger.info(f"[osint] 第三方/CDN 噪声 {len(third)} 个未入库"
                            f"（如 {third[0][0]} ← {third[0][1]}；清单在 "
                            f"config/dicts/js_thirdparty.txt，要放行就往那个文件里删一行）")
        if new:
            # 续171：入库时带上**查询语法**（`icon_hash="123"` / `cert="x"` / `title="x"`），
            # 拓展域名页「语法」列据此展示 —— 用户要求反查结果必须标明用的是哪条语法。
            db.insert_subdomains(ctx.task_id,
                                 [(d, s, "", notes.get(d, "")) for d, s in new])
        if self._fofa_host_ips:
            # 续365：同 IP 命中的行补上解析 IP ⇒ 过 `ext_rows(resolved_only=True)` 的硬门
            # （自动送探只收已解析行）。`set_subdomain_net` 按 (task_id, domain) 更新，
            # 被黑名单/第三方闸挡掉的行本来就不存在，UPDATE 自然空转。
            try:
                db.set_subdomain_net(ctx.task_id,
                                     {d: (ip, "", "") for d, ip in self._fofa_host_ips.items()})
            except Exception as _e365:      # noqa: BLE001 - 回填失败不该拖垮整阶段
                ctx.logger.warning(f"[osint] FOFA host 命中行回填 IP 失败：{_e365}")
        if blocked:
            ctx.logger.info(f"[osint] 黑名单拦截 {len(blocked)} 个域名"
                            + f"（如 {blocked[0][0]} ← {blocked[0][1]}）")
        ctx.results["osint_domains"] = [d for d, _ in new]

        # 续375：IP 维度证据聚合（真实 IP / CDN 边缘）—— 零外部请求，只读本任务库
        try:
            from .. import ipagg as _ipagg375
            _rows375 = _ipagg375.aggregate(ctx.task_id)
            ctx.results["ip_evidence"] = _rows375
            _leads375 = _ipagg375.to_leads(_rows375)
            if _leads375:
                db.insert_leads(ctx.task_id, _leads375)
            ctx.logger.info(
                f"[osint] IP 证据聚合：{len(_rows375)} 个 IP"
                f"（real {sum(1 for x in _rows375 if x['rank'] == 'real')} / "
                f"likely {sum(1 for x in _rows375 if x['rank'] == 'likely')} / "
                f"cdn {sum(1 for x in _rows375 if x['rank'] == 'cdn')}），"
                f"线索新增 {len(_leads375)} 条")
        except Exception as _e375:      # noqa: BLE001 - 聚合失败不该拖垮 OSINT
            ctx.logger.warning(f"[osint] IP 证据聚合失败（不影响其余）：{_e375}")
        ctx.logger.info(f"[osint] 新增域名资产 {len(new)} 个"
                        + (f"（{' / '.join(f'{s}:{n}' for s, n in _tally(new))}）" if new else ""))
        self._save_source_status()

    def _passive_hosts(self):
        """Wayback 历史 URL → 主机名（urlfinder 式：每条根域一次 CDX，最多 max_roots 个）。"""
        ctx = self.ctx
        cfg = ctx.settings.get("passive_urls", {}) or {}
        try:
            roots = targets.roots_of(ctx.targets)[:max(0, int(cfg.get("max_roots", 10) or 0))]
        except Exception:       # noqa: BLE001 - 目标形态异常时安静跳过
            return []
        if not roots:
            return []
        from concurrent.futures import ThreadPoolExecutor
        from .. import passive_urls as _pu334

        def _one(root):
            try:
                return root, _pu334.collect(root, ctx.settings, logger=ctx.logger)
            except Exception as _e:      # noqa: BLE001 - 单根域失败不影响其它
                ctx.logger.warning(f"[osint] 被动 URL 源失败（{root}）：{_e}")
                return root, {}

        with ThreadPoolExecutor(max_workers=min(5, len(roots))) as tp:
            results = list(tp.map(_one, roots))
        out, seen = [], set()
        for root, hosts in results:
            for host, _url in (hosts or {}).items():
                if host in seen:
                    continue
                seen.add(host)
                out.append((host, "osint:wayback", f"wayback *.{root}"))
        ctx.logger.info(f"[osint] Wayback 被动 URL：{len(roots)} 个根域 → {len(out)} 个主机")
        return out

    # ---------- IP 反查（精确 IP；C 段仅历史） ----------

    def _ip_reverse(self):
        """按目标/资产的**真实 IP** 做 IP→域名反查；不做 /24 展开、不写 C 段表。

        这是主理人 2026-11-05 明确要保留的「IP 反查」：
        - 输入是目标/子域名/站点解析出的**精确 IP**；
        - 走 `iprecon.lookup_many` 的第三方反查源（webscan / hackertarget / ip138 / ...）；
        - 结果进拓展域名，source=`osint:reverse`，note 带 `ip="x"` 与「待确认」；
        - 不再调用 `group_segments()`，也不写 `csegs` —— C 段只是旧的展示口径，不是反查单位。
        """
        ctx = self.ctx
        cfg = ctx.settings.get("iprecon", {}) or {}
        if cfg.get("enabled") is not True:
            ctx.logger.info("[osint] IP 反查关闭（iprecon.enabled 未开）")
            return []
        if cfg.get("from_targets") is False:
            ctx.logger.info("[osint] 目标 IP 反查关闭（iprecon.from_targets=false）")
            return []
        if (ctx.options or {}).get("offline"):
            ctx.logger.info("[osint] 离线任务跳过 IP 反查")
            return []

        ips = self._collect_ips()
        if not ips:
            ctx.logger.info("[osint] 没有可用于 IP 反查的 IP")
            return []
        public = [ip for ip in ips if iprecon.is_public_ip(ip)]
        cap_ips = int(cfg.get("max_ips", 500))
        if len(public) > cap_ips:
            ctx.logger.info(f"[osint] 公开 IP {len(public)} 个超过上限 {cap_ips}，"
                            f"仅反查前 {cap_ips} 个")
            public = public[:cap_ips]
        ctx.logger.info(f"[osint] IP 反查：公开 IP {len(public)}/{len(ips)} 个"
                        "（私有地址已跳过，不做 /24 展开）…")
        if not public:
            return []

        mapping, stats = iprecon.lookup_many(public, ctx.settings,
                                             logger=ctx.logger, stop=ctx.stopped)
        if ctx.stopped():
            return []

        src_stats = stats.get("sources") or {}
        if src_stats:
            ctx.logger.info("[osint] IP 反查源：" + iprecon.format_source_stats(src_stats))
            try:
                (ctx.workdir / "iprecon_sources.json").write_text(
                    json.dumps(src_stats, ensure_ascii=False, indent=2), encoding="utf-8")
            except OSError as e:
                ctx.logger.warning(f"[osint] IP 反查源成败落档失败（不影响扫描）：{e}")

        cap = max(1, int(cfg.get("max_domains_per_ip", 100)))
        shared_min = config.shared_ip_min({"iprecon": cfg})
        bases = extdom.confirmed_bases(ctx.task_id)
        found, shared_cap, truncated, dropped_shared = [], 0, 0, 0
        shared_ips = set()
        own_ips = set(extdom.confirmed_ip_map(ctx.task_id))
        # 续341：逐域名标出实际返回它的接口，不再让用户只看到笼统的“第三方接口”。
        _prov = stats.get("domain_sources") or {}
        for ip, doms in mapping.items():
            _original = len(doms)
            _is_shared = _original >= shared_min
            _keep = {}
            if bases and (_is_shared or ip in own_ips):
                # 续363：共享 IP / 与 own 同 IP 时，只保留“像目标”的域名；否则
                # GoDaddy 之类一次返回 5~100 个无关客户域名，既污染拓展页，又吃掉回填上限。
                for d in doms:
                    if extdom.redirect_infra_hit(d):
                        _keep[d] = False
                        continue
                    try:
                        _conf = extdom.confidence(d, bases=bases)
                    except Exception:          # noqa: BLE001 - 单个坏名字不拖垮反查
                        _conf = {}
                    _keep[d] = bool(_conf.get("owned") or extdom.conf_rank(
                        _conf.get("level") or "low") >= extdom.conf_rank("medium"))
                # 与 own 共用 IP、但只要有一个低相似名字，就按共享/噪声处理；
                # 避免 2 个域名的共享主机绕过 >=5 的阈值（重跑实际见到过）。
                if ip in own_ips and any(not v for v in _keep.values()):
                    _is_shared = True
            if _is_shared:
                shared_ips.add(ip)
                if bases:
                    _kept = [d for d in doms if _keep.get(d, True)
                             and not extdom.redirect_infra_hit(d)]
                    dropped_shared += _original - len(_kept)
                    doms = _kept
            else:
                # 注册商/邮箱托管/停放根域即使不在共享 IP 上也不入库。
                doms = [d for d in doms if not extdom.redirect_infra_hit(d)]
            _kept_n = len(doms)          # 过滤后、截断前；备注不能拿 _original 冒充截断数
            if len(doms) > cap:
                # 精确 IP 上挂得太多 → 共享主机/CDN。这里不再整段丢弃（整段丢会让
                # 「IP 反查」在共享 IP 上直接变成 0 条），而是截断并显著标注；
                # 自动送探仍受高置信阈值约束，低相似域名不会因为入库就被深扫。
                shared_cap += 1
                truncated += len(doms) - cap
                doms = doms[:cap]
            for d in doms:
                _srcs = [_s for _s in ((_prov.get(ip) or {}).get(d) or []) if _s]
                _note = iprecon.domain_note(ip, _srcs, _original, cap,
                                            shared=_is_shared, kept=_kept_n)
                found.append((d, extdom.EXT_REVERSE_SOURCE, _note))
        self._shared_ips = shared_ips
        uniq = len({d for d, _s, _n in found})
        _msg = f"[osint] IP 反查 → 域名 {uniq} 个 / 命中 IP {stats['hit_ips']} 个"
        if shared_cap:
            _msg += f"；{shared_cap} 个 IP 命中过多（>{cap}）标为共享并截断（少收 {truncated} 个）"
        if shared_ips:
            _msg += (f"；{len(shared_ips)} 个 IP 判为共享/同机噪声（>={shared_min} 或与 own 同 IP），"
                     f"过滤低相似 {dropped_shared} 个")
        ctx.logger.info(_msg)
        return found

    def _collect_ips(self):
        """汇总待反查的 IP：目标 IP 直接用，其余主机名解析。"""
        ctx = self.ctx
        cfg = ctx.settings.get("iprecon", {}) or {}
        ips, hosts = set(), []
        for kind, raw in ctx.targets:
            if kind == "ip":
                ips.add(raw)
                continue
            host = targets.host_of(kind, raw)     # 续146：收敛到 targets（此前这里又写了一份）
            if host:
                hosts.append(host)
        # 续360-B：同 `_root_domains`，只反查 own 口径。扩展域的 IP 往往挂在
        # CDN/第三方公开域，拿它做 IP 反查会递归放大无关域名。
        for r in db.list_own_subdomain_net(ctx.task_id):
            # 已知 IP 直接用：目标域现在解析不了、但任务里已经解析过的资产
            # （例如 www 子域）仍然是有效的 IP 反查入口，别再靠一次失败 DNS 丢掉。
            _known = [x for x in re.split(r"[,;\s]+", str(r["ip"] or "").strip()) if x]
            if _known:
                ips.update(_known)
            else:
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

        for got in pool_run(_resolve, hosts, workers=max(1, int(cfg.get("workers", 5)) * 2),
                          logger=ctx.logger, label="osint IP 反查"):
            for ip in got or []:
                ips.add(ip)
        return sorted(ips)

    def _c_segments(self):
        """LEGACY（续336 生产停用）：只保留给历史数据/回归测试，`run()` 不再调用。"""
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

        # 续173：把"每个源到底成没成"落档。日志只一行（任务日志能直接读），
        # 完整逐源计数/HTTP 码/失败原因写进工作目录，复盘时不用再猜"反查失败"是哪一路。
        src_stats = stats.get("sources") or {}
        if src_stats:
            ctx.logger.info("[osint] IP 反查源：" + iprecon.format_source_stats(src_stats))
            try:
                (ctx.workdir / "iprecon_sources.json").write_text(
                    json.dumps(src_stats, ensure_ascii=False, indent=2), encoding="utf-8")
            except OSError as e:
                ctx.logger.warning(f"[osint] IP 反查源成败落档失败（不影响扫描）：{e}")

        # C 段本身也是资产视野：即使没反查到域名，也把"段 + IP"落库（含命中数量）
        cap = max(1, int(cfg.get("max_domains_per_ip", 30)))
        rows = []
        for seg, seg_ips in segs.items():
            for ip in seg_ips:
                doms = mapping.get(ip, [])
                # 续110：命中数超过阈值 = 共享主机 / CDN 段，**清单不入库**。
                #   旧行为是"资产拓展不纳入它们"（这一步判对了），却照样把 500 个与目标无关的
                #   域名写进 `csegs.domains`，报告「C 段视野」再原样抄一遍 —— 读者会把别人的
                #   workers.dev 当成本项目标的资产面（2026-10-05 targ3.ai 实测：两个 Cloudflare
                #   任播段各存 500 条）。段与 IP 本身是事实，保留；只把"结论 + 为什么不列清单"
                #   写进 note —— 让页面与报告说得出口，**不是假装没反查到**。
                shared = len(doms) > cap
                rows.append({"segment": seg, "ip": ip,
                             "domains": [] if shared else doms[:cap], "count": len(doms),
                             "note": (f"反查命中 {len(doms)} 个域名（>{cap}）：判为共享主机 / CDN 段，"
                                      "与目标无关，清单不入库") if shared else ""})
        db.insert_csegs(ctx.task_id, rows)
        ctx.results["csegs"] = rows

        found = []
        shared = 0
        for ip, doms in mapping.items():
            if len(doms) > cap:
                # 一个 IP 挂了几十个域名 → 共享主机/CDN，继续当资产拓展只会灌噪声
                shared += 1
                continue
            found += [(d, "osint:cseg", "") for d in doms]
        ctx.logger.info(f"[osint] C 段 → 域名 {stats['domains']} 个 / 命中 IP {stats['hit_ips']} 个"
                        + (f"；{shared} 个 IP 命中过多（>{cap}）判为共享主机，不纳入域名资产"
                           if shared else ""))
        return found

    # ---------- FOFA favicon 反查 ----------

    def _fofa_assets(self):
        ctx = self.ctx
        cfg = ctx.settings.get("fofa", {}) or {}
        if not fofa_mod.available(ctx.settings):
            ctx.logger.info(f"[osint] FOFA {keystore.keys_hint('fofa.email / fofa.key')}，跳过 favicon 反查")
            return []

        sites = [dict(r) for r in db.list_sites(ctx.task_id)]
        if not sites:
            ctx.logger.info("[osint] 无存活站点，跳过 favicon 反查")
            return []
        # 续280：`0 / 负数 = 不限`（与 `limits.brute_max_words: 0 = 全量` 同一套口径）。
        # 原写法在填 0 时走 `sites[:0]` ⇒ **整批站点被清空、一个 favicon 都不算**，
        # 而日志里只有一句"无站点"式的静默 —— 看着像"这个平台没开"。
        cap = int(cfg.get("max_sites", 30) or 0)
        if cap > 0 and len(sites) > cap:
            ctx.logger.info(f"[osint] 站点 {len(sites)} 个超过上限 {cap}，仅取前 {cap} 个算 favicon")
            sites = sites[:cap]

        # 续225：probe 已经把 mmh3 落库（`sites.icon_hash`）⇒ 直接复用，别再抓一遍；
        # 只有老任务/未跑 probe 的行才补抓。同一 hash 只查一次（同图标站点共用结果）。
        hashes = {}
        for s in sites:
            h = int(s.get("icon_hash") or 0)
            if h:
                hashes.setdefault(h, s["url"])
        missing = [s for s in sites if not int(s.get("icon_hash") or 0)]
        if missing:
            def _fav(s):
                if ctx.stopped():
                    return None
                return {"url": s["url"], "hash": favicon_hash(s["url"], ctx.settings)}

            for r in pool_run(_fav, missing, workers=max(1, int(cfg.get("workers", 5))),
                            logger=ctx.logger, label="osint favicon 采集"):
                if r and r["hash"]:
                    hashes.setdefault(r["hash"], r["url"])
        ctx.logger.info(f"[osint] favicon 指纹 {len(hashes)}/{len(sites)} 个站点可算（mmh3，"
                        f"其中 {len(sites) - len(missing)} 个直接复用 probe 已落库的值）")
        if not hashes:
            return []

        found = []
        ip_hits = []
        _fofa_ports = []
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
                # 续331（主理人点单）：FOFA 的 host:port 也是端口资产，别再丢。
                try:
                    _pnum = int(a.get("port") or 0)
                except (TypeError, ValueError):
                    _pnum = 0
                _phost = str(a.get("host") or "").strip()
                if _pnum > 0 and _phost:
                    _fofa_ports.append({"host": _phost, "ip": str(a.get("ip") or ""),
                                        "port": _pnum,
                                        "service": str(a.get("protocol") or ""),
                                        "source": "fofa"})
                domain = _domain_of(a)
                if not domain:
                    # 续314（主理人点单）：裸 IP 先记下来再做「探活 → IP 反查」。
                    # 以前这里直接 append 空域名，随后 `if not domain: continue` 静默丢掉，
                    # 于是"ico 反查到 IP"从来没进过反查流程。
                    _ip = str(a.get("ip") or "").strip()
                    if _ip and _ip not in ip_hits:
                        ip_hits.append(_ip)
                    continue
                # 续171（用户点单"FOFA·ICO 反查的结果你要标明语法"）：随行带上**本次查询
                # 的语法**（`icon_hash="123"`），入库进 `subdomains.note`，拓展域名页可查
                found.append((domain, "osint:fofa", fofa_mod.build_query(icon_hash)))
        ctx.logger.info(f"[osint] FOFA 拓展：查询 {queried} 个 favicon，跳过黑 ico {black} 个")
        if ip_hits:
            self._bare_ips.extend(ip_hits)   # 续366：统一到 run() 末尾反查（不再即时探活）
        self._flush_icon_status()
        if _fofa_ports:
            _uniq = {}
            for _p in _fofa_ports:
                _uniq[(_p["host"], _p["port"])] = _p
            self._fofa_web_ports.extend(_uniq.values())   # 续366：web 探活候选
            try:
                db.insert_ports(ctx.task_id, list(_uniq.values()))
                ctx.logger.info(f"[osint] FOFA 端口资产：入库 {len(_uniq)} 条"
                                f"（host:port，source=fofa；端口页签可查）")
            except Exception as _e:      # noqa: BLE001 - 落库失败不该拖垮整阶段
                ctx.logger.warning(f"[osint] FOFA 端口资产入库失败：{_e}")
        return found

    # ---------- VirusTotal 子域名反查（续214） ----------

    def _vt_domains(self):
        """按注册域问 VirusTotal "这个域名下还有哪些子域"。

        与前三家 favicon 反查不同路：那三家回答"还有谁用了同一个图标"（同源推断），
        VT 回答的是**已收录的父子关系**，正好补上被动收集漏掉的那一格。
        三处口径照既有三家：
        ① 没 key ⇒ **零请求**并点名（`keystore.keys_hint`，与 fofa 同一句）；
        ② `max_domains`（默认 20）夹住请求数，`min_interval` 节流在模块内（免费档 4 次/分钟）；
        ③ 撞 429 就**如实停**（不重试 —— 重试只会把"额度用完"变成"扫得很慢"）。
        随行带查询语法 `domain="<注册域>"` ⇒ 入库进 note（续171 那条口径）。
        """
        ctx = self.ctx
        cfg = ctx.settings.get("virustotal", {}) or {}
        if not vt_mod.available(ctx.settings):
            ctx.logger.info(f"[osint] VirusTotal {keystore.keys_hint('virustotal.key')}，"
                            f"跳过子域反查")
            self._note_source("virustotal", "VirusTotal", "skipped", 0,
                              keystore.keys_hint('virustotal.key'))
            return []
        roots = self._root_domains()
        if not roots:
            ctx.logger.info("[osint] 没有可用于反查的注册域，跳过 VirusTotal 子域反查")
            self._note_source("virustotal", "VirusTotal", "skipped", 0, "没有可用注册域")
            return []
        cap = max(1, int(cfg.get("max_domains") or 20))
        if len(roots) > cap:
            ctx.logger.info(f"[osint] 注册域 {len(roots)} 个超过上限 {cap}，仅反查前 {cap} 个")
            roots = roots[:cap]
        found, queried, failed, last_err = [], 0, 0, ""
        for root in roots:
            if ctx.stopped():
                break
            subs, total, err = vt_mod.search(root, ctx.settings, logger=ctx.logger)
            if err:
                failed += 1
                last_err = str(err)
                ctx.logger.info(f"[osint] VirusTotal 子域反查中止：{err}")
                break
            queried += 1
            for s in subs:
                domain = str(s.get("domain") or "").strip().lower()
                if domain:
                    found.append((domain, "osint:vt", vt_mod.query_of(root)))
        ctx.logger.info(f"[osint] VirusTotal 拓展：查询 {queried} 个注册域 → {len(found)} 个子域")
        _st362 = ("partial" if failed and found else "failed" if failed
                  else "ok" if found else "empty")
        self._note_source("virustotal", "VirusTotal", _st362, len(found),
                          last_err or (f"查询 {queried} 个注册域" if queried else "未查询"))
        return found

    # ---------- FOFA 证书反查 ----------

    def _root_domains(self):
        """汇总待做证书反查的**注册域**（去重、按出现顺序）：

        目标是域名/URL 时取它的注册域；站点与子域名同样折算到注册域。
        证书是按域名签的，同一个注册域下的 `a.example.com` / `b.example.com` 证书内容常重叠，
        折到注册域能把查询次数压下来（省配额）。IP 目标直接跳过 —— 证书反查要的是域名。
        续146：判据收敛到 `targets.hosts_of` / `root_of`。**原来这里的两道手写守门都不用了**：
        `ipaddress.ip_address(h)` 挡裸 IP、`"." in root` 挡单标签 —— `root_of` 的 `is_domain`
        守门一次覆盖两件事（IP 与单标签都不是合法域名 ⇒ 返回空串）。
        """
        ctx = self.ctx
        hosts = list(targets.hosts_of(ctx.targets))
        for r in db.list_sites(ctx.task_id):
            hosts.append(r["host"] or "")
        # 续360-B：只从 own 口径取子域。`js:mine` / `osint:*` 是别人的资产面，
        # 拿它们继续做证书/VT/CT 反查会把第三方域的子域灌进任务。
        for r in db.list_own_subdomains(ctx.task_id):
            hosts.append(r["domain"])
        roots = [targets.root_of(h) for h in hosts]
        return list(dict.fromkeys(r for r in roots if r))

    def _cert_has_valid(self, root):
        """续321：本任务证书表里，该注册域有没有**未过期**的一条（读一次缓存）。

        fail-open：读库失败一律放行 —— 反查闸挂了不该把整条证书反查挡死。
        """
        try:
            rows = getattr(self, "_cert_rows321", None)
            if rows is None:
                rows = [dict(r) for r in db.list_certs(self.ctx.task_id)]
                self._cert_rows321 = rows
        except Exception:      # noqa: BLE001
            return True
        root = str(root or "").lower().strip(".")
        for r in rows:
            h = str(r.get("host") or "").lower().strip(".")
            if (h == root or h.endswith("." + root)) and not int(r.get("expired") or 0):
                return True
        return False

    def _fofa_cert(self):
        ctx = self.ctx
        cfg = ctx.settings.get("fofa", {}) or {}
        if not fofa_mod.available(ctx.settings):
            ctx.logger.info(f"[osint] FOFA {keystore.keys_hint('fofa.email / fofa.key')}，跳过证书反查")
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
        queried = common = pre = stale = 0
        for root in roots:
            if ctx.stopped():
                break
            # 零请求预筛：占位证书（example.com / localhost …）实测命中百万级，连查询都不发
            if fofa_mod.is_generic_cert(root):
                pre += 1
                ctx.logger.info(f'[osint] 证书 cert="{root}" 属已知占位证书（如 example.com），'
                                f"跳过查询")
                continue
            # 续321（主理人 2026-11-03）：整个注册域没有一条未过期证书 ⇒ 跳过。
            # 过期证书是历史证据，但它说明目标大概率已停/换证，cert= 反查白花请求。
            if cfg.get("cert_require_valid", True) is not False and not self._cert_has_valid(root):
                stale += 1
                ctx.logger.info(f'[osint] 证书 cert="{root}" 跳过：本任务库里该注册域'
                                f"没有未过期的证书（要照查设 fofa.cert_require_valid: false）")
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
                # 续171：随行带上证书反查语法（`cert="root"`），入库进 note
                found.append((domain, "osint:fofa-cert", fofa_mod.build_cert_query(root)))
        ctx.logger.info(f"[osint] 证书拓展：查询 {queried} 个注册域，跳过通用证书 {common} 个"
                        + (f"、无有效证书 {stale} 个" if stale else "")
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
            ctx.logger.info(f"[osint] FOFA {keystore.keys_hint('fofa.email / fofa.key')}，跳过标题反查")
            return []
        titles = self._site_titles()
        if not titles:
            ctx.logger.info("[osint] 没有可用于标题反查的站点标题")
            return []
        cap = max(1, int(cfg.get("max_title_queries") or 10))
        if len(titles) > cap:
            ctx.logger.info(f"[osint] 站点标题 {len(titles)} 个超过上限 {cap}，仅反查前 {cap} 个")
            titles = titles[:cap]

        title_match = str(cfg.get("title_match") or "label").lower()
        found = []
        queried = common = skipped = 0
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
                # 相关性过滤（默认 `label`：标题 token 与域名 label 完全相等）：挡掉"标题里
                # 恰好含同一子串"的无关域名。**不碰 `_domain_of()`** —— 它是 favicon / 证书 /
                # 标题 / C 段共用的收口，改它会波及全部 osint 来源。
                if domain and not _title_relevant(title, domain, title_match):
                    skipped += 1
                    continue
                # 续171：随行带上标题反查语法（`title="xxx"`），入库进 note
                found.append((domain, "osint:fofa-title", fofa_mod.build_title_query(title)))
        ctx.logger.info(f"[osint] 标题拓展：查询 {queried} 个标题，跳过公共标题 {common} 个"
                        + (f"，相关性过滤掉 {skipped} 条" if skipped else ""))
        return found

    def _fofa_web_portscan(self):
        """续366：FOFA 端口资产里落在 web 端口上的 host:port → 轻量探活 → 入 sites。

        为什么挂在 osint 而不是新增 STAGE_ORDER 阶段：`probe` 排在 osint **之前**，
        FOFA 端口资产是 osint 才入库的，永远不会回流成站点；而新增阶段会牵动 13 阶段
        清单、建任务页、devflow、报告的全套判据。这里直接写库并**追加到
        `ctx.results["sites"]`**，jsmine / dirscan / vulnscan / crawl 立刻能吃到。

        安全边界（§1）：只对「本任务注册域内」的域名或公网裸 IP 发请求，黑名单与
        第三方清单同样拦；`auth=False`（FOFA 回来的名字未必在授权范围内，不带登录态）、
        `allow_redirects=False`（不跟到外部域）。
        """
        ctx = self.ctx
        fcfg = ctx.settings.get("fofa", {}) or {}
        if fcfg.get("web_portscan") is False:
            return 0
        if (ctx.options or {}).get("offline"):
            ctx.logger.info("[osint] 离线任务跳过 FOFA web 端口探活")
            return 0
        try:
            from .. import portscan as _ps366
            web_ports = set(_ps366.parse_ports(
                (ctx.settings.get("portscan", {}) or {}).get("ports")))
        except Exception as _e366:      # noqa: BLE001 - 端口表坏了不该拖垮整阶段
            ctx.logger.warning(f"[osint] web 端口表解析失败，跳过探活：{_e366}")
            return 0
        if not web_ports:
            return 0
        cap = int(fcfg.get("web_max", 20) or 0)
        try:
            bases = extdom.task_bases(ctx.task_id)
            bl = blacklist.load(ctx.settings, owner_id=getattr(ctx, "owner_id", 0))
        except Exception as _e366b:     # noqa: BLE001 - 读不到闸就宁可不探
            ctx.logger.warning(f"[osint] 授权范围/黑名单读取失败，跳过 web 探活：{_e366b}")
            return 0
        cands, seen = [], set()
        for p in self._fofa_web_ports:
            try:
                port = int(p.get("port") or 0)
            except (TypeError, ValueError):
                continue
            if port not in web_ports:
                continue
            host = str(p.get("host") or "").strip()
            url = fofa_mod.web_url(host, port)
            hn = fofa_mod.host_part(host)
            if not url or not hn or url in seen:
                continue
            if is_domain(hn):
                if not extdom.is_owned(hn, bases):
                    continue
            elif not iprecon.is_public_ip(hn):
                continue
            if blacklist.matches(hn, bl) or jsmine.is_thirdparty(hn):
                continue
            seen.add(url)
            cands.append((url, hn, str(port)))
            if cap > 0 and len(cands) >= cap:
                break
        if not cands:
            ctx.logger.info(f"[osint] FOFA web 端口探活：{len(self._fofa_web_ports)} 条端口资产"
                            "里没有落在 web 端口 / 授权范围内的候选")
            return 0

        def _one366(cand):
            if ctx.stopped():
                return None
            url, hn, port = cand
            r = http_request(url, timeout=3, settings=ctx.settings, verify=False,
                             auth=False, allow_redirects=False)
            if not r:
                return None
            hdrs = r.get("headers") or {}
            return {"url": url, "host": hn, "port": port,
                    "status": int(r.get("status") or 0), "title": "",
                    "length": len(str(r.get("text") or "")),
                    "server": str(hdrs.get("Server") or hdrs.get("server") or ""),
                    "tech": "", "source": "osint:fofa-web"}

        rows = [x for x in pool_run(_one366, cands,
                                    workers=max(1, int(fcfg.get("workers", 5) or 5)),
                                    logger=ctx.logger, label="osint FOFA web 端口探活")
                if x]
        if not rows:
            ctx.logger.info(f"[osint] FOFA web 端口探活 {len(cands)} 个候选，无 HTTP 响应")
            return 0
        new_sites = db.drop_existing(ctx.task_id, "sites", ("url",), rows,
                                     lambda s: (s["url"],))
        if new_sites:
            db.insert_sites(ctx.task_id, new_sites)
        _cur = [s for s in (ctx.results.get("sites") or []) if isinstance(s, dict)]
        _known = {s.get("url") for s in _cur}
        ctx.results["sites"] = _cur + [s for s in rows if s["url"] not in _known]
        ctx.logger.info(f"[osint] FOFA web 端口探活：候选 {len(cands)} 个，有 HTTP 响应 {len(rows)} 个，"
                        f"新站点入库 {len(new_sites)} 条（source=osint:fofa-web；"
                        "已并入 ctx.results['sites'] 供后续阶段使用）")
        return len(new_sites)

    # ---------- FOFA host="<品牌词>" 反查（续365）----------

    def _fofa_host(self):
        """续365（主理人 2026-11-10 点单）：`host=` 反查 + 子域名解析 IP 求交。

        与 `icon_hash=` / `cert=` / `title=` 三路不同，这一路**只认 IP 命中**：
        1. 每个注册域取去掉公共后缀后的首个 label（`acme-portal.cn` → `acme-portal`），
           用 `host="<label>"` 去 FOFA 搜同名资产；
        2. 把 FOFA 资产行的 `ip` 与**本任务子域名的解析 IP 集合**求交。这个集合刻意
           不复用 `extdom.confirmed_ip_map()`：后者只收「非 CDN 的 own 行」，而主理人
           明确「哪怕是 cdn 哪怕是多 ip 其中一个 ip」都要算命中 —— 所以这里
           **不排除 cdn 列、不要求单 IP**，多 A 记录拆开后任意一个相等即命中；
        3. 命中的新域名以 `osint:fofa-host` 入库并回填命中 IP，
           `extdom.apply_fofa_host_evidence()` 据此判「高」，页面徽章与自动送探同口径。

        命中 IP 落在 CDN 段时只作**展示提示**（共享边缘地址，佐证偏弱），不影响是否命中。
        没有已解析的子域名 IP 时零查询 —— 没有比对集合，查了也没法判归属。
        """
        ctx = self.ctx
        cfg = ctx.settings.get("fofa", {}) or {}
        if cfg.get("host_enabled") is False:
            return []
        if not fofa_mod.available(ctx.settings):
            ctx.logger.info(f"[osint] FOFA {keystore.keys_hint('fofa.email / fofa.key')}，"
                            "跳过 host 反查")
            return []

        own_ips, known = set(), set()
        for r in db.list_subdomains(ctx.task_id):
            known.add(str(r["domain"] or "").strip().lower())
            for ip in extdom.ip_components(r["ip"]):
                # 私网/回环地址不可能出现在 FOFA 索引里，也不该拿去跟公网资产比对。
                if iprecon.is_public_ip(ip):
                    own_ips.add(ip)
        if not own_ips:
            ctx.logger.info("[osint] FOFA host 反查跳过：本任务还没有可比对的子域名解析 IP")
            return []

        tokens, seen = [], set()
        for root in self._root_domains():
            token = fofa_mod.host_token(root)
            if token and token not in seen:
                seen.add(token)
                tokens.append(token)
        cap = max(1, int(cfg.get("max_host_queries", 10) or 10))
        if len(tokens) > cap:
            ctx.logger.info(f"[osint] FOFA host 品牌词 {len(tokens)} 个超过上限 {cap}，"
                            f"仅查前 {cap} 个")
            tokens = tokens[:cap]
        if not tokens:
            ctx.logger.info("[osint] 没有可用于 host 反查的品牌词（注册域首段过短或纯数字）")
            return []

        found, hit_ips = [], {}
        queried = hits = no_domain = 0
        for token in tokens:
            if ctx.stopped():
                break
            assets, total, err = fofa_mod.search_host(token, ctx.settings,
                                                      logger=ctx.logger)
            if err:
                ctx.logger.info(f"[osint] FOFA host 反查中止：{err}")
                break
            queried += 1
            ctx.logger.info(f'[osint] FOFA host="{token}" → {len(assets)} 条 / 共 {total} 条'
                            f"（比对 {len(own_ips)} 个子域名 IP）")
            for a in assets:
                same = sorted(set(extdom.ip_components(a.get("ip"))) & own_ips)
                if not same:
                    continue
                hits += 1
                domain = _domain_of(a)
                if not domain:
                    no_domain += 1
                    self._bare_ips.append(str(a.get("ip") or "").strip())
                    continue
                if domain in known or domain in hit_ips:
                    continue
                ip_text = ",".join(same)
                hit_ips[domain] = ip_text
                vendor = cdn_mod.ip_match(same, ctx.settings)
                note = (f"{fofa_mod.build_host_query(token)} · 同 IP 命中 {ip_text}"
                        " · FOFA 归属佐证"
                        + (f"（CDN 共享 IP {vendor}，佐证偏弱）" if vendor else ""))
                found.append((domain, extdom.EXT_FOFA_HOST_SOURCE, note))
        self._fofa_host_ips = hit_ips
        ctx.logger.info(f"[osint] FOFA host 拓展：查询 {queried} 个品牌词，IP 命中 {hits} 条，"
                        f"入库 {len(found)} 个新域名"
                        + (f"（另有 {no_domain} 条只有裸 IP、无域名可入库）" if no_domain else ""))
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
        if cap > 0 and len(sites) > cap:      # 续280：cap<=0 = 不限（填 0 原来是"全部丢掉"）
            ctx.logger.info(f"[osint] 站点 {len(sites)} 个超过上限 {cap}，仅取前 {cap} 个算 favicon")
            sites = sites[:cap]

        # 续225：同样优先复用 probe 已落库的 mmh3；只有缺值的行才补抓。
        hashes = {}
        for s in sites:
            h = int(s.get("icon_hash") or 0)
            if h:
                hashes.setdefault(h, s["url"])
        missing = [s for s in sites if not int(s.get("icon_hash") or 0)]
        if missing:
            def _fav(s):
                if ctx.stopped():
                    return None
                return {"url": s["url"], "hash": favicon_hash(s["url"], ctx.settings)}

            for r in pool_run(_fav, missing, workers=max(1, workers),
                            logger=ctx.logger, label="osint 三方 favicon 采集"):
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
                # 续171：Shodan / Quake 的语法（`http.favicon.hash:N` / `favicon:"N"`）同样随行入库
                found.append((_domain_of(a), f"osint:{name}", mod.build_query(icon_hash)))
        ctx.logger.info(f"[osint] {name} 拓展：查询 {queried} 个 favicon，跳过黑 ico {black} 个")
        self._flush_icon_status()
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
            self._note_source("ctlog", "CT 日志", "skipped", 0, "没有可用注册域")
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
                    found.append((d, "osint:ctlog", ""))
        if certs:
            # 跨运行去重（续25）：同一 (host, port, sha256, serial) 的证书记录不再重复入库
            db.insert_certs(ctx.task_id, db.drop_existing(
                ctx.task_id, "certs", ("host", "port", "sha256", "serial"), certs,
                lambda r: (r.get("host"), r.get("port"), r.get("sha256"), r.get("serial"))))
        ctx.logger.info(f"[osint] CT 日志：查询 {queried} 个注册域，失败 {failed} 个，"
                        f"证书记录 {len(certs)} 条"
                        + ("（已写入「SSL 证书」页签，来源 ct）" if certs else ""))
        _st362 = ("partial" if failed and found else "failed" if failed
                  else "ok" if found else "empty")
        self._note_source("ctlog", "CT 日志", _st362, len(found),
                          f"失败 {failed} 个" if failed else "")
        return found



def _title_tokens(title):
    """把标题切成小写 token（按非字母数字切），去掉停用词与纯数字。"""
    return [t for t in _TITLE_TOKEN_RE.findall(str(title or "").lower())
            if not t.isdigit() and t not in _TITLE_STOPWORDS]


def _title_relevant(title, domain, mode="label"):
    """标题是否与候选域名相关（过滤 FOFA 标题反查带进来的**无关域名**）。

    用户真实数据：标题含 "targ1" 时，FOFA 既带回 `targ1.money` / `targ1.me`（**同品牌不同
    TLD，可能真相关**），也带回 `silviatarg1.com` / `targ1wireline.com` / `kufungatarg1.com`
    / `noise1.net` / `noise2.cn`（只是**恰好含同一子串**，与目标无关）。

    - `mode="label"`（默认）：至少一个标题 token 与域名的某个 label **完全相等**；
    - `mode="substring"`：放宽为"至少一个 token 是域名的**子串**"（回退 / 对照用）；
    - 其它值一律按 `"label"` 处理（未知值不能变成"全放行"）。
    - **fail-open**：标题切不出任何 token（纯中文 / 纯符号标题）时**保留** —— 无法判定相关性
      时宁可不丢（丢资产比留噪音更糟，与 jsmine 的 PSL fail-open 同一取向）。
    """
    host = str(domain or "").lower().strip(".")
    if not host:
        return False
    tokens = _title_tokens(title)
    if not tokens:
        return True
    if mode == "substring":
        return any(tok in host for tok in tokens)
    labels = set(host.split("."))
    return any(tok in labels for tok in tokens)


def _domain_of(asset):
    """从 FOFA 资产行里取**域名**；取不到、或是裸 IP 就返回空串。

    续281：判据与解析全部收口到 `scanner/fofa.py::domain_of()` —— subdomain 阶段
    此前自己用 `host.split(":", 1)[0]`，把 `https://a.test` 切成了 `"https"` 写进库
    （多个任务里的 `domain='https'` 就是这条）。这里只保留原函数名给本模块调用点用。
    """
    return fofa_mod.domain_of(asset)


def _recon_level(d, ctx):
    """续319：IP 反查域名的置信度分级（**零额外请求**，只用本任务已有数据）。

    主理人 2026-11-03 定的口径：
    - 同注册域（d 属于本任务注册域）→ 正常子域名，标「同注册域」；
    - 跨注册域 + 名字相似（`extdom.similarity` 高档）→ 中等；
    - 跨注册域 + 本任务抓到过该主机的证书 → 中等；
    - 跨注册域 + 证书 + 该主机 favicon 也在库 → 高；
    - 其余 → 待确认（现状，不能凭空提权）。

    返回 `(标签, 依据)`；标签直接是 note 里的最终文案。**不加任何网络请求** ——
    证书/favicon 两档只在"这台主机本来就在本任务数据里"时才可能命中；要主动抓
    候选域名的证书/图标（深验证）另立开关，别混进这里。
    """
    try:
        bases = extdom.task_bases(ctx.task_id)
    except Exception:      # noqa: BLE001 - 任务目标读不出来就按空归属集处理
        bases = set()
    if extdom.is_owned(d, bases):
        return "同注册域", ""
    sim = extdom.similarity(d, bases)
    if str(sim.get("level")) == "high":
        return "中等", f"名字相似：{sim.get('reason')}"
    try:
        cert_hosts = {str(r["host"] or "").lower() for r in db.list_certs(ctx.task_id)}
        fav_hosts = {str(r["host"] or "").lower() for r in db.list_sites(ctx.task_id)
                     if (r["favicon"] or "")}
    except Exception:      # noqa: BLE001 - 证书/站点查询失败就按无对照处理
        cert_hosts, fav_hosts = set(), set()
    in_cert = d in cert_hosts
    in_fav = d in fav_hosts
    if in_cert and in_fav:
        return "高", "同证书 + favicon 命中（本任务已抓数据）"
    if in_cert:
        return "中等", "同证书（本任务已抓数据）"
    return "待确认", ""


def _tally(items):
    counts = {}
    for _, src in items:
        counts[src] = counts.get(src, 0) + 1
    return sorted(counts.items())