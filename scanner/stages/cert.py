"""阶段：TLS 证书取证（可选，**默认关闭**）。

位置：`probe` 之后、`screenshot` 之前 —— 必须先有存活站点才知道去连谁。
产物：`certs` 表（一个 `host:port` 一行）+ `logs/task_<id>_<ts>/certs.txt`；
GUI 任务详情「SSL 证书」页签展示（颁发者 / 有效期 / 剩余天数 / CN / SAN / 指纹）。

开关：`cert.enabled`（默认关，策略配置 → 资产面拓展）+ `cert.max_sites`
+ `cert.timeout` + `cert.tls_ports`；建任务时勾选「SSL 证书」= 任务级 `cert_on`，
只对本次生效，不改全局策略（与 `screenshot_on` 同一套门控思路）。

**哪些站点会被握手**（不是无脑全试，见 `_picked()`）：
- URL 是 `https://` 的；或
- 端口命中 `cert.tls_ports`（默认 443/8443/9443）的 —— 覆盖"HTTPS 服务被 probe 记成
  http://host:8443"这种情况。

**不做什么**（避免被当成"证书合法"的判据）：这里**不校验证书**（`verify_mode=CERT_NONE`）。
CTF / 授权测试里最常见的就是自签名、过期、域名不匹配的证书，恰恰是校验会失败的场景；
本阶段是**取证**（把颁发者与有效期读出来给人看），不是建立可信连接。
也不做证书链、不做 CRL/OCSP 校验、不做爆破式的多协议/多密码套件试探 —— 一次握手、只读。
"""
from .base import Stage
from .. import certs, db
from ..utils import write_lines


def pick_targets(sites, tls_ports):
    """挑出值得做 TLS 握手的站点，返回 `[(url, host, port), ...]`（按 host:port 去重）。

    去重是必要的：同一台主机的 80 与 443 往往被 probe 记成两条站点行，
    或者多个 URL 指向同一 `host:port`（路径不同），重复握手既慢又会在库里刷出重复行。

    放在模块级而不是 Stage 方法里：GUI 的「SSL 证书」页签要用**同一套判定**告诉用户
    "本次为什么没有证书"（没有 https/加密端口站点 vs 阶段没开），两处各写一遍必然漂移。
    """
    picked, seen = [], set()
    for s in sites:
        url = (s.get("url") or "").strip()
        host = (s.get("host") or "").strip()
        if not host:
            continue
        try:
            port = int(s.get("port") or 0)
        except (TypeError, ValueError):
            port = 0
        if not port:
            continue
        if not url.lower().startswith("https://") and port not in tls_ports:
            continue
        key = (host, port)
        if key in seen:
            continue
        seen.add(key)
        picked.append((url, host, port))
    return picked


class CertStage(Stage):
    name = "cert"
    description = "TLS 证书取证（握手取证书 → 颁发者/有效期/SAN，产物进 certs 表）"

    def run(self):
        ctx = self.ctx
        cfg = ctx.settings.get("cert", {}) or {}
        # 门控：策略级 `cert.enabled`（默认关）**或** 任务级显式点名（建任务勾选 / CLI -p cert）。
        # 理由同 screenshot 阶段：只认策略开关的话，用户勾了阶段却什么都不发生，
        # 页面上只留一句"未启用"，看起来像功能没做完。
        if cfg.get("enabled") is not True and ctx.options.get("cert_on") is not True:
            ctx.logger.info("[cert] 未启用（策略配置 → 资产面拓展 可打开；"
                            "建任务时勾选「SSL 证书」也可只对本次生效），跳过")
            return
        if ctx.stopped():
            ctx.logger.warning("[cert] 任务已请求停止，跳过")
            return

        sites = ctx.results.get("sites") or [dict(r) for r in db.list_sites(ctx.task_id)]
        tls_ports = certs.tls_ports(ctx.settings)
        picked = pick_targets(sites, tls_ports)
        cap = int(cfg.get("max_sites", 30) or 30)
        if len(picked) > cap:
            ctx.logger.info(f"[cert] 待取证 {len(picked)} 个 host:port 超过上限 {cap}，"
                            f"只取前 {cap} 个")
            picked = picked[:cap]
        if not picked:
            ctx.logger.info(f"[cert] 无适合取证的站点（需 https 或端口 ∈ "
                            f"{sorted(tls_ports)}），跳过")
            return

        timeout = int(cfg.get("timeout", 8) or 8)
        rows, ok = [], 0
        ctx.logger.info(f"[cert] 开始证书取证 {len(picked)} 个 host:port …")
        for url, host, port in picked:
            if ctx.stopped():
                ctx.logger.warning("[cert] 任务已请求停止，结果不再入账")
                break
            info, err = certs.fetch(host, port, timeout=timeout)
            if not info:
                ctx.logger.info(f"[cert] {host}:{port} 取证失败：{err}")
                continue
            ok += 1
            info.update({"url": url, "host": host, "port": port, "source": "tls"})
            rows.append(info)
            ctx.logger.info(f"[cert] {host}:{port} → CN={info.get('cn') or '-'} "
                            f"issuer={info.get('issuer') or '-'} "
                            f"有效至 {info.get('not_after') or '-'}"
                            f"{'（已过期）' if info.get('expired') else ''}")
        if rows:
            db.insert_certs(ctx.task_id, rows)
        # 产物文件：一行一条完整记录，字段用 tab 分隔（失败的行不写，与截图阶段一致）。
        # 表头写在首行，便于直接拿 Excel / awk 打开核对。
        write_lines(ctx.workdir / "certs.txt",
                    ["host:port\tcn\tsubject\tissuer\tnot_before\tnot_after\tdays_left\t"
                     "expired\tself_signed\tsig_algo\tserial\tsha256\tsan"] +
                    [f"{r['host']}:{r['port']}\t{r.get('cn') or ''}\t{r.get('subject') or ''}\t"
                     f"{r.get('issuer') or ''}\t{r.get('not_before') or ''}\t"
                     f"{r.get('not_after') or ''}\t{r.get('days_left')}\t"
                     f"{int(r.get('expired') or 0)}\t{int(r.get('self_signed') or 0)}\t"
                     f"{r.get('sig_algo') or ''}\t{r.get('serial') or ''}\t"
                     f"{r.get('sha256') or ''}\t{','.join(r.get('san') or [])}"
                     for r in rows])
        ctx.logger.info(f"[cert] 完成 {ok}/{len(picked)} 个")