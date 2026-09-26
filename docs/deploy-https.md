# 部署到服务器：用反向代理给控制台加上 HTTPS（续47）

> 适用场景：把控制台放到服务器上给队友用（多用户账号密码登录已在续46 落地）。
> **明文 HTTP 下口令会以明文过线** —— 局域网被镜像、或者走公网，口令就直接暴露。
> 本文给出**最小、可照抄**的落地路径。

## 0. 为什么是"反向代理终止 TLS"，而不是 Flask 内建 `ssl_context`

一句话：**应用侧不碰证书**。证书签发、续期、HTTP→HTTPS 跳转、HSTS、TLS 版本与套件，
都交给成熟组件（Caddy / Nginx / 云负载均衡）去做；而 Flask 自带的是**开发服务器**
（单进程、无生产级并发与超时治理），把它直接挂到公网端口上收 TLS 是错的用法。
所以本框架只做三件小事：**信任反代转发的头、放行部署域名、给 Cookie 加 `Secure`**。

控制台**仍然只绑 `127.0.0.1:5000`**（`gui.host` / `gui.port` 不用改），反代与本机应用同机通信。

## 1. 三步落地

**① 改 `config/settings.yaml` 的 `gui` 段**（改完**重启控制台**才生效）：

```yaml
gui:
  host: 127.0.0.1            # 保持回环：外网入口只有反代
  port: 5000
  token: ctfscanner          # 引导口令（建了第一个账号后自动失效，见续46）
  allowed_hosts: ["scanner.example.com"]   # ← 放行你的部署域名（必填，否则整站 403）
  behind_proxy: true                       # ← 信任反代转发的 X-Forwarded-*
  secure_cookie: true                      # ← 会话 Cookie 加 Secure（TLS 就绪后打开）
```

**② 起反向代理**（下面 §2 Caddy / §3 Nginx 任选一份，或 §4 自签证书用于内网）。

**③ 按 §5 的清单逐条验证**（`curl` 就能验完，不需要打开浏览器）。

## 2. Caddy 样例（推荐：自动签发与续期 Let's Encrypt）

`/etc/caddy/Caddyfile`：

```
scanner.example.com {
    reverse_proxy 127.0.0.1:5000 {
        header_up Host {host}
        header_up X-Forwarded-Proto {scheme}
        header_up X-Forwarded-For {remote_host}
    }
}
```

```bash
sudo caddy validate --config /etc/caddy/Caddyfile   # 先校验语法
sudo systemctl reload caddy                          # 或 caddy run 前台看日志
```

要点：

- 域名解析必须指向这台服务器，且 80/443 可达 —— Caddy 会**自动**申请证书并续期；
- Caddy 默认就会设置 `X-Forwarded-Proto` / `X-Forwarded-For`，上面写出来是为了**显式**可见
  （换个组件时不会漏）；
- 只监听 443/80 即可，**不要**再额外把 5000 暴露出去。

## 3. Nginx 样例

`/etc/nginx/conf.d/ctfscanner.conf`：

```nginx
server {
    listen 443 ssl http2;
    server_name scanner.example.com;

    ssl_certificate     /etc/letsencrypt/live/scanner.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/scanner.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:5000;
        # 四个头都要转：Host 决定 Host 白名单与 Origin 比对；X-Forwarded-Proto 决定 scheme
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 300s;      # 报告导出 / PDF 生成可能较慢，别用默认 60s
    }
}

server {                              # 80 端口只做跳转
    listen 80;
    server_name scanner.example.com;
    return 301 https://$host$request_uri;
}
```

证书可用 `certbot --nginx -d scanner.example.com` 申请（自动改写配置并续期）。

**为什么 `Host` 要按 `$host` 转发**：`_local_guard` 的跨站校验比的是
"`Origin` 的权威段 == 请求的 `Host`"。浏览器发来的 `Origin` 是 `https://scanner.example.com`，
只要 `Host` 也是 `scanner.example.com`，比对天然成立；如果反代用 `Host: 127.0.0.1:5000` 回源
（把真实域名放到 `X-Forwarded-Host`），就必须靠 `behind_proxy: true` 让应用把头"还原"回来，
否则**每个写操作都会被 403 挡掉**（看起来像"页面按钮都没反应"）。

## 4. 内网 / 无域名：自签证书

```bash
# 生成一张 10 年有效的自签证书（CN 填你实际访问用的地址/域名）
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
  -keyout scanner.key -out scanner.crt \
  -subj "/CN=scanner.lan" \
  -addext "subjectAltName=DNS:scanner.lan,IP:192.168.1.10"
```

Nginx 里把 `ssl_certificate` / `ssl_certificate_key` 指到这两个文件，`server_name scanner.lan;`。
**浏览器会报"证书不受信任"**，需要：

- 个人自用：在浏览器里点"高级 → 继续访问"（每次换浏览器/清缓存都要再点一次）；
- 团队共用：把 `scanner.crt` 导入各客户端的**受信任根证书**（Windows：`certmgr.msc` → 受信任的根证书颁发机构 → 导入）。

`gui.allowed_hosts` 要填实际访问用的那个名字（`scanner.lan`），**不要**填 IP 和域名两个都猜 ——
填了哪个就只放行哪个。

## 5. 验证清单（可照抄）

```bash
DOMAIN=scanner.example.com

# ① 能通、且被跳去登录页（未登录访问 / 应 302 到 /login）
curl -sSI "https://$DOMAIN/" | head -5

# ② 登录响应里的会话 Cookie 必须带 Secure（说明 secure_cookie 生效）
curl -sSi -X POST "https://$DOMAIN/login" \
  -d "username=<你的账号>&password=<你的口令>" | grep -i '^set-cookie'

# ③ 换一个**不在白名单**的 Host 必须 403（DNS rebinding 防护仍在）
curl -sS -o /dev/null -w '%{http_code}\n' -H 'Host: evil.example' "http://127.0.0.1:5000/login"

# ④ 反代有没有把真实域名传进来（behind_proxy 生效时，页面里的自跳转会带上域名）
curl -sS "https://$DOMAIN/login" | grep -i '<title>'
```

期望：① 302 到 `/login`；② 出现 `Set-Cookie: session=...; Secure; HttpOnly; SameSite=Lax`；
③ 输出 `403`；④ 正常返回登录页（不是 403）。

**排错对照**：

| 现象 | 原因 | 处理 |
|---|---|---|
| 整站 403，页面提示"Host 不在允许列表内" | 部署域名没进白名单 | 把域名填进 `gui.allowed_hosts` 并重启 |
| 能打开，但**每个按钮/表单都没反应**（POST 403） | `Origin` 与 `Host` 不一致：反代回源时改了 Host，而 `behind_proxy` 没开 | 开 `behind_proxy: true`，或让反代按 `$host` 转发 |
| 登录后立刻"又回到登录页" | 开了 `secure_cookie` 但访问的是 HTTP | 要么走 HTTPS，要么把 `secure_cookie` 关掉 |
| 启动日志警告"已确认在 TLS 反代后却没开 secure_cookie" | TLS 就绪但 Cookie 没加 Secure | 打开 `gui.secure_cookie` |

## 6. 三项配置对照表

| 配置项 | 默认 | 什么时候开 | 开了有什么风险 |
|---|---|---|---|
| `gui.allowed_hosts` | `[]`（只认回环名） | 反代部署、浏览器用域名访问时（**必填**） | 只接受明确枚举；写 `*` / `?` 会被**忽略**并在启动时告警 —— 刻意不提供"放行一切"的口子 |
| `gui.behind_proxy` | `false` | 应用**只被自己的反代**访问，且反代把真实域名/协议放在 `X-Forwarded-*` 里时 | 打开后 `Host`、`scheme` **以及审计/限速用的客户端 IP（`X-Forwarded-For`）都以请求头为准** —— 任何能直接访问 5000 端口的人都能伪造。所以必须同时保证 5000 端口不对外 |
| `gui.secure_cookie` | `false` | 已经在 HTTPS（反代终止 TLS）下访问时 | 走 HTTP 时打开会导致浏览器不回传 Cookie → **登录不上**；它不是安全风险，是可用性风险 |

> 三项都不建议"顺手打开"。默认值（空 / 关 / 关）对应"本机单人使用"，与续32 的行为**逐字节一致**。

## 7. 访问审计与登录限速（续48）

放到服务器给队友用之后，两件"只有多用户 + 公网访问才需要"的事也补上了，**默认就开**：

### 7.1 访问审计流水（`gui.audit`）

- 记录**谁 / 何时 / 从哪个 IP / 对什么对象 / 做了什么 / 成败**：登录成功与失败、被限速拦截、退出、
  账号操作（建号 / 重置口令 / 停用 / 改角色 / 删除）、保存策略配置、POC 管理、任务操作（建 / 停 / 删 /
  重启 / 续跑 / 追加 / 批量）、越权访问被拒。管理员在侧边栏「访问审计」页按类型 / 操作者 / IP / 成败 /
  关键字过滤查看。
- **只记元数据，绝不记口令或凭据**：保存策略配置时只记"改了哪几个区块"，连 `gui.token` 这种**键名**
  都不落库；写入前还会再兜底擦洗一遍 `password=…` / `token=…` / `Bearer …` / `pbkdf2_sha256$…` 形状。
- `retention_days`（默认 30）：超过该天数的记录在**启动时**自动清理（只清 `audit_log` 一张表，不动
  任务与资产）；也可以在「访问审计」页点按钮手动清。

### 7.2 登录限速 / 失败锁定（`gui.login_lockout`）

- **两级判据**：按 **IP 为主**（默认 5 分钟内 10 次失败）、按 **用户名兜底**（默认 5 分钟内 20 次，更宽松）；
  触发后**锁 15 分钟**。被锁时返回 **429 + `Retry-After`**（不是 403），且**即使口令正确也拒绝**。
- **不泄漏账号是否存在**：被锁页面与"账号存在 / 不存在"无关，返回**逐字节相同**的内容（否则"被锁=存在"
  本身就是一条用户名枚举通道）。
- **引导口令（`gui.token`）登录同样受 IP 限速** —— 无账号的迁移期也不例外。
- 阈值刻意宽松（本机 / 小队共用：一次记错口令不该把队友挡在门外）；要更严/更松改 `config/settings.yaml`
  的 `gui.login_lockout`（`window_seconds` / `max_fails_per_ip` / `max_fails_per_user` / `lockout_seconds`）。

**自救（被锁在门外时，按代价从低到高）**：

```bash
# ① 等：最多 lockout_seconds（默认 900s）后自动解锁。
# ② 命令行查看当前锁定 / 清除（只清限速计数，不动审计与业务数据）：
py -3 -m scanner.login_guard --status
py -3 -m scanner.login_guard --clear --ip 1.2.3.4
py -3 -m scanner.login_guard --clear --user alice
py -3 -m scanner.login_guard --clear            # 全清
# ③ 兜底：把 config/settings.yaml 的 gui.login_lockout.enabled 改成 false 并重启（限速整体关闭）。
```

### 7.3 `behind_proxy` 与"客户端 IP"的注意点（续48 新增）

限速的 **IP 判据**与审计里的 **IP 列**都取 `request.remote_addr`。开了 `gui.behind_proxy` 后，
`ProxyFix` 会把它改写成 `X-Forwarded-For` 的**最后一跳** —— 这是**请求头，客户端能伪造**。
因此：**只有"应用只被自己的反向代理访问"（5000 端口不对外）时**，这个 IP 才可信；否则任何人都能
塞一个 `X-Forwarded-For` 把限速按 IP 的判据整个绕开。这正是 §6 表格里 `behind_proxy` 那行"必须同时
保证 5000 端口不对外"的原因。

## 8. 明确"仍然没做"（别把本文当安全承诺）

- **没有验证码 / 账号锁定通知**：限速只是"慢下来 + 临时锁"（续48），挡不住低速慢猜；口令强度仍靠
  创建账号时的长度下限；
- **没有逐表单 CSRF token**：仍然依赖续32 的 `Origin`/`Referer` 中间件（覆盖全部写方法）；
  这是**刻意**的取舍（几十处表单逐处改造，漏一处就是"看起来有防护、实际有缺口"）；
- **没有 SSO / 找回口令**：管理员重置是唯一路径（账号页也写了"口令全丢"时的自救命令）；
- **没有多租户隔离**：所有账号看到的是**同一批任务与资产**，隔离的只是"配置页"（续46）；
- **没有 HSTS / TLS 版本与套件策略**：这些交给你的反代，本框架不设置。

授权边界不变：只对**自己拥有或已获书面授权**的目标使用，见 [security-notice.md](security-notice.md)。
