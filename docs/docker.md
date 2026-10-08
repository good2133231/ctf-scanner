# 用 Docker 跑 CTFScanner

面向"**自己用 / 内网小队用 / 交付给队友**"的容器化部署。设计口径与仓库其它部分一致：
默认值全部**偏保守**，要放开必须自己显式改；每一步都说明"为什么"，不留"照抄就行但不知所以"的坑。

> 法律边界不变：仅用于**自有或已书面授权**的目标。容器化不改变这一点。

---

## 1. 快速开始

```bash
# 仓库是**公开的**，所以拉代码**不需要任何认证**（第 9 节有从 Linux 推回去的办法）
git clone https://github.com/good2133231/ctf-scanner.git ctf-scanner && cd ctf-scanner

docker compose -f docker_todo/docker-compose.yml up -d --build   # 首次会构建镜像（装 4 个 Python 依赖 + 拷贝代码）
docker compose -f docker_todo/docker-compose.yml logs -f   # 启动日志：登录方式、监听地址、各门的现状
```

然后打开日志里那行 **`[*] 控制台地址：http://127.0.0.1:5000/<10 位>/<10 位>/`** —— 后台路径
**每次启动随机生成**（续138），直接开 `http://127.0.0.1:5000` 是 **404 空响应**，那是刻意的。
`restart` / `up -d --build` 之后要**重新 `logs` 一次取新地址**；嫌麻烦就在 compose 里固定：

```yaml
    environment:
      CTFSCANNER_WEB_PATH: /console    # 空串 = 挂回根路径；不写就是每次启动随机
```

容器里通常没有可读的终端，所以首启动向导**不会代填口令**（它只打印该跑的那条命令，不静默跳过）。
在容器里跑一次即可建出第一个管理员：

```bash
# 服务名是 ctfscanner（写 scanner 会直接 "no such service" —— 本文件此前就是错的，续135 改掉）
docker compose -f docker_todo/docker-compose.yml exec ctfscanner python run_users.py --create-admin
# 完全无 TTY 时也可以：CTFSCANNER_ADMIN_PASSWORD='…' python run_users.py --create-admin
```

口令只进 `users` 表的 PBKDF2 派生值，**不写进任何配置文件**（续117 起 `settings.yaml` 里没有登录凭据）。

## 1b. 401 边缘认证门与容器（续135 补，这条最容易咬人）

`gui.edge_auth.enabled: true` 时，控制台在任何路由之前先要一个 Basic 口令（用户名固定 `edge`）。
凭据文件 `config/edge_auth.yaml` 在 `.gitignore` 里 —— **新克隆的容器里没有它**，于是 `/login`
一律 401。两处已按这个事实改过：

- 健康检查认 `200 或 401`（旧写法只认 200 → 容器被判 unhealthy，配上 `restart: unless-stopped`
  就是"一直重启、看起来永远起不来"）；
- `config/` 是挂载进容器的，所以宿主机写好口令、`restart` 一下就生效，**不必重新构建镜像**。

要么用前者（`printf 'password: …\n' > config/edge_auth.yaml && chmod 600 config/edge_auth.yaml`），
要么把 `gui.edge_auth.enabled` 设回 `false`。容器里通常没有可读终端，所以启动向导**不会代填**，
只会打印该跑的那条命令 —— 与上面首启动向导同一口径。

> 端口只发布到**宿主机回环**（`127.0.0.1:5000`）：容器里虽然绑 `0.0.0.0`，
> 但局域网/公网**访问不到**。要让别人用，先读第 6 节。

---

## 2. 改了代码，要不要重新打包？

**看你怎么跑。两种形态，行为不一样：**

| 场景 | 命令 | 改了代码要做什么 |
|---|---|---|
| **交付 / 上服务器**（默认） | `docker compose up -d --build` | 要 **`--build` 重新构建**（代码是 `COPY` 进镜像的） |
| **开发 / 调参**（挂源码） | `docker compose -f docker_todo/docker-compose.yml -f docker_todo/docker-compose.dev.yml up -d` | 只要 **`... restart`**，不用重建 |

挂源码那种形态用的是 `docker_todo/docker-compose.dev.yml`：它把仓库根挂到 `/app`，盖在镜像里那份之上。
⚠ 两个 `-f` 必须**都在 `docker_todo/` 下**：相对路径按第一个 compose 文件的目录算项目根，
拿仓库根那个薄包装去拼 dev 覆盖会把挂载源解析成 `/opt/…` 的上一级目录（实测，续135）。
所以宿主机改完 `restart` 一下就是新代码（Python 是启动时读源码，不需要重装依赖）。

**只改配置（`config/settings.yaml` / `config/keys.yaml`）两种形态都不用重建** ——
配置是**挂载**进去的（`./config:/app/config`）。改完在控制台里点一下，或 `docker compose restart`。

**只改字典（`config/dicts/*.txt`）同理**，不用重建。

---

## 3. 数据在哪 / 怎么备份

全部落在**宿主机**上，容器删了也还在：

| 宿主机路径 | 内容 |
|---|---|
| `./config/` | 策略配置 + `keys.yaml`（第三方 API key）+ 黑名单 |
| `./data/scanner.db` | 主数据库（任务 / 资产 / 漏洞 / 审计） |
| `./logs/` | 每任务的工作目录、报告、截图、任务日志 |
| 命名卷 `ctf-tools` | 一键装的外部工具（subfinder/httpx/puredns） |

备份就是**停一下、拷这三样**：

```bash
docker compose stop
tar czf ctfscanner-backup-$(date +%F).tgz config data logs
docker compose start
```

> 数据库是 SQLite，**不要**在容器跑着的时候直接拷 `data/scanner.db`（可能拷到写了一半的页）。
> 停容器再拷，或者用 `sqlite3 data/scanner.db ".backup /tmp/x.db"`。

---

## 4. 外部工具（subfinder / httpx / puredns）

容器是 Linux，所以**三个都能装** —— 包括本机 Windows 上装不了的 `puredns`
（官方只发 Linux/macOS 产物，见 README）。两种方式：

- 控制台：管理员 → 侧栏「外部工具」→ 勾选 → 「开始下载 / 更新」（默认必须过官方 SHA256）；
- 命令行：`docker compose exec ctfscanner python cli/client.py --update-tools`

装到命名卷 `ctf-tools` 里，**重建镜像不用重装**。多版本共存（`.versions/`）也在那个卷里。

**nmap / fscan / dirmap 三个仍需手工装**（官方没有"可校验的单二进制产物"）：
容器里用 `apt-get install -y nmap` 之后重建镜像，或自己写个基于本镜像的派生 Dockerfile。

> **要在容器里用截图 / PDF，必须同时装浏览器和中文字体**（续103）：
> `apt-get install -y chromium fonts-noto-cjk` 之后重建镜像。只装浏览器、不装字体是**最坏的一种** ——
> 截图照样"成功"、字节数也正常，但图里每个汉字都是豆腐块，而且没有任何失败信号。
> 镜像本身刻意不装这些（"零多余依赖"口径见 `Dockerfile` 头），所以容器里截图与 PDF 导出**从来就不通**；
> 宿主机直跑时用 `python3 run_bootstrap.py --install --with-system`，`fonts-noto-cjk` 已在系统包层清单里。
`dirmap` 是 Python 项目（要 gevent/lxml），装进容器还得补依赖，**不装也不影响**
—— 深扫会自动回退到内置字典扫描。

---

## 5. 想让它扫得更快 / 更省

`config/settings.yaml` 里几个常调的：

- `queue.workers`：并发任务数（默认 **1 = 串行**，最省目标侧带宽）；
- `limits.max_workers` / `portscan.workers`：单任务的并发；
- `portscan.enabled`：端口扫描默认**关**（CTF 里噪声大），要用再开。

改完 `docker compose restart`。这些都不需要重建镜像。

---

## 6. 给队友用（**先读这段再动端口**）

默认只发布到回环 = 只有这台机器能访问。要让队友用，**按顺序**做这三件事，
少做任何一步都会出问题：

**① 先配 Host 白名单。** 控制台有一道 Host 白名单（挡 DNS rebinding）。绑定非回环地址后，
浏览器发来的 Host 是你实际访问用的那个域名/IP —— **不配 `gui.allowed_hosts` 会整站 403**
（这是刻意设计：不允许"放行一切"）。在 `config/settings.yaml` 里：

```yaml
gui:
  host: 0.0.0.0
  allowed_hosts: ["192.168.1.50", "scan.example.com"]   # 明确枚举，支持通配的值会被忽略
```

**② 再改端口映射。** `docker-compose.yml` 里把

```yaml
ports:
  - "127.0.0.1:5000:5000"     # 改成
  - "5000:5000"               # 或更稳的："192.168.1.50:5000:5000"（只绑内网那块网卡）
```

**③ 走 HTTPS 反代。** 容器只跑 HTTP。对外一定要在前面放 Nginx/Caddy 终止 TLS，
并把 `gui.behind_proxy: true` + `gui.secure_cookie: true` 打开 —— 详细步骤与坑
见 [docs/deploy-https.md](deploy-https.md)（那份文档与容器无关，直接用）。

> **别**把 `5000:5000` 直接暴露到公网。这个控制台能让使用者对任意目标发起扫描，
> 并且能用到你配在 `keys.yaml` 里的第三方 API key。

---

## 7. 共享服务器上，"别人会不会把我的源码拿走"？

**会 —— 而且 Docker 不但不解决这个问题，还多开了一个口子。** 这点必须说清楚：

- 镜像是 `COPY . /app` 打出来的，**源码就在镜像层里**。同一台机器上任何能执行
  `docker` 的人，一句 `docker run --rm -it ctf-scanner:latest sh` 就能把 `/app` 整个读走，
  比直接读你的工作目录还方便（连权限位都不用绕）。
- 而 **`docker` 组的成员 ≈ root**（能挂载宿主机根目录）。所以"把源码目录 `chmod 700`、
  但把用户加进 docker 组"这种组合**等于没设防**。

按"防护强度"从高到低：

**① 最稳：镜像只留在你自己机器上，只把端口给出去。**
代码根本不上共享服务器 —— 用 SSH 隧道把端口转发过去即可：

```bash
# 在共享服务器上执行（不需要你有 docker 权限，也不需要源码）：
ssh -N -L 127.0.0.1:5000:127.0.0.1:5000 你的机器
# 队友在服务器上访问 http://127.0.0.1:5000 就落到你机器上的控制台
```

**② 次稳：容器跑在共享服务器上，但用独立的 OS 用户 + 独立 docker 上下文。**
给这个服务单独建个系统用户，只有它能碰这个 compose 项目；**不要**把其他人加进 `docker` 组；
`./config`（里面有 `keys.yaml`）设成 `chmod 700` 且属主是那个用户。
注意：这挡得住"顺手看一眼"，挡不住有 sudo/root 的人。

**③ 只是"不想让人随手翻到"：多阶段构建 + 只留 `.pyc`。**
删掉 `.py` 只留 `__pycache__` 能让"随手翻"变麻烦，但 `.pyc` **可以被反编译** ——
它是**混淆，不是保护**。真在乎就别把代码放上去（回到 ①）。

**④ 明确没用的**：登录口令 / HTTPS / `allowed_hosts` ——
这些是**谁能用这个服务**，与**谁能看到源码**是两件事。别把它们当源码保护。

> 结论：如果诉求是"别人别拿走我的代码"，**唯一的可靠做法是代码不落在共享服务器上**（方案 ①）。
> 容器化解决的是"跑得一致、依赖不打架、交付方便"，不是源码保密。

---

## 8. 常见问题

**Q：`docker compose up` 起来后浏览器打不开？**
先看 `docker compose logs` 有没有 `[!] 启动失败：端口被占用`；再确认你访问的是
`http://127.0.0.1:5000<本次前缀>`（默认只发布到回环，从别的机器访问不通是**预期行为**）。打开裸 `http://127.0.0.1:5000` 得到 **404 空响应也是预期** —— 入口路径每次启动随机，去 `docker compose logs` 里那行「控制台地址」取（见第 1 节）。

**Q：能打开，但每个操作都 403，提示 "Host 不在允许列表内"？**
你把端口放开到局域网了，但没配 `gui.allowed_hosts`。见第 6 节 ①。

**Q：日志时间比本地时间差 8 小时？**
`TZ` 没生效。compose 里已经写了 `TZ: "Asia/Shanghai"`，自定义 compose 时别漏。

**Q：容器里 `tools/dirmap/` 是空的？**
对。`tools/dirmap/` 和 `tools/fscan/` 在本机是**指向仓库外的目录联接**，
`.dockerignore` 刻意不把它们打进镜像。需要就用派生镜像自己装，不装会自动回退。

**Q：能不能用非 root 跑？**
可以，`docker-compose.yml` 里 `user: "1000:1000"` 那行取消注释即可 ——
但要**先确认**该用户对 `./config ./data ./logs` 有读写权限，否则会出现
"控制台能开、存不了配置"这类难查的问题。

**Q：镜像多大？**
基于 `python:3.9-slim`，加三个纯 Python 依赖，量级在 150 MB 左右（不含后装的外部工具）。
## 9. 在 Linux 上获取代码 / 推送（认证办法）

仓库是**公开的**（不带凭据访问 GitHub API 就是 200），所以「部署」和「推代码」是两件事：

### 只部署（拉代码）—— **完全不需要认证**

```bash
git clone https://github.com/good2133231/ctf-scanner.git ctf-scanner && cd ctf-scanner
docker compose up -d --build
```

### 要从这台 Linux 推代码回去 —— 三条路，按推荐顺序

**① SSH 密钥（推荐）**：一次配好，之后 `git push` 不再问，也不在任何文件里留明文口令。

```bash
ssh-keygen -t ed25519 -C "ctfscanner-deploy"    # 一路回车
cat ~/.ssh/id_ed25519.pub                        # 复制这一整行
```

- 要**能推**：GitHub → Settings → SSH and GPG keys → New SSH key → 粘贴
- 只**要拉**（服务器 / 共享机器上更安全）：仓库 → Settings → Deploy keys → Add deploy key ——
  勾 **Allow write access** 才允许推；不勾就是只读

```bash
git remote set-url origin git@github.com:good2133231/ctf-scanner.git
ssh -T git@github.com      # 出现 Hi good2133231! 即成功
```

**② 个人访问令牌 PAT**：`Settings → Developer settings → Personal access tokens → Tokens (classic)`，
勾 `repo`；生成后**只显示一次**。别把它拼进 remote URL（那样会明文写进 `.git/config`），用凭据助手：

```bash
git config --global credential.helper store      # 存到 ~/.git-credentials；务必 chmod 600
# 或者只在内存里留一会儿：git config --global credential.helper 'cache --timeout=3600'
git push                                          # 用户名填 good2133231，口令填那个 PAT
```

**③ CI / 自动化**：用仓库 Secrets 里的 `GITHUB_TOKEN`（或自己的 PAT）当环境变量，
走 `https://x-access-token:${TOKEN}@github.com/...` 的一次性认证头 —— 与 Windows 本机那套同理。


**④ 令牌交给本项目的口令加密（2026-10-03 本机实际采用的一条）**：不单独再存一份明文令牌，
而是并进扫描器自己的加密存储，推送时由 helper 现场解密：

```bash
umask 077 && printf 'github:\n  token: "<PAT>"\n' > config/keys.yaml    # 明文只活一两分钟
.venv/bin/python run_keys.py --encrypt --shred      # 口令不落盘；自校验通过后才删明文
git config --local credential.helper <仓库外目录>/git-cred-helper.py    # .git/config 只出现路径
git push origin main                                # 有终端时会提示一次口令
```

helper 的三条边界，少一条就会出事：只响应 `get`（`store` / `erase` 沉默退出，否则 git 会把凭据
回写成磁盘文件）；只对 `github.com` 出凭据；口令**只**来自 `CTFSCANNER_KEYS_PASSPHRASE`
（进程环境 ≠ 磁盘）或 `/dev/tty`。

> ⚠️ 这里的"有没有终端"**不能用 `sys.stdin.isatty()` 判**：git 把 helper 的 stdin 换成了管道，
> 恒为假，于是 `keystore._prompt` 直接走「非交互」分支、永远不问口令。而裸 `getpass` 在无 tty 时
> 会**退回读 stdin** —— 吃掉的正是不该动的 git 查询串，表现是**推送挂住不动**。正确判据是
> **试开 `/dev/tty`**，打不开就干净失败、绝不回落到 stdin。两条实测口径：无口令时 helper
> `RC=1` 且 stdout **0 字节**（有密文也绝不回落明文）；`push --dry-run` 认证通过而远端**不产生**分支。

换 PAT 不用动 git 配置：重写 `config/keys.yaml` 再跑一次 `--encrypt --shred`（同一口令）。

> 无论哪条：**不要把令牌写进 `.git/config`、更别提交进仓库**。
> Windows 本机靠的是「凭据管理器缓存 + 一次性请求头」；Linux 上没有那个存储，
> 所以换成 SSH 密钥或 PAT —— 思路完全一致：**凭据只放助手/环境变量里，绝不落进仓库文件**。
> 完整口径（含 bash 里 `git credential fill` 会被 SIGTERM 这类坑）见 `AGENTS.md` §2。
