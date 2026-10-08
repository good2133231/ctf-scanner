# `docker_todo/` —— 打包这条路还没完善

实施者：WorkBuddy · Qoder-Agent（远端 Linux，2026-10-08）。

这个目录**本身就是结论**：Docker 那套东西是"能用但没做完"的，所以刻意不和项目主体混在一起，
也不假装它是交付路径。仓库根仍然留了一个 7 行的 `docker-compose.yml` **薄包装**，
只为让 `docker compose up -d --build` 这类既有用法和文档继续有效 —— 真正的定义在这里：

| 文件 | 是什么 |
|---|---|
| `docker-compose.yml` | 默认形态（交付/上服务器）：端口只发布到宿主机回环，`config`/`data`/`logs` 挂宿主机，外部工具用命名卷持久化 |
| `docker-compose.dev.yml` | 开发形态：把源码目录挂进容器，改完 `restart` 即可，不用重建镜像 |
| `Dockerfile` | `python:3.9-slim` + 只装 `requirements.txt` 的 4 个运行期依赖，零多余 |

用法（**两条都用 `-f`，且两个文件要一起给**，见下方陷阱）：

```bash
# 交付形态
docker compose -f docker_todo/docker-compose.yml up -d --build

# 开发形态（挂源码）
docker compose -f docker_todo/docker-compose.yml -f docker_todo/docker-compose.dev.yml up -d
```

⚠ **一个真实陷阱，别用根包装去拼 dev 覆盖**：
`docker compose -f docker-compose.yml -f docker_todo/docker-compose.dev.yml`
会把挂载源解析成**仓库的上一级目录**（实测 `source: /opt/tools/ctf`）—— 因为相对路径是按
"第一个 compose 文件所在目录"算项目根的，而 dev 文件里的 `..:/app` 是按 `docker_todo/` 写的。
上面那两条写法我都用 `docker compose config` 实测过解析结果，混合那种没有。

## 还没完善的地方（按重要性）

1. **镜像版本与本机不一致**：`Dockerfile` 是 `python:3.9-slim`，CI 也是 3.9，而这台开发机跑的是
   3.14。仓库里有一条"跨 Python 版本红线"（正则内联全局标志只能写在串首，`[8d] ⑩` 钉着），
   所以 3.9 与 3.14 都要求能跑；但**没有**在 3.9 容器里真跑过一遍完整 smoke。
2. **容器里没有浏览器** → 截图与 PDF 导出在容器内从来不通（`Dockerfile` 头写了"零多余依赖"口径）。
   要在容器里出图，得自己装 Chromium 并绕开 snap 的 confinement 问题（见 AGENTS.md §7）。
3. **`nmap` / `fscan` / `dirmap` 不进镜像**：官方没有"可下载且带官方 SHA256 的单文件产物"，
   按红线只能人工装（`scanner/toolmgr.py::MANUAL`）。容器里要用得自己 `apt-get install -y nmap` 后重建。
4. **401 边缘认证门与容器的关系**（续131~134 新增，这条最容易咬人）：门是 fail-closed 的，
   而凭据文件 `config/edge_auth.yaml` 在 `.gitignore` 里 —— 新克隆起来的容器**没有**它，
   于是 `/login` 一律 401。健康检查已改成"200 或 401 都算活"（旧写法只认 200，会让容器被判
   unhealthy + `restart: unless-stopped` 反复重启）。要让队友真的能用，二选一：
   在宿主机 `config/edge_auth.yaml` 里写好口令（`config/` 是挂载进容器的，改完 `restart` 生效），
   或把 `gui.edge_auth.enabled` 设回 `false`。
5. **`.dockerignore` 故意留在仓库根**，没跟着挪进来：Docker 找忽略规则的顺序是
   `<dockerfile>.dockerignore` → **构建上下文根**的 `.dockerignore`。上下文根是仓库根，
   把它挪进本目录就等于没有忽略规则 —— 镜像会把 `.venv/`、`data/scanner.db`、`logs/`
   （本机攒过 21 MB+ 的测试沙箱）、以及 `config/keys.yaml`（凭据）全烤进镜像层。
6. **CI 完全不碰 Docker**（两个 workflow 里零引用），所以这里的改动没有任何自动门禁 ——
   上面那些命令是我用 `docker compose config` 手工验的，只证明"解析与路径正确"，
   没证明"镜像能构建成功、容器里 smoke 能过"。

## 想把它做成成品，缺的是这些

- 在 CI 里加一个 job：构建镜像 → 在容器内跑 `tests/smoke.py` → 断言 `/login` 的**期望状态码**
  （200 或 401，取决于有没有挂凭据文件），并把"3.9-slim 镜像 + 本机 3.14"两个版本都覆盖一遍；
- 决定镜像里的 Python 版本口径（跟 CI 走 3.9，还是抬到与开发机一致的 3.14）；
- 想清楚交付形态到底要不要带浏览器 / nmap（带着就违背"零多余依赖"，不带着就功能残缺 ——
  现在是后者，且文档写明了）。
