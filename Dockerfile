# CTFScanner —— 面向 CTF / 授权渗透测试的资产测绘与漏洞初筛框架
#
# 用法、要不要重新打包、数据在哪、共享服务器上的权限隔离 —— 全部见 docs/docker.md。
# 一句话：`docker compose up -d --build`，然后浏览器开 http://127.0.0.1:5000
#
# 镜像只装 requirements.txt 里那三个运行期依赖（flask / requests / PyYAML）——
# 这是本项目的**零多余依赖**口径：截图用系统浏览器、证书解析用标准库、
# 验证码自己画 PNG，都不引入新包。需要的外部工具（subfinder/httpx/puredns）
# 在容器里用「外部工具」页或 `--update-tools` 现装，见 docs/docker.md。

FROM python:3.9-slim

# 运行期依赖。先只 COPY requirements.txt 再装 —— 改代码不会让这一层缓存失效，
# 重建镜像时不必重新下载依赖。
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt \
 && rm -f /tmp/requirements.txt

WORKDIR /app
COPY . /app

# 数据落点。**只建目录，不写任何内容** —— 凭据（config/keys.yaml）靠运行时挂载进来，
# 绝不烤进镜像（.dockerignore 已把它们挡在构建上下文之外）。
RUN mkdir -p /app/data /app/logs

# 容器内必须绑 0.0.0.0 才能被端口映射访问到（本机直跑时默认是 127.0.0.1）。
# 这两个环境变量由 scanner.config.gui_bind() 读取，见 docs/docker.md 的说明。
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    CTFSCANNER_GUI_HOST=0.0.0.0 \
    CTFSCANNER_GUI_PORT=5000 \
    CTFSCANNER_DB=/app/data/scanner.db \
    CTFSCANNER_LOGS=/app/logs

EXPOSE 5000

# 健康检查：登录页能取到 200 即算活着。**不需要账号、不产生任何业务写入** ——
# 只探一个静态可达性，不碰数据库。
HEALTHCHECK --interval=30s --timeout=5s --start-period=25s --retries=3 \
  CMD python -c "import urllib.request,sys; \
sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:5000/login', timeout=4).status == 200 else 1)"

# 控制台入口（与 `py -3 run_gui.py` 同一个 serve()，会一并起持久化任务队列的 worker）。
CMD ["python", "run_gui.py"]
