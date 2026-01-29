# 第一阶段：构建阶段
FROM python:3.9-slim AS builder

WORKDIR /app

# 安装构建依赖
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# 复制依赖文件
COPY requirements.txt .

# 安装Python依赖到虚拟环境
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --no-cache-dir -r requirements.txt

# 第二阶段：运行环境
FROM python:3.9-slim

WORKDIR /app

# 从构建阶段复制虚拟环境
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# 安装运行时依赖
RUN apt-get update && apt-get install -y \
    curl \
    bash \
    wget \
    procps \
    net-tools \
    iputils-ping \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 复制应用文件
COPY app.py .
COPY index.html .

# 创建必要的目录
RUN mkdir -p /app/tmp

# 设置环境变量默认值
ENV UPLOAD_URL=""
ENV PROJECT_URL=""
ENV AUTO_ACCESS="false"
ENV FILE_PATH="/app/tmp"
ENV SUB_PATH="sub"
ENV SERVER_PORT="3000"
ENV PORT="3000"
ENV UUID="e2cae6af-5cdd-fa48-4137-ad3e617fbab0"
ENV NEZHA_SERVER=""
ENV NEZHA_PORT=""
ENV NEZHA_KEY=""
ENV ARGO_DOMAIN=""
ENV ARGO_AUTH=""
ENV ARGO_PORT="7860"
ENV CFIP="cdns.doon.eu.org"
ENV CFPORT="443"
ENV NAME=""
ENV MONITOR_KEY=""
ENV MONITOR_SERVER=""
ENV MONITOR_URL=""
ENV PYTHONUNBUFFERED=1

# 创建非root用户运行应用
RUN useradd -m -u 1000 appuser && \
    chown -R appuser:appuser /app
USER appuser

# 暴露端口
EXPOSE 7860 3000

# 健康检查
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:3000/ || exit 1

# 运行应用
CMD ["python", "app.py"]
