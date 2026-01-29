# 第一阶段：构建依赖
FROM python:3.9-slim AS builder

WORKDIR /app

# 安装系统依赖
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

# 安装运行时依赖（不包含构建工具）
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
COPY requirements.txt .

# 创建必要的目录
RUN mkdir -p /app/tmp

# 设置环境变量
ENV FILE_PATH=/app/tmp
ENV PYTHONUNBUFFERED=1

# 创建非root用户运行应用
RUN useradd -m -u 1000 appuser && \
    chown -R appuser:appuser /app
USER appuser

# 暴露端口
EXPOSE 7860

# 运行应用
CMD ["python", "app.py"]

