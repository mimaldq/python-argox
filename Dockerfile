# ==================== 阶段1: 构建阶段 ====================
FROM python:3.9-slim AS builder

# 安装构建依赖
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    make \
    && rm -rf /var/lib/apt/lists/*

# 创建工作目录
WORKDIR /app

# 复制依赖文件
COPY requirements.txt .

# 安装Python依赖到用户目录
RUN pip install --no-cache-dir --user -r requirements.txt

# ==================== 阶段2: 运行时阶段 ====================
FROM python:3.9-slim

# 设置环境变量
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    TZ=UTC \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

# 安装运行时依赖（包括bash, wget, curl等）
RUN apt-get update && apt-get install -y \
    bash \
    wget \
    curl \
    iproute2 \
    net-tools \
    iputils-ping \
    dnsutils \
    ca-certificates \
    tzdata \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# 创建非root用户
RUN groupadd -r appuser && useradd -r -g appuser -s /bin/bash -m appuser

# 创建工作目录
WORKDIR /app

# 从构建阶段复制Python依赖
COPY --from=builder /root/.local /home/appuser/.local

# 复制应用文件
COPY app.py .
COPY index.html .
COPY requirements.txt .

# 复制配置文件和脚本
COPY *.py ./
COPY *.html ./

# 创建必要的目录
RUN mkdir -p /app/data/tmp

# 设置文件权限
RUN chown -R appuser:appuser /app && \
    chmod 755 /app

# 设置Python路径
ENV PATH=/home/appuser/.local/bin:$PATH
ENV PYTHONPATH=/app

# 切换到非root用户
USER appuser

# 暴露端口
EXPOSE 7860

# 默认命令 - 直接运行app.py
CMD ["python", "app.py"]
