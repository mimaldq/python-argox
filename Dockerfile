# 多阶段构建Dockerfile - 适配app.py并包含index.html
# 第一阶段：构建阶段
FROM python:3.11-slim AS builder

# 设置环境变量
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# 安装系统依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    git \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

# 复制依赖文件和必要的静态文件
COPY requirements.txt .
# 如果存在index.html，也复制它
COPY index.html . 2>/dev/null || echo "index.html not found, will create at runtime if needed"

# 创建虚拟环境并安装依赖
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# 第二阶段：运行阶段
FROM python:3.11-slim AS runtime

# 设置环境变量
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    PATH="/opt/venv/bin:$PATH" \
    TZ=Asia/Shanghai

# 创建非root用户
RUN groupadd -r appuser && useradd -r -g appuser appuser

WORKDIR /app

# 复制虚拟环境和应用代码
COPY --from=builder /opt/venv /opt/venv
# 复制所有应用文件，包括index.html
COPY --chown=appuser:appuser . .

# 设置权限
RUN chown -R appuser:appuser /app && \
    chmod +x /app/*.sh 2>/dev/null || true

# 检查index.html是否存在，如果不存在则创建默认的
RUN if [ ! -f /app/index.html ]; then \
    echo "Creating default index.html"; \

# 切换到非root用户
USER appuser

# 暴露端口
EXPOSE 7860

# 启动命令
CMD ["python", "app.py"]
