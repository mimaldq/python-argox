# 多阶段构建Dockerfile - 优化版
FROM python:3.11-slim AS builder

WORKDIR /app
COPY requirements.txt .
RUN python -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

FROM python:3.11-slim

# 一次性安装所有运行时依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    wget \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r appuser && useradd -r -g appuser appuser

ENV PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"

WORKDIR /app

# 复制所有必需文件
COPY --from=builder /opt/venv /opt/venv
COPY --chown=appuser:appuser app.py requirements.txt ./

RUN chown -R appuser:appuser /app
USER appuser

EXPOSE 7860

# 使用exec格式启动
CMD ["python", "app.py"]
