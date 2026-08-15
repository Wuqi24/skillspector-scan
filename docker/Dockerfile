# skillspector-scan 容器镜像（离线静态安全审查）
# 构建：docker build -t skillspector-scan -f docker/Dockerfile .
FROM mcr.microsoft.com/powershell:latest

RUN apt-get update && apt-get install -y --no-install-recommends python3 git \
    && rm -rf /var/lib/apt/lists/*

ENV CODEX_HOME=/codex
WORKDIR /app
COPY . /app/

ENTRYPOINT ["pwsh", "-NoProfile", "-File", "/app/scripts/scan.ps1"]
