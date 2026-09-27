FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /srv
COPY app ./app
COPY tests ./tests
COPY verify ./verify
COPY verify.sh ./

# 构建检查：全部源码必须能通过字节码编译
RUN python3 -m compileall -q app tests verify \
    && chmod +x verify.sh \
    && useradd --system --no-create-home auditor \
    && mkdir -p /data && chown auditor:auditor /data

USER auditor
ENV PORT=8080 \
    AUDIT_STORE_DIR=/data
EXPOSE 8080

CMD ["python3", "-m", "app.server"]
