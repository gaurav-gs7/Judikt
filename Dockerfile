FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    XDG_STATE_HOME=/app/data/state \
    JUDIKT_AUDIT_DB=/app/data/judikt.db

WORKDIR /app

COPY pyproject.toml README.md ./
COPY scripts ./scripts
COPY src ./src

RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir '.[mcp,observability,auth,redis,aws]' \
    && groupadd --gid 10001 judikt \
    && useradd --uid 10001 --gid judikt --no-create-home --shell /usr/sbin/nologin judikt \
    && mkdir -p /app/data \
    && chown judikt:judikt /app/data

EXPOSE 8080

USER 10001:10001

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).read()"]

CMD ["./scripts/docker_entrypoint.sh"]
