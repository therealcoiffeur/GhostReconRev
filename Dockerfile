FROM python:3.12.8-slim-bookworm AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:$PATH"

WORKDIR /build

RUN python -m venv "$VIRTUAL_ENV"

COPY requirements.txt .

RUN pip install --upgrade pip setuptools wheel \
    && pip install -r requirements.txt


FROM python:3.12.8-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:/app/tools/bin:$PATH" \
    HOME=/tmp \
    DATABASE_URL=sqlite:////app/data/recon_ui.db

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bind9-host \
        ca-certificates \
        nmap \
        tini \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid app --create-home --home-dir /app --shell /usr/sbin/nologin app

COPY --from=builder /opt/venv /opt/venv
COPY recon_ui /app/recon_ui
COPY docker/entrypoint.sh /app/docker/entrypoint.sh
COPY docker/healthcheck.py /app/docker/healthcheck.py
COPY .env.example /app/.env.example
COPY README.md /app/README.md
COPY requirements.txt /app/requirements.txt
COPY tools/bin /app/tools/bin

RUN mkdir -p /app/data /app/artifacts/collectors /app/artifacts/reports /app/tools/bin /tmp \
    && chmod 755 /app/docker/entrypoint.sh /app/docker/healthcheck.py \
    && chown -R app:app /app /opt/venv /tmp

USER app:app

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "/app/docker/healthcheck.py"]

ENTRYPOINT ["/usr/bin/tini", "--", "/app/docker/entrypoint.sh"]
CMD ["uvicorn", "recon_ui.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
