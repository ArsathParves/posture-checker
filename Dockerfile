# Cross-platform container image for the posture-checker web tool.
#
# Build:   docker build -t posture-checker .
# Run:     docker run --rm -p 8000:8000 posture-checker
# Health:  curl http://localhost:8000/healthz
#
# The image ships the web tool (SPA + FastAPI + SSE). The CLI is also
# available inside the container as `posture-cli`.
#
# Design notes:
#   - `python:3.12-slim` (not full, not alpine): small, reproducible, and
#     alpine's musl breaks `cryptography` wheels on some releases.
#   - Multi-stage build keeps the final image ~150 MB by dropping build
#     tooling after the wheel install.
#   - Runs as a dedicated non-root user (`app`) — the tool takes arbitrary
#     domain names from callers and hits arbitrary third-party
#     infrastructure, so dropping privileges limits blast radius of any
#     future container-escape or file-write bug.
#   - Binds 0.0.0.0 (not 127.0.0.1) because container networking requires
#     the process to listen on the container's external interface. The
#     bare `run_web.sh` binds 127.0.0.1 on host, which is correct for
#     local dev but wrong inside a container.

FROM python:3.12-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

# Install into a dedicated prefix that we can copy into the runtime stage
# without dragging along pip's build caches or apt-get artifacts.
COPY pyproject.toml README.md ./
COPY posture ./posture
COPY web ./web

RUN pip install --prefix=/install .[web]


FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Non-root user. UID/GID pinned for reproducibility across rebuilds and to
# play nicely with volume-mount permission conventions.
RUN groupadd --system --gid 1000 app \
 && useradd  --system --uid 1000 --gid app --home-dir /app --shell /sbin/nologin app

# Copy the installed package tree from the builder. `--from=builder` avoids
# shipping build-time apt caches.
COPY --from=builder /install /usr/local

WORKDIR /app
USER app

EXPOSE 8000

# Bind 0.0.0.0 so the port is reachable from outside the container.
# `posture-web` (the console script) binds 127.0.0.1 which is correct for
# local dev but wrong here.
CMD ["uvicorn", "web.server:app", "--host", "0.0.0.0", "--port", "8000"]
