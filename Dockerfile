# ──────────────────────────────────────────────────────────────────────
#  SKComms — sovereign multi-channel agent messaging (REST API server)
#
#  Serves the FastAPI app (skcomms.api:app) via `skcomms serve` on :8080.
#  Mirrors the SKStacks v2 descriptor comms/skcomms/app.yaml
#  (image ghcr.io/smilintux/skcomms:latest, port 8080, /healthz probe; the app
#  also serves /health, so either probe path returns 200).
#
#  Build:  docker build -t ghcr.io/smilintux/skcomms:latest .
# ──────────────────────────────────────────────────────────────────────
FROM python:3.12-slim

WORKDIR /app

# System deps: gnupg for the PGP envelope/crypto path; wget+curl for the healthcheck
# (the descriptor's wget probe renders to a native httpGet on K8s, but Swarm needs the binary).
RUN apt-get update && apt-get install -y --no-install-recommends \
    gnupg2 \
    wget \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install skcomms with the server + cli + framework + crypto extras:
#   api       → fastapi + uvicorn[standard] (the `serve` command / skcomms.api:app)
#   cli       → click + rich (the `skcomms` entrypoint)
#   skcapstone→ skcapstone framework integration (on PyPI)
#   crypto    → capauth + pgpy (PGP-signed envelopes)
COPY pyproject.toml README.md ./
COPY src/ ./src/
RUN pip install --no-cache-dir ".[api,cli,skcapstone,crypto]"

# Sovereign data dir (config / keystore / outbox)
RUN mkdir -p /data && chmod 777 /data
ENV SKCOMMS_DATA_DIR=/data

EXPOSE 8080

# The app serves the liveness probe at BOTH /health and /healthz (skcomms.api:app),
# so the v2 descriptor's /healthz probe and this /health probe both return 200 (the
# mismatch is reconciled by serving both, see api.py).
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD wget -qO- http://localhost:8080/healthz || exit 1

CMD ["skcomms", "serve", "--host", "0.0.0.0", "--port", "8080"]
