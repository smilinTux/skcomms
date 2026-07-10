# ──────────────────────────────────────────────────────────────────────
#  SKComms — sovereign multi-channel agent messaging (REST API server)
#
#  Serves the FastAPI app (skcomms.api:app) via `skcomms serve` on :8080.
#  Mirrors the SKStacks v2 descriptor comms/skcomms/app.yaml
#  (image ghcr.io/smilintux/skcomms:latest, port 8080, /health probe).
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
COPY pyproject.toml README.md constraints.txt ./
COPY src/ ./src/
# -c constraints.txt pins every dependency to the exact versions CI validated,
# so the deployed image runs what was tested instead of re-resolving to whatever
# is latest at build time. Regenerate with scripts/refresh-constraints.sh.
RUN pip install --no-cache-dir -c constraints.txt ".[api,cli,skcapstone,crypto]"

# Sovereign data dir (config / keystore / outbox)
RUN mkdir -p /data && chmod 777 /data
ENV SKCOMMS_DATA_DIR=/data

EXPOSE 8080

# /health is the FastAPI liveness alias (skcomms.api:app). NB: the v2 descriptor probes
# /healthz today — reconcile it to /health (the real route) or add a /healthz alias.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD wget -qO- http://localhost:8080/health || exit 1

CMD ["skcomms", "serve", "--host", "0.0.0.0", "--port", "8080"]
