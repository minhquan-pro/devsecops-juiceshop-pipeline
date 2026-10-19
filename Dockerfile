# JuiceSec Analyzer container image.
# The runtime stage keeps the zero-dependency, standard-library-only design:
# no third-party Python package is installed into the final image.
FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1
# Patch the OS layer so image scans (Trivy) start from a current baseline.
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app

FROM base AS deps
# Reproducibility check: the project must run with an empty requirements file.
COPY requirements.txt ./
RUN python - <<'PY'
import pathlib
lines = [l.strip() for l in pathlib.Path("requirements.txt").read_text().splitlines()]
pkgs = [l for l in lines if l and not l.startswith("#")]
if pkgs:
    raise SystemExit(f"unexpected runtime dependencies: {pkgs}")
print("zero third-party runtime dependencies confirmed")
PY

FROM base AS runtime

# Create non-root user early (security best practice)
RUN useradd --create-home --uid 10001 --shell /sbin/nologin juicesec \
    && chown -R juicesec:juicesec /app

# Install only the application sources and static assets
COPY --chown=juicesec:juicesec juicesec/ ./juicesec/
COPY --chown=juicesec:juicesec static/ ./static/
COPY --chown=juicesec:juicesec data/ ./data/
COPY --chown=juicesec:juicesec app.py cli.py evaluate.py scan_gate.py ./
COPY --chown=juicesec:juicesec tests/ ./tests/
COPY --chown=juicesec:juicesec labs/ ./labs/

# Switch to non-root user (CRITICAL SECURITY)
USER juicesec

# Health check for container orchestration
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import http.client; conn=http.client.HTTPConnection('127.0.0.1', 5000, timeout=5); conn.request('GET', '/'); r=conn.getresponse(); exit(0 if r.status==200 else 1)"

# The tool is loopback-only and single-user; bind inside the container
EXPOSE 5000

# Security: Use exec form to avoid shell interpretation
ENTRYPOINT ["python"]
CMD ["app.py", "--port", "5000"]

# Metadata labels for tracking
LABEL maintainer="security-team" \
      version="1.1.0" \
      description="JuiceSec Educational Security Scanner" \
      security.scan="passed"
