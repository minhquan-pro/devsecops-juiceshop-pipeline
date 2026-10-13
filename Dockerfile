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
# Install only the application sources and static assets.
COPY juicesec/ ./juicesec/
COPY static/ ./static/
COPY data/ ./data/
COPY app.py cli.py evaluate.py ./
COPY tests/ ./tests/
COPY labs/ ./labs/
# Run as a non-root user.
RUN useradd --create-home --uid 10001 juicesec
USER juicesec
# The tool is loopback-only and single-user; bind inside the container.
EXPOSE 5000
# Default command is the UI. Override with `docker run ... python cli.py ...` for batch scans.
ENTRYPOINT ["python"]
CMD ["app.py", "--port", "5000"]
