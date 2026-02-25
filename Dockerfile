FROM python:3.12-slim

# Metadata
LABEL maintainer="logboost" \
      description="LogBoost Web - Flask frontend for LogBoost enrichment engine"

# Install system dependencies, compile Python packages, then remove build tools
# Single RUN keeps image small by not creating separate layers with build toolchain
# curl: retained at runtime for HEALTHCHECK
# build-essential: required for iocextract's regex C-extension compilation, removed after pip install
COPY requirements.txt /tmp/requirements.txt
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    build-essential \
    && pip install --no-cache-dir -r /tmp/requirements.txt \
    && apt-get purge -y --auto-remove build-essential \
    && rm -rf /var/lib/apt/lists/* /tmp/requirements.txt

# Pre-warm tldextract Public Suffix List cache
# Avoids first-request latency and PermissionError if network unavailable at runtime
RUN python -c "import tldextract; tldextract.extract('example.com')"

# Create non-root user with home directory
# Home dir required for tldextract cache (~/.cache/python-tldextract/)
# UID 1000 per user's locked decision
RUN useradd --no-log-init --create-home --uid 1000 logboost

# Working directory
WORKDIR /app

# Copy application source (filtered by .dockerignore allowlist)
COPY . .

# Set ownership of app directory to non-root user
RUN chown -R logboost:logboost /app

# Create directories for uploads and output (writable by logboost user)
# These may be overridden by volume mounts in Phase 2
RUN mkdir -p /app/uploads /app/output && chown -R logboost:logboost /app/uploads /app/output

# Pre-create the admin database file so health check passes on first boot
# sqlite3.connect() auto-creates the file; this ensures it exists before container starts
# The DB path must match the LOGBOOST_DB_PATH default below
# chown required because this runs as root after the earlier chown -R
RUN python -c "from admin import get_db; get_db().close()" \
    && chown logboost:logboost /app/logboost_admin.db

# Default environment variables — all have sensible defaults per user's locked decision
# Container works out of the box; override via env vars or .env file
ENV SECRET_KEY=dev-placeholder-change-me-in-production
ENV FLASK_ENV=production
ENV LOGBOOST_PATH=/usr/local/bin/logboost
ENV MAXMIND_DIR=/data/maxmind
ENV THREAT_DB_DIR=/data/intel
ENV LOGBOOST_LOG_LEVEL=info
ENV LOGBOOST_DB_PATH=/app/logboost_admin.db

# Switch to non-root user (after all root-required operations)
USER logboost

# Health check — curl hits /health endpoint
# --interval=30s: per user's locked decision (30-second interval)
# --timeout=10s: health response should be fast
# --start-period=30s: gunicorn + Flask import warmup time
# --retries=3: mark unhealthy after 3 consecutive failures (90s sustained)
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

# Document the exposed port (still need -p in docker run)
EXPOSE 5000

# Run gunicorn with config file (NEVER python app.py — that uses Flask dev server with debug=True)
CMD ["gunicorn", "--config", "gunicorn.conf.py", "app:app"]
