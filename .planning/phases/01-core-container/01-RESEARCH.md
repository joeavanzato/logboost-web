# Phase 1: Core Container - Research

**Researched:** 2026-02-25
**Domain:** Docker containerization of Flask 3.0+ app with Gunicorn on python:3.12-slim
**Confidence:** HIGH

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Configuration Strategy**
- Use `gunicorn.conf.py` file for all gunicorn settings (not CLI flags)
- Provide `.env.example` template documenting ALL environment variables with example values
- No required env vars - all should have sensible defaults (fail-safe for development)
- Container should work out of the box with defaults, override via env vars as needed

**Health Check Implementation**
- Health check verifies: app responds (HTTP 200), database accessible, external APIs reachable
- Use `curl` to hit `/health` endpoint (add curl to image)
- Standard timing: 30-second interval
- External API failures = degraded but healthy (core app still works)
- Only mark unhealthy if Flask app or database is down

**Build Optimization**
- Single-stage build (not multi-stage) for simplicity
- Optimize for fast rebuilds: copy requirements.txt first, pip install, then copy code
- Use allowlist `.dockerignore` (ignore everything, explicitly include only needed files)
- This prevents accidental inclusion of secrets, large files, or credentials

**Non-Root User Setup**
- Container user: `logboost` with UID 1000
- Create proper home directory at `/home/logboost`
- Working directory: `/app`

### Claude's Discretion
- Exact COPY strategy (what goes in image vs mounted)
- Volume permission handling approach
- Specific health check timeout and retry count
- Whether to include build-essential for iocextract C-extension

### Deferred Ideas (OUT OF SCOPE)
None — discussion stayed within phase scope
</user_constraints>

---

## Summary

This phase creates the Dockerfile, gunicorn.conf.py, .dockerignore, and .env.example for the LogBoost Web Flask application. The app is an existing codebase (Flask 3.0+, gunicorn already in requirements.txt) so this is purely containerization work — no application code changes unless the health endpoint needs enhancement.

The standard approach for this app is: `python:3.12-slim` base image, single-stage build with build-essential for the `iocextract` regex C-extension, non-root user (`logboost`, UID 1000), gunicorn with 1 worker + 4 threads (mandatory for SQLite single-writer), 310s timeout (mandatory for LogBoost subprocess calls), and a curl-based HEALTHCHECK hitting `/health`. The existing `/health` endpoint in app.py already returns HTTP 200 with binary/path info — it only needs to be confirmed that it checks database accessibility per the user's requirements.

Rich prior research (`.planning/research/STACK.md`, `.planning/research/PITFALLS.md`) already documents this project's pitfalls in detail. This research verifies and extends that work with current external sources.

**Primary recommendation:** Single-stage `python:3.12-slim` build with build-essential installed, used for pip, then cleaned up — keeping the image small while supporting C-extension compilation. Use 1 worker + 4 threads (gthread) in gunicorn.conf.py — this is mandatory for SQLite compatibility, not optional.

---

## Standard Stack

### Core

| Library/Tool | Version | Purpose | Why Standard |
|---|---|---|---|
| python:3.12-slim | Current patch (floating tag) | Base OS + Python runtime | Matches codebase Python 3.12; slim variant omits compilers, man pages, locales — smaller attack surface than full image; glibc-compatible unlike Alpine |
| gunicorn | >=21.0.0 (already in requirements.txt) | WSGI HTTP server | Already a project dependency; no addition needed |
| curl | apt package | HEALTHCHECK command | python:3.12-slim does not include curl; must be installed explicitly |

### Supporting

| Tool | Purpose | When to Use |
|---|---|---|
| build-essential | Compile iocextract's `regex` C-extension during pip install | Required in RUN layer; can be purged after pip install to keep image smaller, OR left in if build time matters more than image size |
| tldextract (pre-warm) | Pre-populate Public Suffix List cache at build time | Avoids first-request PermissionError if container user home is writable but network is not available at runtime |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|---|---|---|
| curl for HEALTHCHECK | Python urllib (stdlib) | `python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')"` — avoids curl apt install but spawns a Python interpreter per check; curl is the conventional approach and user has decided to use curl |
| Single-stage build | Multi-stage build | Multi-stage produces smaller images (no build-essential in final layer) but user has explicitly decided single-stage for simplicity |
| build-essential purge | Keep build-essential | Purging build-essential after pip install saves ~200MB but adds RUN layer complexity; research leans toward purge for production but it's Claude's discretion |

**No Python packages to install beyond requirements.txt.** Gunicorn is already present.

---

## Architecture Patterns

### Recommended File Layout (what this phase creates)

```
logboost-web/
├── Dockerfile            # Single-stage python:3.12-slim build
├── .dockerignore         # Allowlist pattern (exclude everything, include only needed)
├── gunicorn.conf.py      # All gunicorn settings (no CLI flags)
└── .env.example          # Documents ALL env vars with example values
```

The app source files (app.py, admin.py, auth.py, security.py, routes/, templates/, static/) are COPY'd into the image at `/app/`. Runtime data (uploads/, output/, *.db, *.mmdb, *.cache) is NOT copied — these are volume-mounted in Phase 2.

### Pattern 1: Dockerfile Layer Order for Fast Rebuilds

**What:** Copy requirements.txt first, run pip install, then copy application code. This exploits Docker layer caching — if only code changes (not dependencies), the pip install layer is cached and skipped.

**When to use:** Always. This is the correct order for Python applications.

```dockerfile
# Source: https://docs.docker.com/build/guide/layers/
FROM python:3.12-slim

# Install system dependencies (apt layer - rarely changes)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user early (stable layer)
RUN useradd -m -u 1000 logboost

WORKDIR /app

# Copy requirements first (changes rarely - cached layer)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code last (changes frequently - invalidates only this layer)
COPY . .

USER logboost
```

**Layer invalidation order:** OS packages → user creation → pip install → app code. Each layer only rebuilds if that layer or a layer above it changes.

### Pattern 2: Allowlist .dockerignore

**What:** Start with `*` (exclude everything), then use `!` exceptions to include only what's needed. This is safer than a denylist because it fails closed — new files are excluded by default.

**When to use:** When the project root contains sensitive files (databases, credentials, large binary data). This project has: `*.mmdb` (GeoIP databases, hundreds of MB), `logboost_admin.db` (hashed passwords), `mm_api.txt` (API key), `*.cache` files, `intel/` directory with threat feeds, and `logboost.exe` (Windows binary).

```
# Exclude everything by default (allowlist pattern)
*

# Include application source
!app.py
!admin.py
!auth.py
!security.py
!requirements.txt
!gunicorn.conf.py
!routes/
!templates/
!static/

# Include config files baked into image (no secrets)
!pytest.ini
```

**What is intentionally excluded:**
- `*.mmdb` — MaxMind databases (mount from host, hundreds of MB)
- `logboost_admin.db` — SQLite database with credentials (mount from host)
- `mm_api.txt` — MaxMind API key (mount from host)
- `feed_config.json` — LogBoost config (mount from host)
- `*.cache` — DNS/WHOIS/IDB caches (mount from host)
- `uploads/`, `output/` — session data (ephemeral or mount from host)
- `intel/`, `threats.db` — threat intelligence data (mount from host)
- `logboost.exe`, `logboost` — host binaries (never in image)
- `tests/`, `.planning/` — development artifacts
- `__pycache__/`, `*.pyc` — compiled bytecode
- `.git/`, `.idea/` — version control and IDE files

### Pattern 3: gunicorn.conf.py Configuration File

**What:** All gunicorn settings in a Python config file. Loaded via `gunicorn --config gunicorn.conf.py app:app`.

**Key settings for this application (verified against gunicorn official docs):**

```python
# Source: https://gunicorn.org/reference/settings/
# gunicorn.conf.py

# Worker configuration
# MUST be 1 worker — SQLite cannot handle concurrent write locking from multiple processes
workers = 1
threads = 4
worker_class = "gthread"  # gthread is automatically used when threads > 1

# Timeout — MUST exceed LogBoost subprocess timeout (300s in app.py)
# Gunicorn kills workers silent for longer than timeout; 310s = 300s + 10s buffer
timeout = 310
graceful_timeout = 30

# Bind address — 0.0.0.0 so Docker port mapping works
bind = "0.0.0.0:5000"

# Logging to stdout/stderr (Docker log collection)
accesslog = "-"   # "-" means stdout
errorlog = "-"    # "-" means stderr
loglevel = "info"

# Process naming (optional, useful in docker exec ps output)
proc_name = "logboost-web"
```

**Why workers=1 is mandatory:** The app uses SQLite with raw `sqlite3.connect()` — no connection pooling. Multiple gunicorn workers create separate processes that compete for SQLite write locks, causing `sqlite3.OperationalError: database is locked` errors on every concurrent write (cache updates, audit logs, task status). Single worker + multiple threads avoids this: threads share one process and therefore one SQLite connection path.

**Why timeout=310 is mandatory:** `run_logboost()` in app.py uses `subprocess.run(..., timeout=300)`. Gunicorn's default timeout is 30 seconds. If gunicorn's timeout is less than the subprocess timeout, gunicorn kills the worker process mid-enrichment, leaving orphaned LogBoost processes on the host.

### Pattern 4: Non-Root User Creation

**What:** Create a dedicated user inside the container before switching to it.

```dockerfile
# Source: https://www.docker.com/blog/understanding-the-docker-user-instruction/
RUN useradd --create-home --uid 1000 logboost

# Set working directory BEFORE switching user
WORKDIR /app

# ... COPY and pip install steps ...

# Switch to non-root user last
USER logboost
```

**Note on --no-log-init:** The `--no-log-init` flag is recommended to avoid lastlog/faillog initialization issues in some Docker scenarios. Pattern: `useradd --no-log-init --create-home --uid 1000 logboost`.

**Home directory:** `/home/logboost` is created by `--create-home`. This is writable by the logboost user — required for `tldextract` cache (`~/.cache/python-tldextract/`) and any other library that writes to home.

### Pattern 5: HEALTHCHECK Directive

**What:** Docker native health check that runs a command inside the container on a schedule.

```dockerfile
# Source: Docker HEALTHCHECK defaults confirmed via WebSearch (2026)
# Defaults: --interval=30s --timeout=30s --start-period=0s --retries=3
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1
```

**Parameter rationale (Claude's discretion):**
- `--interval=30s` — user locked this; checks every 30 seconds
- `--timeout=10s` — if /health doesn't respond in 10s, mark check failed (gunicorn is stuck)
- `--start-period=30s` — give gunicorn time to start (worker process startup, tldextract cache warmup on first import can take 5-15 seconds)
- `--retries=3` — mark unhealthy after 3 consecutive failures (90 seconds of sustained failure)

**The existing /health endpoint in app.py (line 636)** returns:
```json
{"status": "ok", "logboost_available": true/false, "logboost_path": "...", "maxmind_dir": "...", "threat_db_dir": "..."}
```

The endpoint currently does NOT check database accessibility. Per user's locked decision ("Only mark unhealthy if Flask app or database is down"), the health endpoint needs a database check added. This is a code change within this phase.

### Anti-Patterns to Avoid

- **CMD ["python", "app.py"]** — launches Flask dev server with `debug=True` (app.py line 3207), exposing Werkzeug interactive debugger. Always use gunicorn CMD.
- **Copying secrets into image** — `mm_api.txt`, `logboost_admin.db`, `*.mmdb` must never be in the image layer; .dockerignore prevents this
- **gunicorn workers > 1 without WAL mode** — SQLite write lock contention causes intermittent 500 errors; workers=1 is the fix for this project
- **gunicorn timeout <= 300** — kills long-running LogBoost enrichment jobs mid-execution
- **No --start-period on HEALTHCHECK** — causes immediate health check failures during container startup before gunicorn is ready
- **Not cleaning apt cache** — `rm -rf /var/lib/apt/lists/*` saves ~50MB per apt layer

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---|---|---|---|
| WSGI process management | Custom Python multiprocessing | gunicorn (already in requirements.txt) | Signal handling, worker restart, request queuing are all handled |
| Health check command | Custom health check script | `curl -f http://localhost:5000/health` | curl exits non-zero on HTTP error; -f flag makes it fail on 4xx/5xx |
| Python package compilation | Manual gcc setup | `build-essential` apt package | build-essential installs gcc, g++, make, and libc-dev in one step |
| Non-root user permissions | Manual chmod/chown pyramid | `useradd --create-home` + correct WORKDIR before USER switch | useradd handles home directory creation and group membership |

**Key insight:** For Python containerization, the complexity is in the *ordering* of Dockerfile instructions (layer caching), not in the tools used. The tools are all standard. The mistakes are in ordering and omissions.

---

## Common Pitfalls

The project already has detailed pitfall documentation in `.planning/research/PITFALLS.md`. This section surfaces the pitfalls most likely to affect Phase 1 task execution.

### Pitfall 1: iocextract Fails to Install on python:3.12-slim Without build-essential

**What goes wrong:** `pip install iocextract>=1.16.1` fails during `docker build` with `error: command 'gcc' failed with exit status 1`. The `iocextract` package depends on the `regex` module, which is a compiled C extension. `python:3.12-slim` does not include gcc or other build tools.

**Why it happens:** `python:3.12-slim` strips all compilers. The `regex` PyPI package requires gcc to compile its C extension during installation.

**How to avoid:** Add `build-essential` to the apt install layer BEFORE the pip install step. The user's decision marks this as Claude's discretion — the recommendation is to install build-essential, run pip, then purge it:

```dockerfile
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    build-essential \
    && pip install --no-cache-dir -r requirements.txt \
    && apt-get purge -y build-essential \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*
```

However, this approach chains apt, pip, and apt-purge in a single RUN layer, which **destroys layer caching** — any change to requirements.txt rebuilds the entire apt install step too.

**Recommended approach for this project (fast rebuilds are a stated priority):** Install build-essential in a separate stable layer, then pip install in its own layer:

```dockerfile
# Stable layer - only rebuilds when system deps change
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Separate pip layer - only rebuilds when requirements.txt changes
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
```

This keeps build-essential in the final image (~200MB image size increase) but preserves the layer caching that makes iterative development fast. For a local deployment where image size is not critical, this is the correct tradeoff.

**Warning signs:** `docker build` fails with `gcc not found` or `error: command 'x86_64-linux-gnu-gcc' failed`.

### Pitfall 2: tldextract Cache Fails on First Request

**What goes wrong:** `tldextract` downloads and caches the Public Suffix List on first use to `~/.cache/python-tldextract/`. If the non-root user's home directory is not writable (permission issue) or if outbound HTTP is blocked in the container, the first request to any route that calls `tldextract` raises a PermissionError or URLError.

**How to avoid:** Pre-populate the tldextract cache during `docker build` (before switching to non-root user, or after if home is writable):

```dockerfile
RUN pip install --no-cache-dir -r requirements.txt && \
    python -c "import tldextract; tldextract.extract('example.com')"
```

This bakes the Public Suffix List into the image layer — it's a small file (~200KB) and eliminates first-request latency. Run it as root during build so it goes to the root's cache, OR set `TLDEXTRACT_CACHE` to a path under `/app` (owned by logboost user).

**Alternative:** Set env var `TLDEXTRACT_CACHE=/app/.tldextract` so the cache lands in the app's writable directory regardless of user home.

**Warning signs:** First request to any route returns 500 with `PermissionError` or very slow (30+ seconds waiting for HTTP download).

### Pitfall 3: SECRET_KEY Regenerated on Every Container Restart

**What goes wrong:** `app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))` (app.py line 52). If `SECRET_KEY` is not set, a new random key is generated on every container start. All user sessions are invalidated on every restart. CSRF tokens signed with the old key return 400 errors.

**How to avoid:** The .env.example must document SECRET_KEY with a clear warning. Generate a proper key: `python -c "import secrets; print(secrets.token_hex(32))"`. The default in the container (without SECRET_KEY set) should be a fixed development key, NOT os.urandom().

**Note:** The user locked "no required env vars — all should have sensible defaults." This means the Dockerfile should set a default SECRET_KEY (a hardcoded dev-only value) as a Docker ENV, with the .env.example documenting how to override it for production. The Dockerfile ENV default must be clearly labeled as development-only.

**Warning signs:** Users logged out on every container restart; CSRF errors after deployments.

### Pitfall 4: Allowlist .dockerignore — Not Including Needed Subdirectories

**What goes wrong:** The allowlist pattern `!routes/` includes the directory listing but may not include the files inside it depending on Docker's .dockerignore behavior. Docker's .dockerignore uses Go filepath.Match rules — `!routes/` includes the directory and its contents when using COPY . .

**How to avoid:** Test the build and verify route files are accessible inside the container with `docker run --rm logboost-web ls /app/routes/`.

**Warning signs:** ImportError on `from routes import register_blueprints` at container startup.

### Pitfall 5: Health Check start-period Too Short

**What goes wrong:** Gunicorn starts, loads the Flask application (including all imports — shodan, iocextract, tldextract, dnspython), and begins accepting connections. On a cold image (no layer cache), this can take 5-20 seconds. If HEALTHCHECK `--start-period` is 0 or very low, health checks run before gunicorn is ready, fail, and the container may be marked unhealthy before it finishes starting.

**How to avoid:** Set `--start-period=30s`. The first health check result during the start period doesn't count against the retry count.

**Warning signs:** Container marked `unhealthy` in `docker ps` immediately after start, then returns to healthy; or container restarts loop on first deployment.

---

## Code Examples

Verified patterns from official sources and codebase inspection:

### Complete Dockerfile (Recommended)

```dockerfile
# Source: Docker official docs + gunicorn official docs + verified project requirements
FROM python:3.12-slim

# System dependencies: curl for HEALTHCHECK, build-essential for iocextract regex C-extension
# Installed as a separate stable layer to preserve pip install layer caching
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user with home directory (required for tldextract cache)
RUN useradd --no-log-init --create-home --uid 1000 logboost

# Working directory
WORKDIR /app

# Layer caching: requirements first, code second
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Pre-warm tldextract cache (avoids first-request download + PermissionError risk)
RUN python -c "import tldextract; tldextract.extract('example.com')"

# Copy only what's needed (allowlist .dockerignore handles exclusions)
COPY . .

# Set ownership of app directory to non-root user
RUN chown -R logboost:logboost /app

# Switch to non-root user
USER logboost

# Health check - curl must be installed (done above)
# --start-period=30s: gunicorn + Flask import time before health checks count
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

# Port (documentation only - still need -p in docker run)
EXPOSE 5000

# Run gunicorn with config file (never python app.py)
CMD ["gunicorn", "--config", "gunicorn.conf.py", "app:app"]
```

### Complete gunicorn.conf.py

```python
# gunicorn.conf.py
# Source: https://gunicorn.org/reference/settings/ (verified 2026-02-25)
# All gunicorn settings here — no CLI flags used

# Worker configuration
# workers=1 is MANDATORY for SQLite compatibility (no concurrent write locks)
workers = 1
threads = 4
worker_class = "gthread"  # auto-selected when threads > 1, but explicit is clearer

# Timeout — MUST exceed app.py subprocess timeout (300s in run_logboost())
# LogBoost binary can take up to 5 minutes for large file enrichment
timeout = 310
graceful_timeout = 30

# Network binding — 0.0.0.0 required for Docker port mapping
bind = "0.0.0.0:5000"

# Logging to stdout/stderr for docker logs capture
# "-" means stdout (accesslog) or stderr (errorlog)
accesslog = "-"
errorlog = "-"
loglevel = "info"

# Process name (visible in `docker exec <id> ps aux`)
proc_name = "logboost-web"
```

### Complete .dockerignore (Allowlist Pattern)

```
# Allowlist .dockerignore — exclude everything, explicitly include only what's needed
# This prevents secrets, large files, and credentials from entering the build context

# Step 1: Exclude everything
*

# Step 2: Include application source files
!app.py
!admin.py
!auth.py
!security.py
!requirements.txt
!gunicorn.conf.py

# Step 3: Include application directories
!routes/
!templates/
!static/

# Step 4: Include config (no secrets — these are baked in defaults)
!pytest.ini

# Explicitly excluded (documentation of what stays out):
# *.mmdb           — GeoIP databases (large, mount from host)
# logboost_admin.db — SQLite with credentials (mount from host)
# mm_api.txt       — MaxMind API key (mount from host)
# feed_config.json — LogBoost config (mount from host)
# *.cache          — DNS/WHOIS/IDB caches (mount from host)
# uploads/         — session uploads (ephemeral or mount)
# output/          — session output (ephemeral or mount)
# intel/           — threat feed files (large, mount from host)
# threats.db       — threat intelligence (mount from host)
# logboost.exe     — Windows binary (never in Linux container)
# logboost         — host binary (mount, never copy)
# GeoLite2-*.mmdb  — MaxMind databases (covered by *.mmdb above)
# tests/           — test files (not needed at runtime)
# .planning/       — planning artifacts
# .git/            — version control
# __pycache__/     — Python bytecode
# *.pyc            — compiled bytecode
# .env             — secrets file (never in image)
# .env.*           — all env files
# logboost.log     — log file
# *.log            — all log files
# dns.cache        — covered by *.cache
```

### .env.example (Complete)

```bash
# .env.example — All environment variables for logboost-web container
# Copy this file to .env and fill in values for local overrides
# None of these are required — all have defaults that work out of the box

# ============================================================
# SECURITY — Override these for production deployments
# ============================================================

# Flask session signing key
# REQUIRED FOR PRODUCTION: Generate with: python -c "import secrets; print(secrets.token_hex(32))"
# WARNING: The default in the Dockerfile is a development-only placeholder.
#          Using the default means all sessions are signed with a publicly known key.
SECRET_KEY=change-me-generate-with-secrets-token-hex-32

# Flask environment — controls SESSION_COOKIE_SECURE
# Set to 'production' to enable secure (HTTPS-only) session cookies
# WARNING: Without this, session cookies are sent over HTTP even if serving HTTPS
FLASK_ENV=production

# ============================================================
# LOGBOOST BINARY
# ============================================================

# Path to the LogBoost Linux binary inside the container
# Mount the host binary into the container and set this to the container-internal path
# Example with standard mount: docker run -v /usr/local/bin/logboost:/usr/local/bin/logboost:ro
LOGBOOST_PATH=/usr/local/bin/logboost

# Working directory for LogBoost subprocess execution (defaults to current dir)
LOGBOOST_WORKDIR=.

# ============================================================
# DATA PATHS — Mount matching directories from host
# ============================================================

# Directory containing MaxMind GeoIP databases (*.mmdb files)
# Must contain: GeoLite2-City.mmdb, GeoLite2-ASN.mmdb, GeoLite2-Country.mmdb
MAXMIND_DIR=/data/maxmind

# Directory containing threat intelligence database (threats.db)
THREAT_DB_DIR=/data/intel

# ============================================================
# LOGGING
# ============================================================

# Application log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
# Default is WARNING to minimize noise; set to INFO or DEBUG for troubleshooting
LOGBOOST_LOG_LEVEL=WARNING
```

### Health Endpoint Database Check Addition

The existing `/health` endpoint (app.py line 636) checks logboost binary availability but NOT database accessibility. Per user's locked decision, the health check must verify database is accessible. The endpoint needs this addition:

```python
# Addition to /health endpoint in app.py
# After existing logboost_available check, add:
db_accessible = False
try:
    from admin import get_db
    db = get_db()
    db.execute("SELECT 1")
    db_accessible = True
except Exception:
    db_accessible = False

# Health determination (per user's decision):
# - UNHEALTHY: Flask app down (unreachable) OR database inaccessible
# - DEGRADED but HEALTHY (200): External APIs unreachable, binary not found
is_healthy = db_accessible  # Flask being up is implicit (we're responding)

return jsonify({
    'status': 'ok' if is_healthy else 'unhealthy',
    'db_accessible': db_accessible,
    'logboost_available': logboost_available,
    'logboost_path': LOGBOOST_BINARY,
    'maxmind_dir': MAXMIND_DIR,
    'threat_db_dir': THREAT_DB_DIR
}), 200 if is_healthy else 503
```

**Note:** Per user's decision, only return non-200 (503) if database is down. The HEALTHCHECK uses `curl -f` which fails on 4xx/5xx. So: db down = 503 = curl exits non-zero = health check fails = container marked unhealthy. Binary missing = 200 (degraded) = curl succeeds = container marked healthy.

---

## State of the Art

| Old Approach | Current Approach | Impact |
|---|---|---|
| `gunicorn --workers 4 --bind 0.0.0.0:5000 app:app` (CLI flags) | `gunicorn --config gunicorn.conf.py app:app` (config file) | Config file is version-controllable, readable, and avoids shell escaping issues |
| `CMD ["python", "app.py"]` | `CMD ["gunicorn", "--config", "gunicorn.conf.py", "app:app"]` | Prevents Flask dev server with debug mode in production |
| Denylist .dockerignore | Allowlist .dockerignore (`*` + `!exceptions`) | New files excluded by default; secrets can't accidentally slip in |
| `FROM python:3.12` (full image) | `FROM python:3.12-slim` | ~700MB smaller base image |
| `adduser` (Alpine-style) | `useradd --no-log-init --create-home --uid 1000 logboost` | Debian/Ubuntu compatible; creates home for library caches |

**Current gunicorn version:** 21.x (23.x may be available — requirements.txt pins `>=21.0.0`; the floating `>=` means pip will install the latest compatible version). The config file format and setting names are stable across gunicorn 20.x-23.x.

---

## Open Questions

1. **Whether to purge build-essential after pip install**
   - What we know: Purging saves ~200MB but chains apt+pip+apt in one RUN layer, breaking pip layer cache
   - What's unclear: Whether image size vs build speed tradeoff matters for this deployment
   - Recommendation: Keep build-essential as a separate stable layer (prioritize fast rebuilds per user's stated concern about layer caching)

2. **iocextract build-essential: confirmed needed**
   - What we know: iocextract depends on `regex` (C extension). The GitHub README explicitly states: "You may need to install the Python development headers in order to install the `regex` dependency."
   - What's unclear: Whether a pre-compiled wheel for `regex` on python:3.12-slim/Debian would install without gcc (wheels sometimes exist for common platforms)
   - Recommendation: Include build-essential; the blocker is `cannot determine whether wheel is available without test build`. The safe default is to include it. If a test build succeeds without it, it can be removed.
   - Confidence: MEDIUM (sourced from GitHub README, not from test build)

3. **Dockerfile ENV for SECRET_KEY default**
   - What we know: User decision says "no required env vars — all should have sensible defaults." For SECRET_KEY, `os.urandom(24)` is the current code default — this is dangerous for Docker (new key each restart).
   - What's unclear: Should the Dockerfile set a known-bad placeholder via `ENV SECRET_KEY=dev-placeholder-change-me` (visible in `docker inspect`) or leave the os.urandom behavior?
   - Recommendation: Set `ENV SECRET_KEY=dev-placeholder-change-me-in-production` in Dockerfile. This makes the dev default deterministic (sessions survive restarts in dev) while being clearly labeled as a placeholder. Override with actual secret at runtime.

4. **DB_PATH for health check**
   - What we know: `admin.py` line 27: `DB_PATH = Path(__file__).parent / 'logboost_admin.db'` — hardcoded relative to admin.py, not an env var
   - What's unclear: Whether the health endpoint should use `get_db()` (which uses this hardcoded path) or check the file exists via `Path`
   - Recommendation: Use `from admin import get_db; db.execute("SELECT 1")` — this uses the same path the app uses, so it tests what matters

---

## Sources

### Primary (HIGH confidence)

- Codebase inspection: `app.py`, `admin.py`, `requirements.txt` — directly verified env vars, health endpoint, DB path
- `.planning/research/PITFALLS.md` — prior project-specific research, HIGH confidence
- `.planning/research/STACK.md` — prior project-specific research, HIGH confidence
- gunicorn official settings reference: https://gunicorn.org/reference/settings/ — verified setting names, defaults
- gunicorn example config: https://github.com/benoitc/gunicorn/blob/master/examples/example_config.py — verified config file format

### Secondary (MEDIUM confidence)

- Docker HEALTHCHECK parameters (defaults: interval=30s, timeout=30s, start-period=0s, retries=3) — confirmed via WebSearch 2026, multiple sources agree
- iocextract `regex` C-extension dependency — confirmed via GitHub README (https://github.com/InQuest/iocextract): "You may need to install Python development headers for the `regex` dependency"
- python:3.12-slim does not include curl — confirmed via WebSearch multiple sources
- python:3.12-slim does not include gcc/build-essential — confirmed via WebSearch (Docker library issue #882)
- useradd `--no-log-init` pattern — confirmed via WebSearch + Docker official blog

### Tertiary (LOW confidence)

- Whether `regex` C-extension wheel exists for python:3.12-slim/Debian (avoiding build-essential) — not verified empirically; treat as LOW until first `docker build` confirms

---

## Metadata

**Confidence breakdown:**
- Standard stack (python:3.12-slim, gunicorn, curl): HIGH — verified via official sources
- Dockerfile layer ordering pattern: HIGH — standard Docker best practice, multiple official sources
- gunicorn.conf.py setting names and defaults: HIGH — fetched from gunicorn official settings page
- iocextract build-essential requirement: MEDIUM — GitHub README confirmed, not empirical test
- HEALTHCHECK parameters: MEDIUM — WebSearch verified, multiple sources agree
- tldextract cache pre-warm: MEDIUM — confirmed mechanism, exact path may need adjustment
- Pitfalls: HIGH — prior research with detailed codebase analysis

**Research date:** 2026-02-25
**Valid until:** 2026-03-25 (30 days; Docker and gunicorn are stable tooling)

**Prior research leveraged:** `.planning/research/STACK.md` and `.planning/research/PITFALLS.md` — highly detailed project-specific research used as foundation; this document augments with externally verified sources.
