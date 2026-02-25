# Architecture Patterns: Flask Docker Containerization

**Domain:** Flask web application containerization
**Researched:** 2026-02-25
**Confidence:** HIGH — based on direct codebase inspection plus established Docker/Flask patterns

---

## Recommended Architecture

### Overview

The LogBoost web frontend runs as a single Docker container hosting the Flask application under Gunicorn. The LogBoost binary remains on the host (Linux). The container mounts host directories to access backend-managed files. SSL termination happens in the container (or optionally via a reverse proxy on the host).

```
Host OS (Linux)
├── LogBoost binary (/usr/local/bin/logboost or configured path)
├── /opt/logboost/                     ← host-managed backend directory
│   ├── dns.cache                      ← mounted read/write into container
│   ├── idb.cache
│   ├── whois.cache
│   ├── feed_config.json
│   ├── mm_api.txt
│   ├── GeoLite2-ASN.mmdb
│   ├── GeoLite2-City.mmdb
│   ├── GeoLite2-Country.mmdb
│   ├── threats.db
│   └── logboost.log
└── Docker container: logboost-web
    ├── Flask app (Python 3.12)
    ├── Gunicorn (WSGI server)
    ├── /app/logboost_admin.db         ← container-owned SQLite, persisted via volume
    ├── /app/uploads/                  ← ephemeral session uploads (container-local)
    ├── /app/output/                   ← ephemeral session output (container-local)
    └── Volume mounts → /opt/logboost/ paths
```

### Component Boundaries

| Component | Responsibility | Lives Where | Communicates With |
|-----------|---------------|-------------|-------------------|
| Flask app | Web UI, API routes, session mgmt | Container | Gunicorn, LogBoost binary, SQLite |
| Gunicorn | WSGI process management, worker scaling | Container | Flask app, network |
| LogBoost binary | Log enrichment processing | Host | Container via subprocess + volume mounts |
| logboost_admin.db | Users, sessions, tasks, DNS/WHOIS cache | Container volume | Flask/admin module |
| threats.db | Threat intelligence database | Host mount | Flask app (read-only) |
| MaxMind DBs | GeoIP databases | Host mount | LogBoost binary + Flask (read-only) |
| Cache files | dns.cache, idb.cache, whois.cache | Host mount | LogBoost binary (read/write) |
| feed_config.json | LogBoost feed configuration | Host mount | LogBoost binary + admin UI (read/write) |
| mm_api.txt | MaxMind API key file | Host mount | Admin module (read-only) |
| Session uploads | Per-session uploaded log files | Container ephemeral | Flask app, LogBoost via mount |
| Session output | Per-session enriched output CSVs | Container ephemeral | Flask app |

### Data Flow

```
User browser
    │  HTTPS (port 443 or 8443)
    ▼
Gunicorn (port 8000 internal)
    │
    ▼
Flask application
    ├── Auth check (logboost_admin.db)
    ├── File upload → /app/uploads/{session_id}/
    ├── Build subprocess command
    │       LOGBOOST_PATH  → host binary path (bind-mounted or PATH)
    │       -logdir        → /app/uploads/{session_id}/
    │       -outputdir     → /app/output/{session_id}/
    │       -dbdir         → /mnt/logboost/ (MaxMind DBs)
    │
    ▼
LogBoost binary (host binary, executed from container via subprocess)
    ├── Reads from /app/uploads/{session_id}/   ← shared via volume
    ├── Reads MaxMind DBs from /mnt/logboost/
    ├── Reads/writes cache files in /mnt/logboost/
    ├── Writes output to /app/output/{session_id}/
    └── Uses feed_config.json from /mnt/logboost/
    │
    ▼
Flask application (reads output, serves results to browser)
```

**Key data flow constraint:** The LogBoost binary is a Linux ELF binary on the host. The container must either:
1. Bind-mount the host binary directory and set `LOGBOOST_PATH` to the bind-mounted path inside the container, OR
2. Use `--network=host` and call the binary via a socket/API (not applicable — it's a CLI tool, not a server)

Option 1 (bind-mount) is correct. The binary executes within the container's process namespace but operates on the host filesystem paths via volume mounts.

---

## Dockerfile Structure

### Recommended: Two-Stage Build

Use a two-stage build to separate dependency compilation from the final runtime image. For pure Python with no compiled extensions, a single-stage build is also valid — but two stages are recommended for size reduction and clarity.

```dockerfile
# ============================================================
# Stage 1: Builder
# Install and compile Python dependencies
# ============================================================
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build tools only in builder stage
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first — maximizes layer caching
# This layer only rebuilds when requirements.txt changes
COPY requirements.txt .

# Install to a prefix directory for clean copy into runtime stage
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ============================================================
# Stage 2: Runtime
# Minimal image with only what runs in production
# ============================================================
FROM python:3.12-slim AS runtime

WORKDIR /app

# Create non-root user for security
RUN groupadd -r logboost && useradd -r -g logboost logboost

# Copy installed packages from builder stage
COPY --from=builder /install /usr/local

# Copy application code
# Order: least-to-most-frequently-changed for cache efficiency
COPY requirements.txt .
COPY security.py auth.py admin.py app.py ./
COPY routes/ ./routes/
COPY templates/ ./templates/
COPY static/ ./static/

# Create session directories (owned by app user)
RUN mkdir -p /app/uploads /app/output && \
    chown -R logboost:logboost /app

# Create mount points for host-managed files
RUN mkdir -p /mnt/logboost

# Switch to non-root user
USER logboost

# Expose Gunicorn port (not 80/443 — let host networking handle that)
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"

# Production entrypoint
CMD ["gunicorn", \
     "--bind", "0.0.0.0:8000", \
     "--workers", "4", \
     "--worker-class", "sync", \
     "--timeout", "300", \
     "--keep-alive", "5", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "app:app"]
```

### Layer Ordering Rationale

Layer cache is invalidated from the point of first change downward. Order layers by change frequency (slowest-changing first):

| Layer Order | Content | Change Frequency |
|-------------|---------|-----------------|
| 1 | Base image (`FROM python:3.12-slim`) | Rare (monthly) |
| 2 | System packages (`apt-get`) | Rare |
| 3 | `requirements.txt` copy + pip install | When deps change |
| 4 | `security.py`, `auth.py`, `admin.py` | Occasional |
| 5 | `app.py` | Moderate |
| 6 | `routes/` | Frequent |
| 7 | `templates/`, `static/` | Most frequent |

**Build time impact:** Putting `requirements.txt` install early means `pip install` (the slowest step) is cached on every code-only change. A change to a template does not re-run pip install.

---

## File Organization

### Repository Layout (what to add)

```
logboost-web/
├── Dockerfile                    ← build definition
├── .dockerignore                 ← excludes from build context
├── gunicorn.conf.py              ← Gunicorn configuration file
├── docker-run.sh                 ← documented run command (optional helper)
├── .env.example                  ← documents required env vars (never commit .env)
├── app.py
├── admin.py
├── auth.py
├── security.py
├── requirements.txt
├── routes/
├── templates/
├── static/
└── .planning/
```

### .dockerignore

Critical for build performance and security. Excludes files from the build context sent to the Docker daemon.

```dockerignore
# Python artifacts
__pycache__/
*.py[cod]
*.pyo
.pytest_cache/
*.egg-info/

# Test files
tests/
pytest.ini
test.txt

# Development files
.planning/
docs/
*.md

# Runtime data — never bake into image
logboost_admin.db
uploads/
output/
*.cache
*.log

# Secrets and local config
.env
mm_api.txt

# Host binary — NOT in image
logboost.exe
*.exe

# MaxMind databases — mounted from host
*.mmdb
threats.db
feed_config.json

# Version control
.git/
.gitignore
```

**Why this matters:** Without `.dockerignore`, the build context includes all files (including the 3 `.mmdb` database files, the SQLite databases, cache files, and the 100MB+ upload/output directories). This dramatically slows build time and inflates image size.

### gunicorn.conf.py

Prefer a config file over CLI flags for maintainability:

```python
# gunicorn.conf.py
import multiprocessing

# Server socket
bind = "0.0.0.0:8000"
backlog = 2048

# Worker processes
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = "sync"
worker_connections = 1000
timeout = 300          # Must accommodate LogBoost 5-minute run timeout
keepalive = 5

# Logging
accesslog = "-"        # stdout
errorlog = "-"         # stderr
loglevel = "info"

# Process naming
proc_name = "logboost-web"

# Security
limit_request_line = 4096
limit_request_fields = 100
limit_request_field_size = 8190
```

**Timeout note:** app.py uses `subprocess.run(..., timeout=300)` for LogBoost. The Gunicorn worker timeout must be >= 300 seconds, or the worker will be killed mid-processing. Set Gunicorn `timeout = 360` to include overhead.

---

## Volume Mount Strategy

### Volume Categories

| Category | Host Path | Container Path | Access | Rationale |
|----------|-----------|----------------|--------|-----------|
| Admin DB | `/opt/logboost-web/logboost_admin.db` | `/app/logboost_admin.db` | Read/Write | Persists user accounts, scheduled tasks, settings across container restarts |
| MaxMind DBs | `/opt/logboost/*.mmdb` | `/mnt/logboost/` | Read-only | Large files managed by host; LogBoost and Flask both read them |
| Cache files | `/opt/logboost/*.cache` | `/mnt/logboost/` | Read/Write | LogBoost binary writes these; Flask reads for display |
| Threat DB | `/opt/logboost/threats.db` | `/mnt/logboost/threats.db` | Read-only | LogBoost manages updates; Flask queries |
| Feed config | `/opt/logboost/feed_config.json` | `/mnt/logboost/feed_config.json` | Read/Write | Admin UI edits this; LogBoost reads it |
| MM API key | `/opt/logboost/mm_api.txt` | `/mnt/logboost/mm_api.txt` | Read-only | Prefer `MM_API` env var instead |
| LogBoost binary | `/usr/local/bin/logboost` | `/usr/local/bin/logboost` | Read/Execute | Host binary, container must execute it |
| Uploads | *(container-local)* | `/app/uploads/` | Read/Write | Ephemeral per-session; no persistence needed |
| Output | *(container-local)* | `/app/output/` | Read/Write | Ephemeral per-session; no persistence needed |

### Docker Run Command

```bash
docker run -d \
  --name logboost-web \
  --restart unless-stopped \
  \
  # Port mapping (choose one approach)
  -p 8443:8443 \           # SSL in container
  # OR
  -p 127.0.0.1:8000:8000 \ # Plain HTTP, reverse proxy handles SSL
  \
  # LogBoost binary access
  -v /usr/local/bin/logboost:/usr/local/bin/logboost:ro \
  \
  # Persistence: admin database
  -v /opt/logboost-web/logboost_admin.db:/app/logboost_admin.db \
  \
  # Backend files (read-only where possible)
  -v /opt/logboost/GeoLite2-ASN.mmdb:/mnt/logboost/GeoLite2-ASN.mmdb:ro \
  -v /opt/logboost/GeoLite2-City.mmdb:/mnt/logboost/GeoLite2-City.mmdb:ro \
  -v /opt/logboost/GeoLite2-Country.mmdb:/mnt/logboost/GeoLite2-Country.mmdb:ro \
  -v /opt/logboost/threats.db:/mnt/logboost/threats.db:ro \
  -v /opt/logboost/feed_config.json:/mnt/logboost/feed_config.json \
  -v /opt/logboost/dns.cache:/mnt/logboost/dns.cache \
  -v /opt/logboost/idb.cache:/mnt/logboost/idb.cache \
  -v /opt/logboost/whois.cache:/mnt/logboost/whois.cache \
  -v /opt/logboost/mm_api.txt:/mnt/logboost/mm_api.txt:ro \
  \
  # Environment
  -e SECRET_KEY="$(openssl rand -hex 32)" \
  -e FLASK_ENV=production \
  -e LOGBOOST_PATH=/usr/local/bin/logboost \
  -e LOGBOOST_WORKDIR=/mnt/logboost \
  -e MAXMIND_DIR=/mnt/logboost \
  -e THREAT_DB_DIR=/mnt/logboost \
  \
  logboost-web:latest
```

### Volume Pre-creation

Before first run, the host paths must exist:

```bash
# Create persistent storage for admin DB
mkdir -p /opt/logboost-web
touch /opt/logboost-web/logboost_admin.db

# Verify LogBoost backend files exist
ls /opt/logboost/*.mmdb
ls /opt/logboost/*.cache 2>/dev/null || touch /opt/logboost/dns.cache /opt/logboost/idb.cache /opt/logboost/whois.cache
ls /opt/logboost/feed_config.json
```

---

## Environment Variable Configuration

### Complete Variable Reference

| Variable | Required | Default in Code | Container Value | Notes |
|----------|----------|-----------------|-----------------|-------|
| `SECRET_KEY` | YES | `os.urandom(24)` | Long random string | Random default is wrong — Flask sessions reset on restart |
| `FLASK_ENV` | YES | not set | `production` | Enables `SESSION_COOKIE_SECURE` |
| `LOGBOOST_PATH` | YES | `LogBoost` | `/usr/local/bin/logboost` | Must be absolute path inside container |
| `LOGBOOST_WORKDIR` | YES | `.` | `/mnt/logboost` | Working directory for LogBoost subprocess |
| `MAXMIND_DIR` | YES | `.` | `/mnt/logboost` | Path to .mmdb files |
| `THREAT_DB_DIR` | YES | `.` | `/mnt/logboost` | Path to threats.db |
| `MM_API` | NO | reads mm_api.txt | Set or use file mount | MaxMind API key |
| `LOGBOOST_LOG_LEVEL` | NO | `WARNING` | `WARNING` | Flask app log verbosity |

**Critical:** `SECRET_KEY` with the default `os.urandom(24)` generates a new key on every container start. Every restart invalidates all user sessions. Always set this explicitly.

---

## SSL Termination Options

### Option A: SSL in Container (Recommended for Simple Deployment)

Run Gunicorn with SSL certificates bound directly:

```bash
CMD ["gunicorn", \
     "--bind", "0.0.0.0:8443", \
     "--certfile", "/certs/server.crt", \
     "--keyfile", "/certs/server.key", \
     "--workers", "4", \
     "--timeout", "360", \
     "app:app"]
```

Mount certs:
```bash
-v /etc/ssl/logboost:/certs:ro \
-p 8443:8443
```

### Option B: Reverse Proxy on Host (Recommended for Multi-Service Deployments)

Run Nginx or Caddy on the host, proxy to container on `127.0.0.1:8000`.

```bash
# Container: plain HTTP, only accessible from localhost
-p 127.0.0.1:8000:8000
```

Nginx config on host:
```nginx
server {
    listen 443 ssl;
    ssl_certificate /etc/ssl/certs/logboost.crt;
    ssl_certificate_key /etc/ssl/private/logboost.key;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 360s;
    }
}
```

**Choose Option A** if: single service, simple deployment, no existing web server on host.
**Choose Option B** if: existing Nginx/Caddy on host, or multiple services sharing port 443.

---

## Patterns to Follow

### Pattern 1: Non-Root User

**What:** Run the container process as a non-root user.
**When:** Always in production.
**Why:** If the container process is compromised, root in the container can escape to host root on older Docker setups.

```dockerfile
RUN groupadd -r logboost && useradd -r -g logboost logboost
# ... copy files, set ownership ...
USER logboost
```

**Constraint with volume mounts:** Files mounted from host must be readable by the container user. Either:
- Set host file permissions to allow world-read (acceptable for non-secret files like `.mmdb`)
- Add container user GID to host groups
- Run with `--user $(id -u):$(id -g)` matching a host user that owns the files

### Pattern 2: Separate Config from Code

**What:** All environment-specific values via environment variables, never hardcoded.
**When:** Always.
**Applies to:** `SECRET_KEY`, `LOGBOOST_PATH`, `MAXMIND_DIR`, `THREAT_DB_DIR`, `LOGBOOST_WORKDIR`.

The codebase already follows this pattern correctly. The Dockerfile must not introduce hardcoded paths.

### Pattern 3: Gunicorn Config File over CLI Flags

**What:** Use `gunicorn.conf.py` instead of long CLI invocations.
**Why:** Easier to version, document, and modify without Dockerfile changes.

```dockerfile
CMD ["gunicorn", "--config", "gunicorn.conf.py", "app:app"]
```

### Pattern 4: Ephemeral Session Directories

**What:** `uploads/` and `output/` are per-session and ephemeral.
**Why:** These are not shared with the LogBoost binary in the current architecture — the binary is invoked with explicit `-logdir` and `-outputdir` pointing to the session directories inside the container. They do not need to be host volumes.
**Implication:** Session files are lost on container restart, which is correct behavior.

### Pattern 5: Health Check Endpoint

**What:** A `GET /health` route that returns 200 when the app is ready.
**When:** Required for Docker health checks, load balancers, restart policies.

```python
# Add to app.py
@app.route('/health')
def health():
    return {'status': 'ok'}, 200
```

---

## Anti-Patterns to Avoid

### Anti-Pattern 1: Baking Secrets into Image

**What:** Setting `SECRET_KEY`, API keys, or database credentials in the Dockerfile with `ENV`.
**Why bad:** Secrets are visible in `docker inspect`, image layers, and registries.
**Instead:** Pass at runtime via `-e` flags or a secrets manager. Use `.env` files only locally, never committed.

### Anti-Pattern 2: Running as Root

**What:** Not setting `USER` in Dockerfile, defaulting to root.
**Why bad:** Security risk; process escape gives host root.
**Instead:** Always create and switch to a non-root user.

### Anti-Pattern 3: Including Development Files in Image

**What:** Copying `tests/`, `__pycache__/`, `*.pyc`, docs, `.planning/` into the image.
**Why bad:** Bloats image size; exposes internal documentation and test infrastructure.
**Instead:** Comprehensive `.dockerignore`.

### Anti-Pattern 4: Mounting the Entire Host Directory

**What:** `-v /opt/logboost:/mnt/logboost` mounts everything, including logboost.log and binary.
**Why bad:** Overly broad mounts expose more of the host filesystem than needed.
**Instead:** Mount individual files explicitly. More verbose but more secure.

### Anti-Pattern 5: Gunicorn Timeout Shorter than LogBoost Timeout

**What:** Gunicorn `--timeout 30` while `subprocess.run(..., timeout=300)` is used.
**Why bad:** Gunicorn kills the worker after 30 seconds; LogBoost never finishes; silent failure or 502 error.
**Instead:** Gunicorn timeout must exceed the subprocess timeout. Set Gunicorn `timeout=360`.

### Anti-Pattern 6: Single requirements.txt Copy Late in Dockerfile

**What:** Copying `requirements.txt` after `COPY . .` (copying all source first).
**Why bad:** Any source code change invalidates the pip install cache layer.
**Instead:** Copy `requirements.txt` and run pip install before copying application source.

### Anti-Pattern 7: Using `osurandom(24)` as Default Secret Key

**What:** Relying on the code's `os.urandom(24)` default for `SECRET_KEY`.
**Why bad:** Every container restart generates a new secret key, invalidating all active sessions.
**Instead:** Always set `SECRET_KEY` as an environment variable with a stable, long random value.

---

## Build Order Implications for Roadmap

### Phase Dependencies

The following sequence is forced by technical dependencies:

```
1. .dockerignore           (required before any build attempt)
     │
     ▼
2. Dockerfile              (defines the build)
     │
     ▼
3. Health endpoint (/health) (required by HEALTHCHECK in Dockerfile)
     │
     ▼
4. Environment variable audit (all env vars must be documented before docker run)
     │
     ▼
5. gunicorn.conf.py        (replaces CLI flags, must exist before CMD references it)
     │
     ▼
6. Volume mount strategy   (requires knowing all host paths)
     │
     ▼
7. SSL configuration       (last, depends on deployment target choice)
     │
     ▼
8. docker-run.sh / docs    (documents the fully assembled command)
```

### What Must Be Decided Early

1. **SSL approach** (in-container vs reverse proxy) — determines port mapping and Gunicorn command.
2. **Host directory layout** (`/opt/logboost` vs other) — determines all volume mount paths.
3. **LogBoost binary path on host** — determines `LOGBOOST_PATH` value.
4. **User/permission strategy** — determines whether non-root user works with existing file permissions.

### What Can Be Added Incrementally

- Additional environment variables (can add `-e` flags without rebuilding)
- Gunicorn worker count tuning (change `gunicorn.conf.py`, rebuild)
- Log forwarding (add log driver to `docker run`, no rebuild needed)

---

## Scalability Considerations

| Concern | Single Container (Current Target) | Multi-Container (Future) |
|---------|-----------------------------------|--------------------------|
| SQLite contention | No issue — single process group | Problem — SQLite is file-locked, migrate to PostgreSQL |
| Session file sharing | No issue — per-container ephemeral | Problem — uploads/output not shared across containers |
| LogBoost binary | Bind-mounted from host | Each host needs binary; or API service wrapper |
| Cache file contention | Write-through host mounts work | Multiple containers writing to same cache = corruption risk |

The current single-container design is appropriate for the stated scope. SQLite and file-based caches do not support horizontal scaling. This is documented, not a defect.

---

## Sources

- Codebase inspection: `C:/Users/Joe/Documents/GitHub/logboost-web/app.py` — env var usage, subprocess calls, path configuration (HIGH confidence — direct inspection)
- Codebase inspection: `C:/Users/Joe/Documents/GitHub/logboost-web/admin.py` — `LOGBOOST_WORKDIR`, `DB_PATH`, feed_config paths (HIGH confidence — direct inspection)
- Codebase inspection: `C:/Users/Joe/Documents/GitHub/logboost-web/requirements.txt` — confirmed Gunicorn in deps (HIGH confidence)
- PROJECT.md: `.planning/PROJECT.md` — confirmed scope, out-of-scope items, constraints (HIGH confidence)
- Docker layer caching principles: established Docker best practice, consistent with official Docker documentation (HIGH confidence)
- Gunicorn configuration: established patterns, consistent with Gunicorn official docs (HIGH confidence)
- Non-root container user: Docker security best practice (HIGH confidence)
