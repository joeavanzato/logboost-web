# Technology Stack: Docker Containerization

**Project:** LogBoost Web — Flask Frontend Containerization
**Researched:** 2026-02-25
**Research Type:** Stack Dimension — Docker containerization of existing Flask 3.0+ app

---

## Recommended Stack

### Base Image

| Technology | Tag | Purpose | Why |
|------------|-----|---------|-----|
| python | `3.12-slim` | Container base OS + Python runtime | Matches codebase runtime (Python 3.12.12). `slim` variant strips non-essential packages (compilers, man pages, locales) for a smaller attack surface. Smaller than `full`, larger than `alpine` but without alpine's musl libc compatibility issues with some Python C extensions. |

**Confidence: MEDIUM**

Rationale: The existing codebase runs on Python 3.12.12 (confirmed from `.planning/codebase/STACK.md`). The `slim` variant is the standard recommendation for production Python containers: small enough for fast pulls, compatible enough for packages with C extensions (dnspython, iocextract, pypdf). Alpine is explicitly NOT recommended here — `dnspython`, `python-whois`, and `iocextract` all have C-extension dependencies that require glibc, and Alpine's musl libc requires rebuilding wheels, adding build complexity for no meaningful size benefit in this case.

**Do not use:**
- `python:3.12-alpine` — musl libc incompatibilities with several dependencies; requires build tools in image
- `python:3.11-slim` — The README's existing placeholder uses 3.11, but the codebase is confirmed Python 3.12; mismatched versions create subtle bugs
- `python:3.12` (full) — Unnecessary size; ~900MB vs ~130MB for slim

**Verify before pinning:** Check `hub.docker.com/_/python` for the exact `3.12-slim` digest at build time. Consider pinning to `python:3.12.x-slim` (with patch version) for reproducible builds once the Python 3.12 patch version used in production is confirmed.

---

### WSGI Server

| Technology | Version | Purpose | Why |
|------------|---------|---------|-----|
| gunicorn | `>=21.2.0` (from requirements.txt: `>=21.0.0`) | Production WSGI HTTP server | Already a project dependency. Mature, battle-tested, Flask-idiomatic. No additional installation needed. |

**Confidence: HIGH** — gunicorn is already in `requirements.txt` and referenced in existing README deployment docs.

**Recommended gunicorn configuration:**

```
workers = 4                    # (2 * CPU cores) + 1 is common heuristic; 4 is reasonable for local deployment
worker_class = sync            # Default. Appropriate for this app: no async I/O, uses ThreadPoolExecutor internally
bind = 0.0.0.0:5000           # Or 0.0.0.0:443 if terminating SSL in container
timeout = 120                  # Raise from default 30s — LogBoost subprocess calls can take time for large files
keepalive = 5                  # Seconds to wait for next request on a keep-alive connection
accesslog = -                  # Log to stdout (Docker captures stdout/stderr)
errorlog = -                   # Log to stderr
loglevel = warning             # Matches LOGBOOST_LOG_LEVEL default; can be overridden by env var
forwarded_allow_ips = *        # If behind reverse proxy; required for SESSION_COOKIE_SECURE to work correctly
```

**Why `sync` worker class:** The app uses `ThreadPoolExecutor` for parallel enrichment and `subprocess` for LogBoost binary calls. These are I/O-bound but synchronous. The sync worker is correct here; switching to `gevent` or `guvicorn` (async) would require auditing all subprocess calls for coroutine safety — unnecessary complexity for a local deployment.

**Critical:** The `timeout` setting matters. `run_logboost()` in `app.py` executes a subprocess for potentially large CSV files. The default gunicorn timeout of 30 seconds will kill long-running enrichment jobs. Set to 120s minimum; expose as an environment variable so it can be tuned without rebuilding the image.

**Alternatives considered:**

| Alternative | Why Not |
|-------------|---------|
| uWSGI | More complex configuration; gunicorn is already established in this project |
| Waitress | Windows-native alternative; irrelevant for Linux container deployment |
| Flask dev server | Explicitly not for production; single-threaded, no timeout handling |

---

### SSL/TLS Termination

**Confidence: MEDIUM**

Two viable approaches for local Linux Docker deployment. Recommendation differs by use case:

#### Option A: Nginx Reverse Proxy on Host (RECOMMENDED for local deployment)

Run Nginx directly on the Linux host as a reverse proxy. Nginx handles SSL termination and forwards HTTP to the container on port 5000.

```
[HTTPS client] --> [Nginx on host :443] --> [Docker container :5000 HTTP]
```

**Why this is recommended:**
- Keeps the container simpler — no SSL cert management inside container
- Nginx handles cert renewal cleanly (certbot/Let's Encrypt or self-signed)
- Standard Linux deployment pattern; Nginx config is easy to maintain outside the container lifecycle
- Container restart doesn't affect SSL termination
- Works with self-signed certs for local/LAN use without modifying the container

**Flask app requirement:** When behind a proxy, set `FLASK_ENV=production` so `SESSION_COOKIE_SECURE=True` is activated. Also requires `ProxyFix` middleware if trusting `X-Forwarded-Proto` headers — verify `app.py` has this or add it.

**Confidence: MEDIUM** — Standard pattern, well-documented, but `ProxyFix` integration needs verification against current `app.py`.

#### Option B: SSL Inside Container (self-signed, simpler setup)

Pass cert/key files as volume mounts and configure gunicorn with `--certfile` and `--keyfile`.

```
gunicorn --certfile=/certs/cert.pem --keyfile=/certs/key.pem ...
```

**When to use:** Acceptable for LAN/localhost deployments where a self-signed cert is sufficient and you don't want to configure Nginx. Avoids the proxy complexity.

**Why not always:** gunicorn's SSL implementation is functional but not hardened for internet-facing use. Does not support TLS session resumption, HSTS, or OCSP stapling. If this ever moves beyond local deployment, this approach needs replacement.

**Confidence: HIGH** — gunicorn `--certfile`/`--keyfile` flags are well-established.

#### Decision Matrix

| Scenario | Recommendation |
|----------|---------------|
| LAN/localhost only, minimal setup | Option B (gunicorn SSL) |
| Production-grade local deployment | Option A (Nginx on host) |
| Internet-facing (future) | Option A mandatory |
| Already have Nginx on host | Option A |

---

### Health Checks

| Technology | Approach | Why |
|------------|----------|-----|
| Docker `HEALTHCHECK` instruction | HTTP GET to `/health` endpoint | Native Docker mechanism; integrates with `docker ps`, `docker inspect`, restart policies |
| Flask route `/health` | Returns `200 OK` with JSON status | Lightweight; confirms app process is alive and accepting connections |

**Confidence: HIGH** — Docker `HEALTHCHECK` is the standard pattern; no external dependencies needed.

**Recommended Dockerfile HEALTHCHECK:**

```dockerfile
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1
```

**Parameters explained:**
- `--interval=30s` — Check every 30 seconds; frequent enough to detect failures, not so frequent it generates noise
- `--timeout=10s` — If the check doesn't respond in 10s, it's considered failed
- `--start-period=15s` — Give the container 15 seconds to initialize before health checks count against the retries (gunicorn startup takes 2-5 seconds)
- `--retries=3` — Mark unhealthy after 3 consecutive failures (90 seconds of failure before action is taken)

**Requires `curl` in image:** The `python:3.12-slim` base does not include `curl`. Add to Dockerfile:

```dockerfile
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
```

**Alternative:** Use Python itself for the health check to avoid installing curl:

```dockerfile
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')" || exit 1
```

This avoids `curl` installation but is slightly more verbose and slower to start the Python interpreter. Either approach is valid; `curl` is the more conventional choice.

**Flask `/health` endpoint (to be implemented):**

```python
@app.route('/health')
def health():
    return jsonify({'status': 'ok'}), 200
```

A minimal health check is appropriate here. More complex checks (database connectivity, mounted volume accessibility) can be added but increase check complexity and failure surface.

---

### Volume Mounts

| Mount | Host Path | Container Path | Purpose |
|-------|-----------|---------------|---------|
| MaxMind databases | `<host>/path/to/mmdb/` | `/data/maxmind/` | GeoIP enrichment — read by LogBoost binary |
| Threat intelligence | `<host>/path/to/intel/` | `/data/intel/` | Threat feed data — read by LogBoost binary |
| Cache files | `<host>/path/to/caches/` | `/data/cache/` | `dns.cache`, `idb.cache`, `whois.cache` — written by LogBoost binary |
| Config files | `<host>/path/to/config/` | `/data/config/` | `feed_config.json`, `mm_api.txt` — read by LogBoost binary |
| LogBoost binary | `<host>/path/to/logboost` | `/usr/local/bin/logboost` | Linux binary — runs on host filesystem but executed via subprocess |
| SQLite database | `<host>/path/to/data/` | `/app/data/` | `logboost_admin.db` — persistent admin/user/cache data |
| Uploads (optional) | `<host>/path/to/uploads/` | `/app/uploads/` | Session upload files — persist across container restarts |
| Output (optional) | `<host>/path/to/output/` | `/app/output/` | Session output files — persist across container restarts |

**Confidence: HIGH** — Volume mount paths derived directly from project's `INTEGRATIONS.md` and `app.py` environment variable configuration.

**Critical considerations:**

1. **LogBoost binary architecture:** The LogBoost binary runs on the host Linux OS. When mounted into the container, the container must also be Linux/amd64 to execute it via subprocess. This is expected for a local Docker deployment on a Linux host.

2. **File permissions:** The container runs as a non-root user (see security section below). Host-mounted directories must be readable (and writable for cache/uploads/output) by the container user. Use `chown` on host paths or configure Docker volume permissions accordingly.

3. **SQLite database persistence:** `logboost_admin.db` should be mounted to persist user accounts and settings across container rebuilds. If not mounted, the database resets on every container replacement, losing all admin configuration.

4. **Environment variables for paths:** The app already uses env vars for paths (`LOGBOOST_PATH`, `MAXMIND_DIR`, `THREAT_DB_DIR`). Set these to match the container-internal mount paths at runtime, not at build time, so the image remains reusable.

---

### Supporting Libraries (No Changes Required)

All existing `requirements.txt` dependencies remain unchanged. The containerization adds no new Python dependencies.

**Verify at build time:** `iocextract>=1.16.1` and some transitive dependencies compile C extensions. Confirm `python:3.12-slim` has necessary build tools available, or pre-install:

```dockerfile
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && pip install --no-cache-dir -r requirements.txt \
    && apt-get remove -y gcc \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*
```

Alternatively, use a two-stage build: builder stage with gcc, final stage copies only the installed site-packages.

---

## Full Recommended Stack Summary

| Component | Choice | Version/Tag | Confidence |
|-----------|--------|-------------|------------|
| Base image | `python:3.12-slim` | Match codebase Python | MEDIUM |
| WSGI server | gunicorn | `>=21.0.0` (already in requirements) | HIGH |
| SSL termination | Nginx on host (Option A) or gunicorn `--certfile` (Option B) | — | MEDIUM |
| Health check | Docker `HEALTHCHECK` + Flask `/health` route | — | HIGH |
| Volume mounts | Docker `--volume` flags (no Compose) | — | HIGH |
| Worker class | `sync` | Default | HIGH |
| Container user | Non-root (UID 1000) | Security hardening | HIGH |

---

## Alternatives Considered

| Category | Recommended | Alternative | Why Not |
|----------|-------------|-------------|---------|
| Base image | `python:3.12-slim` | `python:3.12-alpine` | Alpine musl libc incompatibility with C-extension packages |
| Base image | `python:3.12-slim` | `python:3.12` (full) | Unnecessary size (~900MB vs ~130MB) |
| WSGI server | gunicorn | uWSGI | Not already in project; more complex config for no benefit here |
| WSGI server | gunicorn | Waitress | Windows-oriented; not idiomatic for Linux container deployment |
| SSL | Nginx on host | Caddy on host | Caddy is simpler to configure for HTTPS but less common on Linux servers; use if Nginx isn't already present |
| SSL | Nginx on host | SSL inside container | gunicorn SSL is functional but not hardened; Nginx on host is more maintainable |
| Health check | curl | wget | Either works; curl is conventional; `python:3.12-slim` includes neither by default |
| Worker class | sync | gevent | App uses synchronous subprocess calls; gevent requires full async audit |

---

## Installation Notes

**No new Python packages required.** gunicorn is already in `requirements.txt`.

Additional OS package needed in Dockerfile:

```bash
# For health check (choose one):
apt-get install -y --no-install-recommends curl    # if using curl-based HEALTHCHECK
# OR use Python stdlib urllib (no apt package needed)
```

**Build command:**

```bash
docker build -t logboost-web:latest .
```

**Run command skeleton (no Compose):**

```bash
docker run -d \
  --name logboost-web \
  -p 443:5000 \
  -e SECRET_KEY="$(openssl rand -hex 32)" \
  -e FLASK_ENV=production \
  -e LOGBOOST_PATH=/usr/local/bin/logboost \
  -e MAXMIND_DIR=/data/maxmind \
  -e THREAT_DB_DIR=/data/intel \
  -v /host/path/to/logboost:/usr/local/bin/logboost:ro \
  -v /host/path/to/mmdb:/data/maxmind:ro \
  -v /host/path/to/intel:/data/intel:ro \
  -v /host/path/to/cache:/data/cache \
  -v /host/path/to/config:/data/config:ro \
  -v /host/path/to/db:/app/data \
  logboost-web:latest
```

---

## Security Notes (Informing Dockerfile)

| Practice | Recommendation | Rationale |
|----------|---------------|-----------|
| Non-root user | `RUN useradd -m -u 1000 appuser && USER appuser` | Principle of least privilege; container processes should not run as root |
| Read-only mounts | Use `:ro` for all volume mounts the app only reads | Reduces blast radius if container is compromised |
| No secrets in image | All secrets via `-e` at runtime | API keys, SECRET_KEY must never be baked into the image |
| `.dockerignore` | Exclude `*.db`, `*.cache`, `*.mmdb`, `uploads/`, `output/`, `.env`, `.idea/` | Prevent sensitive files and runtime data from entering image layer |
| Minimal apt packages | `--no-install-recommends` + clean apt cache | Smaller attack surface, smaller image |

---

## Open Questions / Low Confidence Areas

1. **Exact Python 3.12 patch version for image pinning** — The codebase documents `3.12.12` but Docker Hub tags go by minor version (e.g., `python:3.12-slim`). Verify if `python:3.12.x-slim` tags exist for reproducibility. (LOW confidence — needs Docker Hub check)

2. **`iocextract` C-extension build requirements** — `iocextract` may require build tools at pip install time. This needs a test build to confirm whether `python:3.12-slim` provides sufficient build dependencies or if gcc must be installed. (LOW confidence — needs empirical verification)

3. **ProxyFix middleware** — If Nginx Option A is used, `app.py` needs Werkzeug's `ProxyFix` to correctly handle `X-Forwarded-For` and `X-Forwarded-Proto` headers. Current `app.py` does not appear to have this configured. (MEDIUM confidence — needs code verification)

4. **gunicorn worker count** — `4` workers is the README's existing recommendation. For a local single-user deployment, `2` workers may be sufficient. Worker count should be tunable via an environment variable. (MEDIUM confidence — depends on host hardware and concurrent user count)

5. **LogBoost binary Linux compatibility** — The binary at `logboost.exe` in the repo appears to be a Windows build. The Linux binary for host deployment is separate. Confirm the host Linux binary path before writing volume mount documentation. (MEDIUM confidence — noted from project context, but binary architecture not verified)

---

## Sources

| Source | Type | Confidence Basis |
|--------|------|-----------------|
| `.planning/codebase/STACK.md` | Project file | HIGH — confirmed Python 3.12.12, gunicorn 21.0.0+ |
| `.planning/PROJECT.md` | Project file | HIGH — confirmed requirements, out-of-scope items, constraints |
| `.planning/codebase/INTEGRATIONS.md` | Project file | HIGH — confirmed volume mount candidates, env vars |
| `.planning/codebase/ARCHITECTURE.md` | Project file | HIGH — confirmed subprocess calls, session directories |
| `requirements.txt` | Project file | HIGH — confirmed exact dependencies |
| `README.md` (existing Docker section) | Project file | MEDIUM — placeholder Dockerfile using outdated Python 3.11; used as baseline to improve |
| `app.py` | Project file | HIGH — confirmed env var configuration, session cookie settings |
| Docker/gunicorn/Flask knowledge | Training data (Aug 2025 cutoff) | MEDIUM — standard practices verified against project specifics; WebFetch/WebSearch unavailable during this research session |

**Note on research limitations:** WebFetch and WebSearch tools were unavailable during this research session. Official Docker Hub tags, current gunicorn release notes, and Flask Docker deployment guides could not be fetched to verify current versions. Recommendations are grounded in project-confirmed details and established conventions, but the following should be verified before implementation:
- Current `python:3.12-slim` tag availability on Docker Hub
- Current gunicorn stable release (21.x or newer)
- Flask 3.0+ Docker deployment guidance in official Flask docs

---

*Research completed: 2026-02-25*
