# Domain Pitfalls: Flask Docker Containerization

**Domain:** Flask 3.0+ web application containerization
**Project:** LogBoost Web
**Researched:** 2026-02-25
**Confidence:** HIGH — derived from direct codebase inspection and verified Docker/Flask patterns

---

## Critical Pitfalls

Mistakes that cause the container to not work at all, break security, or require a full rebuild.

---

### Pitfall 1: Binary Path Breaks Inside Container

**What goes wrong:** The `LOGBOOST_PATH` env var defaults to `'LogBoost'` (bare binary name). When the container runs, it inherits a PATH that has no knowledge of the host's binary location. `subprocess.run()` calls `FileNotFoundError`, enrichment silently fails, and the app returns error responses with no clear cause.

**Why it happens:** The binary lives on the HOST, not in the container image. The subprocess call in `run_logboost()` (app.py:251) uses `subprocess.run(cmd, ...)` where `cmd[0]` is the binary path. Inside the container, there is no such path unless explicitly configured.

**This project's exposure:** `LOGBOOST_BINARY = os.environ.get('LOGBOOST_PATH', 'LogBoost')` — the default value `'LogBoost'` will never resolve inside the container.

**Consequences:**
- All enrichment endpoints (`/enrich/text`, `/enrich/file`) return failure responses
- Error message `'LogBoost binary not found at: LogBoost'` is the only signal
- Health check can pass while core functionality is broken

**Prevention:**
- Mount the host binary into the container at a fixed absolute path (e.g., `/usr/local/bin/logboost`)
- Set `LOGBOOST_PATH=/usr/local/bin/logboost` in the Docker run command
- Validate the binary is present and executable at container startup — fail fast with a clear error message
- Never rely on the default value in production; treat it as developer-only fallback

**Detection (warning signs):**
- All `/enrich/*` requests return JSON with `error` key mentioning binary not found
- Container starts successfully but enrichment produces no output
- `docker run ... python -c "import subprocess; print(subprocess.run(['LogBoost'], capture_output=True))"` shows FileNotFoundError

**Phase:** Dockerfile / container entrypoint — address in the first phase that creates the Dockerfile.

---

### Pitfall 2: Volume Mount Path Mismatch Silently Corrupts Data

**What goes wrong:** The app reads backend files using paths derived from `MAXMIND_DIR`, `THREAT_DB_DIR`, and a hardcoded current directory default (`'.'`). If volume mounts land at different paths than these env vars specify, the app falls back silently: GeoIP enrichment returns no results, threat intel returns no matches. No exception is raised — the files simply aren't there.

**Why it happens:** `MAXMIND_DIR = os.environ.get('MAXMIND_DIR', '.')` — the default `.` resolves to the container's working directory at runtime. If the Dockerfile sets `WORKDIR /app` but the actual `.mmdb` files are mounted at `/data/maxmind`, the mismatch is invisible.

**This project's files that must be mounted:**
- `dns.cache`, `whois.cache`, `idb.cache` — LogBoost binary cache files
- `GeoLite2-City.mmdb`, `GeoLite2-ASN.mmdb`, `GeoLite2-Country.mmdb` — MaxMind databases
- `threats.db` — threat intelligence database
- `feed_config.json`, `mm_api.txt` — configuration files
- `logboost_admin.db` — SQLite admin database (if persistence across restarts is needed)

**Consequences:**
- GeoIP enrichment silently returns blank fields
- Threat intel lookups return zero hits
- LogBoost binary fails to find its own cache files and regenerates them in the container (ephemeral, lost on restart)

**Prevention:**
- Define a canonical mount root (e.g., `/data`) with a documented subdirectory layout
- Map ALL env vars (`MAXMIND_DIR`, `THREAT_DB_DIR`, `LOGBOOST_PATH`) to paths under this mount root
- At container startup, verify each required path exists with an explicit check before starting gunicorn
- Document the exact `docker run -v` flags required in the deployment docs

**Detection (warning signs):**
- Enrichment runs but all GeoIP fields are blank
- Threat intel panel shows 0 feeds loaded
- LogBoost binary regenerates cache files on every container start
- File sizes at mount target differ from expected (or are zero/missing)

**Phase:** Dockerfile + environment variable configuration — first phase.

---

### Pitfall 3: SECRET_KEY Regenerated on Every Container Restart

**What goes wrong:** `app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))` generates a new random key if `SECRET_KEY` is not set. Every container restart invalidates all active user sessions. Users are logged out mid-session. More critically, CSRF tokens signed with the old key are rejected, causing 400 errors on form submissions after a restart.

**Why it happens:** `os.urandom(24)` is called at import time, so each new container process gets a different key. In development this is invisible (server rarely restarts). In Docker it happens on every `docker restart` or container replacement.

**This project's exposure:** The default is explicitly `os.urandom(24)` — this is the "safe" Python-dev default but a production footgun.

**Consequences:**
- All users logged out on every restart
- CSRF validation failures on in-flight form submissions
- Admin sessions drop unexpectedly — operations in progress are interrupted

**Prevention:**
- Generate a strong `SECRET_KEY` once: `python -c "import secrets; print(secrets.token_hex(32))"`
- Pass it via `docker run -e SECRET_KEY=...` or store in an env file excluded from version control
- Never use the `os.urandom` default in production — document this as a hard requirement

**Detection (warning signs):**
- Users report being logged out after deployments
- CSRF errors (HTTP 400) appear in logs after container restarts
- Flask session cookie value changes between restarts

**Phase:** Environment variable configuration — first phase.

---

### Pitfall 4: Running Flask's Development Server Instead of Gunicorn

**What goes wrong:** The app's entry point (`app.py:3207`) calls `app.run(debug=True, ...)` when run directly. If the Dockerfile's `CMD` is set to `python app.py` instead of `gunicorn app:app`, the container runs the development server with debug mode enabled. This exposes the Werkzeug debugger console, allows arbitrary code execution by anyone who can reach the port, and handles only one request at a time.

**This project's exposure:** `debug=True` is already flagged in CONCERNS.md as a known issue (app.py:3207). A naive Dockerfile CMD would trigger this.

**Consequences:**
- Debug mode in production: Werkzeug interactive debugger accessible at `/__debugger__`
- Single-threaded: only one request handled at a time
- Hot-reload enabled: file changes restart server unpredictably
- No worker process management

**Prevention:**
- Dockerfile `CMD` must be: `["gunicorn", "--config", "gunicorn.conf.py", "app:app"]`
- Never use `CMD ["python", "app.py"]` in production Dockerfile
- Explicitly set `FLASK_ENV=production` as a Docker ENV or run-time env var — this triggers `SESSION_COOKIE_SECURE=True` and disables debug behavior
- Confirm gunicorn is in `requirements.txt` (it is: `gunicorn>=21.0.0`)

**Detection (warning signs):**
- Container logs show `* Running on http://...` with Werkzeug branding instead of gunicorn worker lines
- `/__debugger__` returns a page (not 404)
- Only one request processes at a time under load

**Phase:** Dockerfile CMD + gunicorn config — first phase.

---

### Pitfall 5: SQLite Database Write Contention with Multiple Gunicorn Workers

**What goes wrong:** Gunicorn spawns multiple worker processes (typically `2*CPU+1`). SQLite uses file-level locking. With multiple workers, concurrent writes to `logboost_admin.db` cause `sqlite3.OperationalError: database is locked` errors during cache writes, task updates, and audit logging. The app has no SQLAlchemy connection pooling — it creates raw `sqlite3.connect()` connections (admin.py:45-49).

**This project's exposure:** The CONCERNS.md already flags "No Connection Pooling" as a known bottleneck. Multiple gunicorn workers will hit this immediately.

**Consequences:**
- Random 500 errors on cache writes, audit log writes, and scheduled task updates
- WHOIS/DNS/Shodan cache writes fail silently — no performance benefit from caching
- Admin panel operations fail intermittently under any concurrent load

**Prevention:**
- Option A (recommended for this project): Run gunicorn with a single worker (`--workers 1`) and multiple threads (`--worker-class gthread --threads 4`). SQLite handles concurrent reads well; threads share one connection and avoid multi-process lock contention.
- Option B: Set `--workers 1` with the default sync worker. Simple, safe, appropriate for single-host local deployment.
- Do NOT use the default gunicorn worker count without addressing SQLite concurrency first
- Set `WAL` mode on the SQLite database (`PRAGMA journal_mode=WAL`) to allow one writer + multiple readers

**Detection (warning signs):**
- `sqlite3.OperationalError: database is locked` in container logs
- Intermittent 500 errors on `/api/*` endpoints under concurrent use
- Cache tables empty despite successful lookups

**Phase:** Gunicorn configuration — first phase. The gunicorn.conf.py must set workers explicitly.

---

### Pitfall 6: HTTPS/SSL Misconfiguration Breaks Session Security

**What goes wrong:** The app sets `SESSION_COOKIE_SECURE = os.environ.get('FLASK_ENV') == 'production'`. If `FLASK_ENV=production` is set but HTTPS is not actually terminating at the container (e.g., SSL is terminated at an upstream load balancer with HTTP to the container), browsers still set and send the secure cookie — but the path between the load balancer and container is unencrypted. Worse: if `FLASK_ENV` is NOT set, `SESSION_COOKIE_SECURE=False` is used, and session cookies are sent over plain HTTP even when the user sees HTTPS.

**Why it happens:** The distinction between "SSL terminates at the container" vs "SSL terminates at a reverse proxy" is often not considered when writing the Dockerfile.

**Consequences:**
- If SSL terminates at container: Flask needs to bind gunicorn with SSL certs directly, or use a sidecar (e.g., nginx)
- If SSL terminates upstream: Flask should set `PREFERRED_URL_SCHEME=https` and configure `ProxyFix` middleware — otherwise redirect URLs and cookie paths are wrong
- CSRF double-submit protection also depends on correct scheme detection

**Prevention:**
- Decide the SSL termination strategy before writing the Dockerfile:
  - Strategy A: Gunicorn + SSL certs in container (simpler for local single-host deployment)
  - Strategy B: Nginx reverse proxy in front (more flexible, standard production pattern)
- For Strategy A: pass cert paths to gunicorn via `--certfile` and `--keyfile`
- For Strategy B: add Werkzeug `ProxyFix` middleware and set `FORWARDED_ALLOW_IPS` env var
- Always set `FLASK_ENV=production` explicitly in Docker run command — never rely on the default

**Detection (warning signs):**
- Redirect URLs use `http://` instead of `https://` after login
- Session cookie missing `Secure` flag in browser DevTools
- CSRF errors on form submissions when accessed via HTTPS

**Phase:** SSL/HTTPS configuration — first phase.

---

## Moderate Pitfalls

Mistakes that cause incomplete functionality, data loss on restart, or operational pain.

---

### Pitfall 7: Upload and Output Directories Not Persisted

**What goes wrong:** The app creates `uploads/{session_id}/` and `output/{session_id}/` directories at runtime. If these directories are inside the container image filesystem (not mounted), they are lost on every container restart. Users lose in-progress enrichment results. Worse, if the app crashes mid-enrichment, the session directory may be in a partial state and there is no cleanup mechanism (CONCERNS.md notes `cleanup_session()` is never called).

**Prevention:**
- Mount both `uploads/` and `output/` as Docker volumes (or bind mounts to host paths)
- Or accept ephemeral session data (per-session results not persisted) and communicate this to users
- For a single-host deployment, bind mounts to host paths are the simplest approach

**Detection (warning signs):**
- Users report results disappearing after container restart
- `/results/page` returns 404 or empty after restart

**Phase:** Volume mount configuration — first phase.

---

### Pitfall 8: Unpinned Python Base Image Changes Under You

**What goes wrong:** `FROM python:3.12` in the Dockerfile resolves to the latest 3.12.x patch release at build time. A new patch (e.g., 3.12.5 → 3.12.6) can change behavior of stdlib modules. More problematically, `FROM python:3.12` vs `FROM python:3.12-slim` have very different sets of system libraries — slim images lack `gcc`, `libffi-dev`, and other build tools that some Python packages require at install time.

**This project's exposure:** `iocextract>=1.16.1` and `python-whois>=0.9.0` have compiled dependencies that may fail to build on slim images without extra apt packages.

**Prevention:**
- Use a pinned digest: `FROM python:3.12.x-slim` where x is a specific patch version
- Use the `-slim` variant but install required build dependencies in the same RUN layer, then remove them (`apt-get purge build-essential && apt-get autoremove`)
- Or use `-slim` and test the full `pip install -r requirements.txt` in CI before shipping

**Detection (warning signs):**
- `pip install` fails during `docker build` with `error: command 'gcc' failed`
- Build succeeds but `import iocextract` fails at runtime with shared library errors

**Phase:** Dockerfile base image selection — first phase.

---

### Pitfall 9: .dockerignore Omissions Bloat the Image and Leak Secrets

**What goes wrong:** Without a `.dockerignore`, the Docker build context includes everything in the project directory: hundreds of `intel/*.txt` threat feed files, all `uploads/` and `output/` session data, `.mmdb` GeoIP databases (hundreds of MB), `logboost_admin.db` (with hashed passwords and API keys), `logboost.exe` (the Windows binary), and `.idea/` IDE files. The resulting image is enormous and may contain secrets.

**This project's exposure:** The project root contains `GeoLite2-City.mmdb`, `GeoLite2-Country.mmdb`, `GeoLite2-ASN.mmdb` (large binary files), `logboost_admin.db`, `mm_api.txt` (API credentials), `feed_config.json`, and dozens of subdirectories with user data.

**Consequences:**
- Image size in the gigabytes instead of hundreds of MB
- `logboost_admin.db` baked into the image = password hashes and API keys in the image layer
- Build takes minutes instead of seconds due to context transfer

**Prevention:**
- Write a comprehensive `.dockerignore` before the first `docker build`:
  ```
  # Development
  .idea/
  __pycache__/
  *.pyc
  .git/

  # Runtime data (should be mounted, not baked in)
  uploads/
  output/
  logboost_admin.db
  *.log

  # Large data files (mount from host)
  *.mmdb
  intel/
  *.cache
  threats.db

  # Credentials and config (mount from host)
  mm_api.txt
  feed_config.json

  # Wrong binary (Linux binary is on host)
  logboost.exe
  LogBoost
  logboost

  # Test artifacts
  .planning/
  tests/
  ```

**Detection (warning signs):**
- `docker build` takes more than 30 seconds before any layer starts
- Image size is over 1GB
- `docker image inspect` shows `.db` files in layers

**Phase:** .dockerignore — must be done before first `docker build`.

---

### Pitfall 10: Gunicorn Timeout Too Short for Long-Running Enrichments

**What goes wrong:** The LogBoost binary has a 5-minute timeout in the Python code (`timeout=300`). Gunicorn's default worker timeout is 30 seconds. If gunicorn's `--timeout` is not set to at least 310 seconds, gunicorn kills the worker mid-enrichment (after 30 seconds), the subprocess is left orphaned, and the user gets a 502/503 response. The LogBoost process continues running on the host, burning resources, with no way to be tracked or stopped from the container.

**Prevention:**
- Set `--timeout 310` in gunicorn config (5 minutes + 10s buffer to match the subprocess timeout)
- Or better: implement async job processing (return job ID immediately, poll for results) — this is flagged in CONCERNS.md as a missing feature
- Consider `--graceful-timeout 30` separately from `--timeout` to allow in-flight requests to complete on shutdown

**Detection (warning signs):**
- Large file enrichments return 502/503 after exactly 30 seconds
- LogBoost process visible in `ps aux` on host after Flask reports failure
- Gunicorn logs show `[CRITICAL] WORKER TIMEOUT`

**Phase:** Gunicorn configuration — first phase.

---

### Pitfall 11: Health Check Tests Wrong Layer

**What goes wrong:** A naive health check pings `GET /` (the main page). The main page requires authentication (redirects to `/login`) and doesn't exercise the backend dependencies. A health check that returns 200 at `/` proves the Flask process is alive but not that gunicorn is correctly configured, that the binary is reachable, or that the database is writable.

**Prevention:**
- Implement a dedicated `/health` endpoint that:
  - Returns 200 JSON: `{"status": "ok", "binary": true/false, "db": true/false}`
  - Checks `os.path.isfile(LOGBOOST_BINARY)` — is the binary mount present?
  - Executes a trivial SQLite query (`SELECT 1`) — is the database accessible?
  - Does NOT require authentication
- Use this endpoint in the Dockerfile `HEALTHCHECK` directive:
  ```dockerfile
  HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1
  ```
- The health check should be a diagnostic tool, not just an uptime ping

**Detection (warning signs):**
- Container reports healthy but enrichment returns errors
- Health check URL requires login redirect (301) instead of returning 200

**Phase:** Health check endpoint implementation — first phase.

---

### Pitfall 12: Container Running as Root

**What goes wrong:** By default, Docker containers run as root (UID 0). This means the Flask/gunicorn process has root privileges inside the container. If an attacker exploits a vulnerability (path traversal, SSRF, or the subprocess binary path), they have root within the container. Volume-mounted host directories written by root inside the container create files owned by root on the host, potentially causing permission conflicts with the LogBoost backend.

**Prevention:**
- Add to Dockerfile:
  ```dockerfile
  RUN useradd -m -u 1000 appuser
  USER appuser
  ```
- Ensure volume mount directories on the host are writable by UID 1000 (`chown 1000:1000 /path/to/uploads`)
- Alternatively use `--user` flag in `docker run` without changing the Dockerfile

**Detection (warning signs):**
- `docker exec <container> whoami` returns `root`
- Files created by container in mounted volumes are owned by root on host

**Phase:** Dockerfile security hardening — first phase.

---

## Minor Pitfalls

Mistakes that cause annoyance or operational friction.

---

### Pitfall 13: Gunicorn Log Format Incompatible with Docker Log Drivers

**What goes wrong:** By default, gunicorn writes access logs to stdout and error logs to stderr in a non-JSON format. Docker captures stdout/stderr and routes them via the configured log driver. If access logs are not written to stdout (only to a log file), `docker logs` shows nothing useful. If error logs go to a file inside the container, they are lost on restart.

**Prevention:**
- Explicitly configure gunicorn: `--access-logfile -` (stdout) and `--error-logfile -` (stderr)
- Set `--log-level info` to avoid silent failures
- Do not write logs to files inside the container image filesystem

**Phase:** Gunicorn configuration — first phase.

---

### Pitfall 14: Missing `curl` or `wget` in Slim Image Breaks Health Check

**What goes wrong:** The Dockerfile `HEALTHCHECK` uses `curl` to hit the health endpoint. `python:3.12-slim` does not include `curl` by default. The health check fails with `/bin/sh: curl: not found`, the container is marked unhealthy, and orchestrators (if used later) may kill it.

**Prevention:**
- Add `RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*` to the Dockerfile
- Or use a Python-based health check script instead of curl: `CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')"`

**Phase:** Dockerfile — before or at health check implementation.

---

### Pitfall 15: `iocextract` and `tldextract` Cache Directories

**What goes wrong:** `tldextract` downloads and caches the Public Suffix List on first use, storing it in `~/.cache/python-tldextract/` inside the container. `iocextract` may also write cache files. If the container's home directory is read-only, these libraries fail on first request with a PermissionError. The error message doesn't mention Docker or volume mounts — it looks like a library bug.

**Prevention:**
- Either ensure the container's working user has a writable home directory
- Or pre-populate the tldextract cache during `docker build` by running `python -c "import tldextract; tldextract.extract('example.com')"` in a `RUN` layer
- Or set `TLDEXTRACT_CACHE` env var to a known-writable path in the container

**Phase:** Dockerfile build steps — discovered during first integration test.

---

## Phase-Specific Warnings

| Phase Topic | Likely Pitfall | Mitigation |
|-------------|---------------|------------|
| Dockerfile creation | Missing .dockerignore bakes in secrets and large data files (Pitfall 9) | Write .dockerignore before first build |
| Dockerfile creation | Python slim image missing build tools for iocextract/python-whois (Pitfall 8) | Test `pip install` in CI; add build deps in RUN layer |
| Dockerfile CMD | Using `python app.py` instead of gunicorn triggers debug mode (Pitfall 4) | Use gunicorn CMD from the start |
| Gunicorn config | Default worker count causes SQLite lock contention (Pitfall 5) | Set `--workers 1 --worker-class gthread --threads 4` |
| Gunicorn config | Default 30s timeout kills LogBoost enrichment jobs (Pitfall 10) | Set `--timeout 310` |
| Gunicorn config | Logs written to file not stdout, invisible in docker logs (Pitfall 13) | Use `--access-logfile - --error-logfile -` |
| Environment vars | SECRET_KEY not set causes session invalidation on restart (Pitfall 3) | Require SECRET_KEY in env; validate at startup |
| Environment vars | LOGBOOST_PATH not set to host binary mount path (Pitfall 1) | Require LOGBOOST_PATH in env; validate at startup |
| Volume mounts | MAXMIND_DIR / THREAT_DB_DIR mismatch causes silent data absence (Pitfall 2) | Startup validation script checks each path |
| Volume mounts | uploads/ and output/ ephemeral inside container (Pitfall 7) | Bind mount both to host paths |
| Health check | Health check endpoint tests Flask liveness, not binary availability (Pitfall 11) | Implement `/health` with binary + db checks |
| SSL/HTTPS | FLASK_ENV not set, SESSION_COOKIE_SECURE=False over HTTPS (Pitfall 6) | Explicitly set FLASK_ENV=production in docker run |
| Security hardening | Container runs as root, creates root-owned files on host mounts (Pitfall 12) | Add non-root USER to Dockerfile |
| Slim image | curl missing for HEALTHCHECK directive (Pitfall 14) | Install curl in RUN layer or use Python fallback |
| First integration test | tldextract cache write fails in container (Pitfall 15) | Pre-populate or configure TLDEXTRACT_CACHE |

---

## Sources

All findings derived from direct inspection of the LogBoost Web codebase combined with verified Flask and Docker production patterns.

- **Codebase files inspected:** `app.py`, `admin.py`, `requirements.txt`, `.planning/codebase/ARCHITECTURE.md`, `.planning/codebase/CONCERNS.md`, `.planning/codebase/INTEGRATIONS.md`, `.planning/codebase/STACK.md`
- **Confidence:** HIGH — pitfalls tied to specific line numbers and code patterns in this codebase
- **Flask/Gunicorn patterns:** Cross-referenced against Flask 3.0 docs and gunicorn 21.x configuration documentation (verified pre-training, stable patterns)
- **Docker patterns:** Standard containerization practices verified against Docker's official best practices documentation

---

*Pitfalls research: 2026-02-25*
