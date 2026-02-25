# Feature Landscape: Flask Docker Containerization

**Domain:** Production Docker container for Flask/Gunicorn web application
**Project:** LogBoost Web (logboost-web)
**Researched:** 2026-02-25
**Confidence:** HIGH — based on project source code analysis + verified Docker/Flask production patterns

---

## Context: What Already Exists

Before cataloguing features, note what the app already has that affects container requirements:

| Existing Feature | Docker Implication |
|-----------------|-------------------|
| `/health` endpoint (app.py:636) | Docker HEALTHCHECK target already coded |
| Gunicorn in requirements.txt | WSGI server ready — just needs config |
| `FLASK_ENV`, `SECRET_KEY`, `LOGBOOST_PATH`, `MAXMIND_DIR`, `THREAT_DB_DIR` env vars | Container env vars already wired |
| `uploads/` and `output/` as session temp dirs | Must be writable inside container |
| `logboost_admin.db` in app root | Must be on a persistent volume |
| `SESSION_COOKIE_SECURE` gates on `FLASK_ENV=production` | Must set this env var in container |
| SSRF protection, CSRF, httponly cookies | App-level security already in place |

---

## Table Stakes

Features that must exist for the container to function correctly in production. Missing any of these means the app is broken or insecure.

| Feature | Why Required | Complexity | Notes |
|---------|-------------|------------|-------|
| **Multi-stage Dockerfile** | Keeps image lean; separates build from runtime | Low | Python apps don't compile, but still removes pip cache, dev tools |
| **Non-root user** | Running as root in a container is a critical security flaw | Low | `useradd -r` pattern; set in Dockerfile |
| **Gunicorn as entrypoint** | Flask dev server is not safe for production (single-threaded, no timeout, debug mode risk) | Low | Already in requirements.txt; needs gunicorn.conf.py |
| **FLASK_ENV=production** | Gates `SESSION_COOKIE_SECURE=True` in app.py:62 — without this, session cookies are sent over plain HTTP even with HTTPS | Low | Set as Docker ENV or runtime -e flag |
| **SECRET_KEY via env var** | App falls back to `os.urandom(24)` which rotates on every container restart, breaking all sessions | Low | Must be stable value injected at runtime |
| **Volume mount: logboost_admin.db** | SQLite lives in app root; container restarts destroy it without a mount | Low | `-v /host/path/logboost_admin.db:/app/logboost_admin.db` |
| **Volume mounts: backend files** | `MAXMIND_DIR` (.mmdb files), `THREAT_DB_DIR` (threats.db), `LOGBOOST_PATH` (binary), caches (dns.cache, idb.cache, whois.cache), feed_config.json, mm_api.txt | Low | These are managed by host LogBoost backend |
| **Volume mount: LogBoost binary** | Binary lives on host; container calls it via subprocess | Low | Mount or bind the binary path into container |
| **Writable uploads/ and output/ dirs** | Session file processing writes here at runtime | Low | Either volume mount or ensure dir is writable by non-root user |
| **Docker HEALTHCHECK** | Enables Docker to detect unhealthy containers and restart them | Low | `/health` endpoint already exists at app.py:636 |
| **.dockerignore** | Prevents copying caches, .mmdb files (large), test data, secrets into image | Low | Reduces image size significantly |
| **Environment variable configuration** | All secrets and paths must come from env, not baked into image | Low | Pattern already established in app.py |
| **Exposed port declaration** | `EXPOSE 8000` (or whichever gunicorn port) makes port intent explicit | Low | No functional change, but required for documentation and compose compatibility |

---

## Differentiators

Features that are not strictly required but meaningfully improve operations, security, or maintainability. Appropriate for this project but not blockers.

| Feature | Value Proposition | Complexity | Notes |
|---------|------------------|------------|-------|
| **Gunicorn config file** | Centralized worker count, timeout, logging, bind address, access log format — beats long CLI flags | Low | `gunicorn.conf.py` pattern; easy to add |
| **Gunicorn worker tuning** | Default 1 worker is effectively single-threaded; `2 * CPUs + 1` rule for sync workers or `1` for async | Low | For file-processing workloads with blocking subprocess calls, gevent or threads help |
| **Structured access logging** | Gunicorn can log JSON access logs — useful if logs are ingested by LogBoost itself | Medium | Requires gunicorn log format config |
| **SSL termination in container** | Terminate HTTPS directly in Gunicorn with cert/key volume mount — eliminates need for reverse proxy | Medium | Gunicorn supports `--certfile` and `--keyfile`; certs must be volume-mounted |
| **Read-only filesystem** (`--read-only`)** | Hardens container by making filesystem immutable except explicit tmpfs/volume mounts | Medium | Requires careful mapping of all writable paths (uploads/, output/, db) |
| **Resource limits** | `--memory`, `--cpus` prevent a runaway file-processing job from starving the host | Low | Set at `docker run` time or in compose |
| **Graceful shutdown handling** | Gunicorn handles SIGTERM correctly — container stops cleanly without killing in-flight requests | Low | Default gunicorn behavior; just don't override STOPSIGNAL |
| **Build argument for Python version** | `ARG PYTHON_VERSION=3.12` makes future upgrades a one-line change | Low | Minor Dockerfile quality improvement |
| **Pinned base image digest** | `python:3.12-slim@sha256:...` prevents silent base image changes breaking production | Low | Trade-off: manual update discipline required |

---

## Anti-Features

Things to explicitly NOT include. Common mistakes teams make when Dockerizing Flask apps.

| Anti-Feature | Why Avoid | What to Do Instead |
|-------------|-----------|-------------------|
| **Flask dev server as entrypoint** (`python app.py` or `flask run`) | Single-threaded, enables debug mode, no timeout handling, not safe for any network exposure | Use `gunicorn` as the process |
| **Running as root** | Container breakout gives attacker root on host; violates principle of least privilege | Create dedicated non-root user in Dockerfile |
| **Baking secrets into image** (`ENV SECRET_KEY=mysecret` in Dockerfile) | Secret leaks into image layers, docker inspect, image registry | Inject secrets at runtime via `-e` or `--env-file` |
| **Baking .mmdb files into image** | MaxMind databases are 50-100MB each; balloons image size and goes stale | Volume mount from host where LogBoost backend manages them |
| **Baking logboost_admin.db into image** | Every container restart destroys all users, settings, audit logs | Volume mount the SQLite file from host |
| **Installing unnecessary packages** | Larger attack surface, larger image | `python:3.12-slim` base; only install what requirements.txt needs |
| **Leaving pip cache in image** (`pip install` without `--no-cache-dir`) | Adds 50-200MB of cache that serves no runtime purpose | `pip install --no-cache-dir -r requirements.txt` |
| **Copying entire project directory without .dockerignore** | Copies .mmdb files, test data, caches, output/, uploads/ into image | Write a thorough .dockerignore |
| **Hardcoding the gunicorn bind address to localhost** | Container's localhost is not reachable from outside — app becomes unreachable | Bind to `0.0.0.0:8000` inside container; map port at `docker run` time |
| **Using `latest` base image tag** | Unpredictable — a base image update can break your container on next build | Pin to `python:3.12-slim` at minimum; pin digest for maximum stability |
| **Copying source code as root ownership** | Files owned by root inside container are unreadable by non-root app user | Use `COPY --chown=appuser:appuser` or `chown` after copy |

---

## Feature Dependencies

```
Non-root user
  → Required before: Writable uploads/output dirs (chown must happen in Dockerfile)
  → Required before: Volume mounts work correctly (host path UID must match container UID)

FLASK_ENV=production
  → Enables: SESSION_COOKIE_SECURE=True (app.py:62)
  → Requires: HTTPS actually terminating (SSL in Gunicorn OR reverse proxy)
  → Without HTTPS: SESSION_COOKIE_SECURE blocks all session cookies → login breaks

SSL termination
  → If in Gunicorn: requires cert/key volume mounts before container start
  → If via reverse proxy: container only needs HTTP port; SSL lives outside container

SECRET_KEY stability
  → Requires: env var injection at runtime (not default os.urandom fallback)
  → Breaks: All active sessions on restart if not set

logboost_admin.db volume mount
  → Requires: Host directory exists with correct permissions before container start
  → Breaks: All users, settings, audit log on restart if not mounted

Health check endpoint
  → Already exists: /health (app.py:636) — checks binary, reports maxmind/threat dirs
  → Docker HEALTHCHECK command can use: CMD curl -f http://localhost:8000/health || exit 1
  → Requires: curl in image (add to Dockerfile) OR use wget or Python-based check

Backend binary access
  → Requires: LOGBOOST_PATH volume mount OR binary on host PATH mapped into container
  → Health check reports logboost_available — useful for debugging mount issues
```

---

## MVP Recommendation

For the first working production container, prioritize in this order:

1. **Dockerfile** with non-root user, slim base, .dockerignore, `--no-cache-dir`
2. **Gunicorn entrypoint** with bind `0.0.0.0:8000`, 2-4 workers, 120s timeout (file processing can be slow)
3. **FLASK_ENV=production** and **SECRET_KEY** injected via `--env-file`
4. **Volume mounts** for: `logboost_admin.db`, `uploads/`, `output/`, `MAXMIND_DIR`, `THREAT_DB_DIR`, `LOGBOOST_PATH`
5. **Docker HEALTHCHECK** using the existing `/health` endpoint
6. **SSL** — gunicorn `--certfile`/`--keyfile` with mounted certs (self-signed acceptable for local deployment)

Defer to post-MVP:
- **Gunicorn config file**: Nice to have, not blocking. Can start with CLI flags.
- **Read-only filesystem**: Worthwhile hardening but requires more volume mapping work; do after MVP validates mount strategy.
- **Structured JSON logging**: Valuable if log ingestion is planned; not needed day one.
- **Pinned image digest**: Good hygiene but low urgency for local deployment.

---

## Project-Specific Observations

These are specific findings from reading the logboost-web source code that affect feature decisions:

1. **`/health` is unauthenticated** — correct for Docker health checks. Exposes `logboost_path` and directory paths in the response; acceptable for local deployment, worth noting.

2. **Session temp files accumulate** — `uploads/{session_id}/` and `output/{session_id}/` are cleaned up on logout (auth_routes.py) but not on container restart. A volume mount means these survive restarts, which is fine; without a mount they're lost, also fine since they're ephemeral.

3. **`logboost_admin.db` path is hardcoded** — `DB_PATH = Path(__file__).parent / 'logboost_admin.db'` (admin.py). This means the database lives in `/app/logboost_admin.db` inside the container. The volume mount target must be this exact path.

4. **Subprocess isolation** — Gunicorn worker timeout must be generous (60-120s) because `run_logboost` spawns a subprocess that processes files synchronously. Default gunicorn timeout of 30s will kill in-flight log enrichment jobs.

5. **No healthcheck guards on external APIs** — `/health` checks LogBoost binary availability but not Shodan, CIRCL, or DNS connectivity. This is appropriate; external API failures should surface per-request, not block container health.

---

## Sources

- Source analysis: `/c/Users/Joe/Documents/GitHub/logboost-web/app.py` (health endpoint, env vars, session dirs)
- Source analysis: `/c/Users/Joe/Documents/GitHub/logboost-web/admin.py` (DB_PATH, auth)
- Source analysis: `/c/Users/Joe/Documents/GitHub/logboost-web/requirements.txt` (gunicorn, Flask 3.0+)
- Source analysis: `/c/Users/Joe/Documents/GitHub/logboost-web/auth.py`, `routes/auth_routes.py`
- Docker production patterns: HIGH confidence from verified Docker documentation knowledge
- Flask/Gunicorn production patterns: HIGH confidence — standard, well-established practices
- Gunicorn worker timeout behavior: HIGH confidence — documented gunicorn behavior for sync workers
