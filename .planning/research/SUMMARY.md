# Project Research Summary

**Project:** LogBoost Web — Flask Frontend Containerization
**Domain:** Docker containerization of an existing Flask 3.0+ / Gunicorn web application
**Researched:** 2026-02-25
**Confidence:** HIGH

---

## Executive Summary

LogBoost Web is a Flask 3.0+ application that wraps a host-resident Linux binary (the LogBoost enrichment engine) in a web UI. Containerizing it is well-scoped but non-trivial: the app depends on external files managed by the host (MaxMind GeoIP databases, threat intel DB, cache files, feed config, the binary itself), and the container must reach all of these via volume mounts while keeping the image small and free of secrets. The core pattern is a single Docker container running Gunicorn, with all host-managed data mounted read-only (or read/write for cache files and the admin DB) from a canonical host directory such as `/opt/logboost`.

The recommended stack is `python:3.12-slim` + Gunicorn 21+ with a `sync` worker class (or `gthread` to mitigate SQLite write contention), a two-stage Dockerfile for lean builds, and a comprehensive `.dockerignore` that excludes the `.mmdb` databases, SQLite files, cache files, and secrets before they can be baked into the image. SSL termination can live either inside Gunicorn (simplest for a local single-host deployment) or at an Nginx reverse proxy on the host (preferred if the host already runs Nginx). The `/health` endpoint already exists in `app.py` and is ready to serve the Docker `HEALTHCHECK`.

The highest-risk pitfalls are all addressable in Phase 1 and are entirely non-novel: missing `SECRET_KEY` (every restart kills sessions), insufficient Gunicorn timeout (kills LogBoost enrichment jobs at 30s when they can take 300s), SQLite write contention with multiple workers, and an absent or incomplete `.dockerignore` that balloons the image with gigabytes of data files and leaks credentials. None of these require discovery during implementation — they are known, prevention is documented, and they must be addressed before the first `docker run`.

---

## Key Findings

### Recommended Stack

The existing codebase has everything needed: Gunicorn is already in `requirements.txt`, the `/health` endpoint is coded in `app.py:636`, all environment variables (`SECRET_KEY`, `FLASK_ENV`, `LOGBOOST_PATH`, `MAXMIND_DIR`, `THREAT_DB_DIR`) are already wired. The Dockerfile is the only artifact that does not yet exist. The base image must be `python:3.12-slim` (not Alpine — several dependencies including `dnspython`, `python-whois`, and `iocextract` have C-extension dependencies that require glibc). A two-stage build (builder stage installs `build-essential` + pip deps; runtime stage copies installed packages) keeps the final image at ~130MB instead of ~900MB.

Gunicorn must use the `sync` worker class (the app uses synchronous subprocess calls to the LogBoost binary — async workers would require a full audit). Worker count must be set to `1` with threads (`--worker-class gthread --threads 4`) to avoid SQLite write contention, or `1` sync worker for maximum simplicity. The gunicorn timeout must be at least 310 seconds to accommodate the app's 300-second subprocess timeout.

**Core technologies:**

| Technology | Tag / Version | Purpose | Confidence |
|------------|--------------|---------|------------|
| `python:3.12-slim` | Match codebase (3.12.12) | Container base OS + Python runtime | MEDIUM |
| gunicorn | `>=21.0.0` (already in requirements) | Production WSGI server | HIGH |
| SSL termination | Gunicorn `--certfile/--keyfile` (Option A) or Nginx on host (Option B) | HTTPS | MEDIUM |
| Docker `HEALTHCHECK` | `GET /health` (already exists) | Container health signaling | HIGH |
| Non-root user | UID 1000 `logboost` | Security hardening | HIGH |

See `.planning/research/STACK.md` for full rationale, alternatives considered, and open questions.

---

### Expected Features

All table-stakes features map directly to Dockerfile or runtime configuration choices — there is no net-new application code required except possibly adding `ProxyFix` middleware if Nginx reverse proxy is chosen.

**Must have (table stakes):**
- Non-root user in Dockerfile — running as root is a critical security flaw
- Gunicorn as CMD entrypoint (not `python app.py`) — dev server exposes debugger
- `FLASK_ENV=production` via env var — gates `SESSION_COOKIE_SECURE=True` in app.py:62
- `SECRET_KEY` injected at runtime — default `os.urandom(24)` invalidates sessions on restart
- Volume mount: `logboost_admin.db` to `/app/logboost_admin.db` — survives container restarts
- Volume mounts: backend files (`.mmdb`, `threats.db`, caches, `feed_config.json`, `mm_api.txt`) — all under `/mnt/logboost/` inside container
- Volume mount: LogBoost binary to `/usr/local/bin/logboost:ro` — required for enrichment
- `LOGBOOST_PATH=/usr/local/bin/logboost` env var — matches mount path
- Docker `HEALTHCHECK` targeting existing `/health` endpoint
- Comprehensive `.dockerignore` — prevents GBs of data files and secrets entering image
- `EXPOSE 8000` (or 8443 for SSL-in-container variant)
- Gunicorn `--timeout 310` — matches 300s subprocess timeout in `app.py`

**Should have (operational quality):**
- `gunicorn.conf.py` config file — cleaner than CLI flags, version-controlled
- Gunicorn logs to stdout/stderr — visible in `docker logs`, not lost on restart
- `--restart unless-stopped` in docker run — automatic recovery
- `docker-run.sh` helper script — documents the full run command for operators
- `.env.example` — documents required env vars without committing actual secrets
- Two-stage Dockerfile build — smaller image, separates build tools from runtime
- `tldextract` cache pre-population in Dockerfile `RUN` layer — prevents runtime PermissionError

**Defer to post-MVP:**
- Read-only container filesystem (`--read-only`) — worthwhile hardening but requires mapping all writable paths
- Structured JSON access logging — useful if logs are ingested by LogBoost; not needed day one
- Pinned image digest (`python:3.12-slim@sha256:...`) — good hygiene, low urgency
- `WAL` mode on SQLite — reduces contention if multi-worker config is used later

See `.planning/research/FEATURES.md` for feature dependency graph and project-specific observations.

---

### Architecture Approach

The architecture is a single container running Flask under Gunicorn. The LogBoost binary remains on the host and is bind-mounted (read/execute) into the container. All host-managed backend files are mounted under a canonical `/mnt/logboost/` path inside the container. The admin SQLite database is persisted via a bind mount to the host. Session upload and output directories (`/app/uploads/`, `/app/output/`) are container-local and ephemeral — they do not need to be host volumes.

A two-stage Dockerfile separates build concerns from runtime. The entrypoint is `gunicorn --config gunicorn.conf.py app:app`. SSL terminates either in Gunicorn (simpler; mount certs at `/certs/`) or at host Nginx (more flexible; container exposes `127.0.0.1:8000` only).

**Major components and responsibilities:**

| Component | Lives Where | Access Mode |
|-----------|------------|-------------|
| Flask + Gunicorn | Container | — |
| LogBoost binary | Host (bind-mounted into container) | Read/Execute |
| `logboost_admin.db` | Container volume → host | Read/Write |
| MaxMind `.mmdb` databases | Host mount at `/mnt/logboost/` | Read-only |
| `threats.db` | Host mount at `/mnt/logboost/` | Read-only |
| Cache files (dns, idb, whois) | Host mount at `/mnt/logboost/` | Read/Write |
| `feed_config.json` | Host mount at `/mnt/logboost/` | Read/Write |
| `mm_api.txt` | Host mount at `/mnt/logboost/` | Read-only (prefer `MM_API` env var) |
| `uploads/`, `output/` | Container-local (ephemeral) | Read/Write |

**Build order (forced by dependencies):**

```
1. .dockerignore          → must exist before first docker build
2. Dockerfile             → defines the image
3. gunicorn.conf.py       → referenced by CMD in Dockerfile
4. Environment var audit  → all vars must be documented before docker run
5. Volume mount strategy  → requires knowing all host paths
6. SSL configuration      → last; depends on deployment choice
7. docker-run.sh / docs   → documents the assembled command
```

See `.planning/research/ARCHITECTURE.md` for full Dockerfile example, volume mount strategy, and data flow diagram.

---

### Critical Pitfalls

All critical pitfalls affect Phase 1 (Dockerfile + configuration). None require discovery during implementation — they are known and preventable.

1. **`SECRET_KEY` not set → sessions reset on every restart** — Always inject via `-e SECRET_KEY=$(openssl rand -hex 32)` or `--env-file`. Never rely on the `os.urandom(24)` default. Generate once, store securely, inject at runtime.

2. **Gunicorn timeout shorter than LogBoost subprocess timeout** — `app.py` uses `subprocess.run(..., timeout=300)`. Gunicorn's default is 30 seconds. Set `--timeout 310` in gunicorn config. Symptom without this fix: all large-file enrichments return 502 after exactly 30 seconds.

3. **SQLite write contention with multiple Gunicorn workers** — The app uses raw `sqlite3.connect()` with no connection pooling. Multiple workers cause `sqlite3.OperationalError: database is locked`. Fix: set `--workers 1 --worker-class gthread --threads 4` in gunicorn config. Do not use default worker count.

4. **`.dockerignore` absent → GBs of data baked into image, secrets leaked** — Without it, `docker build` context includes `.mmdb` databases (hundreds of MB), `logboost_admin.db` (password hashes), `mm_api.txt` (API credentials), all upload/output session data. Write `.dockerignore` before the first `docker build`. See ARCHITECTURE.md for the full exclusion list.

5. **`LOGBOOST_PATH` not set to mount path → enrichment silently fails** — The default is `'LogBoost'` (bare name), which resolves to nothing inside the container. Must be set to the absolute bind-mount path (e.g., `/usr/local/bin/logboost`). The health endpoint at `/health` already reports `logboost_available` — use this to validate after first run.

6. **Volume mount path mismatch → GeoIP and threat intel silently absent** — `MAXMIND_DIR` defaults to `'.'` which is `/app` in the container, not where the mounts land. Define a canonical mount root (`/mnt/logboost/`) and set all env vars to paths under it. Add a startup validation that checks each required path exists before gunicorn starts.

See `.planning/research/PITFALLS.md` for full pitfall catalog including moderate and minor pitfalls (15 total).

---

## Implications for Roadmap

The entire containerization project fits in 2-3 phases. There is no novel technical ground here — all patterns are well-established. The phases are ordered by dependency: you cannot test volume mounts without a working Dockerfile; you cannot validate SSL without working mounts; you cannot harden what doesn't yet run.

### Phase 1: Core Container (Dockerfile + Config + Must-Have Features)

**Rationale:** Everything else depends on a working image. All critical pitfalls live here. This phase is the highest risk because mistakes (wrong gunicorn config, missing `.dockerignore`, no `SECRET_KEY`) create hard-to-debug silent failures.

**Delivers:** A buildable, runnable Docker image with correct security defaults.

**Includes:**
- `.dockerignore` (write this first, before any build attempt)
- Two-stage `Dockerfile` with `python:3.12-slim`, non-root user, `HEALTHCHECK`
- `gunicorn.conf.py` with `workers=1`, `worker_class=gthread`, `threads=4`, `timeout=310`, stdout/stderr logging
- `tldextract` cache pre-population in `RUN` layer
- `.env.example` documenting all required env vars
- `docker-run.sh` with full mount and env var command

**Pitfalls this phase must avoid:**
- Pitfall 3: SECRET_KEY — require in env, document in .env.example
- Pitfall 4: Flask dev server — CMD must be gunicorn
- Pitfall 5: SQLite contention — workers=1 with gthread
- Pitfall 9: .dockerignore — write before first build
- Pitfall 10: Gunicorn timeout — set to 310s
- Pitfall 12: Non-root user — add USER logboost to Dockerfile
- Pitfall 14: Missing curl — install or use Python-based HEALTHCHECK

**Research flag:** SKIP — well-documented patterns, no research needed during planning.

---

### Phase 2: Volume Mount Validation + Environment Variable Wiring

**Rationale:** Volume mounts are the trickiest operational concern for this app. The binary, databases, caches, config files, and SQLite DB all come from the host. Incorrect paths cause silent data absence (GeoIP returns blank, threat intel returns zero hits). This phase validates the full mount strategy and confirms env var → path alignment before adding SSL complexity.

**Delivers:** A running container with enrichment fully functional end-to-end.

**Includes:**
- Complete `-v` mount flags for all host files, with `:ro` enforcement where appropriate
- Env var → container path mapping validation (LOGBOOST_PATH, MAXMIND_DIR, THREAT_DB_DIR, LOGBOOST_WORKDIR)
- Host directory pre-creation script (touch cache files, verify .mmdb files exist)
- Startup validation: check each required path exists before gunicorn starts
- Validation using `/health` endpoint to confirm `logboost_available: true`, mmdb dirs accessible

**Volume mount strategy:**

| Host Path | Container Path | Mode |
|-----------|---------------|------|
| `/usr/local/bin/logboost` | `/usr/local/bin/logboost` | `:ro` |
| `/opt/logboost-web/logboost_admin.db` | `/app/logboost_admin.db` | read/write |
| `/opt/logboost/*.mmdb` | `/mnt/logboost/` | `:ro` |
| `/opt/logboost/threats.db` | `/mnt/logboost/threats.db` | `:ro` |
| `/opt/logboost/*.cache` | `/mnt/logboost/` | read/write |
| `/opt/logboost/feed_config.json` | `/mnt/logboost/feed_config.json` | read/write |
| `/opt/logboost/mm_api.txt` | `/mnt/logboost/mm_api.txt` | `:ro` |

**Pitfalls this phase must avoid:**
- Pitfall 1: LOGBOOST_PATH must resolve to mounted binary path
- Pitfall 2: MAXMIND_DIR / THREAT_DB_DIR mismatch (silent blank results)
- Pitfall 7: uploads/ and output/ writable by non-root container user

**Research flag:** SKIP — volume mount strategy is fully defined by codebase inspection.

---

### Phase 3: SSL + Security Hardening

**Rationale:** SSL comes last because it depends on the deployment choice (Option A: certs in Gunicorn; Option B: Nginx reverse proxy). Security hardening can be layered on after the container is confirmed working.

**Delivers:** HTTPS-secured container with hardened configuration.

**Includes:**
- SSL approach decision: Option A (Gunicorn `--certfile`/`--keyfile` with mounted certs) or Option B (Nginx reverse proxy on host)
- If Option A: cert volume mount at `/certs/`, gunicorn CMD updated with cert flags, port 8443 exposed
- If Option B: Nginx config with `proxy_read_timeout 360s`, `ProxyFix` middleware added to `app.py`, container binds to `127.0.0.1:8000` only
- `FLASK_ENV=production` confirmed in env (gates `SESSION_COOKIE_SECURE=True`)
- Optional: `--read-only` container filesystem with explicit tmpfs for `/tmp`
- Optional: resource limits (`--memory`, `--cpus`)
- `--restart unless-stopped` for auto-recovery

**Open decision:** Option A vs Option B must be resolved before this phase begins. The primary driver is whether Nginx already runs on the host.

**Pitfalls this phase must avoid:**
- Pitfall 6: FLASK_ENV=production must be set; HTTPS must actually terminate where Flask expects it
- ProxyFix middleware must be added to app.py if Option B is chosen (current app.py does not have it — verify before implementation)

**Research flag:** SKIP for Option A. Flag for verification if Option B is chosen — ProxyFix integration in current app.py needs confirmation.

---

### Phase Ordering Rationale

- Phase 1 before Phase 2: Cannot test mount strategy without a working image to mount into.
- Phase 2 before Phase 3: Cannot validate SSL session cookie behavior without confirmed volume mounts (logboost_admin.db must persist across restarts for session testing).
- SSL last: Avoids HTTPS complexity while validating functional correctness; also defers the Option A vs B decision until the host environment is confirmed.
- No separate "security hardening" phase: Non-root user and `.dockerignore` are Phase 1 table stakes, not optional later additions.

### Research Flags

Phases needing deeper research during planning:
- None of the three phases require `/gsd:research-phase`. All patterns are well-documented and all technical decisions are grounded in codebase inspection. The only open question (ProxyFix for Option B) requires code verification, not external research.

Phases with standard patterns (can proceed without research):
- **Phase 1:** Standard Dockerfile patterns; gunicorn config is documented in requirements.txt
- **Phase 2:** Volume strategy fully specified in ARCHITECTURE.md and INTEGRATIONS.md
- **Phase 3:** SSL options well-documented; decision is operational, not technical

---

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Stack | MEDIUM | Base image tag confirmed correct; iocextract C-extension build requirement needs empirical verification during Phase 1 |
| Features | HIGH | Derived from direct codebase inspection (app.py, admin.py, requirements.txt); existing /health endpoint and env vars confirmed |
| Architecture | HIGH | Component boundaries and volume strategy derived from direct codebase inspection; data flow confirmed from subprocess call in app.py |
| Pitfalls | HIGH | All pitfalls tied to specific code patterns and line numbers; no inference required |

**Overall confidence:** HIGH

### Gaps to Address

1. **iocextract C-extension build requirements** — `iocextract>=1.16.1` may require `build-essential` in the builder stage. Confirm during Phase 1 first `docker build`. If compilation fails, add gcc to builder stage or switch to two-stage build that removes build tools after pip install. (LOW confidence on whether slim base has sufficient build deps)

2. **ProxyFix middleware in app.py** — If Option B (Nginx reverse proxy) is chosen for SSL, `app.py` needs Werkzeug's `ProxyFix` to correctly interpret `X-Forwarded-For` and `X-Forwarded-Proto` headers. Current `app.py` does not appear to include this. Verify before Phase 3 begins. (MEDIUM confidence — code inspection did not explicitly confirm absence)

3. **Python 3.12 patch version for image pinning** — `python:3.12-slim` will work; pinning to `python:3.12.12-slim` for reproducibility requires confirming that tag exists on Docker Hub. Low urgency for local deployment. (LOW confidence — needs Docker Hub check)

4. **LogBoost binary Linux architecture** — The repo contains `logboost.exe` (Windows). Confirm the host Linux binary exists at the intended mount path before Phase 2. The `.dockerignore` correctly excludes `*.exe`. (MEDIUM confidence — binary architecture for Linux host not verified)

5. **SSL approach decision (Option A vs B)** — Must be resolved before Phase 3. Primary driver: does Nginx already run on the host? If yes, Option B. If no, Option A (gunicorn SSL) is simpler. This is an operational question, not a technical one.

---

## Sources

### Primary (HIGH confidence — direct codebase inspection)

- `C:/Users/Joe/Documents/GitHub/logboost-web/app.py` — env var wiring, health endpoint (app.py:636), subprocess call pattern, SESSION_COOKIE_SECURE (app.py:62), subprocess timeout (300s)
- `C:/Users/Joe/Documents/GitHub/logboost-web/admin.py` — DB_PATH (hardcoded to app root), LOGBOOST_WORKDIR, feed_config paths, raw sqlite3 connections (lines 45-49)
- `C:/Users/Joe/Documents/GitHub/logboost-web/requirements.txt` — confirmed gunicorn>=21.0.0, iocextract>=1.16.1, python-whois>=0.9.0
- `.planning/codebase/CONCERNS.md` — confirmed: no connection pooling, debug=True flag (app.py:3207), cleanup_session() never called
- `.planning/codebase/INTEGRATIONS.md` — confirmed volume mount candidates, env var names
- `.planning/codebase/ARCHITECTURE.md` — confirmed subprocess call pattern, session directory layout

### Secondary (MEDIUM confidence — established patterns, training data)

- Docker/gunicorn/Flask containerization patterns (training data, cutoff Aug 2025) — standard practices verified against project specifics; WebFetch/WebSearch unavailable during research session
- `README.md` (existing Docker section) — placeholder Dockerfile using Python 3.11; used as baseline to identify gaps

### Tertiary (LOW confidence — needs verification before implementation)

- Docker Hub `python:3.12-slim` tag availability and digest — not verified (WebFetch unavailable)
- iocextract build requirements on slim images — requires test build to confirm
- Current gunicorn stable release (21.x or newer) — training data; verify before pinning

---

*Research completed: 2026-02-25*
*Ready for roadmap: yes*
