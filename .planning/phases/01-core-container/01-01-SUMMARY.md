---
phase: 01-core-container
plan: 01
subsystem: infra
tags: [docker, gunicorn, python, flask, sqlite, tldextract, iocextract]

# Dependency graph
requires: []
provides:
  - Single-stage Dockerfile building python:3.12-slim image at 270MB
  - .dockerignore allowlist excluding secrets, databases, and large binaries
  - gunicorn.conf.py with 1 worker, 4 threads, 310s timeout, stdout/stderr logging
  - Non-root user logboost (UID 1000) with correct file ownership
  - Pre-warmed tldextract PSL cache in image
  - Pre-created logboost_admin.db SQLite file for health check on first boot
  - HEALTHCHECK directive via curl at /health every 30s
affects: [01-02, 02-volumes, 03-ssl]

# Tech tracking
tech-stack:
  added: [gunicorn==25.1.0, python:3.12-slim, iocextract==1.16.1]
  patterns:
    - Allowlist .dockerignore (exclude *, include explicitly)
    - Single-stage build with build-essential purge to minimize image size
    - All gunicorn settings in gunicorn.conf.py (not CLI flags)
    - ENV vars provide sensible defaults; users override at runtime

key-files:
  created:
    - .dockerignore
    - gunicorn.conf.py
    - Dockerfile
  modified: []

key-decisions:
  - "build-essential purged after pip install in same RUN to stay under 500MB (270MB final)"
  - "Single-stage build (no multi-stage) per user locked decision"
  - "Allowlist .dockerignore pattern to prevent secret leaks"
  - "workers=1 mandatory for SQLite single-writer constraint"
  - "timeout=310 exceeds 300s subprocess timeout in app.py run_logboost()"

patterns-established:
  - "Allowlist .dockerignore: start with *, add ! exceptions for only needed files"
  - "gunicorn config in file not CLI flags for readability and maintainability"
  - "build-essential install+use+purge in single RUN for layer size reduction"

# Metrics
duration: 4min
completed: 2026-02-25
---

# Phase 1 Plan 1: Core Container Artifacts Summary

**Single-stage python:3.12-slim Dockerfile at 270MB with non-root logboost user, gunicorn gthread worker, pre-created SQLite DB, and curl HEALTHCHECK**

## Performance

- **Duration:** 4 min
- **Started:** 2026-02-25T22:42:17Z
- **Completed:** 2026-02-25T22:46:11Z
- **Tasks:** 2
- **Files modified:** 3

## Accomplishments
- .dockerignore allowlist pattern prevents secrets (mm_api.txt, *.mmdb, logboost_admin.db) from entering build context
- gunicorn.conf.py enforces 1 worker (SQLite write-lock safety), 4 threads, 310s timeout, stdout/stderr logging
- Dockerfile builds 270MB image (build-essential purged after pip install)
- logboost_admin.db pre-created during build so health check passes on first container boot
- tldextract Public Suffix List cache pre-warmed to avoid first-request latency

## Task Commits

Each task was committed atomically:

1. **Task 1: Create .dockerignore and gunicorn.conf.py** - `cdf6036` (chore)
2. **Task 2: Create Dockerfile** - `075b8b8` (feat)

**Plan metadata:** (docs commit below)

## Files Created/Modified
- `.dockerignore` - Allowlist pattern: excludes all, includes only app.py, admin.py, auth.py, security.py, requirements.txt, gunicorn.conf.py, routes/, templates/, static/
- `gunicorn.conf.py` - Gunicorn WSGI config: 1 worker, 4 threads (gthread), 310s timeout, 0.0.0.0:5000, stdout/stderr logging
- `Dockerfile` - Single-stage python:3.12-slim: apt+pip+purge in one RUN, non-root user, pre-warmed cache, pre-created DB, HEALTHCHECK

## Decisions Made
- **build-essential purge strategy:** Plan specified separate stable layer for apt and pip. Image came in at 698MB with separate layers. Merged apt+pip+purge into single RUN to reduce to 270MB while staying single-stage (user's locked decision). This trades layer cache efficiency for size compliance with the 500MB success criterion.
- **Single-stage confirmed:** iocextract's regex C-extension compiled successfully with build-essential. No multi-stage needed.
- **COPY requirements.txt before COPY . .:** Maintains pip layer cache when only app code changes.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Image size exceeded 500MB success criterion**
- **Found during:** Task 2 verification (`docker images logboost-web --format "{{.Size}}"` returned 698MB)
- **Issue:** Plan specified separate RUN for apt-get install and pip install (stable layer comment). With build-essential installed in a separate layer, all ~350MB of GCC toolchain was retained in the final image.
- **Fix:** Merged apt-get install + pip install + apt-get purge build-essential into a single RUN command. Build-essential is removed after compilation, reducing image from 698MB to 270MB. curl is retained (needed for HEALTHCHECK at runtime).
- **Files modified:** Dockerfile
- **Verification:** `docker images logboost-web --format "{{.Size}}"` returns 270MB
- **Committed in:** `075b8b8` (Task 2 commit)

---

**Total deviations:** 1 auto-fixed (Rule 1 - size constraint bug)
**Impact on plan:** Required merging apt and pip layers to meet 500MB success criterion. Trades per-layer caching granularity for size compliance. No scope creep.

## Issues Encountered
- None beyond the image size deviation documented above.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- Dockerfile builds cleanly at 270MB
- Container runs as logboost (UID 1000)
- gunicorn.conf.py validates as Python and configures correct worker settings
- logboost_admin.db pre-created; health check endpoint will pass on boot (pending /health route existence in app.py)
- Plan 01-02 should make admin.py read DB_PATH from LOGBOOST_DB_PATH env var (currently hardcoded to Path(__file__).parent / 'logboost_admin.db', which happens to match the ENV default /app/logboost_admin.db)

---
*Phase: 01-core-container*
*Completed: 2026-02-25*

## Self-Check: PASSED
