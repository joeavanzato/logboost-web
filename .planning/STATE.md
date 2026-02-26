# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-02-25)

**Core value:** Flask frontend runs reliably in a production-ready Docker container with proper WSGI server, SSL support, and health monitoring
**Current focus:** Phase 2.1 - Bundle LogBoost Binary (Plan 1 complete, Plan 2 pending)

## Current Position

Phase: 2.1 of 4 (Bundle LogBoost Binary) — IN PROGRESS
Plan: 1 of 2 in phase 2.1
Status: In progress — 02.1-01 complete, 02.1-02 pending
Last activity: 2026-02-26 — Completed 02.1-01-PLAN.md (binary bundled in Dockerfile)

Progress: [█████████░] 71% (5 of 7 total plans)

_Note: Phase 3 plans not yet created; 7 total estimated (6 original + Phase 2.1 inserted with 2 plans)._

## Performance Metrics

**Velocity:**
- Total plans completed: 5
- Average duration: 4 min
- Total execution time: ~23 min

**By Phase:**

| Phase | Plans | Total | Avg/Plan |
|-------|-------|-------|----------|
| 01-core-container | 2/2 complete | 14 min | 7 min |
| 02-volume-mount-validation | 2/2 complete | ~7 min | ~3.5 min |
| 02.1-bundle-logboost-binary | 1/2 complete | 2 min | 2 min |

**Recent Trend:**
- Last 5 plans: 01-02 (10 min), 02-01 (2 min), 02-02 (~5 min), 02.1-01 (2 min)
- Trend: fast and stable

*Updated after each plan completion*

## Accumulated Context

### Decisions

Decisions are logged in PROJECT.md Key Decisions table.
Recent decisions affecting current work:

- **02.1-01:** LOGBOOST_VERSION pinned to prod_1_5_0 via ARG — user's locked decision; override with --build-arg for updates
- **02.1-01:** Binary at /usr/local/bin/logboost root-owned 0755; /data/bin added for runtime-updated binaries (logboost UID 1000 can write)
- **02.1-01:** Binary volume mount removed entirely from docker-compose.yml — 7 mounts remain (all data directories)
- **02.1-01:** unzip installed and purged in same RUN layer as binary download (matches build-essential pattern from 01-01)
- **PENDING:** SSL Option A (Gunicorn certfile/keyfile) vs Option B (Nginx reverse proxy) — must resolve before Phase 3. Driver: does Nginx already run on host?
- **02-02:** maxmind_available uses Path.glob('*.mmdb') — no new imports needed; Path already imported
- **02-02:** uploads_writable/output_writable use os.access(W_OK) — accurate for non-root container process
- **02-02:** New /health fields are strictly informational — do not affect 503/200 health logic
- **02-02:** .env created from .env.example (docker compose requires it); .env added to .gitignore
- **02-01:** entrypoint.sh uses /bin/sh not /bin/bash — bash unavailable in python:3.12-slim
- **02-01:** Hard fail on /data not writable; warn-only for missing binary/MaxMind — user's locked decisions
- **02-01:** All 7 volume mounts are read-write — no :ro flags in docker-compose.yml (binary mount removed in 02.1-01)
- **02-01:** LOGBOOST_DB_PATH overridden in compose environment to /data/db/logboost_admin.db — Dockerfile default lost on rebuild
- **02-01:** /data mkdir + entrypoint COPY placed before USER logboost — root required for /data creation and chmod
- **01-02:** Health unhealthy threshold = DB inaccessible only. Binary absence and external API failures produce 200 degraded, not 503.
- **01-02:** DB connection in /health always closed via try/finally — no leak on exception path.
- **01-02:** LOGBOOST_DB_PATH fallback = Path(__file__).parent preserves local dev behavior unchanged.
- **01-02:** Dockerfile must chown pre-created logboost_admin.db to logboost user — RUN steps execute as root, file permissions do not inherit from earlier chown -R.
- **01-01:** build-essential purged after pip install in single RUN — image at 270MB (under 500MB target).
- **01-01:** Single-stage build confirmed viable; iocextract C-extension compiled with build-essential.
- **01-01:** workers=1 enforced in gunicorn.conf.py (SQLite single-writer constraint).
- **01-01:** timeout=310 exceeds 300s subprocess timeout in app.py run_logboost().

### Pending Todos

- Operator must run host setup before first `docker compose up`:
  ```
  sudo mkdir -p /opt/logboost/{maxmind,intel,cache,config,db,uploads,output}
  sudo chown -R 1000:1000 /opt/logboost
  ```
  Note: `/opt/logboost/logboost` host path no longer needed (binary bundled in image)
  (documented in .env.example — cleanup of binary line is Plan 02 work)

### Roadmap Evolution

- **Phase 2.1 inserted** after Phase 2: Bundle LogBoost binary in Docker image (URGENT)
  - Reason: Docker image should include pre-bundled binary instead of requiring download
  - Setup page should detect Docker mode and show "Check for Updates" instead of "Download from GitHub"

### Blockers/Concerns

- **Phase 3 blocker:** SSL option (A vs B) still unresolved — must be decided before Phase 3 plans execute
  - Option A: Gunicorn `certfile`/`keyfile` args — simpler, no Nginx
  - Option B: Nginx reverse proxy — requires Nginx on host; adds ProxyFix middleware to app.py
- **Phase 3 concern:** ProxyFix middleware absent from app.py — required if Option B (Nginx) chosen

## Session Continuity

Last session: 2026-02-26
Stopped at: Completed 02.1-01-PLAN.md — binary bundled in Dockerfile, compose updated
Resume file: .planning/phases/02.1-bundle-logboost-binary/02.1-02-PLAN.md
