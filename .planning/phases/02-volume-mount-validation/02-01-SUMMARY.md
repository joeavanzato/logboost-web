---
phase: 02-volume-mount-validation
plan: 01
subsystem: infra
tags: [docker, docker-compose, entrypoint, bind-mounts, volume, startup-validation]

# Dependency graph
requires:
  - phase: 01-core-container
    provides: Dockerfile with non-root logboost user (UID 1000), /app working directory, gunicorn CMD
provides:
  - entrypoint.sh startup validation: hard-fail on /data not writable, warn-only for missing binary/MaxMind
  - /data directory tree in image: maxmind, intel, cache, config, db subdirs owned by logboost
  - ENTRYPOINT in Dockerfile: gunicorn runs as PID 1 via exec "$@" for proper signal handling
  - docker-compose.yml: 8 bind mounts from /opt/logboost/ to correct container paths, all read-write
  - LOGBOOST_DB_PATH override to /data/db/logboost_admin.db for DB persistence across rebuilds
  - .env.example Phase 2 docs: volume paths, LOGBOOST_DB_PATH, host setup instructions
affects:
  - 02-02 (SSL/TLS) — compose service already defined, SSL plan adds nginx or certfile config
  - 03-ops — /data directory tree and bind mount layout established here

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "POSIX sh entrypoint (#!/bin/sh) — bash not available in python:3.12-slim"
    - "exec replacement pattern — exec \"$@\" makes gunicorn PID 1 for SIGTERM handling"
    - "Allowlist .dockerignore — all new files must be explicitly added to be included in build context"
    - "Compose environment overrides Dockerfile ENV defaults — DB path, data dirs set at compose level"

key-files:
  created:
    - entrypoint.sh
    - docker-compose.yml
  modified:
    - Dockerfile
    - .dockerignore
    - .env.example

key-decisions:
  - "entrypoint.sh uses /bin/sh not /bin/bash — bash unavailable in python:3.12-slim"
  - "Hard fail on /data not writable — user's locked decision; warns on missing binary/MaxMind only"
  - "All 8 volume mounts are read-write — user's locked decision; no :ro flags"
  - "LOGBOOST_DB_PATH overridden in compose environment to /data/db/logboost_admin.db — Dockerfile default /app/logboost_admin.db is lost on rebuild"
  - "/data mkdir + entrypoint COPY placed before USER logboost — requires root to create /data and chmod"

patterns-established:
  - "Pattern: /data/* subdirs pre-created in image as fallback — no mount = writable in-image dirs"
  - "Pattern: compose environment section overrides Dockerfile ENV for deployment-specific paths"

# Metrics
duration: 2min
completed: 2026-02-25
---

# Phase 2 Plan 1: Volume Mount Infrastructure Summary

**entrypoint.sh startup validation + /data directory tree in image + docker-compose.yml with 8 read-write bind mounts from /opt/logboost/ and LOGBOOST_DB_PATH override for DB persistence**

## Performance

- **Duration:** 2 min
- **Started:** 2026-02-26T02:18:42Z
- **Completed:** 2026-02-26T02:20:31Z
- **Tasks:** 2
- **Files modified:** 5

## Accomplishments

- Created entrypoint.sh with /bin/sh shebang (bash absent from python:3.12-slim), hard-fail on /data not writable, warn-only for missing binary/MaxMind, exec "$@" for PID 1 gunicorn
- Updated Dockerfile: /data/{maxmind,intel,cache,config,db} created and chowned to logboost before USER switch, ENTRYPOINT directive added before CMD
- Created docker-compose.yml with all 8 bind mounts (all read-write per locked decision), LOGBOOST_DB_PATH=/data/db/logboost_admin.db override, healthcheck, restart policy, and port with env default

## Task Commits

Each task was committed atomically:

1. **Task 1: entrypoint.sh + /data directory tree + ENTRYPOINT** - `81fba60` (feat)
2. **Task 2: docker-compose.yml + .env.example volume docs** - `6756fc6` (feat)

**Plan metadata:** _(to be committed)_ (docs: complete plan)

## Files Created/Modified

- `entrypoint.sh` - Startup validation: writable /data check (fail), binary/MaxMind checks (warn), exec gunicorn
- `docker-compose.yml` - Service definition: 8 bind mounts from /opt/logboost/, env overrides, healthcheck, restart
- `Dockerfile` - Added /data directory tree (5 subdirs, chowned to logboost), COPY entrypoint.sh, ENTRYPOINT directive
- `.dockerignore` - Added !entrypoint.sh to allowlist
- `.env.example` - Appended Phase 2 section: LOGBOOST_DB_PATH docs, HOST SETUP instructions, LOGBOOST_PORT docs

## Decisions Made

- **entrypoint.sh uses /bin/sh** — python:3.12-slim does not include bash; /bin/sh avoids "exec format error" on container start
- **Hard fail on /data not writable** — user's locked decision; container cannot function without persistent data directory
- **Warn-only for missing binary/MaxMind** — user's locked decision; app handles both gracefully at runtime
- **All mounts read-write** — user's locked decision; no :ro flags anywhere in docker-compose.yml
- **LOGBOOST_DB_PATH overridden in compose environment** — Dockerfile default /app/logboost_admin.db is baked into image and lost on rebuild; compose sets /data/db/logboost_admin.db for persistence
- **/data directories created before USER logboost** — root access required to mkdir /data and chown; entrypoint.sh COPY also happens as root before USER switch

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

- **Git Bash path expansion on Windows**: `docker run --rm logboost-web cat /entrypoint.sh` failed because Git Bash on Windows expands `/entrypoint.sh` to a Windows path before passing to Docker. Used `MSYS_NO_PATHCONV=1` prefix to suppress path conversion for verification commands. This is a local dev environment quirk; no code change needed.

## User Setup Required

Before running `docker compose up`, operator must:

```bash
sudo mkdir -p /opt/logboost/{maxmind,intel,cache,config,db,uploads,output}
sudo chown -R 1000:1000 /opt/logboost
cp .env.example .env
# Edit .env: set SECRET_KEY to a secure random value
```

See `.env.example` HOST SETUP section for full instructions.

## Next Phase Readiness

- Volume mount infrastructure complete; container starts with entrypoint validation
- docker-compose.yml is the primary operator interface from this point forward
- Phase 2 SSL plan (02-02) can now add to the existing compose service definition
- Remaining concern: SSL option (A: gunicorn certfile/keyfile vs B: Nginx reverse proxy) still unresolved — ProxyFix middleware may be needed if Option B is chosen

---
*Phase: 02-volume-mount-validation*
*Completed: 2026-02-25*

## Self-Check: PASSED
