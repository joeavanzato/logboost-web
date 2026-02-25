# Roadmap: LogBoost Web Containerization

## Overview

Three phases take the existing Flask/Gunicorn application from no Docker artifacts to a
production-ready, HTTPS-secured container. Phase 1 produces a buildable, runnable image
with all critical pitfalls addressed. Phase 2 wires every host-managed file into the
container via volume mounts and validates end-to-end enrichment. Phase 3 adds SSL
termination and the documentation an operator needs to deploy from scratch.

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [ ] **Phase 1: Core Container** - Buildable, runnable image with correct security defaults and WSGI config
- [ ] **Phase 2: Volume Mount Validation** - All host files wired in; enrichment works end-to-end
- [ ] **Phase 3: SSL + Documentation** - HTTPS-secured container with complete operator runbook

## Phase Details

### Phase 1: Core Container
**Goal**: A Docker image can be built and started; the application serves requests under Gunicorn with all critical security defaults in place
**Depends on**: Nothing (first phase)
**Requirements**: CNTR-01, CNTR-02, CNTR-03, CNTR-04, WSGI-01, WSGI-02, WSGI-03, WSGI-04, ENV-01, ENV-02, ENV-03, ENV-04, HLTH-01, HLTH-02, HLTH-03
**Success Criteria** (what must be TRUE):
  1. `docker build` completes without error and produces an image under 500MB
  2. `docker run` starts the container and Gunicorn serves requests (HTTP 200 on `/health`)
  3. The container runs as a non-root user (verified via `docker exec whoami`)
  4. `docker logs` shows Gunicorn access and error output (no log files inside container)
  5. The Docker health status transitions to `healthy` within 60 seconds of start
**Plans**: TBD

Plans:
- [ ] 01-01: Dockerfile + .dockerignore + gunicorn.conf.py
- [ ] 01-02: Environment variable wiring + .env.example + health check validation

### Phase 2: Volume Mount Validation
**Goal**: A running container has full access to all host-managed backend files; LogBoost enrichment completes successfully end-to-end
**Depends on**: Phase 1
**Requirements**: VOL-01, VOL-02, VOL-03, VOL-04, VOL-05, VOL-06
**Success Criteria** (what must be TRUE):
  1. `/health` endpoint returns `logboost_available: true` after container start with binary mounted
  2. GeoIP lookups return enriched data (not blank), confirming `.mmdb` mounts are accessible
  3. Admin login persists across container restarts (confirms `logboost_admin.db` mount survives)
  4. Session file uploads and output files are writable inside the container by the non-root user
**Plans**: TBD

Plans:
- [ ] 02-01: Volume mount strategy + docker-run.sh with all -v flags

### Phase 3: SSL + Documentation
**Goal**: The container serves HTTPS and an operator can deploy from scratch using only the README
**Depends on**: Phase 2
**Requirements**: SSL-01, SSL-02, SSL-03, DOC-01, DOC-02, DOC-03, DOC-04
**Success Criteria** (what must be TRUE):
  1. Browser reaches the application over HTTPS without certificate errors (using provided certs)
  2. HTTP requests are not served on the plain port when SSL is active
  3. A new operator can run `docker build` and `docker run` using only the README, with no undocumented flags or env vars
  4. The README documents every required env var with its purpose and an example value
**Plans**: TBD

Plans:
- [ ] 03-01: SSL configuration (Gunicorn certfile/keyfile + env vars + port exposure)
- [ ] 03-02: README documentation (build, run, volumes, env vars, SSL setup)

## Progress

**Execution Order:**
Phases execute in numeric order: 1 → 2 → 3

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Core Container | 0/2 | Not started | - |
| 2. Volume Mount Validation | 0/1 | Not started | - |
| 3. SSL + Documentation | 0/2 | Not started | - |
