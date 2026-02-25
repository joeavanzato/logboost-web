# Requirements: LogBoost Web Containerization

**Defined:** 2026-02-25
**Core Value:** Flask frontend runs reliably in a production-ready Docker container

## v1 Requirements

Requirements for initial Docker containerization.

### Container Foundation

- [ ] **CNTR-01**: Dockerfile uses `python:3.12-slim` base image
- [ ] **CNTR-02**: `.dockerignore` excludes backend files, databases, credentials, and large assets
- [ ] **CNTR-03**: Container runs as non-root user
- [ ] **CNTR-04**: Application source copied with correct layer ordering (requirements.txt first)

### WSGI Configuration

- [ ] **WSGI-01**: `gunicorn.conf.py` configures timeout of 310+ seconds
- [ ] **WSGI-02**: Gunicorn uses single worker with threads (`--workers 1 --threads 4`)
- [ ] **WSGI-03**: Gunicorn logs to stdout/stderr for Docker log collection
- [ ] **WSGI-04**: Container CMD runs gunicorn with config file

### Environment & Secrets

- [ ] **ENV-01**: `SECRET_KEY` injected via environment variable (not random default)
- [ ] **ENV-02**: `FLASK_ENV=production` set for secure session cookies
- [ ] **ENV-03**: `LOGBOOST_PATH` configurable for mounted binary location
- [ ] **ENV-04**: Database and asset paths configurable via environment variables

### Health Monitoring

- [ ] **HLTH-01**: Dockerfile includes `HEALTHCHECK` directive
- [ ] **HLTH-02**: Health check uses existing `/health` endpoint
- [ ] **HLTH-03**: Health check verifies LogBoost binary is accessible

### Volume Mounts

- [ ] **VOL-01**: LogBoost Linux binary mountable from host
- [ ] **VOL-02**: MaxMind databases (*.mmdb) mountable as read-only
- [ ] **VOL-03**: Cache files (dns.cache, idb.cache, whois.cache) mountable as read/write
- [ ] **VOL-04**: Config files (feed_config.json, mm_api.txt) mountable
- [ ] **VOL-05**: SQLite database (logboost_admin.db) mounted from host for persistence
- [ ] **VOL-06**: Session directories (uploads/, output/) writable inside container

### SSL/TLS

- [ ] **SSL-01**: Gunicorn configured to accept `--certfile` and `--keyfile` options
- [ ] **SSL-02**: SSL certificate paths configurable via environment variables
- [ ] **SSL-03**: Container exposes HTTPS port (443 or custom)

### Documentation

- [ ] **DOC-01**: README documents `docker build` command
- [ ] **DOC-02**: README documents `docker run` command with all volume mounts
- [ ] **DOC-03**: README documents required environment variables
- [ ] **DOC-04**: README documents SSL certificate setup

## v2 Requirements

Deferred to future release.

### Security Hardening

- **SEC-01**: Read-only root filesystem with tmpfs for writable paths
- **SEC-02**: Memory and CPU resource limits
- **SEC-03**: Security scanning in CI/CD pipeline

### Deployment

- **DEPL-01**: Docker Compose file for multi-container setup
- **DEPL-02**: Kubernetes manifests for cloud deployment
- **DEPL-03**: CI/CD pipeline for automated builds

### Advanced Features

- **ADV-01**: Multi-stage build for smaller image size
- **ADV-02**: tldextract cache pre-population at build time
- **ADV-03**: Nginx reverse proxy option

## Out of Scope

Explicitly excluded from this containerization effort.

| Feature | Reason |
|---------|--------|
| LogBoost backend containerization | Backend binary runs on host, managed separately |
| Docker Compose | Single container deployment, not needed for v1 |
| Kubernetes/cloud deployment | Target is local Docker on single host |
| CI/CD pipeline | Future scope after container is validated |
| Nginx reverse proxy | Gunicorn handles SSL directly |
| Database migration to PostgreSQL | SQLite sufficient for single-instance deployment |

## Traceability

Which phases cover which requirements. Updated during roadmap creation.

| Requirement | Phase | Status |
|-------------|-------|--------|
| CNTR-01 | Phase 1 | Pending |
| CNTR-02 | Phase 1 | Pending |
| CNTR-03 | Phase 1 | Pending |
| CNTR-04 | Phase 1 | Pending |
| WSGI-01 | Phase 1 | Pending |
| WSGI-02 | Phase 1 | Pending |
| WSGI-03 | Phase 1 | Pending |
| WSGI-04 | Phase 1 | Pending |
| ENV-01 | Phase 1 | Pending |
| ENV-02 | Phase 1 | Pending |
| ENV-03 | Phase 1 | Pending |
| ENV-04 | Phase 1 | Pending |
| HLTH-01 | Phase 1 | Pending |
| HLTH-02 | Phase 1 | Pending |
| HLTH-03 | Phase 1 | Pending |
| VOL-01 | Phase 2 | Pending |
| VOL-02 | Phase 2 | Pending |
| VOL-03 | Phase 2 | Pending |
| VOL-04 | Phase 2 | Pending |
| VOL-05 | Phase 2 | Pending |
| VOL-06 | Phase 2 | Pending |
| SSL-01 | Phase 3 | Pending |
| SSL-02 | Phase 3 | Pending |
| SSL-03 | Phase 3 | Pending |
| DOC-01 | Phase 3 | Pending |
| DOC-02 | Phase 3 | Pending |
| DOC-03 | Phase 3 | Pending |
| DOC-04 | Phase 3 | Pending |

**Coverage:**
- v1 requirements: 28 total
- Mapped to phases: 28
- Unmapped: 0

---
*Requirements defined: 2026-02-25*
*Last updated: 2026-02-25 after roadmap creation*
