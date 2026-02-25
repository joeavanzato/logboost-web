# LogBoost Web Containerization

## What This Is

Docker containerization of the LogBoost Flask web frontend for deployment alongside the Linux LogBoost backend. The container packages the web UI, API routes, and admin panel while mounting host paths for backend-managed files (caches, databases, threat intel).

## Core Value

The Flask frontend runs reliably in a production-ready Docker container with proper WSGI server, SSL support, and health monitoring — deployable on any Linux host running the LogBoost backend.

## Requirements

### Validated

- ✓ Flask web application with modular blueprints — existing
- ✓ Admin panel with user authentication — existing
- ✓ External API integrations (Shodan, CIRCL, DNS, WHOIS) — existing
- ✓ LogBoost binary orchestration via subprocess — existing
- ✓ SQLite persistence for admin/caching — existing
- ✓ Session-based file processing — existing
- ✓ CSRF protection — existing
- ✓ Gunicorn production server support — existing

### Active

- [ ] Dockerfile for Flask frontend
- [ ] Production gunicorn configuration
- [ ] HTTPS/SSL termination
- [ ] Health check endpoint
- [ ] Volume mounts for backend files
- [ ] .dockerignore for build optimization
- [ ] Environment variable configuration
- [ ] Docker build and run documentation

### Out of Scope

- LogBoost backend (Linux binary) — managed separately, runs on host
- Backend data files (dns.cache, idb.cache, whois.cache) — mounted from host
- MaxMind databases (*.mmdb) — mounted from host
- Threat database (threats.db) — mounted from host
- Configuration files (feed_config.json, mm_api.txt) — mounted from host
- LogBoost logs (logboost.log) — stays on host
- Docker Compose — local Docker only for now
- Kubernetes/cloud deployment — future scope
- CI/CD pipeline — future scope

## Context

**Existing Architecture:**
- Flask 3.0+ with modular blueprints (auth, DNS, WHOIS, Chaos)
- Gunicorn already listed as dependency
- Environment variables already used for configuration (SECRET_KEY, FLASK_ENV, LOGBOOST_PATH, MAXMIND_DIR, THREAT_DB_DIR)
- Session directories: uploads/{session_id}/, output/{session_id}/
- SQLite database: logboost_admin.db

**Backend Integration:**
- Frontend calls LogBoost binary via subprocess (build_logboost_command, run_logboost)
- Binary path configurable via LOGBOOST_PATH env var
- Backend manages: dns.cache, idb.cache, whois.cache, feed_config.json, *.mmdb, threats.db

**Deployment Target:**
- Local Docker on same host as LogBoost Linux backend
- Container mounts host paths for backend files
- Single container deployment (no compose needed)

## Constraints

- **Runtime**: Python 3.12 — matches existing codebase
- **WSGI**: Gunicorn — already in requirements.txt
- **SSL**: Must terminate SSL in container or via reverse proxy
- **Mounts**: Backend files must be accessible via volume mounts
- **Compatibility**: Must work with existing LogBoost Linux binary on host

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Gunicorn as WSGI server | Already a dependency, production-ready | — Pending |
| Volume mounts for backend files | Backend manages these files on host | — Pending |
| Environment variables for config | Already used in codebase | — Pending |

---
*Last updated: 2026-02-25 after initialization*
