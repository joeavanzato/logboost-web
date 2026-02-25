# Phase 1: Core Container - Context

**Gathered:** 2026-02-25
**Status:** Ready for planning

<domain>
## Phase Boundary

A buildable Docker image that runs the Flask app under Gunicorn with security defaults. The container should build successfully, start, serve requests, and pass health checks. Volume mounting and SSL configuration are handled in later phases.

</domain>

<decisions>
## Implementation Decisions

### Configuration Strategy
- Use `gunicorn.conf.py` file for all gunicorn settings (not CLI flags)
- Provide `.env.example` template documenting ALL environment variables with example values
- No required env vars - all should have sensible defaults (fail-safe for development)
- Container should work out of the box with defaults, override via env vars as needed

### Health Check Implementation
- Health check verifies: app responds (HTTP 200), database accessible, external APIs reachable
- Use `curl` to hit `/health` endpoint (add curl to image)
- Standard timing: 30-second interval
- External API failures = degraded but healthy (core app still works)
- Only mark unhealthy if Flask app or database is down

### Build Optimization
- Single-stage build (not multi-stage) for simplicity
- Optimize for fast rebuilds: copy requirements.txt first, pip install, then copy code
- Use allowlist `.dockerignore` (ignore everything, explicitly include only needed files)
- This prevents accidental inclusion of secrets, large files, or credentials

### Non-Root User Setup
- Container user: `logboost` with UID 1000
- Create proper home directory at `/home/logboost`
- Working directory: `/app`

### Claude's Discretion
- Exact COPY strategy (what goes in image vs mounted)
- Volume permission handling approach
- Specific health check timeout and retry count
- Whether to include build-essential for iocextract C-extension

</decisions>

<specifics>
## Specific Ideas

- All env vars documented in .env.example even if they have defaults
- Health endpoint should report degraded status for external APIs but still return 200
- Layer caching is important for development workflow

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 01-core-container*
*Context gathered: 2026-02-25*
