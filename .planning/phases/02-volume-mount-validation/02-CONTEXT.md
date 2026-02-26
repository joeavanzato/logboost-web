# Phase 2: Volume Mount Validation - Context

**Gathered:** 2026-02-25
**Status:** Ready for planning

<domain>
## Phase Boundary

Wire all host-managed files into the container via volume mounts and validate LogBoost enrichment works end-to-end. This includes the LogBoost binary, MaxMind databases, threat intelligence, admin database, and user uploads/output.

</domain>

<decisions>
## Implementation Decisions

### Read/write permissions
- LogBoost binary: **Read-write** — app downloads/updates the binary at runtime as part of normal operations
- MaxMind databases (*.mmdb): **Read-write** — app downloads/updates them during operations
- Threat database (threats.db): **Read-write** — created by the binary during normal operations
- logboost.log: **Read-write** — created by the binary
- uploads/ and output/: **Read-write, persistent** — must survive container restarts
- Admin database (logboost_admin.db): **Read-write** — stored in same data directory as other app data

### Operator interface
- **docker-compose.yml** is the primary interface for running the container
- Compose file references **separate .env file** for configuration (operator edits .env)
- Host-side data directory: **/opt/logboost/** — standard location for third-party software

### Directory structure
- Claude's discretion on internal structure within /opt/logboost/
- App creates subdirectories as needed during operations

### Startup validation
- **Start anyway if binary missing** — app has built-in configuration for this; /health reports logboost_available: false
- **Start anyway if MaxMind missing** — downloading/updating is built into app operations
- **Fail to start if main data directory not writable** — can't function without writable storage
- **/health reports detailed mount status** — shows which mounts are available/writable

### Claude's Discretion
- Internal directory structure within container
- Exact mount paths inside container (should align with existing ENV defaults)
- Specific validation checks at startup

</decisions>

<specifics>
## Specific Ideas

- All persistent data should live in one unified data directory (/opt/logboost/ on host)
- The app handles downloading binaries and databases at runtime — mounts just need to be writable
- .env.example already exists from Phase 1 — compose should leverage it

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 02-volume-mount-validation*
*Context gathered: 2026-02-25*
