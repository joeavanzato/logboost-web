# Phase 2: Volume Mount Validation - Research

**Researched:** 2026-02-25
**Domain:** Docker Compose bind mounts, volume permissions for non-root containers, startup validation scripts
**Confidence:** HIGH

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Read/write permissions**
- LogBoost binary: **Read-write** — app downloads/updates the binary at runtime as part of normal operations
- MaxMind databases (*.mmdb): **Read-write** — app downloads/updates them during operations
- Threat database (threats.db): **Read-write** — created by the binary during normal operations
- logboost.log: **Read-write** — created by the binary
- uploads/ and output/: **Read-write, persistent** — must survive container restarts
- Admin database (logboost_admin.db): **Read-write** — stored in same data directory as other app data

**Operator interface**
- **docker-compose.yml** is the primary interface for running the container
- Compose file references **separate .env file** for configuration (operator edits .env)
- Host-side data directory: **/opt/logboost/** — standard location for third-party software

**Directory structure**
- Claude's discretion on internal structure within /opt/logboost/
- App creates subdirectories as needed during operations

**Startup validation**
- **Start anyway if binary missing** — app has built-in configuration for this; /health reports logboost_available: false
- **Start anyway if MaxMind missing** — downloading/updating is built into app operations
- **Fail to start if main data directory not writable** — can't function without writable storage
- **/health reports detailed mount status** — shows which mounts are available/writable

### Claude's Discretion
- Internal directory structure within container
- Exact mount paths inside container (should align with existing ENV defaults)
- Specific validation checks at startup

### Deferred Ideas (OUT OF SCOPE)

None — discussion stayed within phase scope
</user_constraints>

---

## Summary

This phase wires all host-managed files into the running container via Docker Compose bind mounts and validates that LogBoost enrichment works end-to-end. Phase 1 already delivered the working Dockerfile with all ENV defaults. Phase 2 delivers three artifacts: `docker-compose.yml`, a startup validation entrypoint script (`entrypoint.sh`), and an updated `.env.example`. No application code changes are expected unless the `/health` endpoint needs to expose additional mount status fields.

The standard approach for this project: one unified host directory `/opt/logboost/` holds all persistent data, with subdirectories for each concern (binary, maxmind, intel, cache, config, db, uploads, output). All mounts are read-write per user's locked decision. Docker Compose uses `env_file: .env` to load the operator's `.env` file. The existing Dockerfile ENV defaults (`LOGBOOST_PATH=/usr/local/bin/logboost`, `MAXMIND_DIR=/data/maxmind`, `THREAT_DB_DIR=/data/intel`, `LOGBOOST_DB_PATH=/app/logboost_admin.db`) must be overridden in the compose file to point to the mount paths inside the container.

The critical complication: the container runs as non-root user `logboost` (UID 1000). Host directories under `/opt/logboost/` will be created/owned by root unless the operator manually chowns them. The startup validation entrypoint catches this before gunicorn starts.

**Primary recommendation:** Use a minimal `entrypoint.sh` that tests writability of the main data directory, exits 1 with a clear error if not writable, then execs gunicorn. All 8 mounts use the short bind-mount syntax in `docker-compose.yml`. Host directories must be `chown logboost:logboost` or `chmod 777` before first run.

---

## Standard Stack

This phase uses no new libraries. It is purely Docker Compose + shell scripting.

### Core

| Tool | Version | Purpose | Why Standard |
|------|---------|---------|--------------|
| Docker Compose | v2 (`docker compose`) | Orchestrate container with all volume mounts | User's locked decision; standard local deployment interface |
| docker-compose.yml | Compose spec (no `version:` key in modern compose) | Declares service, volumes, env_file | Official recommended format; `version:` field is deprecated in Compose v2 |
| entrypoint.sh | Shell (bash/sh) | Startup validation before gunicorn | Pattern used by Postgres, Nginx, Redis official images; avoids dead-start failures |

### Supporting

| Tool | Purpose | When to Use |
|------|---------|-------------|
| `.env` file | Operator-edited secrets and path overrides | Loaded by Compose via `env_file:` |
| `chown` / `chmod` on host | Fix permissions on `/opt/logboost/` before first run | Required when directories are created as root |

### No Installation Required

No new Python packages. No new apt packages. All tooling is already present in the image from Phase 1.

---

## Architecture Patterns

### Recommended Host Directory Layout

```
/opt/logboost/                  # Host data root (user's locked decision)
├── logboost                    # LogBoost Linux binary (rw — app updates it)
├── maxmind/                    # MaxMind *.mmdb files (rw — app updates them)
│   ├── GeoLite2-City.mmdb
│   ├── GeoLite2-ASN.mmdb
│   └── GeoLite2-Country.mmdb
├── intel/                      # Threat intelligence (rw — binary creates threats.db)
│   └── threats.db
├── cache/                      # LogBoost binary cache files (rw)
│   ├── dns.cache
│   ├── idb.cache
│   └── whois.cache
├── config/                     # Config files (rw — app may update them)
│   ├── feed_config.json
│   └── mm_api.txt
├── db/                         # Admin SQLite database (rw — persistent)
│   └── logboost_admin.db
├── uploads/                    # Session upload files (rw, persistent)
└── output/                     # Session enrichment output (rw, persistent)
```

### Container-Side Mount Paths

The existing Dockerfile ENV defaults define the container-side paths. All mounts must match:

| What | Host Path | Container Path | ENV Var |
|------|-----------|---------------|---------|
| Binary | `/opt/logboost/logboost` | `/usr/local/bin/logboost` | `LOGBOOST_PATH` |
| MaxMind DBs | `/opt/logboost/maxmind` | `/data/maxmind` | `MAXMIND_DIR` |
| Intel/threats | `/opt/logboost/intel` | `/data/intel` | `THREAT_DB_DIR` |
| Cache files | `/opt/logboost/cache` | `/data/cache` | (LogBoost binary reads from cwd or explicit path) |
| Config files | `/opt/logboost/config` | `/data/config` | (LogBoost binary reads from cwd or explicit path) |
| Admin DB | `/opt/logboost/db/logboost_admin.db` | `/data/db/logboost_admin.db` | `LOGBOOST_DB_PATH` |
| Uploads | `/opt/logboost/uploads` | `/app/uploads` | (hardcoded in app.py as `Path(__file__).parent / 'uploads'`) |
| Output | `/opt/logboost/output` | `/app/output` | (hardcoded in app.py as `Path(__file__).parent / 'output'`) |

**CRITICAL NOTE on uploads and output:** These are hardcoded in `app.py` as `Path(__file__).parent / 'uploads'` and `Path(__file__).parent / 'output'` (lines 103-104). They are NOT driven by env vars. The container-side paths are always `/app/uploads` and `/app/output`. The Dockerfile already creates these directories. Volume mounts at these exact container paths will overlay the image's empty directories with the host's persistent directories.

**CRITICAL NOTE on cache and config paths:** The LogBoost binary's working directory and how it discovers `dns.cache`, `idb.cache`, `whois.cache`, `feed_config.json`, and `mm_api.txt` is determined by the binary's own behavior (not app.py env vars). Mount these at `/data/cache` and `/data/config` inside the container and ensure the binary is invoked from or pointed to those paths. Review how `build_logboost_command()` passes arguments to confirm.

**CRITICAL NOTE on admin DB path change:** The current Dockerfile `ENV LOGBOOST_DB_PATH=/app/logboost_admin.db` puts the DB inside the app directory. For Phase 2, the mount path should be changed to `/data/db/logboost_admin.db` in the compose file (via env var override) to match the unified `/data/` mount structure. The `.env.example` must document this.

### Pattern 1: docker-compose.yml with env_file and Bind Mounts

**What:** Single service compose file that references the `.env` file for configuration and declares all bind mounts.

**Key points verified against official Compose docs:**
- `version:` field is deprecated in Compose v2; omit it
- `env_file: .env` loads the operator's `.env` file; variables in `environment:` override `env_file`
- Short bind-mount syntax: `HOST_PATH:CONTAINER_PATH` (no `:ro` — all mounts are read-write per user's decision)
- If host path does not exist when using `--volume`/short syntax, Docker auto-creates it as root-owned — this is the permission pitfall

```yaml
# docker-compose.yml
# Source: https://docs.docker.com/reference/compose-file/

services:
  logboost-web:
    image: logboost-web:latest
    # OR: build: . (if building locally)
    env_file: .env
    environment:
      # Override Dockerfile defaults to point to mounted data directory
      LOGBOOST_PATH: /usr/local/bin/logboost
      MAXMIND_DIR: /data/maxmind
      THREAT_DB_DIR: /data/intel
      LOGBOOST_DB_PATH: /data/db/logboost_admin.db
    ports:
      - "5000:5000"
    volumes:
      # Binary (rw — app updates it)
      - /opt/logboost/logboost:/usr/local/bin/logboost
      # MaxMind databases (rw — app updates them)
      - /opt/logboost/maxmind:/data/maxmind
      # Threat intelligence (rw — binary creates threats.db)
      - /opt/logboost/intel:/data/intel
      # Cache files (rw — binary reads/writes)
      - /opt/logboost/cache:/data/cache
      # Config files (rw)
      - /opt/logboost/config:/data/config
      # Admin SQLite database (rw, persistent)
      - /opt/logboost/db:/data/db
      # Session uploads (rw, persistent)
      - /opt/logboost/uploads:/app/uploads
      # Session output (rw, persistent)
      - /opt/logboost/output:/app/output
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:5000/health"]
      interval: 30s
      timeout: 10s
      start_period: 30s
      retries: 3
```

### Pattern 2: Startup Validation via entrypoint.sh

**What:** A shell script that runs before gunicorn. Validates the main data directory is writable (fail condition) and checks for optional mounts (warn only). Then `exec`s gunicorn so it becomes PID 1.

**When to use:** Any time the container must fail fast with a clear error instead of starting silently with broken mounts.

**Implementation notes:**
- Script must be `chmod +x` in the Dockerfile
- Use `exec "$@"` at the end so gunicorn receives signals correctly (PID 1 requirement)
- Use `/bin/sh` not `/bin/bash` for portability in slim images (bash is not installed in python:3.12-slim unless explicitly added)
- The "fail if main data directory not writable" check is the ONLY hard failure per user's decision

```sh
#!/bin/sh
# entrypoint.sh — Startup validation before gunicorn
# Source: Docker official entrypoint pattern (exec "$@" for PID 1)

set -e

DATA_DIR="/data"

# HARD FAIL: Main data directory must be writable
# Cannot function without writable storage (user's locked decision)
if [ ! -w "$DATA_DIR" ]; then
    echo "ERROR: Data directory $DATA_DIR is not writable by container user."
    echo "On the host, run: sudo chown -R 1000:1000 /opt/logboost"
    echo "Or: sudo chmod -R 777 /opt/logboost"
    exit 1
fi

# WARN ONLY: Binary missing is expected on first run
if [ ! -f "$LOGBOOST_PATH" ]; then
    echo "WARNING: LogBoost binary not found at $LOGBOOST_PATH"
    echo "  /health will report logboost_available: false"
    echo "  Download the binary and place it at /opt/logboost/logboost on the host."
fi

# WARN ONLY: MaxMind databases missing is expected on first run
if [ ! -d "$MAXMIND_DIR" ] || [ -z "$(ls -A $MAXMIND_DIR 2>/dev/null)" ]; then
    echo "WARNING: MaxMind databases not found in $MAXMIND_DIR"
    echo "  GeoIP enrichment will not work until .mmdb files are present."
fi

# Hand off to gunicorn (exec preserves PID 1 for signal handling)
exec "$@"
```

**Dockerfile addition required:**
```dockerfile
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
CMD ["gunicorn", "--config", "gunicorn.conf.py", "app:app"]
```

**Note on DATA_DIR:** The entrypoint checks `/data` as the writable root. All data mounts live under `/data/` except uploads and output which are under `/app/`. The more critical check is `/data` since it holds the DB. If `/data` is writable, the container can function.

### Pattern 3: Health Endpoint Mount Status Enrichment

**What:** The existing `/health` endpoint (app.py lines 636-685) already returns `logboost_available`, `maxmind_dir`, and `threat_db_dir`. Per user's locked decision, `/health` must report "detailed mount status" — which mounts are available/writable.

**Verified current /health response fields:**
```json
{
  "status": "ok|degraded|unhealthy",
  "db_accessible": true,
  "logboost_available": true,
  "logboost_path": "/usr/local/bin/logboost",
  "maxmind_dir": "/data/maxmind",
  "threat_db_dir": "/data/intel"
}
```

**What to add for Phase 2 success criteria:**
- `maxmind_available`: check if `*.mmdb` files exist in `MAXMIND_DIR`
- `uploads_writable`: check if `/app/uploads` is writable
- `output_writable`: check if `/app/output` is writable

```python
# Addition to /health endpoint in app.py
import glob

# Check MaxMind databases present
maxmind_available = bool(list(Path(MAXMIND_DIR).glob('*.mmdb'))) if Path(MAXMIND_DIR).exists() else False

# Check uploads and output are writable (key for VOL-06 success criterion)
def is_writable(path: Path) -> bool:
    return path.exists() and os.access(str(path), os.W_OK)

uploads_writable = is_writable(UPLOAD_FOLDER)
output_writable = is_writable(OUTPUT_FOLDER)

# Add to response dict:
return jsonify({
    'status': status_text,
    'db_accessible': db_accessible,
    'logboost_available': logboost_available,
    'logboost_path': LOGBOOST_BINARY,
    'maxmind_dir': MAXMIND_DIR,
    'maxmind_available': maxmind_available,
    'threat_db_dir': THREAT_DB_DIR,
    'uploads_writable': uploads_writable,
    'output_writable': output_writable,
}), status_code
```

### Anti-Patterns to Avoid

- **Mounting the binary as read-only (`:ro`)** — user's locked decision is read-write for all mounts; the app updates the binary at runtime
- **Using named Docker volumes instead of bind mounts** — operator must be able to inspect and manage host files directly; bind mounts to `/opt/logboost/` are correct
- **Setting `version: "3.8"` in docker-compose.yml** — the `version:` field is deprecated in Compose v2 (current standard); omit it entirely
- **Letting Docker auto-create `/opt/logboost/` subdirectories via `--volume`** — Docker creates them as root-owned, breaking non-root container user (UID 1000); operator must pre-create and chown them
- **Using ENTRYPOINT without `exec "$@"`** — breaks signal handling; gunicorn becomes a child process, not PID 1; SIGTERM doesn't reach it and container stops ungracefully
- **Not mounting the admin DB** — the Dockerfile pre-creates `/app/logboost_admin.db` baked into the image. Without mounting `/data/db/logboost_admin.db`, any data stored (users, sessions, settings) is lost on container rebuild

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Startup validation | Complex Python validation script at app startup | Shell entrypoint.sh with exit 1 | Runs before gunicorn forks workers; simpler and standard |
| Directory creation on host | Docker auto-create via compose | Pre-create with `mkdir -p` + `chown` in operator setup docs | Docker auto-create assigns root ownership, breaking UID 1000 container user |
| Volume permission fixing | Entrypoint `chown -R` at container start | Pre-chown on host before first run | `chown -R` at container start is slow, requires root, and is a security antipattern |
| Env var documentation | Inline comments in docker-compose.yml | Separate .env file + .env.example | Compose env_file is the standard pattern; operators edit .env, not docker-compose.yml |

**Key insight:** For bind mounts with a non-root container user, the permission problem is a host-side problem (who owns `/opt/logboost/`). Solve it with `chown` on the host in setup docs, not inside the container at runtime.

---

## Common Pitfalls

### Pitfall 1: Host Directories Created as Root by Docker

**What goes wrong:** When Docker Compose starts with a bind mount pointing to a host path that does not exist (e.g., `/opt/logboost/maxmind`), Docker auto-creates the directory. On Linux, Docker daemon runs as root, so the auto-created directory is `root:root`. The container process (UID 1000, `logboost` user) cannot write to it. File writes fail silently or raise `PermissionError`.

**Why it happens:** Docker's `--volume` / short bind-mount syntax auto-creates missing host directories as root. The container process runs as UID 1000 (non-root).

**How to avoid:** Pre-create all host directories and chown them before first `docker compose up`:
```bash
sudo mkdir -p /opt/logboost/{maxmind,intel,cache,config,db,uploads,output}
sudo chown -R 1000:1000 /opt/logboost
```

**Warning signs:** Container starts, entrypoint passes initial `/data` check (if `/data` itself is writable), but writes to subdirectories fail. Enrichment produces no output. `docker exec <id> ls -la /data/` shows `root:root` ownership on subdirectories.

**Detection:** `docker exec <id> ls -la /data/` — look for `root root` instead of `logboost logboost` ownership.

---

### Pitfall 2: Admin DB Mount Shadows Dockerfile Pre-Created DB

**What goes wrong:** The Dockerfile pre-creates `/app/logboost_admin.db` during build. When the compose file mounts `/opt/logboost/db/logboost_admin.db:/data/db/logboost_admin.db`, this is a different path from the Dockerfile default (`/app/logboost_admin.db`). If `LOGBOOST_DB_PATH` is not updated to `/data/db/logboost_admin.db` in the compose environment, the app still reads the baked-in image DB at `/app/logboost_admin.db`, and the mount is ignored.

**Why it happens:** The Dockerfile sets `ENV LOGBOOST_DB_PATH=/app/logboost_admin.db` as the default. Unless the compose file overrides this env var, the app uses the image-internal path.

**How to avoid:** The compose file `environment:` section MUST set `LOGBOOST_DB_PATH=/data/db/logboost_admin.db`. The host file at `/opt/logboost/db/logboost_admin.db` must exist (created by the app on first run, or pre-seeded). The `.env.example` must document this override.

**Warning signs:** Admin login works in fresh container, user changes settings, container is rebuilt, all settings are gone. Admin users persist in the image's baked-in DB, not the mounted one.

---

### Pitfall 3: uploads and output Are Hardcoded, Not Env-Var Driven

**What goes wrong:** `UPLOAD_FOLDER = Path(__file__).parent / 'uploads'` and `OUTPUT_FOLDER = Path(__file__).parent / 'output'` in app.py (lines 103-104) are NOT configurable via env vars. If the volume mount is placed at a different container path, the app ignores it entirely.

**Why it happens:** Unlike `LOGBOOST_PATH` and `MAXMIND_DIR`, the uploads/output paths are hardcoded. They are always `/app/uploads` and `/app/output` inside the container.

**How to avoid:** Mount at exactly `/app/uploads` and `/app/output`. Do not try to change these paths via env vars — they don't exist. The mounts must match the hardcoded paths.

**Warning signs:** Files are uploaded and enrichment runs, but outputs disappear after container restart. Check: `docker exec <id> ls /app/uploads` — if the mount isn't at the right path, the directory is empty after restart.

---

### Pitfall 4: Binary Not Executable After Mount

**What goes wrong:** The LogBoost binary file on the host may not have the executable bit set (`chmod +x`). When mounted into the container, it inherits the host file's permissions. `subprocess.run(['/usr/local/bin/logboost', ...])` fails with `PermissionError: [Errno 13] Permission denied` (different from FileNotFoundError).

**Why it happens:** File mode bits carry through bind mounts. If the binary was copied/downloaded on the host without `chmod +x`, it is not executable inside the container.

**How to avoid:** After placing the binary on the host:
```bash
sudo chmod +x /opt/logboost/logboost
```

**Warning signs:** `/health` returns `logboost_available: true` (file exists), but enrichment requests fail with a permission error in the logs rather than "binary not found".

---

### Pitfall 5: Entrypoint exec "$@" Missing — Gunicorn Not PID 1

**What goes wrong:** If the entrypoint script calls `gunicorn` without `exec`, the shell becomes PID 1 and gunicorn is a child process. When Docker sends `SIGTERM` on container stop, the signal goes to the shell (PID 1), not gunicorn. Gunicorn does not receive the signal, does not gracefully drain connections, and is killed by SIGKILL after the stop timeout. In-flight LogBoost enrichment jobs are terminated mid-run.

**Why it happens:** Without `exec`, the shell spawns gunicorn as a subprocess and remains PID 1. Signals sent to PID 1 reach the shell, not gunicorn.

**How to avoid:** Always end the entrypoint with `exec "$@"`:
```sh
exec "$@"   # NOT: gunicorn --config gunicorn.conf.py app:app
```

**Warning signs:** `docker stop` takes the full stop timeout (10s default) and gunicorn processes appear orphaned in host `ps` after stop.

---

### Pitfall 6: DATA_DIR Check Must Exist as a Mount Point

**What goes wrong:** The entrypoint checks `[ ! -w "$DATA_DIR" ]` (where DATA_DIR=/data). If no volume is mounted at `/data`, the directory may not exist at all in the container. The check fails with `[ ! -w "/data" ]` returning false (treating non-existent as non-writable), and the container exits 1 even for a valid configuration.

**Why it happens:** The container image may not have a `/data` directory pre-created. The entrypoint must handle both "directory doesn't exist" and "directory exists but not writable".

**How to avoid:** Create `/data` in the Dockerfile so the check is always against an existing path. If not mounted, `/data` is the image's empty directory (owned by root), and the check fails as expected. If mounted with correct permissions, check passes.
```dockerfile
RUN mkdir -p /data && chown logboost:logboost /data
```

**Warning signs:** Container exits 1 with "not writable" error even when volumes are correctly mounted.

---

## Code Examples

### Complete docker-compose.yml

```yaml
# docker-compose.yml
# Source: https://docs.docker.com/reference/compose-file/ (verified 2026-02-25)
# Compose v2 format — no 'version:' key (deprecated)

services:
  logboost-web:
    image: logboost-web:latest
    env_file: .env
    environment:
      # Override Dockerfile defaults to use mounted data directories
      LOGBOOST_PATH: /usr/local/bin/logboost
      MAXMIND_DIR: /data/maxmind
      THREAT_DB_DIR: /data/intel
      LOGBOOST_DB_PATH: /data/db/logboost_admin.db
    ports:
      - "5000:5000"
    volumes:
      # All mounts are read-write (user's locked decision — app updates these at runtime)
      - /opt/logboost/logboost:/usr/local/bin/logboost
      - /opt/logboost/maxmind:/data/maxmind
      - /opt/logboost/intel:/data/intel
      - /opt/logboost/cache:/data/cache
      - /opt/logboost/config:/data/config
      - /opt/logboost/db:/data/db
      - /opt/logboost/uploads:/app/uploads
      - /opt/logboost/output:/app/output
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:5000/health"]
      interval: 30s
      timeout: 10s
      start_period: 30s
      retries: 3
```

### Complete entrypoint.sh

```sh
#!/bin/sh
# entrypoint.sh — Startup validation for logboost-web container
# Runs before gunicorn to validate mount conditions.
# Fail condition: main data directory not writable (user's locked decision).
# All other missing mounts: warn only, let app handle gracefully.

set -e

echo "==> LogBoost Web startup validation"

# HARD FAIL: /data must be writable — container cannot function without it
if [ ! -w /data ]; then
    echo "ERROR: /data is not writable by container user (UID 1000)."
    echo "Fix on host: sudo chown -R 1000:1000 /opt/logboost"
    exit 1
fi

echo "  [OK] /data is writable"

# WARN: Binary is optional on startup — app handles missing binary gracefully
if [ ! -f "${LOGBOOST_PATH:-/usr/local/bin/logboost}" ]; then
    echo "  [WARN] LogBoost binary not found at ${LOGBOOST_PATH:-/usr/local/bin/logboost}"
    echo "         /health will report logboost_available: false"
fi

# WARN: MaxMind databases are optional on startup — app downloads them
MAXMIND_DIR="${MAXMIND_DIR:-/data/maxmind}"
if [ ! -d "$MAXMIND_DIR" ] || [ -z "$(ls -A "$MAXMIND_DIR" 2>/dev/null)" ]; then
    echo "  [WARN] MaxMind databases not found in $MAXMIND_DIR"
    echo "         GeoIP enrichment will not work until .mmdb files are present"
fi

echo "==> Starting gunicorn"

# exec replaces the shell process — gunicorn becomes PID 1
# This ensures signals (SIGTERM, SIGINT) reach gunicorn for graceful shutdown
exec "$@"
```

### Dockerfile additions for entrypoint and /data directory

```dockerfile
# Add to existing Dockerfile (after the existing RUN mkdir lines, before USER switch)

# Create /data directory tree for volume mount points
# chown ensures container user (logboost, UID 1000) owns the directories
# if no volume is mounted, these are writable empty directories inside the image
RUN mkdir -p /data/maxmind /data/intel /data/cache /data/config /data/db \
    && chown -R logboost:logboost /data

# Copy and enable entrypoint validation script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Switch to non-root user (this line already exists from Phase 1)
USER logboost

# Update CMD to use entrypoint — ENTRYPOINT runs before CMD
ENTRYPOINT ["/entrypoint.sh"]
CMD ["gunicorn", "--config", "gunicorn.conf.py", "app:app"]
```

### Updated .env.example additions for Phase 2

The existing `.env.example` from Phase 1 must be updated with the new `LOGBOOST_DB_PATH` override for compose:

```bash
# Addition to .env.example for Phase 2

# ============================================================
# VOLUME MOUNT PATHS - Must match docker-compose.yml volumes
# ============================================================

# Path to LogBoost binary inside container
# Compose mounts /opt/logboost/logboost -> /usr/local/bin/logboost
LOGBOOST_PATH=/usr/local/bin/logboost

# MaxMind GeoIP database directory inside container
# Compose mounts /opt/logboost/maxmind -> /data/maxmind
MAXMIND_DIR=/data/maxmind

# Threat intelligence directory inside container
# Compose mounts /opt/logboost/intel -> /data/intel
THREAT_DB_DIR=/data/intel

# Admin SQLite database path inside container
# CHANGED FROM DOCKERFILE DEFAULT (/app/logboost_admin.db) for persistence
# Compose mounts /opt/logboost/db -> /data/db; file is /data/db/logboost_admin.db
LOGBOOST_DB_PATH=/data/db/logboost_admin.db
```

### Operator Host Setup Script (for documentation)

```bash
#!/bin/bash
# Host setup — run once as root before first docker compose up
# Creates /opt/logboost/ directory tree with correct ownership for container user (UID 1000)

LOGBOOST_DIR="/opt/logboost"

mkdir -p \
    "${LOGBOOST_DIR}/maxmind" \
    "${LOGBOOST_DIR}/intel" \
    "${LOGBOOST_DIR}/cache" \
    "${LOGBOOST_DIR}/config" \
    "${LOGBOOST_DIR}/db" \
    "${LOGBOOST_DIR}/uploads" \
    "${LOGBOOST_DIR}/output"

# Set ownership to container user (UID 1000 = logboost user in container)
chown -R 1000:1000 "${LOGBOOST_DIR}"

echo "Host directories created and owned by UID 1000."
echo "Place the LogBoost Linux binary at: ${LOGBOOST_DIR}/logboost"
echo "Make it executable: chmod +x ${LOGBOOST_DIR}/logboost"
```

---

## State of the Art

| Old Approach | Current Approach | Impact |
|---|---|---|
| `version: "3.8"` in compose file | No `version:` key (Compose v2 spec) | Field is deprecated; omitting it is correct for modern Docker Compose |
| `docker run -v` with many flags | `docker-compose.yml` with `volumes:` block | Operator-friendly; all mounts in one readable file |
| No startup validation | entrypoint.sh with writable check before gunicorn | Fails fast with actionable error instead of silent broken state |
| Admin DB inside image (`/app/logboost_admin.db`) | DB mounted from host (`/data/db/logboost_admin.db`) | Admin data survives container rebuilds |

---

## Open Questions

1. **Cache and config file paths for LogBoost binary**
   - What we know: `build_logboost_command()` passes `-dbdir` (MaxMind) to the binary but does NOT pass explicit paths for `dns.cache`, `whois.cache`, `idb.cache`, `feed_config.json`, `mm_api.txt`
   - What's unclear: The LogBoost binary may look for these files relative to its current working directory (cwd) or relative to its own binary path. This behavior is not documented in the Flask codebase — it is internal to the closed-source binary.
   - Recommendation: Mount cache and config files at `/data/cache` and `/data/config`, but verify during end-to-end testing that the binary finds them. If the binary uses cwd: the `subprocess.run()` call in `run_logboost()` does not set `cwd`, so it inherits the gunicorn process cwd (likely `/app`). This may require adding a `-cachedir` or `-configdir` argument or passing `cwd=` in the subprocess call.
   - Confidence: LOW — requires empirical testing with the actual binary

2. **Whether /health needs code changes for VOL success criteria**
   - What we know: Success criteria #2 requires "GeoIP lookups return enriched data" — this verifies via actual enrichment test, not just /health. Success criteria #4 requires "uploads and output are writable" — this could be a manual test or /health check.
   - What's unclear: Whether the planner should add `maxmind_available`, `uploads_writable`, `output_writable` to the /health response (code change to app.py) or validate these via separate test commands.
   - Recommendation: Add the writable checks to /health — it is already the "detailed mount status" endpoint per user's decision, and it makes validation straightforward. But this is a code change that may be out of scope for a pure infra phase.

3. **Admin DB initialization on first mount**
   - What we know: The Dockerfile pre-creates `/app/logboost_admin.db` (with schema and default admin user). But when the compose file mounts `/opt/logboost/db/logboost_admin.db` at `/data/db/logboost_admin.db`, the host-side file may not exist on first run.
   - What's unclear: What happens when `LOGBOOST_DB_PATH=/data/db/logboost_admin.db` is set but the host file doesn't exist yet? `sqlite3.connect()` will auto-create the file if the directory is writable, but it will create an empty schema-less DB. The `init_db()` function must be called to create the schema.
   - Recommendation: Verify that `init_admin(app, csrf)` (app.py line 96) calls `init_db()` and that this correctly initializes a fresh DB at the mounted path. The entrypoint.sh does not need to handle this — Flask/admin module should handle it at startup.

---

## Sources

### Primary (HIGH confidence)

- Codebase inspection: `app.py` lines 83, 103-110 — confirmed `get_db` import, UPLOAD_FOLDER/OUTPUT_FOLDER hardcoded paths, LOGBOOST_BINARY/MAXMIND_DIR/THREAT_DB_DIR env vars
- Codebase inspection: `admin.py` lines 26-27 — confirmed `LOGBOOST_DB_PATH` env var read with fallback
- Codebase inspection: `app.py` lines 636-685 — confirmed existing /health response fields
- Codebase inspection: `Dockerfile` — confirmed ENV defaults: LOGBOOST_PATH, MAXMIND_DIR, THREAT_DB_DIR, LOGBOOST_DB_PATH
- `.planning/phases/01-core-container/01-02-SUMMARY.md` — confirmed Phase 1 deliverables: working container, chown fix, env var reads
- Official Docker Compose docs: https://docs.docker.com/reference/compose-file/services/#volumes — verified short/long syntax, bind mount behavior
- Official Docker Compose docs: https://docs.docker.com/reference/compose-file/services/#env_file — verified env_file behavior, variable override precedence
- Official Docker bind mount docs: https://docs.docker.com/engine/storage/bind-mounts/ — confirmed auto-create behavior (creates as root)

### Secondary (MEDIUM confidence)

- WebSearch (2026-02-25, multiple sources agree): Docker bind mount with non-root container user creates root-owned directories on auto-create — solution is pre-create + chown on host
- WebSearch (2026-02-25): `version:` field in docker-compose.yml is deprecated in Compose v2 — confirmed by multiple sources
- WebSearch (2026-02-25): `exec "$@"` pattern in entrypoint for PID 1 — confirmed by multiple sources (Airflow, official Docker blog)

### Tertiary (LOW confidence)

- LogBoost binary cwd behavior for cache/config file discovery — not documented in codebase, requires empirical testing

---

## Metadata

**Confidence breakdown:**
- Standard stack (Docker Compose syntax): HIGH — verified against official docs
- Host directory structure: HIGH — follows from ENV defaults and user's decisions
- Permission pitfalls (UID 1000 / root ownership): HIGH — confirmed by multiple sources
- entrypoint.sh pattern: HIGH — standard Docker pattern, well-documented
- Cache/config file discovery by binary: LOW — internal binary behavior, not documented

**Research date:** 2026-02-25
**Valid until:** 2026-03-25 (30 days; Docker Compose syntax is stable)
