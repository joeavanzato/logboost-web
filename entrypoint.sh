#!/bin/sh
set -e

echo "==> LogBoost Web startup validation"

# HARD FAIL: /data must be writable — container cannot function without it
# Per user's locked decision: fail to start if main data directory not writable
if [ ! -w /data ]; then
    echo "ERROR: /data is not writable by container user (UID 1000)."
    echo "Fix on host: sudo chown -R 1000:1000 /opt/logboost"
    exit 1
fi
echo "  [OK] /data is writable"

# Initialize database if it doesn't exist at LOGBOOST_DB_PATH
# This handles the case where docker-compose overrides to /data/db/logboost_admin.db
# but the host volume is empty (first run or fresh host directory)
DB_FILE="${LOGBOOST_DB_PATH:-/app/logboost_admin.db}"
if [ ! -f "$DB_FILE" ]; then
    echo "  [INFO] Creating database at $DB_FILE"
    # Ensure parent directory exists
    mkdir -p "$(dirname "$DB_FILE")"
    # Initialize with schema via Python
    python -c "from admin import get_db; get_db().close()"
    echo "  [OK] Database initialized"
fi

# WARN ONLY: Binary is optional on startup — app handles missing binary gracefully
if [ ! -f "${LOGBOOST_PATH:-/usr/local/bin/logboost}" ]; then
    echo "  [WARN] LogBoost binary not found at ${LOGBOOST_PATH:-/usr/local/bin/logboost}"
    echo "         /health will report logboost_available: false"
fi

# WARN ONLY: MaxMind databases are optional — app downloads them
MAXMIND_CHECK="${MAXMIND_DIR:-/data/maxmind}"
if [ ! -d "$MAXMIND_CHECK" ] || [ -z "$(ls -A "$MAXMIND_CHECK" 2>/dev/null)" ]; then
    echo "  [WARN] MaxMind databases not found in $MAXMIND_CHECK"
    echo "         GeoIP enrichment will not work until .mmdb files are present"
fi

echo "==> Starting gunicorn"

# exec replaces shell process — gunicorn becomes PID 1 for proper signal handling
exec "$@"
