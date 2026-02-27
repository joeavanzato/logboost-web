#!/bin/sh
set -e

echo "==> LogBoost Web startup validation"

# HARD FAIL: /data must be writable — container cannot function without it
if [ ! -w /data ]; then
    echo "ERROR: /data is not writable by container user (UID 1000)."
    echo "Fix on host: sudo chown -R 1000:1000 /opt/logboost"
    exit 1
fi
echo "  [OK] /data is writable"

# Initialize database if it doesn't exist at LOGBOOST_DB_PATH
DB_FILE="${LOGBOOST_DB_PATH:-/app/logboost_admin.db}"
DB_DIR="$(dirname "$DB_FILE")"

if [ ! -w "$DB_DIR" ]; then
    echo "ERROR: Database directory $DB_DIR is not writable by container user (UID 1000)."
    exit 1
fi

if [ ! -f "$DB_FILE" ]; then
    echo "  [INFO] Creating database at $DB_FILE"
    python -c "from admin import get_db; get_db().close()"
    echo "  [OK] Database initialized"
fi

# ============================================
# Persistent data setup (volumes)
# ============================================

# Copy bundled MaxMind databases to volume on first run
if [ -d /data/maxmind ]; then
    for mmdb in /app/*.mmdb; do
        if [ -f "$mmdb" ]; then
            filename=$(basename "$mmdb")
            if [ ! -f "/data/maxmind/$filename" ]; then
                echo "  [INFO] Copying bundled $filename to /data/maxmind/"
                cp "$mmdb" "/data/maxmind/$filename"
            fi
        fi
    done
fi

# Copy bundled feed_config.json to volume on first run
if [ ! -f /data/intel/feed_config.json ] && [ -f /app/feed_config.json ]; then
    echo "  [INFO] Copying bundled feed_config.json to /data/intel/"
    cp /app/feed_config.json /data/intel/feed_config.json
fi

# Copy bundled threats.db to volume on first run (if bundled)
if [ ! -f /data/intel/threats.db ] && [ -f /app/threats.db ]; then
    echo "  [INFO] Copying bundled threats.db to /data/intel/"
    cp /app/threats.db /data/intel/threats.db
fi

# ============================================
# Symlinks: LogBoost expects files in cwd (/app)
# ============================================

# Symlink feed_config.json so LogBoost finds it in /app
if [ -f /data/intel/feed_config.json ] && [ ! -L /app/feed_config.json ]; then
    # Remove bundled file if it exists (not a symlink)
    [ -f /app/feed_config.json ] && rm /app/feed_config.json
    ln -s /data/intel/feed_config.json /app/feed_config.json
    echo "  [OK] Symlinked /app/feed_config.json -> /data/intel/feed_config.json"
fi

# Symlink threats.db so LogBoost writes to volume
if [ ! -L /app/threats.db ]; then
    # Remove bundled file if it exists (not a symlink)
    [ -f /app/threats.db ] && rm /app/threats.db
    ln -s /data/intel/threats.db /app/threats.db
    echo "  [OK] Symlinked /app/threats.db -> /data/intel/threats.db"
fi

# ============================================
# Validation checks
# ============================================

# Check LogBoost binary
if [ ! -f "${LOGBOOST_PATH:-/app/logboost}" ]; then
    echo "  [WARN] LogBoost binary not found at ${LOGBOOST_PATH:-/app/logboost}"
else
    echo "  [OK] LogBoost binary found"
fi

# Check feed_config.json
if [ -f /app/feed_config.json ]; then
    echo "  [OK] feed_config.json available"
else
    echo "  [WARN] feed_config.json not found"
fi

# Check MaxMind databases
if ls /data/maxmind/*.mmdb >/dev/null 2>&1; then
    echo "  [OK] MaxMind databases found in /data/maxmind"
else
    echo "  [WARN] MaxMind databases not found in /data/maxmind"
fi

# ============================================
# SSL Certificate Setup
# ============================================

# Create SSL directory if it doesn't exist
mkdir -p /data/ssl

# Check if SSL certificate exists
if [ ! -f /data/ssl/cert.pem ]; then
    # Generate self-signed certificate
    SSL_CN="${SSL_COMMON_NAME:-localhost}"
    EXPIRY_DATE=$(date -d "+3650 days" +"%Y-%m-%d")

    echo "  [INFO] Generating self-signed SSL certificate (CN=$SSL_CN)"
    openssl req -x509 -newkey rsa:2048 -nodes \
        -days 3650 \
        -subj "/CN=$SSL_CN" \
        -keyout /data/ssl/key.pem \
        -out /data/ssl/cert.pem

    # Set secure permissions on private key
    chmod 600 /data/ssl/key.pem

    echo "  [OK] Generated self-signed certificate valid until $EXPIRY_DATE"
else
    # Validate that mounted cert and key match
    CERT_MOD=$(openssl x509 -noout -modulus -in /data/ssl/cert.pem 2>/dev/null | openssl md5)
    KEY_MOD=$(openssl rsa -noout -modulus -in /data/ssl/key.pem 2>/dev/null | openssl md5)

    if [ "$CERT_MOD" != "$KEY_MOD" ]; then
        echo "ERROR: SSL certificate and key do not match"
        exit 1
    fi

    echo "  [OK] Using mounted SSL certificate"
fi

echo "==> Starting gunicorn"

exec "$@"
