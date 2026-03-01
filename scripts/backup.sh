#!/bin/sh
# backup.sh - Backup LogBoost databases
#
# Usage:
#   ./scripts/backup.sh                    # Backup to ./backups/
#   ./scripts/backup.sh /path/to/backups   # Backup to custom directory
#   docker exec logboost-web /app/scripts/backup.sh /backups
#
# Backs up:
#   - logboost_admin.db (users, settings, audit logs)
#   - threats.db (threat intelligence data)
#
# Output:
#   {backup_dir}/logboost_admin_{timestamp}.db
#   {backup_dir}/threats_{timestamp}.db
#   {backup_dir}/latest/ (symlinks to most recent backups)

set -e

# Configuration
BACKUP_DIR="${1:-./backups}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
KEEP_DAYS="${BACKUP_KEEP_DAYS:-7}"

# Database paths (container defaults)
ADMIN_DB="${LOGBOOST_DB_PATH:-/data/db/logboost_admin.db}"
THREAT_DB="${THREAT_DB_DIR:-/data/intel}/threats.db"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo "${RED}[ERROR]${NC} $1"
}

# Create backup directory structure
mkdir -p "${BACKUP_DIR}/latest"

log_info "Starting backup at $(date)"
log_info "Backup directory: ${BACKUP_DIR}"

# Backup admin database
if [ -f "$ADMIN_DB" ]; then
    ADMIN_BACKUP="${BACKUP_DIR}/logboost_admin_${TIMESTAMP}.db"
    log_info "Backing up admin database: ${ADMIN_DB}"

    # Use SQLite backup command for consistency (handles WAL mode)
    if command -v sqlite3 >/dev/null 2>&1; then
        sqlite3 "$ADMIN_DB" ".backup '${ADMIN_BACKUP}'"
    else
        # Fallback to copy if sqlite3 not available
        cp "$ADMIN_DB" "$ADMIN_BACKUP"
    fi

    # Update latest symlink
    ln -sf "$(basename "$ADMIN_BACKUP")" "${BACKUP_DIR}/latest/logboost_admin.db"
    log_info "Admin backup complete: ${ADMIN_BACKUP}"
else
    log_warn "Admin database not found: ${ADMIN_DB}"
fi

# Backup threat database
if [ -f "$THREAT_DB" ]; then
    THREAT_BACKUP="${BACKUP_DIR}/threats_${TIMESTAMP}.db"
    log_info "Backing up threat database: ${THREAT_DB}"

    if command -v sqlite3 >/dev/null 2>&1; then
        sqlite3 "$THREAT_DB" ".backup '${THREAT_BACKUP}'"
    else
        cp "$THREAT_DB" "$THREAT_BACKUP"
    fi

    # Update latest symlink
    ln -sf "$(basename "$THREAT_BACKUP")" "${BACKUP_DIR}/latest/threats.db"
    log_info "Threat backup complete: ${THREAT_BACKUP}"
else
    log_warn "Threat database not found: ${THREAT_DB}"
fi

# Cleanup old backups
if [ "$KEEP_DAYS" -gt 0 ]; then
    log_info "Cleaning up backups older than ${KEEP_DAYS} days"
    find "${BACKUP_DIR}" -maxdepth 1 -name "*.db" -type f -mtime +${KEEP_DAYS} -delete 2>/dev/null || true
fi

# Summary
echo ""
log_info "Backup complete!"
echo "  Latest backups available at: ${BACKUP_DIR}/latest/"
if [ -f "${BACKUP_DIR}/latest/logboost_admin.db" ]; then
    echo "    - logboost_admin.db -> $(readlink "${BACKUP_DIR}/latest/logboost_admin.db" 2>/dev/null || echo 'linked')"
fi
if [ -f "${BACKUP_DIR}/latest/threats.db" ]; then
    echo "    - threats.db -> $(readlink "${BACKUP_DIR}/latest/threats.db" 2>/dev/null || echo 'linked')"
fi
