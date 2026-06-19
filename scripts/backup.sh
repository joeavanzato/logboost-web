#!/bin/sh
# backup.sh - Backup and restore LogBoost databases
#
# Usage:
#   ./scripts/backup.sh                              # Backup to ./backups/
#   ./scripts/backup.sh /path/to/backups             # Backup to custom directory
#   ./scripts/backup.sh backup /path/to/backups      # Same as above (explicit)
#   ./scripts/backup.sh restore [options]            # Restore from a backup
#   ./scripts/backup.sh --help                       # Show usage
#
#   docker exec logboost-web /app/scripts/backup.sh /backups
#   docker exec -it logboost-web /app/scripts/backup.sh restore --from /backups
#
# Backup output:
#   {backup_dir}/logboost_admin_{timestamp}.db
#   {backup_dir}/threats_{timestamp}.db
#   {backup_dir}/latest/ (symlinks to most recent backups)
#
# Restore options:
#   --admin <file>    Restore admin DB from this file
#   --threat <file>   Restore threat DB from this file
#   --from <dir>      Restore both DBs from {dir}/latest/ (default: ./backups)
#   --yes             Skip the interactive confirmation prompt
#   --no-safety-copy  Skip the pre-restore snapshot of the current DBs
#
#   If neither --admin nor --threat is given, both are restored from --from/latest/.

set -e

# Configuration
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

log_info()  { echo "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo "${RED}[ERROR]${NC} $1" >&2; }

usage() {
    sed -n '2,28p' "$0" | sed 's/^# \{0,1\}//'
}

# ============================================================
# BACKUP
# ============================================================
cmd_backup() {
    BACKUP_DIR="${1:-./backups}"

    mkdir -p "${BACKUP_DIR}/latest"

    log_info "Starting backup at $(date)"
    log_info "Backup directory: ${BACKUP_DIR}"

    if [ -f "$ADMIN_DB" ]; then
        ADMIN_BACKUP="${BACKUP_DIR}/logboost_admin_${TIMESTAMP}.db"
        log_info "Backing up admin database: ${ADMIN_DB}"
        if command -v sqlite3 >/dev/null 2>&1; then
            sqlite3 "$ADMIN_DB" ".backup '${ADMIN_BACKUP}'"
        else
            cp "$ADMIN_DB" "$ADMIN_BACKUP"
        fi
        ln -sf "../$(basename "$ADMIN_BACKUP")" "${BACKUP_DIR}/latest/logboost_admin.db"
        log_info "Admin backup complete: ${ADMIN_BACKUP}"
    else
        log_warn "Admin database not found: ${ADMIN_DB}"
    fi

    if [ -f "$THREAT_DB" ]; then
        THREAT_BACKUP="${BACKUP_DIR}/threats_${TIMESTAMP}.db"
        log_info "Backing up threat database: ${THREAT_DB}"
        if command -v sqlite3 >/dev/null 2>&1; then
            sqlite3 "$THREAT_DB" ".backup '${THREAT_BACKUP}'"
        else
            cp "$THREAT_DB" "$THREAT_BACKUP"
        fi
        ln -sf "../$(basename "$THREAT_BACKUP")" "${BACKUP_DIR}/latest/threats.db"
        log_info "Threat backup complete: ${THREAT_BACKUP}"
    else
        log_warn "Threat database not found: ${THREAT_DB}"
    fi

    if [ "$KEEP_DAYS" -gt 0 ]; then
        log_info "Cleaning up backups older than ${KEEP_DAYS} days"
        find "${BACKUP_DIR}" -maxdepth 1 -name "*.db" -type f -mtime +${KEEP_DAYS} -delete 2>/dev/null || true
    fi

    echo ""
    log_info "Backup complete!"
    echo "  Latest backups available at: ${BACKUP_DIR}/latest/"
    [ -f "${BACKUP_DIR}/latest/logboost_admin.db" ] && \
        echo "    - logboost_admin.db -> $(readlink "${BACKUP_DIR}/latest/logboost_admin.db" 2>/dev/null || echo 'linked')"
    [ -f "${BACKUP_DIR}/latest/threats.db" ] && \
        echo "    - threats.db -> $(readlink "${BACKUP_DIR}/latest/threats.db" 2>/dev/null || echo 'linked')"
}

# ============================================================
# RESTORE
# ============================================================

# Verify a backup file exists, is non-empty, and contains the expected tables.
# Args: <file> <expected_table_csv> <label>
verify_backup() {
    file="$1"
    expected="$2"
    label="$3"

    if [ ! -f "$file" ]; then
        log_error "${label} backup not found: ${file}"
        return 1
    fi
    if [ ! -s "$file" ]; then
        log_error "${label} backup is empty: ${file}"
        return 1
    fi
    if ! command -v sqlite3 >/dev/null 2>&1; then
        log_warn "sqlite3 not available — skipping schema check on ${file}"
        return 0
    fi

    # Quick integrity check
    integrity=$(sqlite3 "$file" "PRAGMA integrity_check;" 2>&1) || {
        log_error "${label} backup failed integrity check: ${integrity}"
        return 1
    }
    if [ "$integrity" != "ok" ]; then
        log_error "${label} backup integrity_check returned: ${integrity}"
        return 1
    fi

    # Schema check — at least one expected table must be present
    tables=$(sqlite3 "$file" ".tables" 2>/dev/null | tr ' ' '\n')
    found=0
    for t in $(echo "$expected" | tr ',' ' '); do
        if echo "$tables" | grep -qx "$t"; then
            found=1
            break
        fi
    done
    if [ "$found" -eq 0 ]; then
        log_error "${label} backup does not contain any expected tables (${expected}). Wrong file?"
        return 1
    fi
    return 0
}

# Atomically replace a SQLite DB using sqlite3 .restore.
# Handles WAL connections held open by other processes safely.
# Args: <source_file> <target_file> <label>
restore_db() {
    src="$1"
    dst="$2"
    label="$3"

    if [ ! -d "$(dirname "$dst")" ]; then
        log_error "${label} destination directory does not exist: $(dirname "$dst")"
        return 1
    fi

    if command -v sqlite3 >/dev/null 2>&1 && [ -f "$dst" ]; then
        # .restore is the SQLite-recommended online replacement that respects open connections
        log_info "Restoring ${label} via sqlite3 .restore -> ${dst}"
        sqlite3 "$dst" ".restore '${src}'"
    else
        # Fallback: plain copy. Caller should have stopped the app first.
        log_info "Restoring ${label} via cp -> ${dst}"
        cp "$src" "$dst"
    fi

    # Preserve ownership of the destination if it already had an owner
    if [ -f "$dst" ] && command -v stat >/dev/null 2>&1; then
        owner=$(stat -c '%u:%g' "$dst" 2>/dev/null || true)
        if [ -n "$owner" ] && [ "$owner" != "0:0" ]; then
            chown "$owner" "$dst" 2>/dev/null || true
        fi
    fi
}

cmd_restore() {
    SRC_ADMIN=""
    SRC_THREAT=""
    FROM_DIR=""
    SKIP_CONFIRM=0
    SKIP_SAFETY=0

    while [ $# -gt 0 ]; do
        case "$1" in
            --admin)      SRC_ADMIN="$2"; shift 2 ;;
            --threat)     SRC_THREAT="$2"; shift 2 ;;
            --from)       FROM_DIR="$2"; shift 2 ;;
            --yes|-y)     SKIP_CONFIRM=1; shift ;;
            --no-safety-copy) SKIP_SAFETY=1; shift ;;
            -h|--help)    usage; exit 0 ;;
            *)            log_error "Unknown restore option: $1"; usage; exit 2 ;;
        esac
    done

    # Default: pull from {FROM_DIR or ./backups}/latest/ if no per-DB sources given
    if [ -z "$SRC_ADMIN" ] && [ -z "$SRC_THREAT" ]; then
        FROM_DIR="${FROM_DIR:-./backups}"
        if [ -f "${FROM_DIR}/latest/logboost_admin.db" ]; then
            SRC_ADMIN="${FROM_DIR}/latest/logboost_admin.db"
        fi
        if [ -f "${FROM_DIR}/latest/threats.db" ]; then
            SRC_THREAT="${FROM_DIR}/latest/threats.db"
        fi
    fi

    if [ -z "$SRC_ADMIN" ] && [ -z "$SRC_THREAT" ]; then
        log_error "No backup files specified or found. Use --from <dir> or --admin/--threat <file>."
        exit 2
    fi

    # Resolve symlinks so we operate on the actual files
    [ -n "$SRC_ADMIN" ] && SRC_ADMIN=$(readlink -f "$SRC_ADMIN" 2>/dev/null || echo "$SRC_ADMIN")
    [ -n "$SRC_THREAT" ] && SRC_THREAT=$(readlink -f "$SRC_THREAT" 2>/dev/null || echo "$SRC_THREAT")

    # Verify both
    if [ -n "$SRC_ADMIN" ]; then
        verify_backup "$SRC_ADMIN" "users,settings,audit_log,saved_graphs" "admin" || exit 1
    fi
    if [ -n "$SRC_THREAT" ]; then
        verify_backup "$SRC_THREAT" "ips,feeds,categories" "threat" || exit 1
    fi

    # Show plan + confirm
    echo ""
    log_warn "About to restore the following database(s):"
    [ -n "$SRC_ADMIN" ]  && echo "    admin:  ${SRC_ADMIN}  ->  ${ADMIN_DB}"
    [ -n "$SRC_THREAT" ] && echo "    threat: ${SRC_THREAT}  ->  ${THREAT_DB}"
    echo ""
    log_warn "The CURRENT databases will be overwritten. Open sessions may need to log in again."
    if [ "$SKIP_SAFETY" -eq 0 ]; then
        log_info "A safety snapshot of the current databases will be saved alongside them as *.pre-restore.${TIMESTAMP}.db"
    else
        log_warn "Safety snapshot disabled (--no-safety-copy). Rollback will not be possible."
    fi

    if [ "$SKIP_CONFIRM" -eq 0 ]; then
        printf "Type %sRESTORE%s to proceed: " "${YELLOW}" "${NC}"
        read -r confirm
        if [ "$confirm" != "RESTORE" ]; then
            log_info "Aborted."
            exit 0
        fi
    fi

    # Pre-restore safety snapshot of the CURRENT files
    if [ "$SKIP_SAFETY" -eq 0 ]; then
        if [ -n "$SRC_ADMIN" ] && [ -f "$ADMIN_DB" ]; then
            snap="${ADMIN_DB}.pre-restore.${TIMESTAMP}.db"
            log_info "Snapshotting current admin DB: ${snap}"
            if command -v sqlite3 >/dev/null 2>&1; then
                sqlite3 "$ADMIN_DB" ".backup '${snap}'"
            else
                cp "$ADMIN_DB" "$snap"
            fi
        fi
        if [ -n "$SRC_THREAT" ] && [ -f "$THREAT_DB" ]; then
            snap="${THREAT_DB}.pre-restore.${TIMESTAMP}.db"
            log_info "Snapshotting current threat DB: ${snap}"
            if command -v sqlite3 >/dev/null 2>&1; then
                sqlite3 "$THREAT_DB" ".backup '${snap}'"
            else
                cp "$THREAT_DB" "$snap"
            fi
        fi
    fi

    # Apply restore
    [ -n "$SRC_ADMIN" ]  && restore_db "$SRC_ADMIN"  "$ADMIN_DB"  "admin"
    [ -n "$SRC_THREAT" ] && restore_db "$SRC_THREAT" "$THREAT_DB" "threat"

    echo ""
    log_info "Restore complete."
    if [ "$SKIP_SAFETY" -eq 0 ]; then
        echo "  Pre-restore snapshots are stored next to the live DBs with suffix .pre-restore.${TIMESTAMP}.db"
        echo "  Delete them once you've verified the restore looks correct."
    fi
    echo "  Recommended: restart the container so workers pick up clean connections:"
    echo "    docker restart <container_name>"
}

# ============================================================
# DISPATCH
# ============================================================
case "${1:-}" in
    -h|--help)
        usage
        exit 0
        ;;
    restore)
        shift
        cmd_restore "$@"
        ;;
    backup)
        shift
        cmd_backup "$@"
        ;;
    *)
        # Default: backwards-compatible "backup [dir]" behavior
        cmd_backup "$@"
        ;;
esac
