"""
LogBoost Web UI - Flask application for log enrichment
"""

import os
import re
import csv
import json
import sys
import uuid
import secrets
import subprocess
import tempfile
import shutil
import time
import threading
import ipaddress
import logging
import mimetypes
import socket
from pathlib import Path
from datetime import datetime
from functools import wraps
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, quote
from flask import (
    Flask, render_template, request, jsonify, send_file,
    session, redirect, url_for, flash, Response
)
import sqlite3
from werkzeug.utils import secure_filename

# CSRF Protection
from flask_wtf.csrf import CSRFProtect, CSRFError

# Requests library for URL fetching
import requests

# Shodan API
try:
    import shodan
    SHODAN_AVAILABLE = True
except ImportError:
    SHODAN_AVAILABLE = False

# Import security module
from security import (
    is_ip_blocked, validate_url_for_ssrf, safe_fetch_url,
    DEFAULT_MAX_URL_FETCH_SIZE, MAX_REDIRECTS
)

# Import auth module
from auth import login_required, current_user
from http_utils import (
    json_body, str_field, str_list, is_admin, internal_error, upstream_message, upstream_detail, UpstreamError
)

# SECRET_KEY startup validation - fail fast on weak/missing keys
_raw_key = os.environ.get('SECRET_KEY', '')
_KNOWN_WEAK_KEYS = {
    '',
    'dev-placeholder-change-me-in-production',
    'changeme',
    'secret',
    'development',
    'flask-secret-key',
}
_PLACEHOLDER_MARKERS = ('change-me', 'changeme', 'placeholder')  # e.g. the value shipped in .env.example
if (not _raw_key or len(_raw_key) < 32
        or _raw_key.lower() in {k.lower() for k in _KNOWN_WEAK_KEYS}
        or any(marker in _raw_key.lower() for marker in _PLACEHOLDER_MARKERS)):
    sys.stderr.write(
        "FATAL: SECRET_KEY is unset, is a known default or placeholder, or is shorter than "
        "32 characters. The application cannot start.\n"
        "Generate a key: python -c \"import secrets; print(secrets.token_hex(32))\"\n"
    )
    sys.exit(3)  # 3 = gunicorn's "worker failed to boot": the server stops instead of respawning forever

# Some hosts (Windows registry) map .js to text/plain; with X-Content-Type-Options: nosniff the
# browser then refuses the vendored scripts. Pin the type instead of trusting the host.
mimetypes.add_type('text/javascript', '.js')
mimetypes.add_type('font/woff2', '.woff2')

app = Flask(__name__)
app.secret_key = _raw_key

# Behind a reverse proxy, set TRUSTED_PROXY_COUNT to the number of proxies so the real client
# address is used for audit entries and login throttling. Default 0: forwarding headers are ignored.
_trusted_proxies = int(os.environ.get('TRUSTED_PROXY_COUNT') or 0)
if _trusted_proxies:
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=_trusted_proxies, x_proto=_trusted_proxies, x_host=_trusted_proxies)

# ============================================
# Security Configuration
# ============================================

# Session cookie hardening
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,     # Prevent JavaScript access to session cookie
    SESSION_COOKIE_SAMESITE='Lax',    # CSRF mitigation for cross-site requests
    SESSION_COOKIE_SECURE=os.environ.get('FLASK_ENV') == 'production',  # HTTPS only in production
)

# CSRF Protection
# Disable per-token expiry so long-lived single-page views (Intel Browser, Graph, etc.)
# don't get "CSRF token has expired" errors after the default 3600s. The session cookie
# itself still expires normally, which is the real auth boundary.
app.config['WTF_CSRF_TIME_LIMIT'] = None
csrf = CSRFProtect(app)

# ============================================
# Logging Configuration
# ============================================

# Configure logging level via environment variable (disabled by default)
LOG_LEVEL = os.environ.get('LOGBOOST_LOG_LEVEL', 'WARNING').upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.WARNING),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Set Flask app logger level
app.logger.setLevel(getattr(logging, LOG_LEVEL, logging.WARNING))

# Import admin functions (but initialize after CSRF setup)
from admin import init_admin, start_runtime, get_db, db as admin_db, verify_password, ROLE_ADMIN, log_audit, get_effective_logboost_path

# ============================================
# CSRF Configuration
# ============================================

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    """Handle CSRF validation errors."""
    return jsonify({'error': 'CSRF token missing or invalid'}), 400


_CSP_POLICY = (
    "default-src 'self'; "
    # 'unsafe-inline' is required for the existing inline <script>/<style>/onclick blocks.
    # Scripts: htmx, d3 and psl are vendored under static/vendor, so no external hosts.
    # 'unsafe-inline' remains until the inline JavaScript moves to static files.
    "script-src 'self' 'unsafe-inline'; "
    # Google Fonts loads CSS from fonts.googleapis.com.
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src 'self' https://fonts.gstatic.com; "
    # data: + blob: needed for inline SVG icons embedded as background-image and PNG export blobs.
    "img-src 'self' data: blob:; "
    "connect-src 'self'; "
    "frame-ancestors 'self'; "
    "form-action 'self'; "
    "base-uri 'self'; "
    "object-src 'none'"
)

_PERMISSIONS_POLICY = (
    "geolocation=(), microphone=(), camera=(), payment=(), usb=(), "
    "magnetometer=(), accelerometer=(), gyroscope=(), interest-cohort=()"
)


@app.after_request
def add_security_headers(response):
    """Add security headers to every response."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = _CSP_POLICY
    response.headers['Permissions-Policy'] = _PERMISSIONS_POLICY
    # HSTS only on HTTPS responses — pinning HTTP would lock users out on dev/local-IP setups.
    if request.is_secure:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response


# Initialize admin module (with CSRF-enabled blueprint)
init_admin(app, csrf)

# Register route blueprints
from routes import register_blueprints
register_blueprints(app)

# Configuration
UPLOAD_FOLDER = Path(os.environ.get('LOGBOOST_UPLOAD_DIR') or Path(__file__).parent / 'uploads')
OUTPUT_FOLDER = Path(os.environ.get('LOGBOOST_OUTPUT_DIR') or Path(__file__).parent / 'output')
MAXMIND_DIR = os.environ.get('MAXMIND_DIR', '.')

# Required MaxMind database files
REQUIRED_MMDB_FILES = ['GeoLite2-ASN.mmdb', 'GeoLite2-Country.mmdb', 'GeoLite2-City.mmdb']


def check_mmdb_files_exist():
    """Check if all required MaxMind database files exist."""
    maxmind_path = Path(MAXMIND_DIR)
    if not maxmind_path.exists():
        return False, []

    missing = []
    for mmdb_file in REQUIRED_MMDB_FILES:
        if not (maxmind_path / mmdb_file).exists():
            missing.append(mmdb_file)

    return len(missing) == 0, missing

THREAT_DB_DIR = os.environ.get('THREAT_DB_DIR', '.')


def check_threat_db_exists():
    """Check if threats.db exists."""
    # Check both /app/threats.db (symlink) and THREAT_DB_DIR/threats.db
    threat_db_path = Path('/app/threats.db')
    if threat_db_path.exists():
        return True
    threat_db_path = Path(THREAT_DB_DIR) / 'threats.db'
    return threat_db_path.exists()


def setup_steps():
    """The five first-run steps behind the Overview checklist and the sidebar progress card."""
    from admin import get_setting
    with admin_db() as conn:
        schedules_on = conn.execute('SELECT COUNT(*) FROM scheduled_tasks WHERE enabled = 1').fetchone()[0] > 0
    steps = [
        ('admin', True),
        ('geo', check_mmdb_files_exist()[0] or bool(get_setting('maxmind_api_key'))),
        ('threat_db', check_threat_db_exists()),
        ('shodan', bool(get_setting('shodan_api_key'))),
        ('schedules', schedules_on),
    ]
    return {'steps': dict(steps), 'done': sum(1 for _, ok in steps if ok), 'total': len(steps)}


def feed_count():
    """Number of configured threat feeds, or None when the feed config cannot be read."""
    from admin import load_feeds
    try:
        return len(load_feeds())
    except (OSError, ValueError):
        return None


def _as_datetime(value):
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value))
    except ValueError:
        return None


@app.template_filter('ago')
def ago(value):
    """'5 min ago' / 'in 3 hours' for a stored server-local timestamp; the raw value if unparseable."""
    when = _as_datetime(value)
    if when is None:
        return value or ''
    seconds = (datetime.now() - when).total_seconds()
    future, seconds = seconds < 0, abs(seconds)
    if seconds < 60:
        return 'in a moment' if future else 'just now'
    for size, unit in ((86400, 'day'), (3600, 'hour'), (60, 'min')):
        if seconds >= size:
            count = int(seconds // size)
            text = f"{count} {unit}{'s' if count != 1 and unit != 'min' else ''}"
            break
    return f'in {text}' if future else f'{text} ago'


def duration(start, end):
    """'1m 52s' between two stored timestamps; '' when either is missing."""
    start, end = _as_datetime(start), _as_datetime(end)
    if not start or not end:
        return ''
    seconds = max(int((end - start).total_seconds()), 0)
    minutes, seconds = divmod(seconds, 60)
    return f'{minutes}m {seconds:02d}s' if minutes else f'{seconds}s'


@app.context_processor
def inject_shell_helpers():
    """Helpers the shared layout calls; nothing is computed unless a template uses them."""
    return {'setup_steps': setup_steps, 'feed_count': feed_count, 'duration': duration,
            'run_history_days': get_run_history_days}


def _get_threats_db_path():
    """Return Path to threats.db (preferring /app symlink), or None if missing."""
    for p in (Path('/app/threats.db'), Path(THREAT_DB_DIR) / 'threats.db'):
        if p.exists():
            return p
    return None


# Intel stats cache — keyed by threats.db mtime so updates auto-invalidate.
_intel_stats_cache = {'mtime': None, 'data': None}
_intel_stats_lock = threading.Lock()


def _compute_intel_stats():
    """Run aggregate queries against threats.db. Returns dict or None if DB missing."""
    db_path = _get_threats_db_path()
    if not db_path:
        return None
    uri = f'file:{db_path.as_posix()}?mode=ro'
    conn = sqlite3.connect(uri, uri=True, timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        total_entries = conn.execute('SELECT COUNT(*) FROM ips').fetchone()[0]
        unique_ips = conn.execute('SELECT COUNT(DISTINCT ip) FROM ips').fetchone()[0]
        sources = conn.execute('''
            SELECT feeds.feed_id AS id, feeds.feed_name AS name, COUNT(*) AS cnt
            FROM ips LEFT JOIN feeds ON ips.feed = feeds.feed_id
            GROUP BY feeds.feed_id, feeds.feed_name ORDER BY cnt DESC
        ''').fetchall()
        tags = conn.execute('''
            SELECT categories.category_id AS id, categories.category_value AS value, COUNT(*) AS cnt
            FROM ips LEFT JOIN categories ON ips.category = categories.category_id
            GROUP BY categories.category_id, categories.category_value ORDER BY cnt DESC
        ''').fetchall()
        return {
            'total_entries': total_entries,
            'unique_ips': unique_ips,
            'sources': [{'id': r['id'], 'name': r['name'] or '(unknown)', 'count': r['cnt']} for r in sources],
            'tags': [{'id': r['id'], 'value': r['value'] or '(unknown)', 'count': r['cnt']} for r in tags],
        }
    finally:
        conn.close()


def _get_intel_stats():
    """Return cached intel stats; recompute synchronously if threats.db mtime changed."""
    db_path = _get_threats_db_path()
    if not db_path:
        return None
    current_mtime = db_path.stat().st_mtime
    cached_data = _intel_stats_cache.get('data')
    if cached_data is not None and _intel_stats_cache.get('mtime') == current_mtime:
        return cached_data

    # Single-flight: only one thread should recompute at a time. Others wait then re-check.
    with _intel_stats_lock:
        # Re-check inside the lock — another thread may have just refreshed.
        if _intel_stats_cache.get('data') is not None and _intel_stats_cache.get('mtime') == current_mtime:
            return _intel_stats_cache['data']
        try:
            start = time.monotonic()
            data = _compute_intel_stats()
            if data is not None:
                _intel_stats_cache['mtime'] = current_mtime
                _intel_stats_cache['data'] = data
                app.logger.info('Intel: stats recomputed in %.2fs (db mtime=%s)',
                                time.monotonic() - start, current_mtime)
            return data
        except Exception as e:
            app.logger.warning('Intel: stats compute failed: %s', e)
            return cached_data  # serve stale if any


def _ensure_intel_indexes():
    """Create indexes on threats.db ips table to speed up the Intel Browser.

    Runs in a background daemon thread at startup so worker boot isn't blocked
    while a multi-million-row index builds. CREATE INDEX IF NOT EXISTS makes
    this safe to call on every start; subsequent runs are O(metadata).
    """
    db_path = _get_threats_db_path()
    if not db_path:
        return  # threats.db not present yet (first install) — nothing to index

    indexes = [
        ('idx_ips_ip', 'ip'),
        ('idx_ips_feed', 'feed'),
        ('idx_ips_category', 'category'),
    ]

    try:
        # Writable connection (intel browser endpoints use a separate read-only one)
        conn = sqlite3.connect(str(db_path), timeout=60)
        try:
            existing = {row[0] for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index'"
            ).fetchall()}

            to_create = [(n, c) for n, c in indexes if n not in existing]
            if not to_create:
                app.logger.info('Intel: indexes already present on threats.db')
                return

            app.logger.info('Intel: building %d index(es) on threats.db (this may take a few minutes on a large DB)...',
                            len(to_create))
            for idx_name, column in to_create:
                start = time.monotonic()
                conn.execute(f'CREATE INDEX IF NOT EXISTS {idx_name} ON ips({column})')
                conn.commit()
                app.logger.info('Intel: created %s in %.1fs', idx_name, time.monotonic() - start)
        finally:
            conn.close()
    except sqlite3.OperationalError as e:
        # "database is locked" can happen if LogBoost binary is mid-update.
        # Next startup will retry.
        app.logger.warning('Intel: index build skipped (%s) — will retry next startup', e)
    except Exception as e:
        app.logger.warning('Intel: index build failed: %s', e)


def _warm_intel_caches():
    """Background startup task: ensure indexes exist, then prime the stats cache."""
    _ensure_intel_indexes()
    try:
        _get_intel_stats()  # primes the cache so the first user click is instant
    except Exception as e:
        app.logger.warning('Intel: stats prime failed: %s', e)


_runtime_started = False


def create_app():
    """Run startup side effects and return the app. Importing this module has none.

    ponytail: routes stay module-level on one global app; move them to blueprints
    if more than one app instance per process is ever needed.
    """
    global _runtime_started
    if not _runtime_started:
        _runtime_started = True
        UPLOAD_FOLDER.mkdir(exist_ok=True)
        OUTPUT_FOLDER.mkdir(exist_ok=True)
        start_runtime()  # DB schema, binary override, scheduler
        threading.Thread(target=_warm_intel_caches, daemon=True, name='intel-warmup').start()
    return app

# File extensions that LogBoost can auto-detect
ALLOWED_EXTENSIONS = {
    'csv', 'log', 'txt', 'json', 'gz', 'cef', 'syslog'
}

# Maximum upload file size (100MB default)
MAX_UPLOAD_SIZE_MB = 100
app.config['MAX_CONTENT_LENGTH'] = MAX_UPLOAD_SIZE_MB * 1024 * 1024


def allowed_file(filename):
    """Check if file extension is in the allowed list."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.errorhandler(413)
def request_entity_too_large(error):
    """Handle file too large errors."""
    return render_template('partials/error.html', 
        error=f'File too large. Maximum upload size is {MAX_UPLOAD_SIZE_MB}MB.'), 413


# ============================================
# Authentication
# ============================================

# login_required decorator is imported from auth.py
# login/logout routes are in routes/auth_routes.py


# ============================================
# Helper Functions
# ============================================

def _assert_within(path: Path, base: Path) -> Path:
    """Resolve path and assert containment within base. Raises ValueError if not."""
    resolved = path.resolve()
    base_resolved = base.resolve()
    try:
        resolved.relative_to(base_resolved)
    except ValueError:
        raise ValueError(
            f"Security: path {resolved!r} resolves outside of {base_resolved!r}"
        )
    return resolved


def current_output_path():
    """The session's result file as a Path, or None when there is none, it no longer exists,
    or the stored value points outside OUTPUT_FOLDER."""
    raw = session.get('current_output')
    if not raw:
        return None
    try:
        path = _assert_within(Path(raw), OUTPUT_FOLDER)
    except (ValueError, OSError):
        return None
    return path if path.is_file() else None


# LogBoost runs inside the request for up to five minutes. Two at a time leaves the remaining
# gunicorn threads free for the rest of the app; further callers are refused straight away.
# ponytail: in-process semaphore, correct only because gunicorn runs a single worker.
# Background jobs with a queue are the upgrade path.
MAX_CONCURRENT_ENRICHMENTS = 2
_enrich_slots = threading.BoundedSemaphore(MAX_CONCURRENT_ENRICHMENTS)
BUSY_MESSAGE = 'The server is busy with other enrichments. Please try again in a moment.'


def limit_enrichments(as_json=False):
    """Refuse the request immediately when MAX_CONCURRENT_ENRICHMENTS LogBoost runs are in flight."""
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not _enrich_slots.acquire(blocking=False):
                if as_json:
                    return jsonify({'error': BUSY_MESSAGE}), 503
                return render_template('partials/error.html', error=BUSY_MESSAGE)
            try:
                return fn(*args, **kwargs)
            finally:
                _enrich_slots.release()
        return wrapper
    return decorator


def extract_ips(text: str) -> list[str]:
    """Extract all unique IP addresses from text, including defanged IPs."""
    # Use the IOC extraction function which handles defanged IPs and validates public IPs
    ips, _ = extract_iocs_from_text(text)
    return ips


def create_ip_csv(ips: list[str], output_path: Path) -> None:
    """Create a CSV file with IP addresses for LogBoost processing."""
    with open(output_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['IP'])
        for ip in ips:
            writer.writerow([ip])


def build_logboost_command(
    input_dir: str,
    output_dir: str,
    options: dict
) -> list[str]:
    """Build the LogBoost command with all options."""
    cmd = [get_effective_logboost_path()]
    
    # Required directories
    cmd.extend(['-logdir', input_dir])
    cmd.extend(['-outputdir', output_dir])
    
    # MaxMind directory
    dbdir = options.get('dbdir', MAXMIND_DIR)
    if dbdir:
        cmd.extend(['-dbdir', dbdir])

    # Enrichment options
    if options.get('dns'):
        cmd.append('-dns')
    if options.get('whois'):
        cmd.append('-whois')
    if options.get('idb'):
        cmd.append('-idb')
    if options.get('useti'):
        cmd.append('-useti')
        cmd.extend(['-tidb', '/app/threats.db'])

    # Processing options
    if options.get('regex'):
        cmd.append('-regex')
    if options.get('convert'):
        cmd.append('-convert')
    if options.get('fullparse'):
        cmd.append('-fullparse')
    if options.get('rawtxt'):
        cmd.append('-rawtxt')
    if options.get('getall'):
        cmd.append('-getall')
    if options.get('combine'):
        cmd.append('-combine')
    if options.get('passthrough'):
        cmd.append('-passthrough')
    
    # Column specifications
    if options.get('ipcol'):
        cmd.extend(['-ipcol', options['ipcol']])
    if options.get('jsoncol'):
        cmd.extend(['-jsoncol', options['jsoncol']])
    
    # KV parsing options
    if options.get('separator'):
        cmd.extend(['-separator', options['separator']])
    if options.get('delimiter'):
        cmd.extend(['-delimiter', options['delimiter']])
    
    # Date filtering
    if options.get('startdate'):
        cmd.extend(['-startdate', options['startdate']])
    if options.get('enddate'):
        cmd.extend(['-enddate', options['enddate']])
    if options.get('datecol'):
        cmd.extend(['-datecol', options['datecol']])
    if options.get('dateformat'):
        cmd.extend(['-dateformat', options['dateformat']])
    
    # Performance options
    if options.get('maxgoperfile'):
        cmd.extend(['-maxgoperfile', str(options['maxgoperfile'])])
    if options.get('batchsize'):
        cmd.extend(['-batchsize', str(options['batchsize'])])
    if options.get('writebuffer'):
        cmd.extend(['-writebuffer', str(options['writebuffer'])])
    if options.get('concurrentfiles'):
        cmd.extend(['-concurrentfiles', str(options['concurrentfiles'])])
    
    return cmd


def run_logboost(cmd: list[str]) -> tuple[bool, str, str]:
    """Execute LogBoost and return success status and output."""
    # Log exact command line for debugging
    cmd_str = ' '.join(cmd)
    app.logger.info(f"LogBoost command: {cmd_str}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
        )
        return result.returncode == 0, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return False, '', 'LogBoost execution timed out after 5 minutes'
    except FileNotFoundError:
        return False, '', f'LogBoost binary not found at: {get_effective_logboost_path()}'
    except Exception:
        app.logger.exception('LogBoost could not be started')
        return False, '', 'LogBoost could not be started'


def read_csv_paginated(
    filepath: Path,
    page: int = 1,
    page_size: int = 50
) -> dict:
    """Read CSV file with pagination using streaming (memory-efficient)."""
    rows = []
    headers = []
    total_rows = 0
    
    try:
        # First pass: count total rows (streaming, no memory accumulation)
        with open(filepath, 'r', newline='', encoding='utf-8', errors='replace') as f:
            reader = csv.reader(f)
            headers = next(reader, [])
            for _ in reader:
                total_rows += 1
        
        # Second pass: get only the rows we need (streaming)
        start_idx = (page - 1) * page_size
        end_idx = start_idx + page_size
        
        with open(filepath, 'r', newline='', encoding='utf-8', errors='replace') as f:
            reader = csv.reader(f)
            next(reader)  # Skip header
            
            for idx, row in enumerate(reader):
                if idx >= end_idx:
                    break  # Stop reading once we have enough
                if idx >= start_idx:
                    rows.append(row)
            
    except Exception:
        app.logger.exception('Could not read results file')
        return {
            'error': 'Could not read results file',
            'headers': [],
            'rows': [],
            'total_rows': 0,
            'page': page,
            'page_size': page_size,
            'total_pages': 0
        }
    
    total_pages = (total_rows + page_size - 1) // page_size if total_rows > 0 else 1
    
    return {
        'headers': headers,
        'rows': rows,
        'total_rows': total_rows,
        'page': page,
        'page_size': page_size,
        'total_pages': total_pages
    }


def read_csv_all(filepath: Path, max_rows=None) -> dict:
    """Read a CSV for client-side processing. With max_rows, only that many rows are kept;
    total_rows always counts the whole file."""
    rows = []
    headers = []
    total_rows = 0

    try:
        with open(filepath, 'r', newline='', encoding='utf-8', errors='replace') as f:
            reader = csv.reader(f)
            headers = next(reader, [])
            for row in reader:
                total_rows += 1
                if max_rows is None or total_rows <= max_rows:
                    rows.append(row)

    except Exception:
        app.logger.exception('Could not read results file')
        return {
            'error': 'Could not read results file',
            'headers': [],
            'rows': [],
            'total_rows': 0
        }

    return {
        'headers': headers,
        'rows': rows,
        'total_rows': total_rows
    }


def get_session_dir(session_id: str) -> Path:
    """Get or create session-specific directories."""
    session_upload = UPLOAD_FOLDER / session_id
    session_output = OUTPUT_FOLDER / session_id
    _assert_within(session_upload, UPLOAD_FOLDER)
    _assert_within(session_output, OUTPUT_FOLDER)
    session_upload.mkdir(exist_ok=True)
    session_output.mkdir(exist_ok=True)
    return session_upload, session_output


SESSION_DIR_MAX_AGE_DAYS = 7  # a session ends 7 days after login at the latest


def sweep_session_dirs(max_age_days: int = SESSION_DIR_MAX_AGE_DAYS) -> int:
    """Remove upload/output directories untouched for max_age_days: what is left behind when a
    session ends without a logout (closed browser, expired cookie). Returns how many were removed."""
    cutoff = time.time() - max_age_days * 86400
    removed = 0
    for base in (UPLOAD_FOLDER, OUTPUT_FOLDER):
        if not base.is_dir():
            continue
        for entry in base.iterdir():
            try:
                if not entry.is_dir() or entry.name == RUNS_DIRNAME:
                    continue
                newest = max([entry.stat().st_mtime] + [child.stat().st_mtime for child in entry.iterdir()])
                if newest < cutoff:
                    shutil.rmtree(entry)
                    removed += 1
            except OSError:
                app.logger.warning('Could not sweep session directory %s', entry, exc_info=True)
    if removed:
        app.logger.info('Removed %d stale session directories', removed)
    return removed


def cleanup_session(session_id: str) -> None:
    """Clean up session directories."""
    session_upload = UPLOAD_FOLDER / session_id
    session_output = OUTPUT_FOLDER / session_id
    _assert_within(session_upload, UPLOAD_FOLDER)
    _assert_within(session_output, OUTPUT_FOLDER)
    if session_upload.exists():
        shutil.rmtree(session_upload)
    if session_output.exists():
        shutil.rmtree(session_output)


def reset_session_dirs():
    """Empty this session's upload and output directories (subdirectories included) and
    return them as (upload, output)."""
    session_id = session.get('session_id')
    if not session_id:
        session_id = session['session_id'] = str(uuid.uuid4())
    session_upload, session_output = get_session_dir(session_id)
    for directory in (session_upload, session_output):
        shutil.rmtree(directory, ignore_errors=True)
        directory.mkdir(parents=True, exist_ok=True)
    return session_upload, session_output


# ---- run history ----
# Every finished enrichment is kept for run_history_days so its results can be reopened. A run
# belongs to the user who started it; nobody else, administrators included, can list or open it.
RUNS_DIRNAME = '_runs'
RUN_OPTION_KEYS = ('dns', 'whois', 'idb', 'useti')  # the source toggles shown in the run list


def get_run_history_days() -> int:
    from admin import get_int_setting
    return get_int_setting('run_history_days', 7, 1, 365)


def finish_run(output_file: Path, kind: str, label: str, options: dict,
               ip_count=None, input_text=None) -> dict:
    """Make `output_file` the session's current result and return its template data. The file is
    first moved into the user's run history; if that fails the run still completes from where
    the file is, just without a history entry."""
    run_id = secrets.token_urlsafe(12)
    try:
        run_dir = OUTPUT_FOLDER / RUNS_DIRNAME / str(session['user_id']) / run_id
        run_dir.mkdir(parents=True)
        stored = Path(shutil.move(str(output_file), str(run_dir / output_file.name)))
    except (OSError, KeyError):
        app.logger.warning('Could not store run %s in the run history', run_id, exc_info=True)
        stored, run_id = output_file, None

    session['current_output'] = str(stored)
    data = results_payload(stored)
    if ip_count is not None:
        data['ip_count'] = ip_count

    if run_id:
        try:
            with admin_db() as conn:
                conn.execute(
                    '''INSERT INTO enrichment_runs
                       (id, user_id, kind, label, ip_count, row_count, options, input_text, output_path)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                    (run_id, session['user_id'], kind, label, ip_count, data.get('total_rows', 0),
                     json.dumps({key: bool(options.get(key)) for key in RUN_OPTION_KEYS}),
                     input_text, str(stored)))
                conn.commit()
        except sqlite3.Error:
            app.logger.warning('Could not record run %s', run_id, exc_info=True)
    return data


def _own_run(run_id: str):
    """The run row if it belongs to the signed-in user and its file is still there, else None."""
    with admin_db() as conn:
        run = conn.execute('SELECT * FROM enrichment_runs WHERE id = ? AND user_id = ?',
                           (run_id, session.get('user_id'))).fetchone()
    if not run:
        return None
    try:
        path = _assert_within(Path(run['output_path']), OUTPUT_FOLDER / RUNS_DIRNAME)
    except (ValueError, OSError):
        return None
    return run if path.is_file() else None


def _remove_run_files(output_path: str) -> None:
    """Delete a run's directory; never anything outside the run store."""
    try:
        run_dir = _assert_within(Path(output_path), OUTPUT_FOLDER / RUNS_DIRNAME).parent
        if run_dir.parent.parent == (OUTPUT_FOLDER / RUNS_DIRNAME).resolve():
            shutil.rmtree(run_dir, ignore_errors=True)
    except (ValueError, OSError):
        app.logger.warning('Could not remove run files at %s', output_path, exc_info=True)


def cleanup_old_runs() -> int:
    """Housekeeping: drop runs older than run_history_days, rows and files. Returns the count."""
    with admin_db() as conn:
        old = conn.execute(
            "SELECT id, output_path FROM enrichment_runs WHERE created_at < datetime('now', ?)",
            (f'-{get_run_history_days()} days',)).fetchall()
        for run in old:
            _remove_run_files(run['output_path'])
        conn.executemany('DELETE FROM enrichment_runs WHERE id = ?', [(run['id'],) for run in old])
        conn.commit()
    if old:
        app.logger.info('Removed %d expired runs', len(old))
    return len(old)


@app.route('/runs')
@login_required
def list_runs():
    """The signed-in user's past runs, newest first."""
    with admin_db() as conn:
        rows = conn.execute(
            '''SELECT id, kind, label, ip_count, row_count, options, created_at, output_path,
                      input_text IS NOT NULL AS has_input
               FROM enrichment_runs WHERE user_id = ? ORDER BY created_at DESC, rowid DESC LIMIT 200''',
            (session.get('user_id'),)).fetchall()
    runs = []
    for row in rows:
        if not Path(row['output_path']).is_file():
            continue
        try:
            options = json.loads(row['options'] or '{}')
        except ValueError:
            options = {}
        runs.append({
            'id': row['id'], 'kind': row['kind'], 'label': row['label'],
            'ip_count': row['ip_count'], 'row_count': row['row_count'],
            'sources': [key for key in RUN_OPTION_KEYS if options.get(key)],
            'created_at': str(row['created_at']).replace(' ', 'T') + 'Z',  # stored in UTC
            'can_edit': bool(row['has_input']),
        })
    return jsonify({'runs': runs, 'retention_days': get_run_history_days()})


@app.route('/runs/<run_id>')
@login_required
def open_run(run_id):
    """Reopen a past run: it becomes the session's current result."""
    run = _own_run(run_id)
    if not run:
        return render_template('partials/error.html', error='That run is no longer available.'), 404
    path = Path(run['output_path'])
    session['current_output'] = str(path)
    data = results_payload(path)
    if run['ip_count'] is not None:
        data['ip_count'] = run['ip_count']
    if run['kind'] == 'file':
        data['original_filename'] = run['label']
    return render_template('partials/results.html', **data)


@app.route('/runs/<run_id>/input')
@login_required
def run_input(run_id):
    """The pasted text and source toggles of a text run, for "Edit input"."""
    run = _own_run(run_id)
    if not run or run['input_text'] is None:
        return jsonify({'error': 'No stored input for this run'}), 404
    try:
        options = json.loads(run['options'] or '{}')
    except ValueError:
        options = {}
    return jsonify({'text': run['input_text'], 'options': options})


@app.route('/runs/<run_id>/delete', methods=['POST'])
@login_required
def delete_run(run_id):
    with admin_db() as conn:
        run = conn.execute('SELECT output_path FROM enrichment_runs WHERE id = ? AND user_id = ?',
                           (run_id, session.get('user_id'))).fetchone()
        if not run:
            return jsonify({'error': 'Run not found'}), 404
        conn.execute('DELETE FROM enrichment_runs WHERE id = ?', (run_id,))
        conn.commit()
    if current_output_path() and session.get('current_output') == run['output_path']:
        session.pop('current_output', None)
    _remove_run_files(run['output_path'])
    return jsonify({'success': True})


def results_payload(output_file: Path) -> dict:
    """Template data for a result file. At most max_embedded_rows rows go into the page;
    total_rows, statistics and the CSV download always cover the whole file."""
    max_rows = get_max_embedded_rows()
    data = read_csv_all(output_file, max_rows=max_rows)
    data['filename'] = output_file.name
    data['page_size'] = request.form.get('page_size', 50, type=int)
    total_rows = data.get('total_rows', 0)
    if total_rows > max_rows:
        data['rows_embedded'] = max_rows
    elif total_rows > get_large_file_warning_threshold():
        data['large_file_warning'] = (
            f"This result set has {total_rows:,} rows, which may affect browser performance. "
            f"Consider using filters or downloading the CSV for analysis in a spreadsheet application."
        )
    return data


@app.route('/')
@login_required
def index():
    """Main page."""
    # Check if required MMDB files exist
    mmdb_available, missing_files = check_mmdb_files_exist()
    if not mmdb_available:
        return render_template('setup_required.html',
                               missing_files=missing_files,
                               required_files=REQUIRED_MMDB_FILES,
                               maxmind_dir=MAXMIND_DIR,
                               is_admin=session.get('user_role') == ROLE_ADMIN)

    # Check if threat database exists
    threat_db_missing = not check_threat_db_exists()

    # Check for shared results
    shared_id = request.args.get('shared')
    if shared_id:
        shared = get_shared_results_meta(shared_id)
        if shared:
            return render_template('index.html', shared_results=shared_id, threat_db_missing=threat_db_missing)
    return render_template('index.html', threat_db_missing=threat_db_missing)


@app.route('/enrich/text', methods=['POST'])
@login_required
@limit_enrichments()
def enrich_text():
    """Enrich IP addresses extracted from pasted text."""
    session_upload, session_output = reset_session_dirs()

    text = request.form.get('text', '')
    if not text.strip():
        return render_template('partials/error.html', error='No text provided')
    
    # Extract IPs (subprocess; raises ValueError when too large or too slow)
    try:
        ips = extract_ips(text)
    except ValueError as e:
        return render_template('partials/error.html', error=str(e))
    if not ips:
        return render_template('partials/error.html', error='No IP addresses found in the provided text')
    
    # Check adhoc IP limit (configurable in admin settings)
    max_adhoc = get_max_adhoc_ips()
    if len(ips) > max_adhoc:
        return render_template('partials/error.html', 
            error=f'Too many IP addresses ({len(ips):,}). Ad-hoc enrichment is limited to {max_adhoc:,} IPs. '
                  f'For larger datasets, please use file upload instead.')
    
    # Create input CSV
    input_file = session_upload / 'input.csv'
    create_ip_csv(ips, input_file)
    
    # Build options from form
    options = {
        'regex': False,  # We're using specific column
        'ipcol': 'IP',
        'dns': request.form.get('dns') == 'on',
        'whois': request.form.get('whois') == 'on',
        'idb': request.form.get('idb') == 'on',
        'useti': request.form.get('useti') == 'on',
    }
    
    # Add performance options if provided
    if request.form.get('maxgoperfile'):
        try:
            options['maxgoperfile'] = int(request.form.get('maxgoperfile'))
        except ValueError:
            pass
    if request.form.get('batchsize'):
        try:
            options['batchsize'] = int(request.form.get('batchsize'))
        except ValueError:
            pass
    
    # Run LogBoost
    cmd = build_logboost_command(str(session_upload), str(session_output), options)
    success, stdout, stderr = run_logboost(cmd)
    
    if not success:
        error_msg = stderr or 'LogBoost execution failed'
        return render_template('partials/error.html', error=error_msg,
                               command=' '.join(cmd) if is_admin() else None)
    
    # Find output file
    output_files = list(session_output.glob('*.csv'))
    if not output_files:
        return render_template('partials/error.html', error='No output file generated')
    
    data = finish_run(output_files[0], 'text', 'Pasted text', options, ip_count=len(ips), input_text=text)

    log_audit('logboost_enrich', 'logboost', None, {'source': 'text', 'ip_count': len(ips)})
    return render_template('partials/results.html', **data)


@app.route('/enrich/file', methods=['POST'])
@login_required
@limit_enrichments()
def enrich_file():
    """Enrich uploaded log file."""
    session_upload, session_output = reset_session_dirs()

    if 'file' not in request.files:
        return render_template('partials/error.html', error='No file uploaded')
    
    file = request.files['file']
    if file.filename == '':
        return render_template('partials/error.html', error='No file selected')
    
    # Validate file extension
    filename = secure_filename(file.filename)
    if not filename:
        return render_template('partials/error.html', error='Invalid filename')
    
    if not allowed_file(filename):
        allowed_list = ', '.join(sorted(ALLOWED_EXTENSIONS))
        return render_template('partials/error.html', 
            error=f'Invalid file type. Allowed extensions: {allowed_list}')
    
    # Save uploaded file
    input_file = session_upload / filename
    file.save(input_file)
    
    # Build options from form
    options = {
        'convert': True,
        'getall': True,
        'regex': request.form.get('regex') == 'on',
        'fullparse': request.form.get('fullparse') == 'on',
        'rawtxt': request.form.get('rawtxt') == 'on',
        'combine': request.form.get('combine') == 'on',
        'passthrough': request.form.get('passthrough') == 'on',
        'dns': request.form.get('dns') == 'on',
        'whois': request.form.get('whois') == 'on',
        'idb': request.form.get('idb') == 'on',
        'useti': request.form.get('useti') == 'on',
        'dbdir': MAXMIND_DIR,
    }
    
    # Column options
    if not options['regex'] and request.form.get('ipcol'):
        options['ipcol'] = request.form.get('ipcol')
    if request.form.get('jsoncol'):
        options['jsoncol'] = request.form.get('jsoncol')
    
    # KV options
    if request.form.get('separator'):
        options['separator'] = request.form.get('separator')
    if request.form.get('delimiter'):
        options['delimiter'] = request.form.get('delimiter')
    
    # Date filtering
    if request.form.get('startdate'):
        options['startdate'] = request.form.get('startdate')
    if request.form.get('enddate'):
        options['enddate'] = request.form.get('enddate')
    if request.form.get('datecol'):
        options['datecol'] = request.form.get('datecol')
    if request.form.get('dateformat'):
        options['dateformat'] = request.form.get('dateformat')
    
    # Performance options
    if request.form.get('maxgoperfile'):
        try:
            options['maxgoperfile'] = int(request.form.get('maxgoperfile'))
        except ValueError:
            pass
    if request.form.get('batchsize'):
        try:
            options['batchsize'] = int(request.form.get('batchsize'))
        except ValueError:
            pass
    
    # Run LogBoost
    cmd = build_logboost_command(str(session_upload), str(session_output), options)
    success, stdout, stderr = run_logboost(cmd)
    
    if not success:
        error_msg = stderr or 'LogBoost execution failed'
        return render_template('partials/error.html', error=error_msg,
                               command=' '.join(cmd) if is_admin() else None)
    
    # Find output file
    output_files = list(session_output.glob('**/*.csv'))
    if not output_files:
        return render_template('partials/error.html', error='No output file generated')
    
    data = finish_run(output_files[0], 'file', filename, options)
    data['original_filename'] = filename

    log_audit('logboost_enrich', 'logboost', None, {'source': 'file', 'filename': filename, 'row_count': data.get('total_rows', 0)})
    return render_template('partials/results.html', **data)


@app.route('/results/page', methods=['GET'])
@login_required
def results_page():
    """Get a specific page of results."""
    output_path = current_output_path()
    if not output_path:
        return render_template('partials/error.html', error='No results available')

    page = max(1, request.args.get('page', 1, type=int))
    page_size = max(1, min(1000, request.args.get('page_size', 50, type=int)))

    data = read_csv_paginated(output_path, page=page, page_size=page_size)
    data['filename'] = output_path.name

    return render_template('partials/results_table.html', **data)


@app.route('/download')
@login_required
def download():
    """Download the current result file."""
    output_path = current_output_path()
    if not output_path:
        return 'No file available', 404

    return send_file(
        output_path,
        as_attachment=True,
        download_name=output_path.name
    )


@app.route('/clear', methods=['POST'])
@login_required
def clear():
    """Clear current session data."""
    session_id = session.get('session_id')
    if session_id:
        cleanup_session(session_id)
    session.pop('current_output', None)
    return ''


@app.route('/health')
def health():
    """Health check endpoint.

    Health determination (per deployment requirements):
    - UNHEALTHY (503): Database inaccessible (Flask being up is implicit — we're responding)
    - HEALTHY (200): App responds and database is accessible
    - DEGRADED but HEALTHY (200): LogBoost binary not found or external APIs unreachable
      (core app still works for cached data and admin functions)
    """
    # Check if LogBoost binary exists
    # Handle both absolute paths and PATH lookups
    effective_binary = get_effective_logboost_path()
    if os.path.isabs(effective_binary):
        logboost_available = Path(effective_binary).exists()
    else:
        logboost_available = shutil.which(effective_binary) is not None

    # Check database accessibility — use try/finally to prevent connection leak
    try:
        with admin_db() as conn:
            conn.execute("SELECT 1")
        db_accessible = True
    except Exception:
        db_accessible = False

    # Check MaxMind databases present
    maxmind_path = Path(MAXMIND_DIR)
    maxmind_available = bool(list(maxmind_path.glob('*.mmdb'))) if maxmind_path.exists() else False

    # Check uploads and output directories are writable
    uploads_writable = UPLOAD_FOLDER.exists() and os.access(str(UPLOAD_FOLDER), os.W_OK)
    output_writable = OUTPUT_FOLDER.exists() and os.access(str(OUTPUT_FOLDER), os.W_OK)

    # Health logic: only mark unhealthy if database is down
    # Flask being up is implicit (we're responding to this request)
    # LogBoost binary missing = degraded, NOT unhealthy
    is_healthy = db_accessible

    status_code = 200 if is_healthy else 503
    status_text = 'ok' if is_healthy else 'unhealthy'

    # Add degraded indicator when binary is missing but app is healthy
    if is_healthy and not logboost_available:
        status_text = 'degraded'

    body = {
        'status': status_text,
        'db_accessible': db_accessible,
        'logboost_available': logboost_available,
        'maxmind_available': maxmind_available,
        'uploads_writable': uploads_writable,
        'output_writable': output_writable,
    }
    user = current_user()
    if user and user['role'] == ROLE_ADMIN:  # filesystem layout is not for anonymous callers
        body.update(logboost_path=get_effective_logboost_path(), maxmind_dir=MAXMIND_DIR,
                    threat_db_dir=THREAT_DB_DIR)
    return jsonify(body), status_code


@app.route('/stats')
@login_required
def get_stats():
    """Statistics for the current result file, or with ?shared=<id> for a shared result set."""
    share_id = request.args.get('shared')
    if share_id:
        stats = get_shared_results_stats(share_id)
        if not stats:
            return render_template('partials/error.html',
                                   error='Statistics are not available for these shared results')
        return render_template('partials/stats.html', stats=stats, share_id=share_id)

    output_path = current_output_path()
    if not output_path:
        return render_template('partials/error.html', error='No results available for statistics')

    return render_template('partials/stats.html', stats=cached_statistics(output_path))


# Summary sections whose all_* lists can be fetched for the statistics modal
STAT_VALUE_SECTIONS = ('threat_summary', 'geo_summary', 'dns_summary', 'whois_summary', 'shodan_summary')


@app.route('/stats/values/<section>/<name>')
@login_required
def get_stat_values(section: str, name: str):
    """Full value list behind one statistics card, fetched when its modal opens."""
    stats = {}
    if section in STAT_VALUE_SECTIONS and name.startswith('all_'):
        share_id = request.args.get('shared')
        if share_id:
            stats = get_shared_results_stats(share_id) or {}
        else:
            output_path = current_output_path()
            stats = cached_statistics(output_path) if output_path else {}

    return jsonify({
        'values': stats.get(section, {}).get(name) or [],
        'total_rows': stats.get('total_rows', 0)
    })


@app.route('/column-values/<column_name>')
@login_required
def get_column_values(column_name: str):
    """Get unique values for a specific column (for filter dropdowns)."""
    output_path = current_output_path()
    if not output_path:
        return jsonify({'values': []})

    return jsonify({'values': get_unique_column_values(output_path, column_name, limit=100)})


def _pipe_counts(pairs) -> list:
    """Total the counts of the items inside pipe-separated values: [(item, count)], most common first."""
    totals = {}
    for value, count in pairs:
        if value and value != 'none':
            for item in value.split('|'):
                item = item.strip()
                if item:
                    totals[item] = totals.get(item, 0) + count
    return sorted(totals.items(), key=lambda x: x[1], reverse=True)


def compute_statistics(filepath: Path) -> dict:
    """Compute comprehensive statistics for a CSV file.

    Rows are streamed. Each column tracks at most max_unique_values distinct values; once a
    column hits that limit its unique count is a lower bound (unique_count_truncated).
    """
    max_unique = get_max_unique_values()

    stats = {
        'total_rows': 0,
        'total_columns': 0,
        'columns': [],
        'enrichment_summary': {},
        'threat_summary': {},
        'geo_summary': {},
        'dns_summary': {},
        'whois_summary': {},
        'shodan_summary': {},
        'warnings': []  # Track any warnings about truncated data
    }

    try:
        with open(filepath, 'r', newline='', encoding='utf-8', errors='replace') as f:
            reader = csv.DictReader(f)
            headers = reader.fieldnames or []
            stats['total_columns'] = len(headers)

            column_stats = {h: {
                'total_values': 0,
                'empty_count': 0,
                'value_counts': {},
                'truncated': False,  # a new value arrived after the limit was reached
                'sample_values': []
            } for h in headers}

            row_count = 0
            for row in reader:
                row_count += 1
                for header in headers:
                    value = (row.get(header) or '').strip()
                    col_stat = column_stats[header]
                    col_stat['total_values'] += 1

                    if not value or value.lower() == 'none':
                        col_stat['empty_count'] += 1
                        continue

                    counts = col_stat['value_counts']
                    if value in counts:
                        counts[value] += 1
                    elif len(counts) < max_unique:
                        counts[value] = 1
                    else:
                        col_stat['truncated'] = True

                    if len(col_stat['sample_values']) < 5 and value not in col_stat['sample_values']:
                        col_stat['sample_values'].append(value)

            stats['total_rows'] = row_count

            truncated_cols = [h for h, s in column_stats.items() if s['truncated']]
            if truncated_cols:
                stats['warnings'].append(
                    f"Statistics for {len(truncated_cols)} column(s) were limited to {max_unique:,} unique values for memory efficiency."
                )

            for header in headers:
                col_stat = column_stats[header]
                truncated = col_stat['truncated']
                unique_count = len(col_stat['value_counts'])
                total = col_stat['total_values']
                empty = col_stat['empty_count']

                # All tracked values, most common first
                all_values_sorted = sorted(
                    col_stat['value_counts'].items(),
                    key=lambda x: x[1],
                    reverse=True
                )

                # Rare values (appearing only once or twice)
                rare_values = sorted(
                    [(v, c) for v, c in col_stat['value_counts'].items() if c <= 2],
                    key=lambda x: x[1]
                )[:10]

                fill_rate = ((total - empty) / total * 100) if total > 0 else 0
                uniqueness = round((unique_count / (total - empty) * 100) if (total - empty) > 0 else 0, 1)

                stats['columns'].append({
                    'name': header,
                    'is_enrichment': header.startswith('lb_'),
                    'unique_count': unique_count,
                    'unique_count_truncated': truncated,
                    # Past the limit both figures are lower bounds, and are shown as such
                    'unique_display': f"{unique_count:,}{'+' if truncated else ''}",
                    'uniqueness_display': f"{'≥ ' if truncated else ''}{uniqueness}%",
                    'empty_count': empty,
                    'fill_rate': round(fill_rate, 1),
                    'uniqueness': uniqueness,
                    'top_values': all_values_sorted[:10],
                    'all_values': all_values_sorted,
                    'rare_values': rare_values,
                    'sample_values': col_stat['sample_values']
                })

            # Enrichment-specific summaries. Pipe-separated columns are aggregated from
            # all tracked values, not just the ten most common rows.
            threat, geo, dns = stats['threat_summary'], stats['geo_summary'], stats['dns_summary']
            whois, shodan = stats['whois_summary'], stats['shodan_summary']
            for col in stats['columns']:
                name = col['name']
                top, everything = col['top_values'], col['all_values']

                # Threat intelligence
                if name == 'lb_ThreatCategories':
                    threat['all_categories'] = _pipe_counts(everything)
                    threat['categories'] = threat['all_categories'][:10]

                if name == 'lb_ThreatFeedCount':
                    threat['feed_counts'] = top
                    threat['all_feed_counts'] = everything

                if name in ('lb_ThreatFeeds', 'lb_Threat_Feeds', 'lb_ThreatFeed'):
                    threat['all_feeds'] = _pipe_counts(everything)
                    threat['feeds'] = threat['all_feeds'][:10]
                    threat['feeds_column'] = name  # actual column name, for filtering

                # Geo
                if name == 'lb_Country':
                    geo['countries'] = top
                if name == 'lb_ASN':
                    geo['asns'] = top
                if name == 'lb_City':
                    geo['cities'] = top
                if name == 'lb_Org':
                    geo['orgs'] = top

                # DNS and domains
                if name in ('lb_ReverseDNS', 'lb_DNS', 'lb_PTR'):
                    dns['reverse_dns'] = top
                    dns['dns_fill_rate'] = col['fill_rate']
                    dns['dns_unique'] = col['unique_count']

                if name == 'lb_Hostnames':
                    dns['hostnames'] = _pipe_counts(everything)[:10]

                if name in ('lb_Domains', 'lb_Domain'):
                    dns['all_domains'] = _pipe_counts(everything)
                    dns['domains'] = dns['all_domains'][:10]

                if name in ('lb_TLD', 'lb_TopLevelDomain'):
                    dns['tlds'] = top
                    dns['all_tlds'] = everything

                # WhoIS
                if name in ('lb_IPWhoIsOrg', 'lb_WhoIs_OrgName', 'lb_WhoIsOrg'):
                    whois['orgs'] = top
                    whois['all_orgs'] = everything
                if name in ('lb_IPWhoIsCountry', 'lb_WhoIs_Country', 'lb_WhoIsCountry'):
                    whois['countries'] = top
                if name in ('lb_IPWhoIsNetRange', 'lb_WhoIs_NetRange', 'lb_WhoIsNetRange'):
                    whois['net_ranges'] = top
                if name in ('lb_DomainWhoIsRegistrar', 'lb_WhoIsRegistrar'):
                    whois['registrars'] = top
                if name in ('lb_DomainWhoIsOrg', 'lb_DomainOrg'):
                    whois['domain_orgs'] = top
                if name in ('lb_NetName', 'lb_IPWhoIsNetName', 'lb_WhoIsNetName'):
                    whois['netnames'] = top
                    whois['all_netnames'] = everything

                # Shodan InternetDB
                if name in ('lb_Ports', 'lb_InternetDB_Ports', 'lb_ShodanPorts'):
                    shodan['ports'] = _pipe_counts(everything)[:15]
                if name in ('lb_Tags', 'lb_InternetDB_Tags', 'lb_ShodanTags'):
                    shodan['tags'] = _pipe_counts(everything)[:10]
                if name in ('lb_CPEs', 'lb_InternetDB_CPEs', 'lb_ShodanCPEs'):
                    shodan['cpes'] = _pipe_counts(everything)[:10]
                if name in ('lb_Vulns', 'lb_InternetDB_Vulns', 'lb_ShodanVulns'):
                    shodan['vulns'] = _pipe_counts(everything)[:10]

            def first_column(*names):
                return next((c for c in stats['columns'] if c['name'] in names), None)

            # Count IPs with threat indicators
            threat_col = first_column('lb_ThreatCategories')
            if threat_col:
                stats['enrichment_summary']['ips_with_threats'] = stats['total_rows'] - threat_col['empty_count']
                stats['enrichment_summary']['clean_ips'] = threat_col['empty_count']

            # Count IPs with Shodan data
            ports_col = first_column('lb_Ports', 'lb_InternetDB_Ports', 'lb_ShodanPorts')
            if ports_col:
                shodan['ips_with_data'] = stats['total_rows'] - ports_col['empty_count']

            # Count IPs with DNS data
            dns_col = first_column('lb_ReverseDNS', 'lb_DNS', 'lb_PTR')
            if dns_col:
                dns['ips_with_dns'] = stats['total_rows'] - dns_col['empty_count']

            # Count IPs with WhoIS data
            whois_col = first_column('lb_IPWhoIsOrg', 'lb_WhoIs_OrgName', 'lb_WhoIsOrg')
            if whois_col:
                whois['ips_with_whois'] = stats['total_rows'] - whois_col['empty_count']

    except Exception:
        app.logger.exception('Statistics computation failed')
        stats['error'] = 'Could not compute statistics'

    return stats


# Statistics per result file, so the Stats tab, its value modals and /column-values read the
# CSV once. An entry is valid while the file's mtime, size and the unique-value limit are unchanged.
# ponytail: plain dict capped at 8 files, oldest evicted first. Stats hold up to
# max_unique_values entries per column, so raise the cap only with memory to spare.
_STATS_CACHE_FILES = 8
_stats_cache = {}


def cached_statistics(filepath: Path) -> dict:
    """compute_statistics(), cached per result file. Callers must not modify the returned dict."""
    filepath = Path(filepath)
    try:
        st = filepath.stat()
    except OSError:
        return compute_statistics(filepath)
    path_key = str(filepath)
    version = (st.st_mtime_ns, st.st_size, get_max_unique_values())
    hit = _stats_cache.get(path_key)
    if hit and hit[0] == version:
        return hit[1]
    stats = compute_statistics(filepath)
    if 'error' not in stats:
        _stats_cache.pop(path_key, None)
        while len(_stats_cache) >= _STATS_CACHE_FILES:
            _stats_cache.pop(next(iter(_stats_cache)), None)
        _stats_cache[path_key] = (version, stats)
    return stats


def get_unique_column_values(filepath: Path, column_name: str, limit: int = 100) -> list:
    """Most common values of a column with their counts, from the cached statistics."""
    columns = cached_statistics(filepath)['columns']
    col = next((c for c in columns if c['name'] == column_name), None)
    return [{'value': v, 'count': c} for v, c in col['all_values'][:limit]] if col else []


# ============================================
# Graph API Routes
# ============================================

from admin import (
    save_graph, load_graph, list_graphs, delete_graph, set_graph_shared,
    save_shared_results, get_shared_results, get_shared_results_expiry_days, clear_expired_shared_results,
    get_shared_results_meta, get_shared_results_stats, list_shared_results, delete_shared_results,
    get_concurrency_settings,
    get_cached_shodan, set_cached_shodan, get_shodan_cache_settings,
    get_cached_shodan_pivot, set_cached_shodan_pivot,
    get_shodan_pivot_limit,
    get_circl_settings, get_cached_circl_pdns, set_cached_circl_pdns,
    get_hackertarget_settings, get_cached_hackertarget, set_cached_hackertarget,
    get_viewdns_settings, get_cached_viewdns, set_cached_viewdns,
    get_max_unique_values, get_max_adhoc_ips, get_large_file_warning_threshold, get_max_embedded_rows
)


# ========== IOC Extraction ==========
# Implementation lives in ioc.py. Request handlers go through extract_iocs_from_text
# below, which runs it in a subprocess with a size cap and a timeout.

import ioc
from ioc import (
    IP_PATTERN, DOMAIN_PATTERN, IOCEXTRACT_AVAILABLE, TLDEXTRACT_AVAILABLE,
    looks_like_filename, is_valid_domain, is_valid_public_ip, refang_domain,
    extract_defanged_domains_direct, extract_domain_from_url,
)

MAX_IOC_TEXT_BYTES = 5 * 1024 * 1024  # larger inputs are rejected before any regex runs
IOC_EXTRACT_TIMEOUT = 30              # seconds


def extract_iocs_from_text(text):
    """Extract (ips, domains) from text in a subprocess. Raises ValueError if too large or too slow."""
    payload = text.encode('utf-8', errors='replace')
    if len(payload) > MAX_IOC_TEXT_BYTES:
        raise ValueError(
            f'Text is too large for IOC extraction ({len(payload) // (1024 * 1024)} MB; '
            f'limit {MAX_IOC_TEXT_BYTES // (1024 * 1024)} MB).')
    try:
        result = subprocess.run([sys.executable, ioc.__file__], input=payload,
                                capture_output=True, timeout=IOC_EXTRACT_TIMEOUT, check=True)
    except subprocess.TimeoutExpired:
        raise ValueError(f'IOC extraction timed out after {IOC_EXTRACT_TIMEOUT} seconds.')
    except subprocess.CalledProcessError as e:
        app.logger.error('IOC extraction failed: %s', e.stderr.decode(errors='replace')[-500:])
        raise ValueError('IOC extraction failed.')
    found = json.loads(result.stdout)
    return found['ips'], found['domains']


def fetch_url_content(url):
    """
    Fetch content from a URL (HTML or PDF) with SSRF protection.
    
    This function validates the URL to prevent Server-Side Request Forgery (SSRF)
    attacks and limits the response size to prevent memory exhaustion.
    """
    # Use the SSRF-protected fetch function
    content_bytes, content_type = safe_fetch_url(url)
    
    if 'pdf' in content_type or url.lower().endswith('.pdf'):
        # Parse PDF
        return extract_text_from_pdf(content_bytes)
    else:
        # Assume HTML/text - decode bytes to string
        # Try common encodings
        for encoding in ['utf-8', 'latin-1', 'cp1252']:
            try:
                return content_bytes.decode(encoding)
            except UnicodeDecodeError:
                continue
        # Fallback: decode with replacement
        return content_bytes.decode('utf-8', errors='replace')


def extract_text_from_pdf(pdf_bytes):
    """Extract text from PDF bytes."""
    try:
        from pypdf import PdfReader
        import io
        
        reader = PdfReader(io.BytesIO(pdf_bytes))
        text_parts = []
        
        for page in reader.pages:
            text = page.extract_text()
            if text:
                text_parts.append(text)
        
        return '\n'.join(text_parts)
    except Exception as e:
        raise ValueError(f"Failed to parse PDF: {str(e)}")


@app.route('/api/ioc/extract', methods=['POST'])
@login_required
def api_ioc_extract():
    """Extract IOCs from text, URL, or uploaded file."""
    text_content = None
    source = 'unknown'
    
    # Check for URL in JSON body
    if request.is_json:
        data = json_body() or {}
        url = str_field(data, 'url')
        text = str_field(data, 'text')
        
        if url:
            try:
                text_content = fetch_url_content(url)
                source = 'url'
            except requests.exceptions.RequestException as e:
                return jsonify({'error': f'Failed to fetch URL ({upstream_detail(e)})'}), 400
            except ValueError as e:
                return jsonify({'error': str(e)}), 400
        elif text:
            text_content = text
            source = 'text'
    
    # Check for file upload
    elif 'file' in request.files:
        file = request.files['file']
        if file.filename:
            filename = secure_filename(file.filename).lower()
            file_bytes = file.read()
            
            if filename.endswith('.pdf'):
                try:
                    text_content = extract_text_from_pdf(file_bytes)
                    source = 'pdf_upload'
                except ValueError as e:
                    return jsonify({'error': str(e)}), 400
            else:
                # Assume text file
                try:
                    text_content = file_bytes.decode('utf-8', errors='replace')
                    source = 'text_upload'
                except Exception as e:
                    return jsonify({'error': 'Failed to read file'}), 400
    
    # Check for form data text
    elif request.form.get('text'):
        text_content = request.form.get('text', '')
        source = 'text'
    
    if not text_content:
        return jsonify({'error': 'No content provided. Send URL, text, or upload a file.'}), 400
    
    # Extract IOCs (subprocess; raises ValueError when too large or too slow)
    try:
        ips, domains = extract_iocs_from_text(text_content)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    
    log_audit('ioc_extract', 'ioc', None, {
        'source': source,
        'ip_count': len(ips),
        'domain_count': len(domains)
    })
    
    return jsonify({
        'ips': sorted(ips),
        'domains': sorted(domains),
        'total': len(ips) + len(domains),
        'source': source,
        'defang_support': IOCEXTRACT_AVAILABLE,
        'tld_validation': TLDEXTRACT_AVAILABLE
    })


GRAPH_IP_COLUMNS = ('ip', 'ip_address', 'ipaddress', 'src_ip', 'dst_ip', 'lb_ip')


def _geo_columns(headers) -> dict:
    """Locate the IP and geo columns of a LogBoost result. lb_ASN holds the AS name,
    lb_ASN_Number the number."""
    def first(match):
        return next((h for h in headers if match(h)), None)

    return {
        'ip': first(lambda h: h.lower() in GRAPH_IP_COLUMNS),
        'asn_name': first(lambda h: h == 'lb_ASN'),
        'asn_num': first(lambda h: h == 'lb_ASN_Number'),
        'country': first(lambda h: h == 'lb_Country')
                   or first(lambda h: 'country' in h.lower() and h.startswith('lb_') and 'whois' not in h.lower()),
        'city': first(lambda h: h == 'lb_City')
                or first(lambda h: 'city' in h.lower() and h.startswith('lb_')),
        # Prefer the IP WhoIs organisation for IP lookups
        'org': first(lambda h: h == 'lb_IPWhois_Organization')
               or first(lambda h: h in ('lb_Org', 'lb_ISP')),
    }


def _geo_from_row(row: dict, cols: dict) -> dict:
    """ASN / country / city / org of one result row, or {} when it has neither ASN nor country."""
    def cell(key):
        return (row.get(cols[key]) or '').strip() if cols[key] else ''

    asn_name, asn_num = cell('asn_name'), cell('asn_num')
    if not (asn_name or asn_num or cell('country')):
        return {}

    geo = {}
    if asn_num:
        geo['asn_id'] = f'AS{asn_num}'
        geo['asn_name'] = asn_name
        geo['asn'] = f'AS{asn_num} {asn_name}'.strip()
    elif asn_name:
        geo['asn_name'] = asn_name
        geo['asn'] = asn_name
    for key in ('country', 'city', 'org'):
        if cell(key):
            geo[key] = cell(key)
    return geo


def _graph_ips(data: dict):
    """The `ips` of a graph lookup request as (ips, None), or (None, message) when it is not
    a list of IP addresses within the ad-hoc limit."""
    ips = data.get('ips')
    if not ips:
        return None, 'No IPs provided'
    if not isinstance(ips, list):
        return None, 'ips must be a list of IP addresses'
    limit = get_max_adhoc_ips()
    if len(ips) > limit:
        return None, f'Too many IP addresses ({len(ips):,}). Graph lookups are limited to {limit:,} IPs.'
    clean = []
    for ip in ips:
        ip = ip.strip() if isinstance(ip, str) else ''
        try:
            if '%' in ip:  # an IPv6 zone ID may carry arbitrary text
                raise ValueError
            ipaddress.ip_address(ip)
        except ValueError:
            return None, 'ips must be a list of IP addresses'
        clean.append(ip)
    return clean, None


def graph_lookup(ips: list, options: dict):
    """Run LogBoost over `ips` in a throwaway directory and return (rows, None), or
    (None, message) when LogBoost fails. The session's files and current_output are never touched."""
    with tempfile.TemporaryDirectory(prefix='lb-graph-') as tmp:
        in_dir, out_dir = Path(tmp, 'in'), Path(tmp, 'out')
        in_dir.mkdir()
        out_dir.mkdir()
        with open(in_dir / 'graph_ips.csv', 'w', newline='', encoding='utf-8') as f:
            f.write('ip\n' + ''.join(f'{ip}\n' for ip in ips))

        cmd = build_logboost_command(str(in_dir), str(out_dir), {**options, 'ipcol': 'ip'})
        success, _, stderr = run_logboost(cmd)
        if not success:
            return None, stderr or 'LogBoost execution failed'

        output_files = list(out_dir.glob('**/*.csv'))
        if not output_files:
            return None, 'No output file generated'
        with open(output_files[0], 'r', newline='', encoding='utf-8', errors='replace') as f:
            return list(csv.DictReader(f)), None


def _graph_lookup_request(options: dict):
    """Shared front half of the graph lookup endpoints: (ips, rows, None) or (None, None, response)."""
    data = json_body()
    if not data:
        return None, None, (jsonify({'error': 'No JSON data provided'}), 400)
    ips, error = _graph_ips(data)
    if error:
        return None, None, (jsonify({'error': error}), 400)
    try:
        rows, error = graph_lookup(ips, options)
    except Exception as e:
        return None, None, internal_error(e)
    if error:
        return None, None, (jsonify({'error': error}), 500)
    return ips, rows, None


@app.route('/api/graph/related', methods=['POST'])
@login_required
def api_graph_related():
    """Find related IPs/domains from current dataset."""
    data = json_body()
    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400

    value = str_field(data, 'value')
    value_type = data.get('type', 'ip')  # 'ip' or 'domain'
    value_lower = value.lower()

    related = {
        'ips': [],
        'domains': [],
        'tlds': [],
        'asns': [],
        'countries': [],
        'geo_data': {},  # IP -> {asn, asn_name, asn_id, country, city, org}
        'sources': {}
    }

    output_path = current_output_path()
    if not output_path:
        # Return empty results if no enrichment data available
        return jsonify(related)

    def add(kind, item):
        if item and item not in related[kind]:
            related[kind].append(item)
            related['sources'][item] = 'enrichment'

    try:
        with open(output_path, 'r', newline='', encoding='utf-8', errors='replace') as f:
            reader = csv.DictReader(f)
            headers = reader.fieldnames or []
            cols = _geo_columns(headers)
            domain_cols = [h for h in headers if h in ('lb_Domains', 'LB_Domains', 'lb_IDB_HOSTNAMES', 'LB_IDB_HOSTNAMES', 'lb_IDB_hostnames')]
            tld_col = next((h for h in headers if h in ('lb_TLD', 'LB_TLD')), None)

            def add_geo(row_ip, row):
                geo = _geo_from_row(row, cols)
                if geo:
                    add('asns', geo.get('asn'))
                    add('countries', geo.get('country'))
                    related['geo_data'][row_ip] = geo

            for row in reader:
                row_ip = (row.get(cols['ip']) or '') if cols['ip'] else ''
                row_tld = (row.get(tld_col) or '') if tld_col else ''
                row_domains = {
                    d.strip() for dc in domain_cols
                    for d in (row.get(dc) or '').split('|') if d.strip()
                }

                if value_type == 'ip':
                    # Looking for an IP: its domains, TLD and geo data
                    if row_ip.lower() == value_lower:
                        for d in row_domains:
                            add('domains', d)
                        add('tlds', row_tld)
                        add_geo(row_ip, row)
                elif value_lower in {d.lower() for d in row_domains}:
                    # Looking for a domain: the IPs that carry it, and the row's other domains
                    if row_ip and row_ip not in related['ips']:
                        add('ips', row_ip)
                        add_geo(row_ip, row)
                    for d in row_domains:
                        if d.lower() != value_lower:
                            add('domains', d)
                    add('tlds', row_tld)

    except Exception as e:
        return internal_error(e)

    return jsonify(related)


@app.route('/api/graph/enrich', methods=['POST'])
@login_required
@limit_enrichments(as_json=True)
def api_graph_enrich():
    """Geo-enrich IPs on demand for the graph (MaxMind only; InternetDB is /api/graph/enrich-idb)."""
    ips, rows, error_response = _graph_lookup_request({})
    if error_response:
        return error_response

    cols = _geo_columns(list(rows[0].keys()) if rows else [])
    geo_data = {}
    for row in rows:
        row_ip = (row.get(cols['ip']) or '') if cols['ip'] else ''
        geo = _geo_from_row(row, cols)
        if row_ip and geo:
            geo_data[row_ip] = {'ip': row_ip, **geo}

    return jsonify({
        'geo_data': geo_data,
        'enriched_count': len(geo_data),
        'total_ips': len(ips)
    })


@app.route('/api/graph/enrich-idb', methods=['POST'])
@login_required
@limit_enrichments(as_json=True)
def api_graph_enrich_idb():
    """Enrich IPs with Shodan InternetDB data (ports and tags) via LogBoost."""
    ips, rows, error_response = _graph_lookup_request({'idb': True})
    if error_response:
        return error_response

    headers = list(rows[0].keys()) if rows else []
    ip_col = _geo_columns(headers)['ip']
    ports_col = next((h for h in headers if h.lower() in ('lb_idb_ports', 'lb_idb_port')), None)
    tags_col = next((h for h in headers if h.lower() in ('lb_idb_tags', 'lb_idb_tag')), None)

    def items(row, col):
        """Pipe-separated cell as a list, without LogBoost's 'err' markers."""
        cell = (row.get(col) or '') if col else ''
        return [p.strip() for p in cell.split('|') if p.strip() and p.strip().lower() != 'err']

    idb_data = {}
    for row in rows:
        row_ip = (row.get(ip_col) or '') if ip_col else ''
        if not row_ip:
            continue
        idb_info = {'ip': row_ip}
        if items(row, ports_col):
            idb_info['ports'] = items(row, ports_col)
        if items(row, tags_col):
            idb_info['tags'] = items(row, tags_col)
        if len(idb_info) > 1:  # only IPs that have ports or tags
            idb_data[row_ip] = idb_info

    log_audit('logboost_idb_query', 'logboost', None, {'ip_count': len(ips), 'enriched_count': len(idb_data)})
    return jsonify({
        'idb_data': idb_data,
        'enriched_count': len(idb_data),
        'total_ips': len(ips)
    })


@app.route('/api/graph/geo', methods=['POST'])
@login_required
def api_graph_geo():
    """Get geo data (ASN, Country) for IPs from current dataset."""
    data = json_body()
    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400

    # Lowercased IP -> IP as requested, so results are keyed the way the caller asked
    wanted = {ip.lower(): ip for ip in str_list(data.get('ips'))}
    output_path = current_output_path()
    if not wanted or not output_path:
        return jsonify({'geo_data': {}})

    geo_data = {}
    try:
        with open(output_path, 'r', newline='', encoding='utf-8', errors='replace') as f:
            reader = csv.DictReader(f)
            cols = _geo_columns(reader.fieldnames or [])
            if cols['ip']:
                for row in reader:
                    original_ip = wanted.get((row.get(cols['ip']) or '').lower())
                    if original_ip and original_ip not in geo_data:
                        geo = _geo_from_row(row, cols)
                        if geo:
                            geo_data[original_ip] = {'ip': original_ip, **geo}

    except Exception as e:
        return internal_error(e)

    return jsonify({'geo_data': geo_data})


@app.route('/api/graph/save', methods=['POST'])
@login_required
def api_graph_save():
    """Save a graph. Creates new graph if user doesn't own the existing one."""
    data = json_body()
    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400
    
    graph_id = data.get('id')
    name = data.get('name', 'Untitled Graph')
    graph_data = data.get('data', {})
    user_id = session.get('user_id')
    force_new = data.get('force_new', False)  # Force create new graph
    
    is_new = not graph_id or force_new
    if is_new:
        import uuid
        graph_id = str(uuid.uuid4())
    
    # Try to save - if we don't own it, save_graph returns False
    success = save_graph(graph_id, name, graph_data, user_id)
    
    if not success:
        # We don't own this graph - create a new one with a new ID
        import uuid
        graph_id = str(uuid.uuid4())
        save_graph(graph_id, name, graph_data, user_id)
        is_new = True
    
    # Audit log
    node_count = len(graph_data.get('nodes', []))
    edge_count = len(graph_data.get('edges', []))
    log_audit('graph_created' if is_new else 'graph_updated', 'graph', graph_id, 
              {'name': name, 'nodes': node_count, 'edges': edge_count})
    
    return jsonify({'success': True, 'id': graph_id, 'is_owner': True})


@app.route('/api/graph/<graph_id>', methods=['GET'])
@login_required
def api_graph_load(graph_id):
    """Load a graph the user owns or that has been shared. is_owner tells the front end
    whether to open it in place or as the user's own copy."""
    user_id = session.get('user_id')
    graph = load_graph(graph_id, user_id=user_id)
    if graph:
        graph['is_owner'] = graph.get('user_id') in (None, user_id)
        return jsonify(graph)
    return jsonify({'error': 'Graph not found'}), 404


@app.route('/api/graph/<graph_id>', methods=['DELETE'])
@login_required
def api_graph_delete(graph_id):
    """Delete a graph by ID. Only owner can delete."""
    user_id = session.get('user_id')
    if delete_graph(graph_id, user_id):
        log_audit('graph_deleted', 'graph', graph_id)
        return jsonify({'success': True})
    return jsonify({'error': 'Graph not found or not authorized'}), 404


@app.route('/api/graph/<graph_id>/share', methods=['POST', 'DELETE'])
@login_required
def api_graph_share(graph_id):
    """The owner turns link sharing for a graph on (POST) or off (DELETE)."""
    shared = request.method == 'POST'
    if not set_graph_shared(graph_id, session.get('user_id'), shared):
        return jsonify({'error': 'Graph not found or not authorized'}), 404
    log_audit('graph_shared' if shared else 'graph_unshared', 'graph', graph_id)
    return jsonify({
        'success': True,
        'is_shared': shared,
        'share_url': url_for('index', graph=graph_id, _external=True)
    })


@app.route('/api/graph/list', methods=['GET'])
@login_required
def api_graph_list():
    """List saved graphs for current user only."""
    user_id = session.get('user_id')
    graphs = list_graphs(user_id)
    return jsonify({'graphs': graphs})


@app.route('/api/graph/export/<graph_id>', methods=['GET'])
@login_required
def api_graph_export(graph_id):
    """Export graph as JSON. Only the owning user may export it."""
    user_id = session.get('user_id')
    graph = load_graph(graph_id, user_id=user_id)
    if not graph:
        return jsonify({'error': 'Graph not found'}), 404
    
    response = jsonify(graph)
    response.headers['Content-Disposition'] = f'attachment; filename=graph_{graph_id}.json'
    return response


# ============================================
# Shared Results Endpoints
# ============================================

def _shareable_stats(stats: dict) -> dict:
    """Statistics as stored with a share: everything the Stats tab renders, minus the per-column
    value tables (the bulk of the data, only needed to build the summaries)."""
    return {**stats, 'columns': [{**col, 'all_values': []} for col in stats['columns']]}


@app.route('/api/results/share', methods=['POST'])
@login_required
def api_results_share():
    """Create a share link for the current results. Rows and statistics are stored with it."""
    output_file = current_output_path()
    if not output_file:
        return jsonify({'error': 'No results to share'}), 400

    # csv.reader gives a list of lists, the format the results template expects
    try:
        with open(output_file, 'r', newline='', encoding='utf-8', errors='replace') as f:
            reader = csv.reader(f)
            headers = next(reader, [])
            results_data = list(reader)
    except Exception as e:
        return internal_error(e, 'Failed to read results')

    if not results_data:
        return jsonify({'error': 'No data in results'}), 400

    stats = cached_statistics(output_file)
    share_id = secrets.token_urlsafe(16)
    expiry_days = get_shared_results_expiry_days()
    save_shared_results(share_id, session.get('user_id'), output_file.name, results_data,
                        None if 'error' in stats else _shareable_stats(stats), headers, expiry_days)
    log_audit('shared_results_created', 'shared_results', share_id,
              {'filename': output_file.name, 'row_count': len(results_data)})

    return jsonify({
        'success': True,
        'share_id': share_id,
        'share_url': url_for('view_shared_results', share_id=share_id, _external=True),
        'expires_in_days': expiry_days
    })


def _shared_access(share_id, action, with_rows=True):
    """Look up an unexpired share and audit the access. None when it is missing or expired."""
    shared = get_shared_results(share_id) if with_rows else get_shared_results_meta(share_id)
    if not shared:
        log_audit('shared_results_access', 'shared_results', share_id, {
            'action': action,
            'success': False,
            'reason': 'not_found_or_expired'
        })
        return None
    log_audit('shared_results_access', 'shared_results', share_id, {
        'action': action,
        'success': True,
        'owner_user_id': shared.get('user_id'),
        'filename': shared.get('filename'),
        'row_count': shared.get('row_count')
    })
    return shared


@app.route('/shared/results/<share_id>')
@login_required
def view_shared_results(share_id):
    """Share link target: sends the user to the main page, which loads the shared results."""
    if not _shared_access(share_id, 'view', with_rows=False):
        return render_template('index.html', error='Shared results not found or expired'), 404
    return redirect(url_for('index', shared=share_id))


@app.route('/api/shared/results/<share_id>', methods=['GET'])
@login_required
def api_shared_results(share_id):
    """Get shared results data."""
    shared = _shared_access(share_id, 'api_fetch')
    if not shared:
        return jsonify({'error': 'Shared results not found or expired'}), 404

    return jsonify({
        'success': True,
        'id': share_id,
        'filename': shared['filename'],
        'headers': shared['headers'],
        'results': shared['results_data'],
        'stats': shared['stats_data'],
        'created_at': shared['created_at'],
        'expires_at': shared['expires_at']
    })


@app.route('/api/shared/results/<share_id>/render', methods=['GET'])
@login_required
def api_shared_results_render(share_id):
    """Render shared results as HTML partial."""
    shared = _shared_access(share_id, 'render')
    if not shared:
        return render_template('partials/error.html', error='Shared results not found or expired'), 404

    rows = shared['results_data'] or []
    return render_template('partials/results.html',
                           headers=shared['headers'] or [],
                           rows=rows,
                           total_rows=len(rows),
                           original_filename=shared['filename'],
                           is_shared=True,
                           share_id=share_id)


@app.route('/shares')
@login_required
def my_shares():
    """The user's shared result links; an admin sees everyone's."""
    admin_view = is_admin()
    shares = list_shared_results(None if admin_view else session.get('user_id'))
    return render_template('shares.html', shares=shares, admin_view=admin_view,
                           graphs=list_graphs(session.get('user_id')))


@app.route('/shares/<share_id>/delete', methods=['POST'])
@login_required
def delete_share(share_id):
    """Delete a share link: its owner, or an admin."""
    if delete_shared_results(share_id, None if is_admin() else session.get('user_id')):
        log_audit('shared_results_deleted', 'shared_results', share_id)
        flash('Share link deleted', 'success')
    else:
        flash('Share link not found', 'error')
    return redirect(url_for('my_shares'))


@app.route('/api/settings/concurrency', methods=['GET'])
@login_required
def api_get_concurrency_settings():
    """Get current concurrency settings."""
    settings = get_concurrency_settings()
    return jsonify(settings)


# ========== Shodan API Endpoints ==========

def get_shodan_api_key():
    """Get Shodan API key from admin settings."""
    from admin import get_setting
    return get_setting('shodan_api_key')


@app.route('/api/shodan/resolve', methods=['POST'])
@login_required
def api_shodan_resolve():
    """Query Shodan for IP or domain and return full host data with caching."""
    if not SHODAN_AVAILABLE:
        return jsonify({'error': 'Shodan library not installed. Run: pip install shodan'}), 500
    
    data = json_body()
    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400
    
    value = str_field(data, 'value')
    value_type = data.get('type', 'ip')  # 'ip' or 'domain'
    
    if not value:
        return jsonify({'error': 'Value is required'}), 400
    
    # Check cache first
    cached = get_cached_shodan(value, value_type)
    if cached:
        cached['cached'] = True
        return jsonify(cached)
    
    api_key = get_shodan_api_key()
    if not api_key:
        return jsonify({'error': 'Shodan API key not configured. Please set it in Admin Settings.'}), 400
    
    try:
        api = shodan.Shodan(api_key)
        jarm_fingerprints = []
        
        if value_type == 'ip':
            # Query Shodan for IP - get full host data
            try:
                host = api.host(value)
                
                # Extract JARM fingerprints from services
                for svc in host.get('data', []):
                    ssl_data = svc.get('ssl')
                    if ssl_data:
                        jarm = ssl_data.get('jarm')
                        if jarm and jarm != '00000000000000000000000000000000000000000000000000000000000000':
                            existing = next((j for j in jarm_fingerprints if j['jarm'] == jarm), None)
                            if not existing:
                                jarm_fingerprints.append({
                                    'jarm': jarm,
                                    'source_ip': value,
                                    'port': svc.get('port'),
                                    'hostnames': host.get('hostnames', [])
                                })
                
                # Return the full host data directly from Shodan
                # We store it under host_info for consistency with the frontend
                result = {
                    'value': value,
                    'type': value_type,
                    'jarms': jarm_fingerprints,
                    'host_info': host  # Full raw Shodan response
                }
                
                # Cache the result
                cache_settings = get_shodan_cache_settings()
                set_cached_shodan(value, value_type, result, cache_settings['cache_ttl'])
                
                return jsonify(result)
                
            except shodan.APIError as e:
                if 'No information available' in str(e):
                    result = {
                        'value': value,
                        'type': value_type,
                        'jarms': [],
                        'host_info': {},
                        'message': 'No Shodan data available for this IP'
                    }
                    # Cache negative results too (shorter TTL)
                    cache_settings = get_shodan_cache_settings()
                    set_cached_shodan(value, value_type, result, min(cache_settings['cache_ttl'], 300))
                    return jsonify(result)
                raise
        else:
            # Query Shodan for domain (hostname search)
            if not re.fullmatch(r'[A-Za-z0-9._-]{1,253}', value):
                # anything else could append extra Shodan search filters
                return jsonify({'error': 'Invalid hostname'}), 400
            try:
                results = api.search(f'hostname:{value}', limit=100)
                
                # Collect all unique IPs and their data
                ip_data = {}
                all_hostnames = set()
                
                for match in results.get('matches', []):
                    ip = match.get('ip_str')
                    all_hostnames.update(match.get('hostnames', []))
                    
                    if ip not in ip_data:
                        ip_data[ip] = {
                            'ip': ip,
                            'services': []
                        }
                    
                    # Store the full match data
                    ip_data[ip]['services'].append(match)
                    
                    # Also extract org/location from first service for this IP
                    if 'org' not in ip_data[ip]:
                        ip_data[ip]['org'] = match.get('org')
                        ip_data[ip]['isp'] = match.get('isp')
                        ip_data[ip]['asn'] = match.get('asn')
                        ip_data[ip]['location'] = match.get('location', {})
                        ip_data[ip]['hostnames'] = match.get('hostnames', [])
                    
                    # Extract JARM fingerprints
                    ssl_data = match.get('ssl')
                    if ssl_data:
                        jarm = ssl_data.get('jarm')
                        if jarm and jarm != '00000000000000000000000000000000000000000000000000000000000000':
                            existing = next((j for j in jarm_fingerprints if j['jarm'] == jarm), None)
                            if not existing:
                                jarm_fingerprints.append({
                                    'jarm': jarm,
                                    'source_ip': ip,
                                    'port': match.get('port'),
                                    'hostnames': match.get('hostnames', [])
                                })
                
                # Build host_info with full data
                host_info = {
                    'domain': value,
                    'total_results': results.get('total', 0),
                    'unique_ips': len(ip_data),
                    'hostnames': list(all_hostnames),
                    'ips': list(ip_data.values()),
                    'matches': results.get('matches', [])  # Include full raw matches
                }
                
                result = {
                    'value': value,
                    'type': value_type,
                    'jarms': jarm_fingerprints,
                    'host_info': host_info
                }
                
                cache_settings = get_shodan_cache_settings()
                set_cached_shodan(value, value_type, result, cache_settings['cache_ttl'])
                
                return jsonify(result)
                
            except shodan.APIError as e:
                if 'No information available' in str(e):
                    result = {
                        'value': value,
                        'type': value_type,
                        'jarms': [],
                        'host_info': {},
                        'message': 'No Shodan data available for this domain'
                    }
                    cache_settings = get_shodan_cache_settings()
                    set_cached_shodan(value, value_type, result, min(cache_settings['cache_ttl'], 300))
                    return jsonify(result)
                raise
        
    except shodan.APIError as e:
        return jsonify({'error': f'Shodan API error: {e}'}), 500
    except Exception as e:
        return internal_error(e)
    finally:
        # Log after all paths
        log_audit('shodan_query', 'shodan', None, {'value_type': value_type, 'count': 1})


@app.route('/api/shodan/pivot-jarm', methods=['POST'])
@login_required
def api_shodan_pivot_jarm():
    """Pivot on a JARM fingerprint to find other hosts with the same fingerprint."""
    if not SHODAN_AVAILABLE:
        return jsonify({'error': 'Shodan library not installed. Run: pip install shodan'}), 500
    
    data = json_body()
    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400
    
    jarm = str_field(data, 'jarm')
    if not jarm:
        return jsonify({'error': 'JARM fingerprint is required'}), 400
    
    # Validate JARM format (should be 62 hex characters)
    if len(jarm) != 62 or not all(c in '0123456789abcdefABCDEF' for c in jarm):
        return jsonify({'error': 'Invalid JARM fingerprint format'}), 400
    
    # Check pivot cache first
    cached = get_cached_shodan_pivot('jarm', jarm)
    if cached:
        result = cached['results']
        result['from_cache'] = True
        return jsonify(result)
    
    api_key = get_shodan_api_key()
    if not api_key:
        return jsonify({'error': 'Shodan API key not configured. Please set it in Admin Settings.'}), 400
    
    try:
        api = shodan.Shodan(api_key)
        
        # Search for hosts with this JARM fingerprint
        query = f'ssl.jarm:{jarm}'
        results = api.search(query, limit=100)
        
        total_results = results.get('total', 0)
        limited = total_results > 100
        
        ips = set()
        hostnames = set()
        hosts_info = []
        
        for match in results.get('matches', []):
            ip = match.get('ip_str')
            if ip:
                ips.add(ip)
            
            for hostname in match.get('hostnames', []):
                if hostname:
                    hostnames.add(hostname)
            
            hosts_info.append({
                'ip': ip,
                'port': match.get('port'),
                'hostnames': match.get('hostnames', []),
                'org': match.get('org'),
                'country': match.get('location', {}).get('country_name')
            })
        
        result = {
            'jarm': jarm,
            'total_results': total_results,
            'limited': limited,
            'limit_message': f'Results limited to 100 of {total_results} total hosts' if limited else None,
            'ips': list(ips),
            'hostnames': list(hostnames),
            'hosts': hosts_info
        }
        
        # Cache the pivot results
        cache_settings = get_shodan_cache_settings()
        set_cached_shodan_pivot('jarm', jarm, result, total_results, cache_settings['cache_ttl'])
        
        log_audit('shodan_pivot_jarm', 'shodan', None, {'result_count': len(ips)})
        return jsonify(result)
        
    except shodan.APIError as e:
        return jsonify({'error': f'Shodan API error: {e}'}), 500
    except Exception as e:
        return internal_error(e)


@app.route('/api/shodan/pivot', methods=['POST'])
@login_required
def api_shodan_pivot():
    """Pivot on arbitrary Shodan query to find matching hosts."""
    if not SHODAN_AVAILABLE:
        return jsonify({'error': 'Shodan library not installed. Run: pip install shodan'}), 500
    
    data = json_body()
    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400
    
    query = str_field(data, 'query')
    # Normalize whitespace
    query = ' '.join(query.split())
    if not query:
        return jsonify({'error': 'Query is required'}), 400
    
    # Get the source IP for reference
    source_ip = data.get('source_ip', '')
    
    api_key = get_shodan_api_key()
    if not api_key:
        return jsonify({'error': 'Shodan API key not configured. Please set it in Admin Settings.'}), 400
    
    app.logger.debug("[Shodan Pivot] Query: %s, Source IP: %s", query, source_ip)
    
    try:
        api = shodan.Shodan(api_key)
        
        # Get the configured limit
        pivot_limit = get_shodan_pivot_limit()
        
        # Run the query
        app.logger.debug("[Shodan Pivot] Running query: '%s' with limit=%d", query, pivot_limit)
        results = api.search(query, limit=pivot_limit)
        
        # Debug: log raw response structure
        app.logger.debug("[Shodan Pivot] Raw response keys: %s", results.keys() if isinstance(results, dict) else type(results))
        
        total_results = results.get('total', 0)
        app.logger.debug("[Shodan Pivot] Total results from Shodan: %d", total_results)
        
        matches = results.get('matches', [])
        app.logger.debug("[Shodan Pivot] Matches returned: %d", len(matches))
        
        all_ips = set()
        all_hosts = []
        
        for match in matches:
            ip = match.get('ip_str')
            if ip and ip != source_ip:  # Exclude the source IP
                if ip not in all_ips:
                    all_ips.add(ip)
                    all_hosts.append({
                        'ip': ip,
                        'port': match.get('port'),
                        'hostnames': match.get('hostnames', []),
                        'org': match.get('org'),
                        'country': match.get('location', {}).get('country_name'),
                        'asn': match.get('asn')
                    })
        
        limited = total_results > len(all_ips)
        
        app.logger.debug("[Shodan Pivot] Returning %d unique IPs (total from Shodan: %d)", len(all_ips), total_results)
        
        result = {
            'query': query,
            'source_ip': source_ip,
            'total_results': total_results,
            'returned_count': len(all_ips),
            'limited': limited,
            'limit_message': f'Results limited to {len(all_ips)} of {total_results} total hosts' if limited else None,
            'ips': list(all_ips),
            'hosts': all_hosts
        }
        
        log_audit('shodan_pivot', 'shodan', None, {'result_count': len(all_ips), 'total_results': total_results})
        return jsonify(result)
        
    except shodan.APIError as e:
        return jsonify({'error': f'Shodan API error: {e}'}), 500
    except Exception as e:
        return internal_error(e)


# ========== CIRCL Passive DNS ==========

class RateLimiter:
    """Simple rate limiter for API requests."""
    def __init__(self, rate_per_second):
        self.rate = rate_per_second
        self.min_interval = 1.0 / rate_per_second if rate_per_second > 0 else 0
        self.last_request_time = 0
        self.lock = threading.Lock()
    
    def wait(self):
        """Wait if necessary to respect rate limit."""
        with self.lock:
            now = time.time()
            elapsed = now - self.last_request_time
            if elapsed < self.min_interval:
                time.sleep(self.min_interval - elapsed)
            self.last_request_time = time.time()


def query_circl_pdns(query_value, settings):
    """Query CIRCL Passive DNS API for a single value."""
    url = f"https://www.circl.lu/pdns/query/{quote(query_value, safe='')}"
    
    headers = {}
    if settings.get('disable_active_query'):
        headers['dribble-disable-active-query'] = 'true'
    
    if settings.get('max_results'):
        headers['dribble-paginate-count'] = str(settings['max_results'])
    
    auth = None
    if settings.get('username') and settings.get('password'):
        auth = (settings['username'], settings['password'])
    
    try:
        response = requests.get(url, auth=auth, headers=headers, timeout=30)
        response.raise_for_status()
        
        # Parse NDJSON response (newline-delimited JSON)
        results = []
        for line in response.text.strip().split('\n'):
            line = line.strip()
            if line:
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        
        return results
    except requests.exceptions.RequestException as e:
        raise UpstreamError(upstream_message('CIRCL', e))


@app.route('/api/circl/pdns', methods=['POST'])
@login_required
def api_circl_pdns():
    """Query CIRCL Passive DNS for an IP or domain."""
    data = json_body()
    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400
    
    query_value = str_field(data, 'value').lower()
    query_type = data.get('type', 'ip').lower()  # 'ip' or 'domain'
    
    if not query_value:
        return jsonify({'error': 'Query value is required'}), 400
    
    if query_type not in ['ip', 'domain']:
        return jsonify({'error': 'Invalid query type. Use "ip" or "domain"'}), 400
    
    # Get CIRCL settings
    settings = get_circl_settings()
    
    if not settings.get('username') or not settings.get('password'):
        return jsonify({'error': 'CIRCL credentials not configured. Please set them in Admin Settings.'}), 400
    
    # Check cache first
    cached = get_cached_circl_pdns(query_value, query_type)
    if cached:
        app.logger.debug("[CIRCL PDNS] Cache hit for %s", query_value)
        return jsonify({
            'query': query_value,
            'type': query_type,
            'results': cached['results'],
            'result_count': cached['result_count'],
            'from_cache': True,
            'cached_at': cached['cached_at']
        })
    
    app.logger.debug("[CIRCL PDNS] Querying %s (%s)", query_value, query_type)
    
    try:
        results = query_circl_pdns(query_value, settings)
        
        # Cache the results
        set_cached_circl_pdns(query_value, query_type, results, len(results), settings['cache_ttl'])
        
        log_audit('circl_pdns_query', 'circl', query_value, {'type': query_type, 'result_count': len(results)})
        
        return jsonify({
            'query': query_value,
            'type': query_type,
            'results': results,
            'result_count': len(results),
            'from_cache': False
        })
        
    except UpstreamError as e:
        return jsonify({'error': str(e)}), 500
    except Exception as e:
        return internal_error(e)


MAX_CIRCL_BULK_QUERIES = 100


@app.route('/api/circl/pdns/bulk', methods=['POST'])
@login_required
def api_circl_pdns_bulk():
    """Query CIRCL Passive DNS for multiple IPs/domains with rate limiting and concurrency control."""
    data = json_body()
    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400
    
    queries = str_list(data.get('queries'))
    query_type = str_field(data, 'type', 'ip').lower()
    
    if not queries:
        return jsonify({'error': 'No queries provided'}), 400
    if len(queries) > MAX_CIRCL_BULK_QUERIES:
        return jsonify({'error': f'Maximum {MAX_CIRCL_BULK_QUERIES} queries allowed per request'}), 400
    
    if query_type not in ['ip', 'domain']:
        return jsonify({'error': 'Invalid query type. Use "ip" or "domain"'}), 400
    
    # Get CIRCL settings
    settings = get_circl_settings()
    
    if not settings.get('username') or not settings.get('password'):
        return jsonify({'error': 'CIRCL credentials not configured. Please set them in Admin Settings.'}), 400
    
    # Initialize rate limiter
    rate_limiter = RateLimiter(settings['rate_limit'])
    
    results = {}
    errors = {}
    
    def process_query(query_value):
        query_value = query_value.strip().lower()
        
        # Check cache first
        cached = get_cached_circl_pdns(query_value, query_type)
        if cached:
            return query_value, cached['results'], None, True
        
        # Rate limit
        rate_limiter.wait()
        
        try:
            pdns_results = query_circl_pdns(query_value, settings)
            # Cache the results
            set_cached_circl_pdns(query_value, query_type, pdns_results, len(pdns_results), settings['cache_ttl'])
            return query_value, pdns_results, None, False
        except Exception as e:
            return query_value, None, str(e) if isinstance(e, UpstreamError) else 'Lookup failed', False
    
    # Use ThreadPoolExecutor for concurrent requests
    max_workers = settings.get('concurrency', 5)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(process_query, q) for q in queries]
        
        for future in as_completed(futures):
            query_value, pdns_results, error, from_cache = future.result()
            if error:
                errors[query_value] = error
            else:
                results[query_value] = {
                    'results': pdns_results,
                    'result_count': len(pdns_results) if pdns_results else 0,
                    'from_cache': from_cache
                }
    
    log_audit('circl_pdns_bulk_query', 'circl', None, {
        'query_count': len(queries),
        'result_count': len(results),
        'error_count': len(errors)
    })
    
    return jsonify({
        'results': results,
        'errors': errors,
        'total_queries': len(queries),
        'successful': len(results),
        'failed': len(errors)
    })


@app.route('/api/circl/pdns/download/<query_value>')
@login_required
def api_circl_pdns_download(query_value):
    """Download cached CIRCL PDNS results as JSON."""
    query_value = query_value.strip().lower()
    
    # Try to find in cache (check both ip and domain types)
    cached = get_cached_circl_pdns(query_value, 'ip')
    if not cached:
        cached = get_cached_circl_pdns(query_value, 'domain')
    
    if not cached:
        return jsonify({'error': 'No cached results found for this query'}), 404
    
    # Create JSON response with download headers
    response_data = {
        'query': query_value,
        'cached_at': cached['cached_at'],
        'result_count': cached['result_count'],
        'results': cached['results']
    }
    
    response = app.response_class(
        response=json.dumps(response_data, indent=2),
        status=200,
        mimetype='application/json'
    )
    response.headers['Content-Disposition'] = f'attachment; filename=circl_pdns_{query_value}.json'
    return response


# ========== HackerTarget Shared DNS ==========

@app.route('/api/hackertarget/shared-ns', methods=['POST'])
@login_required
def api_hackertarget_shared_ns():
    """Query HackerTarget for domains sharing the same nameserver."""
    data = json_body()
    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400
    
    query_value = str_field(data, 'value').lower()
    
    if not query_value:
        return jsonify({'error': 'Domain/nameserver value is required'}), 400
    
    # Get HackerTarget settings
    settings = get_hackertarget_settings()
    
    # Check cache first
    cached = get_cached_hackertarget(query_value, 'shared_ns')
    if cached:
        app.logger.debug("[HackerTarget] Cache hit for %s", query_value)
        return jsonify({
            'query': query_value,
            'results': cached['results'],
            'result_count': cached['result_count'],
            'from_cache': True,
            'cached_at': cached['cached_at']
        })
    
    app.logger.debug("[HackerTarget] Querying shared NS for %s", query_value)
    
    try:
        # Build URL with or without API key
        params = {'q': query_value}
        if settings.get('api_key'):
            params['apikey'] = settings['api_key']

        response = requests.get('https://api.hackertarget.com/findshareddns/', params=params, timeout=30)
        response.raise_for_status()
        
        # Parse line-delimited results
        text = response.text.strip()
        
        # Check for error responses from HackerTarget
        if text.startswith('error'):
            return jsonify({'error': text}), 400
        
        if text == 'No results found' or not text:
            # Cache empty result
            set_cached_hackertarget(query_value, 'shared_ns', [], 0, settings['cache_ttl'])
            return jsonify({
                'query': query_value,
                'results': [],
                'result_count': 0,
                'from_cache': False
            })
        
        # Parse domains (one per line)
        domains = [d.strip().lower() for d in text.split('\n') if d.strip()]
        
        # Cache the results
        set_cached_hackertarget(query_value, 'shared_ns', domains, len(domains), settings['cache_ttl'])
        
        log_audit('hackertarget_shared_ns', 'hackertarget', query_value, {'result_count': len(domains)})
        
        return jsonify({
            'query': query_value,
            'results': domains,
            'result_count': len(domains),
            'from_cache': False
        })
        
    except requests.exceptions.RequestException as e:
        return jsonify({'error': upstream_message('HackerTarget', e)}), 500
    except Exception as e:
        return internal_error(e)


# ========== ViewDNS API ==========

@app.route('/api/viewdns/settings', methods=['GET'])
@login_required
def api_viewdns_settings():
    """Get ViewDNS settings (for frontend to check if API key is configured)."""
    settings = get_viewdns_settings()
    return jsonify({
        'api_key_configured': bool(settings.get('api_key')),
        'max_nodes': settings.get('max_nodes', 100)
    })


@app.route('/api/viewdns/reverse-mx', methods=['POST'])
@login_required
def api_viewdns_reverse_mx():
    """Query ViewDNS for domains using a specific mail server."""
    data = json_body()
    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400
    
    query_value = str_field(data, 'value').lower()
    
    if not query_value:
        return jsonify({'error': 'Mail server value is required'}), 400
    
    # Get ViewDNS settings
    settings = get_viewdns_settings()
    
    if not settings.get('api_key'):
        return jsonify({'error': 'ViewDNS API key not configured. Please set it in Admin Settings.'}), 400
    
    # Check cache first
    cached = get_cached_viewdns(query_value, 'reverse_mx')
    if cached:
        app.logger.debug("[ViewDNS] Cache hit for reverse_mx: %s", query_value)
        return jsonify({
            'query': query_value,
            'query_type': 'reverse_mx',
            'results': cached['results'],
            'result_count': cached['result_count'],
            'from_cache': True,
            'cached_at': cached['cached_at']
        })
    
    app.logger.debug("[ViewDNS] Querying reverse MX for %s", query_value)
    
    try:
        response = requests.get('https://api.viewdns.info/reversemx/', timeout=30,
                                params={'mx': query_value, 'apikey': settings['api_key'], 'output': 'json'})
        response.raise_for_status()
        
        data = response.json()
        
        # Check for API errors
        if 'error' in data:
            return jsonify({'error': data['error']}), 400
        
        # Parse results
        domains = []
        if 'response' in data and 'domains' in data['response']:
            domains = data['response']['domains']
            # Handle both list of strings and list of dicts
            if domains and isinstance(domains[0], dict):
                domains = [d.get('domain', '') for d in domains if d.get('domain')]
        
        result_count = int(data.get('response', {}).get('domain_count', len(domains)))
        
        # Cache the results
        set_cached_viewdns(query_value, 'reverse_mx', domains, result_count, settings['cache_ttl'])
        
        log_audit('viewdns_reverse_mx', 'viewdns', query_value, {'result_count': result_count})
        
        return jsonify({
            'query': query_value,
            'query_type': 'reverse_mx',
            'results': domains,
            'result_count': result_count,
            'from_cache': False
        })
        
    except requests.exceptions.RequestException as e:
        return jsonify({'error': upstream_message('ViewDNS', e)}), 500
    except Exception as e:
        return internal_error(e)


@app.route('/api/viewdns/reverse-ns', methods=['POST'])
@login_required
def api_viewdns_reverse_ns():
    """Query ViewDNS for domains using a specific nameserver."""
    data = json_body()
    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400
    
    query_value = str_field(data, 'value').lower()
    
    if not query_value:
        return jsonify({'error': 'Nameserver value is required'}), 400
    
    # Get ViewDNS settings
    settings = get_viewdns_settings()
    
    if not settings.get('api_key'):
        return jsonify({'error': 'ViewDNS API key not configured. Please set it in Admin Settings.'}), 400
    
    # Check cache first
    cached = get_cached_viewdns(query_value, 'reverse_ns')
    if cached:
        app.logger.debug("[ViewDNS] Cache hit for reverse_ns: %s", query_value)
        return jsonify({
            'query': query_value,
            'query_type': 'reverse_ns',
            'results': cached['results'],
            'result_count': cached['result_count'],
            'from_cache': True,
            'cached_at': cached['cached_at']
        })
    
    app.logger.debug("[ViewDNS] Querying reverse NS for %s", query_value)
    
    try:
        response = requests.get('https://api.viewdns.info/reversens/', timeout=30,
                                params={'ns': query_value, 'apikey': settings['api_key'], 'output': 'json'})
        response.raise_for_status()
        
        data = response.json()
        
        # Check for API errors
        if 'error' in data:
            return jsonify({'error': data['error']}), 400
        
        # Parse results
        domains = []
        if 'response' in data and 'domains' in data['response']:
            for d in data['response']['domains']:
                if isinstance(d, dict) and 'domain' in d:
                    domains.append(d['domain'])
                elif isinstance(d, str):
                    domains.append(d)
        
        result_count = int(data.get('response', {}).get('domain_count', len(domains)))
        
        # Cache the results
        set_cached_viewdns(query_value, 'reverse_ns', domains, result_count, settings['cache_ttl'])
        
        log_audit('viewdns_reverse_ns', 'viewdns', query_value, {'result_count': result_count})
        
        return jsonify({
            'query': query_value,
            'query_type': 'reverse_ns',
            'results': domains,
            'result_count': result_count,
            'from_cache': False
        })
        
    except requests.exceptions.RequestException as e:
        return jsonify({'error': upstream_message('ViewDNS', e)}), 500
    except Exception as e:
        return internal_error(e)


@app.route('/api/viewdns/reverse-whois', methods=['POST'])
@login_required
def api_viewdns_reverse_whois():
    """Query ViewDNS for domains matching WHOIS data."""
    data = json_body()
    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400
    
    query_value = str_field(data, 'value')
    
    if not query_value:
        return jsonify({'error': 'Search value is required'}), 400
    
    # Get ViewDNS settings
    settings = get_viewdns_settings()
    
    if not settings.get('api_key'):
        return jsonify({'error': 'ViewDNS API key not configured. Please set it in Admin Settings.'}), 400
    
    # Check cache first
    cached = get_cached_viewdns(query_value, 'reverse_whois')
    if cached:
        app.logger.debug("[ViewDNS] Cache hit for reverse_whois: %s", query_value)
        return jsonify({
            'query': query_value,
            'query_type': 'reverse_whois',
            'results': cached['results'],
            'result_count': cached['result_count'],
            'from_cache': True,
            'cached_at': cached['cached_at']
        })
    
    app.logger.debug("[ViewDNS] Querying reverse WHOIS for %s", query_value)
    
    try:
        response = requests.get('https://api.viewdns.info/reversewhois/', timeout=30,
                                params={'q': query_value, 'apikey': settings['api_key'], 'output': 'json'})
        response.raise_for_status()
        
        data = response.json()
        
        # Check for API errors
        if 'error' in data:
            return jsonify({'error': data['error']}), 400
        
        # Parse results - includes domain, created_date, registrar
        matches = []
        if 'response' in data and 'matches' in data['response']:
            matches = data['response']['matches']
        
        result_count = int(data.get('response', {}).get('result_count', len(matches)))
        
        app.logger.debug("[ViewDNS] Reverse WHOIS found %d results for %s", result_count, query_value)
        
        # Cache the results
        set_cached_viewdns(query_value, 'reverse_whois', matches, result_count, settings['cache_ttl'])
        
        log_audit('viewdns_reverse_whois', 'viewdns', query_value, {'result_count': result_count})
        
        return jsonify({
            'query': query_value,
            'query_type': 'reverse_whois',
            'results': matches,
            'result_count': result_count,
            'from_cache': False
        })
        
    except requests.exceptions.RequestException as e:
        return jsonify({'error': upstream_message('ViewDNS', e)}), 500
    except Exception as e:
        return internal_error(e)


def _open_threats_db_ro():
    """Open a read-only connection to threats.db. Raises FileNotFoundError if missing."""
    p = _get_threats_db_path()
    if not p:
        raise FileNotFoundError('threats.db not found')
    uri = f'file:{p.as_posix()}?mode=ro'
    conn = sqlite3.connect(uri, uri=True, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


@app.route('/api/intel/sources', methods=['GET'])
@login_required
def intel_sources():
    """Return all feeds for filter dropdown."""
    try:
        conn = _open_threats_db_ro()
    except FileNotFoundError:
        return jsonify({'sources': []})
    try:
        rows = conn.execute('SELECT feed_id, feed_name FROM feeds ORDER BY feed_name').fetchall()
        return jsonify({'sources': [{'id': r['feed_id'], 'name': r['feed_name']} for r in rows]})
    except sqlite3.Error as e:
        return internal_error(e)
    finally:
        conn.close()


@app.route('/api/intel/tags', methods=['GET'])
@login_required
def intel_tags():
    """Return all categories for filter dropdown."""
    try:
        conn = _open_threats_db_ro()
    except FileNotFoundError:
        return jsonify({'tags': []})
    try:
        rows = conn.execute('SELECT category_id, category_value FROM categories ORDER BY category_value').fetchall()
        return jsonify({'tags': [{'id': r['category_id'], 'value': r['category_value']} for r in rows]})
    except sqlite3.Error as e:
        return internal_error(e)
    finally:
        conn.close()


def _build_intel_query(args, base_select):
    """Build WHERE clause + params from query args. Returns (where_sql, params)."""
    clauses = []
    params = []
    source_id = args.get('source_id', '').strip()
    tag_id = args.get('tag_id', '').strip()
    q = args.get('q', '').strip()
    if source_id.isdigit():
        clauses.append('ips.feed = ?')
        params.append(int(source_id))
    if tag_id.isdigit():
        clauses.append('ips.category = ?')
        params.append(int(tag_id))
    if q:
        # A range on the prefix, not LIKE: SQLite's LIKE is case-insensitive and cannot use
        # idx_ips_ip, so every search used to scan the table. Matches the prefix as typed.
        clauses.append('ips.ip >= ? AND ips.ip < ?')
        params.extend([q, q[:-1] + chr(ord(q[-1]) + 1)])
    where_sql = (' WHERE ' + ' AND '.join(clauses)) if clauses else ''
    return base_select + where_sql, params


@app.route('/api/intel/iocs', methods=['GET'])
@login_required
def intel_iocs():
    """Paginated IOC browser with optional filters."""
    try:
        conn = _open_threats_db_ro()
    except FileNotFoundError:
        return jsonify({'rows': [], 'has_more': False, 'error': 'threats.db not found'}), 200

    try:
        limit = max(1, min(int(request.args.get('limit', 100)), 1000))
    except (TypeError, ValueError):
        limit = 100
    try:
        offset = max(0, int(request.args.get('offset', 0)))
    except (TypeError, ValueError):
        offset = 0

    base = (
        'SELECT ips.ip, '
        'GROUP_CONCAT(DISTINCT feeds.feed_name) AS sources, '
        'GROUP_CONCAT(DISTINCT categories.category_value) AS tags '
        'FROM ips '
        'LEFT JOIN feeds ON ips.feed = feeds.feed_id '
        'LEFT JOIN categories ON ips.category = categories.category_id'
    )
    sql, params = _build_intel_query(request.args, base)
    sql += ' GROUP BY ips.ip ORDER BY ips.ip LIMIT ? OFFSET ?'
    # Fetch limit+1 grouped rows to know if more pages exist without COUNT(*)
    params_with_paging = params + [limit + 1, offset]

    try:
        rows = conn.execute(sql, params_with_paging).fetchall()
    except sqlite3.Error as e:
        conn.close()
        return internal_error(e)

    has_more = len(rows) > limit
    rows = rows[:limit]
    result = [
        {'ip': r['ip'], 'sources': r['sources'] or '', 'tags': r['tags'] or ''}
        for r in rows
    ]
    conn.close()
    return jsonify({'rows': result, 'has_more': has_more, 'limit': limit, 'offset': offset})


@app.route('/api/intel/stats', methods=['GET'])
@login_required
def intel_stats():
    """Aggregate counts for the Intel Browser statistics panel.

    Served from an mtime-keyed cache; recomputed automatically when threats.db
    is rewritten (e.g., LogBoost binary refresh). Cache is primed at startup.
    """
    data = _get_intel_stats()
    if data is None:
        return jsonify({'sources': [], 'tags': [], 'total_entries': 0, 'unique_ips': 0,
                        'error': 'threats.db not found'})
    return jsonify(data)


@app.route('/api/intel/export', methods=['GET'])
@login_required
def intel_export():
    """Streaming CSV export of filtered IOCs."""
    try:
        conn = _open_threats_db_ro()
    except FileNotFoundError:
        return jsonify({'error': 'threats.db not found'}), 404

    base = (
        'SELECT ips.ip, '
        'GROUP_CONCAT(DISTINCT feeds.feed_name) AS sources, '
        'GROUP_CONCAT(DISTINCT categories.category_value) AS tags '
        'FROM ips '
        'LEFT JOIN feeds ON ips.feed = feeds.feed_id '
        'LEFT JOIN categories ON ips.category = categories.category_id'
    )
    sql, params = _build_intel_query(request.args, base)
    sql += ' GROUP BY ips.ip ORDER BY ips.ip'

    def generate():
        try:
            yield 'ip,sources,tags\n'
            cursor = conn.execute(sql, params)
            for row in cursor:
                ip = (row['ip'] or '').replace('"', '""')
                src = (row['sources'] or '').replace('"', '""')
                tag = (row['tags'] or '').replace('"', '""')
                yield f'"{ip}","{src}","{tag}"\n'
        finally:
            conn.close()

    filename = 'intel_export.csv'
    return Response(
        generate(),
        mimetype='text/csv',
        headers={
            'Content-Disposition': f'attachment; filename="{filename}"',
            'Cache-Control': 'no-store',
        },
    )


if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() in ('true', '1', 'yes')
    create_app().run(debug=debug_mode, host='0.0.0.0', port=5001)
