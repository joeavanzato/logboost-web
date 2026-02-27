"""
LogBoost Web UI - Flask application for log enrichment
"""

import os
import re
import csv
import json
import uuid
import subprocess
import tempfile
import shutil
import time
import threading
import ipaddress
import logging
import socket
from pathlib import Path
from datetime import datetime
from functools import wraps
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from flask import (
    Flask, render_template, request, jsonify, send_file,
    session, redirect, url_for, flash
)
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
    BLOCKED_IP_RANGES, DEFAULT_MAX_URL_FETCH_SIZE, MAX_REDIRECTS
)

# Import auth module
from auth import login_required

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))

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
from admin import init_admin, get_db, verify_password, ROLE_ADMIN, log_audit, get_effective_logboost_path

# ============================================
# CSRF Configuration
# ============================================

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    """Handle CSRF validation errors."""
    return jsonify({'error': 'CSRF token missing or invalid'}), 400


# Initialize admin module (with CSRF-enabled blueprint)
init_admin(app, csrf)

# Register route blueprints
from routes import register_blueprints
register_blueprints(app)

# Configuration
UPLOAD_FOLDER = Path(__file__).parent / 'uploads'
OUTPUT_FOLDER = Path(__file__).parent / 'output'
LOGBOOST_BINARY = os.environ.get('LOGBOOST_PATH', 'LogBoost')
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

UPLOAD_FOLDER.mkdir(exist_ok=True)
OUTPUT_FOLDER.mkdir(exist_ok=True)

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


# IP regex pattern
IP_PATTERN = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
    r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
)


# ============================================
# Authentication
# ============================================

# login_required decorator is imported from auth.py
# login/logout routes are in routes/auth_routes.py


# ============================================
# Helper Functions
# ============================================

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
    print(f"[DEBUG] LogBoost command: {cmd_str}", flush=True)

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
    except Exception as e:
        return False, '', str(e)


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
            
    except Exception as e:
        return {
            'error': str(e),
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


def read_csv_all(filepath: Path) -> dict:
    """Read entire CSV file for client-side processing."""
    rows = []
    headers = []
    
    try:
        with open(filepath, 'r', newline='', encoding='utf-8', errors='replace') as f:
            reader = csv.reader(f)
            headers = next(reader, [])
            rows = list(reader)
            
    except Exception as e:
        return {
            'error': str(e),
            'headers': [],
            'rows': [],
            'total_rows': 0
        }
    
    return {
        'headers': headers,
        'rows': rows,
        'total_rows': len(rows)
    }


def get_session_dir(session_id: str) -> Path:
    """Get or create session-specific directories."""
    session_upload = UPLOAD_FOLDER / session_id
    session_output = OUTPUT_FOLDER / session_id
    session_upload.mkdir(exist_ok=True)
    session_output.mkdir(exist_ok=True)
    return session_upload, session_output


def cleanup_session(session_id: str) -> None:
    """Clean up session directories."""
    session_upload = UPLOAD_FOLDER / session_id
    session_output = OUTPUT_FOLDER / session_id
    if session_upload.exists():
        shutil.rmtree(session_upload)
    if session_output.exists():
        shutil.rmtree(session_output)


@app.before_request
def ensure_session():
    """Ensure each user has a session ID."""
    if 'session_id' not in session:
        session['session_id'] = str(uuid.uuid4())


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
                               maxmind_dir=MAXMIND_DIR)

    # Check if threat database exists
    threat_db_missing = not check_threat_db_exists()

    # Check for shared results
    shared_id = request.args.get('shared')
    if shared_id:
        shared = get_shared_results(shared_id)
        if shared:
            return render_template('index.html', shared_results=shared_id, threat_db_missing=threat_db_missing)
    return render_template('index.html', threat_db_missing=threat_db_missing)


@app.route('/enrich/text', methods=['POST'])
@login_required
def enrich_text():
    """Enrich IP addresses extracted from pasted text."""
    session_id = session.get('session_id', str(uuid.uuid4()))
    session_upload, session_output = get_session_dir(session_id)
    
    # Clean previous results
    for f in session_upload.iterdir():
        f.unlink()
    for f in session_output.iterdir():
        f.unlink()
    
    text = request.form.get('text', '')
    if not text.strip():
        return render_template('partials/error.html', error='No text provided')
    
    # Extract IPs
    ips = extract_ips(text)
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
        return render_template('partials/error.html', error=error_msg, command=' '.join(cmd))
    
    # Find output file
    output_files = list(session_output.glob('*.csv'))
    if not output_files:
        return render_template('partials/error.html', error='No output file generated')
    
    output_file = output_files[0]
    session['current_output'] = str(output_file)
    
    # Read all results for client-side processing
    data = read_csv_all(output_file)
    data['ip_count'] = len(ips)
    data['filename'] = output_file.name
    data['page_size'] = int(request.form.get('page_size', 50))
    
    # Add large file warning if threshold exceeded
    large_file_threshold = get_large_file_warning_threshold()
    if data.get('total_rows', 0) > large_file_threshold:
        data['large_file_warning'] = (
            f"This result set has {data['total_rows']:,} rows, which may affect browser performance. "
            f"Consider using filters or downloading the CSV for analysis in a spreadsheet application."
        )
    
    log_audit('logboost_enrich', 'logboost', None, {'source': 'text', 'ip_count': len(ips)})
    return render_template('partials/results.html', **data)


@app.route('/enrich/file', methods=['POST'])
@login_required
def enrich_file():
    """Enrich uploaded log file."""
    session_id = session.get('session_id', str(uuid.uuid4()))
    session_upload, session_output = get_session_dir(session_id)
    
    # Clean previous results
    for f in session_upload.iterdir():
        f.unlink()
    for f in session_output.iterdir():
        f.unlink()
    
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
        'dbdir': request.form.get('dbdir') or MAXMIND_DIR,
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
        return render_template('partials/error.html', error=error_msg, command=' '.join(cmd))
    
    # Find output file
    output_files = list(session_output.glob('**/*.csv'))
    if not output_files:
        return render_template('partials/error.html', error='No output file generated')
    
    output_file = output_files[0]
    session['current_output'] = str(output_file)
    
    # Read all results for client-side processing
    data = read_csv_all(output_file)
    data['filename'] = output_file.name
    data['original_filename'] = filename
    data['page_size'] = int(request.form.get('page_size', 50))
    
    # Add large file warning if threshold exceeded
    large_file_threshold = get_large_file_warning_threshold()
    if data.get('total_rows', 0) > large_file_threshold:
        data['large_file_warning'] = (
            f"This result set has {data['total_rows']:,} rows, which may affect browser performance. "
            f"Consider using filters or downloading the CSV for analysis in a spreadsheet application."
        )
    
    log_audit('logboost_enrich', 'logboost', None, {'source': 'file', 'filename': filename, 'row_count': data.get('total_rows', 0)})
    return render_template('partials/results.html', **data)


@app.route('/results/page', methods=['GET'])
@login_required
def results_page():
    """Get a specific page of results."""
    output_file = session.get('current_output')
    if not output_file or not Path(output_file).exists():
        return render_template('partials/error.html', error='No results available')
    
    page = int(request.args.get('page', 1))
    page_size = int(request.args.get('page_size', 50))
    
    data = read_csv_paginated(Path(output_file), page=page, page_size=page_size)
    data['filename'] = Path(output_file).name
    
    return render_template('partials/results_table.html', **data)


@app.route('/download')
@login_required
def download():
    """Download the current result file."""
    output_file = session.get('current_output')
    if not output_file or not Path(output_file).exists():
        return 'No file available', 404
    
    return send_file(
        output_file,
        as_attachment=True,
        download_name=Path(output_file).name
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
    db_accessible = False
    db = None
    try:
        db = get_db()
        db.execute("SELECT 1")
        db_accessible = True
    except Exception:
        db_accessible = False
    finally:
        if db is not None:
            db.close()

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

    return jsonify({
        'status': status_text,
        'db_accessible': db_accessible,
        'logboost_available': logboost_available,
        'logboost_path': get_effective_logboost_path(),
        'maxmind_dir': MAXMIND_DIR,
        'maxmind_available': maxmind_available,
        'threat_db_dir': THREAT_DB_DIR,
        'uploads_writable': uploads_writable,
        'output_writable': output_writable,
    }), status_code


@app.route('/stats')
@login_required
def get_stats():
    """Generate statistics for the current result file."""
    output_file = session.get('current_output')
    if not output_file or not Path(output_file).exists():
        return render_template('partials/error.html', error='No results available for statistics')
    
    stats = compute_statistics(Path(output_file))
    return render_template('partials/stats.html', stats=stats)


@app.route('/column-values/<column_name>')
@login_required
def get_column_values(column_name: str):
    """Get unique values for a specific column (for filter dropdowns)."""
    output_file = session.get('current_output')
    if not output_file or not Path(output_file).exists():
        return jsonify({'values': []})
    
    values = get_unique_column_values(Path(output_file), column_name, limit=100)
    return jsonify({'values': values})


def compute_statistics(filepath: Path) -> dict:
    """Compute comprehensive statistics for a CSV file.
    
    Memory-efficient version that:
    - Streams rows instead of loading all into memory
    - Caps unique value tracking at configurable limit (default 10,000)
    - Adds truncation flags when limits are exceeded
    """
    # Get configurable limit for unique values per column
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
            
            # Initialize column stats with memory-conscious structures
            column_stats = {h: {
                'name': h,
                'is_enrichment': h.startswith('lb_'),
                'total_values': 0,
                'empty_count': 0,
                'unique_values': set(),
                'unique_truncated': False,  # Flag if we stopped tracking uniques
                'value_counts': {},
                'counts_truncated': False,  # Flag if we stopped tracking counts
                'sample_values': []
            } for h in headers}
            
            # Stream rows instead of loading all into memory
            row_count = 0
            for row in reader:
                row_count += 1
                for header in headers:
                    # Handle None values from CSV
                    raw_value = row.get(header)
                    value = (raw_value or '').strip()
                    col_stat = column_stats[header]
                    col_stat['total_values'] += 1
                    
                    if not value or value.lower() == 'none':
                        col_stat['empty_count'] += 1
                    else:
                        # Track unique values up to the limit
                        if not col_stat['unique_truncated']:
                            if len(col_stat['unique_values']) < max_unique:
                                col_stat['unique_values'].add(value)
                            else:
                                col_stat['unique_truncated'] = True
                        
                        # Track value counts up to the limit
                        if not col_stat['counts_truncated']:
                            if len(col_stat['value_counts']) < max_unique:
                                col_stat['value_counts'][value] = col_stat['value_counts'].get(value, 0) + 1
                            elif value in col_stat['value_counts']:
                                # Still count values we're already tracking
                                col_stat['value_counts'][value] += 1
                            else:
                                col_stat['counts_truncated'] = True
                        elif value in col_stat['value_counts']:
                            col_stat['value_counts'][value] += 1
                        
                        # Collect sample values
                        if len(col_stat['sample_values']) < 5 and value not in col_stat['sample_values']:
                            col_stat['sample_values'].append(value)
            
            stats['total_rows'] = row_count
            
            # Check if any columns were truncated and add warning
            truncated_cols = [h for h, s in column_stats.items() if s['unique_truncated'] or s['counts_truncated']]
            if truncated_cols:
                stats['warnings'].append(
                    f"Statistics for {len(truncated_cols)} column(s) were limited to {max_unique:,} unique values for memory efficiency."
                )
            
            # Process column stats
            for header in headers:
                col_stat = column_stats[header]
                unique_count = len(col_stat['unique_values'])
                total = col_stat['total_values']
                empty = col_stat['empty_count']
                
                # Get ALL values sorted by count (for modal expansion)
                all_values_sorted = sorted(
                    col_stat['value_counts'].items(),
                    key=lambda x: x[1],
                    reverse=True
                )
                
                # Top 10 values
                sorted_values = all_values_sorted[:10]
                
                # Get rare values (appearing only once or twice)
                rare_values = sorted(
                    [(v, c) for v, c in col_stat['value_counts'].items() if c <= 2],
                    key=lambda x: x[1]
                )[:10]
                
                # Calculate entropy/diversity score
                fill_rate = ((total - empty) / total * 100) if total > 0 else 0
                uniqueness = (unique_count / (total - empty) * 100) if (total - empty) > 0 else 0
                
                stats['columns'].append({
                    'name': header,
                    'is_enrichment': col_stat['is_enrichment'],
                    'unique_count': unique_count,
                    'unique_count_truncated': col_stat['unique_truncated'],
                    'empty_count': empty,
                    'fill_rate': round(fill_rate, 1),
                    'uniqueness': round(uniqueness, 1),
                    'top_values': sorted_values,
                    'all_values': all_values_sorted,  # For modal expansion
                    'rare_values': rare_values,
                    'sample_values': col_stat['sample_values']
                })
            
            # Generate enrichment-specific summaries
            for col in stats['columns']:
                name = col['name']
                
                # Threat intelligence summary
                if name == 'lb_ThreatCategories':
                    threat_cats = {}
                    for value, count in col['top_values']:
                        if value and value != 'none':
                            for cat in value.split('|'):
                                cat = cat.strip()
                                if cat:
                                    threat_cats[cat] = threat_cats.get(cat, 0) + count
                    all_categories = sorted(
                        threat_cats.items(), key=lambda x: x[1], reverse=True
                    )
                    stats['threat_summary']['categories'] = all_categories[:10]
                    stats['threat_summary']['all_categories'] = all_categories
                
                if name == 'lb_ThreatFeedCount':
                    stats['threat_summary']['feed_counts'] = col['top_values']
                    stats['threat_summary']['all_feed_counts'] = col.get('all_values', col['top_values'])
                
                if name == 'lb_ThreatFeeds' or name == 'lb_Threat_Feeds' or name == 'lb_ThreatFeed':
                    feed_names = {}
                    for value, count in col['all_values']:
                        if value and value != 'none':
                            for feed in value.split('|'):
                                feed = feed.strip()
                                if feed:
                                    feed_names[feed] = feed_names.get(feed, 0) + count
                    all_feeds = sorted(
                        feed_names.items(), key=lambda x: x[1], reverse=True
                    )
                    stats['threat_summary']['feeds'] = all_feeds[:10]
                    stats['threat_summary']['all_feeds'] = all_feeds
                    # Store the actual column name for filtering
                    stats['threat_summary']['feeds_column'] = name
                
                # Geo summary
                if name == 'lb_Country':
                    stats['geo_summary']['countries'] = col['top_values']
                
                if name == 'lb_ASN':
                    stats['geo_summary']['asns'] = col['top_values']
                
                if name == 'lb_City':
                    stats['geo_summary']['cities'] = col['top_values']
                
                if name == 'lb_Org':
                    stats['geo_summary']['orgs'] = col['top_values']
                
                # DNS summary
                if name == 'lb_ReverseDNS' or name == 'lb_DNS' or name == 'lb_PTR':
                    stats['dns_summary']['reverse_dns'] = col['top_values']
                    stats['dns_summary']['dns_fill_rate'] = col['fill_rate']
                    stats['dns_summary']['dns_unique'] = col['unique_count']
                
                if name == 'lb_Hostnames':
                    hostnames = {}
                    for value, count in col['top_values']:
                        if value and value != 'none':
                            for hostname in value.split('|'):
                                hostname = hostname.strip()
                                if hostname:
                                    hostnames[hostname] = hostnames.get(hostname, 0) + count
                    stats['dns_summary']['hostnames'] = sorted(
                        hostnames.items(), key=lambda x: x[1], reverse=True
                    )[:10]
                
                # WhoIS summary
                if name == 'lb_IPWhoIsOrg' or name == 'lb_WhoIs_OrgName' or name == 'lb_WhoIsOrg':
                    stats['whois_summary']['orgs'] = col['top_values']
                
                if name == 'lb_IPWhoIsCountry' or name == 'lb_WhoIs_Country' or name == 'lb_WhoIsCountry':
                    stats['whois_summary']['countries'] = col['top_values']
                
                if name == 'lb_IPWhoIsNetRange' or name == 'lb_WhoIs_NetRange' or name == 'lb_WhoIsNetRange':
                    stats['whois_summary']['net_ranges'] = col['top_values']
                
                if name == 'lb_DomainWhoIsRegistrar' or name == 'lb_WhoIsRegistrar':
                    stats['whois_summary']['registrars'] = col['top_values']
                
                if name == 'lb_DomainWhoIsOrg' or name == 'lb_DomainOrg':
                    stats['whois_summary']['domain_orgs'] = col['top_values']
                
                # Shodan InternetDB summary
                if name == 'lb_Ports' or name == 'lb_InternetDB_Ports' or name == 'lb_ShodanPorts':
                    ports = {}
                    for value, count in col['top_values']:
                        if value and value != 'none':
                            for port in value.split('|'):
                                port = port.strip()
                                if port:
                                    ports[port] = ports.get(port, 0) + count
                    stats['shodan_summary']['ports'] = sorted(
                        ports.items(), key=lambda x: x[1], reverse=True
                    )[:15]
                
                if name == 'lb_Tags' or name == 'lb_InternetDB_Tags' or name == 'lb_ShodanTags':
                    tags = {}
                    for value, count in col['top_values']:
                        if value and value != 'none':
                            for tag in value.split('|'):
                                tag = tag.strip()
                                if tag:
                                    tags[tag] = tags.get(tag, 0) + count
                    stats['shodan_summary']['tags'] = sorted(
                        tags.items(), key=lambda x: x[1], reverse=True
                    )[:10]
                
                if name == 'lb_CPEs' or name == 'lb_InternetDB_CPEs' or name == 'lb_ShodanCPEs':
                    cpes = {}
                    for value, count in col['top_values']:
                        if value and value != 'none':
                            for cpe in value.split('|'):
                                cpe = cpe.strip()
                                if cpe:
                                    cpes[cpe] = cpes.get(cpe, 0) + count
                    stats['shodan_summary']['cpes'] = sorted(
                        cpes.items(), key=lambda x: x[1], reverse=True
                    )[:10]
                
                if name == 'lb_Vulns' or name == 'lb_InternetDB_Vulns' or name == 'lb_ShodanVulns':
                    vulns = {}
                    for value, count in col['top_values']:
                        if value and value != 'none':
                            for vuln in value.split('|'):
                                vuln = vuln.strip()
                                if vuln:
                                    vulns[vuln] = vulns.get(vuln, 0) + count
                    stats['shodan_summary']['vulns'] = sorted(
                        vulns.items(), key=lambda x: x[1], reverse=True
                    )[:10]
                
                # Domain summary
                if name == 'lb_Domains' or name == 'lb_Domain':
                    domains = {}
                    for value, count in col['all_values']:
                        if value and value != 'none':
                            for domain in value.split('|'):
                                domain = domain.strip()
                                if domain:
                                    domains[domain] = domains.get(domain, 0) + count
                    stats['dns_summary']['domains'] = sorted(
                        domains.items(), key=lambda x: x[1], reverse=True
                    )[:10]
                    stats['dns_summary']['all_domains'] = sorted(
                        domains.items(), key=lambda x: x[1], reverse=True
                    )
                
                # TLD summary
                if name == 'lb_TLD' or name == 'lb_TopLevelDomain':
                    stats['dns_summary']['tlds'] = col['top_values']
                    stats['dns_summary']['all_tlds'] = col['all_values']
                
                # WhoIS NETNAME
                if name == 'lb_NetName' or name == 'lb_IPWhoIsNetName' or name == 'lb_WhoIsNetName':
                    stats['whois_summary']['netnames'] = col['top_values']
                    stats['whois_summary']['all_netnames'] = col['all_values']
                
                # Store all values for whois orgs
                if name == 'lb_IPWhoIsOrg' or name == 'lb_WhoIs_OrgName' or name == 'lb_WhoIsOrg':
                    stats['whois_summary']['orgs'] = col['top_values']
                    stats['whois_summary']['all_orgs'] = col['all_values']
            
            # Count IPs with threat indicators
            threat_col = next((c for c in stats['columns'] if c['name'] == 'lb_ThreatCategories'), None)
            if threat_col:
                threat_count = sum(1 for v, c in threat_col['top_values'] if v and v != 'none')
                stats['enrichment_summary']['ips_with_threats'] = stats['total_rows'] - threat_col['empty_count']
                stats['enrichment_summary']['clean_ips'] = threat_col['empty_count']
            
            # Count IPs with Shodan data
            ports_col = next((c for c in stats['columns'] if c['name'] in ['lb_Ports', 'lb_InternetDB_Ports', 'lb_ShodanPorts']), None)
            if ports_col:
                stats['shodan_summary']['ips_with_data'] = stats['total_rows'] - ports_col['empty_count']
            
            # Count IPs with DNS data
            dns_col = next((c for c in stats['columns'] if c['name'] in ['lb_ReverseDNS', 'lb_DNS', 'lb_PTR']), None)
            if dns_col:
                stats['dns_summary']['ips_with_dns'] = stats['total_rows'] - dns_col['empty_count']
            
            # Count IPs with WhoIS data
            whois_col = next((c for c in stats['columns'] if c['name'] in ['lb_IPWhoIsOrg', 'lb_WhoIs_OrgName', 'lb_WhoIsOrg']), None)
            if whois_col:
                stats['whois_summary']['ips_with_whois'] = stats['total_rows'] - whois_col['empty_count']
    
    except Exception as e:
        stats['error'] = str(e)
    
    return stats


def get_unique_column_values(filepath: Path, column_name: str, limit: int = 100) -> list:
    """Get unique values for a column with their counts."""
    values = {}
    
    try:
        with open(filepath, 'r', newline='', encoding='utf-8', errors='replace') as f:
            reader = csv.DictReader(f)
            for row in reader:
                raw_value = row.get(column_name)
                value = (raw_value or '').strip()
                if value:
                    values[value] = values.get(value, 0) + 1
        
        # Sort by count descending
        sorted_values = sorted(values.items(), key=lambda x: x[1], reverse=True)[:limit]
        return [{'value': v, 'count': c} for v, c in sorted_values]
    
    except Exception:
        return []


# ============================================
# Graph API Routes
# ============================================

from admin import (
    save_graph, load_graph, list_graphs, delete_graph,
    save_shared_results, get_shared_results, get_shared_results_expiry_days, clear_expired_shared_results,
    get_concurrency_settings,
    get_cached_shodan, set_cached_shodan, get_shodan_cache_settings,
    get_cached_shodan_pivot, set_cached_shodan_pivot,
    get_shodan_pivot_limit,
    get_circl_settings, get_cached_circl_pdns, set_cached_circl_pdns,
    get_hackertarget_settings, get_cached_hackertarget, set_cached_hackertarget,
    get_viewdns_settings, get_cached_viewdns, set_cached_viewdns,
    get_max_unique_values, get_max_adhoc_ips, get_large_file_warning_threshold
)


# ========== IOC Extraction ==========

# Domain regex pattern - matches valid domain names
DOMAIN_PATTERN = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
)

# Defanged domain pattern - matches common defanging styles
# Handles: [.] [dot] (.) (dot) {.} {dot} and variations
DEFANGED_DOMAIN_PATTERN = re.compile(
    r'\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)'  # First label
    r'(?:\s*[\[\(\{]\s*(?:\.|\s*dot\s*)\s*[\]\)\}]\s*'     # Defanged separator
    r'([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?))+',  # Subsequent labels
    re.IGNORECASE
)

# Pattern to find and refang defanged domains directly
DEFANG_SEPARATORS = re.compile(
    r'\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|'  # [.] (.) {.}
    r'\[\s*dot\s*\]|\(\s*dot\s*\)|\{\s*dot\s*\}|'  # [dot] (dot) {dot}
    r'\s+dot\s+',  # space dot space
    re.IGNORECASE
)

# Common false positive domains to exclude
IOC_DOMAIN_EXCLUSIONS = {
    'example.com', 'example.org', 'example.net',
    'localhost.localdomain', 'schema.org', 'w3.org',
    'googleapis.com', 'gstatic.com', 'google.com',
    'microsoft.com', 'windows.net', 'azure.com',
    'cloudflare.com', 'amazonaws.com', 'github.com',
    'jquery.com', 'bootstrapcdn.com', 'cdnjs.cloudflare.com',
    'fonts.googleapis.com', 'fonts.gstatic.com',
}

# File extensions that indicate a URL, not a domain IOC
URL_FILE_EXTENSIONS = {'.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.woff', '.woff2', '.ttf', '.eot'}

# File extensions that are also valid TLDs - these need context-based filtering
# These are valid country codes but commonly used as file extensions
FILE_EXTENSION_TLDS = {
    '.md',   # Moldova - but commonly Markdown files
    '.py',   # Paraguay - but commonly Python files  
    '.sh',   # Saint Helena - but commonly shell scripts
    '.pl',   # Poland - but commonly Perl files
    '.rs',   # Serbia - but commonly Rust files
    '.go',   # (not a TLD but common file extension)
    '.cc',   # Cocos Islands - but commonly C++ files
    '.ai',   # Anguilla - but commonly Adobe Illustrator files
    '.ps',   # Palestine - but commonly PostScript files
    '.pm',   # Saint Pierre - but commonly Perl modules
    '.so',   # Somalia - but commonly shared object files
    '.do',   # Dominican Republic - but commonly config files
    '.mo',   # Macau - but commonly gettext files
    '.nu',   # Niue - but commonly config files
    '.to',   # Tonga - but commonly config files  
    '.is',   # Iceland - but commonly config files
    '.as',   # American Samoa - but commonly ActionScript
    '.gg',   # Guernsey - but commonly game files
    '.fm',   # Micronesia - but commonly audio files
    '.am',   # Armenia - but commonly Makefile
    '.re',   # Réunion - but commonly config files
    '.la',   # Laos - but commonly libtool files
    '.in',   # India - but commonly Makefile.in files
}


def looks_like_filename(text):
    """Check if text looks like a filename rather than a domain."""
    if not text or '.' not in text:
        return False
    
    text_lower = text.lower()
    
    # Check for file extension TLDs
    for ext in FILE_EXTENSION_TLDS:
        if text_lower.endswith(ext):
            # Get the "name" part before the extension
            name = text_lower[:-len(ext)]
            
            # If name has no dots (single label), it's likely a file
            # e.g., "README.md" vs "sub.domain.md"
            if '.' not in name:
                # For ambiguous TLDs, single-label "domains" are almost always files
                # Real domains in these TLDs usually have subdomains or are well-known
                # e.g., "bit.ly" is real, but "script.py" is a file
                
                # Check for obvious filename patterns first
                original_name = text[:-len(ext)]
                if (original_name.isupper() or 
                    '_' in original_name or
                    '-' in original_name or
                    original_name.lower() in ('readme', 'license', 'changelog', 'makefile', 
                                               'dockerfile', 'vagrantfile', 'gemfile',
                                               'rakefile', 'procfile', 'setup', 'config',
                                               'index', 'main', 'app', 'test', 'spec',
                                               'skill', 'todo', 'notes', 'script',
                                               'build', 'run', 'start', 'init', 'install')):
                    return True
                
                # For single-label + ambiguous TLD, be conservative and treat as file
                # unless it's a very short name (2-3 chars) which might be a real domain
                # like "t.co" or "bit.ly" patterns
                if len(name) > 3:
                    return True
    
    return False

# Initialize tldextract with caching
try:
    import tldextract
    # Create extractor that uses PSL for validation
    TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=None)  # Use bundled PSL
    TLDEXTRACT_AVAILABLE = True
except ImportError:
    TLDEXTRACT_AVAILABLE = False
    TLD_EXTRACTOR = None

# Initialize iocextract for defanged IOC handling
try:
    import iocextract
    IOCEXTRACT_AVAILABLE = True
except ImportError:
    IOCEXTRACT_AVAILABLE = False


def is_valid_domain(domain):
    """Validate domain has a valid TLD using PSL via tldextract."""
    if not TLDEXTRACT_AVAILABLE or not TLD_EXTRACTOR:
        # Fallback: basic validation
        return '.' in domain and len(domain) >= 4
    
    try:
        extracted = TLD_EXTRACTOR(domain)
        # A valid domain must have both a suffix (TLD) and a domain part
        # suffix is the public suffix (e.g., 'com', 'co.uk')
        # domain is the registered domain name (e.g., 'google' in 'google.com')
        return bool(extracted.suffix and extracted.domain)
    except Exception:
        return False


def is_valid_public_ip(ip_str):
    """
    Validate that an IP address is a legitimate public (globally routable) IP.
    
    Filters out:
    - Private IPs (10.x.x.x, 172.16-31.x.x, 192.168.x.x)
    - Loopback (127.x.x.x)
    - Link-local (169.254.x.x)
    - Multicast (224.x.x.x - 239.x.x.x)
    - Reserved/Documentation (0.x.x.x, 192.0.2.x, 198.51.100.x, 203.0.113.x)
    - Broadcast (255.255.255.255)
    - Carrier-grade NAT (100.64.x.x - 100.127.x.x)
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        
        # Check if it's a global (public) IP
        # is_global returns True for addresses that are allocated for public networks
        if not ip.is_global:
            return False
        
        # Filter out multicast addresses (224.0.0.0 - 239.255.255.255)
        # is_global doesn't catch these
        if ip.is_multicast:
            return False
        
        # Additional check: filter out some edge cases is_global might miss
        # These are technically "global" but not useful as IOCs
        
        # Filter out 0.0.0.0/8 (current network)
        if ip_str.startswith('0.'):
            return False
        
        return True
        
    except (ValueError, TypeError):
        # Invalid IP address format
        return False


def refang_domain(text):
    """Refang a defanged domain string."""
    return DEFANG_SEPARATORS.sub('.', text).lower().strip()


def extract_defanged_domains_direct(text):
    """Extract defanged domains using direct regex (fallback for iocextract)."""
    domains = set()
    
    # Pattern to find sequences that look like defanged domains
    # e.g., "evil[.]com", "bad[.]domain[.]org"
    defang_pattern = re.compile(
        r'\b([a-zA-Z0-9][a-zA-Z0-9-]*'  # Start with alphanumeric
        r'(?:\s*[\[\(\{]\s*(?:\.|\s*dot\s*)\s*[\]\)\}]\s*'  # Defanged dot
        r'[a-zA-Z0-9][a-zA-Z0-9-]*)+)',  # More labels
        re.IGNORECASE
    )
    
    for match in defang_pattern.finditer(text):
        defanged = match.group(1)
        # Refang it
        domain = refang_domain(defanged)
        if domain and '.' in domain:
            domains.add(domain)
    
    return domains


def extract_domain_from_url(url):
    """Extract domain from a URL string."""
    # Remove protocol
    domain = url
    if '://' in domain:
        domain = domain.split('://', 1)[1]
    # Remove path
    if '/' in domain:
        domain = domain.split('/', 1)[0]
    # Remove port
    if ':' in domain:
        domain = domain.split(':', 1)[0]
    # Remove auth
    if '@' in domain:
        domain = domain.split('@', 1)[1]
    return domain.lower()


def extract_iocs_from_text(text):
    """Extract IPs and domains from text, with deduplication, PSL validation, and defang support."""
    ips = set()
    domains = set()
    
    # First, try to extract defanged IOCs using iocextract
    if IOCEXTRACT_AVAILABLE:
        # Extract and refang IPs (handles formats like 192[.]168[.]1[.]1)
        for ip in iocextract.extract_ipv4s(text, refang=True):
            ips.add(ip)
        
        # Extract and refang URLs, then get domains from them
        # This handles formats like hxxp://evil[.]com/path
        for url in iocextract.extract_urls(text, refang=True):
            domain = extract_domain_from_url(url)
            if domain and '.' in domain:
                # Skip if it's an IP
                if not IP_PATTERN.match(domain):
                    domains.add(domain)
    
    # Also extract defanged domains directly using our regex (as fallback)
    # This catches cases iocextract might miss
    defanged_domains = extract_defanged_domains_direct(text)
    domains.update(defanged_domains)
    
    # Also use standard regex extraction for non-defanged IOCs
    # (iocextract might miss some edge cases)
    
    # Extract IPs
    for match in IP_PATTERN.finditer(text):
        ips.add(match.group())
    
    # Extract domains
    for match in DOMAIN_PATTERN.finditer(text):
        domain = match.group().lower()
        
        # Skip if it looks like a file path or has common file extensions
        if any(domain.endswith(ext) for ext in URL_FILE_EXTENSIONS):
            continue
        
        # Skip if it's actually an IP (the domain pattern can match some IP-like strings)
        if IP_PATTERN.match(domain):
            continue
        
        domains.add(domain)
    
    # Validate and filter IPs - only keep public, globally routable addresses
    valid_ips = set()
    for ip in ips:
        if is_valid_public_ip(ip):
            valid_ips.add(ip)
    
    # Validate and filter domains
    valid_domains = set()
    for domain in domains:
        # Skip common false positives
        if domain in IOC_DOMAIN_EXCLUSIONS:
            continue
        
        # Skip very short domains (likely false positives)
        if len(domain) < 4 or '.' not in domain:
            continue
        
        # Skip if it looks like a filename (e.g., README.md, script.py)
        if looks_like_filename(domain):
            continue
        
        # Validate domain has a valid TLD using PSL
        if not is_valid_domain(domain):
            continue
        
        valid_domains.add(domain)
    
    return list(valid_ips), list(valid_domains)


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
        data = request.get_json()
        url = data.get('url', '').strip()
        text = data.get('text', '').strip()
        
        if url:
            try:
                text_content = fetch_url_content(url)
                source = 'url'
            except requests.exceptions.RequestException as e:
                return jsonify({'error': f'Failed to fetch URL: {str(e)}'}), 400
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
                    return jsonify({'error': f'Failed to read file: {str(e)}'}), 400
    
    # Check for form data text
    elif request.form.get('text'):
        text_content = request.form.get('text', '')
        source = 'text'
    
    if not text_content:
        return jsonify({'error': 'No content provided. Send URL, text, or upload a file.'}), 400
    
    # Extract IOCs
    ips, domains = extract_iocs_from_text(text_content)
    
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


@app.route('/api/graph/related', methods=['POST'])
@login_required
def api_graph_related():
    """Find related IPs/domains from current dataset."""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400
    
    value = data.get('value', '').strip()
    value_type = data.get('type', 'ip')  # 'ip' or 'domain'
    
    related = {
        'ips': [],
        'domains': [],
        'tlds': [],
        'asns': [],
        'countries': [],
        'geo_data': {},  # IP -> {asn, asn_name, asn_org, country, city}
        'sources': {}
    }
    
    output_file = session.get('current_output')
    if not output_file or not Path(output_file).exists():
        # Return empty results if no enrichment data available
        return jsonify(related)
    
    try:
        with open(output_file, 'r', newline='', encoding='utf-8', errors='replace') as f:
            reader = csv.DictReader(f)
            headers = reader.fieldnames or []
            
            # Find relevant columns
            ip_col = next((h for h in headers if h.lower() in ('ip', 'ip_address', 'ipaddress', 'src_ip', 'dst_ip', 'lb_ip')), None)
            domain_cols = [h for h in headers if h in ('lb_Domains', 'LB_Domains', 'lb_IDB_HOSTNAMES', 'LB_IDB_HOSTNAMES', 'lb_IDB_hostnames')]
            tld_col = next((h for h in headers if h in ('lb_TLD', 'LB_TLD')), None)
            
            # Geo columns - LogBoost standard column names
            # ASN columns - lb_ASN has name only, lb_ASN_Number has the number only
            asn_name_col = next((h for h in headers if h == 'lb_ASN'), None)
            asn_num_col = next((h for h in headers if h == 'lb_ASN_Number'), None)
            
            country_col = next((h for h in headers if h == 'lb_Country'), None)
            if not country_col:
                country_col = next((h for h in headers if 'country' in h.lower() and h.startswith('lb_') and 'whois' not in h.lower()), None)
            
            city_col = next((h for h in headers if h == 'lb_City'), None)
            if not city_col:
                city_col = next((h for h in headers if 'city' in h.lower() and h.startswith('lb_')), None)
            
            # For org, prefer IPWhois_Organization for IP lookups
            org_col = next((h for h in headers if h == 'lb_IPWhois_Organization'), None)
            if not org_col:
                org_col = next((h for h in headers if h in ('lb_Org', 'lb_ISP')), None)
            
            for row in reader:
                row_ip = row.get(ip_col, '') if ip_col else ''
                
                # Collect domains from all domain columns
                row_domains = set()
                for dc in domain_cols:
                    val = row.get(dc, '')
                    if val:
                        for d in val.split('|'):
                            d = d.strip()
                            if d:
                                row_domains.add(d)
                
                row_tld = row.get(tld_col, '') if tld_col else ''
                
                # Geo data - lb_ASN = name, lb_ASN_Number = number
                row_asn_name = row.get(asn_name_col, '').strip() if asn_name_col else ''
                row_asn_num = row.get(asn_num_col, '').strip() if asn_num_col else ''
                row_country = row.get(country_col, '') if country_col else ''
                row_city = row.get(city_col, '') if city_col else ''
                row_org = row.get(org_col, '') if org_col else ''
                
                if value_type == 'ip':
                    # Looking for IP - find its domains and geo data
                    if row_ip.lower() == value.lower():
                        for d in row_domains:
                            if d not in related['domains']:
                                related['domains'].append(d)
                                related['sources'][d] = 'enrichment'
                        if row_tld and row_tld not in related['tlds']:
                            related['tlds'].append(row_tld)
                            related['sources'][row_tld] = 'enrichment'
                        
                        # Add geo data for this IP
                        if row_asn_name or row_asn_num or row_country:
                            geo_info = {}
                            
                            # Build ASN from lb_ASN (name) and lb_ASN_Number (number)
                            if row_asn_num:
                                asn_id = f"AS{row_asn_num}"
                                geo_info['asn_id'] = asn_id
                                geo_info['asn_name'] = row_asn_name
                                # Full ASN string for display
                                full_asn = f"{asn_id} {row_asn_name}".strip() if row_asn_name else asn_id
                                geo_info['asn'] = full_asn
                                if full_asn not in related['asns']:
                                    related['asns'].append(full_asn)
                                    related['sources'][full_asn] = 'enrichment'
                            elif row_asn_name:
                                # Only have name, no number (shouldn't happen but handle it)
                                geo_info['asn_name'] = row_asn_name
                                geo_info['asn'] = row_asn_name
                                if row_asn_name not in related['asns']:
                                    related['asns'].append(row_asn_name)
                                    related['sources'][row_asn_name] = 'enrichment'
                            
                            if row_country:
                                geo_info['country'] = row_country
                                if row_country not in related['countries']:
                                    related['countries'].append(row_country)
                                    related['sources'][row_country] = 'enrichment'
                            if row_city:
                                geo_info['city'] = row_city
                            if row_org:
                                geo_info['org'] = row_org
                            related['geo_data'][row_ip] = geo_info
                else:
                    # Looking for domain - find IPs that have this domain
                    value_lower = value.lower()
                    # Check if the value matches any domain in this row (exact match in pipe-separated list)
                    for d in row_domains:
                        if d.lower() == value_lower:
                            if row_ip and row_ip not in related['ips']:
                                related['ips'].append(row_ip)
                                related['sources'][row_ip] = 'enrichment'
                                
                                # Add geo data for discovered IPs
                                if row_asn_name or row_asn_num or row_country:
                                    geo_info = {}
                                    
                                    # Build ASN from lb_ASN (name) and lb_ASN_Number (number)
                                    if row_asn_num:
                                        asn_id = f"AS{row_asn_num}"
                                        geo_info['asn_id'] = asn_id
                                        geo_info['asn_name'] = row_asn_name
                                        full_asn = f"{asn_id} {row_asn_name}".strip() if row_asn_name else asn_id
                                        geo_info['asn'] = full_asn
                                        if full_asn not in related['asns']:
                                            related['asns'].append(full_asn)
                                            related['sources'][full_asn] = 'enrichment'
                                    elif row_asn_name:
                                        geo_info['asn_name'] = row_asn_name
                                        geo_info['asn'] = row_asn_name
                                        if row_asn_name not in related['asns']:
                                            related['asns'].append(row_asn_name)
                                            related['sources'][row_asn_name] = 'enrichment'
                                    
                                    if row_country:
                                        geo_info['country'] = row_country
                                        if row_country not in related['countries']:
                                            related['countries'].append(row_country)
                                            related['sources'][row_country] = 'enrichment'
                                    if row_city:
                                        geo_info['city'] = row_city
                                    if row_org:
                                        geo_info['org'] = row_org
                                    related['geo_data'][row_ip] = geo_info
                                    
                            # Also add other domains from this row as related
                            for other_d in row_domains:
                                if other_d.lower() != value_lower and other_d not in related['domains']:
                                    related['domains'].append(other_d)
                                    related['sources'][other_d] = 'enrichment'
                            # Add TLD if present
                            if row_tld and row_tld not in related['tlds']:
                                related['tlds'].append(row_tld)
                                related['sources'][row_tld] = 'enrichment'
                            break
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
    return jsonify(related)


@app.route('/api/graph/enrich', methods=['POST'])
@login_required
def api_graph_enrich():
    """Enrich IPs on-demand using LogBoost for the graph feature."""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400
    
    ips = data.get('ips', [])
    if not ips:
        return jsonify({'error': 'No IPs provided'}), 400
    
    # Get or create session directories
    session_id = session.get('session_id')
    if not session_id:
        session_id = str(uuid.uuid4())
        session['session_id'] = session_id
    
    session_upload, session_output = get_session_dir(session_id)
    
    # Clean previous results in these directories
    for f in session_upload.iterdir():
        f.unlink()
    for f in session_output.iterdir():
        f.unlink()
    
    # Create a simple CSV with just IP addresses
    input_file = session_upload / 'graph_ips.csv'
    with open(input_file, 'w', newline='', encoding='utf-8') as f:
        f.write('ip\n')
        for ip in ips:
            f.write(f'{ip}\n')
    
    # Build LogBoost command - MaxMind geo enrichment only (fast)
    # IDB (ports/tags) is done separately via /api/graph/enrich-idb
    options = {
        'dbdir': MAXMIND_DIR,
        'ipcol': 'ip'
    }
    
    cmd = build_logboost_command(str(session_upload), str(session_output), options)
    success, stdout, stderr = run_logboost(cmd)
    
    if not success:
        return jsonify({'error': stderr or 'LogBoost execution failed', 'command': ' '.join(cmd)}), 500
    
    # Find output file
    output_files = list(session_output.glob('*.csv'))
    if not output_files:
        return jsonify({'error': 'No output file generated'}), 500
    
    output_file = output_files[0]
    session['current_output'] = str(output_file)
    
    # Now read the enriched data and return geo info
    geo_data = {}
    
    try:
        with open(output_file, 'r', newline='', encoding='utf-8', errors='replace') as f:
            reader = csv.DictReader(f)
            headers = reader.fieldnames or []
            
            # Find relevant columns
            ip_col = next((h for h in headers if h.lower() in ('ip', 'ip_address', 'ipaddress', 'src_ip', 'dst_ip', 'lb_ip')), None)
            
            # ASN columns - lb_ASN has name, lb_ASN_Number has the number
            asn_name_col = next((h for h in headers if h == 'lb_ASN'), None)
            asn_num_col = next((h for h in headers if h == 'lb_ASN_Number'), None)
            
            country_col = next((h for h in headers if h == 'lb_Country'), None)
            if not country_col:
                country_col = next((h for h in headers if 'country' in h.lower() and h.startswith('lb_') and 'whois' not in h.lower()), None)
            city_col = next((h for h in headers if h == 'lb_City'), None)
            org_col = next((h for h in headers if h == 'lb_IPWhois_Organization'), None)
            
            for row in reader:
                row_ip = row.get(ip_col, '') if ip_col else ''
                if row_ip:
                    row_asn_name = row.get(asn_name_col, '').strip() if asn_name_col else ''
                    row_asn_num = row.get(asn_num_col, '').strip() if asn_num_col else ''
                    row_country = row.get(country_col, '') if country_col else ''
                    row_city = row.get(city_col, '') if city_col else ''
                    row_org = row.get(org_col, '') if org_col else ''
                    
                    if row_asn_name or row_asn_num or row_country:
                        geo_info = {'ip': row_ip}
                        
                        # Build ASN info from lb_ASN (name) and lb_ASN_Number (number)
                        if row_asn_num:
                            asn_id = f"AS{row_asn_num}"
                            geo_info['asn_id'] = asn_id
                            geo_info['asn_name'] = row_asn_name
                            # Full ASN string for display
                            geo_info['asn'] = f"{asn_id} {row_asn_name}".strip() if row_asn_name else asn_id
                        elif row_asn_name:
                            # Only have name, no number
                            geo_info['asn_name'] = row_asn_name
                            geo_info['asn'] = row_asn_name
                        
                        if row_country:
                            geo_info['country'] = row_country
                        if row_city:
                            geo_info['city'] = row_city
                        if row_org:
                            geo_info['org'] = row_org
                        
                        geo_data[row_ip] = geo_info
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
    return jsonify({
        'geo_data': geo_data,
        'enriched_count': len(geo_data),
        'total_ips': len(ips),
        'output_file': str(output_file)
    })


@app.route('/api/graph/enrich-idb', methods=['POST'])
@login_required
def api_graph_enrich_idb():
    """Enrich IPs with Shodan InternetDB data (ports and tags) via LogBoost."""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400
    
    ips = data.get('ips', [])
    if not ips:
        return jsonify({'error': 'No IPs provided'}), 400
    
    # Get or create session directories
    session_id = session.get('session_id')
    if not session_id:
        session_id = str(uuid.uuid4())
        session['session_id'] = session_id
    
    session_upload, session_output = get_session_dir(session_id)
    
    # Clean previous results in these directories
    for f in session_upload.iterdir():
        f.unlink()
    for f in session_output.iterdir():
        f.unlink()
    
    # Create a simple CSV with just IP addresses
    input_file = session_upload / 'graph_ips_idb.csv'
    with open(input_file, 'w', newline='', encoding='utf-8') as f:
        f.write('ip\n')
        for ip in ips:
            f.write(f'{ip}\n')
    
    # Build LogBoost command with IDB option
    options = {
        'ipcol': 'ip',
        'idb': True  # Enable Shodan InternetDB enrichment
    }
    
    cmd = build_logboost_command(str(session_upload), str(session_output), options)
    success, stdout, stderr = run_logboost(cmd)
    
    if not success:
        return jsonify({'error': stderr or 'LogBoost execution failed', 'command': ' '.join(cmd)}), 500
    
    # Find output file
    output_files = list(session_output.glob('*.csv'))
    if not output_files:
        return jsonify({'error': 'No output file generated'}), 500
    
    output_file = output_files[0]
    
    # Read the enriched data and return ports/tags
    idb_data = {}
    
    try:
        with open(output_file, 'r', newline='', encoding='utf-8', errors='replace') as f:
            reader = csv.DictReader(f)
            headers = reader.fieldnames or []
            
            # Find relevant columns
            ip_col = next((h for h in headers if h.lower() in ('ip', 'ip_address', 'ipaddress', 'src_ip', 'dst_ip', 'lb_ip')), None)
            
            # Shodan IDB columns for ports and tags
            ports_col = next((h for h in headers if h.lower() in ('lb_idb_ports', 'lb_idb_port')), None)
            tags_col = next((h for h in headers if h.lower() in ('lb_idb_tags', 'lb_idb_tag')), None)
            
            for row in reader:
                row_ip = row.get(ip_col, '') if ip_col else ''
                if row_ip:
                    row_ports = row.get(ports_col, '').strip() if ports_col else ''
                    row_tags = row.get(tags_col, '').strip() if tags_col else ''
                    
                    idb_info = {'ip': row_ip}
                    
                    # Parse ports (pipe-separated), skip 'err' values
                    if row_ports and row_ports.lower() != 'err':
                        ports = [p.strip() for p in row_ports.split('|') if p.strip() and p.strip().lower() != 'err']
                        if ports:
                            idb_info['ports'] = ports
                    
                    # Parse tags (pipe-separated), skip 'err' values
                    if row_tags and row_tags.lower() != 'err':
                        tags = [t.strip() for t in row_tags.split('|') if t.strip() and t.strip().lower() != 'err']
                        if tags:
                            idb_info['tags'] = tags
                    
                    # Only add if we got ports or tags
                    if 'ports' in idb_info or 'tags' in idb_info:
                        idb_data[row_ip] = idb_info
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
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
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400
    
    ips = data.get('ips', [])
    if not ips:
        return jsonify({'geo_data': {}, 'debug': {'reason': 'no_ips_provided'}})
    
    output_file = session.get('current_output')
    if not output_file or not Path(output_file).exists():
        # Return empty results if no enrichment data available
        return jsonify({'geo_data': {}, 'debug': {'reason': 'no_output_file', 'output_file': output_file}})
    
    geo_data = {}
    debug_info = {
        'requested_ips': ips,
        'output_file': output_file
    }
    
    # Create a mapping from lowercase IP to original IP for matching
    ip_map = {ip.lower(): ip for ip in ips}
    ip_set = set(ip_map.keys())
    
    try:
        with open(output_file, 'r', newline='', encoding='utf-8', errors='replace') as f:
            reader = csv.DictReader(f)
            headers = reader.fieldnames or []
            
            # Find relevant columns
            ip_col = next((h for h in headers if h.lower() in ('ip', 'ip_address', 'ipaddress', 'src_ip', 'dst_ip', 'lb_ip')), None)
            
            # Geo columns - LogBoost standard column names
            # ASN columns - lb_ASN has name only, lb_ASN_Number has the number only
            asn_name_col = next((h for h in headers if h == 'lb_ASN'), None)
            asn_num_col = next((h for h in headers if h == 'lb_ASN_Number'), None)
            
            country_col = next((h for h in headers if h == 'lb_Country'), None)
            if not country_col:
                country_col = next((h for h in headers if 'country' in h.lower() and h.startswith('lb_') and 'whois' not in h.lower()), None)
            
            city_col = next((h for h in headers if h == 'lb_City'), None)
            if not city_col:
                city_col = next((h for h in headers if 'city' in h.lower() and h.startswith('lb_')), None)
            
            # For org, prefer IPWhois_Organization for IP lookups
            org_col = next((h for h in headers if h == 'lb_IPWhois_Organization'), None)
            if not org_col:
                org_col = next((h for h in headers if h in ('lb_Org', 'lb_ISP')), None)
            
            debug_info['columns'] = {
                'ip_col': ip_col,
                'asn_name_col': asn_name_col,
                'asn_num_col': asn_num_col,
                'country_col': country_col,
                'city_col': city_col,
                'org_col': org_col,
                'all_headers': headers[:20]  # First 20 headers for debug
            }
            
            if not ip_col:
                debug_info['error'] = 'no_ip_column_found'
                return jsonify({'geo_data': {}, 'debug': debug_info})
            
            # Sample some IPs from the file to see what's there
            sample_ips = []
            matched_count = 0
            for i, row in enumerate(reader):
                row_ip = row.get(ip_col, '')
                row_ip_lower = row_ip.lower()
                
                if i < 5:
                    sample_ips.append({
                        'ip': row_ip,
                        'asn_name': row.get(asn_name_col, '') if asn_name_col else '',
                        'asn_num': row.get(asn_num_col, '') if asn_num_col else '',
                        'country': row.get(country_col, '') if country_col else ''
                    })
                
                # Check if this IP is one we're looking for (case-insensitive)
                if row_ip_lower in ip_set:
                    matched_count += 1
                    # Use the original IP from the request as the key
                    original_ip = ip_map[row_ip_lower]
                    
                    if original_ip not in geo_data:
                        row_asn_name = row.get(asn_name_col, '').strip() if asn_name_col else ''
                        row_asn_num = row.get(asn_num_col, '').strip() if asn_num_col else ''
                        row_country = row.get(country_col, '') if country_col else ''
                        row_city = row.get(city_col, '') if city_col else ''
                        row_org = row.get(org_col, '') if org_col else ''
                        
                        if row_asn_name or row_asn_num or row_country:
                            geo_info = {'ip': original_ip}
                            
                            # Build ASN from lb_ASN (name) and lb_ASN_Number (number)
                            if row_asn_num:
                                asn_id = f"AS{row_asn_num}"
                                geo_info['asn_id'] = asn_id
                                geo_info['asn_name'] = row_asn_name
                                geo_info['asn'] = f"{asn_id} {row_asn_name}".strip() if row_asn_name else asn_id
                            elif row_asn_name:
                                geo_info['asn_name'] = row_asn_name
                                geo_info['asn'] = row_asn_name
                            
                            if row_country:
                                geo_info['country'] = row_country
                            if row_city:
                                geo_info['city'] = row_city
                            if row_org:
                                geo_info['org'] = row_org
                            geo_data[original_ip] = geo_info
            
            debug_info['sample_ips_from_file'] = sample_ips
            debug_info['matched_count'] = matched_count
            debug_info['geo_data_count'] = len(geo_data)
    
    except Exception as e:
        return jsonify({'error': str(e), 'debug': debug_info}), 500
    
    return jsonify({'geo_data': geo_data, 'debug': debug_info})


@app.route('/api/graph/debug-columns', methods=['GET'])
@login_required
def api_graph_debug_columns():
    """Debug endpoint to show available columns in current output file."""
    output_file = session.get('current_output')
    if not output_file or not Path(output_file).exists():
        return jsonify({'error': 'No enrichment data available', 'output_file': output_file})
    
    try:
        with open(output_file, 'r', newline='', encoding='utf-8', errors='replace') as f:
            reader = csv.DictReader(f)
            headers = reader.fieldnames or []
            
            # Find all lb_ columns
            lb_columns = [h for h in headers if h.startswith('lb_')]
            
            # Find specific geo columns - LogBoost standard column names
            ip_col = next((h for h in headers if h.lower() in ('ip', 'ip_address', 'ipaddress', 'src_ip', 'dst_ip', 'lb_ip')), None)
            
            asn_col = next((h for h in headers if h in ('lb_ASN', 'lb_ASN_Number')), None)
            if not asn_col:
                asn_col = next((h for h in headers if 'asn' in h.lower() and h.startswith('lb_')), None)
            
            country_col = next((h for h in headers if h == 'lb_Country'), None)
            if not country_col:
                country_col = next((h for h in headers if 'country' in h.lower() and h.startswith('lb_') and 'whois' not in h.lower()), None)
            
            city_col = next((h for h in headers if h == 'lb_City'), None)
            if not city_col:
                city_col = next((h for h in headers if 'city' in h.lower() and h.startswith('lb_')), None)
            
            org_col = next((h for h in headers if h == 'lb_IPWhois_Organization'), None)
            if not org_col:
                org_col = next((h for h in headers if h in ('lb_Org', 'lb_ISP')), None)
            
            # Get sample data from first row
            sample_data = {}
            for row in reader:
                if ip_col:
                    sample_data['ip'] = row.get(ip_col, '')
                if asn_col:
                    sample_data['asn'] = row.get(asn_col, '')
                if country_col:
                    sample_data['country'] = row.get(country_col, '')
                if city_col:
                    sample_data['city'] = row.get(city_col, '')
                if org_col:
                    sample_data['org'] = row.get(org_col, '')
                break
            
            return jsonify({
                'output_file': output_file,
                'total_columns': len(headers),
                'all_columns': headers,
                'lb_columns': lb_columns,
                'detected': {
                    'ip_col': ip_col,
                    'asn_col': asn_col,
                    'country_col': country_col,
                    'city_col': city_col,
                    'org_col': org_col
                },
                'sample_data': sample_data
            })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/graph/save', methods=['POST'])
@login_required
def api_graph_save():
    """Save a graph. Creates new graph if user doesn't own the existing one."""
    data = request.get_json()
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
    """Load a graph by ID. Anyone with the ID can load it."""
    graph = load_graph(graph_id)
    if graph:
        user_id = session.get('user_id')
        graph['is_owner'] = (graph.get('user_id') == user_id) or (graph.get('user_id') is None)
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
    """Export graph as JSON."""
    graph = load_graph(graph_id)
    if not graph:
        return jsonify({'error': 'Graph not found'}), 404
    
    response = jsonify(graph)
    response.headers['Content-Disposition'] = f'attachment; filename=graph_{graph_id}.json'
    return response


# ============================================
# Shared Results Endpoints
# ============================================

@app.route('/api/results/share', methods=['POST'])
@login_required
def api_results_share():
    """Create a shareable link for current results."""
    import uuid
    
    # Get current results from session
    output_file = session.get('current_output')
    if not output_file or not Path(output_file).exists():
        return jsonify({'error': 'No results to share'}), 400
    
    # Read the results data - use csv.reader to get list of lists (matching read_csv_all format)
    try:
        with open(output_file, 'r', newline='', encoding='utf-8', errors='replace') as f:
            reader = csv.reader(f)
            headers = next(reader, [])
            results_data = list(reader)
    except Exception as e:
        return jsonify({'error': f'Failed to read results: {str(e)}'}), 500
    
    if not results_data:
        return jsonify({'error': 'No data in results'}), 400
    
    # Get stats if available
    stats_data = session.get('current_stats')
    
    # Get filename
    filename = Path(output_file).name
    
    # Generate share ID
    share_id = str(uuid.uuid4())[:12]  # Shorter ID for URLs
    
    # Get expiry days from settings
    expiry_days = get_shared_results_expiry_days()
    
    # Save to database
    user_id = session.get('user_id')
    save_shared_results(share_id, user_id, filename, results_data, stats_data, headers, expiry_days)
    
    # Build share URL
    share_url = url_for('view_shared_results', share_id=share_id, _external=True)
    
    return jsonify({
        'success': True,
        'share_id': share_id,
        'share_url': share_url,
        'expires_in_days': expiry_days
    })


@app.route('/shared/results/<share_id>')
def view_shared_results(share_id):
    """View shared results page."""
    shared = get_shared_results(share_id)
    if not shared:
        # Log failed access attempt
        log_audit('shared_results_access', 'shared_results', share_id, {
            'action': 'view',
            'success': False,
            'reason': 'not_found_or_expired'
        })
        return render_template('index.html', error='Shared results not found or expired'), 404
    
    # Log successful access
    log_audit('shared_results_access', 'shared_results', share_id, {
        'action': 'view',
        'success': True,
        'owner_user_id': shared.get('user_id'),
        'filename': shared.get('filename'),
        'row_count': len(shared.get('results_data', []))
    })
    
    # Redirect to main page with shared results context
    return redirect(url_for('index', shared=share_id))


@app.route('/api/shared/results/<share_id>', methods=['GET'])
def api_shared_results(share_id):
    """Get shared results data."""
    shared = get_shared_results(share_id)
    if not shared:
        # Log failed access attempt
        log_audit('shared_results_access', 'shared_results', share_id, {
            'action': 'api_fetch',
            'success': False,
            'reason': 'not_found_or_expired'
        })
        return jsonify({'error': 'Shared results not found or expired'}), 404
    
    # Log successful access
    log_audit('shared_results_access', 'shared_results', share_id, {
        'action': 'api_fetch',
        'success': True,
        'owner_user_id': shared.get('user_id'),
        'filename': shared.get('filename'),
        'row_count': len(shared.get('results_data', []))
    })
    
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
def api_shared_results_render(share_id):
    """Render shared results as HTML partial."""
    shared = get_shared_results(share_id)
    if not shared:
        # Log failed access attempt
        log_audit('shared_results_access', 'shared_results', share_id, {
            'action': 'render',
            'success': False,
            'reason': 'not_found_or_expired'
        })
        return render_template('partials/error.html', error='Shared results not found or expired'), 404
    
    # Log successful access
    log_audit('shared_results_access', 'shared_results', share_id, {
        'action': 'render',
        'success': True,
        'owner_user_id': shared.get('user_id'),
        'filename': shared.get('filename'),
        'row_count': len(shared.get('results_data', []))
    })
    
    # Prepare data for the results template
    headers = shared['headers'] or []
    results = shared['results_data'] or []
    stats = shared['stats_data'] or {}
    
    return render_template('partials/results.html',
                         headers=headers,
                         rows=results,
                         total_rows=len(results),
                         original_filename=shared['filename'],
                         ip_count=stats.get('total_ips') if stats else None,
                         stats=stats,
                         is_shared=True)


@app.route('/api/settings/concurrency', methods=['GET'])
@login_required
def api_get_concurrency_settings():
    """Get current concurrency settings."""
    settings = get_concurrency_settings()
    return jsonify(settings)


# ========== Shodan API Endpoints ==========

def get_shodan_api_key():
    """Get Shodan API key from admin settings."""
    from admin import get_db
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT value FROM settings WHERE key = 'shodan_api_key'")
    row = cursor.fetchone()
    return row[0] if row else None


@app.route('/api/shodan/resolve', methods=['POST'])
@login_required
def api_shodan_resolve():
    """Query Shodan for IP or domain and return full host data with caching."""
    if not SHODAN_AVAILABLE:
        return jsonify({'error': 'Shodan library not installed. Run: pip install shodan'}), 500
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400
    
    value = data.get('value', '').strip()
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
        return jsonify({'error': f'Shodan API error: {str(e)}'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        # Log after all paths
        log_audit('shodan_query', 'shodan', None, {'value_type': value_type, 'count': 1})


@app.route('/api/shodan/pivot-jarm', methods=['POST'])
@login_required
def api_shodan_pivot_jarm():
    """Pivot on a JARM fingerprint to find other hosts with the same fingerprint."""
    if not SHODAN_AVAILABLE:
        return jsonify({'error': 'Shodan library not installed. Run: pip install shodan'}), 500
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400
    
    jarm = data.get('jarm', '').strip()
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
        return jsonify({'error': f'Shodan API error: {str(e)}'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/shodan/pivot', methods=['POST'])
@login_required
def api_shodan_pivot():
    """Pivot on arbitrary Shodan query to find matching hosts."""
    if not SHODAN_AVAILABLE:
        return jsonify({'error': 'Shodan library not installed. Run: pip install shodan'}), 500
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400
    
    query = data.get('query', '').strip()
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
        app.logger.warning("[Shodan Pivot] API Error: %s", str(e))
        return jsonify({'error': f'Shodan API error: {str(e)}'}), 500
    except Exception as e:
        app.logger.error("[Shodan Pivot] Exception: %s", str(e))
        return jsonify({'error': str(e)}), 500


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
    url = f"https://www.circl.lu/pdns/query/{query_value}"
    
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
        raise Exception(f"CIRCL API request failed: {str(e)}")


@app.route('/api/circl/pdns', methods=['POST'])
@login_required
def api_circl_pdns():
    """Query CIRCL Passive DNS for an IP or domain."""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400
    
    query_value = data.get('value', '').strip().lower()
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
        
    except Exception as e:
        app.logger.warning("[CIRCL PDNS] Error: %s", str(e))
        return jsonify({'error': str(e)}), 500


@app.route('/api/circl/pdns/bulk', methods=['POST'])
@login_required
def api_circl_pdns_bulk():
    """Query CIRCL Passive DNS for multiple IPs/domains with rate limiting and concurrency control."""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400
    
    queries = data.get('queries', [])
    query_type = data.get('type', 'ip').lower()
    
    if not queries:
        return jsonify({'error': 'No queries provided'}), 400
    
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
            return query_value, None, str(e), False
    
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
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400
    
    query_value = data.get('value', '').strip().lower()
    
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
        url = f"https://api.hackertarget.com/findshareddns/?q={query_value}"
        if settings.get('api_key'):
            url += f"&apikey={settings['api_key']}"
        
        response = requests.get(url, timeout=30)
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
        app.logger.warning("[HackerTarget] Error: %s", str(e))
        return jsonify({'error': f'HackerTarget API request failed: {str(e)}'}), 500
    except Exception as e:
        app.logger.error("[HackerTarget] Exception: %s", str(e))
        return jsonify({'error': str(e)}), 500


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
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400
    
    query_value = data.get('value', '').strip().lower()
    
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
        url = f"https://api.viewdns.info/reversemx/?mx={query_value}&apikey={settings['api_key']}&output=json"
        response = requests.get(url, timeout=30)
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
        app.logger.warning("[ViewDNS] Error: %s", str(e))
        return jsonify({'error': f'ViewDNS API request failed: {str(e)}'}), 500
    except Exception as e:
        app.logger.error("[ViewDNS] Exception: %s", str(e))
        return jsonify({'error': str(e)}), 500


@app.route('/api/viewdns/reverse-ns', methods=['POST'])
@login_required
def api_viewdns_reverse_ns():
    """Query ViewDNS for domains using a specific nameserver."""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400
    
    query_value = data.get('value', '').strip().lower()
    
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
        url = f"https://api.viewdns.info/reversens/?ns={query_value}&apikey={settings['api_key']}&output=json"
        response = requests.get(url, timeout=30)
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
        app.logger.warning("[ViewDNS] Error: %s", str(e))
        return jsonify({'error': f'ViewDNS API request failed: {str(e)}'}), 500
    except Exception as e:
        app.logger.error("[ViewDNS] Exception: %s", str(e))
        return jsonify({'error': str(e)}), 500


@app.route('/api/viewdns/reverse-whois', methods=['POST'])
@login_required
def api_viewdns_reverse_whois():
    """Query ViewDNS for domains matching WHOIS data."""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400
    
    query_value = data.get('value', '').strip()
    
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
        # URL encode the query value for special characters (including @, spaces, etc)
        import urllib.parse
        # Use quote with safe='' to encode everything including @ symbol
        encoded_value = urllib.parse.quote(query_value, safe='')
        url = f"https://api.viewdns.info/reversewhois/?q={encoded_value}&apikey={settings['api_key']}&output=json"
        
        # Log URL with redacted API key (NEVER log the actual key)
        safe_url = url.replace(settings['api_key'], 'REDACTED')
        app.logger.debug("[ViewDNS] Request URL: %s", safe_url)
        
        response = requests.get(url, timeout=30)
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
        app.logger.warning("[ViewDNS] Error: %s", str(e))
        return jsonify({'error': f'ViewDNS API request failed: {str(e)}'}), 500
    except Exception as e:
        app.logger.error("[ViewDNS] Exception: %s", str(e), exc_info=True)
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() in ('true', '1', 'yes')
    app.run(debug=debug_mode, host='0.0.0.0', port=5001)
