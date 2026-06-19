"""
LogBoost Web UI - Admin Module
Handles authentication, scheduled tasks, and settings management
"""

import os
import io
import json
import sqlite3
import hashlib
import secrets
import subprocess
import threading
import time
import logging
import zipfile
import requests
from datetime import datetime, timedelta
from pathlib import Path
from flask import Blueprint, render_template, request, redirect, url_for, session, flash, jsonify
from auth import login_required, admin_required

# Get logger
logger = logging.getLogger(__name__)

# Blueprint for admin routes
admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

# Database path — configurable via LOGBOOST_DB_PATH env var
DB_PATH = Path(os.environ.get('LOGBOOST_DB_PATH', Path(__file__).parent / 'logboost_admin.db'))

# REMOVED - No default credentials (first-user setup flow instead)
# DEFAULT_ADMIN_USER = 'admin'
# DEFAULT_ADMIN_PASS = 'changeme'

# LogBoost binary path
LOGBOOST_BINARY = os.environ.get('LOGBOOST_PATH', 'LogBoost')

# Bundled LogBoost version (matches Dockerfile ARG LOGBOOST_VERSION)
BUNDLED_LOGBOOST_VERSION = "prod_1_5_0"
GITHUB_RELEASES_API = "https://api.github.com/repos/joeavanzato/LogBoost/releases/latest"

# User roles
ROLE_USER = 'user'
ROLE_ADMIN = 'admin'


# ============================================
# Database Functions
# ============================================

def get_db():
    """Get database connection."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def needs_setup() -> bool:
    """Check if initial setup is needed (no admin users exist)."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM users WHERE role = ?', (ROLE_ADMIN,))
    count = cursor.fetchone()[0]
    conn.close()
    return count == 0


def init_db():
    """Initialize the database schema."""
    conn = get_db()
    cursor = conn.cursor()
    
    # Users table (unified for all users)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Migrate from old admin_accounts table if it exists
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='admin_accounts'")
    if cursor.fetchone():
        # Check if users table is empty (fresh migration)
        cursor.execute('SELECT COUNT(*) FROM users')
        if cursor.fetchone()[0] == 0:
            # Migrate existing admin accounts to users table with admin role
            cursor.execute('''
                INSERT INTO users (id, username, password_hash, role, created_at, updated_at)
                SELECT id, username, password_hash, 'admin', created_at, updated_at 
                FROM admin_accounts
            ''')
            conn.commit()
        # Drop old table
        cursor.execute('DROP TABLE admin_accounts')
        conn.commit()
    
    # Scheduled tasks table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scheduled_tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_type TEXT UNIQUE NOT NULL,
            interval_hours INTEGER DEFAULT 24,
            enabled INTEGER DEFAULT 0,
            last_run TIMESTAMP,
            next_run TIMESTAMP,
            running INTEGER DEFAULT 0,
            running_since TIMESTAMP,
            runner_id TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Migration: Add running columns to scheduled_tasks if they don't exist
    cursor.execute("PRAGMA table_info(scheduled_tasks)")
    columns = [col[1] for col in cursor.fetchall()]
    if 'running' not in columns:
        cursor.execute('ALTER TABLE scheduled_tasks ADD COLUMN running INTEGER DEFAULT 0')
        cursor.execute('ALTER TABLE scheduled_tasks ADD COLUMN running_since TIMESTAMP')
        cursor.execute('ALTER TABLE scheduled_tasks ADD COLUMN runner_id TEXT')
        conn.commit()
    
    # Task history/logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS task_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_type TEXT NOT NULL,
            status TEXT NOT NULL,
            started_at TIMESTAMP NOT NULL,
            completed_at TIMESTAMP,
            output TEXT,
            error TEXT
        )
    ''')
    
    # Settings table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # DNS cache table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS dns_cache (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            query TEXT NOT NULL,
            record_type TEXT NOT NULL,
            results TEXT,
            resolved_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            UNIQUE(query, record_type)
        )
    ''')
    
    # WHOIS cache table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS whois_cache (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL UNIQUE,
            results TEXT,
            resolved_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL
        )
    ''')
    
    # Shodan cache table - uses composite unique on (query, query_type)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS shodan_cache (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            query TEXT NOT NULL,
            query_type TEXT NOT NULL,
            results TEXT,
            resolved_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            UNIQUE(query, query_type)
        )
    ''')
    
    # Migration: Fix shodan_cache if it has the old schema (UNIQUE only on query)
    # Check if the unique constraint is only on 'query' by looking at index info
    cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='shodan_cache'")
    result = cursor.fetchone()
    if result:
        schema_sql = result[0]
        # Old schema has 'query TEXT NOT NULL UNIQUE' without composite
        if 'query TEXT NOT NULL UNIQUE' in schema_sql and 'UNIQUE(query, query_type)' not in schema_sql:
            logger.info("Migrating shodan_cache to use composite unique constraint")
            # Create new table with correct schema
            cursor.execute('''
                CREATE TABLE shodan_cache_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    query TEXT NOT NULL,
                    query_type TEXT NOT NULL,
                    results TEXT,
                    resolved_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL,
                    UNIQUE(query, query_type)
                )
            ''')
            # Copy existing data
            cursor.execute('''
                INSERT OR IGNORE INTO shodan_cache_new (id, query, query_type, results, resolved_at, expires_at)
                SELECT id, query, query_type, results, resolved_at, expires_at FROM shodan_cache
            ''')
            # Swap tables
            cursor.execute('DROP TABLE shodan_cache')
            cursor.execute('ALTER TABLE shodan_cache_new RENAME TO shodan_cache')
            conn.commit()
            logger.info("shodan_cache migration complete")
    
    # Shodan pivot cache table (for JARM and other attribute searches)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS shodan_pivot_cache (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pivot_type TEXT NOT NULL,
            pivot_value TEXT NOT NULL,
            results TEXT,
            result_count INTEGER DEFAULT 0,
            resolved_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            UNIQUE(pivot_type, pivot_value)
        )
    ''')
    
    # CIRCL Passive DNS cache table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS circl_pdns_cache (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            query_value TEXT NOT NULL,
            query_type TEXT NOT NULL,
            results_json TEXT,
            result_count INTEGER DEFAULT 0,
            cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            UNIQUE(query_value, query_type)
        )
    ''')
    
    # HackerTarget cache table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS hackertarget_cache (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            query_value TEXT NOT NULL,
            query_type TEXT NOT NULL,
            results_json TEXT,
            result_count INTEGER DEFAULT 0,
            cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            UNIQUE(query_value, query_type)
        )
    ''')
    
    # ViewDNS cache table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS viewdns_cache (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            query_value TEXT NOT NULL,
            query_type TEXT NOT NULL,
            results_json TEXT,
            result_count INTEGER DEFAULT 0,
            cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            UNIQUE(query_value, query_type)
        )
    ''')
    
    # Chaos (ProjectDiscovery) subdomain cache table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS chaos_cache (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            results_json TEXT,
            subdomain_count INTEGER DEFAULT 0,
            cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            UNIQUE(domain)
        )
    ''')
    
    # Saved graphs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS saved_graphs (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            data TEXT NOT NULL,
            user_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    # Add user_id column to saved_graphs if it doesn't exist (migration)
    cursor.execute("PRAGMA table_info(saved_graphs)")
    columns = [col[1] for col in cursor.fetchall()]
    if 'user_id' not in columns:
        cursor.execute('ALTER TABLE saved_graphs ADD COLUMN user_id INTEGER')
    
    # Shared results table for sharing LogBoost enrichment results
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS shared_results (
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            filename TEXT,
            results_data TEXT NOT NULL,
            stats_data TEXT,
            headers TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    # Audit logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER,
            username TEXT,
            ip_address TEXT,
            user_agent TEXT,
            action TEXT NOT NULL,
            resource_type TEXT,
            resource_id TEXT,
            details TEXT,
            success INTEGER DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    # Create index on audit_logs for faster queries
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action)')
    
    conn.commit()

    # Create default task entries if none exist
    cursor.execute('SELECT COUNT(*) FROM scheduled_tasks')
    if cursor.fetchone()[0] == 0:
        tasks = [
            ('update_geo', 168, 0),  # Weekly by default
            ('update_ti', 24, 0),    # Daily by default
            ('backup', 24, 0),       # Daily by default
        ]
        cursor.executemany(
            'INSERT INTO scheduled_tasks (task_type, interval_hours, enabled) VALUES (?, ?, ?)',
            tasks
        )
        conn.commit()
    
    conn.close()


def hash_password(password: str) -> str:
    """Hash a password with salt."""
    salt = secrets.token_hex(16)
    hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return f"{salt}:{hash_obj.hex()}"


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password against its hash."""
    try:
        salt, hash_value = password_hash.split(':')
        hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return hash_obj.hex() == hash_value
    except Exception:
        return False


# ============================================
# Authentication
# ============================================
# Decorators imported from auth.py - single source of truth.
# Both decorators validate users against the database on every request,
# preventing stale session cookies from granting access after a DB wipe.
# from auth import login_required, admin_required  (imported at top of file)


@admin_bp.route('/login', methods=['GET', 'POST'])
def admin_login():
    """Redirect to main login page."""
    return redirect(url_for('auth_routes.login'))


@admin_bp.route('/logout')
def logout():
    """Logout and redirect to main login."""
    session.clear()
    return redirect(url_for('auth_routes.login'))


# ============================================
# Audit Logging
# ============================================

def log_audit(action, resource_type=None, resource_id=None, details=None, success=True, user_id=None, username=None):
    """
    Log an audit event to the database.
    
    Args:
        action: The action being performed (e.g., 'login', 'setting_modified', 'shodan_query')
        resource_type: Category of resource (e.g., 'graph', 'setting', 'intel_feed')
        resource_id: Specific resource identifier if applicable
        details: JSON-serializable dict with additional context
        success: Whether the action succeeded
        user_id: Override user_id (for failed logins with unknown user)
        username: Override username (for failed logins)
    """
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # Get user info from session if not provided
        if user_id is None:
            user_id = session.get('user_id')
        if username is None:
            username = session.get('username')
        
        # Get client IP address
        ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
        if ip_address and ',' in ip_address:
            ip_address = ip_address.split(',')[0].strip()
        
        # Get user agent
        user_agent = request.headers.get('User-Agent', '')[:500]  # Limit length
        
        # Serialize details to JSON if provided
        details_json = json.dumps(details) if details else None
        
        cursor.execute('''
            INSERT INTO audit_logs (user_id, username, ip_address, user_agent, action, resource_type, resource_id, details, success)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (user_id, username, ip_address, user_agent, action, resource_type, resource_id, details_json, 1 if success else 0))
        
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error("[Audit] Failed to log audit event: %s", e)


def get_audit_retention_days():
    """Get the audit log retention period in days."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT value FROM settings WHERE key = ?', ('audit_retention_days',))
    result = cursor.fetchone()
    conn.close()
    if result and result[0]:
        try:
            return int(result[0])
        except (ValueError, TypeError):
            pass
    return 90  # Default 90 days


def cleanup_old_audit_logs():
    """Delete audit logs older than the retention period."""
    try:
        retention_days = get_audit_retention_days()
        cutoff_date = datetime.now() - timedelta(days=retention_days)
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM audit_logs WHERE timestamp < ?', (cutoff_date.isoformat(),))
        deleted_count = cursor.rowcount
        conn.commit()
        conn.close()
        
        if deleted_count > 0:
            logger.info("[Audit] Cleaned up %d audit log entries older than %d days", deleted_count, retention_days)
        
        return deleted_count
    except Exception as e:
        logger.error("[Audit] Failed to cleanup old logs: %s", e)
        return 0


def get_audit_logs(limit=100, offset=0, action_filter=None, user_filter=None, start_date=None, end_date=None):
    """
    Retrieve audit logs with optional filtering.
    
    Returns tuple of (logs, total_count)
    """
    conn = get_db()
    cursor = conn.cursor()
    
    # Build query with filters
    where_clauses = []
    params = []
    
    if action_filter:
        where_clauses.append('action = ?')
        params.append(action_filter)
    
    if user_filter:
        where_clauses.append('(username LIKE ? OR ip_address LIKE ?)')
        params.extend([f'%{user_filter}%', f'%{user_filter}%'])
    
    if start_date:
        where_clauses.append('timestamp >= ?')
        params.append(start_date)
    
    if end_date:
        where_clauses.append('timestamp <= ?')
        params.append(end_date)
    
    where_sql = ' AND '.join(where_clauses) if where_clauses else '1=1'
    
    # Get total count
    cursor.execute(f'SELECT COUNT(*) FROM audit_logs WHERE {where_sql}', params)
    total_count = cursor.fetchone()[0]
    
    # Get paginated results
    cursor.execute(f'''
        SELECT * FROM audit_logs 
        WHERE {where_sql}
        ORDER BY timestamp DESC
        LIMIT ? OFFSET ?
    ''', params + [limit, offset])
    
    logs = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    # Parse details JSON
    for log in logs:
        if log.get('details'):
            try:
                log['details'] = json.loads(log['details'])
            except (json.JSONDecodeError, TypeError):
                pass
    
    return logs, total_count


def get_audit_action_types():
    """Get list of distinct action types in audit logs."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT DISTINCT action FROM audit_logs ORDER BY action')
    actions = [row[0] for row in cursor.fetchall()]
    conn.close()
    return actions


# ============================================
# Dashboard
# ============================================

@admin_bp.route('/')
@admin_bp.route('/dashboard')
@admin_required
def dashboard():
    """Admin dashboard."""
    conn = get_db()
    cursor = conn.cursor()
    
    # Get scheduled tasks
    cursor.execute('SELECT * FROM scheduled_tasks ORDER BY task_type')
    tasks = cursor.fetchall()
    
    # Get recent logs
    cursor.execute('''
        SELECT * FROM task_logs 
        ORDER BY started_at DESC 
        LIMIT 10
    ''')
    recent_logs = cursor.fetchall()
    
    # Get MaxMind API key status
    cursor.execute("SELECT value FROM settings WHERE key = 'maxmind_api_key'")
    maxmind_row = cursor.fetchone()
    maxmind_key_set = bool(maxmind_row and maxmind_row['value'])
    
    # Get Shodan API key status
    cursor.execute("SELECT value FROM settings WHERE key = 'shodan_api_key'")
    shodan_row = cursor.fetchone()
    shodan_key_set = bool(shodan_row and shodan_row['value'])
    
    # Get account count
    cursor.execute('SELECT COUNT(*) as count FROM users')
    account_count = cursor.fetchone()['count']

    conn.close()

    # Check if threat database exists
    threat_db_path = Path('/app/threats.db')
    if not threat_db_path.exists():
        threat_db_path = Path(os.environ.get('THREAT_DB_DIR', '.')) / 'threats.db'
    threat_db_missing = not threat_db_path.exists()

    return render_template('admin/dashboard.html',
                           tasks=tasks,
                           recent_logs=recent_logs,
                           maxmind_key_set=maxmind_key_set,
                           shodan_key_set=shodan_key_set,
                           account_count=account_count,
                           threat_db_missing=threat_db_missing)


# ============================================
# Account Management
# ============================================

@admin_bp.route('/accounts')
@admin_required
def accounts():
    """List all user accounts."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, role, created_at, updated_at FROM users ORDER BY role, username')
    accounts = cursor.fetchall()
    conn.close()
    return render_template('admin/accounts.html', accounts=accounts)


@admin_bp.route('/accounts/create', methods=['GET', 'POST'])
@admin_required
def create_account():
    """Create new user account."""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        role = request.form.get('role', ROLE_USER)
        
        # Validate role
        if role not in [ROLE_USER, ROLE_ADMIN]:
            role = ROLE_USER
        
        errors = []
        if not username:
            errors.append('Username is required')
        if len(username) < 3:
            errors.append('Username must be at least 3 characters')
        if not password:
            errors.append('Password is required')
        if len(password) < 8:
            errors.append('Password must be at least 8 characters')
        if password != confirm_password:
            errors.append('Passwords do not match')
        
        if not errors:
            conn = get_db()
            cursor = conn.cursor()
            try:
                password_hash = hash_password(password)
                cursor.execute(
                    'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
                    (username, password_hash, role)
                )
                conn.commit()
                flash(f'Account "{username}" created successfully as {role}', 'success')
                return redirect(url_for('admin.accounts'))
            except sqlite3.IntegrityError:
                errors.append('Username already exists')
            finally:
                conn.close()
        
        for error in errors:
            flash(error, 'error')
    
    return render_template('admin/create_account.html', roles=[ROLE_USER, ROLE_ADMIN])


@admin_bp.route('/accounts/<int:account_id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_account(account_id):
    """Edit user account role."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, role FROM users WHERE id = ?', (account_id,))
    account = cursor.fetchone()
    
    if not account:
        conn.close()
        flash('Account not found', 'error')
        return redirect(url_for('admin.accounts'))
    
    if request.method == 'POST':
        role = request.form.get('role', ROLE_USER)
        
        # Validate role
        if role not in [ROLE_USER, ROLE_ADMIN]:
            role = ROLE_USER
        
        # Prevent demoting yourself
        if account_id == session.get('user_id') and role != ROLE_ADMIN:
            flash('Cannot change your own role', 'error')
            conn.close()
            return redirect(url_for('admin.accounts'))
        
        cursor.execute(
            'UPDATE users SET role = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
            (role, account_id)
        )
        conn.commit()
        conn.close()
        flash(f'Account "{account["username"]}" updated to {role}', 'success')
        return redirect(url_for('admin.accounts'))
    
    conn.close()
    return render_template('admin/edit_account.html', account=account, roles=[ROLE_USER, ROLE_ADMIN])


@admin_bp.route('/accounts/<int:account_id>/password', methods=['GET', 'POST'])
@admin_required
def change_password(account_id):
    """Change account password."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, username FROM users WHERE id = ?', (account_id,))
    account = cursor.fetchone()
    
    if not account:
        conn.close()
        flash('Account not found', 'error')
        return redirect(url_for('admin.accounts'))
    
    if request.method == 'POST':
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        errors = []
        if not new_password:
            errors.append('New password is required')
        if len(new_password) < 8:
            errors.append('Password must be at least 8 characters')
        if new_password != confirm_password:
            errors.append('Passwords do not match')
        
        if not errors:
            password_hash = hash_password(new_password)
            cursor.execute(
                'UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
                (password_hash, account_id)
            )
            conn.commit()
            conn.close()
            flash(f'Password for "{account["username"]}" updated successfully', 'success')
            return redirect(url_for('admin.accounts'))
        
        for error in errors:
            flash(error, 'error')
    
    conn.close()
    return render_template('admin/change_password.html', account=account)


@admin_bp.route('/accounts/<int:account_id>/delete', methods=['POST'])
@admin_required
def delete_account(account_id):
    """Delete user account."""
    # Prevent deleting own account
    if account_id == session.get('user_id'):
        flash('Cannot delete your own account', 'error')
        return redirect(url_for('admin.accounts'))
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Check if this is the last admin account
    cursor.execute('SELECT role FROM users WHERE id = ?', (account_id,))
    account = cursor.fetchone()
    
    if account and account['role'] == ROLE_ADMIN:
        cursor.execute("SELECT COUNT(*) as count FROM users WHERE role = ?", (ROLE_ADMIN,))
        if cursor.fetchone()['count'] <= 1:
            conn.close()
            flash('Cannot delete the last admin account', 'error')
            return redirect(url_for('admin.accounts'))
    
    cursor.execute('SELECT username FROM users WHERE id = ?', (account_id,))
    account = cursor.fetchone()
    
    if account:
        cursor.execute('DELETE FROM users WHERE id = ?', (account_id,))
        conn.commit()
        flash(f'Account "{account["username"]}" deleted', 'success')
    else:
        flash('Account not found', 'error')
    
    conn.close()
    return redirect(url_for('admin.accounts'))


# ============================================
# Settings
# ============================================

@admin_bp.route('/settings')
@admin_required
def settings():
    """Manage settings."""
    conn = get_db()
    cursor = conn.cursor()
    
    # Get MaxMind API key
    cursor.execute("SELECT value FROM settings WHERE key = 'maxmind_api_key'")
    maxmind_row = cursor.fetchone()
    maxmind_key = maxmind_row['value'] if maxmind_row else ''
    
    # Get Shodan API key
    cursor.execute("SELECT value FROM settings WHERE key = 'shodan_api_key'")
    shodan_row = cursor.fetchone()
    shodan_key = shodan_row['value'] if shodan_row else ''
    
    # Get Shodan account info if key is set
    shodan_info = None
    if shodan_key:
        shodan_info = get_shodan_account_info(shodan_key)
    
    # Get DNS settings
    cursor.execute("SELECT value FROM settings WHERE key = 'dns_servers'")
    dns_servers_row = cursor.fetchone()
    dns_servers = dns_servers_row['value'] if dns_servers_row else '8.8.8.8,8.8.4.4,1.1.1.1'
    
    cursor.execute("SELECT value FROM settings WHERE key = 'dns_cache_ttl'")
    dns_cache_ttl_row = cursor.fetchone()
    dns_cache_ttl = int(dns_cache_ttl_row['value']) if dns_cache_ttl_row else 3600
    
    cursor.execute("SELECT value FROM settings WHERE key = 'dns_timeout'")
    dns_timeout_row = cursor.fetchone()
    dns_timeout = int(dns_timeout_row['value']) if dns_timeout_row else 5
    
    cursor.execute("SELECT value FROM settings WHERE key = 'dns_max_domains'")
    dns_max_domains_row = cursor.fetchone()
    dns_max_domains = int(dns_max_domains_row['value']) if dns_max_domains_row else 100
    
    # Get concurrency settings
    cursor.execute("SELECT value FROM settings WHERE key = 'dns_concurrency'")
    dns_concurrency_row = cursor.fetchone()
    dns_concurrency = int(dns_concurrency_row['value']) if dns_concurrency_row else 10
    
    cursor.execute("SELECT value FROM settings WHERE key = 'whois_concurrency'")
    whois_concurrency_row = cursor.fetchone()
    whois_concurrency = int(whois_concurrency_row['value']) if whois_concurrency_row else 5
    
    # Get WHOIS cache TTL
    cursor.execute("SELECT value FROM settings WHERE key = 'whois_cache_ttl'")
    whois_cache_ttl_row = cursor.fetchone()
    whois_cache_ttl = int(whois_cache_ttl_row['value']) if whois_cache_ttl_row else 86400
    
    # Get Shodan cache TTL
    cursor.execute("SELECT value FROM settings WHERE key = 'shodan_cache_ttl'")
    shodan_cache_ttl_row = cursor.fetchone()
    shodan_cache_ttl = int(shodan_cache_ttl_row['value']) if shodan_cache_ttl_row else 3600
    
    # Get Shodan pivot limit
    cursor.execute("SELECT value FROM settings WHERE key = 'shodan_pivot_limit'")
    shodan_pivot_limit_row = cursor.fetchone()
    shodan_pivot_limit = int(shodan_pivot_limit_row['value']) if shodan_pivot_limit_row else 100
    
    # Get shared results expiry days
    cursor.execute("SELECT value FROM settings WHERE key = 'shared_results_expiry_days'")
    shared_results_expiry_row = cursor.fetchone()
    shared_results_expiry_days = int(shared_results_expiry_row['value']) if shared_results_expiry_row else 30
    
    # Get CIRCL Passive DNS settings
    cursor.execute("SELECT value FROM settings WHERE key = 'circl_username'")
    circl_username_row = cursor.fetchone()
    circl_username = circl_username_row['value'] if circl_username_row else ''
    
    cursor.execute("SELECT value FROM settings WHERE key = 'circl_password'")
    circl_password_row = cursor.fetchone()
    circl_password = circl_password_row['value'] if circl_password_row else ''
    
    cursor.execute("SELECT value FROM settings WHERE key = 'circl_disable_active_query'")
    circl_disable_active_row = cursor.fetchone()
    circl_disable_active_query = circl_disable_active_row['value'] == '1' if circl_disable_active_row else False
    
    cursor.execute("SELECT value FROM settings WHERE key = 'circl_max_results'")
    circl_max_results_row = cursor.fetchone()
    circl_max_results = int(circl_max_results_row['value']) if circl_max_results_row else 100
    
    cursor.execute("SELECT value FROM settings WHERE key = 'circl_cache_ttl'")
    circl_cache_ttl_row = cursor.fetchone()
    circl_cache_ttl = int(circl_cache_ttl_row['value']) if circl_cache_ttl_row else 604800  # 7 days default
    
    cursor.execute("SELECT value FROM settings WHERE key = 'circl_concurrency'")
    circl_concurrency_row = cursor.fetchone()
    circl_concurrency = int(circl_concurrency_row['value']) if circl_concurrency_row else 5
    
    cursor.execute("SELECT value FROM settings WHERE key = 'circl_rate_limit'")
    circl_rate_limit_row = cursor.fetchone()
    circl_rate_limit = float(circl_rate_limit_row['value']) if circl_rate_limit_row else 5.0  # requests per second
    
    # Get HackerTarget settings
    cursor.execute("SELECT value FROM settings WHERE key = 'hackertarget_api_key'")
    hackertarget_api_key_row = cursor.fetchone()
    hackertarget_api_key = hackertarget_api_key_row['value'] if hackertarget_api_key_row else ''
    
    cursor.execute("SELECT value FROM settings WHERE key = 'hackertarget_cache_ttl'")
    hackertarget_cache_ttl_row = cursor.fetchone()
    hackertarget_cache_ttl = int(hackertarget_cache_ttl_row['value']) if hackertarget_cache_ttl_row else 86400  # 1 day default
    
    # Get ViewDNS settings
    cursor.execute("SELECT value FROM settings WHERE key = 'viewdns_api_key'")
    viewdns_api_key_row = cursor.fetchone()
    viewdns_api_key = viewdns_api_key_row['value'] if viewdns_api_key_row else ''
    
    cursor.execute("SELECT value FROM settings WHERE key = 'viewdns_cache_ttl'")
    viewdns_cache_ttl_row = cursor.fetchone()
    viewdns_cache_ttl = int(viewdns_cache_ttl_row['value']) if viewdns_cache_ttl_row else 86400  # 1 day default
    
    cursor.execute("SELECT value FROM settings WHERE key = 'viewdns_rate_limit'")
    viewdns_rate_limit_row = cursor.fetchone()
    viewdns_rate_limit = float(viewdns_rate_limit_row['value']) if viewdns_rate_limit_row else 1.0  # 1 request per second default
    
    cursor.execute("SELECT value FROM settings WHERE key = 'viewdns_max_nodes'")
    viewdns_max_nodes_row = cursor.fetchone()
    viewdns_max_nodes = int(viewdns_max_nodes_row['value']) if viewdns_max_nodes_row else 100  # Default 100 max nodes
    
    # Get Chaos (ProjectDiscovery) settings
    cursor.execute("SELECT value FROM settings WHERE key = 'chaos_api_key'")
    chaos_api_key_row = cursor.fetchone()
    chaos_api_key = chaos_api_key_row['value'] if chaos_api_key_row else ''
    
    cursor.execute("SELECT value FROM settings WHERE key = 'chaos_cache_ttl'")
    chaos_cache_ttl_row = cursor.fetchone()
    chaos_cache_ttl = int(chaos_cache_ttl_row['value']) if chaos_cache_ttl_row else 86400  # 1 day default
    
    cursor.execute("SELECT value FROM settings WHERE key = 'chaos_rate_limit'")
    chaos_rate_limit_row = cursor.fetchone()
    chaos_rate_limit = float(chaos_rate_limit_row['value']) if chaos_rate_limit_row else 5.0  # 5 req/sec default
    
    # Get scalability settings
    cursor.execute("SELECT value FROM settings WHERE key = 'max_adhoc_ips'")
    max_adhoc_ips_row = cursor.fetchone()
    max_adhoc_ips = int(max_adhoc_ips_row['value']) if max_adhoc_ips_row else 1000
    
    cursor.execute("SELECT value FROM settings WHERE key = 'max_unique_values'")
    max_unique_values_row = cursor.fetchone()
    max_unique_values = int(max_unique_values_row['value']) if max_unique_values_row else 10000
    
    cursor.execute("SELECT value FROM settings WHERE key = 'large_file_warning_threshold'")
    large_file_warning_row = cursor.fetchone()
    large_file_warning_threshold = int(large_file_warning_row['value']) if large_file_warning_row else 10000
    
    cursor.execute("SELECT value FROM settings WHERE key = 'max_url_fetch_size_mb'")
    max_url_fetch_size_row = cursor.fetchone()
    max_url_fetch_size_mb = int(max_url_fetch_size_row['value']) if max_url_fetch_size_row else 10
    
    conn.close()
    
    return render_template('admin/settings.html',
                           maxmind_key=maxmind_key,
                           maxmind_key_set=bool(maxmind_key),
                           shodan_key=shodan_key,
                           shodan_key_set=bool(shodan_key),
                           shodan_info=shodan_info,
                           dns_servers=dns_servers,
                           dns_cache_ttl=dns_cache_ttl,
                           dns_timeout=dns_timeout,
                           dns_max_domains=dns_max_domains,
                           dns_concurrency=dns_concurrency,
                           whois_concurrency=whois_concurrency,
                           whois_cache_ttl=whois_cache_ttl,
                           shodan_cache_ttl=shodan_cache_ttl,
                           shodan_pivot_limit=shodan_pivot_limit,
                           shared_results_expiry_days=shared_results_expiry_days,
                           circl_username=circl_username,
                           circl_password_set=bool(circl_password),
                           circl_disable_active_query=circl_disable_active_query,
                           circl_max_results=circl_max_results,
                           circl_cache_ttl=circl_cache_ttl,
                           circl_concurrency=circl_concurrency,
                           circl_rate_limit=circl_rate_limit,
                           hackertarget_api_key=hackertarget_api_key,
                           hackertarget_api_key_set=bool(hackertarget_api_key),
                           hackertarget_cache_ttl=hackertarget_cache_ttl,
                           viewdns_api_key=viewdns_api_key,
                           viewdns_api_key_set=bool(viewdns_api_key),
                           viewdns_cache_ttl=viewdns_cache_ttl,
                           viewdns_rate_limit=viewdns_rate_limit,
                           viewdns_max_nodes=viewdns_max_nodes,
                           chaos_api_key=chaos_api_key,
                           chaos_api_key_set=bool(chaos_api_key),
                           chaos_cache_ttl=chaos_cache_ttl,
                           chaos_rate_limit=chaos_rate_limit,
                           max_adhoc_ips=max_adhoc_ips,
                           max_unique_values=max_unique_values,
                           large_file_warning_threshold=large_file_warning_threshold,
                           max_url_fetch_size_mb=max_url_fetch_size_mb)


@admin_bp.route('/settings/maxmind', methods=['POST'])
@admin_required
def save_maxmind_key():
    """Save MaxMind API key."""
    api_key = request.form.get('maxmind_api_key', '').strip()
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT OR REPLACE INTO settings (key, value, updated_at) 
        VALUES ('maxmind_api_key', ?, CURRENT_TIMESTAMP)
    ''', (api_key,))
    conn.commit()
    conn.close()
    
    log_audit('api_key_modified', 'setting', 'maxmind_api_key', {'key_set': bool(api_key)})
    flash('MaxMind API key saved successfully', 'success')
    return redirect(url_for('admin.settings'))


@admin_bp.route('/settings/upload-mmdb', methods=['POST'])
@admin_required
def upload_mmdb():
    """Upload MaxMind database files."""
    MAXMIND_DIR = os.environ.get('MAXMIND_DIR', '/data/maxmind')
    REQUIRED_FILES = ['GeoLite2-ASN.mmdb', 'GeoLite2-Country.mmdb', 'GeoLite2-City.mmdb']

    if 'mmdb_files' not in request.files:
        return jsonify({'error': 'No files provided'}), 400

    files = request.files.getlist('mmdb_files')
    if not files:
        return jsonify({'error': 'No files provided'}), 400

    # Validate file names
    uploaded_names = [f.filename for f in files if f.filename]
    missing = [req for req in REQUIRED_FILES if req not in uploaded_names]
    if missing:
        return jsonify({'error': f'Missing required files: {", ".join(missing)}'}), 400

    # Ensure MaxMind directory exists
    maxmind_path = Path(MAXMIND_DIR)
    maxmind_path.mkdir(parents=True, exist_ok=True)

    # Save each file
    saved_files = []
    try:
        for file in files:
            if file.filename in REQUIRED_FILES:
                dest_path = maxmind_path / file.filename
                file.save(str(dest_path))
                saved_files.append(file.filename)

        log_audit('mmdb_files_uploaded', 'setting', 'maxmind', {'files': saved_files})
        return jsonify({
            'success': True,
            'message': f'Successfully uploaded {len(saved_files)} database files',
            'files': saved_files
        })

    except Exception as e:
        # Clean up any partially saved files
        for fname in saved_files:
            try:
                (maxmind_path / fname).unlink()
            except OSError:
                pass
        return jsonify({'error': f'Upload failed: {str(e)}'}), 500


@admin_bp.route('/settings/shodan', methods=['POST'])
@admin_required
def save_shodan_key():
    """Save Shodan API key."""
    api_key = request.form.get('shodan_api_key', '').strip()
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT OR REPLACE INTO settings (key, value, updated_at) 
        VALUES ('shodan_api_key', ?, CURRENT_TIMESTAMP)
    ''', (api_key,))
    conn.commit()
    conn.close()
    
    log_audit('api_key_modified', 'setting', 'shodan_api_key', {'key_set': bool(api_key)})
    flash('Shodan API key saved successfully', 'success')
    return redirect(url_for('admin.settings'))


@admin_bp.route('/settings/dns', methods=['POST'])
@admin_required
def save_dns_settings():
    """Save DNS settings."""
    dns_servers = request.form.get('dns_servers', '8.8.8.8,8.8.4.4,1.1.1.1').strip()
    dns_cache_ttl = request.form.get('dns_cache_ttl', '3600').strip()
    dns_timeout = request.form.get('dns_timeout', '5').strip()
    dns_max_domains = request.form.get('dns_max_domains', '100').strip()
    
    conn = get_db()
    cursor = conn.cursor()
    
    settings_to_save = [
        ('dns_servers', dns_servers),
        ('dns_cache_ttl', dns_cache_ttl),
        ('dns_timeout', dns_timeout),
        ('dns_max_domains', dns_max_domains),
    ]
    
    for key, value in settings_to_save:
        cursor.execute('''
            INSERT OR REPLACE INTO settings (key, value, updated_at) 
            VALUES (?, ?, CURRENT_TIMESTAMP)
        ''', (key, value))
    
    conn.commit()
    conn.close()
    
    log_audit('setting_modified', 'setting', 'dns', {'dns_servers': dns_servers, 'dns_cache_ttl': dns_cache_ttl})
    flash('DNS settings saved successfully', 'success')
    return redirect(url_for('admin.settings'))


@admin_bp.route('/settings/concurrency', methods=['POST'])
@admin_required
def save_concurrency_settings():
    """Save concurrency settings."""
    dns_concurrency = request.form.get('dns_concurrency', '10').strip()
    whois_concurrency = request.form.get('whois_concurrency', '5').strip()
    
    # Validate ranges
    try:
        dns_concurrency = max(1, min(50, int(dns_concurrency)))
        whois_concurrency = max(1, min(20, int(whois_concurrency)))
    except ValueError:
        dns_concurrency = 10
        whois_concurrency = 5
    
    conn = get_db()
    cursor = conn.cursor()
    
    settings_to_save = [
        ('dns_concurrency', str(dns_concurrency)),
        ('whois_concurrency', str(whois_concurrency)),
    ]
    
    for key, value in settings_to_save:
        cursor.execute('''
            INSERT OR REPLACE INTO settings (key, value, updated_at) 
            VALUES (?, ?, CURRENT_TIMESTAMP)
        ''', (key, value))
    
    conn.commit()
    conn.close()
    
    log_audit('setting_modified', 'setting', 'concurrency', {'dns': dns_concurrency, 'whois': whois_concurrency})
    flash('Concurrency settings saved successfully', 'success')
    return redirect(url_for('admin.settings'))


@admin_bp.route('/settings/cache', methods=['POST'])
@admin_required
def save_cache_settings():
    """Save cache TTL settings."""
    whois_cache_ttl = request.form.get('whois_cache_ttl', '86400').strip()
    shodan_cache_ttl = request.form.get('shodan_cache_ttl', '3600').strip()
    
    # Validate ranges (minimum 60 seconds, max 7 days)
    try:
        whois_cache_ttl = max(60, min(604800, int(whois_cache_ttl)))
        shodan_cache_ttl = max(60, min(604800, int(shodan_cache_ttl)))
    except ValueError:
        whois_cache_ttl = 86400
        shodan_cache_ttl = 3600
    
    conn = get_db()
    cursor = conn.cursor()
    
    settings_to_save = [
        ('whois_cache_ttl', str(whois_cache_ttl)),
        ('shodan_cache_ttl', str(shodan_cache_ttl)),
    ]
    
    for key, value in settings_to_save:
        cursor.execute('''
            INSERT OR REPLACE INTO settings (key, value, updated_at) 
            VALUES (?, ?, CURRENT_TIMESTAMP)
        ''', (key, value))
    
    conn.commit()
    conn.close()
    
    log_audit('setting_modified', 'setting', 'cache', {'whois_ttl': whois_cache_ttl, 'shodan_ttl': shodan_cache_ttl})
    flash('Cache settings saved successfully', 'success')
    return redirect(url_for('admin.settings'))


@admin_bp.route('/settings/shodan-pivot', methods=['POST'])
@admin_required
def save_shodan_pivot_settings():
    """Save Shodan pivot settings."""
    shodan_pivot_limit = request.form.get('shodan_pivot_limit', '100').strip()
    
    # Validate range (minimum 10, max 1000)
    try:
        shodan_pivot_limit = max(10, min(1000, int(shodan_pivot_limit)))
    except ValueError:
        shodan_pivot_limit = 100
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT OR REPLACE INTO settings (key, value, updated_at) 
        VALUES (?, ?, CURRENT_TIMESTAMP)
    ''', ('shodan_pivot_limit', str(shodan_pivot_limit)))
    
    conn.commit()
    conn.close()
    
    log_audit('setting_modified', 'setting', 'shodan_pivot_limit', {'value': shodan_pivot_limit})
    flash('Shodan pivot settings saved successfully', 'success')
    return redirect(url_for('admin.settings'))


@admin_bp.route('/settings/sharing', methods=['POST'])
@admin_required
def save_sharing_settings():
    """Save sharing settings."""
    shared_results_expiry_days = request.form.get('shared_results_expiry_days', '30').strip()
    
    # Validate range (minimum 1 day, max 365 days)
    try:
        shared_results_expiry_days = max(1, min(365, int(shared_results_expiry_days)))
    except ValueError:
        shared_results_expiry_days = 30
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT OR REPLACE INTO settings (key, value, updated_at) 
        VALUES ('shared_results_expiry_days', ?, CURRENT_TIMESTAMP)
    ''', (str(shared_results_expiry_days),))
    
    conn.commit()
    conn.close()
    
    log_audit('setting_modified', 'setting', 'shared_results_expiry_days', {'value': shared_results_expiry_days})
    flash('Sharing settings saved successfully', 'success')
    return redirect(url_for('admin.settings'))


@admin_bp.route('/settings/scalability', methods=['POST'])
@admin_required
def save_scalability_settings():
    """Save scalability settings."""
    max_adhoc_ips = request.form.get('max_adhoc_ips', '1000').strip()
    max_unique_values = request.form.get('max_unique_values', '10000').strip()
    large_file_warning_threshold = request.form.get('large_file_warning_threshold', '10000').strip()
    max_url_fetch_size_mb = request.form.get('max_url_fetch_size_mb', '10').strip()
    
    # Validate ranges
    try:
        max_adhoc_ips = max(100, min(100000, int(max_adhoc_ips)))
    except ValueError:
        max_adhoc_ips = 1000
    
    try:
        max_unique_values = max(1000, min(1000000, int(max_unique_values)))
    except ValueError:
        max_unique_values = 10000
    
    try:
        large_file_warning_threshold = max(1000, min(1000000, int(large_file_warning_threshold)))
    except ValueError:
        large_file_warning_threshold = 10000
    
    try:
        max_url_fetch_size_mb = max(1, min(100, int(max_url_fetch_size_mb)))
    except ValueError:
        max_url_fetch_size_mb = 10
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT OR REPLACE INTO settings (key, value, updated_at) 
        VALUES ('max_adhoc_ips', ?, CURRENT_TIMESTAMP)
    ''', (str(max_adhoc_ips),))
    
    cursor.execute('''
        INSERT OR REPLACE INTO settings (key, value, updated_at) 
        VALUES ('max_unique_values', ?, CURRENT_TIMESTAMP)
    ''', (str(max_unique_values),))
    
    cursor.execute('''
        INSERT OR REPLACE INTO settings (key, value, updated_at) 
        VALUES ('large_file_warning_threshold', ?, CURRENT_TIMESTAMP)
    ''', (str(large_file_warning_threshold),))
    
    cursor.execute('''
        INSERT OR REPLACE INTO settings (key, value, updated_at) 
        VALUES ('max_url_fetch_size_mb', ?, CURRENT_TIMESTAMP)
    ''', (str(max_url_fetch_size_mb),))
    
    conn.commit()
    conn.close()
    
    log_audit('setting_modified', 'setting', 'scalability_settings', {
        'max_adhoc_ips': max_adhoc_ips,
        'max_unique_values': max_unique_values,
        'large_file_warning_threshold': large_file_warning_threshold,
        'max_url_fetch_size_mb': max_url_fetch_size_mb
    })
    flash('Scalability settings saved successfully', 'success')
    return redirect(url_for('admin.settings'))


@admin_bp.route('/settings/circl', methods=['POST'])
@admin_required
def save_circl_settings():
    """Save CIRCL Passive DNS settings."""
    circl_username = request.form.get('circl_username', '').strip()
    circl_password = request.form.get('circl_password', '').strip()
    circl_disable_active_query = '1' if request.form.get('circl_disable_active_query') == 'on' else '0'
    circl_max_results = request.form.get('circl_max_results', '100').strip()
    circl_cache_ttl = request.form.get('circl_cache_ttl', '604800').strip()
    circl_concurrency = request.form.get('circl_concurrency', '5').strip()
    circl_rate_limit = request.form.get('circl_rate_limit', '5.0').strip()
    
    # Validate values
    try:
        circl_max_results = max(1, min(10000, int(circl_max_results)))
    except ValueError:
        circl_max_results = 100
    
    try:
        circl_cache_ttl = max(3600, int(circl_cache_ttl))  # Minimum 1 hour
    except ValueError:
        circl_cache_ttl = 604800
    
    try:
        circl_concurrency = max(1, min(20, int(circl_concurrency)))
    except ValueError:
        circl_concurrency = 5
    
    try:
        circl_rate_limit = max(0.1, min(100, float(circl_rate_limit)))
    except ValueError:
        circl_rate_limit = 5.0
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT OR REPLACE INTO settings (key, value, updated_at) 
        VALUES ('circl_username', ?, CURRENT_TIMESTAMP)
    ''', (circl_username,))
    
    # Only update password if provided (allows keeping existing password)
    if circl_password:
        cursor.execute('''
            INSERT OR REPLACE INTO settings (key, value, updated_at) 
            VALUES ('circl_password', ?, CURRENT_TIMESTAMP)
        ''', (circl_password,))
    
    cursor.execute('''
        INSERT OR REPLACE INTO settings (key, value, updated_at) 
        VALUES ('circl_disable_active_query', ?, CURRENT_TIMESTAMP)
    ''', (circl_disable_active_query,))
    
    cursor.execute('''
        INSERT OR REPLACE INTO settings (key, value, updated_at) 
        VALUES ('circl_max_results', ?, CURRENT_TIMESTAMP)
    ''', (str(circl_max_results),))
    
    cursor.execute('''
        INSERT OR REPLACE INTO settings (key, value, updated_at) 
        VALUES ('circl_cache_ttl', ?, CURRENT_TIMESTAMP)
    ''', (str(circl_cache_ttl),))
    
    cursor.execute('''
        INSERT OR REPLACE INTO settings (key, value, updated_at) 
        VALUES ('circl_concurrency', ?, CURRENT_TIMESTAMP)
    ''', (str(circl_concurrency),))
    
    cursor.execute('''
        INSERT OR REPLACE INTO settings (key, value, updated_at) 
        VALUES ('circl_rate_limit', ?, CURRENT_TIMESTAMP)
    ''', (str(circl_rate_limit),))
    
    conn.commit()
    conn.close()
    
    log_audit('setting_modified', 'setting', 'circl_pdns', {
        'username_set': bool(circl_username),
        'max_results': circl_max_results,
        'cache_ttl': circl_cache_ttl
    })
    flash('CIRCL Passive DNS settings saved successfully', 'success')
    return redirect(url_for('admin.settings'))


@admin_bp.route('/settings/hackertarget', methods=['POST'])
@admin_required
def save_hackertarget_settings():
    """Save HackerTarget settings."""
    hackertarget_api_key = request.form.get('hackertarget_api_key', '').strip()
    hackertarget_cache_ttl = request.form.get('hackertarget_cache_ttl', '86400').strip()
    
    # Validate cache TTL
    try:
        hackertarget_cache_ttl = max(3600, int(hackertarget_cache_ttl))  # Minimum 1 hour
    except ValueError:
        hackertarget_cache_ttl = 86400
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT OR REPLACE INTO settings (key, value, updated_at) 
        VALUES ('hackertarget_api_key', ?, CURRENT_TIMESTAMP)
    ''', (hackertarget_api_key,))
    
    cursor.execute('''
        INSERT OR REPLACE INTO settings (key, value, updated_at) 
        VALUES ('hackertarget_cache_ttl', ?, CURRENT_TIMESTAMP)
    ''', (str(hackertarget_cache_ttl),))
    
    conn.commit()
    conn.close()
    
    log_audit('setting_modified', 'setting', 'hackertarget', {
        'api_key_set': bool(hackertarget_api_key),
        'cache_ttl': hackertarget_cache_ttl
    })
    flash('HackerTarget settings saved successfully', 'success')
    return redirect(url_for('admin.settings'))


@admin_bp.route('/settings/viewdns', methods=['POST'])
@admin_required
def save_viewdns_settings():
    """Save ViewDNS settings."""
    viewdns_api_key = request.form.get('viewdns_api_key', '').strip()
    viewdns_cache_ttl = request.form.get('viewdns_cache_ttl', '86400').strip()
    viewdns_rate_limit = request.form.get('viewdns_rate_limit', '1.0').strip()
    viewdns_max_nodes = request.form.get('viewdns_max_nodes', '100').strip()
    
    # Validate values
    try:
        viewdns_cache_ttl = max(3600, int(viewdns_cache_ttl))  # Minimum 1 hour
    except ValueError:
        viewdns_cache_ttl = 86400
    
    try:
        viewdns_rate_limit = max(0.1, min(10, float(viewdns_rate_limit)))
    except ValueError:
        viewdns_rate_limit = 1.0
    
    try:
        viewdns_max_nodes = max(10, min(1000, int(viewdns_max_nodes)))
    except ValueError:
        viewdns_max_nodes = 100
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT OR REPLACE INTO settings (key, value, updated_at) 
        VALUES ('viewdns_api_key', ?, CURRENT_TIMESTAMP)
    ''', (viewdns_api_key,))
    
    cursor.execute('''
        INSERT OR REPLACE INTO settings (key, value, updated_at) 
        VALUES ('viewdns_cache_ttl', ?, CURRENT_TIMESTAMP)
    ''', (str(viewdns_cache_ttl),))
    
    cursor.execute('''
        INSERT OR REPLACE INTO settings (key, value, updated_at) 
        VALUES ('viewdns_rate_limit', ?, CURRENT_TIMESTAMP)
    ''', (str(viewdns_rate_limit),))
    
    cursor.execute('''
        INSERT OR REPLACE INTO settings (key, value, updated_at) 
        VALUES ('viewdns_max_nodes', ?, CURRENT_TIMESTAMP)
    ''', (str(viewdns_max_nodes),))
    
    conn.commit()
    conn.close()
    
    log_audit('setting_modified', 'setting', 'viewdns', {
        'api_key_set': bool(viewdns_api_key),
        'cache_ttl': viewdns_cache_ttl,
        'rate_limit': viewdns_rate_limit,
        'max_nodes': viewdns_max_nodes
    })
    flash('ViewDNS settings saved successfully', 'success')
    return redirect(url_for('admin.settings'))


@admin_bp.route('/settings/chaos', methods=['POST'])
@admin_required
def save_chaos_settings():
    """Save Chaos (ProjectDiscovery) settings."""
    chaos_api_key = request.form.get('chaos_api_key', '').strip()
    chaos_cache_ttl = request.form.get('chaos_cache_ttl', '86400').strip()
    chaos_rate_limit = request.form.get('chaos_rate_limit', '5.0').strip()
    
    # Validate values
    try:
        chaos_cache_ttl = max(3600, int(chaos_cache_ttl))  # Minimum 1 hour
    except ValueError:
        chaos_cache_ttl = 86400
    
    try:
        chaos_rate_limit = max(0.1, min(100, float(chaos_rate_limit)))
    except ValueError:
        chaos_rate_limit = 5.0
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT OR REPLACE INTO settings (key, value, updated_at) 
        VALUES ('chaos_api_key', ?, CURRENT_TIMESTAMP)
    ''', (chaos_api_key,))
    
    cursor.execute('''
        INSERT OR REPLACE INTO settings (key, value, updated_at) 
        VALUES ('chaos_cache_ttl', ?, CURRENT_TIMESTAMP)
    ''', (str(chaos_cache_ttl),))
    
    cursor.execute('''
        INSERT OR REPLACE INTO settings (key, value, updated_at) 
        VALUES ('chaos_rate_limit', ?, CURRENT_TIMESTAMP)
    ''', (str(chaos_rate_limit),))
    
    conn.commit()
    conn.close()
    
    log_audit('setting_modified', 'setting', 'chaos', {
        'api_key_set': bool(chaos_api_key),
        'cache_ttl': chaos_cache_ttl,
        'rate_limit': chaos_rate_limit
    })
    flash('Chaos (ProjectDiscovery) settings saved successfully', 'success')
    return redirect(url_for('admin.settings'))


@admin_bp.route('/settings/test-maxmind', methods=['POST'])
@admin_required
def test_maxmind_key():
    """Test MaxMind API key."""
    api_key = request.form.get('api_key', '').strip()
    
    if not api_key:
        return jsonify({'success': False, 'message': 'API key is required'})
    
    # Validate format (should be ACCOUNT_ID:LICENSE_KEY)
    if ':' not in api_key:
        return jsonify({'success': False, 'message': 'Invalid format. Expected: ACCOUNT_ID:LICENSE_KEY'})
    
    # Try to make a test request to MaxMind
    try:
        import urllib.request
        import urllib.error
        import base64
        
        account_id, license_key = api_key.split(':', 1)
        
        # Test URL for GeoLite2 database info
        test_url = 'https://download.maxmind.com/geoip/databases/GeoLite2-Country/download?suffix=tar.gz'
        
        # Create request with auth
        req = urllib.request.Request(test_url, method='HEAD')
        credentials = base64.b64encode(f"{account_id}:{license_key}".encode()).decode()
        req.add_header('Authorization', f'Basic {credentials}')
        
        urllib.request.urlopen(req, timeout=10)
        return jsonify({'success': True, 'message': 'API key is valid!'})
        
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return jsonify({'success': False, 'message': 'Invalid API key or account ID'})
        return jsonify({'success': False, 'message': f'HTTP Error: {e.code}'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Connection error: {str(e)}'})


@admin_bp.route('/settings/test-shodan', methods=['POST'])
@admin_required
def test_shodan_key():
    """Test Shodan API key."""
    api_key = request.form.get('api_key', '').strip()
    
    if not api_key:
        return jsonify({'success': False, 'message': 'API key is required'})
    
    # Try to make a test request to Shodan API
    try:
        import urllib.request
        import urllib.error
        import json
        
        # Test URL for Shodan API info
        test_url = f'https://api.shodan.io/api-info?key={api_key}'
        
        req = urllib.request.Request(test_url)
        req.add_header('User-Agent', 'LogBoost-Web/1.0')
        
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode())
            
            return jsonify({
                'success': True,
                'message': 'API key is valid!',
                'plan': data.get('plan', 'Unknown'),
                'query_credits': data.get('query_credits', 0),
                'scan_credits': data.get('scan_credits', 0)
            })
        
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return jsonify({'success': False, 'message': 'Invalid API key'})
        return jsonify({'success': False, 'message': f'HTTP Error: {e.code}'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Connection error: {str(e)}'})


def get_shodan_account_info(api_key):
    """Get Shodan account information."""
    try:
        import urllib.request
        import json
        
        url = f'https://api.shodan.io/api-info?key={api_key}'
        req = urllib.request.Request(url)
        req.add_header('User-Agent', 'LogBoost-Web/1.0')
        
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode())
            return {
                'plan': data.get('plan', 'Unknown'),
                'query_credits': data.get('query_credits', 0),
                'scan_credits': data.get('scan_credits', 0)
            }
    except Exception:
        return None


# Legacy route for backwards compatibility
@admin_bp.route('/settings/test-api', methods=['POST'])
@admin_required
def test_api_key():
    """Test MaxMind API key (legacy route)."""
    return test_maxmind_key()


# ============================================
# Task Management
# ============================================

@admin_bp.route('/tasks')
@admin_required
def tasks():
    """View and manage scheduled tasks."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM scheduled_tasks ORDER BY task_type')
    tasks = cursor.fetchall()
    conn.close()
    return render_template('admin/tasks.html', tasks=tasks)


@admin_bp.route('/tasks/<task_type>/configure', methods=['POST'])
@admin_required
def configure_task(task_type):
    """Configure a scheduled task."""
    interval_hours = request.form.get('interval_hours', type=int)
    enabled = request.form.get('enabled') == 'on'
    
    if interval_hours is None or interval_hours < 1:
        flash('Invalid interval', 'error')
        return redirect(url_for('admin.tasks'))
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Calculate next run time if enabling
    next_run = None
    if enabled:
        next_run = datetime.now() + timedelta(hours=interval_hours)
    
    cursor.execute('''
        UPDATE scheduled_tasks 
        SET interval_hours = ?, enabled = ?, next_run = ?
        WHERE task_type = ?
    ''', (interval_hours, 1 if enabled else 0, next_run, task_type))
    conn.commit()
    conn.close()
    
    flash(f'Task "{task_type}" configuration updated', 'success')
    return redirect(url_for('admin.tasks'))


@admin_bp.route('/tasks/<task_type>/run', methods=['POST'])
@admin_required
def run_task(task_type):
    """Run a task immediately."""
    # Start task in background thread
    thread = threading.Thread(target=execute_task, args=(task_type,))
    thread.daemon = True
    thread.start()
    
    flash(f'Task "{task_type}" started. Check logs for progress.', 'success')
    return redirect(url_for('admin.logs'))


# ============================================
# Task Logs
# ============================================

@admin_bp.route('/logs')
@admin_required
def logs():
    """View task logs."""
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Get total count
    cursor.execute('SELECT COUNT(*) as count FROM task_logs')
    total = cursor.fetchone()['count']
    
    # Get paginated logs
    offset = (page - 1) * per_page
    cursor.execute('''
        SELECT * FROM task_logs 
        ORDER BY started_at DESC 
        LIMIT ? OFFSET ?
    ''', (per_page, offset))
    logs = cursor.fetchall()
    
    conn.close()
    
    total_pages = (total + per_page - 1) // per_page
    
    return render_template('admin/logs.html', 
                           logs=logs, 
                           page=page, 
                           total_pages=total_pages,
                           total=total)


@admin_bp.route('/logs/<int:log_id>')
@admin_required
def log_detail(log_id):
    """View detailed log entry."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM task_logs WHERE id = ?', (log_id,))
    log = cursor.fetchone()
    conn.close()
    
    if not log:
        flash('Log entry not found', 'error')
        return redirect(url_for('admin.logs'))
    
    return render_template('admin/log_detail.html', log=log)


@admin_bp.route('/logs/clear', methods=['POST'])
@admin_required
def clear_logs():
    """Clear all task logs."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM task_logs')
    conn.commit()
    conn.close()
    
    flash('All logs cleared', 'success')
    return redirect(url_for('admin.logs'))


# ============================================
# Audit Logs
# ============================================

@admin_bp.route('/audit')
@admin_required
def audit_logs():
    """View audit logs."""
    # Get filter parameters
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    action_filter = request.args.get('action', '')
    user_filter = request.args.get('user', '')
    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')
    
    # Clamp per_page
    per_page = max(10, min(200, per_page))
    
    # Calculate offset
    offset = (page - 1) * per_page
    
    # Get logs
    logs, total_count = get_audit_logs(
        limit=per_page,
        offset=offset,
        action_filter=action_filter if action_filter else None,
        user_filter=user_filter if user_filter else None,
        start_date=start_date if start_date else None,
        end_date=end_date if end_date else None
    )
    
    # Get action types for filter dropdown
    action_types = get_audit_action_types()
    
    # Calculate pagination
    total_pages = (total_count + per_page - 1) // per_page
    
    # Get retention setting
    retention_days = get_audit_retention_days()
    
    return render_template('admin/audit_logs.html',
        logs=logs,
        total_count=total_count,
        page=page,
        per_page=per_page,
        total_pages=total_pages,
        action_filter=action_filter,
        user_filter=user_filter,
        start_date=start_date,
        end_date=end_date,
        action_types=action_types,
        retention_days=retention_days
    )


@admin_bp.route('/audit/export')
@admin_required
def export_audit_logs():
    """Export audit logs as CSV."""
    # Get filter parameters (same as view)
    action_filter = request.args.get('action', '')
    user_filter = request.args.get('user', '')
    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')
    
    # Get all matching logs (no pagination for export)
    logs, _ = get_audit_logs(
        limit=10000,  # Reasonable max for export
        offset=0,
        action_filter=action_filter if action_filter else None,
        user_filter=user_filter if user_filter else None,
        start_date=start_date if start_date else None,
        end_date=end_date if end_date else None
    )
    
    # Build CSV
    import csv
    import io
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Header
    writer.writerow(['Timestamp', 'User', 'IP Address', 'Action', 'Resource Type', 'Resource ID', 'Success', 'Details', 'User Agent'])
    
    # Rows
    for log in logs:
        details_str = json.dumps(log.get('details', '')) if log.get('details') else ''
        writer.writerow([
            log.get('timestamp', ''),
            log.get('username', ''),
            log.get('ip_address', ''),
            log.get('action', ''),
            log.get('resource_type', ''),
            log.get('resource_id', ''),
            'Yes' if log.get('success') else 'No',
            details_str,
            log.get('user_agent', '')[:100]  # Truncate user agent
        ])
    
    # Create response
    from flask import Response
    response = Response(output.getvalue(), mimetype='text/csv')
    response.headers['Content-Disposition'] = f'attachment; filename=audit_logs_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    return response


@admin_bp.route('/audit/clear', methods=['POST'])
@admin_required
def clear_audit_logs():
    """Clear all audit logs."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM audit_logs')
    deleted = cursor.rowcount
    conn.commit()
    conn.close()
    
    log_audit('audit_logs_cleared', 'audit', None, {'deleted_count': deleted})
    flash(f'Cleared {deleted} audit log entries', 'success')
    return redirect(url_for('admin.audit_logs'))


@admin_bp.route('/audit/cleanup', methods=['POST'])
@admin_required
def cleanup_audit_logs():
    """Manually trigger cleanup of old audit logs."""
    deleted = cleanup_old_audit_logs()
    flash(f'Cleaned up {deleted} old audit log entries', 'success')
    return redirect(url_for('admin.audit_logs'))


@admin_bp.route('/settings/audit-retention', methods=['POST'])
@admin_required
def save_audit_retention():
    """Save audit log retention setting."""
    days = request.form.get('audit_retention_days', 90, type=int)
    days = max(7, min(365, days))  # Clamp between 7-365 days
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT OR REPLACE INTO settings (key, value, updated_at)
        VALUES (?, ?, CURRENT_TIMESTAMP)
    ''', ('audit_retention_days', str(days)))
    conn.commit()
    conn.close()
    
    log_audit('setting_modified', 'setting', 'audit_retention_days', {'value': days})
    flash(f'Audit log retention set to {days} days', 'success')
    return redirect(url_for('admin.audit_logs'))


# ============================================
# Task Execution
# ============================================

def get_api_key():
    """Get MaxMind API key from settings or environment."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM settings WHERE key = 'maxmind_api_key'")
    row = cursor.fetchone()
    conn.close()
    
    if row and row['value']:
        return row['value']
    
    # Fallback to environment variable or file
    api_key = os.environ.get('MM_API', '')
    if not api_key:
        api_file = Path('.') / 'mm_api.txt'
        if api_file.exists():
            api_key = api_file.read_text().strip()
    
    return api_key


def execute_task(task_type: str):
    """Execute a LogBoost task."""
    conn = get_db()
    cursor = conn.cursor()
    
    started_at = datetime.now()
    
    # Create log entry
    cursor.execute('''
        INSERT INTO task_logs (task_type, status, started_at) 
        VALUES (?, 'running', ?)
    ''', (task_type, started_at))
    log_id = cursor.lastrowid
    conn.commit()
    
    try:
        # Build command based on task type
        cmd = [LOGBOOST_BINARY]
        
        if task_type == 'update_geo':
            api_key = get_api_key()
            if api_key:
                cmd.extend(['-api', api_key])
            cmd.append('-updategeo')
            cmd.extend(['-dbdir', '/data/maxmind'])
        elif task_type == 'update_ti':
            cmd.append('-updateti')
            cmd.extend(['-tidb', '/app/threats.db'])
        elif task_type == 'build_ti':
            cmd.append('-buildti')
            cmd.extend(['-tidb', '/app/threats.db'])
        elif task_type == 'backup':
            # Backup task uses shell script, not LogBoost binary
            backup_dir = os.environ.get('BACKUP_DIR', '/data/backups')
            cmd = ['/bin/sh', '/app/scripts/backup.sh', backup_dir]
        else:
            raise ValueError(f'Unknown task type: {task_type}')

        # Set working directory based on task type
        # Threat intel tasks run in /app where feed_config.json and logboost binary live
        if task_type in ('update_ti', 'build_ti'):
            workdir = '/app'
        else:
            workdir = os.environ.get('LOGBOOST_WORKDIR', '.')

        # Log command for debugging
        cmd_str = ' '.join(cmd)
        print(f"[DEBUG] Task {task_type}: {cmd_str} (cwd={workdir})", flush=True)

        # Execute command
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=3600,  # 1 hour timeout
            cwd=workdir
        )
        
        completed_at = datetime.now()
        
        if result.returncode == 0:
            status = 'success'
            output = result.stdout
            error = None
        else:
            status = 'failed'
            output = result.stdout
            error = result.stderr
        
        # Update log entry
        cursor.execute('''
            UPDATE task_logs 
            SET status = ?, completed_at = ?, output = ?, error = ?
            WHERE id = ?
        ''', (status, completed_at, output, error, log_id))
        
        # Update task last_run
        cursor.execute('''
            UPDATE scheduled_tasks 
            SET last_run = ?
            WHERE task_type = ?
        ''', (completed_at, task_type))
        
        # Calculate next run if task is enabled
        cursor.execute('SELECT interval_hours, enabled FROM scheduled_tasks WHERE task_type = ?', (task_type,))
        task = cursor.fetchone()
        if task and task['enabled']:
            next_run = completed_at + timedelta(hours=task['interval_hours'])
            cursor.execute('UPDATE scheduled_tasks SET next_run = ? WHERE task_type = ?', (next_run, task_type))
        
        conn.commit()
        
    except subprocess.TimeoutExpired:
        cursor.execute('''
            UPDATE task_logs 
            SET status = 'failed', completed_at = ?, error = ?
            WHERE id = ?
        ''', (datetime.now(), 'Task timed out after 1 hour', log_id))
        conn.commit()
        
    except FileNotFoundError:
        cursor.execute('''
            UPDATE task_logs 
            SET status = 'failed', completed_at = ?, error = ?
            WHERE id = ?
        ''', (datetime.now(), f'LogBoost binary not found: {LOGBOOST_BINARY}', log_id))
        conn.commit()
        
    except Exception as e:
        cursor.execute('''
            UPDATE task_logs 
            SET status = 'failed', completed_at = ?, error = ?
            WHERE id = ?
        ''', (datetime.now(), str(e), log_id))
        conn.commit()
    
    finally:
        conn.close()


# ============================================
# Background Scheduler
# ============================================

class TaskScheduler:
    """
    Background task scheduler with database-level locking.
    
    This implementation prevents duplicate task execution in multi-worker
    deployments by using the database as a distributed lock:
    - Each task has a 'running' flag that is atomically set when claimed
    - Only one worker can claim a task at a time
    - The runner_id tracks which process is running the task
    - Stale locks (running_since > 2 hours) are automatically cleared
    """
    
    # Timeout for stale task locks (2 hours)
    STALE_LOCK_TIMEOUT_HOURS = 2
    
    def __init__(self):
        self.running = False
        self.thread = None
        # Unique identifier for this scheduler instance (hostname + pid)
        import socket
        self.runner_id = f"{socket.gethostname()}:{os.getpid()}"
    
    def start(self):
        """Start the scheduler."""
        if self.running:
            return
        
        self.running = True
        self.thread = threading.Thread(target=self._run)
        self.thread.daemon = True
        self.thread.start()
        logger.info("Task scheduler started (runner_id: %s)", self.runner_id)
    
    def stop(self):
        """Stop the scheduler."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        logger.info("Task scheduler stopped")
    
    def _run(self):
        """Main scheduler loop."""
        cleanup_counter = 0
        while self.running:
            try:
                self._clear_stale_locks()
                self._check_tasks()
                
                # Run audit log cleanup every hour (60 iterations * 60 seconds = 1 hour)
                cleanup_counter += 1
                if cleanup_counter >= 60:
                    cleanup_counter = 0
                    try:
                        cleanup_old_audit_logs()
                    except Exception as e:
                        logger.error("Audit log cleanup error: %s", e)
                        
            except Exception as e:
                logger.error("Scheduler error: %s", e)
            
            # Check every minute
            time.sleep(60)
    
    def _clear_stale_locks(self):
        """Clear locks from tasks that have been running too long (crashed workers)."""
        try:
            conn = get_db()
            cursor = conn.cursor()
            
            stale_cutoff = datetime.now() - timedelta(hours=self.STALE_LOCK_TIMEOUT_HOURS)
            
            cursor.execute('''
                UPDATE scheduled_tasks 
                SET running = 0, running_since = NULL, runner_id = NULL
                WHERE running = 1 AND running_since < ?
            ''', (stale_cutoff,))
            
            if cursor.rowcount > 0:
                logger.warning("Cleared %d stale task locks", cursor.rowcount)
            
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error("Error clearing stale locks: %s", e)
    
    def _check_tasks(self):
        """Check for tasks that need to run and claim them atomically."""
        conn = get_db()
        cursor = conn.cursor()
        
        now = datetime.now()
        
        # Find tasks that are due and not already running
        cursor.execute('''
            SELECT task_type, interval_hours FROM scheduled_tasks 
            WHERE enabled = 1 
              AND running = 0 
              AND next_run IS NOT NULL 
              AND next_run <= ?
        ''', (now,))
        
        candidate_tasks = cursor.fetchall()
        
        for task in candidate_tasks:
            task_type = task['task_type']
            interval_hours = task['interval_hours']
            
            # Try to atomically claim this task
            # This UPDATE will only affect rows where running is still 0
            cursor.execute('''
                UPDATE scheduled_tasks 
                SET running = 1, running_since = ?, runner_id = ?
                WHERE task_type = ? AND running = 0
            ''', (now, self.runner_id, task_type))
            
            conn.commit()
            
            # Check if we successfully claimed the task
            if cursor.rowcount > 0:
                logger.info("Claimed task %s (runner: %s)", task_type, self.runner_id)
                
                # Calculate and set next run time immediately
                next_run = now + timedelta(hours=interval_hours)
                cursor.execute('''
                    UPDATE scheduled_tasks 
                    SET next_run = ?
                    WHERE task_type = ?
                ''', (next_run, task_type))
                conn.commit()
                
                # Run task with cleanup callback
                thread = threading.Thread(
                    target=self._run_task_with_cleanup,
                    args=(task_type,)
                )
                thread.daemon = True
                thread.start()
            else:
                logger.debug("Task %s already claimed by another worker", task_type)
        
        conn.close()
    
    def _run_task_with_cleanup(self, task_type):
        """Execute a task and ensure the running flag is cleared afterward."""
        try:
            execute_task(task_type)
        except Exception as e:
            logger.error("Task %s failed: %s", task_type, e)
        finally:
            # Always clear the running flag when done
            try:
                conn = get_db()
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE scheduled_tasks 
                    SET running = 0, running_since = NULL, runner_id = NULL, last_run = ?
                    WHERE task_type = ?
                ''', (datetime.now(), task_type))
                conn.commit()
                conn.close()
                logger.info("Task %s completed, lock released", task_type)
            except Exception as e:
                logger.error("Error releasing lock for task %s: %s", task_type, e)


# Global scheduler instance
scheduler = TaskScheduler()


# ============================================
# DNS Cache Functions
# ============================================

def get_dns_settings():
    """Get DNS settings from database."""
    conn = get_db()
    cursor = conn.cursor()
    
    settings = {
        'servers': '8.8.8.8,8.8.4.4,1.1.1.1',
        'cache_ttl': 3600,
        'timeout': 5,
        'max_domains': 100
    }
    
    cursor.execute("SELECT value FROM settings WHERE key = 'dns_servers'")
    row = cursor.fetchone()
    if row:
        settings['servers'] = row['value']
    
    cursor.execute("SELECT value FROM settings WHERE key = 'dns_cache_ttl'")
    row = cursor.fetchone()
    if row:
        settings['cache_ttl'] = int(row['value'])
    
    cursor.execute("SELECT value FROM settings WHERE key = 'dns_timeout'")
    row = cursor.fetchone()
    if row:
        settings['timeout'] = int(row['value'])
    
    cursor.execute("SELECT value FROM settings WHERE key = 'dns_max_domains'")
    row = cursor.fetchone()
    if row:
        settings['max_domains'] = int(row['value'])
    
    conn.close()
    return settings


def get_concurrency_settings():
    """Get concurrency settings from database."""
    conn = get_db()
    cursor = conn.cursor()
    
    settings = {
        'dns_concurrency': 10,
        'whois_concurrency': 5
    }
    
    cursor.execute("SELECT value FROM settings WHERE key = 'dns_concurrency'")
    row = cursor.fetchone()
    if row:
        settings['dns_concurrency'] = int(row['value'])
    
    cursor.execute("SELECT value FROM settings WHERE key = 'whois_concurrency'")
    row = cursor.fetchone()
    if row:
        settings['whois_concurrency'] = int(row['value'])
    
    conn.close()
    return settings


def get_cached_dns(query, record_type):
    """Get cached DNS result if not expired."""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT results FROM dns_cache 
        WHERE query = ? AND record_type = ? AND expires_at > CURRENT_TIMESTAMP
    ''', (query.lower(), record_type))
    
    row = cursor.fetchone()
    conn.close()
    
    if row:
        import json
        return json.loads(row['results'])
    return None


def set_cached_dns(query, record_type, results, ttl_seconds):
    """Cache DNS result."""
    import json
    conn = get_db()
    cursor = conn.cursor()
    
    # Use SQLite's datetime function for timezone-consistent expiration
    cursor.execute('''
        INSERT OR REPLACE INTO dns_cache (query, record_type, results, resolved_at, expires_at)
        VALUES (?, ?, ?, CURRENT_TIMESTAMP, datetime(CURRENT_TIMESTAMP, '+' || ? || ' seconds'))
    ''', (query.lower(), record_type, json.dumps(results), ttl_seconds))
    
    conn.commit()
    conn.close()


def clear_expired_dns_cache():
    """Remove expired DNS cache entries."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM dns_cache WHERE expires_at < CURRENT_TIMESTAMP')
    conn.commit()
    conn.close()


# ============================================
# WHOIS Cache Functions
# ============================================

def get_whois_cache_settings():
    """Get WHOIS cache settings from database."""
    conn = get_db()
    cursor = conn.cursor()
    
    settings = {
        'cache_ttl': 86400,  # Default 24 hours
    }
    
    cursor.execute("SELECT value FROM settings WHERE key = 'whois_cache_ttl'")
    row = cursor.fetchone()
    if row:
        settings['cache_ttl'] = int(row['value'])
    
    conn.close()
    return settings


def get_shodan_pivot_limit():
    """Get Shodan pivot result limit from database."""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("SELECT value FROM settings WHERE key = 'shodan_pivot_limit'")
    row = cursor.fetchone()
    conn.close()
    
    if row:
        return int(row['value'])
    return 100  # Default


def get_cached_whois(domain):
    """Get cached WHOIS result if not expired."""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT results FROM whois_cache 
        WHERE domain = ? AND expires_at > CURRENT_TIMESTAMP
    ''', (domain.lower(),))
    
    row = cursor.fetchone()
    conn.close()
    
    if row:
        import json
        return json.loads(row['results'])
    return None


def set_cached_whois(domain, results, ttl_seconds):
    """Cache WHOIS result."""
    import json
    conn = get_db()
    cursor = conn.cursor()
    
    # Use SQLite's datetime function for timezone-consistent expiration
    cursor.execute('''
        INSERT OR REPLACE INTO whois_cache (domain, results, resolved_at, expires_at)
        VALUES (?, ?, CURRENT_TIMESTAMP, datetime(CURRENT_TIMESTAMP, '+' || ? || ' seconds'))
    ''', (domain.lower(), json.dumps(results), ttl_seconds))
    
    conn.commit()
    conn.close()


def clear_expired_whois_cache():
    """Remove expired WHOIS cache entries."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM whois_cache WHERE expires_at < CURRENT_TIMESTAMP')
    conn.commit()
    conn.close()


# ============================================
# Shodan Cache Functions
# ============================================

def get_shodan_cache_settings():
    """Get Shodan cache settings from database."""
    conn = get_db()
    cursor = conn.cursor()
    
    settings = {
        'cache_ttl': 3600,  # Default 1 hour
    }
    
    cursor.execute("SELECT value FROM settings WHERE key = 'shodan_cache_ttl'")
    row = cursor.fetchone()
    if row:
        settings['cache_ttl'] = int(row['value'])
    
    conn.close()
    return settings


def get_cached_shodan(query, query_type='ip'):
    """Get cached Shodan result if not expired."""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT results FROM shodan_cache 
        WHERE query = ? AND query_type = ? AND expires_at > CURRENT_TIMESTAMP
    ''', (query.lower(), query_type))
    
    row = cursor.fetchone()
    conn.close()
    
    if row:
        import json
        return json.loads(row['results'])
    return None


def set_cached_shodan(query, query_type, results, ttl_seconds):
    """Cache Shodan result."""
    import json
    conn = get_db()
    cursor = conn.cursor()
    
    # Use SQLite's datetime function for timezone-consistent expiration
    cursor.execute('''
        INSERT OR REPLACE INTO shodan_cache (query, query_type, results, resolved_at, expires_at)
        VALUES (?, ?, ?, CURRENT_TIMESTAMP, datetime(CURRENT_TIMESTAMP, '+' || ? || ' seconds'))
    ''', (query.lower(), query_type, json.dumps(results), ttl_seconds))
    
    conn.commit()
    conn.close()


def clear_expired_shodan_cache():
    """Remove expired Shodan cache entries."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM shodan_cache WHERE expires_at < CURRENT_TIMESTAMP')
    conn.commit()
    conn.close()


def get_cached_shodan_pivot(pivot_type, pivot_value):
    """Get cached Shodan pivot results if not expired."""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT results, result_count FROM shodan_pivot_cache 
        WHERE pivot_type = ? AND pivot_value = ? AND expires_at > CURRENT_TIMESTAMP
    ''', (pivot_type.lower(), pivot_value))
    
    row = cursor.fetchone()
    conn.close()
    
    if row and row['results']:
        return {
            'results': json.loads(row['results']),
            'result_count': row['result_count']
        }
    return None


def set_cached_shodan_pivot(pivot_type, pivot_value, results, result_count, ttl_seconds):
    """Cache Shodan pivot results."""
    conn = get_db()
    cursor = conn.cursor()
    
    # Use SQLite's datetime function for timezone-consistent expiration
    cursor.execute('''
        INSERT OR REPLACE INTO shodan_pivot_cache (pivot_type, pivot_value, results, result_count, resolved_at, expires_at)
        VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, datetime(CURRENT_TIMESTAMP, '+' || ? || ' seconds'))
    ''', (pivot_type.lower(), pivot_value, json.dumps(results), result_count, ttl_seconds))
    
    conn.commit()
    conn.close()


def clear_expired_shodan_pivot_cache():
    """Remove expired Shodan pivot cache entries."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM shodan_pivot_cache WHERE expires_at < CURRENT_TIMESTAMP')
    conn.commit()
    conn.close()


# ============================================
# CIRCL Passive DNS Cache Functions
# ============================================

def get_circl_settings():
    """Get CIRCL Passive DNS settings."""
    conn = get_db()
    cursor = conn.cursor()
    
    settings = {
        'username': '',
        'password': '',
        'disable_active_query': False,
        'max_results': 100,
        'cache_ttl': 604800,  # 7 days
        'concurrency': 5,
        'rate_limit': 5.0
    }
    
    cursor.execute("SELECT value FROM settings WHERE key = 'circl_username'")
    row = cursor.fetchone()
    if row:
        settings['username'] = row['value']
    
    cursor.execute("SELECT value FROM settings WHERE key = 'circl_password'")
    row = cursor.fetchone()
    if row:
        settings['password'] = row['value']
    
    cursor.execute("SELECT value FROM settings WHERE key = 'circl_disable_active_query'")
    row = cursor.fetchone()
    if row:
        settings['disable_active_query'] = row['value'] == '1'
    
    cursor.execute("SELECT value FROM settings WHERE key = 'circl_max_results'")
    row = cursor.fetchone()
    if row:
        settings['max_results'] = int(row['value'])
    
    cursor.execute("SELECT value FROM settings WHERE key = 'circl_cache_ttl'")
    row = cursor.fetchone()
    if row:
        settings['cache_ttl'] = int(row['value'])
    
    cursor.execute("SELECT value FROM settings WHERE key = 'circl_concurrency'")
    row = cursor.fetchone()
    if row:
        settings['concurrency'] = int(row['value'])
    
    cursor.execute("SELECT value FROM settings WHERE key = 'circl_rate_limit'")
    row = cursor.fetchone()
    if row:
        settings['rate_limit'] = float(row['value'])
    
    conn.close()
    return settings


def get_cached_circl_pdns(query_value, query_type='ip'):
    """Get cached CIRCL PDNS results."""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT results_json, result_count, cached_at FROM circl_pdns_cache 
        WHERE query_value = ? AND query_type = ? AND expires_at > CURRENT_TIMESTAMP
    ''', (query_value.lower(), query_type.lower()))
    
    row = cursor.fetchone()
    conn.close()
    
    if row and row['results_json']:
        return {
            'results': json.loads(row['results_json']),
            'result_count': row['result_count'],
            'cached_at': row['cached_at'],
            'from_cache': True
        }
    return None


def set_cached_circl_pdns(query_value, query_type, results, result_count, ttl_seconds):
    """Cache CIRCL PDNS results."""
    conn = get_db()
    cursor = conn.cursor()
    
    # Use SQLite's datetime function for timezone-consistent expiration
    cursor.execute('''
        INSERT OR REPLACE INTO circl_pdns_cache (query_value, query_type, results_json, result_count, cached_at, expires_at)
        VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, datetime(CURRENT_TIMESTAMP, '+' || ? || ' seconds'))
    ''', (query_value.lower(), query_type.lower(), json.dumps(results), result_count, ttl_seconds))
    
    conn.commit()
    conn.close()


def clear_expired_circl_pdns_cache():
    """Remove expired CIRCL PDNS cache entries."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM circl_pdns_cache WHERE expires_at < CURRENT_TIMESTAMP')
    conn.commit()
    conn.close()


# ============================================
# HackerTarget Cache Functions
# ============================================

def get_hackertarget_settings():
    """Get HackerTarget settings."""
    conn = get_db()
    cursor = conn.cursor()
    
    settings = {
        'api_key': '',
        'cache_ttl': 86400  # 1 day default
    }
    
    cursor.execute("SELECT value FROM settings WHERE key = 'hackertarget_api_key'")
    row = cursor.fetchone()
    if row:
        settings['api_key'] = row['value']
    
    cursor.execute("SELECT value FROM settings WHERE key = 'hackertarget_cache_ttl'")
    row = cursor.fetchone()
    if row:
        settings['cache_ttl'] = int(row['value'])
    
    conn.close()
    return settings


def get_cached_hackertarget(query_value, query_type='shared_ns'):
    """Get cached HackerTarget results."""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT results_json, result_count, cached_at FROM hackertarget_cache 
        WHERE query_value = ? AND query_type = ? AND expires_at > CURRENT_TIMESTAMP
    ''', (query_value.lower(), query_type.lower()))
    
    row = cursor.fetchone()
    conn.close()
    
    if row and row['results_json']:
        return {
            'results': json.loads(row['results_json']),
            'result_count': row['result_count'],
            'cached_at': row['cached_at'],
            'from_cache': True
        }
    return None


def set_cached_hackertarget(query_value, query_type, results, result_count, ttl_seconds):
    """Cache HackerTarget results."""
    conn = get_db()
    cursor = conn.cursor()
    
    # Use SQLite's datetime function for timezone-consistent expiration
    cursor.execute('''
        INSERT OR REPLACE INTO hackertarget_cache (query_value, query_type, results_json, result_count, cached_at, expires_at)
        VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, datetime(CURRENT_TIMESTAMP, '+' || ? || ' seconds'))
    ''', (query_value.lower(), query_type.lower(), json.dumps(results), result_count, ttl_seconds))
    
    conn.commit()
    conn.close()


def clear_expired_hackertarget_cache():
    """Remove expired HackerTarget cache entries."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM hackertarget_cache WHERE expires_at < CURRENT_TIMESTAMP')
    conn.commit()
    conn.close()


# ============================================
# ViewDNS Cache Functions
# ============================================

def get_viewdns_settings():
    """Get ViewDNS settings."""
    conn = get_db()
    cursor = conn.cursor()
    
    settings = {
        'api_key': '',
        'cache_ttl': 86400,  # 1 day default
        'rate_limit': 1.0,   # 1 request per second
        'max_nodes': 100     # Max nodes to create per enrichment
    }
    
    cursor.execute("SELECT value FROM settings WHERE key = 'viewdns_api_key'")
    row = cursor.fetchone()
    if row:
        settings['api_key'] = row['value']
    
    cursor.execute("SELECT value FROM settings WHERE key = 'viewdns_cache_ttl'")
    row = cursor.fetchone()
    if row:
        settings['cache_ttl'] = int(row['value'])
    
    cursor.execute("SELECT value FROM settings WHERE key = 'viewdns_rate_limit'")
    row = cursor.fetchone()
    if row:
        settings['rate_limit'] = float(row['value'])
    
    cursor.execute("SELECT value FROM settings WHERE key = 'viewdns_max_nodes'")
    row = cursor.fetchone()
    if row:
        settings['max_nodes'] = int(row['value'])
    
    conn.close()
    return settings


def get_cached_viewdns(query_value, query_type):
    """Get cached ViewDNS results."""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT results_json, result_count, cached_at FROM viewdns_cache 
        WHERE query_value = ? AND query_type = ? AND expires_at > CURRENT_TIMESTAMP
    ''', (query_value.lower(), query_type.lower()))
    
    row = cursor.fetchone()
    conn.close()
    
    if row and row['results_json']:
        return {
            'results': json.loads(row['results_json']),
            'result_count': row['result_count'],
            'cached_at': row['cached_at'],
            'from_cache': True
        }
    return None


def set_cached_viewdns(query_value, query_type, results, result_count, ttl_seconds):
    """Cache ViewDNS results."""
    conn = get_db()
    cursor = conn.cursor()
    
    # Use SQLite's datetime function for timezone-consistent expiration
    cursor.execute('''
        INSERT OR REPLACE INTO viewdns_cache (query_value, query_type, results_json, result_count, cached_at, expires_at)
        VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, datetime(CURRENT_TIMESTAMP, '+' || ? || ' seconds'))
    ''', (query_value.lower(), query_type.lower(), json.dumps(results), result_count, ttl_seconds))
    
    conn.commit()
    conn.close()


def clear_expired_viewdns_cache():
    """Remove expired ViewDNS cache entries."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM viewdns_cache WHERE expires_at < CURRENT_TIMESTAMP')
    conn.commit()
    conn.close()


# ============================================
# Chaos (ProjectDiscovery) Functions
# ============================================

def get_chaos_settings():
    """Get Chaos (ProjectDiscovery) API settings."""
    conn = get_db()
    cursor = conn.cursor()
    
    settings = {
        'api_key': '',
        'cache_ttl': 86400,  # 1 day default
        'rate_limit': 5.0,   # 5 requests per second default
    }
    
    cursor.execute("SELECT value FROM settings WHERE key = 'chaos_api_key'")
    row = cursor.fetchone()
    if row:
        settings['api_key'] = row['value']
    
    cursor.execute("SELECT value FROM settings WHERE key = 'chaos_cache_ttl'")
    row = cursor.fetchone()
    if row:
        settings['cache_ttl'] = int(row['value'])
    
    cursor.execute("SELECT value FROM settings WHERE key = 'chaos_rate_limit'")
    row = cursor.fetchone()
    if row:
        settings['rate_limit'] = float(row['value'])
    
    conn.close()
    return settings


def get_cached_chaos(domain):
    """Get cached Chaos subdomain results."""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT results_json, subdomain_count, cached_at FROM chaos_cache 
        WHERE domain = ? AND expires_at > CURRENT_TIMESTAMP
    ''', (domain.lower(),))
    
    row = cursor.fetchone()
    conn.close()
    
    if row and row['results_json']:
        return {
            'subdomains': json.loads(row['results_json']),
            'subdomain_count': row['subdomain_count'],
            'cached_at': row['cached_at'],
            'from_cache': True
        }
    return None


def set_cached_chaos(domain, subdomains, subdomain_count, ttl_seconds):
    """Cache Chaos subdomain results."""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT OR REPLACE INTO chaos_cache (domain, results_json, subdomain_count, cached_at, expires_at)
        VALUES (?, ?, ?, CURRENT_TIMESTAMP, datetime(CURRENT_TIMESTAMP, '+' || ? || ' seconds'))
    ''', (domain.lower(), json.dumps(subdomains), subdomain_count, ttl_seconds))
    
    conn.commit()
    conn.close()


def clear_expired_chaos_cache():
    """Remove expired Chaos cache entries."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM chaos_cache WHERE expires_at < CURRENT_TIMESTAMP')
    conn.commit()
    conn.close()


# ============================================
# Graph Storage Functions
# ============================================

def save_graph(graph_id, name, data, user_id=None):
    """Save or update a graph. Only owner can update existing graph."""
    import json
    conn = get_db()
    cursor = conn.cursor()
    
    # Check if graph exists and get its owner
    cursor.execute('SELECT user_id FROM saved_graphs WHERE id = ?', (graph_id,))
    existing = cursor.fetchone()
    
    if existing:
        # Graph exists - only update if same owner or no owner set
        existing_user_id = existing['user_id']
        if existing_user_id is not None and existing_user_id != user_id:
            # Different owner - don't allow update (caller should create new graph)
            conn.close()
            return False
    
    cursor.execute('''
        INSERT OR REPLACE INTO saved_graphs (id, name, data, user_id, created_at, updated_at)
        VALUES (?, ?, ?, ?,
            COALESCE((SELECT created_at FROM saved_graphs WHERE id = ?), CURRENT_TIMESTAMP),
            CURRENT_TIMESTAMP)
    ''', (graph_id, name, json.dumps(data), user_id, graph_id))
    
    conn.commit()
    conn.close()
    return True


def load_graph(graph_id, user_id=None):
    """Load a graph by ID. Requires ownership unless user_id is None (admin path)."""
    conn = get_db()
    cursor = conn.cursor()
    if user_id is not None:
        cursor.execute(
            'SELECT * FROM saved_graphs WHERE id = ? AND user_id = ?',
            (graph_id, user_id)
        )
    else:
        cursor.execute('SELECT * FROM saved_graphs WHERE id = ?', (graph_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    result = dict(row)
    result['data'] = json.loads(result['data'])
    return result


def list_graphs(user_id=None):
    """List saved graphs for a specific user."""
    conn = get_db()
    cursor = conn.cursor()
    
    if user_id is not None:
        cursor.execute(
            'SELECT id, name, created_at, updated_at FROM saved_graphs WHERE user_id = ? ORDER BY updated_at DESC',
            (user_id,)
        )
    else:
        # Fallback for backwards compatibility - list all (shouldn't be used normally)
        cursor.execute('SELECT id, name, created_at, updated_at FROM saved_graphs ORDER BY updated_at DESC')
    
    rows = cursor.fetchall()
    conn.close()
    
    return [dict(row) for row in rows]


def delete_graph(graph_id, user_id=None):
    """Delete a graph by ID. Only owner can delete."""
    conn = get_db()
    cursor = conn.cursor()
    
    if user_id is not None:
        cursor.execute('DELETE FROM saved_graphs WHERE id = ? AND user_id = ?', (graph_id, user_id))
    else:
        cursor.execute('DELETE FROM saved_graphs WHERE id = ?', (graph_id,))
    
    deleted = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return deleted


# ============================================
# Shared Results Functions
# ============================================

def save_shared_results(share_id, user_id, filename, results_data, stats_data, headers, expiry_days=30):
    """Save shared results with expiration."""
    import json
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Use SQLite's datetime function for timezone-consistent expiration
    cursor.execute('''
        INSERT INTO shared_results (id, user_id, filename, results_data, stats_data, headers, expires_at)
        VALUES (?, ?, ?, ?, ?, ?, datetime(CURRENT_TIMESTAMP, '+' || ? || ' days'))
    ''', (share_id, user_id, filename, json.dumps(results_data), json.dumps(stats_data) if stats_data else None, 
          json.dumps(headers) if headers else None, expiry_days))
    
    conn.commit()
    conn.close()
    return True


def get_shared_results(share_id):
    """Get shared results by ID if not expired."""
    import json
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT * FROM shared_results 
        WHERE id = ? AND expires_at > CURRENT_TIMESTAMP
    ''', (share_id,))
    
    row = cursor.fetchone()
    conn.close()
    
    if row:
        return {
            'id': row['id'],
            'user_id': row['user_id'],
            'filename': row['filename'],
            'results_data': json.loads(row['results_data']),
            'stats_data': json.loads(row['stats_data']) if row['stats_data'] else None,
            'headers': json.loads(row['headers']) if row['headers'] else None,
            'created_at': row['created_at'],
            'expires_at': row['expires_at']
        }
    return None


def clear_expired_shared_results():
    """Remove expired shared results."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM shared_results WHERE expires_at < CURRENT_TIMESTAMP')
    deleted = cursor.rowcount
    conn.commit()
    conn.close()
    return deleted


def get_shared_results_expiry_days():
    """Get the configured expiry days for shared results."""
    return int(get_setting('shared_results_expiry_days', '30'))


# ============================================
# Settings Helper Functions
# ============================================

def get_setting(key, default=None):
    """Get a setting value from the database."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM settings WHERE key = ?", (key,))
    row = cursor.fetchone()
    conn.close()
    return row['value'] if row else default


def set_setting(key, value):
    """Set a setting value in the database."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT OR REPLACE INTO settings (key, value, updated_at) 
        VALUES (?, ?, CURRENT_TIMESTAMP)
    ''', (key, value))
    conn.commit()
    conn.close()


def get_feed_config_path():
    """Get the path to feed_config.json -- lives in /app with binary."""
    return '/app/feed_config.json'


# ============================================
# Scalability Settings
# ============================================

def get_max_unique_values():
    """Get the maximum number of unique values to track per column in statistics.
    
    This prevents memory exhaustion when processing files with high-cardinality columns.
    Default: 10000
    """
    try:
        return int(get_setting('max_unique_values', '10000'))
    except (ValueError, TypeError):
        return 10000


def get_max_adhoc_ips():
    """Get the maximum number of IPs allowed for ad-hoc enrichment.
    
    This prevents users from accidentally overloading the system with very large
    paste operations. File-based enrichment is not limited.
    Default: 1000
    """
    try:
        return int(get_setting('max_adhoc_ips', '1000'))
    except (ValueError, TypeError):
        return 1000


def get_large_file_warning_threshold():
    """Get the row count threshold for showing large file warnings.
    
    When results exceed this threshold, a warning is shown to users about
    potential browser performance issues.
    Default: 10000
    """
    try:
        return int(get_setting('large_file_warning_threshold', '10000'))
    except (ValueError, TypeError):
        return 10000


def get_max_url_fetch_size_mb():
    """Get the maximum URL fetch size in MB for IOC extraction.
    
    Default: 10
    """
    try:
        return int(get_setting('max_url_fetch_size_mb', '10'))
    except (ValueError, TypeError):
        return 10


# ============================================
# LogBoost Docker-mode Helpers
# ============================================

def _parse_logboost_tag(tag: str) -> tuple:
    """Parse 'prod_1_5_0' -> (1, 5, 0). Returns (0,) on parse failure."""
    try:
        parts = tag.replace('prod_', '').split('_')
        return tuple(int(p) for p in parts)
    except (ValueError, AttributeError):
        return (0,)


def _is_newer_logboost_tag(latest: str, current: str) -> bool:
    """Compare prod_X_Y_Z tags. Returns True if latest > current."""
    return _parse_logboost_tag(latest) > _parse_logboost_tag(current)


def get_effective_logboost_path() -> str:
    """Get the effective LogBoost binary path, preferring override if it exists.

    Priority:
    1. /data/bin/logboost if logboost_override_path setting exists AND file exists
    2. LOGBOOST_PATH env var (default: /usr/local/bin/logboost, the bundled binary)
    """
    try:
        override_path = get_setting('logboost_override_path')
        if override_path and Path(override_path).exists():
            return override_path
    except Exception:
        pass  # DB not ready yet at startup -- fall through to env var
    return os.environ.get('LOGBOOST_PATH', '/usr/local/bin/logboost')


# ============================================
# LogBoost Setup Routes
# ============================================

@admin_bp.route('/setup')
@admin_required
def setup():
    """LogBoost Setup page -- Docker mode."""
    binary_path = get_effective_logboost_path()
    binary_exists = Path(binary_path).exists()
    override_path = get_setting('logboost_override_path')
    override_active = bool(override_path and Path(override_path).exists())
    installed_version = get_setting('logboost_installed_version', BUNDLED_LOGBOOST_VERSION)
    last_checked = get_setting('github_latest_checked', None)
    cached_latest = get_setting('github_latest_version', None)

    return render_template('admin/setup.html',
        bundled_version=BUNDLED_LOGBOOST_VERSION,
        binary_path=binary_path,
        binary_exists=binary_exists,
        override_active=override_active,
        installed_version=installed_version,
        last_checked=last_checked,
        cached_latest=cached_latest)


@admin_bp.route('/api/setup/status')
@admin_required
def get_setup_status():
    """Get current LogBoost setup status -- Docker mode."""
    binary_path = get_effective_logboost_path()
    override_setting = get_setting('logboost_override_path')
    return jsonify({
        'binary_path': binary_path,
        'binary_exists': Path(binary_path).exists(),
        'bundled_version': BUNDLED_LOGBOOST_VERSION,
        'installed_version': get_setting('logboost_installed_version', BUNDLED_LOGBOOST_VERSION),
        'override_active': bool(override_setting and Path(override_setting).exists()),
        'last_checked': get_setting('github_latest_checked', None),
        'cached_latest': get_setting('github_latest_version', None)
    })


@admin_bp.route('/api/setup/check-update')
@admin_required
def check_logboost_update():
    """Check GitHub releases API for a newer LogBoost version."""
    try:
        resp = requests.get(
            GITHUB_RELEASES_API,
            timeout=10,
            headers={'Accept': 'application/vnd.github+json'}
        )
        if resp.status_code == 403:
            return jsonify({'error': 'GitHub API rate limited. Try again later.'}), 429
        resp.raise_for_status()
        data = resp.json()
        tag_name = data.get('tag_name', '')

        # Cache result
        checked_at = datetime.now().isoformat()
        set_setting('github_latest_version', tag_name)
        set_setting('github_latest_checked', checked_at)

        installed_version = get_setting('logboost_installed_version', BUNDLED_LOGBOOST_VERSION)
        update_available = _is_newer_logboost_tag(tag_name, installed_version)

        return jsonify({
            'latest_tag': tag_name,
            'installed_version': installed_version,
            'update_available': update_available,
            'release_url': data.get('html_url', ''),
            'checked_at': checked_at
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/setup/install-update', methods=['POST'])
@admin_required
def install_logboost_update():
    """Download and install the latest LogBoost binary from GitHub."""
    latest_tag = get_setting('github_latest_version')
    if not latest_tag:
        return jsonify({'error': 'Run Check for Updates first'}), 400

    download_url = f'https://github.com/joeavanzato/LogBoost/releases/download/{latest_tag}/logboost_linux_amd64.zip'
    try:
        resp = requests.get(download_url, timeout=120)
        resp.raise_for_status()

        with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
            # Find the binary inside the zip (not a directory entry)
            binary_name = next(
                (n for n in zf.namelist()
                 if not zf.getinfo(n).is_dir() and n.lower().rstrip('/').endswith('logboost')),
                None
            )
            if not binary_name:
                return jsonify({'error': 'Could not find logboost binary in downloaded zip'}), 500

            os.makedirs('/data/bin', exist_ok=True)
            dest_path = '/data/bin/logboost'
            with open(dest_path, 'wb') as f:
                f.write(zf.read(binary_name))

        os.chmod(dest_path, 0o755)

        # Update module global and settings
        global LOGBOOST_BINARY
        LOGBOOST_BINARY = dest_path
        set_setting('logboost_override_path', dest_path)
        set_setting('logboost_installed_version', latest_tag)

        return jsonify({'success': True, 'path': dest_path, 'version': latest_tag})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================
# Threat Intel Routes
# ============================================

@admin_bp.route('/threat-intel')
@admin_required
def threat_intel():
    """Threat Intel feeds management page."""
    feed_config_path = get_feed_config_path()

    feeds = []
    error = None

    if not os.path.isfile(feed_config_path):
        error = 'feed_config.json not found at /data/config/feed_config.json. It will be created when you add your first feed.'
    else:
        try:
            with open(feed_config_path, 'r') as f:
                data = json.load(f)
                feeds = data.get('feeds', [])
        except json.JSONDecodeError as e:
            error = f'Invalid JSON in feed_config.json: {str(e)}'
        except Exception as e:
            error = f'Error reading feed_config.json: {str(e)}'

    # Get unique tags for suggestion
    all_tags = set()
    for feed in feeds:
        for tag in feed.get('type', []):
            all_tags.add(tag)

    return render_template('admin/threat_intel.html',
                           feeds=feeds,
                           error=error,
                           all_tags=sorted(all_tags),
                           logboost_path=get_effective_logboost_path())


@admin_bp.route('/api/threat-intel/feeds', methods=['GET'])
@admin_required
def get_feeds():
    """Get all threat intel feeds."""
    feed_config_path = get_feed_config_path()
    
    if not feed_config_path or not os.path.isfile(feed_config_path):
        return jsonify({'error': 'feed_config.json not found'}), 404
    
    try:
        with open(feed_config_path, 'r') as f:
            data = json.load(f)
            return jsonify({'feeds': data.get('feeds', [])})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/threat-intel/feeds', methods=['POST'])
@admin_required
def save_feeds():
    """Save all threat intel feeds."""
    feed_config_path = get_feed_config_path()
    
    if not feed_config_path:
        return jsonify({'error': 'LogBoost path not configured'}), 400
    
    data = request.get_json()
    feeds = data.get('feeds', [])
    
    try:
        # Validate feed structure
        for feed in feeds:
            if not feed.get('name'):
                return jsonify({'error': 'Each feed must have a name'}), 400
            if not feed.get('url'):
                return jsonify({'error': 'Each feed must have a URL'}), 400
            if not isinstance(feed.get('type', []), list):
                feed['type'] = [feed.get('type', 'suspicious')]
        
        # Save to file
        with open(feed_config_path, 'w') as f:
            json.dump({'feeds': feeds}, f, indent='\t')
        
        log_audit('intel_feeds_modified', 'intel_feed', None, {'feed_count': len(feeds)})
        return jsonify({'success': True, 'count': len(feeds)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/threat-intel/feed/<int:index>', methods=['PUT'])
@admin_required
def update_feed(index):
    """Update a single feed by index."""
    feed_config_path = get_feed_config_path()
    
    if not feed_config_path or not os.path.isfile(feed_config_path):
        return jsonify({'error': 'feed_config.json not found'}), 404
    
    data = request.get_json()
    
    try:
        with open(feed_config_path, 'r') as f:
            config = json.load(f)
        
        feeds = config.get('feeds', [])
        
        if index < 0 or index >= len(feeds):
            return jsonify({'error': 'Feed index out of range'}), 400
        
        # Update feed fields
        if 'name' in data:
            feeds[index]['name'] = data['name']
        if 'url' in data:
            feeds[index]['url'] = data['url']
        if 'type' in data:
            feeds[index]['type'] = data['type'] if isinstance(data['type'], list) else [data['type']]
        
        # Save back
        with open(feed_config_path, 'w') as f:
            json.dump({'feeds': feeds}, f, indent='\t')
        
        log_audit('intel_feed_updated', 'intel_feed', feeds[index].get('name'), {'index': index})
        return jsonify({'success': True, 'feed': feeds[index]})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/threat-intel/feed/<int:index>', methods=['DELETE'])
@admin_required
def delete_feed(index):
    """Delete a feed by index."""
    feed_config_path = get_feed_config_path()
    
    if not feed_config_path or not os.path.isfile(feed_config_path):
        return jsonify({'error': 'feed_config.json not found'}), 404
    
    try:
        with open(feed_config_path, 'r') as f:
            config = json.load(f)
        
        feeds = config.get('feeds', [])
        
        if index < 0 or index >= len(feeds):
            return jsonify({'error': 'Feed index out of range'}), 400
        
        deleted_feed = feeds.pop(index)
        
        # Save back
        with open(feed_config_path, 'w') as f:
            json.dump({'feeds': feeds}, f, indent='\t')
        
        log_audit('intel_feed_deleted', 'intel_feed', deleted_feed.get('name'), {'index': index})
        return jsonify({'success': True, 'deleted': deleted_feed['name']})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/threat-intel/feed', methods=['POST'])
@admin_required
def add_feed():
    """Add a new feed."""
    feed_config_path = get_feed_config_path()
    
    if not feed_config_path:
        return jsonify({'error': 'LogBoost path not configured'}), 400
    
    data = request.get_json()
    
    if not data.get('name'):
        return jsonify({'error': 'Feed name is required'}), 400
    if not data.get('url'):
        return jsonify({'error': 'Feed URL is required'}), 400
    
    new_feed = {
        'name': data['name'],
        'url': data['url'],
        'type': data.get('type', ['suspicious']) if isinstance(data.get('type'), list) else [data.get('type', 'suspicious')]
    }
    
    try:
        # Read existing config or create new
        if os.path.isfile(feed_config_path):
            with open(feed_config_path, 'r') as f:
                config = json.load(f)
        else:
            config = {'feeds': []}
        
        feeds = config.get('feeds', [])
        feeds.append(new_feed)
        
        # Save back
        with open(feed_config_path, 'w') as f:
            json.dump({'feeds': feeds}, f, indent='\t')
        
        log_audit('intel_feed_added', 'intel_feed', new_feed['name'], {'url': new_feed['url']})
        return jsonify({'success': True, 'feed': new_feed, 'index': len(feeds) - 1})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/threat-intel/test-feed', methods=['POST'])
@admin_required
def test_feed():
    """Probe a feed URL for connectivity without downloading the full body.

    Tries HEAD first; falls back to a Range GET (first 1KB) if HEAD is
    rejected with 405/501. Validates against SSRF rules before any request.
    """
    from security import validate_url_for_ssrf

    payload = request.get_json(silent=True) or {}
    url = (payload.get('url') or '').strip()

    if not url:
        return jsonify({'ok': False, 'error': 'URL is required', 'status_code': None, 'elapsed_ms': 0}), 400

    is_valid, ssrf_error = validate_url_for_ssrf(url)
    if not is_valid:
        return jsonify({'ok': False, 'error': ssrf_error, 'status_code': None, 'elapsed_ms': 0}), 200

    headers = {'User-Agent': 'LogBoost/1.0 connectivity-probe'}
    timeout = 5
    started = time.monotonic()

    def _elapsed():
        return int((time.monotonic() - started) * 1000)

    try:
        resp = requests.head(url, headers=headers, timeout=timeout, allow_redirects=True)
        method = 'HEAD'

        if resp.status_code in (405, 501):
            range_headers = dict(headers)
            range_headers['Range'] = 'bytes=0-1023'
            resp = requests.get(url, headers=range_headers, timeout=timeout,
                                allow_redirects=True, stream=True)
            try:
                next(resp.iter_content(2048), b'')
            finally:
                resp.close()
            method = 'GET-Range'

        cl_header = resp.headers.get('Content-Length', '')
        content_length = int(cl_header) if cl_header.isdigit() else None
        ok = 200 <= resp.status_code < 400

        return jsonify({
            'ok': ok,
            'status_code': resp.status_code,
            'content_length': content_length,
            'content_type': resp.headers.get('Content-Type'),
            'elapsed_ms': _elapsed(),
            'method': method,
            'error': None if ok else f'HTTP {resp.status_code}',
        }), 200
    except requests.exceptions.Timeout:
        return jsonify({'ok': False, 'error': f'Timeout after {timeout}s',
                        'status_code': None, 'elapsed_ms': _elapsed()}), 200
    except requests.exceptions.SSLError as e:
        return jsonify({'ok': False, 'error': f'SSL error: {str(e)[:120]}',
                        'status_code': None, 'elapsed_ms': _elapsed()}), 200
    except requests.exceptions.ConnectionError as e:
        return jsonify({'ok': False, 'error': f'Connection error: {str(e)[:120]}',
                        'status_code': None, 'elapsed_ms': _elapsed()}), 200
    except Exception as e:
        return jsonify({'ok': False, 'error': f'{type(e).__name__}: {str(e)[:120]}',
                        'status_code': None, 'elapsed_ms': _elapsed()}), 200


def init_admin(app, csrf=None):
    """Initialize admin module with Flask app.

    Args:
        app: Flask application
        csrf: CSRFProtect instance (optional, kept for backwards compatibility)
    """
    # Initialize database
    init_db()

    # Resolve LogBoost binary override from settings (after DB is ready)
    global LOGBOOST_BINARY
    try:
        override_path = get_setting('logboost_override_path')
        if override_path and Path(override_path).exists():
            LOGBOOST_BINARY = override_path
            logger.info(f"LogBoost binary override active: {override_path}")
    except Exception:
        pass  # DB not ready or setting absent -- use env var default

    # Register blueprint
    app.register_blueprint(admin_bp)

    # Start scheduler
    scheduler.start()
