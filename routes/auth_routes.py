"""
Authentication routes - first-run setup, login, logout, self-service password change.
"""

import hmac
import time
import uuid

from flask import Blueprint, request, session, redirect, url_for, flash, render_template
from admin import (
    db, verify_password, hash_password, needs_rehash, ROLE_ADMIN, log_audit, needs_setup,
    get_setup_token, set_setting, login_blocked, record_login_failure, clear_login_failures,
)
from auth import login_required


auth_routes_bp = Blueprint('auth_routes', __name__)

# Verified against when the username is unknown, so response time does not reveal which names exist.
_DUMMY_HASH = hash_password(uuid.uuid4().hex)


def _password_errors(password, confirm_password):
    errors = []
    if not password or len(password) < 8:
        errors.append('Password must be at least 8 characters')
    if password != confirm_password:
        errors.append('Passwords do not match')
    return errors


@auth_routes_bp.route('/setup', methods=['GET', 'POST'])
def setup():
    """First-user setup - create initial admin account."""
    # If setup already complete, redirect to login
    if not needs_setup():
        return redirect(url_for('auth_routes.login'))

    setup_token = get_setup_token()  # also (re)writes it to the server log

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        errors = []
        if not hmac.compare_digest(request.form.get('setup_token', '').strip().encode(), setup_token.encode()):
            errors.append('Invalid setup token. Find it in the server log (docker logs <container>).')
        if not username or len(username) < 3:
            errors.append('Username must be at least 3 characters')
        errors += _password_errors(password, request.form.get('confirm_password', ''))

        if errors:
            for error in errors:
                flash(error, 'error')
            return render_template('setup_admin.html', username=username)

        try:
            with db() as conn:
                # One write transaction for check + insert, so two simultaneous
                # setup requests cannot both create an admin.
                conn.isolation_level = None
                conn.execute('BEGIN IMMEDIATE')
                if conn.execute('SELECT COUNT(*) FROM users WHERE role = ?', (ROLE_ADMIN,)).fetchone()[0]:
                    conn.execute('ROLLBACK')
                    return redirect(url_for('auth_routes.login'))
                conn.execute(
                    'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
                    (username, hash_password(password), ROLE_ADMIN)
                )
                conn.execute('COMMIT')
        except Exception:
            flash('Failed to create account', 'error')
            return render_template('setup_admin.html', username=username)

        set_setting('setup_token', '')
        log_audit('setup_complete', 'user', None, {'admin_username': username}, success=True)
        flash('Admin account created. Please log in.', 'success')
        return redirect(url_for('auth_routes.login'))

    return render_template('setup_admin.html')


@auth_routes_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Main login page."""
    # Redirect to setup if no admin exists.
    # Clear any stale session first - the DB may have been wiped.
    if needs_setup():
        if session.get('logged_in'):
            session.clear()
        return redirect(url_for('auth_routes.setup'))

    if session.get('logged_in'):
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        ip = request.remote_addr or ''

        if login_blocked(username, ip):
            log_audit('login_throttled', 'user', None, {'attempted_username': username},
                      success=False, username=username)
            flash('Too many failed attempts. Try again in 15 minutes.', 'error')
            return render_template('login.html'), 429

        with db() as conn:
            user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

            # Always run the hash, even for unknown users, so timing is the same either way.
            password_ok = verify_password(password, user['password_hash'] if user else _DUMMY_HASH)

            if user and password_ok and user['is_active']:
                if needs_rehash(user['password_hash']):
                    conn.execute('UPDATE users SET password_hash = ? WHERE id = ?',
                                 (hash_password(password), user['id']))
                    conn.commit()

        if user and password_ok and user['is_active']:
            clear_login_failures(username, ip)
            session.clear()
            session['logged_in'] = True
            session['username'] = username
            session['user_id'] = user['id']
            session['user_role'] = user['role']
            session['sv'] = user['session_version']
            session['login_at'] = time.time()
            session['session_id'] = str(uuid.uuid4())  # names this session's upload/output dirs

            log_audit('login', 'user', str(user['id']), {'role': user['role']}, success=True)

            # Redirect admins to admin panel, users to main app
            if user['role'] == ROLE_ADMIN:
                return redirect(url_for('admin.dashboard'))
            return redirect(url_for('index'))

        record_login_failure(username, ip)
        log_audit('login_failed', 'user', None, {'attempted_username': username},
                  success=False, user_id=None, username=username)
        flash('Invalid username or password', 'error')

    return render_template('login.html')


@auth_routes_bp.route('/logout', methods=['POST'])
def logout():
    """Logout user."""
    # Import cleanup_session here to avoid circular imports
    # It's defined in app.py and uses app-level config
    from app import cleanup_session

    # Log logout before clearing session
    log_audit('logout', 'user', str(session.get('user_id', '')))

    # Clean up session directories to prevent disk space accumulation
    session_id = session.get('session_id')
    if session_id:
        cleanup_session(session_id)

    session.clear()
    return redirect(url_for('auth_routes.login'))


@auth_routes_bp.route('/account/password', methods=['GET', 'POST'])
@login_required
def account_password():
    """Any logged-in user changes their own password."""
    if request.method == 'POST':
        user_id = session['user_id']
        username = session.get('username', '')
        ip = request.remote_addr or ''
        new_password = request.form.get('new_password', '')

        if login_blocked(username, ip):
            flash('Too many failed attempts. Try again in 15 minutes.', 'error')
            return render_template('login.html', change_password=True), 429

        with db() as conn:
            row = conn.execute('SELECT password_hash FROM users WHERE id = ?', (user_id,)).fetchone()
            errors = _password_errors(new_password, request.form.get('confirm_password', ''))
            if not verify_password(request.form.get('current_password', ''), row['password_hash']):
                record_login_failure(username, ip)
                errors.insert(0, 'Current password is incorrect')

            if not errors:
                # Bumping session_version signs out this user's other sessions; keep this one.
                conn.execute(
                    '''UPDATE users SET password_hash = ?, session_version = session_version + 1,
                       updated_at = CURRENT_TIMESTAMP WHERE id = ?''',
                    (hash_password(new_password), user_id))
                conn.commit()
                session['sv'] = session.get('sv', 0) + 1

        if not errors:
            log_audit('account_password_changed', 'user', username, {'by_admin': False})
            flash('Password updated. Other sessions have been signed out.', 'success')
            return redirect(url_for('index'))
        for error in errors:
            flash(error, 'error')

    return render_template('login.html', change_password=True)
