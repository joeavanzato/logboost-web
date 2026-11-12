"""
Authentication module.

Contains the login_required and admin_required decorators for protecting routes.
Login/logout routes are in routes/auth_routes.py.

Every request re-validates the session against the database, so a session stops
working as soon as the account is deleted or disabled, its password changes, or
the session reaches its maximum age.
"""

import time
from functools import wraps
from flask import session, redirect, url_for, flash, request

SESSION_LIFETIME = 7 * 24 * 3600  # seconds from login until the user must sign in again


def current_user():
    """Row for the logged-in user, or None if the session is no longer valid."""
    if not session.get('logged_in'):
        return None
    if time.time() - session.get('login_at', 0) > SESSION_LIFETIME:
        return None

    from admin import db  # lazy: admin imports auth
    with db() as conn:
        user = conn.execute(
            'SELECT id, username, role, is_active, session_version FROM users WHERE id = ?',
            (session.get('user_id'),)
        ).fetchone()

    # Gone, disabled, or signed out everywhere (password change bumps session_version)
    if not user or not user['is_active'] or user['session_version'] != session.get('sv', 0):
        return None
    session['user_role'] = user['role']  # keep the UI in step with role changes
    return user


def _require(admin_only):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = current_user()
            if not user:
                session.clear()
                # A share link opened while signed out: come back to it after login
                if request.method == 'GET' and (request.path.startswith('/shared/results/')
                                                or (request.path == '/' and request.query_string)):
                    session['next'] = request.full_path
                return redirect(url_for('auth_routes.login'))
            if admin_only and user['role'] != 'admin':
                flash('Admin access required', 'error')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


login_required = _require(admin_only=False)
admin_required = _require(admin_only=True)
