"""
Authentication module.

Contains the login_required and admin_required decorators for protecting routes.
Login/logout routes are in routes/auth_routes.py.

Both decorators validate users against the database on every request.
This ensures stale session cookies (e.g. after a DB wipe) cannot grant access.
"""

from functools import wraps
from flask import session, redirect, url_for, flash


def login_required(f):
    """Decorator to require any logged-in user.

    Validates the session user ID against the database on every request.
    If the user no longer exists (e.g. after a DB wipe), the session is
    cleared and the user is redirected to login.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Quick reject: no session flag at all
        if not session.get('logged_in'):
            return redirect(url_for('auth_routes.login'))

        # DB validation: confirm user still exists
        user_id = session.get('user_id')
        # Lazy import to avoid circular dependency (admin imports auth)
        from admin import get_db
        conn = get_db()
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT id, role FROM users WHERE id = ?', (user_id,))
            user = cursor.fetchone()
        finally:
            conn.close()

        if not user:
            # User no longer exists - stale session
            session.clear()
            return redirect(url_for('auth_routes.login'))

        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """Decorator to require admin role.

    Validates the session user ID against the database on every request,
    then checks that the user has the admin role.
    If the user no longer exists (e.g. after a DB wipe), the session is
    cleared and the user is redirected to login.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Quick reject: no session flag at all
        if not session.get('logged_in'):
            return redirect(url_for('auth_routes.login'))

        # DB validation: confirm user still exists and has admin role
        user_id = session.get('user_id')
        # Lazy import to avoid circular dependency (admin imports auth)
        from admin import get_db, ROLE_ADMIN
        conn = get_db()
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT id, role FROM users WHERE id = ?', (user_id,))
            user = cursor.fetchone()
        finally:
            conn.close()

        if not user:
            # User no longer exists - stale session
            session.clear()
            return redirect(url_for('auth_routes.login'))

        if user['role'] != ROLE_ADMIN:
            flash('Admin access required', 'error')
            return redirect(url_for('index'))

        return f(*args, **kwargs)
    return decorated_function
