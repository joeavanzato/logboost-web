"""
Authentication module.

Contains the login_required decorator for protecting routes.
Login/logout routes are in routes/auth_routes.py.
"""

from functools import wraps
from flask import session, redirect, url_for


def login_required(f):
    """Decorator to require any logged-in user."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('auth_routes.login'))
        return f(*args, **kwargs)
    return decorated_function
