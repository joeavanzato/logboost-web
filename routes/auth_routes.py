"""
Authentication routes - login and logout.
"""

from flask import Blueprint, request, session, redirect, url_for, flash, render_template
from admin import get_db, verify_password, ROLE_ADMIN, log_audit


auth_routes_bp = Blueprint('auth_routes', __name__)


@auth_routes_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Main login page."""
    if session.get('logged_in'):
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()
        
        if user and verify_password(password, user['password_hash']):
            session['logged_in'] = True
            session['username'] = username
            session['user_id'] = user['id']
            session['user_role'] = user['role']
            
            # Log successful login
            log_audit('login', 'user', str(user['id']), {'role': user['role']}, success=True)
            
            # Redirect admins to admin panel, users to main app
            if user['role'] == ROLE_ADMIN:
                return redirect(url_for('admin.dashboard'))
            return redirect(url_for('index'))
        else:
            # Log failed login attempt
            log_audit('login_failed', 'user', None, {'attempted_username': username}, success=False, user_id=None, username=username)
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
