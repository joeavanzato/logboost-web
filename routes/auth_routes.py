"""
Authentication routes - login and logout.
"""

from flask import Blueprint, request, session, redirect, url_for, flash, render_template
from admin import get_db, verify_password, ROLE_ADMIN, log_audit, needs_setup, hash_password


auth_routes_bp = Blueprint('auth_routes', __name__)


@auth_routes_bp.route('/setup', methods=['GET', 'POST'])
def setup():
    """First-user setup - create initial admin account."""
    # If setup already complete, redirect to login
    if not needs_setup():
        return redirect(url_for('auth_routes.login'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        # Validation
        errors = []
        if not username or len(username) < 3:
            errors.append('Username must be at least 3 characters')
        if not password or len(password) < 8:
            errors.append('Password must be at least 8 characters')
        if password != confirm_password:
            errors.append('Passwords do not match')

        if errors:
            for error in errors:
                flash(error, 'error')
            return render_template('setup_admin.html', username=username)

        # Create admin account
        conn = get_db()
        cursor = conn.cursor()
        try:
            password_hash = hash_password(password)
            cursor.execute(
                'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
                (username, password_hash, ROLE_ADMIN)
            )
            conn.commit()
            log_audit('setup_complete', 'user', None, {'admin_username': username}, success=True)
            flash('Admin account created. Please log in.', 'success')
            return redirect(url_for('auth_routes.login'))
        except Exception as e:
            flash(f'Failed to create account: {str(e)}', 'error')
        finally:
            conn.close()

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
