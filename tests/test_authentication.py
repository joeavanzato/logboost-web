"""
Tests for authentication functionality.

Tests cover:
- Password hashing and verification
- Login flow (success and failure)
- Logout flow
- Session management
- login_required decorator
- admin_required decorator
- Account creation validation
- Role-based access control
"""

import pytest
from unittest.mock import patch, Mock


class TestPasswordHashing:
    """Tests for password hashing functions."""
    
    def test_hash_password_returns_salted_hash(self, test_db):
        """hash_password returns pbkdf2$<iterations>$<salt>$<hash>."""
        import admin

        scheme, iterations, salt, digest = admin.hash_password('testpassword123').split('$')
        assert scheme == 'pbkdf2'
        assert int(iterations) == admin.PBKDF2_ITERATIONS
        assert len(salt) == 32   # 16 random bytes, hex
        assert len(digest) == 64  # SHA-256, hex

    def test_hash_password_unique_salts(self, test_db):
        """Test that hashing same password twice produces different hashes."""
        import admin
        
        password = 'samepassword'
        hash1 = admin.hash_password(password)
        hash2 = admin.hash_password(password)
        
        # Different salts should produce different hashes
        assert hash1 != hash2
    
    def test_verify_password_correct(self, test_db):
        """Test that verify_password returns True for correct password."""
        import admin
        
        password = 'correctpassword'
        hashed = admin.hash_password(password)
        
        assert admin.verify_password(password, hashed) == True
    
    def test_verify_password_incorrect(self, test_db):
        """Test that verify_password returns False for incorrect password."""
        import admin
        
        password = 'correctpassword'
        hashed = admin.hash_password(password)
        
        assert admin.verify_password('wrongpassword', hashed) == False
    
    def test_verify_password_empty_password(self, test_db):
        """Test verify_password with empty password."""
        import admin
        
        hashed = admin.hash_password('somepassword')
        
        assert admin.verify_password('', hashed) == False
    
    def test_verify_password_invalid_hash_format(self, test_db):
        """Test verify_password with invalid hash format returns False."""
        import admin
        
        # Missing colon separator
        assert admin.verify_password('password', 'invalidhash') == False
        
        # Empty string
        assert admin.verify_password('password', '') == False
        
        # None-like
        assert admin.verify_password('password', 'none') == False
    
    def test_verify_password_handles_exceptions(self, test_db):
        """Test that verify_password handles exceptions gracefully."""
        import admin
        
        # Various malformed inputs should return False, not raise
        assert admin.verify_password('password', ':') == False
        assert admin.verify_password('password', 'a:b:c') == False
    
    def test_hash_password_special_characters(self, test_db):
        """Test hashing passwords with special characters."""
        import admin
        
        special_passwords = [
            'pass@word!123',
            'пароль',  # Russian
            '密码',    # Chinese
            'p@$$w0rd!@#$%^&*()',
            'password with spaces',
        ]
        
        for password in special_passwords:
            hashed = admin.hash_password(password)
            assert admin.verify_password(password, hashed) == True


@pytest.mark.usefixtures('admin_exists')
class TestLoginFlow:
    """Tests for login functionality."""
    
    def test_login_page_renders(self, client):
        """Test that login page renders for unauthenticated users."""
        response = client.get('/login')
        assert response.status_code == 200
        assert b'login' in response.data.lower() or b'Login' in response.data
    
    def test_login_redirects_when_logged_in(self, authenticated_client):
        """Test that login page redirects when already logged in."""
        response = authenticated_client.get('/login')
        assert response.status_code == 302  # Redirect
    
    def test_login_success_admin(self, client, test_db):
        """Test successful login as admin."""
        import admin
        
        # Create admin user
        conn = admin.get_db()
        cursor = conn.cursor()
        password_hash = admin.hash_password('adminpass123')
        cursor.execute(
            'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
            ('adminuser', password_hash, 'admin')
        )
        conn.commit()
        conn.close()
        
        # Attempt login
        response = client.post('/login', data={
            'username': 'adminuser',
            'password': 'adminpass123'
        }, follow_redirects=False)
        
        # Should redirect to admin dashboard
        assert response.status_code == 302
        assert '/admin' in response.location
        
        # Check session
        with client.session_transaction() as sess:
            assert sess['logged_in'] == True
            assert sess['username'] == 'adminuser'
            assert sess['user_role'] == 'admin'
    
    def test_login_success_user(self, client, test_db):
        """Test successful login as regular user."""
        import admin
        
        # Create regular user
        conn = admin.get_db()
        cursor = conn.cursor()
        password_hash = admin.hash_password('userpass123')
        cursor.execute(
            'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
            ('regularuser', password_hash, 'user')
        )
        conn.commit()
        conn.close()
        
        # Attempt login
        response = client.post('/login', data={
            'username': 'regularuser',
            'password': 'userpass123'
        }, follow_redirects=False)
        
        # Should redirect to index (main app)
        assert response.status_code == 302
        
        # Check session
        with client.session_transaction() as sess:
            assert sess['logged_in'] == True
            assert sess['username'] == 'regularuser'
            assert sess['user_role'] == 'user'
    
    def test_login_failure_wrong_password(self, client, test_db):
        """Test login failure with wrong password."""
        import admin
        
        # Create user
        conn = admin.get_db()
        cursor = conn.cursor()
        password_hash = admin.hash_password('correctpassword')
        cursor.execute(
            'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
            ('testuser', password_hash, 'user')
        )
        conn.commit()
        conn.close()
        
        # Attempt login with wrong password
        response = client.post('/login', data={
            'username': 'testuser',
            'password': 'wrongpassword'
        }, follow_redirects=True)
        
        # Should stay on login page with error
        assert response.status_code == 200
        assert b'Invalid' in response.data or b'invalid' in response.data
        
        # Check session - should not be logged in
        with client.session_transaction() as sess:
            assert sess.get('logged_in') != True
    
    def test_login_failure_nonexistent_user(self, client, test_db):
        """Test login failure with nonexistent user."""
        response = client.post('/login', data={
            'username': 'nonexistent',
            'password': 'somepassword'
        }, follow_redirects=True)
        
        assert response.status_code == 200
        assert b'Invalid' in response.data or b'invalid' in response.data
        
        with client.session_transaction() as sess:
            assert sess.get('logged_in') != True
    
    def test_login_failure_empty_credentials(self, client, test_db):
        """Test login failure with empty credentials."""
        response = client.post('/login', data={
            'username': '',
            'password': ''
        }, follow_redirects=True)
        
        assert response.status_code == 200
        
        with client.session_transaction() as sess:
            assert sess.get('logged_in') != True


class TestLogoutFlow:
    """Tests for logout functionality."""
    
    def test_logout_clears_session(self, authenticated_client):
        """Test that logout clears the session."""
        # Verify logged in first
        with authenticated_client.session_transaction() as sess:
            assert sess.get('logged_in') == True
        
        # Logout (POST request)
        response = authenticated_client.post('/logout', follow_redirects=False)
        
        assert response.status_code == 302
        assert '/login' in response.location
        
        # Session should be cleared
        with authenticated_client.session_transaction() as sess:
            assert sess.get('logged_in') != True
            assert sess.get('username') is None
    
    def test_logout_redirects_to_login(self, authenticated_client):
        """Test that logout redirects to login page."""
        response = authenticated_client.post('/logout', follow_redirects=True)
        
        assert response.status_code == 200
        # Should be on login page
        assert b'login' in response.data.lower() or b'Login' in response.data
    
    def test_logout_rejects_get_request(self, authenticated_client):
        """Test that GET requests to logout are rejected."""
        response = authenticated_client.get('/logout')
        assert response.status_code == 405  # Method Not Allowed


class TestLoginRequiredDecorator:
    """Tests for login_required decorator."""
    
    def test_protected_route_redirects_unauthenticated(self, client):
        """Test that protected routes redirect unauthenticated users."""
        # Try to access main app (protected)
        response = client.get('/', follow_redirects=False)
        
        assert response.status_code == 302
        assert '/login' in response.location
    
    def test_protected_route_allows_authenticated(self, authenticated_client):
        """Test that protected routes allow authenticated users."""
        response = authenticated_client.get('/')
        
        # Should not redirect to login
        assert response.status_code == 200


class TestAdminRequiredDecorator:
    """Tests for admin_required decorator."""
    
    def test_admin_route_redirects_unauthenticated(self, client, test_db):
        """Test that admin routes redirect unauthenticated users."""
        response = client.get('/admin/', follow_redirects=False)
        
        assert response.status_code == 302
        assert '/login' in response.location
    
    def test_admin_route_redirects_non_admin(self, client, test_db):
        """Test that admin routes redirect non-admin users."""
        import admin
        
        # Create regular user
        conn = admin.get_db()
        cursor = conn.cursor()
        password_hash = admin.hash_password('userpass')
        cursor.execute(
            'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
            ('regularuser', password_hash, 'user')
        )
        conn.commit()
        conn.close()
        
        # Login as regular user
        with client.session_transaction() as sess:
            sess['logged_in'] = True
            sess['login_at'] = __import__('time').time()
            sess['user_id'] = 1
            sess['username'] = 'regularuser'
            sess['user_role'] = 'user'
        
        # Try to access admin dashboard
        response = client.get('/admin/', follow_redirects=False)
        
        # Should redirect away from admin
        assert response.status_code == 302
        assert '/admin' not in response.location or 'login' in response.location
    
    def test_admin_route_allows_admin(self, authenticated_client):
        """Test that admin routes allow admin users."""
        # authenticated_client has admin role
        response = authenticated_client.get('/admin/')
        
        assert response.status_code == 200


class TestAccountCreation:
    """Tests for account creation validation."""
    
    def test_create_account_success(self, authenticated_client, test_db):
        """Test successful account creation."""
        response = authenticated_client.post('/admin/accounts/create', data={
            'username': 'newuser',
            'password': 'password123',
            'confirm_password': 'password123',
            'role': 'user'
        }, follow_redirects=True)
        
        assert response.status_code == 200
        
        # Verify user was created
        import admin
        conn = admin.get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', ('newuser',))
        user = cursor.fetchone()
        conn.close()
        
        assert user is not None
        assert user['role'] == 'user'
    
    def test_create_account_username_too_short(self, authenticated_client, test_db):
        """Test account creation fails with short username."""
        response = authenticated_client.post('/admin/accounts/create', data={
            'username': 'ab',  # Too short
            'password': 'password123',
            'confirm_password': 'password123',
            'role': 'user'
        }, follow_redirects=True)
        
        assert response.status_code == 200
        assert b'at least 3 characters' in response.data or b'Username' in response.data
    
    def test_create_account_password_too_short(self, authenticated_client, test_db):
        """Test account creation fails with short password."""
        response = authenticated_client.post('/admin/accounts/create', data={
            'username': 'validuser',
            'password': 'short',  # Too short
            'confirm_password': 'short',
            'role': 'user'
        }, follow_redirects=True)
        
        assert response.status_code == 200
        assert b'at least 8 characters' in response.data or b'Password' in response.data
    
    def test_create_account_passwords_dont_match(self, authenticated_client, test_db):
        """Test account creation fails when passwords don't match."""
        response = authenticated_client.post('/admin/accounts/create', data={
            'username': 'validuser',
            'password': 'password123',
            'confirm_password': 'differentpassword',
            'role': 'user'
        }, follow_redirects=True)
        
        assert response.status_code == 200
        assert b'match' in response.data.lower()
    
    def test_create_account_duplicate_username(self, authenticated_client, test_db):
        """Test account creation fails with duplicate username."""
        import admin
        
        # Create existing user
        conn = admin.get_db()
        cursor = conn.cursor()
        password_hash = admin.hash_password('existingpass')
        cursor.execute(
            'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
            ('existinguser', password_hash, 'user')
        )
        conn.commit()
        conn.close()
        
        # Try to create user with same username
        response = authenticated_client.post('/admin/accounts/create', data={
            'username': 'existinguser',
            'password': 'password123',
            'confirm_password': 'password123',
            'role': 'user'
        }, follow_redirects=True)
        
        assert response.status_code == 200
        assert b'already exists' in response.data.lower() or b'exists' in response.data.lower()
    
    def test_create_account_invalid_role_defaults_to_user(self, authenticated_client, test_db):
        """Test that invalid role defaults to user."""
        response = authenticated_client.post('/admin/accounts/create', data={
            'username': 'roletest',
            'password': 'password123',
            'confirm_password': 'password123',
            'role': 'invalid_role'
        }, follow_redirects=True)
        
        assert response.status_code == 200
        
        # Verify user was created with 'user' role
        import admin
        conn = admin.get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT role FROM users WHERE username = ?', ('roletest',))
        user = cursor.fetchone()
        conn.close()
        
        assert user is not None
        assert user['role'] == 'user'
    
    def test_create_admin_account(self, authenticated_client, test_db):
        """Test creating an admin account."""
        response = authenticated_client.post('/admin/accounts/create', data={
            'username': 'newadmin',
            'password': 'adminpass123',
            'confirm_password': 'adminpass123',
            'role': 'admin'
        }, follow_redirects=True)
        
        assert response.status_code == 200
        
        # Verify admin was created
        import admin
        conn = admin.get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT role FROM users WHERE username = ?', ('newadmin',))
        user = cursor.fetchone()
        conn.close()
        
        assert user is not None
        assert user['role'] == 'admin'


@pytest.mark.usefixtures('admin_exists')
class TestSessionManagement:
    """Tests for session management."""
    
    def test_session_contains_required_fields(self, client, test_db):
        """Test that session contains all required fields after login."""
        import admin
        
        # Create user
        conn = admin.get_db()
        cursor = conn.cursor()
        password_hash = admin.hash_password('testpass123')
        cursor.execute(
            'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
            ('sessiontest', password_hash, 'user')
        )
        conn.commit()
        conn.close()
        
        # Login
        client.post('/login', data={
            'username': 'sessiontest',
            'password': 'testpass123'
        })
        
        # Check session
        with client.session_transaction() as sess:
            assert 'logged_in' in sess
            assert 'username' in sess
            assert 'user_id' in sess
            assert 'user_role' in sess
            
            assert sess['logged_in'] == True
            assert sess['username'] == 'sessiontest'
            assert sess['user_role'] == 'user'
            assert sess['user_id'] is not None
    
    def test_session_user_id_matches_database(self, client, test_db):
        """Test that session user_id matches database ID."""
        import admin
        
        # Create user
        conn = admin.get_db()
        cursor = conn.cursor()
        password_hash = admin.hash_password('testpass123')
        cursor.execute(
            'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
            ('idtest', password_hash, 'user')
        )
        conn.commit()
        
        # Get the user ID
        cursor.execute('SELECT id FROM users WHERE username = ?', ('idtest',))
        db_user_id = cursor.fetchone()['id']
        conn.close()
        
        # Login
        client.post('/login', data={
            'username': 'idtest',
            'password': 'testpass123'
        })
        
        # Check session user_id matches
        with client.session_transaction() as sess:
            assert sess['user_id'] == db_user_id


class TestPasswordEdgeCases:
    """Edge case tests for password handling."""
    
    def test_very_long_password(self, test_db):
        """Test handling of very long passwords."""
        import admin
        
        # 1000 character password
        long_password = 'a' * 1000
        hashed = admin.hash_password(long_password)
        
        assert admin.verify_password(long_password, hashed) == True
        assert admin.verify_password(long_password + 'x', hashed) == False
    
    def test_unicode_password(self, test_db):
        """Test handling of unicode passwords."""
        import admin
        
        passwords = [
            '密码测试',      # Chinese
            'пароль123',    # Russian
            '🔐🔑password',  # Emoji
            'Ñoño123',      # Spanish
        ]
        
        for password in passwords:
            hashed = admin.hash_password(password)
            assert admin.verify_password(password, hashed) == True
    
    def test_password_with_null_bytes(self, test_db):
        """Test that passwords with null bytes are handled safely."""
        import admin
        
        # This could be a security issue if not handled properly
        password = 'pass\x00word'
        hashed = admin.hash_password(password)
        
        # Should verify correctly
        assert admin.verify_password(password, hashed) == True
        # Password without null should fail
        assert admin.verify_password('password', hashed) == False


@pytest.mark.usefixtures('admin_exists')
class TestLoginAuditLogging:
    """Tests for audit logging during authentication."""
    
    def test_successful_login_is_logged(self, client, test_db):
        """Test that successful logins are audit logged."""
        import admin
        
        # Create user
        conn = admin.get_db()
        cursor = conn.cursor()
        password_hash = admin.hash_password('testpass123')
        cursor.execute(
            'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
            ('audituser', password_hash, 'user')
        )
        conn.commit()
        conn.close()
        
        # Login
        client.post('/login', data={
            'username': 'audituser',
            'password': 'testpass123'
        })
        
        # Check audit log
        conn = admin.get_db()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM audit_logs WHERE action = 'login' AND username = ?",
            ('audituser',)
        )
        log_entry = cursor.fetchone()
        conn.close()
        
        assert log_entry is not None
        assert log_entry['success'] == 1
    
    def test_failed_login_is_logged(self, client, test_db):
        """Test that failed logins are audit logged."""
        import admin
        
        # Create user
        conn = admin.get_db()
        cursor = conn.cursor()
        password_hash = admin.hash_password('correctpass')
        cursor.execute(
            'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
            ('failuser', password_hash, 'user')
        )
        conn.commit()
        conn.close()
        
        # Attempt login with wrong password
        client.post('/login', data={
            'username': 'failuser',
            'password': 'wrongpassword'
        })
        
        # Check audit log
        conn = admin.get_db()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM audit_logs WHERE action = 'login_failed' AND username = ?",
            ('failuser',)
        )
        log_entry = cursor.fetchone()
        conn.close()
        
        assert log_entry is not None
        assert log_entry['success'] == 0
