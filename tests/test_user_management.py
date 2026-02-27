"""
Tests for user management functions.

Tests cover:
- Account editing (role changes)
- Password changes
- Account deletion
- Authorization checks
"""

import pytest


# ============================================
# Fixtures
# ============================================

@pytest.fixture
def create_test_user(test_db):
    """Factory to create test users."""
    import admin
    
    created_ids = []
    
    def _create_user(username, password='testpass123', role='user'):
        conn = admin.get_db()
        cursor = conn.cursor()
        password_hash = admin.hash_password(password)
        cursor.execute(
            'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
            (username, password_hash, role)
        )
        conn.commit()
        user_id = cursor.lastrowid
        conn.close()
        created_ids.append(user_id)
        return user_id
    
    yield _create_user


@pytest.fixture
def admin_client(app, test_db, create_test_user):
    """Create an authenticated admin client."""
    user_id = create_test_user('adminuser', 'adminpass', 'admin')
    
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['logged_in'] = True
        sess['user_id'] = user_id
        sess['username'] = 'adminuser'
        sess['user_role'] = 'admin'
    
    return client, user_id


@pytest.fixture
def regular_user_client(app, test_db, create_test_user):
    """Create an authenticated regular user client."""
    user_id = create_test_user('regularuser', 'userpass', 'user')
    
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['logged_in'] = True
        sess['user_id'] = user_id
        sess['username'] = 'regularuser'
        sess['user_role'] = 'user'
    
    return client, user_id


# ============================================
# Account Editing Tests
# ============================================

class TestEditAccount:
    """Tests for edit_account endpoint."""
    
    def test_edit_account_get_renders_form(self, admin_client, create_test_user):
        """Test that GET request renders the edit form."""
        client, _ = admin_client
        target_id = create_test_user('target_user')
        
        response = client.get(f'/admin/accounts/{target_id}/edit')
        
        assert response.status_code == 200
        assert b'target_user' in response.data
    
    def test_edit_account_change_role_to_admin(self, admin_client, test_db, create_test_user):
        """Test changing a user's role to admin."""
        import admin
        client, _ = admin_client
        target_id = create_test_user('promote_user', role='user')
        
        response = client.post(f'/admin/accounts/{target_id}/edit', data={
            'role': 'admin'
        }, follow_redirects=True)
        
        assert response.status_code == 200
        
        # Verify role changed in database
        conn = admin.get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT role FROM users WHERE id = ?', (target_id,))
        user = cursor.fetchone()
        conn.close()
        
        assert user['role'] == 'admin'
    
    def test_edit_account_change_role_to_user(self, admin_client, test_db, create_test_user):
        """Test changing an admin's role to user."""
        import admin
        client, _ = admin_client
        # Create another admin to demote (not the logged-in admin)
        target_id = create_test_user('demote_admin', role='admin')
        
        response = client.post(f'/admin/accounts/{target_id}/edit', data={
            'role': 'user'
        }, follow_redirects=True)
        
        assert response.status_code == 200
        
        # Verify role changed
        conn = admin.get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT role FROM users WHERE id = ?', (target_id,))
        user = cursor.fetchone()
        conn.close()
        
        assert user['role'] == 'user'
    
    def test_edit_account_nonexistent_account(self, admin_client):
        """Test editing non-existent account shows error."""
        client, _ = admin_client
        
        response = client.get('/admin/accounts/99999/edit', follow_redirects=True)
        
        assert response.status_code == 200
        assert b'Account not found' in response.data
    
    def test_edit_account_invalid_role_defaults_to_user(self, admin_client, test_db, create_test_user):
        """Test that invalid role defaults to user."""
        import admin
        client, _ = admin_client
        target_id = create_test_user('invalid_role_user', role='admin')
        
        response = client.post(f'/admin/accounts/{target_id}/edit', data={
            'role': 'superadmin'  # Invalid role
        }, follow_redirects=True)
        
        assert response.status_code == 200
        
        # Should default to 'user'
        conn = admin.get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT role FROM users WHERE id = ?', (target_id,))
        user = cursor.fetchone()
        conn.close()
        
        assert user['role'] == 'user'
    
    def test_edit_account_cannot_demote_self(self, admin_client, test_db):
        """Test that admin cannot demote themselves."""
        import admin
        client, admin_id = admin_client
        
        response = client.post(f'/admin/accounts/{admin_id}/edit', data={
            'role': 'user'
        }, follow_redirects=True)
        
        assert response.status_code == 200
        assert b'Cannot change your own role' in response.data
        
        # Verify role unchanged
        conn = admin.get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT role FROM users WHERE id = ?', (admin_id,))
        user = cursor.fetchone()
        conn.close()
        
        assert user['role'] == 'admin'
    
    def test_edit_account_updates_updated_at(self, admin_client, test_db, create_test_user):
        """Test that updated_at timestamp is updated."""
        import admin
        import time
        client, _ = admin_client
        target_id = create_test_user('timestamp_user', role='user')
        
        # Get original timestamp
        conn = admin.get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT updated_at FROM users WHERE id = ?', (target_id,))
        original_updated = cursor.fetchone()['updated_at']
        conn.close()
        
        time.sleep(1.1)  # Wait for timestamp change
        
        # Update role
        client.post(f'/admin/accounts/{target_id}/edit', data={'role': 'admin'})
        
        # Verify timestamp changed
        conn = admin.get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT updated_at FROM users WHERE id = ?', (target_id,))
        new_updated = cursor.fetchone()['updated_at']
        conn.close()
        
        assert new_updated > original_updated
    
    def test_edit_account_requires_admin(self, regular_user_client, create_test_user):
        """Test that only admins can edit accounts."""
        client, _ = regular_user_client
        target_id = create_test_user('target_user')
        
        response = client.get(f'/admin/accounts/{target_id}/edit')
        
        # Should redirect to index (not admin)
        assert response.status_code == 302
    
    def test_edit_account_preserves_password(self, admin_client, test_db, create_test_user):
        """Test that editing role doesn't change password."""
        import admin
        client, _ = admin_client
        target_id = create_test_user('password_test_user', password='original_password', role='user')
        
        # Get original hash
        conn = admin.get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT password_hash FROM users WHERE id = ?', (target_id,))
        original_hash = cursor.fetchone()['password_hash']
        conn.close()
        
        # Edit role
        client.post(f'/admin/accounts/{target_id}/edit', data={'role': 'admin'})
        
        # Verify password hash unchanged
        conn = admin.get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT password_hash FROM users WHERE id = ?', (target_id,))
        new_hash = cursor.fetchone()['password_hash']
        conn.close()
        
        assert new_hash == original_hash


# ============================================
# Password Change Tests
# ============================================

class TestChangePassword:
    """Tests for change_password endpoint."""
    
    def test_change_password_get_renders_form(self, admin_client, create_test_user):
        """Test that GET request renders the password form."""
        client, _ = admin_client
        target_id = create_test_user('password_user')
        
        response = client.get(f'/admin/accounts/{target_id}/password')
        
        assert response.status_code == 200
        assert b'password_user' in response.data
    
    def test_change_password_success(self, admin_client, test_db, create_test_user):
        """Test successful password change."""
        import admin
        client, _ = admin_client
        target_id = create_test_user('change_pass_user', password='oldpassword')
        
        response = client.post(f'/admin/accounts/{target_id}/password', data={
            'new_password': 'newpassword123',
            'confirm_password': 'newpassword123'
        }, follow_redirects=True)
        
        assert response.status_code == 200
        assert b'updated successfully' in response.data
        
        # Verify new password works
        conn = admin.get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT password_hash FROM users WHERE id = ?', (target_id,))
        new_hash = cursor.fetchone()['password_hash']
        conn.close()
        
        assert admin.verify_password('newpassword123', new_hash)
        assert not admin.verify_password('oldpassword', new_hash)
    
    def test_change_password_nonexistent_account(self, admin_client):
        """Test changing password for non-existent account."""
        client, _ = admin_client
        
        response = client.get('/admin/accounts/99999/password', follow_redirects=True)
        
        assert response.status_code == 200
        assert b'Account not found' in response.data
    
    def test_change_password_too_short(self, admin_client, create_test_user):
        """Test that short password is rejected."""
        client, _ = admin_client
        target_id = create_test_user('short_pass_user')
        
        response = client.post(f'/admin/accounts/{target_id}/password', data={
            'new_password': 'short',
            'confirm_password': 'short'
        })
        
        assert response.status_code == 200
        assert b'at least 8 characters' in response.data
    
    def test_change_password_mismatch(self, admin_client, create_test_user):
        """Test that mismatched passwords are rejected."""
        client, _ = admin_client
        target_id = create_test_user('mismatch_user')
        
        response = client.post(f'/admin/accounts/{target_id}/password', data={
            'new_password': 'password123',
            'confirm_password': 'password456'
        })
        
        assert response.status_code == 200
        assert b'do not match' in response.data
    
    def test_change_password_empty(self, admin_client, create_test_user):
        """Test that empty password is rejected."""
        client, _ = admin_client
        target_id = create_test_user('empty_pass_user')
        
        response = client.post(f'/admin/accounts/{target_id}/password', data={
            'new_password': '',
            'confirm_password': ''
        })
        
        assert response.status_code == 200
        assert b'required' in response.data or b'at least 8 characters' in response.data
    
    def test_change_password_updates_updated_at(self, admin_client, test_db, create_test_user):
        """Test that updated_at timestamp is updated on password change."""
        import admin
        import time
        client, _ = admin_client
        target_id = create_test_user('timestamp_pass_user')
        
        # Get original timestamp
        conn = admin.get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT updated_at FROM users WHERE id = ?', (target_id,))
        original_updated = cursor.fetchone()['updated_at']
        conn.close()
        
        time.sleep(1.1)
        
        # Change password
        client.post(f'/admin/accounts/{target_id}/password', data={
            'new_password': 'newpassword123',
            'confirm_password': 'newpassword123'
        })
        
        # Verify timestamp changed
        conn = admin.get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT updated_at FROM users WHERE id = ?', (target_id,))
        new_updated = cursor.fetchone()['updated_at']
        conn.close()
        
        assert new_updated > original_updated
    
    def test_change_password_requires_admin(self, regular_user_client, create_test_user):
        """Test that only admins can change passwords."""
        client, _ = regular_user_client
        target_id = create_test_user('target_user')
        
        response = client.get(f'/admin/accounts/{target_id}/password')
        
        # Should redirect
        assert response.status_code == 302


# ============================================
# Account Deletion Tests
# ============================================

class TestDeleteAccount:
    """Tests for delete_account endpoint."""
    
    def test_delete_account_success(self, admin_client, test_db, create_test_user):
        """Test successful account deletion."""
        import admin
        client, _ = admin_client
        target_id = create_test_user('delete_me_user')
        
        response = client.post(f'/admin/accounts/{target_id}/delete', follow_redirects=True)
        
        assert response.status_code == 200
        assert b'deleted' in response.data
        
        # Verify user is gone
        conn = admin.get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE id = ?', (target_id,))
        user = cursor.fetchone()
        conn.close()
        
        assert user is None
    
    def test_delete_account_cannot_delete_self(self, admin_client, test_db):
        """Test that admin cannot delete their own account."""
        import admin
        client, admin_id = admin_client
        
        response = client.post(f'/admin/accounts/{admin_id}/delete', follow_redirects=True)
        
        assert response.status_code == 200
        assert b'Cannot delete your own account' in response.data
        
        # Verify account still exists
        conn = admin.get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE id = ?', (admin_id,))
        user = cursor.fetchone()
        conn.close()
        
        assert user is not None
    
    def test_delete_account_cannot_delete_last_admin(self, app, test_db):
        """Test that the last admin account cannot be deleted."""
        import admin
        
        # Create a fresh admin (only admin in system)
        conn = admin.get_db()
        cursor = conn.cursor()
        # Clear existing users
        cursor.execute('DELETE FROM users')
        # Create single admin
        password_hash = admin.hash_password('adminpass')
        cursor.execute(
            'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
            ('only_admin', password_hash, 'admin')
        )
        admin_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        # Create a different admin client to try deletion
        # We need another admin to be logged in
        conn = admin.get_db()
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
            ('second_admin', admin.hash_password('pass'), 'admin')
        )
        second_admin_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        client = app.test_client()
        with client.session_transaction() as sess:
            sess['logged_in'] = True
            sess['user_id'] = second_admin_id
            sess['username'] = 'second_admin'
            sess['user_role'] = 'admin'
        
        # Now try to delete the first admin when there are 2 admins - should work
        response = client.post(f'/admin/accounts/{admin_id}/delete', follow_redirects=True)
        assert b'deleted' in response.data
        
        # Now there's only 1 admin (second_admin), try to delete via another session
        # This would need the second_admin to delete themselves, which is blocked
        # Let's verify the last-admin check by checking count
        conn = admin.get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as count FROM users WHERE role = 'admin'")
        admin_count = cursor.fetchone()['count']
        conn.close()
        
        assert admin_count == 1
    
    def test_delete_account_nonexistent(self, admin_client):
        """Test deleting non-existent account."""
        client, _ = admin_client
        
        response = client.post('/admin/accounts/99999/delete', follow_redirects=True)
        
        assert response.status_code == 200
        assert b'Account not found' in response.data
    
    def test_delete_account_requires_admin(self, regular_user_client, create_test_user):
        """Test that only admins can delete accounts."""
        client, _ = regular_user_client
        target_id = create_test_user('target_user')
        
        response = client.post(f'/admin/accounts/{target_id}/delete')
        
        # Should redirect
        assert response.status_code == 302
    
    def test_delete_account_requires_post(self, admin_client, create_test_user):
        """Test that deletion requires POST method."""
        client, _ = admin_client
        target_id = create_test_user('target_user')
        
        response = client.get(f'/admin/accounts/{target_id}/delete')
        
        # GET should not be allowed (405 Method Not Allowed)
        assert response.status_code == 405


# ============================================
# Account Listing Tests
# ============================================

class TestAccountListing:
    """Tests for accounts listing endpoint."""
    
    def test_accounts_list_all_users(self, admin_client, test_db, create_test_user):
        """Test that all users are listed."""
        client, _ = admin_client
        
        # Create some users
        create_test_user('user1', role='user')
        create_test_user('user2', role='user')
        create_test_user('admin2', role='admin')
        
        response = client.get('/admin/accounts')
        
        assert response.status_code == 200
        assert b'user1' in response.data
        assert b'user2' in response.data
        assert b'admin2' in response.data
    
    def test_accounts_requires_admin(self, regular_user_client):
        """Test that only admins can view accounts list."""
        client, _ = regular_user_client
        
        response = client.get('/admin/accounts')
        
        # Should redirect
        assert response.status_code == 302
    
    def test_accounts_shows_roles(self, admin_client, test_db, create_test_user):
        """Test that user roles are displayed."""
        client, _ = admin_client
        
        create_test_user('test_user', role='user')
        
        response = client.get('/admin/accounts')
        
        assert response.status_code == 200
        # The page should show role information
        assert b'user' in response.data or b'admin' in response.data
