"""Happy-path checks for the audit fix wave, phase 1 (login, sessions, accounts, setup)."""
import hashlib
import time

import pytest


def _add_user(username='alice', password='correct-horse', role='user', password_hash=None):
    import admin
    with admin.db() as conn:
        cur = conn.execute('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
                           (username, password_hash or admin.hash_password(password), role))
        conn.commit()
        return cur.lastrowid


def _login(client, username='alice', password='correct-horse'):
    return client.post('/login', data={'username': username, 'password': password})


@pytest.mark.usefixtures('admin_exists')
class TestLogin:
    def test_lockout_after_five_failures(self, client):
        _add_user()
        for _ in range(5):
            assert _login(client, password='wrong').status_code == 200
        # Even the right password is refused while locked out
        assert _login(client).status_code == 429

    def test_legacy_hash_logs_in_and_is_upgraded(self, client):
        import admin
        legacy = 'aa' * 16 + ':' + hashlib.pbkdf2_hmac('sha256', b'correct-horse', ('aa' * 16).encode(), 100_000).hex()
        user_id = _add_user(password_hash=legacy)
        assert _login(client).status_code == 302
        with admin.db() as conn:
            stored = conn.execute('SELECT password_hash FROM users WHERE id = ?', (user_id,)).fetchone()[0]
        assert stored.startswith(f'pbkdf2${admin.PBKDF2_ITERATIONS}$')

    def test_disabled_account_cannot_log_in(self, client):
        import admin
        user_id = _add_user()
        with admin.db() as conn:
            conn.execute('UPDATE users SET is_active = 0 WHERE id = ?', (user_id,))
            conn.commit()
        assert _login(client).status_code == 200  # back on the login page, not redirected in


@pytest.mark.usefixtures('admin_exists')
class TestSessions:
    def test_password_change_signs_out_other_sessions(self, app):
        _add_user()
        here, elsewhere = app.test_client(), app.test_client()
        _login(here)
        _login(elsewhere)

        response = here.post('/account/password', data={
            'current_password': 'correct-horse', 'new_password': 'new-password-1', 'confirm_password': 'new-password-1'})
        assert response.status_code == 302

        assert here.get('/api/graph/list').status_code == 200        # this session survives
        assert elsewhere.get('/api/graph/list').status_code == 302   # the other is signed out
        assert _login(app.test_client(), password='new-password-1').status_code == 302

    def test_session_expires_after_seven_days(self, client):
        _add_user()
        _login(client)
        with client.session_transaction() as sess:
            sess['login_at'] = time.time() - 8 * 24 * 3600
        assert client.get('/api/graph/list').status_code == 302

    def test_admin_can_disable_and_enable_account(self, admin_client, app):
        user_id = _add_user()
        user = app.test_client()
        _login(user)

        admin_client.post(f'/admin/accounts/{user_id}/active', data={'active': '0'})
        assert user.get('/api/graph/list').status_code == 302  # signed out immediately

        admin_client.post(f'/admin/accounts/{user_id}/active', data={'active': '1'})
        assert _login(app.test_client()).status_code == 302


class TestSetup:
    def test_setup_requires_token(self, client, test_db):
        import admin
        form = {'username': 'root', 'password': 'first-password', 'confirm_password': 'first-password'}

        client.post('/setup', data={**form, 'setup_token': 'wrong'})
        assert admin.needs_setup()

        response = client.post('/setup', data={**form, 'setup_token': admin.get_setup_token()})
        assert response.status_code == 302
        assert not admin.needs_setup()
