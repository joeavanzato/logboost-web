"""Happy-path checks for the UI redesign, phase 1 (shared layout, sign in, setup, account)."""


def test_sign_in_page_uses_the_local_stylesheet_and_no_external_hosts(client, admin_exists):
    html = client.get('/login').get_data(as_text=True)
    assert '/static/app.css' in html
    assert '/static/js/auth.js' in html
    assert 'fonts.googleapis.com' not in html
    assert '<script>' not in html  # no inline script


def test_setup_works_without_a_confirm_field(client, test_db):
    import admin
    response = client.post('/setup', data={
        'setup_token': admin.get_setup_token(), 'username': 'root', 'password': 'correct-horse-9'})
    assert response.status_code == 302
    with admin.db() as conn:
        assert conn.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'").fetchone()[0] == 1


def test_setup_still_rejects_a_mismatched_confirm_when_one_is_sent(client, test_db):
    import admin
    client.post('/setup', data={'setup_token': admin.get_setup_token(), 'username': 'root',
                                'password': 'correct-horse-9', 'confirm_password': 'something-else'})
    with admin.db() as conn:
        assert conn.execute('SELECT COUNT(*) FROM users').fetchone()[0] == 0


def test_account_page_shows_admin_navigation_and_setup_progress_to_an_admin(admin_client):
    html = admin_client.get('/account/password').get_data(as_text=True)
    assert 'Change password' in html
    assert 'Threat feeds' in html and 'Audit log' in html
    assert 'Finish setup' in html  # a fresh test install has no geo data, threat db or schedules


def test_account_page_hides_admin_navigation_from_a_user(regular_user_client):
    html = regular_user_client.get('/account/password').get_data(as_text=True)
    assert 'Change password' in html
    assert 'Intel browser' in html
    assert 'Audit log' not in html and 'Finish setup' not in html


def test_setup_steps_counts_completed_steps(app, test_db, monkeypatch):
    import admin
    import app as app_module
    monkeypatch.setattr(app_module, 'check_mmdb_files_exist', lambda: (True, []))
    monkeypatch.setattr(app_module, 'check_threat_db_exists', lambda: True)
    with app.app_context():
        with admin.db() as conn:
            conn.execute('UPDATE scheduled_tasks SET enabled = 1')
            conn.commit()
        status = app_module.setup_steps()
    assert status['total'] == 5
    assert status['steps'] == {'admin': True, 'geo': True, 'threat_db': True, 'shodan': False, 'schedules': True}
    assert status['done'] == 4


def test_sidebar_has_a_collapse_toggle_and_an_icon_and_tooltip_per_item(admin_client):
    html = admin_client.get('/account/password').get_data(as_text=True)
    head = html.split('</head>')[0]
    assert '/static/js/sidebar.js' in head  # in the head, so the stored state applies before first paint
    assert 'data-side-toggle' in html
    # every navigation link carries an icon and a title that names it when labels are hidden
    links = [chunk.split('</a>')[0] for chunk in html.split('data-nav="')[1:]]
    assert len(links) == 11
    assert all('<svg class="ico"' in link and 'title="' in link for link in links)
    assert 'title="Sign out"' in html
