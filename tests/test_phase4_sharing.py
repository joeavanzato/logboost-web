"""
Fix wave Phase 4: shared results need a login, carry statistics and a row count, and can be
listed and deleted; graphs are shared explicitly and opened by others as a copy.
"""

import time

import admin


def _user_client(app, username, role='user'):
    """A logged-in test client for a new user. Returns (client, user_id)."""
    conn = admin.get_db()
    cursor = conn.execute('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
                          (username, admin.hash_password('password-123'), role))
    user_id = cursor.lastrowid
    conn.commit()
    conn.close()

    client = app.test_client()
    with client.session_transaction() as sess:
        sess.update(logged_in=True, login_at=time.time(), user_id=user_id, username=username, user_role=role)
    return client, user_id


def _share_results(client, tmp_path):
    """Share a 15-row result file through the API; returns the share ID."""
    path = tmp_path / 'results.csv'
    path.write_text('IP,lb_ThreatCategories\n' + ''.join(f'10.0.0.{i},malware|family{i}\n' for i in range(15)))
    with client.session_transaction() as sess:
        sess['current_output'] = str(path)
    response = client.post('/api/results/share')
    assert response.status_code == 200
    return response.get_json()['share_id']


GRAPH = {'nodes': [{'id': '8.8.8.8', 'type': 'ip'}], 'edges': []}


class TestSharedResults:

    def test_anonymous_is_sent_to_login_and_returns_to_the_share(self, app, test_db, admin_exists, tmp_path):
        owner, _ = _user_client(app, 'owner')
        share_id = _share_results(owner, tmp_path)

        anonymous = app.test_client()
        for url in (f'/shared/results/{share_id}', f'/api/shared/results/{share_id}',
                    f'/api/shared/results/{share_id}/render'):
            response = anonymous.get(url)
            assert response.status_code == 302, url
            assert '/login' in response.location

        # Signing in from the share link lands back on it
        anonymous.get(f'/shared/results/{share_id}')
        response = anonymous.post('/login', data={'username': 'owner', 'password': 'password-123'})
        assert response.status_code == 302
        assert response.location.startswith(f'/shared/results/{share_id}')

    def test_share_stores_rows_stats_and_count_for_other_users(self, app, test_db, tmp_path):
        owner, owner_id = _user_client(app, 'owner')
        viewer, _ = _user_client(app, 'viewer')
        share_id = _share_results(owner, tmp_path)

        assert len(share_id) >= 22  # secrets.token_urlsafe(16): 128 bits
        meta = admin.get_shared_results_meta(share_id)
        assert (meta['user_id'], meta['filename'], meta['row_count']) == (owner_id, 'results.csv', 15)
        assert 'results_data' not in meta

        redirect = viewer.get(f'/shared/results/{share_id}')
        assert redirect.status_code == 302 and f'shared={share_id}' in redirect.location

        data = viewer.get(f'/api/shared/results/{share_id}').get_json()
        assert len(data['results']) == 15
        assert data['stats']['total_rows'] == 15

        page = viewer.get(f'/api/shared/results/{share_id}/render').data.decode()
        assert '10.0.0.14' in page
        assert f'?shared={share_id}' in page  # the Stats tab asks for this share's statistics

        # Stats tab and its value modal work for the viewer, who has no result file of their own
        stats_page = viewer.get(f'/stats?shared={share_id}').data.decode()
        assert '<b class="stat-value">15</b>' in stats_page
        assert 'Threat categories' in stats_page
        values = viewer.get(f'/stats/values/threat_summary/all_categories?shared={share_id}').get_json()
        assert ['malware', 15] in values['values'] and len(values['values']) == 16

    def test_my_shares_lists_and_deletes_by_owner_or_admin(self, app, test_db, tmp_path):
        owner, _ = _user_client(app, 'owner')
        other, _ = _user_client(app, 'other')
        boss, _ = _user_client(app, 'boss', role='admin')
        first = _share_results(owner, tmp_path)
        second = _share_results(owner, tmp_path)

        assert first in owner.get('/shares').data.decode()
        assert first not in other.get('/shares').data.decode()
        admin_page = boss.get('/shares').data.decode()
        assert first in admin_page and 'owner' in admin_page

        # another user cannot delete it
        other.post(f'/shares/{first}/delete')
        assert admin.get_shared_results_meta(first) is not None

        owner.post(f'/shares/{first}/delete')
        assert admin.get_shared_results_meta(first) is None
        assert owner.get(f'/api/shared/results/{first}').status_code == 404

        boss.post(f'/shares/{second}/delete')
        assert admin.get_shared_results_meta(second) is None


class TestSharedGraphs:

    def test_graph_is_private_until_shared_then_opens_as_copy(self, app, test_db):
        owner, _ = _user_client(app, 'owner')
        other, _ = _user_client(app, 'other')
        graph_id = owner.post('/api/graph/save', json={'name': 'Mine', 'data': GRAPH}).get_json()['id']

        assert other.get(f'/api/graph/{graph_id}').status_code == 404

        shared = owner.post(f'/api/graph/{graph_id}/share')
        assert shared.status_code == 200
        assert f'graph={graph_id}' in shared.get_json()['share_url']
        assert owner.get('/api/graph/list').get_json()['graphs'][0]['is_shared'] == 1

        opened = other.get(f'/api/graph/{graph_id}').get_json()
        assert opened['is_owner'] is False
        assert opened['data'] == GRAPH
        assert owner.get(f'/api/graph/{graph_id}').get_json()['is_owner'] is True

        # The other user cannot overwrite, unshare or delete it; saving gives them their own copy
        saved = other.post('/api/graph/save',
                           json={'id': graph_id, 'name': 'Hijacked', 'data': {'nodes': [], 'edges': []}}).get_json()
        assert saved['id'] != graph_id
        assert other.delete(f'/api/graph/{graph_id}/share').status_code == 404
        assert other.delete(f'/api/graph/{graph_id}').status_code == 404
        original = owner.get(f'/api/graph/{graph_id}').get_json()
        assert original['name'] == 'Mine' and original['data'] == GRAPH

        # The owner's own save keeps the graph shared
        owner.post('/api/graph/save', json={'id': graph_id, 'name': 'Mine v2', 'data': GRAPH})
        assert other.get(f'/api/graph/{graph_id}').get_json()['name'] == 'Mine v2'

        # Unsharing closes the link
        assert owner.delete(f'/api/graph/{graph_id}/share').status_code == 200
        assert other.get(f'/api/graph/{graph_id}').status_code == 404
        assert owner.get(f'/api/graph/{graph_id}').status_code == 200


class TestSharingMigration:

    def test_existing_database_gains_new_columns(self, test_db):
        """A database created before this phase is upgraded in place, with row counts backfilled."""
        conn = admin.get_db()
        conn.executescript('''
            DROP TABLE shared_results;
            CREATE TABLE shared_results (
                id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, filename TEXT, results_data TEXT NOT NULL,
                stats_data TEXT, headers TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL);
            INSERT INTO shared_results (id, user_id, filename, results_data, expires_at)
                VALUES ('old-share', 1, 'old.csv', '[["a"], ["b"], ["c"]]', datetime('now', '+1 day'));
            DROP TABLE saved_graphs;
            CREATE TABLE saved_graphs (
                id TEXT PRIMARY KEY, name TEXT NOT NULL, data TEXT NOT NULL, user_id INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
            INSERT INTO saved_graphs (id, name, data, user_id) VALUES ('old-graph', 'Old', '{}', 1);
        ''')
        conn.commit()
        conn.close()

        admin.init_db()

        assert admin.get_shared_results_meta('old-share')['row_count'] == 3
        assert admin.list_graphs(1)[0]['is_shared'] == 0
        assert admin.load_graph('old-graph', user_id=2) is None
