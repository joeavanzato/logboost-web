"""Audit detail: what a settings save changed, secrets kept out, and a readable client."""

import json


CHROME_WINDOWS = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
                  'Chrome/126.0.0.0 Safari/537.36')
FIREFOX_MAC = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:127.0) Gecko/20100101 Firefox/127.0'


def _audit_rows(action):
    """Audit rows for an action, oldest first, read straight from the database."""
    import admin
    conn = admin.get_db()
    rows = conn.execute('SELECT details, user_agent FROM audit_logs WHERE action = ? ORDER BY id',
                        (action,)).fetchall()
    conn.close()
    return rows


def _save_dns(client, cache_ttl, **kwargs):
    return client.post('/admin/settings/dns', data={
        'dns_servers': '1.1.1.1,8.8.8.8', 'dns_cache_ttl': cache_ttl,
        'dns_timeout': '5', 'dns_max_domains': '100'}, **kwargs)


def test_dns_save_records_only_the_changed_setting(admin_client, test_db):
    assert _save_dns(admin_client, '3600').status_code == 302
    assert _save_dns(admin_client, '7200').status_code == 302

    details = json.loads(_audit_rows('setting_modified')[-1]['details'])
    assert details['changes'] == {'dns_cache_ttl': {'from': '3600', 'to': 7200}}
    assert details['dns_servers'] == '1.1.1.1,8.8.8.8'  # existing detail keys are kept


def test_unchanged_save_has_no_changes_key(admin_client, test_db):
    _save_dns(admin_client, '3600')
    _save_dns(admin_client, '3600')

    rows = _audit_rows('setting_modified')
    assert len(rows) == 2
    assert 'changes' not in json.loads(rows[-1]['details'])


def test_api_key_values_never_reach_the_audit_log(admin_client, test_db):
    for key in ('first-secret-key-111', 'second-secret-key-222'):
        assert admin_client.post('/admin/settings/shodan', data={'shodan_api_key': key}).status_code == 302

    import admin
    conn = admin.get_db()
    everything = ' '.join(str(row['details']) for row in conn.execute('SELECT details FROM audit_logs'))
    conn.close()
    assert 'first-secret-key-111' not in everything
    assert 'second-secret-key-222' not in everything
    assert 'secret-key' not in everything

    first, second = [json.loads(row['details']) for row in _audit_rows('api_key_modified')]
    assert first['key_set'] is True
    assert first['changes'] == {'shodan_api_key': {'from': 'not set', 'to': 'set'}}
    assert second['changes'] == {'shodan_api_key': {'from': 'set', 'to': 'replaced'}}


def test_setting_changes_helper():
    import admin
    changes = admin._setting_changes(
        {'limit': '5', 'name': 'a', 'circl_password': 'old-pw'},
        {'limit': 5, 'name': 'b', 'circl_password': ''})
    assert changes == {'name': {'from': 'a', 'to': 'b'},
                       'circl_password': {'from': 'set', 'to': 'not set'}}


def test_describe_user_agent():
    import admin
    assert admin.describe_user_agent(CHROME_WINDOWS) == 'Chrome 126 · Windows'
    assert admin.describe_user_agent(FIREFOX_MAC) == 'Firefox 127 · macOS'
    assert admin.describe_user_agent('curl/8.5.0') == 'curl 8.5.0'
    assert admin.describe_user_agent('') == ''


def test_audit_page_shows_changes_table_and_client(admin_client, test_db):
    _save_dns(admin_client, '3600', headers={'User-Agent': CHROME_WINDOWS})
    _save_dns(admin_client, '7200', headers={'User-Agent': CHROME_WINDOWS})

    page = admin_client.get('/admin/audit').get_data(as_text=True)
    assert '<th>Setting</th><th>Previous</th><th>New</th>' in page
    assert '<td class="mono">dns_cache_ttl</td>' in page
    assert '>3600</td>' in page and '>7200</td>' in page
    assert '<dt>Client</dt><dd>Chrome 126 · Windows</dd>' in page
    assert '<dt>User agent</dt><dd>Mozilla/5.0 (Windows NT 10.0;' in page
