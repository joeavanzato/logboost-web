"""
Fix wave Phase 6: feed config writes, task locking, housekeeping, audit dates, DNS settings,
Intel Browser search, updater asset name, WHOIS parsing.
"""

import json
import os
import sqlite3
import time
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

import admin
import app as app_module


def _query(sql, params=()):
    with admin.db() as conn:
        return conn.execute(sql, params).fetchall()


def _execute(sql, params=()):
    with admin.db() as conn:
        conn.execute(sql, params)
        conn.commit()


class TestFeedConfig:

    def _config(self, directory):
        path = directory / 'feed_config.json'
        path.write_text(json.dumps({'feeds': [{'name': 'One', 'url': 'https://example.com/1', 'type': ['c2']}]}))
        return path

    def test_save_through_symlink_keeps_the_symlink(self, admin_client, test_db, tmp_path, monkeypatch):
        """In the container /app/feed_config.json is a symlink into the data volume."""
        volume = tmp_path / 'volume'
        volume.mkdir()
        real = self._config(volume)
        link = tmp_path / 'feed_config.json'
        try:
            link.symlink_to(real)
        except OSError:
            pytest.skip('symlinks are not available to this user on this platform')
        monkeypatch.setattr(admin, 'FEED_CONFIG_PATH', str(link))

        response = admin_client.post('/admin/api/threat-intel/feed',
                                     json={'name': 'Two', 'url': 'https://example.com/2', 'type': 'malware'})

        assert response.status_code == 200
        assert link.is_symlink()
        assert [feed['name'] for feed in json.loads(real.read_text())['feeds']] == ['One', 'Two']
        assert os.listdir(volume) == ['feed_config.json']  # no temp file left behind

    def test_edit_delete_and_bad_requests(self, admin_client, test_db, tmp_path, monkeypatch):
        path = self._config(tmp_path)
        monkeypatch.setattr(admin, 'FEED_CONFIG_PATH', str(path))

        updated = admin_client.put('/admin/api/threat-intel/feed/0', json={'name': 'Renamed', 'type': 'phishing'})
        assert updated.get_json()['feed'] == {'name': 'Renamed', 'url': 'https://example.com/1', 'type': ['phishing']}
        assert admin.load_feeds()[0]['name'] == 'Renamed'

        assert admin_client.put('/admin/api/threat-intel/feed/5', json={'name': 'x'}).status_code == 400
        # a body that is not JSON used to raise
        assert admin_client.post('/admin/api/threat-intel/feed', data='nope', content_type='text/plain').status_code == 400

        assert admin_client.delete('/admin/api/threat-intel/feed/0').get_json()['deleted'] == 'Renamed'
        assert admin.load_feeds() == []

    def test_page_names_the_real_path_when_the_file_is_missing(self, admin_client, test_db, tmp_path, monkeypatch):
        missing = tmp_path / 'feed_config.json'
        monkeypatch.setattr(admin, 'FEED_CONFIG_PATH', str(missing))
        page = admin_client.get('/admin/threat-intel').data.decode()
        assert 'feed_config.json not found at' in page and '/data/config/feed_config.json' not in page


class TestTaskLocking:

    def test_second_run_now_reports_already_running(self, admin_client, test_db):
        assert admin.claim_task('update_ti', 'someone-else') is True  # a scheduled run is in flight

        with patch('admin.execute_task') as execute:
            response = admin_client.post('/admin/tasks/update_ti/run', follow_redirects=True)

        assert b'already running' in response.data
        execute.assert_not_called()

        admin.release_task('update_ti')
        assert admin.claim_task('update_ti', 'me') is True
        assert admin.claim_task('update_ti', 'me') is False

    def test_run_now_takes_and_releases_the_lock(self, admin_client, test_db):
        seen = {}

        def fake_execute(task_type):
            seen['running'] = _query('SELECT running FROM scheduled_tasks WHERE task_type = ?', (task_type,))[0][0]

        with patch('admin.execute_task', side_effect=fake_execute):
            admin_client.post('/admin/tasks/build_ti/run').close()
            for _ in range(50):
                if seen and _query("SELECT running FROM scheduled_tasks WHERE task_type = 'build_ti'")[0][0] == 0:
                    break
                time.sleep(0.05)

        assert seen == {'running': 1}
        assert _query("SELECT running FROM scheduled_tasks WHERE task_type = 'build_ti'")[0][0] == 0

    def test_unknown_task_type_is_refused(self, admin_client, test_db):
        with patch('admin.execute_task') as execute:
            response = admin_client.post('/admin/tasks/rm-rf/run', follow_redirects=True)
        assert b'Unknown task' in response.data
        execute.assert_not_called()
        assert _query("SELECT COUNT(*) FROM task_logs WHERE task_type = 'rm-rf'")[0][0] == 0

    def test_tasks_use_configured_paths_and_keep_the_key_off_the_command_line(self, test_db, monkeypatch):
        monkeypatch.setenv('MAXMIND_DIR', '/custom/maxmind')
        admin.set_setting('maxmind_api_key', '123:secret')
        result = MagicMock(returncode=0, stdout='ok', stderr='')

        with patch('admin.subprocess.run', return_value=result) as run, \
             patch('admin.get_effective_logboost_path', return_value='/data/bin/logboost'):
            admin.execute_task('update_geo')

        argv = run.call_args[0][0]
        assert argv == ['/data/bin/logboost', '-updategeo', '-dbdir', '/custom/maxmind']
        assert run.call_args.kwargs['env']['MM_API'] == '123:secret'


class TestHousekeeping:

    def test_one_scheduler_tick_purges_expired_rows_and_stale_session_dirs(self, test_db, tmp_path):
        admin.set_cached_dns('expired.example', 'A', ['1.2.3.4'], 3600)
        admin.set_cached_dns('fresh.example', 'A', ['1.2.3.4'], 3600)
        _execute("UPDATE dns_cache SET expires_at = datetime('now', '-1 hour') WHERE query = 'expired.example'")
        admin.save_shared_results('expired-share', 1, 'a.csv', [['x']], None, ['h'], 30)
        admin.save_shared_results('fresh-share', 1, 'b.csv', [['x']], None, ['h'], 30)
        _execute("UPDATE shared_results SET expires_at = datetime('now', '-1 day') WHERE id = 'expired-share'")

        # OUTPUT_FOLDER is tmp_path in tests
        stale, fresh = tmp_path / 'stale-session', tmp_path / 'fresh-session'
        for directory in (stale, fresh):
            directory.mkdir()
            (directory / 'out.csv').write_text('IP\n')
        eight_days_ago = time.time() - 8 * 86400
        os.utime(stale / 'out.csv', (eight_days_ago, eight_days_ago))
        os.utime(stale, (eight_days_ago, eight_days_ago))

        admin.TaskScheduler()._tick()

        assert [r[0] for r in _query('SELECT query FROM dns_cache')] == ['fresh.example']
        assert [r[0] for r in _query('SELECT id FROM shared_results')] == ['fresh-share']
        assert not stale.exists() and fresh.exists()


class TestAuditDates:

    def test_end_date_includes_the_whole_day(self, test_db):
        _execute("INSERT INTO audit_logs (action) VALUES ('phase6_marker')")  # timestamp defaults to now (UTC)
        today = datetime.now(timezone.utc).strftime('%Y-%m-%d')

        logs, total = admin.get_audit_logs(action_filter='phase6_marker', start_date=today, end_date=today)

        assert total == 1 and logs[0]['action'] == 'phase6_marker'

    def test_retention_cutoff_is_computed_in_utc(self, test_db):
        _execute("INSERT INTO audit_logs (timestamp, action) VALUES (datetime('now', '-91 days'), 'old')")
        _execute("INSERT INTO audit_logs (timestamp, action) VALUES (datetime('now', '-89 days', '-23 hours'), 'recent')")
        admin.set_setting('audit_retention_days', '90')

        assert admin.cleanup_old_audit_logs() == 1
        assert [r[0] for r in _query("SELECT action FROM audit_logs WHERE action IN ('old', 'recent')")] == ['recent']


class TestDnsSettings:

    def test_servers_must_be_ip_addresses_and_numbers_are_clamped(self, admin_client, test_db):
        response = admin_client.post('/admin/settings/dns', follow_redirects=True, data={
            'dns_servers': '8.8.8.8, not-an-ip', 'dns_cache_ttl': '60', 'dns_timeout': '5', 'dns_max_domains': '10'})
        assert b'must be a comma-separated list of IP addresses' in response.data
        assert _query("SELECT COUNT(*) FROM settings WHERE key = 'dns_servers'")[0][0] == 0

        admin_client.post('/admin/settings/dns', data={
            'dns_servers': '9.9.9.9, 2620:fe::fe', 'dns_cache_ttl': 'abc', 'dns_timeout': '9999', 'dns_max_domains': '0'}).close()
        stored = dict(_query("SELECT key, value FROM settings WHERE key LIKE 'dns_%'"))
        assert stored == {'dns_servers': '9.9.9.9,2620:fe::fe', 'dns_cache_ttl': '3600',
                          'dns_timeout': '60', 'dns_max_domains': '1'}


class TestIntelBrowser:

    @pytest.fixture
    def threats_db(self, tmp_path, monkeypatch):
        path = tmp_path / 'threats.db'
        conn = sqlite3.connect(path)
        conn.executescript('''
            CREATE TABLE feeds (feed_id INTEGER PRIMARY KEY, feed_name TEXT);
            CREATE TABLE categories (category_id INTEGER PRIMARY KEY, category_value TEXT);
            CREATE TABLE ips (ip TEXT, feed INTEGER, category INTEGER);
            INSERT INTO feeds VALUES (1, 'feed-a');
            INSERT INTO categories VALUES (1, 'c2');
        ''')
        conn.executemany('INSERT INTO ips VALUES (?, 1, 1)',
                         [('10.1.0.1',), ('10.1.0.2',), ('10.10.0.1',), ('10.2.0.1',), ('100.1.1.1',), ('9.9.9.9',)])
        conn.commit()
        conn.close()
        monkeypatch.setattr(app_module, 'THREAT_DB_DIR', str(tmp_path))
        return path

    def test_prefix_search_uses_the_index(self, authenticated_client, threats_db):
        assert admin._intel_indexes_present(threats_db) is False  # what the dashboard notice reports
        app_module._ensure_intel_indexes()
        assert admin._intel_indexes_present(threats_db) is True

        rows = authenticated_client.get('/api/intel/iocs?q=10.1').get_json()['rows']
        assert [r['ip'] for r in rows] == ['10.1.0.1', '10.1.0.2', '10.10.0.1']

        sql, params = app_module._build_intel_query({'q': '10.1'}, 'SELECT ips.ip FROM ips')
        conn = sqlite3.connect(threats_db)
        plan = ' '.join(row[-1] for row in conn.execute('EXPLAIN QUERY PLAN ' + sql, params))
        conn.close()
        assert 'idx_ips_ip' in plan and 'SCAN' not in plan

    def test_index_build_runs_after_a_threat_intel_update(self, test_db, threats_db):
        result = MagicMock(returncode=0, stdout='ok', stderr='')
        with patch('admin.subprocess.run', return_value=result), \
             patch('admin.get_effective_logboost_path', return_value='/app/logboost'):
            admin.execute_task('update_ti')
        assert admin._intel_indexes_present(threats_db) is True


class TestUpdaterAssetName:

    def test_install_requests_the_published_asset(self, admin_client, test_db):
        admin.set_setting('github_latest_version', 'prod_1_5_0')
        with patch('admin.requests.get', side_effect=RuntimeError('stop before download')) as get:
            response = admin_client.post('/admin/api/setup/install-update')

        assert response.status_code == 500
        assert get.call_args[0][0] == ('https://github.com/joeavanzato/LogBoost/releases/download/'
                                       'prod_1_5_0/logboost-linux-x64.zip')


class TestWhoisParsing:

    def test_single_and_bulk_return_the_same_fields(self, authenticated_client, test_db):
        record = MagicMock(spec=['emails', 'org', 'registrar', 'name', 'creation_date', 'expiration_date', 'name_servers'])
        record.emails = ['Admin@Example.com', 'admin@example.com', 'abuse@example.com']
        record.org, record.registrar, record.name = 'Example Org', ['Reg A', 'Reg B'], None
        record.creation_date, record.expiration_date = [datetime(2020, 1, 2)], None
        record.name_servers = ['NS1.EXAMPLE.COM']

        with patch('whois.whois', return_value=record):
            single = authenticated_client.post('/api/whois/resolve', json={'domain': 'single.example'}).get_json()
            bulk = authenticated_client.post('/api/whois/resolve-bulk',
                                             json={'domains': ['bulk.example']}).get_json()['results']['bulk.example']

        assert set(single) == set(bulk)
        assert single['all_emails'] == ['Admin@Example.com', 'abuse@example.com']
        assert single['registrar'] == 'Reg A' and single['all_registrars'] == ['Reg A', 'Reg B']
        assert single['creation_date'] == '2020-01-02' and single['name_servers'] == ['ns1.example.com']
        assert bulk['organization'] == 'Example Org' and bulk['name_servers'] == ['ns1.example.com']
