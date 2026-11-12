"""
Fix wave Phase 5: XSS hardening of the results UI, vendored scripts, settings page without
stored secrets, asynchronous Shodan account info, UTC labels.

The escaping itself runs in the browser, so the template checks here are of two kinds: the
server-rendered partial must not place data inside handler source, and the JavaScript must not
contain the patterns that made that possible.
"""

import csv
import re
from pathlib import Path
from unittest.mock import MagicMock, patch

import admin

TEMPLATES = Path(__file__).parent.parent / 'templates'
ATTRIBUTE_PAYLOAD = 'x" onmouseover="alert(1)'
HANDLER_PAYLOAD = "&#39;);alert(1);//"
QUOTE_PAYLOAD = "');alert(1);//"


def _read(name):
    return (TEMPLATES / name).read_text(encoding='utf-8')


def _stored(key):
    """A setting straight from the database (get_setting caches per request context)."""
    with admin.db() as conn:
        row = conn.execute('SELECT value FROM settings WHERE key = ?', (key,)).fetchone()
    return row['value'] if row else None


def _render_results(client, header, rows):
    """Run a text enrichment whose LogBoost output is the given CSV; returns the page."""
    def fake_logboost(cmd):
        out_dir = Path(cmd[cmd.index('-outputdir') + 1])
        with open(out_dir / 'enriched.csv', 'w', newline='', encoding='utf-8') as f:
            csv.writer(f).writerows([header] + rows)
        return True, '', ''

    with patch('app.extract_ips', return_value=['8.8.8.8']), patch('app.run_logboost', side_effect=fake_logboost):
        return client.post('/enrich/text', data={'text': '8.8.8.8'}).data.decode()


class TestResultsPartialXss:

    def test_payloads_never_reach_markup_or_handler_source(self, authenticated_client):
        page = _render_results(
            authenticated_client,
            ['IP', ATTRIBUTE_PAYLOAD, QUOTE_PAYLOAD, HANDLER_PAYLOAD],
            [['8.8.8.8', ATTRIBUTE_PAYLOAD, QUOTE_PAYLOAD, HANDLER_PAYLOAD]])

        assert 'alert(1)' in page  # the data is there (as JSON and in data-* attributes)
        # no attribute break-out: the raw payload with live quotes appears nowhere
        assert 'onmouseover="alert(1)' not in page
        # no event handler has the payload in its source, in any encoding
        for handler in re.findall(r'\son[a-z]+="([^"]*)"', page):
            assert 'alert' not in handler, handler
        # column names travel in data-column and are read back with dataset
        assert 'onchange="window.toggleColumn(this.dataset.column)"' in page

    def test_server_side_table_keeps_headers_out_of_handlers(self, authenticated_client, tmp_path):
        path = tmp_path / 'results.csv'
        with open(path, 'w', newline='', encoding='utf-8') as f:
            csv.writer(f).writerows([['IP', QUOTE_PAYLOAD], ['8.8.8.8', 'x']])
        with authenticated_client.session_transaction() as sess:
            sess['current_output'] = str(path)

        page = authenticated_client.get('/results/page').data.decode()

        for handler in re.findall(r'\son[a-z]+="([^"]*)"', page):
            assert 'alert' not in handler, handler


class TestEscapers:

    def test_every_escaper_escapes_quotes(self):
        for name in ('index.html', 'partials/results.html'):
            content = _read(name)
            # the textContent/innerHTML trick leaves " and ' alone
            assert 'return div.innerHTML' not in content, name
            assert content.count('.replace(/"/g, \'&quot;\').replace(/\'/g, \'&#39;\')') >= 1, name
        assert 'escapeAttr' not in _read('index.html')

    def test_handlers_are_not_built_from_data(self):
        index = _read('index.html')
        for handler in re.findall(r'on[a-z]+="([^"]*\$\{[^"]*)"', index):
            # the one remaining interpolation is a fixed keyword and a number
            assert handler.startswith("intelPivotTo('${kind}', ${Number(i.id)})"), handler
        # string-concatenated handler arguments (the old \'' + value + '\' pattern)
        assert "(\\'' + " not in _read('partials/results.html')
        assert "{{ header }}'" not in _read('partials/results.html')
        assert "{{ header }}'" not in _read('partials/results_table.html')

    def test_toasts_and_graph_fields_are_escaped(self):
        index = _read('index.html')
        assert '<span class="toast-message">${escapeHtml(message)}</span>' in index
        assert '(${this.escapeHtml(conn.relationship)})' in index
        assert '${this.escapeHtml(typeStr)}' in index
        assert '${this.escapeHtml(String(node.type).toUpperCase())}' in index

    def test_stats_modal_builds_dom_nodes(self):
        stats = _read('partials/stats.html')
        assert 'body.innerHTML' not in stats
        assert 'body.replaceChildren(list)' in stats


class TestVendoredScripts:

    def test_no_cdn_scripts_and_csp_allows_only_self(self, authenticated_client):
        for name in ('index.html', 'admin/base.html'):
            content = _read(name)
            assert 'unpkg.com' not in content and 'cdnjs.cloudflare.com' not in content, name

        response = authenticated_client.get('/static/vendor/htmx-1.9.10.min.js')
        assert response.status_code == 200
        # pinned in app.py: a host that maps .js to text/plain would trip nosniff
        assert response.headers['Content-Type'].startswith('text/javascript')
        csp = response.headers['Content-Security-Policy']
        assert "script-src 'self' 'unsafe-inline';" in csp
        assert 'unpkg' not in csp and 'cdnjs' not in csp
        response.close()

        for name in ('d3-7.8.5.min.js', 'psl-1.9.0.min.js'):
            response = authenticated_client.get(f'/static/vendor/{name}')
            assert response.status_code == 200, name
            response.close()


class TestSettingsSecrets:
    KEYS = {
        'maxmind_api_key': '123456:maxmind-secret-value',
        'shodan_api_key': 'shodan-secret-value',
        'hackertarget_api_key': 'hackertarget-secret-value',
        'viewdns_api_key': 'viewdns-secret-value',
        'chaos_api_key': 'chaos-secret-value',
    }

    def _store_keys(self):
        for key, value in self.KEYS.items():
            admin.set_setting(key, value)

    def test_settings_page_does_not_contain_stored_keys(self, admin_client, test_db):
        self._store_keys()
        with patch('admin.get_shodan_account_info') as shodan_info:
            page = admin_client.get('/admin/settings').data.decode()

        for value in self.KEYS.values():
            assert value not in page
        assert page.count('name="remove_key"') == len(self.KEYS)
        shodan_info.assert_not_called()  # no outbound call while rendering the page

    def test_blank_keeps_key_and_remove_deletes_it(self, admin_client, test_db):
        self._store_keys()
        forms = {
            'maxmind_api_key': '/admin/settings/maxmind',
            'shodan_api_key': '/admin/settings/shodan',
            'hackertarget_api_key': '/admin/settings/hackertarget',
            'viewdns_api_key': '/admin/settings/viewdns',
            'chaos_api_key': '/admin/settings/chaos',
        }
        for key, url in forms.items():
            admin_client.post(url, data={key: ''})
            assert _stored(key) == self.KEYS[key], key

            admin_client.post(url, data={key: 'replacement-value'})
            assert _stored(key) == 'replacement-value', key

            admin_client.post(url, data={key: '', 'remove_key': '1'})
            assert _stored(key) == '', key

    def test_test_button_falls_back_to_stored_key(self, admin_client, test_db):
        self._store_keys()
        with patch('urllib.request.urlopen', return_value=MagicMock()) as urlopen:
            response = admin_client.post('/admin/settings/test-maxmind', data={'api_key': ''})

        assert response.get_json()['success'] is True
        request = urlopen.call_args[0][0]
        assert request.get_header('Authorization')  # built from the stored account and key

    def test_shodan_account_info_is_served_separately(self, admin_client, test_db):
        self._store_keys()
        info = {'plan': 'dev', 'query_credits': 100, 'scan_credits': 5}
        with patch('admin.get_shodan_account_info', return_value=info) as lookup:
            response = admin_client.get('/admin/settings/shodan-info')

        assert response.get_json() == info
        lookup.assert_called_once_with(self.KEYS['shodan_api_key'])


class TestAuditUtcLabels:

    def test_audit_page_labels_times_as_utc(self, admin_client, test_db):
        admin.log_audit('test_action', 'test', '1', username='tester')
        page = admin_client.get('/admin/audit').data.decode()
        assert 'Start Date (UTC)' in page and 'End Date (UTC)' in page
        assert 'Timestamp (UTC)' in page
