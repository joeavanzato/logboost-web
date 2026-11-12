"""
Fix wave Phase 3: graph lookups isolated from the main results, row cap, statistics
aggregation and cache, enrichment concurrency limit, result path containment.
"""

import csv
from pathlib import Path
from unittest.mock import patch

import app as app_module


def _write_csv(path, header, rows):
    with open(path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(rows)
    return path


def _fake_logboost(header, rows):
    """A run_logboost stand-in that writes a result CSV into the command's -outputdir."""
    def run(cmd):
        out_dir = Path(cmd[cmd.index('-outputdir') + 1])
        _write_csv(out_dir / 'enriched.csv', header, rows)
        return True, '', ''
    return run


def _main_results(client, tmp_path):
    """Three-row main result file registered as the session's current output."""
    path = _write_csv(tmp_path / 'main_results.csv', ['IP', 'lb_Country'],
                      [['8.8.8.8', 'US'], ['1.1.1.1', 'AU'], ['9.9.9.9', 'US']])
    with client.session_transaction() as sess:
        sess['current_output'] = str(path)
    return path


class TestGraphLookupIsolation:
    """B3: graph lookups must not replace or delete the main results."""

    def test_download_and_stats_survive_graph_enrichment(self, authenticated_client, tmp_path):
        main = _main_results(authenticated_client, tmp_path)
        graph_rows = _fake_logboost(['ip', 'lb_ASN', 'lb_ASN_Number', 'lb_Country'],
                                    [['4.4.4.4', 'Level 3', '3356', 'United States']])

        with patch('app.run_logboost', side_effect=graph_rows) as run:
            geo = authenticated_client.post('/api/graph/enrich', json={'ips': ['4.4.4.4']})
            idb = authenticated_client.post('/api/graph/enrich-idb', json={'ips': ['4.4.4.4']})

        assert geo.status_code == 200
        assert geo.get_json()['geo_data']['4.4.4.4']['asn'] == 'AS3356 Level 3'
        assert idb.status_code == 200

        # LogBoost ran in a throwaway directory that is gone afterwards
        for call in run.call_args_list:
            cmd = call.args[0]
            out_dir = Path(cmd[cmd.index('-outputdir') + 1])
            assert tmp_path not in out_dir.parents
            assert not out_dir.exists()

        with authenticated_client.session_transaction() as sess:
            assert sess['current_output'] == str(main)

        download = authenticated_client.get('/download')
        assert download.status_code == 200
        assert b'9.9.9.9' in download.data and b'4.4.4.4' not in download.data
        download.close()

        stats = authenticated_client.get('/stats')
        assert stats.status_code == 200
        assert b'<span class="stat-value">3</span>' in stats.data  # three main rows

    def test_graph_lookup_rejects_non_ip_input(self, authenticated_client):
        with patch('app.run_logboost') as run:
            for bad in (['8.8.8.8\n1.1.1.1'], ['example.com'], [5], 'not-a-list', ['fe80::1%eth0']):
                response = authenticated_client.post('/api/graph/enrich', json={'ips': bad})
                assert response.status_code == 400, bad
            with patch('app.get_max_adhoc_ips', return_value=2):
                response = authenticated_client.post('/api/graph/enrich-idb',
                                                     json={'ips': ['1.1.1.1', '8.8.8.8', '9.9.9.9']})
                assert response.status_code == 400
        run.assert_not_called()


class TestResultPathContainment:
    """S11: only files under OUTPUT_FOLDER are served."""

    def test_output_outside_output_folder_is_not_served(self, authenticated_client, tmp_path, monkeypatch):
        outside = _write_csv(tmp_path / 'secret.csv', ['IP'], [['8.8.8.8']])
        inside = tmp_path / 'output'
        inside.mkdir()
        monkeypatch.setattr(app_module, 'OUTPUT_FOLDER', inside)
        with authenticated_client.session_transaction() as sess:
            sess['current_output'] = str(outside)

        assert authenticated_client.get('/download').status_code == 404
        assert b'8.8.8.8' not in authenticated_client.get('/stats').data
        assert authenticated_client.get('/column-values/IP').get_json() == {'values': []}
        assert authenticated_client.post('/api/results/share').status_code == 400
        related = authenticated_client.post('/api/graph/related', json={'value': '8.8.8.8', 'type': 'ip'})
        assert related.get_json()['geo_data'] == {}


class TestStatistics:
    """B6 and P3."""

    def test_pipe_separated_column_is_aggregated_from_all_values(self, tmp_path):
        # 15 distinct values; the old code only looked at the ten most common
        rows = [[f'10.0.0.{i}', f'malware|family{i}'] for i in range(15)]
        path = _write_csv(tmp_path / 'threats.csv', ['IP', 'lb_ThreatCategories'], rows)

        categories = dict(app_module.compute_statistics(path)['threat_summary']['all_categories'])

        assert categories['malware'] == 15
        assert len(categories) == 16
        assert all(categories[f'family{i}'] == 1 for i in range(15))

    def test_truncated_unique_count_is_shown_as_lower_bound(self, tmp_path):
        rows = [[f'v{i}', 'same'] for i in range(5)]
        path = _write_csv(tmp_path / 'many.csv', ['many', 'few'], rows)

        with patch('app.get_max_unique_values', return_value=3):
            columns = {c['name']: c for c in app_module.compute_statistics(path)['columns']}

        assert columns['many']['unique_count_truncated'] is True
        assert columns['many']['unique_display'] == '3+'
        assert columns['many']['uniqueness_display'] == '≥ 60.0%'
        assert columns['few']['unique_count_truncated'] is False
        assert columns['few']['unique_display'] == '1'

    def test_column_exactly_at_limit_is_not_truncated(self, tmp_path):
        rows = [['a'], ['b'], ['c'], ['a'], ['b']]
        path = _write_csv(tmp_path / 'exact.csv', ['col'], rows)

        with patch('app.get_max_unique_values', return_value=3):
            col = app_module.compute_statistics(path)['columns'][0]

        assert col['unique_count'] == 3
        assert col['unique_count_truncated'] is False

    def test_statistics_are_cached_per_file_and_refreshed_on_change(self, tmp_path):
        path = _write_csv(tmp_path / 'cached.csv', ['IP'], [['8.8.8.8']])

        with patch('app.compute_statistics', wraps=app_module.compute_statistics) as compute:
            first = app_module.cached_statistics(path)
            assert app_module.cached_statistics(path) is first
            assert app_module.get_unique_column_values(path, 'IP') == [{'value': '8.8.8.8', 'count': 1}]
            assert compute.call_count == 1

            _write_csv(path, ['IP'], [['8.8.8.8'], ['1.1.1.1']])  # size changes, so the entry is stale
            assert app_module.cached_statistics(path)['total_rows'] == 2
            assert compute.call_count == 2

    def test_stat_values_are_fetched_on_demand_not_embedded(self, authenticated_client, tmp_path):
        rows = [[f'10.0.0.{i}', f'malware|<b>family{i}</b>'] for i in range(15)]
        path = _write_csv(tmp_path / 'threats.csv', ['IP', 'lb_ThreatCategories'], rows)
        with authenticated_client.session_transaction() as sess:
            sess['current_output'] = str(path)

        page = authenticated_client.get('/stats').data
        assert b'data-values-key="threat_summary/all_categories"' in page
        assert b'all-values-data' not in page
        assert b'family14' not in page  # beyond the ten shown on the card

        body = authenticated_client.get('/stats/values/threat_summary/all_categories').get_json()
        assert body['total_rows'] == 15
        assert ['malware', 15] in body['values']
        assert len(body['values']) == 16

        assert authenticated_client.get('/stats/values/columns/all_x').get_json()['values'] == []


class TestRowCap:
    """P2: the page embeds at most max_embedded_rows rows; the file is served whole."""

    def test_result_above_cap_shows_banner_and_downloads_in_full(self, authenticated_client):
        rows = [[f'10.0.0.{i}', 'US'] for i in range(12)]

        with patch('app.extract_ips', return_value=['10.0.0.1']), \
             patch('app.run_logboost', side_effect=_fake_logboost(['IP', 'lb_Country'], rows)), \
             patch('app.get_max_embedded_rows', return_value=5):
            response = authenticated_client.post('/enrich/text', data={'text': '10.0.0.1'})

        page = response.data.decode()
        assert response.status_code == 200
        assert 'id="row-cap-banner"' in page
        assert 'Showing the first 5 of 12 rows' in page
        assert '10.0.0.4' in page and '10.0.0.5' not in page
        assert '<span id="total-rows-display">12</span>' in page

        download = authenticated_client.get('/download')
        assert download.status_code == 200
        assert download.data.count(b'10.0.0.') == 12
        download.close()

        # statistics cover the full file
        assert b'<span class="stat-value">12</span>' in authenticated_client.get('/stats').data

    def test_result_within_cap_has_no_banner(self, authenticated_client):
        with patch('app.extract_ips', return_value=['10.0.0.1']), \
             patch('app.run_logboost', side_effect=_fake_logboost(['IP'], [['10.0.0.1']])):
            response = authenticated_client.post('/enrich/text', data={'text': '10.0.0.1'})

        assert b'row-cap-banner' not in response.data
        assert b'10.0.0.1' in response.data


class TestEnrichmentLimit:
    """P1: two LogBoost runs at a time; the next caller is refused at once."""

    def test_third_concurrent_enrichment_is_refused(self, authenticated_client, tmp_path):
        main = _main_results(authenticated_client, tmp_path)
        slots = app_module._enrich_slots
        assert app_module.MAX_CONCURRENT_ENRICHMENTS == 2
        slots.acquire()
        slots.acquire()
        try:
            with patch('app.run_logboost') as run:
                text = authenticated_client.post('/enrich/text', data={'text': '8.8.8.8'})
                graph = authenticated_client.post('/api/graph/enrich', json={'ips': ['8.8.8.8']})
            run.assert_not_called()
        finally:
            slots.release()
            slots.release()

        assert app_module.BUSY_MESSAGE.encode() in text.data
        assert graph.status_code == 503
        assert main.exists()  # a refused request leaves the previous results alone

        # slots are free again
        with patch('app.extract_ips', return_value=['8.8.8.8']), \
             patch('app.run_logboost', side_effect=_fake_logboost(['IP'], [['8.8.8.8']])):
            response = authenticated_client.post('/enrich/text', data={'text': '8.8.8.8'})
        assert app_module.BUSY_MESSAGE.encode() not in response.data


class TestSessionDirReset:
    """B4: output from a previous run in a subdirectory no longer breaks the next enrichment."""

    def test_enrichment_clears_nested_output(self, authenticated_client, tmp_path):
        with authenticated_client.session_transaction() as sess:
            sess['session_id'] = 'phase3-nested'
        nested = tmp_path / 'phase3-nested' / 'sub'
        nested.mkdir(parents=True)
        (nested / 'old.csv').write_text('IP\n1.2.3.4\n')

        with patch('app.extract_ips', return_value=['8.8.8.8']), \
             patch('app.run_logboost', side_effect=_fake_logboost(['IP'], [['8.8.8.8']])):
            response = authenticated_client.post('/enrich/text', data={'text': '8.8.8.8'})

        assert response.status_code == 200
        assert b'8.8.8.8' in response.data
        assert not nested.exists()
