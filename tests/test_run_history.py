"""Run history: finished enrichments are kept per user and can be reopened (UI redesign, phase 5)."""
import os
import time
from pathlib import Path

import pytest


@pytest.fixture
def fake_logboost(monkeypatch):
    """Replace the LogBoost run with one that writes a small result file into the output directory."""
    import app as app_module

    def build(upload_dir, output_dir, options):
        return ['logboost', output_dir]

    def run(cmd):
        Path(cmd[1], 'enriched.csv').write_text('IP,lb_Country\n8.8.8.8,United States\n1.1.1.1,Australia\n',
                                                encoding='utf-8')
        return True, '', ''

    monkeypatch.setattr(app_module, 'build_logboost_command', build)
    monkeypatch.setattr(app_module, 'run_logboost', run)
    monkeypatch.setattr(app_module, 'extract_ips', lambda text: ['8.8.8.8', '1.1.1.1'])


def _enrich(client, **form):
    response = client.post('/enrich/text', data={'text': 'seen 8.8.8.8 and 1.1.1.1', **form})
    assert response.status_code == 200
    response.close()


def _runs(client):
    return client.get('/runs').get_json()['runs']


def test_enrichment_is_recorded_and_can_be_reopened(regular_user_client, fake_logboost):
    import app as app_module
    _enrich(regular_user_client, dns='on')

    runs = _runs(regular_user_client)
    assert len(runs) == 1
    run = runs[0]
    assert (run['kind'], run['label'], run['ip_count'], run['row_count']) == ('text', 'Pasted text', 2, 2)
    assert run['sources'] == ['dns'] and run['can_edit'] is True

    # The result file now lives in the user's run store, not in the session directory
    stored = list((app_module.OUTPUT_FOLDER / '_runs').rglob('enriched.csv'))
    assert len(stored) == 1

    # A later enrichment empties the session directory; the first run must still open
    _enrich(regular_user_client)
    reopened = regular_user_client.get(f"/runs/{run['id']}")
    assert reopened.status_code == 200 and b'United States' in reopened.data

    stored_input = regular_user_client.get(f"/runs/{run['id']}/input").get_json()
    assert stored_input['text'] == 'seen 8.8.8.8 and 1.1.1.1'
    assert stored_input['options'] == {'dns': True, 'whois': False, 'idb': False, 'useti': False}


def test_download_serves_the_reopened_run(regular_user_client, fake_logboost):
    _enrich(regular_user_client)
    run_id = _runs(regular_user_client)[0]['id']
    regular_user_client.get(f'/runs/{run_id}').close()
    download = regular_user_client.get('/download')
    assert download.status_code == 200 and b'8.8.8.8,United States' in download.data
    assert 'enriched.csv' in download.headers['Content-Disposition']


def test_runs_are_private_even_from_administrators(regular_user_client, admin_client, fake_logboost):
    _enrich(regular_user_client)
    run_id = _runs(regular_user_client)[0]['id']

    assert _runs(admin_client) == []
    assert admin_client.get(f'/runs/{run_id}').status_code == 404
    assert admin_client.get(f'/runs/{run_id}/input').status_code == 404
    assert admin_client.post(f'/runs/{run_id}/delete').status_code == 404
    assert len(_runs(regular_user_client)) == 1  # untouched


def test_delete_removes_the_row_and_the_file(regular_user_client, fake_logboost):
    import app as app_module
    _enrich(regular_user_client)
    run_id = _runs(regular_user_client)[0]['id']

    assert regular_user_client.post(f'/runs/{run_id}/delete').get_json() == {'success': True}
    assert _runs(regular_user_client) == []
    assert list((app_module.OUTPUT_FOLDER / '_runs').rglob('enriched.csv')) == []
    assert regular_user_client.get('/download').status_code == 404


def test_expired_runs_are_cleaned_up(app, regular_user_client, fake_logboost):
    import admin
    import app as app_module
    _enrich(regular_user_client)
    _enrich(regular_user_client)
    old_id = _runs(regular_user_client)[1]['id']
    with admin.db() as conn:
        conn.execute("UPDATE enrichment_runs SET created_at = datetime('now', '-8 days') WHERE id = ?", (old_id,))
        conn.commit()

    with app.app_context():
        assert app_module.cleanup_old_runs() == 1

    remaining = _runs(regular_user_client)
    assert len(remaining) == 1 and remaining[0]['id'] != old_id
    assert len(list((app_module.OUTPUT_FOLDER / '_runs').rglob('enriched.csv'))) == 1


def test_session_directory_sweep_leaves_the_run_store_alone(app, regular_user_client, fake_logboost):
    """Regression: the hourly sweep deletes output directories untouched for 7 days; the run
    store sits in the same folder and has its own retention."""
    import app as app_module
    _enrich(regular_user_client)
    store = app_module.OUTPUT_FOLDER / '_runs'
    long_ago = time.time() - 30 * 86400
    for path in [store, *store.rglob('*')]:
        os.utime(path, (long_ago, long_ago))

    with app.app_context():
        app_module.sweep_session_dirs()

    assert len(list(store.rglob('enriched.csv'))) == 1
