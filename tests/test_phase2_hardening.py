"""Checks for the audit fix wave, phase 2 (SSRF, regex DoS, error text, input parsing)."""
import time
from unittest.mock import patch, MagicMock

import pytest
import requests


# ---- S2: SSRF filter (regression: these passed validation before the fix)
@pytest.mark.parametrize('url', [
    'http://[::ffff:127.0.0.1]:8443/health',
    'http://[::ffff:169.254.169.254]/latest/meta-data/',
    'http://[::ffff:10.0.0.1]/',
    'http://[::127.0.0.1]/',
])
def test_ipv4_mapped_ipv6_urls_are_blocked(url):
    from security import validate_url_for_ssrf
    assert validate_url_for_ssrf(url)[0] is False


def test_public_addresses_still_allowed():
    from security import is_ip_blocked
    assert not is_ip_blocked('8.8.8.8')
    assert not is_ip_blocked('2001:4860:4860::8888')


# ---- S3: regex DoS (regression: 40 KB of "a-" took 12 s; "a." took 6 s in DOMAIN_PATTERN)
@pytest.mark.parametrize('unit', ['a-', 'a.'])
def test_our_patterns_are_linear_on_adversarial_input(unit):
    import ioc
    text = unit * 20000
    start = time.time()
    ioc.extract_defanged_domains_direct(text)
    list(ioc.DOMAIN_PATTERN.finditer(text))
    assert time.time() - start < 2


def test_extraction_times_out_cleanly(monkeypatch):
    """iocextract's own URL pattern is quadratic on this input; the subprocess timeout contains it."""
    import app
    monkeypatch.setattr(app, 'IOC_EXTRACT_TIMEOUT', 1)
    with pytest.raises(ValueError, match='timed out'):
        app.extract_iocs_from_text('a.' * 20000)


def test_oversized_text_is_rejected(authenticated_client, monkeypatch):
    import app
    monkeypatch.setattr(app, 'MAX_IOC_TEXT_BYTES', 100)
    response = authenticated_client.post('/api/ioc/extract', json={'text': '8.8.8.8 ' * 100})
    assert response.status_code == 400
    assert 'too large' in response.get_json()['error']


# ---- F1: IPv6 indicators
def test_ipv6_is_extracted_and_private_ipv6_dropped():
    import ioc
    ips, _ = ioc.extract_iocs_from_text('seen 2001:4860:4860::8888 and fe80::1 and 8.8.8.8')
    assert set(ips) == {'2001:4860:4860::8888', '8.8.8.8'}


# ---- S5: API keys never reach the client
def test_viewdns_error_does_not_leak_api_key(authenticated_client):
    error = requests.exceptions.HTTPError(
        '429 Client Error for url: https://api.viewdns.info/reversemx/?mx=x&apikey=SECRET-KEY',
        response=MagicMock(status_code=429))
    with patch('app.get_viewdns_settings', return_value={'api_key': 'SECRET-KEY', 'cache_ttl': 3600}), \
         patch('app.get_cached_viewdns', return_value=None), \
         patch('requests.get', side_effect=error):
        response = authenticated_client.post('/api/viewdns/reverse-mx', json={'value': 'mx.example.com'})
    assert response.status_code == 500
    assert 'SECRET-KEY' not in response.get_data(as_text=True)
    assert 'HTTP 429' in response.get_json()['error']


# ---- B18: malformed input is a 400, not a 500
def test_non_object_json_body_is_400(authenticated_client):
    assert authenticated_client.post('/api/whois/resolve', json=['not', 'an', 'object']).status_code == 400
    assert authenticated_client.post('/api/dns/resolve', json='string').status_code == 400


def test_bad_page_parameters_do_not_crash(authenticated_client):
    assert authenticated_client.get('/results/page?page=abc&page_size=0').status_code == 200


# ---- S13
def test_shodan_hostname_with_extra_filters_is_rejected(authenticated_client):
    with patch('app.get_cached_shodan', return_value=None), patch('app.get_shodan_api_key', return_value='k'):
        response = authenticated_client.post('/api/shodan/resolve',
                                             json={'value': 'example.com country:US', 'type': 'domain'})
    assert response.status_code == 400
