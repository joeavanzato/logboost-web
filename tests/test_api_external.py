"""
Tests for HackerTarget and ViewDNS API endpoints.

Tests cover:
- POST /api/hackertarget/shared-ns - Find domains sharing nameserver
- GET /api/viewdns/settings - Get ViewDNS settings
- POST /api/viewdns/reverse-mx - Reverse MX lookup
- POST /api/viewdns/reverse-ns - Reverse NS lookup
- POST /api/viewdns/reverse-whois - Reverse WHOIS lookup
"""

import pytest
import json
from unittest.mock import patch, MagicMock


@pytest.fixture
def mock_hackertarget_response():
    """Sample HackerTarget shared NS response."""
    return "example.com\ntest.org\nmysite.net\ndemo.io"


@pytest.fixture
def mock_viewdns_reverse_mx_response():
    """Sample ViewDNS reverse MX response."""
    return {
        'response': {
            'domain_count': '3',
            'domains': ['example.com', 'example.org', 'example.net']
        }
    }


@pytest.fixture
def mock_viewdns_reverse_ns_response():
    """Sample ViewDNS reverse NS response."""
    return {
        'response': {
            'domain_count': '2',
            'domains': [
                {'domain': 'example.com'},
                {'domain': 'test.org'}
            ]
        }
    }


@pytest.fixture
def mock_viewdns_reverse_whois_response():
    """Sample ViewDNS reverse WHOIS response."""
    return {
        'response': {
            'result_count': '2',
            'matches': [
                {'domain': 'example.com', 'created_date': '2012-08-03', 'registrar': 'NAME.COM'},
                {'domain': 'example.org', 'created_date': '2015-02-15', 'registrar': 'GoDaddy'}
            ]
        }
    }


class TestHackerTargetSharedNsApi:
    """Tests for POST /api/hackertarget/shared-ns endpoint."""
    
    def test_hackertarget_shared_ns_requires_auth(self, client):
        """Test that endpoint requires authentication."""
        response = client.post('/api/hackertarget/shared-ns',
                              json={'value': 'ns1.example.com'})
        assert response.status_code in (302, 401, 403)
    
    def test_hackertarget_shared_ns_no_json(self, authenticated_client):
        """Test error when no JSON provided."""
        response = authenticated_client.post('/api/hackertarget/shared-ns',
                                             data='not json',
                                             content_type='application/json')
        assert response.status_code == 400
    
    def test_hackertarget_shared_ns_missing_value(self, authenticated_client):
        """Test error when value not provided."""
        response = authenticated_client.post('/api/hackertarget/shared-ns',
                                             json={'other_field': 'value'})
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'required' in data['error'].lower() or 'value' in data['error'].lower()
    
    def test_hackertarget_shared_ns_empty_value(self, authenticated_client):
        """Test error when value is empty."""
        response = authenticated_client.post('/api/hackertarget/shared-ns',
                                             json={'value': ''})
        assert response.status_code == 400
    
    def test_hackertarget_shared_ns_returns_cached(self, authenticated_client):
        """Test that cached results are returned."""
        cached_result = {
            'results': ['example.com', 'test.org'],
            'result_count': 2,
            'cached_at': '2024-01-01 00:00:00'
        }
        
        with patch('app.get_hackertarget_settings', return_value={'cache_ttl': 3600}):
            with patch('app.get_cached_hackertarget', return_value=cached_result):
                response = authenticated_client.post('/api/hackertarget/shared-ns',
                                                     json={'value': 'ns1.example.com'})
                assert response.status_code == 200
                data = json.loads(response.data)
                assert data['from_cache'] == True
    
    def test_hackertarget_shared_ns_success(self, authenticated_client, mock_hackertarget_response):
        """Test successful shared NS query."""
        mock_response = MagicMock()
        mock_response.text = mock_hackertarget_response
        mock_response.raise_for_status = MagicMock()
        
        with patch('app.get_hackertarget_settings', return_value={'cache_ttl': 3600, 'api_key': None}):
            with patch('app.get_cached_hackertarget', return_value=None):
                with patch('requests.get', return_value=mock_response):
                    with patch('app.set_cached_hackertarget'):
                        with patch('app.log_audit'):
                            response = authenticated_client.post('/api/hackertarget/shared-ns',
                                                                 json={'value': 'ns1.example.com'})
                            assert response.status_code == 200
                            data = json.loads(response.data)
                            assert 'results' in data
                            assert len(data['results']) == 4
                            assert data['from_cache'] == False
    
    def test_hackertarget_shared_ns_no_results(self, authenticated_client):
        """Test handling when no results found."""
        mock_response = MagicMock()
        mock_response.text = 'No results found'
        mock_response.raise_for_status = MagicMock()
        
        with patch('app.get_hackertarget_settings', return_value={'cache_ttl': 3600, 'api_key': None}):
            with patch('app.get_cached_hackertarget', return_value=None):
                with patch('requests.get', return_value=mock_response):
                    with patch('app.set_cached_hackertarget'):
                        response = authenticated_client.post('/api/hackertarget/shared-ns',
                                                             json={'value': 'ns1.example.com'})
                        assert response.status_code == 200
                        data = json.loads(response.data)
                        assert data['results'] == []
                        assert data['result_count'] == 0
    
    def test_hackertarget_shared_ns_error_response(self, authenticated_client):
        """Test handling of error response from HackerTarget."""
        mock_response = MagicMock()
        mock_response.text = 'error API count exceeded'
        mock_response.raise_for_status = MagicMock()
        
        with patch('app.get_hackertarget_settings', return_value={'cache_ttl': 3600, 'api_key': None}):
            with patch('app.get_cached_hackertarget', return_value=None):
                with patch('requests.get', return_value=mock_response):
                    response = authenticated_client.post('/api/hackertarget/shared-ns',
                                                         json={'value': 'ns1.example.com'})
                    assert response.status_code == 400
                    data = json.loads(response.data)
                    assert 'error' in data
    
    def test_hackertarget_shared_ns_request_failure(self, authenticated_client):
        """Test handling of request failures."""
        import requests
        
        with patch('app.get_hackertarget_settings', return_value={'cache_ttl': 3600, 'api_key': None}):
            with patch('app.get_cached_hackertarget', return_value=None):
                with patch('requests.get', side_effect=requests.exceptions.Timeout('Connection timed out')):
                    response = authenticated_client.post('/api/hackertarget/shared-ns',
                                                         json={'value': 'ns1.example.com'})
                    assert response.status_code == 500
                    data = json.loads(response.data)
                    assert 'error' in data
    
    def test_hackertarget_shared_ns_with_api_key(self, authenticated_client, mock_hackertarget_response):
        """Test that API key is included when configured."""
        mock_response = MagicMock()
        mock_response.text = mock_hackertarget_response
        mock_response.raise_for_status = MagicMock()
        
        with patch('app.get_hackertarget_settings', return_value={'cache_ttl': 3600, 'api_key': 'test-key'}):
            with patch('app.get_cached_hackertarget', return_value=None):
                with patch('requests.get', return_value=mock_response) as mock_get:
                    with patch('app.set_cached_hackertarget'):
                        with patch('app.log_audit'):
                            response = authenticated_client.post('/api/hackertarget/shared-ns',
                                                                 json={'value': 'ns1.example.com'})
                            assert response.status_code == 200
                            # The key travels as a query parameter, not inside a hand-built URL
                            assert mock_get.call_args.kwargs['params']['apikey'] == 'test-key'
    
    def test_hackertarget_shared_ns_logs_audit(self, authenticated_client, mock_hackertarget_response):
        """Test that queries are logged to audit."""
        mock_response = MagicMock()
        mock_response.text = mock_hackertarget_response
        mock_response.raise_for_status = MagicMock()
        
        with patch('app.get_hackertarget_settings', return_value={'cache_ttl': 3600, 'api_key': None}):
            with patch('app.get_cached_hackertarget', return_value=None):
                with patch('requests.get', return_value=mock_response):
                    with patch('app.set_cached_hackertarget'):
                        with patch('app.log_audit') as mock_audit:
                            response = authenticated_client.post('/api/hackertarget/shared-ns',
                                                                 json={'value': 'ns1.example.com'})
                            assert response.status_code == 200
                            mock_audit.assert_called_once()
                            assert mock_audit.call_args[0][0] == 'hackertarget_shared_ns'


class TestViewDnsSettingsApi:
    """Tests for GET /api/viewdns/settings endpoint."""
    
    def test_viewdns_settings_requires_auth(self, client):
        """Test that endpoint requires authentication."""
        response = client.get('/api/viewdns/settings')
        assert response.status_code in (302, 401, 403)
    
    def test_viewdns_settings_returns_config(self, authenticated_client):
        """Test that settings are returned."""
        with patch('app.get_viewdns_settings', return_value={'api_key': 'test-key', 'max_nodes': 100}):
            response = authenticated_client.get('/api/viewdns/settings')
            assert response.status_code == 200
            data = json.loads(response.data)
            assert 'api_key_configured' in data
            assert data['api_key_configured'] == True
            assert 'max_nodes' in data
    
    def test_viewdns_settings_no_api_key(self, authenticated_client):
        """Test when API key not configured."""
        with patch('app.get_viewdns_settings', return_value={'api_key': '', 'max_nodes': 100}):
            response = authenticated_client.get('/api/viewdns/settings')
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data['api_key_configured'] == False


class TestViewDnsReverseMxApi:
    """Tests for POST /api/viewdns/reverse-mx endpoint."""
    
    def test_viewdns_reverse_mx_requires_auth(self, client):
        """Test that endpoint requires authentication."""
        response = client.post('/api/viewdns/reverse-mx',
                              json={'value': 'mail.example.com'})
        assert response.status_code in (302, 401, 403)
    
    def test_viewdns_reverse_mx_no_json(self, authenticated_client):
        """Test error when no JSON provided."""
        response = authenticated_client.post('/api/viewdns/reverse-mx',
                                             data='not json',
                                             content_type='application/json')
        assert response.status_code == 400
    
    def test_viewdns_reverse_mx_missing_value(self, authenticated_client):
        """Test error when value not provided."""
        response = authenticated_client.post('/api/viewdns/reverse-mx',
                                             json={'other_field': 'value'})
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'required' in data['error'].lower() or 'value' in data['error'].lower()
    
    def test_viewdns_reverse_mx_no_api_key(self, authenticated_client):
        """Test error when API key not configured."""
        with patch('app.get_viewdns_settings', return_value={'api_key': '', 'cache_ttl': 3600}):
            response = authenticated_client.post('/api/viewdns/reverse-mx',
                                                 json={'value': 'mail.example.com'})
            assert response.status_code == 400
            data = json.loads(response.data)
            assert 'API key not configured' in data['error']
    
    def test_viewdns_reverse_mx_returns_cached(self, authenticated_client):
        """Test that cached results are returned."""
        cached_result = {
            'results': ['example.com', 'test.org'],
            'result_count': 2,
            'cached_at': '2024-01-01 00:00:00'
        }
        
        with patch('app.get_viewdns_settings', return_value={'api_key': 'test-key', 'cache_ttl': 3600}):
            with patch('app.get_cached_viewdns', return_value=cached_result):
                response = authenticated_client.post('/api/viewdns/reverse-mx',
                                                     json={'value': 'mail.example.com'})
                assert response.status_code == 200
                data = json.loads(response.data)
                assert data['from_cache'] == True
    
    def test_viewdns_reverse_mx_success(self, authenticated_client, mock_viewdns_reverse_mx_response):
        """Test successful reverse MX query."""
        mock_response = MagicMock()
        mock_response.json.return_value = mock_viewdns_reverse_mx_response
        mock_response.raise_for_status = MagicMock()
        
        with patch('app.get_viewdns_settings', return_value={'api_key': 'test-key', 'cache_ttl': 3600}):
            with patch('app.get_cached_viewdns', return_value=None):
                with patch('requests.get', return_value=mock_response):
                    with patch('app.set_cached_viewdns'):
                        with patch('app.log_audit'):
                            response = authenticated_client.post('/api/viewdns/reverse-mx',
                                                                 json={'value': 'mail.example.com'})
                            assert response.status_code == 200
                            data = json.loads(response.data)
                            assert data['query_type'] == 'reverse_mx'
                            assert 'results' in data
    
    def test_viewdns_reverse_mx_logs_audit(self, authenticated_client, mock_viewdns_reverse_mx_response):
        """Test that queries are logged to audit."""
        mock_response = MagicMock()
        mock_response.json.return_value = mock_viewdns_reverse_mx_response
        mock_response.raise_for_status = MagicMock()
        
        with patch('app.get_viewdns_settings', return_value={'api_key': 'test-key', 'cache_ttl': 3600}):
            with patch('app.get_cached_viewdns', return_value=None):
                with patch('requests.get', return_value=mock_response):
                    with patch('app.set_cached_viewdns'):
                        with patch('app.log_audit') as mock_audit:
                            response = authenticated_client.post('/api/viewdns/reverse-mx',
                                                                 json={'value': 'mail.example.com'})
                            assert response.status_code == 200
                            mock_audit.assert_called_once()
                            assert mock_audit.call_args[0][0] == 'viewdns_reverse_mx'


class TestViewDnsReverseNsApi:
    """Tests for POST /api/viewdns/reverse-ns endpoint."""
    
    def test_viewdns_reverse_ns_requires_auth(self, client):
        """Test that endpoint requires authentication."""
        response = client.post('/api/viewdns/reverse-ns',
                              json={'value': 'ns1.example.com'})
        assert response.status_code in (302, 401, 403)
    
    def test_viewdns_reverse_ns_no_json(self, authenticated_client):
        """Test error when no JSON provided."""
        response = authenticated_client.post('/api/viewdns/reverse-ns',
                                             data='not json',
                                             content_type='application/json')
        assert response.status_code == 400
    
    def test_viewdns_reverse_ns_missing_value(self, authenticated_client):
        """Test error when value not provided."""
        response = authenticated_client.post('/api/viewdns/reverse-ns',
                                             json={})
        assert response.status_code == 400
    
    def test_viewdns_reverse_ns_no_api_key(self, authenticated_client):
        """Test error when API key not configured."""
        with patch('app.get_viewdns_settings', return_value={'api_key': '', 'cache_ttl': 3600}):
            response = authenticated_client.post('/api/viewdns/reverse-ns',
                                                 json={'value': 'ns1.example.com'})
            assert response.status_code == 400
    
    def test_viewdns_reverse_ns_returns_cached(self, authenticated_client):
        """Test that cached results are returned."""
        cached_result = {
            'results': ['example.com'],
            'result_count': 1,
            'cached_at': '2024-01-01 00:00:00'
        }
        
        with patch('app.get_viewdns_settings', return_value={'api_key': 'test-key', 'cache_ttl': 3600}):
            with patch('app.get_cached_viewdns', return_value=cached_result):
                response = authenticated_client.post('/api/viewdns/reverse-ns',
                                                     json={'value': 'ns1.example.com'})
                assert response.status_code == 200
                data = json.loads(response.data)
                assert data['from_cache'] == True
    
    def test_viewdns_reverse_ns_success(self, authenticated_client, mock_viewdns_reverse_ns_response):
        """Test successful reverse NS query."""
        mock_response = MagicMock()
        mock_response.json.return_value = mock_viewdns_reverse_ns_response
        mock_response.raise_for_status = MagicMock()
        
        with patch('app.get_viewdns_settings', return_value={'api_key': 'test-key', 'cache_ttl': 3600}):
            with patch('app.get_cached_viewdns', return_value=None):
                with patch('requests.get', return_value=mock_response):
                    with patch('app.set_cached_viewdns'):
                        with patch('app.log_audit'):
                            response = authenticated_client.post('/api/viewdns/reverse-ns',
                                                                 json={'value': 'ns1.example.com'})
                            assert response.status_code == 200
                            data = json.loads(response.data)
                            assert data['query_type'] == 'reverse_ns'


class TestViewDnsReverseWhoisApi:
    """Tests for POST /api/viewdns/reverse-whois endpoint."""
    
    def test_viewdns_reverse_whois_requires_auth(self, client):
        """Test that endpoint requires authentication."""
        response = client.post('/api/viewdns/reverse-whois',
                              json={'value': 'admin@example.com'})
        assert response.status_code in (302, 401, 403)
    
    def test_viewdns_reverse_whois_no_json(self, authenticated_client):
        """Test error when no JSON provided."""
        response = authenticated_client.post('/api/viewdns/reverse-whois',
                                             data='not json',
                                             content_type='application/json')
        assert response.status_code == 400
    
    def test_viewdns_reverse_whois_missing_value(self, authenticated_client):
        """Test error when value not provided."""
        response = authenticated_client.post('/api/viewdns/reverse-whois',
                                             json={})
        assert response.status_code == 400
    
    def test_viewdns_reverse_whois_no_api_key(self, authenticated_client):
        """Test error when API key not configured."""
        with patch('app.get_viewdns_settings', return_value={'api_key': '', 'cache_ttl': 3600}):
            response = authenticated_client.post('/api/viewdns/reverse-whois',
                                                 json={'value': 'admin@example.com'})
            assert response.status_code == 400
    
    def test_viewdns_reverse_whois_returns_cached(self, authenticated_client):
        """Test that cached results are returned."""
        cached_result = {
            'results': [{'domain': 'example.com', 'registrar': 'GoDaddy'}],
            'result_count': 1,
            'cached_at': '2024-01-01 00:00:00'
        }
        
        with patch('app.get_viewdns_settings', return_value={'api_key': 'test-key', 'cache_ttl': 3600}):
            with patch('app.get_cached_viewdns', return_value=cached_result):
                response = authenticated_client.post('/api/viewdns/reverse-whois',
                                                     json={'value': 'admin@example.com'})
                assert response.status_code == 200
                data = json.loads(response.data)
                assert data['from_cache'] == True
    
    def test_viewdns_reverse_whois_success(self, authenticated_client, mock_viewdns_reverse_whois_response):
        """Test successful reverse WHOIS query."""
        mock_response = MagicMock()
        mock_response.json.return_value = mock_viewdns_reverse_whois_response
        mock_response.raise_for_status = MagicMock()
        
        with patch('app.get_viewdns_settings', return_value={'api_key': 'test-key', 'cache_ttl': 3600}):
            with patch('app.get_cached_viewdns', return_value=None):
                with patch('requests.get', return_value=mock_response):
                    with patch('app.set_cached_viewdns'):
                        with patch('app.log_audit'):
                            response = authenticated_client.post('/api/viewdns/reverse-whois',
                                                                 json={'value': 'admin@example.com'})
                            assert response.status_code == 200
                            data = json.loads(response.data)
                            assert data['query_type'] == 'reverse_whois'
                            assert 'results' in data
    
    def test_viewdns_reverse_whois_logs_audit(self, authenticated_client, mock_viewdns_reverse_whois_response):
        """Test that queries are logged to audit."""
        mock_response = MagicMock()
        mock_response.json.return_value = mock_viewdns_reverse_whois_response
        mock_response.raise_for_status = MagicMock()
        
        with patch('app.get_viewdns_settings', return_value={'api_key': 'test-key', 'cache_ttl': 3600}):
            with patch('app.get_cached_viewdns', return_value=None):
                with patch('requests.get', return_value=mock_response):
                    with patch('app.set_cached_viewdns'):
                        with patch('app.log_audit') as mock_audit:
                            response = authenticated_client.post('/api/viewdns/reverse-whois',
                                                                 json={'value': 'admin@example.com'})
                            assert response.status_code == 200
                            mock_audit.assert_called_once()
                            assert mock_audit.call_args[0][0] == 'viewdns_reverse_whois'
