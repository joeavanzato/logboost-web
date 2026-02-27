"""
Tests for CIRCL Passive DNS API endpoints.

Tests cover:
- POST /api/circl/pdns - Single PDNS query
- POST /api/circl/pdns/bulk - Bulk PDNS queries
- GET /api/circl/pdns/download/<query_value> - Download PDNS results
"""

import pytest
import json
from unittest.mock import patch, MagicMock


@pytest.fixture
def mock_circl_pdns_response():
    """Sample CIRCL PDNS response."""
    return [
        {
            'rrname': '8.8.8.8',
            'rrtype': 'A',
            'rdata': 'dns.google',
            'time_first': 1577836800,
            'time_last': 1704067200,
            'count': 1000
        },
        {
            'rrname': '8.8.8.8',
            'rrtype': 'A',
            'rdata': 'google-public-dns-a.google.com',
            'time_first': 1577836800,
            'time_last': 1704067200,
            'count': 500
        }
    ]


class TestCirclPdnsApi:
    """Tests for POST /api/circl/pdns endpoint."""
    
    def test_circl_pdns_requires_auth(self, client):
        """Test that endpoint requires authentication."""
        response = client.post('/api/circl/pdns',
                              json={'value': '8.8.8.8', 'type': 'ip'})
        assert response.status_code in (302, 401, 403)
    
    def test_circl_pdns_no_json(self, authenticated_client):
        """Test error when no JSON provided."""
        response = authenticated_client.post('/api/circl/pdns',
                                             data='not json',
                                             content_type='application/json')
        assert response.status_code == 400
    
    def test_circl_pdns_missing_value(self, authenticated_client):
        """Test error when value not provided."""
        response = authenticated_client.post('/api/circl/pdns',
                                             json={'type': 'ip'})
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'required' in data['error'].lower()
    
    def test_circl_pdns_empty_value(self, authenticated_client):
        """Test error when value is empty."""
        response = authenticated_client.post('/api/circl/pdns',
                                             json={'value': '', 'type': 'ip'})
        assert response.status_code == 400
    
    def test_circl_pdns_invalid_type(self, authenticated_client):
        """Test error when invalid query type."""
        response = authenticated_client.post('/api/circl/pdns',
                                             json={'value': '8.8.8.8', 'type': 'invalid'})
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'Invalid query type' in data['error']
    
    def test_circl_pdns_no_credentials(self, authenticated_client):
        """Test error when CIRCL credentials not configured."""
        with patch('app.get_circl_settings', return_value={'username': '', 'password': ''}):
            response = authenticated_client.post('/api/circl/pdns',
                                                 json={'value': '8.8.8.8', 'type': 'ip'})
            assert response.status_code == 400
            data = json.loads(response.data)
            assert 'credentials not configured' in data['error'].lower()
    
    def test_circl_pdns_returns_cached(self, authenticated_client):
        """Test that cached results are returned."""
        cached_result = {
            'results': [{'rrname': '8.8.8.8', 'rdata': 'dns.google'}],
            'result_count': 1,
            'cached_at': '2024-01-01 00:00:00'
        }
        
        with patch('app.get_circl_settings', return_value={'username': 'user', 'password': 'pass', 'cache_ttl': 3600}):
            with patch('app.get_cached_circl_pdns', return_value=cached_result):
                response = authenticated_client.post('/api/circl/pdns',
                                                     json={'value': '8.8.8.8', 'type': 'ip'})
                assert response.status_code == 200
                data = json.loads(response.data)
                assert data['from_cache'] == True
    
    def test_circl_pdns_success_ip(self, authenticated_client, mock_circl_pdns_response):
        """Test successful IP PDNS query."""
        with patch('app.get_circl_settings', return_value={'username': 'user', 'password': 'pass', 'cache_ttl': 3600}):
            with patch('app.get_cached_circl_pdns', return_value=None):
                with patch('app.query_circl_pdns', return_value=mock_circl_pdns_response):
                    with patch('app.set_cached_circl_pdns'):
                        with patch('app.log_audit'):
                            response = authenticated_client.post('/api/circl/pdns',
                                                                 json={'value': '8.8.8.8', 'type': 'ip'})
                            assert response.status_code == 200
                            data = json.loads(response.data)
                            assert data['query'] == '8.8.8.8'
                            assert data['type'] == 'ip'
                            assert 'results' in data
                            assert data['result_count'] == 2
    
    def test_circl_pdns_success_domain(self, authenticated_client, mock_circl_pdns_response):
        """Test successful domain PDNS query."""
        with patch('app.get_circl_settings', return_value={'username': 'user', 'password': 'pass', 'cache_ttl': 3600}):
            with patch('app.get_cached_circl_pdns', return_value=None):
                with patch('app.query_circl_pdns', return_value=mock_circl_pdns_response):
                    with patch('app.set_cached_circl_pdns'):
                        with patch('app.log_audit'):
                            response = authenticated_client.post('/api/circl/pdns',
                                                                 json={'value': 'example.com', 'type': 'domain'})
                            assert response.status_code == 200
                            data = json.loads(response.data)
                            assert data['type'] == 'domain'
    
    def test_circl_pdns_normalizes_value(self, authenticated_client, mock_circl_pdns_response):
        """Test that query value is normalized (lowercase, stripped)."""
        with patch('app.get_circl_settings', return_value={'username': 'user', 'password': 'pass', 'cache_ttl': 3600}):
            with patch('app.get_cached_circl_pdns', return_value=None) as mock_cache:
                with patch('app.query_circl_pdns', return_value=mock_circl_pdns_response):
                    with patch('app.set_cached_circl_pdns'):
                        with patch('app.log_audit'):
                            response = authenticated_client.post('/api/circl/pdns',
                                                                 json={'value': '  EXAMPLE.COM  ', 'type': 'domain'})
                            assert response.status_code == 200
                            # Should have been normalized
                            mock_cache.assert_called_once_with('example.com', 'domain')
    
    def test_circl_pdns_handles_query_error(self, authenticated_client):
        """Test handling of query errors."""
        with patch('app.get_circl_settings', return_value={'username': 'user', 'password': 'pass', 'cache_ttl': 3600}):
            with patch('app.get_cached_circl_pdns', return_value=None):
                with patch('app.query_circl_pdns', side_effect=Exception('Connection failed')):
                    response = authenticated_client.post('/api/circl/pdns',
                                                         json={'value': '8.8.8.8', 'type': 'ip'})
                    assert response.status_code == 500
                    data = json.loads(response.data)
                    assert 'error' in data
    
    def test_circl_pdns_logs_audit(self, authenticated_client, mock_circl_pdns_response):
        """Test that queries are logged to audit."""
        with patch('app.get_circl_settings', return_value={'username': 'user', 'password': 'pass', 'cache_ttl': 3600}):
            with patch('app.get_cached_circl_pdns', return_value=None):
                with patch('app.query_circl_pdns', return_value=mock_circl_pdns_response):
                    with patch('app.set_cached_circl_pdns'):
                        with patch('app.log_audit') as mock_audit:
                            response = authenticated_client.post('/api/circl/pdns',
                                                                 json={'value': '8.8.8.8', 'type': 'ip'})
                            assert response.status_code == 200
                            mock_audit.assert_called_once()
                            assert mock_audit.call_args[0][0] == 'circl_pdns_query'


class TestCirclPdnsBulkApi:
    """Tests for POST /api/circl/pdns/bulk endpoint."""
    
    def test_circl_pdns_bulk_requires_auth(self, client):
        """Test that endpoint requires authentication."""
        response = client.post('/api/circl/pdns/bulk',
                              json={'queries': ['8.8.8.8'], 'type': 'ip'})
        assert response.status_code in (302, 401, 403)
    
    def test_circl_pdns_bulk_no_json(self, authenticated_client):
        """Test error when no JSON provided."""
        response = authenticated_client.post('/api/circl/pdns/bulk',
                                             data='not json',
                                             content_type='application/json')
        assert response.status_code == 400
    
    def test_circl_pdns_bulk_missing_queries(self, authenticated_client):
        """Test error when queries not provided."""
        response = authenticated_client.post('/api/circl/pdns/bulk',
                                             json={'type': 'ip'})
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'No queries provided' in data['error']
    
    def test_circl_pdns_bulk_empty_queries(self, authenticated_client):
        """Test error when queries list is empty."""
        response = authenticated_client.post('/api/circl/pdns/bulk',
                                             json={'queries': [], 'type': 'ip'})
        assert response.status_code == 400
    
    def test_circl_pdns_bulk_invalid_type(self, authenticated_client):
        """Test error when invalid query type."""
        response = authenticated_client.post('/api/circl/pdns/bulk',
                                             json={'queries': ['8.8.8.8'], 'type': 'invalid'})
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'Invalid query type' in data['error']
    
    def test_circl_pdns_bulk_no_credentials(self, authenticated_client):
        """Test error when CIRCL credentials not configured."""
        with patch('app.get_circl_settings', return_value={'username': '', 'password': ''}):
            response = authenticated_client.post('/api/circl/pdns/bulk',
                                                 json={'queries': ['8.8.8.8'], 'type': 'ip'})
            assert response.status_code == 400
    
    def test_circl_pdns_bulk_success(self, authenticated_client, mock_circl_pdns_response):
        """Test successful bulk PDNS query."""
        cached_result = {
            'results': mock_circl_pdns_response,
            'result_count': len(mock_circl_pdns_response),
            'cached_at': '2024-01-01 00:00:00'
        }
        
        with patch('app.get_circl_settings', return_value={'username': 'user', 'password': 'pass', 'cache_ttl': 3600, 'rate_limit': 5}):
            with patch('app.get_cached_circl_pdns', return_value=cached_result):
                with patch('app.get_concurrency_settings', return_value={'circl_concurrency': 2}):
                    with patch('app.log_audit'):
                        response = authenticated_client.post('/api/circl/pdns/bulk',
                                                             json={'queries': ['8.8.8.8', '1.1.1.1'], 'type': 'ip'})
                        assert response.status_code == 200
                        data = json.loads(response.data)
                        assert 'results' in data
    
    def test_circl_pdns_bulk_default_type(self, authenticated_client, mock_circl_pdns_response):
        """Test that default query type is 'ip'."""
        cached_result = {
            'results': mock_circl_pdns_response,
            'result_count': len(mock_circl_pdns_response),
            'cached_at': '2024-01-01 00:00:00'
        }
        
        with patch('app.get_circl_settings', return_value={'username': 'user', 'password': 'pass', 'cache_ttl': 3600, 'rate_limit': 5}):
            with patch('app.get_cached_circl_pdns', return_value=cached_result) as mock_cache:
                with patch('app.get_concurrency_settings', return_value={'circl_concurrency': 2}):
                    with patch('app.log_audit'):
                        response = authenticated_client.post('/api/circl/pdns/bulk',
                                                             json={'queries': ['8.8.8.8']})
                        assert response.status_code == 200


class TestCirclPdnsDownloadApi:
    """Tests for GET /api/circl/pdns/download/<query_value> endpoint."""
    
    def test_circl_pdns_download_requires_auth(self, client):
        """Test that endpoint requires authentication."""
        response = client.get('/api/circl/pdns/download/8.8.8.8')
        assert response.status_code in (302, 401, 403)
    
    def test_circl_pdns_download_cached_results(self, authenticated_client, mock_circl_pdns_response):
        """Test downloading cached PDNS results."""
        cached_result = {
            'results': mock_circl_pdns_response,
            'result_count': len(mock_circl_pdns_response),
            'cached_at': '2024-01-01 00:00:00'
        }
        
        with patch('app.get_cached_circl_pdns', return_value=cached_result):
            response = authenticated_client.get('/api/circl/pdns/download/8.8.8.8')
            assert response.status_code == 200
            # Should return JSON as attachment
            assert 'application/json' in response.content_type
    
    def test_circl_pdns_download_no_cache(self, authenticated_client):
        """Test download when no cached results."""
        with patch('app.get_cached_circl_pdns', return_value=None):
            response = authenticated_client.get('/api/circl/pdns/download/8.8.8.8')
            assert response.status_code == 404
            data = json.loads(response.data)
            assert 'No cached results' in data['error'] or 'not found' in data['error'].lower()
