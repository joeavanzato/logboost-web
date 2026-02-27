"""
Tests for DNS API endpoints.

Tests cover:
- POST /api/dns/resolve - Single/batch DNS resolution
- POST /api/dns/resolve-bulk - Concurrent bulk DNS resolution
"""

import pytest
import json
from unittest.mock import patch, MagicMock


class TestDnsResolveApi:
    """Tests for /api/dns/resolve endpoint."""
    
    def test_dns_resolve_requires_auth(self, client):
        """Test that endpoint requires authentication."""
        response = client.post('/api/dns/resolve',
                              json={'queries': ['example.com']})
        # Should redirect to login
        assert response.status_code in (302, 401, 403)
    
    def test_dns_resolve_no_json(self, authenticated_client):
        """Test error when no JSON provided."""
        response = authenticated_client.post('/api/dns/resolve',
                                             data='not json',
                                             content_type='application/json')
        assert response.status_code == 400
    
    def test_dns_resolve_empty_queries(self, authenticated_client):
        """Test with empty queries list."""
        with patch('routes.dns.resolve_dns') as mock_resolve:
            with patch('routes.dns.log_audit'):
                response = authenticated_client.post('/api/dns/resolve',
                                                     json={'queries': []})
                assert response.status_code == 200
                data = json.loads(response.data)
                assert 'results' in data
                assert data['results'] == {}
                mock_resolve.assert_not_called()
    
    def test_dns_resolve_single_domain(self, authenticated_client, sample_dns_results):
        """Test resolving a single domain."""
        with patch('routes.dns.resolve_dns', return_value=sample_dns_results) as mock_resolve:
            with patch('routes.dns.log_audit'):
                response = authenticated_client.post('/api/dns/resolve',
                                                     json={'queries': ['example.com']})
                assert response.status_code == 200
                data = json.loads(response.data)
                assert 'results' in data
                assert 'example.com' in data['results']
                assert data['results']['example.com'] == sample_dns_results
                mock_resolve.assert_called_once_with('example.com')
    
    def test_dns_resolve_multiple_domains(self, authenticated_client):
        """Test resolving multiple domains."""
        def mock_resolve_fn(domain):
            return {'A': [f'1.2.3.{hash(domain) % 256}']}
        
        with patch('routes.dns.resolve_dns', side_effect=mock_resolve_fn):
            with patch('routes.dns.log_audit'):
                response = authenticated_client.post('/api/dns/resolve',
                                                     json={'queries': ['example.com', 'test.org', 'sample.net']})
                assert response.status_code == 200
                data = json.loads(response.data)
                assert len(data['results']) == 3
                assert 'example.com' in data['results']
                assert 'test.org' in data['results']
                assert 'sample.net' in data['results']
    
    def test_dns_resolve_strips_whitespace(self, authenticated_client):
        """Test that queries are stripped of whitespace."""
        with patch('routes.dns.resolve_dns', return_value={'A': ['1.2.3.4']}) as mock_resolve:
            with patch('routes.dns.log_audit'):
                response = authenticated_client.post('/api/dns/resolve',
                                                     json={'queries': ['  example.com  ']})
                assert response.status_code == 200
                mock_resolve.assert_called_once_with('example.com')
    
    def test_dns_resolve_skips_empty_queries(self, authenticated_client):
        """Test that empty queries are skipped."""
        with patch('routes.dns.resolve_dns', return_value={'A': ['1.2.3.4']}) as mock_resolve:
            with patch('routes.dns.log_audit'):
                response = authenticated_client.post('/api/dns/resolve',
                                                     json={'queries': ['', '  ', 'example.com', '']})
                assert response.status_code == 200
                # Only example.com should be resolved
                mock_resolve.assert_called_once_with('example.com')
    
    def test_dns_resolve_ip_type_reverse(self, authenticated_client):
        """Test reverse DNS lookup with type=ip."""
        with patch('routes.dns.reverse_dns', return_value=['dns.google']) as mock_reverse:
            with patch('routes.dns.log_audit'):
                response = authenticated_client.post('/api/dns/resolve',
                                                     json={'queries': ['8.8.8.8'], 'type': 'ip'})
                assert response.status_code == 200
                data = json.loads(response.data)
                assert '8.8.8.8' in data['results']
                assert 'PTR' in data['results']['8.8.8.8']
                mock_reverse.assert_called_once_with('8.8.8.8')
    
    def test_dns_resolve_max_queries_exceeded(self, authenticated_client):
        """Test error when max queries exceeded."""
        queries = [f'domain{i}.com' for i in range(1001)]
        
        with patch('routes.dns.get_dns_settings', return_value={'max_domains': 100}):
            response = authenticated_client.post('/api/dns/resolve',
                                                 json={'queries': queries})
            assert response.status_code == 400
            data = json.loads(response.data)
            assert 'Maximum' in data['error']
    
    def test_dns_resolve_logs_audit(self, authenticated_client):
        """Test that DNS queries are logged to audit."""
        with patch('routes.dns.resolve_dns', return_value={'A': ['1.2.3.4']}):
            with patch('routes.dns.log_audit') as mock_audit:
                response = authenticated_client.post('/api/dns/resolve',
                                                     json={'queries': ['example.com', 'test.org']})
                assert response.status_code == 200
                mock_audit.assert_called_once()
                call_args = mock_audit.call_args
                assert call_args[0][0] == 'dns_query'
    
    def test_dns_resolve_default_type_is_domain(self, authenticated_client):
        """Test that default type is 'domain' not 'ip'."""
        with patch('routes.dns.resolve_dns', return_value={'A': ['1.2.3.4']}) as mock_resolve:
            with patch('routes.dns.reverse_dns') as mock_reverse:
                with patch('routes.dns.log_audit'):
                    response = authenticated_client.post('/api/dns/resolve',
                                                         json={'queries': ['example.com']})
                    assert response.status_code == 200
                    mock_resolve.assert_called_once()
                    mock_reverse.assert_not_called()


class TestDnsResolveBulkApi:
    """Tests for /api/dns/resolve-bulk endpoint."""
    
    def test_dns_bulk_requires_auth(self, client):
        """Test that endpoint requires authentication."""
        response = client.post('/api/dns/resolve-bulk',
                              json={'queries': ['example.com']})
        assert response.status_code in (302, 401, 403)
    
    def test_dns_bulk_no_json(self, authenticated_client):
        """Test error when no JSON provided."""
        response = authenticated_client.post('/api/dns/resolve-bulk',
                                             data='not json',
                                             content_type='application/json')
        assert response.status_code == 400
    
    def test_dns_bulk_single_domain(self, authenticated_client, sample_dns_results):
        """Test bulk resolve with single domain."""
        with patch('routes.dns.resolve_dns', return_value=sample_dns_results):
            with patch('routes.dns.get_concurrency_settings', return_value={'dns_concurrency': 5}):
                with patch('routes.dns.log_audit'):
                    response = authenticated_client.post('/api/dns/resolve-bulk',
                                                         json={'queries': ['example.com']})
                    assert response.status_code == 200
                    data = json.loads(response.data)
                    assert 'example.com' in data['results']
    
    def test_dns_bulk_multiple_domains(self, authenticated_client):
        """Test bulk resolve with multiple domains."""
        def mock_resolve_fn(domain):
            return {'A': [f'1.2.3.{hash(domain) % 256}']}
        
        with patch('routes.dns.resolve_dns', side_effect=mock_resolve_fn):
            with patch('routes.dns.get_concurrency_settings', return_value={'dns_concurrency': 5}):
                with patch('routes.dns.log_audit'):
                    queries = ['example.com', 'test.org', 'sample.net', 'demo.io']
                    response = authenticated_client.post('/api/dns/resolve-bulk',
                                                         json={'queries': queries})
                    assert response.status_code == 200
                    data = json.loads(response.data)
                    assert len(data['results']) == 4
    
    def test_dns_bulk_ip_type_reverse(self, authenticated_client):
        """Test bulk reverse DNS with type=ip."""
        with patch('routes.dns.reverse_dns', return_value=['dns.google']):
            with patch('routes.dns.get_concurrency_settings', return_value={'dns_concurrency': 5}):
                with patch('routes.dns.log_audit'):
                    response = authenticated_client.post('/api/dns/resolve-bulk',
                                                         json={'queries': ['8.8.8.8', '1.1.1.1'], 'type': 'ip'})
                    assert response.status_code == 200
                    data = json.loads(response.data)
                    assert '8.8.8.8' in data['results']
                    assert 'PTR' in data['results']['8.8.8.8']
    
    def test_dns_bulk_handles_errors_per_query(self, authenticated_client):
        """Test that errors are handled per-query, not failing entire batch."""
        def mock_resolve_fn(domain):
            if 'error' in domain:
                raise Exception('DNS resolution failed')
            return {'A': ['1.2.3.4']}
        
        with patch('routes.dns.resolve_dns', side_effect=mock_resolve_fn):
            with patch('routes.dns.get_concurrency_settings', return_value={'dns_concurrency': 5}):
                with patch('routes.dns.log_audit'):
                    response = authenticated_client.post('/api/dns/resolve-bulk',
                                                         json={'queries': ['good.com', 'error.com']})
                    assert response.status_code == 200
                    data = json.loads(response.data)
                    # good.com should succeed
                    assert 'good.com' in data['results']
                    # error.com should have error message
                    assert 'error.com' in data['results']
                    assert 'error' in data['results']['error.com']
    
    def test_dns_bulk_max_queries_exceeded(self, authenticated_client):
        """Test error when max queries exceeded."""
        queries = [f'domain{i}.com' for i in range(1001)]
        
        with patch('routes.dns.get_dns_settings', return_value={'max_domains': 100}):
            response = authenticated_client.post('/api/dns/resolve-bulk',
                                                 json={'queries': queries})
            assert response.status_code == 400
            data = json.loads(response.data)
            assert 'Maximum' in data['error']
    
    def test_dns_bulk_logs_audit(self, authenticated_client):
        """Test that bulk DNS queries are logged to audit."""
        with patch('routes.dns.resolve_dns', return_value={'A': ['1.2.3.4']}):
            with patch('routes.dns.get_concurrency_settings', return_value={'dns_concurrency': 5}):
                with patch('routes.dns.log_audit') as mock_audit:
                    response = authenticated_client.post('/api/dns/resolve-bulk',
                                                         json={'queries': ['example.com', 'test.org']})
                    assert response.status_code == 200
                    mock_audit.assert_called_once()
                    call_args = mock_audit.call_args
                    assert call_args[0][0] == 'dns_query_bulk'
    
    def test_dns_bulk_empty_queries_skipped(self, authenticated_client):
        """Test that empty queries are skipped in bulk."""
        with patch('routes.dns.resolve_dns', return_value={'A': ['1.2.3.4']}):
            with patch('routes.dns.get_concurrency_settings', return_value={'dns_concurrency': 5}):
                with patch('routes.dns.log_audit'):
                    response = authenticated_client.post('/api/dns/resolve-bulk',
                                                         json={'queries': ['', 'example.com', '  ']})
                    assert response.status_code == 200
                    data = json.loads(response.data)
                    # Only example.com should be in results
                    assert 'example.com' in data['results']
                    assert '' not in data['results']
