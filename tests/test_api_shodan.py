"""
Tests for Shodan API endpoints.

Tests cover:
- POST /api/shodan/resolve - Shodan IP/domain lookup
- POST /api/shodan/pivot - Arbitrary Shodan query pivot
- POST /api/shodan/pivot-jarm - JARM fingerprint pivot
"""

import pytest
import json
import sys
from unittest.mock import patch, MagicMock


# Create mock shodan module for tests
class MockShodanAPIError(Exception):
    """Mock Shodan API Error."""
    pass


class MockShodanModule:
    """Mock Shodan module."""
    APIError = MockShodanAPIError
    
    @staticmethod
    def Shodan(api_key):
        return MagicMock()


# Ensure mock is available
if 'shodan' not in sys.modules:
    sys.modules['shodan'] = MockShodanModule()


@pytest.fixture
def mock_shodan_host_response():
    """Sample Shodan host response for IP lookup."""
    return {
        'ip_str': '8.8.8.8',
        'hostnames': ['dns.google'],
        'org': 'Google LLC',
        'country_name': 'United States',
        'asn': 'AS15169',
        'ports': [53, 443],
        'data': [
            {
                'port': 443,
                'transport': 'tcp',
                'ssl': {
                    'jarm': '29d29d00029d29d00042d43d00041d44609a459e553d63294a6820b5f89751'
                }
            },
            {
                'port': 53,
                'transport': 'udp'
            }
        ]
    }


@pytest.fixture
def mock_shodan_search_response():
    """Sample Shodan search response for domain/JARM queries."""
    return {
        'total': 150,
        'matches': [
            {
                'ip_str': '1.1.1.1',
                'port': 443,
                'hostnames': ['one.one.one.one'],
                'org': 'Cloudflare',
                'isp': 'Cloudflare Inc',
                'asn': 'AS13335',
                'location': {'country_name': 'Australia'},
                'ssl': {
                    'jarm': '29d29d00029d29d00042d43d00041d44609a459e553d63294a6820b5f89751'
                }
            },
            {
                'ip_str': '9.9.9.9',
                'port': 443,
                'hostnames': ['dns.quad9.net'],
                'org': 'Quad9',
                'isp': 'Quad9',
                'asn': 'AS19281',
                'location': {'country_name': 'United States'},
                'ssl': {
                    'jarm': '29d29d00029d29d00042d43d00041d44609a459e553d63294a6820b5f89751'
                }
            }
        ]
    }


@pytest.fixture
def valid_jarm():
    """Valid 62-character JARM fingerprint."""
    return '29d29d00029d29d00042d43d00041d44609a459e553d63294a6820b5f89751'


@pytest.fixture
def mock_shodan_api():
    """Create a mock Shodan API instance."""
    return MagicMock()


# =============================================================================
# Tests for /api/shodan/resolve
# =============================================================================

class TestShodanResolveApi:
    """Tests for POST /api/shodan/resolve endpoint."""
    
    def test_shodan_resolve_requires_auth(self, client):
        """Test that endpoint requires authentication."""
        response = client.post('/api/shodan/resolve',
                              json={'value': '8.8.8.8', 'type': 'ip'})
        assert response.status_code in (302, 401, 403)
    
    def test_shodan_resolve_no_json(self, authenticated_client):
        """Test error when no JSON provided."""
        with patch('app.SHODAN_AVAILABLE', True):
            response = authenticated_client.post('/api/shodan/resolve',
                                                 data='not json',
                                                 content_type='application/json')
            assert response.status_code == 400
    
    def test_shodan_resolve_missing_value(self, authenticated_client):
        """Test error when value not provided."""
        with patch('app.SHODAN_AVAILABLE', True):
            response = authenticated_client.post('/api/shodan/resolve',
                                                 json={'type': 'ip'})
            assert response.status_code == 400
            data = json.loads(response.data)
            assert 'Value is required' in data['error']
    
    def test_shodan_resolve_empty_value(self, authenticated_client):
        """Test error when value is empty."""
        with patch('app.SHODAN_AVAILABLE', True):
            response = authenticated_client.post('/api/shodan/resolve',
                                                 json={'value': '', 'type': 'ip'})
            assert response.status_code == 400
    
    def test_shodan_resolve_library_not_available(self, authenticated_client):
        """Test error when Shodan library not installed."""
        with patch('app.SHODAN_AVAILABLE', False):
            response = authenticated_client.post('/api/shodan/resolve',
                                                 json={'value': '8.8.8.8', 'type': 'ip'})
            assert response.status_code == 500
            data = json.loads(response.data)
            assert 'not installed' in data['error']
    
    def test_shodan_resolve_no_api_key(self, authenticated_client):
        """Test error when API key not configured."""
        with patch('app.SHODAN_AVAILABLE', True):
            with patch('app.get_cached_shodan', return_value=None):
                with patch('app.get_shodan_api_key', return_value=None):
                    response = authenticated_client.post('/api/shodan/resolve',
                                                         json={'value': '8.8.8.8', 'type': 'ip'})
                    assert response.status_code == 400
                    data = json.loads(response.data)
                    assert 'API key not configured' in data['error']
    
    def test_shodan_resolve_returns_cached(self, authenticated_client):
        """Test that cached results are returned."""
        cached_result = {
            'value': '8.8.8.8',
            'type': 'ip',
            'host_info': {'org': 'Google'}
        }
        
        with patch('app.SHODAN_AVAILABLE', True):
            with patch('app.get_cached_shodan', return_value=cached_result):
                response = authenticated_client.post('/api/shodan/resolve',
                                                     json={'value': '8.8.8.8', 'type': 'ip'})
                assert response.status_code == 200
                data = json.loads(response.data)
                assert data['cached'] == True
    
    def test_shodan_resolve_default_type_is_ip(self, authenticated_client):
        """Test that default type is 'ip'."""
        cached = {'value': '8.8.8.8', 'type': 'ip', 'host_info': {}}
        
        with patch('app.SHODAN_AVAILABLE', True):
            with patch('app.get_cached_shodan', return_value=cached) as mock_cache:
                response = authenticated_client.post('/api/shodan/resolve',
                                                     json={'value': '8.8.8.8'})
                assert response.status_code == 200
                # Should have been called with type='ip'
                mock_cache.assert_called_once_with('8.8.8.8', 'ip')
    
    def test_shodan_resolve_ip_success(self, authenticated_client, mock_shodan_host_response, mock_shodan_api):
        """Test successful IP lookup."""
        mock_shodan_api.host.return_value = mock_shodan_host_response
        
        with patch('app.SHODAN_AVAILABLE', True):
            with patch('app.get_cached_shodan', return_value=None):
                with patch('app.get_shodan_api_key', return_value='test_api_key'):
                    with patch('app.shodan') as mock_shodan_module:
                        mock_shodan_module.Shodan.return_value = mock_shodan_api
                        with patch('app.get_shodan_cache_settings', return_value={'cache_ttl': 3600}):
                            with patch('app.set_cached_shodan'):
                                with patch('app.log_audit'):
                                    response = authenticated_client.post('/api/shodan/resolve',
                                                                         json={'value': '8.8.8.8', 'type': 'ip'})
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        assert data['value'] == '8.8.8.8'
        assert data['type'] == 'ip'
        assert 'host_info' in data
        assert data['host_info']['org'] == 'Google LLC'
        assert 'jarms' in data
        assert len(data['jarms']) > 0
    
    def test_shodan_resolve_ip_extracts_jarm(self, authenticated_client, mock_shodan_host_response, mock_shodan_api):
        """Test that JARM fingerprints are extracted from IP response."""
        mock_shodan_api.host.return_value = mock_shodan_host_response
        
        with patch('app.SHODAN_AVAILABLE', True):
            with patch('app.get_cached_shodan', return_value=None):
                with patch('app.get_shodan_api_key', return_value='test_api_key'):
                    with patch('app.shodan') as mock_shodan_module:
                        mock_shodan_module.Shodan.return_value = mock_shodan_api
                        with patch('app.get_shodan_cache_settings', return_value={'cache_ttl': 3600}):
                            with patch('app.set_cached_shodan'):
                                with patch('app.log_audit'):
                                    response = authenticated_client.post('/api/shodan/resolve',
                                                                         json={'value': '8.8.8.8', 'type': 'ip'})
        
        data = json.loads(response.data)
        assert len(data['jarms']) == 1
        jarm_entry = data['jarms'][0]
        assert jarm_entry['jarm'] == '29d29d00029d29d00042d43d00041d44609a459e553d63294a6820b5f89751'
        assert jarm_entry['source_ip'] == '8.8.8.8'
        assert jarm_entry['port'] == 443
    
    def test_shodan_resolve_ip_no_data(self, authenticated_client, mock_shodan_api):
        """Test IP lookup when Shodan has no data."""
        mock_shodan_api.host.side_effect = MockShodanAPIError('No information available for that IP')
        
        with patch('app.SHODAN_AVAILABLE', True):
            with patch('app.get_cached_shodan', return_value=None):
                with patch('app.get_shodan_api_key', return_value='test_api_key'):
                    with patch('app.shodan') as mock_shodan_module:
                        mock_shodan_module.Shodan.return_value = mock_shodan_api
                        mock_shodan_module.APIError = MockShodanAPIError
                        with patch('app.get_shodan_cache_settings', return_value={'cache_ttl': 3600}):
                            with patch('app.set_cached_shodan'):
                                with patch('app.log_audit'):
                                    response = authenticated_client.post('/api/shodan/resolve',
                                                                         json={'value': '192.168.1.1', 'type': 'ip'})
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['message'] == 'No Shodan data available for this IP'
        assert data['jarms'] == []
    
    def test_shodan_resolve_domain_success(self, authenticated_client, mock_shodan_search_response, mock_shodan_api):
        """Test successful domain lookup."""
        mock_shodan_api.search.return_value = mock_shodan_search_response
        
        with patch('app.SHODAN_AVAILABLE', True):
            with patch('app.get_cached_shodan', return_value=None):
                with patch('app.get_shodan_api_key', return_value='test_api_key'):
                    with patch('app.shodan') as mock_shodan_module:
                        mock_shodan_module.Shodan.return_value = mock_shodan_api
                        with patch('app.get_shodan_cache_settings', return_value={'cache_ttl': 3600}):
                            with patch('app.set_cached_shodan'):
                                with patch('app.log_audit'):
                                    response = authenticated_client.post('/api/shodan/resolve',
                                                                         json={'value': 'example.com', 'type': 'domain'})
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        assert data['value'] == 'example.com'
        assert data['type'] == 'domain'
        assert 'host_info' in data
        host_info = data['host_info']
        assert host_info['domain'] == 'example.com'
        assert host_info['total_results'] == 150
        assert host_info['unique_ips'] == 2
        assert 'one.one.one.one' in host_info['hostnames']
        
        # Check IPs were collected
        ip_addrs = [ip['ip'] for ip in host_info['ips']]
        assert '1.1.1.1' in ip_addrs
        assert '9.9.9.9' in ip_addrs
    
    def test_shodan_resolve_domain_extracts_jarm(self, authenticated_client, mock_shodan_search_response, mock_shodan_api):
        """Test that JARM fingerprints are extracted from domain response."""
        mock_shodan_api.search.return_value = mock_shodan_search_response
        
        with patch('app.SHODAN_AVAILABLE', True):
            with patch('app.get_cached_shodan', return_value=None):
                with patch('app.get_shodan_api_key', return_value='test_api_key'):
                    with patch('app.shodan') as mock_shodan_module:
                        mock_shodan_module.Shodan.return_value = mock_shodan_api
                        with patch('app.get_shodan_cache_settings', return_value={'cache_ttl': 3600}):
                            with patch('app.set_cached_shodan'):
                                with patch('app.log_audit'):
                                    response = authenticated_client.post('/api/shodan/resolve',
                                                                         json={'value': 'example.com', 'type': 'domain'})
        
        data = json.loads(response.data)
        # Should have one unique JARM (both matches have the same JARM)
        assert len(data['jarms']) == 1
    
    def test_shodan_resolve_domain_no_data(self, authenticated_client, mock_shodan_api):
        """Test domain lookup when Shodan has no data."""
        mock_shodan_api.search.side_effect = MockShodanAPIError('No information available')
        
        with patch('app.SHODAN_AVAILABLE', True):
            with patch('app.get_cached_shodan', return_value=None):
                with patch('app.get_shodan_api_key', return_value='test_api_key'):
                    with patch('app.shodan') as mock_shodan_module:
                        mock_shodan_module.Shodan.return_value = mock_shodan_api
                        mock_shodan_module.APIError = MockShodanAPIError
                        with patch('app.get_shodan_cache_settings', return_value={'cache_ttl': 3600}):
                            with patch('app.set_cached_shodan'):
                                with patch('app.log_audit'):
                                    response = authenticated_client.post('/api/shodan/resolve',
                                                                         json={'value': 'unknown.example', 'type': 'domain'})
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['message'] == 'No Shodan data available for this domain'
    
    def test_shodan_resolve_api_error(self, authenticated_client, mock_shodan_api):
        """Test handling of general Shodan API errors."""
        mock_shodan_api.host.side_effect = MockShodanAPIError('Rate limit exceeded')
        
        with patch('app.SHODAN_AVAILABLE', True):
            with patch('app.get_cached_shodan', return_value=None):
                with patch('app.get_shodan_api_key', return_value='test_api_key'):
                    with patch('app.shodan') as mock_shodan_module:
                        mock_shodan_module.Shodan.return_value = mock_shodan_api
                        mock_shodan_module.APIError = MockShodanAPIError
                        with patch('app.log_audit'):
                            response = authenticated_client.post('/api/shodan/resolve',
                                                                 json={'value': '8.8.8.8', 'type': 'ip'})
        
        assert response.status_code == 500
        data = json.loads(response.data)
        assert 'Shodan API error' in data['error']
    
    def test_shodan_resolve_caches_result(self, authenticated_client, mock_shodan_host_response, mock_shodan_api):
        """Test that results are cached after fetching."""
        mock_shodan_api.host.return_value = mock_shodan_host_response
        
        with patch('app.SHODAN_AVAILABLE', True):
            with patch('app.get_cached_shodan', return_value=None):
                with patch('app.get_shodan_api_key', return_value='test_api_key'):
                    with patch('app.shodan') as mock_shodan_module:
                        mock_shodan_module.Shodan.return_value = mock_shodan_api
                        with patch('app.get_shodan_cache_settings', return_value={'cache_ttl': 3600}):
                            with patch('app.set_cached_shodan') as mock_set_cache:
                                with patch('app.log_audit'):
                                    response = authenticated_client.post('/api/shodan/resolve',
                                                                         json={'value': '8.8.8.8', 'type': 'ip'})
        
        assert response.status_code == 200
        # Verify cache was set
        mock_set_cache.assert_called_once()
        args = mock_set_cache.call_args[0]
        assert args[0] == '8.8.8.8'  # value
        assert args[1] == 'ip'  # type
        assert args[3] == 3600  # TTL


# =============================================================================
# Tests for /api/shodan/pivot
# =============================================================================

class TestShodanPivotApi:
    """Tests for POST /api/shodan/pivot endpoint."""
    
    def test_shodan_pivot_requires_auth(self, client):
        """Test that endpoint requires authentication."""
        response = client.post('/api/shodan/pivot',
                              json={'query': 'ssl.jarm:abc123'})
        assert response.status_code in (302, 401, 403)
    
    def test_shodan_pivot_no_json(self, authenticated_client):
        """Test error when no JSON provided."""
        with patch('app.SHODAN_AVAILABLE', True):
            response = authenticated_client.post('/api/shodan/pivot',
                                                 data='not json',
                                                 content_type='application/json')
            assert response.status_code == 400
    
    def test_shodan_pivot_missing_query(self, authenticated_client):
        """Test error when query not provided."""
        with patch('app.SHODAN_AVAILABLE', True):
            response = authenticated_client.post('/api/shodan/pivot',
                                                 json={'source_ip': '8.8.8.8'})
            assert response.status_code == 400
            data = json.loads(response.data)
            assert 'Query is required' in data['error']
    
    def test_shodan_pivot_empty_query(self, authenticated_client):
        """Test error when query is empty."""
        with patch('app.SHODAN_AVAILABLE', True):
            response = authenticated_client.post('/api/shodan/pivot',
                                                 json={'query': ''})
            assert response.status_code == 400
    
    def test_shodan_pivot_whitespace_query(self, authenticated_client):
        """Test error when query is only whitespace."""
        with patch('app.SHODAN_AVAILABLE', True):
            response = authenticated_client.post('/api/shodan/pivot',
                                                 json={'query': '   '})
            assert response.status_code == 400
    
    def test_shodan_pivot_library_not_available(self, authenticated_client):
        """Test error when Shodan library not installed."""
        with patch('app.SHODAN_AVAILABLE', False):
            response = authenticated_client.post('/api/shodan/pivot',
                                                 json={'query': 'ssl.jarm:abc123'})
            assert response.status_code == 500
    
    def test_shodan_pivot_no_api_key(self, authenticated_client):
        """Test error when API key not configured."""
        with patch('app.SHODAN_AVAILABLE', True):
            with patch('app.get_shodan_api_key', return_value=None):
                response = authenticated_client.post('/api/shodan/pivot',
                                                     json={'query': 'ssl.jarm:abc123'})
                assert response.status_code == 400
                data = json.loads(response.data)
                assert 'API key not configured' in data['error']
    
    def test_shodan_pivot_success(self, authenticated_client, mock_shodan_search_response, mock_shodan_api):
        """Test successful pivot query."""
        mock_shodan_api.search.return_value = mock_shodan_search_response
        
        with patch('app.SHODAN_AVAILABLE', True):
            with patch('app.get_shodan_api_key', return_value='test_api_key'):
                with patch('app.shodan') as mock_shodan_module:
                    mock_shodan_module.Shodan.return_value = mock_shodan_api
                    with patch('app.get_shodan_pivot_limit', return_value=100):
                        with patch('app.log_audit'):
                            response = authenticated_client.post('/api/shodan/pivot',
                                                                 json={'query': 'org:"Google"'})
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        assert data['query'] == 'org:"Google"'
        assert data['total_results'] == 150
        assert len(data['ips']) == 2
        assert '1.1.1.1' in data['ips']
        assert '9.9.9.9' in data['ips']
        assert len(data['hosts']) == 2
    
    def test_shodan_pivot_excludes_source_ip(self, authenticated_client, mock_shodan_search_response, mock_shodan_api):
        """Test that source IP is excluded from results."""
        mock_shodan_api.search.return_value = mock_shodan_search_response
        
        with patch('app.SHODAN_AVAILABLE', True):
            with patch('app.get_shodan_api_key', return_value='test_api_key'):
                with patch('app.shodan') as mock_shodan_module:
                    mock_shodan_module.Shodan.return_value = mock_shodan_api
                    with patch('app.get_shodan_pivot_limit', return_value=100):
                        with patch('app.log_audit'):
                            response = authenticated_client.post('/api/shodan/pivot',
                                                                 json={'query': 'org:"Cloudflare"',
                                                                       'source_ip': '1.1.1.1'})
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        # Source IP should be excluded
        assert '1.1.1.1' not in data['ips']
        assert '9.9.9.9' in data['ips']
        assert len(data['ips']) == 1
    
    def test_shodan_pivot_limited_results(self, authenticated_client, mock_shodan_api):
        """Test that limited results are indicated."""
        mock_response = {
            'total': 500,  # More than we return
            'matches': [
                {'ip_str': f'1.1.1.{i}', 'port': 443, 'hostnames': [], 'org': 'Test',
                 'location': {'country_name': 'US'}, 'asn': 'AS1234'}
                for i in range(10)
            ]
        }
        
        mock_shodan_api.search.return_value = mock_response
        
        with patch('app.SHODAN_AVAILABLE', True):
            with patch('app.get_shodan_api_key', return_value='test_api_key'):
                with patch('app.shodan') as mock_shodan_module:
                    mock_shodan_module.Shodan.return_value = mock_shodan_api
                    with patch('app.get_shodan_pivot_limit', return_value=10):
                        with patch('app.log_audit'):
                            response = authenticated_client.post('/api/shodan/pivot',
                                                                 json={'query': 'org:"Test"'})
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        assert data['limited'] == True
        assert data['total_results'] == 500
        assert 'limit_message' in data
    
    def test_shodan_pivot_normalizes_query_whitespace(self, authenticated_client, mock_shodan_search_response, mock_shodan_api):
        """Test that query whitespace is normalized."""
        mock_shodan_api.search.return_value = mock_shodan_search_response
        
        with patch('app.SHODAN_AVAILABLE', True):
            with patch('app.get_shodan_api_key', return_value='test_api_key'):
                with patch('app.shodan') as mock_shodan_module:
                    mock_shodan_module.Shodan.return_value = mock_shodan_api
                    with patch('app.get_shodan_pivot_limit', return_value=100):
                        with patch('app.log_audit'):
                            response = authenticated_client.post('/api/shodan/pivot',
                                                                 json={'query': '  org:"Google"   country:US  '})
        
        assert response.status_code == 200
        data = json.loads(response.data)
        # Query should be normalized
        assert data['query'] == 'org:"Google" country:US'
    
    def test_shodan_pivot_api_error(self, authenticated_client, mock_shodan_api):
        """Test handling of Shodan API errors."""
        mock_shodan_api.search.side_effect = MockShodanAPIError('Query syntax error')
        
        with patch('app.SHODAN_AVAILABLE', True):
            with patch('app.get_shodan_api_key', return_value='test_api_key'):
                with patch('app.shodan') as mock_shodan_module:
                    mock_shodan_module.Shodan.return_value = mock_shodan_api
                    mock_shodan_module.APIError = MockShodanAPIError
                    with patch('app.get_shodan_pivot_limit', return_value=100):
                        response = authenticated_client.post('/api/shodan/pivot',
                                                             json={'query': 'invalid[query'})
        
        assert response.status_code == 500
        data = json.loads(response.data)
        assert 'Shodan API error' in data['error']
    
    def test_shodan_pivot_host_info(self, authenticated_client, mock_shodan_search_response, mock_shodan_api):
        """Test that host info is properly extracted."""
        mock_shodan_api.search.return_value = mock_shodan_search_response
        
        with patch('app.SHODAN_AVAILABLE', True):
            with patch('app.get_shodan_api_key', return_value='test_api_key'):
                with patch('app.shodan') as mock_shodan_module:
                    mock_shodan_module.Shodan.return_value = mock_shodan_api
                    with patch('app.get_shodan_pivot_limit', return_value=100):
                        with patch('app.log_audit'):
                            response = authenticated_client.post('/api/shodan/pivot',
                                                                 json={'query': 'org:"Cloudflare"'})
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        # Check host info structure
        hosts = data['hosts']
        assert len(hosts) == 2
        
        # Check first host
        cloudflare_host = next(h for h in hosts if h['ip'] == '1.1.1.1')
        assert cloudflare_host['port'] == 443
        assert cloudflare_host['org'] == 'Cloudflare'
        assert cloudflare_host['country'] == 'Australia'
        assert cloudflare_host['asn'] == 'AS13335'


# =============================================================================
# Tests for /api/shodan/pivot-jarm
# =============================================================================

class TestShodanPivotJarmApi:
    """Tests for POST /api/shodan/pivot-jarm endpoint."""
    
    def test_shodan_pivot_jarm_requires_auth(self, client, valid_jarm):
        """Test that endpoint requires authentication."""
        response = client.post('/api/shodan/pivot-jarm',
                              json={'jarm': valid_jarm})
        assert response.status_code in (302, 401, 403)
    
    def test_shodan_pivot_jarm_no_json(self, authenticated_client):
        """Test error when no JSON provided."""
        with patch('app.SHODAN_AVAILABLE', True):
            response = authenticated_client.post('/api/shodan/pivot-jarm',
                                                 data='not json',
                                                 content_type='application/json')
            assert response.status_code == 400
    
    def test_shodan_pivot_jarm_missing_jarm(self, authenticated_client):
        """Test error when JARM not provided."""
        with patch('app.SHODAN_AVAILABLE', True):
            response = authenticated_client.post('/api/shodan/pivot-jarm',
                                                 json={'source_ip': '8.8.8.8'})
            assert response.status_code == 400
    
    def test_shodan_pivot_jarm_empty_jarm(self, authenticated_client):
        """Test error when JARM is empty."""
        with patch('app.SHODAN_AVAILABLE', True):
            response = authenticated_client.post('/api/shodan/pivot-jarm',
                                                 json={'jarm': ''})
            assert response.status_code == 400
    
    def test_shodan_pivot_jarm_invalid_length(self, authenticated_client):
        """Test error when JARM has invalid length."""
        with patch('app.SHODAN_AVAILABLE', True):
            response = authenticated_client.post('/api/shodan/pivot-jarm',
                                                 json={'jarm': 'abc123'})  # Too short
            assert response.status_code == 400
            data = json.loads(response.data)
            assert 'Invalid JARM fingerprint format' in data['error']
    
    def test_shodan_pivot_jarm_invalid_characters(self, authenticated_client):
        """Test error when JARM has invalid characters."""
        with patch('app.SHODAN_AVAILABLE', True):
            # Valid length but invalid characters
            invalid_jarm = 'gg' + '0' * 60  # 'gg' not valid hex
            response = authenticated_client.post('/api/shodan/pivot-jarm',
                                                 json={'jarm': invalid_jarm})
            assert response.status_code == 400
            data = json.loads(response.data)
            assert 'Invalid JARM fingerprint format' in data['error']
    
    def test_shodan_pivot_jarm_library_not_available(self, authenticated_client, valid_jarm):
        """Test error when Shodan library not installed."""
        with patch('app.SHODAN_AVAILABLE', False):
            response = authenticated_client.post('/api/shodan/pivot-jarm',
                                                 json={'jarm': valid_jarm})
            assert response.status_code == 500
    
    def test_shodan_pivot_jarm_no_api_key(self, authenticated_client, valid_jarm):
        """Test error when API key not configured."""
        with patch('app.SHODAN_AVAILABLE', True):
            with patch('app.get_cached_shodan_pivot', return_value=None):
                with patch('app.get_shodan_api_key', return_value=None):
                    response = authenticated_client.post('/api/shodan/pivot-jarm',
                                                         json={'jarm': valid_jarm})
                    assert response.status_code == 400
    
    def test_shodan_pivot_jarm_returns_cached(self, authenticated_client, valid_jarm):
        """Test that cached pivot results are returned."""
        cached_result = {
            'results': {
                'jarm': valid_jarm,
                'ips': ['1.1.1.1'],
                'total_results': 1
            }
        }
        
        with patch('app.SHODAN_AVAILABLE', True):
            with patch('app.get_cached_shodan_pivot', return_value=cached_result):
                response = authenticated_client.post('/api/shodan/pivot-jarm',
                                                     json={'jarm': valid_jarm})
                assert response.status_code == 200
                data = json.loads(response.data)
                assert data.get('from_cache') == True
    
    def test_shodan_pivot_jarm_success(self, authenticated_client, valid_jarm, mock_shodan_search_response, mock_shodan_api):
        """Test successful JARM pivot."""
        mock_shodan_api.search.return_value = mock_shodan_search_response
        
        with patch('app.SHODAN_AVAILABLE', True):
            with patch('app.get_cached_shodan_pivot', return_value=None):
                with patch('app.get_shodan_api_key', return_value='test_api_key'):
                    with patch('app.shodan') as mock_shodan_module:
                        mock_shodan_module.Shodan.return_value = mock_shodan_api
                        with patch('app.get_shodan_cache_settings', return_value={'cache_ttl': 3600}):
                            with patch('app.set_cached_shodan_pivot'):
                                with patch('app.log_audit'):
                                    response = authenticated_client.post('/api/shodan/pivot-jarm',
                                                                         json={'jarm': valid_jarm})
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        assert data['jarm'] == valid_jarm
        assert data['total_results'] == 150
        assert '1.1.1.1' in data['ips']
        assert '9.9.9.9' in data['ips']
        assert 'one.one.one.one' in data['hostnames']
        assert 'dns.quad9.net' in data['hostnames']
    
    def test_shodan_pivot_jarm_hosts_info(self, authenticated_client, valid_jarm, mock_shodan_search_response, mock_shodan_api):
        """Test that hosts info is properly returned."""
        mock_shodan_api.search.return_value = mock_shodan_search_response
        
        with patch('app.SHODAN_AVAILABLE', True):
            with patch('app.get_cached_shodan_pivot', return_value=None):
                with patch('app.get_shodan_api_key', return_value='test_api_key'):
                    with patch('app.shodan') as mock_shodan_module:
                        mock_shodan_module.Shodan.return_value = mock_shodan_api
                        with patch('app.get_shodan_cache_settings', return_value={'cache_ttl': 3600}):
                            with patch('app.set_cached_shodan_pivot'):
                                with patch('app.log_audit'):
                                    response = authenticated_client.post('/api/shodan/pivot-jarm',
                                                                         json={'jarm': valid_jarm})
        
        data = json.loads(response.data)
        
        # Check hosts structure
        assert len(data['hosts']) == 2
        
        cloudflare = next(h for h in data['hosts'] if h['ip'] == '1.1.1.1')
        assert cloudflare['port'] == 443
        assert cloudflare['org'] == 'Cloudflare'
        assert cloudflare['country'] == 'Australia'
    
    def test_shodan_pivot_jarm_limited_results(self, authenticated_client, valid_jarm, mock_shodan_api):
        """Test handling of limited results."""
        mock_response = {
            'total': 500,  # More than 100 limit
            'matches': [
                {'ip_str': f'1.1.1.{i}', 'port': 443, 'hostnames': [f'host{i}.example.com'],
                 'org': 'Test', 'location': {'country_name': 'US'}}
                for i in range(100)
            ]
        }
        
        mock_shodan_api.search.return_value = mock_response
        
        with patch('app.SHODAN_AVAILABLE', True):
            with patch('app.get_cached_shodan_pivot', return_value=None):
                with patch('app.get_shodan_api_key', return_value='test_api_key'):
                    with patch('app.shodan') as mock_shodan_module:
                        mock_shodan_module.Shodan.return_value = mock_shodan_api
                        with patch('app.get_shodan_cache_settings', return_value={'cache_ttl': 3600}):
                            with patch('app.set_cached_shodan_pivot'):
                                with patch('app.log_audit'):
                                    response = authenticated_client.post('/api/shodan/pivot-jarm',
                                                                         json={'jarm': valid_jarm})
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        assert data['limited'] == True
        assert data['total_results'] == 500
        assert 'limit_message' in data
        assert '100 of 500' in data['limit_message']
    
    def test_shodan_pivot_jarm_caches_result(self, authenticated_client, valid_jarm, mock_shodan_search_response, mock_shodan_api):
        """Test that pivot results are cached."""
        mock_shodan_api.search.return_value = mock_shodan_search_response
        
        with patch('app.SHODAN_AVAILABLE', True):
            with patch('app.get_cached_shodan_pivot', return_value=None):
                with patch('app.get_shodan_api_key', return_value='test_api_key'):
                    with patch('app.shodan') as mock_shodan_module:
                        mock_shodan_module.Shodan.return_value = mock_shodan_api
                        with patch('app.get_shodan_cache_settings', return_value={'cache_ttl': 3600}):
                            with patch('app.set_cached_shodan_pivot') as mock_cache:
                                with patch('app.log_audit'):
                                    response = authenticated_client.post('/api/shodan/pivot-jarm',
                                                                         json={'jarm': valid_jarm})
        
        assert response.status_code == 200
        mock_cache.assert_called_once()
        args = mock_cache.call_args[0]
        assert args[0] == 'jarm'  # pivot_type
        assert args[1] == valid_jarm  # pivot_value
    
    def test_shodan_pivot_jarm_api_error(self, authenticated_client, valid_jarm, mock_shodan_api):
        """Test handling of API errors."""
        mock_shodan_api.search.side_effect = MockShodanAPIError('API error')
        
        with patch('app.SHODAN_AVAILABLE', True):
            with patch('app.get_cached_shodan_pivot', return_value=None):
                with patch('app.get_shodan_api_key', return_value='test_api_key'):
                    with patch('app.shodan') as mock_shodan_module:
                        mock_shodan_module.Shodan.return_value = mock_shodan_api
                        mock_shodan_module.APIError = MockShodanAPIError
                        response = authenticated_client.post('/api/shodan/pivot-jarm',
                                                             json={'jarm': valid_jarm})
        
        assert response.status_code == 500
        data = json.loads(response.data)
        assert 'Shodan API error' in data['error']
    
    def test_shodan_pivot_jarm_case_insensitive(self, authenticated_client, valid_jarm, mock_shodan_search_response, mock_shodan_api):
        """Test that JARM fingerprint is accepted in different cases."""
        mock_shodan_api.search.return_value = mock_shodan_search_response
        
        # Test uppercase version
        with patch('app.SHODAN_AVAILABLE', True):
            with patch('app.get_cached_shodan_pivot', return_value=None):
                with patch('app.get_shodan_api_key', return_value='test_api_key'):
                    with patch('app.shodan') as mock_shodan_module:
                        mock_shodan_module.Shodan.return_value = mock_shodan_api
                        with patch('app.get_shodan_cache_settings', return_value={'cache_ttl': 3600}):
                            with patch('app.set_cached_shodan_pivot'):
                                with patch('app.log_audit'):
                                    response = authenticated_client.post('/api/shodan/pivot-jarm',
                                                                         json={'jarm': valid_jarm.upper()})
        
        # Should be valid (uppercase hex is allowed)
        assert response.status_code == 200


# =============================================================================
# Integration Tests
# =============================================================================

class TestShodanIntegration:
    """Integration tests for Shodan workflow."""
    
    def test_resolve_then_pivot_workflow(self, authenticated_client, mock_shodan_host_response, mock_shodan_search_response, valid_jarm, mock_shodan_api):
        """Test typical workflow: resolve IP, then pivot on JARM."""
        mock_shodan_api.host.return_value = mock_shodan_host_response
        mock_shodan_api.search.return_value = mock_shodan_search_response
        
        with patch('app.SHODAN_AVAILABLE', True):
            with patch('app.get_cached_shodan', return_value=None):
                with patch('app.get_cached_shodan_pivot', return_value=None):
                    with patch('app.get_shodan_api_key', return_value='test_api_key'):
                        with patch('app.shodan') as mock_shodan_module:
                            mock_shodan_module.Shodan.return_value = mock_shodan_api
                            with patch('app.get_shodan_cache_settings', return_value={'cache_ttl': 3600}):
                                with patch('app.set_cached_shodan'):
                                    with patch('app.set_cached_shodan_pivot'):
                                        with patch('app.log_audit'):
                                            # Step 1: Resolve IP
                                            response1 = authenticated_client.post('/api/shodan/resolve',
                                                                                  json={'value': '8.8.8.8', 'type': 'ip'})
                                            assert response1.status_code == 200
                                            data1 = json.loads(response1.data)
                                            
                                            # Get JARM from response
                                            assert len(data1['jarms']) > 0
                                            jarm = data1['jarms'][0]['jarm']
                                            
                                            # Step 2: Pivot on JARM
                                            response2 = authenticated_client.post('/api/shodan/pivot-jarm',
                                                                                  json={'jarm': jarm})
                                            assert response2.status_code == 200
                                            data2 = json.loads(response2.data)
                                            
                                            # Should have found other hosts
                                            assert len(data2['ips']) > 0


# =============================================================================
# Additional Edge Case Tests
# =============================================================================

class TestShodanResolveEdgeCases:
    """Additional edge case tests for /api/shodan/resolve endpoint."""
    
    def test_shodan_resolve_ip_reraises_other_api_errors(self, authenticated_client, mock_shodan_api):
        """Test that non-'No information available' errors are re-raised."""
        mock_shodan_api.host.side_effect = MockShodanAPIError('Rate limit exceeded')
        
        with patch('app.SHODAN_AVAILABLE', True):
            with patch('app.get_cached_shodan', return_value=None):
                with patch('app.get_shodan_api_key', return_value='test_api_key'):
                    with patch('app.shodan') as mock_shodan_module:
                        mock_shodan_module.Shodan.return_value = mock_shodan_api
                        mock_shodan_module.APIError = MockShodanAPIError
                        with patch('app.log_audit'):
                            response = authenticated_client.post('/api/shodan/resolve',
                                                                 json={'value': '8.8.8.8', 'type': 'ip'})
        
        assert response.status_code == 500
        data = json.loads(response.data)
        assert 'Rate limit' in data['error']
    
    def test_shodan_resolve_ip_general_exception(self, authenticated_client, mock_shodan_api):
        """Test handling of non-APIError exceptions in IP lookup."""
        mock_shodan_api.host.side_effect = RuntimeError('Unexpected error')
        
        with patch('app.SHODAN_AVAILABLE', True):
            with patch('app.get_cached_shodan', return_value=None):
                with patch('app.get_shodan_api_key', return_value='test_api_key'):
                    with patch('app.shodan') as mock_shodan_module:
                        mock_shodan_module.Shodan.return_value = mock_shodan_api
                        mock_shodan_module.APIError = MockShodanAPIError
                        with patch('app.log_audit'):
                            response = authenticated_client.post('/api/shodan/resolve',
                                                                 json={'value': '8.8.8.8', 'type': 'ip'})
        
        assert response.status_code == 500
        data = json.loads(response.data)
        assert 'Unexpected error' in data['error']
    
    def test_shodan_resolve_domain_general_exception(self, authenticated_client, mock_shodan_api):
        """Test handling of non-APIError exceptions in domain lookup."""
        mock_shodan_api.search.side_effect = RuntimeError('Connection timeout')
        
        with patch('app.SHODAN_AVAILABLE', True):
            with patch('app.get_cached_shodan', return_value=None):
                with patch('app.get_shodan_api_key', return_value='test_api_key'):
                    with patch('app.shodan') as mock_shodan_module:
                        mock_shodan_module.Shodan.return_value = mock_shodan_api
                        mock_shodan_module.APIError = MockShodanAPIError
                        with patch('app.log_audit'):
                            response = authenticated_client.post('/api/shodan/resolve',
                                                                 json={'value': 'example.com', 'type': 'domain'})
        
        assert response.status_code == 500
        data = json.loads(response.data)
        assert 'Connection timeout' in data['error']
    
    def test_shodan_resolve_domain_reraises_other_api_errors(self, authenticated_client, mock_shodan_api):
        """Test that domain lookup re-raises non-'No information available' errors."""
        mock_shodan_api.search.side_effect = MockShodanAPIError('Invalid API key')
        
        with patch('app.SHODAN_AVAILABLE', True):
            with patch('app.get_cached_shodan', return_value=None):
                with patch('app.get_shodan_api_key', return_value='test_api_key'):
                    with patch('app.shodan') as mock_shodan_module:
                        mock_shodan_module.Shodan.return_value = mock_shodan_api
                        mock_shodan_module.APIError = MockShodanAPIError
                        with patch('app.log_audit'):
                            response = authenticated_client.post('/api/shodan/resolve',
                                                                 json={'value': 'example.com', 'type': 'domain'})
        
        assert response.status_code == 500
        data = json.loads(response.data)
        assert 'Invalid API key' in data['error']
    
    def test_shodan_resolve_ip_with_zero_jarm(self, authenticated_client, mock_shodan_api):
        """Test that all-zero JARM fingerprints are filtered out."""
        mock_response = {
            'ip_str': '8.8.8.8',
            'hostnames': ['dns.google'],
            'org': 'Google LLC',
            'data': [
                {
                    'port': 443,
                    'ssl': {
                        'jarm': '00000000000000000000000000000000000000000000000000000000000000'  # All zeros
                    }
                }
            ]
        }
        
        mock_shodan_api.host.return_value = mock_response
        
        with patch('app.SHODAN_AVAILABLE', True):
            with patch('app.get_cached_shodan', return_value=None):
                with patch('app.get_shodan_api_key', return_value='test_api_key'):
                    with patch('app.shodan') as mock_shodan_module:
                        mock_shodan_module.Shodan.return_value = mock_shodan_api
                        with patch('app.get_shodan_cache_settings', return_value={'cache_ttl': 3600}):
                            with patch('app.set_cached_shodan'):
                                with patch('app.log_audit'):
                                    response = authenticated_client.post('/api/shodan/resolve',
                                                                         json={'value': '8.8.8.8', 'type': 'ip'})
        
        assert response.status_code == 200
        data = json.loads(response.data)
        # All-zero JARMs should be filtered out
        assert data['jarms'] == []
    
    def test_shodan_resolve_ip_deduplicates_jarms(self, authenticated_client, mock_shodan_api):
        """Test that duplicate JARM fingerprints are deduplicated."""
        same_jarm = '29d29d00029d29d00042d43d00041d44609a459e553d63294a6820b5f89751'
        mock_response = {
            'ip_str': '8.8.8.8',
            'hostnames': ['dns.google'],
            'org': 'Google LLC',
            'data': [
                {'port': 443, 'ssl': {'jarm': same_jarm}},
                {'port': 8443, 'ssl': {'jarm': same_jarm}},  # Same JARM, different port
                {'port': 9443, 'ssl': {'jarm': same_jarm}}   # Same JARM again
            ]
        }
        
        mock_shodan_api.host.return_value = mock_response
        
        with patch('app.SHODAN_AVAILABLE', True):
            with patch('app.get_cached_shodan', return_value=None):
                with patch('app.get_shodan_api_key', return_value='test_api_key'):
                    with patch('app.shodan') as mock_shodan_module:
                        mock_shodan_module.Shodan.return_value = mock_shodan_api
                        with patch('app.get_shodan_cache_settings', return_value={'cache_ttl': 3600}):
                            with patch('app.set_cached_shodan'):
                                with patch('app.log_audit'):
                                    response = authenticated_client.post('/api/shodan/resolve',
                                                                         json={'value': '8.8.8.8', 'type': 'ip'})
        
        assert response.status_code == 200
        data = json.loads(response.data)
        # Should only have one unique JARM
        assert len(data['jarms']) == 1


class TestShodanPivotEdgeCases:
    """Additional edge case tests for /api/shodan/pivot endpoint."""
    
    def test_shodan_pivot_general_exception(self, authenticated_client, mock_shodan_api):
        """Test handling of non-APIError exceptions."""
        mock_shodan_api.search.side_effect = RuntimeError('Network error')
        
        with patch('app.SHODAN_AVAILABLE', True):
            with patch('app.get_shodan_api_key', return_value='test_api_key'):
                with patch('app.shodan') as mock_shodan_module:
                    mock_shodan_module.Shodan.return_value = mock_shodan_api
                    mock_shodan_module.APIError = MockShodanAPIError
                    with patch('app.get_shodan_pivot_limit', return_value=100):
                        response = authenticated_client.post('/api/shodan/pivot',
                                                             json={'query': 'org:"Test"'})
        
        assert response.status_code == 500
        data = json.loads(response.data)
        assert 'Network error' in data['error']
    
    def test_shodan_pivot_no_matches(self, authenticated_client, mock_shodan_api):
        """Test handling of empty results."""
        mock_shodan_api.search.return_value = {
            'total': 0,
            'matches': []
        }
        
        with patch('app.SHODAN_AVAILABLE', True):
            with patch('app.get_shodan_api_key', return_value='test_api_key'):
                with patch('app.shodan') as mock_shodan_module:
                    mock_shodan_module.Shodan.return_value = mock_shodan_api
                    with patch('app.get_shodan_pivot_limit', return_value=100):
                        with patch('app.log_audit'):
                            response = authenticated_client.post('/api/shodan/pivot',
                                                                 json={'query': 'org:"NonexistentOrg"'})
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['total_results'] == 0
        assert data['ips'] == []
        assert data['hosts'] == []
    
    def test_shodan_pivot_filters_null_ips(self, authenticated_client, mock_shodan_api):
        """Test that null IPs are filtered out."""
        mock_shodan_api.search.return_value = {
            'total': 3,
            'matches': [
                {'ip_str': '1.1.1.1', 'port': 443, 'hostnames': [], 'org': 'Test', 'location': {'country_name': 'US'}, 'asn': 'AS1'},
                {'ip_str': None, 'port': 443, 'hostnames': [], 'org': 'Test', 'location': {'country_name': 'US'}, 'asn': 'AS1'},
                {'ip_str': '', 'port': 443, 'hostnames': [], 'org': 'Test', 'location': {'country_name': 'US'}, 'asn': 'AS1'}
            ]
        }
        
        with patch('app.SHODAN_AVAILABLE', True):
            with patch('app.get_shodan_api_key', return_value='test_api_key'):
                with patch('app.shodan') as mock_shodan_module:
                    mock_shodan_module.Shodan.return_value = mock_shodan_api
                    with patch('app.get_shodan_pivot_limit', return_value=100):
                        with patch('app.log_audit'):
                            response = authenticated_client.post('/api/shodan/pivot',
                                                                 json={'query': 'org:"Test"'})
        
        assert response.status_code == 200
        data = json.loads(response.data)
        # Only the valid IP should be included
        assert len(data['ips']) == 1
        assert '1.1.1.1' in data['ips']


class TestShodanPivotJarmEdgeCases:
    """Additional edge case tests for /api/shodan/pivot-jarm endpoint."""
    
    def test_shodan_pivot_jarm_general_exception(self, authenticated_client, valid_jarm, mock_shodan_api):
        """Test handling of non-APIError exceptions."""
        mock_shodan_api.search.side_effect = RuntimeError('Socket timeout')
        
        with patch('app.SHODAN_AVAILABLE', True):
            with patch('app.get_cached_shodan_pivot', return_value=None):
                with patch('app.get_shodan_api_key', return_value='test_api_key'):
                    with patch('app.shodan') as mock_shodan_module:
                        mock_shodan_module.Shodan.return_value = mock_shodan_api
                        mock_shodan_module.APIError = MockShodanAPIError
                        response = authenticated_client.post('/api/shodan/pivot-jarm',
                                                             json={'jarm': valid_jarm})
        
        assert response.status_code == 500
        data = json.loads(response.data)
        assert 'Socket timeout' in data['error']
    
    def test_shodan_pivot_jarm_no_matches(self, authenticated_client, valid_jarm, mock_shodan_api):
        """Test handling of empty results."""
        mock_shodan_api.search.return_value = {
            'total': 0,
            'matches': []
        }
        
        with patch('app.SHODAN_AVAILABLE', True):
            with patch('app.get_cached_shodan_pivot', return_value=None):
                with patch('app.get_shodan_api_key', return_value='test_api_key'):
                    with patch('app.shodan') as mock_shodan_module:
                        mock_shodan_module.Shodan.return_value = mock_shodan_api
                        with patch('app.get_shodan_cache_settings', return_value={'cache_ttl': 3600}):
                            with patch('app.set_cached_shodan_pivot'):
                                with patch('app.log_audit'):
                                    response = authenticated_client.post('/api/shodan/pivot-jarm',
                                                                         json={'jarm': valid_jarm})
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['total_results'] == 0
        assert data['ips'] == []
        assert data['hostnames'] == []
    
    def test_shodan_pivot_jarm_filters_empty_hostnames(self, authenticated_client, valid_jarm, mock_shodan_api):
        """Test that empty hostnames are filtered."""
        mock_shodan_api.search.return_value = {
            'total': 2,
            'matches': [
                {'ip_str': '1.1.1.1', 'port': 443, 'hostnames': ['example.com', '', None], 'org': 'Test', 'location': {'country_name': 'US'}},
                {'ip_str': '2.2.2.2', 'port': 443, 'hostnames': [], 'org': 'Test', 'location': {'country_name': 'US'}}
            ]
        }
        
        with patch('app.SHODAN_AVAILABLE', True):
            with patch('app.get_cached_shodan_pivot', return_value=None):
                with patch('app.get_shodan_api_key', return_value='test_api_key'):
                    with patch('app.shodan') as mock_shodan_module:
                        mock_shodan_module.Shodan.return_value = mock_shodan_api
                        with patch('app.get_shodan_cache_settings', return_value={'cache_ttl': 3600}):
                            with patch('app.set_cached_shodan_pivot'):
                                with patch('app.log_audit'):
                                    response = authenticated_client.post('/api/shodan/pivot-jarm',
                                                                         json={'jarm': valid_jarm})
        
        assert response.status_code == 200
        data = json.loads(response.data)
        # Only the non-empty hostname should be included
        assert 'example.com' in data['hostnames']
        assert '' not in data['hostnames']
        assert len(data['hostnames']) == 1
    
    def test_shodan_pivot_jarm_handles_missing_location(self, authenticated_client, valid_jarm, mock_shodan_api):
        """Test handling of matches with missing location data."""
        mock_shodan_api.search.return_value = {
            'total': 1,
            'matches': [
                {'ip_str': '1.1.1.1', 'port': 443, 'hostnames': [], 'org': 'Test'}
                # No 'location' key
            ]
        }
        
        with patch('app.SHODAN_AVAILABLE', True):
            with patch('app.get_cached_shodan_pivot', return_value=None):
                with patch('app.get_shodan_api_key', return_value='test_api_key'):
                    with patch('app.shodan') as mock_shodan_module:
                        mock_shodan_module.Shodan.return_value = mock_shodan_api
                        with patch('app.get_shodan_cache_settings', return_value={'cache_ttl': 3600}):
                            with patch('app.set_cached_shodan_pivot'):
                                with patch('app.log_audit'):
                                    response = authenticated_client.post('/api/shodan/pivot-jarm',
                                                                         json={'jarm': valid_jarm})
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert len(data['hosts']) == 1
        assert data['hosts'][0]['country'] is None

