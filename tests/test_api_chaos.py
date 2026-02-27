"""
Tests for Chaos (ProjectDiscovery) API endpoints.

Tests cover:
- POST /api/chaos/subdomains - Subdomain lookup
- GET /api/chaos/settings - Settings check
- Cache functions
- Admin settings
"""

import pytest
import json
from unittest.mock import patch, MagicMock


class TestChaosSubdomainsApi:
    """Tests for POST /api/chaos/subdomains endpoint."""
    
    def test_chaos_subdomains_requires_auth(self, client):
        """Test that endpoint requires authentication."""
        response = client.post('/api/chaos/subdomains',
                              json={'domain': 'example.com'})
        assert response.status_code in (302, 401, 403)
    
    def test_chaos_subdomains_no_json(self, authenticated_client):
        """Test error when no JSON provided."""
        response = authenticated_client.post('/api/chaos/subdomains',
                                             data='not json',
                                             content_type='application/json')
        assert response.status_code == 400
    
    def test_chaos_subdomains_missing_domain(self, authenticated_client):
        """Test error when domain not provided."""
        response = authenticated_client.post('/api/chaos/subdomains',
                                             json={'other_field': 'value'})
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'required' in data['error'].lower()
    
    def test_chaos_subdomains_empty_domain(self, authenticated_client):
        """Test error when domain is empty."""
        response = authenticated_client.post('/api/chaos/subdomains',
                                             json={'domain': ''})
        assert response.status_code == 400
    
    def test_chaos_subdomains_no_api_key(self, authenticated_client):
        """Test error when API key not configured."""
        with patch('routes.chaos.get_chaos_settings', return_value={'api_key': ''}):
            response = authenticated_client.post('/api/chaos/subdomains',
                                                 json={'domain': 'example.com'})
            assert response.status_code == 400
            data = json.loads(response.data)
            assert 'not configured' in data['error'].lower()
    
    def test_chaos_subdomains_returns_cached(self, authenticated_client):
        """Test that cached results are returned."""
        cached_result = {
            'subdomains': ['www', 'api', 'mail'],
            'subdomain_count': 3,
            'cached_at': '2024-01-01 00:00:00',
            'from_cache': True
        }
        
        with patch('routes.chaos.get_chaos_settings', return_value={'api_key': 'test_key', 'cache_ttl': 86400}):
            with patch('routes.chaos.get_cached_chaos', return_value=cached_result):
                response = authenticated_client.post('/api/chaos/subdomains',
                                                     json={'domain': 'example.com'})
                assert response.status_code == 200
                data = json.loads(response.data)
                assert data['from_cache'] == True
                assert data['subdomain_count'] == 3
    
    def test_chaos_subdomains_success(self, authenticated_client):
        """Test successful subdomain lookup."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'domain': 'example.com',
            'subdomains': ['www', 'api', 'mail', 'dev'],
            'count': 4
        }
        
        with patch('routes.chaos.get_chaos_settings', return_value={'api_key': 'test_key', 'cache_ttl': 86400}):
            with patch('routes.chaos.get_cached_chaos', return_value=None):
                with patch('requests.get', return_value=mock_response):
                    with patch('routes.chaos.set_cached_chaos') as mock_cache:
                        with patch('routes.chaos.log_audit'):
                            response = authenticated_client.post('/api/chaos/subdomains',
                                                                 json={'domain': 'example.com'})
                            assert response.status_code == 200
                            data = json.loads(response.data)
                            assert data['subdomain_count'] == 4
                            assert 'www' in data['subdomains']
                            assert data['from_cache'] == False
                            mock_cache.assert_called_once()
    
    def test_chaos_subdomains_normalizes_domain(self, authenticated_client):
        """Test that domain is normalized to lowercase."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'domain': 'example.com',
            'subdomains': ['www'],
            'count': 1
        }
        
        with patch('routes.chaos.get_chaos_settings', return_value={'api_key': 'test_key', 'cache_ttl': 86400}):
            with patch('routes.chaos.get_cached_chaos', return_value=None):
                with patch('requests.get', return_value=mock_response) as mock_get:
                    with patch('routes.chaos.set_cached_chaos'):
                        with patch('routes.chaos.log_audit'):
                            response = authenticated_client.post('/api/chaos/subdomains',
                                                                 json={'domain': 'EXAMPLE.COM'})
                            assert response.status_code == 200
                            # Verify the URL contains lowercase domain
                            call_url = mock_get.call_args[0][0]
                            assert 'example.com' in call_url
    
    def test_chaos_subdomains_unauthorized(self, authenticated_client):
        """Test handling of unauthorized (invalid API key) error."""
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.raise_for_status.side_effect = Exception('401 Unauthorized')
        
        import requests
        http_error = requests.exceptions.HTTPError(response=MagicMock(status_code=401))
        mock_response.raise_for_status.side_effect = http_error
        
        with patch('routes.chaos.get_chaos_settings', return_value={'api_key': 'bad_key', 'cache_ttl': 86400}):
            with patch('routes.chaos.get_cached_chaos', return_value=None):
                with patch('requests.get', return_value=mock_response):
                    mock_response.raise_for_status.side_effect = http_error
                    response = authenticated_client.post('/api/chaos/subdomains',
                                                         json={'domain': 'example.com'})
                    assert response.status_code == 401
                    data = json.loads(response.data)
                    assert 'invalid' in data['error'].lower()
    
    def test_chaos_subdomains_not_found(self, authenticated_client):
        """Test handling of 404 (no data) response."""
        import requests
        mock_response = MagicMock()
        mock_response.status_code = 404
        http_error = requests.exceptions.HTTPError(response=MagicMock(status_code=404))
        mock_response.raise_for_status.side_effect = http_error
        
        with patch('routes.chaos.get_chaos_settings', return_value={'api_key': 'test_key', 'cache_ttl': 86400}):
            with patch('routes.chaos.get_cached_chaos', return_value=None):
                with patch('requests.get', return_value=mock_response):
                    with patch('routes.chaos.set_cached_chaos') as mock_cache:
                        response = authenticated_client.post('/api/chaos/subdomains',
                                                             json={'domain': 'nonexistent-domain-12345.com'})
                        assert response.status_code == 200
                        data = json.loads(response.data)
                        assert data['subdomains'] == []
                        assert data['subdomain_count'] == 0
                        # Should cache empty result
                        mock_cache.assert_called_once()
    
    def test_chaos_subdomains_request_error(self, authenticated_client):
        """Test handling of request errors."""
        import requests
        
        with patch('routes.chaos.get_chaos_settings', return_value={'api_key': 'test_key', 'cache_ttl': 86400}):
            with patch('routes.chaos.get_cached_chaos', return_value=None):
                with patch('requests.get', side_effect=requests.exceptions.ConnectionError('Network error')):
                    response = authenticated_client.post('/api/chaos/subdomains',
                                                         json={'domain': 'example.com'})
                    assert response.status_code == 500
                    data = json.loads(response.data)
                    assert 'failed' in data['error'].lower()


class TestChaosSettingsApi:
    """Tests for GET /api/chaos/settings endpoint."""
    
    def test_chaos_settings_requires_auth(self, client):
        """Test that endpoint requires authentication."""
        response = client.get('/api/chaos/settings')
        assert response.status_code in (302, 401, 403)
    
    def test_chaos_settings_configured(self, authenticated_client):
        """Test settings when API key is configured."""
        with patch('routes.chaos.get_chaos_settings', return_value={'api_key': 'test_key'}):
            response = authenticated_client.get('/api/chaos/settings')
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data['api_key_configured'] == True
    
    def test_chaos_settings_not_configured(self, authenticated_client):
        """Test settings when API key is not configured."""
        with patch('routes.chaos.get_chaos_settings', return_value={'api_key': ''}):
            response = authenticated_client.get('/api/chaos/settings')
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data['api_key_configured'] == False


class TestChaosCacheFunctions:
    """Tests for Chaos cache functions in admin.py."""
    
    def test_get_chaos_settings_defaults(self, app, test_db):
        """Test get_chaos_settings returns defaults when not configured."""
        from admin import get_chaos_settings
        
        settings = get_chaos_settings()
        
        assert settings['api_key'] == ''
        assert settings['cache_ttl'] == 86400
        assert settings['rate_limit'] == 5.0
    
    def test_get_chaos_settings_configured(self, app, test_db):
        """Test get_chaos_settings returns configured values."""
        from admin import get_chaos_settings, get_db
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO settings (key, value) VALUES ('chaos_api_key', 'my_api_key')")
        cursor.execute("INSERT INTO settings (key, value) VALUES ('chaos_cache_ttl', '172800')")
        cursor.execute("INSERT INTO settings (key, value) VALUES ('chaos_rate_limit', '10.0')")
        conn.commit()
        conn.close()
        
        settings = get_chaos_settings()
        
        assert settings['api_key'] == 'my_api_key'
        assert settings['cache_ttl'] == 172800
        assert settings['rate_limit'] == 10.0
    
    def test_get_cached_chaos_miss(self, app, test_db):
        """Test cache miss returns None."""
        from admin import get_cached_chaos
        
        result = get_cached_chaos('example.com')
        assert result is None
    
    def test_set_and_get_cached_chaos(self, app, test_db):
        """Test setting and getting cached Chaos results."""
        from admin import get_cached_chaos, set_cached_chaos
        
        subdomains = ['www', 'api', 'mail']
        set_cached_chaos('example.com', subdomains, 3, 86400)
        
        result = get_cached_chaos('example.com')
        
        assert result is not None
        assert result['subdomains'] == subdomains
        assert result['subdomain_count'] == 3
        assert result['from_cache'] == True
    
    def test_cached_chaos_case_insensitive(self, app, test_db):
        """Test cache lookup is case-insensitive."""
        from admin import get_cached_chaos, set_cached_chaos
        
        set_cached_chaos('EXAMPLE.COM', ['www'], 1, 86400)
        
        result = get_cached_chaos('example.com')
        assert result is not None
        
        result = get_cached_chaos('Example.Com')
        assert result is not None
    
    def test_cached_chaos_expired(self, app, test_db):
        """Test that expired cache entries are not returned."""
        from admin import get_cached_chaos, get_db
        
        # Insert expired cache entry directly
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO chaos_cache (domain, results_json, subdomain_count, cached_at, expires_at)
            VALUES (?, ?, ?, datetime('now', '-1 day'), datetime('now', '-1 hour'))
        ''', ('expired.com', json.dumps(['www']), 1))
        conn.commit()
        conn.close()
        
        result = get_cached_chaos('expired.com')
        assert result is None
    
    def test_clear_expired_chaos_cache(self, app, test_db):
        """Test clearing expired cache entries."""
        from admin import clear_expired_chaos_cache, get_db
        
        conn = get_db()
        cursor = conn.cursor()
        # Insert expired entry
        cursor.execute('''
            INSERT INTO chaos_cache (domain, results_json, subdomain_count, cached_at, expires_at)
            VALUES (?, ?, ?, datetime('now', '-2 days'), datetime('now', '-1 day'))
        ''', ('expired.com', '[]', 0))
        # Insert valid entry
        cursor.execute('''
            INSERT INTO chaos_cache (domain, results_json, subdomain_count, cached_at, expires_at)
            VALUES (?, ?, ?, datetime('now'), datetime('now', '+1 day'))
        ''', ('valid.com', '["www"]', 1))
        conn.commit()
        conn.close()
        
        clear_expired_chaos_cache()
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT domain FROM chaos_cache')
        domains = [row['domain'] for row in cursor.fetchall()]
        conn.close()
        
        assert 'expired.com' not in domains
        assert 'valid.com' in domains


class TestChaosAdminSettings:
    """Tests for Chaos admin settings endpoints."""
    
    def test_save_chaos_settings_requires_admin(self, client, test_db):
        """Test that saving settings requires admin authentication."""
        response = client.post('/admin/settings/chaos',
                              data={'chaos_api_key': 'test_key'})
        assert response.status_code in (302, 401, 403)
    
    def test_save_chaos_settings_success(self, admin_client, test_db):
        """Test successfully saving Chaos settings."""
        response = admin_client.post('/admin/settings/chaos',
                                     data={
                                         'chaos_api_key': 'my_test_key',
                                         'chaos_cache_ttl': '172800',
                                         'chaos_rate_limit': '10.0'
                                     },
                                     follow_redirects=True)
        assert response.status_code == 200
        
        # Verify settings were saved
        from admin import get_chaos_settings
        settings = get_chaos_settings()
        assert settings['api_key'] == 'my_test_key'
        assert settings['cache_ttl'] == 172800
        assert settings['rate_limit'] == 10.0
    
    def test_save_chaos_settings_validates_cache_ttl(self, admin_client, test_db):
        """Test that cache TTL is validated (minimum 1 hour)."""
        response = admin_client.post('/admin/settings/chaos',
                                     data={
                                         'chaos_api_key': 'key',
                                         'chaos_cache_ttl': '100',  # Too low
                                         'chaos_rate_limit': '5.0'
                                     },
                                     follow_redirects=True)
        assert response.status_code == 200
        
        from admin import get_chaos_settings
        settings = get_chaos_settings()
        assert settings['cache_ttl'] >= 3600  # Should be clamped to minimum
    
    def test_save_chaos_settings_validates_rate_limit(self, admin_client, test_db):
        """Test that rate limit is validated."""
        response = admin_client.post('/admin/settings/chaos',
                                     data={
                                         'chaos_api_key': 'key',
                                         'chaos_cache_ttl': '86400',
                                         'chaos_rate_limit': '0.01'  # Too low
                                     },
                                     follow_redirects=True)
        assert response.status_code == 200
        
        from admin import get_chaos_settings
        settings = get_chaos_settings()
        assert settings['rate_limit'] >= 0.1  # Should be clamped to minimum
    
    def test_save_chaos_settings_invalid_values(self, admin_client, test_db):
        """Test that invalid values fall back to defaults."""
        response = admin_client.post('/admin/settings/chaos',
                                     data={
                                         'chaos_api_key': 'key',
                                         'chaos_cache_ttl': 'not_a_number',
                                         'chaos_rate_limit': 'invalid'
                                     },
                                     follow_redirects=True)
        assert response.status_code == 200
        
        from admin import get_chaos_settings
        settings = get_chaos_settings()
        # Should use defaults
        assert settings['cache_ttl'] == 86400
        assert settings['rate_limit'] == 5.0
