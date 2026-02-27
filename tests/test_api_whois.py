"""
Tests for WHOIS API endpoints.

Tests cover:
- POST /api/whois/resolve - Single domain WHOIS lookup
- POST /api/whois/resolve-bulk - Bulk WHOIS resolution
"""

import pytest
import json
from datetime import datetime
from unittest.mock import patch, MagicMock


class TestWhoisResolveApi:
    """Tests for /api/whois/resolve endpoint."""
    
    def test_whois_resolve_requires_auth(self, client):
        """Test that endpoint requires authentication."""
        response = client.post('/api/whois/resolve',
                              json={'domain': 'example.com'})
        assert response.status_code in (302, 401, 403)
    
    def test_whois_resolve_no_json(self, authenticated_client):
        """Test error when no JSON provided."""
        response = authenticated_client.post('/api/whois/resolve',
                                             data='not json',
                                             content_type='application/json')
        assert response.status_code == 400
    
    def test_whois_resolve_missing_domain(self, authenticated_client):
        """Test error when domain not provided."""
        response = authenticated_client.post('/api/whois/resolve',
                                             json={'other_field': 'value'})
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'Domain is required' in data['error']
    
    def test_whois_resolve_empty_domain(self, authenticated_client):
        """Test error when domain is empty."""
        response = authenticated_client.post('/api/whois/resolve',
                                             json={'domain': ''})
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'Domain is required' in data['error']
    
    def test_whois_resolve_whitespace_domain(self, authenticated_client):
        """Test error when domain is only whitespace."""
        response = authenticated_client.post('/api/whois/resolve',
                                             json={'domain': '   '})
        assert response.status_code == 400
    
    def test_whois_resolve_returns_cached_result(self, authenticated_client, sample_whois_results):
        """Test that cached result is returned if available."""
        cached = sample_whois_results.copy()
        
        with patch('routes.whois.get_cached_whois', return_value=cached) as mock_cache:
            with patch('routes.whois.log_audit'):
                response = authenticated_client.post('/api/whois/resolve',
                                                     json={'domain': 'example.com'})
                assert response.status_code == 200
                data = json.loads(response.data)
                assert data['cached'] == True
                mock_cache.assert_called_once_with('example.com')
    
    def test_whois_resolve_performs_lookup_on_cache_miss(self, authenticated_client):
        """Test that WHOIS lookup is performed on cache miss."""
        mock_whois_result = MagicMock()
        mock_whois_result.emails = ['admin@example.com']
        mock_whois_result.name = 'John Doe'
        mock_whois_result.org = 'Example Org'
        mock_whois_result.registrar = 'Example Registrar'
        mock_whois_result.creation_date = None
        mock_whois_result.expiration_date = None
        mock_whois_result.name_servers = ['ns1.example.com']
        
        with patch('routes.whois.get_cached_whois', return_value=None):
            with patch('whois.whois', return_value=mock_whois_result):
                with patch('routes.whois.get_whois_cache_settings', return_value={'cache_ttl': 3600}):
                    with patch('routes.whois.set_cached_whois'):
                        with patch('routes.whois.log_audit'):
                            response = authenticated_client.post('/api/whois/resolve',
                                                                 json={'domain': 'example.com'})
                            assert response.status_code == 200
                            data = json.loads(response.data)
                            assert data['domain'] == 'example.com'
    
    def test_whois_resolve_caches_result(self, authenticated_client):
        """Test that WHOIS result is cached."""
        mock_whois_result = MagicMock()
        mock_whois_result.emails = None
        mock_whois_result.name = None
        mock_whois_result.org = None
        mock_whois_result.registrar = 'Test Registrar'
        mock_whois_result.creation_date = None
        mock_whois_result.expiration_date = None
        mock_whois_result.name_servers = None
        
        with patch('routes.whois.get_cached_whois', return_value=None):
            with patch('whois.whois', return_value=mock_whois_result):
                with patch('routes.whois.get_whois_cache_settings', return_value={'cache_ttl': 3600}):
                    with patch('routes.whois.set_cached_whois') as mock_set_cache:
                        with patch('routes.whois.log_audit'):
                            response = authenticated_client.post('/api/whois/resolve',
                                                                 json={'domain': 'example.com'})
                            assert response.status_code == 200
                            mock_set_cache.assert_called_once()
    
    def test_whois_resolve_handles_exception(self, authenticated_client):
        """Test error handling when WHOIS lookup fails."""
        with patch('routes.whois.get_cached_whois', return_value=None):
            with patch('whois.whois', side_effect=Exception('WHOIS lookup failed')):
                response = authenticated_client.post('/api/whois/resolve',
                                                     json={'domain': 'example.com'})
                assert response.status_code == 500
                data = json.loads(response.data)
                assert 'error' in data
    
    def test_whois_resolve_logs_audit_cached(self, authenticated_client, sample_whois_results):
        """Test audit logging for cached WHOIS lookup."""
        with patch('routes.whois.get_cached_whois', return_value=sample_whois_results):
            with patch('routes.whois.log_audit') as mock_audit:
                response = authenticated_client.post('/api/whois/resolve',
                                                     json={'domain': 'example.com'})
                assert response.status_code == 200
                mock_audit.assert_called_once()
                call_args = mock_audit.call_args
                assert call_args[0][0] == 'whois_query'
    
    def test_whois_resolve_strips_domain_whitespace(self, authenticated_client, sample_whois_results):
        """Test that domain whitespace is stripped."""
        with patch('routes.whois.get_cached_whois', return_value=sample_whois_results) as mock_cache:
            with patch('routes.whois.log_audit'):
                response = authenticated_client.post('/api/whois/resolve',
                                                     json={'domain': '  example.com  '})
                assert response.status_code == 200
                mock_cache.assert_called_once_with('example.com')
    
    def test_whois_resolve_extracts_all_emails(self, authenticated_client):
        """Test that all emails are extracted from WHOIS result."""
        mock_whois_result = MagicMock()
        mock_whois_result.emails = ['admin@example.com', 'tech@example.com']
        mock_whois_result.email = 'registrant@example.com'
        mock_whois_result.registrant_email = None
        mock_whois_result.admin_email = None
        mock_whois_result.tech_email = None
        mock_whois_result.name = None
        mock_whois_result.registrant_name = None
        mock_whois_result.admin_name = None
        mock_whois_result.tech_name = None
        mock_whois_result.org = None
        mock_whois_result.organization = None
        mock_whois_result.registrant_organization = None
        mock_whois_result.registrar = None
        mock_whois_result.creation_date = None
        mock_whois_result.expiration_date = None
        mock_whois_result.name_servers = None
        
        with patch('routes.whois.get_cached_whois', return_value=None):
            with patch('whois.whois', return_value=mock_whois_result):
                with patch('routes.whois.get_whois_cache_settings', return_value={'cache_ttl': 3600}):
                    with patch('routes.whois.set_cached_whois'):
                        with patch('routes.whois.log_audit'):
                            response = authenticated_client.post('/api/whois/resolve',
                                                                 json={'domain': 'example.com'})
                            assert response.status_code == 200
                            data = json.loads(response.data)
                            assert 'all_emails' in data
                            assert len(data['all_emails']) >= 1


class TestWhoisResolveBulkApi:
    """Tests for /api/whois/resolve-bulk endpoint."""
    
    def test_whois_bulk_requires_auth(self, client):
        """Test that endpoint requires authentication."""
        response = client.post('/api/whois/resolve-bulk',
                              json={'domains': ['example.com']})
        assert response.status_code in (302, 401, 403)
    
    def test_whois_bulk_no_json(self, authenticated_client):
        """Test error when no JSON provided."""
        response = authenticated_client.post('/api/whois/resolve-bulk',
                                             data='not json',
                                             content_type='application/json')
        assert response.status_code == 400
    
    def test_whois_bulk_missing_domains(self, authenticated_client):
        """Test error when domains not provided."""
        response = authenticated_client.post('/api/whois/resolve-bulk',
                                             json={'other_field': 'value'})
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'Domains' in data['error'] or 'domains' in data['error'].lower()
    
    def test_whois_bulk_empty_domains(self, authenticated_client):
        """Test error when domains list is empty."""
        response = authenticated_client.post('/api/whois/resolve-bulk',
                                             json={'domains': []})
        assert response.status_code == 400
    
    def test_whois_bulk_single_domain(self, authenticated_client, sample_whois_results):
        """Test bulk WHOIS with single domain."""
        with patch('routes.whois.get_cached_whois', return_value=sample_whois_results):
            with patch('routes.whois.get_concurrency_settings', return_value={'whois_concurrency': 3}):
                with patch('routes.whois.log_audit'):
                    response = authenticated_client.post('/api/whois/resolve-bulk',
                                                         json={'domains': ['example.com']})
                    assert response.status_code == 200
                    data = json.loads(response.data)
                    assert 'results' in data
                    assert 'example.com' in data['results']
    
    def test_whois_bulk_multiple_domains(self, authenticated_client, sample_whois_results):
        """Test bulk WHOIS with multiple domains."""
        def mock_get_cached(domain):
            result = sample_whois_results.copy()
            result['domain'] = domain
            return result
        
        with patch('routes.whois.get_cached_whois', side_effect=mock_get_cached):
            with patch('routes.whois.get_concurrency_settings', return_value={'whois_concurrency': 3}):
                with patch('routes.whois.log_audit'):
                    domains = ['example.com', 'test.org', 'sample.net']
                    response = authenticated_client.post('/api/whois/resolve-bulk',
                                                         json={'domains': domains})
                    assert response.status_code == 200
                    data = json.loads(response.data)
                    assert len(data['results']) == 3
    
    def test_whois_bulk_handles_errors_per_domain(self, authenticated_client, sample_whois_results):
        """Test that errors are handled per-domain, not failing entire batch."""
        def mock_get_cached(domain):
            if domain == 'error.com':
                return None
            return sample_whois_results.copy()
        
        with patch('routes.whois.get_cached_whois', side_effect=mock_get_cached):
            with patch('whois.whois', side_effect=Exception('WHOIS failed')):
                with patch('routes.whois.get_concurrency_settings', return_value={'whois_concurrency': 3}):
                    with patch('routes.whois.log_audit'):
                        response = authenticated_client.post('/api/whois/resolve-bulk',
                                                             json={'domains': ['example.com', 'error.com']})
                        assert response.status_code == 200
                        data = json.loads(response.data)
                        # example.com should succeed (cached)
                        assert 'example.com' in data['results']
                        # error.com should have error
                        assert 'error.com' in data['results']
                        assert 'error' in data['results']['error.com']
    
    def test_whois_bulk_logs_audit(self, authenticated_client, sample_whois_results):
        """Test that bulk WHOIS queries are logged to audit."""
        with patch('routes.whois.get_cached_whois', return_value=sample_whois_results):
            with patch('routes.whois.get_concurrency_settings', return_value={'whois_concurrency': 3}):
                with patch('routes.whois.log_audit') as mock_audit:
                    response = authenticated_client.post('/api/whois/resolve-bulk',
                                                         json={'domains': ['example.com', 'test.org']})
                    assert response.status_code == 200
                    mock_audit.assert_called_once()
                    call_args = mock_audit.call_args
                    assert call_args[0][0] == 'whois_query_bulk'
    
    def test_whois_bulk_skips_empty_domains(self, authenticated_client, sample_whois_results):
        """Test that empty domains are skipped."""
        with patch('routes.whois.get_cached_whois', return_value=sample_whois_results):
            with patch('routes.whois.get_concurrency_settings', return_value={'whois_concurrency': 3}):
                with patch('routes.whois.log_audit'):
                    response = authenticated_client.post('/api/whois/resolve-bulk',
                                                         json={'domains': ['', 'example.com', '  ']})
                    assert response.status_code == 200
                    data = json.loads(response.data)
                    # Only example.com should be in results
                    assert 'example.com' in data['results']
                    assert '' not in data['results']
    
    def test_whois_bulk_max_domains_exceeded(self, authenticated_client):
        """Test error when max domains exceeded."""
        # Many domains
        domains = [f'domain{i}.com' for i in range(1001)]
        
        with patch('routes.whois.get_whois_cache_settings', return_value={'max_domains': 100}):
            response = authenticated_client.post('/api/whois/resolve-bulk',
                                                 json={'domains': domains})
            assert response.status_code == 400
            data = json.loads(response.data)
            assert 'Maximum' in data['error'] or 'max' in data['error'].lower()


# =============================================================================
# Tests for WHOIS resolution logic (not cached)
# =============================================================================

class TestWhoisBulkResolution:
    """Tests for the actual WHOIS resolution logic in bulk endpoint."""
    
    @pytest.fixture
    def mock_whois_response(self):
        """Create a mock WHOIS response object."""
        mock = MagicMock()
        mock.emails = ['admin@example.com', 'tech@example.com']
        mock.email = None
        mock.registrant_email = 'registrant@example.com'
        mock.admin_email = None
        mock.tech_email = None
        mock.name = 'John Doe'
        mock.registrant_name = None
        mock.admin_name = 'Admin Person'
        mock.tech_name = None
        mock.org = 'Example Corp'
        mock.organization = None
        mock.registrant_organization = None
        mock.registrar = 'GoDaddy'
        mock.creation_date = datetime(2020, 1, 15)
        mock.expiration_date = datetime(2025, 1, 15)
        mock.name_servers = ['ns1.example.com', 'NS2.EXAMPLE.COM']
        return mock
    
    def test_whois_bulk_resolves_uncached_domain(self, authenticated_client, mock_whois_response):
        """Test actual WHOIS resolution for uncached domains."""
        with patch('routes.whois.get_cached_whois', return_value=None):
            with patch('whois.whois', return_value=mock_whois_response):
                with patch('routes.whois.get_concurrency_settings', return_value={'whois_concurrency': 3}):
                    with patch('routes.whois.get_whois_cache_settings', return_value={'cache_ttl': 3600}):
                        with patch('routes.whois.set_cached_whois'):
                            with patch('routes.whois.log_audit'):
                                response = authenticated_client.post('/api/whois/resolve-bulk',
                                                                     json={'domains': ['example.com']})
        
        assert response.status_code == 200
        data = json.loads(response.data)
        result = data['results']['example.com']
        
        # Check emails were extracted
        assert 'admin@example.com' in result['all_emails']
        assert 'registrant@example.com' in result['all_emails']
        assert result['registrant_email'] is not None
        
        # Check names were extracted
        assert 'John Doe' in result['all_names']
        assert 'Admin Person' in result['all_names']
        
        # Check organization
        assert result['organization'] == 'Example Corp'
        
        # Check registrar
        assert result['registrar'] == 'GoDaddy'
        
        # Check dates
        assert result['creation_date'] == '2020-01-15'
        assert result['expiration_date'] == '2025-01-15'
        
        # Check name servers (should be lowercased)
        assert 'ns1.example.com' in result['name_servers']
        assert 'ns2.example.com' in result['name_servers']
    
    def test_whois_bulk_handles_list_values(self, authenticated_client):
        """Test handling of WHOIS fields that return lists."""
        mock = MagicMock()
        mock.emails = ['email1@test.com', 'email2@test.com', 'email1@test.com']  # Duplicate
        mock.email = None
        mock.registrant_email = None
        mock.admin_email = None
        mock.tech_email = None
        mock.name = ['Name One', 'Name Two']  # List of names
        mock.registrant_name = None
        mock.admin_name = None
        mock.tech_name = None
        mock.org = ['Org One', 'Org Two']
        mock.organization = None
        mock.registrant_organization = None
        mock.registrar = ['Registrar One']
        mock.creation_date = [datetime(2020, 1, 1), datetime(2019, 6, 15)]  # List of dates
        mock.expiration_date = None
        mock.name_servers = None
        
        with patch('routes.whois.get_cached_whois', return_value=None):
            with patch('whois.whois', return_value=mock):
                with patch('routes.whois.get_concurrency_settings', return_value={'whois_concurrency': 3}):
                    with patch('routes.whois.get_whois_cache_settings', return_value={'cache_ttl': 3600}):
                        with patch('routes.whois.set_cached_whois'):
                            with patch('routes.whois.log_audit'):
                                response = authenticated_client.post('/api/whois/resolve-bulk',
                                                                     json={'domains': ['test.com']})
        
        assert response.status_code == 200
        data = json.loads(response.data)
        result = data['results']['test.com']
        
        # Duplicates should be removed
        assert len(result['all_emails']) == 2
        
        # Lists should be handled
        assert 'Name One' in result['all_names']
        assert 'Name Two' in result['all_names']
        
        # First date from list should be used
        assert result['creation_date'] == '2020-01-01'
    
    def test_whois_bulk_handles_none_values(self, authenticated_client):
        """Test handling when all WHOIS fields are None."""
        mock = MagicMock()
        mock.emails = None
        mock.email = None
        mock.registrant_email = None
        mock.admin_email = None
        mock.tech_email = None
        mock.name = None
        mock.registrant_name = None
        mock.admin_name = None
        mock.tech_name = None
        mock.org = None
        mock.organization = None
        mock.registrant_organization = None
        mock.registrar = None
        mock.creation_date = None
        mock.expiration_date = None
        mock.name_servers = None
        
        with patch('routes.whois.get_cached_whois', return_value=None):
            with patch('whois.whois', return_value=mock):
                with patch('routes.whois.get_concurrency_settings', return_value={'whois_concurrency': 3}):
                    with patch('routes.whois.get_whois_cache_settings', return_value={'cache_ttl': 3600}):
                        with patch('routes.whois.set_cached_whois'):
                            with patch('routes.whois.log_audit'):
                                response = authenticated_client.post('/api/whois/resolve-bulk',
                                                                     json={'domains': ['empty.com']})
        
        assert response.status_code == 200
        data = json.loads(response.data)
        result = data['results']['empty.com']
        
        assert result['all_emails'] == []
        assert result['all_names'] == []
        assert result['all_organizations'] == []
        assert result['registrant_email'] is None
        assert result['organization'] is None
        assert result['creation_date'] is None
    
    def test_whois_bulk_handles_single_name_server(self, authenticated_client):
        """Test handling of single name server (not a list)."""
        mock = MagicMock()
        mock.emails = None
        mock.email = None
        mock.registrant_email = None
        mock.admin_email = None
        mock.tech_email = None
        mock.name = None
        mock.registrant_name = None
        mock.admin_name = None
        mock.tech_name = None
        mock.org = None
        mock.organization = None
        mock.registrant_organization = None
        mock.registrar = None
        mock.creation_date = None
        mock.expiration_date = None
        mock.name_servers = 'ns1.single.com'  # Single string, not list
        
        with patch('routes.whois.get_cached_whois', return_value=None):
            with patch('whois.whois', return_value=mock):
                with patch('routes.whois.get_concurrency_settings', return_value={'whois_concurrency': 3}):
                    with patch('routes.whois.get_whois_cache_settings', return_value={'cache_ttl': 3600}):
                        with patch('routes.whois.set_cached_whois'):
                            with patch('routes.whois.log_audit'):
                                response = authenticated_client.post('/api/whois/resolve-bulk',
                                                                     json={'domains': ['single.com']})
        
        assert response.status_code == 200
        data = json.loads(response.data)
        result = data['results']['single.com']
        
        assert result['name_servers'] == ['ns1.single.com']
    
    def test_whois_bulk_handles_exception_in_resolution(self, authenticated_client):
        """Test handling of exceptions during WHOIS resolution."""
        with patch('routes.whois.get_cached_whois', return_value=None):
            with patch('whois.whois', side_effect=Exception('Connection timeout')):
                with patch('routes.whois.get_concurrency_settings', return_value={'whois_concurrency': 3}):
                    with patch('routes.whois.get_whois_cache_settings', return_value={'cache_ttl': 3600}):
                        with patch('routes.whois.log_audit'):
                            response = authenticated_client.post('/api/whois/resolve-bulk',
                                                                 json={'domains': ['error.com']})
        
        assert response.status_code == 200
        data = json.loads(response.data)
        result = data['results']['error.com']
        
        assert 'error' in result
        assert 'Connection timeout' in result['error']
    
    def test_whois_bulk_deduplicates_emails_case_insensitive(self, authenticated_client):
        """Test that duplicate emails are removed case-insensitively."""
        mock = MagicMock()
        mock.emails = ['Admin@Example.COM', 'admin@example.com', 'ADMIN@EXAMPLE.COM']
        mock.email = 'admin@example.com'  # Another duplicate
        mock.registrant_email = None
        mock.admin_email = None
        mock.tech_email = None
        mock.name = None
        mock.registrant_name = None
        mock.admin_name = None
        mock.tech_name = None
        mock.org = None
        mock.organization = None
        mock.registrant_organization = None
        mock.registrar = None
        mock.creation_date = None
        mock.expiration_date = None
        mock.name_servers = None
        
        with patch('routes.whois.get_cached_whois', return_value=None):
            with patch('whois.whois', return_value=mock):
                with patch('routes.whois.get_concurrency_settings', return_value={'whois_concurrency': 3}):
                    with patch('routes.whois.get_whois_cache_settings', return_value={'cache_ttl': 3600}):
                        with patch('routes.whois.set_cached_whois'):
                            with patch('routes.whois.log_audit'):
                                response = authenticated_client.post('/api/whois/resolve-bulk',
                                                                     json={'domains': ['dedup.com']})
        
        assert response.status_code == 200
        data = json.loads(response.data)
        result = data['results']['dedup.com']
        
        # Should only have one unique email
        assert len(result['all_emails']) == 1
    
    def test_whois_bulk_handles_date_without_strftime(self, authenticated_client):
        """Test handling of dates that don't have strftime method."""
        mock = MagicMock()
        mock.emails = None
        mock.email = None
        mock.registrant_email = None
        mock.admin_email = None
        mock.tech_email = None
        mock.name = None
        mock.registrant_name = None
        mock.admin_name = None
        mock.tech_name = None
        mock.org = None
        mock.organization = None
        mock.registrant_organization = None
        mock.registrar = None
        mock.creation_date = '2020-05-15'  # String date, not datetime
        mock.expiration_date = 12345  # Some other non-datetime value
        mock.name_servers = None
        
        with patch('routes.whois.get_cached_whois', return_value=None):
            with patch('whois.whois', return_value=mock):
                with patch('routes.whois.get_concurrency_settings', return_value={'whois_concurrency': 3}):
                    with patch('routes.whois.get_whois_cache_settings', return_value={'cache_ttl': 3600}):
                        with patch('routes.whois.set_cached_whois'):
                            with patch('routes.whois.log_audit'):
                                response = authenticated_client.post('/api/whois/resolve-bulk',
                                                                     json={'domains': ['stringdate.com']})
        
        assert response.status_code == 200
        data = json.loads(response.data)
        result = data['results']['stringdate.com']
        
        # String dates should be returned as-is
        assert result['creation_date'] == '2020-05-15'
        assert result['expiration_date'] == '12345'
    
    def test_whois_bulk_filters_empty_strings(self, authenticated_client):
        """Test that empty strings are filtered from lists."""
        mock = MagicMock()
        mock.emails = ['valid@test.com', '', '  ', None]
        mock.email = None
        mock.registrant_email = None
        mock.admin_email = None
        mock.tech_email = None
        mock.name = ['Valid Name', '', '   ']
        mock.registrant_name = None
        mock.admin_name = None
        mock.tech_name = None
        mock.org = None
        mock.organization = None
        mock.registrant_organization = None
        mock.registrar = None
        mock.creation_date = None
        mock.expiration_date = None
        mock.name_servers = ['ns1.test.com', None, '']
        
        with patch('routes.whois.get_cached_whois', return_value=None):
            with patch('whois.whois', return_value=mock):
                with patch('routes.whois.get_concurrency_settings', return_value={'whois_concurrency': 3}):
                    with patch('routes.whois.get_whois_cache_settings', return_value={'cache_ttl': 3600}):
                        with patch('routes.whois.set_cached_whois'):
                            with patch('routes.whois.log_audit'):
                                response = authenticated_client.post('/api/whois/resolve-bulk',
                                                                     json={'domains': ['filter.com']})
        
        assert response.status_code == 200
        data = json.loads(response.data)
        result = data['results']['filter.com']
        
        # Only valid values should be present
        assert len(result['all_emails']) == 1
        assert result['all_emails'][0] == 'valid@test.com'
        assert len(result['all_names']) == 1
        assert result['all_names'][0] == 'Valid Name'
    
    def test_whois_bulk_concurrent_execution(self, authenticated_client):
        """Test that multiple domains are resolved concurrently."""
        call_count = {'count': 0}
        
        def mock_whois(domain):
            call_count['count'] += 1
            mock = MagicMock()
            mock.emails = [f'admin@{domain}']
            mock.email = None
            mock.registrant_email = None
            mock.admin_email = None
            mock.tech_email = None
            mock.name = f'Owner of {domain}'
            mock.registrant_name = None
            mock.admin_name = None
            mock.tech_name = None
            mock.org = None
            mock.organization = None
            mock.registrant_organization = None
            mock.registrar = None
            mock.creation_date = None
            mock.expiration_date = None
            mock.name_servers = None
            return mock
        
        with patch('routes.whois.get_cached_whois', return_value=None):
            with patch('whois.whois', side_effect=mock_whois):
                with patch('routes.whois.get_concurrency_settings', return_value={'whois_concurrency': 5}):
                    with patch('routes.whois.get_whois_cache_settings', return_value={'cache_ttl': 3600}):
                        with patch('routes.whois.set_cached_whois'):
                            with patch('routes.whois.log_audit'):
                                domains = ['a.com', 'b.com', 'c.com', 'd.com', 'e.com']
                                response = authenticated_client.post('/api/whois/resolve-bulk',
                                                                     json={'domains': domains})
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        # All domains should be resolved
        assert len(data['results']) == 5
        assert call_count['count'] == 5
        
        # Each domain should have correct results
        for domain in domains:
            assert domain in data['results']
            assert f'admin@{domain}' in data['results'][domain]['all_emails']
    
    def test_whois_bulk_caches_results(self, authenticated_client):
        """Test that resolved results are cached."""
        mock = MagicMock()
        mock.emails = ['test@example.com']
        mock.email = None
        mock.registrant_email = None
        mock.admin_email = None
        mock.tech_email = None
        mock.name = None
        mock.registrant_name = None
        mock.admin_name = None
        mock.tech_name = None
        mock.org = 'Test Org'
        mock.organization = None
        mock.registrant_organization = None
        mock.registrar = None
        mock.creation_date = None
        mock.expiration_date = None
        mock.name_servers = None
        
        with patch('routes.whois.get_cached_whois', return_value=None):
            with patch('whois.whois', return_value=mock):
                with patch('routes.whois.get_concurrency_settings', return_value={'whois_concurrency': 3}):
                    with patch('routes.whois.get_whois_cache_settings', return_value={'cache_ttl': 7200}):
                        with patch('routes.whois.set_cached_whois') as mock_set_cache:
                            with patch('routes.whois.log_audit'):
                                response = authenticated_client.post('/api/whois/resolve-bulk',
                                                                     json={'domains': ['cache.com']})
        
        assert response.status_code == 200
        
        # Verify cache was called with correct TTL
        mock_set_cache.assert_called_once()
        args = mock_set_cache.call_args[0]
        assert args[0] == 'cache.com'
        assert args[2] == 7200  # TTL
    
    def test_whois_bulk_mixed_cached_uncached(self, authenticated_client):
        """Test mix of cached and uncached domains."""
        cached_result = {
            'domain': 'cached.com',
            'all_emails': ['cached@test.com'],
            'organization': 'Cached Org'
        }
        
        mock = MagicMock()
        mock.emails = ['uncached@test.com']
        mock.email = None
        mock.registrant_email = None
        mock.admin_email = None
        mock.tech_email = None
        mock.name = None
        mock.registrant_name = None
        mock.admin_name = None
        mock.tech_name = None
        mock.org = 'Uncached Org'
        mock.organization = None
        mock.registrant_organization = None
        mock.registrar = None
        mock.creation_date = None
        mock.expiration_date = None
        mock.name_servers = None
        
        def mock_get_cached(domain):
            if domain == 'cached.com':
                return cached_result
            return None
        
        with patch('routes.whois.get_cached_whois', side_effect=mock_get_cached):
            with patch('whois.whois', return_value=mock):
                with patch('routes.whois.get_concurrency_settings', return_value={'whois_concurrency': 3}):
                    with patch('routes.whois.get_whois_cache_settings', return_value={'cache_ttl': 3600}):
                        with patch('routes.whois.set_cached_whois'):
                            with patch('routes.whois.log_audit'):
                                response = authenticated_client.post('/api/whois/resolve-bulk',
                                                                     json={'domains': ['cached.com', 'uncached.com']})
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        # Cached domain should have cached flag
        assert data['results']['cached.com']['cached'] == True
        assert data['results']['cached.com']['organization'] == 'Cached Org'
        
        # Uncached domain should have resolved data
        assert 'cached' not in data['results']['uncached.com']
        assert data['results']['uncached.com']['organization'] == 'Uncached Org'
        
        # Cached count should be reported
        assert data['cached_count'] == 1
