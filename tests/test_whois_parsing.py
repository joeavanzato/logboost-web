"""
Tests for WHOIS parsing logic.

Tests cover:
- Field extraction from various WHOIS response formats
- Deduplication of emails, names, organizations
- Date formatting
- Name server extraction
- Edge cases: None values, empty lists, mixed case
- Backwards compatibility (single values still populated)
"""

import json
import pytest
from unittest.mock import Mock, patch


class MockWhoisResponse:
    """Mock whois library response object for testing."""
    
    def __init__(self, **kwargs):
        # Set defaults to None
        self.domain_name = kwargs.get('domain_name')
        self.registrar = kwargs.get('registrar')
        self.emails = kwargs.get('emails')
        self.email = kwargs.get('email')
        self.registrant_email = kwargs.get('registrant_email')
        self.admin_email = kwargs.get('admin_email')
        self.tech_email = kwargs.get('tech_email')
        self.name = kwargs.get('name')
        self.registrant_name = kwargs.get('registrant_name')
        self.admin_name = kwargs.get('admin_name')
        self.tech_name = kwargs.get('tech_name')
        self.org = kwargs.get('org')
        self.organization = kwargs.get('organization')
        self.registrant_organization = kwargs.get('registrant_organization')
        self.creation_date = kwargs.get('creation_date')
        self.expiration_date = kwargs.get('expiration_date')
        self.name_servers = kwargs.get('name_servers')


class TestWhoisEmailExtraction:
    """Tests for email extraction from WHOIS data."""
    
    def test_single_email_in_emails_field(self, authenticated_client):
        """Test extraction of single email from emails field."""
        mock_response = MockWhoisResponse(
            emails='admin@example.com'
        )
        
        with patch('whois.whois', return_value=mock_response):
            response = authenticated_client.post('/api/whois/resolve',
                json={'domain': 'example.com'},
                content_type='application/json')
        
        assert response.status_code == 200
        data = response.get_json()
        
        assert data['all_emails'] == ['admin@example.com']
        assert data['registrant_email'] == 'admin@example.com'
    
    def test_multiple_emails_in_emails_field(self, authenticated_client):
        """Test extraction of multiple emails from emails list."""
        mock_response = MockWhoisResponse(
            emails=['admin@example.com', 'tech@example.com', 'abuse@example.com']
        )
        
        with patch('whois.whois', return_value=mock_response):
            response = authenticated_client.post('/api/whois/resolve',
                json={'domain': 'example.com'},
                content_type='application/json')
        
        assert response.status_code == 200
        data = response.get_json()
        
        assert len(data['all_emails']) == 3
        assert 'admin@example.com' in data['all_emails']
        assert 'tech@example.com' in data['all_emails']
        assert 'abuse@example.com' in data['all_emails']
        # First email should be registrant_email for backwards compat
        assert data['registrant_email'] == 'admin@example.com'
    
    def test_emails_from_multiple_fields(self, authenticated_client):
        """Test extraction of emails from multiple WHOIS fields."""
        mock_response = MockWhoisResponse(
            emails='general@example.com',
            registrant_email='registrant@example.com',
            admin_email='admin@example.com',
            tech_email='tech@example.com'
        )
        
        with patch('whois.whois', return_value=mock_response):
            response = authenticated_client.post('/api/whois/resolve',
                json={'domain': 'example.com'},
                content_type='application/json')
        
        assert response.status_code == 200
        data = response.get_json()
        
        assert len(data['all_emails']) == 4
        assert 'general@example.com' in data['all_emails']
        assert 'registrant@example.com' in data['all_emails']
        assert 'admin@example.com' in data['all_emails']
        assert 'tech@example.com' in data['all_emails']
    
    def test_email_deduplication_case_insensitive(self, authenticated_client):
        """Test that duplicate emails are removed (case-insensitive)."""
        mock_response = MockWhoisResponse(
            emails=['Admin@Example.com', 'admin@example.com', 'ADMIN@EXAMPLE.COM'],
            registrant_email='admin@example.com'
        )
        
        with patch('whois.whois', return_value=mock_response):
            response = authenticated_client.post('/api/whois/resolve',
                json={'domain': 'example.com'},
                content_type='application/json')
        
        assert response.status_code == 200
        data = response.get_json()
        
        # Should only have one email after deduplication
        assert len(data['all_emails']) == 1
    
    def test_no_emails_available(self, authenticated_client):
        """Test handling when no emails are in WHOIS data."""
        mock_response = MockWhoisResponse(
            registrar='Example Registrar'
        )
        
        with patch('whois.whois', return_value=mock_response):
            response = authenticated_client.post('/api/whois/resolve',
                json={'domain': 'example.com'},
                content_type='application/json')
        
        assert response.status_code == 200
        data = response.get_json()
        
        assert data['all_emails'] == []
        assert data['registrant_email'] is None


class TestWhoisNameExtraction:
    """Tests for registrant name extraction from WHOIS data."""
    
    def test_single_name(self, authenticated_client):
        """Test extraction of single name."""
        mock_response = MockWhoisResponse(
            name='John Doe'
        )
        
        with patch('whois.whois', return_value=mock_response):
            response = authenticated_client.post('/api/whois/resolve',
                json={'domain': 'example.com'},
                content_type='application/json')
        
        assert response.status_code == 200
        data = response.get_json()
        
        assert data['all_names'] == ['John Doe']
        assert data['registrant_name'] == 'John Doe'
    
    def test_names_from_multiple_fields(self, authenticated_client):
        """Test extraction of names from multiple fields."""
        mock_response = MockWhoisResponse(
            name='John Doe',
            registrant_name='Jane Smith',
            admin_name='Bob Admin',
            tech_name='Alice Tech'
        )
        
        with patch('whois.whois', return_value=mock_response):
            response = authenticated_client.post('/api/whois/resolve',
                json={'domain': 'example.com'},
                content_type='application/json')
        
        assert response.status_code == 200
        data = response.get_json()
        
        assert len(data['all_names']) == 4
        assert 'John Doe' in data['all_names']
        assert 'Jane Smith' in data['all_names']
        # First name becomes registrant_name for backwards compat
        assert data['registrant_name'] == 'John Doe'
    
    def test_name_deduplication(self, authenticated_client):
        """Test that duplicate names are removed."""
        mock_response = MockWhoisResponse(
            name='John Doe',
            registrant_name='john doe',  # Same name, different case
            admin_name='John Doe'
        )
        
        with patch('whois.whois', return_value=mock_response):
            response = authenticated_client.post('/api/whois/resolve',
                json={'domain': 'example.com'},
                content_type='application/json')
        
        assert response.status_code == 200
        data = response.get_json()
        
        # Should deduplicate case-insensitively
        assert len(data['all_names']) == 1


class TestWhoisOrganizationExtraction:
    """Tests for organization extraction from WHOIS data."""
    
    def test_single_organization(self, authenticated_client):
        """Test extraction of single organization."""
        mock_response = MockWhoisResponse(
            org='Example Corp'
        )
        
        with patch('whois.whois', return_value=mock_response):
            response = authenticated_client.post('/api/whois/resolve',
                json={'domain': 'example.com'},
                content_type='application/json')
        
        assert response.status_code == 200
        data = response.get_json()
        
        assert data['all_organizations'] == ['Example Corp']
        assert data['organization'] == 'Example Corp'
    
    def test_organizations_from_multiple_fields(self, authenticated_client):
        """Test extraction of orgs from multiple fields."""
        mock_response = MockWhoisResponse(
            org='Parent Company',
            organization='Subsidiary Inc',
            registrant_organization='Operating Company'
        )
        
        with patch('whois.whois', return_value=mock_response):
            response = authenticated_client.post('/api/whois/resolve',
                json={'domain': 'example.com'},
                content_type='application/json')
        
        assert response.status_code == 200
        data = response.get_json()
        
        assert len(data['all_organizations']) == 3
        assert 'Parent Company' in data['all_organizations']
        assert 'Subsidiary Inc' in data['all_organizations']
        assert 'Operating Company' in data['all_organizations']
    
    def test_organization_deduplication(self, authenticated_client):
        """Test that duplicate organizations are removed."""
        mock_response = MockWhoisResponse(
            org='Example Corp',
            organization='example corp',
            registrant_organization='EXAMPLE CORP'
        )
        
        with patch('whois.whois', return_value=mock_response):
            response = authenticated_client.post('/api/whois/resolve',
                json={'domain': 'example.com'},
                content_type='application/json')
        
        assert response.status_code == 200
        data = response.get_json()
        
        assert len(data['all_organizations']) == 1


class TestWhoisRegistrarExtraction:
    """Tests for registrar extraction from WHOIS data."""
    
    def test_single_registrar(self, authenticated_client):
        """Test extraction of single registrar."""
        mock_response = MockWhoisResponse(
            registrar='GoDaddy.com, LLC'
        )
        
        with patch('whois.whois', return_value=mock_response):
            response = authenticated_client.post('/api/whois/resolve',
                json={'domain': 'example.com'},
                content_type='application/json')
        
        assert response.status_code == 200
        data = response.get_json()
        
        assert data['all_registrars'] == ['GoDaddy.com, LLC']
        assert data['registrar'] == 'GoDaddy.com, LLC'
    
    def test_multiple_registrars_in_list(self, authenticated_client):
        """Test handling of registrar list (some WHOIS return history)."""
        mock_response = MockWhoisResponse(
            registrar=['Current Registrar', 'Previous Registrar']
        )
        
        with patch('whois.whois', return_value=mock_response):
            response = authenticated_client.post('/api/whois/resolve',
                json={'domain': 'example.com'},
                content_type='application/json')
        
        assert response.status_code == 200
        data = response.get_json()
        
        assert len(data['all_registrars']) == 2
        # First registrar is the primary one
        assert data['registrar'] == 'Current Registrar'


class TestWhoisDateFormatting:
    """Tests for date formatting in WHOIS data."""
    
    def test_datetime_object_formatting(self, authenticated_client):
        """Test formatting of datetime objects."""
        from datetime import datetime
        
        mock_response = MockWhoisResponse(
            creation_date=datetime(2020, 1, 15),
            expiration_date=datetime(2025, 1, 15)
        )
        
        with patch('whois.whois', return_value=mock_response):
            response = authenticated_client.post('/api/whois/resolve',
                json={'domain': 'example.com'},
                content_type='application/json')
        
        assert response.status_code == 200
        data = response.get_json()
        
        assert data['creation_date'] == '2020-01-15'
        assert data['expiration_date'] == '2025-01-15'
    
    def test_date_list_takes_first(self, authenticated_client):
        """Test that when dates are lists, first value is used."""
        from datetime import datetime
        
        mock_response = MockWhoisResponse(
            creation_date=[datetime(2020, 1, 15), datetime(2019, 1, 15)],
            expiration_date=[datetime(2025, 1, 15)]
        )
        
        with patch('whois.whois', return_value=mock_response):
            response = authenticated_client.post('/api/whois/resolve',
                json={'domain': 'example.com'},
                content_type='application/json')
        
        assert response.status_code == 200
        data = response.get_json()
        
        assert data['creation_date'] == '2020-01-15'
    
    def test_none_dates(self, authenticated_client):
        """Test handling of None dates."""
        mock_response = MockWhoisResponse(
            creation_date=None,
            expiration_date=None
        )
        
        with patch('whois.whois', return_value=mock_response):
            response = authenticated_client.post('/api/whois/resolve',
                json={'domain': 'example.com'},
                content_type='application/json')
        
        assert response.status_code == 200
        data = response.get_json()
        
        assert data['creation_date'] is None
        assert data['expiration_date'] is None


class TestWhoisNameServerExtraction:
    """Tests for name server extraction from WHOIS data."""
    
    def test_name_servers_list(self, authenticated_client):
        """Test extraction of name servers list."""
        mock_response = MockWhoisResponse(
            name_servers=['NS1.EXAMPLE.COM', 'NS2.EXAMPLE.COM']
        )
        
        with patch('whois.whois', return_value=mock_response):
            response = authenticated_client.post('/api/whois/resolve',
                json={'domain': 'example.com'},
                content_type='application/json')
        
        assert response.status_code == 200
        data = response.get_json()
        
        # Name servers should be lowercased
        assert 'ns1.example.com' in data['name_servers']
        assert 'ns2.example.com' in data['name_servers']
    
    def test_single_name_server(self, authenticated_client):
        """Test extraction of single name server."""
        mock_response = MockWhoisResponse(
            name_servers='NS1.EXAMPLE.COM'
        )
        
        with patch('whois.whois', return_value=mock_response):
            response = authenticated_client.post('/api/whois/resolve',
                json={'domain': 'example.com'},
                content_type='application/json')
        
        assert response.status_code == 200
        data = response.get_json()
        
        assert data['name_servers'] == ['ns1.example.com']
    
    def test_no_name_servers(self, authenticated_client):
        """Test handling when no name servers present."""
        mock_response = MockWhoisResponse()
        
        with patch('whois.whois', return_value=mock_response):
            response = authenticated_client.post('/api/whois/resolve',
                json={'domain': 'example.com'},
                content_type='application/json')
        
        assert response.status_code == 200
        data = response.get_json()
        
        assert data['name_servers'] is None


class TestWhoisEdgeCases:
    """Tests for edge cases in WHOIS parsing."""
    
    def test_empty_string_values_filtered(self, authenticated_client):
        """Test that empty strings are filtered out."""
        mock_response = MockWhoisResponse(
            emails=['admin@example.com', '', '  ', None],
            name=['John Doe', '', None]
        )
        
        with patch('whois.whois', return_value=mock_response):
            response = authenticated_client.post('/api/whois/resolve',
                json={'domain': 'example.com'},
                content_type='application/json')
        
        assert response.status_code == 200
        data = response.get_json()
        
        assert data['all_emails'] == ['admin@example.com']
        assert data['all_names'] == ['John Doe']
    
    def test_whitespace_trimming(self, authenticated_client):
        """Test that whitespace is trimmed from values."""
        mock_response = MockWhoisResponse(
            emails=['  admin@example.com  '],
            name=['  John Doe  '],
            org=['  Example Corp  ']
        )
        
        with patch('whois.whois', return_value=mock_response):
            response = authenticated_client.post('/api/whois/resolve',
                json={'domain': 'example.com'},
                content_type='application/json')
        
        assert response.status_code == 200
        data = response.get_json()
        
        assert data['all_emails'] == ['admin@example.com']
        assert data['all_names'] == ['John Doe']
        assert data['all_organizations'] == ['Example Corp']
    
    def test_complete_whois_response(self, authenticated_client):
        """Test parsing a complete WHOIS response with all fields."""
        from datetime import datetime
        
        mock_response = MockWhoisResponse(
            domain_name='example.com',
            registrar='Example Registrar, LLC',
            emails=['admin@example.com', 'tech@example.com'],
            registrant_email='registrant@example.com',
            name='Domain Admin',
            registrant_name='John Registrant',
            org='Example Organization',
            registrant_organization='Example Holdings',
            creation_date=datetime(2010, 3, 15),
            expiration_date=datetime(2030, 3, 15),
            name_servers=['NS1.EXAMPLE.COM', 'NS2.EXAMPLE.COM']
        )
        
        with patch('whois.whois', return_value=mock_response):
            response = authenticated_client.post('/api/whois/resolve',
                json={'domain': 'example.com'},
                content_type='application/json')
        
        assert response.status_code == 200
        data = response.get_json()
        
        # Check all_* fields
        assert len(data['all_emails']) == 3
        assert len(data['all_names']) == 2
        assert len(data['all_organizations']) == 2
        assert len(data['all_registrars']) == 1
        
        # Check backwards compat fields
        assert data['registrant_email'] is not None
        assert data['registrant_name'] is not None
        assert data['organization'] is not None
        assert data['registrar'] == 'Example Registrar, LLC'
        
        # Check dates
        assert data['creation_date'] == '2010-03-15'
        assert data['expiration_date'] == '2030-03-15'
        
        # Check name servers
        assert len(data['name_servers']) == 2
    
    def test_all_none_fields(self, authenticated_client):
        """Test handling of WHOIS response with all None fields."""
        mock_response = MockWhoisResponse()
        
        with patch('whois.whois', return_value=mock_response):
            response = authenticated_client.post('/api/whois/resolve',
                json={'domain': 'example.com'},
                content_type='application/json')
        
        assert response.status_code == 200
        data = response.get_json()
        
        assert data['all_emails'] == []
        assert data['all_names'] == []
        assert data['all_organizations'] == []
        assert data['all_registrars'] == []
        assert data['registrant_email'] is None
        assert data['registrant_name'] is None
        assert data['organization'] is None
        assert data['registrar'] is None


class TestWhoisAPIValidation:
    """Tests for WHOIS API input validation."""
    
    def test_missing_domain(self, authenticated_client):
        """Test error when domain is missing."""
        response = authenticated_client.post('/api/whois/resolve',
            json={},
            content_type='application/json')
        
        assert response.status_code == 400
        data = response.get_json()
        assert 'error' in data
    
    def test_empty_domain(self, authenticated_client):
        """Test error when domain is empty."""
        response = authenticated_client.post('/api/whois/resolve',
            json={'domain': ''},
            content_type='application/json')
        
        assert response.status_code == 400
        data = response.get_json()
        assert 'error' in data
    
    def test_whitespace_only_domain(self, authenticated_client):
        """Test error when domain is whitespace only."""
        response = authenticated_client.post('/api/whois/resolve',
            json={'domain': '   '},
            content_type='application/json')
        
        assert response.status_code == 400
        data = response.get_json()
        assert 'error' in data
    
    def test_no_json_body(self, authenticated_client):
        """Test error when no JSON body provided."""
        response = authenticated_client.post('/api/whois/resolve',
            content_type='application/json')
        
        assert response.status_code == 400


class TestWhoisCaching:
    """Tests for WHOIS result caching."""
    
    def test_result_is_cached(self, authenticated_client, test_db):
        """Test that WHOIS results are cached."""
        import admin
        
        mock_response = MockWhoisResponse(
            registrar='Test Registrar',
            emails='test@example.com'
        )
        
        with patch('whois.whois', return_value=mock_response):
            # First request
            response1 = authenticated_client.post('/api/whois/resolve',
                json={'domain': 'cachetest.com'},
                content_type='application/json')
            
            assert response1.status_code == 200
        
        # Check cache was populated
        cached = admin.get_cached_whois('cachetest.com')
        assert cached is not None
        assert cached['registrar'] == 'Test Registrar'
    
    def test_cached_result_returned(self, authenticated_client, test_db):
        """Test that cached results are returned on subsequent requests."""
        import admin
        
        # Pre-populate cache
        cached_result = {
            'domain': 'precached.com',
            'registrar': 'Cached Registrar',
            'registrant_email': 'cached@example.com',
            'all_emails': ['cached@example.com'],
            'all_names': [],
            'all_organizations': [],
            'all_registrars': ['Cached Registrar']
        }
        admin.set_cached_whois('precached.com', cached_result, 86400)
        
        # Request should return cached result without calling whois
        with patch('whois.whois') as mock_whois:
            response = authenticated_client.post('/api/whois/resolve',
                json={'domain': 'precached.com'},
                content_type='application/json')
            
            # whois should not have been called
            mock_whois.assert_not_called()
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['registrar'] == 'Cached Registrar'
        assert data['cached'] == True


class TestWhoisErrorHandling:
    """Tests for WHOIS error handling."""
    
    def test_whois_library_exception(self, authenticated_client):
        """Test handling of whois library exceptions."""
        with patch('whois.whois', side_effect=Exception('WHOIS lookup failed')):
            response = authenticated_client.post('/api/whois/resolve',
                json={'domain': 'error.com'},
                content_type='application/json')
        
        assert response.status_code == 500
        data = response.get_json()
        assert 'error' in data
        assert data['domain'] == 'error.com'
