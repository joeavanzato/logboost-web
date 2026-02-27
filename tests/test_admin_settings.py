"""
Tests for Admin Settings Management.

Tests cover:
- get_setting() / set_setting() - Core settings functions
- get_dns_settings() - DNS configuration retrieval
- get_concurrency_settings() - Concurrency configuration
- get_whois_cache_settings() - WHOIS cache settings
- get_shodan_cache_settings() - Shodan cache settings
- get_circl_settings() - CIRCL PDNS settings
- get_hackertarget_settings() - HackerTarget settings
- get_viewdns_settings() - ViewDNS settings
- Settings save endpoints
"""

import pytest
import json
from unittest.mock import patch, MagicMock


class TestGetSetSettings:
    """Tests for get_setting and set_setting functions."""
    
    def test_get_setting_returns_value(self, test_db):
        """Test getting an existing setting."""
        import admin
        admin.set_setting('test_key', 'test_value')
        result = admin.get_setting('test_key')
        assert result == 'test_value'
    
    def test_get_setting_returns_default_when_missing(self, test_db):
        """Test default value for missing setting."""
        import admin
        result = admin.get_setting('nonexistent_key', 'default_val')
        assert result == 'default_val'
    
    def test_get_setting_returns_none_when_no_default(self, test_db):
        """Test None returned when no default provided."""
        import admin
        result = admin.get_setting('nonexistent_key')
        assert result is None
    
    def test_set_setting_creates_new(self, test_db):
        """Test creating a new setting."""
        import admin
        admin.set_setting('new_key', 'new_value')
        result = admin.get_setting('new_key')
        assert result == 'new_value'
    
    def test_set_setting_updates_existing(self, test_db):
        """Test updating an existing setting."""
        import admin
        admin.set_setting('update_key', 'original')
        admin.set_setting('update_key', 'updated')
        result = admin.get_setting('update_key')
        assert result == 'updated'


class TestGetDnsSettings:
    """Tests for get_dns_settings function."""
    
    def test_get_dns_settings_defaults(self, test_db):
        """Test default DNS settings."""
        import admin
        settings = admin.get_dns_settings()
        assert 'servers' in settings
        assert 'timeout' in settings
        assert 'cache_ttl' in settings
    
    def test_get_dns_settings_custom_values(self, test_db):
        """Test custom DNS settings."""
        import admin
        admin.set_setting('dns_servers', '1.1.1.1,9.9.9.9')
        admin.set_setting('dns_timeout', '10')
        admin.set_setting('dns_cache_ttl', '7200')
        settings = admin.get_dns_settings()
        assert settings['servers'] == '1.1.1.1,9.9.9.9'
        assert settings['timeout'] == 10
        assert settings['cache_ttl'] == 7200


class TestGetConcurrencySettings:
    """Tests for get_concurrency_settings function."""
    
    def test_get_concurrency_settings_defaults(self, test_db):
        """Test default concurrency settings."""
        import admin
        settings = admin.get_concurrency_settings()
        assert 'dns_concurrency' in settings
        assert 'whois_concurrency' in settings
        assert settings['dns_concurrency'] >= 1
        assert settings['whois_concurrency'] >= 1
    
    def test_get_concurrency_settings_custom_values(self, test_db):
        """Test custom concurrency settings."""
        import admin
        admin.set_setting('dns_concurrency', '20')
        admin.set_setting('whois_concurrency', '10')
        settings = admin.get_concurrency_settings()
        assert settings['dns_concurrency'] == 20
        assert settings['whois_concurrency'] == 10


class TestGetWhoisCacheSettings:
    """Tests for get_whois_cache_settings function."""
    
    def test_get_whois_cache_settings_defaults(self, test_db):
        """Test default WHOIS cache settings."""
        import admin
        settings = admin.get_whois_cache_settings()
        assert 'cache_ttl' in settings
        assert settings['cache_ttl'] > 0
    
    def test_get_whois_cache_settings_custom(self, test_db):
        """Test custom WHOIS cache settings."""
        import admin
        admin.set_setting('whois_cache_ttl', '172800')
        settings = admin.get_whois_cache_settings()
        assert settings['cache_ttl'] == 172800


class TestGetShodanCacheSettings:
    """Tests for get_shodan_cache_settings function."""
    
    def test_get_shodan_cache_settings_defaults(self, test_db):
        """Test default Shodan cache settings."""
        import admin
        settings = admin.get_shodan_cache_settings()
        assert 'cache_ttl' in settings
        assert settings['cache_ttl'] > 0
    
    def test_get_shodan_cache_settings_custom(self, test_db):
        """Test custom Shodan cache settings."""
        import admin
        admin.set_setting('shodan_cache_ttl', '7200')
        settings = admin.get_shodan_cache_settings()
        assert settings['cache_ttl'] == 7200


class TestGetShodanPivotLimit:
    """Tests for get_shodan_pivot_limit function."""
    
    def test_get_shodan_pivot_limit_default(self, test_db):
        """Test default Shodan pivot limit."""
        import admin
        limit = admin.get_shodan_pivot_limit()
        assert limit > 0
    
    def test_get_shodan_pivot_limit_custom(self, test_db):
        """Test custom Shodan pivot limit."""
        import admin
        admin.set_setting('shodan_pivot_limit', '200')
        limit = admin.get_shodan_pivot_limit()
        assert limit == 200


class TestGetCirclSettings:
    """Tests for get_circl_settings function."""
    
    def test_get_circl_settings_defaults(self, test_db):
        """Test default CIRCL settings."""
        import admin
        settings = admin.get_circl_settings()
        assert 'username' in settings
        assert 'password' in settings
        assert 'cache_ttl' in settings
        assert 'rate_limit' in settings
    
    def test_get_circl_settings_with_credentials(self, test_db):
        """Test CIRCL settings with credentials."""
        import admin
        admin.set_setting('circl_username', 'testuser')
        admin.set_setting('circl_password', 'testpass')
        admin.set_setting('circl_cache_ttl', '86400')
        settings = admin.get_circl_settings()
        assert settings['username'] == 'testuser'
        assert settings['password'] == 'testpass'
        assert settings['cache_ttl'] == 86400


class TestGetHackertargetSettings:
    """Tests for get_hackertarget_settings function."""
    
    def test_get_hackertarget_settings_defaults(self, test_db):
        """Test default HackerTarget settings."""
        import admin
        settings = admin.get_hackertarget_settings()
        assert 'api_key' in settings
        assert 'cache_ttl' in settings
    
    def test_get_hackertarget_settings_with_api_key(self, test_db):
        """Test HackerTarget settings with API key."""
        import admin
        admin.set_setting('hackertarget_api_key', 'test-api-key')
        admin.set_setting('hackertarget_cache_ttl', '43200')
        settings = admin.get_hackertarget_settings()
        assert settings['api_key'] == 'test-api-key'
        assert settings['cache_ttl'] == 43200


class TestGetViewdnsSettings:
    """Tests for get_viewdns_settings function."""
    
    def test_get_viewdns_settings_defaults(self, test_db):
        """Test default ViewDNS settings."""
        import admin
        settings = admin.get_viewdns_settings()
        assert 'api_key' in settings
        assert 'cache_ttl' in settings
    
    def test_get_viewdns_settings_with_api_key(self, test_db):
        """Test ViewDNS settings with API key."""
        import admin
        admin.set_setting('viewdns_api_key', 'viewdns-key-123')
        admin.set_setting('viewdns_cache_ttl', '86400')
        settings = admin.get_viewdns_settings()
        assert settings['api_key'] == 'viewdns-key-123'
        assert settings['cache_ttl'] == 86400


class TestSaveDnsSettingsEndpoint:
    """Tests for POST /admin/settings/dns endpoint."""
    
    def test_save_dns_success(self, admin_client, test_db):
        """Test successful DNS settings save."""
        with patch('admin.log_audit'):
            response = admin_client.post('/admin/settings/dns',
                data={'dns_servers': '1.1.1.1,8.8.8.8', 'dns_cache_ttl': '7200', 
                      'dns_timeout': '10', 'dns_max_domains': '200'},
                follow_redirects=False)
        assert response.status_code == 302
        import admin
        settings = admin.get_dns_settings()
        assert '1.1.1.1' in settings['servers']


class TestSaveConcurrencySettingsEndpoint:
    """Tests for POST /admin/settings/concurrency endpoint."""
    
    def test_save_concurrency_success(self, admin_client, test_db):
        """Test successful concurrency settings save."""
        with patch('admin.log_audit'):
            response = admin_client.post('/admin/settings/concurrency',
                data={'dns_concurrency': '25', 'whois_concurrency': '15'},
                follow_redirects=False)
        assert response.status_code == 302
    
    def test_save_concurrency_validates_range(self, admin_client, test_db):
        """Test that concurrency values are validated."""
        with patch('admin.log_audit'):
            response = admin_client.post('/admin/settings/concurrency',
                data={'dns_concurrency': '1000', 'whois_concurrency': '-5'},
                follow_redirects=False)
        assert response.status_code == 302
        import admin
        settings = admin.get_concurrency_settings()
        assert settings['dns_concurrency'] <= 50
        assert settings['whois_concurrency'] >= 1


class TestSaveCacheSettingsEndpoint:
    """Tests for POST /admin/settings/cache endpoint."""
    
    def test_save_cache_success(self, admin_client, test_db):
        """Test successful cache settings save."""
        with patch('admin.log_audit'):
            response = admin_client.post('/admin/settings/cache',
                data={'whois_cache_ttl': '172800', 'shodan_cache_ttl': '7200'},
                follow_redirects=False)
        assert response.status_code == 302


class TestSaveApiKeysEndpoints:
    """Tests for API key save endpoints."""
    
    def test_save_maxmind_key_success(self, admin_client, test_db):
        """Test successful MaxMind key save."""
        with patch('admin.log_audit'):
            response = admin_client.post('/admin/settings/maxmind',
                data={'maxmind_api_key': 'test-maxmind-key'},
                follow_redirects=False)
        assert response.status_code == 302
        import admin
        key = admin.get_setting('maxmind_api_key')
        assert key == 'test-maxmind-key'
    
    def test_save_shodan_key_success(self, admin_client, test_db):
        """Test successful Shodan key save."""
        with patch('admin.log_audit'):
            response = admin_client.post('/admin/settings/shodan',
                data={'shodan_api_key': 'test-shodan-key'},
                follow_redirects=False)
        assert response.status_code == 302


class TestSaveCirclSettingsEndpoint:
    """Tests for POST /admin/settings/circl endpoint."""
    
    def test_save_circl_success(self, admin_client, test_db):
        """Test successful CIRCL settings save."""
        with patch('admin.log_audit'):
            response = admin_client.post('/admin/settings/circl',
                data={'circl_username': 'testuser', 'circl_password': 'testpass',
                      'circl_cache_ttl': '86400', 'circl_rate_limit': '5'},
                follow_redirects=False)
        assert response.status_code == 302


class TestSaveHackertargetSettingsEndpoint:
    """Tests for POST /admin/settings/hackertarget endpoint."""
    
    def test_save_hackertarget_success(self, admin_client, test_db):
        """Test successful HackerTarget settings save."""
        with patch('admin.log_audit'):
            response = admin_client.post('/admin/settings/hackertarget',
                data={'hackertarget_api_key': 'ht-api-key', 'hackertarget_cache_ttl': '43200'},
                follow_redirects=False)
        assert response.status_code == 302


class TestSaveViewdnsSettingsEndpoint:
    """Tests for POST /admin/settings/viewdns endpoint."""
    
    def test_save_viewdns_success(self, admin_client, test_db):
        """Test successful ViewDNS settings save."""
        with patch('admin.log_audit'):
            response = admin_client.post('/admin/settings/viewdns',
                data={'viewdns_api_key': 'vd-api-key', 'viewdns_cache_ttl': '86400'},
                follow_redirects=False)
        assert response.status_code == 302


class TestAdminSettingsPage:
    """Tests for GET /admin/settings endpoint."""
    
    def test_settings_page_loads(self, admin_client, test_db):
        """Test that settings page loads for admin."""
        response = admin_client.get('/admin/settings')
        assert response.status_code == 200
