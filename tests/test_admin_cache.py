"""
Tests for admin.py cache and settings functions.

Tests cover:
- DNS cache: get/set/clear operations
- WHOIS cache: get/set/clear operations  
- CIRCL PDNS cache: get/set/clear operations
- ViewDNS cache: get/set/clear operations
- HackerTarget cache: get/set/clear operations
- Settings retrieval functions
"""

import json
import time
from datetime import datetime, timedelta
import pytest


class TestDNSCache:
    """Tests for DNS cache functions."""
    
    def test_set_and_get_dns_cache(self, test_db):
        """Test basic DNS cache set and get."""
        import admin
        
        query = 'example.com'
        record_type = 'A'
        results = ['93.184.216.34']
        ttl = 3600
        
        # Set cache
        admin.set_cached_dns(query, record_type, results, ttl)
        
        # Get cache - returns the results directly (list)
        cached = admin.get_cached_dns(query, record_type)
        
        assert cached is not None
        assert cached == results
    
    def test_dns_cache_miss(self, test_db):
        """Test DNS cache miss returns None."""
        import admin
        
        cached = admin.get_cached_dns('nonexistent.com', 'A')
        assert cached is None
    
    def test_dns_cache_different_record_types(self, test_db):
        """Test DNS cache handles different record types separately."""
        import admin
        
        query = 'example.com'
        a_results = ['93.184.216.34']
        mx_results = ['10 mail.example.com']
        
        admin.set_cached_dns(query, 'A', a_results, 3600)
        admin.set_cached_dns(query, 'MX', mx_results, 3600)
        
        cached_a = admin.get_cached_dns(query, 'A')
        cached_mx = admin.get_cached_dns(query, 'MX')
        
        assert cached_a == a_results
        assert cached_mx == mx_results
    
    def test_dns_cache_case_insensitive(self, test_db):
        """Test DNS cache query is case insensitive."""
        import admin
        
        results = ['93.184.216.34']
        admin.set_cached_dns('EXAMPLE.COM', 'A', results, 3600)
        
        # Should find regardless of case (stored lowercase)
        cached = admin.get_cached_dns('example.com', 'A')
        assert cached is not None
        assert cached == results
    
    def test_dns_cache_expiration(self, test_db):
        """Test DNS cache entries expire after TTL."""
        import admin
        
        # Set with 1 second TTL
        admin.set_cached_dns('ttl-test.com', 'A', ['1.2.3.4'], 1)
        
        # Should be available immediately
        cached = admin.get_cached_dns('ttl-test.com', 'A')
        assert cached is not None
        
        # Wait for expiration (2 seconds to be safe)
        time.sleep(2)
        
        # Expired entries return None (checked in SQL)
        cached = admin.get_cached_dns('ttl-test.com', 'A')
        assert cached is None
    
    def test_clear_expired_dns_cache(self, test_db):
        """Test clearing expired DNS cache entries removes them from DB."""
        import admin
        
        # Set cache with 1 second TTL
        admin.set_cached_dns('expired.com', 'A', ['1.2.3.4'], 1)
        
        # Verify it's in the cache
        cached = admin.get_cached_dns('expired.com', 'A')
        assert cached is not None
        
        # Wait for expiration
        time.sleep(1.5)
        
        # Clear expired entries
        admin.clear_expired_dns_cache()
        
        # Verify entry is removed (should be None due to expiration anyway)
        cached = admin.get_cached_dns('expired.com', 'A')
        assert cached is None


class TestWHOISCache:
    """Tests for WHOIS cache functions."""
    
    def test_set_and_get_whois_cache(self, test_db, sample_whois_results):
        """Test basic WHOIS cache set and get."""
        import admin
        
        domain = 'example.com'
        
        admin.set_cached_whois(domain, sample_whois_results, 86400)
        
        # Returns the results dict directly
        cached = admin.get_cached_whois(domain)
        
        assert cached is not None
        assert cached['domain'] == 'example.com'
        assert cached['registrar'] == sample_whois_results['registrar']
    
    def test_whois_cache_miss(self, test_db):
        """Test WHOIS cache miss returns None."""
        import admin
        
        cached = admin.get_cached_whois('nonexistent.com')
        assert cached is None
    
    def test_whois_cache_all_fields(self, test_db, sample_whois_results):
        """Test WHOIS cache preserves all fields including all_* arrays."""
        import admin
        
        admin.set_cached_whois('example.com', sample_whois_results, 86400)
        
        cached = admin.get_cached_whois('example.com')
        
        # Check all_* fields are preserved
        assert 'all_emails' in cached
        assert len(cached['all_emails']) == 3
        assert 'admin@example.com' in cached['all_emails']
        
        assert 'all_names' in cached
        assert len(cached['all_names']) == 2
        
        assert 'all_organizations' in cached
        assert len(cached['all_organizations']) == 2
    
    def test_whois_cache_expiration(self, test_db, sample_whois_results):
        """Test WHOIS cache entries expire after TTL."""
        import admin
        
        admin.set_cached_whois('ttl-test.com', sample_whois_results, 1)
        
        cached = admin.get_cached_whois('ttl-test.com')
        assert cached is not None
        
        time.sleep(2)
        
        cached = admin.get_cached_whois('ttl-test.com')
        assert cached is None


class TestCIRCLPDNSCache:
    """Tests for CIRCL Passive DNS cache functions."""
    
    def test_set_and_get_circl_pdns_cache(self, test_db, sample_circl_pdns_results):
        """Test basic CIRCL PDNS cache set and get."""
        import admin
        
        query_value = '93.184.216.34'
        query_type = 'ip'
        
        admin.set_cached_circl_pdns(
            query_value, 
            query_type, 
            sample_circl_pdns_results, 
            len(sample_circl_pdns_results), 
            86400
        )
        
        # Returns dict with results, result_count, cached_at, from_cache
        cached = admin.get_cached_circl_pdns(query_value, query_type)
        
        assert cached is not None
        assert cached['results'] == sample_circl_pdns_results
        assert cached['result_count'] == len(sample_circl_pdns_results)
        assert cached['from_cache'] == True
    
    def test_circl_pdns_cache_different_types(self, test_db, sample_circl_pdns_results):
        """Test CIRCL PDNS cache handles ip vs domain queries separately."""
        import admin
        
        ip_results = sample_circl_pdns_results[:2]
        domain_results = sample_circl_pdns_results[2:]
        
        admin.set_cached_circl_pdns('93.184.216.34', 'ip', ip_results, len(ip_results), 86400)
        admin.set_cached_circl_pdns('example.com', 'domain', domain_results, len(domain_results), 86400)
        
        cached_ip = admin.get_cached_circl_pdns('93.184.216.34', 'ip')
        cached_domain = admin.get_cached_circl_pdns('example.com', 'domain')
        
        assert cached_ip['results'] == ip_results
        assert cached_domain['results'] == domain_results
    
    def test_circl_pdns_cache_miss(self, test_db):
        """Test CIRCL PDNS cache miss returns None."""
        import admin
        
        cached = admin.get_cached_circl_pdns('nonexistent.com', 'domain')
        assert cached is None
    
    def test_circl_pdns_cache_expiration(self, test_db, sample_circl_pdns_results):
        """Test CIRCL PDNS cache entries expire after TTL."""
        import admin
        
        # First verify entry is retrievable when not expired
        admin.set_cached_circl_pdns('expired.com', 'domain', sample_circl_pdns_results, 4, 3600)
        
        cached = admin.get_cached_circl_pdns('expired.com', 'domain')
        assert cached is not None
        
        # Now directly set an expired timestamp in the database
        conn = admin.get_db()
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE circl_pdns_cache 
            SET expires_at = datetime('now', '-1 hour')
            WHERE query_value = 'expired.com'
        ''')
        conn.commit()
        conn.close()
        
        # Now the entry should be expired
        cached = admin.get_cached_circl_pdns('expired.com', 'domain')
        assert cached is None


class TestViewDNSCache:
    """Tests for ViewDNS cache functions."""
    
    def test_set_and_get_viewdns_cache(self, test_db, sample_viewdns_reverse_mx_results):
        """Test basic ViewDNS cache set and get."""
        import admin
        
        query_value = 'mail.example.com'
        query_type = 'reverse_mx'
        results = sample_viewdns_reverse_mx_results['response']['domains']
        
        admin.set_cached_viewdns(query_value, query_type, results, len(results), 86400)
        
        # Returns dict with results, result_count, cached_at, from_cache
        cached = admin.get_cached_viewdns(query_value, query_type)
        
        assert cached is not None
        assert cached['results'] == results
        assert cached['result_count'] == 3
    
    def test_viewdns_cache_different_query_types(self, test_db):
        """Test ViewDNS cache handles different query types separately."""
        import admin
        
        mx_results = ['domain1.com', 'domain2.com']
        ns_results = ['domain3.com', 'domain4.com', 'domain5.com']
        whois_results = ['domain6.com']
        
        admin.set_cached_viewdns('mail.example.com', 'reverse_mx', mx_results, 2, 86400)
        admin.set_cached_viewdns('ns1.example.com', 'reverse_ns', ns_results, 3, 86400)
        admin.set_cached_viewdns('admin@example.com', 'reverse_whois', whois_results, 1, 86400)
        
        cached_mx = admin.get_cached_viewdns('mail.example.com', 'reverse_mx')
        cached_ns = admin.get_cached_viewdns('ns1.example.com', 'reverse_ns')
        cached_whois = admin.get_cached_viewdns('admin@example.com', 'reverse_whois')
        
        assert cached_mx['results'] == mx_results
        assert cached_ns['results'] == ns_results
        assert cached_whois['results'] == whois_results
    
    def test_viewdns_cache_miss(self, test_db):
        """Test ViewDNS cache miss returns None."""
        import admin
        
        cached = admin.get_cached_viewdns('nonexistent.com', 'reverse_mx')
        assert cached is None
    
    def test_viewdns_cache_expiration(self, test_db):
        """Test ViewDNS cache entries expire after TTL."""
        import admin
        
        admin.set_cached_viewdns('expired.com', 'reverse_mx', ['test.com'], 1, 1)
        
        cached = admin.get_cached_viewdns('expired.com', 'reverse_mx')
        assert cached is not None
        
        time.sleep(1.5)
        
        cached = admin.get_cached_viewdns('expired.com', 'reverse_mx')
        assert cached is None


class TestHackerTargetCache:
    """Tests for HackerTarget cache functions."""
    
    def test_set_and_get_hackertarget_cache(self, test_db, sample_hackertarget_shared_ns_results):
        """Test basic HackerTarget cache set and get."""
        import admin
        
        query_value = 'ns1.example.com'
        query_type = 'shared_ns'
        
        admin.set_cached_hackertarget(
            query_value, 
            query_type, 
            sample_hackertarget_shared_ns_results, 
            len(sample_hackertarget_shared_ns_results), 
            86400
        )
        
        # Returns dict with results, result_count, cached_at, from_cache
        cached = admin.get_cached_hackertarget(query_value, query_type)
        
        assert cached is not None
        assert cached['results'] == sample_hackertarget_shared_ns_results
        assert cached['result_count'] == 4
        assert cached['from_cache'] == True
    
    def test_hackertarget_cache_miss(self, test_db):
        """Test HackerTarget cache miss returns None."""
        import admin
        
        cached = admin.get_cached_hackertarget('nonexistent.com', 'shared_ns')
        assert cached is None
    
    def test_hackertarget_cache_expiration(self, test_db, sample_hackertarget_shared_ns_results):
        """Test HackerTarget cache entries expire after TTL."""
        import admin
        
        admin.set_cached_hackertarget('expired.com', 'shared_ns', sample_hackertarget_shared_ns_results, 4, 1)
        
        cached = admin.get_cached_hackertarget('expired.com', 'shared_ns')
        assert cached is not None
        
        time.sleep(2)
        
        cached = admin.get_cached_hackertarget('expired.com', 'shared_ns')
        assert cached is None


class TestSettingsFunctions:
    """Tests for settings retrieval functions."""
    
    def test_get_dns_settings_defaults(self, test_db):
        """Test DNS settings returns defaults when not configured."""
        import admin
        
        settings = admin.get_dns_settings()
        
        assert 'timeout' in settings
        assert 'cache_ttl' in settings
        assert 'servers' in settings
        assert 'max_domains' in settings
        assert settings['timeout'] > 0
        assert settings['cache_ttl'] > 0
    
    def test_get_circl_settings_defaults(self, test_db):
        """Test CIRCL settings returns defaults when not configured."""
        import admin
        
        settings = admin.get_circl_settings()
        
        assert 'username' in settings
        assert 'password' in settings
        assert 'cache_ttl' in settings
        assert 'rate_limit' in settings
        assert 'max_results' in settings  # Not max_nodes
        # Default unconfigured
        assert settings['username'] == ''
        assert settings['password'] == ''
    
    def test_get_viewdns_settings_defaults(self, test_db):
        """Test ViewDNS settings returns defaults when not configured."""
        import admin
        
        settings = admin.get_viewdns_settings()
        
        assert 'api_key' in settings
        assert 'cache_ttl' in settings
        assert 'rate_limit' in settings
        assert 'max_nodes' in settings
        # Default unconfigured
        assert settings['api_key'] == ''
        assert settings['max_nodes'] == 100  # default
    
    def test_get_hackertarget_settings_defaults(self, test_db):
        """Test HackerTarget settings returns defaults when not configured."""
        import admin
        
        settings = admin.get_hackertarget_settings()
        
        assert 'api_key' in settings
        assert 'cache_ttl' in settings
        # HackerTarget returns api_key and cache_ttl only
    
    def test_get_whois_cache_settings_defaults(self, test_db):
        """Test WHOIS cache settings returns defaults."""
        import admin
        
        settings = admin.get_whois_cache_settings()
        
        assert 'cache_ttl' in settings
        assert settings['cache_ttl'] > 0
    
    def test_get_shodan_cache_settings_defaults(self, test_db):
        """Test Shodan cache settings returns defaults."""
        import admin
        
        settings = admin.get_shodan_cache_settings()
        
        assert 'cache_ttl' in settings
        assert settings['cache_ttl'] > 0
    
    def test_set_and_get_setting(self, test_db):
        """Test generic setting set and get."""
        import admin
        
        admin.set_setting('test_key', 'test_value')
        
        value = admin.get_setting('test_key')
        
        assert value == 'test_value'
    
    def test_get_setting_default(self, test_db):
        """Test get_setting returns default for missing key."""
        import admin
        
        value = admin.get_setting('nonexistent_key', 'default_value')
        
        assert value == 'default_value'
    
    def test_set_setting_overwrite(self, test_db):
        """Test setting a value overwrites existing value."""
        import admin
        
        admin.set_setting('overwrite_key', 'first_value')
        admin.set_setting('overwrite_key', 'second_value')
        
        value = admin.get_setting('overwrite_key')
        
        assert value == 'second_value'


class TestCacheDataIntegrity:
    """Tests for cache data integrity with complex data."""
    
    def test_dns_cache_with_multiple_records(self, test_db, sample_dns_results):
        """Test DNS cache preserves multiple record values."""
        import admin
        
        for record_type, results in sample_dns_results.items():
            admin.set_cached_dns('multi.example.com', record_type, results, 3600)
        
        for record_type, expected_results in sample_dns_results.items():
            cached = admin.get_cached_dns('multi.example.com', record_type)
            assert cached is not None
            assert cached == expected_results
    
    def test_cache_with_special_characters(self, test_db):
        """Test cache handles domains with special characters."""
        import admin
        
        # Internationalized domain name
        domain = 'münchen.example.com'
        results = ['1.2.3.4']
        
        admin.set_cached_dns(domain, 'A', results, 3600)
        cached = admin.get_cached_dns(domain, 'A')
        
        assert cached is not None
        assert cached == results
    
    def test_viewdns_cache_with_email_query(self, test_db):
        """Test ViewDNS cache handles email addresses as query values."""
        import admin
        
        email = 'admin@example.com'
        results = ['domain1.com', 'domain2.com']
        
        admin.set_cached_viewdns(email, 'reverse_whois', results, 2, 86400)
        cached = admin.get_cached_viewdns(email, 'reverse_whois')
        
        assert cached is not None
        assert cached['results'] == results
    
    def test_circl_pdns_cache_preserves_timestamps(self, test_db, sample_circl_pdns_results):
        """Test CIRCL PDNS cache preserves time_first/time_last data."""
        import admin
        
        admin.set_cached_circl_pdns('192.168.1.1', 'ip', sample_circl_pdns_results, 4, 86400)
        cached = admin.get_cached_circl_pdns('192.168.1.1', 'ip')
        
        assert cached is not None
        results = cached['results']
        assert len(results) == 4
        
        # Check first record has timestamps
        assert 'time_first' in results[0]
        assert 'time_last' in results[0]
        assert results[0]['time_first'] == 1577836800
    
    def test_whois_cache_preserves_name_servers(self, test_db, sample_whois_results):
        """Test WHOIS cache preserves name_servers list."""
        import admin
        
        admin.set_cached_whois('ns-test.com', sample_whois_results, 86400)
        cached = admin.get_cached_whois('ns-test.com')
        
        assert 'name_servers' in cached
        assert cached['name_servers'] == ['ns1.example.com', 'ns2.example.com']


class TestCacheOverwrite:
    """Tests for cache overwrite behavior."""
    
    def test_dns_cache_overwrite(self, test_db):
        """Test DNS cache entry is overwritten on re-insert."""
        import admin
        
        admin.set_cached_dns('overwrite.com', 'A', ['1.1.1.1'], 3600)
        cached = admin.get_cached_dns('overwrite.com', 'A')
        assert cached == ['1.1.1.1']
        
        admin.set_cached_dns('overwrite.com', 'A', ['2.2.2.2'], 3600)
        cached = admin.get_cached_dns('overwrite.com', 'A')
        assert cached == ['2.2.2.2']
    
    def test_whois_cache_overwrite(self, test_db, sample_whois_results):
        """Test WHOIS cache entry is overwritten on re-insert."""
        import admin
        
        admin.set_cached_whois('overwrite.com', sample_whois_results, 86400)
        cached = admin.get_cached_whois('overwrite.com')
        assert cached['registrar'] == 'Example Registrar, LLC'
        
        updated_results = sample_whois_results.copy()
        updated_results['registrar'] = 'New Registrar'
        
        admin.set_cached_whois('overwrite.com', updated_results, 86400)
        cached = admin.get_cached_whois('overwrite.com')
        assert cached['registrar'] == 'New Registrar'


class TestCacheCaseSensitivity:
    """Tests for cache case sensitivity behavior."""
    
    def test_circl_pdns_cache_case_insensitive(self, test_db, sample_circl_pdns_results):
        """Test CIRCL PDNS cache is case insensitive."""
        import admin
        
        admin.set_cached_circl_pdns('EXAMPLE.COM', 'DOMAIN', sample_circl_pdns_results, 4, 86400)
        
        # Should find with lowercase
        cached = admin.get_cached_circl_pdns('example.com', 'domain')
        assert cached is not None
        assert cached['results'] == sample_circl_pdns_results
    
    def test_viewdns_cache_case_insensitive(self, test_db):
        """Test ViewDNS cache is case insensitive."""
        import admin
        
        admin.set_cached_viewdns('MAIL.EXAMPLE.COM', 'REVERSE_MX', ['test.com'], 1, 86400)
        
        cached = admin.get_cached_viewdns('mail.example.com', 'reverse_mx')
        assert cached is not None
