"""
Tests for DNS resolution functions.

Tests cover:
- 3.1 Record Type Parsing (A, AAAA, CNAME, MX, NS, TXT, SOA, PTR)
- 3.2 Error Handling (NXDOMAIN, NoAnswer, Timeout, exceptions)
- 3.3 Caching Behavior (hits, misses, bypass, expiration)
"""

import json
import time
from unittest.mock import Mock, patch, MagicMock
import pytest
import dns.resolver
import dns.exception


# ============================================
# Mock DNS Response Helpers
# ============================================

class MockRdataA:
    """Mock A record response."""
    def __init__(self, ip):
        self.ip = ip
    
    def __str__(self):
        return self.ip


class MockRdataAAAA:
    """Mock AAAA record response."""
    def __init__(self, ip):
        self.ip = ip
    
    def __str__(self):
        return self.ip


class MockRdataCNAME:
    """Mock CNAME record response."""
    def __init__(self, target):
        self.target = target


class MockRdataMX:
    """Mock MX record response."""
    def __init__(self, exchange, preference=10):
        self.exchange = exchange
        self.preference = preference


class MockRdataNS:
    """Mock NS record response."""
    def __init__(self, target):
        self.target = target


class MockRdataTXT:
    """Mock TXT record response."""
    def __init__(self, *strings):
        self.strings = [s.encode() if isinstance(s, str) else s for s in strings]


class MockRdataSOA:
    """Mock SOA record response."""
    def __init__(self, mname, rname='admin.example.com.'):
        self.mname = mname
        self.rname = rname


class MockRdataPTR:
    """Mock PTR record response."""
    def __init__(self, target):
        self.target = target


class MockAnswer:
    """Mock DNS answer that can be iterated."""
    def __init__(self, records):
        self.records = records
    
    def __iter__(self):
        return iter(self.records)


@pytest.fixture
def mock_dns_settings(test_db):
    """Set up DNS settings in test database."""
    import admin
    
    conn = admin.get_db()
    cursor = conn.cursor()
    cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('dns_servers', '8.8.8.8')")
    cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('dns_cache_ttl', '3600')")
    cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('dns_timeout', '5')")
    conn.commit()
    conn.close()
    
    return {'servers': '8.8.8.8', 'cache_ttl': 3600, 'timeout': 5, 'max_domains': 100}


# ============================================
# 3.1 Record Type Parsing Tests
# ============================================

class TestDNSRecordTypeParsing:
    """Tests for parsing different DNS record types."""
    
    def test_resolve_dns_a_record(self, test_db, mock_dns_settings):
        """Test parsing A record responses."""
        from routes import dns as dns_module
        import dns.resolver
        
        with patch.object(dns.resolver, 'Resolver') as MockResolver:
            mock_instance = Mock()
            MockResolver.return_value = mock_instance
            mock_instance.resolve.return_value = MockAnswer([
                MockRdataA('93.184.216.34'),
                MockRdataA('93.184.216.35')
            ])
            
            with patch.object(dns_module, 'get_dns_settings', return_value=mock_dns_settings):
                results = dns_module.resolve_dns('example.com', record_types=['A'], use_cache=False)
            
            assert 'A' in results
            assert results['A'] == ['93.184.216.34', '93.184.216.35']
    
    def test_resolve_dns_aaaa_record(self, test_db, mock_dns_settings):
        """Test parsing AAAA record responses."""
        from routes import dns as dns_module
        import dns.resolver
        
        with patch.object(dns.resolver, 'Resolver') as MockResolver:
            mock_instance = Mock()
            MockResolver.return_value = mock_instance
            mock_instance.resolve.return_value = MockAnswer([
                MockRdataAAAA('2606:2800:220:1:248:1893:25c8:1946')
            ])
            
            with patch.object(dns_module, 'get_dns_settings', return_value=mock_dns_settings):
                results = dns_module.resolve_dns('example.com', record_types=['AAAA'], use_cache=False)
            
            assert 'AAAA' in results
            assert results['AAAA'] == ['2606:2800:220:1:248:1893:25c8:1946']
    
    def test_resolve_dns_cname_record(self, test_db, mock_dns_settings):
        """Test parsing CNAME record responses with trailing dot removal."""
        from routes import dns as dns_module
        import dns.resolver
        
        with patch.object(dns.resolver, 'Resolver') as MockResolver:
            mock_instance = Mock()
            MockResolver.return_value = mock_instance
            mock_instance.resolve.return_value = MockAnswer([
                MockRdataCNAME('cdn.example.com.')
            ])
            
            with patch.object(dns_module, 'get_dns_settings', return_value=mock_dns_settings):
                results = dns_module.resolve_dns('www.example.com', record_types=['CNAME'], use_cache=False)
            
            assert 'CNAME' in results
            assert results['CNAME'] == ['cdn.example.com']  # Trailing dot removed
    
    def test_resolve_dns_mx_record(self, test_db, mock_dns_settings):
        """Test parsing MX record responses with trailing dot removal."""
        from routes import dns as dns_module
        import dns.resolver
        
        with patch.object(dns.resolver, 'Resolver') as MockResolver:
            mock_instance = Mock()
            MockResolver.return_value = mock_instance
            mock_instance.resolve.return_value = MockAnswer([
                MockRdataMX('mail1.example.com.', 10),
                MockRdataMX('mail2.example.com.', 20)
            ])
            
            with patch.object(dns_module, 'get_dns_settings', return_value=mock_dns_settings):
                results = dns_module.resolve_dns('example.com', record_types=['MX'], use_cache=False)
            
            assert 'MX' in results
            assert results['MX'] == ['mail1.example.com', 'mail2.example.com']
    
    def test_resolve_dns_ns_record(self, test_db, mock_dns_settings):
        """Test parsing NS record responses."""
        from routes import dns as dns_module
        import dns.resolver
        
        with patch.object(dns.resolver, 'Resolver') as MockResolver:
            mock_instance = Mock()
            MockResolver.return_value = mock_instance
            mock_instance.resolve.return_value = MockAnswer([
                MockRdataNS('ns1.example.com.'),
                MockRdataNS('ns2.example.com.')
            ])
            
            with patch.object(dns_module, 'get_dns_settings', return_value=mock_dns_settings):
                results = dns_module.resolve_dns('example.com', record_types=['NS'], use_cache=False)
            
            assert 'NS' in results
            assert results['NS'] == ['ns1.example.com', 'ns2.example.com']
    
    def test_resolve_dns_txt_record(self, test_db, mock_dns_settings):
        """Test parsing TXT record responses with concatenation."""
        from routes import dns as dns_module
        import dns.resolver
        
        with patch.object(dns.resolver, 'Resolver') as MockResolver:
            mock_instance = Mock()
            MockResolver.return_value = mock_instance
            mock_instance.resolve.return_value = MockAnswer([
                MockRdataTXT('v=spf1 include:_spf.google.com ~all')
            ])
            
            with patch.object(dns_module, 'get_dns_settings', return_value=mock_dns_settings):
                results = dns_module.resolve_dns('example.com', record_types=['TXT'], use_cache=False)
            
            assert 'TXT' in results
            assert results['TXT'] == ['v=spf1 include:_spf.google.com ~all']
    
    def test_resolve_dns_txt_concatenates_parts(self, test_db, mock_dns_settings):
        """Test TXT records with multiple string parts are concatenated."""
        from routes import dns as dns_module
        import dns.resolver
        
        with patch.object(dns.resolver, 'Resolver') as MockResolver:
            mock_instance = Mock()
            MockResolver.return_value = mock_instance
            # TXT records can have multiple strings that should be joined
            mock_instance.resolve.return_value = MockAnswer([
                MockRdataTXT('part1', 'part2', 'part3')
            ])
            
            with patch.object(dns_module, 'get_dns_settings', return_value=mock_dns_settings):
                results = dns_module.resolve_dns('example.com', record_types=['TXT'], use_cache=False)
            
            assert 'TXT' in results
            assert results['TXT'] == ['part1part2part3']
    
    def test_resolve_dns_soa_record(self, test_db, mock_dns_settings):
        """Test parsing SOA record responses (extracts mname)."""
        from routes import dns as dns_module
        import dns.resolver
        
        with patch.object(dns.resolver, 'Resolver') as MockResolver:
            mock_instance = Mock()
            MockResolver.return_value = mock_instance
            mock_instance.resolve.return_value = MockAnswer([
                MockRdataSOA('ns1.example.com.')
            ])
            
            with patch.object(dns_module, 'get_dns_settings', return_value=mock_dns_settings):
                results = dns_module.resolve_dns('example.com', record_types=['SOA'], use_cache=False)
            
            assert 'SOA' in results
            assert results['SOA'] == ['ns1.example.com']
    
    def test_resolve_dns_multiple_record_types(self, test_db, mock_dns_settings):
        """Test resolving multiple record types in one call."""
        from routes import dns as dns_module
        import dns.resolver
        
        def mock_resolve_side_effect(query, rtype):
            if rtype == 'A':
                return MockAnswer([MockRdataA('93.184.216.34')])
            elif rtype == 'MX':
                return MockAnswer([MockRdataMX('mail.example.com.')])
            elif rtype == 'NS':
                return MockAnswer([MockRdataNS('ns1.example.com.')])
            return MockAnswer([])
        
        with patch.object(dns.resolver, 'Resolver') as MockResolver:
            mock_instance = Mock()
            MockResolver.return_value = mock_instance
            mock_instance.resolve.side_effect = mock_resolve_side_effect
            
            with patch.object(dns_module, 'get_dns_settings', return_value=mock_dns_settings):
                results = dns_module.resolve_dns('example.com', record_types=['A', 'MX', 'NS'], use_cache=False)
            
            assert results['A'] == ['93.184.216.34']
            assert results['MX'] == ['mail.example.com']
            assert results['NS'] == ['ns1.example.com']
    
    def test_resolve_dns_default_record_types(self, test_db, mock_dns_settings):
        """Test that default record types are used when none specified."""
        from routes import dns as dns_module
        import dns.resolver
        
        with patch.object(dns.resolver, 'Resolver') as MockResolver:
            mock_instance = Mock()
            MockResolver.return_value = mock_instance
            mock_instance.resolve.return_value = MockAnswer([])
            
            with patch.object(dns_module, 'get_dns_settings', return_value=mock_dns_settings):
                results = dns_module.resolve_dns('example.com', use_cache=False)
            
            # Should have attempted all default types
            expected_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA']
            for rtype in expected_types:
                assert rtype in results
    
    def test_reverse_dns_valid_ip(self, test_db, mock_dns_settings):
        """Test reverse DNS lookup for valid IP."""
        from routes import dns as dns_module
        import dns.resolver
        
        with patch.object(dns.resolver, 'Resolver') as MockResolver:
            mock_instance = Mock()
            MockResolver.return_value = mock_instance
            mock_instance.resolve.return_value = MockAnswer([
                MockRdataPTR('server1.example.com.')
            ])
            
            with patch.object(dns_module, 'get_dns_settings', return_value=mock_dns_settings):
                with patch('dns.reversename.from_address') as mock_from_addr:
                    mock_from_addr.return_value = '34.216.184.93.in-addr.arpa.'
                    results = dns_module.reverse_dns('93.184.216.34')
            
            assert results == ['server1.example.com']
    
    def test_reverse_dns_returns_list(self, test_db, mock_dns_settings):
        """Test reverse DNS returns list of hostnames."""
        from routes import dns as dns_module
        import dns.resolver
        
        with patch.object(dns.resolver, 'Resolver') as MockResolver:
            mock_instance = Mock()
            MockResolver.return_value = mock_instance
            mock_instance.resolve.return_value = MockAnswer([
                MockRdataPTR('host1.example.com.'),
                MockRdataPTR('host2.example.com.')
            ])
            
            with patch.object(dns_module, 'get_dns_settings', return_value=mock_dns_settings):
                with patch('dns.reversename.from_address') as mock_from_addr:
                    mock_from_addr.return_value = '1.0.168.192.in-addr.arpa.'
                    results = dns_module.reverse_dns('192.168.0.1')
            
            assert len(results) == 2
            assert 'host1.example.com' in results
            assert 'host2.example.com' in results


# ============================================
# 3.2 Error Handling Tests
# ============================================

class TestDNSErrorHandling:
    """Tests for DNS resolution error handling."""
    
    def test_resolve_dns_nxdomain_returns_empty(self, test_db, mock_dns_settings):
        """Test NXDOMAIN (non-existent domain) returns empty list."""
        from routes import dns as dns_module
        import dns.resolver
        
        with patch.object(dns.resolver, 'Resolver') as MockResolver:
            mock_instance = Mock()
            MockResolver.return_value = mock_instance
            mock_instance.resolve.side_effect = dns.resolver.NXDOMAIN()
            
            with patch.object(dns_module, 'get_dns_settings', return_value=mock_dns_settings):
                results = dns_module.resolve_dns('nonexistent.invalid', record_types=['A'], use_cache=False)
            
            assert results['A'] == []
    
    def test_resolve_dns_no_answer_returns_empty(self, test_db, mock_dns_settings):
        """Test NoAnswer (domain exists but no record) returns empty list."""
        from routes import dns as dns_module
        import dns.resolver
        
        with patch.object(dns.resolver, 'Resolver') as MockResolver:
            mock_instance = Mock()
            MockResolver.return_value = mock_instance
            mock_instance.resolve.side_effect = dns.resolver.NoAnswer()
            
            with patch.object(dns_module, 'get_dns_settings', return_value=mock_dns_settings):
                results = dns_module.resolve_dns('example.com', record_types=['AAAA'], use_cache=False)
            
            assert results['AAAA'] == []
    
    def test_resolve_dns_timeout_returns_error_dict(self, test_db, mock_dns_settings):
        """Test Timeout returns error dict (not empty list)."""
        from routes import dns as dns_module
        import dns.resolver
        import dns.exception
        
        with patch.object(dns.resolver, 'Resolver') as MockResolver:
            mock_instance = Mock()
            MockResolver.return_value = mock_instance
            mock_instance.resolve.side_effect = dns.exception.Timeout()
            
            with patch.object(dns_module, 'get_dns_settings', return_value=mock_dns_settings):
                results = dns_module.resolve_dns('slow.example.com', record_types=['A'], use_cache=False)
            
            assert isinstance(results['A'], dict)
            assert results['A']['error'] == 'timeout'
    
    def test_resolve_dns_generic_exception_returns_error(self, test_db, mock_dns_settings):
        """Test generic exceptions are captured in error dict."""
        from routes import dns as dns_module
        import dns.resolver
        
        with patch.object(dns.resolver, 'Resolver') as MockResolver:
            mock_instance = Mock()
            MockResolver.return_value = mock_instance
            mock_instance.resolve.side_effect = Exception('Connection refused')
            
            with patch.object(dns_module, 'get_dns_settings', return_value=mock_dns_settings):
                results = dns_module.resolve_dns('example.com', record_types=['A'], use_cache=False)
            
            assert isinstance(results['A'], dict)
            assert 'error' in results['A']
            assert results['A']['error'] == 'lookup failed'  # raw exception text is not returned
    
    def test_reverse_dns_invalid_ip_returns_empty(self, test_db, mock_dns_settings):
        """Test reverse DNS with invalid IP returns empty list."""
        from routes import dns as dns_module
        import dns.resolver
        
        with patch.object(dns.resolver, 'Resolver') as MockResolver:
            mock_instance = Mock()
            MockResolver.return_value = mock_instance
            
            with patch.object(dns_module, 'get_dns_settings', return_value=mock_dns_settings):
                with patch('dns.reversename.from_address') as mock_from_addr:
                    mock_from_addr.side_effect = Exception('Invalid IP address')
                    results = dns_module.reverse_dns('not-an-ip')
        
        assert results == []
    
    def test_reverse_dns_no_ptr_record(self, test_db, mock_dns_settings):
        """Test reverse DNS returns empty when no PTR record exists."""
        from routes import dns as dns_module
        import dns.resolver
        
        with patch.object(dns.resolver, 'Resolver') as MockResolver:
            mock_instance = Mock()
            MockResolver.return_value = mock_instance
            mock_instance.resolve.side_effect = dns.resolver.NXDOMAIN()
            
            with patch.object(dns_module, 'get_dns_settings', return_value=mock_dns_settings):
                with patch('dns.reversename.from_address') as mock_from_addr:
                    mock_from_addr.return_value = '1.2.3.4.in-addr.arpa.'
                    results = dns_module.reverse_dns('4.3.2.1')
        
        assert results == []
    
    def test_resolve_dns_mixed_success_and_errors(self, test_db, mock_dns_settings):
        """Test that some record types can succeed while others fail."""
        from routes import dns as dns_module
        import dns.resolver
        import dns.exception
        
        def mock_resolve_side_effect(query, rtype):
            if rtype == 'A':
                return MockAnswer([MockRdataA('93.184.216.34')])
            elif rtype == 'AAAA':
                raise dns.resolver.NoAnswer()
            elif rtype == 'MX':
                raise dns.exception.Timeout()
            return MockAnswer([])
        
        with patch.object(dns.resolver, 'Resolver') as MockResolver:
            mock_instance = Mock()
            MockResolver.return_value = mock_instance
            mock_instance.resolve.side_effect = mock_resolve_side_effect
        
            with patch.object(dns_module, 'get_dns_settings', return_value=mock_dns_settings):
                results = dns_module.resolve_dns('example.com', record_types=['A', 'AAAA', 'MX'], use_cache=False)
        
        assert results['A'] == ['93.184.216.34']  # Success
        assert results['AAAA'] == []  # NoAnswer
        assert results['MX'] == {'error': 'timeout'}  # Timeout
    
    def test_resolve_dns_empty_query(self, test_db, mock_dns_settings):
        """Test resolving with empty query string."""
        from routes import dns as dns_module
        import dns.resolver
        
        with patch.object(dns.resolver, 'Resolver') as MockResolver:
            mock_instance = Mock()
            MockResolver.return_value = mock_instance
            mock_instance.resolve.side_effect = Exception('Empty query')
            
            with patch.object(dns_module, 'get_dns_settings', return_value=mock_dns_settings):
                results = dns_module.resolve_dns('', record_types=['A'], use_cache=False)
            
            assert 'error' in results['A']


# ============================================
# 3.3 Caching Behavior Tests
# ============================================

class TestDNSCachingBehavior:
    """Tests for DNS caching behavior."""
    
    def test_resolve_dns_uses_cache_when_available(self, test_db, mock_dns_settings):
        """Test that cached results are returned without making DNS query."""
        from routes import dns as dns_module
        import admin
        import dns.resolver
        
        # Pre-populate cache
        admin.set_cached_dns('cached.example.com', 'A', ['1.2.3.4'], 3600)
        
        with patch.object(dns.resolver, 'Resolver') as MockResolver:
            mock_instance = Mock()
            MockResolver.return_value = mock_instance
            
            with patch.object(dns_module, 'get_dns_settings', return_value=mock_dns_settings):
                results = dns_module.resolve_dns('cached.example.com', record_types=['A'], use_cache=True)
            
            # Resolver's resolve method should NOT have been called
            mock_instance.resolve.assert_not_called()
        
        assert results['A'] == ['1.2.3.4']
    
    def test_resolve_dns_bypasses_cache_when_disabled(self, test_db, mock_dns_settings):
        """Test that cache is bypassed when use_cache=False."""
        from routes import dns as dns_module
        import admin
        import dns.resolver
        
        # Pre-populate cache with stale data
        admin.set_cached_dns('example.com', 'A', ['old.ip.addr.1'], 3600)
        
        with patch.object(dns.resolver, 'Resolver') as MockResolver:
            mock_instance = Mock()
            MockResolver.return_value = mock_instance
            mock_instance.resolve.return_value = MockAnswer([MockRdataA('new.ip.addr.2')])
            
            with patch.object(dns_module, 'get_dns_settings', return_value=mock_dns_settings):
                results = dns_module.resolve_dns('example.com', record_types=['A'], use_cache=False)
            
            # Resolver SHOULD have been called despite cache
            mock_instance.resolve.assert_called_once()
        
        assert results['A'] == ['new.ip.addr.2']
    
    def test_resolve_dns_caches_successful_results(self, test_db, mock_dns_settings):
        """Test that successful DNS results are cached."""
        from routes import dns as dns_module
        import admin
        import dns.resolver
        
        with patch.object(dns.resolver, 'Resolver') as MockResolver:
            mock_instance = Mock()
            MockResolver.return_value = mock_instance
            mock_instance.resolve.return_value = MockAnswer([MockRdataA('93.184.216.34')])
            
            with patch.object(dns_module, 'get_dns_settings', return_value=mock_dns_settings):
                dns_module.resolve_dns('newquery.example.com', record_types=['A'], use_cache=False)
        
        # Check cache was populated
        cached = admin.get_cached_dns('newquery.example.com', 'A')
        assert cached is not None
        assert cached == ['93.184.216.34']
    
    def test_resolve_dns_caches_empty_results(self, test_db, mock_dns_settings):
        """Test that NXDOMAIN/NoAnswer results are cached as empty lists."""
        from routes import dns as dns_module
        import admin
        import dns.resolver
        
        with patch.object(dns.resolver, 'Resolver') as MockResolver:
            mock_instance = Mock()
            MockResolver.return_value = mock_instance
            mock_instance.resolve.side_effect = dns.resolver.NXDOMAIN()
            
            with patch.object(dns_module, 'get_dns_settings', return_value=mock_dns_settings):
                dns_module.resolve_dns('nxdomain.example.com', record_types=['A'], use_cache=False)
        
        # Empty results should be cached
        cached = admin.get_cached_dns('nxdomain.example.com', 'A')
        assert cached == []
    
    def test_get_cached_dns_returns_none_when_expired(self, test_db):
        """Test that expired cache entries return None."""
        import admin
        
        # Set cache with 1 second TTL
        admin.set_cached_dns('expired.example.com', 'A', ['1.2.3.4'], 2)
        
        # Verify it's there
        assert admin.get_cached_dns('expired.example.com', 'A') is not None
        
        # Wait for expiration
        time.sleep(2.5)
        
        # Should now return None
        cached = admin.get_cached_dns('expired.example.com', 'A')
        assert cached is None
    
    def test_get_cached_dns_returns_none_when_missing(self, test_db):
        """Test that missing cache entries return None."""
        import admin
        
        cached = admin.get_cached_dns('never-cached.example.com', 'A')
        assert cached is None
    
    def test_set_cached_dns_updates_existing(self, test_db):
        """Test that setting cache for existing entry updates it."""
        import admin
        
        # Set initial cache
        admin.set_cached_dns('example.com', 'A', ['1.1.1.1'], 3600)
        
        # Update cache
        admin.set_cached_dns('example.com', 'A', ['2.2.2.2'], 3600)
        
        # Should have new value
        cached = admin.get_cached_dns('example.com', 'A')
        assert cached == ['2.2.2.2']
    
    def test_clear_expired_dns_cache_removes_old_entries(self, test_db):
        """Test that clear_expired_dns_cache removes expired entries."""
        import admin
        
        # Set cache with 1 second TTL
        admin.set_cached_dns('toexpire.example.com', 'A', ['1.2.3.4'], 2)
        
        # Wait for expiration (SQLite CURRENT_TIMESTAMP has 1-second resolution)
        time.sleep(2.5)
        
        # Clear expired
        admin.clear_expired_dns_cache()
        
        # Direct database check - entry should be gone
        conn = admin.get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM dns_cache WHERE query = ?', ('toexpire.example.com',))
        row = cursor.fetchone()
        conn.close()
        
        assert row is None
    
    def test_clear_expired_dns_cache_keeps_valid_entries(self, test_db):
        """Test that clear_expired_dns_cache keeps non-expired entries."""
        import admin
        
        # Set cache with long TTL
        admin.set_cached_dns('valid.example.com', 'A', ['1.2.3.4'], 3600)
        
        # Clear expired (shouldn't affect this one)
        admin.clear_expired_dns_cache()
        
        # Should still be there
        cached = admin.get_cached_dns('valid.example.com', 'A')
        assert cached == ['1.2.3.4']
    
    def test_dns_cache_different_record_types_independent(self, test_db, mock_dns_settings):
        """Test that different record types are cached independently."""
        from routes import dns as dns_module
        import admin
        
        # Cache A record
        admin.set_cached_dns('example.com', 'A', ['1.2.3.4'], 3600)
        
        # MX should not be cached
        cached_mx = admin.get_cached_dns('example.com', 'MX')
        assert cached_mx is None
        
        # A should be cached
        cached_a = admin.get_cached_dns('example.com', 'A')
        assert cached_a == ['1.2.3.4']
    
    def test_reverse_dns_uses_cache(self, test_db, mock_dns_settings):
        """Test that reverse DNS also uses caching."""
        from routes import dns as dns_module
        import admin
        import dns.resolver
        
        # Pre-populate PTR cache
        admin.set_cached_dns('192.168.1.1', 'PTR', ['host.example.com'], 3600)
        
        with patch.object(dns.resolver, 'Resolver') as MockResolver:
            mock_instance = Mock()
            MockResolver.return_value = mock_instance
            
            with patch.object(dns_module, 'get_dns_settings', return_value=mock_dns_settings):
                results = dns_module.reverse_dns('192.168.1.1')
            
            # Resolver's resolve should NOT have been called
            mock_instance.resolve.assert_not_called()
        
        assert results == ['host.example.com']
    
    def test_reverse_dns_caches_results(self, test_db, mock_dns_settings):
        """Test that reverse DNS results are cached."""
        from routes import dns as dns_module
        import admin
        import dns.resolver
        
        with patch.object(dns.resolver, 'Resolver') as MockResolver:
            mock_instance = Mock()
            MockResolver.return_value = mock_instance
            mock_instance.resolve.return_value = MockAnswer([MockRdataPTR('server.example.com.')])
            
            with patch.object(dns_module, 'get_dns_settings', return_value=mock_dns_settings):
                with patch('dns.reversename.from_address') as mock_from_addr:
                    mock_from_addr.return_value = '1.1.168.192.in-addr.arpa.'
                    dns_module.reverse_dns('192.168.1.1')
        
        # Check cache was populated
        cached = admin.get_cached_dns('192.168.1.1', 'PTR')
        assert cached == ['server.example.com']
    
    def test_reverse_dns_does_not_cache_failures(self, test_db, mock_dns_settings):
        """A failed reverse lookup (timeout, resolver error) must NOT be cached as 'no PTR'."""
        from routes import dns as dns_module
        import admin
        import dns.resolver
        
        with patch.object(dns.resolver, 'Resolver') as MockResolver:
            mock_instance = Mock()
            MockResolver.return_value = mock_instance
            mock_instance.resolve.side_effect = Exception('No PTR')
            
            with patch.object(dns_module, 'get_dns_settings', return_value=mock_dns_settings):
                with patch('dns.reversename.from_address') as mock_from_addr:
                    mock_from_addr.return_value = '1.2.3.10.in-addr.arpa.'
                    dns_module.reverse_dns('10.3.2.1')
        
        cached = admin.get_cached_dns('10.3.2.1', 'PTR')
        assert cached is None
    
    def test_dns_cache_case_insensitive(self, test_db):
        """Test that DNS cache queries are case-insensitive."""
        import admin
        
        # Cache with uppercase
        admin.set_cached_dns('EXAMPLE.COM', 'A', ['1.2.3.4'], 3600)
        
        # Retrieve with lowercase
        cached = admin.get_cached_dns('example.com', 'A')
        assert cached == ['1.2.3.4']
        
        # Retrieve with mixed case
        cached = admin.get_cached_dns('Example.Com', 'A')
        assert cached == ['1.2.3.4']


# ============================================
# DNS Settings Tests
# ============================================

class TestDNSSettings:
    """Tests for DNS settings retrieval."""
    
    def test_get_dns_settings_defaults(self, test_db):
        """Test that get_dns_settings returns defaults when not configured."""
        import admin
        
        settings = admin.get_dns_settings()
        
        assert 'servers' in settings
        assert 'cache_ttl' in settings
        assert 'timeout' in settings
        assert 'max_domains' in settings
        
        # Check reasonable defaults
        assert settings['cache_ttl'] > 0
        assert settings['timeout'] > 0
        assert settings['max_domains'] > 0
    
    def test_get_dns_settings_custom_values(self, test_db):
        """Test that custom DNS settings are retrieved."""
        import admin
        
        # Set custom values
        conn = admin.get_db()
        cursor = conn.cursor()
        cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('dns_servers', '1.1.1.1,9.9.9.9')")
        cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('dns_cache_ttl', '7200')")
        cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('dns_timeout', '10')")
        cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('dns_max_domains', '200')")
        conn.commit()
        conn.close()
        
        settings = admin.get_dns_settings()
        
        assert settings['servers'] == '1.1.1.1,9.9.9.9'
        assert settings['cache_ttl'] == 7200
        assert settings['timeout'] == 10
        assert settings['max_domains'] == 200
    
    def test_resolve_dns_uses_configured_timeout(self, test_db):
        """Test that resolve_dns uses configured timeout value."""
        from routes import dns as dns_module
        
        # Set custom timeout
        import admin
        conn = admin.get_db()
        cursor = conn.cursor()
        cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('dns_timeout', '15')")
        conn.commit()
        conn.close()
        
        with patch.object(dns.resolver, 'Resolver') as MockResolver:
            mock_instance = Mock()
            MockResolver.return_value = mock_instance
            mock_instance.resolve.return_value = MockAnswer([MockRdataA('1.2.3.4')])
            
            dns_module.resolve_dns('example.com', record_types=['A'], use_cache=False)
            
            # Check timeout was set
            assert mock_instance.timeout == 15
            assert mock_instance.lifetime == 15
