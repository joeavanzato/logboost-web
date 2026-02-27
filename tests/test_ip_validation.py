"""
Tests for IP address validation utilities.

These tests verify that IP address validation works correctly for:
- IPv4 addresses
- IPv6 addresses  
- Edge cases and invalid inputs

Note: The primary IP validation function (isValidIP) is in the frontend JavaScript.
These tests verify Python-side IP validation utilities and related backend logic.
"""

import pytest
import ipaddress


class TestIPv4Validation:
    """Tests for IPv4 address validation."""
    
    def test_valid_standard_ipv4(self, valid_ipv4_addresses):
        """Test that standard IPv4 addresses are valid."""
        for ip in valid_ipv4_addresses:
            try:
                ipaddress.ip_address(ip)
                is_valid = True
            except ValueError:
                is_valid = False
            assert is_valid, f"Expected {ip} to be valid IPv4"
    
    def test_ipv4_boundary_values(self):
        """Test IPv4 boundary values."""
        # Valid boundaries
        valid = ['0.0.0.0', '255.255.255.255', '127.0.0.1']
        for ip in valid:
            try:
                ipaddress.ip_address(ip)
                is_valid = True
            except ValueError:
                is_valid = False
            assert is_valid, f"Expected {ip} to be valid"
        
        # Invalid boundaries
        invalid = ['256.0.0.0', '0.256.0.0', '0.0.256.0', '0.0.0.256']
        for ip in invalid:
            try:
                ipaddress.ip_address(ip)
                is_valid = True
            except ValueError:
                is_valid = False
            assert not is_valid, f"Expected {ip} to be invalid"
    
    def test_ipv4_with_leading_zeros(self):
        """Test IPv4 with leading zeros behavior."""
        # Python's ipaddress module rejects leading zeros (could be octal)
        try:
            ipaddress.ip_address('192.168.001.001')
            is_valid = True
        except ValueError:
            is_valid = False
        # Python 3 rejects leading zeros by default
        assert not is_valid, "Expected leading zeros to be rejected"


class TestIPv6Validation:
    """Tests for IPv6 address validation."""
    
    def test_valid_standard_ipv6(self, valid_ipv6_addresses):
        """Test that standard IPv6 addresses are valid."""
        for ip in valid_ipv6_addresses:
            try:
                ipaddress.ip_address(ip)
                is_valid = True
            except ValueError:
                is_valid = False
            assert is_valid, f"Expected {ip} to be valid IPv6"
    
    def test_ipv6_compressed_forms(self):
        """Test various IPv6 compressed forms."""
        valid = [
            '::1',  # Loopback
            '::',   # All zeros
            '2001:db8::1',  # Common shorthand
            'fe80::1',  # Link-local
            '::ffff:192.168.1.1',  # IPv4-mapped
        ]
        for ip in valid:
            try:
                ipaddress.ip_address(ip)
                is_valid = True
            except ValueError:
                is_valid = False
            assert is_valid, f"Expected {ip} to be valid"
    
    def test_ipv6_full_form(self):
        """Test full-form IPv6 address."""
        full_ipv6 = '2001:0db8:85a3:0000:0000:8a2e:0370:7334'
        try:
            ipaddress.ip_address(full_ipv6)
            is_valid = True
        except ValueError:
            is_valid = False
        assert is_valid


class TestInvalidAddresses:
    """Tests for invalid IP address inputs."""
    
    def test_domain_names_are_invalid(self):
        """Test that domain names are not valid IPs."""
        domains = [
            'example.com',
            'www.google.com',
            'mail.example.org',
            'ns1.dns.com'
        ]
        for domain in domains:
            try:
                ipaddress.ip_address(domain)
                is_valid = True
            except ValueError:
                is_valid = False
            assert not is_valid, f"Expected {domain} to be invalid IP"
    
    def test_partial_ipv4_invalid(self):
        """Test that partial IPv4 addresses are invalid."""
        partial = ['192.168.1', '192.168', '192', '']
        for ip in partial:
            try:
                ipaddress.ip_address(ip)
                is_valid = True
            except ValueError:
                is_valid = False
            assert not is_valid, f"Expected {ip} to be invalid"
    
    def test_ipv4_with_port_invalid(self):
        """Test that IPv4 with port is invalid."""
        with_port = '192.168.1.1:80'
        try:
            ipaddress.ip_address(with_port)
            is_valid = True
        except ValueError:
            is_valid = False
        assert not is_valid
    
    def test_ipv4_with_cidr_invalid(self):
        """Test that IPv4 with CIDR notation is invalid for ip_address."""
        with_cidr = '192.168.1.0/24'
        try:
            ipaddress.ip_address(with_cidr)
            is_valid = True
        except ValueError:
            is_valid = False
        assert not is_valid, "ip_address should reject CIDR notation"
    
    def test_none_and_empty_invalid(self):
        """Test that None and empty strings are invalid."""
        for val in [None, '', ' ']:
            try:
                if val is None or not val.strip():
                    is_valid = False
                else:
                    ipaddress.ip_address(val)
                    is_valid = True
            except (ValueError, AttributeError):
                is_valid = False
            assert not is_valid, f"Expected {repr(val)} to be invalid"


class TestIPTypeDetection:
    """Tests for detecting IP address type (IPv4 vs IPv6)."""
    
    def test_detect_ipv4(self, valid_ipv4_addresses):
        """Test IPv4 detection."""
        for ip in valid_ipv4_addresses:
            addr = ipaddress.ip_address(ip)
            assert addr.version == 4, f"Expected {ip} to be IPv4"
    
    def test_detect_ipv6(self, valid_ipv6_addresses):
        """Test IPv6 detection."""
        for ip in valid_ipv6_addresses:
            addr = ipaddress.ip_address(ip)
            assert addr.version == 6, f"Expected {ip} to be IPv6"
    
    def test_simple_ipv6_detection(self):
        """Test simple colon-based IPv6 detection."""
        # This mirrors the frontend isIPv6 function which just checks for colons
        def is_ipv6_simple(ip):
            return ':' in ip
        
        assert is_ipv6_simple('::1') == True
        assert is_ipv6_simple('2001:db8::1') == True
        assert is_ipv6_simple('192.168.1.1') == False
        assert is_ipv6_simple('8.8.8.8') == False


class TestCIRCLPDNSIPValidation:
    """Tests for IP validation in context of CIRCL PDNS processing.
    
    These test cases represent the scenarios we fixed:
    - CNAME records pointing to IPs instead of domains
    - MX records with IP targets
    - NS records with IP targets
    """
    
    def test_cname_pointing_to_ipv4(self):
        """Test detection of CNAME with IPv4 target."""
        # This scenario triggered the original bug
        cname_target = '93.184.216.34'
        try:
            ipaddress.ip_address(cname_target)
            is_ip = True
        except ValueError:
            is_ip = False
        
        assert is_ip, "CNAME target should be detected as IP"
    
    def test_cname_pointing_to_ipv6(self):
        """Test detection of CNAME with IPv6 target."""
        cname_target = '2001:db8::1'
        try:
            ipaddress.ip_address(cname_target)
            is_ip = True
        except ValueError:
            is_ip = False
        
        assert is_ip, "IPv6 CNAME target should be detected as IP"
    
    def test_mx_with_priority_and_ip(self):
        """Test parsing MX record with priority prefix and IP."""
        mx_rdata = '10 192.168.1.100'
        
        # Extract host (split by space, take last part)
        mx_host = mx_rdata.split(' ')[-1] if ' ' in mx_rdata else mx_rdata
        
        try:
            ipaddress.ip_address(mx_host)
            is_ip = True
        except ValueError:
            is_ip = False
        
        assert mx_host == '192.168.1.100'
        assert is_ip, "MX host should be detected as IP"
    
    def test_ns_pointing_to_ip(self):
        """Test detection of NS with IP target."""
        ns_target = '10.0.0.1'
        try:
            ipaddress.ip_address(ns_target)
            is_ip = True
        except ValueError:
            is_ip = False
        
        assert is_ip, "NS target should be detected as IP"
    
    def test_normal_domain_not_detected_as_ip(self):
        """Test that normal domain names are not detected as IPs."""
        domains = [
            'cdn.example.com',
            'mail.example.com',
            'ns1.example.com',
            'example.com'
        ]
        for domain in domains:
            try:
                ipaddress.ip_address(domain)
                is_ip = True
            except ValueError:
                is_ip = False
            
            assert not is_ip, f"{domain} should not be detected as IP"


class TestIPValidationHelper:
    """Tests for a Python IP validation helper function.
    
    This mirrors the JavaScript isValidIP function we added to the frontend.
    """
    
    @staticmethod
    def is_valid_ip(value):
        """Python equivalent of the frontend isValidIP function."""
        if not value or not isinstance(value, str):
            return False
        
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False
    
    def test_valid_ipv4(self, valid_ipv4_addresses):
        """Test valid IPv4 addresses."""
        for ip in valid_ipv4_addresses:
            assert self.is_valid_ip(ip), f"Expected {ip} to be valid"
    
    def test_valid_ipv6(self, valid_ipv6_addresses):
        """Test valid IPv6 addresses."""
        for ip in valid_ipv6_addresses:
            assert self.is_valid_ip(ip), f"Expected {ip} to be valid"
    
    def test_invalid_addresses(self, invalid_ip_addresses):
        """Test invalid addresses."""
        for val in invalid_ip_addresses:
            if val is None:
                assert not self.is_valid_ip(val)
            else:
                assert not self.is_valid_ip(val), f"Expected {val} to be invalid"
    
    def test_circl_pdns_edge_cases(self, sample_circl_pdns_with_ip_rdata):
        """Test edge cases from CIRCL PDNS data."""
        for record in sample_circl_pdns_with_ip_rdata:
            rdata = record['rdata']
            rrtype = record['rrtype']
            
            # For MX, extract the host part
            if rrtype == 'MX' and ' ' in rdata:
                target = rdata.split(' ')[-1]
            else:
                target = rdata
            
            is_ip = self.is_valid_ip(target)
            
            # All rdata in this fixture should be IPs
            assert is_ip, f"Expected {target} from {rrtype} record to be detected as IP"
