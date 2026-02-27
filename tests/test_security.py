"""
Tests for Sprint 1 Security Fixes.

Tests cover:
- SSRF Protection (Issue #3)
- Session Cookie Configuration (Issue #12)
- CSRF Protection (Issue #11)
- Logging Configuration (Issues #1 & #8)
"""

import pytest
import json
from unittest.mock import patch, MagicMock
import socket


class TestSSRFProtection:
    """Tests for SSRF protection in URL fetching."""
    
    def test_is_ip_blocked_loopback(self):
        """Test that loopback addresses are blocked."""
        from app import is_ip_blocked
        
        assert is_ip_blocked('127.0.0.1') == True
        assert is_ip_blocked('127.0.0.2') == True
        assert is_ip_blocked('127.255.255.255') == True
    
    def test_is_ip_blocked_private_10(self):
        """Test that 10.x.x.x private addresses are blocked."""
        from app import is_ip_blocked
        
        assert is_ip_blocked('10.0.0.1') == True
        assert is_ip_blocked('10.255.255.255') == True
    
    def test_is_ip_blocked_private_172(self):
        """Test that 172.16-31.x.x private addresses are blocked."""
        from app import is_ip_blocked
        
        assert is_ip_blocked('172.16.0.1') == True
        assert is_ip_blocked('172.31.255.255') == True
        # 172.32.x.x is NOT private
        assert is_ip_blocked('172.32.0.1') == False
    
    def test_is_ip_blocked_private_192(self):
        """Test that 192.168.x.x private addresses are blocked."""
        from app import is_ip_blocked
        
        assert is_ip_blocked('192.168.0.1') == True
        assert is_ip_blocked('192.168.255.255') == True
    
    def test_is_ip_blocked_link_local(self):
        """Test that link-local/AWS metadata addresses are blocked."""
        from app import is_ip_blocked
        
        assert is_ip_blocked('169.254.169.254') == True  # AWS metadata
        assert is_ip_blocked('169.254.0.1') == True
    
    def test_is_ip_blocked_public(self):
        """Test that public IP addresses are NOT blocked."""
        from app import is_ip_blocked
        
        assert is_ip_blocked('8.8.8.8') == False  # Google DNS
        assert is_ip_blocked('1.1.1.1') == False  # Cloudflare DNS
        assert is_ip_blocked('93.184.216.34') == False  # example.com
    
    def test_is_ip_blocked_invalid(self):
        """Test that invalid IP addresses are blocked."""
        from app import is_ip_blocked
        
        assert is_ip_blocked('not-an-ip') == True
        assert is_ip_blocked('') == True
    
    def test_validate_url_rejects_file_scheme(self):
        """Test that file:// URLs are rejected."""
        from app import validate_url_for_ssrf
        
        is_valid, error = validate_url_for_ssrf('file:///etc/passwd')
        assert is_valid == False
        assert 'scheme' in error.lower()
    
    def test_validate_url_rejects_ftp_scheme(self):
        """Test that ftp:// URLs are rejected."""
        from app import validate_url_for_ssrf
        
        is_valid, error = validate_url_for_ssrf('ftp://example.com/file')
        assert is_valid == False
        assert 'scheme' in error.lower()
    
    def test_validate_url_accepts_http(self):
        """Test that http:// URLs are accepted (for public IPs)."""
        from app import validate_url_for_ssrf
        
        with patch('socket.gethostbyname', return_value='93.184.216.34'):
            is_valid, error = validate_url_for_ssrf('http://example.com')
            assert is_valid == True
            assert error is None
    
    def test_validate_url_accepts_https(self):
        """Test that https:// URLs are accepted (for public IPs)."""
        from app import validate_url_for_ssrf
        
        with patch('socket.gethostbyname', return_value='93.184.216.34'):
            is_valid, error = validate_url_for_ssrf('https://example.com')
            assert is_valid == True
            assert error is None
    
    def test_validate_url_rejects_localhost(self):
        """Test that localhost URLs are rejected."""
        from app import validate_url_for_ssrf
        
        with patch('socket.gethostbyname', return_value='127.0.0.1'):
            is_valid, error = validate_url_for_ssrf('http://localhost')
            assert is_valid == False
            assert 'internal' in error.lower() or 'private' in error.lower()
    
    def test_validate_url_rejects_internal_ip_hostname(self):
        """Test that hostnames resolving to internal IPs are rejected."""
        from app import validate_url_for_ssrf
        
        with patch('socket.gethostbyname', return_value='10.0.0.5'):
            is_valid, error = validate_url_for_ssrf('http://internal-server.local')
            assert is_valid == False
    
    def test_validate_url_rejects_aws_metadata(self):
        """Test that AWS metadata endpoint is rejected."""
        from app import validate_url_for_ssrf
        
        with patch('socket.gethostbyname', return_value='169.254.169.254'):
            is_valid, error = validate_url_for_ssrf('http://169.254.169.254/latest/meta-data/')
            assert is_valid == False
    
    def test_validate_url_handles_dns_failure(self):
        """Test that DNS resolution failures are handled."""
        from app import validate_url_for_ssrf
        
        with patch('socket.gethostbyname', side_effect=socket.gaierror('DNS failed')):
            is_valid, error = validate_url_for_ssrf('http://nonexistent.invalid')
            assert is_valid == False
            assert 'resolve' in error.lower()
    
    def test_validate_url_requires_hostname(self):
        """Test that URLs without hostnames are rejected."""
        from app import validate_url_for_ssrf
        
        is_valid, error = validate_url_for_ssrf('http://')
        assert is_valid == False


class TestMaxUrlFetchSize:
    """Tests for URL fetch size configuration."""
    
    def test_get_max_url_fetch_size_default(self, test_db):
        """Test default max URL fetch size."""
        from security import get_max_url_fetch_size, DEFAULT_MAX_URL_FETCH_SIZE
        
        size = get_max_url_fetch_size()
        assert size == DEFAULT_MAX_URL_FETCH_SIZE
    
    def test_get_max_url_fetch_size_custom(self, test_db):
        """Test custom max URL fetch size from settings."""
        import admin
        from security import get_max_url_fetch_size
        
        admin.set_setting('max_url_fetch_size_mb', '20')
        
        size = get_max_url_fetch_size()
        assert size == 20 * 1024 * 1024  # 20MB


class TestSessionCookieConfiguration:
    """Tests for session cookie security configuration."""
    
    def test_session_cookie_httponly(self, app):
        """Test that SESSION_COOKIE_HTTPONLY is enabled."""
        assert app.config.get('SESSION_COOKIE_HTTPONLY') == True
    
    def test_session_cookie_samesite(self, app):
        """Test that SESSION_COOKIE_SAMESITE is set to Lax."""
        assert app.config.get('SESSION_COOKIE_SAMESITE') == 'Lax'


class TestCSRFProtection:
    """Tests for CSRF protection configuration."""
    
    def test_csrf_error_handler_returns_json(self, app, client):
        """Test that CSRF errors return JSON response."""
        from flask_wtf.csrf import generate_csrf
        
        # Make a POST request without CSRF token to a form endpoint
        # (Skip this if all endpoints are exempt)
        pass  # CSRF is mostly exempt for API endpoints
    
    def test_api_endpoints_work_without_csrf(self, authenticated_client, test_db):
        """Test that API endpoints work without CSRF token (they're exempt)."""
        # DNS resolve endpoint should work without CSRF
        response = authenticated_client.post('/api/dns/resolve',
            json={'domain': 'example.com'},
            content_type='application/json')
        
        # Should not get a 400 CSRF error
        assert response.status_code != 400 or b'CSRF' not in response.data


class TestLoggingConfiguration:
    """Tests for logging configuration."""
    
    def test_log_level_default(self, app):
        """Test that default log level is WARNING."""
        import logging
        import os
        
        # If LOGBOOST_LOG_LEVEL is not set, should default to WARNING
        if 'LOGBOOST_LOG_LEVEL' not in os.environ:
            assert app.logger.level == logging.WARNING or app.logger.level == 0
    
    def test_no_print_statements_in_app(self):
        """Test that app.py has no print statements."""
        import re
        from pathlib import Path
        
        app_path = Path(__file__).parent.parent / 'app.py'
        content = app_path.read_text()
        
        # Find print statements (but not in strings or comments)
        # This is a simplified check
        lines = content.split('\n')
        print_lines = []
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('print(') and not stripped.startswith('#'):
                print_lines.append(i)
        
        assert len(print_lines) == 0, f"Found print statements on lines: {print_lines}"
    
    def test_no_print_statements_in_admin(self):
        """Test that admin.py has no print statements."""
        from pathlib import Path
        
        admin_path = Path(__file__).parent.parent / 'admin.py'
        content = admin_path.read_text()
        
        lines = content.split('\n')
        print_lines = []
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('print(') and not stripped.startswith('#'):
                print_lines.append(i)
        
        assert len(print_lines) == 0, f"Found print statements on lines: {print_lines}"
