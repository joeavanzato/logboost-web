"""
Tests for Sprint 3 Security Fixes.

Tests cover:
- /health Check Path Bug (Issue #9)
- Logout Session Cleanup (Issue #10)
- XSS Risk from innerHTML (Issue #17)
"""

import pytest
import json
import os
import shutil
from pathlib import Path
from unittest.mock import patch, MagicMock



def _workspace_source():
    """templates/index.html plus the page scripts that used to be inline in it."""
    root = Path(__file__).parent.parent
    parts = [root / 'templates' / 'index.html']
    parts += [root / 'static' / 'js' / name for name in ('workspace.js', 'enrich.js', 'graph-dialogs.js', 'graph.js', 'intel-browser.js')]
    return '\n'.join(p.read_text(encoding='utf-8') for p in parts)

class TestHealthCheckPathBug:
    """Tests for /health endpoint path handling (Issue #9)."""
    
    def test_health_check_with_relative_path(self, client, test_db):
        """Test health check with relative binary path."""
        response = client.get('/health')
        assert response.status_code == 200
        data = response.get_json()
        assert 'status' in data
        assert data['status'] in ('ok', 'degraded')  # degraded = binary not installed
        assert 'logboost_available' in data
    
    def test_health_check_paths_only_for_admin(self, client, admin_client):
        """Filesystem paths are returned to a logged-in admin, not to anonymous callers."""
        anonymous = client.get('/health').get_json()
        assert 'logboost_path' not in anonymous and 'maxmind_dir' not in anonymous

        as_admin = admin_client.get('/health').get_json()
        assert 'logboost_path' in as_admin
        assert 'maxmind_dir' in as_admin
        assert 'threat_db_dir' in as_admin
    
    def test_health_check_with_absolute_path_exists(self, client, test_db, tmp_path):
        """Test health check correctly detects existing absolute path binary."""
        # Create a fake binary file
        fake_binary = tmp_path / 'logboost'
        fake_binary.write_text('#!/bin/bash\necho test')
        fake_binary.chmod(0o755)
        
        with patch('app.get_effective_logboost_path', return_value=str(fake_binary)):
            response = client.get('/health')
            data = response.get_json()
            assert data['logboost_available'] == True
    
    def test_health_check_with_absolute_path_not_exists(self, client, test_db):
        """Test health check correctly detects non-existent absolute path binary."""
        with patch('app.get_effective_logboost_path', return_value='/nonexistent/path/to/logboost'):
            response = client.get('/health')
            data = response.get_json()
            assert data['logboost_available'] == False
    
    def test_health_check_absolute_vs_relative_path_detection(self):
        """Test that os.path.isabs correctly distinguishes path types."""
        import os
        
        # Absolute paths (POSIX)
        assert os.path.isabs('/usr/bin/logboost') is True
        assert os.path.isabs('/home/user/app/logboost') is True
        
        # Relative paths
        assert os.path.isabs('logboost') is False
        assert os.path.isabs('./logboost') is False
        assert os.path.isabs('../bin/logboost') is False


class TestLogoutSessionCleanup:
    """Tests for logout session cleanup (Issue #10)."""
    
    def test_logout_clears_session(self, authenticated_client, test_db):
        """Test that logout clears the session."""
        # Verify we're logged in
        response = authenticated_client.get('/')
        assert response.status_code == 200
        
        # Logout (POST request)
        response = authenticated_client.post('/logout')
        assert response.status_code == 302  # Redirect to login
        
        # Verify we're logged out (accessing protected page redirects)
        response = authenticated_client.get('/', follow_redirects=False)
        assert response.status_code == 302
    
    def test_logout_calls_cleanup_session(self, app, authenticated_client, test_db):
        """Test that logout calls cleanup_session."""
        with authenticated_client.session_transaction() as sess:
            sess['session_id'] = 'test-session-123'
        
        with patch('app.cleanup_session') as mock_cleanup:
            response = authenticated_client.post('/logout')
            assert response.status_code == 302
            mock_cleanup.assert_called_once_with('test-session-123')
    
    def test_logout_without_session_id(self, authenticated_client, test_db):
        """Test that logout works even without session_id."""
        # Remove session_id if present
        with authenticated_client.session_transaction() as sess:
            sess.pop('session_id', None)
        
        # Should not raise an error
        response = authenticated_client.post('/logout')
        assert response.status_code == 302
    
    def test_cleanup_session_removes_directories(self, app, test_db):
        """Test that cleanup_session removes upload and output directories."""
        from app import cleanup_session, UPLOAD_FOLDER, OUTPUT_FOLDER
        
        session_id = 'test-cleanup-session'
        
        # Create test directories
        upload_dir = UPLOAD_FOLDER / session_id
        output_dir = OUTPUT_FOLDER / session_id
        
        upload_dir.mkdir(parents=True, exist_ok=True)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Create test files
        (upload_dir / 'test.txt').write_text('test')
        (output_dir / 'result.csv').write_text('result')
        
        # Verify directories exist
        assert upload_dir.exists()
        assert output_dir.exists()
        
        # Cleanup
        cleanup_session(session_id)
        
        # Verify directories are removed
        assert not upload_dir.exists()
        assert not output_dir.exists()


class TestXSSProtection:
    """Tests for XSS protection in templates (Issue #17)."""
    
    def test_escape_html_function_exists(self):
        """Test that escapeHtml function is defined in index.html."""
        content = _workspace_source()
        
        assert 'function escapeHtml' in content
    
    def test_idb_ports_escaped(self):
        """Test that InternetDB ports are escaped in rendering."""
        content = _workspace_source()
        
        # Check that idb.ports uses escapeHtml
        assert 'idb.ports.map(p => this.escapeHtml(String(p)))' in content
    
    def test_idb_tags_escaped(self):
        """Test that InternetDB tags are escaped in rendering."""
        content = _workspace_source()
        
        # Check that idb.tags uses escapeHtml
        assert 'idb.tags.map(t => this.escapeHtml(String(t)))' in content
    
    def test_shodan_ports_escaped(self):
        """Test that Shodan ports are escaped in rendering."""
        content = _workspace_source()
        
        # Check that Shodan ports use escapeHtml
        assert 's.ports].sort((a,b) => a-b).map(p => this.escapeHtml(String(p)))' in content
    
    def test_shodan_service_port_escaped(self):
        """Test that Shodan service port/transport are escaped."""
        content = _workspace_source()
        
        # Check that service port and transport use escapeHtml
        assert 'this.escapeHtml(String(svc.port))' in content
        assert 'this.escapeHtml(svc.transport' in content
    
    def test_node_type_labels_escaped(self):
        """Test that node type labels in filters are escaped."""
        content = _workspace_source()
        
        # Check filter-item-label uses escapeHtml
        assert '<span class="filter-item-label">${this.escapeHtml(type)}</span>' in content
    
    def test_search_result_type_escaped(self):
        """Test that search result type is escaped."""
        content = _workspace_source()
        
        # Check search result type uses escapeHtml
        assert 'class="search-result-type">${this.escapeHtml(n.type)}' in content
    
    def test_whois_fields_escaped(self):
        """Test that WHOIS fields are escaped in rendering."""
        content = _workspace_source()
        
        # Check key WHOIS fields use escapeHtml
        assert 'this.escapeHtml(w.organization)' in content
        assert 'this.escapeHtml(w.registrar)' in content
        assert 'this.escapeHtml(w.registrant_name)' in content
        assert 'this.escapeHtml(w.registrant_email)' in content
    
    def test_no_unescaped_third_party_data(self):
        """Test that common third-party data patterns are escaped."""
        content = _workspace_source()
        
        # These patterns should NOT appear (unescaped third-party data)
        # Note: Some of these might be in comments or strings, so this is a heuristic
        dangerous_patterns = [
            '${idb.ports.join',  # Should use map + escapeHtml
            '${idb.tags.join(',  # Should use map + escapeHtml
            '${s.ports].sort((a,b) => a-b).join',  # Should use map + escapeHtml
        ]
        
        for pattern in dangerous_patterns:
            assert pattern not in content, f"Found potentially dangerous pattern: {pattern}"


class TestEscapeHtmlImplementation:
    """Tests for escapeHtml function implementation."""
    
    def test_escape_html_handles_special_chars(self):
        """Test escapeHtml handles HTML special characters."""
        # This is a JavaScript function, so we test by checking the implementation
        content = _workspace_source()
        
        # The escapeHtml function should use textContent approach or replace approach
        # Both are valid XSS prevention methods
        assert ('div.textContent = text' in content or 
                ".replace(/</g, '&lt;')" in content or
                '.replace(/&/g' in content)
    
    def test_multiple_escape_html_definitions(self):
        """Test that escapeHtml functions are defined where needed."""
        content = _workspace_source()
        
        # Count escapeHtml function definitions
        count = content.count('function escapeHtml')
        
        # Should have at least one definition
        assert count >= 1
