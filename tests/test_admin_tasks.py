"""
Tests for Admin Task Execution and Logs.

Tests cover:
- execute_task function - Task execution with various outcomes
- Task logs endpoints - View, detail, clear
- Audit logs endpoints - View, export, clear, retention
"""

import pytest
import json
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock
import subprocess


class TestExecuteTask:
    """Tests for the execute_task function."""
    
    def test_execute_task_update_geo_success(self, app, test_db):
        """Test successful geo update task execution."""
        from admin import execute_task, get_db
        
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = 'Geo databases updated successfully'
        mock_result.stderr = ''
        
        with patch('admin.subprocess.run', return_value=mock_result) as mock_run:
            with patch('admin.get_api_key', return_value='test_api_key'):
                with patch('admin.LOGBOOST_BINARY', '/usr/bin/logboost'):
                    execute_task('update_geo')
        
        # Check subprocess was called with correct args
        mock_run.assert_called_once()
        call_args = mock_run.call_args[0][0]
        assert '/usr/bin/logboost' in call_args
        assert '-api' in call_args
        assert 'test_api_key' in call_args
        assert '-updategeo' in call_args
        
        # Check log was created
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM task_logs WHERE task_type = ? ORDER BY id DESC LIMIT 1', ('update_geo',))
        log = cursor.fetchone()
        conn.close()
        
        assert log is not None
        assert log['status'] == 'success'
        assert 'updated successfully' in log['output']
    
    def test_execute_task_update_ti_success(self, app, test_db):
        """Test successful threat intel update task execution."""
        from admin import execute_task, get_db
        
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = 'TI feeds updated'
        mock_result.stderr = ''
        
        with patch('admin.subprocess.run', return_value=mock_result):
            with patch('admin.LOGBOOST_BINARY', '/usr/bin/logboost'):
                execute_task('update_ti')
        
        # Check log was created with success
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM task_logs WHERE task_type = ? ORDER BY id DESC LIMIT 1', ('update_ti',))
        log = cursor.fetchone()
        conn.close()
        
        assert log['status'] == 'success'
    
    def test_execute_task_build_ti_success(self, app, test_db):
        """Test successful threat intel build task execution."""
        from admin import execute_task, get_db
        
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = 'TI database built'
        mock_result.stderr = ''
        
        with patch('admin.subprocess.run', return_value=mock_result):
            with patch('admin.LOGBOOST_BINARY', '/usr/bin/logboost'):
                execute_task('build_ti')
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM task_logs WHERE task_type = ? ORDER BY id DESC LIMIT 1', ('build_ti',))
        log = cursor.fetchone()
        conn.close()
        
        assert log['status'] == 'success'
    
    def test_execute_task_failure(self, app, test_db):
        """Test failed task execution."""
        from admin import execute_task, get_db
        
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ''
        mock_result.stderr = 'Error: Database not found'
        
        with patch('admin.subprocess.run', return_value=mock_result):
            with patch('admin.LOGBOOST_BINARY', '/usr/bin/logboost'):
                execute_task('update_geo')
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM task_logs WHERE task_type = ? ORDER BY id DESC LIMIT 1', ('update_geo',))
        log = cursor.fetchone()
        conn.close()
        
        assert log['status'] == 'failed'
        assert 'Database not found' in log['error']
    
    def test_execute_task_timeout(self, app, test_db):
        """Test task execution timeout."""
        from admin import execute_task, get_db
        
        with patch('admin.subprocess.run', side_effect=subprocess.TimeoutExpired(cmd='logboost', timeout=3600)):
            with patch('admin.LOGBOOST_BINARY', '/usr/bin/logboost'):
                execute_task('update_geo')
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM task_logs WHERE task_type = ? ORDER BY id DESC LIMIT 1', ('update_geo',))
        log = cursor.fetchone()
        conn.close()
        
        assert log['status'] == 'failed'
        assert 'timed out' in log['error'].lower()
    
    def test_execute_task_binary_not_found(self, app, test_db):
        """Test task execution when binary is not found."""
        from admin import execute_task, get_db
        
        with patch('admin.subprocess.run', side_effect=FileNotFoundError()):
            with patch('admin.LOGBOOST_BINARY', '/nonexistent/logboost'):
                execute_task('update_geo')
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM task_logs WHERE task_type = ? ORDER BY id DESC LIMIT 1', ('update_geo',))
        log = cursor.fetchone()
        conn.close()
        
        assert log['status'] == 'failed'
        assert 'not found' in log['error'].lower()
    
    def test_execute_task_unknown_type(self, app, test_db):
        """Test task execution with unknown task type."""
        from admin import execute_task, get_db
        
        with patch('admin.LOGBOOST_BINARY', '/usr/bin/logboost'):
            execute_task('unknown_task')
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM task_logs WHERE task_type = ? ORDER BY id DESC LIMIT 1', ('unknown_task',))
        log = cursor.fetchone()
        conn.close()
        
        assert log['status'] == 'failed'
        assert 'Unknown task type' in log['error']
    
    def test_execute_task_updates_next_run(self, app, test_db):
        """Test that task execution updates next_run for enabled tasks."""
        from admin import execute_task, get_db
        
        # First create a scheduled task (or update if exists)
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO scheduled_tasks (task_type, enabled, interval_hours) 
            VALUES ('update_geo', 1, 24)
        ''')
        conn.commit()
        conn.close()
        
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = 'Success'
        mock_result.stderr = ''
        
        with patch('admin.subprocess.run', return_value=mock_result):
            with patch('admin.get_api_key', return_value='key'):
                with patch('admin.LOGBOOST_BINARY', '/usr/bin/logboost'):
                    execute_task('update_geo')
        
        # Check next_run was updated
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT next_run, last_run FROM scheduled_tasks WHERE task_type = ?', ('update_geo',))
        task = cursor.fetchone()
        conn.close()
        
        assert task['last_run'] is not None
        assert task['next_run'] is not None
    
    def test_execute_task_without_api_key(self, app, test_db):
        """Test geo update task without API key."""
        from admin import execute_task
        
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = 'Success'
        mock_result.stderr = ''
        
        with patch('admin.subprocess.run', return_value=mock_result) as mock_run:
            with patch('admin.get_api_key', return_value=None):
                with patch('admin.LOGBOOST_BINARY', '/usr/bin/logboost'):
                    execute_task('update_geo')
        
        # Check -api flag was not included
        call_args = mock_run.call_args[0][0]
        assert '-api' not in call_args


class TestAdminLogsEndpoints:
    """Tests for admin logs endpoints."""
    
    def test_logs_page_requires_admin(self, client, test_db):
        """Test that logs page requires admin authentication."""
        response = client.get('/admin/logs')
        assert response.status_code in (302, 401, 403)
    
    def test_logs_page_success(self, admin_client, test_db):
        """Test viewing logs page."""
        # Create some test logs
        from admin import get_db
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO task_logs (task_type, status, started_at, completed_at, output)
            VALUES ('update_geo', 'success', datetime('now'), datetime('now'), 'Test output')
        ''')
        conn.commit()
        conn.close()
        
        response = admin_client.get('/admin/logs')
        assert response.status_code == 200
        assert b'update_geo' in response.data or b'Logs' in response.data
    
    def test_logs_page_pagination(self, admin_client, test_db):
        """Test logs page pagination."""
        response = admin_client.get('/admin/logs?page=1')
        assert response.status_code == 200
    
    def test_log_detail_requires_admin(self, client, test_db):
        """Test that log detail requires admin authentication."""
        response = client.get('/admin/logs/1')
        assert response.status_code in (302, 401, 403)
    
    def test_log_detail_success(self, admin_client, test_db):
        """Test viewing log detail."""
        # Create a test log
        from admin import get_db
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO task_logs (task_type, status, started_at, completed_at, output, error)
            VALUES ('update_geo', 'success', datetime('now'), datetime('now'), 'Detailed output', NULL)
        ''')
        log_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        response = admin_client.get(f'/admin/logs/{log_id}')
        assert response.status_code == 200
    
    def test_log_detail_not_found(self, admin_client, test_db):
        """Test log detail for non-existent log."""
        response = admin_client.get('/admin/logs/99999')
        # Should redirect with error flash
        assert response.status_code in (302, 404)
    
    def test_clear_logs_requires_admin(self, client, test_db):
        """Test that clearing logs requires admin authentication."""
        response = client.post('/admin/logs/clear')
        assert response.status_code in (302, 401, 403)
    
    def test_clear_logs_success(self, admin_client, test_db):
        """Test clearing all logs."""
        # Create some test logs
        from admin import get_db
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO task_logs (task_type, status, started_at) VALUES ('test', 'success', datetime('now'))
        ''')
        cursor.execute('''
            INSERT INTO task_logs (task_type, status, started_at) VALUES ('test2', 'failed', datetime('now'))
        ''')
        conn.commit()
        conn.close()
        
        response = admin_client.post('/admin/logs/clear')
        assert response.status_code == 302  # Redirect after clear
        
        # Verify logs were cleared
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) as count FROM task_logs')
        count = cursor.fetchone()['count']
        conn.close()
        
        assert count == 0


class TestAuditLogsEndpoints:
    """Tests for audit logs endpoints."""
    
    def test_audit_logs_requires_admin(self, client, test_db):
        """Test that audit logs page requires admin authentication."""
        response = client.get('/admin/audit')
        assert response.status_code in (302, 401, 403)
    
    def test_audit_logs_page_success(self, admin_client, test_db):
        """Test viewing audit logs page."""
        response = admin_client.get('/admin/audit')
        assert response.status_code == 200
    
    def test_audit_logs_with_filters(self, admin_client, test_db):
        """Test audit logs with various filters."""
        response = admin_client.get('/admin/audit?action=login&user=admin')
        assert response.status_code == 200
    
    def test_audit_logs_date_filter(self, admin_client, test_db):
        """Test audit logs with date filters."""
        response = admin_client.get('/admin/audit?start_date=2024-01-01&end_date=2024-12-31')
        assert response.status_code == 200
    
    def test_audit_logs_pagination(self, admin_client, test_db):
        """Test audit logs pagination."""
        response = admin_client.get('/admin/audit?page=1&per_page=10')
        assert response.status_code == 200
    
    def test_audit_logs_per_page_clamped(self, admin_client, test_db):
        """Test that per_page is clamped to valid range."""
        # Too small
        response = admin_client.get('/admin/audit?per_page=1')
        assert response.status_code == 200
        
        # Too large
        response = admin_client.get('/admin/audit?per_page=1000')
        assert response.status_code == 200
    
    def test_audit_export_requires_admin(self, client, test_db):
        """Test that audit export requires admin authentication."""
        response = client.get('/admin/audit/export')
        assert response.status_code in (302, 401, 403)
    
    def test_audit_export_csv(self, admin_client, test_db):
        """Test exporting audit logs as CSV."""
        # Create some audit logs first
        from admin import log_audit
        log_audit('test_action', 'test', 'target', {'key': 'value'})
        
        response = admin_client.get('/admin/audit/export')
        assert response.status_code == 200
        assert 'text/csv' in response.content_type
    
    def test_audit_export_with_filters(self, admin_client, test_db):
        """Test exporting audit logs with filters."""
        from admin import log_audit
        log_audit('test_action', 'test', 'target', {'key': 'value'})
        
        response = admin_client.get('/admin/audit/export?action=test_action')
        assert response.status_code == 200
        assert 'text/csv' in response.content_type
    
    def test_audit_retention_requires_admin(self, client, test_db):
        """Test that setting audit retention requires admin authentication."""
        response = client.post('/admin/settings/audit-retention',
                               data={'retention_days': 30})
        assert response.status_code in (302, 401, 403)
    
    def test_audit_retention_success(self, admin_client, test_db):
        """Test setting audit retention days."""
        response = admin_client.post('/admin/settings/audit-retention',
                                     data={'retention_days': '60'},
                                     follow_redirects=True)
        assert response.status_code == 200


class TestQueryCirclPdns:
    """Tests for the query_circl_pdns function."""
    
    def test_query_circl_pdns_success(self):
        """Test successful CIRCL PDNS query."""
        from app import query_circl_pdns
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = '{"rrname": "8.8.8.8", "rdata": "dns.google"}\n{"rrname": "8.8.8.8", "rdata": "other.google"}'
        mock_response.raise_for_status = MagicMock()
        
        with patch('requests.get', return_value=mock_response):
            settings = {'username': 'user', 'password': 'pass'}
            results = query_circl_pdns('8.8.8.8', settings)
        
        assert len(results) == 2
        assert results[0]['rrname'] == '8.8.8.8'
    
    def test_query_circl_pdns_with_auth(self):
        """Test CIRCL PDNS query with authentication."""
        from app import query_circl_pdns
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = '{}'
        mock_response.raise_for_status = MagicMock()
        
        with patch('requests.get', return_value=mock_response) as mock_get:
            settings = {'username': 'testuser', 'password': 'testpass'}
            query_circl_pdns('8.8.8.8', settings)
        
        # Check auth was passed
        call_kwargs = mock_get.call_args[1]
        assert call_kwargs['auth'] == ('testuser', 'testpass')
    
    def test_query_circl_pdns_with_headers(self):
        """Test CIRCL PDNS query with optional headers."""
        from app import query_circl_pdns
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = '{}'
        mock_response.raise_for_status = MagicMock()
        
        with patch('requests.get', return_value=mock_response) as mock_get:
            settings = {
                'username': 'user',
                'password': 'pass',
                'disable_active_query': True,
                'max_results': 100
            }
            query_circl_pdns('8.8.8.8', settings)
        
        # Check headers were set
        call_kwargs = mock_get.call_args[1]
        assert 'dribble-disable-active-query' in call_kwargs['headers']
        assert call_kwargs['headers']['dribble-paginate-count'] == '100'
    
    def test_query_circl_pdns_without_auth(self):
        """Test CIRCL PDNS query without authentication."""
        from app import query_circl_pdns
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = '{}'
        mock_response.raise_for_status = MagicMock()
        
        with patch('requests.get', return_value=mock_response) as mock_get:
            settings = {}  # No username/password
            query_circl_pdns('8.8.8.8', settings)
        
        # Check auth was None
        call_kwargs = mock_get.call_args[1]
        assert call_kwargs['auth'] is None
    
    def test_query_circl_pdns_handles_malformed_json(self):
        """Test CIRCL PDNS handles malformed JSON lines."""
        from app import query_circl_pdns
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = '{"valid": "json"}\nnot valid json\n{"also": "valid"}'
        mock_response.raise_for_status = MagicMock()
        
        with patch('requests.get', return_value=mock_response):
            settings = {'username': 'user', 'password': 'pass'}
            results = query_circl_pdns('8.8.8.8', settings)
        
        # Should have 2 valid results, skipping the invalid line
        assert len(results) == 2
    
    def test_query_circl_pdns_handles_empty_lines(self):
        """Test CIRCL PDNS handles empty lines."""
        from app import query_circl_pdns
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = '{"data": 1}\n\n\n{"data": 2}\n'
        mock_response.raise_for_status = MagicMock()
        
        with patch('requests.get', return_value=mock_response):
            settings = {'username': 'user', 'password': 'pass'}
            results = query_circl_pdns('8.8.8.8', settings)
        
        assert len(results) == 2
    
    def test_query_circl_pdns_request_error(self):
        """Test CIRCL PDNS handles request errors."""
        from app import query_circl_pdns
        import requests
        
        with patch('requests.get', side_effect=requests.exceptions.ConnectionError('Network error')):
            settings = {'username': 'user', 'password': 'pass'}
            
            with pytest.raises(Exception) as exc_info:
                query_circl_pdns('8.8.8.8', settings)
            
            assert 'CIRCL API request failed' in str(exc_info.value)
    
    def test_query_circl_pdns_empty_response(self):
        """Test CIRCL PDNS handles empty response."""
        from app import query_circl_pdns
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = ''
        mock_response.raise_for_status = MagicMock()
        
        with patch('requests.get', return_value=mock_response):
            settings = {'username': 'user', 'password': 'pass'}
            results = query_circl_pdns('8.8.8.8', settings)
        
        assert results == []


class TestRateLimiter:
    """Tests for the RateLimiter class."""
    
    def test_rate_limiter_creation(self):
        """Test RateLimiter initialization."""
        from app import RateLimiter
        
        limiter = RateLimiter(10)  # 10 requests per second
        assert limiter.rate == 10
        assert limiter.min_interval == 0.1
    
    def test_rate_limiter_zero_rate(self):
        """Test RateLimiter with zero rate."""
        from app import RateLimiter
        
        limiter = RateLimiter(0)
        assert limiter.min_interval == 0
    
    def test_rate_limiter_wait_no_delay(self):
        """Test RateLimiter.wait() doesn't delay on first call."""
        from app import RateLimiter
        import time
        
        limiter = RateLimiter(1)  # 1 request per second
        
        start = time.time()
        limiter.wait()
        elapsed = time.time() - start
        
        # First call should be immediate (< 0.1 seconds)
        assert elapsed < 0.1
    
    def test_rate_limiter_wait_delays(self):
        """Test RateLimiter.wait() delays subsequent calls."""
        from app import RateLimiter
        import time
        
        limiter = RateLimiter(10)  # 10 requests per second = 0.1s interval
        
        limiter.wait()  # First call
        
        start = time.time()
        limiter.wait()  # Second call should wait
        elapsed = time.time() - start
        
        # Should have waited approximately 0.1 seconds (with some tolerance)
        assert elapsed >= 0.05  # At least some delay


class TestAdminSetupEndpoints:
    """Tests for admin setup endpoints."""
    
    def test_setup_status_requires_admin(self, client, test_db):
        """Test that setup status requires admin authentication."""
        response = client.get('/admin/api/setup/status')
        assert response.status_code in (302, 401, 403)
    
    def test_setup_status_success(self, admin_client, test_db):
        """Test getting setup status."""
        response = admin_client.get('/admin/api/setup/status')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'binary_path' in data

