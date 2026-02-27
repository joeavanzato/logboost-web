"""
Tests for audit logging functions.

Tests cover:
- Event logging (log_audit)
- Log retrieval with filters (get_audit_logs)
- Action type discovery (get_audit_action_types)
- Retention settings (get_audit_retention_days)
- Cleanup operations (cleanup_old_audit_logs)
"""

import json
import time
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock
import pytest


# ============================================
# Fixtures
# ============================================

@pytest.fixture
def sample_audit_logs(test_db):
    """Create sample audit logs for testing."""
    import admin
    
    logs_data = [
        ('login', 'user', '1', None, 1, 1, 'alice', '192.168.1.1'),
        ('login_failed', 'user', None, '{"attempted_username": "baduser"}', 0, None, 'baduser', '10.0.0.1'),
        ('graph_created', 'graph', 'graph-123', '{"name": "Test Graph"}', 1, 1, 'alice', '192.168.1.1'),
        ('setting_modified', 'setting', 'dns_servers', '{"old": "8.8.8.8", "new": "1.1.1.1"}', 1, 2, 'bob', '192.168.1.2'),
        ('logout', 'user', '1', None, 1, 1, 'alice', '192.168.1.1'),
    ]
    
    conn = admin.get_db()
    cursor = conn.cursor()
    
    for action, res_type, res_id, details, success, user_id, username, ip in logs_data:
        cursor.execute('''
            INSERT INTO audit_logs (action, resource_type, resource_id, details, success, user_id, username, ip_address, user_agent)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (action, res_type, res_id, details, success, user_id, username, ip, 'Test Agent'))
        time.sleep(0.01)  # Small delay to ensure different timestamps
    
    conn.commit()
    conn.close()
    
    return logs_data


# ============================================
# Event Logging Tests (log_audit)
# ============================================

class TestLogAudit:
    """Tests for log_audit function."""
    
    def test_log_audit_creates_record(self, app, test_db):
        """Test that log_audit creates a database record."""
        import admin
        
        with app.test_request_context(headers={'User-Agent': 'TestAgent'}):
            # Use flask session directly in the app context
            from flask import session
            with app.test_client() as client:
                with client.session_transaction() as sess:
                    sess['user_id'] = 1
                    sess['username'] = 'testuser'
                
                # Make a request to establish the session
                client.get('/')
                
            # Now log audit with the real request context
            admin.log_audit('test_action', 'test_resource', 'resource-123')
        
        # Verify record was created
        logs, count = admin.get_audit_logs(limit=10)
        
        test_log = next((l for l in logs if l['action'] == 'test_action'), None)
        assert test_log is not None
        assert test_log['resource_type'] == 'test_resource'
        assert test_log['resource_id'] == 'resource-123'
    
    def test_log_audit_with_explicit_user(self, app, test_db):
        """Test that explicit user_id and username override session."""
        import admin
        
        with app.test_request_context():
            admin.log_audit('explicit_user_test', user_id=42, username='explicituser')
        
        logs, _ = admin.get_audit_logs(limit=10)
        test_log = next((l for l in logs if l['action'] == 'explicit_user_test'), None)
        
        assert test_log['user_id'] == 42
        assert test_log['username'] == 'explicituser'
    
    def test_log_audit_captures_ip_address(self, app, test_db):
        """Test that client IP is captured from request."""
        import admin
        
        with app.test_request_context(environ_base={'REMOTE_ADDR': '10.20.30.40'}):
            admin.log_audit('ip_test', user_id=1, username='testuser')
        
        logs, _ = admin.get_audit_logs(limit=10)
        test_log = next((l for l in logs if l['action'] == 'ip_test'), None)
        
        assert test_log['ip_address'] == '10.20.30.40'
    
    def test_log_audit_handles_forwarded_ip(self, app, test_db):
        """Test that X-Forwarded-For header is used for IP."""
        import admin
        
        with app.test_request_context(headers={'X-Forwarded-For': '203.0.113.50, 198.51.100.1'}):
            admin.log_audit('forwarded_ip_test', user_id=1, username='test')
        
        logs, _ = admin.get_audit_logs(limit=10)
        test_log = next((l for l in logs if l['action'] == 'forwarded_ip_test'), None)
        
        # Should use first IP in chain
        assert test_log['ip_address'] == '203.0.113.50'
    
    def test_log_audit_captures_user_agent(self, app, test_db):
        """Test that User-Agent header is captured."""
        import admin
        
        with app.test_request_context(headers={'User-Agent': 'Mozilla/5.0 CustomBrowser/1.0'}):
            admin.log_audit('ua_test', user_id=1, username='test')
        
        logs, _ = admin.get_audit_logs(limit=10)
        test_log = next((l for l in logs if l['action'] == 'ua_test'), None)
        
        assert 'CustomBrowser' in test_log['user_agent']
    
    def test_log_audit_truncates_long_user_agent(self, app, test_db):
        """Test that very long User-Agent is truncated."""
        import admin
        
        long_ua = 'A' * 1000
        
        with app.test_request_context(headers={'User-Agent': long_ua}):
            admin.log_audit('long_ua_test', user_id=1, username='test')
        
        logs, _ = admin.get_audit_logs(limit=10)
        test_log = next((l for l in logs if l['action'] == 'long_ua_test'), None)
        
        # User agent should be truncated to 500 chars
        assert len(test_log['user_agent']) <= 500
    
    def test_log_audit_serializes_details_to_json(self, app, test_db):
        """Test that details dict is serialized to JSON."""
        import admin
        
        details = {'key1': 'value1', 'count': 42, 'nested': {'a': 1}}
        
        with app.test_request_context():
            admin.log_audit('details_test', details=details, user_id=1, username='test')
        
        logs, _ = admin.get_audit_logs(limit=10)
        test_log = next((l for l in logs if l['action'] == 'details_test'), None)
        
        assert test_log['details'] == details
        assert test_log['details']['nested']['a'] == 1
    
    def test_log_audit_handles_null_details(self, app, test_db):
        """Test that None details are handled correctly."""
        import admin
        
        with app.test_request_context():
            admin.log_audit('null_details_test', details=None, user_id=1, username='test')
        
        logs, _ = admin.get_audit_logs(limit=10)
        test_log = next((l for l in logs if l['action'] == 'null_details_test'), None)
        
        assert test_log['details'] is None
    
    def test_log_audit_records_success_flag(self, app, test_db):
        """Test that success flag is recorded correctly."""
        import admin
        
        with app.test_request_context():
            admin.log_audit('success_test', success=True, user_id=1, username='test')
            admin.log_audit('failure_test', success=False, user_id=1, username='test')
        
        logs, _ = admin.get_audit_logs(limit=10)
        
        success_log = next((l for l in logs if l['action'] == 'success_test'), None)
        failure_log = next((l for l in logs if l['action'] == 'failure_test'), None)
        
        assert success_log['success'] == 1
        assert failure_log['success'] == 0
    
    def test_log_audit_null_user_for_failed_logins(self, app, test_db):
        """Test logging failed login with null user_id but explicit username."""
        import admin
        
        with app.test_request_context():
            admin.log_audit('login_failed', username='attempted_user', user_id=None)
        
        logs, _ = admin.get_audit_logs(limit=10)
        test_log = next((l for l in logs if l['action'] == 'login_failed'), None)
        
        assert test_log['username'] == 'attempted_user'
        assert test_log['user_id'] is None
    
    def test_log_audit_handles_exceptions_gracefully(self, app, test_db):
        """Test that exceptions don't propagate from log_audit."""
        import admin
        
        with app.test_request_context():
            # Mock get_db to raise an exception
            with patch.object(admin, 'get_db', side_effect=Exception('DB Error')):
                # Should not raise
                admin.log_audit('error_test')
        
        # Test passes if no exception was raised
    
    def test_log_audit_resource_type_and_id(self, app, test_db):
        """Test that resource_type and resource_id are stored correctly."""
        import admin
        
        with app.test_request_context():
            admin.log_audit('resource_test', 
                          resource_type='graph', 
                          resource_id='graph-abc-123',
                          user_id=1, username='test')
        
        logs, _ = admin.get_audit_logs(limit=10)
        test_log = next((l for l in logs if l['action'] == 'resource_test'), None)
        
        assert test_log['resource_type'] == 'graph'
        assert test_log['resource_id'] == 'graph-abc-123'


# ============================================
# Log Retrieval Tests (get_audit_logs)
# ============================================

class TestGetAuditLogs:
    """Tests for get_audit_logs function."""
    
    def test_get_audit_logs_basic_retrieval(self, test_db, sample_audit_logs):
        """Test basic retrieval of audit logs."""
        import admin
        
        logs, total_count = admin.get_audit_logs()
        
        assert total_count == 5
        assert len(logs) == 5
    
    def test_get_audit_logs_pagination_limit(self, test_db, sample_audit_logs):
        """Test that limit parameter works correctly."""
        import admin
        
        logs, total_count = admin.get_audit_logs(limit=2)
        
        assert len(logs) == 2
        assert total_count == 5  # Total unchanged
    
    def test_get_audit_logs_pagination_offset(self, test_db, sample_audit_logs):
        """Test that offset parameter works correctly."""
        import admin
        
        # Get first page
        logs_page1, _ = admin.get_audit_logs(limit=2, offset=0)
        # Get second page
        logs_page2, _ = admin.get_audit_logs(limit=2, offset=2)
        
        # Pages should have different logs
        page1_ids = {l['id'] for l in logs_page1}
        page2_ids = {l['id'] for l in logs_page2}
        
        assert len(page1_ids & page2_ids) == 0  # No overlap
    
    def test_get_audit_logs_filter_by_action(self, test_db, sample_audit_logs):
        """Test filtering by action type."""
        import admin
        
        logs, total_count = admin.get_audit_logs(action_filter='login')
        
        assert total_count == 1
        assert all(l['action'] == 'login' for l in logs)
    
    def test_get_audit_logs_filter_by_user(self, test_db, sample_audit_logs):
        """Test filtering by username."""
        import admin
        
        logs, total_count = admin.get_audit_logs(user_filter='alice')
        
        assert total_count == 3  # alice has 3 logs
        assert all('alice' in l['username'] for l in logs)
    
    def test_get_audit_logs_filter_by_ip(self, test_db, sample_audit_logs):
        """Test filtering by IP address."""
        import admin
        
        logs, total_count = admin.get_audit_logs(user_filter='192.168.1.1')
        
        assert total_count >= 1
        assert all('192.168.1.1' in l['ip_address'] for l in logs)
    
    def test_get_audit_logs_filter_by_start_date(self, test_db, sample_audit_logs):
        """Test filtering by start date."""
        import admin
        
        # First, get the actual earliest timestamp from the database
        conn = admin.get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT MIN(timestamp) as min_ts FROM audit_logs')
        min_ts = cursor.fetchone()['min_ts']
        conn.close()
        
        # Use a date before the earliest log entry (subtract 1 day to be safe)
        start = (datetime.fromisoformat(min_ts) - timedelta(days=1)).strftime('%Y-%m-%d %H:%M:%S')
        logs, total_count = admin.get_audit_logs(start_date=start)
        
        # All sample logs should be within this range
        assert total_count == 5
    
    def test_get_audit_logs_filter_by_end_date(self, test_db, sample_audit_logs):
        """Test filtering by end date."""
        import admin
        
        # First, get the actual latest timestamp from the database
        conn = admin.get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT MAX(timestamp) as max_ts FROM audit_logs')
        max_ts = cursor.fetchone()['max_ts']
        conn.close()
        
        # Use a date after the latest log entry (add 1 day to be safe)
        end = (datetime.fromisoformat(max_ts) + timedelta(days=1)).strftime('%Y-%m-%d %H:%M:%S')
        logs, total_count = admin.get_audit_logs(end_date=end)
        
        assert total_count == 5
    
    def test_get_audit_logs_filter_by_date_range_excludes(self, test_db, sample_audit_logs):
        """Test that date filters actually exclude records outside range."""
        import admin
        
        # Use a date range in the far past that should exclude all records
        old_start = '2000-01-01 00:00:00'
        old_end = '2000-01-02 00:00:00'
        
        logs, total_count = admin.get_audit_logs(start_date=old_start, end_date=old_end)
        
        # No logs should match this ancient date range
        assert total_count == 0
    
    def test_get_audit_logs_combined_filters(self, test_db, sample_audit_logs):
        """Test combining multiple filters."""
        import admin
        
        logs, total_count = admin.get_audit_logs(
            action_filter='login',
            user_filter='alice'
        )
        
        assert total_count == 1
        assert logs[0]['action'] == 'login'
        assert logs[0]['username'] == 'alice'
    
    def test_get_audit_logs_returns_total_count(self, test_db, sample_audit_logs):
        """Test that total count is returned correctly with pagination."""
        import admin
        
        logs, total_count = admin.get_audit_logs(limit=1)
        
        assert len(logs) == 1
        assert total_count == 5
    
    def test_get_audit_logs_parses_details_json(self, test_db, sample_audit_logs):
        """Test that details JSON is parsed correctly."""
        import admin
        
        logs, _ = admin.get_audit_logs(action_filter='setting_modified')
        
        assert len(logs) == 1
        assert isinstance(logs[0]['details'], dict)
        assert logs[0]['details']['old'] == '8.8.8.8'
        assert logs[0]['details']['new'] == '1.1.1.1'
    
    def test_get_audit_logs_ordered_by_timestamp_desc(self, test_db, sample_audit_logs):
        """Test that logs are ordered by timestamp descending."""
        import admin
        
        logs, _ = admin.get_audit_logs()
        
        # Most recent should be first
        for i in range(len(logs) - 1):
            assert logs[i]['timestamp'] >= logs[i + 1]['timestamp']
    
    def test_get_audit_logs_empty_when_no_logs(self, test_db):
        """Test that empty list is returned when no logs exist."""
        import admin
        
        logs, total_count = admin.get_audit_logs()
        
        assert logs == []
        assert total_count == 0


# ============================================
# Action Type Discovery Tests
# ============================================

class TestGetAuditActionTypes:
    """Tests for get_audit_action_types function."""
    
    def test_get_audit_action_types_returns_distinct(self, test_db, sample_audit_logs):
        """Test that distinct action types are returned."""
        import admin
        
        actions = admin.get_audit_action_types()
        
        # Should have unique actions from sample data
        expected = {'login', 'login_failed', 'graph_created', 'setting_modified', 'logout'}
        assert set(actions) == expected
    
    def test_get_audit_action_types_ordered(self, test_db, sample_audit_logs):
        """Test that action types are alphabetically ordered."""
        import admin
        
        actions = admin.get_audit_action_types()
        
        assert actions == sorted(actions)
    
    def test_get_audit_action_types_empty_when_no_logs(self, test_db):
        """Test that empty list is returned when no logs exist."""
        import admin
        
        actions = admin.get_audit_action_types()
        
        assert actions == []


# ============================================
# Retention Settings Tests
# ============================================

class TestGetAuditRetentionDays:
    """Tests for get_audit_retention_days function."""
    
    def test_get_audit_retention_days_default(self, test_db):
        """Test that default retention period is returned."""
        import admin
        
        days = admin.get_audit_retention_days()
        
        assert days == 90  # Default is 90 days
    
    def test_get_audit_retention_days_from_settings(self, test_db):
        """Test that custom retention period is retrieved."""
        import admin
        
        # Set custom retention
        conn = admin.get_db()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO settings (key, value) VALUES ('audit_retention_days', '30')")
        conn.commit()
        conn.close()
        
        days = admin.get_audit_retention_days()
        
        assert days == 30
    
    def test_get_audit_retention_days_invalid_value(self, test_db):
        """Test that invalid value returns default."""
        import admin
        
        # Set invalid value
        conn = admin.get_db()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO settings (key, value) VALUES ('audit_retention_days', 'not-a-number')")
        conn.commit()
        conn.close()
        
        days = admin.get_audit_retention_days()
        
        assert days == 90  # Should fall back to default


# ============================================
# Cleanup Tests
# ============================================

class TestCleanupOldAuditLogs:
    """Tests for cleanup_old_audit_logs function."""
    
    def test_cleanup_old_audit_logs_removes_expired(self, test_db):
        """Test that old logs are removed based on retention period."""
        import admin
        
        # Set short retention period
        conn = admin.get_db()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO settings (key, value) VALUES ('audit_retention_days', '1')")
        
        # Insert an old log (manually with old timestamp)
        old_date = (datetime.now() - timedelta(days=5)).isoformat()
        cursor.execute('''
            INSERT INTO audit_logs (action, timestamp, success)
            VALUES ('old_action', ?, 1)
        ''', (old_date,))
        
        # Insert a recent log
        cursor.execute('''
            INSERT INTO audit_logs (action, success)
            VALUES ('recent_action', 1)
        ''')
        conn.commit()
        conn.close()
        
        # Run cleanup
        deleted_count = admin.cleanup_old_audit_logs()
        
        assert deleted_count == 1
        
        # Verify old log is gone
        logs, _ = admin.get_audit_logs()
        actions = [l['action'] for l in logs]
        assert 'old_action' not in actions
        assert 'recent_action' in actions
    
    def test_cleanup_old_audit_logs_keeps_recent(self, test_db, sample_audit_logs):
        """Test that recent logs are kept."""
        import admin
        
        # Default retention is 90 days, sample logs are recent
        deleted_count = admin.cleanup_old_audit_logs()
        
        assert deleted_count == 0
        
        logs, total = admin.get_audit_logs()
        assert total == 5
    
    def test_cleanup_old_audit_logs_returns_count(self, test_db):
        """Test that deleted count is returned."""
        import admin
        
        # Set 1 day retention
        conn = admin.get_db()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO settings (key, value) VALUES ('audit_retention_days', '1')")
        
        # Insert old logs
        old_date = (datetime.now() - timedelta(days=10)).isoformat()
        for i in range(3):
            cursor.execute('''
                INSERT INTO audit_logs (action, timestamp, success)
                VALUES (?, ?, 1)
            ''', (f'old_action_{i}', old_date))
        conn.commit()
        conn.close()
        
        deleted_count = admin.cleanup_old_audit_logs()
        
        assert deleted_count == 3
    
    def test_cleanup_old_audit_logs_handles_errors(self, test_db):
        """Test that errors are handled gracefully."""
        import admin
        
        with patch.object(admin, 'get_audit_retention_days', side_effect=Exception('DB Error')):
            deleted_count = admin.cleanup_old_audit_logs()
        
        assert deleted_count == 0
    
    def test_cleanup_respects_custom_retention(self, test_db):
        """Test that cleanup respects custom retention period."""
        import admin
        
        # Set 7 day retention
        conn = admin.get_db()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO settings (key, value) VALUES ('audit_retention_days', '7')")
        
        # Insert log from 5 days ago (should be kept)
        five_days_ago = (datetime.now() - timedelta(days=5)).isoformat()
        cursor.execute('''
            INSERT INTO audit_logs (action, timestamp, success)
            VALUES ('five_day_old', ?, 1)
        ''', (five_days_ago,))
        
        # Insert log from 10 days ago (should be deleted)
        ten_days_ago = (datetime.now() - timedelta(days=10)).isoformat()
        cursor.execute('''
            INSERT INTO audit_logs (action, timestamp, success)
            VALUES ('ten_day_old', ?, 1)
        ''', (ten_days_ago,))
        
        conn.commit()
        conn.close()
        
        deleted_count = admin.cleanup_old_audit_logs()
        
        assert deleted_count == 1
        
        logs, _ = admin.get_audit_logs()
        actions = [l['action'] for l in logs]
        assert 'five_day_old' in actions
        assert 'ten_day_old' not in actions
