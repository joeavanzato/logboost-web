"""
Tests for Sprint 2 Security Fixes.

Tests cover:
- Shodan Cache Schema Fix (Issue #5)
- File Upload Validation (Issue #6)
- Scheduler Duplicate Prevention (Issue #2)
- Multi-Worker Scheduler Protection (Issue #7)
"""

import pytest
import json
import time
import threading
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock
from io import BytesIO


class TestShodanCacheSchemaFix:
    """Tests for Shodan cache composite unique constraint (Issue #5)."""
    
    def test_shodan_cache_different_query_types_no_collision(self, test_db):
        """Test that same query with different types don't collide."""
        import admin
        
        # Cache the same query as two different types
        admin.set_cached_shodan('8.8.8.8', 'ip', {'data': 'ip_result'}, 3600)
        admin.set_cached_shodan('8.8.8.8', 'domain', {'data': 'domain_result'}, 3600)
        
        # Both should be retrievable
        ip_cached = admin.get_cached_shodan('8.8.8.8', 'ip')
        domain_cached = admin.get_cached_shodan('8.8.8.8', 'domain')
        
        assert ip_cached is not None
        assert domain_cached is not None
        assert ip_cached['data'] == 'ip_result'
        assert domain_cached['data'] == 'domain_result'
    
    def test_shodan_cache_same_query_type_overwrites(self, test_db):
        """Test that same query+type combination overwrites existing entry."""
        import admin
        
        # Cache same query+type twice
        admin.set_cached_shodan('test.com', 'domain', {'version': 1}, 3600)
        admin.set_cached_shodan('test.com', 'domain', {'version': 2}, 3600)
        
        # Should get the second version
        cached = admin.get_cached_shodan('test.com', 'domain')
        assert cached is not None
        assert cached['version'] == 2
    
    def test_shodan_cache_schema_has_composite_unique(self, test_db):
        """Test that the schema has composite unique constraint."""
        import admin
        
        conn = admin.get_db()
        cursor = conn.cursor()
        
        # Get the table schema
        cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='shodan_cache'")
        result = cursor.fetchone()
        conn.close()
        
        assert result is not None
        schema_sql = result[0]
        
        # Should have composite unique, not single column unique
        assert 'UNIQUE(query, query_type)' in schema_sql or 'UNIQUE (query, query_type)' in schema_sql


class TestFileUploadValidation:
    """Tests for file upload validation (Issue #6)."""
    
    def test_allowed_file_accepts_valid_extensions(self):
        """Test that allowed_file accepts valid extensions."""
        from app import allowed_file, ALLOWED_EXTENSIONS
        
        for ext in ALLOWED_EXTENSIONS:
            assert allowed_file(f'test.{ext}') == True
            assert allowed_file(f'test.{ext.upper()}') == True  # Case insensitive
    
    def test_allowed_file_rejects_invalid_extensions(self):
        """Test that allowed_file rejects invalid extensions."""
        from app import allowed_file
        
        assert allowed_file('test.exe') == False
        assert allowed_file('test.php') == False
        assert allowed_file('test.sh') == False
        assert allowed_file('test.py') == False
        assert allowed_file('test.html') == False
    
    def test_allowed_file_rejects_no_extension(self):
        """Test that allowed_file rejects files without extensions."""
        from app import allowed_file
        
        assert allowed_file('testfile') == False
        assert allowed_file('') == False
    
    def test_max_content_length_configured(self, app):
        """Test that MAX_CONTENT_LENGTH is configured."""
        assert 'MAX_CONTENT_LENGTH' in app.config
        assert app.config['MAX_CONTENT_LENGTH'] == 100 * 1024 * 1024  # 100MB
    
    def test_enrich_file_rejects_invalid_extension(self, authenticated_client, test_db):
        """Test that /enrich/file rejects invalid file extensions."""
        data = {
            'file': (BytesIO(b'test content'), 'malicious.exe')
        }
        response = authenticated_client.post('/enrich/file',
            data=data,
            content_type='multipart/form-data')
        
        assert response.status_code == 200  # Returns HTML error partial
        assert b'Invalid file type' in response.data or b'Allowed extensions' in response.data
    
    def test_enrich_file_accepts_valid_extension(self, authenticated_client, test_db):
        """Test that /enrich/file accepts valid file extensions."""
        # Create a simple CSV file
        csv_content = b'ip,count\n192.168.1.1,5\n10.0.0.1,3'
        data = {
            'file': (BytesIO(csv_content), 'test.csv')
        }
        response = authenticated_client.post('/enrich/file',
            data=data,
            content_type='multipart/form-data')
        
        # Should not return "Invalid file type" error
        assert b'Invalid file type' not in response.data
    
    def test_enrich_file_rejects_empty_filename(self, authenticated_client, test_db):
        """Test that /enrich/file rejects empty filename."""
        data = {
            'file': (BytesIO(b'test content'), '')
        }
        response = authenticated_client.post('/enrich/file',
            data=data,
            content_type='multipart/form-data')
        
        assert b'No file selected' in response.data or b'Invalid' in response.data


class TestSchedulerDuplicatePrevention:
    """Tests for scheduler duplicate task prevention (Issue #2)."""
    
    def test_scheduled_tasks_has_running_columns(self, test_db):
        """Test that scheduled_tasks table has running state columns."""
        import admin
        
        conn = admin.get_db()
        cursor = conn.cursor()
        
        cursor.execute("PRAGMA table_info(scheduled_tasks)")
        columns = {col[1]: col[2] for col in cursor.fetchall()}
        conn.close()
        
        assert 'running' in columns
        assert 'running_since' in columns
        assert 'runner_id' in columns
    
    def test_task_claim_sets_running_flag(self, test_db):
        """Test that claiming a task sets the running flag."""
        import admin
        
        conn = admin.get_db()
        cursor = conn.cursor()
        
        # Set up a task that's due to run
        now = datetime.now()
        past = now - timedelta(minutes=5)
        
        cursor.execute('''
            UPDATE scheduled_tasks 
            SET enabled = 1, next_run = ?, running = 0
            WHERE task_type = 'update_geo'
        ''', (past,))
        conn.commit()
        
        # Simulate claiming the task
        cursor.execute('''
            UPDATE scheduled_tasks 
            SET running = 1, running_since = ?, runner_id = 'test-runner'
            WHERE task_type = 'update_geo' AND running = 0
        ''', (now,))
        conn.commit()
        
        # Verify the task is marked as running
        cursor.execute('SELECT running, runner_id FROM scheduled_tasks WHERE task_type = ?', ('update_geo',))
        result = cursor.fetchone()
        conn.close()
        
        assert result['running'] == 1
        assert result['runner_id'] == 'test-runner'
    
    def test_running_task_cannot_be_claimed_again(self, test_db):
        """Test that a running task cannot be claimed by another worker."""
        import admin
        
        conn = admin.get_db()
        cursor = conn.cursor()
        
        # Set up a task that's already running
        now = datetime.now()
        past = now - timedelta(minutes=5)
        
        cursor.execute('''
            UPDATE scheduled_tasks 
            SET enabled = 1, next_run = ?, running = 1, runner_id = 'worker-1'
            WHERE task_type = 'update_geo'
        ''', (past,))
        conn.commit()
        
        # Try to claim as another worker
        cursor.execute('''
            UPDATE scheduled_tasks 
            SET running = 1, running_since = ?, runner_id = 'worker-2'
            WHERE task_type = 'update_geo' AND running = 0
        ''', (now,))
        conn.commit()
        
        affected_rows = cursor.rowcount
        
        # Verify original runner is still set
        cursor.execute('SELECT runner_id FROM scheduled_tasks WHERE task_type = ?', ('update_geo',))
        result = cursor.fetchone()
        conn.close()
        
        assert affected_rows == 0  # No rows should be updated
        assert result['runner_id'] == 'worker-1'  # Original runner unchanged
    
    def test_stale_lock_detection(self, test_db):
        """Test that stale locks can be detected based on running_since."""
        import admin
        
        conn = admin.get_db()
        cursor = conn.cursor()
        
        # Set up a task with a stale lock (3 hours old)
        stale_time = datetime.now() - timedelta(hours=3)
        
        cursor.execute('''
            UPDATE scheduled_tasks 
            SET running = 1, running_since = ?, runner_id = 'dead-worker'
            WHERE task_type = 'update_geo'
        ''', (stale_time,))
        conn.commit()
        
        # Query for stale locks (older than 2 hours)
        cutoff = datetime.now() - timedelta(hours=2)
        cursor.execute('''
            SELECT task_type FROM scheduled_tasks
            WHERE running = 1 AND running_since < ?
        ''', (cutoff,))
        
        stale_tasks = cursor.fetchall()
        conn.close()
        
        assert len(stale_tasks) == 1
        assert stale_tasks[0]['task_type'] == 'update_geo'


class TestSchedulerClass:
    """Tests for TaskScheduler class functionality."""
    
    def test_scheduler_has_runner_id(self, test_db):
        """Test that scheduler generates a unique runner_id."""
        import admin
        
        scheduler = admin.TaskScheduler()
        
        assert scheduler.runner_id is not None
        assert ':' in scheduler.runner_id  # Format: hostname:pid
    
    def test_scheduler_clear_stale_locks(self, test_db):
        """Test that _clear_stale_locks clears old locks."""
        import admin
        
        conn = admin.get_db()
        cursor = conn.cursor()
        
        # Set up a stale lock
        stale_time = datetime.now() - timedelta(hours=3)
        cursor.execute('''
            UPDATE scheduled_tasks 
            SET running = 1, running_since = ?, runner_id = 'dead-worker'
            WHERE task_type = 'update_geo'
        ''', (stale_time,))
        conn.commit()
        conn.close()
        
        # Create scheduler and clear stale locks
        scheduler = admin.TaskScheduler()
        scheduler._clear_stale_locks()
        
        # Verify lock was cleared
        conn = admin.get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT running, runner_id FROM scheduled_tasks WHERE task_type = ?', ('update_geo',))
        result = cursor.fetchone()
        conn.close()
        
        assert result['running'] == 0
        assert result['runner_id'] is None
    
    def test_scheduler_does_not_clear_fresh_locks(self, test_db):
        """Test that _clear_stale_locks doesn't clear fresh locks."""
        import admin
        
        conn = admin.get_db()
        cursor = conn.cursor()
        
        # Set up a fresh lock (5 minutes old)
        fresh_time = datetime.now() - timedelta(minutes=5)
        cursor.execute('''
            UPDATE scheduled_tasks 
            SET running = 1, running_since = ?, runner_id = 'active-worker'
            WHERE task_type = 'update_geo'
        ''', (fresh_time,))
        conn.commit()
        conn.close()
        
        # Create scheduler and clear stale locks
        scheduler = admin.TaskScheduler()
        scheduler._clear_stale_locks()
        
        # Verify lock was NOT cleared
        conn = admin.get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT running, runner_id FROM scheduled_tasks WHERE task_type = ?', ('update_geo',))
        result = cursor.fetchone()
        conn.close()
        
        assert result['running'] == 1
        assert result['runner_id'] == 'active-worker'


class TestMultiWorkerProtection:
    """Tests for multi-worker scheduler protection (Issue #7)."""
    
    def test_concurrent_claim_attempts(self, test_db):
        """Test that only one worker can claim a task when multiple try simultaneously."""
        import admin
        
        conn = admin.get_db()
        cursor = conn.cursor()
        
        # Set up a task that's due to run
        now = datetime.now()
        past = now - timedelta(minutes=5)
        
        cursor.execute('''
            UPDATE scheduled_tasks 
            SET enabled = 1, next_run = ?, running = 0, runner_id = NULL
            WHERE task_type = 'update_geo'
        ''', (past,))
        conn.commit()
        conn.close()
        
        # Simulate multiple workers trying to claim
        successful_claims = []
        
        def try_claim(worker_id):
            conn = admin.get_db()
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE scheduled_tasks 
                SET running = 1, running_since = ?, runner_id = ?
                WHERE task_type = 'update_geo' AND running = 0
            ''', (datetime.now(), worker_id))
            conn.commit()
            if cursor.rowcount > 0:
                successful_claims.append(worker_id)
            conn.close()
        
        # Run claims in threads
        threads = []
        for i in range(5):
            t = threading.Thread(target=try_claim, args=(f'worker-{i}',))
            threads.append(t)
        
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # Only one worker should have successfully claimed
        assert len(successful_claims) == 1
    
    def test_runner_id_format(self, test_db):
        """Test that runner_id includes hostname and PID."""
        import admin
        import socket
        import os
        
        scheduler = admin.TaskScheduler()
        
        expected_prefix = socket.gethostname()
        expected_suffix = str(os.getpid())
        
        assert scheduler.runner_id.startswith(expected_prefix)
        assert scheduler.runner_id.endswith(expected_suffix)
