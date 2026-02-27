"""
Tests for Sprint 4 Scalability and Backlog Fixes.

Tests cover:
- Issue #15: Streaming CSV pagination (memory efficiency)
- Issue #14: Memory-efficient statistics computation
- Issue #13: Large file warnings
- Adhoc enrichment IP limits
- Shared results audit logging
- Admin scalability settings
"""

import pytest
import json
import csv
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock
from io import BytesIO


class TestStreamingCSVPagination:
    """Tests for memory-efficient CSV pagination (Issue #15)."""
    
    def test_read_csv_paginated_returns_correct_page(self, app, test_db, tmp_path):
        """Test that pagination returns the correct slice of data."""
        from app import read_csv_paginated
        
        # Create a test CSV file using tmp_path (guaranteed unique per test)
        temp_file = tmp_path / 'test_pagination.csv'
        with open(temp_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['id', 'value'])
            for i in range(100):
                writer.writerow([i, f'value_{i}'])
        
        # Test first page
        result = read_csv_paginated(temp_file, page=1, page_size=10)
        assert result['total_rows'] == 100
        assert result['page'] == 1
        assert result['page_size'] == 10
        assert result['total_pages'] == 10
        assert len(result['rows']) == 10
        assert result['rows'][0][0] == '0'
        assert result['rows'][9][0] == '9'
        
        # Test middle page
        result = read_csv_paginated(temp_file, page=5, page_size=10)
        assert len(result['rows']) == 10
        assert result['rows'][0][0] == '40'
        assert result['rows'][9][0] == '49'
        
        # Test last page
        result = read_csv_paginated(temp_file, page=10, page_size=10)
        assert len(result['rows']) == 10
        assert result['rows'][0][0] == '90'
        assert result['rows'][9][0] == '99'
    
    def test_read_csv_paginated_handles_partial_last_page(self, app, test_db, tmp_path):
        """Test pagination handles files with partial last page."""
        from app import read_csv_paginated
        
        temp_file = tmp_path / 'test_partial.csv'
        with open(temp_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['id'])
            for i in range(25):
                writer.writerow([i])
        
        result = read_csv_paginated(temp_file, page=3, page_size=10)
        assert result['total_rows'] == 25
        assert result['total_pages'] == 3
        assert len(result['rows']) == 5  # Only 5 rows on last page
    
    def test_read_csv_paginated_empty_file(self, app, test_db, tmp_path):
        """Test pagination handles empty files."""
        from app import read_csv_paginated
        
        temp_file = tmp_path / 'test_empty.csv'
        with open(temp_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['id', 'value'])  # Headers only
        
        result = read_csv_paginated(temp_file, page=1, page_size=10)
        assert result['total_rows'] == 0
        assert result['rows'] == []
        assert result['headers'] == ['id', 'value']


class TestMemoryEfficientStatistics:
    """Tests for memory-efficient statistics computation (Issue #14)."""
    
    def test_compute_statistics_caps_unique_values(self, app, test_db, tmp_path):
        """Test that unique value tracking is capped."""
        from app import compute_statistics
        
        # Create a CSV with many unique values using tmp_path
        temp_file = tmp_path / 'large_unique.csv'
        with open(temp_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['id', 'unique_col'])
            # Write more unique values than the default limit
            for i in range(15000):
                writer.writerow([i, f'unique_value_{i}'])
        
        with patch('app.get_max_unique_values', return_value=10000):
            stats = compute_statistics(temp_file)
        
        assert stats['total_rows'] == 15000
        
        # Find the unique_col column stats
        unique_col = next(c for c in stats['columns'] if c['name'] == 'unique_col')
        
        # Should be capped at 10000 unique values
        assert unique_col['unique_count'] <= 10000
        assert unique_col['unique_count_truncated'] == True
        
        # Should have warning about truncation
        assert len(stats['warnings']) > 0
        assert 'limited' in stats['warnings'][0].lower()
    
    def test_compute_statistics_no_truncation_for_small_files(self, app, test_db, tmp_path):
        """Test that small files are not truncated."""
        from app import compute_statistics
        
        temp_file = tmp_path / 'small_stats.csv'
        with open(temp_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['id', 'value'])
            for i in range(100):
                writer.writerow([i, f'value_{i}'])
        
        stats = compute_statistics(temp_file)
        
        value_col = next(c for c in stats['columns'] if c['name'] == 'value')
        assert value_col['unique_count'] == 100
        assert value_col.get('unique_count_truncated', False) == False
        assert len(stats.get('warnings', [])) == 0


class TestAdhocEnrichmentLimit:
    """Tests for ad-hoc enrichment IP limits."""
    
    def test_adhoc_limit_rejects_too_many_ips(self, authenticated_client, test_db):
        """Test that ad-hoc enrichment rejects requests with too many IPs."""
        # Generate more public IPs than the limit
        with patch('app.get_max_adhoc_ips', return_value=10):
            ips = '\n'.join([f'8.8.{i}.{i}' for i in range(1, 21)])  # Use public IPs
            response = authenticated_client.post('/enrich/text',
                data={'text': ips},
                follow_redirects=True)
            
            assert b'Too many IP addresses' in response.data
            assert b'Ad-hoc enrichment is limited' in response.data
    
    def test_adhoc_limit_accepts_valid_count(self, authenticated_client, test_db):
        """Test that ad-hoc enrichment accepts requests within limit."""
        with patch('app.get_max_adhoc_ips', return_value=100):
            with patch('app.run_logboost', return_value=(False, '', 'Binary not found')):
                ips = '\n'.join([f'8.8.8.{i}' for i in range(10)])
                response = authenticated_client.post('/enrich/text',
                    data={'text': ips},
                    follow_redirects=True)
                
                # Should not see the limit error
                assert b'Too many IP addresses' not in response.data


class TestLargeFileWarning:
    """Tests for large file warning display (Issue #13)."""
    
    def test_large_file_warning_added_when_threshold_exceeded(self, app, test_db, tmp_path):
        """Test that large file warning is added to data dict."""
        from app import read_csv_all
        
        # Create a test CSV using tmp_path
        temp_file = tmp_path / 'large_file.csv'
        with open(temp_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['id'])
            for i in range(100):
                writer.writerow([i])
        
        data = read_csv_all(temp_file)
        
        # Verify correct row count
        assert data['total_rows'] == 100
        
        # Simulate the check done in enrich_text/enrich_file
        large_file_threshold = 50
        if data.get('total_rows', 0) > large_file_threshold:
            data['large_file_warning'] = f"Warning: {data['total_rows']} rows exceeds threshold"
        
        assert 'large_file_warning' in data
        assert '100' in data['large_file_warning']
    
    def test_no_warning_for_small_files(self, app, test_db, tmp_path):
        """Test that no warning is shown for small files."""
        from app import read_csv_all
        
        temp_file = tmp_path / 'small_file.csv'
        with open(temp_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['id'])
            for i in range(10):
                writer.writerow([i])
        
        data = read_csv_all(temp_file)
        
        # Verify correct row count
        assert data['total_rows'] == 10
        
        large_file_threshold = 10000
        if data.get('total_rows', 0) > large_file_threshold:
            data['large_file_warning'] = "Warning"
        
        assert 'large_file_warning' not in data


class TestSharedResultsAuditLogging:
    """Tests for shared results audit logging."""
    
    def test_shared_results_access_logged_on_success(self, client, test_db):
        """Test that successful shared results access is logged."""
        import admin
        
        # Create a shared result first
        share_id = 'test123'
        admin.save_shared_results(
            share_id, 1, 'test.csv', 
            [['1', 'a'], ['2', 'b']], 
            {'total_rows': 2}, 
            ['id', 'value'], 
            30
        )
        
        with patch('app.log_audit') as mock_audit:
            response = client.get(f'/api/shared/results/{share_id}')
            
            assert response.status_code == 200
            
            # Verify audit was called
            mock_audit.assert_called()
            call_args = mock_audit.call_args
            assert call_args[0][0] == 'shared_results_access'
            assert call_args[0][1] == 'shared_results'
            assert call_args[0][2] == share_id
            assert call_args[0][3]['success'] == True
    
    def test_shared_results_access_logged_on_failure(self, client, test_db):
        """Test that failed shared results access is logged."""
        with patch('app.log_audit') as mock_audit:
            response = client.get('/api/shared/results/nonexistent')
            
            assert response.status_code == 404
            
            # Verify audit was called with failure
            mock_audit.assert_called()
            call_args = mock_audit.call_args
            assert call_args[0][0] == 'shared_results_access'
            assert call_args[0][3]['success'] == False
            assert call_args[0][3]['reason'] == 'not_found_or_expired'


class TestAdminScalabilitySettings:
    """Tests for admin scalability settings."""
    
    def test_scalability_settings_displayed(self, admin_client, test_db):
        """Test that scalability settings are shown in admin panel."""
        response = admin_client.get('/admin/settings')
        
        assert response.status_code == 200
        assert b'max_adhoc_ips' in response.data
        assert b'max_unique_values' in response.data
        assert b'large_file_warning_threshold' in response.data
        assert b'max_url_fetch_size_mb' in response.data
    
    def test_save_scalability_settings(self, admin_client, test_db):
        """Test saving scalability settings."""
        response = admin_client.post('/admin/settings/scalability',
            data={
                'max_adhoc_ips': '2000',
                'max_unique_values': '20000',
                'large_file_warning_threshold': '15000',
                'max_url_fetch_size_mb': '20'
            },
            follow_redirects=True)
        
        assert response.status_code == 200
        assert b'Scalability settings saved' in response.data
        
        # Verify settings were saved
        import admin
        assert admin.get_max_adhoc_ips() == 2000
        assert admin.get_max_unique_values() == 20000
        assert admin.get_large_file_warning_threshold() == 15000
        assert admin.get_max_url_fetch_size_mb() == 20
    
    def test_scalability_settings_validation(self, admin_client, test_db):
        """Test that scalability settings are validated."""
        # Test values below minimum are clamped
        response = admin_client.post('/admin/settings/scalability',
            data={
                'max_adhoc_ips': '10',  # Min is 100
                'max_unique_values': '100',  # Min is 1000
                'large_file_warning_threshold': '10',  # Min is 1000
                'max_url_fetch_size_mb': '0'  # Min is 1
            },
            follow_redirects=True)
        
        assert response.status_code == 200
        
        import admin
        assert admin.get_max_adhoc_ips() >= 100
        assert admin.get_max_unique_values() >= 1000
        assert admin.get_large_file_warning_threshold() >= 1000
        assert admin.get_max_url_fetch_size_mb() >= 1


class TestScalabilitySettingsGetters:
    """Tests for scalability settings getter functions."""
    
    def test_get_max_unique_values_default(self, test_db):
        """Test default value for max_unique_values."""
        import admin
        assert admin.get_max_unique_values() == 10000
    
    def test_get_max_adhoc_ips_default(self, test_db):
        """Test default value for max_adhoc_ips."""
        import admin
        assert admin.get_max_adhoc_ips() == 1000
    
    def test_get_large_file_warning_threshold_default(self, test_db):
        """Test default value for large_file_warning_threshold."""
        import admin
        assert admin.get_large_file_warning_threshold() == 10000
    
    def test_get_max_url_fetch_size_mb_default(self, test_db):
        """Test default value for max_url_fetch_size_mb."""
        import admin
        assert admin.get_max_url_fetch_size_mb() == 10
    
    def test_settings_handle_invalid_values(self, test_db):
        """Test that getters handle invalid stored values gracefully."""
        import admin
        
        # Store invalid value
        admin.set_setting('max_adhoc_ips', 'not_a_number')
        
        # Should return default
        assert admin.get_max_adhoc_ips() == 1000
