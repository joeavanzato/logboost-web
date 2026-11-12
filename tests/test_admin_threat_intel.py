"""
Tests for Threat Intelligence and Setup Management.

Tests cover:
- Threat Intel feed management
- Setup status and paths
"""

import pytest
import json
import os
import tempfile
from unittest.mock import patch, MagicMock


@pytest.fixture
def mock_feed_config(tmp_path, monkeypatch):
    """Create a mock feed_config.json file."""
    feed_config = tmp_path / 'feed_config.json'
    feeds = {
        'feeds': [
            {'name': 'Test Feed 1', 'url': 'https://example.com/feed1.txt', 
             'type': ['malware', 'c2'], 'enabled': True},
            {'name': 'Test Feed 2', 'url': 'https://example.com/feed2.csv', 
             'type': ['suspicious'], 'enabled': False}
        ]
    }
    feed_config.write_text(json.dumps(feeds, indent=2))
    import admin
    monkeypatch.setattr(admin, 'FEED_CONFIG_PATH', str(feed_config))
    return feed_config


class TestThreatIntelPage:
    """Tests for threat intel page."""
    
    def test_threat_intel_page_no_logboost_path(self, admin_client, test_db):
        """Test threat intel page when LogBoost path not configured."""
        response = admin_client.get('/admin/threat-intel')
        assert response.status_code == 200
    
    def test_threat_intel_page_with_config(self, admin_client, test_db, mock_feed_config):
        """Test threat intel page with valid config."""
        import admin
        admin.set_setting('logboost_path', str(mock_feed_config.parent))
        response = admin_client.get('/admin/threat-intel')
        assert response.status_code == 200


class TestGetFeedsApi:
    """Tests for GET /admin/api/threat-intel/feeds endpoint."""
    
    def test_get_feeds_no_config_file(self, admin_client, test_db):
        """Test get feeds when config file doesn't exist."""
        import admin
        admin.set_setting('logboost_path', '/nonexistent/path')
        response = admin_client.get('/admin/api/threat-intel/feeds')
        assert response.status_code == 404
    
    def test_get_feeds_success(self, admin_client, test_db, mock_feed_config):
        """Test successful feed retrieval."""
        import admin
        admin.set_setting('logboost_path', str(mock_feed_config.parent))
        response = admin_client.get('/admin/api/threat-intel/feeds')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'feeds' in data
        assert len(data['feeds']) == 2


class TestSaveFeedsApi:
    """Tests for POST /admin/api/threat-intel/feeds endpoint."""
    
    def test_save_feeds_no_logboost_path(self, admin_client, test_db):
        """Test save feeds when LogBoost path not configured."""
        response = admin_client.post('/admin/api/threat-intel/feeds', json={'feeds': []})
        assert response.status_code == 400
    
    def test_save_feeds_missing_name(self, admin_client, test_db, mock_feed_config):
        """Test save feeds with missing name."""
        import admin
        admin.set_setting('logboost_path', str(mock_feed_config.parent))
        response = admin_client.post('/admin/api/threat-intel/feeds',
            json={'feeds': [{'url': 'http://example.com'}]})
        assert response.status_code == 400
    
    def test_save_feeds_missing_url(self, admin_client, test_db, mock_feed_config):
        """Test save feeds with missing URL."""
        import admin
        admin.set_setting('logboost_path', str(mock_feed_config.parent))
        response = admin_client.post('/admin/api/threat-intel/feeds',
            json={'feeds': [{'name': 'Test'}]})
        assert response.status_code == 400
    
    def test_save_feeds_success(self, admin_client, test_db, mock_feed_config):
        """Test successful feed save."""
        import admin
        admin.set_setting('logboost_path', str(mock_feed_config.parent))
        new_feeds = [{'name': 'New Feed', 'url': 'https://example.com/new.txt', 
                      'type': ['phishing'], 'enabled': True}]
        with patch('admin.log_audit'):
            response = admin_client.post('/admin/api/threat-intel/feeds',
                json={'feeds': new_feeds})
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] == True


class TestUpdateFeedApi:
    """Tests for PUT /admin/api/threat-intel/feed/<index> endpoint."""
    
    def test_update_feed_no_config(self, admin_client, test_db):
        """Test update when config doesn't exist."""
        import admin
        admin.set_setting('logboost_path', '/nonexistent')
        response = admin_client.put('/admin/api/threat-intel/feed/0',
            json={'name': 'Updated'})
        assert response.status_code == 404


class TestDeleteFeedApi:
    """Tests for DELETE /admin/api/threat-intel/feed/<index> endpoint."""
    
    def test_delete_feed_no_config(self, admin_client, test_db):
        """Test delete when config doesn't exist."""
        import admin
        admin.set_setting('logboost_path', '/nonexistent')
        response = admin_client.delete('/admin/api/threat-intel/feed/0')
        assert response.status_code == 404


class TestAddFeedApi:
    """Tests for POST /admin/api/threat-intel/feed endpoint."""
    
    def test_add_feed_no_logboost_path(self, admin_client, test_db):
        """Test add feed when LogBoost path not configured."""
        response = admin_client.post('/admin/api/threat-intel/feed',
            json={'name': 'Test', 'url': 'http://test.com'})
        assert response.status_code in (400, 404)
    
    def test_add_feed_missing_fields(self, admin_client, test_db, mock_feed_config):
        """Test add feed with missing fields."""
        import admin
        admin.set_setting('logboost_path', str(mock_feed_config.parent))
        response = admin_client.post('/admin/api/threat-intel/feed',
            json={'name': 'Test'})  # Missing URL
        assert response.status_code == 400


class TestSetupPage:
    """Tests for setup page."""
    
    def test_setup_page_loads(self, admin_client, test_db):
        """Test that setup page loads for admin."""
        response = admin_client.get('/admin/setup')
        assert response.status_code == 200


class TestTasksPage:
    """Tests for tasks page."""
    
    def test_tasks_page_loads(self, admin_client, test_db):
        """Test that tasks page loads for admin."""
        response = admin_client.get('/admin/tasks')
        assert response.status_code == 200


class TestTaskScheduler:
    """Tests for TaskScheduler class."""
    
    def test_task_scheduler_init(self, test_db):
        """Test TaskScheduler initialization."""
        import admin
        scheduler = admin.TaskScheduler()
        assert scheduler is not None


class TestSharingSetting:
    """Tests for sharing settings endpoint."""
    
    def test_save_sharing_success(self, admin_client, test_db):
        """Test successful sharing settings save."""
        with patch('admin.log_audit'):
            response = admin_client.post('/admin/settings/sharing',
                data={'sharing_expiry_days': '14'},
                follow_redirects=False)
        assert response.status_code == 302


class TestShodanPivotSettings:
    """Tests for Shodan pivot settings endpoint."""
    
    def test_save_shodan_pivot_success(self, admin_client, test_db):
        """Test successful Shodan pivot settings save."""
        with patch('admin.log_audit'):
            response = admin_client.post('/admin/settings/shodan-pivot',
                data={'shodan_pivot_limit': '200'},
                follow_redirects=False)
        assert response.status_code == 302
        import admin
        limit = admin.get_shodan_pivot_limit()
        assert limit == 200
