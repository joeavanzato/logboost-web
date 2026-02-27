"""
Tests for Results Sharing API endpoints.

Tests cover:
- POST /api/results/share - Create shared results link
- GET /api/shared/results/<share_id> - Get shared results data
- GET /api/shared/results/<share_id>/render - Render shared results as HTML
- GET /shared/results/<share_id> - View shared results page
"""

import pytest
import json
import os
import tempfile
from unittest.mock import patch, MagicMock


class TestResultsShareApi:
    """Tests for POST /api/results/share endpoint."""
    
    def test_results_share_requires_auth(self, client):
        """Test that endpoint requires authentication."""
        response = client.post('/api/results/share')
        assert response.status_code in (302, 401, 403)
    
    def test_results_share_no_results(self, authenticated_client):
        """Test error when no results to share."""
        # No current_output in session
        response = authenticated_client.post('/api/results/share')
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'No results to share' in data['error']
    
    def test_results_share_file_not_exists(self, authenticated_client, app):
        """Test error when results file doesn't exist."""
        with authenticated_client.session_transaction() as sess:
            sess['current_output'] = '/nonexistent/file.csv'
        
        response = authenticated_client.post('/api/results/share')
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'No results to share' in data['error']
    
    def test_results_share_success(self, authenticated_client, app, tmp_path):
        """Test successful results sharing."""
        # Create a temp CSV file
        csv_file = tmp_path / "results.csv"
        csv_file.write_text("ip,domain\n8.8.8.8,example.com\n1.1.1.1,test.org\n")
        
        with authenticated_client.session_transaction() as sess:
            sess['current_output'] = str(csv_file)
            sess['current_stats'] = {'total_ips': 2}
        
        with patch('app.save_shared_results') as mock_save:
            with patch('app.get_shared_results_expiry_days', return_value=30):
                response = authenticated_client.post('/api/results/share')
                assert response.status_code == 200
                data = json.loads(response.data)
                assert data['success'] == True
                assert 'share_id' in data
                assert 'share_url' in data
                assert 'expires_in_days' in data
                mock_save.assert_called_once()
    
    def test_results_share_generates_short_id(self, authenticated_client, app, tmp_path):
        """Test that share ID is short (12 chars)."""
        csv_file = tmp_path / "results.csv"
        csv_file.write_text("ip\n8.8.8.8\n")
        
        with authenticated_client.session_transaction() as sess:
            sess['current_output'] = str(csv_file)
        
        with patch('app.save_shared_results'):
            with patch('app.get_shared_results_expiry_days', return_value=30):
                response = authenticated_client.post('/api/results/share')
                assert response.status_code == 200
                data = json.loads(response.data)
                assert len(data['share_id']) == 12
    
    def test_results_share_empty_data(self, authenticated_client, app, tmp_path):
        """Test error when results file is empty (only headers)."""
        csv_file = tmp_path / "results.csv"
        csv_file.write_text("ip,domain\n")  # Only headers, no data
        
        with authenticated_client.session_transaction() as sess:
            sess['current_output'] = str(csv_file)
        
        response = authenticated_client.post('/api/results/share')
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'No data' in data['error']
    
    def test_results_share_read_error(self, authenticated_client, app, tmp_path):
        """Test error handling when file read fails."""
        csv_file = tmp_path / "results.csv"
        csv_file.write_text("ip\n8.8.8.8\n")
        
        with authenticated_client.session_transaction() as sess:
            sess['current_output'] = str(csv_file)
        
        with patch('builtins.open', side_effect=Exception('Read error')):
            response = authenticated_client.post('/api/results/share')
            assert response.status_code == 500
            data = json.loads(response.data)
            assert 'Failed to read' in data['error']


class TestSharedResultsApi:
    """Tests for GET /api/shared/results/<share_id> endpoint."""
    
    def test_shared_results_get_success(self, client):
        """Test getting shared results data."""
        mock_shared = {
            'filename': 'results.csv',
            'headers': ['ip', 'domain'],
            'results_data': [['8.8.8.8', 'example.com']],
            'stats_data': {'total_ips': 1},
            'created_at': '2024-01-01 00:00:00',
            'expires_at': '2024-01-31 00:00:00'
        }
        
        with patch('app.get_shared_results', return_value=mock_shared):
            response = client.get('/api/shared/results/abc123')
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data['success'] == True
            assert data['id'] == 'abc123'
            assert data['filename'] == 'results.csv'
            assert 'headers' in data
            assert 'results' in data
            assert 'stats' in data
    
    def test_shared_results_not_found(self, client):
        """Test getting non-existent shared results."""
        with patch('app.get_shared_results', return_value=None):
            response = client.get('/api/shared/results/nonexistent')
            assert response.status_code == 404
            data = json.loads(response.data)
            assert 'error' in data
            assert 'not found' in data['error'].lower() or 'expired' in data['error'].lower()
    
    def test_shared_results_no_auth_required(self, client):
        """Test that shared results don't require authentication."""
        mock_shared = {
            'filename': 'results.csv',
            'headers': ['ip'],
            'results_data': [['8.8.8.8']],
            'stats_data': None,
            'created_at': '2024-01-01 00:00:00',
            'expires_at': '2024-01-31 00:00:00'
        }
        
        with patch('app.get_shared_results', return_value=mock_shared):
            # Using unauthenticated client
            response = client.get('/api/shared/results/abc123')
            assert response.status_code == 200


class TestSharedResultsRenderApi:
    """Tests for GET /api/shared/results/<share_id>/render endpoint."""
    
    def test_shared_results_render_success(self, client):
        """Test rendering shared results as HTML."""
        mock_shared = {
            'filename': 'results.csv',
            'headers': ['ip', 'domain'],
            'results_data': [['8.8.8.8', 'example.com']],
            'stats_data': {'total_ips': 1},
            'created_at': '2024-01-01 00:00:00',
            'expires_at': '2024-01-31 00:00:00'
        }
        
        with patch('app.get_shared_results', return_value=mock_shared):
            response = client.get('/api/shared/results/abc123/render')
            assert response.status_code == 200
            # Should return HTML
            assert b'<!DOCTYPE html>' in response.data or b'<' in response.data
    
    def test_shared_results_render_not_found(self, client):
        """Test rendering non-existent shared results."""
        with patch('app.get_shared_results', return_value=None):
            response = client.get('/api/shared/results/nonexistent/render')
            assert response.status_code == 404
    
    def test_shared_results_render_no_auth_required(self, client):
        """Test that render endpoint doesn't require authentication."""
        mock_shared = {
            'filename': 'results.csv',
            'headers': ['ip'],
            'results_data': [['8.8.8.8']],
            'stats_data': None,
            'created_at': '2024-01-01 00:00:00',
            'expires_at': '2024-01-31 00:00:00'
        }
        
        with patch('app.get_shared_results', return_value=mock_shared):
            response = client.get('/api/shared/results/abc123/render')
            assert response.status_code == 200


class TestViewSharedResults:
    """Tests for GET /shared/results/<share_id> endpoint."""
    
    def test_view_shared_results_success(self, client):
        """Test viewing shared results page redirects to main page."""
        mock_shared = {
            'filename': 'results.csv',
            'headers': ['ip'],
            'results_data': [['8.8.8.8']],
            'stats_data': None,
            'created_at': '2024-01-01 00:00:00',
            'expires_at': '2024-01-31 00:00:00'
        }
        
        with patch('app.get_shared_results', return_value=mock_shared):
            response = client.get('/shared/results/abc123')
            # Should redirect
            assert response.status_code == 302
            assert 'shared=abc123' in response.location
    
    def test_view_shared_results_not_found(self, client):
        """Test viewing non-existent shared results."""
        with patch('app.get_shared_results', return_value=None):
            response = client.get('/shared/results/nonexistent')
            assert response.status_code == 404
    
    def test_view_shared_results_no_auth_required(self, client):
        """Test that viewing shared results doesn't require authentication."""
        mock_shared = {
            'filename': 'results.csv',
            'headers': ['ip'],
            'results_data': [['8.8.8.8']],
            'stats_data': None,
            'created_at': '2024-01-01 00:00:00',
            'expires_at': '2024-01-31 00:00:00'
        }
        
        with patch('app.get_shared_results', return_value=mock_shared):
            response = client.get('/shared/results/abc123')
            # Should redirect (not require login)
            assert response.status_code == 302
