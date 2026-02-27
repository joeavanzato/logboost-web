"""
Tests for Graph API endpoints.

Tests cover:
- POST /api/graph/save - Save graph
- GET /api/graph/<graph_id> - Load graph
- DELETE /api/graph/<graph_id> - Delete graph
- GET /api/graph/list - List user's graphs
- GET /api/graph/export/<graph_id> - Export graph as JSON
- POST /api/graph/related - Find related infrastructure
"""

import pytest
import json
import uuid
from unittest.mock import patch, MagicMock


@pytest.fixture
def sample_graph_data():
    """Sample graph data for testing."""
    return {
        'nodes': [
            {'id': '8.8.8.8', 'type': 'ip', 'data': {'geo': {'country': 'US'}}},
            {'id': 'example.com', 'type': 'domain', 'data': {}},
            {'id': 'AS15169', 'type': 'asn', 'data': {'asn_name': 'GOOGLE'}}
        ],
        'edges': [
            {'source': '8.8.8.8', 'target': 'example.com', 'type': 'resolves_to'},
            {'source': '8.8.8.8', 'target': 'AS15169', 'type': 'belongs_to'}
        ]
    }


class TestGraphSaveApi:
    """Tests for POST /api/graph/save endpoint."""
    
    def test_graph_save_requires_auth(self, client, sample_graph_data):
        """Test that endpoint requires authentication."""
        response = client.post('/api/graph/save',
                              json={'name': 'Test Graph', 'data': sample_graph_data})
        assert response.status_code in (302, 401, 403)
    
    def test_graph_save_no_json(self, authenticated_client):
        """Test error when no JSON provided."""
        response = authenticated_client.post('/api/graph/save',
                                             data='not json',
                                             content_type='application/json')
        assert response.status_code == 400
    
    def test_graph_save_new_graph(self, authenticated_client, sample_graph_data):
        """Test saving a new graph without ID."""
        with patch('app.save_graph', return_value=True) as mock_save:
            with patch('app.log_audit'):
                response = authenticated_client.post('/api/graph/save',
                                                     json={'name': 'Test Graph', 'data': sample_graph_data})
                assert response.status_code == 200
                data = json.loads(response.data)
                assert data['success'] == True
                assert 'id' in data
                # New ID should be a UUID
                assert len(data['id']) > 20
                mock_save.assert_called_once()
    
    def test_graph_save_existing_graph_owned(self, authenticated_client, sample_graph_data):
        """Test updating an existing owned graph."""
        graph_id = str(uuid.uuid4())
        
        with patch('app.save_graph', return_value=True) as mock_save:
            with patch('app.log_audit'):
                response = authenticated_client.post('/api/graph/save',
                                                     json={'id': graph_id, 'name': 'Updated Graph', 'data': sample_graph_data})
                assert response.status_code == 200
                data = json.loads(response.data)
                assert data['success'] == True
                assert data['id'] == graph_id
    
    def test_graph_save_existing_graph_not_owned(self, authenticated_client, sample_graph_data):
        """Test saving a graph when user doesn't own the existing one creates new."""
        graph_id = str(uuid.uuid4())
        
        # First save returns False (not owner), second returns True (new graph)
        with patch('app.save_graph', side_effect=[False, True]) as mock_save:
            with patch('app.log_audit'):
                response = authenticated_client.post('/api/graph/save',
                                                     json={'id': graph_id, 'name': 'My Copy', 'data': sample_graph_data})
                assert response.status_code == 200
                data = json.loads(response.data)
                assert data['success'] == True
                # Should get a new ID, not the original
                assert data['id'] != graph_id
    
    def test_graph_save_force_new(self, authenticated_client, sample_graph_data):
        """Test force_new flag creates new graph even with existing ID."""
        graph_id = str(uuid.uuid4())
        
        with patch('app.save_graph', return_value=True) as mock_save:
            with patch('app.log_audit'):
                response = authenticated_client.post('/api/graph/save',
                                                     json={'id': graph_id, 'name': 'New Copy', 
                                                           'data': sample_graph_data, 'force_new': True})
                assert response.status_code == 200
                data = json.loads(response.data)
                # force_new should create new graph with new ID
                assert data['id'] != graph_id
    
    def test_graph_save_default_name(self, authenticated_client, sample_graph_data):
        """Test that default name is used when not provided."""
        with patch('app.save_graph', return_value=True) as mock_save:
            with patch('app.log_audit'):
                response = authenticated_client.post('/api/graph/save',
                                                     json={'data': sample_graph_data})
                assert response.status_code == 200
                # Check that save_graph was called with default name
                call_args = mock_save.call_args
                assert call_args[0][1] == 'Untitled Graph'
    
    def test_graph_save_logs_audit_created(self, authenticated_client, sample_graph_data):
        """Test audit logging for new graph creation."""
        with patch('app.save_graph', return_value=True):
            with patch('app.log_audit') as mock_audit:
                response = authenticated_client.post('/api/graph/save',
                                                     json={'name': 'Test Graph', 'data': sample_graph_data})
                assert response.status_code == 200
                mock_audit.assert_called_once()
                call_args = mock_audit.call_args
                assert call_args[0][0] == 'graph_created'
    
    def test_graph_save_logs_audit_updated(self, authenticated_client, sample_graph_data):
        """Test audit logging for graph update."""
        graph_id = str(uuid.uuid4())
        
        with patch('app.save_graph', return_value=True):
            with patch('app.log_audit') as mock_audit:
                response = authenticated_client.post('/api/graph/save',
                                                     json={'id': graph_id, 'name': 'Updated', 'data': sample_graph_data})
                assert response.status_code == 200
                mock_audit.assert_called_once()
                call_args = mock_audit.call_args
                assert call_args[0][0] == 'graph_updated'


class TestGraphLoadApi:
    """Tests for GET /api/graph/<graph_id> endpoint."""
    
    def test_graph_load_requires_auth(self, client):
        """Test that endpoint requires authentication."""
        graph_id = str(uuid.uuid4())
        response = client.get(f'/api/graph/{graph_id}')
        assert response.status_code in (302, 401, 403)
    
    def test_graph_load_existing(self, authenticated_client, sample_graph_data):
        """Test loading an existing graph."""
        graph_id = str(uuid.uuid4())
        mock_graph = {
            'id': graph_id,
            'name': 'Test Graph',
            'data': sample_graph_data,
            'user_id': 1
        }
        
        with patch('app.load_graph', return_value=mock_graph):
            response = authenticated_client.get(f'/api/graph/{graph_id}')
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data['id'] == graph_id
            assert data['name'] == 'Test Graph'
    
    def test_graph_load_not_found(self, authenticated_client):
        """Test loading a non-existent graph."""
        graph_id = str(uuid.uuid4())
        
        with patch('app.load_graph', return_value=None):
            response = authenticated_client.get(f'/api/graph/{graph_id}')
            assert response.status_code == 404
            data = json.loads(response.data)
            assert 'error' in data
    
    def test_graph_load_includes_ownership_flag_owner(self, authenticated_client, sample_graph_data):
        """Test that is_owner flag is True for owner."""
        graph_id = str(uuid.uuid4())
        
        # Get the user_id from the session
        with authenticated_client.session_transaction() as sess:
            user_id = sess.get('user_id')
        
        mock_graph = {
            'id': graph_id,
            'name': 'My Graph',
            'data': sample_graph_data,
            'user_id': user_id  # Match the authenticated user's ID
        }
        
        with patch('app.load_graph', return_value=mock_graph):
            response = authenticated_client.get(f'/api/graph/{graph_id}')
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data['is_owner'] == True
    
    def test_graph_load_includes_ownership_flag_not_owner(self, authenticated_client, sample_graph_data):
        """Test that is_owner flag is False for non-owner."""
        graph_id = str(uuid.uuid4())
        mock_graph = {
            'id': graph_id,
            'name': 'Other Graph',
            'data': sample_graph_data,
            'user_id': 999  # Different user
        }
        
        with patch('app.load_graph', return_value=mock_graph):
            response = authenticated_client.get(f'/api/graph/{graph_id}')
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data['is_owner'] == False
    
    def test_graph_load_null_user_id_is_owner(self, authenticated_client, sample_graph_data):
        """Test that graph with null user_id is considered owned."""
        graph_id = str(uuid.uuid4())
        mock_graph = {
            'id': graph_id,
            'name': 'Legacy Graph',
            'data': sample_graph_data,
            'user_id': None
        }
        
        with patch('app.load_graph', return_value=mock_graph):
            response = authenticated_client.get(f'/api/graph/{graph_id}')
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data['is_owner'] == True


class TestGraphDeleteApi:
    """Tests for DELETE /api/graph/<graph_id> endpoint."""
    
    def test_graph_delete_requires_auth(self, client):
        """Test that endpoint requires authentication."""
        graph_id = str(uuid.uuid4())
        response = client.delete(f'/api/graph/{graph_id}')
        assert response.status_code in (302, 401, 403)
    
    def test_graph_delete_success(self, authenticated_client):
        """Test successful graph deletion."""
        graph_id = str(uuid.uuid4())
        
        with patch('app.delete_graph', return_value=True) as mock_delete:
            with patch('app.log_audit'):
                response = authenticated_client.delete(f'/api/graph/{graph_id}')
                assert response.status_code == 200
                data = json.loads(response.data)
                assert data['success'] == True
                mock_delete.assert_called_once()
    
    def test_graph_delete_not_found_or_unauthorized(self, authenticated_client):
        """Test deletion of non-existent or unauthorized graph."""
        graph_id = str(uuid.uuid4())
        
        with patch('app.delete_graph', return_value=False):
            response = authenticated_client.delete(f'/api/graph/{graph_id}')
            assert response.status_code == 404
            data = json.loads(response.data)
            assert 'error' in data
    
    def test_graph_delete_logs_audit(self, authenticated_client):
        """Test that deletion is logged to audit."""
        graph_id = str(uuid.uuid4())
        
        with patch('app.delete_graph', return_value=True):
            with patch('app.log_audit') as mock_audit:
                response = authenticated_client.delete(f'/api/graph/{graph_id}')
                assert response.status_code == 200
                mock_audit.assert_called_once()
                call_args = mock_audit.call_args
                assert call_args[0][0] == 'graph_deleted'
                assert call_args[0][2] == graph_id


class TestGraphListApi:
    """Tests for GET /api/graph/list endpoint."""
    
    def test_graph_list_requires_auth(self, client):
        """Test that endpoint requires authentication."""
        response = client.get('/api/graph/list')
        assert response.status_code in (302, 401, 403)
    
    def test_graph_list_empty(self, authenticated_client):
        """Test listing graphs when user has none."""
        with patch('app.list_graphs', return_value=[]):
            response = authenticated_client.get('/api/graph/list')
            assert response.status_code == 200
            data = json.loads(response.data)
            assert 'graphs' in data
            assert data['graphs'] == []
    
    def test_graph_list_returns_user_graphs(self, authenticated_client):
        """Test listing user's saved graphs."""
        mock_graphs = [
            {'id': str(uuid.uuid4()), 'name': 'Graph 1', 'updated_at': '2024-01-01'},
            {'id': str(uuid.uuid4()), 'name': 'Graph 2', 'updated_at': '2024-01-02'},
            {'id': str(uuid.uuid4()), 'name': 'Graph 3', 'updated_at': '2024-01-03'}
        ]
        
        with patch('app.list_graphs', return_value=mock_graphs) as mock_list:
            response = authenticated_client.get('/api/graph/list')
            assert response.status_code == 200
            data = json.loads(response.data)
            assert len(data['graphs']) == 3
            mock_list.assert_called_once()
    
    def test_graph_list_passes_user_id(self, authenticated_client):
        """Test that user_id is passed to list_graphs."""
        with patch('app.list_graphs', return_value=[]) as mock_list:
            response = authenticated_client.get('/api/graph/list')
            assert response.status_code == 200
            # Should be called with user_id from session
            mock_list.assert_called_once()
            call_args = mock_list.call_args
            assert call_args[0][0] is not None  # user_id should be passed


class TestGraphExportApi:
    """Tests for GET /api/graph/export/<graph_id> endpoint."""
    
    def test_graph_export_requires_auth(self, client):
        """Test that endpoint requires authentication."""
        graph_id = str(uuid.uuid4())
        response = client.get(f'/api/graph/export/{graph_id}')
        assert response.status_code in (302, 401, 403)
    
    def test_graph_export_success(self, authenticated_client, sample_graph_data):
        """Test successful graph export."""
        graph_id = str(uuid.uuid4())
        mock_graph = {
            'id': graph_id,
            'name': 'Export Test',
            'data': sample_graph_data
        }
        
        with patch('app.load_graph', return_value=mock_graph):
            response = authenticated_client.get(f'/api/graph/export/{graph_id}')
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data['id'] == graph_id
    
    def test_graph_export_not_found(self, authenticated_client):
        """Test export of non-existent graph."""
        graph_id = str(uuid.uuid4())
        
        with patch('app.load_graph', return_value=None):
            response = authenticated_client.get(f'/api/graph/export/{graph_id}')
            assert response.status_code == 404
    
    def test_graph_export_has_attachment_header(self, authenticated_client, sample_graph_data):
        """Test that export has Content-Disposition header."""
        graph_id = str(uuid.uuid4())
        mock_graph = {
            'id': graph_id,
            'name': 'Export Test',
            'data': sample_graph_data
        }
        
        with patch('app.load_graph', return_value=mock_graph):
            response = authenticated_client.get(f'/api/graph/export/{graph_id}')
            assert response.status_code == 200
            assert 'Content-Disposition' in response.headers
            assert 'attachment' in response.headers['Content-Disposition']
            assert graph_id in response.headers['Content-Disposition']


class TestGraphRelatedApi:
    """Tests for POST /api/graph/related endpoint."""
    
    def test_graph_related_requires_auth(self, client):
        """Test that endpoint requires authentication."""
        response = client.post('/api/graph/related',
                              json={'value': '8.8.8.8', 'type': 'ip'})
        assert response.status_code in (302, 401, 403)
    
    def test_graph_related_no_json(self, authenticated_client):
        """Test error when no JSON provided."""
        response = authenticated_client.post('/api/graph/related',
                                             data='not json',
                                             content_type='application/json')
        assert response.status_code == 400
    
    def test_graph_related_no_session_data(self, authenticated_client):
        """Test related returns empty when no enrichment data."""
        response = authenticated_client.post('/api/graph/related',
                                             json={'value': '8.8.8.8', 'type': 'ip'})
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'ips' in data
        assert 'domains' in data
        assert data['ips'] == []
        assert data['domains'] == []
    
    def test_graph_related_returns_structure(self, authenticated_client):
        """Test that related returns expected structure."""
        response = authenticated_client.post('/api/graph/related',
                                             json={'value': 'example.com', 'type': 'domain'})
        assert response.status_code == 200
        data = json.loads(response.data)
        
        # Check expected keys
        assert 'ips' in data
        assert 'domains' in data
        assert 'tlds' in data
        assert 'asns' in data
        assert 'countries' in data
        assert 'geo_data' in data
        assert 'sources' in data
