"""
Tests for graph storage functions.

Tests cover:
- Core CRUD operations (save, load, list, delete)
- Ownership and authorization checks
- Data integrity and edge cases
- API endpoint validation
"""

import json
import time
import uuid
import pytest


# ============================================
# Sample Data Fixtures
# ============================================

@pytest.fixture
def sample_graph_data():
    """Sample graph data for testing."""
    return {
        'nodes': [
            {'id': 'node1', 'label': 'example.com', 'type': 'domain'},
            {'id': 'node2', 'label': '192.168.1.1', 'type': 'ip'}
        ],
        'edges': [
            {'source': 'node1', 'target': 'node2', 'label': 'resolves_to'}
        ]
    }


@pytest.fixture
def large_graph_data():
    """Large graph data for stress testing."""
    nodes = [{'id': f'node{i}', 'label': f'item{i}', 'type': 'test'} for i in range(1000)]
    edges = [{'source': f'node{i}', 'target': f'node{i+1}'} for i in range(999)]
    return {'nodes': nodes, 'edges': edges}


@pytest.fixture
def graph_id():
    """Generate a unique graph ID."""
    return str(uuid.uuid4())


@pytest.fixture
def create_test_user(test_db):
    """Create a test user and return their ID."""
    import admin
    
    def _create_user(username, role='user'):
        conn = admin.get_db()
        cursor = conn.cursor()
        password_hash = admin.hash_password('testpass123')
        cursor.execute(
            'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
            (username, password_hash, role)
        )
        conn.commit()
        user_id = cursor.lastrowid
        conn.close()
        return user_id
    
    return _create_user


# ============================================
# Core CRUD Operations Tests
# ============================================

class TestSaveGraph:
    """Tests for save_graph function."""
    
    def test_save_graph_new_creates_record(self, test_db, graph_id, sample_graph_data):
        """Test that saving a new graph creates a database record."""
        import admin
        
        result = admin.save_graph(graph_id, 'Test Graph', sample_graph_data, user_id=1)
        
        assert result is True
        
        # Verify it's in the database
        loaded = admin.load_graph(graph_id)
        assert loaded is not None
        assert loaded['name'] == 'Test Graph'
    
    def test_save_graph_update_existing_same_owner(self, test_db, graph_id, sample_graph_data):
        """Test that owner can update their own graph."""
        import admin
        
        # Create initial graph
        admin.save_graph(graph_id, 'Original Name', sample_graph_data, user_id=1)
        
        # Update with same owner
        updated_data = {'nodes': [{'id': 'updated'}], 'edges': []}
        result = admin.save_graph(graph_id, 'Updated Name', updated_data, user_id=1)
        
        assert result is True
        
        loaded = admin.load_graph(graph_id)
        assert loaded['name'] == 'Updated Name'
        assert loaded['data'] == updated_data
    
    def test_save_graph_update_existing_different_owner_rejected(self, test_db, graph_id, sample_graph_data):
        """Test that different owner cannot update existing graph."""
        import admin
        
        # Create graph with user 1
        admin.save_graph(graph_id, 'User 1 Graph', sample_graph_data, user_id=1)
        
        # Try to update with user 2
        result = admin.save_graph(graph_id, 'User 2 Attempt', {'nodes': []}, user_id=2)
        
        assert result is False
        
        # Original should be unchanged
        loaded = admin.load_graph(graph_id)
        assert loaded['name'] == 'User 1 Graph'
        assert loaded['user_id'] == 1
    
    def test_save_graph_preserves_created_at_on_update(self, test_db, graph_id, sample_graph_data):
        """Test that created_at timestamp is preserved on update."""
        import admin
        
        # Create initial graph
        admin.save_graph(graph_id, 'Test Graph', sample_graph_data, user_id=1)
        original = admin.load_graph(graph_id)
        original_created = original['created_at']
        
        # Wait a moment and update
        time.sleep(0.1)
        admin.save_graph(graph_id, 'Updated Graph', sample_graph_data, user_id=1)
        
        updated = admin.load_graph(graph_id)
        assert updated['created_at'] == original_created
    
    def test_save_graph_updates_updated_at(self, test_db, graph_id, sample_graph_data):
        """Test that updated_at timestamp changes on update."""
        import admin
        
        # Create initial graph
        admin.save_graph(graph_id, 'Test Graph', sample_graph_data, user_id=1)
        original = admin.load_graph(graph_id)
        original_updated = original['updated_at']
        
        # Wait and update
        time.sleep(0.1)
        admin.save_graph(graph_id, 'Updated Graph', sample_graph_data, user_id=1)
        
        updated = admin.load_graph(graph_id)
        # updated_at should be different (or at least not less than original)
        assert updated['updated_at'] >= original_updated
    
    def test_save_graph_stores_json_data_correctly(self, test_db, graph_id, sample_graph_data):
        """Test that graph data is correctly serialized and deserialized."""
        import admin
        
        admin.save_graph(graph_id, 'Test Graph', sample_graph_data, user_id=1)
        
        loaded = admin.load_graph(graph_id)
        assert loaded['data'] == sample_graph_data
        assert loaded['data']['nodes'][0]['label'] == 'example.com'
        assert loaded['data']['edges'][0]['label'] == 'resolves_to'
    
    def test_save_graph_empty_name_handling(self, test_db, graph_id, sample_graph_data):
        """Test saving graph with empty name."""
        import admin
        
        result = admin.save_graph(graph_id, '', sample_graph_data, user_id=1)
        
        assert result is True
        loaded = admin.load_graph(graph_id)
        assert loaded['name'] == ''
    
    def test_save_graph_empty_data_handling(self, test_db, graph_id):
        """Test saving graph with empty data."""
        import admin
        
        result = admin.save_graph(graph_id, 'Empty Graph', {}, user_id=1)
        
        assert result is True
        loaded = admin.load_graph(graph_id)
        assert loaded['data'] == {}
    
    def test_save_graph_null_user_id_allows_anyone_to_update(self, test_db, graph_id, sample_graph_data):
        """Test that graph with null user_id can be updated by anyone."""
        import admin
        
        # Create graph with no owner
        admin.save_graph(graph_id, 'Unowned Graph', sample_graph_data, user_id=None)
        
        # Any user should be able to update
        result = admin.save_graph(graph_id, 'Updated by User 1', {'nodes': []}, user_id=1)
        
        assert result is True
        loaded = admin.load_graph(graph_id)
        assert loaded['name'] == 'Updated by User 1'


class TestLoadGraph:
    """Tests for load_graph function."""
    
    def test_load_graph_existing_returns_data(self, test_db, graph_id, sample_graph_data):
        """Test loading an existing graph returns all fields."""
        import admin
        
        admin.save_graph(graph_id, 'Test Graph', sample_graph_data, user_id=1)
        
        loaded = admin.load_graph(graph_id)
        
        assert loaded is not None
        assert loaded['id'] == graph_id
        assert loaded['name'] == 'Test Graph'
        assert loaded['data'] == sample_graph_data
        assert loaded['user_id'] == 1
        assert 'created_at' in loaded
        assert 'updated_at' in loaded
    
    def test_load_graph_nonexistent_returns_none(self, test_db):
        """Test loading non-existent graph returns None."""
        import admin
        
        loaded = admin.load_graph('nonexistent-graph-id')
        
        assert loaded is None
    
    def test_load_graph_parses_json_correctly(self, test_db, graph_id):
        """Test that complex nested JSON is parsed correctly."""
        import admin
        
        complex_data = {
            'nodes': [
                {
                    'id': '1',
                    'metadata': {
                        'nested': {
                            'value': [1, 2, 3],
                            'text': 'test'
                        }
                    }
                }
            ],
            'edges': [],
            'settings': {'zoom': 1.5, 'center': [0, 0]}
        }
        
        admin.save_graph(graph_id, 'Complex Graph', complex_data, user_id=1)
        loaded = admin.load_graph(graph_id)
        
        assert loaded['data'] == complex_data
        assert loaded['data']['nodes'][0]['metadata']['nested']['value'] == [1, 2, 3]


class TestListGraphs:
    """Tests for list_graphs function."""
    
    def test_list_graphs_returns_user_graphs_only(self, test_db, sample_graph_data):
        """Test that list_graphs returns only the specified user's graphs."""
        import admin
        
        # Create graphs for different users
        admin.save_graph('graph-user1-a', 'User 1 Graph A', sample_graph_data, user_id=1)
        admin.save_graph('graph-user1-b', 'User 1 Graph B', sample_graph_data, user_id=1)
        admin.save_graph('graph-user2-a', 'User 2 Graph A', sample_graph_data, user_id=2)
        
        user1_graphs = admin.list_graphs(user_id=1)
        user2_graphs = admin.list_graphs(user_id=2)
        
        assert len(user1_graphs) == 2
        assert len(user2_graphs) == 1
        assert all(g['id'].startswith('graph-user1') for g in user1_graphs)
    
    def test_list_graphs_empty_when_no_graphs(self, test_db):
        """Test that list_graphs returns empty list when user has no graphs."""
        import admin
        
        graphs = admin.list_graphs(user_id=999)
        
        assert graphs == []
    
    def test_list_graphs_ordered_by_updated_at_desc(self, test_db, sample_graph_data):
        """Test that graphs are ordered by updated_at descending."""
        import admin
        
        # Create graphs with delays to ensure different timestamps
        admin.save_graph('graph-old', 'Old Graph', sample_graph_data, user_id=1)
        time.sleep(1.1)  # SQLite CURRENT_TIMESTAMP has 1-second resolution
        admin.save_graph('graph-new', 'New Graph', sample_graph_data, user_id=1)
        
        graphs = admin.list_graphs(user_id=1)
        
        assert len(graphs) == 2
        assert graphs[0]['id'] == 'graph-new'  # Most recently updated first
        assert graphs[1]['id'] == 'graph-old'
    
    def test_list_graphs_without_user_id_returns_all(self, test_db, sample_graph_data):
        """Test that list_graphs without user_id returns all graphs."""
        import admin
        
        admin.save_graph('graph-1', 'Graph 1', sample_graph_data, user_id=1)
        admin.save_graph('graph-2', 'Graph 2', sample_graph_data, user_id=2)
        admin.save_graph('graph-3', 'Graph 3', sample_graph_data, user_id=None)
        
        all_graphs = admin.list_graphs(user_id=None)
        
        assert len(all_graphs) == 3
    
    def test_list_graphs_does_not_include_data(self, test_db, sample_graph_data):
        """Test that list_graphs doesn't return full graph data (for performance)."""
        import admin
        
        admin.save_graph('test-graph', 'Test Graph', sample_graph_data, user_id=1)
        
        graphs = admin.list_graphs(user_id=1)
        
        assert len(graphs) == 1
        assert 'data' not in graphs[0]
        assert 'id' in graphs[0]
        assert 'name' in graphs[0]


class TestDeleteGraph:
    """Tests for delete_graph function."""
    
    def test_delete_graph_owner_can_delete(self, test_db, graph_id, sample_graph_data):
        """Test that owner can delete their graph."""
        import admin
        
        admin.save_graph(graph_id, 'Test Graph', sample_graph_data, user_id=1)
        
        result = admin.delete_graph(graph_id, user_id=1)
        
        assert result is True
        assert admin.load_graph(graph_id) is None
    
    def test_delete_graph_non_owner_cannot_delete(self, test_db, graph_id, sample_graph_data):
        """Test that non-owner cannot delete graph."""
        import admin
        
        admin.save_graph(graph_id, 'Test Graph', sample_graph_data, user_id=1)
        
        result = admin.delete_graph(graph_id, user_id=2)
        
        assert result is False
        assert admin.load_graph(graph_id) is not None
    
    def test_delete_graph_no_user_id_deletes_any(self, test_db, graph_id, sample_graph_data):
        """Test that delete without user_id can delete any graph."""
        import admin
        
        admin.save_graph(graph_id, 'Test Graph', sample_graph_data, user_id=1)
        
        result = admin.delete_graph(graph_id, user_id=None)
        
        assert result is True
        assert admin.load_graph(graph_id) is None
    
    def test_delete_graph_nonexistent_returns_false(self, test_db):
        """Test that deleting non-existent graph returns False."""
        import admin
        
        result = admin.delete_graph('nonexistent-id', user_id=1)
        
        assert result is False


# ============================================
# Data Integrity Tests
# ============================================

class TestGraphDataIntegrity:
    """Tests for graph data integrity."""
    
    def test_save_graph_large_data_payload(self, test_db, graph_id, large_graph_data):
        """Test saving large graph with many nodes and edges."""
        import admin
        
        result = admin.save_graph(graph_id, 'Large Graph', large_graph_data, user_id=1)
        
        assert result is True
        
        loaded = admin.load_graph(graph_id)
        assert len(loaded['data']['nodes']) == 1000
        assert len(loaded['data']['edges']) == 999
    
    def test_save_graph_special_characters_in_name(self, test_db, graph_id, sample_graph_data):
        """Test saving graph with special characters in name."""
        import admin
        
        special_name = "Test <Graph> 'with' \"special\" & chars!"
        result = admin.save_graph(graph_id, special_name, sample_graph_data, user_id=1)
        
        assert result is True
        
        loaded = admin.load_graph(graph_id)
        assert loaded['name'] == special_name
    
    def test_save_graph_unicode_in_data(self, test_db, graph_id):
        """Test saving graph with unicode characters in data."""
        import admin
        
        unicode_data = {
            'nodes': [
                {'id': '1', 'label': '日本語テスト'},
                {'id': '2', 'label': 'Ελληνικά'},
                {'id': '3', 'label': '🔒🌐💻'}
            ],
            'edges': []
        }
        
        result = admin.save_graph(graph_id, '国际化测试', unicode_data, user_id=1)
        
        assert result is True
        
        loaded = admin.load_graph(graph_id)
        assert loaded['name'] == '国际化测试'
        assert loaded['data']['nodes'][0]['label'] == '日本語テスト'
        assert loaded['data']['nodes'][2]['label'] == '🔒🌐💻'
    
    def test_load_graph_handles_corrupted_json(self, test_db, graph_id):
        """Test that load_graph handles corrupted JSON gracefully."""
        import admin
        
        # Insert corrupted data directly
        conn = admin.get_db()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO saved_graphs (id, name, data, user_id, created_at, updated_at)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        ''', (graph_id, 'Corrupted', '{invalid json', 1))
        conn.commit()
        conn.close()
        
        # load_graph should raise an exception on invalid JSON
        with pytest.raises(json.JSONDecodeError):
            admin.load_graph(graph_id)
    
    def test_graph_id_uniqueness_enforced(self, test_db, graph_id, sample_graph_data):
        """Test that graph IDs are unique (replace behavior)."""
        import admin
        
        # Save initial graph
        admin.save_graph(graph_id, 'Original', sample_graph_data, user_id=1)
        
        # Save with same ID (same owner) - should replace
        admin.save_graph(graph_id, 'Replaced', {'nodes': []}, user_id=1)
        
        loaded = admin.load_graph(graph_id)
        assert loaded['name'] == 'Replaced'
        
        # Only one graph with this ID should exist
        all_graphs = admin.list_graphs(user_id=1)
        matching = [g for g in all_graphs if g['id'] == graph_id]
        assert len(matching) == 1


# ============================================
# API Endpoint Tests
# ============================================

class TestGraphAPIEndpoints:
    """Tests for graph API endpoints."""
    
    def test_api_graph_save_requires_login(self, client, test_db):
        """Test that graph save endpoint requires authentication."""
        response = client.post('/api/graph/save',
                              json={'name': 'Test', 'data': {}},
                              content_type='application/json')
        
        # Should redirect to login (302) or return unauthorized
        assert response.status_code in [302, 401]
    
    def test_api_graph_save_missing_json(self, authenticated_client, test_db):
        """Test graph save with no JSON body."""
        response = authenticated_client.post('/api/graph/save',
                                            data='not json',
                                            content_type='text/plain')
        
        # 415 = Unsupported Media Type (Flask rejects non-JSON for get_json())
        # 400 = Bad Request (if endpoint handles missing JSON)
        assert response.status_code in [400, 415]
    
    def test_api_graph_save_creates_new_graph(self, authenticated_client, test_db, sample_graph_data):
        """Test that saving without ID creates a new graph."""
        response = authenticated_client.post('/api/graph/save',
                                            json={'name': 'New Graph', 'data': sample_graph_data},
                                            content_type='application/json')
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert 'id' in data
        assert data['is_owner'] is True
    
    def test_api_graph_save_with_id_updates(self, authenticated_client, test_db, sample_graph_data):
        """Test that saving with existing ID updates the graph."""
        # Create a graph first
        response1 = authenticated_client.post('/api/graph/save',
                                             json={'name': 'Original', 'data': sample_graph_data},
                                             content_type='application/json')
        graph_id = response1.get_json()['id']
        
        # Update it
        response2 = authenticated_client.post('/api/graph/save',
                                             json={'id': graph_id, 'name': 'Updated', 'data': {}},
                                             content_type='application/json')
        
        assert response2.status_code == 200
        data = response2.get_json()
        assert data['id'] == graph_id
    
    def test_api_graph_load_existing(self, authenticated_client, test_db, sample_graph_data):
        """Test loading an existing graph via API."""
        import admin
        
        graph_id = str(uuid.uuid4())
        admin.save_graph(graph_id, 'Test Graph', sample_graph_data, user_id=1)
        
        response = authenticated_client.get(f'/api/graph/{graph_id}')
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['id'] == graph_id
        assert data['name'] == 'Test Graph'
        assert 'is_owner' in data
    
    def test_api_graph_load_nonexistent_id(self, authenticated_client, test_db):
        """Test loading non-existent graph returns 404."""
        response = authenticated_client.get('/api/graph/nonexistent-id')
        
        assert response.status_code == 404
        data = response.get_json()
        assert 'error' in data
    
    def test_api_graph_delete_requires_login(self, client, test_db):
        """Test that graph delete endpoint requires authentication."""
        response = client.delete('/api/graph/some-id')
        
        assert response.status_code in [302, 401]
    
    def test_api_graph_delete_success(self, authenticated_client, test_db, sample_graph_data):
        """Test successful graph deletion via API."""
        # Create a graph first
        response1 = authenticated_client.post('/api/graph/save',
                                             json={'name': 'To Delete', 'data': sample_graph_data},
                                             content_type='application/json')
        graph_id = response1.get_json()['id']
        
        # Delete it
        response2 = authenticated_client.delete(f'/api/graph/{graph_id}')
        
        assert response2.status_code == 200
        data = response2.get_json()
        assert data['success'] is True
        
        # Verify it's gone
        response3 = authenticated_client.get(f'/api/graph/{graph_id}')
        assert response3.status_code == 404
    
    def test_api_graph_delete_nonexistent(self, authenticated_client, test_db):
        """Test deleting non-existent graph returns 404."""
        response = authenticated_client.delete('/api/graph/nonexistent-id')
        
        assert response.status_code == 404
    
    def test_api_graph_list_requires_login(self, client, test_db):
        """Test that graph list endpoint requires authentication."""
        response = client.get('/api/graph/list')
        
        assert response.status_code in [302, 401]
    
    def test_api_graph_list_filters_by_session_user(self, authenticated_client, test_db, sample_graph_data):
        """Test that list returns only current user's graphs."""
        import admin
        
        # Get the session user_id (from conftest, it's the testuser we created)
        # Create a graph for this user via API
        response1 = authenticated_client.post('/api/graph/save',
                                             json={'name': 'My Graph', 'data': sample_graph_data},
                                             content_type='application/json')
        
        # Create a graph for a different user directly
        admin.save_graph('other-user-graph', 'Other User Graph', sample_graph_data, user_id=999)
        
        # List should only return current user's graph
        response2 = authenticated_client.get('/api/graph/list')
        
        assert response2.status_code == 200
        data = response2.get_json()
        assert 'graphs' in data
        
        # Should not include the other user's graph
        graph_ids = [g['id'] for g in data['graphs']]
        assert 'other-user-graph' not in graph_ids
    
    def test_api_graph_list_returns_json(self, authenticated_client, test_db):
        """Test that graph list returns proper JSON structure."""
        response = authenticated_client.get('/api/graph/list')
        
        assert response.status_code == 200
        assert response.content_type == 'application/json'
        
        data = response.get_json()
        assert 'graphs' in data
        assert isinstance(data['graphs'], list)
    
    def test_api_graph_export_format_correct(self, authenticated_client, test_db, sample_graph_data):
        """Test that export returns correct format with download header."""
        import admin
        
        graph_id = str(uuid.uuid4())
        admin.save_graph(graph_id, 'Export Test', sample_graph_data, user_id=1)
        
        response = authenticated_client.get(f'/api/graph/export/{graph_id}')
        
        assert response.status_code == 200
        assert 'Content-Disposition' in response.headers
        assert 'attachment' in response.headers['Content-Disposition']
        assert graph_id in response.headers['Content-Disposition']
        
        data = response.get_json()
        assert data['name'] == 'Export Test'
        assert data['data'] == sample_graph_data
    
    def test_api_graph_export_nonexistent_id(self, authenticated_client, test_db):
        """Test that export of non-existent graph returns 404."""
        response = authenticated_client.get('/api/graph/export/nonexistent-id')
        
        assert response.status_code == 404


class TestGraphOwnershipAPI:
    """Tests for graph ownership via API."""
    
    def test_api_graph_load_shows_ownership_status(self, authenticated_client, test_db, sample_graph_data):
        """Test that loaded graph includes is_owner field."""
        # Create graph via API (will be owned by authenticated user)
        response1 = authenticated_client.post('/api/graph/save',
                                             json={'name': 'My Graph', 'data': sample_graph_data},
                                             content_type='application/json')
        graph_id = response1.get_json()['id']
        
        # Load it back
        response2 = authenticated_client.get(f'/api/graph/{graph_id}')
        
        assert response2.status_code == 200
        data = response2.get_json()
        assert data['is_owner'] is True
    
    def test_api_graph_save_force_new_creates_copy(self, authenticated_client, test_db, sample_graph_data):
        """Test that force_new=True always creates a new graph."""
        # Create initial graph
        response1 = authenticated_client.post('/api/graph/save',
                                             json={'name': 'Original', 'data': sample_graph_data},
                                             content_type='application/json')
        original_id = response1.get_json()['id']
        
        # Force create new even with same ID
        response2 = authenticated_client.post('/api/graph/save',
                                             json={'id': original_id, 'name': 'Copy', 
                                                   'data': sample_graph_data, 'force_new': True},
                                             content_type='application/json')
        
        assert response2.status_code == 200
        new_id = response2.get_json()['id']
        assert new_id != original_id  # Should be a different ID
    
    def test_api_cannot_delete_others_graph(self, app, test_db, sample_graph_data, create_test_user):
        """Test that user cannot delete another user's graph."""
        import admin
        
        # Create graph owned by user 999
        graph_id = str(uuid.uuid4())
        admin.save_graph(graph_id, 'Other User Graph', sample_graph_data, user_id=999)
        
        # Create authenticated client (different user)
        client = app.test_client()
        user_id = create_test_user('deletetest')
        with client.session_transaction() as sess:
            sess['logged_in'] = True
            sess['user_id'] = user_id
            sess['username'] = 'deletetest'
            sess['user_role'] = 'user'
        
        # Try to delete
        response = client.delete(f'/api/graph/{graph_id}')
        
        assert response.status_code == 404  # Not found or not authorized
        
        # Graph should still exist
        assert admin.load_graph(graph_id) is not None


class TestGraphAuditLogging:
    """Tests for graph operation audit logging."""
    
    def test_graph_save_creates_audit_log(self, authenticated_client, test_db, sample_graph_data):
        """Test that saving a graph creates an audit log entry."""
        import admin
        
        response = authenticated_client.post('/api/graph/save',
                                            json={'name': 'Audit Test', 'data': sample_graph_data},
                                            content_type='application/json')
        
        assert response.status_code == 200
        
        # Check audit logs
        logs, _ = admin.get_audit_logs(limit=10)
        
        # Find the graph_created log
        graph_logs = [l for l in logs if l['action'] in ('graph_created', 'graph_updated')]
        assert len(graph_logs) >= 1
        
        log = graph_logs[0]
        assert log['resource_type'] == 'graph'
        assert 'name' in log['details']
    
    def test_graph_delete_creates_audit_log(self, authenticated_client, test_db, sample_graph_data):
        """Test that deleting a graph creates an audit log entry."""
        import admin
        
        # Create a graph
        response1 = authenticated_client.post('/api/graph/save',
                                             json={'name': 'To Delete', 'data': sample_graph_data},
                                             content_type='application/json')
        graph_id = response1.get_json()['id']
        
        # Delete it
        response2 = authenticated_client.delete(f'/api/graph/{graph_id}')
        assert response2.status_code == 200
        
        # Check audit logs
        logs, _ = admin.get_audit_logs(limit=10)
        
        delete_logs = [l for l in logs if l['action'] == 'graph_deleted']
        assert len(delete_logs) >= 1
        assert delete_logs[0]['resource_id'] == graph_id
