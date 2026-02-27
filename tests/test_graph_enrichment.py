"""
Tests for Graph Enrichment API endpoints.

Covers:
- /api/graph/related - Find related IPs/domains from CSV data
- /api/graph/enrich - Enrich IPs using LogBoost
- /api/graph/enrich-idb - Enrich IPs using InternetDB via LogBoost
- /api/graph/geo - Get geo data for IPs from current dataset
- /api/graph/debug-columns - Debug endpoint for columns
"""

import pytest
import json
import csv
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock


class TestGraphRelatedApi:
    """Tests for /api/graph/related endpoint."""
    
    def test_graph_related_requires_auth(self, client, test_db):
        """Test that graph related endpoint requires authentication."""
        response = client.post('/api/graph/related',
            json={'value': '8.8.8.8', 'type': 'ip'})
        assert response.status_code == 302  # Redirect to login
    
    def test_graph_related_no_json(self, authenticated_client, test_db):
        """Test error when no JSON data provided."""
        response = authenticated_client.post('/api/graph/related',
            data='not json',
            content_type='text/plain')
        assert response.status_code in (400, 415)  # 415 = Unsupported Media Type
    
    def test_graph_related_no_session_data(self, authenticated_client, test_db):
        """Test returns empty results when no session data."""
        response = authenticated_client.post('/api/graph/related',
            json={'value': '8.8.8.8', 'type': 'ip'})
        assert response.status_code == 200
        data = response.get_json()
        assert data['ips'] == []
        assert data['domains'] == []
    
    def test_graph_related_returns_expected_structure(self, authenticated_client, test_db):
        """Test that response has expected structure."""
        response = authenticated_client.post('/api/graph/related',
            json={'value': '8.8.8.8', 'type': 'ip'})
        assert response.status_code == 200
        data = response.get_json()
        assert 'ips' in data
        assert 'domains' in data
        assert 'tlds' in data
        assert 'asns' in data
        assert 'countries' in data
        assert 'geo_data' in data
        assert 'sources' in data
    
    def test_graph_related_finds_domains_for_ip(self, authenticated_client, test_db, tmp_path):
        """Test finding related domains for an IP address."""
        # Create a mock enrichment CSV file
        csv_file = tmp_path / 'enriched.csv'
        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['ip', 'lb_Domains', 'lb_TLD', 'lb_ASN', 'lb_ASN_Number', 'lb_Country', 'lb_City'])
            writer.writerow(['8.8.8.8', 'dns.google|google.com', 'com', 'Google LLC', '15169', 'United States', 'Mountain View'])
            writer.writerow(['1.1.1.1', 'one.one.one.one|cloudflare.com', 'one', 'Cloudflare', '13335', 'Australia', 'Sydney'])
        
        with authenticated_client.session_transaction() as sess:
            sess['current_output'] = str(csv_file)
        
        response = authenticated_client.post('/api/graph/related',
            json={'value': '8.8.8.8', 'type': 'ip'})
        
        assert response.status_code == 200
        data = response.get_json()
        assert 'dns.google' in data['domains']
        assert 'google.com' in data['domains']
        assert 'com' in data['tlds']
        assert any('15169' in asn for asn in data['asns'])
        assert 'United States' in data['countries']
        assert '8.8.8.8' in data['geo_data']
    
    def test_graph_related_finds_ips_for_domain(self, authenticated_client, test_db, tmp_path):
        """Test finding related IPs for a domain."""
        csv_file = tmp_path / 'enriched.csv'
        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['ip', 'lb_Domains', 'lb_ASN_Number', 'lb_Country'])
            writer.writerow(['8.8.8.8', 'dns.google|google.com', '15169', 'United States'])
            writer.writerow(['8.8.4.4', 'dns.google', '15169', 'United States'])
            writer.writerow(['1.1.1.1', 'cloudflare.com', '13335', 'Australia'])
        
        with authenticated_client.session_transaction() as sess:
            sess['current_output'] = str(csv_file)
        
        response = authenticated_client.post('/api/graph/related',
            json={'value': 'dns.google', 'type': 'domain'})
        
        assert response.status_code == 200
        data = response.get_json()
        assert '8.8.8.8' in data['ips']
        assert '8.8.4.4' in data['ips']
        assert '1.1.1.1' not in data['ips']  # Different domain
    
    def test_graph_related_case_insensitive_ip_match(self, authenticated_client, test_db, tmp_path):
        """Test that IP matching is case-insensitive."""
        csv_file = tmp_path / 'enriched.csv'
        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['IP', 'lb_Domains'])
            writer.writerow(['8.8.8.8', 'google.com'])
        
        with authenticated_client.session_transaction() as sess:
            sess['current_output'] = str(csv_file)
        
        response = authenticated_client.post('/api/graph/related',
            json={'value': '8.8.8.8', 'type': 'ip'})
        
        assert response.status_code == 200
        data = response.get_json()
        assert 'google.com' in data['domains']
    
    def test_graph_related_case_insensitive_domain_match(self, authenticated_client, test_db, tmp_path):
        """Test that domain matching is case-insensitive."""
        csv_file = tmp_path / 'enriched.csv'
        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['ip', 'lb_Domains'])
            writer.writerow(['8.8.8.8', 'Google.COM'])
        
        with authenticated_client.session_transaction() as sess:
            sess['current_output'] = str(csv_file)
        
        response = authenticated_client.post('/api/graph/related',
            json={'value': 'google.com', 'type': 'domain'})
        
        assert response.status_code == 200
        data = response.get_json()
        assert '8.8.8.8' in data['ips']
    
    def test_graph_related_handles_idb_hostnames(self, authenticated_client, test_db, tmp_path):
        """Test that IDB hostnames column is also checked for domains."""
        csv_file = tmp_path / 'enriched.csv'
        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['ip', 'lb_Domains', 'lb_IDB_HOSTNAMES'])
            writer.writerow(['8.8.8.8', 'google.com', 'dns.google|ns1.google.com'])
        
        with authenticated_client.session_transaction() as sess:
            sess['current_output'] = str(csv_file)
        
        response = authenticated_client.post('/api/graph/related',
            json={'value': '8.8.8.8', 'type': 'ip'})
        
        assert response.status_code == 200
        data = response.get_json()
        assert 'google.com' in data['domains']
        assert 'dns.google' in data['domains']
        assert 'ns1.google.com' in data['domains']
    
    def test_graph_related_adds_geo_data(self, authenticated_client, test_db, tmp_path):
        """Test that geo data is included in response."""
        csv_file = tmp_path / 'enriched.csv'
        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['ip', 'lb_Domains', 'lb_ASN', 'lb_ASN_Number', 'lb_Country', 'lb_City', 'lb_IPWhois_Organization'])
            writer.writerow(['8.8.8.8', 'google.com', 'Google LLC', '15169', 'United States', 'Mountain View', 'Google Inc'])
        
        with authenticated_client.session_transaction() as sess:
            sess['current_output'] = str(csv_file)
        
        response = authenticated_client.post('/api/graph/related',
            json={'value': '8.8.8.8', 'type': 'ip'})
        
        assert response.status_code == 200
        data = response.get_json()
        geo = data['geo_data'].get('8.8.8.8', {})
        assert geo.get('asn_id') == 'AS15169'
        assert geo.get('asn_name') == 'Google LLC'
        assert geo.get('country') == 'United States'
        assert geo.get('city') == 'Mountain View'
        assert geo.get('org') == 'Google Inc'
    
    def test_graph_related_handles_file_read_error(self, authenticated_client, test_db, tmp_path):
        """Test error handling when file cannot be read."""
        with authenticated_client.session_transaction() as sess:
            sess['current_output'] = '/nonexistent/path/file.csv'
        
        response = authenticated_client.post('/api/graph/related',
            json={'value': '8.8.8.8', 'type': 'ip'})
        
        # Should return empty results, not error
        assert response.status_code == 200
        data = response.get_json()
        assert data['ips'] == []
    
    def test_graph_related_finds_related_domains_when_searching_domain(self, authenticated_client, test_db, tmp_path):
        """Test that searching for a domain also finds other domains on the same IP."""
        csv_file = tmp_path / 'enriched.csv'
        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['ip', 'lb_Domains', 'lb_TLD'])
            writer.writerow(['8.8.8.8', 'google.com|dns.google|mail.google.com', 'com'])
        
        with authenticated_client.session_transaction() as sess:
            sess['current_output'] = str(csv_file)
        
        response = authenticated_client.post('/api/graph/related',
            json={'value': 'google.com', 'type': 'domain'})
        
        assert response.status_code == 200
        data = response.get_json()
        # Should find other domains on the same IP
        assert 'dns.google' in data['domains']
        assert 'mail.google.com' in data['domains']
        # Should also find the IP
        assert '8.8.8.8' in data['ips']


class TestGraphEnrichApi:
    """Tests for /api/graph/enrich endpoint."""
    
    def test_graph_enrich_requires_auth(self, client, test_db):
        """Test that graph enrich endpoint requires authentication."""
        response = client.post('/api/graph/enrich',
            json={'ips': ['8.8.8.8']})
        assert response.status_code == 302
    
    def test_graph_enrich_no_json(self, authenticated_client, test_db):
        """Test error when no JSON data provided."""
        response = authenticated_client.post('/api/graph/enrich',
            data='not json',
            content_type='text/plain')
        assert response.status_code in (400, 415)  # 415 = Unsupported Media Type
    
    def test_graph_enrich_no_ips(self, authenticated_client, test_db):
        """Test error when no IPs provided."""
        response = authenticated_client.post('/api/graph/enrich',
            json={'ips': []})
        assert response.status_code == 400
        data = response.get_json()
        assert 'error' in data
        assert 'No IPs' in data['error']
    
    def test_graph_enrich_empty_ips_list(self, authenticated_client, test_db):
        """Test error when IPs key missing."""
        response = authenticated_client.post('/api/graph/enrich',
            json={'other_key': 'value'})
        assert response.status_code == 400
    
    @patch('app.run_logboost')
    def test_graph_enrich_logboost_failure(self, mock_run, authenticated_client, test_db):
        """Test handling when LogBoost execution fails."""
        mock_run.return_value = (False, '', 'LogBoost error')
        
        response = authenticated_client.post('/api/graph/enrich',
            json={'ips': ['8.8.8.8']})
        
        assert response.status_code == 500
        data = response.get_json()
        assert 'error' in data
    
    @patch('app.run_logboost')
    def test_graph_enrich_success(self, mock_run, authenticated_client, test_db, tmp_path):
        """Test successful IP enrichment."""
        output_dir = tmp_path / 'output'
        output_dir.mkdir()
        upload_dir = tmp_path / 'upload'
        upload_dir.mkdir()
        
        def run_logboost_side_effect(cmd):
            # Create output file when LogBoost "runs"
            output_file = output_dir / 'graph_ips_enriched.csv'
            with open(output_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['ip', 'lb_ASN', 'lb_ASN_Number', 'lb_Country', 'lb_City'])
                writer.writerow(['8.8.8.8', 'Google LLC', '15169', 'United States', 'Mountain View'])
                writer.writerow(['1.1.1.1', 'Cloudflare', '13335', 'Australia', 'Sydney'])
            return (True, 'Success', '')
        
        mock_run.side_effect = run_logboost_side_effect
        
        with patch('app.get_session_dir') as mock_session_dir:
            mock_session_dir.return_value = (upload_dir, output_dir)
            
            response = authenticated_client.post('/api/graph/enrich',
                json={'ips': ['8.8.8.8', '1.1.1.1']})
        
        assert response.status_code == 200
        data = response.get_json()
        assert 'geo_data' in data
        assert data['enriched_count'] == 2
        assert data['total_ips'] == 2
        assert '8.8.8.8' in data['geo_data']
        assert data['geo_data']['8.8.8.8']['asn_id'] == 'AS15169'
        assert data['geo_data']['8.8.8.8']['country'] == 'United States'
    
    @patch('app.run_logboost')
    def test_graph_enrich_no_output_file(self, mock_run, authenticated_client, test_db, tmp_path):
        """Test handling when no output file is generated."""
        mock_run.return_value = (True, 'Success', '')
        
        with patch('app.get_session_dir') as mock_session_dir:
            upload_dir = tmp_path / 'upload'
            output_dir = tmp_path / 'output'
            upload_dir.mkdir()
            output_dir.mkdir()
            mock_session_dir.return_value = (upload_dir, output_dir)
            
            response = authenticated_client.post('/api/graph/enrich',
                json={'ips': ['8.8.8.8']})
        
        assert response.status_code == 500
        data = response.get_json()
        assert 'error' in data
        assert 'No output file' in data['error']
    
    @patch('app.run_logboost')
    def test_graph_enrich_creates_session_if_missing(self, mock_run, authenticated_client, test_db, tmp_path):
        """Test that session ID is created if missing."""
        output_dir = tmp_path / 'output'
        output_dir.mkdir()
        upload_dir = tmp_path / 'upload'
        upload_dir.mkdir()
        
        def run_logboost_side_effect(cmd):
            output_file = output_dir / 'enriched.csv'
            with open(output_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['ip', 'lb_Country'])
                writer.writerow(['8.8.8.8', 'US'])
            return (True, '', '')
        
        mock_run.side_effect = run_logboost_side_effect
        
        with patch('app.get_session_dir') as mock_session_dir:
            mock_session_dir.return_value = (upload_dir, output_dir)
            
            # Clear session
            with authenticated_client.session_transaction() as sess:
                if 'session_id' in sess:
                    del sess['session_id']
            
            response = authenticated_client.post('/api/graph/enrich',
                json={'ips': ['8.8.8.8']})
        
        assert response.status_code == 200
    
    @patch('app.run_logboost')
    def test_graph_enrich_handles_asn_name_only(self, mock_run, authenticated_client, test_db, tmp_path):
        """Test handling when only ASN name is present (no number)."""
        output_dir = tmp_path / 'output'
        output_dir.mkdir()
        upload_dir = tmp_path / 'upload'
        upload_dir.mkdir()
        
        def run_logboost_side_effect(cmd):
            output_file = output_dir / 'enriched.csv'
            with open(output_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['ip', 'lb_ASN', 'lb_Country'])  # No lb_ASN_Number
                writer.writerow(['8.8.8.8', 'Google LLC', 'United States'])
            return (True, '', '')
        
        mock_run.side_effect = run_logboost_side_effect
        
        with patch('app.get_session_dir') as mock_session_dir:
            mock_session_dir.return_value = (upload_dir, output_dir)
            
            response = authenticated_client.post('/api/graph/enrich',
                json={'ips': ['8.8.8.8']})
        
        assert response.status_code == 200
        data = response.get_json()
        geo = data['geo_data'].get('8.8.8.8', {})
        assert geo.get('asn_name') == 'Google LLC'
        assert geo.get('asn') == 'Google LLC'


class TestGraphEnrichIdbApi:
    """Tests for /api/graph/enrich-idb endpoint."""
    
    def test_graph_enrich_idb_requires_auth(self, client, test_db):
        """Test that endpoint requires authentication."""
        response = client.post('/api/graph/enrich-idb',
            json={'ips': ['8.8.8.8']})
        assert response.status_code == 302
    
    def test_graph_enrich_idb_no_json(self, authenticated_client, test_db):
        """Test error when no JSON data provided."""
        response = authenticated_client.post('/api/graph/enrich-idb',
            data='not json',
            content_type='text/plain')
        assert response.status_code in (400, 415)  # 415 = Unsupported Media Type
    
    def test_graph_enrich_idb_no_ips(self, authenticated_client, test_db):
        """Test error when no IPs provided."""
        response = authenticated_client.post('/api/graph/enrich-idb',
            json={'ips': []})
        assert response.status_code == 400
    
    @patch('app.run_logboost')
    def test_graph_enrich_idb_logboost_failure(self, mock_run, authenticated_client, test_db):
        """Test handling when LogBoost execution fails."""
        mock_run.return_value = (False, '', 'IDB lookup failed')
        
        response = authenticated_client.post('/api/graph/enrich-idb',
            json={'ips': ['8.8.8.8']})
        
        assert response.status_code == 500
        data = response.get_json()
        assert 'error' in data
    
    @patch('app.run_logboost')
    @patch('app.log_audit')
    def test_graph_enrich_idb_success(self, mock_audit, mock_run, authenticated_client, test_db, tmp_path):
        """Test successful IDB enrichment."""
        output_dir = tmp_path / 'output'
        output_dir.mkdir()
        upload_dir = tmp_path / 'upload'
        upload_dir.mkdir()
        
        def run_logboost_side_effect(cmd):
            output_file = output_dir / 'idb_enriched.csv'
            with open(output_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['ip', 'lb_IDB_PORTS', 'lb_IDB_TAGS'])
                writer.writerow(['8.8.8.8', '53|443|80', 'dns|cloud'])
                writer.writerow(['1.1.1.1', '53|443', 'cdn|dns'])
            return (True, '', '')
        
        mock_run.side_effect = run_logboost_side_effect
        
        with patch('app.get_session_dir') as mock_session_dir:
            mock_session_dir.return_value = (upload_dir, output_dir)
            
            response = authenticated_client.post('/api/graph/enrich-idb',
                json={'ips': ['8.8.8.8', '1.1.1.1']})
        
        assert response.status_code == 200
        data = response.get_json()
        assert 'idb_data' in data
        assert data['enriched_count'] == 2
        assert '8.8.8.8' in data['idb_data']
        assert '53' in data['idb_data']['8.8.8.8']['ports']
        assert 'dns' in data['idb_data']['8.8.8.8']['tags']
        
        # Verify audit log was called
        mock_audit.assert_called()
    
    @patch('app.run_logboost')
    def test_graph_enrich_idb_filters_err_values(self, mock_run, authenticated_client, test_db, tmp_path):
        """Test that 'err' values are filtered out from ports and tags."""
        output_dir = tmp_path / 'output'
        output_dir.mkdir()
        upload_dir = tmp_path / 'upload'
        upload_dir.mkdir()
        
        def run_logboost_side_effect(cmd):
            output_file = output_dir / 'idb_enriched.csv'
            with open(output_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['ip', 'lb_IDB_PORTS', 'lb_IDB_TAGS'])
                writer.writerow(['8.8.8.8', 'err', 'err'])  # Both error
                writer.writerow(['1.1.1.1', '53|err|443', 'dns|err'])  # Mixed
            return (True, '', '')
        
        mock_run.side_effect = run_logboost_side_effect
        
        with patch('app.get_session_dir') as mock_session_dir:
            mock_session_dir.return_value = (upload_dir, output_dir)
            
            response = authenticated_client.post('/api/graph/enrich-idb',
                json={'ips': ['8.8.8.8', '1.1.1.1']})
        
        assert response.status_code == 200
        data = response.get_json()
        # 8.8.8.8 should not be in results (both err)
        assert '8.8.8.8' not in data['idb_data']
        # 1.1.1.1 should have filtered values
        assert '1.1.1.1' in data['idb_data']
        assert 'err' not in data['idb_data']['1.1.1.1']['ports']
        assert '53' in data['idb_data']['1.1.1.1']['ports']
    
    @patch('app.run_logboost')
    def test_graph_enrich_idb_no_output_file(self, mock_run, authenticated_client, test_db, tmp_path):
        """Test handling when no output file is generated."""
        mock_run.return_value = (True, '', '')
        
        with patch('app.get_session_dir') as mock_session_dir:
            upload_dir = tmp_path / 'upload'
            output_dir = tmp_path / 'output'
            upload_dir.mkdir()
            output_dir.mkdir()
            mock_session_dir.return_value = (upload_dir, output_dir)
            
            response = authenticated_client.post('/api/graph/enrich-idb',
                json={'ips': ['8.8.8.8']})
        
        assert response.status_code == 500


class TestGraphGeoApi:
    """Tests for /api/graph/geo endpoint."""
    
    def test_graph_geo_requires_auth(self, client, test_db):
        """Test that endpoint requires authentication."""
        response = client.post('/api/graph/geo',
            json={'ips': ['8.8.8.8']})
        assert response.status_code == 302
    
    def test_graph_geo_no_json(self, authenticated_client, test_db):
        """Test error when no JSON data provided."""
        response = authenticated_client.post('/api/graph/geo',
            data='not json',
            content_type='text/plain')
        assert response.status_code in (400, 415)  # 415 = Unsupported Media Type
    
    def test_graph_geo_no_ips(self, authenticated_client, test_db):
        """Test returns empty when no IPs provided."""
        response = authenticated_client.post('/api/graph/geo',
            json={'ips': []})
        assert response.status_code == 200
        data = response.get_json()
        assert data['geo_data'] == {}
        assert data['debug']['reason'] == 'no_ips_provided'
    
    def test_graph_geo_no_session_data(self, authenticated_client, test_db):
        """Test returns empty when no session output file."""
        response = authenticated_client.post('/api/graph/geo',
            json={'ips': ['8.8.8.8']})
        assert response.status_code == 200
        data = response.get_json()
        assert data['geo_data'] == {}
        assert 'no_output_file' in data['debug']['reason']
    
    def test_graph_geo_returns_geo_data(self, authenticated_client, test_db, tmp_path):
        """Test successful geo data retrieval."""
        csv_file = tmp_path / 'enriched.csv'
        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['ip', 'lb_ASN', 'lb_ASN_Number', 'lb_Country', 'lb_City', 'lb_IPWhois_Organization'])
            writer.writerow(['8.8.8.8', 'Google LLC', '15169', 'United States', 'Mountain View', 'Google Inc'])
            writer.writerow(['1.1.1.1', 'Cloudflare', '13335', 'Australia', 'Sydney', 'Cloudflare Inc'])
        
        with authenticated_client.session_transaction() as sess:
            sess['current_output'] = str(csv_file)
        
        response = authenticated_client.post('/api/graph/geo',
            json={'ips': ['8.8.8.8']})
        
        assert response.status_code == 200
        data = response.get_json()
        assert '8.8.8.8' in data['geo_data']
        geo = data['geo_data']['8.8.8.8']
        assert geo['asn_id'] == 'AS15169'
        assert geo['country'] == 'United States'
        assert geo['city'] == 'Mountain View'
    
    def test_graph_geo_case_insensitive_matching(self, authenticated_client, test_db, tmp_path):
        """Test that IP matching is case-insensitive."""
        csv_file = tmp_path / 'enriched.csv'
        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['IP', 'lb_Country'])
            writer.writerow(['8.8.8.8', 'United States'])
        
        with authenticated_client.session_transaction() as sess:
            sess['current_output'] = str(csv_file)
        
        response = authenticated_client.post('/api/graph/geo',
            json={'ips': ['8.8.8.8']})
        
        assert response.status_code == 200
        data = response.get_json()
        assert '8.8.8.8' in data['geo_data']
    
    def test_graph_geo_returns_debug_info(self, authenticated_client, test_db, tmp_path):
        """Test that debug info is included in response."""
        csv_file = tmp_path / 'enriched.csv'
        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['ip', 'lb_ASN', 'lb_Country'])
            writer.writerow(['8.8.8.8', 'Google', 'US'])
        
        with authenticated_client.session_transaction() as sess:
            sess['current_output'] = str(csv_file)
        
        response = authenticated_client.post('/api/graph/geo',
            json={'ips': ['8.8.8.8']})
        
        assert response.status_code == 200
        data = response.get_json()
        assert 'debug' in data
        assert 'columns' in data['debug']
        assert 'sample_ips_from_file' in data['debug']
    
    def test_graph_geo_handles_missing_ip_column(self, authenticated_client, test_db, tmp_path):
        """Test handling when IP column is missing."""
        csv_file = tmp_path / 'enriched.csv'
        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['not_ip', 'lb_Country'])
            writer.writerow(['8.8.8.8', 'US'])
        
        with authenticated_client.session_transaction() as sess:
            sess['current_output'] = str(csv_file)
        
        response = authenticated_client.post('/api/graph/geo',
            json={'ips': ['8.8.8.8']})
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['geo_data'] == {}
        assert data['debug']['error'] == 'no_ip_column_found'
    
    def test_graph_geo_handles_multiple_ips(self, authenticated_client, test_db, tmp_path):
        """Test retrieval of multiple IPs at once."""
        csv_file = tmp_path / 'enriched.csv'
        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['ip', 'lb_Country'])
            writer.writerow(['8.8.8.8', 'United States'])
            writer.writerow(['1.1.1.1', 'Australia'])
            writer.writerow(['9.9.9.9', 'Switzerland'])
        
        with authenticated_client.session_transaction() as sess:
            sess['current_output'] = str(csv_file)
        
        response = authenticated_client.post('/api/graph/geo',
            json={'ips': ['8.8.8.8', '1.1.1.1']})
        
        assert response.status_code == 200
        data = response.get_json()
        assert len(data['geo_data']) == 2
        assert '8.8.8.8' in data['geo_data']
        assert '1.1.1.1' in data['geo_data']
        assert '9.9.9.9' not in data['geo_data']  # Not requested


class TestGraphDebugColumnsApi:
    """Tests for /api/graph/debug-columns endpoint."""
    
    def test_debug_columns_requires_auth(self, client, test_db):
        """Test that endpoint requires authentication."""
        response = client.get('/api/graph/debug-columns')
        assert response.status_code == 302
    
    def test_debug_columns_no_session_data(self, authenticated_client, test_db):
        """Test returns error when no session output file."""
        response = authenticated_client.get('/api/graph/debug-columns')
        assert response.status_code == 200
        data = response.get_json()
        assert 'error' in data
        assert 'No enrichment data' in data['error']
    
    def test_debug_columns_returns_column_info(self, authenticated_client, test_db, tmp_path):
        """Test successful column info retrieval."""
        csv_file = tmp_path / 'enriched.csv'
        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['ip', 'lb_ASN', 'lb_ASN_Number', 'lb_Country', 'lb_City', 'other_col'])
            writer.writerow(['8.8.8.8', 'Google', '15169', 'US', 'MV', 'data'])
        
        with authenticated_client.session_transaction() as sess:
            sess['current_output'] = str(csv_file)
        
        response = authenticated_client.get('/api/graph/debug-columns')
        
        assert response.status_code == 200
        data = response.get_json()
        assert 'all_columns' in data
        assert 'lb_columns' in data
        assert 'detected' in data
        assert 'sample_data' in data
        assert 'lb_ASN' in data['lb_columns']
        assert data['detected']['ip_col'] == 'ip'
    
    def test_debug_columns_detects_lb_columns(self, authenticated_client, test_db, tmp_path):
        """Test that lb_ prefixed columns are identified."""
        csv_file = tmp_path / 'enriched.csv'
        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['ip', 'lb_ASN', 'lb_Country', 'lb_City', 'lb_TLD', 'custom_col'])
            writer.writerow(['8.8.8.8', 'Google', 'US', 'MV', 'com', 'data'])
        
        with authenticated_client.session_transaction() as sess:
            sess['current_output'] = str(csv_file)
        
        response = authenticated_client.get('/api/graph/debug-columns')
        
        assert response.status_code == 200
        data = response.get_json()
        assert len(data['lb_columns']) == 4
        assert 'lb_ASN' in data['lb_columns']
        assert 'custom_col' not in data['lb_columns']
    
    def test_debug_columns_returns_sample_data(self, authenticated_client, test_db, tmp_path):
        """Test that sample data from first row is included."""
        csv_file = tmp_path / 'enriched.csv'
        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['ip', 'lb_ASN', 'lb_Country'])
            writer.writerow(['8.8.8.8', 'Google', 'US'])
            writer.writerow(['1.1.1.1', 'Cloudflare', 'AU'])  # Should not be in sample
        
        with authenticated_client.session_transaction() as sess:
            sess['current_output'] = str(csv_file)
        
        response = authenticated_client.get('/api/graph/debug-columns')
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['sample_data']['ip'] == '8.8.8.8'
        assert data['sample_data']['country'] == 'US'
    
    def test_debug_columns_handles_file_error(self, authenticated_client, test_db):
        """Test handling when file cannot be read."""
        with authenticated_client.session_transaction() as sess:
            sess['current_output'] = '/nonexistent/file.csv'
        
        response = authenticated_client.get('/api/graph/debug-columns')
        
        assert response.status_code == 200
        data = response.get_json()
        assert 'error' in data
    
    def test_debug_columns_detects_various_ip_column_names(self, authenticated_client, test_db, tmp_path):
        """Test detection of various IP column name formats."""
        for col_name in ['ip', 'IP', 'ip_address', 'ipaddress', 'src_ip', 'dst_ip']:
            csv_file = tmp_path / f'enriched_{col_name}.csv'
            with open(csv_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([col_name, 'lb_Country'])
                writer.writerow(['8.8.8.8', 'US'])
            
            with authenticated_client.session_transaction() as sess:
                sess['current_output'] = str(csv_file)
            
            response = authenticated_client.get('/api/graph/debug-columns')
            
            assert response.status_code == 200
            data = response.get_json()
            assert data['detected']['ip_col'] == col_name, f"Failed to detect {col_name}"
