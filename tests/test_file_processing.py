"""
Tests for File Processing Pipeline.

Tests cover:
- extract_ips() - Extract IPs from text
- create_ip_csv() - Create input CSV
- build_logboost_command() - Build CLI command
- run_logboost() - Execute LogBoost CLI
- get_session_dir() - Get/create session directories
- cleanup_session() - Clean up session files
- enrich_text endpoint
- enrich_file endpoint
"""

import pytest
import json
import csv
import io
import tempfile
import shutil
from pathlib import Path
from unittest.mock import patch, MagicMock


class TestExtractIps:
    """Tests for extract_ips function."""
    
    def test_extract_single_ip(self):
        """Test extracting a single IP address."""
        from app import extract_ips
        
        with patch('app.extract_iocs_from_text', return_value=(['8.8.8.8'], [])):
            result = extract_ips('Server IP: 8.8.8.8')
            assert result == ['8.8.8.8']
    
    def test_extract_multiple_ips(self):
        """Test extracting multiple IP addresses."""
        from app import extract_ips
        
        with patch('app.extract_iocs_from_text', return_value=(['8.8.8.8', '1.1.1.1', '9.9.9.9'], [])):
            result = extract_ips('IPs: 8.8.8.8, 1.1.1.1, 9.9.9.9')
            assert len(result) == 3
            assert '8.8.8.8' in result
            assert '1.1.1.1' in result
    
    def test_extract_no_ips(self):
        """Test with text containing no IPs."""
        from app import extract_ips
        
        with patch('app.extract_iocs_from_text', return_value=([], [])):
            result = extract_ips('No IP addresses here')
            assert result == []
    
    def test_extract_deduplicates_ips(self):
        """Test that duplicate IPs are removed."""
        from app import extract_ips
        
        # extract_iocs_from_text should return deduplicated list
        with patch('app.extract_iocs_from_text', return_value=(['8.8.8.8'], [])):
            result = extract_ips('IP: 8.8.8.8 and again 8.8.8.8')
            assert result == ['8.8.8.8']
    
    def test_extract_ignores_domains(self):
        """Test that domains are not included in IP extraction."""
        from app import extract_ips
        
        # extract_iocs_from_text returns IPs and domains separately
        with patch('app.extract_iocs_from_text', return_value=(['8.8.8.8'], ['example.com'])):
            result = extract_ips('IP: 8.8.8.8 Domain: example.com')
            assert result == ['8.8.8.8']
            assert 'example.com' not in result


class TestCreateIpCsv:
    """Tests for create_ip_csv function."""
    
    def test_create_csv_with_ips(self, tmp_path):
        """Test creating CSV with IP addresses."""
        from app import create_ip_csv
        
        output_path = tmp_path / 'test.csv'
        ips = ['8.8.8.8', '1.1.1.1', '9.9.9.9']
        
        create_ip_csv(ips, output_path)
        
        assert output_path.exists()
        
        # Read and verify contents
        with open(output_path, 'r') as f:
            reader = csv.reader(f)
            rows = list(reader)
        
        assert rows[0] == ['IP']  # Header
        assert rows[1] == ['8.8.8.8']
        assert rows[2] == ['1.1.1.1']
        assert rows[3] == ['9.9.9.9']
        assert len(rows) == 4  # Header + 3 IPs
    
    def test_create_csv_empty_list(self, tmp_path):
        """Test creating CSV with empty IP list."""
        from app import create_ip_csv
        
        output_path = tmp_path / 'empty.csv'
        
        create_ip_csv([], output_path)
        
        assert output_path.exists()
        
        with open(output_path, 'r') as f:
            reader = csv.reader(f)
            rows = list(reader)
        
        assert rows[0] == ['IP']  # Header only
        assert len(rows) == 1
    
    def test_create_csv_single_ip(self, tmp_path):
        """Test creating CSV with single IP."""
        from app import create_ip_csv
        
        output_path = tmp_path / 'single.csv'
        
        create_ip_csv(['192.168.1.1'], output_path)
        
        with open(output_path, 'r') as f:
            content = f.read()
        
        assert 'IP' in content
        assert '192.168.1.1' in content


class TestBuildLogboostCommand:
    """Tests for build_logboost_command function."""
    
    def test_basic_command(self):
        """Test building basic command with required options."""
        from app import build_logboost_command
        from admin import get_effective_logboost_path
        
        cmd = build_logboost_command('/input', '/output', {})
        
        assert cmd[0] == get_effective_logboost_path()
        assert '-logdir' in cmd
        assert '/input' in cmd
        assert '-outputdir' in cmd
        assert '/output' in cmd
    
    def test_command_with_dns_option(self):
        """Test command with DNS enrichment enabled."""
        from app import build_logboost_command
        
        cmd = build_logboost_command('/input', '/output', {'dns': True})
        
        assert '-dns' in cmd
    
    def test_command_with_whois_option(self):
        """Test command with WHOIS enrichment enabled."""
        from app import build_logboost_command
        
        cmd = build_logboost_command('/input', '/output', {'whois': True})
        
        assert '-whois' in cmd
    
    def test_command_with_idb_option(self):
        """Test command with IntelligenceDB enrichment enabled."""
        from app import build_logboost_command
        
        cmd = build_logboost_command('/input', '/output', {'idb': True})
        
        assert '-idb' in cmd
    
    def test_command_with_threat_intel(self):
        """Test command with threat intel enabled."""
        from app import build_logboost_command
        
        cmd = build_logboost_command('/input', '/output', {'useti': True})
        
        assert '-useti' in cmd
    
    def test_command_with_ipcol(self):
        """Test command with IP column specified."""
        from app import build_logboost_command
        
        cmd = build_logboost_command('/input', '/output', {'ipcol': 'src_ip'})
        
        assert '-ipcol' in cmd
        assert 'src_ip' in cmd
    
    def test_command_with_jsoncol(self):
        """Test command with JSON column specified."""
        from app import build_logboost_command
        
        cmd = build_logboost_command('/input', '/output', {'jsoncol': 'json_data'})
        
        assert '-jsoncol' in cmd
        assert 'json_data' in cmd
    
    def test_command_with_regex_option(self):
        """Test command with regex mode enabled."""
        from app import build_logboost_command
        
        cmd = build_logboost_command('/input', '/output', {'regex': True})
        
        assert '-regex' in cmd
    
    def test_command_with_convert_option(self):
        """Test command with convert mode enabled."""
        from app import build_logboost_command
        
        cmd = build_logboost_command('/input', '/output', {'convert': True})
        
        assert '-convert' in cmd
    
    def test_command_with_date_filtering(self):
        """Test command with date filtering options."""
        from app import build_logboost_command
        
        options = {
            'startdate': '2024-01-01',
            'enddate': '2024-12-31',
            'datecol': 'timestamp',
            'dateformat': 'YYYY-MM-DD'
        }
        cmd = build_logboost_command('/input', '/output', options)
        
        assert '-startdate' in cmd
        assert '2024-01-01' in cmd
        assert '-enddate' in cmd
        assert '2024-12-31' in cmd
        assert '-datecol' in cmd
        assert 'timestamp' in cmd
        assert '-dateformat' in cmd
    
    def test_command_with_performance_options(self):
        """Test command with performance tuning options."""
        from app import build_logboost_command
        
        options = {
            'maxgoperfile': 100,
            'batchsize': 1000,
            'writebuffer': 50,
            'concurrentfiles': 4
        }
        cmd = build_logboost_command('/input', '/output', options)
        
        assert '-maxgoperfile' in cmd
        assert '100' in cmd
        assert '-batchsize' in cmd
        assert '1000' in cmd
        assert '-writebuffer' in cmd
        assert '50' in cmd
        assert '-concurrentfiles' in cmd
        assert '4' in cmd
    
    def test_command_with_kv_parsing(self):
        """Test command with KV parsing options."""
        from app import build_logboost_command
        
        options = {
            'separator': '=',
            'delimiter': ','
        }
        cmd = build_logboost_command('/input', '/output', options)
        
        assert '-separator' in cmd
        assert '=' in cmd
        assert '-delimiter' in cmd
        assert ',' in cmd
    
    def test_command_with_dbdir(self):
        """Test command with MaxMind database directory."""
        from app import build_logboost_command
        
        cmd = build_logboost_command('/input', '/output', {'dbdir': '/path/to/maxmind'})
        
        assert '-dbdir' in cmd
        assert '/path/to/maxmind' in cmd
    
    def test_command_with_all_processing_options(self):
        """Test command with all processing mode options."""
        from app import build_logboost_command
        
        options = {
            'fullparse': True,
            'rawtxt': True,
            'getall': True,
            'combine': True,
            'passthrough': True
        }
        cmd = build_logboost_command('/input', '/output', options)
        
        assert '-fullparse' in cmd
        assert '-rawtxt' in cmd
        assert '-getall' in cmd
        assert '-combine' in cmd
        assert '-passthrough' in cmd


class TestRunLogboost:
    """Tests for run_logboost function."""
    
    def test_run_success(self):
        """Test successful LogBoost execution."""
        from app import run_logboost
        
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = 'Processing complete'
        mock_result.stderr = ''
        
        with patch('subprocess.run', return_value=mock_result):
            success, stdout, stderr = run_logboost(['logboost', '-logdir', '/input'])
            
            assert success == True
            assert stdout == 'Processing complete'
            assert stderr == ''
    
    def test_run_failure(self):
        """Test failed LogBoost execution."""
        from app import run_logboost
        
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ''
        mock_result.stderr = 'Error: Invalid input'
        
        with patch('subprocess.run', return_value=mock_result):
            success, stdout, stderr = run_logboost(['logboost'])
            
            assert success == False
            assert stderr == 'Error: Invalid input'
    
    def test_run_timeout(self):
        """Test LogBoost execution timeout."""
        from app import run_logboost
        import subprocess
        
        with patch('subprocess.run', side_effect=subprocess.TimeoutExpired('logboost', 300)):
            success, stdout, stderr = run_logboost(['logboost'])
            
            assert success == False
            assert 'timed out' in stderr.lower()
    
    def test_run_binary_not_found(self):
        """Test when LogBoost binary is not found."""
        from app import run_logboost
        
        with patch('subprocess.run', side_effect=FileNotFoundError()):
            success, stdout, stderr = run_logboost(['logboost'])
            
            assert success == False
            assert 'not found' in stderr.lower()
    
    def test_run_generic_exception(self):
        """Test handling of generic exceptions."""
        from app import run_logboost
        
        with patch('subprocess.run', side_effect=Exception('Unexpected error')):
            success, stdout, stderr = run_logboost(['logboost'])
            
            assert success == False
            assert stderr == 'LogBoost could not be started'


class TestSessionManagement:
    """Tests for session directory management functions."""
    
    def test_get_session_dir_creates_directories(self, tmp_path):
        """Test that get_session_dir creates necessary directories."""
        from app import get_session_dir, UPLOAD_FOLDER, OUTPUT_FOLDER
        
        with patch('app.UPLOAD_FOLDER', tmp_path / 'uploads'):
            with patch('app.OUTPUT_FOLDER', tmp_path / 'output'):
                # Create parent directories
                (tmp_path / 'uploads').mkdir(exist_ok=True)
                (tmp_path / 'output').mkdir(exist_ok=True)
                
                session_id = 'test-session-123'
                upload_dir, output_dir = get_session_dir(session_id)
                
                assert upload_dir.exists()
                assert output_dir.exists()
                assert session_id in str(upload_dir)
                assert session_id in str(output_dir)
    
    def test_cleanup_session_removes_directories(self, tmp_path):
        """Test that cleanup_session removes session directories."""
        from app import cleanup_session
        
        # Create session directories
        session_id = 'test-cleanup-session'
        upload_dir = tmp_path / 'uploads' / session_id
        output_dir = tmp_path / 'output' / session_id
        upload_dir.mkdir(parents=True)
        output_dir.mkdir(parents=True)
        
        # Create some files
        (upload_dir / 'test.csv').write_text('test')
        (output_dir / 'result.csv').write_text('result')
        
        with patch('app.UPLOAD_FOLDER', tmp_path / 'uploads'):
            with patch('app.OUTPUT_FOLDER', tmp_path / 'output'):
                cleanup_session(session_id)
                
                assert not upload_dir.exists()
                assert not output_dir.exists()
    
    def test_cleanup_session_nonexistent(self, tmp_path):
        """Test cleanup_session with non-existent directories."""
        from app import cleanup_session
        
        with patch('app.UPLOAD_FOLDER', tmp_path / 'uploads'):
            with patch('app.OUTPUT_FOLDER', tmp_path / 'output'):
                # Should not raise exception
                cleanup_session('nonexistent-session')


class TestEnrichTextEndpoint:
    """Tests for POST /enrich/text endpoint."""
    
    def test_enrich_text_requires_auth(self, client):
        """Test that endpoint requires authentication."""
        response = client.post('/enrich/text', data={'text': '8.8.8.8'})
        assert response.status_code in (302, 401, 403)
    
    def test_enrich_text_no_text_provided(self, authenticated_client):
        """Test error when no text provided."""
        response = authenticated_client.post('/enrich/text', data={})
        assert response.status_code == 200
        assert b'No text provided' in response.data or b'error' in response.data.lower()
    
    def test_enrich_text_empty_text(self, authenticated_client):
        """Test error when text is empty."""
        response = authenticated_client.post('/enrich/text', data={'text': ''})
        assert response.status_code == 200
        assert b'No text provided' in response.data or b'error' in response.data.lower()
    
    def test_enrich_text_whitespace_only(self, authenticated_client):
        """Test error when text is whitespace only."""
        response = authenticated_client.post('/enrich/text', data={'text': '   '})
        assert response.status_code == 200
        assert b'No text provided' in response.data or b'error' in response.data.lower()
    
    def test_enrich_text_no_ips_found(self, authenticated_client):
        """Test error when no IPs found in text."""
        with patch('app.extract_ips', return_value=[]):
            response = authenticated_client.post('/enrich/text', 
                                                 data={'text': 'No IPs here'})
            assert response.status_code == 200
            assert b'No IP addresses found' in response.data or b'error' in response.data.lower()
    
    def test_enrich_text_logboost_failure(self, authenticated_client, tmp_path, test_db):
        """Test handling of LogBoost execution failure."""
        with patch('app.extract_ips', return_value=['8.8.8.8']):
            with patch('app.get_max_adhoc_ips', return_value=1000):
                with patch('app.get_session_dir', return_value=(tmp_path, tmp_path)):
                    with patch('app.create_ip_csv'):
                        with patch('app.run_logboost', return_value=(False, '', 'LogBoost error')):
                            response = authenticated_client.post('/enrich/text',
                                                                 data={'text': '8.8.8.8'})
                            assert response.status_code == 200
                            assert b'error' in response.data.lower()
    
    def test_enrich_text_success(self, authenticated_client, tmp_path, test_db):
        """Test successful text enrichment."""
        # Create mock output file
        output_file = tmp_path / 'output.csv'
        output_file.write_text('IP,lb_Country\n8.8.8.8,US\n')
        
        with patch('app.extract_ips', return_value=['8.8.8.8']):
            with patch('app.get_max_adhoc_ips', return_value=1000):
                with patch('app.get_session_dir', return_value=(tmp_path, tmp_path)):
                    with patch('app.create_ip_csv'):
                        with patch('app.run_logboost', return_value=(True, 'Success', '')):
                            with patch('app.log_audit'):
                                response = authenticated_client.post('/enrich/text',
                                                                     data={'text': '8.8.8.8'})
                                # Should render results template
                                assert response.status_code == 200


class TestEnrichFileEndpoint:
    """Tests for POST /enrich/file endpoint."""
    
    def test_enrich_file_requires_auth(self, client):
        """Test that endpoint requires authentication."""
        response = client.post('/enrich/file')
        assert response.status_code in (302, 401, 403)
    
    def test_enrich_file_no_file_uploaded(self, authenticated_client):
        """Test error when no file uploaded."""
        response = authenticated_client.post('/enrich/file', data={})
        assert response.status_code == 200
        assert b'No file uploaded' in response.data or b'error' in response.data.lower()
    
    def test_enrich_file_empty_filename(self, authenticated_client):
        """Test error when file has empty filename."""
        response = authenticated_client.post(
            '/enrich/file',
            data={'file': (io.BytesIO(b''), '')},
            content_type='multipart/form-data'
        )
        assert response.status_code == 200
        assert b'No file selected' in response.data or b'error' in response.data.lower()
    
    def test_enrich_file_logboost_failure(self, authenticated_client, tmp_path, test_db):
        """Test handling of LogBoost execution failure."""
        file_content = b'IP\n8.8.8.8\n'
        
        with patch('app.get_session_dir', return_value=(tmp_path, tmp_path)):
            with patch('app.run_logboost', return_value=(False, '', 'LogBoost error')):
                response = authenticated_client.post(
                    '/enrich/file',
                    data={'file': (io.BytesIO(file_content), 'test.csv')},
                    content_type='multipart/form-data'
                )
                assert response.status_code == 200
                assert b'error' in response.data.lower()
    
    def test_enrich_file_no_output_generated(self, authenticated_client, tmp_path, test_db):
        """Test error when no output file is generated."""
        file_content = b'IP\n8.8.8.8\n'
        
        with patch('app.get_session_dir', return_value=(tmp_path, tmp_path)):
            with patch('app.run_logboost', return_value=(True, 'Success', '')):
                with patch('app.get_large_file_warning_threshold', return_value=10000):
                    response = authenticated_client.post(
                        '/enrich/file',
                        data={'file': (io.BytesIO(file_content), 'test.csv')},
                        content_type='multipart/form-data'
                    )
                    assert response.status_code == 200
                    assert b'No output file' in response.data or b'error' in response.data.lower()
    
    def test_enrich_file_with_options(self, authenticated_client, tmp_path, test_db):
        """Test file enrichment with various options."""
        file_content = b'IP\n8.8.8.8\n'
        output_file = tmp_path / 'output.csv'
        output_file.write_text('IP,lb_Country\n8.8.8.8,US\n')
        
        with patch('app.get_session_dir', return_value=(tmp_path, tmp_path)):
            with patch('app.run_logboost', return_value=(True, 'Success', '')) as mock_run:
                with patch('app.get_large_file_warning_threshold', return_value=10000):
                    with patch('app.log_audit'):
                        response = authenticated_client.post(
                            '/enrich/file',
                            data={
                                'file': (io.BytesIO(file_content), 'test.csv'),
                                'dns': 'on',
                                'whois': 'on',
                                'regex': 'on'
                            },
                            content_type='multipart/form-data'
                        )
                        # Verify run_logboost was called
                        assert mock_run.called
