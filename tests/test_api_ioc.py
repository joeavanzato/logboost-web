"""
Tests for IOC Extraction API endpoint.

Tests cover:
- POST /api/ioc/extract - Extract IOCs from text, URL, or uploaded file
"""

import pytest
import json
import io
from unittest.mock import patch, MagicMock


class TestIocExtractApi:
    """Tests for /api/ioc/extract endpoint."""
    
    def test_ioc_extract_requires_auth(self, client):
        """Test that endpoint requires authentication."""
        response = client.post('/api/ioc/extract',
                              json={'text': 'test 8.8.8.8 example.com'})
        assert response.status_code in (302, 401, 403)
    
    def test_ioc_extract_no_content(self, authenticated_client):
        """Test error when no content provided."""
        response = authenticated_client.post('/api/ioc/extract',
                                             json={})
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'No content provided' in data['error']
    
    def test_ioc_extract_from_text(self, authenticated_client):
        """Test extracting IOCs from text."""
        text = """
        Malicious IPs: 8.8.8.8, 1.1.1.1
        Domains: evil.com, malware.org
        """
        
        with patch('app.extract_iocs_from_text', return_value=(['8.8.8.8', '1.1.1.1'], ['evil.com', 'malware.org'])):
            with patch('app.log_audit'):
                response = authenticated_client.post('/api/ioc/extract',
                                                     json={'text': text})
                assert response.status_code == 200
                data = json.loads(response.data)
                assert 'ips' in data
                assert 'domains' in data
                assert data['source'] == 'text'
                assert len(data['ips']) == 2
                assert len(data['domains']) == 2
    
    def test_ioc_extract_from_url(self, authenticated_client):
        """Test extracting IOCs from URL."""
        mock_content = "Found: 8.8.8.8 and evil.com"
        
        with patch('app.fetch_url_content', return_value=mock_content):
            with patch('app.extract_iocs_from_text', return_value=(['8.8.8.8'], ['evil.com'])):
                with patch('app.log_audit'):
                    response = authenticated_client.post('/api/ioc/extract',
                                                         json={'url': 'https://example.com/iocs.txt'})
                    assert response.status_code == 200
                    data = json.loads(response.data)
                    assert data['source'] == 'url'
    
    def test_ioc_extract_url_fetch_error(self, authenticated_client):
        """Test error handling when URL fetch fails."""
        import requests
        
        with patch('app.fetch_url_content', side_effect=requests.exceptions.RequestException('Connection failed')):
            response = authenticated_client.post('/api/ioc/extract',
                                                 json={'url': 'https://invalid.example.com'})
            assert response.status_code == 400
            data = json.loads(response.data)
            assert 'Failed to fetch URL' in data['error']
    
    def test_ioc_extract_url_value_error(self, authenticated_client):
        """Test error handling when URL validation fails."""
        with patch('app.fetch_url_content', side_effect=ValueError('Invalid URL')):
            response = authenticated_client.post('/api/ioc/extract',
                                                 json={'url': 'not-a-valid-url'})
            assert response.status_code == 400
            data = json.loads(response.data)
            assert 'Invalid URL' in data['error']
    
    def test_ioc_extract_from_text_file(self, authenticated_client):
        """Test extracting IOCs from uploaded text file."""
        file_content = b"IPs: 8.8.8.8\nDomains: test.com"
        
        with patch('app.extract_iocs_from_text', return_value=(['8.8.8.8'], ['test.com'])):
            with patch('app.log_audit'):
                response = authenticated_client.post(
                    '/api/ioc/extract',
                    data={'file': (io.BytesIO(file_content), 'iocs.txt')},
                    content_type='multipart/form-data'
                )
                assert response.status_code == 200
                data = json.loads(response.data)
                assert data['source'] == 'text_upload'
    
    def test_ioc_extract_from_pdf_file(self, authenticated_client):
        """Test extracting IOCs from uploaded PDF file."""
        # Fake PDF content
        pdf_content = b'%PDF-1.4 fake pdf content'
        
        with patch('app.extract_text_from_pdf', return_value='IP: 8.8.8.8 Domain: evil.com'):
            with patch('app.extract_iocs_from_text', return_value=(['8.8.8.8'], ['evil.com'])):
                with patch('app.log_audit'):
                    response = authenticated_client.post(
                        '/api/ioc/extract',
                        data={'file': (io.BytesIO(pdf_content), 'report.pdf')},
                        content_type='multipart/form-data'
                    )
                    assert response.status_code == 200
                    data = json.loads(response.data)
                    assert data['source'] == 'pdf_upload'
    
    def test_ioc_extract_pdf_error(self, authenticated_client):
        """Test error handling when PDF extraction fails."""
        pdf_content = b'invalid pdf'
        
        with patch('app.extract_text_from_pdf', side_effect=ValueError('Could not extract text from PDF')):
            response = authenticated_client.post(
                '/api/ioc/extract',
                data={'file': (io.BytesIO(pdf_content), 'bad.pdf')},
                content_type='multipart/form-data'
            )
            assert response.status_code == 400
            data = json.loads(response.data)
            assert 'PDF' in data['error'] or 'extract' in data['error'].lower()
    
    def test_ioc_extract_from_form_text(self, authenticated_client):
        """Test extracting IOCs from form data text."""
        with patch('app.extract_iocs_from_text', return_value=(['8.8.8.8'], ['test.com'])):
            with patch('app.log_audit'):
                response = authenticated_client.post(
                    '/api/ioc/extract',
                    data={'text': 'IP: 8.8.8.8 Domain: test.com'},
                    content_type='application/x-www-form-urlencoded'
                )
                assert response.status_code == 200
                data = json.loads(response.data)
                assert data['source'] == 'text'
    
    def test_ioc_extract_returns_sorted_results(self, authenticated_client):
        """Test that results are sorted."""
        with patch('app.extract_iocs_from_text', return_value=(['8.8.8.8', '1.1.1.1'], ['zoo.com', 'apple.com'])):
            with patch('app.log_audit'):
                response = authenticated_client.post('/api/ioc/extract',
                                                     json={'text': 'test'})
                assert response.status_code == 200
                data = json.loads(response.data)
                # Results should be sorted
                assert data['ips'] == sorted(data['ips'])
                assert data['domains'] == sorted(data['domains'])
    
    def test_ioc_extract_returns_total_count(self, authenticated_client):
        """Test that total count is returned."""
        with patch('app.extract_iocs_from_text', return_value=(['8.8.8.8', '1.1.1.1'], ['test.com'])):
            with patch('app.log_audit'):
                response = authenticated_client.post('/api/ioc/extract',
                                                     json={'text': 'test'})
                assert response.status_code == 200
                data = json.loads(response.data)
                assert data['total'] == 3  # 2 IPs + 1 domain
    
    def test_ioc_extract_logs_audit(self, authenticated_client):
        """Test that extraction is logged to audit."""
        with patch('app.extract_iocs_from_text', return_value=(['8.8.8.8'], ['test.com'])):
            with patch('app.log_audit') as mock_audit:
                response = authenticated_client.post('/api/ioc/extract',
                                                     json={'text': 'test 8.8.8.8 test.com'})
                assert response.status_code == 200
                mock_audit.assert_called_once()
                call_args = mock_audit.call_args
                assert call_args[0][0] == 'ioc_extract'
                # Details are the 4th positional argument
                details = call_args[0][3]
                assert 'ip_count' in details
                assert 'domain_count' in details
    
    def test_ioc_extract_empty_text(self, authenticated_client):
        """Test extraction from empty text."""
        response = authenticated_client.post('/api/ioc/extract',
                                             json={'text': ''})
        assert response.status_code == 400
    
    def test_ioc_extract_whitespace_only_text(self, authenticated_client):
        """Test extraction from whitespace-only text."""
        response = authenticated_client.post('/api/ioc/extract',
                                             json={'text': '   '})
        assert response.status_code == 400
    
    def test_ioc_extract_url_takes_precedence(self, authenticated_client):
        """Test that URL takes precedence over text when both provided."""
        mock_url_content = "URL content: 8.8.8.8"
        
        with patch('app.fetch_url_content', return_value=mock_url_content) as mock_fetch:
            with patch('app.extract_iocs_from_text', return_value=(['8.8.8.8'], [])):
                with patch('app.log_audit'):
                    response = authenticated_client.post('/api/ioc/extract',
                                                         json={'url': 'https://example.com', 'text': 'ignored'})
                    assert response.status_code == 200
                    data = json.loads(response.data)
                    assert data['source'] == 'url'
                    mock_fetch.assert_called_once()
    
    def test_ioc_extract_no_iocs_found(self, authenticated_client):
        """Test when no IOCs are found in content."""
        with patch('app.extract_iocs_from_text', return_value=([], [])):
            with patch('app.log_audit'):
                response = authenticated_client.post('/api/ioc/extract',
                                                     json={'text': 'No IOCs here, just regular text.'})
                assert response.status_code == 200
                data = json.loads(response.data)
                assert data['ips'] == []
                assert data['domains'] == []
                assert data['total'] == 0
    
    def test_ioc_extract_returns_feature_flags(self, authenticated_client):
        """Test that feature flags are returned."""
        with patch('app.extract_iocs_from_text', return_value=([], [])):
            with patch('app.log_audit'):
                with patch('app.IOCEXTRACT_AVAILABLE', True):
                    with patch('app.TLDEXTRACT_AVAILABLE', True):
                        response = authenticated_client.post('/api/ioc/extract',
                                                             json={'text': 'test'})
                        assert response.status_code == 200
                        data = json.loads(response.data)
                        assert 'defang_support' in data
                        assert 'tld_validation' in data
    
    def test_ioc_extract_file_empty_filename(self, authenticated_client):
        """Test handling of file upload with empty filename."""
        response = authenticated_client.post(
            '/api/ioc/extract',
            data={'file': (io.BytesIO(b''), '')},
            content_type='multipart/form-data'
        )
        # Should return error since no content
        assert response.status_code == 400
