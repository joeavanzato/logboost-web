"""
Tests for URL fetching functionality with SSRF protection.

Tests cover:
- safe_fetch_url function - SSRF-protected URL fetching
- Redirect handling with validation at each hop
- Content size limits
- Error handling
"""

import pytest
from unittest.mock import patch, MagicMock


class TestSafeFetchUrl:
    """Tests for safe_fetch_url function with SSRF protection."""
    
    def test_safe_fetch_url_basic_success(self):
        """Test successful URL fetch."""
        from app import safe_fetch_url
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {'Content-Type': 'text/plain', 'Content-Length': '5'}
        mock_response.iter_content = MagicMock(return_value=[b'hello'])
        mock_response.raise_for_status = MagicMock()
        
        with patch('security.validate_url_for_ssrf', return_value=(True, None)):
            with patch('requests.Session') as MockSession:
                mock_session = MagicMock()
                mock_session.get.return_value = mock_response
                MockSession.return_value = mock_session
                
                content, content_type = safe_fetch_url('https://example.com/test.txt')
                
                assert content == b'hello'
                assert 'text/plain' in content_type
    
    def test_safe_fetch_url_ssrf_blocked(self):
        """Test that SSRF-blocked URLs raise ValueError."""
        from app import safe_fetch_url
        
        with patch('security.validate_url_for_ssrf', return_value=(False, 'Private IP address')):
            with pytest.raises(ValueError) as exc_info:
                safe_fetch_url('http://192.168.1.1/admin')
            
            assert 'Private IP address' in str(exc_info.value)
    
    def test_safe_fetch_url_redirect_to_blocked(self):
        """Test that redirects to SSRF-blocked URLs are rejected."""
        from app import safe_fetch_url
        
        # First call validates original URL (OK)
        # Second call on redirect target fails
        validate_calls = [(True, None), (False, 'Redirect to private IP')]
        
        mock_response = MagicMock()
        mock_response.status_code = 302
        mock_response.headers = {'Location': 'http://192.168.1.1/admin'}
        
        with patch('security.validate_url_for_ssrf', side_effect=validate_calls):
            with patch('requests.Session') as MockSession:
                mock_session = MagicMock()
                mock_session.get.return_value = mock_response
                MockSession.return_value = mock_session
                
                with pytest.raises(ValueError) as exc_info:
                    safe_fetch_url('https://example.com/redirect')
                
                assert 'Redirect to blocked URL' in str(exc_info.value)
    
    def test_safe_fetch_url_too_many_redirects(self):
        """Test that too many redirects raises ValueError."""
        from app import safe_fetch_url, MAX_REDIRECTS
        
        mock_response = MagicMock()
        mock_response.status_code = 302
        mock_response.headers = {'Location': 'https://example.com/next'}
        
        with patch('security.validate_url_for_ssrf', return_value=(True, None)):
            with patch('requests.Session') as MockSession:
                mock_session = MagicMock()
                mock_session.get.return_value = mock_response
                MockSession.return_value = mock_session
                
                with pytest.raises(ValueError) as exc_info:
                    safe_fetch_url('https://example.com/start')
                
                assert 'Too many redirects' in str(exc_info.value)
    
    def test_safe_fetch_url_redirect_no_location(self):
        """Test that redirect without Location header raises ValueError."""
        from app import safe_fetch_url
        
        mock_response = MagicMock()
        mock_response.status_code = 302
        mock_response.headers = {}  # No Location header
        
        with patch('security.validate_url_for_ssrf', return_value=(True, None)):
            with patch('requests.Session') as MockSession:
                mock_session = MagicMock()
                mock_session.get.return_value = mock_response
                MockSession.return_value = mock_session
                
                with pytest.raises(ValueError) as exc_info:
                    safe_fetch_url('https://example.com/redirect')
                
                assert 'Location header' in str(exc_info.value)
    
    def test_safe_fetch_url_relative_redirect(self):
        """Test that relative redirects are handled properly."""
        from app import safe_fetch_url
        
        redirect_response = MagicMock()
        redirect_response.status_code = 302
        redirect_response.headers = {'Location': '/new-path'}
        
        final_response = MagicMock()
        final_response.status_code = 200
        final_response.headers = {'Content-Type': 'text/html'}
        final_response.iter_content = MagicMock(return_value=[b'<html>'])
        final_response.raise_for_status = MagicMock()
        
        with patch('security.validate_url_for_ssrf', return_value=(True, None)):
            with patch('requests.Session') as MockSession:
                mock_session = MagicMock()
                mock_session.get.side_effect = [redirect_response, final_response]
                MockSession.return_value = mock_session
                
                content, content_type = safe_fetch_url('https://example.com/old-path')
                
                assert content == b'<html>'
    
    def test_safe_fetch_url_content_length_exceeded(self):
        """Test that response with Content-Length > max_size is rejected."""
        from app import safe_fetch_url
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {'Content-Length': '20000000'}  # 20MB
        mock_response.raise_for_status = MagicMock()
        
        with patch('security.validate_url_for_ssrf', return_value=(True, None)):
            with patch('requests.Session') as MockSession:
                mock_session = MagicMock()
                mock_session.get.return_value = mock_response
                MockSession.return_value = mock_session
                
                with pytest.raises(ValueError) as exc_info:
                    safe_fetch_url('https://example.com/large.bin', max_size=1000000)
                
                assert 'too large' in str(exc_info.value).lower()
    
    def test_safe_fetch_url_streaming_exceeded(self):
        """Test that response exceeding max_size during streaming is rejected."""
        from app import safe_fetch_url
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {}  # No Content-Length, so we rely on streaming
        mock_response.raise_for_status = MagicMock()
        # Return chunks that exceed max_size
        mock_response.iter_content = MagicMock(return_value=[b'x' * 5000, b'x' * 5000, b'x' * 5000])
        
        with patch('security.validate_url_for_ssrf', return_value=(True, None)):
            with patch('requests.Session') as MockSession:
                mock_session = MagicMock()
                mock_session.get.return_value = mock_response
                MockSession.return_value = mock_session
                
                with pytest.raises(ValueError) as exc_info:
                    safe_fetch_url('https://example.com/stream.bin', max_size=10000)
                
                assert 'exceeded maximum size' in str(exc_info.value)
    
    def test_safe_fetch_url_uses_default_max_size(self):
        """Test that default max_size is fetched from settings."""
        from app import safe_fetch_url
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {'Content-Type': 'text/plain'}
        mock_response.iter_content = MagicMock(return_value=[b'data'])
        mock_response.raise_for_status = MagicMock()
        
        with patch('security.validate_url_for_ssrf', return_value=(True, None)):
            with patch('security.get_max_url_fetch_size', return_value=5000000) as mock_max:
                with patch('requests.Session') as MockSession:
                    mock_session = MagicMock()
                    mock_session.get.return_value = mock_response
                    MockSession.return_value = mock_session
                    
                    safe_fetch_url('https://example.com/file.txt')
                    
                    mock_max.assert_called_once()
    
    def test_safe_fetch_url_handles_multiple_redirect_codes(self):
        """Test that all redirect status codes are handled."""
        from app import safe_fetch_url
        
        for status_code in [301, 302, 303, 307, 308]:
            redirect_response = MagicMock()
            redirect_response.status_code = status_code
            redirect_response.headers = {'Location': 'https://example.com/final'}
            
            final_response = MagicMock()
            final_response.status_code = 200
            final_response.headers = {'Content-Type': 'text/plain'}
            final_response.iter_content = MagicMock(return_value=[b'ok'])
            final_response.raise_for_status = MagicMock()
            
            with patch('security.validate_url_for_ssrf', return_value=(True, None)):
                with patch('requests.Session') as MockSession:
                    mock_session = MagicMock()
                    mock_session.get.side_effect = [redirect_response, final_response]
                    MockSession.return_value = mock_session
                    
                    content, _ = safe_fetch_url(f'https://example.com/redirect-{status_code}')
                    assert content == b'ok'
    
    def test_safe_fetch_url_multiple_chunks(self):
        """Test handling of response with multiple chunks."""
        from app import safe_fetch_url
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {'Content-Type': 'application/octet-stream'}
        mock_response.iter_content = MagicMock(return_value=[b'chunk1', b'chunk2', b'chunk3'])
        mock_response.raise_for_status = MagicMock()
        
        with patch('security.validate_url_for_ssrf', return_value=(True, None)):
            with patch('requests.Session') as MockSession:
                mock_session = MagicMock()
                mock_session.get.return_value = mock_response
                MockSession.return_value = mock_session
                
                content, _ = safe_fetch_url('https://example.com/data.bin')
                
                assert content == b'chunk1chunk2chunk3'
    
    def test_safe_fetch_url_empty_response(self):
        """Test handling of empty response."""
        from app import safe_fetch_url
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {'Content-Type': 'text/plain'}
        mock_response.iter_content = MagicMock(return_value=[])
        mock_response.raise_for_status = MagicMock()
        
        with patch('security.validate_url_for_ssrf', return_value=(True, None)):
            with patch('requests.Session') as MockSession:
                mock_session = MagicMock()
                mock_session.get.return_value = mock_response
                MockSession.return_value = mock_session
                
                content, content_type = safe_fetch_url('https://example.com/empty')
                
                assert content == b''
                assert 'text/plain' in content_type
    
    def test_safe_fetch_url_no_content_type(self):
        """Test handling of response without Content-Type header."""
        from app import safe_fetch_url
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {}  # No Content-Type
        mock_response.iter_content = MagicMock(return_value=[b'data'])
        mock_response.raise_for_status = MagicMock()
        
        with patch('security.validate_url_for_ssrf', return_value=(True, None)):
            with patch('requests.Session') as MockSession:
                mock_session = MagicMock()
                mock_session.get.return_value = mock_response
                MockSession.return_value = mock_session
                
                content, content_type = safe_fetch_url('https://example.com/unknown')
                
                assert content == b'data'
                assert content_type == ''
    
    def test_safe_fetch_url_chain_of_redirects(self):
        """Test following a chain of valid redirects."""
        from app import safe_fetch_url
        
        redirect1 = MagicMock()
        redirect1.status_code = 302
        redirect1.headers = {'Location': 'https://example.com/step2'}
        
        redirect2 = MagicMock()
        redirect2.status_code = 302
        redirect2.headers = {'Location': 'https://example.com/step3'}
        
        final = MagicMock()
        final.status_code = 200
        final.headers = {'Content-Type': 'text/plain'}
        final.iter_content = MagicMock(return_value=[b'done'])
        final.raise_for_status = MagicMock()
        
        with patch('security.validate_url_for_ssrf', return_value=(True, None)):
            with patch('requests.Session') as MockSession:
                mock_session = MagicMock()
                mock_session.get.side_effect = [redirect1, redirect2, final]
                MockSession.return_value = mock_session
                
                content, _ = safe_fetch_url('https://example.com/step1')
                
                assert content == b'done'
                assert mock_session.get.call_count == 3


class TestFetchUrlContent:
    """Tests for fetch_url_content helper function."""
    
    def test_fetch_url_content_text(self):
        """Test fetching text content from URL."""
        from app import fetch_url_content
        
        with patch('app.safe_fetch_url', return_value=(b'Hello World', 'text/plain')):
            content = fetch_url_content('https://example.com/text.txt')
            assert content == 'Hello World'
    
    def test_fetch_url_content_html(self):
        """Test fetching HTML content from URL."""
        from app import fetch_url_content
        
        html = b'<html><body>Content</body></html>'
        with patch('app.safe_fetch_url', return_value=(html, 'text/html')):
            content = fetch_url_content('https://example.com/page.html')
            assert 'Content' in content
    
    def test_fetch_url_content_pdf(self):
        """Test that PDF content triggers PDF extraction."""
        from app import fetch_url_content
        
        pdf_content = b'%PDF-1.4 mock pdf content'
        
        with patch('app.safe_fetch_url', return_value=(pdf_content, 'application/pdf')):
            with patch('app.extract_text_from_pdf', return_value='Extracted PDF text') as mock_extract:
                content = fetch_url_content('https://example.com/document.pdf')
                
                mock_extract.assert_called_once_with(pdf_content)
                assert content == 'Extracted PDF text'
    
    def test_fetch_url_content_error(self):
        """Test error handling in fetch_url_content."""
        from app import fetch_url_content
        
        with patch('app.safe_fetch_url', side_effect=ValueError('SSRF blocked')):
            with pytest.raises(ValueError):
                fetch_url_content('http://192.168.1.1/malicious')
    
    def test_fetch_url_content_binary_as_text(self):
        """Test handling binary content with text decoding errors."""
        from app import fetch_url_content
        
        # Binary content that can't be decoded as UTF-8
        binary_content = b'\x89PNG\r\n\x1a\n\x00\x00\x00'
        
        with patch('app.safe_fetch_url', return_value=(binary_content, 'image/png')):
            # Should handle decode error gracefully
            content = fetch_url_content('https://example.com/image.png')
            # Will either decode with errors='replace' or return empty
            assert isinstance(content, str)


class TestExtractTextFromPdf:
    """Tests for PDF text extraction."""
    
    def test_extract_text_from_pdf_success(self):
        """Test successful PDF text extraction."""
        from app import extract_text_from_pdf
        
        mock_reader = MagicMock()
        mock_page = MagicMock()
        mock_page.extract_text.return_value = 'Page 1 content'
        mock_reader.pages = [mock_page]
        
        with patch('pypdf.PdfReader', return_value=mock_reader):
            result = extract_text_from_pdf(b'%PDF-1.4 content')
            assert 'Page 1 content' in result
    
    def test_extract_text_from_pdf_multiple_pages(self):
        """Test PDF extraction with multiple pages."""
        from app import extract_text_from_pdf
        
        mock_reader = MagicMock()
        mock_page1 = MagicMock()
        mock_page1.extract_text.return_value = 'Page 1'
        mock_page2 = MagicMock()
        mock_page2.extract_text.return_value = 'Page 2'
        mock_reader.pages = [mock_page1, mock_page2]
        
        with patch('pypdf.PdfReader', return_value=mock_reader):
            result = extract_text_from_pdf(b'%PDF-1.4 content')
            assert 'Page 1' in result
            assert 'Page 2' in result
    
    def test_extract_text_from_pdf_empty_pages(self):
        """Test PDF extraction when pages return empty text."""
        from app import extract_text_from_pdf
        
        mock_reader = MagicMock()
        mock_page = MagicMock()
        mock_page.extract_text.return_value = ''
        mock_reader.pages = [mock_page]
        
        with patch('pypdf.PdfReader', return_value=mock_reader):
            result = extract_text_from_pdf(b'%PDF-1.4 content')
            assert result == ''
    
    def test_extract_text_from_pdf_error(self):
        """Test PDF extraction error handling."""
        from app import extract_text_from_pdf
        
        with patch('pypdf.PdfReader', side_effect=Exception('Invalid PDF')):
            with pytest.raises(ValueError) as exc_info:
                extract_text_from_pdf(b'not a pdf')
            
            assert 'Failed to parse PDF' in str(exc_info.value)
