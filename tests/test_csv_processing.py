"""
Tests for CSV Processing Functions.

Tests cover:
- read_csv_paginated() - Paginated CSV reading
- read_csv_all() - Full CSV reading
- compute_statistics() - Compute result statistics
- get_unique_column_values() - Get column unique values
- get_stats() endpoint - Statistics generation endpoint
- results_page() endpoint - Results pagination endpoint
- get_column_values() endpoint - Column values endpoint
"""

import pytest
import json
import csv
from pathlib import Path
from unittest.mock import patch, MagicMock


@pytest.fixture
def sample_csv_file(tmp_path):
    """Create a sample CSV file for testing."""
    csv_file = tmp_path / 'sample.csv'
    with open(csv_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['IP', 'lb_Country', 'lb_ASN', 'lb_City'])
        writer.writerow(['8.8.8.8', 'US', 'AS15169', 'Mountain View'])
        writer.writerow(['1.1.1.1', 'AU', 'AS13335', 'Sydney'])
        writer.writerow(['9.9.9.9', 'US', 'AS19281', 'Reston'])
        writer.writerow(['208.67.222.222', 'US', 'AS36692', 'San Francisco'])
        writer.writerow(['208.67.220.220', 'US', 'AS36692', 'San Francisco'])
    return csv_file


@pytest.fixture
def large_csv_file(tmp_path):
    """Create a larger CSV file for pagination testing."""
    csv_file = tmp_path / 'large.csv'
    with open(csv_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['IP', 'Country'])
        for i in range(100):
            writer.writerow([f'192.168.1.{i}', 'US' if i % 2 == 0 else 'CA'])
    return csv_file


@pytest.fixture
def enrichment_csv_file(tmp_path):
    """Create a CSV file with enrichment columns for statistics testing."""
    csv_file = tmp_path / 'enriched.csv'
    with open(csv_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['IP', 'lb_Country', 'lb_ASN', 'lb_ThreatCategories', 'lb_ThreatFeedCount', 'lb_Domains'])
        writer.writerow(['8.8.8.8', 'US', 'AS15169 GOOGLE', 'none', '0', 'dns.google'])
        writer.writerow(['185.220.100.1', 'DE', 'AS24940 HETZNER', 'tor|proxy', '2', 'example.com'])
        writer.writerow(['185.220.100.2', 'DE', 'AS24940 HETZNER', 'tor', '1', 'test.com'])
        writer.writerow(['1.1.1.1', 'AU', 'AS13335 CLOUDFLARE', 'none', '0', 'one.one.one.one'])
        writer.writerow(['45.33.32.156', 'US', 'AS63949 LINODE', 'scanner', '1', 'scanme.nmap.org'])
    return csv_file


class TestReadCsvPaginated:
    """Tests for read_csv_paginated function."""
    
    def test_read_first_page(self, sample_csv_file):
        """Test reading first page of CSV."""
        from app import read_csv_paginated
        
        result = read_csv_paginated(sample_csv_file, page=1, page_size=2)
        
        assert 'error' not in result
        assert result['headers'] == ['IP', 'lb_Country', 'lb_ASN', 'lb_City']
        assert len(result['rows']) == 2
        assert result['total_rows'] == 5
        assert result['page'] == 1
        assert result['page_size'] == 2
        assert result['total_pages'] == 3
    
    def test_read_middle_page(self, sample_csv_file):
        """Test reading middle page of CSV."""
        from app import read_csv_paginated
        
        result = read_csv_paginated(sample_csv_file, page=2, page_size=2)
        
        assert len(result['rows']) == 2
        assert result['page'] == 2
    
    def test_read_last_page(self, sample_csv_file):
        """Test reading last page of CSV."""
        from app import read_csv_paginated
        
        result = read_csv_paginated(sample_csv_file, page=3, page_size=2)
        
        assert len(result['rows']) == 1  # Only 1 row on last page
        assert result['page'] == 3
    
    def test_read_beyond_last_page(self, sample_csv_file):
        """Test reading page beyond available data."""
        from app import read_csv_paginated
        
        result = read_csv_paginated(sample_csv_file, page=10, page_size=2)
        
        assert len(result['rows']) == 0
        assert result['total_rows'] == 5
    
    def test_read_large_page_size(self, sample_csv_file):
        """Test reading with page size larger than data."""
        from app import read_csv_paginated
        
        result = read_csv_paginated(sample_csv_file, page=1, page_size=100)
        
        assert len(result['rows']) == 5  # All rows fit in one page
        assert result['total_pages'] == 1
    
    def test_read_nonexistent_file(self, tmp_path):
        """Test reading non-existent file."""
        from app import read_csv_paginated
        
        result = read_csv_paginated(tmp_path / 'nonexistent.csv')
        
        assert 'error' in result
        assert result['rows'] == []
        assert result['headers'] == []
    
    def test_pagination_calculation(self, large_csv_file):
        """Test pagination calculations."""
        from app import read_csv_paginated
        
        result = read_csv_paginated(large_csv_file, page=1, page_size=10)
        
        assert result['total_rows'] == 100
        assert result['total_pages'] == 10
        assert len(result['rows']) == 10
    
    def test_default_pagination(self, sample_csv_file):
        """Test default pagination values."""
        from app import read_csv_paginated
        
        result = read_csv_paginated(sample_csv_file)
        
        assert result['page'] == 1
        assert result['page_size'] == 50  # Default


class TestReadCsvAll:
    """Tests for read_csv_all function."""
    
    def test_read_all_rows(self, sample_csv_file):
        """Test reading all rows from CSV."""
        from app import read_csv_all
        
        result = read_csv_all(sample_csv_file)
        
        assert 'error' not in result
        assert result['headers'] == ['IP', 'lb_Country', 'lb_ASN', 'lb_City']
        assert len(result['rows']) == 5
        assert result['total_rows'] == 5
    
    def test_read_empty_csv(self, tmp_path):
        """Test reading CSV with only headers."""
        from app import read_csv_all
        
        csv_file = tmp_path / 'empty.csv'
        csv_file.write_text('IP,Country\n')
        
        result = read_csv_all(csv_file)
        
        assert result['headers'] == ['IP', 'Country']
        assert result['rows'] == []
        assert result['total_rows'] == 0
    
    def test_read_nonexistent_file(self, tmp_path):
        """Test reading non-existent file."""
        from app import read_csv_all
        
        result = read_csv_all(tmp_path / 'nonexistent.csv')
        
        assert 'error' in result
        assert result['rows'] == []
    
    def test_read_preserves_row_order(self, sample_csv_file):
        """Test that row order is preserved."""
        from app import read_csv_all
        
        result = read_csv_all(sample_csv_file)
        
        # First row should be 8.8.8.8
        assert result['rows'][0][0] == '8.8.8.8'
        # Last row should be 208.67.220.220
        assert result['rows'][-1][0] == '208.67.220.220'


class TestComputeStatistics:
    """Tests for compute_statistics function."""
    
    def test_basic_statistics(self, sample_csv_file):
        """Test computing basic statistics."""
        from app import compute_statistics
        
        stats = compute_statistics(sample_csv_file)
        
        assert stats['total_rows'] == 5
        assert stats['total_columns'] == 4
        assert len(stats['columns']) == 4
    
    def test_column_statistics(self, sample_csv_file):
        """Test column-level statistics."""
        from app import compute_statistics
        
        stats = compute_statistics(sample_csv_file)
        
        # Find the lb_Country column
        country_col = next(c for c in stats['columns'] if c['name'] == 'lb_Country')
        
        assert country_col['is_enrichment'] == True
        assert country_col['unique_count'] == 2  # US and AU
        assert country_col['fill_rate'] == 100.0
    
    def test_enrichment_detection(self, sample_csv_file):
        """Test detection of enrichment columns."""
        from app import compute_statistics
        
        stats = compute_statistics(sample_csv_file)
        
        # IP column is not enrichment
        ip_col = next(c for c in stats['columns'] if c['name'] == 'IP')
        assert ip_col['is_enrichment'] == False
        
        # lb_Country is enrichment
        country_col = next(c for c in stats['columns'] if c['name'] == 'lb_Country')
        assert country_col['is_enrichment'] == True
    
    def test_top_values(self, sample_csv_file):
        """Test top values extraction."""
        from app import compute_statistics
        
        stats = compute_statistics(sample_csv_file)
        
        # Find the lb_Country column
        country_col = next(c for c in stats['columns'] if c['name'] == 'lb_Country')
        
        # US should be most common (4 occurrences)
        assert country_col['top_values'][0][0] == 'US'
        assert country_col['top_values'][0][1] == 4
    
    def test_empty_value_counting(self, tmp_path):
        """Test handling of empty values."""
        from app import compute_statistics
        
        csv_file = tmp_path / 'empty_values.csv'
        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['IP', 'lb_Country'])
            writer.writerow(['8.8.8.8', 'US'])
            writer.writerow(['1.1.1.1', ''])
            writer.writerow(['9.9.9.9', 'none'])
        
        stats = compute_statistics(csv_file)
        country_col = next(c for c in stats['columns'] if c['name'] == 'lb_Country')
        
        assert country_col['empty_count'] == 2  # Empty string and 'none'
    
    def test_threat_summary_extraction(self, enrichment_csv_file):
        """Test extraction of threat intelligence summary."""
        from app import compute_statistics
        
        stats = compute_statistics(enrichment_csv_file)
        
        # Should have threat summary
        assert 'threat_summary' in stats
        if 'categories' in stats['threat_summary']:
            categories = dict(stats['threat_summary']['categories'])
            assert 'tor' in categories or len(categories) > 0
    
    def test_geo_summary_extraction(self, enrichment_csv_file):
        """Test extraction of geo summary."""
        from app import compute_statistics
        
        stats = compute_statistics(enrichment_csv_file)
        
        assert 'geo_summary' in stats
        if 'countries' in stats['geo_summary']:
            assert len(stats['geo_summary']['countries']) > 0
    
    def test_nonexistent_file(self, tmp_path):
        """Test statistics for non-existent file."""
        from app import compute_statistics
        
        stats = compute_statistics(tmp_path / 'nonexistent.csv')
        
        assert stats['total_rows'] == 0
        assert stats['total_columns'] == 0
    
    def test_sample_values_collection(self, sample_csv_file):
        """Test that sample values are collected."""
        from app import compute_statistics
        
        stats = compute_statistics(sample_csv_file)
        
        ip_col = next(c for c in stats['columns'] if c['name'] == 'IP')
        
        assert 'sample_values' in ip_col
        assert len(ip_col['sample_values']) <= 5  # Max 5 samples


class TestGetUniqueColumnValues:
    """Tests for get_unique_column_values function."""
    
    def test_get_values_with_counts(self, sample_csv_file):
        """Test getting unique values with counts."""
        from app import get_unique_column_values
        
        result = get_unique_column_values(sample_csv_file, 'lb_Country')
        
        assert len(result) > 0
        # Should have value and count keys
        assert all('value' in r and 'count' in r for r in result)
    
    def test_values_sorted_by_count(self, sample_csv_file):
        """Test that values are sorted by count descending."""
        from app import get_unique_column_values
        
        result = get_unique_column_values(sample_csv_file, 'lb_Country')
        
        # US should be first (4 occurrences)
        assert result[0]['value'] == 'US'
        assert result[0]['count'] == 4
    
    def test_limit_respected(self, large_csv_file):
        """Test that limit is respected."""
        from app import get_unique_column_values
        
        result = get_unique_column_values(large_csv_file, 'Country', limit=1)
        
        assert len(result) == 1
    
    def test_nonexistent_column(self, sample_csv_file):
        """Test handling of non-existent column."""
        from app import get_unique_column_values
        
        result = get_unique_column_values(sample_csv_file, 'NonExistent')
        
        assert result == []
    
    def test_nonexistent_file(self, tmp_path):
        """Test handling of non-existent file."""
        from app import get_unique_column_values
        
        result = get_unique_column_values(tmp_path / 'nonexistent.csv', 'IP')
        
        assert result == []
    
    def test_empty_values_excluded(self, tmp_path):
        """Test that empty values are excluded."""
        from app import get_unique_column_values
        
        csv_file = tmp_path / 'empty_values.csv'
        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['IP', 'Country'])
            writer.writerow(['8.8.8.8', 'US'])
            writer.writerow(['1.1.1.1', ''])
            writer.writerow(['9.9.9.9', 'CA'])
        
        result = get_unique_column_values(csv_file, 'Country')
        
        values = [r['value'] for r in result]
        assert '' not in values


class TestGetStatsEndpoint:
    """Tests for GET /stats endpoint."""
    
    def test_stats_requires_auth(self, client):
        """Test that endpoint requires authentication."""
        response = client.get('/stats')
        assert response.status_code in (302, 401, 403)
    
    def test_stats_no_results(self, authenticated_client):
        """Test stats when no results available."""
        response = authenticated_client.get('/stats')
        assert response.status_code == 200
        assert b'error' in response.data.lower() or b'No results' in response.data
    
    def test_stats_success(self, authenticated_client, tmp_path):
        """Test successful statistics generation."""
        csv_file = tmp_path / 'results.csv'
        csv_file.write_text('IP,lb_Country\n8.8.8.8,US\n1.1.1.1,AU\n')
        
        with authenticated_client.session_transaction() as sess:
            sess['current_output'] = str(csv_file)
        
        response = authenticated_client.get('/stats')
        assert response.status_code == 200


class TestResultsPageEndpoint:
    """Tests for GET /results/page endpoint."""
    
    def test_results_page_requires_auth(self, client):
        """Test that endpoint requires authentication."""
        response = client.get('/results/page')
        assert response.status_code in (302, 401, 403)
    
    def test_results_page_no_results(self, authenticated_client):
        """Test results page when no results available."""
        response = authenticated_client.get('/results/page')
        assert response.status_code == 200
        assert b'error' in response.data.lower() or b'No results' in response.data
    
    def test_results_page_success(self, authenticated_client):
        """Test successful results page retrieval."""
        import app as app_module
        csv_file = app_module.OUTPUT_FOLDER / 'results.csv'
        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['IP', 'Country'])
            for i in range(100):
                writer.writerow([f'192.168.1.{i}', 'US'])
        
        with authenticated_client.session_transaction() as sess:
            sess['current_output'] = str(csv_file)
        
        response = authenticated_client.get('/results/page?page=1&page_size=10')
        assert response.status_code == 200
    
    def test_results_page_pagination(self, authenticated_client):
        """Test results page with specific pagination."""
        import app as app_module
        csv_file = app_module.OUTPUT_FOLDER / 'results.csv'
        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['IP'])
            for i in range(100):
                writer.writerow([f'192.168.1.{i}'])
        
        with authenticated_client.session_transaction() as sess:
            sess['current_output'] = str(csv_file)
        
        # Get second page
        response = authenticated_client.get('/results/page?page=2&page_size=20')
        assert response.status_code == 200


class TestGetColumnValuesEndpoint:
    """Tests for GET /column-values/<column_name> endpoint."""
    
    def test_column_values_requires_auth(self, client):
        """Test that endpoint requires authentication."""
        response = client.get('/column-values/IP')
        assert response.status_code in (302, 401, 403)
    
    def test_column_values_no_results(self, authenticated_client):
        """Test column values when no results available."""
        response = authenticated_client.get('/column-values/IP')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['values'] == []
    
    def test_column_values_success(self, authenticated_client, tmp_path):
        """Test successful column values retrieval."""
        csv_file = tmp_path / 'results.csv'
        csv_file.write_text('IP,lb_Country\n8.8.8.8,US\n1.1.1.1,AU\n9.9.9.9,US\n')
        
        with authenticated_client.session_transaction() as sess:
            sess['current_output'] = str(csv_file)
        
        response = authenticated_client.get('/column-values/lb_Country')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'values' in data
        assert len(data['values']) == 2  # US and AU
    
    def test_column_values_nonexistent_column(self, authenticated_client, tmp_path):
        """Test column values for non-existent column."""
        csv_file = tmp_path / 'results.csv'
        csv_file.write_text('IP,Country\n8.8.8.8,US\n')
        
        with authenticated_client.session_transaction() as sess:
            sess['current_output'] = str(csv_file)
        
        response = authenticated_client.get('/column-values/NonExistent')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['values'] == []
