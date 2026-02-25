# Testing Patterns

**Analysis Date:** 2026-02-25

## Test Framework

**Runner:**
- pytest 8.0.0+ (from `requirements.txt`)
- Config: `/c/Users/Joe/Documents/GitHub/logboost-web/pytest.ini`

**Assertion Library:**
- pytest's built-in assert statements

**Run Commands:**
```bash
pytest                          # Run all tests
pytest -m "not slow"           # Skip slow tests
pytest tests/test_authentication.py  # Run single test file
pytest -v                      # Verbose output
pytest --tb=short              # Short traceback format (configured default)
```

**Configuration Details (pytest.ini):**
```ini
[pytest]
testpaths = tests                  # Tests live in tests/ directory
python_files = test_*.py           # Test file naming pattern
python_classes = Test*             # Test class naming pattern
python_functions = test_*          # Test function naming pattern
addopts = -v --tb=short           # Always use verbose + short tracebacks
markers =
    slow: marks tests as slow
    integration: marks tests requiring external services
```

## Test File Organization

**Location:**
- Test files colocated in single directory: `/c/Users/Joe/Documents/GitHub/logboost-web/logboost-web/tests/`
- Tests separate from source code (not co-located with modules)

**Naming:**
- Follows `test_*.py` pattern
- One test file per major feature area:
  - `test_authentication.py` - Auth, passwords, session management
  - `test_api_dns.py` - DNS resolution endpoints
  - `test_api_ioc.py` - IOC extraction endpoints
  - `test_admin_cache.py` - Caching functions
  - `test_file_processing.py` - CSV/file enrichment
  - `test_data_normalization.py` - Domain/IP validation
  - And 16+ more feature-specific test modules

**Fixture Organization:**
- Centralized fixtures in `/c/Users/Joe/Documents/GitHub/logboost-web/logboost-web/tests/conftest.py`
- Contains database, client, and data fixtures
- Scope: function-level isolation (each test gets fresh database)

## Test Structure

**Suite Organization:**
```python
class TestPasswordHashing:
    """Tests for password hashing functions."""

    def test_hash_password_returns_salted_hash(self, test_db):
        """Test that hash_password returns a salted hash in correct format."""
        import admin

        password = 'testpassword123'
        hashed = admin.hash_password(password)

        # Should be in format salt:hash
        assert ':' in hashed
        parts = hashed.split(':')
        assert len(parts) == 2
```

**Patterns:**
- Test classes group related tests: `class Test<Functionality>`
- Each test method name starts with `test_` prefix
- Docstrings describe what is being tested
- Arrange/Act/Assert pattern (though not strictly enforced):
  1. Setup: Get data/create objects
  2. Execute: Call function being tested
  3. Verify: Assert expected outcome

**Fixtures Used:**
```python
def test_something(self, test_db, authenticated_client, app):
    # test_db: isolated SQLite database per test
    # authenticated_client: Flask test client with login session
    # app: Flask application instance configured for testing
```

## Fixture Patterns

**Database Fixture (test_db):**
```python
@pytest.fixture(scope='function')
def test_db(tmp_path, monkeypatch):
    """Create a temporary database for each test.

    Uses monkeypatch to ensure DB_PATH is changed BEFORE any imports
    and is properly isolated per test.
    """
    db_file = tmp_path / "test_logboost.db"
    import admin
    monkeypatch.setattr(admin, 'DB_PATH', str(db_file))
    admin.init_db()
    yield str(db_file)
    # Cleanup is automatic with monkeypatch
```
- Scope: `function` (fresh database per test)
- Uses `monkeypatch` to override module-level `DB_PATH` before imports
- Automatically initializes schema with `admin.init_db()`

**Client Fixtures:**
```python
@pytest.fixture
def client(app):
    """Create test client."""
    return app.test_client()

@pytest.fixture
def authenticated_client(app, test_db):
    """Create authenticated test client with admin role (default for API access)."""
    import admin

    # Create test user
    conn = admin.get_db()
    cursor = conn.cursor()
    password_hash = admin.hash_password('testpassword')
    cursor.execute(
        'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
        ('testuser', password_hash, 'admin')
    )
    conn.commit()
    conn.close()

    client = app.test_client()

    # Fetch user ID from database
    conn = admin.get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM users WHERE username = ?', ('testuser',))
    row = cursor.fetchone()
    user_id = row['id'] if row else 1
    conn.close()

    # Set session with login credentials
    with client.session_transaction() as sess:
        sess['logged_in'] = True
        sess['user_id'] = user_id
        sess['username'] = 'testuser'
        sess['user_role'] = 'admin'

    return client
```
- Three authentication levels provided:
  - `client`: unauthenticated
  - `authenticated_client`: admin user
  - `regular_user_client`: non-admin user
  - `admin_client`: explicit admin alias

**Data Fixtures (Sample Data):**
```python
@pytest.fixture
def sample_dns_results():
    """Sample DNS resolution results."""
    return {
        'A': ['93.184.216.34'],
        'AAAA': ['2606:2800:220:1:248:1893:25c8:1946'],
        'MX': ['0 mail.example.com.'],
        'NS': ['ns1.example.com.', 'ns2.example.com.'],
        'TXT': ['v=spf1 -all']
    }

@pytest.fixture
def sample_whois_results():
    """Sample WHOIS resolution results."""
    return {
        'domain': 'example.com',
        'registrar': 'Example Registrar, LLC',
        # ... more fields ...
    }

@pytest.fixture
def valid_ipv4_addresses():
    """Valid IPv4 addresses for testing."""
    return [
        '192.168.1.1',
        '10.0.0.1',
        '172.16.0.1',
        '255.255.255.255',
        '0.0.0.0',
        '8.8.8.8',
        '93.184.216.34'
    ]
```
- Fixtures provide realistic sample data for multiple test scenarios
- Includes DNS results, WHOIS data, IP address lists
- Also include edge-case data like `invalid_ip_addresses`, `sample_circl_pdns_with_ip_rdata`

## Mocking

**Framework:** `unittest.mock` (standard library)

**Patterns:**
```python
from unittest.mock import patch, MagicMock, Mock

# Patch function return value
with patch('app.extract_iocs_from_text', return_value=(['8.8.8.8', '1.1.1.1'], ['evil.com'])):
    response = authenticated_client.post('/api/ioc/extract', json={'text': text})

# Patch with side effect (exception)
with patch('app.fetch_url_content', side_effect=requests.exceptions.RequestException('Connection failed')):
    response = authenticated_client.post('/api/ioc/extract', json={'url': 'https://invalid.example.com'})

# Mock DNS responses with custom classes
class MockRdataA:
    def __init__(self, ip):
        self.ip = ip
    def __str__(self):
        return self.ip

class MockAnswer:
    def __init__(self, records):
        self.records = records
    def __iter__(self):
        return iter(self.records)
```

**What to Mock:**
- External API calls (Shodan, CIRCL, ViewDNS, HackerTarget)
- Network operations (DNS lookups, URL fetches)
- File operations (PDF parsing, CSV reading)
- Subprocess calls (`run_logboost()`)
- Audit logging functions

**What NOT to Mock:**
- Database operations (use real `test_db` fixture instead)
- Authentication functions (test with real password hashing/verification)
- Input validation functions (test edge cases without mocking)
- Session management (use Flask test client session fixtures)

## Testing Database Operations

**Pattern:**
- Use `test_db` fixture to get isolated database
- Use `admin.get_db()` to get connection
- Create test data directly via cursor:
  ```python
  import admin

  conn = admin.get_db()
  cursor = conn.cursor()
  password_hash = admin.hash_password('testpassword')
  cursor.execute(
      'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
      ('testuser', password_hash, 'admin')
  )
  conn.commit()
  conn.close()
  ```

## Testing API Endpoints

**Pattern:**
```python
class TestIocExtractApi:
    """Tests for /api/ioc/extract endpoint."""

    def test_ioc_extract_requires_auth(self, client):
        """Test that endpoint requires authentication."""
        response = client.post('/api/ioc/extract', json={'text': 'test 8.8.8.8 example.com'})
        assert response.status_code in (302, 401, 403)

    def test_ioc_extract_success(self, authenticated_client):
        """Test successful IOC extraction."""
        with patch('app.extract_iocs_from_text', return_value=(['8.8.8.8'], ['evil.com'])):
            with patch('app.log_audit'):
                response = authenticated_client.post('/api/ioc/extract', json={'text': 'some text'})
                assert response.status_code == 200
                data = json.loads(response.data)
                assert 'ips' in data
                assert 'domains' in data
```

**Patterns:**
- Use appropriate client fixture for auth level required
- Test 3 scenarios per endpoint:
  1. Unauthenticated access (should fail)
  2. Successful happy path
  3. Error cases (missing data, invalid input, external service failures)
- Parse JSON responses: `data = json.loads(response.data)`
- Assert response status codes and data structure
- Mock external service calls within test

## Testing Authentication

**Pattern:**
```python
class TestPasswordHashing:
    """Tests for password hashing functions."""

    def test_hash_password_returns_salted_hash(self, test_db):
        """Test that hash_password returns a salted hash in correct format."""
        import admin

        password = 'testpassword123'
        hashed = admin.hash_password(password)

        # Should be in format salt:hash
        assert ':' in hashed
        parts = hashed.split(':')
        assert len(parts) == 2
        assert len(parts[0]) == 32  # Salt: 32 hex chars
        assert len(parts[1]) == 64  # Hash: 64 hex chars

    def test_verify_password_correct(self, test_db):
        """Test that verify_password returns True for correct password."""
        import admin

        password = 'correctpassword'
        hashed = admin.hash_password(password)

        assert admin.verify_password(password, hashed) == True

    def test_verify_password_incorrect(self, test_db):
        """Test that verify_password returns False for incorrect password."""
        import admin

        password = 'correctpassword'
        hashed = admin.hash_password(password)

        assert admin.verify_password('wrongpassword', hashed) == False
```

**Edge Cases Tested:**
- Valid and invalid passwords
- Empty passwords
- Invalid hash formats
- Special characters in passwords
- Unicode characters
- Very long passwords

## Testing Error Cases

**Pattern:**
```python
def test_ioc_extract_url_fetch_error(self, authenticated_client):
    """Test error handling when URL fetch fails."""
    import requests

    with patch('app.fetch_url_content', side_effect=requests.exceptions.RequestException('Connection failed')):
        response = authenticated_client.post('/api/ioc/extract', json={'url': 'https://invalid.example.com'})
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'Failed to fetch URL' in data['error']
```

**Common Error Scenarios:**
- Missing required parameters → 400 status
- Authentication failures → 302/401 redirect
- External service errors → caught and returned as 400 with error message
- Invalid input validation failures → 400 with validation message
- File upload too large → appropriate error response

## Test Coverage

**Requirements:** Not enforced (no coverage tool configuration)

**Coverage Areas:**
- All public API endpoints tested
- Authentication and session management
- All validation functions (domains, IPs, URLs)
- Cache operations (set/get/clear)
- Database operations
- Error paths for external service calls

## Async Testing

**Pattern:**
Tests do NOT use async/await. All tests are synchronous.

## File Upload Testing

**Pattern:**
```python
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
```

- Use `io.BytesIO()` for in-memory file uploads
- Provide filename and content type
- Mock file processing functions to avoid actual parsing

## Test Markers

**Available Markers:**
```
@pytest.mark.slow        # Marks tests as slow (deselect with '-m "not slow"')
@pytest.mark.integration # Marks tests requiring external services
```

## Test Execution Best Practices

**Database Isolation:**
- Each test function gets its own fresh database (scope='function')
- Monkeypatch ensures module-level DB_PATH is overridden before imports
- Automatic cleanup via pytest fixture teardown

**Session Isolation:**
- Each client fixture creates independent session
- No shared state between tests
- Flask test client allows `session_transaction()` for setting session data

**Mocking External Services:**
- All external API calls mocked by default (no real network requests)
- Tests run offline and fast
- Specific response patterns tested via mock return_value
- Error conditions tested via side_effect exceptions

---

*Testing analysis: 2026-02-25*
