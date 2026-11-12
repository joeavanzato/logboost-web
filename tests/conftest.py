"""
Pytest configuration and fixtures for LogBoost Web tests.

IMPORTANT: All tests use isolated in-memory databases to prevent
any modification to the production database.
"""

import os
import sys
import json
import tempfile
import pytest

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Set SECRET_KEY before app import — the startup validation runs at module load time
# and will exit if SECRET_KEY is absent or weak.
os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-pytest-minimum-32-chars')

# Point every data path at a throwaway directory BEFORE the app is imported, so tests
# can never read or write the real admin DB, threats.db, uploads or output.
_TEST_DATA_DIR = tempfile.mkdtemp(prefix='logboost-tests-')
os.environ['LOGBOOST_DB_PATH'] = os.path.join(_TEST_DATA_DIR, 'default.db')
os.environ['THREAT_DB_DIR'] = _TEST_DATA_DIR
os.environ['LOGBOOST_UPLOAD_DIR'] = os.path.join(_TEST_DATA_DIR, 'uploads')
os.environ['LOGBOOST_OUTPUT_DIR'] = os.path.join(_TEST_DATA_DIR, 'output')


import admin as _admin
_admin.PBKDF2_ITERATIONS = 1000  # real value (600k) would add minutes of hashing to the suite


@pytest.fixture(scope='session', autouse=True)
def _throwaway_runtime():
    """Schema + data dirs in the throwaway location; no scheduler or warm-up thread."""
    import admin
    import app as app_module
    admin.init_db()
    app_module.UPLOAD_FOLDER.mkdir(exist_ok=True)
    app_module.OUTPUT_FOLDER.mkdir(exist_ok=True)
    yield
    import shutil
    shutil.rmtree(_TEST_DATA_DIR, ignore_errors=True)


@pytest.fixture(scope='function')
def test_db(tmp_path, monkeypatch):
    """Create a temporary database for each test.
    
    Uses monkeypatch to ensure DB_PATH is changed BEFORE any imports
    and is properly isolated per test.
    """
    # Create temp database file
    db_file = tmp_path / "test_logboost.db"
    
    # Use monkeypatch to override DB_PATH - this happens before module access
    import admin
    monkeypatch.setattr(admin, 'DB_PATH', str(db_file))
    
    # Initialize the database schema
    admin.init_db()
    
    yield str(db_file)
    
    # Cleanup is automatic with monkeypatch


@pytest.fixture(scope='function')
def app(test_db, monkeypatch):
    """Create Flask application for testing.
    
    Depends on test_db to ensure database is isolated.
    """
    import admin
    from app import app as flask_app
    
    # Configure for testing
    flask_app.config.update({
        'TESTING': True,
        'SECRET_KEY': 'test-secret-key-for-pytest-minimum-32-chars',
        'WTF_CSRF_ENABLED': False,
    })
    
    yield flask_app


@pytest.fixture
def admin_exists(test_db):
    """An admin account exists, so /login does not redirect to first-run /setup."""
    import admin
    conn = admin.get_db()
    conn.execute('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
                 ('setupadmin', admin.hash_password('setupadminpass'), 'admin'))
    conn.commit()
    conn.close()


@pytest.fixture
def client(app):
    """Create test client."""
    return app.test_client()


@pytest.fixture
def authenticated_client(app, test_db):
    """Create authenticated test client with admin role (default for API access)."""
    import admin
    
    # Create a test user with admin role
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
    
    # Get the actual user ID from the database
    conn = admin.get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM users WHERE username = ?', ('testuser',))
    row = cursor.fetchone()
    user_id = row['id'] if row else 1
    conn.close()
    
    # Log in with correct session keys
    with client.session_transaction() as sess:
        sess['logged_in'] = True
        sess['login_at'] = __import__('time').time()
        sess['user_id'] = user_id
        sess['username'] = 'testuser'
        sess['user_role'] = 'admin'
    
    return client


@pytest.fixture
def admin_client(app, test_db):
    """Create authenticated test client with admin role (alias for clarity in admin tests)."""
    import admin
    
    # Create an admin user
    conn = admin.get_db()
    cursor = conn.cursor()
    password_hash = admin.hash_password('adminpassword')
    cursor.execute(
        'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
        ('adminuser', password_hash, 'admin')
    )
    conn.commit()
    conn.close()
    
    client = app.test_client()
    
    # Get the actual user ID from the database
    conn = admin.get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM users WHERE username = ?', ('adminuser',))
    row = cursor.fetchone()
    user_id = row['id'] if row else 1
    conn.close()
    
    # Log in with admin role
    with client.session_transaction() as sess:
        sess['logged_in'] = True
        sess['login_at'] = __import__('time').time()
        sess['user_id'] = user_id
        sess['username'] = 'adminuser'
        sess['user_role'] = 'admin'
    
    return client


@pytest.fixture
def regular_user_client(app, test_db):
    """Create authenticated test client with regular user role (non-admin)."""
    import admin
    
    # Create a regular user
    conn = admin.get_db()
    cursor = conn.cursor()
    password_hash = admin.hash_password('userpassword')
    cursor.execute(
        'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
        ('regularuser', password_hash, 'user')
    )
    conn.commit()
    conn.close()
    
    client = app.test_client()
    
    # Get the actual user ID from the database
    conn = admin.get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM users WHERE username = ?', ('regularuser',))
    row = cursor.fetchone()
    user_id = row['id'] if row else 1
    conn.close()
    
    # Log in with user role
    with client.session_transaction() as sess:
        sess['logged_in'] = True
        sess['login_at'] = __import__('time').time()
        sess['user_id'] = user_id
        sess['username'] = 'regularuser'
        sess['user_role'] = 'user'
    
    return client


# ========== Sample Data Fixtures ==========

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
        'registrant_name': 'John Doe',
        'registrant_email': 'admin@example.com',
        'organization': 'Example Organization',
        'creation_date': '1995-08-14T00:00:00',
        'expiration_date': '2025-08-13T00:00:00',
        'name_servers': ['ns1.example.com', 'ns2.example.com'],
        'all_emails': ['admin@example.com', 'tech@example.com', 'abuse@example.com'],
        'all_names': ['John Doe', 'Jane Smith'],
        'all_organizations': ['Example Organization', 'Example Holdings'],
        'all_registrars': ['Example Registrar, LLC']
    }


@pytest.fixture
def sample_circl_pdns_results():
    """Sample CIRCL Passive DNS results."""
    return [
        {
            'rrname': '93.184.216.34',
            'rrtype': 'A',
            'rdata': 'example.com',
            'time_first': 1577836800,
            'time_last': 1704067200,
            'count': 1000
        },
        {
            'rrname': 'example.com',
            'rrtype': 'CNAME',
            'rdata': 'cdn.example.com',
            'time_first': 1577836800,
            'time_last': 1704067200,
            'count': 500
        },
        {
            'rrname': 'example.com',
            'rrtype': 'MX',
            'rdata': '10 mail.example.com',
            'time_first': 1577836800,
            'time_last': 1704067200,
            'count': 250
        },
        {
            'rrname': 'test.example.com',
            'rrtype': 'A',
            'rdata': '192.168.1.1',
            'time_first': 1577836800,
            'time_last': 1704067200,
            'count': 100
        }
    ]


@pytest.fixture
def sample_circl_pdns_with_ip_rdata():
    """Sample CIRCL PDNS results where rdata contains IPs in unexpected places."""
    return [
        {
            'rrname': 'cdn.example.com',
            'rrtype': 'CNAME',
            'rdata': '93.184.216.34',  # CNAME pointing to IP (unusual but possible)
            'time_first': 1577836800,
            'time_last': 1704067200,
            'count': 50
        },
        {
            'rrname': 'mail.example.com',
            'rrtype': 'MX',
            'rdata': '10 192.168.1.100',  # MX with IP instead of hostname
            'time_first': 1577836800,
            'time_last': 1704067200,
            'count': 25
        },
        {
            'rrname': 'ns.example.com',
            'rrtype': 'NS',
            'rdata': '10.0.0.1',  # NS pointing to IP
            'time_first': 1577836800,
            'time_last': 1704067200,
            'count': 10
        },
        {
            'rrname': 'ipv6.example.com',
            'rrtype': 'CNAME',
            'rdata': '2001:db8::1',  # CNAME pointing to IPv6
            'time_first': 1577836800,
            'time_last': 1704067200,
            'count': 5
        }
    ]


@pytest.fixture
def sample_viewdns_reverse_mx_results():
    """Sample ViewDNS Reverse MX results."""
    return {
        'response': {
            'domain_count': '3',
            'domains': ['example.com', 'example.org', 'test.example.com']
        }
    }


@pytest.fixture
def sample_viewdns_reverse_ns_results():
    """Sample ViewDNS Reverse NS results."""
    return {
        'response': {
            'domain_count': '2217',
            'domains': [{'domain': 'example.com'}, {'domain': 'test.com'}]
        }
    }


@pytest.fixture
def sample_viewdns_reverse_whois_results():
    """Sample ViewDNS Reverse WHOIS results."""
    return {
        'response': {
            'result_count': '12',
            'matches': [
                {'domain': 'example.com', 'created_date': '2012-08-03', 'registrar': 'NAME.COM, LLC'},
                {'domain': 'example.org', 'created_date': '2015-02-15', 'registrar': 'NAME.COM, LLC'},
                {'domain': 'mysite.net', 'created_date': '2018-11-20', 'registrar': 'GoDaddy.com, LLC'}
            ]
        }
    }


@pytest.fixture
def sample_hackertarget_shared_ns_results():
    """Sample HackerTarget Shared NS results."""
    return [
        'example1.com',
        'example2.com',
        'test.example.com',
        'mysite.org'
    ]


# ========== IP Validation Test Data ==========

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


@pytest.fixture
def valid_ipv6_addresses():
    """Valid IPv6 addresses for testing."""
    return [
        '2001:db8::1',
        '::1',
        '::',
        '2606:2800:220:1:248:1893:25c8:1946',
        'fe80::1',
        '2001:0db8:85a3:0000:0000:8a2e:0370:7334'
    ]


@pytest.fixture
def invalid_ip_addresses():
    """Invalid IP addresses that should not match."""
    return [
        'example.com',
        'mail.example.com',
        '256.256.256.256',
        '192.168.1',
        '192.168.1.1.1',
        'not-an-ip',
        '',
        None,
        '192.168.1.1/24',
        'http://192.168.1.1'
    ]
