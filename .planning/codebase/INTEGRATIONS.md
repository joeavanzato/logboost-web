# External Integrations

**Analysis Date:** 2026-02-25

## APIs & External Services

**Shodan (Search Engine):**
- Shodan API - Internet-wide device/service search engine
  - SDK/Client: `shodan` Python package (1.31.0+)
  - Auth: API key stored in settings table with key `shodan_api_key`
  - Usage: `GET /api/shodan/resolve` - Query for IP or domain data
  - Endpoint: Shodan public API (accessed via Python SDK)
  - Cache: Results cached in `shodan_cache` and `shodan_pivot_cache` tables
  - File: `app.py` (lines 2311-2400+), imported and called via `shodan.Shodan(api_key).host()` and `api.search()`

**CIRCL Passive DNS (circl.lu):**
- CIRCL Passive DNS API - Passive DNS resolution history
  - Client: `requests` library
  - Auth: HTTP Basic Auth (username/password) stored in settings with keys `circl_username`, `circl_password`
  - Endpoint: `https://www.circl.lu/pdns/query/{query_value}`
  - Usage: `POST /api/circl/pdns` and `POST /api/circl/pdns/bulk` - Query IP or domain DNS resolution history
  - Headers: Supports `dribble-disable-active-query` and `dribble-paginate-count` headers
  - Cache: Results cached in `circl_pdns_cache` table
  - File: `app.py` (lines 2672-2850+), query function at `query_circl_pdns()`

**Chaos (ProjectDiscovery):**
- Chaos subdomain enumeration API - Subdomain discovery service
  - Client: `requests` library
  - Auth: API key sent via Authorization header, stored in settings with key `chaos_api_key`
  - Endpoint: `https://dns.projectdiscovery.io/dns/{domain}/subdomains`
  - Usage: `POST /api/chaos/subdomains` - Enumerate subdomains for a domain
  - Cache: Results cached in database (chaos caching functions in admin module)
  - File: `routes/chaos.py` (lines 25-80+)

**HackerTarget:**
- HackerTarget API - Shared nameserver and reverse lookup service
  - Auth: API key stored in settings with key `hackertarget_api_key`
  - Usage: `POST /api/hackertarget/shared-ns` - Query for shared nameserver information
  - Cache: Results cached in `hackertarget_cache` table
  - File: `app.py` (lines 2877+)

**ViewDNS.info:**
- ViewDNS API - DNS and reverse IP lookup service
  - Auth: API key stored in settings with key `viewdns_api_key`
  - Cache: Results cached in `viewdns_cache` table
  - File: References in `admin.py` settings configuration (lines 911-923)

**MaxMind GeoIP Databases:**
- MaxMind GeoLite2 databases - IP geolocation and ASN information
  - Type: Local database files (not API)
  - Files: `GeoLite2-City.mmdb`, `GeoLite2-ASN.mmdb`, `GeoLite2-Country.mmdb` (present in root directory)
  - Usage: IP geolocation enrichment during LogBoost binary execution
  - Location: Configured via `MAXMIND_DIR` environment variable
  - Reference: `app.py` line 106-107

## Data Storage

**Databases:**
- SQLite (`logboost_admin.db`)
  - Location: `logboost_admin.db` (in project root directory)
  - Client: Python's built-in `sqlite3` module
  - Connection: `get_db()` function in `admin.py` returns connection objects
  - Tables:
    - `users` - User authentication (username, password_hash, role)
    - `settings` - Configuration key-value store (API keys, cache TTLs, timeouts)
    - `scheduled_tasks` - Scheduled job configuration and status
    - `task_logs` - Task execution history
    - `dns_cache` - Cached DNS resolution results with TTL
    - `whois_cache` - Cached WHOIS query results with expiration
    - `shodan_cache` - Cached Shodan host lookups (composite unique: query+query_type)
    - `shodan_pivot_cache` - Cached Shodan pivot/attribute searches
    - `circl_pdns_cache` - Cached CIRCL Passive DNS results
    - `hackertarget_cache` - Cached HackerTarget results
    - `viewdns_cache` - Cached ViewDNS results

**File Storage:**
- Local filesystem only
  - Upload directory: Configured path (referenced in app as `upload` handling)
  - Output directory: For generated reports and downloads
  - DNS cache file: `dns.cache` (present in root)
  - WHOIS cache file: `whois.cache` (present in root)
  - IDB cache file: `idb.cache` (present in root)
  - Threat database directory: Configured via `THREAT_DB_DIR` environment variable

**Caching:**
- Internal SQLite caching for:
  - DNS queries (with configurable TTL via `dns_cache_ttl` setting)
  - WHOIS responses (with configurable TTL via `whois_cache_ttl` setting)
  - API responses (Shodan, CIRCL, HackerTarget, ViewDNS - each with configurable TTL)
  - Chaos subdomain results (with `chaos_cache_ttl` setting)
- No external cache service (Redis, Memcached) detected

## Authentication & Identity

**Auth Provider:**
- Custom local authentication
  - Implementation: Session-based with Flask session cookies
  - Details: `auth.py` contains `login_required` decorator that checks `session.get('logged_in')`
  - Login routes: `routes/auth_routes.py`
  - User storage: SQLite `users` table with username, password_hash, role
  - Default admin: Username `admin`, password `changeme` (hardcoded defaults in `admin.py`)

**Session Security:**
- `SESSION_COOKIE_HTTPONLY=True` - Prevents JavaScript access
- `SESSION_COOKIE_SAMESITE='Lax'` - CSRF mitigation
- `SESSION_COOKIE_SECURE` - HTTPS only in production (set based on FLASK_ENV)
- CSRF Protection: Flask-WTF CSRFProtect enabled on app

## Monitoring & Observability

**Error Tracking:**
- None detected (no Sentry, Rollbar, or similar integration)

**Logs:**
- Python logging module configured
  - Level: Configurable via `LOGBOOST_LOG_LEVEL` environment variable (defaults to WARNING)
  - Format: `%(asctime)s - %(name)s - %(levelname)s - %(message)s`
  - File: `logboost.log` (present in root directory)
  - Audit logging: Custom `log_audit()` function in `admin.py` logs events to database

## CI/CD & Deployment

**Hosting:**
- Not explicitly configured - application designed to run standalone
- Production use: gunicorn WSGI server (21.0.0+)
- Development use: Flask development server

**CI Pipeline:**
- None detected in repository

## Environment Configuration

**Required env vars:**
- `LOGBOOST_PATH` - Path to LogBoost binary (critical for enrichment functionality)
- `MAXMIND_DIR` - Directory containing MaxMind GeoIP databases (for geo-enrichment)
- `THREAT_DB_DIR` - Directory containing threat intelligence databases

**Optional env vars:**
- `SECRET_KEY` - Flask session encryption (auto-generated if missing, non-persistent)
- `FLASK_ENV` - Environment mode (affects session cookie security)
- `LOGBOOST_LOG_LEVEL` - Logging verbosity (WARNING default)

**Secrets location:**
- API keys and credentials stored in SQLite `settings` table (encrypted at rest via OS file permissions only)
- Environment variables can be passed via:
  - System environment
  - `.env` file (if loaded by application)
  - Process environment when launching gunicorn

**Note:** No `.env` file observed in repository. Secrets stored in database, not environment variables.

## Webhooks & Callbacks

**Incoming:**
- None detected

**Outgoing:**
- None detected

---

*Integration audit: 2026-02-25*
