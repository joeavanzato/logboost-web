# Technology Stack

**Analysis Date:** 2026-02-25

## Languages

**Primary:**
- Python 3.12.12 - Backend application, core business logic, data processing
- HTML/Jinja2 - Server-side template rendering via Flask
- JavaScript - Frontend interactivity and API client code
- SQL - SQLite database queries

**Secondary:**
- CSV - Data import/export format
- JSON - Configuration and API data exchange

## Runtime

**Environment:**
- Python 3.12.12

**Package Manager:**
- pip - Python package management
- Lockfile: `requirements.txt` (present, non-pinned versions)

## Frameworks

**Core:**
- Flask 3.0.0+ - Web framework, routing, request handling
- Flask-WTF 1.2.0+ - CSRF protection and form handling
- Werkzeug 3.0.0+ - WSGI utilities and secure filename handling

**Server:**
- gunicorn 21.0.0+ - Production WSGI HTTP server

**Testing:**
- pytest 8.0.0+ - Test runner
- pytest-flask 1.3.0+ - Flask test fixtures and utilities

## Key Dependencies

**Critical:**
- requests 2.31.0+ - HTTP client for external API calls (Chaos, CIRCL, HackerTarget, ViewDNS)
- dnspython 2.4.0+ - DNS resolution (used in `routes/dns.py` for A, AAAA, CNAME, MX, NS, TXT, SOA queries)
- shodan 1.31.0+ - Shodan search engine API client (optional, gracefully disabled if not installed)
- python-whois 0.9.0+ - WHOIS domain information lookup
- tldextract 5.1.0+ - TLD and domain parsing
- iocextract 1.16.0+ - IOC (Indicator of Compromise) extraction from text

**Data Processing:**
- pypdf 4.0.0+ - PDF parsing and handling for log file uploads

## Configuration

**Environment:**
- Configured via environment variables:
  - `SECRET_KEY` - Flask session encryption key (defaults to random 24-byte value)
  - `FLASK_ENV` - Environment mode (determines SESSION_COOKIE_SECURE)
  - `LOGBOOST_LOG_LEVEL` - Logging verbosity (WARNING default, set via logging module)
  - `LOGBOOST_PATH` - Path to LogBoost binary (defaults to 'LogBoost')
  - `MAXMIND_DIR` - Directory containing MaxMind GeoIP databases (defaults to '.')
  - `THREAT_DB_DIR` - Directory containing threat intelligence databases (defaults to '.')

**Build:**
- No explicit build configuration files present
- Application runs directly with Flask development server or gunicorn

## Platform Requirements

**Development:**
- Python 3.12.12
- pip package manager
- Optional: Shodan library for Shodan API integration

**Production:**
- Python 3.12.12
- gunicorn WSGI server
- Sufficient disk space for:
  - SQLite database (`logboost_admin.db`)
  - MaxMind GeoIP databases (referenced in MAXMIND_DIR)
  - Threat intelligence databases (referenced in THREAT_DB_DIR)
  - Upload directory for user-submitted files
  - Cache files for DNS, WHOIS, and API responses

---

*Stack analysis: 2026-02-25*
