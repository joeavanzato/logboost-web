# Codebase Structure

**Analysis Date:** 2026-02-25

## Directory Layout

```
logboost-web/
├── app.py                    # Main Flask application with core routes
├── admin.py                  # Admin module: auth, database, scheduler, settings
├── auth.py                   # Authentication decorator (login_required)
├── security.py               # SSRF protection, URL validation, safe fetching
├── requirements.txt          # Python dependencies
├── pytest.ini                # pytest configuration
├── logboost_admin.db         # SQLite database (created on first run)
├── routes/                   # Modular route blueprints
│   ├── __init__.py          # register_blueprints() function
│   ├── auth_routes.py       # Login/logout routes
│   ├── dns.py               # DNS query API endpoints
│   ├── whois.py             # WHOIS query API endpoints
│   └── chaos.py             # ProjectDiscovery Chaos subdomain API
├── templates/                # Jinja2 HTML templates
│   ├── index.html           # Main application template
│   ├── login.html           # Login page
│   ├── admin/               # Admin panel templates
│   │   ├── base.html        # Admin base layout
│   │   ├── dashboard.html   # Admin dashboard (tasks, logs)
│   │   ├── login.html       # Admin login (alternative)
│   │   ├── tasks.html       # Scheduled tasks management
│   │   ├── logs.html        # Task execution logs
│   │   ├── log_detail.html  # Single task log detail
│   │   ├── settings.html    # Admin settings (API keys, cache)
│   │   ├── accounts.html    # User/admin account management
│   │   ├── create_account.html # Create new account form
│   │   └── change_password.html # Password change form
│   └── partials/            # Partial templates for AJAX updates
│       ├── results.html     # Results container
│       ├── results_table.html # Paginated results table
│       ├── stats.html       # Statistics panel
│       └── error.html       # Error message display
├── static/                   # CSS and client-side assets
│   ├── style.css            # Main application styles
│   └── admin.css            # Admin panel styles
├── uploads/                  # Temporary upload file storage
│   └── {session_id}/        # Per-session upload directory
├── output/                   # LogBoost processing output
│   └── {session_id}/        # Per-session output directory
├── tests/                    # Pytest test files
│   ├── conftest.py          # Pytest fixtures and configuration
│   ├── test_admin_*.py      # Admin functionality tests
│   ├── test_api_*.py        # API endpoint tests
│   └── test_audit_logging.py # Audit log tests
├── intel/                    # Threat intelligence data directory
├── docs/                     # Documentation
├── logboost.log             # Application log file
└── GeoLite2-*.mmdb          # MaxMind geolocation databases (in root or MAXMIND_DIR)
```

## Directory Purposes

**Root Level:**
- Purpose: Application entry points, configuration, and top-level modules
- Contains: Flask app, admin module, auth utilities, security functions
- Key files: `app.py` (entry point), `admin.py` (database + auth)

**routes/**
- Purpose: Modular Flask blueprints for feature-specific endpoints
- Contains: Route handlers for authentication, DNS lookups, WHOIS queries, Chaos subdomain enumeration
- Key files: `__init__.py` (blueprint registration), individual route modules

**templates/**
- Purpose: Server-rendered HTML templates (Jinja2)
- Contains: Main UI, login page, admin panel, AJAX-updatable partials
- Key files: `index.html` (main interface), admin panel templates, `partials/` for dynamic content

**templates/admin/**
- Purpose: Admin panel interface templates
- Contains: Dashboard, task management, logs, settings, account management
- Layout: Inherits from `base.html`

**templates/partials/**
- Purpose: Partial HTML snippets for AJAX updates via HTMX
- Contains: Results table pagination, statistics, error messages
- Used by: AJAX endpoints to return partial content

**static/**
- Purpose: Client-side assets (CSS, static JS)
- Contains: Stylesheets for main app and admin panel
- Organization: `style.css` for main UI, `admin.css` for admin panel

**uploads/{session_id}/**
- Purpose: Temporary storage for user-uploaded files
- Generated: Yes (created when file uploaded)
- Committed: No (ephemeral, cleaned on logout)

**output/{session_id}/**
- Purpose: LogBoost processing output CSV files
- Generated: Yes (created after LogBoost execution)
- Committed: No (ephemeral, cleaned on logout)

**tests/**
- Purpose: Pytest test suite
- Contains: Unit and integration tests for all modules
- Organization: `conftest.py` for fixtures, tests grouped by feature (`test_admin_*`, `test_api_*`)

**intel/**
- Purpose: Threat intelligence data directory
- Generated: Yes (populated by admin task `/admin/tasks/update-threat-intel`)
- Committed: No (external data)

## Key File Locations

**Entry Points:**
- `app.py`: Main Flask application (run with `python app.py`)
- `admin.py`: Admin module initialization (imported by `app.py`)

**Configuration:**
- `requirements.txt`: Python dependency list
- `pytest.ini`: pytest runner configuration
- Environment variables: `LOGBOOST_PATH`, `MAXMIND_DIR`, `THREAT_DB_DIR`, `SECRET_KEY`, `FLASK_ENV`, `LOGBOOST_LOG_LEVEL`

**Core Logic:**
- `app.py`: Main route handlers (enrichment, file processing, graph APIs, external service queries)
- `admin.py`: Database functions, user authentication, task scheduling
- `security.py`: SSRF validation, URL safety checks
- `auth.py`: Login decorator

**Route Modules:**
- `routes/auth_routes.py`: Login/logout POST handlers
- `routes/dns.py`: DNS query endpoints
- `routes/whois.py`: WHOIS query endpoints
- `routes/chaos.py`: ProjectDiscovery Chaos API endpoints

**Database:**
- `logboost_admin.db`: SQLite database (single file at project root)
- Schema: users, scheduled_tasks, task_logs, settings, DNS/WHOIS/Shodan/CIRCL/HackerTarget/ViewDNS/Chaos caches, saved_graphs, shared_results, audit_logs

**Templates:**
- `templates/index.html`: Main UI (439KB - large)
- `templates/login.html`: Login page
- `templates/admin/*.html`: Admin panel templates
- `templates/partials/*.html`: AJAX partial templates

**Tests:**
- `tests/conftest.py`: Fixtures (mock Flask app, test database)
- `tests/test_admin_*.py`: Admin auth, settings, tasks, caching, threat intel
- `tests/test_api_*.py`: API endpoints (Shodan, CIRCL, DNS, WHOIS, IOC, graph, external APIs, chaos)
- `tests/test_audit_logging.py`: Audit logging verification

## Naming Conventions

**Files:**
- Python modules: `snake_case.py` (e.g., `admin.py`, `auth_routes.py`)
- Test files: `test_<feature>.py` (e.g., `test_admin_tasks.py`, `test_api_shodan.py`)
- Temporary files: `{uuid}` in `uploads/` and `output/` directories
- Database: `logboost_admin.db` (single file, not per-user)

**Directories:**
- Feature modules: `snake_case` (e.g., `routes/`, `templates/`)
- Session directories: `{uuid}` (e.g., `uploads/08a8bd0c-00cd-4a54-b9ba-60dc630ea527/`)
- Admin templates: `feature_name.html` (e.g., `tasks.html`, `settings.html`)

**Functions:**
- Route handlers: `route_name()` or `api_<feature>_<action>()` (e.g., `enrich_text()`, `api_shodan_resolve()`)
- Helper functions: `verb_noun()` (e.g., `extract_ips()`, `build_logboost_command()`, `read_csv_paginated()`)
- Validation functions: `is_<check>()` or `validate_<check>()` (e.g., `is_valid_public_ip()`, `validate_url_for_ssrf()`)

**Variables:**
- Classes: `PascalCase` (e.g., `RateLimiter`)
- Module-level constants: `UPPER_CASE` (e.g., `ALLOWED_EXTENSIONS`, `MAXMIND_DIR`)
- Instance/local variables: `snake_case` (e.g., `session_id`, `csv_reader`)

**Database Tables:**
- `snake_case_plural` (e.g., `users`, `scheduled_tasks`, `dns_cache`, `whois_cache`, `shodan_cache`)

## Where to Add New Code

**New Enrichment Feature (e.g., new external API):**
- Create route file: `routes/new_service.py` with Blueprint
- Register in: `routes/__init__.py` via `register_blueprints()`
- Add cache table: Define in `admin.py` `init_db()`
- Add routes: Implement in `routes/new_service.py` with cache lookup pattern
- Add tests: Create `tests/test_api_new_service.py`
- UI integration: Add AJAX endpoint calls in `templates/index.html` JavaScript

**New Admin Setting:**
- Add to: `admin.py` `get_setting()` / `set_setting()` functions
- Create form: Add input to `templates/admin/settings.html`
- Handle POST: Add handler in admin route for `/admin/settings`
- Test: Add to `tests/test_admin_settings.py`

**New Scheduled Task:**
- Define task type: Add to LogBoost task execution logic in `admin.py` `execute_task()`
- Database entry: Insert into `scheduled_tasks` table with interval
- UI control: Add to `templates/admin/tasks.html`
- Logging: Implement as new `log_audit()` call in `admin.py`
- Test: Add to `tests/test_admin_tasks.py`

**New Validation Rule:**
- Add helper: Create `is_valid_<thing>()` function in appropriate file (security.py for SSRF, app.py for domain/IP)
- Reuse: Call from route handlers before processing
- Test: Add to test suite

**New Database Table (Cache or State):**
- Define schema: Add to `admin.py` `init_db()` with CREATE TABLE
- Add migration: Check for existence, handle schema upgrades
- Access pattern: Follow existing cache pattern (lookup by key, check expiry, insert/update on miss)
- Cleanup: Optionally add cleanup job in admin scheduler

**New Static Asset:**
- CSS: Add to `static/style.css` (main app) or `static/admin.css` (admin panel)
- JavaScript: Inline in template or link via `<script src="/static/...">` in template
- Images/Fonts: Place in `static/` subdirectory if needed

## Special Directories

**uploads/ and output/:**
- Purpose: Per-session file storage for temporary processing
- Generated: Yes (runtime-created)
- Committed: No (ephemeral, `.gitignore`d)
- Cleanup: `cleanup_session()` called on logout or route handler

**intel/**
- Purpose: External threat intelligence feed data
- Generated: Yes (populated by admin task)
- Committed: No (external data, `.gitignore`d)
- Update: Admin task `/admin/tasks/update-threat-intel` refreshes

**tests/__pycache__/ and .pytest_cache/**
- Purpose: pytest internal cache
- Generated: Yes (by pytest)
- Committed: No (standard `.gitignore`d)

**dns.cache/ and idb.cache/**
- Purpose: Project Discovery Chaos and other external service caches (file-based)
- Generated: Yes (by external libraries)
- Committed: No
- Alternative: SQLite cache tables preferred for new queries

