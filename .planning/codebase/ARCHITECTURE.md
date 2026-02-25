# Architecture

**Analysis Date:** 2026-02-25

## Pattern Overview

**Overall:** Layered MVC with external process orchestration

**Key Characteristics:**
- Flask web framework with modular route blueprints
- Subprocess orchestration (LogBoost binary execution)
- Multi-layer data enrichment (IP/domain intelligence)
- Session-based file processing with temp storage
- SQLite persistence for admin functions, user accounts, and caching

## Layers

**Presentation Layer:**
- Purpose: Server-rendered HTML templates with AJAX-driven updates via HTMX
- Location: `templates/` (Jinja2 templates) and `static/` (CSS/JS)
- Contains: Main UI template (`index.html`), admin panel templates, partials for results display
- Depends on: Flask route handlers, AJAX endpoints
- Used by: Browser clients

**API/Route Layer:**
- Purpose: Flask routes and blueprints exposing endpoints for text enrichment, file processing, graph operations, and external service queries
- Location: `app.py` (main routes), `routes/` (modular blueprints)
- Contains:
  - Main endpoints: `/enrich/text`, `/enrich/file`, `/results/page`, `/download`
  - Graph API: `/api/graph/related`, `/api/graph/enrich`, `/api/graph/save`
  - External service APIs: `/api/shodan/*`, `/api/circl/*`, `/api/dns/*`, `/api/whois/*`, `/api/chaos/*`
  - Admin routes: `/admin/*` (in `admin.py` via Blueprint)
- Depends on: Helper functions, security module, external service clients
- Used by: Presentation layer, external API consumers

**Business Logic Layer:**
- Purpose: Processing logic for IP/domain extraction, file handling, LogBoost orchestration, and data transformation
- Location: `app.py` (helper functions)
- Contains:
  - IOC extraction: `extract_iocs_from_text()`, `extract_defanged_domains_direct()`, `extract_domain_from_url()`
  - LogBoost integration: `build_logboost_command()`, `run_logboost()`
  - CSV processing: `read_csv_paginated()`, `read_csv_all()`, `compute_statistics()`
  - IP/domain validation: `is_valid_public_ip()`, `is_valid_domain()`, `validate_url_for_ssrf()`
- Depends on: External libraries (requests, shodan, dnspython), LogBoost binary
- Used by: Route layer

**Data Access Layer:**
- Purpose: Persistent storage management for user accounts, admin settings, caching, and saved state
- Location: `admin.py` (database functions)
- Contains: SQLite database operations for users, scheduled tasks, settings, various cache tables (DNS, WHOIS, Shodan, CIRCL, HackerTarget, ViewDNS, Chaos), saved graphs, shared results
- Depends on: sqlite3
- Used by: Admin routes, background tasks, cache lookups

**Security Layer:**
- Purpose: SSRF protection, CSRF protection, authentication, and audit logging
- Location: `security.py`, `auth.py`, `routes/auth_routes.py`
- Contains:
  - SSRF validation: `validate_url_for_ssrf()`, `is_ip_blocked()`, `safe_fetch_url()`
  - CSRF protection: CSRFProtect integration
  - Authentication: `login_required` decorator, session management
  - Audit logging: `log_audit()` function
- Depends on: Flask security utilities, requests library
- Used by: All route handlers

**Infrastructure Layer:**
- Purpose: System integration and background processes
- Location: `admin.py` (task scheduler), subprocess calls in `app.py`
- Contains: Task scheduling thread, LogBoost binary execution, file system operations
- Depends on: subprocess, threading, file system
- Used by: Flask app lifecycle

## Data Flow

**Ad-hoc IP Enrichment Flow:**

1. User pastes text in UI
2. POST to `/enrich/text` route
3. `extract_iocs_from_text()` parses text for IPs/domains
4. For each IP: build CSV temporary file → execute LogBoost binary → parse results CSV
5. Results stored in session directory
6. Return paginated results via `/results/page`
7. Client renders results table with HTMX

**File Upload Processing Flow:**

1. User uploads file via multipart form
2. POST to `/enrich/file` route
3. File saved to `uploads/{session_id}/`
4. Build LogBoost command with user-selected options
5. Execute LogBoost binary with input file and options
6. Read output CSV from `output/{session_id}/`
7. Compute statistics and return results
8. Client can download CSV or view paginated results

**External Service Query Flow:**

1. User queries IP/domain via Shodan, CIRCL pDNS, DNS, WHOIS, or Chaos routes
2. Route handler validates input and checks cache (in SQLite)
3. If cached and not expired: return cached results
4. If cache miss or expired:
   - Call external service API (using requests library or SDK)
   - Parse response
   - Cache results with TTL
   - Return to client
5. Results rendered in graph or table format

**Admin Authentication and Persistence:**

1. User submits login form
2. `/login` route verifies credentials against `users` table
3. On success: set session cookie, log audit event
4. Admin panel accessible at `/admin/` (requires login)
5. Changes (settings, tasks, accounts) persisted to SQLite

**State Management:**

- **Session State:** User's current enrichment results stored in `UPLOAD_FOLDER/{session_id}/` and `OUTPUT_FOLDER/{session_id}/`
- **Persistent State:** User accounts, admin settings, scheduled tasks, caching data in SQLite at `logboost_admin.db`
- **In-Memory State:** Request context (current page, selected columns), Flask session dict

## Key Abstractions

**Session Management:**

- Purpose: Isolate user work and manage temporary files
- Examples: `get_session_dir()`, `cleanup_session()`
- Pattern: UUID-based session directories for uploads and output, with cleanup on logout

**Command Builder Pattern:**

- Purpose: Construct complex LogBoost CLI commands dynamically
- Examples: `build_logboost_command()`
- Pattern: Accumulate options into list, join and execute via subprocess

**Cache Abstraction:**

- Purpose: Avoid redundant external API calls with time-based expiry
- Examples: `dns_cache`, `whois_cache`, `shodan_cache`, `circl_pdns_cache`, etc. tables
- Pattern: SQLite tables with composite unique constraints and `expires_at` TIMESTAMP

**IOC Extraction Pipeline:**

- Purpose: Multi-format indicator extraction (IPs, domains, URLs) with validation
- Examples: `extract_iocs_from_text()`, `extract_defanged_domains_direct()`
- Pattern: Regex matching with validation (public IP check, domain format check)

**Blueprint-based Route Organization:**

- Purpose: Modular route registration
- Examples: `auth_routes_bp`, `dns_bp`, `whois_bp`, `chaos_bp` in `routes/`
- Pattern: Flask Blueprint per feature group, registered via `register_blueprints()`

## Entry Points

**Web Application:**
- Location: `app.py`
- Triggers: `python app.py` (development) or `gunicorn app:app` (production)
- Responsibilities: Flask app initialization, CSRF setup, route registration, request/response handling

**Admin Module:**
- Location: `admin.py`
- Triggers: Imported by `app.py` via `init_admin(app, csrf)`
- Responsibilities: Database initialization, user authentication, task scheduling, settings management

**Route Blueprints:**
- Location: `routes/__init__.py`
- Triggers: Called from `app.py` via `register_blueprints(app)`
- Responsibilities: Register modular routes (auth, DNS, WHOIS, Chaos) with Flask app

## Error Handling

**Strategy:** Try-catch blocks with graceful fallbacks; errors returned as JSON or error templates

**Patterns:**

- **Subprocess Errors:** `run_logboost()` catches `TimeoutExpired`, `FileNotFoundError`, generic `Exception`; returns `(False, '', error_message)`
- **CSV Processing Errors:** `read_csv_paginated()` and `read_csv_all()` catch and return error dict with empty rows
- **External API Errors:** Route handlers catch requests exceptions, log, and return JSON error response
- **CSRF Errors:** `@app.errorhandler(CSRFError)` returns 400 JSON response
- **File Upload Errors:** `@app.errorhandler(413)` for oversized uploads
- **Database Errors:** Most database calls wrapped in try-except; transactions committed only on success

## Cross-Cutting Concerns

**Logging:**
- Framework: `logging` module configured in `app.py` with level controlled by `LOGBOOST_LOG_LEVEL` env var
- Audit logging: `log_audit()` in `admin.py` records user actions to `audit_logs` table

**Validation:**
- IP validation: `is_valid_public_ip()` checks IPv4 format and rejectability
- Domain validation: `is_valid_domain()` checks TLD presence and format
- SSRF validation: `validate_url_for_ssrf()` resolves hostname and checks against blocked IP ranges
- URL validation: Scheme check (http/https only), hostname presence

**Authentication:**
- Mechanism: Session-based with login_required decorator
- Default credentials: admin/changeme
- Password hashing: SHA256 with salt (see `verify_password()` in `admin.py`)
- Audit: Every login/logout logged with `log_audit()`

**CSRF Protection:**
- Mechanism: Flask-WTF CSRFProtect
- Form tokens embedded in templates
- Configured for Lax SameSite cookies

**Rate Limiting:**
- For CIRCL pDNS: Custom RateLimiter class with wait() method (1 query per second)
- No global rate limiter; per-service limits implemented as needed

**Caching Strategy:**
- All external service responses cached in SQLite with TTL
- Cache check on every request before calling external service
- Expired entries remain until explicitly queried (lazy cleanup)

