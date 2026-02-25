# Coding Conventions

**Analysis Date:** 2026-02-25

## Naming Patterns

**Files:**
- Module files: lowercase with underscores (e.g., `app.py`, `admin.py`, `security.py`, `auth.py`)
- Test files: `test_*.py` pattern (e.g., `test_authentication.py`, `test_api_ioc.py`)
- Blueprint/route files: lowercase with descriptive names (e.g., `auth_routes.py`, `chaos.py`)

**Functions:**
- Use snake_case for all functions (e.g., `extract_ips()`, `build_logboost_command()`, `get_cached_dns()`)
- Descriptive names that indicate purpose/return value
- Private helper functions don't use underscore prefix—all functions are public-facing
- Examples from `app.py`:
  - `allowed_file()` - validation function
  - `create_ip_csv()` - creation/write function
  - `build_logboost_command()` - builder function
  - `run_logboost()` - execution function
  - `extract_iocs_from_text()` - extraction function

**Variables:**
- Use snake_case for all variables (e.g., `output_path`, `logboost_command`, `session_id`)
- Constants: ALL_CAPS (e.g., `BLOCKED_IP_RANGES`, `DEFAULT_ADMIN_USER`, `LOGBOOST_BINARY`)
- Boolean variables: descriptive names that read naturally (e.g., `SHODAN_AVAILABLE`, `logged_in`)
- Collection variables: plural names (e.g., `ips`, `domains`, `results`)

**Types/Classes:**
- Class names: PascalCase (e.g., `MockRdataA`, `MockAnswer`, `TestPasswordHashing`)
- Only used for test mock objects and pytest test classes
- Exception classes follow standard Python convention (inherit from Exception)

## Code Style

**Formatting:**
- No linting configuration detected (`.pylintrc`, `.flake8`, `pyproject.toml` not present)
- Follows implicit PEP 8 conventions
- Module docstrings: Use triple quotes at file start with description (e.g., `"""LogBoost Web UI - Admin Module"""`)
- Indentation: 4 spaces (standard Python)

**Imports:**
- Organized in three sections, separated by blank lines:
  1. Standard library imports (`os`, `re`, `json`, `logging`, `subprocess`, etc.)
  2. Third-party imports (`flask`, `werkzeug`, `requests`, `sqlite3`, etc.)
  3. Local/project imports (relative imports from same project)
- Example from `app.py`:
  ```python
  import os
  import re
  import csv
  import json
  # ... more stdlib ...
  from flask import Flask, render_template, request, jsonify
  # ... more third-party ...
  from security import is_ip_blocked, validate_url_for_ssrf
  from auth import login_required
  ```

**Import Organization:**
- Use `from X import Y` style for specific imports (preferred)
- Use conditional imports with try/except for optional dependencies:
  ```python
  try:
      import shodan
      SHODAN_AVAILABLE = True
  except ImportError:
      SHODAN_AVAILABLE = False
  ```
- Wildcard imports avoided

## Comments and Documentation

**Module Docstrings:**
- Include description of module purpose at top of file
- Example: `"""LogBoost Web UI - Admin Module\nHandles authentication, scheduled tasks, and settings management"""`

**Function Docstrings:**
- Not consistently used; most functions lack docstrings
- When present, use simple description format
- No formal docstring format (not following strict Google/Sphinx style)

**Inline Comments:**
- Used sparingly, mainly for:
  - Section separators (e.g., `# ============================================\n# Database Functions\n# ============================================`)
  - Important security notes (e.g., `# SSRF Protection`, `# Session cookie hardening`)
  - Non-obvious logic explanations

**Code Sections:**
- Major sections marked with comment blocks:
  ```python
  # ============================================
  # Section Name
  # ============================================
  ```

## Error Handling

**Patterns:**
- Use try/except blocks for exception handling
- Specific exception types caught when possible (e.g., `except subprocess.TimeoutExpired`, `except requests.exceptions.RequestException`)
- Generic `except Exception as e:` used as fallback for unexpected errors
- Exceptions include error message context: `raise ValueError(f"Failed to parse PDF: {str(e)}")`
- Error handling in routes returns JSON responses:
  ```python
  try:
      # operation
  except Exception as e:
      return jsonify({'error': str(e)}), 400
  ```

**Special Cases:**
- SSRF validation returns tuple: `(is_valid, error_message)` pattern
- Functions raising ValueError for user-input validation
- Functions returning `None` for cache misses or not-found results

## Logging

**Framework:** `logging` module (standard Python library)

**Configuration:**
- Configured in `app.py` with environment variable control:
  ```python
  LOG_LEVEL = os.environ.get('LOGBOOST_LOG_LEVEL', 'WARNING').upper()
  logging.basicConfig(
      level=getattr(logging, LOG_LEVEL, logging.WARNING),
      format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
  )
  ```
- Logger obtained per module: `logger = logging.getLogger(__name__)`
- Default log level: WARNING (debug logging disabled by default)

**Logging Patterns:**
- Used in `admin.py` for task execution and lifecycle events
- No pervasive logging throughout codebase—selectively used
- Flask app logger accessed via `app.logger`

## Audit Logging

**Pattern:**
- Custom audit logging via `log_audit()` function from `admin` module
- Used to track user actions (e.g., login success/failure, API calls)
- Called from route handlers:
  ```python
  log_audit('user_login', username=username, success=True)
  ```

## Function Design

**Size:**
- Functions typically 10-50 lines for simple operations
- Complex functions (like `run_logboost()`, `extract_iocs_from_text()`) range 50-200 lines
- CSV processing and enrichment functions are larger due to file I/O complexity

**Parameters:**
- Prefer explicit parameters over **kwargs
- Type hints used in function signatures where clarity helps (e.g., `text: str -> list[str]`)
- Optional parameters with default values

**Return Values:**
- Single return values preferred
- Tuple returns used for multi-value results (e.g., `(success, stdout, stderr)` from `run_logboost()`)
- None returned for "not found" or "no result" cases
- Lists returned for collections (e.g., `['8.8.8.8', '1.1.1.1']`)

## Module Design

**Exports:**
- All functions at module level are public
- No `__all__` declarations for controlling exports
- Private logic kept in same module, not separated

**Blueprints:**
- Flask blueprints used for route organization
- Named with `_bp` suffix: `admin_bp`, `auth_routes`
- Initialized with URL prefix: `Blueprint('admin', __name__, url_prefix='/admin')`

**Decorators:**
- Functional decorators for cross-cutting concerns: `@login_required`, `@admin_required`
- Flask decorators for routing: `@app.route()`, `@csrf.exempt`
- Custom decorators use `@wraps` from `functools` to preserve function metadata

## Security Conventions

**Input Validation:**
- URL validation before fetching: `validate_url_for_ssrf(url)` returns `(bool, str)`
- IP blocking for private/reserved ranges in `security.py`
- CSRF protection enabled via `CSRFProtect(app)`
- Session cookies hardened:
  - `SESSION_COOKIE_HTTPONLY=True`
  - `SESSION_COOKIE_SAMESITE='Lax'`
  - `SESSION_COOKIE_SECURE` in production

**Password Management:**
- Passwords hashed with salt: `hash_password()` returns `"salt:hash"` format
- Salts: 32 hex chars (16 bytes random)
- Verification: `verify_password(password, hashed)` returns boolean

## Configuration

**Environment Variables:**
- Used for runtime configuration:
  - `SECRET_KEY` - Flask session key (default: random 24 bytes)
  - `FLASK_ENV` - Production/development mode
  - `LOGBOOST_PATH` - Path to LogBoost binary
  - `LOGBOOST_LOG_LEVEL` - Logging verbosity
- Configuration approach: `os.environ.get('VAR', default_value)`

**Flask Configuration:**
- Done in route initialization: `app.config.update({...})`
- Testing overrides in test fixtures

---

*Convention analysis: 2026-02-25*
