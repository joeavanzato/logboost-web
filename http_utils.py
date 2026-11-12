"""Small request/response helpers shared by app.py and the route blueprints."""

import logging
import uuid

from flask import request, jsonify, session

logger = logging.getLogger(__name__)


class UpstreamError(Exception):
    """A third-party API call failed. The message is safe to show to users (no URLs or keys)."""


def json_body():
    """Request body as a dict, or None if it is missing or is not a JSON object."""
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else None


def str_field(data, key, default=''):
    """A string field from a JSON body, stripped; anything that is not a string becomes the default."""
    value = data.get(key, default)
    return value.strip() if isinstance(value, str) else default


def str_list(value):
    """A list of non-empty stripped strings; anything else is dropped."""
    if not isinstance(value, list):
        return []
    return [v.strip() for v in value if isinstance(v, str) and v.strip()]


def is_admin():
    return session.get('user_role') == 'admin'


def internal_error(exc, message='Internal error'):
    """Log the exception with a reference ID and return a generic 500 that carries only the ID."""
    ref = uuid.uuid4().hex[:8]
    logger.error('%s [ref %s]', message, ref, exc_info=exc)
    return jsonify({'error': f'{message} (ref {ref})'}), 500


def upstream_detail(exc):
    """'HTTP 429' or the exception class name. Never the URL, which may hold an API key."""
    status = getattr(getattr(exc, 'response', None), 'status_code', None)
    return f'HTTP {status}' if status else type(exc).__name__


def upstream_message(service, exc):
    """User-safe text for a failed `requests` call to a third-party API."""
    logger.warning('%s request failed: %s', service, upstream_detail(exc))
    return f'{service} API request failed ({upstream_detail(exc)})'
