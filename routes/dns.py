"""
DNS resolution routes and utilities.
"""

from flask import Blueprint, request, jsonify
from concurrent.futures import ThreadPoolExecutor

import dns.resolver
import dns.exception
from dns.reversename import from_address

from admin import (
    get_dns_settings, get_cached_dns, set_cached_dns,
    get_concurrency_settings, log_audit
)
from auth import login_required
from http_utils import json_body, str_list


dns_bp = Blueprint('dns', __name__, url_prefix='/api/dns')

RECORD_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA']
MAX_DNS_THREADS = 50  # per request, shared across all domains and record types


def _record_value(rtype, rdata):
    if rtype in ('A', 'AAAA'):
        return str(rdata)
    if rtype == 'CNAME':
        return str(rdata.target).rstrip('.')
    if rtype == 'MX':
        return str(rdata.exchange).rstrip('.')
    if rtype in ('NS', 'PTR'):
        return str(rdata.target).rstrip('.')
    if rtype == 'TXT':
        return b''.join(rdata.strings).decode('utf-8', errors='replace')
    if rtype == 'SOA':
        return str(rdata.mname).rstrip('.')  # primary nameserver
    return str(rdata)


def _lookup(query, rtype, settings, use_cache=True):
    """One cached lookup. Returns a list of records, or {'error': ...}.

    Only real answers are cached (records, NXDOMAIN, NoAnswer). Timeouts and
    resolver failures are not, so a brief outage does not stick for the whole TTL.
    """
    if use_cache:
        cached = get_cached_dns(query, rtype)
        if cached is not None:
            return cached

    resolver = dns.resolver.Resolver()
    resolver.nameservers = [s.strip() for s in settings['servers'].split(',') if s.strip()]
    resolver.timeout = settings['timeout']
    resolver.lifetime = settings['timeout']

    try:
        name = from_address(query) if rtype == 'PTR' else query
        records = [_record_value(rtype, rdata) for rdata in resolver.resolve(name, rtype)]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        records = []
    except dns.exception.Timeout:
        return {'error': 'timeout'}
    except Exception:
        return {'error': 'lookup failed'}

    set_cached_dns(query, rtype, records, settings['cache_ttl'])
    return records


def resolve_dns(query, record_types=None, use_cache=True):
    """Resolve all record types for one name, concurrently. Returns {rtype: records | {'error': ...}}."""
    record_types = record_types or RECORD_TYPES
    settings = get_dns_settings()
    with ThreadPoolExecutor(max_workers=len(record_types)) as pool:
        results = pool.map(lambda rtype: _lookup(query, rtype, settings, use_cache), record_types)
        return dict(zip(record_types, results))


def reverse_dns(ip):
    """Reverse (PTR) lookup. Returns a list of hostnames; empty on any failure."""
    result = _lookup(ip, 'PTR', get_dns_settings())
    return result if isinstance(result, list) else []


def _resolve_one(query, query_type):
    try:
        return {'PTR': reverse_dns(query)} if query_type == 'ip' else resolve_dns(query)
    except Exception:
        return {'error': 'lookup failed'}


def _resolve_many(queries, query_type):
    """Resolve several names at once without exceeding MAX_DNS_THREADS in total."""
    per_query = 1 if query_type == 'ip' else len(RECORD_TYPES)  # resolve_dns fans out per record type
    workers = max(1, min(MAX_DNS_THREADS // per_query, get_concurrency_settings()['dns_concurrency']))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return dict(zip(queries, pool.map(lambda q: _resolve_one(q, query_type), queries)))


def _handle_resolve(audit_action):
    data = json_body()
    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400

    queries = str_list(data.get('queries'))
    query_type = data.get('type', 'domain')  # 'domain' or 'ip'

    max_domains = get_dns_settings()['max_domains']
    if len(queries) > max_domains:
        return jsonify({'error': f'Maximum {max_domains} queries allowed'}), 400

    results = _resolve_many(queries, query_type)
    log_audit(audit_action, 'dns', None, {'query_count': len(queries), 'type': query_type})
    return jsonify({'results': results})


@dns_bp.route('/resolve', methods=['POST'])
@login_required
def api_dns_resolve():
    """Resolve DNS for domains or IPs."""
    return _handle_resolve('dns_query')


@dns_bp.route('/resolve-bulk', methods=['POST'])
@login_required
def api_dns_resolve_bulk():
    """Resolve DNS for multiple domains. Same implementation as /resolve; kept for existing clients."""
    return _handle_resolve('dns_query_bulk')
