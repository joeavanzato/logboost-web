"""
WHOIS resolution routes.
"""

from flask import Blueprint, request, jsonify
from concurrent.futures import ThreadPoolExecutor, as_completed

from admin import (
    get_cached_whois, set_cached_whois, get_whois_cache_settings,
    get_concurrency_settings, log_audit
)
from auth import login_required
from http_utils import json_body, str_field, str_list


whois_bp = Blueprint('whois', __name__, url_prefix='/api/whois')


def _whois_values(record, fields) -> list:
    """Values of the given WHOIS fields as stripped strings, de-duplicated case-insensitively
    with the original order kept."""
    seen, values = set(), []
    for field in fields:
        raw = getattr(record, field, None)
        for item in (raw if isinstance(raw, list) else [raw]):
            text = str(item).strip() if item else ''
            if text and text.lower() not in seen:
                seen.add(text.lower())
                values.append(text)
    return values


def _whois_date(value):
    if isinstance(value, list):
        value = value[0] if value else None
    if not value:
        return None
    try:
        return value.strftime('%Y-%m-%d') if hasattr(value, 'strftime') else str(value)
    except (AttributeError, ValueError):
        return str(value)


def parse_whois(domain, record) -> dict:
    """The fields the UI uses from a python-whois record. Used by the single and the bulk
    lookup, so both return the same shape."""
    emails = _whois_values(record, ('emails', 'email', 'registrant_email', 'admin_email', 'tech_email'))
    names = _whois_values(record, ('name', 'registrant_name', 'admin_name', 'tech_name'))
    organizations = _whois_values(record, ('org', 'organization', 'registrant_organization'))
    registrars = _whois_values(record, ('registrar',))
    name_servers = getattr(record, 'name_servers', None)
    if name_servers:
        name_servers = [str(n).lower() for n in (name_servers if isinstance(name_servers, list) else [name_servers]) if n]
    return {
        'domain': domain,
        # first values, for callers that want one
        'registrant_name': names[0] if names else None,
        'registrant_email': emails[0] if emails else None,
        'organization': organizations[0] if organizations else None,
        'registrar': registrars[0] if registrars else None,
        'creation_date': _whois_date(getattr(record, 'creation_date', None)),
        'expiration_date': _whois_date(getattr(record, 'expiration_date', None)),
        'name_servers': name_servers or None,
        # every value
        'all_emails': emails,
        'all_names': names,
        'all_organizations': organizations,
        'all_registrars': registrars,
    }


@whois_bp.route('/resolve', methods=['POST'])
@login_required
def api_whois_resolve():
    """Resolve WHOIS for a domain with caching."""
    data = json_body()
    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400
    
    domain = str_field(data, 'domain')
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400
    
    # Check cache first
    cached = get_cached_whois(domain)
    if cached:
        cached['cached'] = True
        log_audit('whois_query', 'whois', None, {'domain_count': 1, 'cached': True})
        return jsonify(cached)
    
    try:
        import whois
        
        result = parse_whois(domain, whois.whois(domain))

        # Cache the result
        cache_settings = get_whois_cache_settings()
        set_cached_whois(domain, result, cache_settings['cache_ttl'])
        
        log_audit('whois_query', 'whois', None, {'domain_count': 1, 'cached': False})
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e), 'domain': domain}), 500


@whois_bp.route('/resolve-bulk', methods=['POST'])
@login_required
def api_whois_resolve_bulk():
    """Resolve WHOIS for multiple domains concurrently with caching."""
    data = json_body()
    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400
    
    domains = str_list(data.get('domains'))
    if not domains:
        return jsonify({'error': 'Domains list is required'}), 400
    
    # Limit to prevent abuse
    if len(domains) > 100:
        return jsonify({'error': 'Maximum 100 domains allowed per request'}), 400
    
    concurrency_settings = get_concurrency_settings()
    max_workers = concurrency_settings['whois_concurrency']
    cache_settings = get_whois_cache_settings()
    cache_ttl = cache_settings['cache_ttl']
    
    results = {}
    domains_to_resolve = []
    
    # Check cache first for all domains
    for domain in domains:
        domain = domain.strip()
        if not domain:
            continue
        cached = get_cached_whois(domain)
        if cached:
            cached['cached'] = True
            results[domain] = cached
        else:
            domains_to_resolve.append(domain)
    
    def resolve_whois_single(domain):
        """Resolve WHOIS for a single domain."""
        domain = domain.strip()
        if not domain:
            return domain, None
        
        try:
            import whois
            result = parse_whois(domain, whois.whois(domain))

            # Cache the result
            set_cached_whois(domain, result, cache_ttl)
            
            return domain, result
            
        except Exception as e:
            return domain, {'error': str(e), 'domain': domain}
    
    # Resolve uncached domains concurrently
    if domains_to_resolve:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(resolve_whois_single, d): d for d in domains_to_resolve}
            for future in as_completed(futures):
                try:
                    domain, result = future.result()
                    if domain and result:
                        results[domain] = result
                except Exception as e:
                    domain = futures[future]
                    results[domain] = {'error': str(e), 'domain': domain}
    
    log_audit('whois_query_bulk', 'whois', None, {'domain_count': len(domains), 'cached_count': len(domains) - len(domains_to_resolve)})
    return jsonify({'results': results, 'cached_count': len(domains) - len(domains_to_resolve)})
