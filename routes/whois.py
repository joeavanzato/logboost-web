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


whois_bp = Blueprint('whois', __name__, url_prefix='/api/whois')


@whois_bp.route('/resolve', methods=['POST'])
@login_required
def api_whois_resolve():
    """Resolve WHOIS for a domain with caching."""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400
    
    domain = data.get('domain', '').strip()
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
        
        w = whois.whois(domain)
        
        # Extract relevant fields - capture all values, not just first
        result = {
            'domain': domain,
            # Single values (for backwards compatibility)
            'registrant_name': None,
            'registrant_email': None,
            'organization': None,
            'registrar': None,
            'creation_date': None,
            'expiration_date': None,
            'name_servers': None,
            # All values as lists
            'all_emails': [],
            'all_names': [],
            'all_organizations': [],
            'all_registrars': []
        }
        
        # Helper to get first value (for backwards compatibility)
        def get_first(val):
            if isinstance(val, list):
                return val[0] if val else None
            return val
        
        # Helper to get all values as a list
        def get_all(val):
            if val is None:
                return []
            if isinstance(val, list):
                # Filter out None and empty values, deduplicate
                seen = set()
                result = []
                for v in val:
                    if v is not None and str(v).strip():
                        v_str = str(v).strip()
                        if v_str.lower() not in seen:
                            seen.add(v_str.lower())
                            result.append(v_str)
                return result
            return [str(val).strip()] if val and str(val).strip() else []
        
        def format_date(val):
            if val is None:
                return None
            if isinstance(val, list):
                val = val[0] if val else None
            if val:
                try:
                    return val.strftime('%Y-%m-%d') if hasattr(val, 'strftime') else str(val)
                except (AttributeError, ValueError):
                    return str(val)
            return None
        
        # Get all emails from multiple possible fields
        all_emails = []
        for field in ['emails', 'email', 'registrant_email', 'admin_email', 'tech_email']:
            emails = get_all(getattr(w, field, None))
            all_emails.extend(emails)
        # Deduplicate emails
        seen_emails = set()
        unique_emails = []
        for e in all_emails:
            if e.lower() not in seen_emails:
                seen_emails.add(e.lower())
                unique_emails.append(e)
        result['all_emails'] = unique_emails
        result['registrant_email'] = unique_emails[0] if unique_emails else None
        
        # Get all names from multiple possible fields
        all_names = []
        for field in ['name', 'registrant_name', 'admin_name', 'tech_name']:
            names = get_all(getattr(w, field, None))
            all_names.extend(names)
        # Deduplicate names
        seen_names = set()
        unique_names = []
        for n in all_names:
            if n.lower() not in seen_names:
                seen_names.add(n.lower())
                unique_names.append(n)
        result['all_names'] = unique_names
        result['registrant_name'] = unique_names[0] if unique_names else None
        
        # Get all organizations
        all_orgs = []
        for field in ['org', 'organization', 'registrant_organization']:
            orgs = get_all(getattr(w, field, None))
            all_orgs.extend(orgs)
        # Deduplicate orgs
        seen_orgs = set()
        unique_orgs = []
        for o in all_orgs:
            if o.lower() not in seen_orgs:
                seen_orgs.add(o.lower())
                unique_orgs.append(o)
        result['all_organizations'] = unique_orgs
        result['organization'] = unique_orgs[0] if unique_orgs else None
        
        # Get all registrars
        all_registrars = get_all(getattr(w, 'registrar', None))
        result['all_registrars'] = all_registrars
        result['registrar'] = all_registrars[0] if all_registrars else None
        
        # Dates
        result['creation_date'] = format_date(getattr(w, 'creation_date', None))
        result['expiration_date'] = format_date(getattr(w, 'expiration_date', None))
        
        # Name servers
        ns = getattr(w, 'name_servers', None)
        if ns:
            if isinstance(ns, list):
                result['name_servers'] = [str(n).lower() for n in ns if n]
            else:
                result['name_servers'] = [str(ns).lower()]
        
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
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400
    
    domains = data.get('domains', [])
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
            w = whois.whois(domain)
            
            def get_first(val):
                if isinstance(val, list):
                    return val[0] if val else None
                return val
            
            def get_all(val):
                if val is None:
                    return []
                if isinstance(val, list):
                    seen = set()
                    result = []
                    for v in val:
                        if v is not None and str(v).strip():
                            v_str = str(v).strip()
                            if v_str.lower() not in seen:
                                seen.add(v_str.lower())
                                result.append(v_str)
                    return result
                return [str(val).strip()] if val and str(val).strip() else []
            
            def format_date(val):
                if val is None:
                    return None
                if isinstance(val, list):
                    val = val[0] if val else None
                if val:
                    try:
                        return val.strftime('%Y-%m-%d') if hasattr(val, 'strftime') else str(val)
                    except (AttributeError, ValueError):
                        return str(val)
                return None
            
            result = {
                'domain': domain,
                'all_emails': [],
                'all_names': [],
                'all_organizations': [],
                'all_registrars': []
            }
            
            # Get all emails
            all_emails = []
            for field in ['emails', 'email', 'registrant_email', 'admin_email', 'tech_email']:
                emails = get_all(getattr(w, field, None))
                all_emails.extend(emails)
            seen_emails = set()
            unique_emails = []
            for e in all_emails:
                if e.lower() not in seen_emails:
                    seen_emails.add(e.lower())
                    unique_emails.append(e)
            result['all_emails'] = unique_emails
            result['registrant_email'] = unique_emails[0] if unique_emails else None
            
            # Get all names
            all_names = []
            for field in ['name', 'registrant_name', 'admin_name', 'tech_name']:
                names = get_all(getattr(w, field, None))
                all_names.extend(names)
            seen_names = set()
            unique_names = []
            for n in all_names:
                if n.lower() not in seen_names:
                    seen_names.add(n.lower())
                    unique_names.append(n)
            result['all_names'] = unique_names
            result['registrant_name'] = unique_names[0] if unique_names else None
            
            # Get all organizations
            all_orgs = []
            for field in ['org', 'organization', 'registrant_organization']:
                orgs = get_all(getattr(w, field, None))
                all_orgs.extend(orgs)
            seen_orgs = set()
            unique_orgs = []
            for o in all_orgs:
                if o.lower() not in seen_orgs:
                    seen_orgs.add(o.lower())
                    unique_orgs.append(o)
            result['all_organizations'] = unique_orgs
            result['organization'] = unique_orgs[0] if unique_orgs else None
            
            # Get all registrars
            all_registrars = get_all(getattr(w, 'registrar', None))
            result['all_registrars'] = all_registrars
            result['registrar'] = all_registrars[0] if all_registrars else None
            
            # Dates
            result['creation_date'] = format_date(getattr(w, 'creation_date', None))
            result['expiration_date'] = format_date(getattr(w, 'expiration_date', None))
            
            # Name servers
            ns = getattr(w, 'name_servers', None)
            if ns:
                if isinstance(ns, list):
                    result['name_servers'] = [str(n).lower() for n in ns if n]
                else:
                    result['name_servers'] = [str(ns).lower()]
            
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
