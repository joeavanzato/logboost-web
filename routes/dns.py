"""
DNS resolution routes and utilities.
"""

from flask import Blueprint, request, jsonify
from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.resolver
import dns.exception

from admin import (
    get_dns_settings, get_cached_dns, set_cached_dns,
    get_concurrency_settings, log_audit
)
from auth import login_required


dns_bp = Blueprint('dns', __name__, url_prefix='/api/dns')


def resolve_dns(query, record_types=None, use_cache=True):
    """Resolve DNS for a query with caching."""
    if record_types is None:
        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA']
    
    settings = get_dns_settings()
    servers = [s.strip() for s in settings['servers'].split(',') if s.strip()]
    timeout = settings['timeout']
    cache_ttl = settings['cache_ttl']
    
    results = {}
    
    for rtype in record_types:
        # Check cache first
        if use_cache:
            cached = get_cached_dns(query, rtype)
            if cached is not None:
                results[rtype] = cached
                continue
        
        # Resolve
        resolver = dns.resolver.Resolver()
        resolver.nameservers = servers
        resolver.timeout = timeout
        resolver.lifetime = timeout
        
        try:
            answers = resolver.resolve(query, rtype)
            records = []
            for rdata in answers:
                if rtype in ('A', 'AAAA'):
                    records.append(str(rdata))
                elif rtype == 'CNAME':
                    records.append(str(rdata.target).rstrip('.'))
                elif rtype == 'MX':
                    records.append(str(rdata.exchange).rstrip('.'))
                elif rtype == 'NS':
                    records.append(str(rdata.target).rstrip('.'))
                elif rtype == 'TXT':
                    # Join TXT record parts and decode
                    txt_data = b''.join(rdata.strings).decode('utf-8', errors='replace')
                    records.append(txt_data)
                elif rtype == 'SOA':
                    # Extract primary nameserver from SOA
                    records.append(str(rdata.mname).rstrip('.'))
            results[rtype] = records
            
            # Cache the result
            set_cached_dns(query, rtype, records, cache_ttl)
            
        except dns.resolver.NXDOMAIN:
            results[rtype] = []
            set_cached_dns(query, rtype, [], cache_ttl)
        except dns.resolver.NoAnswer:
            results[rtype] = []
            set_cached_dns(query, rtype, [], cache_ttl)
        except dns.exception.Timeout:
            results[rtype] = {'error': 'timeout'}
        except Exception as e:
            results[rtype] = {'error': str(e)}
    
    return results


def reverse_dns(ip):
    """Perform reverse DNS lookup."""
    settings = get_dns_settings()
    servers = [s.strip() for s in settings['servers'].split(',') if s.strip()]
    timeout = settings['timeout']
    cache_ttl = settings['cache_ttl']
    
    # Check cache
    cached = get_cached_dns(ip, 'PTR')
    if cached is not None:
        return cached
    
    resolver = dns.resolver.Resolver()
    resolver.nameservers = servers
    resolver.timeout = timeout
    resolver.lifetime = timeout
    
    try:
        from dns.reversename import from_address
        rev_name = from_address(ip)
        answers = resolver.resolve(rev_name, 'PTR')
        results = [str(rdata.target).rstrip('.') for rdata in answers]
        set_cached_dns(ip, 'PTR', results, cache_ttl)
        return results
    except Exception:
        set_cached_dns(ip, 'PTR', [], cache_ttl)
        return []


@dns_bp.route('/resolve', methods=['POST'])
@login_required
def api_dns_resolve():
    """Resolve DNS for domains or IPs."""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400
    
    queries = data.get('queries', [])
    query_type = data.get('type', 'domain')  # 'domain' or 'ip'
    
    settings = get_dns_settings()
    max_domains = settings['max_domains']
    
    if len(queries) > max_domains:
        return jsonify({'error': f'Maximum {max_domains} queries allowed'}), 400
    
    results = {}
    
    for query in queries:
        query = query.strip()
        if not query:
            continue
        
        if query_type == 'ip':
            results[query] = {'PTR': reverse_dns(query)}
        else:
            results[query] = resolve_dns(query)
    
    log_audit('dns_query', 'dns', None, {'query_count': len(queries), 'type': query_type})
    return jsonify({'results': results})


@dns_bp.route('/resolve-bulk', methods=['POST'])
@login_required
def api_dns_resolve_bulk():
    """Resolve DNS for multiple domains concurrently."""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400
    
    queries = data.get('queries', [])
    query_type = data.get('type', 'domain')  # 'domain' or 'ip'
    
    settings = get_dns_settings()
    max_domains = settings['max_domains']
    
    if len(queries) > max_domains:
        return jsonify({'error': f'Maximum {max_domains} queries allowed'}), 400
    
    concurrency_settings = get_concurrency_settings()
    max_workers = concurrency_settings['dns_concurrency']
    
    results = {}
    
    def resolve_single(query):
        query = query.strip()
        if not query:
            return query, None
        if query_type == 'ip':
            return query, {'PTR': reverse_dns(query)}
        else:
            return query, resolve_dns(query)
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(resolve_single, q): q for q in queries}
        for future in as_completed(futures):
            try:
                query, result = future.result()
                if query and result:
                    results[query] = result
            except Exception as e:
                query = futures[future]
                results[query] = {'error': str(e)}
    
    log_audit('dns_query_bulk', 'dns', None, {'query_count': len(queries), 'type': query_type})
    return jsonify({'results': results})
