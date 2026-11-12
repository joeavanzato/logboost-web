"""
Chaos (ProjectDiscovery) subdomain enumeration routes.
"""

from flask import Blueprint, request, jsonify, current_app
import requests

from admin import get_chaos_settings, get_cached_chaos, set_cached_chaos, log_audit
from auth import login_required
from http_utils import json_body, str_field, internal_error, upstream_message
from urllib.parse import quote


chaos_bp = Blueprint('chaos', __name__, url_prefix='/api/chaos')


@chaos_bp.route('/settings', methods=['GET'])
@login_required
def api_chaos_settings():
    """Get Chaos settings (for frontend to check if API key is configured)."""
    settings = get_chaos_settings()
    return jsonify({
        'api_key_configured': bool(settings.get('api_key'))
    })


@chaos_bp.route('/subdomains', methods=['POST'])
@login_required
def api_chaos_subdomains():
    """Fetch subdomains for a domain using Chaos (ProjectDiscovery) API."""
    data = json_body()
    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400
    
    domain = str_field(data, 'domain').lower()
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400
    
    # Get Chaos settings
    settings = get_chaos_settings()
    
    if not settings.get('api_key'):
        return jsonify({'error': 'Chaos API key not configured. Please set it in Admin Settings.'}), 400
    
    # Check cache first
    cached = get_cached_chaos(domain)
    if cached:
        current_app.logger.debug("[Chaos] Cache hit for domain: %s", domain)
        return jsonify({
            'domain': domain,
            'subdomains': cached['subdomains'],
            'subdomain_count': cached['subdomain_count'],
            'from_cache': True,
            'cached_at': cached['cached_at']
        })
    
    current_app.logger.debug("[Chaos] Querying subdomains for domain: %s", domain)
    
    try:
        # Call Chaos API
        url = f"https://dns.projectdiscovery.io/dns/{quote(domain, safe='')}/subdomains"
        headers = {
            'Authorization': settings['api_key'],
            'Connection': 'close'
        }
        
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        
        result = response.json()
        
        subdomains = result.get('subdomains', [])
        subdomain_count = result.get('count', len(subdomains))
        
        current_app.logger.debug("[Chaos] Found %d subdomains for %s", subdomain_count, domain)
        
        # Cache the results
        set_cached_chaos(domain, subdomains, subdomain_count, settings['cache_ttl'])
        
        log_audit('chaos_subdomains', 'chaos', domain, {'subdomain_count': subdomain_count})
        
        return jsonify({
            'domain': domain,
            'subdomains': subdomains,
            'subdomain_count': subdomain_count,
            'from_cache': False
        })
        
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 401:
            current_app.logger.warning("[Chaos] Unauthorized - invalid API key")
            return jsonify({'error': 'Invalid Chaos API key'}), 401
        elif e.response.status_code == 404:
            current_app.logger.debug("[Chaos] No data found for domain: %s", domain)
            # Cache empty result to avoid repeated lookups
            set_cached_chaos(domain, [], 0, settings['cache_ttl'])
            return jsonify({
                'domain': domain,
                'subdomains': [],
                'subdomain_count': 0,
                'from_cache': False
            })
        return jsonify({'error': f'Chaos API error: {e.response.status_code}'}), 500
    except requests.exceptions.RequestException as e:
        return jsonify({'error': upstream_message('Chaos', e)}), 500
    except Exception as e:
        return internal_error(e)
