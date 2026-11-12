"""
Security module for SSRF protection and URL validation.
"""

import ipaddress
import socket
from urllib.parse import urlparse, urljoin
import requests


# Globally-routable IPv6 prefixes that embed an IPv4 address, which could be a private one.
_IPV6_EMBEDS_IPV4 = [
    ipaddress.ip_network('64:ff9b::/96'),    # NAT64 (RFC 6052)
    ipaddress.ip_network('64:ff9b:1::/48'),  # NAT64 local use (RFC 8215)
    ipaddress.ip_network('2002::/16'),       # 6to4
    ipaddress.ip_network('::/96'),           # deprecated IPv4-compatible (::127.0.0.1)
]

# Default max URL fetch size (10MB), configurable via admin
DEFAULT_MAX_URL_FETCH_SIZE = 10 * 1024 * 1024  # 10MB
MAX_REDIRECTS = 3


def is_ip_blocked(ip_str):
    """True unless the address is a globally routable unicast address."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # Invalid IP, block it
    if ip.version == 6:
        if ip.ipv4_mapped:  # ::ffff:127.0.0.1 reaches 127.0.0.1
            ip = ip.ipv4_mapped
        elif any(ip in net for net in _IPV6_EMBEDS_IPV4):
            return True
    # ipaddress tracks the IANA special-purpose registries, so this covers loopback,
    # private, link-local (cloud metadata), CGN, documentation and reserved ranges.
    return not ip.is_global or ip.is_multicast


def validate_url_for_ssrf(url):
    """
    Validate a URL to prevent SSRF attacks.

    Resolves all A and AAAA records via getaddrinfo so that multi-homed
    hosts and IPv6 addresses are checked against blocked ranges.

    Returns (is_valid, error_message)
    """
    try:
        parsed = urlparse(url)

        # Check scheme
        if parsed.scheme not in ('http', 'https'):
            return False, f"Invalid URL scheme: {parsed.scheme}. Only http and https are allowed."

        # Check hostname exists
        if not parsed.hostname:
            return False, "URL must contain a hostname."

        # Resolve all A and AAAA records for the hostname
        try:
            # getaddrinfo returns list of (family, type, proto, canonname, sockaddr)
            # sockaddr is (address, port) for AF_INET and (address, port, flow, scope) for AF_INET6
            results = socket.getaddrinfo(parsed.hostname, None)
        except socket.gaierror:
            return False, f"Could not resolve hostname: {parsed.hostname}"

        if not results:
            return False, f"No DNS records found for hostname: {parsed.hostname}"

        # Check every resolved IP address against blocked ranges
        for family, _type, _proto, _canonname, sockaddr in results:
            resolved_ip = sockaddr[0]
            if is_ip_blocked(resolved_ip):
                return False, "Access to internal/private IP addresses is not allowed."

        return True, None

    except Exception as e:
        return False, f"Invalid URL: {str(e)}"


def get_max_url_fetch_size():
    """Get the maximum URL fetch size from settings or default."""
    try:
        from admin import get_setting
        size_mb = get_setting('max_url_fetch_size_mb')
        if size_mb:
            return int(size_mb) * 1024 * 1024
    except (ValueError, TypeError):
        pass
    return DEFAULT_MAX_URL_FETCH_SIZE


def safe_fetch_url(url, max_size=None):
    """
    Safely fetch content from a URL with SSRF protection and size limits.
    
    Args:
        url: The URL to fetch
        max_size: Maximum response size in bytes (default from settings or 10MB)
    
    Returns:
        tuple: (content_bytes, content_type) or raises ValueError on error
    """
    if max_size is None:
        max_size = get_max_url_fetch_size()
    
    # Validate initial URL
    is_valid, error = validate_url_for_ssrf(url)
    if not is_valid:
        raise ValueError(f"URL validation failed: {error}")
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }
    
    # Use a session to track redirects
    sess = requests.Session()
    sess.max_redirects = MAX_REDIRECTS
    
    # Custom redirect handling to validate each hop
    redirect_count = 0
    current_url = url
    
    while redirect_count <= MAX_REDIRECTS:
        # Validate current URL
        is_valid, error = validate_url_for_ssrf(current_url)
        if not is_valid:
            raise ValueError(f"Redirect to blocked URL: {error}")
        
        response = sess.get(
            current_url, 
            headers=headers, 
            timeout=(10, 30),  # (connect_timeout, read_timeout)
            allow_redirects=False,
            stream=True
        )
        
        # Handle redirects manually
        if response.status_code in (301, 302, 303, 307, 308):
            redirect_count += 1
            if redirect_count > MAX_REDIRECTS:
                raise ValueError(f"Too many redirects (max {MAX_REDIRECTS})")
            
            redirect_url = response.headers.get('Location')
            if not redirect_url:
                raise ValueError("Redirect without Location header")
            
            current_url = urljoin(current_url, redirect_url)  # handles relative Location values
            continue
        
        # Check response status
        response.raise_for_status()
        
        # Check content length header if available
        content_length = response.headers.get('Content-Length')
        if content_length and int(content_length) > max_size:
            raise ValueError(f"Response too large: {int(content_length)} bytes (max {max_size})")
        
        # Stream and read with size limit
        content = bytearray()
        for chunk in response.iter_content(chunk_size=8192):
            content += chunk
            if len(content) > max_size:
                raise ValueError(f"Response exceeded maximum size of {max_size} bytes")
        content = bytes(content)
        
        content_type = response.headers.get('Content-Type', '').lower()
        return content, content_type
    
    raise ValueError("Failed to fetch URL after redirect handling")
