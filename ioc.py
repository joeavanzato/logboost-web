"""
IOC extraction: IPs and domains from free text, with defang support.

Kept free of Flask/app imports so it can run as a subprocess (`python ioc.py`,
text on stdin, JSON on stdout). app.extract_iocs_from_text runs it that way with
a timeout, so a pathological input cannot stall the web worker.
"""

import ipaddress
import json
import re
import sys
from urllib.parse import urlparse

# IP regex pattern
IP_PATTERN = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
    r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
)


# ========== IOC Extraction ==========

# Domain regex pattern - matches valid domain names
DOMAIN_PATTERN = re.compile(
    # {1,126}: a DNS name has at most 127 labels. An unbounded "+" is quadratic on "a.a.a.a...".
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.){1,126}[a-zA-Z]{2,}\b'
)

# Pattern to find and refang defanged domains directly
DEFANG_SEPARATORS = re.compile(
    r'\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|'  # [.] (.) {.}
    r'\[\s*dot\s*\]|\(\s*dot\s*\)|\{\s*dot\s*\}|'  # [dot] (dot) {dot}
    r'\s+dot\s+',  # space dot space
    re.IGNORECASE
)

# Common false positive domains to exclude
IOC_DOMAIN_EXCLUSIONS = {
    'example.com', 'example.org', 'example.net',
    'localhost.localdomain', 'schema.org', 'w3.org',
    'googleapis.com', 'gstatic.com', 'google.com',
    'microsoft.com', 'windows.net', 'azure.com',
    'cloudflare.com', 'amazonaws.com', 'github.com',
    'jquery.com', 'bootstrapcdn.com', 'cdnjs.cloudflare.com',
    'fonts.googleapis.com', 'fonts.gstatic.com',
}

# File extensions that indicate a URL, not a domain IOC
URL_FILE_EXTENSIONS = {'.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.woff', '.woff2', '.ttf', '.eot'}

# File extensions that are also valid TLDs - these need context-based filtering
# These are valid country codes but commonly used as file extensions
FILE_EXTENSION_TLDS = {
    '.md',   # Moldova - but commonly Markdown files
    '.py',   # Paraguay - but commonly Python files  
    '.sh',   # Saint Helena - but commonly shell scripts
    '.pl',   # Poland - but commonly Perl files
    '.rs',   # Serbia - but commonly Rust files
    '.go',   # (not a TLD but common file extension)
    '.cc',   # Cocos Islands - but commonly C++ files
    '.ai',   # Anguilla - but commonly Adobe Illustrator files
    '.ps',   # Palestine - but commonly PostScript files
    '.pm',   # Saint Pierre - but commonly Perl modules
    '.so',   # Somalia - but commonly shared object files
    '.do',   # Dominican Republic - but commonly config files
    '.mo',   # Macau - but commonly gettext files
    '.nu',   # Niue - but commonly config files
    '.to',   # Tonga - but commonly config files  
    '.is',   # Iceland - but commonly config files
    '.as',   # American Samoa - but commonly ActionScript
    '.gg',   # Guernsey - but commonly game files
    '.fm',   # Micronesia - but commonly audio files
    '.am',   # Armenia - but commonly Makefile
    '.re',   # Réunion - but commonly config files
    '.la',   # Laos - but commonly libtool files
    '.in',   # India - but commonly Makefile.in files
}


def looks_like_filename(text):
    """Check if text looks like a filename rather than a domain."""
    if not text or '.' not in text:
        return False
    
    text_lower = text.lower()
    
    # Check for file extension TLDs
    for ext in FILE_EXTENSION_TLDS:
        if text_lower.endswith(ext):
            # Get the "name" part before the extension
            name = text_lower[:-len(ext)]
            
            # If name has no dots (single label), it's likely a file
            # e.g., "README.md" vs "sub.domain.md"
            if '.' not in name:
                # For ambiguous TLDs, single-label "domains" are almost always files
                # Real domains in these TLDs usually have subdomains or are well-known
                # e.g., "bit.ly" is real, but "script.py" is a file
                
                # Check for obvious filename patterns first
                original_name = text[:-len(ext)]
                if (original_name.isupper() or 
                    '_' in original_name or
                    '-' in original_name or
                    original_name.lower() in ('readme', 'license', 'changelog', 'makefile', 
                                               'dockerfile', 'vagrantfile', 'gemfile',
                                               'rakefile', 'procfile', 'setup', 'config',
                                               'index', 'main', 'app', 'test', 'spec',
                                               'skill', 'todo', 'notes', 'script',
                                               'build', 'run', 'start', 'init', 'install')):
                    return True
                
                # For single-label + ambiguous TLD, be conservative and treat as file
                # unless it's a very short name (2-3 chars) which might be a real domain
                # like "t.co" or "bit.ly" patterns
                if len(name) > 3:
                    return True
    
    return False

# Initialize tldextract with caching
try:
    import tldextract
    # Create extractor that uses PSL for validation
    TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=None)  # Use bundled PSL
    TLDEXTRACT_AVAILABLE = True
except ImportError:
    TLDEXTRACT_AVAILABLE = False
    TLD_EXTRACTOR = None

# Initialize iocextract for defanged IOC handling
try:
    import iocextract
    IOCEXTRACT_AVAILABLE = True
except ImportError:
    IOCEXTRACT_AVAILABLE = False


def is_valid_domain(domain):
    """Validate domain has a valid TLD using PSL via tldextract."""
    if not TLDEXTRACT_AVAILABLE or not TLD_EXTRACTOR:
        # Fallback: basic validation
        return '.' in domain and len(domain) >= 4
    
    try:
        extracted = TLD_EXTRACTOR(domain)
        # A valid domain must have both a suffix (TLD) and a domain part
        # suffix is the public suffix (e.g., 'com', 'co.uk')
        # domain is the registered domain name (e.g., 'google' in 'google.com')
        return bool(extracted.suffix and extracted.domain)
    except Exception:
        return False


def is_valid_public_ip(ip_str):
    """
    Validate that an IP address is a legitimate public (globally routable) IP.
    
    Filters out:
    - Private IPs (10.x.x.x, 172.16-31.x.x, 192.168.x.x)
    - Loopback (127.x.x.x)
    - Link-local (169.254.x.x)
    - Multicast (224.x.x.x - 239.x.x.x)
    - Reserved/Documentation (0.x.x.x, 192.0.2.x, 198.51.100.x, 203.0.113.x)
    - Broadcast (255.255.255.255)
    - Carrier-grade NAT (100.64.x.x - 100.127.x.x)
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        
        # Check if it's a global (public) IP
        # is_global returns True for addresses that are allocated for public networks
        if not ip.is_global:
            return False
        
        # Filter out multicast addresses (224.0.0.0 - 239.255.255.255)
        # is_global doesn't catch these
        if ip.is_multicast:
            return False
        
        # Additional check: filter out some edge cases is_global might miss
        # These are technically "global" but not useful as IOCs
        
        # Filter out 0.0.0.0/8 (current network)
        if ip_str.startswith('0.'):
            return False
        
        return True
        
    except (ValueError, TypeError):
        # Invalid IP address format
        return False


def refang_domain(text):
    """Refang a defanged domain string."""
    return DEFANG_SEPARATORS.sub('.', text).lower().strip()


def extract_defanged_domains_direct(text):
    """Extract defanged domains using direct regex (fallback for iocextract)."""
    domains = set()
    
    # Pattern to find sequences that look like defanged domains
    # e.g., "evil[.]com", "bad[.]domain[.]org"
    defang_pattern = re.compile(
        # Labels are capped at 63 chars (the DNS limit) and whitespace runs at 3.
        # Unbounded, this pattern is quadratic on long hyphenated runs: 40 KB took 12 s.
        r'\b([a-zA-Z0-9][a-zA-Z0-9-]{0,62}'  # Start with alphanumeric
        r'(?:\s{0,3}[\[\(\{]\s{0,3}(?:\.|dot)\s{0,3}[\]\)\}]\s{0,3}'  # Defanged dot
        r'[a-zA-Z0-9][a-zA-Z0-9-]{0,62})+)',  # More labels
        re.IGNORECASE
    )
    
    for match in defang_pattern.finditer(text):
        defanged = match.group(1)
        # Refang it
        domain = refang_domain(defanged)
        if domain and '.' in domain:
            domains.add(domain)
    
    return domains


def extract_domain_from_url(url):
    """Extract the hostname from a URL string (with or without a scheme)."""
    try:
        host = urlparse(url if '://' in url else '//' + url).hostname
    except ValueError:
        host = None
    return (host or '').lower()


def extract_iocs_from_text(text):
    """Extract IPs and domains from text, with deduplication, PSL validation, and defang support."""
    ips = set()
    domains = set()
    
    # First, try to extract defanged IOCs using iocextract
    if IOCEXTRACT_AVAILABLE:
        # Extract and refang IPs (handles formats like 192[.]168[.]1[.]1)
        for ip in iocextract.extract_ipv4s(text, refang=True):
            ips.add(ip)
        
        # Extract and refang URLs, then get domains from them
        # This handles formats like hxxp://evil[.]com/path
        for url in iocextract.extract_urls(text, refang=True):
            domain = extract_domain_from_url(url)
            if domain and '.' in domain:
                # Skip if it's an IP
                if not IP_PATTERN.match(domain):
                    domains.add(domain)
    
    # Also extract defanged domains directly using our regex (as fallback)
    # This catches cases iocextract might miss
    defanged_domains = extract_defanged_domains_direct(text)
    domains.update(defanged_domains)
    
    # Also use standard regex extraction for non-defanged IOCs
    # (iocextract might miss some edge cases)
    
    # Extract IPs
    for match in IP_PATTERN.finditer(text):
        ips.add(match.group())

    # IPv6: loose candidates from iocextract, kept only if they parse (validated as global below)
    if IOCEXTRACT_AVAILABLE:
        for candidate in iocextract.extract_ipv6s(text):
            try:
                ips.add(str(ipaddress.ip_address(candidate.strip('[]'))))
            except ValueError:
                pass
    
    # Extract domains
    for match in DOMAIN_PATTERN.finditer(text):
        domain = match.group().lower()
        
        # Skip if it looks like a file path or has common file extensions
        if any(domain.endswith(ext) for ext in URL_FILE_EXTENSIONS):
            continue
        
        # Skip if it's actually an IP (the domain pattern can match some IP-like strings)
        if IP_PATTERN.match(domain):
            continue
        
        domains.add(domain)
    
    # Validate and filter IPs - only keep public, globally routable addresses
    valid_ips = set()
    for ip in ips:
        if is_valid_public_ip(ip):
            valid_ips.add(ip)
    
    # Validate and filter domains
    valid_domains = set()
    for domain in domains:
        # Skip common false positives
        if domain in IOC_DOMAIN_EXCLUSIONS:
            continue
        
        # Skip very short domains (likely false positives)
        if len(domain) < 4 or '.' not in domain:
            continue
        
        # Skip if it looks like a filename (e.g., README.md, script.py)
        if looks_like_filename(domain):
            continue
        
        # Validate domain has a valid TLD using PSL
        if not is_valid_domain(domain):
            continue
        
        valid_domains.add(domain)
    
    return list(valid_ips), list(valid_domains)


if __name__ == '__main__':
    _ips, _domains = extract_iocs_from_text(sys.stdin.buffer.read().decode('utf-8', errors='replace'))
    json.dump({'ips': _ips, 'domains': _domains}, sys.stdout)
