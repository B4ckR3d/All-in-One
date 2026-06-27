"""
JavaScript Scanner - Extract endpoints, secrets, and data from JS files
"""
import requests
import re
import subprocess
from urllib.parse import urlparse

GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
RESET = '\033[0m'

# Patterns to search in JS files
SECRET_PATTERNS = {
    'AWS Access Key': r'AKIA[0-9A-Z]{16}',
    'AWS Secret Key': r'[A-Za-z0-9/+=]{40}',
    'Google API': r'AIza[0-9A-Za-z\-_]{35}',
    'GitHub Token': r'gh[pousr]_[A-Za-z0-9_]{36,255}',
    'Twitter API': r'[0-9A-Za-z\-_]{25}',
    'Stripe API': r'sk_live_[0-9a-zA-Z]{24}',
    'Stripe Publishable': r'pk_live_[0-9a-zA-Z]{24}',
    'Slack Token': r'xox[baprs]-[0-9a-zA-Z\-]+',
    'Discord Token': r'[MN][A-Za-z\d]{23,}\.[\w\-]{6}\.[\w\-]{27}',
    'Generic API Key': r'[aA][pP][iI][-_]?[kK][eE][yY].*[\'"][0-9a-zA-Z_\-]{20,}[\'"]',
    'Generic Secret': r'[sS][eE][cC][rR][eE][tT].*[\'"][0-9a-zA-Z_\-]{20,}[\'"]',
    'Bearer Token': r'[Bb]earer\s+[0-9a-zA-Z_\-\.]+',
    'Basic Auth': r'[Bb]asic\s+[0-9a-zA-Z_\-]+=*',
    'JWT Token': r'eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+',
    'Password in URL': r'://[0-9a-zA-Z_\-]+:[0-9a-zA-Z_\-]+@',
}

ENDPOINT_PATTERNS = [
    r'["\'](/[a-zA-Z0-9_\-/\.?&=\[\]]{3,})["\']',
    r'["\'](https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}[a-zA-Z0-9_\-/\.?&=\[\]]*)["\']',
    r'fetch\(["\']([^"\']+)["\']',
    r'\.get\(["\']([^"\']+)["\']',
    r'\.post\(["\']([^"\']+)["\']',
    r'\.put\(["\']([^"\']+)["\']',
    r'\.delete\(["\']([^"\']+)["\']',
    r'axios\.(get|post|put|delete)\(["\']([^"\']+)["\']',
    r'window\.open\(["\']([^"\']+)["\']',
    r'location\.href\s*=\s*["\']([^"\']+)["\']',
]

API_PATTERNS = [
    r'api[_-]?key',
    r'apikey',
    r'access[_-]?token',
    r'accessToken',
    r'refresh[_-]?token',
    r'secret[_-]?key',
    r'auth[_-]?token',
    r'bearer',
    r'password',
    r'passwd',
    r'credential',
]

def fetch_js_file(url: str, verbose: bool = False):
    """Fetch and analyze a single JS file"""
    results = {
        'url': url,
        'secrets': [],
        'endpoints': [],
        'apis': [],
        'errors': []
    }
    
    try:
        r = requests.get(url, timeout=10)
        content = r.text
        
        if verbose:
            print(f"{CYAN}[*] Scanning: {url}{RESET}")
        
        # Find secrets
        for name, pattern in SECRET_PATTERNS.items():
            matches = re.findall(pattern, content)
            if matches:
                for match in matches[:5]:  # Limit per type
                    results['secrets'].append({
                        'type': name,
                        'value': match if len(str(match)) < 100 else str(match)[:100] + '...'
                    })
                    print(f"{RED}[!] SECRET FOUND: {name} in {url}{RESET}")
        
        # Find endpoints
        for pattern in ENDPOINT_PATTERNS:
            matches = re.findall(pattern, content)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0]
                if match and len(match) > 3:
                    results['endpoints'].append(match)
        
        # Find API references
        for api in API_PATTERNS:
            if re.search(api, content, re.IGNORECASE):
                results['apis'].append(api)
        
    except Exception as e:
        results['errors'].append(str(e))
    
    return results

def js_scan(domain: str, verbose: bool = False):
    """Scan all JS files found on domain"""
    print(f"\n{CYAN}[*] Scanning JavaScript files on: {domain}{RESET}")
    
    all_results = {
        'files_scanned': 0,
        'secrets': [],
        'endpoints': [],
        'apis': []
    }
    
    js_urls = set()
    
    # First, get JS files from main page
    try:
        parsed = urlparse(domain if '://' in domain else f'https://{domain}')
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        r = requests.get(base_url, timeout=10)
        content = r.text
        
        # Find JS files
        js_pattern = re.compile(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', re.IGNORECASE)
        inline_js = re.findall(r'<script[^>]*>([^<]+)</script>', content, re.IGNORECASE)
        
        for match in js_pattern.finditer(content):
            js_url = match.group(1)
            if js_url.startswith('/'):
                js_url = base_url + js_url
            js_urls.add(js_url)
        
        print(f"{GREEN}[+] Found {len(js_urls)} JS files{RESET}")
        
        # Scan each JS file
        for js_url in list(js_urls)[:20]:  # Limit to 20
            result = fetch_js_file(js_url, verbose)
            all_results['files_scanned'] += 1
            
            all_results['secrets'].extend(result['secrets'])
            all_results['endpoints'].extend(result['endpoints'])
            all_results['apis'].extend(result['apis'])
        
        # Dedupe
        all_results['endpoints'] = list(set(all_results['endpoints']))[:50]
        all_results['apis'] = list(set(all_results['apis']))
        
        print(f"\n{GREEN}[+] Summary:{RESET}")
        print(f"  Files scanned: {all_results['files_scanned']}")
        print(f"  Secrets found: {len(all_results['secrets'])}")
        print(f"  Endpoints found: {len(all_results['endpoints'])}")
        print(f"  API references: {len(all_results['apis'])}")
        
    except Exception as e:
        print(f"{RED}[!] Error: {e}{RESET}")
    
    return all_results

def extract_endpoints_from_js(js_content: str, verbose: bool = False):
    """Extract API endpoints from JS content"""
    endpoints = []
    
    # URL patterns
    patterns = [
        r'["\'](/api/[a-zA-Z0-9_\-/]+)["\']',
        r'["\'](/v[0-9]+/[a-zA-Z0-9_\-/]+)["\']',
        r'["\'](https?://[a-zA-Z0-9\.-]+/api/[a-zA-Z0-9_\-/]+)["\']',
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, js_content)
        endpoints.extend(matches)
    
    return list(set(endpoints))

def run(domain: str, verbose: bool = False):
    """Run JS scanning"""
    print(f"\n{'='*60}")
    print(f"  JAVASCRIPT SECURITY SCANNER")
    print(f"{'='*60}")
    
    return js_scan(domain, verbose)
