"""
Wayback Machine / URL Discovery Module
Uses Wayback Machine and Gau to find historical URLs
"""
import subprocess
import re
from urllib.parse import urlparse

GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
RESET = '\033[0m'

def wayback_enumerate(domain: str, verbose: bool = False):
    """Enumerate URLs from Wayback Machine"""
    results = []
    print(f"\n{CYAN}[*] Querying Wayback Machine for: {domain}{RESET}")
    
    try:
        # Use curl to query Wayback Machine CDX API
        url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&limit=100"
        result = subprocess.run(['curl', '-s', '--max-time', '30', url], 
                              capture_output=True, text=True, timeout=35)
        
        if result.stdout:
            lines = result.stdout.strip().split('\n')
            if len(lines) > 1:  # First line is header
                for line in lines[1:]:
                    if line.strip():
                        results.append(line.strip())
        
        print(f"{GREEN}[+] Found {len(results)} URLs in Wayback Machine{RESET}")
        
    except Exception as e:
        print(f"{RED}[!] Wayback error: {e}{RESET}")
    
    return results

def gau_scan(domain: str, verbose: bool = False):
    """Scan using Gau (Get All URLs)"""
    results = []
    print(f"\n{CYAN}[*] Running Gau scan for: {domain}{RESET}")
    
    try:
        result = subprocess.run(['gau', '--subs', domain], 
                              capture_output=True, text=True, timeout=60)
        
        if result.stdout:
            urls = result.stdout.strip().split('\n')
            results = [u for u in urls if u.strip()]
        
        print(f"{GREEN}[+] Gau found {len(results)} URLs{RESET}")
        
    except FileNotFoundError:
        print(f"{YELLOW}[!] Gau not installed. Install: go install github.com/lc/gau@latest{RESET}")
    except Exception as e:
        print(f"{RED}[!] Gau error: {e}{RESET}")
    
    return results

def js_enumerate(domain: str, verbose: bool = False):
    """Find JavaScript files on the domain"""
    results = []
    print(f"\n{CYAN}[*] Enumerating JavaScript files for: {domain}{RESET}")
    
    try:
        # Get URLs from wayback
        wayback_urls = wayback_enumerate(domain, verbose)
        js_pattern = re.compile(r'.*\.js(?:\?.*)?$', re.IGNORECASE)
        
        for url in wayback_urls:
            if js_pattern.match(url):
                results.append(url)
        
        print(f"{GREEN}[+] Found {len(results)} JavaScript files{RESET}")
        
    except Exception as e:
        print(f"{RED}[!] JS enumeration error: {e}{RESET}")
    
    return results

def parameter_discovery(domain: str, verbose: bool = False):
    """Discover URL parameters from Wayback Machine"""
    params = set()
    print(f"\n{CYAN}[*] Discovering parameters from: {domain}{RESET}")
    
    try:
        wayback_urls = wayback_enumerate(domain, verbose)
        
        for url in wayback_urls:
            parsed = urlparse(url)
            if parsed.query:
                query_params = parsed.query.split('&')
                for p in query_params:
                    if '=' in p:
                        param_name = p.split('=')[0]
                        params.add(param_name)
        
        print(f"{GREEN}[+] Found {len(params)} unique parameters{RESET}")
        
    except Exception as e:
        print(f"{RED}[!] Parameter discovery error: {e}{RESET}")
    
    return sorted(list(params))

def run(domain: str, verbose: bool = False):
    """Run all wayback/discovery modules"""
    print(f"\n{'='*60}")
    print(f"  WAYBACK & URL DISCOVERY")
    print(f"{'='*60}")
    
    all_results = {
        'wayback_urls': wayback_enumerate(domain, verbose),
        'gau_urls': gau_scan(domain, verbose),
        'js_files': js_enumerate(domain, verbose),
        'parameters': parameter_discovery(domain, verbose)
    }
    
    return all_results
