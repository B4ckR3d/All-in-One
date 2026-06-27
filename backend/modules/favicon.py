"""
Favicon Hash Finder - Use favicon to identify technologies
"""
import requests
import mmh3
import codecs
import base64
import hashlib
import re

GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
RESET = '\033[0m'

def get_favicon_hash(domain: str, verbose: bool = False):
    """Get favicon hash (used by Shodan)"""
    print(f"\n{CYAN}[*] Getting favicon hash for: {domain}{RESET}")
    
    base_url = domain if '://' in domain else f'https://{domain}'
    
    try:
        # Try common favicon paths
        favicon_paths = ['/favicon.ico', '/favicon.png', '/apple-touch-icon.png', '/favicon.svg']
        favicon_data = None
        
        for path in favicon_paths:
            try:
                url = base_url.rstrip('/') + path
                r = requests.get(url, timeout=5)
                if r.status_code == 200 and len(r.content) > 0:
                    favicon_data = r.content
                    print(f"{GREEN}[+] Found favicon at: {path}{RESET}")
                    break
            except:
                pass
        
        # Also try to extract from HTML
        if not favicon_data:
            r = requests.get(base_url, timeout=10)
            match = re.search(r'<link[^>]+rel=["\'][^"\']*icon[^"\']*["\'][^>]+href=["\']([^"\']+)["\']', r.text, re.IGNORECASE)
            if match:
                icon_url = match.group(1)
                if not icon_url.startswith('http'):
                    icon_url = base_url.rstrip('/') + '/' + icon_url.lstrip('/')
                icon_r = requests.get(icon_url, timeout=5)
                if icon_r.status_code == 200:
                    favicon_data = icon_r.content
                    print(f"{GREEN}[+] Found favicon via HTML: {icon_url}{RESET}")
        
        if favicon_data:
            # Calculate MurmurHash3
            favicon_b64 = base64.b64encode(favicon_data).decode('utf-8')
            hash_value = mmh3.hash(favicon_b64)
            
            print(f"{GREEN}[+] Favicon MMH3 Hash: {hash_value}{RESET}")
            print(f"{CYAN}[*] Use in Shodan: http.favicon.hash:{hash_value}{RESET}")
            
            # Also calculate MD5
            md5_hash = hashlib.md5(favicon_data).hexdigest()
            print(f"{CYAN}[*] MD5: {md5_hash}{RESET}")
            
            return {
                'mmh3': hash_value,
                'md5': md5_hash,
                'shodan_query': f'http.favicon.hash:{hash_value}'
            }
        else:
            print(f"{RED}[!] No favicon found{RESET}")
            return None
            
    except Exception as e:
        print(f"{RED}[!] Error: {e}{RESET}")
        return None

def find_favicon(domain: str, verbose: bool = False):
    """Find and analyze favicon"""
    return get_favicon_hash(domain, verbose)

def run(domain: str, verbose: bool = False):
    """Run favicon analysis"""
    print(f"\n{'='*60}")
    print(f"  FAVICON HASH FINDER")
    print(f"{'='*60}")
    
    return get_favicon_hash(domain, verbose)
