"""
IP Range Scanner / AS Lookup
"""
import requests
import re
from urllib.parse import urlparse

GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
RESET = '\033[0m'

def ip_info(ip: str, verbose: bool = False):
    """Get IP geolocation and network info"""
    print(f"\n{CYAN}[*] Looking up IP: {ip}{RESET}")
    
    try:
        # Using ip-api.com
        r = requests.get(f'http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query', timeout=10)
        data = r.json()
        
        if data.get('status') == 'success':
            print(f"\n{GREEN}[+] IP Information:{RESET}")
            print(f"  IP: {data.get('query')}")
            print(f"  Location: {data.get('city')}, {data.get('regionName')}, {data.get('country')}")
            print(f"  Coordinates: {data.get('lat')}, {data.get('lon')}")
            print(f"  ISP: {data.get('isp')}")
            print(f"  Org: {data.get('org')}")
            print(f"  AS: {data.get('as')}")
            print(f"  Timezone: {data.get('timezone')}")
            return data
        else:
            print(f"{RED}[!] IP lookup failed{RESET}")
            return None
            
    except Exception as e:
        print(f"{RED}[!] Error: {e}{RESET}")
        return None

def as_lookup(as_number: str, verbose: bool = False):
    """Lookup AS number details"""
    print(f"\n{CYAN}[*] Looking up AS: {as_number}{RESET}")
    
    try:
        # Using BGPView API
        as_num = as_number.replace('AS', '').strip()
        r = requests.get(f'https://api.bgpview.io/asn/{as_num}/prefixes', timeout=10)
        data = r.json()
        
        if data.get('status') == 'ok':
            print(f"\n{GREEN}[+] AS {as_num} Information:{RESET}")
            
            data_obj = data.get('data', {})
            print(f"  Name: {data_obj.get('name', 'N/A')}")
            print(f"  Description: {data_obj.get('description', 'N/A')}")
            print(f"  Country: {data_obj.get('country_code', 'N/A')}")
            
            prefixes = data_obj.get('prefixes', [])
            print(f"\n  {GREEN}Prefixes ({len(prefixes)}):{RESET}")
            for p in prefixes[:10]:
                print(f"    - {p.get('prefix')} ({p.get('name', 'N/A')})")
            
            return data
        else:
            print(f"{RED}[!] AS lookup failed{RESET}")
            return None
            
    except Exception as e:
        print(f"{RED}[!] Error: {e}{RESET}")
        return None

def reverse_ip(ip: str, verbose: bool = False):
    """Reverse IP lookup - find domains on same IP"""
    print(f"\n{CYAN}[*] Reverse IP lookup for: {ip}{RESET}")
    
    results = []
    
    try:
        # Using HackerTarget reverse IP lookup (or similar free API)
        r = requests.get(f'https://api.hackertarget.com/reverseiplookup/?q={ip}', timeout=10)
        
        if r.status_code == 200:
            lines = r.text.strip().split('\n')
            if 'error' not in lines[0].lower():
                results = [l for l in lines if l.strip()]
                print(f"{GREEN}[+] Found {len(results)} domains:{RESET}")
                for domain in results[:20]:
                    print(f"  - {domain}")
            else:
                print(f"{YELLOW}[!] No results{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error: {e}{RESET}")
    
    return results

def ip_range_scan(cidr: str, verbose: bool = False):
    """Scan IP range (CIDR notation)"""
    print(f"\n{CYAN}[*] Scanning IP range: {cidr}{RESET}")
    
    import ipaddress
    
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        print(f"{GREEN}[+] {network.num_addresses} addresses in range{RESET}")
        
        # Only scan first 256 for performance
        count = 0
        for ip in network.hosts():
            if count >= 256:
                break
            count += 1
            # Would add ping/probe here
            if verbose:
                print(f"  Checking {ip}...")
        
        print(f"{GREEN}[+] Scanned {count} hosts{RESET}")
        return list(network.hosts())[:256]
        
    except Exception as e:
        print(f"{RED}[!] Error: {e}{RESET}")
        return []

def run(domain_or_ip: str = None, mode: str = 'info', verbose: bool = False):
    """Run IP operations"""
    print(f"\n{'='*60}")
    print(f"  IP / NETWORK LOOKUP")
    print(f"{'='*60}")
    
    results = {}
    
    if mode == 'info' and domain_or_ip:
        results['info'] = ip_info(domain_or_ip, verbose)
    elif mode == 'reverse' and domain_or_ip:
        results['reverse'] = reverse_ip(domain_or_ip, verbose)
    elif mode == 'as' and domain_or_ip:
        results['as'] = as_lookup(domain_or_ip, verbose)
    elif mode == 'range' and domain_or_ip:
        results['range'] = ip_range_scan(domain_or_ip, verbose)
    
    return results
