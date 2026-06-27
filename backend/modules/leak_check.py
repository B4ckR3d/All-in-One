"""
LeakDB / Password Breach Checker
Uses HaveIBeenPwned and similar APIs
"""
import requests
import hashlib
import json

GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
RESET = '\033[0m'

def check_hibp(password: str, verbose: bool = False):
    """Check password against HaveIBeenPwned"""
    print(f"\n{CYAN}[*] Checking password against HIBP...{RESET}")
    
    # Hash password (SHA-1)
    sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]
    
    try:
        # Check k-anonymity API
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        r = requests.get(url, timeout=10)
        
        if r.status_code == 200:
            hashes = r.text.strip().split('\n')
            for h in hashes:
                if ':' in h:
                    h_suffix, count = h.split(':')
                    if h_suffix == suffix:
                        print(f"{RED}[!] FOUND! Password seen {count} times in breaches!{RESET}")
                        return {'found': True, 'count': int(count.strip())}
            
            print(f"{GREEN}[+] Password NOT found in breach database{RESET}")
            return {'found': False, 'count': 0}
        else:
            print(f"{RED}[!] HIBP API error: {r.status_code}{RESET}")
            return None
            
    except Exception as e:
        print(f"{RED}[!] Error: {e}{RESET}")
        return None

def check_email_breach(email: str, api_key: str = None, verbose: bool = False):
    """Check email against breach databases"""
    print(f"\n{CYAN}[*] Checking breaches for: {email}{RESET}")
    
    results = []
    
    # Using HaveIBeenPwned API
    if api_key:
        try:
            headers = {'hibp-api-key': api_key}
            url = f'https://haveibeenpwned.com/api/v3/breachedaccount/{email}'
            r = requests.get(url, headers=headers, timeout=15)
            
            if r.status_code == 200:
                breaches = r.json()
                print(f"{RED}[!] FOUND {len(breaches)} breaches!{RESET}")
                for breach in breaches:
                    print(f"  {RED}- {breach.get('Name', 'Unknown')}{RESET}")
                    results.append(breach)
            elif r.status_code == 404:
                print(f"{GREEN}[+] No breaches found{RESET}")
            elif r.status_code == 429:
                print(f"{YELLOW}[!] Rate limited{RESET}")
            else:
                print(f"{YELLOW}[!] Status: {r.status_code}{RESET}")
        except Exception as e:
            print(f"{RED}[!] Error: {e}{RESET}")
    else:
        print(f"{YELLOW}[!] Need HIBP API key for email breach check{RESET}")
        print(f"{CYAN}[*] Get free API key from: https://haveibeenpwned.com/API/Key{RESET}")
    
    return results

def check_domain_breach(domain: str, api_key: str = None, verbose: bool = False):
    """Check all emails in a domain for breaches"""
    print(f"\n{CYAN}[*] Checking breaches for domain: {domain}{RESET}")
    
    # This would require enumeration of emails first
    # Using hunter.io or similar for email discovery
    
    print(f"{YELLOW}[!] Domain breach check requires external email enumeration{RESET}")
    print(f"{CYAN}[*] Tip: Use the wayback module to find emails on the domain{RESET}")
    
    return []

def search_exposed_emails(domain: str, verbose: bool = False):
    """Search for exposed emails using public databases"""
    print(f"\n{CYAN}[*] Searching for exposed data on: {domain}{RESET}")
    
    results = []
    
    # Search public pastebins
    try:
        # Using Leak-Lookup free API or similar
        url = f"https://leak-lookup.com/api/search?email=@{domain}"
        # This is a placeholder - real implementation needs API key
        print(f"{YELLOW}[!] LeakDB requires API key{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error: {e}{RESET}")
    
    return results

def run(mode: str = 'password', value: str = None, api_key: str = None, verbose: bool = False):
    """Run leak check"""
    print(f"\n{'='*60}")
    print(f"  LEAK / BREACH CHECKER")
    print(f"{'='*60}")
    
    results = {'password_check': None, 'email_breaches': [], 'domain_breaches': []}
    
    if mode == 'password' and value:
        results['password_check'] = check_hibp(value, verbose)
    elif mode == 'email' and value:
        results['email_breaches'] = check_email_breach(value, api_key, verbose)
    elif mode == 'domain' and value:
        results['domain_breaches'] = check_domain_breach(value, api_key, verbose)
    
    return results
