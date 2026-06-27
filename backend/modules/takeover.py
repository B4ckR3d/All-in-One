"""
Subdomain Takeover Checker
"""
import requests
import re
from urllib.parse import urlparse

GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
RESET = '\033[0m'

# Services that are vulnerable to takeover
TAKEOVER_SERVICES = {
    'AWS S3': {
        'cname_pattern': r'.*\.s3\.amazonaws\.com',
        'check_code': 404,
        'fingerprint': None,
        'service_url': 'https://aws.amazon.com/s3/'
    },
    'GitHub Pages': {
        'cname_pattern': r'.*\.github\.io',
        'check_code': 404,
        'fingerprint': 'There isn\'t a GitHub Pages site here.',
        'service_url': 'https://pages.github.com/'
    },
    'Heroku': {
        'cname_pattern': r'.*\.herokuapp\.com',
        'check_code': 404,
        'fingerprint': 'No such app',
        'service_url': 'https://heroku.com/'
    },
    'Netlify': {
        'cname_pattern': r'.*\.netlify\.app',
        'check_code': 404,
        'fingerprint': 'Not Found',
        'service_url': 'https://netlify.com/'
    },
    'Vercel': {
        'cname_pattern': r'.*\.vercel\.app',
        'check_code': 404,
        'fingerprint': 'Not Found',
        'service_url': 'https://vercel.com/'
    },
    'Cloudflare Pages': {
        'cname_pattern': r'.*\.pages\.dev',
        'check_code': 404,
        'fingerprint': 'Not Found',
        'service_url': 'https://pages.cloudflare.com/'
    },
    'WordPress.com': {
        'cname_pattern': r'.*\.wordpress\.com',
        'check_code': 404,
        'fingerprint': 'Do you want to register',
        'service_url': 'https://wordpress.com/'
    },
    'Shopify': {
        'cname_pattern': r'.*\.myshopify\.com',
        'check_code': 404,
        'fingerprint': 'Sorry, this shop is currently unavailable',
        'service_url': 'https://shopify.com/'
    },
    'Ghost': {
        'cname_pattern': r'.*\.ghost\.io',
        'check_code': 404,
        'fingerprint': 'The thing you were looking for does not exist',
        'service_url': 'https://ghost.org/'
    },
    'Cargo': {
        'cname_pattern': r'.*\.cargocollective\.com',
        'check_code': 404,
        'fingerprint': 'Site not found',
        'service_url': 'https://cargocollective.com/'
    },
    'FeedBurner': {
        'cname_pattern': r'.*\.feedburner\.com',
        'check_code': 404,
        'fingerprint': None,
        'service_url': 'https://feedburner.com/'
    },
    'Firebase': {
        'cname_pattern': r'.*\.firebaseapp\.com',
        'check_code': 404,
        'fingerprint': 'Firebase console',
        'service_url': 'https://firebase.google.com/'
    },
    'Read.Docs': {
        'cname_pattern': r'.*\.readthedocs.io',
        'check_code': 404,
        'fingerprint': 'Read the Docs',
        'service_url': 'https://readthedocs.org/'
    },
    'UserVoice': {
        'cname_pattern': r'.*\.uservoice\.com',
        'check_code': 404,
        'fingerprint': 'This UserVoice subdomain is currently available!',
        'service_url': 'https://uservoice.com/'
    },
    'GetFeedback': {
        'cname_pattern': r'.*\.quicksurvey\.io',
        'check_code': 404,
        'fingerprint': None,
        'service_url': 'https://getfeedback.com/'
    }
}

def check_takeover(subdomain: str, service: str, service_config: dict, verbose: bool = False):
    """Check if a subdomain is vulnerable to takeover"""
    url = f"https://{subdomain}"
    
    try:
        r = requests.get(url, timeout=10, allow_redirects=True)
        status = r.status_code
        content = r.text[:1000]
        
        # Check by status code
        if service_config['check_code'] == status:
            # Check fingerprint
            if service_config['fingerprint']:
                if service_config['fingerprint'].lower() in content.lower():
                    return True
            else:
                return True
        
        # Some services return 200 with specific content
        if service == 'GitHub Pages' and 'There isn\'t a GitHub Pages site here' in content:
            return True
        if service == 'WordPress.com' and ('do you want to register' in content.lower() or 'is available' in content.lower()):
            return True
            
    except requests.exceptions.ConnectionError:
        # Connection error might mean no service is running
        return None
    except Exception:
        pass
    
    return False

def run(subdomains: list = None, domain: str = None, verbose: bool = False):
    """Run subdomain takeover check"""
    print(f"\n{'='*60}")
    print(f"  SUBDOMAIN TAKEOVER CHECKER")
    print(f"{'='*60}")
    
    results = {
        'vulnerable': [],
        'safe': [],
        'unknown': []
    }
    
    if not subdomains:
        # Need subdomains from previous scan
        print(f"{YELLOW}[!] No subdomains provided. Run subdomain enum first.{RESET}")
        return results
    
    print(f"\n{CYAN}[*] Checking {len(subdomains)} subdomains for takeover vulnerabilities...{RESET}")
    
    for subdomain in subdomains:
        is_takeoverable = False
        detected_service = None
        
        for service, config in TAKEOVER_SERVICES.items():
            # Check if CNAME matches service pattern
            if re.match(config['cname_pattern'], subdomain):
                detected_service = service
                result = check_takeover(subdomain, service, config, verbose)
                
                if result == True:
                    print(f"{RED}[!] VULNERABLE: {subdomain} ({service}){RESET}")
                    results['vulnerable'].append({
                        'subdomain': subdomain,
                        'service': service,
                        'url': f"https://{subdomain}",
                        'service_url': config['service_url']
                    })
                    is_takeoverable = True
                elif result == False:
                    print(f"{GREEN}[-] SAFE: {subdomain}{RESET}")
                    results['safe'].append(subdomain)
                break
        
        if not is_takeoverable and not detected_service:
            results['unknown'].append(subdomain)
    
    print(f"\n{GREEN}[+] Takeover vulnerable: {len(results['vulnerable'])}{RESET}")
    print(f"{YELLOW}[!] Safe: {len(results['safe'])}{RESET}")
    
    return results
