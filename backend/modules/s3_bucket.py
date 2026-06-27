"""
S3 Bucket Finder - AWS S3 Bucket enumeration
"""
import subprocess
import requests
from urllib.parse import urlparse

GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
RESET = '\033[0m'

COMMON_BUCKET_NAMES = [
    '{domain}', '{domain}-dev', '{domain}-staging', '{domain}-prod',
    '{domain}-production', '{domain}-backup', '{domain}-test',
    'www', 'assets', 'static', 'media', 'files', 'uploads',
    'images', 'img', 'cdn', 'app', 'apps', 'web', 'api',
    'backup', 'backups', 'db', 'database', 'logs', 'admin',
    '{domain}-www', '{domain}-static', '{domain}-assets',
    'prod', 'production', 'dev', 'development', 'stage', 'staging'
]

def find_s3_buckets(domain: str, verbose: bool = False):
    """Find S3 buckets related to domain"""
    buckets = []
    print(f"\n{CYAN}[*] Searching for S3 buckets: {domain}{RESET}")
    
    # Generate bucket names
    names = []
    for template in COMMON_BUCKET_NAMES:
        names.append(template.replace('{domain}', domain.replace('.', '-')))
        names.append(template.replace('{domain}', domain.replace('.', '')))
    
    # Check each bucket
    found_count = 0
    for name in names[:50]:  # Limit to 50
        url = f"https://{name}.s3.amazonaws.com"
        try:
            r = requests.head(url, timeout=5, allow_redirects=True)
            if r.status_code == 200:
                print(f"{GREEN}[+] FOUND: {name}.s3.amazonaws.com{RESET}")
                buckets.append({
                    'name': name,
                    'url': url,
                    'status': 'accessible' if r.status_code == 200 else 'denied'
                })
                found_count += 1
            elif r.status_code == 403:
                print(f"{YELLOW}[~] EXISTS: {name}.s3.amazonaws.com (Access Denied){RESET}")
                buckets.append({
                    'name': name,
                    'url': url,
                    'status': 'forbidden'
                })
        except:
            pass
    
    print(f"\n{GREEN}[+] Found {found_count} potentially accessible buckets{RESET}")
    return buckets

def check_bucket_acl(bucket_url: str, verbose: bool = False):
    """Check S3 bucket ACL"""
    print(f"\n{CYAN}[*] Checking bucket ACL: {bucket_url}{RESET}")
    
    try:
        # Try bucket listing
        r = requests.get(f"{bucket_url}?list-type=2", timeout=10)
        if r.status_code == 200:
            print(f"{GREEN}[+] Bucket listing is ALLOWED!{RESET}")
            return True
        else:
            print(f"{YELLOW}[-] Bucket listing denied{RESET}")
            return False
    except Exception as e:
        print(f"{RED}[!] Error checking bucket: {e}{RESET}")
        return False

def run(domain: str, verbose: bool = False):
    """Run S3 bucket enumeration"""
    print(f"\n{'='*60}")
    print(f"  S3 BUCKET ENUMERATION")
    print(f"{'='*60}")
    
    buckets = find_s3_buckets(domain, verbose)
    
    # Check ACL for found buckets
    for bucket in buckets:
        if bucket['status'] == 'accessible':
            check_bucket_acl(bucket['url'], verbose)
    
    return buckets
