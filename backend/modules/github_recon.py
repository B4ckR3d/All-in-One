"""
GitHub Recon - GitHub dorking and repo discovery
"""
import requests
import re
from urllib.parse import quote

GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
RESET = '\033[0m'

GITHUB_SEARCH_QUERIES = [
    'org:{org} filename:.env',
    'org:{org} filename:config.json password',
    'org:{org} filename:credentials.json',
    'org:{org} filename:secrets.yml',
    'org:{org} filename:.htpasswd',
    'org:{org} filename:wp-config.php',
    'org:{org} filename:database.yml',
    'org:{org} path:/configs filename:*',
    'org:{org} extension:pem private',
    'org:{org} extension:key private',
    '"{domain}" filename:*.sql',
    '"{domain}" filename:*.bak',
    '"{domain}" filename:*.log',
    '"{domain}" "api_key"',
    '"{domain}" "password"',
    '"{domain}" "secret"',
    '"{domain}" "token"',
    '"{domain}" "AWS_ACCESS_KEY"',
    '"{domain}" "DB_PASSWORD"',
]

def github_search(query: str, token: str = None, verbose: bool = False):
    """Search GitHub"""
    results = []
    headers = {'Accept': 'application/vnd.github.v3+json'}
    if token:
        headers['Authorization'] = f'token {token}'
    
    url = f'https://api.github.com/search/code?q={quote(query)}'
    
    try:
        r = requests.get(url, headers=headers, timeout=30)
        if r.status_code == 200:
            data = r.json()
            results = data.get('items', [])
            print(f"{GREEN}[+] Found {len(results)} results{RESET}")
        elif r.status_code == 403:
            print(f"{RED}[!] Rate limited! Need GitHub token{RESET}")
        else:
            print(f"{YELLOW}[!] Status: {r.status_code}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error: {e}{RESET}")
    
    return results

def github_dork(domain: str, org: str = None, token: str = None, verbose: bool = False):
    """Run GitHub dorks"""
    print(f"\n{CYAN}[*] Running GitHub dorks for: {domain}{RESET}")
    
    all_results = []
    queries = []
    
    if org:
        for q in GITHUB_SEARCH_QUERIES:
            queries.append(q.replace('{org}', org))
    else:
        # Domain-based queries
        queries = [q.replace('{domain}', domain) for q in GITHUB_SEARCH_QUERIES if '{domain}' in q]
    
    for q in queries[:15]:  # Limit to avoid rate limits
        print(f"\n{YELLOW}[*] Query: {q}{RESET}")
        results = github_search(q, token, verbose)
        if results:
            all_results.extend(results)
            for item in results[:5]:  # Show first 5
                print(f"  {GREEN}- {item.get('html_url', 'N/A')}{RESET}")
    
    return all_results

def find_github_repos(org: str, token: str = None, verbose: bool = False):
    """Find all repos for an org"""
    print(f"\n{CYAN}[*] Finding repos for org: {org}{RESET}")
    
    repos = []
    headers = {'Accept': 'application/vnd.github.v3+json'}
    if token:
        headers['Authorization'] = f'token {token}'
    
    url = f'https://api.github.com/orgs/{org}/repos?per_page=100'
    
    try:
        r = requests.get(url, headers=headers, timeout=30)
        if r.status_code == 200:
            repos = r.json()
            print(f"{GREEN}[+] Found {len(repos)} repositories{RESET}")
            for repo in repos[:10]:
                print(f"  {GREEN}- {repo.get('full_name')} ({repo.get('visibility', 'unknown')}){RESET}")
        else:
            print(f"{RED}[!] Status: {r.status_code}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error: {e}{RESET}")
    
    return repos

def run(domain: str = None, org: str = None, token: str = None, verbose: bool = False):
    """Run GitHub recon"""
    print(f"\n{'='*60}")
    print(f"  GITHUB RECON")
    print(f"{'='*60}")
    
    results = {
        'dorks': [],
        'repos': []
    }
    
    if domain:
        results['dorks'] = github_dork(domain, org, token, verbose)
    
    if org:
        results['repos'] = find_github_repos(org, token, verbose)
    
    return results
