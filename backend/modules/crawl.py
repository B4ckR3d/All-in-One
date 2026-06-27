"""
Web Crawler - Extract links, forms, and data from website
"""
import requests
import re
from urllib.parse import urljoin, urlparse, parse_qs
from collections import deque
import time

GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
RESET = '\033[0m'

class Crawler:
    def __init__(self, base_url: str, max_pages: int = 50, timeout: int = 10):
        self.base_url = base_url
        self.max_pages = max_pages
        self.timeout = timeout
        self.visited = set()
        self.queue = deque()
        self.results = {
            'urls': [],
            'forms': [],
            'params': [],
            'emails': [],
            'phones': [],
            'social_media': []
        }
        
    def normalize_url(self, url: str) -> str:
        """Normalize URL to avoid duplicates"""
        parsed = urlparse(url)
        # Remove fragments and trailing slash
        normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if normalized.endswith('/') and len(normalized) > len(self.base_url):
            normalized = normalized[:-1]
        return normalized
    
    def extract_data(self, url: str, content: str):
        """Extract forms, emails, phones, social media from page"""
        # Extract forms
        forms = re.findall(r'<form[^>]*>(.*?)</form>', content, re.DOTALL | re.IGNORECASE)
        for form in forms:
            method = re.search(r'method=["\']([^"\']+)["\']', form, re.IGNORECASE)
            action = re.search(r'action=["\']([^"\']+)["\']', form, re.IGNORECASE)
            inputs = re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', form, re.IGNORECASE)
            
            self.results['forms'].append({
                'url': url,
                'method': method.group(1) if method else 'GET',
                'action': action.group(1) if action else '/',
                'inputs': inputs
            })
        
        # Extract emails
        emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', content)
        for email in emails:
            if email not in self.results['emails']:
                self.results['emails'].append(email)
        
        # Extract phones
        phones = re.findall(r'[\+]?[0-9]{1,3}[-.\s]?[\(]?[0-9]{1,4}[\)]?[-.\s]?[0-9]{1,4}[-.\s]?[0-9]{1,9}', content)
        for phone in phones:
            clean = re.sub(r'[^\d+]', '', phone)
            if len(clean) >= 10 and clean not in self.results['phones']:
                self.results['phones'].append(clean)
        
        # Extract social media
        social_patterns = {
            'twitter': r'twitter\.com/([a-zA-Z0-9_]+)',
            'github': r'github\.com/([a-zA-Z0-9_-]+)',
            'linkedin': r'linkedin\.com/in/([a-zA-Z0-9_-]+)',
            'facebook': r'facebook\.com/([a-zA-Z0-9_.]+)',
            'instagram': r'instagram\.com/([a-zA-Z0-9_.]+)'
        }
        
        for platform, pattern in social_patterns.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                self.results['social_media'].append({
                    'platform': platform,
                    'handle': match
                })
    
    def crawl(self, verbose: bool = False):
        """Start crawling"""
        print(f"\n{CYAN}[*] Starting crawl of: {self.base_url}{RESET}")
        self.queue.append(self.base_url)
        
        while self.queue and len(self.visited) < self.max_pages:
            url = self.queue.popleft()
            normalized = self.normalize_url(url)
            
            if normalized in self.visited:
                continue
            
            self.visited.add(normalized)
            
            try:
                if verbose:
                    print(f"{CYAN}[*] Crawling: {normalized}{RESET}")
                
                r = requests.get(normalized, timeout=self.timeout, verify=False, allow_redirects=True)
                content = r.text
                
                # Extract data from page
                self.extract_data(normalized, content)
                
                # Parse for new URLs
                parsed_base = urlparse(self.base_url)
                
                # Find all links
                links = re.findall(r'href=["\']([^"\']+)["\']', content)
                for link in links:
                    if link.startswith('/') or link.startswith(parsed_base.netloc):
                        absolute = urljoin(self.base_url, link)
                        if urlparse(absolute).netloc == parsed_base.netloc:
                            if self.normalize_url(absolute) not in self.visited:
                                self.queue.append(absolute)
                
                # Find URL parameters
                if '?' in normalized:
                    query = urlparse(normalized).query
                    params = parse_qs(query)
                    for key in params.keys():
                        if key not in self.results['params']:
                            self.results['params'].append(key)
                
                # Also check forms for params
                for form in self.results['forms']:
                    if form['url'] == normalized:
                        for inp in form['inputs']:
                            if inp not in self.results['params']:
                                self.results['params'].append(inp)
                
            except Exception as e:
                if verbose:
                    print(f"{RED}[!] Error crawling {url}: {e}{RESET}")
            
            time.sleep(0.5)  # Be polite
        
        return self.results

def run(domain: str, max_pages: int = 50, verbose: bool = False):
    """Run crawler"""
    print(f"\n{'='*60}")
    print(f"  WEB CRAWLER")
    print(f"{'='*60}")
    
    base_url = domain if '://' in domain else f'https://{domain}'
    crawler = Crawler(base_url, max_pages=max_pages)
    results = crawler.crawl(verbose)
    
    print(f"\n{GREEN}[+] Crawl Summary:{RESET}")
    print(f"  Pages visited: {len(crawler.visited)}")
    print(f"  URLs found: {len(results['urls'])}")
    print(f"  Forms found: {len(results['forms'])}")
    print(f"  Parameters: {len(results['params'])}")
    print(f"  Emails: {len(results['emails'])}")
    print(f"  Social media: {len(results['social_media'])}")
    
    return results
