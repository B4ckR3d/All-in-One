"""
CMS Detector - Detect WordPress, Laravel, Drupal, etc.
"""
import requests
import re
from urllib.parse import urlparse

GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
RESET = '\033[0m'

CMS_SIGNATURES = {
    'WordPress': {
        'paths': ['/wp-login.php', '/wp-admin/', '/wp-content/', '/wp-includes/'],
        'patterns': ['wp-content', 'wp-includes', 'wordpress', 'generator" content="WordPress'],
        'meta': ['WordPress']
    },
    'Joomla': {
        'paths': ['/administrator/', '/components/', '/modules/'],
        'patterns': ['joomla', 'Joomla', '/media/jui/'],
        'meta': ['Joomla']
    },
    'Drupal': {
        'paths': ['/user/login', '/node/', '/sites/default/'],
        'patterns': ['drupal', 'Drupal', 'sites/default'],
        'meta': ['Drupal']
    },
    'Laravel': {
        'paths': ['/.env', '/storage/', '/vendor/'],
        'patterns': ['laravel_session', 'XSRF-TOKEN', 'laravel'],
        'meta': ['Laravel']
    },
    'React': {
        'paths': ['/static/js/', '/static/css/', '/_next/'],
        'patterns': ['react', 'React', '_next/static', '__NEXT_DATA__'],
        'meta': ['React']
    },
    'Vue': {
        'paths': ['/js/chunk-vendors.', '/css/chunk-'],
        'patterns': ['vue', 'Vue', '__nuxt', 'nuxt.config'],
        'meta': ['Vue.js']
    },
    'Next.js': {
        'paths': ['/_next/', '/next/'],
        'patterns': ['__NEXT_DATA__', '_next/static', 'next'],
        'meta': ['Next.js']
    },
    'Django': {
        'paths': ['/admin/', '/static/', '/media/'],
        'patterns': ['csrftoken', 'django', 'csrfmiddlewaretoken'],
        'meta': ['Django']
    },
    'Flask': {
        'paths': ['/static/', '/templates/'],
        'patterns': ['flask', 'Flask'],
        'meta': ['Flask']
    },
    'Express': {
        'paths': ['/node_modules/', '/package.json'],
        'patterns': ['express', 'Express'],
        'meta': ['Express']
    },
    'Angular': {
        'paths': ['/main-es2015.', '/polyfills-es2019.'],
        'patterns': ['ng-app', 'angular', '@angular'],
        'meta': ['Angular']
    },
    'CodeIgniter': {
        'paths': ['/system/', '/application/'],
        'patterns': ['codeigniter', 'CodeIgniter'],
        'meta': ['CodeIgniter']
    },
    'Magento': {
        'paths': ['/skin/frontend/', '/media/catalog/', '/downloader/'],
        'patterns': ['mage-', 'magento', 'Magento'],
        'meta': ['Magento']
    },
    'Shopify': {
        'paths': ['/cdn.shopify.com/', '/assets/'],
        'patterns': ['shopify', 'cdn.shopify.com'],
        'meta': ['Shopify']
    },
    'Wix': {
        'paths': ['/static/', '/_cache/'],
        'patterns': ['wix', 'wix.com', 'Wix'],
        'meta': ['Wix']
    },
    'Ghost': {
        'paths': ['/ghost/', '/content/'],
        'patterns': ['ghost', 'Ghost'],
        'meta': ['Ghost']
    },
    'Hexo': {
        'paths': ['/themes/', '/_posts/'],
        'patterns': ['hexo', 'Hexo'],
        'meta': ['Hexo']
    },
    'Hugo': {
        'paths': ['/css/', '/js/'],
        'patterns': ['hugo', 'Hugo'],
        'meta': ['Hugo']
    }
}

def detect_cms(domain: str, verbose: bool = False):
    """Detect CMS from domain"""
    print(f"\n{CYAN}[*] Detecting CMS for: {domain}{RESET}")
    
    base_url = domain if '://' in domain else f'https://{domain}'
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    
    results = {
        'detected': [],
        'version': None,
        'plugins': [],
        'themes': []
    }
    
    try:
        # Fetch main page
        r = requests.get(base, timeout=10, verify=False)
        content = r.text
        headers = str(r.headers).lower()
        
        print(f"{CYAN}[*] Analyzing page content...{RESET}")
        
        # Check each CMS
        for cms_name, cms_data in CMS_SIGNATURES.items():
            score = 0
            matches = []
            
            # Check meta generator tag
            generator = re.search(r'<meta[^>]+generator[^>]+content=["\']([^"\']+)["\']', content, re.IGNORECASE)
            if generator:
                gen_content = generator.group(1).lower()
                for meta in cms_data.get('meta', []):
                    if meta.lower() in gen_content:
                        score += 3
                        matches.append(f"Meta: {meta}")
            
            # Check paths in HTML
            for path in cms_data.get('paths', []):
                if path in content or path in headers:
                    score += 1
                    matches.append(f"Path: {path}")
            
            # Check patterns
            for pattern in cms_data.get('patterns', []):
                if pattern.lower() in content.lower() or pattern in headers:
                    score += 1
                    matches.append(f"Pattern: {pattern}")
            
            if score > 0:
                results['detected'].append({
                    'cms': cms_name,
                    'score': score,
                    'matches': matches
                })
                print(f"{GREEN}[+] {cms_name} detected (score: {score}){RESET}")
        
        # Sort by score
        results['detected'].sort(key=lambda x: x['score'], reverse=True)
        
        if results['detected']:
            top_cms = results['detected'][0]['cms']
            print(f"\n{GREEN}[+] Primary CMS: {top_cms}{RESET}")
            
            # Try to detect version
            version = detect_version(content, top_cms)
            if version:
                results['version'] = version
                print(f"{GREEN}[+] Version: {version}{RESET}")
        
    except Exception as e:
        print(f"{RED}[!] Error: {e}{RESET}")
    
    return results

def detect_version(content: str, cms: str):
    """Try to detect CMS version"""
    versions = []
    
    if cms == 'WordPress':
        # Look for WordPress version in meta
        match = re.search(r'version=[\'"]([0-9.]+)[\'"]', content)
        generator = re.search(r'generator" content="WordPress ([0-9.]+)', content, re.IGNORECASE)
        if generator:
            versions.append(generator.group(1))
    
    elif cms == 'Joomla':
        match = re.search(r'meta name="generator" content="Joomla! ([0-9.]+)', content, re.IGNORECASE)
        if match:
            versions.append(match.group(1))
    
    elif cms == 'Drupal':
        match = re.search(r'Drupal ([0-9.]+)', content, re.IGNORECASE)
        if match:
            versions.append(match.group(1))
    
    return versions[0] if versions else None

def detect_plugins(domain: str, cms: str, verbose: bool = False):
    """Detect CMS plugins/themes (WordPress focus)"""
    print(f"\n{CYAN}[*] Detecting {cms} plugins...{RESET}")
    
    plugins = []
    
    if cms == 'WordPress':
        # Check common plugin paths
        common_plugins = [
            'akismet', 'jetpack', 'woocommerce', 'elementor',
            'contact-form-7', 'wpforms', 'yoast-seo', 'all-in-one-seo',
            'wordfence', 'sucuri', 'updraftplus', 'backup-wordpress'
        ]
        
        for plugin in common_plugins:
            try:
                url = f"{domain}/wp-content/plugins/{plugin}/readme.txt"
                r = requests.get(url, timeout=5)
                if r.status_code == 200:
                    version = re.search(r'^Stable tag: (.+)$', r.text, re.MULTILINE)
                    if version:
                        plugins.append(f"{plugin} ({version.group(1)})")
                        print(f"  {GREEN}+ {plugin}: {version.group(1)}{RESET}")
            except:
                pass
    
    return plugins

def run(domain: str, verbose: bool = False):
    """Run CMS detection"""
    print(f"\n{'='*60}")
    print(f"  CMS / TECHNOLOGY DETECTION")
    print(f"{'='*60}")
    
    results = detect_cms(domain, verbose)
    
    if results['detected']:
        top_cms = results['detected'][0]['cms']
        plugins = detect_plugins(domain, top_cms, verbose)
        results['plugins'] = plugins
    
    return results
