#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                     ALL-IN-ONE SECURITY TOOLKIT                          ║
║                    Recon • Scanner • Exploiter                           ║
║                                                                            ║
║  Supported Modules:                                                        ║
║    RECON    → Subdomains, DNS, WHOIS, Port Scan, CORS, SSL, Tech Detect  ║
║    SCANNER  → XSS, SQLi, SSRF, Open Redirect, Directory Busting          ║
║    CVE      → CVE Search by Year/ID/Keyword                              ║
║    LOOKUP   → WHOIS, IP Lookup, Reverse DNS, CDN Lookup                   ║
║    UTILS    → Hash Cracker, Base64 Encode/Decode, URL Encode/Decode      ║
║                                                                            ║
║  Usage:                                                                    ║
║    python3 run.py --recon --target example.com                           ║
║    python3 run.py --scan-xss --target "https://example.com/?q=test"     ║
║    python3 run.py --cve --year 2024 --keyword "xss"                       ║
║    python3 run.py --whois --target example.com                            ║
║                                                                            ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import argparse
import asyncio
import concurrent.futures
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import urllib.error
import threading
import hashlib
import base64
import xml.etree.ElementTree as ET
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional, List, Dict, Any

# ═══════════════════════════════════════════════════════════════════
# ANSI COLORS
# ═══════════════════════════════════════════════════════════════════
RED     = '\033[91m'
GREEN   = '\033[92m'
YELLOW  = '\033[93m'
BLUE    = '\033[94m'
MAGENTA = '\033[95m'
CYAN    = '\033[96m'
WHITE   = '\033[97m'
BOLD    = '\033[1m'
DIM     = '\033[2m'
RESET   = '\033[0m'

# ═══════════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════════
VERSION = "2.0.0"
BANNER = f"""
{CYAN}{BOLD}
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   ██████╗ ██╗   ██╗ ██████╗     ████████╗███████╗███╗   ███╗██████╗ ██╗     ║
║   ██╔══██╗██║   ██║██╔════╝     ╚══██╔══╝██╔════╝████╗ ████║██╔══██╗██║     ║
║   ██████╔╝██║   ██║██║  ███╗       ██║   █████╗  ██╔████╔██║██████╔╝██║     ║
║   ██╔═══╝ ██║   ██║██║   ██║       ██║   ██╔══╝  ██║╚██╔╝██║██╔═══╝ ██║     ║
║   ██║     ╚██████╔╝╚██████╔╝       ██║   ███████╗██║ ╚═╝ ██║██║     ███████╗║
║   ╚═╝      ╚═════╝  ╚═════╝        ╚═╝   ╚══════╝╚═╝     ╚═╝╚═╝     ╚══════╝║
║                                                                              ║
║   {RESET}{MAGENTA}SECURITY TOOLKIT v{VERSION} - All-in-One Recon & Scanner{RESET}{CYAN}{BOLD}                           ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
{RESET}
"""

# ═══════════════════════════════════════════════════════════════════
# DATACLASSES
# ═══════════════════════════════════════════════════════════════════
@dataclass
class Target:
    domain: str
    ip: Optional[str] = None
    subdomains: Dict[str, str] = field(default_factory=dict)
    ports: Dict[int, str] = field(default_factory=dict)
    endpoints: Dict[str, Any] = field(default_factory=dict)
    cors: Dict[str, Any] = field(default_factory=dict)
    dns_records: Dict[str, List[str]] = field(default_factory=dict)
    ssl_info: Dict[str, Any] = field(default_factory=dict)
    tech: List[str] = field(default_factory=list)
    cf_access: Dict[str, Any] = field(default_factory=dict)
    whois: Dict[str, Any] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    screenshots: List[str] = field(default_factory=list)
    cves: List[Dict] = field(default_factory=list)
    vulns: List[Dict] = field(default_factory=list)

@dataclass
class ScanResult:
    module: str
    status: str
    findings: Dict[str, Any]
    timestamp: str
    duration: float
    errors: List[str] = field(default_factory=list)

# ═══════════════════════════════════════════════════════════════════
# LOGGING
# ═══════════════════════════════════════════════════════════════════
class Logger:
    def __init__(self, verbose=False, quiet=False, json_output=False):
        self.verbose = verbose
        self.quiet = quiet
        self.json_output = json_output
        self.lock = threading.Lock()
        self.results = []
    
    def _print(self, color, symbol, msg, **kwargs):
        if self.quiet:
            return
        timestamp = datetime.now().strftime("%H:%M:%S")
        with self.lock:
            if self.json_output:
                self.results.append({"time": timestamp, "level": symbol, "msg": msg, **kwargs})
            else:
                print(f"{DIM}[{timestamp}]{RESET} {color}{symbol}{RESET} {msg}")
                for k, v in kwargs.items():
                    print(f"       {color}{k}:{RESET} {v}")
    
    def info(self, msg, **kw): self._print(BLUE, "ℹ", msg, **kw)
    def ok(self, msg, **kw): self._print(GREEN, "✓", msg, **kw)
    def warn(self, msg, **kw): self._print(YELLOW, "⚠", msg, **kw)
    def fail(self, msg, **kw): self._print(RED, "✗", msg, **kw)
    def found(self, msg, **kw): self._print(CYAN, "◆", msg, **kw)
    def vuln(self, msg, **kw): self._print(MAGENTA, "⚡", msg, **kw)
    def section(self, title):
        if self.json_output:
            return
        sep = "═" * 70
        print(f"\n{BOLD}{CYAN}{sep}{RESET}")
        print(f"{BOLD}{CYAN}  {title}{RESET}")
        print(f"{BOLD}{CYAN}{sep}{RESET}\n")
    
    def verbose(self, msg):
        if self.verbose and not self.json_output:
            print(f"{DIM}    {msg}{RESET}")
    
    def raw(self, msg):
        if not self.json_output:
            print(msg)
    
    def get_results(self):
        return self.results

# ═══════════════════════════════════════════════════════════════════
# HTTP UTILS
# ═══════════════════════════════════════════════════════════════════
def http_get(url, headers=None, timeout=10, allow_redirects=True):
    return _http_request("GET", url, headers=headers, timeout=timeout, allow_redirects=allow_redirects)

def http_post(url, data=None, headers=None, timeout=10):
    return _http_request("POST", url, data=data, headers=headers, timeout=timeout)

def http_request(method, url, headers=None, data=None, timeout=10, allow_redirects=True):
    return _http_request(method, url, headers=headers, data=data, timeout=timeout, allow_redirects=allow_redirects)

def _http_request(method, url, headers=None, data=None, timeout=10, allow_redirects=False):
    default_headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Connection': 'close',
    }
    if headers:
        default_headers.update(headers)
    
    try:
        body = None
        if data:
            if isinstance(data, dict):
                body = urllib.parse.urlencode(data).encode()
            else:
                body = data.encode() if isinstance(data, str) else data
        
        req = urllib.request.Request(url, data=body, headers=default_headers, method=method)
        
        if not allow_redirects:
            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, headers, newurl):
                    return None
            opener = urllib.request.build_opener(NoRedirect)
            response = opener.open(req, timeout=timeout)
        else:
            response = urllib.request.urlopen(req, timeout=timeout)
        
        raw = response.read()
        content_type = response.headers.get('Content-Type', '')
        
        if 'json' in content_type:
            text = raw.decode('utf-8', errors='ignore')
            try:
                body = json.loads(text)
            except:
                body = text
        elif 'xml' in content_type:
            body = raw
        else:
            body = raw.decode('utf-8', errors='ignore')
        
        return {
            'status': response.getcode(),
            'headers': dict(response.headers),
            'body': body,
            'url': response.geturl(),
            'error': None
        }
    except urllib.error.HTTPError as e:
        raw = e.read()
        return {
            'status': e.code,
            'headers': dict(e.headers),
            'body': raw.decode('utf-8', errors='ignore')[:2000] if raw else '',
            'url': url,
            'error': None
        }
    except urllib.error.URLError as e:
        return {'status': 0, 'headers': {}, 'body': '', 'url': url, 'error': str(e.reason)}
    except Exception as e:
        return {'status': 0, 'headers': {}, 'body': '', 'url': url, 'error': str(e)}

# ═══════════════════════════════════════════════════════════════════
# COMMON WORDLISTS
# ═══════════════════════════════════════════════════════════════════
SUBDOMAIN_WORDLIST = [
    'api', 'app', 'www', 'admin', 'staging', 'dev', 'test', 'beta', 'demo', 'uat',
    'web', 'www2', 'cdn', 'static', 'assets', 'media', 'files', 'upload', 'img',
    'docs', 'help', 'support', 'forum', 'blog', 'shop', 'store', 'pay', 'payment',
    'checkout', 'order', 'cart', 'v1', 'v2', 'v3', 'v4', 'old', 'new', 'legacy',
    'archive', 'internal', 'private', 'secure', 'auth', 'login', 'register',
    'account', 'profile', 'user', 'users', 'dashboard', 'panel', 'cp', 'wallet',
    'swap', 'trade', 'exchange', 'market', 'markets', 'liquidity', 'pool', 'pools',
    'staking', 'farm', 'yield', 'bridge', 'nft', 'marketplace', 'defi', 'crypto',
    'chain', 'blockchain', 'solana', 'ethereum', 'bitcoin', 'rpc', 'node', 'validator',
    'tx', 'transaction', 'transactions', 'history', 'tx-history', 'gateway', 'worker',
    'ws', 'websocket', 'socket', 'io', 'realtime', 'live', 'stream', 'feed', 'ticker',
    'price', 'chart', 'charts', 'orderbook', 'book', 'trades', 'depth', 'kline',
    'index', 'search', 'query', 'analytics', 'stats', 'monitor', 'infra', 'ops',
    'db', 'database', 'mysql', 'redis', 'postgres', 'mongo', 'elastic', 'kafka',
    'mail', 'email', 'smtp', 'pop', 'imap', 'mx', 'dns', 'ns1', 'ns2', 'ftp',
    'sftp', 'ssh', 'vpn', 'git', 'gitlab', 'github', 'jenkins', 'ci', 'cd', 'deploy',
    'prod', 'qa', 'pre', 'post', 'backup', 'bak', 'fra', 'eu', 'us', 'us1', 'us2',
    'apac', 'asia', 'tokyo', 'singapore', 'syd', 'london', 'frankfurt', 'amsterdam',
    'nyc', 'la', 'scanner', '漏', 'search', 'lookup', 'console', 'terminal'
]

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 8888, 10000]

EXTENDED_PORTS = list(range(1, 1001)) + [1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 9200, 27017, 11211]

DIR_WORDLIST = [
    'admin', 'api', 'backup', 'backups', 'beta', 'blog', 'cgi-bin', 'config',
    'dashboard', 'database', 'db', 'debug', 'demo', 'dev', 'developer', 'developers',
    'docs', 'documentation', 'export', 'files', 'forum', 'git', 'github', 'help',
    'images', 'import', 'includes', 'index', 'index.php', 'internal', 'js', 'lib',
    'library', 'login', 'logs', 'media', 'monitor', 'old', 'panel', 'phpinfo',
    'private', 'public', 'robots.txt', 'scripts', 'search', 'secure', 'security',
    'server', 'sitemap.xml', 'sql', 'src', 'ssl', 'static', 'status', 'swagger',
    'test', 'tmp', 'tools', 'uploads', 'usage', 'var', 'v1', 'v2', 'version', 'web',
    'webdav', 'wp-admin', 'wp-content', 'wp-includes', 'xmlrpc.php', '.env',
    '.git', '.git/config', '.git/HEAD', '.htaccess', '.htpasswd', '.well-known',
    'api/v1', 'api/v2', 'api/v3', 'health', 'healthz', 'ping', 'ready', 'metrics',
    'monitoring', 'grafana', 'prometheus', 'kibana', 'jenkins', 'swagger', 'docs'
]

# ═══════════════════════════════════════════════════════════════════
# XSS PAYLOADS
# ═══════════════════════════════════════════════════════════════════
XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<script>alert(String.fromCharCode(49))</script>',
    '<img src="x" onerror="alert(1)">',
    '<svg><script>alert(1)</script></svg>',
    '<iframe src="javascript:alert(1)">',
    '<object data="javascript:alert(1)">',
    '<embed src="javascript:alert(1)">',
    '<body onload=alert(1)>',
    '<select onfocus=alert(1) autofocus>',
    '<textarea onfocus=alert(1) autofocus>',
    '<keygen onfocus=alert(1) autofocus>',
    '<video><source onerror="alert(1)">',
    '<audio src=x onerror=alert(1)>',
    '<marquee onstart=alert(1)>',
    'javascript:alert(1)',
    '<script>alert(document.domain)</script>',
    '<script>alert(document.cookie)</script>',
]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' #",
    "' OR '1'='1'/*",
    "admin' --",
    "admin' #",
    "admin'/*",
    "' or 1=1--",
    "' or 1=1#",
    "' or 1=1/*",
    "') or '1'='1--",
    "') or ('1'='1--",
    '" OR "1"="1',
    '" OR "1"="1"--',
    '" OR "1"="1"#',
    '" OR "1"="1"/*',
    '1" OR "1"="1"',
    '1\' OR \'1\'=\'1',
    '1" OR "1"="1"',
    '1 AND 1=1',
    '1 AND 1=2',
    '1 OR 1=1',
    "1' AND '1'='1",
    "1' AND '1'='2",
    "1' OR '1'='1",
]

# ═══════════════════════════════════════════════════════════════════
# TECHNOLOGY DETECTION
# ═══════════════════════════════════════════════════════════════════
TECH_PATTERNS = {
    'Apache': [r'Apache/[\d.]+', r'server: apache'],
    'Nginx': [r'nginx/[\d.]+', r'server: nginx'],
    'Cloudflare': [r'cf-ray', r'__cfduid', r'cloudflare'],
    'WordPress': [r'wp-content', r'wp-includes', r'wordpress'],
    'Laravel': [r'laravel_session', r'laravel_session'],
    'Next.js': [r'__next', r'Next.js', r'_next/static'],
    'React': [r'react', r'react-dom'],
    'Vue.js': [r'vue\.js', r'vuejs'],
    'Angular': [r'ng-app', r'angular'],
    'Django': [r'django\.css', r'csrftoken'],
    'Express': [r'express', r'express-session'],
    'Flask': [r'flask', r'werkzeug'],
    'Spring': [r'spring', r'pivotal'],
    'jQuery': [r'jquery', r'jQuery'],
    'Bootstrap': [r'bootstrap', r'bootstrapcdn'],
    'Tailwind': [r'tailwind', r'tailwindcss'],
    'PHP': [r'X-Powered-By: PHP', r'\.php'],
    'Node.js': [r'x-powered-by: express', r'node'],
    'Python': [r'python', r'wsgi'],
    'Ruby': [r'ruby', r'passenger'],
    'Java': [r'java', r'tomcat', r'jboss'],
    '.NET': [r'asp\.net', r'__viewstate', r'\.aspx'],
    'AWS': [r'amazon', r'aws', r'aws-sdk'],
    'Google Cloud': [r'google', r'gcloud', r'googleapis'],
    'Azure': [r'azure', r'microsoft', r'azurewebsites'],
    'Stripe': [r'stripe', r'stripe\.com'],
    'Cloudflare Access': [r'cloudflare-access', r'CF_AppSession'],
    'Vercel': [r'vercel', r'vercel\.app'],
    'Firebase': [r'firebase', r'firebaseapp'],
    'Supabase': [r'supabase', r'supabase\.io'],
    'Auth0': [r'auth0', r'auth0\.com'],
    'Okta': [r'okta', r'okta\.com'],
    'JWT': [r'eyJ', r'jwt', r'bearer'],
    'GraphQL': [r'graphql', r'__schema'],
    'Swagger': [r'swagger', r'api-docs'],
    'OpenAPI': [r'openapi', r'swagger-ui'],
}

# ═══════════════════════════════════════════════════════════════════
# CVE DATABASE (NVD API)
# ═══════════════════════════════════════════════════════════════════
def search_cve(query=None, year=None, cve_id=None, limit=50):
    """
    Search CVEs from NVD API
    """
    results = []
    
    if cve_id:
        # Search by specific CVE ID
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        data = _fetch_json(url)
        if data and 'vulnerabilities' in data:
            results.extend(data['vulnerabilities'])
    
    elif year and query:
        # Search by year + keyword
        start = f"{year}-01-01T00:00:00.000"
        end = f"{year}-12-31T23:59:59.999"
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0/?pubStartDate={start}&pubEndDate={end}&keywordSearch={query}&resultsPerPage={limit}"
        data = _fetch_json(url)
        if data and 'vulnerabilities' in data:
            results.extend(data['vulnerabilities'])
    
    elif year:
        # All CVEs from year
        start = f"{year}-01-01T00:00:00.000"
        end = f"{year}-12-31T23:59:59.999"
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0/?pubStartDate={start}&pubEndDate={end}&resultsPerPage={limit}"
        data = _fetch_json(url)
        if data and 'vulnerabilities' in data:
            results.extend(data['vulnerabilities'])
    
    elif query:
        # Search by keyword only
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0/?keywordSearch={query}&resultsPerPage={limit}"
        data = _fetch_json(url)
        if data and 'vulnerabilities' in data:
            results.extend(data['vulnerabilities'])
    
    else:
        # Recent CVEs
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage={limit}"
        data = _fetch_json(url)
        if data and 'vulnerabilities' in data:
            results.extend(data['vulnerabilities'])
    
    formatted = []
    for item in results[:limit]:
        cve = item.get('cve', {})
        cve_id = cve.get('id', '')
        desc = cve.get('descriptions', [{}])
        en_desc = next((d['value'] for d in desc if d.get('lang') == 'en'), '')
        
        metrics = cve.get('metrics', {})
        cvss = metrics.get('cvssMetricV31', metrics.get('cvssMetricV30', metrics.get('cvssMetricV2', [])))
        score = 'N/A'
        severity = 'UNKNOWN'
        if cvss:
            cvss_data = cvss[0].get('cvssData', {})
            score = cvss_data.get('baseScore', 'N/A')
            severity = cvss_data.get('baseSeverity', 'N/A')
        
        formatted.append({
            'id': cve_id,
            'description': en_desc[:300],
            'score': score,
            'severity': severity,
            'published': cve.get('published', ''),
            'last_modified': cve.get('lastModified', ''),
            'references': [r['url'] for r in cve.get('references', [])[:3]],
        })
    
    return formatted

def _fetch_json(url, timeout=15):
    """Fetch JSON from URL"""
    try:
        req = urllib.request.Request(url, headers={
            'User-Agent': 'Mozilla/5.0 SecurityToolkit/2.0',
            'Accept': 'application/json'
        })
        response = urllib.request.urlopen(req, timeout=timeout)
        return json.loads(response.read())
    except Exception as e:
        return None

# ═══════════════════════════════════════════════════════════════════
# RECON MODULE
# ═══════════════════════════════════════════════════════════════════
class Recon:
    def __init__(self, target, logger):
        self.target = target
        self.logger = logger
        self.results = Target(target)
    
    def run_all(self, args):
        self.logger.section(f"RECON: {self.target}")
        
        if args.subdomains or args.recon_all:
            self._enum_subdomains()
        if args.dns or args.recon_all:
            self._dns_enum()
        if args.ports or args.recon_all:
            self._port_scan(args.port_range or 'common')
        if args.probe or args.recon_all:
            self._http_probe()
        if args.cors or args.recon_all:
            self._cors_check()
        if args.ssl or args.recon_all:
            self._ssl_info()
        if args.whois_lookup or args.recon_all:
            self._whois()
        if args.headers or args.recon_all:
            self._headers_check()
        if args.tech or args.recon_all:
            self._tech_detect()
        if args.dirbust or args.recon_all:
            self._dir_busting()
        
        return self.results
    
    def _resolve_ip(self):
        try:
            ip = socket.gethostbyname(self.target)
            self.results.ip = ip
            self.logger.ok(f"Resolved {self.target} -> {ip}")
            return ip
        except Exception as e:
            self.logger.fail(f"DNS resolution failed: {e}")
            return None
    
    def _enum_subdomains(self):
        self.logger.info(f"Enumerating subdomains for {self.target}")
        found = {}
        
        def check(sub):
            try:
                host = f"{sub}.{self.target}"
                ip = socket.gethostbyname(host)
                return (host, ip)
            except:
                return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
            futures = [ex.submit(check, s) for s in SUBDOMAIN_WORDLIST]
            for f in concurrent.futures.as_completed(futures):
                r = f.result()
                if r:
                    host, ip = r
                    found[host] = ip
                    self.logger.found(f"{host} -> {ip}")
        
        self.results.subdomains = found
        self.logger.ok(f"Found {len(found)} subdomains")
    
    def _dns_enum(self):
        self.logger.info("Enumerating DNS records")
        record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA']
        resolver = '8.8.8.8'
        
        for rtype in record_types:
            try:
                cmd = ['dig', '+short', f'@{resolver}', self.target, rtype]
                out = subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout.strip()
                if out:
                    self.results.dns_records[rtype] = out.split('\n')
                    self.logger.found(f"{rtype}: {out[:80]}")
            except:
                pass
    
    def _port_scan(self, range_type='common'):
        ip = self.results.ip or self._resolve_ip()
        if not ip:
            self.logger.fail("No IP, skipping port scan")
            return
        
        ports = COMMON_PORTS if range_type == 'common' else EXTENDED_PORTS
        self.logger.info(f"Scanning {len(ports)} ports on {ip}")
        
        def scan(p):
            try:
                s = socket.socket()
                s.settimeout(2)
                if s.connect_ex((ip, p)) == 0:
                    s.close()
                    return p
            except:
                pass
            return None
        
        open_ports = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=200) as ex:
            futures = [ex.submit(scan, p) for p in ports]
            for f in concurrent.futures.as_completed(futures):
                p = f.result()
                if p:
                    open_ports[p] = 'open'
                    self.logger.found(f"Port {p} OPEN")
        
        self.results.ports = open_ports
        self.logger.ok(f"Found {len(open_ports)} open ports")
    
    def _http_probe(self):
        self.logger.info("Probing HTTP endpoints")
        targets = [f"https://{self.target}"]
        targets.extend([f"https://{s}" for s in self.results.subdomains.keys()])
        
        paths = ['', '/', '/api', '/api/v1', '/api/v2', '/health', '/api/health',
                 '/admin', '/login', '/dashboard', '/v2', '/v3']
        
        for base in targets[:15]:
            base = base.rstrip('/')
            for path in paths:
                url = base + path
                resp = http_get(url, allow_redirects=False)
                if resp['status'] in [200, 301, 302, 401, 403]:
                    self.logger.found(f"{url} [{resp['status']}]")
                    self.results.endpoints[url] = {
                        'status': resp['status'],
                        'headers': dict(resp['headers']),
                        'redirect': resp['headers'].get('Location')
                    }
    
    def _cors_check(self):
        self.logger.info("Checking CORS configuration")
        targets = list(self.results.endpoints.keys())[:10]
        if not targets:
            targets = [f"https://{self.target}"]
        
        for url in targets:
            resp = http_get(url, headers={'Origin': 'https://evil.com'}, allow_redirects=False)
            if resp['status'] > 0:
                acao = resp['headers'].get('Access-Control-Allow-Origin', '')
                if acao:
                    if acao == '*':
                        self.logger.vuln(f"CORS WIDE OPEN: {url}")
                        self.logger.vuln(f"  Allow-Origin: {acao}")
                        self.results.cors[url] = {'allow_origin': acao, 'risk': 'CRITICAL'}
                    elif acao == 'https://evil.com':
                        self.logger.warn(f"CORS REFLECTED: {url}")
                        self.results.cors[url] = {'allow_origin': acao, 'risk': 'HIGH'}
    
    def _ssl_info(self):
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((self.target, 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    cipher = ssock.cipher()
                    
                    self.results.ssl_info = {
                        'protocol': ssock.version(),
                        'cipher': cipher[0] if cipher else None,
                        'encrypted': True
                    }
                    self.logger.ok(f"SSL: {ssock.version()} / {cipher[0] if cipher else 'N/A'}")
        except Exception as e:
            self.logger.warn(f"SSL check failed: {e}")
    
    def _whois(self):
        try:
            out = subprocess.run(['whois', self.target], capture_output=True, text=True, timeout=10).stdout
            # Parse key fields
            whois_data = {}
            for line in out.split('\n')[:60]:
                if ':' in line:
                    k, v = line.split(':', 1)
                    k = k.strip().lower().replace(' ', '_')
                    v = v.strip()
                    if v and k:
                        whois_data[k] = v
            
            self.results.whois = whois_data
            self.logger.ok("WHOIS data collected")
            
            # Print summary
            for key in ['domain_name', 'registrar', 'creation_date', 'expiration_date', 'name_servers']:
                if key in whois_data:
                    self.logger.found(f"{key}: {whois_data[key][:80]}")
        except Exception as e:
            self.logger.fail(f"WHOIS failed: {e}")
    
    def _headers_check(self):
        resp = http_get(f"https://{self.target}")
        if resp['status'] > 0:
            self.results.headers = dict(resp['headers'])
            
            security_headers = {
                'X-Frame-Options': 'PROTECTED',
                'X-Content-Type-Options': 'PROTECTED',
                'X-XSS-Protection': 'PROTECTED',
                'Strict-Transport-Security': 'CRITICAL',
                'Content-Security-Policy': 'HIGH',
            }
            
            for header, severity in security_headers.items():
                if header in resp['headers']:
                    self.logger.ok(f"{header}: {resp['headers'][header][:50]}")
                else:
                    self.logger.warn(f"{header}: MISSING ({severity})")
    
    def _tech_detect(self):
        self.logger.info("Detecting technologies")
        resp = http_get(f"https://{self.target}")
        if resp['status'] > 0 and resp['body']:
            body = resp['body'] if isinstance(resp['body'], str) else str(resp['body'])
            headers = resp['headers']
            
            detected = []
            for tech, patterns in TECH_PATTERNS.items():
                for pat in patterns:
                    if re.search(pat, body, re.I) or re.search(pat, str(headers), re.I):
                        if tech not in detected:
                            detected.append(tech)
                            self.logger.found(f"Technology: {tech}")
            
            self.results.tech = detected
    
    def _dir_busting(self):
        self.logger.info("Directory busting")
        base = f"https://{self.target}"
        found_dirs = {}
        
        def check_dir(path):
            url = base.rstrip('/') + path
            resp = http_get(url, allow_redirects=False)
            if resp['status'] in [200, 301, 302, 403]:
                return (path, resp['status'])
            return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
            futures = [ex.submit(check_dir, d) for d in DIR_WORDLIST]
            for f in concurrent.futures.as_completed(futures):
                r = f.result()
                if r:
                    path, status = r
                    found_dirs[path] = status
                    self.logger.found(f"{path} [{status}]")
        
        self.logger.ok(f"Found {len(found_dirs)} directories/files")


# ═══════════════════════════════════════════════════════════════════
# SCANNER MODULE
# ═══════════════════════════════════════════════════════════════════
class Scanner:
    def __init__(self, target, logger):
        self.target = target
        self.logger = logger
    
    def scan_xss(self, params=None):
        """Scan for XSS vulnerabilities"""
        self.logger.section(f"XSS SCAN: {self.target}")
        
        if not params:
            # Auto-detect parameters
            params = self._find_params()
            if not params:
                self.logger.fail("No parameters found. Provide URL with params (?q=test)")
                return []
        
        results = []
        for param in params:
            for payload in XSS_PAYLOADS[:10]:  # Limit payloads
                test_url = self.target.replace(f"{param}=", f"{param}={urllib.parse.quote(payload)}")
                resp = http_get(test_url)
                
                if resp['status'] > 0 and payload in (resp['body'] if isinstance(resp['body'], str) else ''):
                    self.logger.vuln(f"XSS FOUND! Param: {param}")
                    self.logger.vuln(f"  Payload: {payload}")
                    self.logger.vuln(f"  URL: {test_url[:100]}")
                    results.append({
                        'type': 'XSS',
                        'param': param,
                        'payload': payload,
                        'url': test_url,
                        'status': resp['status']
                    })
                    break
        
        self.logger.ok(f"Scan complete. Found {len(results)} XSS")
        return results
    
    def scan_sqli(self):
        """Scan for SQL injection"""
        self.logger.section(f"SQLi SCAN: {self.target}")
        
        params = self._find_params()
        if not params:
            self.logger.fail("No parameters found")
            return []
        
        results = []
        for param in params:
            for payload in SQLI_PAYLOADS[:15]:
                test_url = self.target.replace(f"{param}=", f"{param}={urllib.parse.quote(payload)}")
                resp = http_get(test_url)
                
                body = resp['body'] if isinstance(resp['body'], str) else ''
                
                # Check for SQL error patterns
                sql_errors = ['sql', 'syntax', 'mysql', 'postgres', 'sqlite', 'oracle', 'microsoft sql',
                              'odbc', 'ora-', 'sqlstate', 'warning: mysql', 'postgresql', 'sqlite_error']
                
                if any(err in body.lower() for err in sql_errors):
                    self.logger.vuln(f"SQLi ERROR FOUND! Param: {param}")
                    self.logger.vuln(f"  Payload: {payload}")
                    results.append({
                        'type': 'SQLi',
                        'param': param,
                        'payload': payload,
                        'url': test_url,
                        'evidence': 'SQL Error detected'
                    })
                    break
                
                # Check for time-based (simple)
                if 'sleep' in payload.lower() and resp['status'] == 0:
                    self.logger.vuln(f"Possible Time-based SQLi: {param}")
                    results.append({
                        'type': 'SQLi-TimeBased',
                        'param': param,
                        'payload': payload,
                        'url': test_url
                    })
        
        self.logger.ok(f"Scan complete. Found {len(results)} potential SQLi")
        return results
    
    def scan_ssrf(self):
        """Scan for SSRF"""
        self.logger.section(f"SSRF SCAN: {self.target}")
        
        ssrf_payloads = [
            'http://localhost',
            'http://127.0.0.1',
            'http://169.254.169.254',
            'http://metadata.google.internal',
            'http://169.254.169.254/latest/meta-data/',
            'http://internal',
        ]
        
        params = self._find_params()
        results = []
        
        for param in params:
            for payload in ssrf_payloads:
                test_url = self.target.replace(f"{param}=", f"{param}={urllib.parse.quote(payload)}")
                resp = http_get(test_url)
                
                body = resp['body'] if isinstance(resp['body'], str) else ''
                
                if any(hint in body.lower() for hint in ['localhost', '127.0.0.1', 'amazon aws', 'meta-data', 'instance']):
                    self.logger.vuln(f"SSRF FOUND: {param} -> {payload}")
                    results.append({'type': 'SSRF', 'param': param, 'payload': payload})
        
        self.logger.ok(f"Found {len(results)} SSRF")
        return results
    
    def scan_open_redirect(self):
        """Scan for open redirect"""
        self.logger.section(f"OPEN REDIRECT SCAN: {self.target}")
        
        redirect_payloads = [
            'https://google.com',
            'https://evil.com',
            '//google.com',
            '///google.com',
            'javascript:alert(1)',
            '\/\/google.com',
        ]
        
        params = self._find_params()
        results = []
        
        for param in params:
            for payload in redirect_payloads:
                test_url = self.target.replace(f"{param}=", f"{param}={urllib.parse.quote(payload)}")
                resp = http_get(test_url, allow_redirects=False)
                
                location = resp['headers'].get('Location', '')
                if location and (payload in location or 'google' in location):
                    self.logger.vuln(f"OPEN REDIRECT: {param} -> {payload}")
                    results.append({'type': 'OpenRedirect', 'param': param, 'payload': payload, 'location': location})
        
        self.logger.ok(f"Found {len(results)} Open Redirects")
        return results
    
    def _find_params(self):
        """Extract URL parameters"""
        parsed = urllib.parse.urlparse(self.target)
        if parsed.query:
            params = urllib.parse.parse_qsl(parsed.query)
            return [p[0] for p in params]
        return []


# ═══════════════════════════════════════════════════════════════════
# LOOKUP MODULES
# ═══════════════════════════════════════════════════════════════════
class Lookup:
    def __init__(self, logger):
        self.logger = logger
    
    def whois(self, target):
        """WHOIS lookup"""
        self.logger.section(f"WHOIS: {target}")
        try:
            out = subprocess.run(['whois', target], capture_output=True, text=True, timeout=15).stdout
            self.logger.raw(out[:3000])
            return out
        except Exception as e:
            self.logger.fail(f"WHOIS failed: {e}")
            return None
    
    def ip_lookup(self, ip):
        """IP Geolocation lookup"""
        self.logger.section(f"IP LOOKUP: {ip}")
        
        # Use ip-api.com (free)
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
        
        try:
            data = _fetch_json(url)
            if data and data.get('status') == 'success':
                for k, v in data.items():
                    if v:
                        self.logger.ok(f"{k}: {v}")
                return data
            else:
                self.logger.fail(f"Lookup failed: {data.get('message', 'Unknown')}")
        except Exception as e:
            self.logger.fail(f"IP lookup failed: {e}")
        
        return None
    
    def reverse_dns(self, ip):
        """Reverse DNS lookup"""
        self.logger.section(f"REVERSE DNS: {ip}")
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            self.logger.ok(f"Hostname: {hostname}")
            return hostname
        except Exception as e:
            self.logger.fail(f"Reverse DNS failed: {e}")
            return None
    
    def cdn_lookup(self, target):
        """CDN/Proxy detection"""
        self.logger.section(f"CDN CHECK: {target}")
        
        resp = http_get(f"https://{target}", headers={'Host': target})
        
        checks = {
            'Cloudflare': ['cf-ray', '__cfduid', 'cf-cache-status'],
            'AWS CloudFront': ['x-amz-cf-id', 'x-amz-id-2'],
            'Azure': ['x-azure-ref', 'x-ec-custom-error'],
            'Google Cloud': ['x-goog-hash', 'x-guploader-upload'],
            'Fastly': ['x-served-by', 'x-cache'],
            'Akamai': ['x-akamai-transformed', 'akamai-origin-hop'],
            'CloudFront': ['via:', 'x-amz-cf-'],
        }
        
        found = []
        headers_str = str(resp['headers'])
        
        for cdn, markers in checks.items():
            if any(m.lower() in headers_str.lower() for m in markers):
                self.logger.ok(f"CDN: {cdn}")
                found.append(cdn)
        
        if not found:
            self.logger.warn("No common CDN detected")
        
        return found if found else None
    
    def whois_lookup(self, domain):
        """WHOIS via API (alternative to CLI)"""
        return self.whois(domain)


# ═══════════════════════════════════════════════════════════════════
# UTILS MODULE
# ═══════════════════════════════════════════════════════════════════
class Utils:
    def __init__(self, logger):
        self.logger = logger
    
    def encode_base64(self, text):
        return base64.b64encode(text.encode()).decode()
    
    def decode_base64(self, text):
        try:
            return base64.b64decode(text.encode()).decode()
        except:
            return "Invalid Base64"
    
    def url_encode(self, text):
        return urllib.parse.quote(text)
    
    def url_decode(self, text):
        return urllib.parse.unquote(text)
    
    def hash_md5(self, text):
        return hashlib.md5(text.encode()).hexdigest()
    
    def hash_sha1(self, text):
        return hashlib.sha1(text.encode()).hexdigest()
    
    def hash_sha256(self, text):
        return hashlib.sha256(text.encode()).hexdigest()
    
    def hex_encode(self, text):
        return text.encode().hex()
    
    def hex_decode(self, text):
        return bytes.fromhex(text).decode()


# ═══════════════════════════════════════════════════════════════════
# MAIN RUNNER
# ═══════════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(
        description='All-in-One Security Toolkit',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  {CYAN}# Recon{RESET}
  python3 run.py -t example.com --recon
  python3 run.py -t example.com --subdomains --dns --whois --cors
  python3 run.py -t example.com --deep

  {CYAN}# CVE Search{RESET}
  python3 run.py --cve --year 2024
  python3 run.py --cve --year 2023 --keyword xss
  python3 run.py --cve --cve-id CVE-2024-1234
  python3 run.py --cve --keyword "remote code execution"

  {CYAN}# Vulnerability Scanner{RESET}
  python3 run.py -t "https://example.com/?q=test" --scan-xss
  python3 run.py -t "https://example.com/?id=1" --scan-sqli
  python3 run.py -t "https://example.com/?url=test" --scan-ssrf
  python3 run.py -t "https://example.com/?redirect=test" --scan-redirect

  {CYAN}# Lookups{RESET}
  python3 run.py --whois -t example.com
  python3 run.py --ip-lookup -t 8.8.8.8
  python3 run.py --reverse-dns -t 8.8.8.8
  python3 run.py --cdn -t example.com

  {CYAN}# Utils{RESET}
  python3 run.py --encode-base64 "hello world"
  python3 run.py --decode-base64 "aGVsbG8gd29ybGQ="
  python3 run.py --hash-md5 "text"
  python3 run.py --hash-sha256 "text"
  python3 run.py --url-encode "hello world"
  python3 run.py --hex-encode "test"
        """
    )
    
    parser.add_argument('-t', '--target', help='Target URL or domain')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-q', '--quiet', action='store_true', help='Quiet mode')
    parser.add_argument('-o', '--output', help='Output file (JSON)')
    
    # Recon modules
    parser.add_argument('--recon', action='store_true', help='Run basic recon')
    parser.add_argument('--recon-all', action='store_true', help='Run full recon')
    parser.add_argument('--deep', action='store_true', help='Deep reconnaissance')
    parser.add_argument('--subdomains', action='store_true', help='Subdomain enumeration')
    parser.add_argument('--dns', action='store_true', help='DNS enumeration')
    parser.add_argument('--ports', action='store_true', help='Port scanning')
    parser.add_argument('--port-range', choices=['common', 'extended'], default='common')
    parser.add_argument('--probe', action='store_true', help='HTTP probe')
    parser.add_argument('--cors', action='store_true', help='CORS check')
    parser.add_argument('--ssl', action='store_true', help='SSL info')
    parser.add_argument('--whois-lookup', action='store_true', help='WHOIS lookup')
    parser.add_argument('--headers', action='store_true', help='Security headers check')
    parser.add_argument('--tech', action='store_true', help='Technology detection')
    parser.add_argument('--dirbust', action='store_true', help='Directory busting')
    
    # CVE Search
    parser.add_argument('--cve', action='store_true', help='CVE search mode')
    parser.add_argument('--cve-id', help='Specific CVE ID (e.g. CVE-2024-1234)')
    parser.add_argument('--year', type=int, help='CVE year (e.g. 2024)')
    parser.add_argument('--keyword', help='CVE keyword search')
    
    # Scanner modules
    parser.add_argument('--scan-xss', action='store_true', help='XSS scanner')
    parser.add_argument('--scan-sqli', action='store_true', help='SQLi scanner')
    parser.add_argument('--scan-ssrf', action='store_true', help='SSRF scanner')
    parser.add_argument('--scan-redirect', action='store_true', help='Open redirect scanner')
    parser.add_argument('--scan-all', action='store_true', help='Run all scanners')
    
    # Lookup modules
    parser.add_argument('--whois', action='store_true', help='WHOIS lookup')
    parser.add_argument('--ip-lookup', action='store_true', help='IP geolocation')
    parser.add_argument('--reverse-dns', action='store_true', help='Reverse DNS')
    parser.add_argument('--cdn', action='store_true', help='CDN detection')
    
    # Utils
    parser.add_argument('--encode-base64', help='Encode to Base64')
    parser.add_argument('--decode-base64', help='Decode from Base64')
    parser.add_argument('--url-encode', help='URL encode')
    parser.add_argument('--url-decode', help='URL decode')
    parser.add_argument('--hash-md5', help='MD5 hash')
    parser.add_argument('--hash-sha1', help='SHA1 hash')
    parser.add_argument('--hash-sha256', help='SHA256 hash')
    parser.add_argument('--hex-encode', help='Hex encode')
    parser.add_argument('--hex-decode', help='Hex decode')
    
    args = parser.parse_args()
    
    print(BANNER)
    
    logger = Logger(verbose=args.verbose, quiet=args.quiet)
    utils = Utils(logger)
    
    # Handle utils (no target needed)
    if args.encode_base64:
        result = utils.encode_base64(args.encode_base64)
        logger.section("BASE64 ENCODE")
        logger.ok(f"Input: {args.encode_base64}")
        logger.ok(f"Output: {result}")
        return
    
    if args.decode_base64:
        result = utils.decode_base64(args.decode_base64)
        logger.section("BASE64 DECODE")
        logger.ok(f"Input: {args.decode_base64}")
        logger.ok(f"Output: {result}")
        return
    
    if args.url_encode:
        result = utils.url_encode(args.url_encode)
        logger.section("URL ENCODE")
        logger.ok(f"Input: {args.url_encode}")
        logger.ok(f"Output: {result}")
        return
    
    if args.url_decode:
        result = utils.url_decode(args.url_decode)
        logger.section("URL DECODE")
        logger.ok(f"Input: {args.url_decode}")
        logger.ok(f"Output: {result}")
        return
    
    if args.hash_md5:
        result = utils.hash_md5(args.hash_md5)
        logger.section("MD5 HASH")
        logger.ok(f"Input: {args.hash_md5}")
        logger.ok(f"Hash: {result}")
        return
    
    if args.hash_sha1:
        result = utils.hash_sha1(args.hash_sha1)
        logger.section("SHA1 HASH")
        logger.ok(f"Input: {args.hash_sha1}")
        logger.ok(f"Hash: {result}")
        return
    
    if args.hash_sha256:
        result = utils.hash_sha256(args.hash_sha256)
        logger.section("SHA256 HASH")
        logger.ok(f"Input: {args.hash_sha256}")
        logger.ok(f"Hash: {result}")
        return
    
    if args.hex_encode:
        result = utils.hex_encode(args.hex_encode)
        logger.section("HEX ENCODE")
        logger.ok(f"Input: {args.hex_encode}")
        logger.ok(f"Output: {result}")
        return
    
    if args.hex_decode:
        result = utils.hex_decode(args.hex_decode)
        logger.section("HEX DECODE")
        logger.ok(f"Input: {args.hex_decode}")
        logger.ok(f"Output: {result}")
        return
    
    # CVE Search (no target needed)
    if args.cve:
        logger.section("CVE SEARCH")
        
        if args.cve_id:
            logger.info(f"Searching CVE ID: {args.cve_id}")
            results = search_cve(cve_id=args.cve_id)
        elif args.year and args.keyword:
            logger.info(f"Searching CVEs from {args.year} with keyword: {args.keyword}")
            results = search_cve(year=args.year, query=args.keyword)
        elif args.year:
            logger.info(f"Listing CVEs from year: {args.year}")
            results = search_cve(year=args.year)
        elif args.keyword:
            logger.info(f"Searching CVEs with keyword: {args.keyword}")
            results = search_cve(query=args.keyword)
        else:
            logger.info("Fetching recent CVEs...")
            results = search_cve()
        
        if results:
            logger.ok(f"Found {len(results)} CVEs")
            for cve in results[:20]:
                severity_color = RED if cve['severity'] in ['CRITICAL', 'HIGH'] else YELLOW if cve['severity'] == 'MEDIUM' else GREEN
                logger.raw(f"\n{severity_color}{cve['id']}{RESET} | {severity_color}CVSS: {cve['score']}{RESET} | {cve['severity']}")
                logger.raw(f"  {cve['description'][:150]}...")
                logger.raw(f"  Published: {cve['published'][:10]}")
        else:
            logger.fail("No CVEs found or API error")
        
        return
    
    # Lookup modules (target can be domain or IP)
    if not args.target:
        logger.fail("Target is required for this operation")
        return
    
    lookup = Lookup(logger)
    target = args.target.replace('https://', '').replace('http://', '').strip('/')
    
    if args.whois:
        lookup.whois(target)
        return
    
    if args.ip_lookup:
        # Check if it looks like an IP
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', target):
            lookup.ip_lookup(target)
        else:
            ip = socket.gethostbyname(target)
            lookup.ip_lookup(ip)
        return
    
    if args.reverse_dns:
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', target):
            lookup.reverse_dns(target)
        else:
            ip = socket.gethostbyname(target)
            lookup.reverse_dns(ip)
        return
    
    if args.cdn:
        lookup.cdn_lookup(target)
        return
    
    # Scanner modules
    if any([args.scan_xss, args.scan_sqli, args.scan_ssrf, args.scan_redirect, args.scan_all]):
        scanner = Scanner(args.target, logger)
        
        all_results = []
        
        if args.scan_xss or args.scan_all:
            all_results.extend(scanner.scan_xss())
        if args.scan_sqli or args.scan_all:
            all_results.extend(scanner.scan_sqli())
        if args.scan_ssrf or args.scan_all:
            all_results.extend(scanner.scan_ssrf())
        if args.scan_redirect or args.scan_all:
            all_results.extend(scanner.scan_open_redirect())
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(all_results, f, indent=2)
            logger.ok(f"Results saved to {args.output}")
        
        return
    
    # Recon modules
    recon = Recon(target, logger)
    results = recon.run_all(args)
    
    if args.output:
        report = asdict(results)
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        logger.ok(f"Report saved to {args.output}")


if __name__ == '__main__':
    main()
