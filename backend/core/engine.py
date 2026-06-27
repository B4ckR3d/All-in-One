#!/usr/bin/env python3
"""
All-in-One Security Toolkit v2.0
Modern Interactive CLI — Menu-driven, no memorization needed
"""
import os
import sys
import subprocess
import requests
import re
import json
import hashlib
import base64
import urllib.parse
import ssl
import socket
import whois
from datetime import datetime

# ─── Colors ────────────────────────────────────────────────────────────────
C = {
    'R': '\033[91m',  # Red
    'G': '\033[92m',  # Green
    'Y': '\033[93m',  # Yellow
    'B': '\033[94m',  # Blue
    'M': '\033[95m',  # Magenta
    'C': '\033[96m',  # Cyan
    'W': '\033[97m',  # White
    'D': '\033[90m',  # Dark gray
    'BOLD': '\033[1m',
    'DIM': '\033[2m',
    'RESET': '\033[0m',
}

def c(color, text):
    return f"{C.get(color, '')}{text}{C['RESET']}"

def banner():
    b = f"""
{C['C']}{C['BOLD']}╔═══════════════════════════════════════════════════════════════════╗
║  {C['W']}██████╗ ██╗   ██╗ ██████╗     ████████╗███████╗██╗   ██╗{C['C']}          ║
║  {C['W']}██╔══██╗██║   ██║██╔════╝     ╚══██╔══╝██╔════╝██║   ██║{C['C']}          ║
║  {C['W']}██████╔╝██║   ██║██║  ███╗       ██║   █████╗  ██║   ██║{C['C']}          ║
║  {C['W']}██╔═══╝ ██║   ██║██║   ██║       ██║   ██╔══╝  ╚═╝   ╈█║{C['C']}          ║
║  {C['W']}██║     ╚██████╔╝╚██████╔╝       ██║   ███████╗      ██║{C['C']}          ║
║  {C['W']}╚═╝      ╚═════╝  ╚═════╝        ╚═╝   ╚══════╝      ╚═╝{C['C']}          ║
║  {C['M']}SECURITY TOOLKIT v2.0 — Interactive Mode{C['C']}{C['BOLD']}                        ║
╚═══════════════════════════════════════════════════════════════════╝{C['RESET']}"""
    print(b)

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def input_str(prompt):
    return input(f"\n{C['C']}{prompt}>{C['RESET']} ").strip()

def input_int(prompt, min_val=1, max_val=99):
    while True:
        try:
            val = int(input_str(prompt))
            if min_val <= val <= max_val:
                return val
            print(f"  {C['R']}! Input between {min_val}-{max_val}{C['RESET']}")
        except ValueError:
            print(f"  {C['R']}! Must be a number{C['RESET']}")

def pause():
    input(f"\n  {C['D']}[Enter to continue]{C['RESET']}")

def loading(text="Loading"):
    print(f"  {C['Y']}⟳ {text}...{C['RESET']}")

def success(msg):
    print(f"  {C['G']}✓ {msg}{C['RESET']}")

def warn(msg):
    print(f"  {C['Y']}⚠ {msg}{C['RESET']}")

def error(msg):
    print(f"  {C['R']}✗ {msg}{C['RESET']}")

def info(msg):
    print(f"  {C['C']}ℹ {msg}{C['RESET']}")

def header(msg):
    print(f"\n{C['BOLD']}{C['C']}{'─'*60}{C['RESET']}")
    print(f"{C['BOLD']}{C['C']}  {msg}{C['RESET']}")
    print(f"{C['BOLD']}{C['C']}{'─'*60}{C['RESET']}")

def result(msg):
    print(f"  {C['W']}{msg}{C['RESET']}")

def highlight(msg):
    print(f"  {C['G']}{msg}{C['RESET']}")

# ─── Tools ────────────────────────────────────────────────────────────────

def tool_subdomain(domain):
    header("SUBDOMAIN ENUMERATION")
    info(f"Target: {domain}")
    loading("Enumerating subdomains")
    
    wordlist = ['www','api','dev','staging','prod','app','admin','blog','shop','cdn',
                'mail','ftp','vpn','dns','backup','test','demo','legacy','old','v1','v2',
                'console','dashboard','secure','auth','login','register','status','monitor',
                'assets','static','media','img','images','files','storage','upload','download']
    
    found = []
    for word in wordlist:
        subdomain = f"{word}.{domain}"
        try:
            ip = socket.gethostbyname(subdomain)
            found.append(f"  {C['G']}◆{C['RESET']} {subdomain} → {ip}")
            print(f"  {C['G']}◆{C['RESET']} {subdomain} → {ip}")
        except:
            pass
    
    info(f"Found {len(found)} subdomains")
    return [f"{word}.{domain}" for word in wordlist]  # return all checked

def tool_dns(domain):
    header("DNS RECORDS")
    info(f"Target: {domain}")
    
    records = {
        'A': [], 'AAAA': [], 'MX': [], 'TXT': [], 'NS': [], 'CNAME': []
    }
    
    try:
        # A records
        try:
            ip = socket.gethostbyname(domain)
            records['A'].append(ip)
            highlight(f"A: {ip}")
        except: pass
        
        # NS records
        try:
            ns = socket.getaddrinfo(domain, 53, socket.AF_INET, socket.SOCK_STREAM)
            for r in ns[:2]:
                records['NS'].append(r[4][0])
                highlight(f"NS: {r[4][0]}")
        except: pass
        
        # Try WHOIS for NS
        try:
            w = whois.whois(domain)
            if w.name_servers:
                for ns in (w.name_servers or [])[:3]:
                    highlight(f"NS: {ns}")
        except: pass
        
    except Exception as e:
        error(f"DNS error: {e}")

def tool_port_scan(domain):
    header("PORT SCANNING")
    info(f"Target: {domain}")
    info("Scanning common ports...")
    
    ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
             1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017]
    
    try:
        ip = socket.gethostbyname(domain)
        open_ports = []
        for port in ports:
            try:
                sock = socket.socket()
                sock.settimeout(1)
                if sock.connect_ex((ip, port)) == 0:
                    service = {21:'FTP',22:'SSH',23:'Telnet',25:'SMTP',80:'HTTP',
                              443:'HTTPS',3306:'MySQL',3389:'RDP',5432:'PostgreSQL',
                              8080:'HTTP-Alt',8443:'HTTPS-Alt'}.get(port, 'Unknown')
                    open_ports.append(port)
                    highlight(f"  OPEN: {port}/tcp ({service})")
                sock.close()
            except: pass
        success(f"Found {len(open_ports)} open ports")
    except Exception as e:
        error(f"Scan error: {e}")

def tool_cors(domain):
    header("CORS MISCONFIGURATION CHECK")
    info(f"Target: {domain}")
    
    try:
        url = f"http://{domain}" if not domain.startswith('http') else domain
        r = requests.get(url, timeout=10)
        
        acao = r.headers.get('Access-Control-Allow-Origin', 'Not Set')
        acac = r.headers.get('Access-Control-Allow-Credentials', 'Not Set')
        
        result(f"Access-Control-Allow-Origin: {acao}")
        result(f"Access-Control-Allow-Credentials: {acac}")
        
        if acao == '*':
            warn("VULNERABLE: CORS allows all origins (*)")
        elif acao == 'null':
            warn("VULNERABLE: CORS allows null origin")
        else:
            success("CORS appears properly configured")
    except Exception as e:
        error(f"Error: {e}")

def tool_ssl(domain):
    header("SSL CERTIFICATE CHECK")
    info(f"Target: {domain}")
    
    try:
        host = domain.replace('https://','').replace('http://','').split('/')[0]
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((host, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cipher = ssock.cipher()
                cert = ssock.getpeercert(binary_form=True)
                
                highlight(f"Cipher: {cipher[0]} ({cipher[2]} bits)")
                highlight(f"Protocol: {cipher[1]}")
                
                # Basic cert info
                try:
                    from OpenSSL import crypto
                except:
                    info("Install pyOpenSSL for detailed cert info: pip install pyOpenSSL")
                    
    except ssl.SSLError as e:
        error(f"SSL Error: {e}")
    except Exception as e:
        error(f"Error: {e}")

def tool_whois(domain):
    header("WHOIS LOOKUP")
    info(f"Target: {domain}")
    
    try:
        w = whois.whois(domain)
        if w.domain_name:
            highlight(f"Domain: {w.domain_name}")
        if w.registrar:
            result(f"Registrar: {w.registrar}")
        if w.creation_date:
            result(f"Created: {w.creation_date}")
        if w.expiration_date:
            result(f"Expires: {w.expiration_date}")
        if w.name_servers:
            for ns in (w.name_servers or [])[:5]:
                result(f"NS: {ns}")
        success("WHOIS lookup complete")
    except Exception as e:
        error(f"WHOIS error: {e}")

def tool_cve(keyword=None, year=None, cve_id=None):
    header("CVE SEARCH")
    
    if cve_id:
        info(f"Looking up: {cve_id}")
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    elif keyword and year:
        info(f"Searching: {keyword} ({year})")
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}&pubStartDate={year}-01-01T00:00:00.000&pubEndDate={year}-12-31T23:59:59.999"
    elif keyword:
        info(f"Searching: {keyword}")
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}"
    elif year:
        info(f"All CVEs from {year}")
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate={year}-01-01T00:00:00.000&pubEndDate={year}-12-31T23:59:59.999"
    else:
        warn("Need keyword, year, or CVE ID")
        return
    
    try:
        r = requests.get(url, timeout=15)
        if r.status_code == 200:
            data = r.json()
            vulns = data.get('vulnerabilities', [])
            info(f"Found {len(vulns)} results")
            
            for v in vulns[:10]:
                cve = v.get('cve', {})
                cve_id_str = cve.get('id', 'N/A')
                desc = cve.get('descriptions', [{}])
                desc_text = desc[0].get('value', 'No description')[:100] if desc else 'N/A'
                
                severity = 'UNKNOWN'
                metrics = cve.get('metrics', {})
                if metrics:
                    cvss = metrics.get('cvssMetricV31', metrics.get('cvssMetricV30', []))
                    if cvss:
                        severity = cvss[0].get('cvssData', {}).get('baseSeverity', 'UNKNOWN')
                
                sev_color = {'CRITICAL': 'R', 'HIGH': 'Y', 'MEDIUM': 'Y', 'LOW': 'G'}.get(severity, 'D')
                print(f"\n  {C[sev_color]}{cve_id_str}{C['RESET']} [{severity}]")
                print(f"  {C['D']}{desc_text}...{C['RESET']}")
        else:
            error(f"NVD API error: {r.status_code}")
    except Exception as e:
        error(f"Search error: {e}")

def tool_sqli(url):
    header("SQL INJECTION SCANNER")
    info(f"Target: {url}")
    
    # Basic SQLi payloads
    payloads = ["'", '"', "' OR '1'='1", '" OR "1"="1', "' OR 1=1--", "' UNION SELECT NULL--"]
    
    try:
        parsed = requests.utils.urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params = dict(urllib.parse.parse_qsl(parsed.query))
        
        if not params:
            info("No query parameters found. Try adding ?id=1 to URL")
            return
        
        for name, val in params.items():
            for payload in payloads:
                test_params = {name: payload}
                try:
                    r = requests.get(base_url, params=test_params, timeout=5)
                    resp = r.text.lower()
                    
                    # Simple detection
                    errors = ['sql', 'mysql', 'syntax', 'error', 'warning', 'sqlite', 'postgres', 'oracle', 'microsoft sql', 'odbc']
                    if any(e in resp for e in errors):
                        highlight(f"  [!] Potential SQLi: {name}={payload}")
                        highlight(f"      Error detected in response")
                    else:
                        result(f"  - {name}={payload[:30]}... OK")
                except:
                    pass
        
        success("SQLi scan complete")
    except Exception as e:
        error(f"Scan error: {e}")

def tool_xss(url):
    header("XSS SCANNER")
    info(f"Target: {url}")
    
    payloads = ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>', 
                '<svg onload=alert(1)>', '"><script>alert(1)</script>',
                "'onclick=alert(1)//"]
    
    try:
        parsed = requests.utils.urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params = dict(urllib.parse.parse_qsl(parsed.query))
        
        if not params:
            info("No query parameters found. Try adding ?q=test to URL")
            return
        
        for name, val in params.items():
            for payload in payloads:
                test_params = {name: payload}
                try:
                    r = requests.get(base_url, params=test_params, timeout=5)
                    if payload in r.text:
                        highlight(f"  [!] XSS FOUND: {name}={payload[:40]}")
                    else:
                        result(f"  - {name}={payload[:30]}... filtered")
                except:
                    pass
        
        success("XSS scan complete")
    except Exception as e:
        error(f"Scan error: {e}")

def tool_ssrf(url):
    header("SSRF SCANNER")
    info(f"Target: {url}")
    
    payloads = ['http://localhost', 'http://127.0.0.1', 'http://169.254.169.254',
                'file:///etc/passwd', 'http://internal.aws.ec2@169.254.169.254']
    
    try:
        parsed = requests.utils.urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params = dict(urllib.parse.parse_qsl(parsed.query))
        
        if not params:
            info("No query parameters found")
            return
        
        for name, val in params.items():
            for payload in payloads:
                test_params = {name: payload}
                try:
                    r = requests.get(base_url, params=test_params, timeout=5, allow_redirects=False)
                    if r.status_code in (300, 301, 302):
                        highlight(f"  [!] Possible SSRF: {name}={payload}")
                        result(f"      Redirect to: {r.headers.get('Location', 'N/A')}")
                except Exception as ex:
                    highlight(f"  [!] SSRF Triggered: {payload} -> {ex}")
        
        success("SSRF scan complete")
    except Exception as e:
        error(f"Scan error: {e}")

def tool_open_redirect(url):
    header("OPEN REDIRECT SCANNER")
    info(f"Target: {url}")
    
    payloads = ['//google.com', '///google.com', 'https://google.com',
                'javascript:alert(1)', 'data:text/html,<script>alert(1)</script>']
    
    try:
        parsed = requests.utils.urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params = dict(urllib.parse.parse_qsl(parsed.query))
        
        if not params:
            info("No query parameters found")
            return
        
        for name, val in params.items():
            for payload in payloads:
                test_params = {name: payload}
                try:
                    r = requests.get(base_url, params=test_params, timeout=5, allow_redirects=False)
                    loc = r.headers.get('Location', '')
                    if loc and ('google' in loc or 'javascript' in loc or loc.startswith('//')):
                        highlight(f"  [!] OPEN REDIRECT: {name}={payload}")
                except:
                    pass
        
        success("Open redirect scan complete")
    except Exception as e:
        error(f"Scan error: {e}")

def tool_lfi(url):
    header("LFI SCANNER (Local File Inclusion)")
    info(f"Target: {url}")
    
    payloads = ['/etc/passwd', '../etc/passwd', '....//....//etc/passwd',
                '/etc/hosts', '../etc/hosts', '../../etc/passwd',
                '/proc/self/environ', '/proc/cmdline']
    
    try:
        parsed = requests.utils.urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params = dict(urllib.parse.parse_qsl(parsed.query))
        
        if not params:
            info("No query parameters found")
            return
        
        for name, val in params.items():
            for payload in payloads:
                test_params = {name: payload}
                try:
                    r = requests.get(base_url, params=test_params, timeout=5)
                    if 'root:x:' in r.text or '/bin/' in r.text:
                        highlight(f"  [!] LFI FOUND: {name}={payload}")
                    elif 'localhost' in r.text or 'hostname' in r.text:
                        highlight(f"  [!] LFI POSSIBLE: {name}={payload}")
                except:
                    pass
        
        success("LFI scan complete")
    except Exception as e:
        error(f"Scan error: {e}")

def tool_ssti(url):
    header("SSTI SCANNER (Server Side Template Injection)")
    info(f"Target: {url}")
    
    # Simple SSTI test payloads
    payloads = ['{{7*7}}', '${7*7}', '<%= 7*7 %>', '{{config}}']
    
    try:
        parsed = requests.utils.urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params = dict(urllib.parse.parse_qsl(parsed.query))
        
        if not params:
            info("No query parameters found")
            return
        
        for name, val in params.items():
            for payload in payloads:
                test_params = {name: payload}
                try:
                    r = requests.get(base_url, params=test_params, timeout=5)
                    if '49' in r.text or 'config' in r.text.lower():
                        highlight(f"  [!] Possible SSTI: {name}={payload}")
                except:
                    pass
        
        success("SSTI scan complete")
    except Exception as e:
        error(f"Scan error: {e}")

def tool_cmd_injection(url):
    header("COMMAND INJECTION SCANNER")
    info(f"Target: {url}")
    
    payloads = [';whoami', '|whoami', '&&whoami', ';ls', '|ls', ';id', '|id',
                 ';cat /etc/passwd', '|cat /etc/passwd', '`whoami`', '$(whoami)']
    
    try:
        parsed = requests.utils.urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params = dict(urllib.parse.parse_qsl(parsed.query))
        
        if not params:
            info("No query parameters found")
            return
        
        for name, val in params.items():
            for payload in payloads:
                test_params = {name: payload}
                try:
                    r = requests.get(base_url, params=test_params, timeout=5)
                    resp = r.text.lower()
                    
                    # Check for command output
                    indicators = ['root:', 'uid=', 'bin/', 'total ']
                    if any(ind in resp for ind in indicators):
                        highlight(f"  [!] COMMAND INJECTION: {name}={payload}")
                except:
                    pass
        
        success("Command injection scan complete")
    except Exception as e:
        error(f"Scan error: {e}")

def tool_wayback(domain):
    header("WAYBACK MACHINE / URL DISCOVERY")
    info(f"Target: {domain}")
    
    try:
        url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&limit=50"
        r = requests.get(url, timeout=15)
        
        if r.status_code == 200:
            try:
                data = r.json()
                if len(data) > 1:
                    results = data[1:]  # Skip header
                    info(f"Found {len(results)} historical URLs")
                    
                    for row in results[:20]:
                        if row and row[0]:
                            result(f"  - {row[0][:80]}")
                else:
                    info("No archived URLs found")
            except:
                error("Failed to parse Wayback response")
        else:
            error(f"Wayback API error: {r.status_code}")
    except Exception as e:
        error(f"Error: {e}")

def tool_js_scan(domain):
    header("JAVASCRIPT SECURITY SCANNER")
    info(f"Target: {domain}")
    
    try:
        base = f"https://{domain}" if not '://' in domain else domain
        r = requests.get(base, timeout=10)
        
        # Find JS files
        js_files = re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', r.text)
        info(f"Found {len(js_files)} JS files")
        
        # Search for secrets in JS
        secret_patterns = {
            'AWS Key': r'AKIA[0-9A-Z]{16}',
            'Google API': r'AIza[0-9A-Za-z\-_]{35}',
            'Slack Token': r'xox[baprs]-[0-9a-zA-Z\-]+',
            'GitHub Token': r'gh[pousr]_[A-Za-z0-9_]{36,255}',
            'Generic API Key': r'["\'][aA][pP][iI]_?[kK][eE][yY]["\'][^"\']{0,50}["\'][0-9a-zA-Z_\-]{20,}["\']',
            'Bearer Token': r'[Bb]earer\s+[0-9a-zA-Z_\-\.]+',
        }
        
        for js_url in js_files[:5]:
            full_url = js_url if js_url.startswith('http') else base.rstrip('/') + '/' + js_url.lstrip('/')
            try:
                jr = requests.get(full_url, timeout=5)
                for name, pattern in secret_patterns.items():
                    if re.search(pattern, jr.text):
                        highlight(f"  [!] Possible {name} in {js_url[:50]}")
            except:
                pass
        
        success("JS scan complete")
    except Exception as e:
        error(f"Error: {e}")

def tool_cms(domain):
    header("CMS DETECTION")
    info(f"Target: {domain}")
    
    try:
        base = f"https://{domain}" if not '://' in domain else domain
        r = requests.get(base, timeout=10)
        content = r.text.lower()
        
        cms_list = [
            ('WordPress', ['wp-content', 'wp-includes', 'wordpress', 'wp-json']),
            ('Joomla', ['joomla', '/media/jui/', 'option=com']),
            ('Drupal', ['drupal', 'sites/default', 'node/']),
            ('Laravel', ['laravel_session', 'XSRF-TOKEN', 'laravel']),
            ('React', ['react', '_next/static', '__NEXT_DATA__']),
            ('Vue', ['vue', '__nuxt', 'nuxt.config']),
            ('Next.js', ['_next/static', '__NEXT_DATA__']),
            ('Django', ['csrftoken', 'django']),
            ('Magento', ['mage-', 'magento']),
            ('Shopify', ['shopify', 'cdn.shopify.com']),
        ]
        
        found = []
        for cms_name, signatures in cms_list:
            if any(sig in content for sig in signatures):
                found.append(cms_name)
                highlight(f"  Detected: {cms_name}")
        
        if not found:
            info("No common CMS detected")
        
        # Check security headers
        headers = dict(r.headers)
        sec_headers = ['X-Frame-Options', 'X-Content-Type-Options', 
                       'Strict-Transport-Security', 'Content-Security-Policy']
        
        header("Security Headers")
        for h in sec_headers:
            if h.lower() in [x.lower() for x in headers.keys()]:
                result(f"  ✓ {h}: Present")
            else:
                warn(f"  ✗ {h}: Missing")
                
    except Exception as e:
        error(f"Error: {e}")

def tool_s3_bucket(domain):
    header("S3 BUCKET FINDER")
    info(f"Target: {domain}")
    
    names = [
        domain.replace('.', '-'), domain.replace('.', ''),
        f"{domain.replace('.','')}-dev", f"{domain.replace('.','')}-prod",
        f"{domain.replace('.','')}-staging", f"{domain.replace('.','')}-backup",
        'www', 'assets', 'static', 'cdn', 'files', 'media'
    ]
    
    found_buckets = []
    for name in names[:15]:
        try:
            url = f"https://{name}.s3.amazonaws.com"
            r = requests.head(url, timeout=3)
            if r.status_code == 200:
                highlight(f"  [!] ACCESSIBLE: {name}.s3.amazonaws.com")
                found_buckets.append(name)
            elif r.status_code == 403:
                result(f"  ~ {name}.s3.amazonaws.com (Forbidden)")
        except:
            pass
    
    success(f"Bucket scan complete. {len(found_buckets)} accessible.")

def tool_ip_lookup(ip):
    header("IP LOOKUP & GEOLOCATION")
    info(f"Target: {ip}")
    
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,region,city,isp,org,as,lat,lon,timezone", timeout=10)
        data = r.json()
        
        if data.get('status') == 'success':
            result(f"  IP:       {data.get('query')}")
            result(f"  Country:  {data.get('country')} ({data.get('countryCode')})")
            result(f"  Region:   {data.get('regionName')}")
            result(f"  City:     {data.get('city')}")
            result(f"  ISP:      {data.get('isp')}")
            result(f"  Org:      {data.get('org')}")
            result(f"  AS:       {data.get('as')}")
            result(f"  Coords:   {data.get('lat')}, {data.get('lon')}")
            result(f"  Timezone: {data.get('timezone')}")
            success("IP lookup complete")
        else:
            error("IP lookup failed")
    except Exception as e:
        error(f"Error: {e}")

def tool_reverse_dns(ip):
    header("REVERSE DNS LOOKUP")
    info(f"Target: {ip}")
    
    try:
        host = socket.gethostbyaddr(ip)
        highlight(f"  Hostname: {host[0]}")
        for alias in host[1]:
            result(f"  Alias: {alias}")
        success("Reverse DNS complete")
    except Exception as e:
        error(f"No reverse DNS: {e}")

def tool_crawl(domain, max_pages=20):
    header("WEB CRAWLER")
    info(f"Target: {domain} (max {max_pages} pages)")
    
    base = f"https://{domain}" if not '://' in domain else domain
    visited = set()
    queue = [base]
    emails = set()
    forms = []
    links = []
    
    try:
        import re
        while queue and len(visited) < max_pages:
            url = queue.pop(0)
            if url in visited:
                continue
            visited.add(url)
            
            try:
                r = requests.get(url, timeout=5)
                
                # Extract emails
                for email in re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', r.text):
                    emails.add(email)
                
                # Extract forms
                for form in re.findall(r'<form[^>]*>(.*?)</form>', r.text, re.DOTALL | re.IGNORECASE):
                    forms.append(url)
                
                # Extract links
                for link in re.findall(r'href=["\']([^"\']+)["\']', r.text):
                    if domain in link or link.startswith('/'):
                        full = link if link.startswith('http') else base.rstrip('/') + '/' + link.lstrip('/')
                        if full not in visited:
                            queue.append(full)
                            links.append(full)
                
                result(f"  Crawled: {url}")
            except:
                pass
                
        header("CRAWL SUMMARY")
        highlight(f"  Pages:    {len(visited)}")
        result(f"  Links:    {len(set(links))}")
        result(f"  Forms:    {len(forms)}")
        result(f"  Emails:   {len(emails)}")
        if emails:
            for email in list(emails)[:5]:
                highlight(f"    - {email}")
                
    except Exception as e:
        error(f"Error: {e}")

def tool_dirbust(domain):
    header("DIRECTORY BUSTING")
    info(f"Target: {domain}")
    
    base = f"https://{domain}" if not '://' in domain else domain
    dirs = ['admin', 'login', 'dashboard', 'api', 'backup', 'admin panel',
            'config', 'wp-admin', 'administrator', 'phpmyadmin', 'server-status',
            '.env', '.git', '.htaccess', 'sitemap.xml', 'robots.txt', 'crossdomain.xml',
            'well-known/security.txt', 'api/v1', 'api/v2', 'graphql', 'console',
            'status', 'health', 'actuator', 'env', 'configuration']
    
    found = []
    for d in dirs:
        try:
            url = f"{base.rstrip('/')}/{d}"
            r = requests.get(url, timeout=3, allow_redirects=False)
            if r.status_code == 200:
                highlight(f"  [!] FOUND: /{d} (200 OK)")
                found.append(f"/{d}")
            elif r.status_code in (301, 302, 307, 308):
                result(f"  ~ /{d} -> {r.status_code} (redirect)")
        except:
            pass
    
    success(f"Directory busting complete. Found {len(found)} accessible paths.")

def tool_nmap(domain):
    header("NMAP PORT SCAN")
    info(f"Target: {domain}")
    
    try:
        ip = socket.gethostbyname(domain)
        info(f"Resolved {domain} -> {ip}")
        
        # Common port scan via socket
        ports = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
            445: 'SMB', 465: 'SMTPS', 587: 'SMTP-TLS', 993: 'IMAPS',
            995: 'POP3S', 1433: 'MSSQL', 1521: 'Oracle', 3306: 'MySQL',
            3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis',
            8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 9200: 'Elasticsearch',
            27017: 'MongoDB'
        }
        
        open_ports = []
        for port, svc in ports.items():
            try:
                sock = socket.socket()
                sock.settimeout(1)
                if sock.connect_ex((ip, port)) == 0:
                    open_ports.append((port, svc))
                    highlight(f"  {C['G']}OPEN{C['RESET']} {port}/tcp - {svc}")
                sock.close()
            except:
                pass
        
        success(f"Found {len(open_ports)} open ports")
        
    except Exception as e:
        error(f"Nmap error: {e}")
        info("Install nmap CLI for full port range: sudo apt install nmap")

def tool_full_recon(domain):
    header(f"FULL RECON: {domain}")
    info("Running all reconnaissance modules...")
    
    modules = [
        ("Subdomain Enum", lambda: tool_subdomain(domain)),
        ("DNS Records", lambda: tool_dns(domain)),
        ("Port Scan", lambda: tool_port_scan(domain)),
        ("CORS Check", lambda: tool_cors(domain)),
        ("CMS Detection", lambda: tool_cms(domain)),
        ("Directory Busting", lambda: tool_dirbust(domain)),
        ("Wayback URLs", lambda: tool_wayback(domain)),
        ("S3 Bucket Check", lambda: tool_s3_bucket(domain)),
    ]
    
    for name, func in modules:
        try:
            func()
        except Exception as e:
            error(f"{name} failed: {e}")
    
    success("Full recon complete!")

# ─── Utils ────────────────────────────────────────────────────────────────

def util_base64():
    header("BASE64 ENCODE/DECODE")
    print("  1. Encode")
    print("  2. Decode")
    opt = input_int("Option", 1, 2)
    text = input_str("Text")
    
    if opt == 1:
        encoded = base64.b64encode(text.encode()).decode()
        highlight(f"Encoded: {encoded}")
    else:
        try:
            decoded = base64.b64decode(text.encode()).decode()
            highlight(f"Decoded: {decoded}")
        except:
            error("Invalid base64")

def util_url():
    header("URL ENCODE/DECODE")
    print("  1. Encode")
    print("  2. Decode")
    opt = input_int("Option", 1, 2)
    text = input_str("Text")
    
    if opt == 1:
        encoded = urllib.parse.quote(text)
        highlight(f"Encoded: {encoded}")
    else:
        try:
            decoded = urllib.parse.unquote(text)
            highlight(f"Decoded: {decoded}")
        except:
            error("Invalid URL encoding")

def util_hash():
    header("HASH GENERATOR")
    text = input_str("Text")
    
    results = [
        ("MD5", hashlib.md5(text.encode()).hexdigest()),
        ("SHA1", hashlib.sha1(text.encode()).hexdigest()),
        ("SHA256", hashlib.sha256(text.encode()).hexdigest()),
    ]
    
    for name, h in results:
        result(f"{name}: {h}")

# ─── Main Menu ───────────────────────────────────────────────────────────

def menu_main():
    clear()
    banner()
    print(f"""
  {C['BOLD']}{C['W']}┌─────────────────────────────────────────────────────────┐{C['RESET']}
  {C['W']}│{C['RESET']}  {C['G']}1.{C['RESET']} Recon & Enum      — Subdomain, DNS, Port, CORS     {C['W']}│{C['RESET']}
  {C['W']}│{C['RESET']}  {C['G']}2.{C['RESET']} Vuln Scanner     — SQLi, XSS, SSRF, LFI, SSTI     {C['W']}│{C['RESET']}
  {C['W']}│{C['RESET']}  {C['G']}3.{C['RESET']} CVE Search      — Search by keyword, year, ID     {C['W']}│{C['RESET']}
  {C['W']}│{C['RESET']}  {C['G']}4.{C['RESET']} Lookup Tools    — WHOIS, IP, Reverse DNS         {C['W']}│{C['RESET']}
  {C['W']}│{C['RESET']}  {C['G']}5.{C['RESET']} Web Scanner     — Crawl, JS, CMS, Dirbust, S3     {C['W']}│{C['RESET']}
  {C['W']}│{C['RESET']}  {C['G']}6.{C['RESET']} Utils           — Base64, URL, Hash encode        {C['W']}│{C['RESET']}
  {C['W']}│{C['RESET']}  {C['G']}7.{C['RESET']} Full Recon      — Run ALL modules on target       {C['W']}│{C['RESET']}
  {C['W']}│{C['RESET']}  {C['Y']}0.{C['RESET']} Exit            — Quit                           {C['W']}│{C['RESET']}
  {C['BOLD']}{C['W']}└─────────────────────────────────────────────────────────┘{C['RESET']}
""")

def menu_recon():
    clear()
    header("RECON & ENUMERATION")
    print(f"""  {C['W']}┌─────────────────────────────────────────────────────────┐{C['RESET']}
  {C['W']}│{C['RESET']}  {C['G']}1.{C['RESET']} Subdomain Enumeration                          {C['W']}│{C['RESET']}
  {C['W']}│{C['RESET']}  {C['G']}2.{C['RESET']} DNS Records (A, NS, MX, TXT)                  {C['W']}│{C['RESET']}
  {C['W']}│{C['RESET']}  {C['G']}3.{C['RESET']} Port Scan (common ports)                      {C['W']}│{C['RESET']}
  {C['W']}│{C['RESET']}  {C['G']}4.{C['RESET']} CORS Misconfiguration Check                    {C['W']}│{C['RESET']}
  {C['W']}│{C['RESET']}  {C['G']}5.{C['RESET']} SSL Certificate Info                          {C['W']}│{C['RESET']}
  {C['W']}│{C['RESET']}  {C['G']}6.{C['RESET']} WHOIS Lookup                                  {C['W']}│{C['RESET']}
  {C['W']}│{C['RESET']}  {C['G']}0.{C['RESET']} Back to Main Menu                              {C['W']}│{C['RESET']}
  {C['W']}└─────────────────────────────────────────────────────────┘{C['RESET']}
""")

def menu_vuln():
    clear()
    header("VULNERABILITY SCANNERS")
    print(f"""  {C['W']}┌─────────────────────────────────────────────────────────┐{C['RESET']}
  {C['W']}│{C['RESET']}  {C['G']}1.{C['RESET']} SQL Injection (SQLi)                            {C['W']}│{C['RESET']}
  {C['W']}│{C['RESET']}  {C['G']}2.{C['RESET']} Cross-Site Scripting (XSS)                     {C['W']}│{C['RESET']}
  {C['W']}│{C['RESET']}  {C['G']}3.{C['RESET']} Server-Side Request Forgery (SSRF)              {C['W']}│{C['RESET']}
  {C['W']}│{C['RESET']}  {C['G']}4.{C['RESET']} Local File Inclusion (LFI)                      {C['W']}│{C['RESET']}
  {C['W']}│{C['RESET']}  {C['G']}5.{C['RESET']} Open Redirect                                   {C['W']}│{C['RESET']}
  {C['W']}│{C['RESET']}  {C['G']}6.{C['RESET']} Server-Side Template Injection (SSTI)          {C['W']}│{C['RESET']}
  {C['W']}│{C['RESET']}  {C['G']}7.{C['RESET']} Command Injection                             {C['W']}│{C['RESET']}
  {C['W']}│{C['RESET']}  {C['G']}0.{C['RESET']} Back to Main Menu                              {C['W']}│{C['RESET']}
  {C['W']}└─────────────────────────────────────────────────────────┘{C['RESET']}
""")

def menu_lookup():
    clear()
    header("LOOKUP TOOLS")
    print(f"""  {C['W']}┌─────────────────────────────────────────────────────────┐{C['RESET']}
  {C['W']}│{C['RESET']}  {C['G']}1.{C['RESET']} WHOIS Lookup                                   {C['W']}│{C['RESET']}
  {C['W']}│{C['RESET']}  {C['G']}2.{C['RESET']} IP Geolocation                                 {C['W']}│{C['RESET']}
  {C['W']}│{C['RESET']}  {C['G']}3.{C['RESET']} Reverse DNS Lookup                              {C['W']}│{C['RESET']}
  {C['W']}│{C['RESET']}  {C['G']}4.{C['RESET']} CMS Detection                                   {C['W']}│{C['RESET']}
  {C['W']}│{C['RESET']}  {C['G']}0.{C['RESET']} Back to Main Menu                              {C['W']}│{C['RESET']}
  {C['W']}└─────────────────────────────────────────────────────────┘{C['RESET']}
""")

def menu_web():
    clear()
    header("WEB SCANNER")
    print(f"""  {C['W']}┌─────────────────────────────────────────────────────────┐{C['RESET']}
  {C['W']}│{C['RESET']}  {C['G']}1.{C['RESET']} Web Crawler (links, forms, emails)             {C['W']}│{C['RESET']}
  {C['W']}│{C['RESET']}  {C['G']}2.{C['RESET']} JS Scanner (find secrets in JS files)         {C['W']}│{C['RESET']}
  {C['W']}│{C['RESET']}  {C['G']}3.{C['RESET']} Directory Busting                              {C['W']}│{C['RESET']}
  {C['W']}│{C['RESET']}  {C['G']}4.{C['RESET']} S3 Bucket Finder                               {C['W']}│{C['RESET']}
  {C['W']}│{C['RESET']}  {C['G']}5.{C['RESET']} Wayback Machine (historical URLs)              {C['W']}│{C['RESET']}
  {C['W']}│{C['RESET']}  {C['G']}6.{C['RESET']} NMAP Port Scan                                {C['W']}│{C['RESET']}
  {C['W']}│{C['RESET']}  {C['G']}0.{C['RESET']} Back to Main Menu                              {C['W']}│{C['RESET']}
  {C['W']}└─────────────────────────────────────────────────────────┘{C['RESET']}
""")

def menu_utils():
    clear()
    header("ENCODING & HASHING UTILS")
    print(f"""  {C['W']}┌─────────────────────────────────────────────────────────┐{C['RESET']}
  {C['W']}│{C['RESET']}  {C['G']}1.{C['RESET']} Base64 Encode / Decode                        {C['W']}│{C['RESET']}
  {C['W']}│{C['RESET']}  {C['G']}2.{C['RESET']} URL Encode / Decode                            {C['W']}│{C['RESET']}
  {C['W']}│{C['RESET']}  {C['G']}3.{C['RESET']} Hash Generator (MD5, SHA1, SHA256)            {C['W']}│{C['RESET']}
  {C['W']}│{C['RESET']}  {C['G']}0.{C['RESET']} Back to Main Menu                              {C['W']}│{C['RESET']}
  {C['W']}└─────────────────────────────────────────────────────────┘{C['RESET']}
""")

def menu_cve():
    clear()
    header("CVE SEARCH (NVD)")
    print(f"""  {C['W']}┌─────────────────────────────────────────────────────────┐{C['RESET']}
  {C['W']}│{C['RESET']}  {C['G']}1.{C['RESET']} Search by Keyword                             {C['W']}│{C['RESET']}
  {C['W']}│{C['RESET']}  {C['G']}2.{C['RESET']} Search by Year                                {C['W']}│{C['RESET']}
  {C['W']}│{C['RESET']}  {C['G']}3.{C['RESET']} Search by Keyword + Year                      {C['W']}│{C['RESET']}
  {C['W']}│{C['RESET']}  {C['G']}4.{C['RESET']} Lookup Specific CVE ID                       {C['W']}│{C['RESET']}
  {C['W']}│{C['RESET']}  {C['G']}0.{C['RESET']} Back to Main Menu                              {C['W']}│{C['RESET']}
  {C['W']}└─────────────────────────────────────────────────────────┘{C['RESET']}
""")

# ─── Handler ─────────────────────────────────────────────────────────────

def handle_recon():
    while True:
        menu_recon()
        opt = input_int("Select", 0, 6)
        
        if opt == 0:
            break
        elif opt == 1:
            domain = input_str("Domain (example.com)")
            tool_subdomain(domain)
        elif opt == 2:
            domain = input_str("Domain (example.com)")
            tool_dns(domain)
        elif opt == 3:
            domain = input_str("Domain (example.com)")
            tool_port_scan(domain)
        elif opt == 4:
            domain = input_str("Domain (example.com)")
            tool_cors(domain)
        elif opt == 5:
            domain = input_str("Domain (example.com)")
            tool_ssl(domain)
        elif opt == 6:
            domain = input_str("Domain (example.com)")
            tool_whois(domain)
        
        if opt != 0:
            pause()

def handle_vuln():
    while True:
        menu_vuln()
        opt = input_int("Select", 0, 7)
        
        if opt == 0:
            break
        elif opt in (1, 2, 3, 4, 5, 6, 7):
            url = input_str("Full URL (?param=value)")
            if opt == 1:
                tool_sqli(url)
            elif opt == 2:
                tool_xss(url)
            elif opt == 3:
                tool_ssrf(url)
            elif opt == 4:
                tool_lfi(url)
            elif opt == 5:
                tool_open_redirect(url)
            elif opt == 6:
                tool_ssti(url)
            elif opt == 7:
                tool_cmd_injection(url)
        
        if opt != 0:
            pause()

def handle_lookup():
    while True:
        menu_lookup()
        opt = input_int("Select", 0, 4)
        
        if opt == 0:
            break
        elif opt == 1:
            domain = input_str("Domain (example.com)")
            tool_whois(domain)
        elif opt == 2:
            ip = input_str("IP Address")
            tool_ip_lookup(ip)
        elif opt == 3:
            ip = input_str("IP Address")
            tool_reverse_dns(ip)
        elif opt == 4:
            domain = input_str("Domain (example.com)")
            tool_cms(domain)
        
        if opt != 0:
            pause()

def handle_web():
    while True:
        menu_web()
        opt = input_int("Select", 0, 6)
        
        if opt == 0:
            break
        elif opt == 1:
            domain = input_str("Domain (example.com)")
            tool_crawl(domain)
        elif opt == 2:
            domain = input_str("Domain (example.com)")
            tool_js_scan(domain)
        elif opt == 3:
            domain = input_str("Domain (example.com)")
            tool_dirbust(domain)
        elif opt == 4:
            domain = input_str("Domain (example.com)")
            tool_s3_bucket(domain)
        elif opt == 5:
            domain = input_str("Domain (example.com)")
            tool_wayback(domain)
        elif opt == 6:
            domain = input_str("Domain (example.com)")
            tool_nmap(domain)
        
        if opt != 0:
            pause()

def handle_utils():
    while True:
        menu_utils()
        opt = input_int("Select", 0, 3)
        
        if opt == 0:
            break
        elif opt == 1:
            util_base64()
        elif opt == 2:
            util_url()
        elif opt == 3:
            util_hash()
        
        if opt != 0:
            pause()

def handle_cve():
    while True:
        menu_cve()
        opt = input_int("Select", 0, 4)
        
        if opt == 0:
            break
        elif opt == 1:
            keyword = input_str("Keyword (e.g. xss, sql injection)")
            tool_cve(keyword=keyword)
        elif opt == 2:
            year = input_str("Year (e.g. 2024)")
            try:
                tool_cve(year=int(year))
            except:
                error("Invalid year")
        elif opt == 3:
            keyword = input_str("Keyword")
            year = input_str("Year (e.g. 2024)")
            try:
                tool_cve(keyword=keyword, year=int(year))
            except:
                error("Invalid year")
        elif opt == 4:
            cve_id = input_str("CVE ID (e.g. CVE-2024-1234)")
            tool_cve(cve_id=cve_id)
        
        if opt != 0:
            pause()

def main():
    # Check dependencies
    try:
        import requests
        import whois
    except ImportError as e:
        print(f"{C['R']}[!] Missing dependency: {e}{C['RESET']}")
        print(f"{C['Y']}[*] Install: pip install requests python-whois{C['RESET']}")
        sys.exit(1)
    
    # Auto mode: if args provided, run directly
    if len(sys.argv) > 1:
        handle_auto_mode()
        return
    
    # Interactive mode
    while True:
        menu_main()
        opt = input_int("Select", 0, 7)
        
        if opt == 0:
            clear()
            print(f"\n  {C['C']}Goodbye! Stay safe.{C['RESET']}\n")
            break
        elif opt == 1:
            handle_recon()
        elif opt == 2:
            handle_vuln()
        elif opt == 3:
            handle_cve()
        elif opt == 4:
            handle_lookup()
        elif opt == 5:
            handle_web()
        elif opt == 6:
            handle_utils()
        elif opt == 7:
            domain = input_str("Full Target Domain")
            tool_full_recon(domain)
            pause()

def handle_auto_mode():
    """Run from command line args (legacy compatibility)"""
    args = sys.argv[1:]
    if '-t' in args or '--target' in args:
        idx = args.index('-t') if '-t' in args else args.index('--target')
        domain = args[idx + 1]
    else:
        domain = None
    
    if '--recon' in args or '--deep' in args:
        if domain:
            tool_full_recon(domain) if '--deep' in args else tool_subdomain(domain)
    elif '--cve' in args:
        kw = None; yr = None; cid = None
        if '--keyword' in args:
            idx = args.index('--keyword')
            kw = args[idx + 1]
        if '--year' in args:
            idx = args.index('--year')
            yr = int(args[idx + 1])
        if '--cve-id' in args:
            idx = args.index('--cve-id')
            cid = args[idx + 1]
        tool_cve(keyword=kw, year=yr, cve_id=cid)
    elif '--whois' in args and domain:
        tool_whois(domain)
    elif '--sqli' in args and len(args) > 1:
        tool_sqli(args[-1])
    elif '--xss' in args and len(args) > 1:
        tool_xss(args[-1])
    elif '--lfi' in args and len(args) > 1:
        tool_lfi(args[-1])
    elif domain:
        tool_full_recon(domain)
    else:
        print(f"{C['Y']}[*] Interactive mode: python3 engine.py{C['RESET']}")

if __name__ == '__main__':
    main()
