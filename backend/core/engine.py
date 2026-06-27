#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║   ██████╗ ██████╗  ██████╗ ██████╗  █████╗ ███████╗███████╗ █████╗  ██████╗   ║
║   ██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██╔══██╗██╔════╝██╔════╝██╔══██╗██╔════╝   ║
║   ██████╔╝██████╔╝██║   ██║██║  ██║███████║███████╗███████╗███████║██║  ███╗  ║
║   ██╔═══╝ ██╔══██╗██║   ██║██║  ██║██╔══██║╚════██║╚════██║██╔══██║██║   ██║  ║
║   ██║     ██║  ██║╚██████╔╝██████╔╝██║  ██║███████║███████║██║  ██║╚██████╔╝  ║
║   ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝   ║
║                                                                           ║
║   SECURITY TOOLKIT v3.0 — AUTO RECON + INTERACTIVE MENU                  ║
║   Author: PUKI AI AGENT — All-in-One Bug Bounty & Recon Framework        ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝

Modern security recon toolkit with:
  - AUTO RECON: Full automation, just input URL
  - Amass: Advanced subdomain enumeration
  - Nuclei: Template-based vulnerability scanner
  - SQLMap: SQL Injection scanner
  - ffuf: Directory/content fuzzing
  - CVE: NVD database search
  - +30 built-in modules
"""

import os
import sys
import re
import json
import time
import socket
import subprocess
import requests
import hashlib
import base64
import urllib.parse
import ssl
import whois
import ipaddress
from datetime import datetime, timezone
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import deque

# ─── Colors ────────────────────────────────────────────────────────────────
C = {
    'R': '\033[91m', 'G': '\033[92m', 'Y': '\033[93m', 'B': '\033[94m',
    'M': '\033[95m', 'C': '\033[96m', 'W': '\033[97m', 'D': '\033[90m',
    'BOLD': '\033[1m', 'DIM': '\033[2m', 'RESET': '\033[0m',
}
def c(col, txt): return f"{C.get(col,'')}{txt}{C['RESET']}"

# ─── Output Dir ───────────────────────────────────────────────────────────
OUTPUT_DIR = Path("scan_results")
OUTPUT_DIR.mkdir(exist_ok=True)

def save_report(domain, content, filename=None):
    fn = filename or f"{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    path = OUTPUT_DIR / fn
    path.parent.mkdir(exist_ok=True)
    with open(path, 'w') as f:
        f.write(content)
    return path

# ─── Banner ───────────────────────────────────────────────────────────────
def banner():
    print("""
    \033[96m\033[1m
    ╔═══════════════════════════════════════════════════════════════════════════════╗
    ║   ██████╗ ██████╗  ██████╗ ██████╗  █████╗ ███████╗███████╗ █████╗  ██████╗   ║
    ║   ██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██╔══██╗██╔════╝██╔════╝██╔══██╗██╔════╝   ║
    ║   ██████╔╝██████╔╝██║   ██║██║  ██║███████║███████╗███████╗███████║██║  ███╗  ║
    ║   ██╔═══╝ ██╔══██╗██║   ██║██║  ██║██╔══██║╚════██║╚════██║██╔══██║██║   ██║  ║
    ║   ██║     ██║  ██║╚██████╔╝██████╔╝██║  ██║███████║███████║██║  ██║╚██████╔╝  ║
    ║   ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝   ║
    ║                                                                               ║
    ║   v3.0 - PUKI AI AGENT - AUTO RECON + NUCLEI + SQLMAP + FFUF + AMASS        ║
    ║                                                                               ║
    ╚═══════════════════════════════════════════════════════════════════════════════╝
    \033[0m""")

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def inp(prompt):
    return input(f"\n  {c('C','›')} {c('W',prompt)}: ").strip()

def inp_int(prompt, min_v=1, max_v=99):
    while True:
        try:
            v = int(inp(prompt))
            if min_v <= v <= max_v:
                return v
            print(f"  {c('R','✗')} Input between {min_v}-{max_v}")
        except ValueError:
            print(f"  {c('R','✗')} Must be a number")

def pause():
    input(f"\n  {c('D','[ Press ENTER to continue ]')}")

def ok(msg): print(f"  {c('G','✓')} {msg}")
def no(msg): print(f"  {c('R','✗')} {msg}")
def warn(msg): print(f"  {c('Y','⚠')} {msg}")
def info(msg): print(f"  {c('C','ℹ')} {msg}")
def step(msg): print(f"\n  {c('M','▸')} {c('BOLD',msg)}")
def result(msg): print(f"  {c('W',msg)}")
def highlight(msg): print(f"  {c('G',msg)}")
def separator():
    print(f"  {c('D','─'*58)}")

# ─── Tool Status Check ────────────────────────────────────────────────────
def check_tool(name, cmd):
    try:
        subprocess.run(cmd, shell=True, capture_output=True, timeout=5)
        return True
    except:
        return False

TOOLS = {
    'nuclei':   check_tool('nuclei',   'nuclei -version'),
    'amass':     check_tool('amass',    'amass enum -version'),
    'sqlmap':    check_tool('sqlmap',   'sqlmap --version'),
    'ffuf':      check_tool('ffuf',     'ffuf -V'),
    'subfinder': check_tool('subfinder','subfinder -version'),
    'assetfinder': check_tool('assetfinder','assetfinder --version'),
    'nmap':      check_tool('nmap',     'nmap --version'),
    ' httpx':    check_tool('httpx',    'httpx -version'),
    'anew':      check_tool('anew',     'anew --help'),
    'notify':    check_tool('notify',   'notify -version'),
    'wev':       check_tool('wev',     'wev --help'),
    'naabu':     check_tool('naabu',    'naabu --version'),
}

def check_tools():
    info("Checking tools...")
    available = []
    missing = []
    for tool, present in TOOLS.items():
        if present:
            available.append(tool)
            ok(f"{tool} installed")
        else:
            missing.append(tool)
            no(f"{tool} NOT found")
    
    if missing:
        warn(f"\nInstall missing tools: sudo apt install {' '.join(missing)}")
        warn("Or: go install, pip install, or see tool docs")
    return available

# ─── Domain Utils ─────────────────────────────────────────────────────────
def extract_domain(url):
    url = url.strip()
    if not re.match(r'^https?://', url):
        url = 'http://' + url
    try:
        parsed = requests.utils.urlparse(url)
        return parsed.netloc or parsed.path
    except:
        return url.split('/')[0].split('?')[0]

def resolve_domain(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return None

def is_valid_domain(domain):
    try:
        socket.getaddrinfo(domain, 80)
        return True
    except:
        return False

# ─── Auto Recon Engine ────────────────────────────────────────────────────
def auto_recon(domain):
    """Full automated recon — just input URL, everything runs automatically"""
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    domain_safe = re.sub(r'[^a-zA-Z0-9._-]', '_', domain)
    report_file = OUTPUT_DIR / f"auto_recon_{domain_safe}_{ts}.txt"
    
    results = {
        'domain': domain,
        'ip': resolve_domain(domain),
        'subdomains': [],
        'open_ports': [],
        'vulnerabilities': [],
        'cves': [],
        'tech': [],
        'urls': [],
        'secrets': [],
    }
    
    report_lines = []
    def log(msg):
        report_lines.append(msg)
        print(f"  {c('C','•')} {msg}")
    
    def section(name):
        print(f"\n  {c('BOLD',c('M','═'*55))}")
        print(f"  {c('BOLD',c('M',f'  ▶ {name}'))}")
        print(f"  {c('BOLD',c('M','═'*55))}")
    
    # ── 1. WHOIS ──────────────────────────────────────────────────────
    section("1/8 | WHOIS LOOKUP")
    try:
        w = whois.whois(domain)
        log(f"Domain: {w.domain_name}")
        log(f"Registrar: {w.registrar}")
        if w.creation_date:
            log(f"Created: {w.creation_date}")
        if w.expiration_date:
            log(f"Expires: {w.expiration_date}")
        if w.name_servers:
            for ns in (w.name_servers or [])[:5]:
                log(f"NS: {ns}")
    except Exception as e:
        warn(f"WHOIS failed: {e}")
    
    # ── 2. Subdomain Enumeration ───────────────────────────────────────
    section("2/8 | SUBDOMAIN ENUMERATION")
    found_subs = set()
    
    # Tool-based
    if check_tool('subfinder', 'subfinder -version'):
        log("Running subfinder...")
        try:
            out = subprocess.run(f"subfinder -d {domain} -silent", 
                              shell=True, capture_output=True, timeout=60)
            for line in out.stdout.decode().strip().split('\n'):
                if line.strip():
                    found_subs.add(line.strip())
                    log(f"  {c('G','+')} {line.strip()}")
        except Exception as e:
            warn(f"subfinder error: {e}")
    
    if check_tool('amass', 'amass enum -version'):
        log("Running amass...")
        try:
            out = subprocess.run(f"amass enum -passive -d {domain}", 
                              shell=True, capture_output=True, timeout=120)
            for line in out.stdout.decode().strip().split('\n'):
                if line.strip() and '.' in line.strip():
                    found_subs.add(line.strip())
                    log(f"  {c('G','+')} {line.strip()}")
        except Exception as e:
            warn(f"amass error: {e}")
    
    if check_tool('assetfinder', 'assetfinder --version'):
        log("Running assetfinder...")
        try:
            out = subprocess.run(f"assetfinder {domain}", 
                              shell=True, capture_output=True, timeout=60)
            for line in out.stdout.decode().strip().split('\n'):
                if line.strip():
                    found_subs.add(line.strip())
        except: pass
    
    # Built-in wordlist scan
    log("Running built-in subdomain scan...")
    sub_wordlist = ['www','api','dev','staging','app','admin','blog','shop',
                    'cdn','mail','ftp','vpn','dns','backup','test','demo',
                    'legacy','old','v1','v2','console','dashboard','secure',
                    'auth','login','register','status','monitor','assets',
                    'static','media','img','files','storage','m','mx','smtp']
    
    def check_sub(word):
        sub = f"{word}.{domain}"
        try:
            ip = socket.gethostbyname(sub)
            return (sub, ip)
        except:
            return None
    
    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = [ex.submit(check_sub, w) for w in sub_wordlist]
        for f in futures:
            r = f.result()
            if r:
                found_subs.add(r[0])
                log(f"  {c('G','+')} {r[0]} → {r[1]}")
    
    results['subdomains'] = list(found_subs)
    log(f"Total subdomains found: {len(found_subs)}")
    
    # ── 3. Port Scan ──────────────────────────────────────────────────
    section("3/8 | PORT SCANNING")
    if check_tool('nmap', 'nmap --version'):
        log("Running Nmap scan (top 100 ports)...")
        try:
            out = subprocess.run(
                f"nmap -T4 -F --open -sV {domain} -oG -",
                shell=True, capture_output=True, timeout=120
            )
            for line in out.stdout.decode().split('\n'):
                m = re.search(r'Ports: ([^/]+)/', line)
                if m:
                    log(f"  {c('G','+')} {m.group(1)}")
        except Exception as e:
            warn(f"nmap error: {e}")
    else:
        log("Nmap not available, using built-in port scan...")
        common_ports = {21:'FTP',22:'SSH',23:'Telnet',25:'SMTP',53:'DNS',
                        80:'HTTP',110:'POP3',143:'IMAP',443:'HTTPS',
                        445:'SMB',465:'SMTPS',587:'SMTP-TLS',993:'IMAPS',
                        995:'POP3S',1433:'MSSQL',1521:'Oracle',3306:'MySQL',
                        3389:'RDP',5432:'PostgreSQL',5900:'VNC',6379:'Redis',
                        8080:'HTTP-Alt',8443:'HTTPS-Alt',9200:'Elasticsearch'}
        ip = results['ip']
        if ip:
            for port, svc in common_ports.items():
                try:
                    sock = socket.socket()
                    sock.settimeout(1)
                    if sock.connect_ex((ip, port)) == 0:
                        results['open_ports'].append(port)
                        log(f"  {c('G','OPEN')} {port}/tcp ({svc})")
                    sock.close()
                except: pass
    
    # ── 4. Technology Detection ─────────────────────────────────────────
    section("4/8 | TECHNOLOGY DETECTION")
    try:
        url = f"http://{domain}" if not domain.startswith('http') else domain
        r = requests.get(url, timeout=10, verify=False)
        headers = dict(r.headers)
        
        # Detect CMS/Framework
        content = r.text.lower()
        techs = []
        
        cms_map = {
            'WordPress': ['wp-content','wp-includes','wordpress','wp-json'],
            'Joomla': ['joomla', '/media/jui/', 'option=com'],
            'Drupal': ['drupal', 'sites/default'],
            'Laravel': ['laravel_session', 'XSRF-TOKEN'],
            'React': ['react', '__next/static', '__NEXT_DATA__'],
            'Vue': ['vue', '__nuxt'],
            'Next.js': ['_next/static', '__NEXT_DATA__'],
            'Django': ['csrftoken', 'django'],
            'Angular': ['ng-component', 'angular', '@angular'],
            'jQuery': ['jquery'],
            'Bootstrap': ['bootstrap'],
            'Tailwind': ['tailwind'],
            'Node.js': ['node', 'express'],
            'PHP': ['php', '.php'],
            'Apache': ['apache'],
            'Nginx': ['nginx'],
        }
        
        for tech, sigs in cms_map.items():
            if any(s in content for s in sigs):
                techs.append(tech)
                log(f"  {c('G','+')} {tech}")
        
        # Security headers
        sec_headers = ['X-Frame-Options','X-Content-Type-Options',
                       'Strict-Transport-Security','Content-Security-Policy',
                       'X-XSS-Protection']
        log(f"\n  {c('BOLD','Security Headers:')}")
        for h in sec_headers:
            if h.lower() in [x.lower() for x in headers.keys()]:
                log(f"    {c('G','✓')} {h}: Present")
            else:
                log(f"    {c('R','✗')} {h}: MISSING")
        
        results['tech'] = techs
    except Exception as e:
        warn(f"Tech detection error: {e}")
    
    # ── 5. Nuclei Scan ─────────────────────────────────────────────────
    section("5/8 | NUCLEI VULNERABILITY SCAN")
    if check_tool('nuclei', 'nuclei -version'):
        log("Running Nuclei scan (critical + high templates)...")
        nuclei_out = OUTPUT_DIR / f"nuclei_{domain_safe}_{ts}.txt"
        try:
            cmd = f"nuclei -u http://{domain} -t critical,high -silent -o {nuclei_out} -stats"
            log(f"Command: {cmd}")
            proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            for line in iter(proc.stdout.readline, b''):
                l = line.decode().strip()
                if l:
                    log(l)
            proc.wait()
            if nuclei_out.exists():
                with open(nuclei_out) as f:
                    lines = f.readlines()
                    log(f"Nuclei found {len(lines)} issues")
                    for l in lines[:10]:
                        results['vulnerabilities'].append(l.strip())
        except Exception as e:
            warn(f"Nuclei error: {e}")
    else:
        warn("Nuclei not installed. Install: https://github.com/projectdiscovery/nuclei")
        log("Running built-in vulnerability checks instead...")
        # Built-in checks
        try:
            url = f"http://{domain}"
            # Check for common issues
            r = requests.get(url, timeout=10, verify=False)
            
            # CORS
            acao = r.headers.get('Access-Control-Allow-Origin','')
            if acao == '*':
                results['vulnerabilities'].append(f"CORS MISCONFIG: Wildcard origin (*)")
                log(f"  {c('R','!')} CORS: Wildcard origin (*)")
            
            # Server version disclosure
            server = r.headers.get('Server','')
            if server and not any(x in server for x in ['nginx','apache','cloudflare']):
                results['vulnerabilities'].append(f"SERVER INFO: {server} disclosed")
                log(f"  {c('Y','!')} Server version disclosed: {server}")
            
            # X-Content-Type-Options
            if 'X-Content-Type-Options' not in r.headers:
                log(f"  {c('Y','!')} X-Content-Type-Options: MISSING")
            
            # Check directory listing
            if 'Index of' in r.text or '<title>Index of' in r.text:
                results['vulnerabilities'].append("DIRECTORY LISTING: Enabled")
                log(f"  {c('R','!')} Directory listing enabled")
                
        except Exception as e:
            warn(f"Basic scan error: {e}")
    
    # ── 6. SQLMap Scan ─────────────────────────────────────────────────
    section("6/8 | SQLMAP SCAN")
    if check_tool('sqlmap', 'sqlmap --version'):
        log("Running SQLMap scan (fast mode)...")
        sqlmap_out = OUTPUT_DIR / f"sqlmap_{domain_safe}_{ts}.txt"
        try:
            # Check for params first
            parsed_url = urllib.parse.urlparse(url if '://' in url else f"http://{domain}")
            if parsed_url.query:
                cmd = f"sqlmap -u '{domain}?{parsed_url.query}' --batch --level=1 --risk=1 --silent -o"
                log(f"Testing: {domain}?{parsed_url.query}")
                log("Note: SQLMap runs in background. Check sqlmap directory for results.")
                try:
                    out = subprocess.run(cmd, shell=True, capture_output=True, timeout=120)
                    output = out.stdout.decode() + out.stderr.decode()
                    if 'vulnerable' in output.lower() or 'injection' in output.lower():
                        results['vulnerabilities'].append("SQL INJECTION: Possible")
                        log(f"  {c('R','!')} Possible SQL Injection detected")
                    else:
                        log("SQLMap scan complete (no obvious injection found)")
                except Exception as e:
                    warn(f"SQLMap error: {e}")
            else:
                log("No query parameters found. Add ?param=value to URL for SQLi testing.")
        except Exception as e:
            warn(f"SQLMap error: {e}")
    else:
        warn("SQLMap not installed. Install: pip install sqlmap or sudo apt install sqlmap")
    
    # ── 7. Directory/Content Fuzz ───────────────────────────────────────
    section("7/8 | DIRECTORY FUZZING")
    if check_tool('ffuf', 'ffuf -V'):
        log("Running ffuf fuzzing...")
        ffuf_out = OUTPUT_DIR / f"ffuf_{domain_safe}_{ts}.txt"
        try:
            # Common dirs
            cmd = f"ffuf -u http://{domain}/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,204,301,302,307,401,403 -t 50 -silent -o {ffuf_out}"
            proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            found_dirs = []
            for line in iter(proc.stdout.readline, b''):
                l = line.decode().strip()
                if l and 'html' not in l.lower():
                    log(f"  {c('G','+')} {l}")
                    found_dirs.append(l)
            proc.wait()
            log(f"ffuf found {len(found_dirs)} accessible paths")
        except Exception as e:
            warn(f"ffuf error: {e}")
    else:
        log("ffuf not installed. Running built-in dirbust...")
        common_dirs = ['admin','login','dashboard','api','backup','wp-admin',
                       'administrator','phpmyadmin','server-status','.env',
                       '.git','robots.txt','sitemap.xml','actuator','env',
                       'config','api/v1','console','status','health']
        for d in common_dirs:
            try:
                r = requests.head(f"http://{domain}/{d}", timeout=3, allow_redirects=False)
                if r.status_code == 200:
                    log(f"  {c('G','+')} /{d} (200 OK)")
                    results['urls'].append(f"http://{domain}/{d}")
                elif r.status_code in (301,302,307,308):
                    loc = r.headers.get('Location','')
                    log(f"  {c('Y','~')} /{d} -> {r.status_code} ({loc[:40]})")
            except: pass
    
    # ── 8. Wayback & JS Analysis ───────────────────────────────────────
    section("8/8 | WAYBACK & JS ANALYSIS")
    try:
        log("Querying Wayback Machine...")
        wb_url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&limit=30"
        r = requests.get(wb_url, timeout=15)
        if r.status_code == 200:
            try:
                data = r.json()
                if len(data) > 1:
                    for row in data[1:]:
                        if row and row[0]:
                            log(f"  {c('C','↗')} {row[0][:80]}")
                            results['urls'].append(row[0])
            except: pass
    except Exception as e:
        warn(f"Wayback error: {e}")
    
    # JS file scanner
    try:
        log("\nScanning JS files for secrets...")
        base_url = f"http://{domain}" if not '://' in domain else domain
        r = requests.get(base_url, timeout=10, verify=False)
        js_files = re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', r.text)
        
        secret_patterns = {
            'AWS Key': r'AKIA[0-9A-Z]{16}',
            'Google API': r'AIza[0-9A-Za-z\-_]{35}',
            'Slack Token': r'xox[baprs]-[0-9a-zA-Z\-]+',
            'GitHub Token': r'gh[pousr]_[A-Za-z0-9_]{36,255}',
            'Generic API Key': r'["\'][aA][pP][iI]_?[kK][eE][yY]["\']',
            'Bearer Token': r'[Bb]earer\s+[0-9a-zA-Z_\-\.]+',
        }
        
        for js_url in js_files[:5]:
            full_url = js_url if js_url.startswith('http') else base_url.rstrip('/') + '/' + js_url.lstrip('/')
            try:
                jr = requests.get(full_url, timeout=5, verify=False)
                for name, pattern in secret_patterns.items():
                    if re.search(pattern, jr.text):
                        results['secrets'].append(f"{name} in {js_url}")
                        log(f"  {c('R','!')} Possible {name} in {js_url[:50]}")
            except: pass
    except Exception as e:
        warn(f"JS scan error: {e}")
    
    # ── Summary ─────────────────────────────────────────────────────────
    section("AUTO RECON COMPLETE — SUMMARY")
    print("""
  {c('BOLD','Target:')}       {domain}
  {c('BOLD','IP Address:')}   {results['ip']}
  {c('BOLD','Subdomains:')}    {len(results['subdomains'])} found
  {c('BOLD','Open Ports:')}   {len(results['open_ports'])} found
  {c('BOLD','Technologies:')} {', '.join(results['tech']) if results['tech'] else 'Unknown'}
  {c('BOLD','Vulns:')}        {len(results['vulnerabilities'])} found
  {c('BOLD','URLs:')}         {len(results['urls'])} found
  {c('BOLD','Secrets:')}      {len(results['secrets'])} found
""")
    
    # Save report
    report = '\n'.join(report_lines)
    save_report(domain, report)
    
    if results['vulnerabilities']:
        print(f"  {c('BOLD',c('R','⚠ VULNERABILITIES FOUND:'))}")
        for v in results['vulnerabilities'][:20]:
            print(f"    {c('R','•')} {v}")
    
    ok(f"Full report saved to: {report_file}")
    return results

# ─── Manual Recon Modules ─────────────────────────────────────────────────

def mod_subdomains():
    domain = inp("Target domain")
    if not domain: return
    
    step("Subdomain Enumeration")
    info(f"Target: {domain}")
    
    found = []
    
    # subfinder
    if check_tool('subfinder', 'subfinder -version'):
        info("Running subfinder...")
        try:
            out = subprocess.run(f"subfinder -d {domain} -silent", 
                              shell=True, capture_output=True, timeout=60)
            for line in out.stdout.decode().strip().split('\n'):
                if line.strip():
                    found.append(line.strip())
                    highlight(f"  + {line.strip()}")
        except: pass
    
    # amass
    if check_tool('amass', 'amass enum -version'):
        info("Running amass...")
        try:
            out = subprocess.run(f"amass enum -passive -d {domain}", 
                              shell=True, capture_output=True, timeout=120)
            for line in out.stdout.decode().strip().split('\n'):
                if line.strip() and '.' in line.strip():
                    if line.strip() not in found:
                        found.append(line.strip())
                        highlight(f"  + {line.strip()}")
        except: pass
    
    # wordlist scan
    info("Running wordlist scan...")
    subs = ['www','api','dev','staging','app','admin','blog','shop','cdn',
            'mail','ftp','vpn','backup','test','demo','legacy','old',
            'v1','v2','console','dashboard','secure','auth','login']
    def check_s(sub):
        try:
            ip = socket.gethostbyname(f"{sub}.{domain}")
            return (f"{sub}.{domain}", ip)
        except: return None
    
    with ThreadPoolExecutor(max_workers=20) as ex:
        for r in ex.map(check_s, subs):
            if r:
                found.append(r[0])
                highlight(f"  + {r[0]} → {r[1]}")
    
    ok(f"Total: {len(found)} subdomains")
    return found

def mod_nuclei():
    domain = inp("Target URL (http://...)")
    if not domain: return
    
    if not domain.startswith('http'):
        domain = f"http://{domain}"
    
    step("Nuclei Vulnerability Scanner")
    info(f"Target: {domain}")
    info("Templates: critical + high severity")
    
    templates = inp("Templates [1=Critical+High, 2=All, 3=Custom]") or "1"
    
    if templates == "1":
        t_flag = "-t critical,high"
    elif templates == "2":
        t_flag = ""
    else:
        t_dir = inp("Template directory path")
        t_flag = f"-t {t_dir}" if t_dir else "-t critical,high"
    
    out_file = OUTPUT_DIR / f"nuclei_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    cmd = f"nuclei -u {domain} {t_flag} -silent -o {out_file}"
    
    info(f"Running: {cmd}")
    info("Scanning... (this may take a few minutes)")
    
    try:
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        vuln_count = 0
        for line in iter(proc.stdout.readline, b''):
            l = line.decode().strip()
            if l:
                print(f"  {c('Y','↗')} {l}")
                vuln_count += 1
        proc.wait()
        
        if vuln_count > 0:
            ok(f"Nuclei found {vuln_count} vulnerabilities")
        else:
            info("No vulnerabilities found by Nuclei")
        
        if out_file.exists():
            ok(f"Results saved to: {out_file}")
    except Exception as e:
        error(f"Nuclei error: {e}")

def mod_sqlmap():
    url = inp("Target URL with params (e.g. http://site.com/page.php?id=1)")
    if not url: return
    
    if not url.startswith('http'):
        url = f"http://{url}"
    
    step("SQLMap SQL Injection Scanner")
    info(f"Target: {url}")
    
    level = inp("Scan level [1=Quick, 2=Medium, 3=Deep]") or "1"
    risk = inp("Risk level [1=Safe, 2=Moderate, 3=High]") or "1"
    
    level_map = {'1':'--level=1','2':'--level=2','3':'--level=3'}
    risk_map = {'1':'--risk=1','2':'--risk=2','3':'--risk=3'}
    
    cmd = f"sqlmap -u '{url}' --batch {level_map.get(level,'--level=1')} {risk_map.get(risk,'--risk=1')} -o"
    
    info(f"Running: {cmd}")
    info("SQLMap scan running... (may take 5-30 minutes)")
    info("Output saved to: ~/.sqlmap/output/")
    
    try:
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        found = False
        for line in iter(proc.stdout.readline, b''):
            l = line.decode().strip()
            if l:
                if any(x in l.lower() for x in ['injection','vulnerable','error']):
                    print(f"  {c('R','!')} {l}")
                    found = True
                elif len(l) < 100:
                    print(f"  {c('D',l[:80])}")
        proc.wait()
        if found:
            warn("SQL Injection may be present! Manual verification needed.")
        else:
            ok("SQLMap scan complete. No obvious injection detected.")
    except Exception as e:
        error(f"SQLMap error: {e}")

def mod_ffuf():
    domain = inp("Target domain (e.g. example.com)")
    if not domain: return
    
    if not domain.startswith('http'):
        domain = f"http://{domain}"
    
    step("FFUF Directory Fuzzing")
    info(f"Target: {domain}")
    
    wordlist = inp("Wordlist [/usr/share/wordlists/dirb/common.txt]") or "/usr/share/wordlists/dirb/common.txt"
    threads = inp("Threads [50]") or "50"
    
    out_file = OUTPUT_DIR / f"ffuf_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    cmd = f"ffuf -u {domain}/FUZZ -w {wordlist} -mc 200,204,301,302,307,401,403 -t {threads} -silent -o {out_file} -of json"
    
    info(f"Running ffuf...")
    info("Press Ctrl+C to stop early")
    
    try:
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        found = []
        for line in iter(proc.stdout.readline, b''):
            l = line.decode().strip()
            if l and 'html' not in l.lower():
                highlight(f"  + {l}")
                found.append(l)
        proc.wait()
        
        ok(f"Found {len(found)} accessible paths")
        if out_file.exists():
            ok(f"Results: {out_file}")
    except KeyboardInterrupt:
        info("Stopped by user")
    except Exception as e:
        error(f"ffuf error: {e}")

def mod_cve():
    step("CVE Search (NVD)")
    print("""
  [1] Search by Keyword (e.g. xss, sql injection)
  [2] Search by Year (e.g. 2024)
  [3] Search by Keyword + Year
  [4] Lookup specific CVE ID (e.g. CVE-2024-1234)
""")
    
    opt = inp_int("Option", 1, 4)
    
    if opt == 1:
        kw = inp("Keyword")
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={urllib.parse.quote(kw)}"
    elif opt == 2:
        yr = inp("Year")
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate={yr}-01-01T00:00:00.000&pubEndDate={yr}-12-31T23:59:59.999"
    elif opt == 3:
        kw = inp("Keyword")
        yr = inp("Year")
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={urllib.parse.quote(kw)}&pubStartDate={yr}-01-01T00:00:00.000&pubEndDate={yr}-12-31T23:59:59.999"
    elif opt == 4:
        cve_id = inp("CVE ID")
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id.upper()}"
    
    info(f"Querying NVD... (may take a few seconds)")
    
    try:
        r = requests.get(url, timeout=20)
        if r.status_code == 200:
            data = r.json()
            vulns = data.get('vulnerabilities', [])
            ok(f"Found {len(vulns)} results")
            
            for v in vulns[:20]:
                cve = v.get('cve', {})
                cid = cve.get('id', 'N/A')
                desc = cve.get('descriptions', [{}])
                desc_text = desc[0].get('value', 'N/A')[:100] if desc else 'N/A'
                
                severity = 'N/A'
                metrics = cve.get('metrics', {})
                if metrics:
                    cvss = metrics.get('cvssMetricV31', metrics.get('cvssMetricV30', []))
                    if cvss:
                        severity = cvss[0].get('cvssData', {}).get('baseSeverity', 'N/A')
                
                sev_c = {'CRITICAL': 'R', 'HIGH': 'Y', 'MEDIUM': 'Y', 'LOW': 'G'}.get(severity, 'D')
                print(f"\n  {c(sev_c,c('BOLD',cid))} [{severity}]")
                print(f"  {c('D',desc_text)}")
        else:
            error(f"NVD API error: {r.status_code}")
    except Exception as e:
        error(f"Search error: {e}")

def mod_ssrf():
    url = inp("Target URL with param (e.g. http://site.com?url=)")
    if not url: return
    
    step("SSRF Scanner")
    info(f"Target: {url}")
    
    payloads = [
        ('http://localhost', 'localhost'),
        ('http://127.0.0.1', 'localhost IP'),
        ('http://169.254.169.254', 'AWS metadata'),
        ('http://0.0.0.0', 'zero'),
        ('file:///etc/passwd', 'LFI via file://'),
    ]
    
    found = []
    for payload, desc in payloads:
        try:
            test_url = f"{url}{urllib.parse.quote(payload)}"
            r = requests.get(test_url, timeout=5, allow_redirects=False)
            
            # Check for SSRF indicators
            resp_lower = r.text.lower()
            if any(x in resp_lower for x in ['root:', 'bin/bash', 'ec2', 'ami-id', 'metadata']):
                highlight(f"  {c('R','[!]')} SSRF Triggered: {desc} -> {payload[:40]}")
                found.append((desc, payload))
            else:
                result(f"  - {payload[:50]}... no response")
        except Exception as ex:
            highlight(f"  {c('Y','[~]')} {desc}: {str(ex)[:50]}")
    
    if found:
        ok(f"SSRF triggers found: {len(found)}")
    else:
        info("No obvious SSRF triggers detected")

def mod_xss():
    url = inp("Target URL with param (e.g. http://site.com?q=)")
    if not url: return
    
    step("XSS Scanner")
    info(f"Target: {url}")
    
    payloads = [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '"><script>alert(1)</script>',
        "'onclick=alert(1)//",
        '<iframe src="javascript:alert(1)">',
        '{{constructor.constructor("alert(1)")()}}',
    ]
    
    parsed = urllib.parse.urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    params = dict(urllib.parse.parse_qsl(parsed.query))
    
    if not params:
        warn("No parameters found in URL")
        return
    
    for name, val in params.items():
        info(f"Testing param: {name}")
        for payload in payloads:
            try:
                test_params = {name: payload}
                r = requests.get(base, params=test_params, timeout=5)
                
                # Simple reflection check
                if payload in r.text:
                    highlight(f"  {c('R','[!]')} XSS REFLECTED: {name}={payload[:40]}")
                    highlight(f"      Payload reflected in response!")
                else:
                    result(f"  - {payload[:40]}... filtered")
            except: pass
    
    ok("XSS scan complete")

def mod_sqli():
    url = inp("Target URL with param (e.g. http://site.com?id=1)")
    if not url: return
    
    step("SQL Injection Scanner")
    info(f"Target: {url}")
    
    payloads = [
        "'", '"', "' OR '1'='1", '" OR "1"="1',
        "' OR 1=1--", "' UNION SELECT NULL--",
        "1' AND '1'='1", "1\" AND \"1\"=\"1",
    ]
    
    error_patterns = [
        'sql', 'mysql', 'syntax error', 'warning',
        'sqlite', 'postgres', 'oracle', 'microsoft sql',
        'odbc', 'sqlstate', 'sqlsrv'
    ]
    
    parsed = urllib.parse.urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    params = dict(urllib.parse.parse_qsl(parsed.query))
    
    if not params:
        warn("No parameters found in URL")
        return
    
    found_sqli = []
    for name, val in params.items():
        info(f"Testing param: {name}")
        for payload in payloads:
            try:
                test_params = {name: payload}
                r = requests.get(base, params=test_params, timeout=5)
                resp = r.text.lower()
                
                if any(ep in resp for ep in error_patterns):
                    highlight(f"  {c('R','[!]')} SQL ERROR: {name}={payload}")
                    highlight(f"      Error pattern detected in response")
                    found_sqli.append((name, payload))
                else:
                    # Check for boolean-based
                    orig = requests.get(base, params={name: val}, timeout=5)
                    mod = requests.get(base, params={name: f"{val} AND 1=1"}, timeout=5)
                    if orig.status_code == mod.status_code and len(orig.text) != len(mod.text):
                        highlight(f"  {c('Y','[~]')} Possible boolean-based SQLi: {name}={payload}")
            except: pass
    
    if found_sqli:
        warn(f"Potential SQL injection found: {len(found_sqli)}")
    else:
        info("No obvious SQL injection detected")

def mod_lfi():
    url = inp("Target URL with param (e.g. http://site.com?file=)")
    if not url: return
    
    step("LFI Scanner (Local File Inclusion)")
    info(f"Target: {url}")
    
    payloads = [
        '/etc/passwd',
        '../etc/passwd',
        '....//....//etc/passwd',
        '../../etc/passwd',
        '/etc/hosts',
        '../etc/hosts',
        '/proc/self/environ',
        '/proc/cmdline',
        '/proc/version',
        '..%2F..%2Fetc%2Fpasswd',
    ]
    
    parsed = urllib.parse.urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    params = dict(urllib.parse.parse_qsl(parsed.query))
    
    if not params:
        warn("No parameters found")
        return
    
    for name, val in params.items():
        info(f"Testing param: {name}")
        for payload in payloads:
            try:
                test_params = {name: payload}
                r = requests.get(base, params=test_params, timeout=5)
                
                if 'root:x:' in r.text or '/bin/' in r.text:
                    highlight(f"  {c('R','[!]')} LFI FOUND: {name}={payload}")
                    highlight(f"      /etc/passwd content leaked!")
                elif any(x in r.text.lower() for x in ['localhost', 'hostname', 'amazon']):
                    highlight(f"  {c('Y','[~]')} LFI Possible: {name}={payload}")
            except: pass
    
    ok("LFI scan complete")

def mod_cmd_injection():
    url = inp("Target URL with param (e.g. http://site.com?cmd=)")
    if not url: return
    
    step("Command Injection Scanner")
    info(f"Target: {url}")
    
    payloads = [
        ';whoami', '|whoami', '&&whoami',
        ';id', '|id', '&&id',
        ';ls', '|ls', '&&ls',
        ';cat /etc/passwd', '|cat /etc/passwd',
        '`whoami`', '$(whoami)',
    ]
    
    indicators = ['root:', 'uid=', 'bin/', 'total ', '/home/']
    
    parsed = urllib.parse.urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    params = dict(urllib.parse.parse_qsl(parsed.query))
    
    if not params:
        warn("No parameters found")
        return
    
    for name, val in params.items():
        info(f"Testing param: {name}")
        for payload in payloads:
            try:
                test_params = {name: payload}
                r = requests.get(base, params=test_params, timeout=5)
                resp = r.text.lower()
                
                if any(ind in resp for ind in indicators):
                    highlight(f"  {c('R','[!]')} COMMAND INJECTION: {name}={payload}")
                    highlight(f"      Command output leaked!")
            except: pass
    
    ok("Command injection scan complete")

def mod_open_redirect():
    url = inp("Target URL with param (e.g. http://site.com?redirect=)")
    if not url: return
    
    step("Open Redirect Scanner")
    info(f"Target: {url}")
    
    payloads = [
        '//google.com',
        '///google.com',
        'https://google.com',
        'javascript:alert(1)',
        'data:text/html,<script>alert(1)</script>',
    ]
    
    parsed = urllib.parse.urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    params = dict(urllib.parse.parse_qsl(parsed.query))
    
    if not params:
        warn("No parameters found")
        return
    
    for name, val in params.items():
        info(f"Testing param: {name}")
        for payload in payloads:
            try:
                test_params = {name: payload}
                r = requests.get(base, params=test_params, timeout=5, allow_redirects=False)
                loc = r.headers.get('Location', '')
                
                if loc and ('google' in loc.lower() or loc.startswith('//') or 'javascript' in loc):
                    highlight(f"  {c('R','[!]')} OPEN REDIRECT: {name}={payload[:40]}")
                    highlight(f"      Redirects to: {loc[:60]}")
            except: pass
    
    ok("Open redirect scan complete")

def mod_ssti():
    url = inp("Target URL with param (e.g. http://site.com?tpl=)")
    if not url: return
    
    step("SSTI Scanner (Server Side Template Injection)")
    info(f"Target: {url}")
    
    payloads = [
        '{{7*7}}',
        '${7*7}',
        '<%= 7*7 %>',
        '{{config}}',
        '{{request}}',
        '{7*7}',
        '*a*a*a*',
    ]
    
    parsed = urllib.parse.urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    params = dict(urllib.parse.parse_qsl(parsed.query))
    
    if not params:
        warn("No parameters found")
        return
    
    for name, val in params.items():
        info(f"Testing param: {name}")
        for payload in payloads:
            try:
                test_params = {name: payload}
                r = requests.get(base, params=test_params, timeout=5)
                
                # Check for template evaluation
                checks = [('49', 'Jinja2/Twig'), ('7777777', 'ERB'), ('{{config}}', 'Angular')]
                for check, engine in checks:
                    if check in r.text:
                        highlight(f"  {c('R','[!]')} SSTI FOUND: {name}={payload}")
                        highlight(f"      Template engine: {engine}")
            except: pass
    
    ok("SSTI scan complete")

def mod_cors():
    domain = inp("Target domain")
    if not domain: return
    if not domain.startswith('http'):
        domain = f"http://{domain}"
    
    step("CORS Misconfiguration Check")
    info(f"Target: {domain}")
    
    try:
        r = requests.get(domain, timeout=10)
        
        acao = r.headers.get('Access-Control-Allow-Origin', 'Not Set')
        acac = r.headers.get('Access-Control-Allow-Credentials', 'Not Set')
        acah = r.headers.get('Access-Control-Allow-Headers', 'Not Set')
        acam = r.headers.get('Access-Control-Allow-Methods', 'Not Set')
        
        print(f"\n  {c('W','Access-Control-Allow-Origin:')} {acao}")
        print(f"  {c('W','Access-Control-Allow-Credentials:')} {acac}")
        print(f"  {c('W','Access-Control-Allow-Headers:')} {acah}")
        print(f"  {c('W','Access-Control-Allow-Methods:')} {acam}")
        
        if acao == '*':
            no("VULNERABLE: CORS allows all origins (*)")
        elif acao == 'null':
            warn("VULNERABLE: CORS allows null origin")
        elif acac.lower() == 'true' and acao != domain:
            no(f"VULNERABLE: Credentials allowed with origin: {acao}")
        else:
            ok("CORS configuration appears safe")
            
    except Exception as e:
        error(f"Error: {e}")

def mod_whois():
    domain = inp("Target domain")
    if not domain: return
    
    step("WHOIS Lookup")
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
        if w.updated_date:
            result(f"Updated: {w.updated_date}")
        if w.name_servers:
            print(f"\n  {c('BOLD','Name Servers:')}")
            for ns in (w.name_servers or [])[:8]:
                result(f"    - {ns}")
        if w.registrant:
            print(f"\n  {c('BOLD','Registrant:')}")
            for k, v in w.registrant.__dict__.items():
                if v:
                    result(f"    {k}: {v}")
        ok("WHOIS lookup complete")
    except Exception as e:
        error(f"WHOIS error: {e}")

def mod_ip_lookup():
    ip = inp("IP Address")
    if not ip: return
    
    step("IP Geolocation Lookup")
    info(f"Target: {ip}")
    
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,"
            f"region,city,isp,org,as,lat,lon,timezone",
            timeout=10
        )
        data = r.json()
        
        if data.get('status') == 'success':
            fields = [
                ('IP', 'query'), ('Country', 'country'), ('Code', 'countryCode'),
                ('Region', 'regionName'), ('City', 'city'), ('ISP', 'isp'),
                ('Org', 'org'), ('AS', 'as'), ('Coords', 'lat,lon'),
                ('Timezone', 'timezone')
            ]
            for label, key in fields:
                if key == 'lat,lon':
                    result(f"  {label}: {data.get('lat')}, {data.get('lon')}")
                else:
                    result(f"  {label}: {data.get(key, 'N/A')}")
            ok("IP lookup complete")
        else:
            error("IP lookup failed")
    except Exception as e:
        error(f"Error: {e}")

def mod_reverse_dns():
    ip = inp("IP Address")
    if not ip: return
    
    step("Reverse DNS Lookup")
    info(f"Target: {ip}")
    
    try:
        host, aliases, addrs = socket.gethostbyaddr(ip)
        highlight(f"Hostname: {host}")
        for alias in aliases:
            result(f"Alias: {alias}")
        for addr in addrs:
            result(f"Address: {addr}")
        ok("Reverse DNS complete")
    except Exception as e:
        error(f"No reverse DNS: {e}")

def mod_port_scan():
    domain = inp("Target domain or IP")
    if not domain: return
    
    step("Port Scan")
    info(f"Target: {domain}")
    
    info("Scanning common ports...")
    
    common = {
        21:'FTP', 22:'SSH', 23:'Telnet', 25:'SMTP', 53:'DNS',
        80:'HTTP', 110:'POP3', 143:'IMAP', 443:'HTTPS',
        445:'SMB', 465:'SMTPS', 587:'SMTP-TLS', 993:'IMAPS',
        995:'POP3S', 1433:'MSSQL', 1521:'Oracle', 3306:'MySQL',
        3389:'RDP', 5432:'PostgreSQL', 5900:'VNC', 6379:'Redis',
        8080:'HTTP-Alt', 8443:'HTTPS-Alt', 9200:'Elasticsearch',
        27017:'MongoDB', 11211:'Memcached'
    }
    
    try:
        ip = socket.gethostbyname(domain) if not is_valid_ip(domain) else domain
        info(f"Resolved: {ip}")
    except:
        ip = domain
    
    open_ports = []
    for port, svc in common.items():
        try:
            sock = socket.socket()
            sock.settimeout(1)
            if sock.connect_ex((ip, port)) == 0:
                open_ports.append((port, svc))
                highlight(f"  {c('G','OPEN')} {port}/tcp → {svc}")
            sock.close()
        except: pass
    
    ok(f"Scan complete. {len(open_ports)} open ports found.")

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except: return False

def mod_s3_bucket():
    domain = inp("Target domain")
    if not domain: return
    
    step("S3 Bucket Finder")
    info(f"Target: {domain}")
    
    names = [
        domain.replace('.', '-'),
        domain.replace('.', ''),
        f"{domain.replace('.','')}-dev",
        f"{domain.replace('.','')}-prod",
        f"{domain.replace('.','')}-staging",
        f"{domain.replace('.','')}-backup",
        f"{domain.replace('.','')}-static",
        'www', 'assets', 'cdn', 'files', 'media', 'img'
    ]
    
    info(f"Testing {len(names)} bucket names...")
    
    found = []
    for name in names[:20]:
        try:
            url = f"https://{name}.s3.amazonaws.com"
            r = requests.head(url, timeout=3)
            if r.status_code == 200:
                highlight(f"  {c('G','ACCESSIBLE')} {name}.s3.amazonaws.com")
                found.append(name)
            elif r.status_code == 403:
                result(f"  {c('Y','~')} {name}.s3.amazonaws.com (Forbidden - exists)")
        except: pass
    
    ok(f"Bucket scan complete. {len(found)} accessible buckets.")

def mod_wayback():
    domain = inp("Target domain")
    if not domain: return
    
    step("Wayback Machine URL Discovery")
    info(f"Target: {domain}")
    
    try:
        url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&limit=50"
        r = requests.get(url, timeout=15)
        
        if r.status_code == 200:
            try:
                data = r.json()
                if len(data) > 1:
                    info(f"Found {len(data)-1} historical URLs")
                    for row in data[1:]:
                        if row and row[0]:
                            highlight(f"  {c('C','↗')} {row[0][:80]}")
                else:
                    info("No archived URLs found")
            except:
                error("Failed to parse Wayback response")
        else:
            error(f"Wayback API error: {r.status_code}")
    except Exception as e:
        error(f"Error: {e}")

def mod_js_scan():
    domain = inp("Target domain")
    if not domain: return
    if not domain.startswith('http'):
        domain = f"http://{domain}"
    
    step("JavaScript Security Scanner")
    info(f"Target: {domain}")
    
    try:
        r = requests.get(domain, timeout=10, verify=False)
        
        js_files = re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', r.text)
        info(f"Found {len(js_files)} JS files")
        
        secret_patterns = {
            'AWS Key': r'AKIA[0-9A-Z]{16}',
            'Google API': r'AIza[0-9A-Za-z\-_]{35}',
            'Slack Token': r'xox[baprs]-[0-9a-zA-Z\-]+',
            'GitHub Token': r'gh[pousr]_[A-Za-z0-9_]{36,255}',
            'Generic Secret': r'["\'][a-zA-Z0-9_-]{20,}["\'][^"\']{0,20}["\'][a-zA-Z0-9_-]{20,}["\']',
            'Bearer Token': r'[Bb]earer\s+[0-9a-zA-Z_\-\.]+',
            'Basic Auth': r'[Bb]asic\s+[A-Za-z0-9+/=]+',
        }
        
        for js_url in js_files[:10]:
            full_url = js_url if js_url.startswith('http') else domain.rstrip('/') + '/' + js_url.lstrip('/')
            try:
                jr = requests.get(full_url, timeout=5, verify=False)
                
                for name, pattern in secret_patterns.items():
                    matches = re.findall(pattern, jr.text)
                    if matches:
                        for m in matches[:3]:
                            highlight(f"  {c('R','[!]')} {name} in {js_url[:50]}")
                            highlight(f"      Match: {str(m)[:80]}")
            except: pass
        
        ok("JS scan complete")
    except Exception as e:
        error(f"Error: {e}")

def mod_cms():
    domain = inp("Target domain")
    if not domain: return
    if not domain.startswith('http'):
        domain = f"http://{domain}"
    
    step("CMS & Technology Detection")
    info(f"Target: {domain}")
    
    try:
        r = requests.get(domain, timeout=10, verify=False)
        content = r.text.lower()
        headers = dict(r.headers)
        
        cms_map = {
            'WordPress': ['wp-content','wp-includes','wordpress','wp-json'],
            'Joomla': ['joomla', '/media/jui/', 'option=com'],
            'Drupal': ['drupal', 'sites/default'],
            'Laravel': ['laravel_session', 'XSRF-TOKEN', 'laravel'],
            'React': ['react', '__next/static', '__NEXT_DATA__'],
            'Vue': ['vue', '__nuxt'],
            'Next.js': ['_next/static', '__NEXT_DATA__'],
            'Django': ['csrftoken', 'django'],
            'Angular': ['ng-component', '@angular'],
            'Flask': ['flask', '__PYTHONSTARTUP__'],
            'Express': ['express', 'node_modules/express'],
        }
        
        found_cms = []
        for cms, sigs in cms_map.items():
            if any(s in content for s in sigs):
                found_cms.append(cms)
                highlight(f"  {c('G','+')} {cms}")
        
        if not found_cms:
            info("No common CMS detected")
        
        # Security headers
        print(f"\n  {c('BOLD','Security Headers:')}")
        sec = ['X-Frame-Options','X-Content-Type-Options','Strict-Transport-Security',
               'Content-Security-Policy','X-XSS-Protection','Referrer-Policy']
        for h in sec:
            if h in headers:
                ok(f"  {h}: Present")
            else:
                no(f"  {h}: MISSING")
        
        # Server
        if 'Server' in headers:
            result(f"  Server: {headers['Server']}")
        
        ok("CMS detection complete")
    except Exception as e:
        error(f"Error: {e}")

def mod_amass():
    domain = inp("Target domain")
    if not domain: return
    
    step("Amass Subdomain Enumeration")
    info(f"Target: {domain}")
    
    if not check_tool('amass', 'amass enum -version'):
        error("Amass not installed. Install: https://github.com/owasp-amass/amass")
        return
    
    info("Running amass (passive mode)...")
    info("This may take a few minutes...")
    
    out_file = OUTPUT_DIR / f"amass_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    
    try:
        cmd = f"amass enum -passive -d {domain} -o {out_file}"
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        
        found = []
        for line in iter(proc.stdout.readline, b''):
            l = line.decode().strip()
            if l and '.' in l:
                found.append(l)
                highlight(f"  + {l}")
        
        proc.wait()
        ok(f"Amass found {len(found)} subdomains")
        if out_file.exists():
            ok(f"Results saved: {out_file}")
    except Exception as e:
        error(f"Amass error: {e}")

def mod_dirbust():
    domain = inp("Target domain")
    if not domain: return
    if not domain.startswith('http'):
        domain = f"http://{domain}"
    
    step("Directory Busting")
    info(f"Target: {domain}")
    
    dirs = ['admin','login','dashboard','api','backup','wp-admin','admin.php',
            'administrator','phpmyadmin','server-status','.env','.git',
            '.htaccess','robots.txt','sitemap.xml','actuator','env',
            'config','api/v1','console','status','health','swagger',
            'api-docs','v1/api','v2/api','graphql','debug','trace',
            'env.bak','config.bak','database.sql','backup.sql',
            '.well-known/security.txt','CFIDE','jmx-console','web-console']
    
    info(f"Testing {len(dirs)} common paths...")
    
    found = []
    for d in dirs:
        try:
            r = requests.head(f"{domain.rstrip('/')}/{d}", timeout=3, allow_redirects=False)
            if r.status_code == 200:
                highlight(f"  {c('G','+')} /{d} (200 OK)")
                found.append(f"/{d}")
            elif r.status_code in (301,302,307,308):
                loc = r.headers.get('Location','')
                result(f"  {c('Y','~')} /{d} -> {r.status_code} ({loc[:40]})")
        except: pass
    
    ok(f"Directory busting complete. Found {len(found)} accessible paths.")

# ─── Utilities ─────────────────────────────────────────────────────────────

def util_hash():
    step("Hash Generator")
    text = inp("Text to hash")
    if not text: return
    
    print(f"\n  {c('BOLD','Hash Results:')}")
    print(f"  MD5:    {hashlib.md5(text.encode()).hexdigest()}")
    print(f"  SHA1:   {hashlib.sha1(text.encode()).hexdigest()}")
    print(f"  SHA256: {hashlib.sha256(text.encode()).hexdigest()}")
    print(f"  SHA512: {hashlib.sha512(text.encode()).hexdigest()}")

def util_base64():
    step("Base64 Encode/Decode")
    print(f"  {c('W','1.')} Encode")
    print(f"  {c('W','2.')} Decode")
    opt = inp_int("Option", 1, 2)
    text = inp("Text")
    if not text: return
    
    if opt == 1:
        highlight(f"Encoded: {base64.b64encode(text.encode()).decode()}")
    else:
        try:
            highlight(f"Decoded: {base64.b64decode(text.encode()).decode()}")
        except:
            error("Invalid base64")

def util_url():
    step("URL Encode/Decode")
    print(f"  {c('W','1.')} Encode")
    print(f"  {c('W','2.')} Decode")
    opt = inp_int("Option", 1, 2)
    text = inp("Text")
    if not text: return
    
    if opt == 1:
        highlight(f"Encoded: {urllib.parse.quote(text)}")
    else:
        try:
            highlight(f"Decoded: {urllib.parse.unquote(text)}")
        except:
            error("Invalid URL encoding")

# ─── Main Menu ─────────────────────────────────────────────────────────────

def main_menu():
    clear()
    banner()
    print("""
    \033[1m┌────────────────────────────────────────────────────────────────┐\033[0m
    │  \033[92m1.\033[0m AUTO RECON     - Full automation, just input URL           \033[1m│\033[0m
    │  \033[92m2.\033[0m Subdomain     - Amass + Subfinder + Wordlist           \033[1m│\033[0m
    │  \033[92m3.\033[0m Nuclei Scan   - Template-based vulnerability scanner    \033[1m│\033[0m
    │  \033[92m4.\033[0m SQLMap        - SQL Injection scanner                   \033[1m│\033[0m
    │  \033[92m5.\033[0m FFUF          - Directory/content fuzzing                \033[1m│\033[0m
    │  \033[92m6.\033[0m CVE Search    - NVD database (keyword, year, ID)       \033[1m│\033[0m
    │  \033[92m7.\033[0m Vuln Scan     - XSS, SQLi, SSRF, LFI, Cmd Inj, SSTI    \033[1m│\033[0m
    │  \033[92m8.\033[0m Lookup        - WHOIS, IP, Reverse DNS, CMS            \033[1m│\033[0m
    │  \033[92m9.\033[0m Web Scan      - Crawl, JS, S3, Wayback, Dirbust       \033[1m│\033[0m
    │  \033[92m10\033[0m Utils        - Hash, Base64, URL encode/decode        \033[1m│\033[0m
    │  \033[93m0.\033[0m Exit          - Quit                                    \033[1m│\033[0m
    \033[1m└────────────────────────────────────────────────────────────────┘\033[0m
    """)

def vuln_menu():
    clear()
    step("VULNERABILITY SCANNERS")
    print("""  \033[97m\033[1m┌───────────────────────────────────────────────────────┐\033[0m\033[97m
  \033[97m│\033[0m  \033[92m1.\033[0m XSS Scanner          \033[90m—\033[0m Cross-Site Scripting          \033[97m│\033[0m
  \033[97m│\033[0m  \033[92m2.\033[0m SQL Injection        \033[90m—\033[0m SQLi detection                 \033[97m│\033[0m
  \033[97m│\033[0m  \033[92m3.\033[0m SSRF Scanner         \033[90m—\033[0m Server-Side Request Forgery   \033[97m│\033[0m
  \033[97m│\033[0m  \033[92m4.\033[0m LFI Scanner          \033[90m—\033[0m Local File Inclusion          \033[97m│\033[0m
  \033[97m│\033[0m  \033[92m5.\033[0m Command Injection    \033[90m—\033[0m OS command execution          \033[97m│\033[0m
  \033[97m│\033[0m  \033[92m6.\033[0m Open Redirect        \033[90m—\033[0m URL redirection vulnerability \033[97m│\033[0m
  \033[97m│\033[0m  \033[92m7.\033[0m SSTI Scanner         \033[90m—\033[0m Template injection             \033[97m│\033[0m
  \033[97m│\033[0m  \033[92m8.\033[0m CORS Misconfig       \033[90m—\033[0m CORS vulnerability check      \033[97m│\033[0m
  \033[97m│\033[0m  \033[93m0.\033[0m Back to Main Menu                                \033[97m│\033[0m
  \033[97m\033[1m└───────────────────────────────────────────────────────┘\033[0m
""")

def lookup_menu():
    clear()
    step("LOOKUP TOOLS")
    print(""""
    [1] WHOIS Lookup         - Domain registration info
    [2] IP Geolocation       - IP location lookup
    [3] Reverse DNS        - IP to hostname
    [4] Port Scan           - Common port scanner
    [5] CMS Detection      - WordPress, Laravel, etc.
    [0] Back to Main Menu
""")
def web_menu():
    clear()
    step("WEB SCANNER")
    print("""
  [1] Directory Busting    - Common path discovery
  [2] S3 Bucket Finder    - AWS bucket enumeration
  [3] Wayback URLs        - Historical URL discovery
  [4] JS Security Scan    - Secrets in JS files
  [5] Subdomain Enum      - All subdomain methods
  [0] Back to Main Menu
""")

def utils_menu():
    clear()
    step("ENCODING & HASHING UTILS")
    print("""
  [1] Hash Generator       - MD5, SHA1, SHA256, SHA512
  [2] Base64 Encode/Decode - Base64 tool
  [3] URL Encode/Decode   - URL encoding tool
  [0] Back to Main Menu
""")

def main():
    # Check deps
    try:
        import requests, whois
    except ImportError as e:
        print(f"{c('R',f'[!] Missing: {e}')}")
        print(f"{c('Y','[*] Install: pip install requests python-whois')}")
        sys.exit(1)
    
    # Auto mode from args
    if len(sys.argv) > 1:
        domain = None
        args = sys.argv[1:]
        
        # Parse -t flag
        if '-t' in args:
            idx = args.index('-t')
            domain = args[idx+1] if idx+1 < len(args) else None
        
        # Single arg (domain)
        if not domain and args and not args[0].startswith('-'):
            domain = args[0]
        
        if domain:
            auto_recon(domain)
            return
        
        # CLI flags
        if '--check' in args:
            check_tools()
            return
        
        print(f"{c('Y','Usage:')}")
        print(f"  Interactive: python3 engine.py")
        print(f"  Auto recon:  python3 engine.py -t example.com")
        print(f"  Check tools: python3 engine.py --check")
        return
    
    # Interactive mode
    while True:
        main_menu()
        opt = inp_int("Select", 0, 10)
        
        if opt == 0:
            clear()
            print(f"\n  {c('C','Goodbye! Stay safe. 🛡️')}\n")
            break
        
        elif opt == 1:
            clear()
            banner()
            domain = inp("Target URL (e.g. example.com or https://example.com)")
            if domain:
                auto_recon(domain)
                pause()
        
        elif opt == 2:
            mod_amass() if check_tool('amass', 'amass enum -version') else mod_subdomains()
            pause()
        
        elif opt == 3:
            mod_nuclei()
            pause()
        
        elif opt == 4:
            mod_sqlmap()
            pause()
        
        elif opt == 5:
            mod_ffuf()
            pause()
        
        elif opt == 6:
            mod_cve()
            pause()
        
        elif opt == 7:
            while True:
                vuln_menu()
                v_opt = inp_int("Select", 0, 8)
                if v_opt == 0: break
                if v_opt == 1: mod_xss()
                elif v_opt == 2: mod_sqli()
                elif v_opt == 3: mod_ssrf()
                elif v_opt == 4: mod_lfi()
                elif v_opt == 5: mod_cmd_injection()
                elif v_opt == 6: mod_open_redirect()
                elif v_opt == 7: mod_ssti()
                elif v_opt == 8: mod_cors()
                pause()
        
        elif opt == 8:
            while True:
                lookup_menu()
                l_opt = inp_int("Select", 0, 5)
                if l_opt == 0: break
                if l_opt == 1: mod_whois()
                elif l_opt == 2: mod_ip_lookup()
                elif l_opt == 3: mod_reverse_dns()
                elif l_opt == 4: mod_port_scan()
                elif l_opt == 5: mod_cms()
                pause()
        
        elif opt == 9:
            while True:
                web_menu()
                w_opt = inp_int("Select", 0, 5)
                if w_opt == 0: break
                if w_opt == 1: mod_dirbust()
                elif w_opt == 2: mod_s3_bucket()
                elif w_opt == 3: mod_wayback()
                elif w_opt == 4: mod_js_scan()
                elif w_opt == 5: mod_amass() if check_tool('amass', 'amass enum -version') else mod_subdomains()
                pause()
        
        elif opt == 10:
            while True:
                utils_menu()
                u_opt = inp_int("Select", 0, 3)
                if u_opt == 0: break
                if u_opt == 1: util_hash()
                elif u_opt == 2: util_base64()
                elif u_opt == 3: util_url()
                pause()

if __name__ == '__main__':
    main()
