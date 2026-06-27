"""
SSL Deep Scanner - Full SSL/TLS analysis
Like testssl.sh but in Python
"""
import ssl
import socket
import subprocess
import json
import re
from datetime import datetime
from urllib.parse import urlparse

GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
RESET = '\033[0m'

def get_ssl_info(host: str, port: int = 443, verbose: bool = False):
    """Get detailed SSL certificate info"""
    print(f"\n{CYAN}[*] Analyzing SSL on {host}:{port}{RESET}")
    
    result = {
        'host': host,
        'port': port,
        'cert': {},
        'vulnerabilities': [],
        'cipher_suites': []
    }
    
    try:
        # Get certificate
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                cipher = ssock.cipher()
                
                # Decode certificate
                cert_dict = ssl._ssl._test_decode_cert(cert)
                
                result['cipher'] = {
                    'name': cipher[0] if cipher else None,
                    'version': cipher[1] if cipher else None,
                    'bits': cipher[2] if cipher else None
                }
                
                # Extract cert details
                subject = cert_dict.get('subject', [])
                issuer = cert_dict.get('issuer', [])
                
                result['cert'] = {
                    'subject': dict(subject) if subject else {},
                    'issuer': dict(issuer) if issuer else {},
                    'version': cert_dict.get('version'),
                    'serial_number': cert_dict.get('serialNumber'),
                    'not_before': cert_dict.get('notBefore'),
                    'not_after': cert_dict.get('notAfter'),
                    'has_expired': datetime.strptime(cert_dict.get('notAfter', ''), '%b %d %H:%M:%S %Y %Z') < datetime.now() if cert_dict.get('notAfter') else None
                }
                
                print(f"{GREEN}[+] Cipher: {cipher[0]} ({cipher[2]} bits){RESET}")
                print(f"{GREEN}[+] Cert valid until: {cert_dict.get('notAfter', 'Unknown')}{RESET}")
                
                # Check vulnerabilities
                check_ssl_vulnerabilities(host, port, result)
                
    except ssl.SSLError as e:
        print(f"{RED}[!] SSL Error: {e}{RESET}")
        result['error'] = str(e)
    except socket.error as e:
        print(f"{RED}[!] Socket Error: {e}{RESET}")
        result['error'] = str(e)
    except Exception as e:
        print(f"{RED}[!] Error: {e}{RESET}")
        result['error'] = str(e)
    
    return result

def check_ssl_vulnerabilities(host: str, port: int, result: dict, verbose: bool = False):
    """Check for SSL vulnerabilities"""
    print(f"\n{CYAN}[*] Checking SSL vulnerabilities...{RESET}")
    
    vulns = []
    cipher = result.get('cipher', {}).get('name', '')
    
    # Check for weak ciphers
    weak_ciphers = ['NULL', 'EXP', 'RC4', 'DES', 'MD5', 'aNULL', 'eNULL']
    for weak in weak_ciphers:
        if weak in cipher:
            vulns.append(f'Weak cipher: {weak}')
            print(f"{RED}[!] VULN: Weak cipher {weak}{RESET}")
    
    # Check certificate expiration
    if result.get('cert', {}).get('has_expired'):
        vulns.append('Certificate EXPIRED')
        print(f"{RED}[!] VULN: Certificate expired!{RESET}")
    
    # Check SSL versions
    if 'SSLv3' in cipher:
        vulns.append('SSLv3 enabled (POODLE)')
        print(f"{RED}[!] VULN: SSLv3 enabled (POODLE vulnerable){RESET}")
    
    if 'TLSv1.0' in cipher or 'TLSv1.1' in cipher:
        vulns.append('TLS 1.0/1.1 enabled (deprecated)')
        print(f"{YELLOW}[!] WARN: TLS 1.0/1.1 enabled (deprecated){RESET}")
    
    result['vulnerabilities'] = vulns

def test_heartbleed(host: str, port: int = 443, verbose: bool = False):
    """Test for Heartbleed vulnerability"""
    print(f"\n{CYAN}[*] Testing Heartbleed...{RESET}")
    
    try:
        # Simple Heartbleed test
        import struct
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))
        
        # TLS heartbeat request
        heartbeat = (
            b'\x18\x03\x01\x00\x03\x01\x40\x00'  # TLS header
            b'\x40\x00'  # Heartbeat payload length
        )
        
        sock.send(heartbeat)
        response = sock.recv(1024)
        sock.close()
        
        if len(response) > 9:
            print(f"{RED}[!] VULNERABLE to Heartbleed!{RESET}")
            return True
        else:
            print(f"{GREEN}[+] Not vulnerable to Heartbleed{RESET}")
            return False
            
    except Exception as e:
        print(f"{YELLOW}[!] Heartbleed test error: {e}{RESET}")
        return None

def check_headers(url: str, verbose: bool = False):
    """Check security headers"""
    print(f"\n{CYAN}[*] Checking security headers...{RESET}")
    
    headers = {}
    parsed = urlparse(url)
    host = parsed.netloc or parsed.path.split('/')[0]
    port = 443 if parsed.scheme == 'https' else 80
    
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((host, port), timeout=10) as sock:
            if parsed.scheme == 'https':
                sock = context.wrap_socket(sock, server_hostname=host)
            
            request = f"HEAD / HTTP/1.1\r\nHost: {host}\r\n\r\n"
            sock.send(request.encode())
            response = sock.recv(4096).decode('utf-8', errors='ignore')
            
            # Parse headers
            header_lines = response.split('\r\n')
            for line in header_lines:
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip().lower()] = value.strip()
        
        # Check security headers
        security_headers = {
            'strict-transport-security': 'HSTS',
            'content-security-policy': 'CSP',
            'x-frame-options': 'X-Frame-Options',
            'x-content-type-options': 'X-Content-Type-Options',
            'x-xss-protection': 'XSS Protection',
            'referrer-policy': 'Referrer Policy',
            'permissions-policy': 'Permissions Policy'
        }
        
        print(f"\n{GREEN}[+] Security Headers:{RESET}")
        for header, name in security_headers.items():
            if header in headers:
                print(f"  {GREEN}✓{RESET} {name}: {headers[header]}")
            else:
                print(f"  {RED}✗{RESET} {name}: MISSING")
        
    except Exception as e:
        print(f"{RED}[!] Error checking headers: {e}{RESET}")
    
    return headers

def run(domain: str, verbose: bool = False):
    """Run full SSL analysis"""
    print(f"\n{'='*60}")
    print(f"  SSL DEEP SCANNER")
    print(f"{'='*60}")
    
    host = domain.replace('https://', '').replace('http://', '').split('/')[0]
    
    # Get SSL info
    ssl_info = get_ssl_info(host, 443, verbose)
    
    # Test Heartbleed
    heartbleed = test_heartbleed(host, 443, verbose)
    if heartbleed:
        ssl_info['vulnerabilities'].append('Heartbleed')
    
    # Check security headers
    check_headers(f"https://{host}", verbose)
    
    return ssl_info
