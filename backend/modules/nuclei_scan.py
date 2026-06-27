"""
Nuclei Scanner - Template-based vulnerability scanner
"""
import subprocess
import json
import os
from pathlib import Path

GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
RESET = '\033[0m'

NUCLEI_TEMPLATES = {
    'cves': 'https://github.com/projectdiscovery/nuclei-templates/raw/main/cves/',
    ' exposures': 'https://github.com/projectdiscovery/nuclei-templates/raw/main/exposed-panels/',
    'vulnerabilities': 'https://github.com/projectdiscovery/nuclei-templates/raw/main/vulnerabilities/',
    'technologies': 'https://github.com/projectdiscovery/nuclei-templates/raw/main/technologies/',
    'default': 'https://github.com/projectdiscovery/nuclei-templates/raw/main/'
}

def run_nuclei(target: str, template_type: str = 'default', verbose: bool = False):
    """Run nuclei scanner"""
    results = []
    print(f"\n{CYAN}[*] Running Nuclei scan on: {target}{RESET}")
    print(f"{YELLOW}[!] Nuclei requires installation: https://github.com/projectdiscovery/nuclei{RESET}")
    
    try:
        cmd = ['nuclei', '-u', target, '-json', '-silent']
        
        if template_type != 'default':
            cmd.extend(['-t', template_type])
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        if result.stdout:
            for line in result.stdout.strip().split('\n'):
                if line:
                    try:
                        data = json.loads(line)
                        results.append(data)
                        severity = data.get('info', {}).get('severity', 'unknown')
                        print(f"{GREEN}[+] [{severity.upper()}] {data.get('matched-at', 'unknown')}{RESET}")
                    except:
                        pass
        
        print(f"{GREEN}[+] Nuclei found {len(results)} issues{RESET}")
        
    except FileNotFoundError:
        print(f"{RED}[!] Nuclei not installed!{RESET}")
        print(f"{CYAN}[*] Install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest{RESET}")
    except subprocess.TimeoutExpired:
        print(f"{RED}[!] Nuclei scan timed out{RESET}")
    except Exception as e:
        print(f"{RED}[!] Nuclei error: {e}{RESET}")
    
    return results

def run_nuclei_with_templates(target: str, templates_dir: str = None, verbose: bool = False):
    """Run nuclei with custom template directory"""
    results = []
    print(f"\n{CYAN}[*] Running Nuclei with templates on: {target}{RESET}")
    
    try:
        cmd = ['nuclei', '-u', target, '-json', '-silent']
        
        if templates_dir and os.path.exists(templates_dir):
            cmd.extend(['-t', templates_dir])
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        if result.stdout:
            for line in result.stdout.strip().split('\n'):
                if line:
                    try:
                        data = json.loads(line)
                        results.append(data)
                    except:
                        pass
        
        print(f"{GREEN}[+] Nuclei found {len(results)} issues{RESET}")
        
    except FileNotFoundError:
        print(f"{RED}[!] Nuclei not installed!{RESET}")
    except Exception as e:
        print(f"{RED}[!] Nuclei error: {e}{RESET}")
    
    return results

def list_template_types():
    """List available nuclei template types"""
    print(f"\n{CYAN}Available Nuclei Template Types:{RESET}")
    for name in NUCLEI_TEMPLATES.keys():
        print(f"  - {name}")

if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        target = sys.argv[1]
        run_nuclei(target)
    else:
        print(f"{RED}[!] Usage: python3 nuclei_scan.py <target>{RESET}")
