#!/bin/bash
# ═══════════════════════════════════════════════════════════════════
# All-in-One Security Toolkit - CLI Launcher
# ═══════════════════════════════════════════════════════════════════

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
RED='\033[91m'
GREEN='\033[92m'
YELLOW='\033[93m'
BLUE='\033[94m'
CYAN='\033[96m'
BOLD='\033[1m'
RESET='\033[0m'

BANNER="
${CYAN}${BOLD}
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   ██████╗ ██╗   ██╗ ██████╗     ████████╗███████╗███╗   ███╗██████╗ ██╗     ║
║   ██╔══██╗██║   ██║██╔════╝     ╚══██╔══╝██╔════╝████╗ ████║██╔══██╗██║     ║
║   ██████╔╝██║   ██║██║  ███╗       ██║   █████╗  ██╔████╔██║██████╔╝██║     ║
║   ██╔═══╝ ██║   ██║██║   ██║       ██║   ██╔══╝  ██║╚██╔╝██║██╔═══╝ ██║     ║
║   ██║     ╚██████╔╝╚██████╔╝       ██║   ███████╗██║ ╚═╝ ██║██║     ███████╗║
║   ╚═╝      ╚═════╝  ╚═════╝        ╚═╝   ╚══════╝╚═╝     ╚═╝╚═╝     ╚══════╝║
║                                                                              ║
║   ${RESET}${MAGENTA}SECURITY TOOLKIT v2.0.0 - All-in-One Recon & Scanner${RESET}${CYAN}${BOLD}                           ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
${RESET}
"

show_help() {
    echo -e "$BANNER"
    echo -e "${BOLD}Usage:${RESET} $0 [OPTIONS]"
    echo ""
    echo -e "${BOLD}RECON MODULES:${RESET}"
    echo "  -t, --target DOMAIN     Target domain (required for recon)"
    echo "  --recon                 Run basic recon"
    echo "  --recon-all             Run full recon"
    echo "  --deep                  Deep reconnaissance"
    echo "  --subdomains            Enumerate subdomains"
    echo "  --dns                   DNS enumeration"
    echo "  --ports                 Port scanning"
    echo "  --probe                 HTTP endpoint probing"
    echo "  --cors                  CORS check"
    echo "  --ssl                   SSL certificate info"
    echo "  --whois                 WHOIS lookup"
    echo "  --headers               Security headers check"
    echo "  --tech                  Technology detection"
    echo "  --dirbust               Directory busting"
    echo ""
    echo -e "${BOLD}CVE SEARCH:${RESET}"
    echo "  --cve                   CVE search mode"
    echo "  --year YEAR             CVE year (e.g. 2024)"
    echo "  --keyword KEYWORD        CVE keyword"
    echo "  --cve-id CVE-ID          Specific CVE ID"
    echo ""
    echo -e "${BOLD}SCANNER:${RESET}"
    echo "  --scan-xss              XSS scanner"
    echo "  --scan-sqli             SQLi scanner"
    echo "  --scan-ssrf             SSRF scanner"
    echo "  --scan-redirect         Open redirect scanner"
    echo "  --scan-all              Run all scanners"
    echo ""
    echo -e "${BOLD}LOOKUP:${RESET}"
    echo "  --whois                 WHOIS lookup"
    echo "  --ip-lookup             IP geolocation"
    echo "  --reverse-dns           Reverse DNS"
    echo "  --cdn                   CDN detection"
    echo ""
    echo -e "${BOLD}UTILS:${RESET}"
    echo "  --encode-base64 TEXT    Base64 encode"
    echo "  --decode-base64 TEXT    Base64 decode"
    echo "  --url-encode TEXT       URL encode"
    echo "  --url-decode TEXT       URL decode"
    echo "  --hash-md5 TEXT         MD5 hash"
    echo "  --hash-sha256 TEXT      SHA256 hash"
    echo ""
    echo -e "${BOLD}OPTIONS:${RESET}"
    echo "  -v, --verbose           Verbose output"
    echo "  -o, --output FILE       Output JSON file"
    echo "  -h, --help              Show this help"
    echo ""
    echo -e "${BOLD}EXAMPLES:${RESET}"
    echo "  $0 -t example.com --recon"
    echo "  $0 -t example.com --deep"
    echo "  $0 --cve --year 2024 --keyword xss"
    echo "  $0 --scan-xss -t \"https://example.com/?q=test\""
    echo "  $0 --whois -t example.com"
    echo "  $0 --encode-base64 \"hello world\""
}

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: python3 is not installed${RESET}"
    exit 1
fi

# Run the tool
exec python3 "$SCRIPT_DIR/backend/core/engine.py" "$@"
