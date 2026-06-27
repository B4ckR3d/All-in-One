#!/bin/bash
# ═══════════════════════════════════════════════════════════════════
# All-in-One Security Toolkit v2.0
# Interactive Menu Mode — Just click click, no memorization!
# ═══════════════════════════════════════════════════════════════════

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLKIT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$TOOLKIT_DIR"

# Colors
R='\033[91m'; G='\033[92m'; Y='\033[93m'; C='\033[96m'; W='\033[97m'; BOLD='\033[1m'; RESET='\033[0m'

echo -e "${C}${BOLD}"
echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║  ███████╗ ██████╗  ██████╗ ██████╗ ██╗   ██╗███████╗███████╗██████╗  ║"
echo "║  ██╔════╝██╔═══██╗██╔═══██╗██╔══██╗██║   ██║██╔════╝██╔════╝██╔══██╗ ║"
echo "║  █████╗  ██║   ██║██║   ██║██████╔╝██║   ██║███████╗█████╗  ██████╔╝ ║"
echo "║  ██╔══╝  ██║   ██║██║   ██║██╔══██╗██║   ██║╚════██║██╔══╝  ██╔══██╗ ║"
echo "║  ██║     ╚██████╔╝╚██████╔╝██║  ██║╚██████╔╝███████║███████╗██║  ██║ ║"
echo "║  ╚═╝      ╚═════╝  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝ ║"
echo "║              SECURITY TOOLKIT v2.0 — Interactive Mode               ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"
echo -e "${RESET}"

# Check Python
if ! command -v python3 &> /dev/null; then
    echo -e "${R}[!] Error: python3 is not installed${RESET}"
    exit 1
fi

# Check dependencies
echo -e "${C}[*] Checking dependencies...${RESET}"
python3 -c "import requests; import whois" 2>/dev/null
if [ $? -ne 0 ]; then
    echo -e "${Y}[!] Installing dependencies...${RESET}"
    pip install requests python-whois -q
fi

# Run in interactive mode (no args)
exec python3 "$TOOLKIT_DIR/backend/core/engine.py"
