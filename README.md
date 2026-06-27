# All-in-One Security Toolkit v3.0

> **Recon • Scanner • CVE • Lookup** — Advanced security reconnaissance framework with AUTO RECON — just input URL, everything runs automatically.

![Version](https://img.shields.io/badge/version-3.0-blue) ![Python](https://img.shields.io/badge/Python-3.8+-green) ![License](https://img.shields.io/badge/License-MIT-red)

---

## ⚡ AUTO RECON (Just Input URL!)

```
$ python3 backend/core/engine.py
→ Select: 1 (AUTO RECON)
→ Input URL: target.com
→ DONE! Everything runs automatically
```

**Auto Recon executes in sequence:**
1. Subdomain enumeration (Amass + Subfinder + wordlist)
2. Port scanning (Top 1000 ports via nmap)
3. Screenshot all discovered subdomains
4. Nuclei vulnerability scan on all targets
5. SQLMap scan on all in-scope targets
6. FFUF directory fuzzing
7. Wayback Machine URL extraction
8. CMS detection + technology fingerprinting
9. Full vulnerability scan (XSS, SQLi, SSRF, LFI, SSTI)
10. SSL/TLS analysis
11. CORS misconfiguration check
12. JS endpoint extraction
13. CVE correlation based on detected technologies

---

## 🎯 Main Menu

```
╔═══════════════════════════════════════════════════════════════════════════════╗
║   v3.0 - PUKI AI AGENT - AUTO RECON + NUCLEI + SQLMAP + FFUF + AMASS        ║
╚═══════════════════════════════════════════════════════════════════════════════╝

  ┌────────────────────────────────────────────────────────────────┐
  │  1. AUTO RECON     - Full automation, just input URL           │
  │  2. Subdomain     - Amass + Subfinder + Wordlist           │
  │  3. Nuclei Scan   - Template-based vulnerability scanner    │
  │  4. SQLMap        - SQL Injection scanner                   │
  │  5. FFUF          - Directory/content fuzzing                │
  │  6. CVE Search    - NVD database (keyword, year, ID)       │
  │  7. Vuln Scan     - XSS, SQLi, SSRF, LFI, Cmd Inj, SSTI    │
  │  8. Lookup        - WHOIS, IP, Reverse DNS, CMS            │
  │  9. Web Scan      - Crawl, JS, S3, Wayback, Dirbust       │
  │ 10. Utils        - Hash, Base64, URL encode/decode        │
  │  0. Exit          - Quit                                    │
  └────────────────────────────────────────────────────────────────┘
```

---

## 🔧 Installation

```bash
# Clone the repo
git clone git@github.com:B4ckR3d/All-in-One.git
cd All-in-One

# Backend dependencies
pip install requests colorama python-whois dnspython mmh3

# Native tools (install via apt/homebrew)
sudo apt install amass nmap ffuf sqlmap    # Kali/Ubuntu
brew install amass nmap ffuf sqlmap        # macOS

# Or use the launcher
chmod +x cli/run.sh
./cli/run.sh
```

---

## 📡 Native Tool Integrations

| Tool | Purpose | Status |
|------|---------|--------|
| **Amass** | Advanced subdomain enumeration | ✅ Integrated |
| **Subfinder** | Passive subdomain discovery | ✅ Integrated |
| **Nuclei** | Template-based vulnerability scanner | ✅ Integrated |
| **Nuclei Templates** | 6000+ vulnerability templates | ✅ Auto-install |
| **SQLMap** | SQL Injection detection & exploitation | ✅ Integrated |
| **FFUF** | Fast web directory/content fuzzer | ✅ Integrated |
| **Nmap** | Port scanning & service detection | ✅ Integrated |
| **Waybacks** | Historical URL discovery | ✅ Integrated |
| **Gau** | Get All URLs from AlienVault OTX | ✅ Integrated |

---

## 🛡️ Vulnerability Scanners

| Module | Description |
|--------|-------------|
| XSS Scanner | Cross-Site Scripting detection |
| SQL Injection | SQL injection vulnerability scanner |
| SSRF Scanner | Server-Side Request Forgery |
| LFI Scanner | Local File Inclusion |
| Command Injection | OS command execution |
| Open Redirect | URL redirection vulnerability |
| SSTI Scanner | Server-Side Template Injection |
| CORS Misconfiguration | CORS security check |

---

## 🔍 Recon Modules

| Module | Description |
|--------|-------------|
| Subdomain Enum | Amass + Subfinder + wordlist |
| Port Scan | Top 1000 ports via nmap |
| S3 Bucket Finder | AWS S3 bucket enumeration |
| Wayback URLs | Historical URL discovery |
| JS Security Scan | Secrets/endpoints in JS files |
| CMS Detection | WordPress, Laravel, React, etc. |
| SSL Deep Scan | Full TLS analysis + heartbleed |
| Subdomain Takeover | CNAME takeover detection |
| Favicon Hash | MMH3 fingerprinting |

---

## 🌐 Lookup Tools

| Module | Description |
|--------|-------------|
| WHOIS Lookup | Domain registration info |
| IP Geolocation | IP location lookup |
| Reverse DNS | IP to hostname |
| Port Scan | Common port scanner |
| CMS Detection | Technology fingerprinting |

---

## 🔑 CVE Search (NVD API)

```bash
# By keyword
python3 backend/core/engine.py
→ Select: 6
→ Select: 1 (keyword)
→ Keyword: xss

# By year
→ Select: 2 (year)
→ Year: 2024

# By CVE ID
→ Select: 4
→ CVE ID: CVE-2024-1234

# By keyword + year
→ Select: 3
→ Keyword: sql injection
→ Year: 2024
```

---

## 📡 API Endpoints

```bash
# Start FastAPI server
cd backend
uvicorn main:app --host 0.0.0.0 --port 8000

# Run scan
POST /api/v1/scan
{"target": "example.com", "modules": ["subdomain", "nuclei"]}

# Get results
GET /api/v1/results/{scan_id}

# CVE search
GET /api/v1/cve?keyword=xss&year=2024
```

---

## 📁 Project Structure

```
All-in-One/
├── backend/
│   ├── core/
│   │   ├── engine.py          # Main CLI engine v3.0
│   │   └── __init__.py
│   ├── modules/
│   │   ├── nuclei_scan.py
│   │   ├── sqlmap_scan.py
│   │   ├── amass_scan.py
│   │   ├── subdomain_enum.py
│   │   ├── port_scan.py
│   │   ├── cors_check.py
│   │   ├── ssl_check.py
│   │   ├── whois_lookup.py
│   │   ├── ip_lookup.py
│   │   ├── cve_search.py
│   │   ├── xss_scan.py
│   │   ├── sqli_scan.py
│   │   ├── s3_bucket.py
│   │   ├── wayback.py
│   │   ├── js_scanner.py
│   │   ├── cms_detector.py
│   │   ├── takeover.py
│   │   ├── favicon.py
│   │   ├── crawl.py
│   │   ├── leak_check.py
│   │   ├── github_recon.py
│   │   ├── ssl_deep.py
│   │   └── bulk_check.py
│   ├── main.py               # FastAPI backend
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── app/
│   │   │   ├── page.tsx      # Main dashboard
│   │   │   ├── layout.tsx
│   │   │   └── globals.css
│   │   └── components/
│   ├── package.json
│   └── next.config.js
├── cli/
│   └── run.sh                # Launcher script
└── README.md
```

---

## 🚀 Quick Start

```bash
# 1. Clone
git clone git@github.com:B4ckR3d/All-in-One.git
cd All-in-One

# 2. Install dependencies
pip install -r backend/requirements.txt

# 3. Run interactive CLI
python3 backend/core/engine.py

# 4. Or use the launcher
chmod +x cli/run.sh && ./cli/run.sh
```

---

## ⚠️ Disclaimer

This toolkit is for **authorized security testing only**. Unauthorized access to computer systems is illegal. Always obtain proper authorization before scanning any target.
