# All-in-One Security Toolkit

> **Recon • Scanner • CVE • Lookup** — A comprehensive security reconnaissance and vulnerability scanning toolkit with Next.js dashboard UI.

![Version](https://img.shields.io/badge/version-2.0.0-blue)
![Python](https://img.shields.io/badge/python-3.9+-green)
![Next.js](https://img.shields.io/badge/next.js-14-black)

---

## 🎯 Features

### Recon Modules
| Module | Description |
|--------|-------------|
| Subdomain Enum | DNS enumeration with wordlist |
| DNS Records | A, AAAA, MX, TXT, NS, CNAME, SOA |
| Port Scan | Common ports + extended range |
| HTTP Probe | Endpoint discovery + tech detection |
| CORS Check | CORS misconfiguration scanner |
| SSL Info | Certificate analysis |
| WHOIS Lookup | Domain registration info |
| Security Headers | X-Frame-Options, CSP, HSTS, etc. |
| CMS Detector | WordPress, Laravel, React, Django, etc. |
| Directory Busting | Common path discovery |
| Web Crawler | Extract links, forms, emails, social media |
| Wayback Machine | Historical URL discovery |
| Favicon Hash | MMH3 hash for Shodan integration |

### CVE Search
- Search by **Year** (e.g., 2024 CVEs)
- Search by **Keyword** (e.g., "xss", "sql injection")
- Search by **CVE ID** (e.g., CVE-2024-1234)
- Real-time data from **NVD (National Vulnerability Database)**

### Vulnerability Scanners
| Scanner | Description |
|---------|-------------|
| XSS | Cross-Site Scripting detection |
| SQLi | SQL Injection detection |
| SSRF | Server-Side Request Forgery |
| Open Redirect | Redirect vulnerability |
| Nuclei Scan | Template-based vulnerability scanner |
| Subdomain Takeover | AWS S3, GitHub Pages, Heroku, Netlify, etc. |

### Advanced Recon
| Module | Description |
|--------|-------------|
| S3 Bucket Finder | AWS S3 bucket enumeration |
| GitHub Recon | GitHub dorking, repo discovery |
| JS Scanner | Extract secrets & endpoints from JS files |
| SSL Deep Scan | Full TLS analysis, cipher suites, vulnerabilities |
| IP Lookup | Geolocation, reverse DNS, AS lookup |

### Leak / Breach Check
- **HaveIBeenPwned** password check
- Email breach lookup (requires API key)
- Domain breach enumeration

### Lookup Tools
- **WHOIS** — Domain registration lookup
- **IP Lookup** — Geolocation + ISP info
- **Reverse DNS** — Hostname from IP
- **CDN Detection** — Cloudflare, AWS, Azure, etc.

### Utilities
- Base64 Encode/Decode
- URL Encode/Decode
- MD5, SHA1, SHA256 Hashing
- Hex Encode/Decode

---

## 🚀 Quick Start

### CLI Usage

```bash
# Clone the repo
git clone git@github.com:B4ckR3d/All-in-One.git
cd All-in-One

# Install Python dependencies
pip install -r backend/requirements.txt

# Run recon on target
python3 backend/core/engine.py -t example.com --recon

# Deep recon
python3 backend/core/engine.py -t example.com --deep

# CVE search
python3 backend/core/engine.py --cve --year 2024 --keyword xss

# WHOIS lookup
python3 backend/core/engine.py --whois -t example.com

# Specific modules
python3 backend/core/engine.py -t example.com --subdomains --cors --dns
python3 backend/core/engine.py -t example.com --cms --js-scan
python3 backend/core/engine.py -t example.com --wayback
python3 backend/core/engine.py -t example.com --s3-bucket
python3 backend/core/engine.py -t example.com --ssl-deep
python3 backend/core/engine.py --leak-check --password mysecretpassword

# Or use the launcher
chmod +x cli/run.sh
./cli/run.sh -t example.com --deep
```

### Web UI (Next.js + FastAPI)

```bash
# Terminal 1: Start API
cd backend
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000

# Terminal 2: Start Frontend
cd frontend
npm install
npm run dev

# Open http://localhost:3000
```

---

## 📁 Project Structure

```
All-in-One/
├── backend/
│   ├── core/
│   │   └── engine.py          # Main CLI engine
│   ├── modules/               # All recon modules
│   │   ├── subdomain_enum.py
│   │   ├── dns_enum.py
│   │   ├── port_scan.py
│   │   ├── cors_check.py
│   │   ├── ssl_check.py
│   │   ├── ssl_deep.py
│   │   ├── whois_lookup.py
│   │   ├── cms_detector.py
│   │   ├── js_scanner.py
│   │   ├── crawl.py
│   │   ├── wayback.py
│   │   ├── nuclei_scan.py
│   │   ├── s3_bucket.py
│   │   ├── github_recon.py
│   │   ├── leak_check.py
│   │   ├── takeover.py
│   │   ├── favicon.py
│   │   └── ip_lookup.py
│   └── main.py                 # FastAPI server
├── frontend/
│   └── src/app/
│       └── page.tsx           # Next.js dashboard
├── cli/
│   └── run.sh                  # CLI launcher
└── README.md
```

---

## 🛠️ Installation

### Python Dependencies

```bash
pip install requests urllib3 colorama pydantic python-multipart mmh3
```

### External Tools (Optional)

```bash
# Nuclei (vulnerability scanner)
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Gau (URL collector)
go install github.com/lc/gau@latest

# subfinder (subdomain enumeration)
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# httpx (HTTP probe)
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
```

---

## 📊 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | API info |
| GET | `/health` | Health check |
| POST | `/api/recon` | Start recon scan |
| GET | `/api/recon/{job_id}` | Get recon results |
| POST | `/api/cve` | CVE search |
| POST | `/api/scan` | Start vulnerability scan |
| GET | `/api/scan/{job_id}` | Get scan results |
| POST | `/api/lookup` | WHOIS/IP lookup |
| POST | `/api/utils` | Encode/Decode/Hash |

---

## 🔧 Configuration

### Environment Variables

```bash
# Backend (optional)
NEXT_PUBLIC_API_URL=http://localhost:8000

# Python dependencies
requests>=2.31.0
urllib3>=2.0.0
mmh3>=3.0
```

---

## 🛡️ Disclaimer

This toolkit is for **authorized security testing** and **educational purposes** only. Do not use against systems without explicit permission.

---

## 📝 License

MIT License - See LICENSE file for details.
