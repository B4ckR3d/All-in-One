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
| Subdomain Enum | DNS enumeration with 100+ wordlist |
| DNS Records | A, AAAA, MX, TXT, NS, CNAME, SOA |
| Port Scan | Common ports + extended range |
| HTTP Probe | Endpoint discovery + tech detection |
| CORS Check | Misconfiguration scanner |
| SSL Info | Certificate analysis |
| WHOIS Lookup | Domain registration info |
| Security Headers | X-Frame-Options, CSP, HSTS, etc. |
| Tech Detection | WordPress, Laravel, React, etc. |
| Directory Busting | Common path discovery |

### CVE Search
- Search by **Year** (e.g., 2024 CVEs)
- Search by **Keyword** (e.g., "xss", "sql injection")
- Search by **CVE ID** (e.g., CVE-2024-1234)
- Real-time data from **NVD (National Vulnerability Database)**

### Vulnerability Scanners
- **XSS** — Cross-Site Scripting detection
- **SQLi** — SQL Injection detection
- **SSRF** — Server-Side Request Forgery
- **Open Redirect** — Redirect vulnerability

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

# Run CLI
python3 backend/core/engine.py -t example.com --recon
python3 backend/core/engine.py --cve --year 2024 --keyword xss
python3 backend/core/engine.py --whois -t example.com

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
│   ├── main.py                 # FastAPI server
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   └── app/
│   │       └── page.tsx       # Next.js dashboard
│   └── package.json
├── cli/
│   └── run.sh                  # CLI launcher
├── docs/
│   └── README.md
└── README.md
```

---

## 🔧 Configuration

### Environment Variables

```bash
# Backend (optional)
NEXT_PUBLIC_API_URL=http://localhost:8000

# Python dependencies
requests>=2.31.0
urllib3>=2.0.0
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

## 🛡️ Disclaimer

This toolkit is for **authorized security testing** and **educational purposes** only. Do not use against systems without explicit permission.

---

## 📝 License

MIT License - See LICENSE file for details.
