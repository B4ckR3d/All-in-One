#!/usr/bin/env python3
"""
FastAPI Backend - All-in-One Security Toolkit API
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import json
import asyncio
import sys
import os

# Add backend to path
sys.path.insert(0, os.path.dirname(__file__))

from core.engine import (
    Recon, Scanner, Lookup, Utils, Logger,
    search_cve, http_get, SUBDOMAIN_WORDLIST, BANNER
)

app = FastAPI(
    title="All-in-One Security Toolkit API",
    description="Recon • Scanner • CVE • Lookup",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory job storage
jobs = {}

# ═══════════════════════════════════════════════════════════════════
# REQUEST/RESPONSE MODELS
# ═══════════════════════════════════════════════════════════════════
class ReconRequest(BaseModel):
    target: str
    subdomains: bool = True
    dns: bool = True
    ports: bool = False
    probe: bool = True
    cors: bool = True
    ssl: bool = True
    whois: bool = True
    headers: bool = True
    tech: bool = True
    dirbust: bool = False
    deep: bool = False

class ScanRequest(BaseModel):
    target: str
    type: List[str] = ["xss"]  # xss, sqli, ssrf, redirect

class LookupRequest(BaseModel):
    target: str
    type: str = "whois"  # whois, ip, reverse-dns, cdn

class CVERequest(BaseModel):
    cve_id: Optional[str] = None
    year: Optional[int] = None
    keyword: Optional[str] = None
    limit: int = 50

class UtilsRequest(BaseModel):
    action: str  # encode64, decode64, urlencode, urldecode, hash-md5, hash-sha256, hex-encode, hex-decode
    value: str

# ═══════════════════════════════════════════════════════════════════
# UTILITY ENDPOINTS
# ═══════════════════════════════════════════════════════════════════
@app.get("/")
async def root():
    return {
        "name": "All-in-One Security Toolkit API",
        "version": "2.0.0",
        "modules": ["recon", "scanner", "cve", "lookup", "utils"]
    }

@app.get("/health")
async def health():
    return {"status": "healthy"}

@app.post("/api/utils")
async def utils(req: UtilsRequest):
    logger = Logger(quiet=True)
    util = Utils(logger)
    
    actions = {
        'encode64': lambda v: util.encode_base64(v),
        'decode64': lambda v: util.decode_base64(v),
        'urlencode': lambda v: util.url_encode(v),
        'urldecode': lambda v: util.url_decode(v),
        'hash-md5': lambda v: util.hash_md5(v),
        'hash-sha1': lambda v: util.hash_sha1(v),
        'hash-sha256': lambda v: util.hash_sha256(v),
        'hex-encode': lambda v: util.hex_encode(v),
        'hex-decode': lambda v: util.hex_decode(v),
    }
    
    if req.action not in actions:
        raise HTTPException(status_code=400, detail=f"Unknown action: {req.action}")
    
    try:
        result = actions[req.action](req.value)
        return {"action": req.action, "input": req.value, "result": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ═══════════════════════════════════════════════════════════════════
# CVE ENDPOINT
# ═══════════════════════════════════════════════════════════════════
@app.post("/api/cve")
async def cve_search(req: CVERequest):
    try:
        results = search_cve(
            query=req.keyword,
            year=req.year,
            cve_id=req.cve_id,
            limit=req.limit
        )
        return {
            "count": len(results),
            "results": results
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ═══════════════════════════════════════════════════════════════════
# LOOKUP ENDPOINTS
# ═══════════════════════════════════════════════════════════════════
@app.post("/api/lookup")
async def lookup(req: LookupRequest):
    logger = Logger(quiet=True)
    lookup_tool = Lookup(logger)
    target = req.target.replace('https://', '').replace('http://', '').strip('/')
    
    try:
        if req.type == "whois":
            result = lookup_tool.whois(target)
            return {"type": "whois", "data": result}
        
        elif req.type == "ip":
            if '.' in target and not target.startswith('http'):
                ip = target
            else:
                import socket
                ip = socket.gethostbyname(target)
            data = lookup_tool.ip_lookup(ip)
            return {"type": "ip_lookup", "ip": ip, "data": data}
        
        elif req.type == "reverse-dns":
            import socket
            if '.' in target and not target.startswith('http'):
                ip = target
            else:
                ip = socket.gethostbyname(target)
            hostname = lookup_tool.reverse_dns(ip)
            return {"type": "reverse_dns", "ip": ip, "hostname": hostname}
        
        elif req.type == "cdn":
            data = lookup_tool.cdn_lookup(target)
            return {"type": "cdn", "data": data}
        
        else:
            raise HTTPException(status_code=400, detail=f"Unknown lookup type: {req.type}")
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ═══════════════════════════════════════════════════════════════════
# RECON ENDPOINT
# ═══════════════════════════════════════════════════════════════════
@app.post("/api/recon")
async def recon(req: ReconRequest, background_tasks: BackgroundTasks):
    import uuid
    job_id = str(uuid.uuid4())[:8]
    
    # Quick validation
    target = req.target.replace('https://', '').replace('http://', '').strip('/')
    if not target:
        raise HTTPException(status_code=400, detail="Invalid target")
    
    async def run_recon():
        logger = Logger(quiet=True)
        
        class Args:
            subdomains = req.subdomains
            dns = req.dns
            ports = req.ports
            probe = req.probe
            cors = req.cors
            ssl = req.ssl
            whois_lookup = req.whois
            headers = req.headers
            tech = req.tech
            dirbust = req.dirbust
            recon_all = req.deep
            port_range = 'common'
        
        recon_tool = Recon(target, logger)
        results = recon_tool.run_all(Args())
        
        import json
        from dataclasses import asdict
        report = asdict(results)
        
        # Store in jobs
        jobs[job_id] = {
            "status": "completed",
            "results": report,
            "target": target
        }
    
    background_tasks.add_task(run_recon)
    
    return {
        "job_id": job_id,
        "status": "running",
        "message": f"Recon started for {req.target}. Check /api/recon/{job_id} for results."
    }

@app.get("/api/recon/{job_id}")
async def get_recon(job_id: str):
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    
    return jobs[job_id]

# ═══════════════════════════════════════════════════════════════════
# SCANNER ENDPOINT
# ═══════════════════════════════════════════════════════════════════
@app.post("/api/scan")
async def scan(req: ScanRequest, background_tasks: BackgroundTasks):
    import uuid
    job_id = str(uuid.uuid4())[:8]
    
    if not req.target.startswith('http'):
        raise HTTPException(status_code=400, detail="Target must be a full URL with params (?q=test)")
    
    async def run_scan():
        logger = Logger(quiet=True)
        scanner = Scanner(req.target, logger)
        
        results = []
        
        if "xss" in req.type:
            results.extend(scanner.scan_xss())
        if "sqli" in req.type:
            results.extend(scanner.scan_sqli())
        if "ssrf" in req.type:
            results.extend(scanner.scan_ssrf())
        if "redirect" in req.type:
            results.extend(scanner.scan_open_redirect())
        
        jobs[job_id] = {
            "status": "completed",
            "results": results,
            "target": req.target,
            "types": req.type
        }
    
    background_tasks.add_task(run_scan)
    
    return {
        "job_id": job_id,
        "status": "running",
        "message": f"Scan started. Check /api/scan/{job_id} for results."
    }

@app.get("/api/scan/{job_id}")
async def get_scan(job_id: str):
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    return jobs[job_id]

# ═══════════════════════════════════════════════════════════════════
# STARTUP
# ═══════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    import uvicorn
    print(BANNER)
    print(f"{GREEN}API Server starting on http://0.0.0.0:8000{RESET}")
    uvicorn.run(app, host="0.0.0.0", port=8000)
