'use client';

import { useState } from 'react';
import { Shield, Search, Bug, Database, Globe, Lock, Terminal, ChevronRight, Zap, AlertTriangle, CheckCircle, XCircle, Loader2 } from 'lucide-react';

type Module = 'dashboard' | 'recon' | 'cve' | 'scanner' | 'lookup' | 'utils';

interface NavItem {
  id: Module;
  label: string;
  icon: React.ReactNode;
  color: string;
}

const navItems: NavItem[] = [
  { id: 'dashboard', label: 'Dashboard', icon: <Shield size={20} />, color: 'text-cyan-400' },
  { id: 'recon', label: 'Recon', icon: <Search size={20} />, color: 'text-blue-400' },
  { id: 'cve', label: 'CVE Search', icon: <Database size={20} />, color: 'text-purple-400' },
  { id: 'scanner', label: 'Scanner', icon: <Bug size={20} />, color: 'text-red-400' },
  { id: 'lookup', label: 'Lookup', icon: <Globe size={20} />, color: 'text-green-400' },
  { id: 'utils', label: 'Utils', icon: <Terminal size={20} />, color: 'text-yellow-400' },
];

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

export default function Home() {
  const [activeModule, setActiveModule] = useState<Module>('dashboard');
  const [output, setOutput] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Recon state
  const [reconTarget, setReconTarget] = useState('');
  const [reconOptions, setReconOptions] = useState({
    subdomains: true,
    dns: true,
    ports: false,
    cors: true,
    ssl: true,
    whois: true,
    tech: true,
    headers: true,
  });

  // CVE state
  const [cveSearchType, setCveSearchType] = useState<'year' | 'keyword' | 'id'>('year');
  const [cveYear, setCveYear] = useState('2024');
  const [cveKeyword, setCveKeyword] = useState('');
  const [cveId, setCveId] = useState('');
  const [cveResults, setCveResults] = useState<any[]>([]);

  // Scanner state
  const [scanUrl, setScanUrl] = useState('');
  const [scanTypes, setScanTypes] = useState({ xss: true, sqli: false, ssrf: false, redirect: false });

  // Lookup state
  const [lookupTarget, setLookupTarget] = useState('');
  const [lookupType, setLookupType] = useState('whois');

  // Utils state
  const [utilsAction, setUtilsAction] = useState('encode64');
  const [utilsValue, setUtilsValue] = useState('');
  const [utilsResult, setUtilsResult] = useState('');

  const runRecon = async () => {
    if (!reconTarget) return;
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/api/recon`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target: reconTarget,
          ...reconOptions,
        }),
      });
      const data = await res.json();
      if (data.job_id) {
        // Poll for results
        const poll = async () => {
          for (let i = 0; i < 30; i++) {
            await new Promise(r => setTimeout(r, 1000));
            const r = await fetch(`${API_BASE}/api/recon/${data.job_id}`);
            const d = await r.json();
            if (d.status === 'completed') {
              setOutput(d.results);
              setLoading(false);
              return;
            }
          }
          setError('Timeout waiting for results');
          setLoading(false);
        };
        poll();
      }
    } catch (e: any) {
      setError(e.message);
      setLoading(false);
    }
  };

  const runCVE = async () => {
    setLoading(true);
    setError(null);
    try {
      const body: any = { limit: 50 };
      if (cveSearchType === 'year') body.year = parseInt(cveYear);
      else if (cveSearchType === 'keyword') body.keyword = cveKeyword;
      else if (cveSearchType === 'id') body.cve_id = cveId;

      const res = await fetch(`${API_BASE}/api/cve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      setCveResults(data.results || []);
    } catch (e: any) {
      setError(e.message);
    }
    setLoading(false);
  };

  const runUtils = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/utils`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: utilsAction, value: utilsValue }),
      });
      const data = await res.json();
      setUtilsResult(data.result || '');
    } catch (e: any) {
      setError(e.message);
    }
    setLoading(false);
  };

  const runLookup = async () => {
    if (!lookupTarget) return;
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/api/lookup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: lookupTarget, type: lookupType }),
      });
      const data = await res.json();
      setOutput(data);
    } catch (e: any) {
      setError(e.message);
    }
    setLoading(false);
  };

  const getSeverityColor = (sev: string) => {
    if (sev === 'CRITICAL') return 'text-red-400 bg-red-900/30';
    if (sev === 'HIGH') return 'text-orange-400 bg-orange-900/30';
    if (sev === 'MEDIUM') return 'text-yellow-400 bg-yellow-900/30';
    return 'text-green-400 bg-green-900/30';
  };

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100">
      {/* Header */}
      <header className="border-b border-gray-800 bg-gray-900/50 backdrop-blur">
        <div className="max-w-7xl mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Shield className="text-cyan-400" size={32} />
            <div>
              <h1 className="font-bold text-xl text-white">All-in-One Security Toolkit</h1>
              <p className="text-xs text-gray-500">Recon • Scanner • CVE • Lookup</p>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <span className="text-xs text-gray-500">v2.0.0</span>
            <a href="/api-docs" className="text-xs text-cyan-400 hover:underline">API Docs</a>
          </div>
        </div>
      </header>

      <div className="flex max-w-7xl mx-auto">
        {/* Sidebar */}
        <nav className="w-56 border-r border-gray-800 min-h-[calc(100vh-73px)] p-4 space-y-1">
          {navItems.map(item => (
            <button
              key={item.id}
              onClick={() => setActiveModule(item.id)}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg text-left transition-all ${
                activeModule === item.id
                  ? 'bg-gray-800 text-white'
                  : 'text-gray-400 hover:bg-gray-900 hover:text-gray-200'
              }`}
            >
              <span className={item.color}>{item.icon}</span>
              <span className="font-medium">{item.label}</span>
              {activeModule === item.id && <ChevronRight size={16} className="ml-auto" />}
            </button>
          ))}
        </nav>

        {/* Main Content */}
        <main className="flex-1 p-6">
          {/* Dashboard */}
          {activeModule === 'dashboard' && (
            <div className="space-y-6">
              <h2 className="text-2xl font-bold text-white">Dashboard</h2>
              <div className="grid grid-cols-3 gap-4">
                {[
                  { label: 'Recon Modules', value: '9', icon: <Search />, color: 'text-blue-400 bg-blue-900/20' },
                  { label: 'CVE Database', value: 'NVD', icon: <Database />, color: 'text-purple-400 bg-purple-900/20' },
                  { label: 'Scanner Types', value: '4', icon: <Bug />, color: 'text-red-400 bg-red-900/20' },
                  { label: 'Lookup Tools', value: '4', icon: <Globe />, color: 'text-green-400 bg-green-900/20' },
                  { label: 'Utils Functions', value: '9', icon: <Terminal />, color: 'text-yellow-400 bg-yellow-900/20' },
                  { label: 'API Status', value: 'Online', icon: <Zap />, color: 'text-cyan-400 bg-cyan-900/20' },
                ].map((stat, i) => (
                  <div key={i} className={`p-6 rounded-xl border border-gray-800 ${stat.color}`}>
                    <div className="flex items-center gap-3 mb-2">
                      {stat.icon}
                      <span className="text-sm text-gray-400">{stat.label}</span>
                    </div>
                    <p className="text-2xl font-bold">{stat.value}</p>
                  </div>
                ))}
              </div>

              <div className="bg-gray-900 rounded-xl border border-gray-800 p-6">
                <h3 className="text-lg font-semibold text-white mb-4">Quick Start</h3>
                <div className="space-y-3">
                  {[
                    { title: 'Recon', desc: 'Enumerate subdomains, DNS, ports, and more', module: 'recon' },
                    { title: 'CVE Search', desc: 'Search CVEs by year, keyword, or ID', module: 'cve' },
                    { title: 'Vulnerability Scanner', desc: 'Scan for XSS, SQLi, SSRF, Open Redirect', module: 'scanner' },
                    { title: 'WHOIS & IP Lookup', desc: 'Domain and IP information lookup', module: 'lookup' },
                  ].map((item, i) => (
                    <button
                      key={i}
                      onClick={() => setActiveModule(item.module as Module)}
                      className="w-full flex items-center justify-between p-4 bg-gray-800/50 hover:bg-gray-800 rounded-lg transition-colors border border-gray-700"
                    >
                      <div>
                        <p className="font-medium text-white">{item.title}</p>
                        <p className="text-sm text-gray-400">{item.desc}</p>
                      </div>
                      <ChevronRight className="text-gray-500" size={20} />
                    </button>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Recon Module */}
          {activeModule === 'recon' && (
            <div className="space-y-6">
              <h2 className="text-2xl font-bold text-white">Reconnaissance</h2>
              
              <div className="bg-gray-900 rounded-xl border border-gray-800 p-6">
                <label className="block text-sm text-gray-400 mb-2">Target Domain</label>
                <div className="flex gap-3">
                  <input
                    type="text"
                    value={reconTarget}
                    onChange={e => setReconTarget(e.target.value)}
                    placeholder="example.com"
                    className="flex-1 bg-gray-800 border border-gray-700 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500"
                  />
                  <button
                    onClick={runRecon}
                    disabled={loading || !reconTarget}
                    className="px-6 py-3 bg-cyan-600 hover:bg-cyan-700 disabled:bg-gray-700 disabled:text-gray-500 rounded-lg font-medium flex items-center gap-2 transition-colors"
                  >
                    {loading ? <Loader2 className="animate-spin" size={18} /> : <Search size={18} />}
                    Scan
                  </button>
                </div>

                <div className="mt-4 grid grid-cols-4 gap-3">
                  {Object.entries(reconOptions).map(([key, val]) => (
                    <label key={key} className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={val}
                        onChange={e => setReconOptions(prev => ({ ...prev, [key]: e.target.checked }))}
                        className="w-4 h-4 rounded bg-gray-800 border-gray-600 text-cyan-500 focus:ring-cyan-500"
                      />
                      <span className="text-sm text-gray-300 capitalize">{key}</span>
                    </label>
                  ))}
                </div>
              </div>

              {loading && (
                <div className="flex items-center gap-3 text-cyan-400 p-4 bg-cyan-900/20 rounded-lg">
                  <Loader2 className="animate-spin" size={20} />
                  <span>Reconnaissance in progress...</span>
                </div>
              )}

              {error && (
                <div className="flex items-center gap-3 text-red-400 p-4 bg-red-900/20 rounded-lg">
                  <XCircle size={20} />
                  <span>{error}</span>
                </div>
              )}

              {output && (
                <div className="space-y-4">
                  {output.subdomains && Object.keys(output.subdomains).length > 0 && (
                    <div className="bg-gray-900 rounded-xl border border-gray-800 p-6">
                      <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                        <CheckCircle className="text-green-400" size={20} />
                        Subdomains ({Object.keys(output.subdomains).length})
                      </h3>
                      <div className="space-y-2">
                        {Object.entries(output.subdomains).map(([host, ip]: [string, any]) => (
                          <div key={host} className="flex items-center justify-between p-3 bg-gray-800/50 rounded-lg">
                            <span className="text-cyan-400 font-mono text-sm">{host}</span>
                            <span className="text-gray-500 text-sm">{ip}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {output.cors && Object.keys(output.cors).length > 0 && (
                    <div className="bg-gray-900 rounded-xl border border-red-900/50 p-6">
                      <h3 className="text-lg font-semibold text-red-400 mb-4 flex items-center gap-2">
                        <AlertTriangle size={20} />
                        CORS Vulnerabilities ({Object.keys(output.cors).length})
                      </h3>
                      <div className="space-y-2">
                        {Object.entries(output.cors).map(([url, info]: [string, any]) => (
                          <div key={url} className="p-3 bg-red-900/20 border border-red-900/50 rounded-lg">
                            <p className="text-red-300 font-mono text-sm">{url}</p>
                            <p className="text-xs text-red-500 mt-1">Risk: {info.risk} | Allow-Origin: {info.allow_origin}</p>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {output.dns_records && Object.keys(output.dns_records).length > 0 && (
                    <div className="bg-gray-900 rounded-xl border border-gray-800 p-6">
                      <h3 className="text-lg font-semibold text-white mb-4">DNS Records</h3>
                      {Object.entries(output.dns_records).map(([type, records]: [string, any]) => (
                        records.length > 0 && (
                          <div key={type} className="mb-3">
                            <p className="text-sm text-gray-400 mb-1">{type}</p>
                            <div className="space-y-1">
                              {(Array.isArray(records) ? records : [records]).map((r: string, i: number) => (
                                <p key={i} className="text-gray-300 text-sm font-mono bg-gray-800/50 px-3 py-1 rounded">{r}</p>
                              ))}
                            </div>
                          </div>
                        )
                      ))}
                    </div>
                  )}

                  {output.whois && Object.keys(output.whois).length > 0 && (
                    <div className="bg-gray-900 rounded-xl border border-gray-800 p-6">
                      <h3 className="text-lg font-semibold text-white mb-4">WHOIS</h3>
                      <div className="grid grid-cols-2 gap-3">
                        {Object.entries(output.whois).slice(0, 10).map(([key, val]: [string, any]) => (
                          <div key={key}>
                            <p className="text-xs text-gray-500 uppercase">{key}</p>
                            <p className="text-sm text-gray-300 truncate">{String(val).slice(0, 50)}</p>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* CVE Module */}
          {activeModule === 'cve' && (
            <div className="space-y-6">
              <h2 className="text-2xl font-bold text-white">CVE Search</h2>
              
              <div className="bg-gray-900 rounded-xl border border-gray-800 p-6">
                <div className="flex gap-3 mb-4">
                  {[
                    { id: 'year', label: 'By Year' },
                    { id: 'keyword', label: 'By Keyword' },
                    { id: 'id', label: 'By CVE ID' },
                  ].map(t => (
                    <button
                      key={t.id}
                      onClick={() => setCveSearchType(t.id as any)}
                      className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                        cveSearchType === t.id
                          ? 'bg-purple-600 text-white'
                          : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
                      }`}
                    >
                      {t.label}
                    </button>
                  ))}
                </div>

                <div className="flex gap-3">
                  {cveSearchType === 'year' && (
                    <input
                      type="number"
                      value={cveYear}
                      onChange={e => setCveYear(e.target.value)}
                      placeholder="Year (e.g. 2024)"
                      className="flex-1 bg-gray-800 border border-gray-700 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-purple-500"
                    />
                  )}
                  {cveSearchType === 'keyword' && (
                    <input
                      type="text"
                      value={cveKeyword}
                      onChange={e => setCveKeyword(e.target.value)}
                      placeholder="Keyword (e.g. xss, sql injection)"
                      className="flex-1 bg-gray-800 border border-gray-700 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-purple-500"
                    />
                  )}
                  {cveSearchType === 'id' && (
                    <input
                      type="text"
                      value={cveId}
                      onChange={e => setCveId(e.target.value)}
                      placeholder="CVE ID (e.g. CVE-2024-1234)"
                      className="flex-1 bg-gray-800 border border-gray-700 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-purple-500"
                    />
                  )}
                  <button
                    onClick={runCVE}
                    disabled={loading}
                    className="px-6 py-3 bg-purple-600 hover:bg-purple-700 disabled:bg-gray-700 rounded-lg font-medium flex items-center gap-2 transition-colors"
                  >
                    {loading ? <Loader2 className="animate-spin" size={18} /> : <Database size={18} />}
                    Search
                  </button>
                </div>
              </div>

              {cveResults.length > 0 && (
                <div className="space-y-3">
                  <p className="text-sm text-gray-400">{cveResults.length} CVEs found</p>
                  {cveResults.map((cve: any, i: number) => (
                    <div key={i} className="bg-gray-900 rounded-xl border border-gray-800 p-4">
                      <div className="flex items-center justify-between mb-2">
                        <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(cve.severity)}`}>
                          {cve.id}
                        </span>
                        <span className="text-xs text-gray-500">
                          CVSS: <span className="text-white">{cve.score}</span> | {cve.severity}
                        </span>
                      </div>
                      <p className="text-sm text-gray-300 mb-2 line-clamp-2">{cve.description}</p>
                      <p className="text-xs text-gray-500">Published: {cve.published?.slice(0, 10)}</p>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Scanner Module */}
          {activeModule === 'scanner' && (
            <div className="space-y-6">
              <h2 className="text-2xl font-bold text-white">Vulnerability Scanner</h2>
              
              <div className="bg-gray-900 rounded-xl border border-gray-800 p-6">
                <label className="block text-sm text-gray-400 mb-2">Target URL (with parameters)</label>
                <input
                  type="text"
                  value={scanUrl}
                  onChange={e => setScanUrl(e.target.value)}
                  placeholder="https://example.com/?q=test&id=1"
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-red-500 mb-4"
                />

                <div className="grid grid-cols-4 gap-3 mb-4">
                  {Object.entries(scanTypes).map(([key, val]) => (
                    <label key={key} className="flex items-center gap-2 cursor-pointer p-3 bg-gray-800/50 rounded-lg border border-gray-700">
                      <input
                        type="checkbox"
                        checked={val}
                        onChange={e => setScanTypes(prev => ({ ...prev, [key]: e.target.checked }))}
                        className="w-4 h-4 rounded bg-gray-800 border-gray-600 text-red-500 focus:ring-red-500"
                      />
                      <span className="text-sm text-gray-300 uppercase">{key}</span>
                    </label>
                  ))}
                </div>

                <button
                  disabled={loading || !scanUrl}
                  className="px-6 py-3 bg-red-600 hover:bg-red-700 disabled:bg-gray-700 disabled:text-gray-500 rounded-lg font-medium flex items-center gap-2 transition-colors"
                >
                  {loading ? <Loader2 className="animate-spin" size={18} /> : <Bug size={18} />}
                  Start Scan
                </button>
              </div>

              <div className="bg-gray-900 rounded-xl border border-gray-800 p-6">
                <h3 className="text-lg font-semibold text-white mb-4">Scanner Types</h3>
                <div className="grid grid-cols-2 gap-4">
                  {[
                    { name: 'XSS', desc: 'Cross-Site Scripting detection', icon: <AlertTriangle className="text-red-400" /> },
                    { name: 'SQLi', desc: 'SQL Injection detection', icon: <Database className="text-orange-400" /> },
                    { name: 'SSRF', desc: 'Server-Side Request Forgery', icon: <Globe className="text-yellow-400" /> },
                    { name: 'Open Redirect', desc: 'Open Redirect vulnerability', icon: <ChevronRight className="text-green-400" /> },
                  ].map((s, i) => (
                    <div key={i} className="p-4 bg-gray-800/50 rounded-lg border border-gray-700">
                      <div className="flex items-center gap-3 mb-2">
                        {s.icon}
                        <span className="font-medium text-white">{s.name}</span>
                      </div>
                      <p className="text-sm text-gray-400">{s.desc}</p>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Lookup Module */}
          {activeModule === 'lookup' && (
            <div className="space-y-6">
              <h2 className="text-2xl font-bold text-white">Lookup Tools</h2>
              
              <div className="bg-gray-900 rounded-xl border border-gray-800 p-6">
                <div className="flex gap-3 mb-4">
                  {[
                    { id: 'whois', label: 'WHOIS' },
                    { id: 'ip', label: 'IP Lookup' },
                    { id: 'reverse-dns', label: 'Reverse DNS' },
                    { id: 'cdn', label: 'CDN Check' },
                  ].map(t => (
                    <button
                      key={t.id}
                      onClick={() => setLookupType(t.id)}
                      className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                        lookupType === t.id
                          ? 'bg-green-600 text-white'
                          : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
                      }`}
                    >
                      {t.label}
                    </button>
                  ))}
                </div>

                <div className="flex gap-3">
                  <input
                    type="text"
                    value={lookupTarget}
                    onChange={e => setLookupTarget(e.target.value)}
                    placeholder={lookupType === 'ip' ? 'IP or Domain' : 'Domain'}
                    className="flex-1 bg-gray-800 border border-gray-700 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-green-500"
                  />
                  <button
                    onClick={runLookup}
                    disabled={loading || !lookupTarget}
                    className="px-6 py-3 bg-green-600 hover:bg-green-700 disabled:bg-gray-700 disabled:text-gray-500 rounded-lg font-medium flex items-center gap-2 transition-colors"
                  >
                    {loading ? <Loader2 className="animate-spin" size={18} /> : <Globe size={18} />}
                    Lookup
                  </button>
                </div>
              </div>

              {output && (
                <div className="bg-gray-900 rounded-xl border border-gray-800 p-6">
                  <pre className="text-sm text-gray-300 overflow-x-auto whitespace-pre-wrap">
                    {typeof output === 'string' ? output : JSON.stringify(output, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          )}

          {/* Utils Module */}
          {activeModule === 'utils' && (
            <div className="space-y-6">
              <h2 className="text-2xl font-bold text-white">Utilities</h2>
              
              <div className="bg-gray-900 rounded-xl border border-gray-800 p-6">
                <div className="grid grid-cols-3 gap-3 mb-4">
                  {[
                    { id: 'encode64', label: 'Base64 Encode' },
                    { id: 'decode64', label: 'Base64 Decode' },
                    { id: 'urlencode', label: 'URL Encode' },
                    { id: 'urldecode', label: 'URL Decode' },
                    { id: 'hash-md5', label: 'MD5 Hash' },
                    { id: 'hash-sha256', label: 'SHA256 Hash' },
                    { id: 'hex-encode', label: 'Hex Encode' },
                    { id: 'hex-decode', label: 'Hex Decode' },
                  ].map(u => (
                    <button
                      key={u.id}
                      onClick={() => setUtilsAction(u.id)}
                      className={`px-4 py-3 rounded-lg text-sm font-medium transition-colors ${
                        utilsAction === u.id
                          ? 'bg-yellow-600 text-white'
                          : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
                      }`}
                    >
                      {u.label}
                    </button>
                  ))}
                </div>

                <textarea
                  value={utilsValue}
                  onChange={e => setUtilsValue(e.target.value)}
                  placeholder="Enter text..."
                  rows={4}
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-yellow-500 mb-4 font-mono"
                />

                <div className="flex gap-3">
                  <button
                    onClick={runUtils}
                    disabled={loading || !utilsValue}
                    className="px-6 py-3 bg-yellow-600 hover:bg-yellow-700 disabled:bg-gray-700 disabled:text-gray-500 rounded-lg font-medium flex items-center gap-2 transition-colors"
                  >
                    {loading ? <Loader2 className="animate-spin" size={18} /> : <Terminal size={18} />}
                    Execute
                  </button>
                  <button
                    onClick={() => setUtilsValue('')}
                    className="px-6 py-3 bg-gray-800 hover:bg-gray-700 rounded-lg font-medium transition-colors"
                  >
                    Clear
                  </button>
                </div>
              </div>

              {utilsResult && (
                <div className="bg-gray-900 rounded-xl border border-gray-800 p-6">
                  <div className="flex items-center justify-between mb-3">
                    <h3 className="text-sm text-gray-400">Result</h3>
                    <button
                      onClick={() => navigator.clipboard.writeText(utilsResult)}
                      className="text-xs text-cyan-400 hover:underline"
                    >
                      Copy
                    </button>
                  </div>
                  <pre className="text-sm text-green-400 font-mono bg-gray-950 p-4 rounded-lg overflow-x-auto">
                    {utilsResult}
                  </pre>
                </div>
              )}
            </div>
          )}
        </main>
      </div>
    </div>
  );
}
