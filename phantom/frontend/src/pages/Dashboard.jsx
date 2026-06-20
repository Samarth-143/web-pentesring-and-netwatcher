import React, { useState } from 'react';
import { fetchAuth } from '../api';

const MODULES_LIST = [
  { id: "port_scanner",    name: "Port Scanner",           type: "Recon",   icon: "🔌", desc: "Nmap-powered open port discovery" },
  { id: "subdomain_enum",  name: "Subdomain Enumerator",   type: "Recon",   icon: "🌐", desc: "DNS brute-force + cert transparency" },
  { id: "dir_enum",        name: "Directory Enumerator",   type: "Recon",   icon: "📂", desc: "Hidden path & backup detection" },
  { id: "waf_detect",      name: "WAF Detector",           type: "Recon",   icon: "🛡️", desc: "Fingerprints Cloudflare, Akamai, etc." },
  { id: "whois_lookup",    name: "WHOIS Lookup",           type: "Recon",   icon: "📋", desc: "Domain registration & expiry info" },
  { id: "dns_recon",       name: "DNS Recon",              type: "Recon",   icon: "🔍", desc: "Full DNS records + zone transfer test" },
  { id: "cve_lookup",      name: "CVE Lookup",             type: "Recon",   icon: "📰", desc: "NVD API — known CVE intelligence" },
  { id: "sqli_tester",     name: "SQL Injection Tester",   type: "Exploit", icon: "💉", desc: "Error, time-based, union & boolean SQLi" },
  { id: "xss_detector",    name: "XSS Detector",           type: "Exploit", icon: "⚡", desc: "13 reflected XSS payload probes" },
  { id: "csrf_detector",   name: "CSRF Detector",          type: "Exploit", icon: "🔄", desc: "Cross-site request forgery checks" },
  { id: "ssrf_detector",   name: "SSRF Detector",          type: "Exploit", icon: "↩️", desc: "Server-side request forgery probes" },
  { id: "xxe_detector",    name: "XXE Detector",           type: "Exploit", icon: "📄", desc: "XML External Entity injection tests" },
  { id: "auth_tester",     name: "Broken Auth Tester",     type: "Exploit", icon: "🔑", desc: "Authentication bypass & weak cred tests" },
  { id: "open_redirect",   name: "Open Redirect Tester",   type: "Exploit", icon: "🔀", desc: "URL redirect chain & header injection" },
  { id: "header_analyzer", name: "HTTP Header Analyzer",   type: "Audit",   icon: "📊", desc: "Security header scoring & grading" },
  { id: "ssl_analyzer",    name: "SSL/TLS Analyzer",       type: "Audit",   icon: "🔒", desc: "Certificate validity & cipher strength" },
];

const TYPE_COLORS = {
  Recon:   { bg: 'rgba(46,219,255,0.08)',  border: 'rgba(46,219,255,0.3)',  text: '#2edbff' },
  Exploit: { bg: 'rgba(255,46,92,0.08)',   border: 'rgba(255,46,92,0.3)',   text: '#ff2e5c' },
  Audit:   { bg: 'rgba(46,255,156,0.08)', border: 'rgba(46,255,156,0.3)', text: '#2eff9c' },
};

const MODULE_ENDPOINT_MAP = {
  port_scanner:    '/api/port-scan',
  sqli_tester:     '/api/sqli-test',
  xss_detector:    '/api/xss-detect',
  subdomain_enum:  '/api/subdomain-enum',
  header_analyzer: '/api/header-analyze',
  ssl_analyzer:    '/api/ssl-analyze',
  dir_enum:        '/api/dir-enum',
  waf_detect:      '/api/waf-detect',
  whois_lookup:    '/api/whois',
  dns_recon:       '/api/dns-recon',
  cve_lookup:      '/api/cve-lookup',
  csrf_detector:   '/api/csrf-detect',
  ssrf_detector:   '/api/ssrf-detect',
  xxe_detector:    '/api/xxe-detect',
  auth_tester:     '/api/auth-test',
  open_redirect:   '/api/open-redirect',
};

function Dashboard({ alerts, setAlerts, stats, loadStats }) {
  const [scanTarget, setScanTarget] = useState('');
  const [selectedModules, setSelectedModules] = useState(['port_scanner', 'sqli_tester', 'xss_detector']);
  const [scanStatus, setScanStatus] = useState('idle'); // idle, running, completed, failed
  const [scanResult, setScanResult] = useState(null);
  const [scanDuration, setScanDuration] = useState(0);
  const [expandedResult, setExpandedResult] = useState({});
  const [exportingPDF, setExportingPDF] = useState(false);

  const handleStartScan = async () => {
    if (!scanTarget.trim()) return;
    setScanStatus('running');
    setScanResult(null);
    setScanDuration(0);
    const start = performance.now();
    
    try {
      const isFullScan = selectedModules.length >= 16;
      
      let resData;
      if (isFullScan) {
        resData = await fetchAuth('/api/full-scan', {
          method: 'POST',
          body: JSON.stringify({ target: scanTarget, options: {} })
        });
      } else if (selectedModules.length > 1) {
        const moduleResults = await Promise.allSettled(
          selectedModules.map(mod =>
            fetchAuth(MODULE_ENDPOINT_MAP[mod] || `/api/${mod.replace(/_/g, '-')}`, {
              method: 'POST',
              body: JSON.stringify({ target: scanTarget, options: {} })
            }).then(data => ({ mod, data }))
          )
        );
        const combined = {};
        moduleResults.forEach(r => {
          if (r.status === 'fulfilled') {
            combined[r.value.mod] = r.value.data;
          } else {
            combined[r.value?.mod || 'unknown'] = { risk: 'ERROR', error: r.reason?.message };
          }
        });
        resData = { results: combined };
      } else {
        const mod = selectedModules[0];
        const endpoint = MODULE_ENDPOINT_MAP[mod] || `/api/${mod.replace(/_/g, '-')}`;
        const raw = await fetchAuth(endpoint, {
          method: 'POST',
          body: JSON.stringify({ target: scanTarget, options: {} })
        });
        resData = { results: { [mod]: raw } };
      }
      
      setScanDuration(Math.round((performance.now() - start) / 1000));
      setScanResult(resData);
      setScanStatus('completed');
      
      const newAlerts = [];
      Object.keys(resData.results || {}).forEach(m => {
        const modRes = resData.results[m];
        if (modRes && modRes.vulnerable) {
          newAlerts.push({
            module_name: m,
            severity: modRes.risk || 'INFO',
            description: `Vulnerability verified on target: ${scanTarget}`,
            timestamp: new Date().toLocaleTimeString()
          });
        }
      });
      setAlerts(prev => [...newAlerts, ...prev]);
      if(loadStats) loadStats();
    } catch (e) {
      setScanStatus('failed');
    }
  };

  const handleExportPDF = async () => {
    if (!scanTarget || !scanResult) return;
    setExportingPDF(true);
    try {
      const payload = { target: scanTarget, options: { results: scanResult.results } };
      const res = await fetchAuth('/api/report', { method: 'POST', body: JSON.stringify(payload) });
      if (res.error) { alert("Failed to generate PDF: " + res.error); return; }
      if (res.pdf_data) {
        const linkSource = `data:application/pdf;base64,${res.pdf_data}`;
        const downloadLink = document.createElement("a");
        downloadLink.href = linkSource;
        const cleanTarget = scanTarget.replace(/https?:\/\//, '').replace(/[^a-zA-Z0-9]/g, '_');
        downloadLink.download = res.filename || `phantom_report_${cleanTarget}.pdf`;
        downloadLink.click();
      }
    } catch (e) { alert("Failed to export report: " + e.message); } 
    finally { setExportingPDF(false); }
  };

  return (
    <>
      <div style={{ padding: '15px 20px', background: 'rgba(0,0,0,0.2)', borderBottom: '1px solid var(--border)' }}>
        <div className="scan-controls" style={{ justifyContent: 'flex-start' }}>
          <input 
            type="text" 
            className="target-input" 
            placeholder="Target host, FQDN or target URL (e.g. http://example.com/)" 
            value={scanTarget}
            onChange={e => setScanTarget(e.target.value)}
          />
          <button 
            type="button" 
            className="scan-btn" 
            onClick={handleStartScan}
            disabled={scanStatus === 'running'}
          >
            {scanStatus === 'running' ? 'SCANNING...' : 'RUN AUDIT'}
          </button>
        </div>
      </div>
      <div className="dashboard-grid" style={{ padding: '20px' }}>
        <div className="pane">
          <h3 className="pane-title">Scanning Engine Directives</h3>
          <div style={{ display: 'flex', gap: '8px', marginBottom: '10px', flexWrap: 'wrap', alignItems: 'center' }}>
            <span style={{ fontSize: '11px', color: 'var(--text-muted)', marginRight: '4px' }}>
              {selectedModules.length} / {MODULES_LIST.length} selected
            </span>
            <button type="button" style={{ fontSize: '10px', padding: '3px 10px', background: 'rgba(46,219,255,0.1)', border: '1px solid rgba(46,219,255,0.3)', color: 'var(--neon-cyan)', borderRadius: '4px', cursor: 'pointer', fontFamily: 'var(--font-nav)' }} onClick={() => setSelectedModules(MODULES_LIST.map(m => m.id))}>SELECT ALL</button>
            <button type="button" style={{ fontSize: '10px', padding: '3px 10px', background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border-light)', color: 'var(--text-muted)', borderRadius: '4px', cursor: 'pointer', fontFamily: 'var(--font-nav)' }} onClick={() => setSelectedModules([])}>CLEAR</button>
            {['Recon','Exploit','Audit'].map(t => (
              <button key={t} type="button" style={{ fontSize: '10px', padding: '3px 10px', background: TYPE_COLORS[t].bg, border: `1px solid ${TYPE_COLORS[t].border}`, color: TYPE_COLORS[t].text, borderRadius: '4px', cursor: 'pointer', fontFamily: 'var(--font-nav)' }} onClick={() => {
                  const ofType = MODULES_LIST.filter(m => m.type === t).map(m => m.id);
                  const allSelected = ofType.every(id => selectedModules.includes(id));
                  if (allSelected) setSelectedModules(prev => prev.filter(id => !ofType.includes(id)));
                  else setSelectedModules(prev => [...new Set([...prev, ...ofType])]);
                }}>{t.toUpperCase()}</button>
            ))}
          </div>

          <div className="modules-checklist">
            {['Recon','Exploit','Audit'].map(group => (
              <div key={group} style={{ marginBottom: '14px' }}>
                <div style={{ fontSize: '10px', letterSpacing: '2px', color: TYPE_COLORS[group].text, fontFamily: 'var(--font-nav)', marginBottom: '6px', borderBottom: `1px solid ${TYPE_COLORS[group].border}`, paddingBottom: '4px' }}>
                  ── {group.toUpperCase()} MODULES ──
                </div>
                {MODULES_LIST.filter(m => m.type === group).map(mod => {
                  const isSelected = selectedModules.includes(mod.id);
                  return (
                    <div key={mod.id} className={`module-checkbox-card ${isSelected ? 'selected' : ''}`}
                      style={isSelected ? { borderColor: TYPE_COLORS[group].border, background: TYPE_COLORS[group].bg } : {}}
                      onClick={() => {
                        if (isSelected) setSelectedModules(prev => prev.filter(x => x !== mod.id));
                        else setSelectedModules(prev => [...prev, mod.id]);
                      }}
                    >
                      <input type="checkbox" checked={isSelected} onChange={() => {}} />
                      <span style={{ marginRight: '6px', fontSize: '14px' }}>{mod.icon}</span>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <span className="module-label">{mod.name}</span>
                        <div style={{ fontSize: '10px', color: 'var(--text-muted)', marginTop: '1px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{mod.desc}</div>
                      </div>
                    </div>
                  );
                })}
              </div>
            ))}
          </div>

          <h3 className="pane-title">Vulnerability Findings & Execution logs</h3>
          
          {scanStatus === 'running' && (
            <div style={{ textAlign: 'center', padding: '50px', background: 'rgba(157, 0, 255, 0.05)', borderRadius: '8px', border: '1px solid var(--border-glow)', animation: 'pulseGlow 2s infinite' }}>
              <h4 style={{ fontFamily: 'var(--font-heading)', color: 'var(--text-glow)', letterSpacing: '2px' }}>ENGAGING PHANTOM MODULES CONCURRENTLY...</h4>
              <p style={{ fontSize: '12px', marginTop: '12px', color: 'var(--neon-cyan)', animation: 'neonFlicker 3s infinite' }}>Probing vulnerabilities, headers, and endpoints on <span style={{color: '#fff'}}>{scanTarget}</span></p>
            </div>
          )}

          {scanStatus === 'idle' && (
            <div style={{ textAlign: 'center', padding: '60px', color: 'var(--text-muted)' }}>
              <p>Enter target URL and choose audit directives above to initialize scan.</p>
            </div>
          )}

          {scanStatus === 'completed' && scanResult && (
            <div className="results-container">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '11px', color: 'var(--text-muted)', marginBottom: '10px' }}>
                <span>TARGET: {scanTarget} // COMPLETED IN {scanDuration}s</span>
                <button type="button" className="scan-btn" style={{ padding: '4px 10px', fontSize: '10px', margin: 0, height: 'auto' }}
                  onClick={handleExportPDF} disabled={exportingPDF}>
                  {exportingPDF ? "EXPORTING..." : "EXPORT PDF REPORT"}
                </button>
              </div>
              {Object.keys(scanResult.results || {}).map(m => {
                const modData = scanResult.results[m];
                const isExpanded = !!expandedResult[m];
                if (!modData) return null;
                
                const risk = (modData.risk || 'INFO').toLowerCase();
                
                return (
                  <div key={m} className="result-card">
                    <div className="result-header" onClick={() => setExpandedResult(prev => ({ ...prev, [m]: !prev[m] }))}>
                      <div className="module-title-section"><span className="module-name-tag">{m.toUpperCase()}</span></div>
                      <span className={`result-badge ${risk}`}>{modData.risk || 'INFO'}</span>
                    </div>
                    
                    {isExpanded && (
                      <div className="result-body">
                        {modData.findings && modData.findings.length > 0 ? (
                          <ul style={{ marginLeft: '16px', listStyleType: 'square' }}>
                            {modData.findings.map((f, i) => <li key={i} style={{ marginBottom: '4px' }}>{f}</li>)}
                          </ul>
                        ) : (
                          <p style={{ color: 'var(--text-muted)' }}>No high severity findings reported. Refer to raw JSON payload below.</p>
                        )}
                        <pre className="json-dump">{JSON.stringify(modData, null, 2)}</pre>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>

        <div className="pane">
          <h3 className="pane-title">Real-time Session Summary</h3>
          {stats ? (
            <div className="telemetry-grid">
              <div className="telemetry-card">
                <div className="telemetry-label">Total Audits</div>
                <div className="telemetry-value ok">{stats.total_scans}</div>
              </div>
              <div className="telemetry-card">
                <div className="telemetry-label">Vulns Identified</div>
                <div className="telemetry-value anomaly">{stats.total_vulnerabilities}</div>
              </div>
            </div>
          ) : <p style={{ color: 'var(--text-muted)', fontSize: '12px' }}>Loading platform metrics...</p>}

          <h3 className="pane-title">Active Alerts Logger</h3>
          <div className="alerts-list">
            {alerts.length === 0 ? (
              <div style={{ color: 'var(--text-muted)', fontSize: '11px', textAlign: 'center', padding: '20px' }}>
                No active alerts logged in current session.
              </div>
            ) : (
              alerts.map((al, idx) => (
                <div key={idx} className={`alert-node ${al.severity}`} style={{ animation: 'slideInUp 0.3s ease-out' }}>
                  <div style={{ fontWeight: 'bold' }}>{al.module_name.toUpperCase()}</div>
                  <div>{al.description}</div>
                  <div className="alert-meta">
                    <span>SEVERITY: {al.severity}</span>
                    <span>{al.timestamp}</span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </>
  );
}

export default Dashboard;
