import React, { useState, useEffect } from 'react';
import { fetchAuth } from '../api';

function History({ loadStats }) {
  const [historyList, setHistoryList] = useState([]);
  const [selectedHistory, setSelectedHistory] = useState(null);
  const [historyTotal, setHistoryTotal] = useState(0);
  const [exportingPDF, setExportingPDF] = useState(false);

  const [reports, setReports] = useState([]);
  const [reportsTotal, setReportsTotal] = useState(0);
  const [activeTab, setActiveTab] = useState('scans');

  const loadHistory = async () => {
    try {
      const data = await fetchAuth('/api/history?limit=20');
      setHistoryList(data.sessions || []);
      setHistoryTotal(data.total || 0);
    } catch (e) { }
  };

  const loadReports = async () => {
    try {
      const data = await fetchAuth('/api/reports?limit=50');
      setReports(data.reports || []);
      setReportsTotal(data.total || 0);
    } catch (e) { }
  };

  useEffect(() => { loadHistory(); loadReports(); }, []);

  const viewHistoryDetail = async (id) => {
    try {
      const data = await fetchAuth(`/api/history/${id}`);
      setSelectedHistory(data);
    } catch (e) { }
  };

  const deleteHistorySession = async (id) => {
    try {
      if (!window.confirm("Are you sure you want to permanently delete this scan?")) return;
      await fetchAuth(`/api/history/${id}`, { method: 'DELETE' });
      loadHistory();
      if (selectedHistory?.id === id) setSelectedHistory(null);
      if (loadStats) loadStats();
    } catch (e) {
      alert("Error deleting scan: " + e.message);
    }
  };

  const handleExportHistoryPDF = async () => {
    if (!selectedHistory) return;
    setExportingPDF(true);
    try {
      const resultsDict = {};
      selectedHistory.results.forEach(r => {
        resultsDict[r.module_name] = r.result_data || { risk: r.risk_level, vulnerable: r.vulnerable, findings: [] };
      });
      const payload = { target: selectedHistory.target, options: { results: resultsDict } };
      const res = await fetchAuth('/api/report', { method: 'POST', body: JSON.stringify(payload) });
      if (res.pdf_data) {
        const linkSource = `data:application/pdf;base64,${res.pdf_data}`;
        const downloadLink = document.createElement("a");
        downloadLink.href = linkSource;
        const cleanTarget = selectedHistory.target.replace(/https?:\/\//, '').replace(/[^a-zA-Z0-9]/g, '_');
        downloadLink.download = res.filename || `phantom_report_${cleanTarget}.pdf`;
        downloadLink.click();
        loadReports();
      }
    } catch (e) { alert("Failed: " + e.message); }
    finally { setExportingPDF(false); }
  };

  const downloadReport = async (reportId) => {
    try {
      const res = await fetchAuth(`/api/reports/${reportId}/download`);
      if (res.download_url) {
        window.open(res.download_url, '_blank');
      }
    } catch (e) { alert("Failed to get download link: " + e.message); }
  };

  const deleteReport = async (reportId) => {
    try {
      if (!window.confirm("Delete this PDF report?")) return;
      await fetchAuth(`/api/reports/${reportId}`, { method: 'DELETE' });
      loadReports();
    } catch (e) { alert("Failed to delete report: " + e.message); }
  };

  return (
    <div className="pane" style={{ height: '100%' }}>
      <div style={{ display: 'flex', gap: '0', marginBottom: '20px', borderBottom: '1px solid var(--border-light)' }}>
        <button
          className={`tab-btn ${activeTab === 'scans' ? 'active' : ''}`}
          onClick={() => setActiveTab('scans')}
        >
          Scan History ({historyTotal})
        </button>
        <button
          className={`tab-btn ${activeTab === 'archive' ? 'active' : ''}`}
          onClick={() => setActiveTab('archive')}
        >
          PDF Archive ({reportsTotal})
        </button>
      </div>

      {activeTab === 'archive' && (
        <div>
          <h3 className="pane-title">Saved Reports</h3>
          {reports.length === 0 ? (
            <p style={{ color: 'var(--text-muted)', fontSize: '13px', padding: '20px 0' }}>
              No reports saved yet. Export a PDF from a scan to save it here.
            </p>
          ) : (
            <div className="history-list">
              {reports.map((r, i) => (
                <div key={r.id} className="glass-panel-row" style={{ animation: 'slideInUp 0.3s ease-out backwards', animationDelay: `${i * 0.05}s` }}>
                  <div style={{ fontWeight: 'bold', color: 'var(--text-main)', fontSize: '14px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', paddingRight: '10px', flex: 2 }}>
                    {r.filename}
                  </div>
                  <div style={{ flex: 1, fontSize: '12px', color: 'var(--text-muted)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                    {r.target}
                  </div>
                  <div style={{ flex: 'none' }}>
                    <span className={`result-badge ${r.overall_risk.toLowerCase()}`}>{r.overall_risk}</span>
                  </div>
                  <div style={{ fontSize: '12px', color: 'var(--text-muted)', flex: 'none' }}>
                    {new Date(r.created_at + 'Z').toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
                  </div>
                  <div style={{ display: 'flex', gap: '10px', flex: 'none' }}>
                    <button className="history-btn-premium" onClick={() => downloadReport(r.id)}>Download</button>
                    <button className="history-btn-premium delete" onClick={() => deleteReport(r.id)}>Purge</button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {activeTab === 'scans' && (
        <div>
          <h3 className="pane-title">Scan Archives ({historyTotal} Total)</h3>
          <div className="history-header-row">
            <div>Target Host</div>
            <div>Risk Rating</div>
            <div>Status</div>
            <div>Audit Date</div>
            <div>Operations</div>
          </div>
          <div className="history-list">
            {historyList.map((item, i) => (
              <div key={item.id} className="glass-panel-row" style={{ animation: 'slideInUp 0.3s ease-out backwards', animationDelay: `${i * 0.05}s` }}>
                <div style={{ fontWeight: 'bold', color: 'var(--text-main)', fontSize: '14px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', paddingRight: '10px' }}>
                  {item.target}
                </div>
                <div>
                  <span className={`result-badge ${item.overall_risk.toLowerCase()}`} style={{ boxShadow: item.overall_risk === 'CRITICAL' || item.overall_risk === 'HIGH' ? '0 0 10px currentColor' : 'none' }}>
                    {item.overall_risk}
                  </span>
                </div>
                <div style={{ textTransform: 'uppercase', fontSize: '12px', display: 'flex', alignItems: 'center' }}>
                  <span className={`status-dot ${item.status.toLowerCase()}`}></span>
                  {item.status}
                </div>
                <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                  {new Date(item.created_at + 'Z').toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
                </div>
                <div style={{ display: 'flex', gap: '10px' }}>
                  <button className="history-btn-premium" onClick={() => viewHistoryDetail(item.id)}>Details</button>
                  <button className="history-btn-premium delete" onClick={() => deleteHistorySession(item.id)}>Purge</button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {selectedHistory && (
        <div style={{ marginTop: '30px', padding: '20px', border: '1px solid var(--border-light)', borderRadius: '6px', background: 'rgba(0, 0, 0, 0.4)' }}>
          <h3 className="pane-title" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span>SESSION DETAIL // ID: {selectedHistory.id}</span>
            <div style={{ display: 'flex', gap: '15px', alignItems: 'center' }}>
              <button className="scan-btn" style={{ padding: '4px 10px', fontSize: '10px', margin: 0, height: 'auto' }} onClick={handleExportHistoryPDF} disabled={exportingPDF}>
                {exportingPDF ? "EXPORTING..." : "EXPORT PDF"}
              </button>
              <button style={{ background: 'transparent', border: 'none', color: 'var(--neon-red)', cursor: 'pointer', fontFamily: 'var(--font-nav)', fontSize: '12px' }} onClick={() => setSelectedHistory(null)}>
                CLOSE [X]
              </button>
            </div>
          </h3>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px', marginTop: '16px' }}>
            <div>
              <h4 style={{ fontFamily: 'var(--font-nav)', textTransform: 'uppercase', color: 'var(--neon-cyan)' }}>Module Results</h4>
              <div className="results-container" style={{ marginTop: '10px' }}>
                {selectedHistory.results.map((r, i) => (
                  <div key={i} className="result-card">
                    <div className="result-header">
                      <span className="module-name-tag">{r.module_name.toUpperCase()}</span>
                      <span className={`result-badge ${r.risk_level.toLowerCase()}`}>{r.risk_level}</span>
                    </div>
                    <div className="result-body" style={{ background: 'rgba(0,0,0,0.1)' }}>
                      <p>Duration: {r.duration_seconds.toFixed(2)}s</p>
                      {r.error_message && <p style={{ color: 'var(--neon-red)' }}>Error: {r.error_message}</p>}
                      <pre className="json-dump">{JSON.stringify(r.result_data, null, 2)}</pre>
                    </div>
                  </div>
                ))}
              </div>
            </div>
            <div>
              <h4 style={{ fontFamily: 'var(--font-nav)', textTransform: 'uppercase', color: 'var(--neon-red)' }}>Vulnerability Alerts</h4>
              <div className="alerts-list" style={{ marginTop: '10px' }}>
                {selectedHistory.alerts.length === 0 ? (
                  <p style={{ color: 'var(--text-muted)', fontSize: '12px' }}>No vulnerabilities flagged during this audit session.</p>
                ) : (
                  selectedHistory.alerts.map((al, idx) => (
                    <div key={idx} className={`alert-node ${al.severity}`}>
                      <div style={{ fontWeight: 'bold' }}>{al.module_name.toUpperCase()}</div>
                      <div>{al.description}</div>
                      <div className="alert-meta"><span>SEVERITY: {al.severity}</span><span>{new Date(al.timestamp + 'Z').toLocaleTimeString()}</span></div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default History;
