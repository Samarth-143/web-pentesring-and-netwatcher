import React, { useState, useEffect } from 'react';
import { fetchAuth } from '../api';

const MODULES_LIST = [
  { id: "port_scanner", name: "Port Scanner" },
  { id: "subdomain_enum", name: "Subdomain Enumerator" },
  { id: "dir_enum", name: "Directory Enumerator" },
  { id: "waf_detect", name: "WAF Detector" },
  { id: "whois_lookup", name: "WHOIS Lookup" },
  { id: "dns_recon", name: "DNS Recon" },
  { id: "cve_lookup", name: "CVE Lookup" },
  { id: "sqli_tester", name: "SQL Injection Tester" },
  { id: "xss_detector", name: "XSS Detector" },
  { id: "csrf_detector", name: "CSRF Detector" },
  { id: "ssrf_detector", name: "SSRF Detector" },
  { id: "xxe_detector", name: "XXE Detector" },
  { id: "auth_tester", name: "Broken Auth Tester" },
  { id: "open_redirect", name: "Open Redirect Tester" },
  { id: "header_analyzer", name: "HTTP Header Analyzer" },
  { id: "ssl_analyzer", name: "SSL/TLS Analyzer" }
];

function Schedule() {
  const [scheduleList, setScheduleList] = useState([]);
  const [schedTarget, setSchedTarget] = useState('');
  const [schedModules, setSchedModules] = useState(['port_scanner']);
  const [schedInterval, setSchedInterval] = useState(60);
  const [schedCron, setSchedCron] = useState('');
  const [schedTriggerType, setSchedTriggerType] = useState('interval');

  const loadSchedules = async () => {
    try {
      const data = await fetchAuth('/api/schedule');
      setScheduleList(data || []);
    } catch (e) { }
  };

  useEffect(() => { loadSchedules(); }, []);

  const handleCreateSchedule = async (e) => {
    e.preventDefault();
    if (!schedTarget.trim()) return;
    try {
      const body = { target: schedTarget, modules: schedModules };
      if (schedTriggerType === 'interval') { body.interval_seconds = schedInterval; }
      else { body.cron_expression = schedCron; }
      await fetchAuth('/api/schedule', { method: 'POST', body: JSON.stringify(body) });
      setSchedTarget('');
      loadSchedules();
    } catch (e) { }
  };

  const pauseJob = async (id) => {
    try { await fetchAuth(`/api/schedule/${id}/pause`, { method: 'POST' }); loadSchedules(); } catch (e) { }
  };
  const resumeJob = async (id) => {
    try { await fetchAuth(`/api/schedule/${id}/resume`, { method: 'POST' }); loadSchedules(); } catch (e) { }
  };
  const removeJob = async (id) => {
    try { await fetchAuth(`/api/schedule/${id}`, { method: 'DELETE' }); loadSchedules(); } catch (e) { }
  };

  return (
    <div className="pane" style={{ height: '100%' }}>
      <h3 className="pane-title">Create New Audit Directive Schedule</h3>
      <form className="schedule-form" onSubmit={handleCreateSchedule}>
        <div className="form-group">
          <label className="form-label">Target URL / Host</label>
          <input type="text" className="form-input" placeholder="e.g. 192.168.1.1 or http://test.com/" value={schedTarget} onChange={e => setSchedTarget(e.target.value)} required />
        </div>
        <div className="schedule-grid">
          <div className="form-group">
            <label className="form-label">Trigger Strategy</label>
            <select className="form-input" value={schedTriggerType} onChange={e => setSchedTriggerType(e.target.value)}>
              <option value="interval">Interval Seconds</option>
              <option value="cron">Cron Expression</option>
            </select>
          </div>
          {schedTriggerType === 'interval' ? (
            <div className="form-group">
              <label className="form-label">Interval (Seconds)</label>
              <input type="number" className="form-input" value={schedInterval} onChange={e => setSchedInterval(Number(e.target.value))} required />
            </div>
          ) : (
            <div className="form-group">
              <label className="form-label">Cron Expression (e.g. "0 12 * * *")</label>
              <input type="text" className="form-input" placeholder="0 12 * * *" value={schedCron} onChange={e => setSchedCron(e.target.value)} required />
            </div>
          )}
        </div>
        <div className="form-group">
          <label className="form-label" style={{ marginBottom: '8px' }}>Select Audit Modules</label>
          <div className="modules-checklist">
            {MODULES_LIST.map(mod => {
              const isSelected = schedModules.includes(mod.id);
              return (
                <div key={mod.id} className={`module-checkbox-card ${isSelected ? 'selected' : ''}`} onClick={() => {
                  if (isSelected) setSchedModules(prev => prev.filter(x => x !== mod.id));
                  else setSchedModules(prev => [...prev, mod.id]);
                }}>
                  <input type="checkbox" checked={isSelected} onChange={() => {}} />
                  <span className="module-label">{mod.name}</span>
                </div>
              );
            })}
          </div>
        </div>
        <button type="submit" className="login-btn">Register Cron Schedule</button>
      </form>

      <h3 className="pane-title" style={{ marginTop: '40px' }}>Active Scheduled Directives</h3>
      <table className="history-table">
        <thead>
          <tr><th>Target</th><th>Modules Enabled</th><th>Next Run Time</th><th>Actions</th></tr>
        </thead>
        <tbody>
          {scheduleList.length === 0 ? (
            <tr><td colSpan="4" style={{ color: 'var(--text-muted)', textAlign: 'center' }}>No active scheduled audits.</td></tr>
          ) : (
            scheduleList.map(item => (
              <tr key={item.id}>
                <td style={{ fontWeight: 'bold', color: 'var(--text-glow)' }}>{item.target}</td>
                <td style={{ fontSize: '11px', color: 'var(--neon-cyan)' }}>{item.modules ? item.modules.join(', ') : 'All'}</td>
                <td style={{ fontSize: '12px' }}>{item.next_run_time ? new Date(item.next_run_time + 'Z').toLocaleString() : 'Paused'}</td>
                <td>
                  {item.next_run_time ? <button className="history-btn" onClick={() => pauseJob(item.id)}>Pause</button> : <button className="history-btn" onClick={() => resumeJob(item.id)}>Resume</button>}
                  <button className="history-btn delete" onClick={() => removeJob(item.id)}>Remove</button>
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}

export default Schedule;
