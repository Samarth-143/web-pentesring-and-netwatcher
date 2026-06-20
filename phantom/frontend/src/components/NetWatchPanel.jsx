import React, { useState, useEffect, useRef } from 'react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

// Net-Watch real-time WebSocket traffic monitor panel (Enhanced)
function NetWatchPanel() {
  const [snapshot, setSnapshot] = useState(null);
  const [anomalyLogs, setAnomalyLogs] = useState([]);
  const [chartData, setChartData] = useState([]);
  const [wsConnected, setWsConnected] = useState(false);
  const [wsError, setWsError] = useState(false);
  const [activeView, setActiveView] = useState('telemetry'); // 'telemetry' | 'alerts'
  const wsRef = useRef(null);

  useEffect(() => {
    let wsUrl = (import.meta.env.VITE_WS_URL || 'ws://127.0.0.1:8000/ws/traffic?interface=eth0');
    const token = localStorage.getItem('token');
    if (token) {
      wsUrl += (wsUrl.includes('?') ? '&' : '?') + 'token=' + encodeURIComponent(token);
    }

    const connect = () => {
      const socket = new WebSocket(wsUrl);
      wsRef.current = socket;

      socket.onopen = () => { setWsConnected(true); setWsError(false); };
      socket.onclose = (event) => {
        setWsConnected(false);
        // Code 4001 = auth failure (invalid/expired token)
        if (event.code === 4001) {
          localStorage.removeItem('token');
          localStorage.removeItem('username');
          localStorage.removeItem('role');
          window.location.reload(); // Redirect to login
          return;
        }
        setTimeout(connect, 4000);
      };
      socket.onerror = () => { setWsError(true); setWsConnected(false); };

      socket.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          setSnapshot(data);

          setChartData(prev => {
            const timeStr = new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
            return [...prev, { time: timeStr, bps: data.bytes_per_second || 0, pps: data.packets_per_second || 0 }].slice(-30);
          });

          if (data.status && data.status !== 'normal' && data.status !== 'learning' && data.status !== 'error' && data.status !== 'empty') {
            setAnomalyLogs(prev => {
              const isDup = prev.length > 0 && prev[0].status === data.status && prev[0].timestamp === data.timestamp;
              if (isDup) return prev;
              return [{ status: data.status, z_score: data.z_score, timestamp: data.timestamp, pps: data.packets_per_second, bps: data.bytes_per_second }, ...prev].slice(0, 50);
            });
          }
        } catch (err) { /* silent */ }
      };
    };

    connect();
    return () => { if (wsRef.current) wsRef.current.close(); };
  }, []);

  const getStatusClass = (status) => {
    if (!status || status === 'learning' || status === 'normal') return 'ok';
    if (status === 'error' || status === 'empty') return 'anomaly';
    return 'anomaly';
  };

  const getStatusColor = (status) => {
    if (!status || status === 'normal' || status === 'learning') return 'var(--neon-cyan)';
    if (status === 'DDOS_SUSPECTED') return 'var(--neon-red)';
    if (status === 'PORT_SCAN') return '#a855f7';
    if (status === 'TRAFFIC_SPIKE') return 'var(--neon-orange)';
    return 'var(--neon-yellow)';
  };

  const isAnomalous = snapshot && snapshot.z_score > 2.0;

  return (
    <div>
      {/* Connection status bar */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', padding: '8px 14px', background: 'rgba(0,0,0,0.3)', borderRadius: '6px', border: '1px solid var(--border)' }}>
        <span style={{ fontFamily: 'var(--font-nav)', fontSize: '13px', letterSpacing: '1px' }}>NET-WATCH TELEMETRY</span>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '11px' }}>
          <span style={{
            display: 'inline-block', width: '8px', height: '8px', borderRadius: '50%',
            background: wsError ? 'var(--neon-red)' : wsConnected ? 'var(--neon-cyan)' : '#666',
            boxShadow: wsConnected ? '0 0 8px var(--neon-cyan)' : wsError ? '0 0 8px var(--neon-red)' : 'none',
            animation: wsConnected ? 'pulse-dot 2s infinite' : 'none'
          }} />
          <span style={{ color: wsError ? 'var(--neon-red)' : wsConnected ? 'var(--neon-cyan)' : 'var(--text-muted)' }}>
            {wsError ? 'CONNECTION ERROR' : wsConnected ? 'DAEMON ONLINE' : 'CONNECTING...'}
          </span>
        </div>
        <div style={{ display: 'flex', gap: '8px' }}>
          <button
            style={{ background: activeView === 'telemetry' ? 'rgba(0,212,170,0.15)' : 'transparent', border: '1px solid var(--border)', borderRadius: '4px', padding: '3px 10px', color: activeView === 'telemetry' ? 'var(--neon-cyan)' : 'var(--text-muted)', cursor: 'pointer', fontSize: '10px', fontFamily: 'var(--font-nav)' }}
            onClick={() => setActiveView('telemetry')}>METRICS</button>
          <button
            style={{ background: activeView === 'alerts' ? 'rgba(255,59,59,0.15)' : 'transparent', border: '1px solid var(--border)', borderRadius: '4px', padding: '3px 10px', color: activeView === 'alerts' ? 'var(--neon-red)' : 'var(--text-muted)', cursor: 'pointer', fontSize: '10px', fontFamily: 'var(--font-nav)' }}
            onClick={() => setActiveView('alerts')}>
            ALERTS {anomalyLogs.length > 0 && <span style={{ background: 'var(--neon-red)', color: '#000', borderRadius: '8px', padding: '0 5px', marginLeft: '4px' }}>{anomalyLogs.length}</span>}
          </button>
        </div>
      </div>

      {!snapshot ? (
        <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '300px', flexDirection: 'column', gap: '12px' }}>
          <div className="spinner" />
          <span style={{ color: 'var(--text-muted)', fontSize: '12px', letterSpacing: '1px' }}>INITIALIZING NETWORK CAPTURE DAEMON...</span>
          <span style={{ color: 'var(--text-muted)', fontSize: '11px' }}>Ensure traffic_daemon.py is running with admin privileges</span>
        </div>
      ) : activeView === 'telemetry' ? (
        <div className="dashboard-grid">
          <div className="pane" style={{ padding: '0', background: 'transparent', border: 'none' }}>
            {/* Metric cards */}
            <div className="telemetry-grid" style={{ gridTemplateColumns: 'repeat(3, 1fr)', gap: '12px' }}>
              <div className="glass-panel">
                <div className="telemetry-label">Capture Interface</div>
                <div className="telemetry-value metric-glow" style={{ fontSize: '20px', color: 'var(--neon-cyan)' }}>{(snapshot.interface || 'eth0').toUpperCase()}</div>
              </div>
              <div className={`glass-panel ${isAnomalous ? 'anomaly-alert-pulse' : ''}`}>
                <div className="telemetry-label">Packets / sec</div>
                <div className="telemetry-value metric-glow" style={{ fontSize: '22px', color: isAnomalous ? 'var(--neon-orange)' : 'inherit' }}>{snapshot.packets_per_second ?? '--'}</div>
              </div>
              <div className={`glass-panel ${isAnomalous ? 'anomaly-alert-pulse' : ''}`}>
                <div className="telemetry-label">Bytes / sec</div>
                <div className="telemetry-value metric-glow" style={{ fontSize: '22px', color: isAnomalous ? 'var(--neon-orange)' : 'inherit' }}>{snapshot.bytes_per_second ?? '--'}</div>
              </div>
            </div>

            {/* Status bar */}
            <div className={`glass-panel ${isAnomalous ? 'anomaly-alert-pulse' : ''}`} style={{ marginTop: '12px', padding: '14px 18px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <div className="telemetry-label">Sniffer Status</div>
                  <div className={`telemetry-value ${getStatusClass(snapshot.status)}`} style={{ fontSize: '18px', color: getStatusColor(snapshot.status) }}>
                    {(snapshot.status || 'unknown').replace(/_/g, ' ')}
                  </div>
                </div>
                <div style={{ textAlign: 'center' }}>
                  <div className="telemetry-label">Source Engine</div>
                  <div style={{ fontSize: '11px', color: snapshot.is_simulated ? 'var(--neon-yellow)' : 'var(--neon-cyan)', fontFamily: 'var(--font-mono)' }}>
                    {snapshot.is_simulated ? 'SIMULATOR_FALLBACK' : 'RAW_SOCKET_CAP_NET_RAW'}
                  </div>
                </div>
                <div style={{ textAlign: 'right' }}>
                  <div className="telemetry-label">Anomaly Z-Score</div>
                  <div className={`telemetry-value ${isAnomalous ? 'anomaly' : 'ok'}`} style={{ fontSize: '24px', textShadow: isAnomalous ? '0 0 15px var(--neon-red)' : 'none' }}>
                    {snapshot.z_score ?? '0.00'}
                  </div>
                </div>
              </div>
            </div>

            {/* Charts: BPS + PPS side by side */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginTop: '12px' }}>
              <div className="glass-panel" style={{ height: '180px', padding: '10px 16px' }}>
                <div className="telemetry-label" style={{ marginBottom: '6px' }}>Traffic Velocity — B/s</div>
                <ResponsiveContainer width="100%" height="85%">
                  <AreaChart data={chartData} margin={{ top: 0, right: 0, left: -20, bottom: 0 }}>
                    <defs>
                      <linearGradient id="gradBps" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="var(--neon-cyan)" stopOpacity={0.7}/>
                        <stop offset="95%" stopColor="var(--neon-cyan)" stopOpacity={0}/>
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.07)" vertical={false} />
                    <XAxis dataKey="time" stroke="var(--text-muted)" tick={{fontSize: 9}} minTickGap={40} />
                    <YAxis stroke="var(--text-muted)" tick={{fontSize: 9}} />
                    <Tooltip contentStyle={{ backgroundColor: 'rgba(10,10,15,0.95)', border: '1px solid var(--border)', borderRadius: '6px', fontSize: '11px' }} />
                    <Area type="monotone" dataKey="bps" name="B/s" stroke="var(--neon-cyan)" fillOpacity={1} fill="url(#gradBps)" isAnimationActive={false} />
                  </AreaChart>
                </ResponsiveContainer>
              </div>

              <div className="glass-panel" style={{ height: '180px', padding: '10px 16px' }}>
                <div className="telemetry-label" style={{ marginBottom: '6px' }}>Packet Rate — PPS</div>
                <ResponsiveContainer width="100%" height="85%">
                  <AreaChart data={chartData} margin={{ top: 0, right: 0, left: -20, bottom: 0 }}>
                    <defs>
                      <linearGradient id="gradPps" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="var(--neon-purple)" stopOpacity={0.7}/>
                        <stop offset="95%" stopColor="var(--neon-purple)" stopOpacity={0}/>
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.07)" vertical={false} />
                    <XAxis dataKey="time" stroke="var(--text-muted)" tick={{fontSize: 9}} minTickGap={40} />
                    <YAxis stroke="var(--text-muted)" tick={{fontSize: 9}} />
                    <Tooltip contentStyle={{ backgroundColor: 'rgba(10,10,15,0.95)', border: '1px solid var(--border)', borderRadius: '6px', fontSize: '11px' }} />
                    <Area type="monotone" dataKey="pps" name="Pkts/s" stroke="var(--neon-purple)" fillOpacity={1} fill="url(#gradPps)" isAnimationActive={false} />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Cumulative stats */}
            <div className="glass-panel" style={{ marginTop: '12px', display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
              <div>
                <div className="telemetry-label" style={{ marginBottom: '6px' }}>Accumulated Metrics</div>
                <p style={{ fontSize: '12px', margin: '3px 0' }}>Total Bytes: <span style={{ color: 'var(--neon-cyan)', fontWeight: 'bold' }}>{(snapshot.total_bytes || 0).toLocaleString()}</span></p>
                <p style={{ fontSize: '12px', margin: '3px 0' }}>Total Packets: <span style={{ color: 'var(--neon-cyan)', fontWeight: 'bold' }}>{(snapshot.total_packets || 0).toLocaleString()}</span></p>
              </div>
              {snapshot.details && snapshot.details.max_ports_scanned > 0 && (
                <div style={{ borderLeft: '2px solid var(--neon-orange)', paddingLeft: '12px' }}>
                  <div className="telemetry-label" style={{ color: 'var(--neon-orange)', marginBottom: '6px' }}>Active Port Probe</div>
                  <p style={{ fontSize: '12px', margin: '3px 0' }}>Source: <span style={{ color: 'var(--neon-yellow)', fontWeight: 'bold' }}>{snapshot.details.scanner_ip}</span></p>
                  <p style={{ fontSize: '12px', margin: '3px 0' }}>Ports Scanned: <span style={{ color: 'var(--neon-red)', fontWeight: 'bold' }}>{snapshot.details.max_ports_scanned}</span></p>
                </div>
              )}
              <div style={{ textAlign: 'right' }}>
                <div className="telemetry-label" style={{ marginBottom: '6px' }}>Rolling Window</div>
                <p style={{ fontSize: '12px', margin: '3px 0' }}>Mean BPS: <span style={{ color: 'var(--text-main)' }}>{snapshot.details?.mean_bps?.toFixed(1) ?? '--'}</span></p>
                <p style={{ fontSize: '12px', margin: '3px 0' }}>Mean PPS: <span style={{ color: 'var(--text-main)' }}>{snapshot.details?.mean_pps?.toFixed(1) ?? '--'}</span></p>
              </div>
            </div>

            {/* Per-IP LIVE Table */}
            {snapshot.per_ip && snapshot.per_ip.length > 0 && (
              <div className="glass-panel" style={{ marginTop: '12px', padding: '10px 16px', overflowX: 'auto' }}>
                <div className="telemetry-label" style={{ marginBottom: '8px', display: 'flex', justifyContent: 'space-between' }}>
                  <span>Active Sources (LIVE)</span>
                  <span style={{ fontSize: '10px', color: 'var(--text-muted)' }}>Top 50 by PPS</span>
                </div>
                <table className="history-table" style={{ fontSize: '11px', width: '100%' }}>
                  <thead>
                    <tr>
                      <th style={{ textAlign: 'left', padding: '6px 4px' }}>Source IP</th>
                      <th style={{ textAlign: 'right', padding: '6px 4px' }}>PPS</th>
                      <th style={{ textAlign: 'right', padding: '6px 4px' }}>KB/s</th>
                      <th style={{ textAlign: 'center', padding: '6px 4px' }}>Proto</th>
                      <th style={{ textAlign: 'center', padding: '6px 4px' }}>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {snapshot.per_ip.map((row, idx) => (
                      <tr key={idx} style={{ background: row.anomaly !== 'normal' && row.anomaly !== 'learning' ? 'rgba(255, 46, 92, 0.05)' : 'transparent' }}>
                        <td style={{ padding: '6px 4px', fontFamily: 'var(--font-mono)', color: row.private ? 'var(--text-main)' : 'var(--neon-cyan)' }}>
                          {row.ip}
                        </td>
                        <td style={{ padding: '6px 4px', textAlign: 'right', fontFamily: 'var(--font-mono)' }}>{row.pps}</td>
                        <td style={{ padding: '6px 4px', textAlign: 'right', fontFamily: 'var(--font-mono)' }}>{row.kbs}</td>
                        <td style={{ padding: '6px 4px', textAlign: 'center' }}>
                          <span style={{ background: 'rgba(255,255,255,0.05)', padding: '2px 6px', borderRadius: '3px', fontSize: '9px' }}>
                            {row.top_proto}
                          </span>
                        </td>
                        <td style={{ padding: '6px 4px', textAlign: 'center' }}>
                          <span style={{ color: getStatusColor(row.anomaly), fontWeight: row.anomaly !== 'normal' ? 'bold' : 'normal' }}>
                            {row.anomaly.replace(/_/g, ' ')}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Right panel: anomaly log preview */}
          <div className="pane glass-panel">
            <h3 className="pane-title" style={{ borderBottom: '1px solid rgba(255,255,255,0.1)', paddingBottom: '10px', display: 'flex', justifyContent: 'space-between' }}>
              <span>Anomaly Alert Logs</span>
              {anomalyLogs.length > 0 && (
                <button onClick={() => setAnomalyLogs([])} style={{ background: 'transparent', border: '1px solid var(--border)', color: 'var(--text-muted)', cursor: 'pointer', borderRadius: '4px', fontSize: '10px', padding: '2px 8px' }}>CLEAR</button>
              )}
            </h3>
            <div className="alerts-list">
              {anomalyLogs.length === 0 ? (
                <p style={{ color: 'var(--text-muted)', fontSize: '11px', textAlign: 'center', padding: '40px 20px' }}>
                  NO ANOMALIES DETECTED.<br/><br/>
                  Monitoring for port scans, volumetric spikes, and DDoS profiles...
                </p>
              ) : (
                anomalyLogs.map((log, i) => (
                  <div key={i} className="alert-item" style={{ background: 'rgba(0,0,0,0.3)', borderLeft: `3px solid ${getStatusColor(log.status)}`, marginBottom: '10px', animation: 'slideInUp 0.3s ease-out backwards', animationDelay: `${i * 0.05}s` }}>
                    <div className="alert-type" style={{ color: getStatusColor(log.status) }}>{log.status.replace(/_/g, ' ')}</div>
                    <div className="alert-desc">Z-score: <span style={{ color: 'var(--neon-red)', fontWeight: 'bold' }}>{log.z_score}</span></div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '6px' }}>
                      <div style={{ fontSize: '10px', color: 'var(--text-muted)' }}>pps: {log.pps} // bps: {log.bps}</div>
                      <div className="alert-time">{log.timestamp ? new Date(log.timestamp + 'Z').toLocaleTimeString() : '--'}</div>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      ) : (
        /* ALERTS full view */
        <div className="pane">
          <h3 className="pane-title" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span>All Anomaly Events ({anomalyLogs.length})</span>
            {anomalyLogs.length > 0 && (
              <button onClick={() => setAnomalyLogs([])} style={{ background: 'rgba(255,59,59,0.1)', border: '1px solid var(--neon-red)', color: 'var(--neon-red)', cursor: 'pointer', borderRadius: '4px', fontSize: '10px', padding: '3px 10px' }}>CLEAR ALL</button>
            )}
          </h3>
          {anomalyLogs.length === 0 ? (
            <p style={{ color: 'var(--text-muted)', textAlign: 'center', padding: '60px 20px' }}>No anomalies captured this session.</p>
          ) : (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '12px', marginTop: '16px' }}>
              {anomalyLogs.map((log, i) => (
                <div key={i} className="glass-panel" style={{ borderLeft: `3px solid ${getStatusColor(log.status)}`, animation: 'slideInUp 0.3s ease-out backwards', animationDelay: `${i * 0.05}s` }}>
                  <div style={{ fontWeight: 'bold', color: getStatusColor(log.status), fontSize: '12px', marginBottom: '6px' }}>{log.status.replace(/_/g, ' ')}</div>
                  <div style={{ fontSize: '12px' }}>Z-score: <strong style={{ color: 'var(--neon-red)' }}>{log.z_score}</strong></div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>PPS: {log.pps} | BPS: {log.bps}</div>
                  <div style={{ fontSize: '10px', color: 'var(--text-muted)', marginTop: '4px' }}>{log.timestamp ? new Date(log.timestamp + 'Z').toLocaleString() : '--'}</div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}


export default NetWatchPanel;
