import React, { useState } from 'react';
import { NavLink, Outlet, useNavigate } from 'react-router-dom';
import { clearAuthData } from '../api';
import AddUserModal from './AddUserModal';

const NavIcon = ({ type, active }) => {
  const color = active ? '#a855f7' : '#6b7a99';
  const glow = active ? 'drop-shadow(0 0 6px rgba(168,85,247,0.5))' : 'none';
  const icons = {
    dashboard: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ filter: glow }}>
        <rect x="3" y="3" width="7" height="7" rx="1" /><rect x="14" y="3" width="7" height="7" rx="1" />
        <rect x="3" y="14" width="7" height="7" rx="1" /><rect x="14" y="14" width="7" height="7" rx="1" />
      </svg>
    ),
    monitor: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ filter: glow }}>
        <path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7S2 12 2 12z" /><circle cx="12" cy="12" r="3" />
      </svg>
    ),
    archive: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ filter: glow }}>
        <polyline points="21 8 21 21 3 21 3 8" /><rect x="1" y="3" width="22" height="5" rx="1" />
        <line x1="10" y1="12" x2="14" y2="12" />
      </svg>
    ),
    schedule: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ filter: glow }}>
        <circle cx="12" cy="12" r="10" /><polyline points="12 6 12 12 16 14" />
      </svg>
    ),
  };
  return icons[type] || null;
};

function Layout({ username, role, onLogout }) {
  const [showLegalModal, setShowLegalModal] = useState(false);
  const [showAddUserModal, setShowAddUserModal] = useState(false);
  const [isSidebarExpanded, setIsSidebarExpanded] = useState(true);
  const navigate = useNavigate();

  const handleLogout = () => {
    clearAuthData();
    onLogout();
    navigate('/login');
  };

  return (
    <>
      <header className="header-bar">
        <div className="logo-section">
          <button
            onClick={() => setIsSidebarExpanded(!isSidebarExpanded)}
            style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: '18px', padding: '4px', transition: 'color 0.2s' }}
            onMouseEnter={e => e.target.style.color = 'var(--neon-cyan)'}
            onMouseLeave={e => e.target.style.color = 'var(--text-muted)'}
          >
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
              <line x1="3" y1="6" x2="21" y2="6" /><line x1="3" y1="12" x2="21" y2="12" /><line x1="3" y1="18" x2="21" y2="18" />
            </svg>
          </button>
          <div>
            <h1 className="logo-text">PHANTOM</h1>
            <p className="logo-sub">Security Console v3.0</p>
          </div>
        </div>

        <div style={{ flex: 1 }}></div>

        <div className="user-profile">
          <button
            type="button"
            className="scan-btn"
            style={{ background: 'rgba(249, 115, 22, 0.08)', color: 'var(--neon-orange)', border: '1px solid rgba(249, 115, 22, 0.25)', boxShadow: '0 0 15px rgba(249, 115, 22, 0.08)' }}
            onClick={() => setShowLegalModal(true)}
          >
            LEGAL & SAFE TARGETS
          </button>
          {role === 'admin' && (
            <button
              type="button"
              className="scan-btn"
              style={{ background: 'rgba(34, 211, 238, 0.08)', color: 'var(--neon-cyan)', border: '1px solid rgba(34, 211, 238, 0.25)', boxShadow: '0 0 15px rgba(34, 211, 238, 0.08)' }}
              onClick={() => setShowAddUserModal(true)}
            >
              + ADD USER
            </button>
          )}
          <span className="user-role">{username} // {role}</span>
          <button type="button" className="logout-btn" onClick={handleLogout}>DISCONNECT</button>
        </div>
      </header>

      {showLegalModal && (
        <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.85)', backdropFilter: 'blur(8px)', zIndex: 9999, display: 'flex', alignItems: 'center', justifyContent: 'center', animation: 'fadeIn 0.2s ease-out' }}>
          <div className="glass-panel" style={{ maxWidth: '600px', width: '90%', maxHeight: '80vh', overflowY: 'auto', position: 'relative', animation: 'slideInUp 0.3s ease-out' }}>
            <button
              onClick={() => setShowLegalModal(false)}
              style={{ position: 'absolute', top: '15px', right: '15px', background: 'transparent', border: 'none', color: 'var(--neon-red)', cursor: 'pointer', fontFamily: 'var(--font-mono)', fontSize: '12px', letterSpacing: '1px' }}
            >[X] CLOSE</button>
            <h2 style={{ color: 'var(--neon-orange)', borderBottom: '1px solid rgba(249,115,22,0.2)', paddingBottom: '12px', fontFamily: 'var(--font-heading)', fontSize: '16px', letterSpacing: '1px' }}>LEGAL DISCLAIMER & SAFE TARGETS</h2>

            <div style={{ marginTop: '20px', lineHeight: '1.7', fontSize: '13px' }}>
              <h3 style={{ color: 'var(--neon-cyan)', marginBottom: '8px', fontFamily: 'var(--font-heading)', fontSize: '13px', letterSpacing: '1px' }}>Responsible Disclosure</h3>
              <p style={{ color: 'var(--text-muted)' }}>
                Phantom is an automated offensive security suite. It is designed <strong style={{ color: 'var(--text-main)' }}>strictly</strong> for educational purposes, authorized security auditing, and testing systems you own.
              </p>
              <p style={{ color: 'var(--text-muted)', marginTop: '8px' }}>
                You are solely responsible for ensuring you have explicit, written permission before initiating any scans.
              </p>

              <h3 style={{ color: 'var(--neon-cyan)', marginTop: '24px', marginBottom: '8px', fontFamily: 'var(--font-heading)', fontSize: '13px', letterSpacing: '1px' }}>Safe Practice Targets</h3>
              <ul style={{ color: 'var(--text-main)', fontFamily: 'var(--font-mono)', fontSize: '12px', background: 'rgba(0,0,0,0.3)', padding: '16px 24px', borderRadius: '8px', border: '1px solid rgba(100,120,180,0.1)', lineHeight: '2' }}>
                <li>scanme.nmap.org</li>
                <li>testphp.vulnweb.com</li>
                <li>juice-shop.herokuapp.com</li>
                <li>xss-game.appspot.com</li>
                <li>example.com</li>
              </ul>
            </div>

            <div style={{ marginTop: '30px', textAlign: 'right' }}>
              <button
                onClick={() => setShowLegalModal(false)}
                className="scan-btn"
              >I UNDERSTAND</button>
            </div>
          </div>
        </div>
      )}

      {showAddUserModal && role === 'admin' && (
        <AddUserModal onClose={() => setShowAddUserModal(false)} />
      )}

      <div className="app-container">
        <aside className="sidebar" style={{ width: isSidebarExpanded ? '220px' : '60px', transition: 'width 0.3s cubic-bezier(0.4, 0, 0.2, 1)' }}>
          <nav className="nav-menu">
            <NavLink to="/" className={({isActive}) => `nav-item ${isActive ? 'active' : ''}`} end>
              <NavIcon type="dashboard" active={window.location.pathname === '/'} />
              {isSidebarExpanded && <span>Audits Dashboard</span>}
            </NavLink>
            <NavLink to="/netwatch" className={({isActive}) => `nav-item ${isActive ? 'active' : ''}`}>
              <NavIcon type="monitor" active={window.location.pathname === '/netwatch'} />
              {isSidebarExpanded && <span>Net-Watch Monitor</span>}
            </NavLink>
            <NavLink to="/history" className={({isActive}) => `nav-item ${isActive ? 'active' : ''}`}>
              <NavIcon type="archive" active={window.location.pathname === '/history'} />
              {isSidebarExpanded && <span>Scan Archives</span>}
            </NavLink>
            <NavLink to="/schedule" className={({isActive}) => `nav-item ${isActive ? 'active' : ''}`}>
              <NavIcon type="schedule" active={window.location.pathname === '/schedule'} />
              {isSidebarExpanded && <span>Audit Scheduler</span>}
            </NavLink>
          </nav>

          <div className="sidebar-footer" style={{ textAlign: isSidebarExpanded ? 'left' : 'center' }}>
            {isSidebarExpanded ? (
              <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: 'var(--neon-green)', boxShadow: '0 0 6px var(--neon-green)', animation: 'pulseDot 2s infinite' }}></span>
                SYSTEM STABLE
              </span>
            ) : (
              <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: 'var(--neon-green)', boxShadow: '0 0 6px var(--neon-green)', display: 'inline-block' }}></span>
            )}
          </div>
        </aside>

        <main className="content-area">
          <Outlet />
        </main>
      </div>
    </>
  );
}

export default Layout;
