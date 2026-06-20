import React, { useState, useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import './index.css';

import { getToken, setAuthData, fetchAuth } from './api';

// Components & Pages
import Layout from './components/Layout';
import NetWatchPanel from './components/NetWatchPanel';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import History from './pages/History';
import Schedule from './pages/Schedule';

function App() {
  const [token, setToken] = useState(getToken() || '');
  const [username, setUsername] = useState(localStorage.getItem('username') || '');
  const [role, setRole] = useState(localStorage.getItem('role') || '');

  // Global app state for dashboard
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState(null);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const urlToken = params.get('token');
    if (urlToken) {
      try {
        const payload = JSON.parse(atob(urlToken.split('.')[1]));
        const urlUsername = payload.sub;
        const urlRole = payload.role;
        setAuthData(urlToken, urlUsername, urlRole);
        setToken(urlToken);
        setUsername(urlUsername);
        setRole(urlRole);
        window.history.replaceState({}, document.title, window.location.pathname);
      } catch (e) {
        console.error("Invalid token in URL", e);
      }
    }
  }, []);

  const loadStats = async () => {
    if (!token) return;
    try {
      const data = await fetchAuth('/api/stats');
      setStats(data);
    } catch (e) { }
  };

  useEffect(() => {
    if (token) {
      loadStats();
    }
  }, [token]);

  const handleLoginSuccess = (tok, usr, rl) => {
    setToken(tok);
    setUsername(usr);
    setRole(rl);
  };

  const handleLogout = () => {
    setToken('');
    setUsername('');
    setRole('');
  };

  if (!token) {
    return (
      <BrowserRouter>
        <Routes>
          <Route path="*" element={<Login onLoginSuccess={handleLoginSuccess} />} />
        </Routes>
      </BrowserRouter>
    );
  }

  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Layout username={username} role={role} onLogout={handleLogout} />}>
          <Route index element={<Dashboard alerts={alerts} setAlerts={setAlerts} stats={stats} loadStats={loadStats} />} />
          <Route path="netwatch" element={<NetWatchPanel />} />
          <Route path="history" element={<History loadStats={loadStats} />} />
          <Route path="schedule" element={<Schedule />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}

export default App;