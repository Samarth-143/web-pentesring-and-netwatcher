import React, { useState, useEffect, useCallback } from 'react';
import { fetchAuth } from '../api';

function AddUserModal({ onClose }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState('user');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [users, setUsers] = useState([]);

  const loadUsers = useCallback(async () => {
    try {
      const data = await fetchAuth('/auth/users');
      if (Array.isArray(data)) setUsers(data);
    } catch (e) {
      // non-fatal: listing requires admin, errors are surfaced on actions
    }
  }, []);

  useEffect(() => {
    loadUsers();
  }, [loadUsers]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    setSubmitting(true);
    try {
      const data = await fetchAuth('/auth/users', {
        method: 'POST',
        body: JSON.stringify({ username: username.trim(), password, role })
      });
      if (data && data.id) {
        setSuccess(`User "${data.username}" (${data.role}) created.`);
        setUsername('');
        setPassword('');
        setRole('user');
        loadUsers();
      } else {
        setError((data && data.detail) ? String(data.detail) : 'Failed to create user');
      }
    } catch (err) {
      setError(err.message || 'Failed to create user');
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async (user) => {
    setError('');
    setSuccess('');
    try {
      const data = await fetchAuth(`/auth/users/${user.id}`, { method: 'DELETE' });
      if (data && data.status === 'success') {
        setSuccess(data.message);
        loadUsers();
      } else {
        setError((data && data.detail) ? String(data.detail) : 'Failed to delete user');
      }
    } catch (err) {
      setError(err.message || 'Failed to delete user');
    }
  };

  return (
    <div style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, background: 'rgba(0,0,0,0.85)', zIndex: 9999, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <div className="glass-panel" style={{ maxWidth: '560px', width: '90%', maxHeight: '85vh', overflowY: 'auto', position: 'relative' }}>
        <button
          onClick={onClose}
          style={{ position: 'absolute', top: '15px', right: '15px', background: 'transparent', border: 'none', color: 'var(--neon-red)', cursor: 'pointer', fontFamily: 'var(--font-mono)' }}
        >[X] CLOSE</button>

        <h2 style={{ color: 'var(--neon-cyan)', borderBottom: '1px solid rgba(0,255,255,0.3)', paddingBottom: '10px' }}>👤 USER MANAGEMENT</h2>

        <form onSubmit={handleSubmit} style={{ marginTop: '20px' }}>
          <div className="form-group">
            <label className="form-label">Username</label>
            <input
              type="text"
              className="form-input"
              placeholder="e.g. analyst1"
              value={username}
              onChange={e => setUsername(e.target.value)}
              minLength={3}
              required
            />
          </div>
          <div className="form-group">
            <label className="form-label">Password</label>
            <input
              type="password"
              className="form-input"
              placeholder="•••••••• (min 6 chars)"
              value={password}
              onChange={e => setPassword(e.target.value)}
              minLength={6}
              required
            />
          </div>
          <div className="form-group">
            <label className="form-label">Role</label>
            <select
              className="form-input"
              value={role}
              onChange={e => setRole(e.target.value)}
            >
              <option value="user">user</option>
              <option value="admin">admin</option>
            </select>
          </div>

          {error && <div className="login-error" style={{ marginBottom: '10px' }}>{error}</div>}
          {success && <div style={{ color: 'var(--neon-green, #39ff14)', marginBottom: '10px', fontFamily: 'var(--font-mono)', fontSize: '13px' }}>{success}</div>}

          <button type="submit" className="login-btn" disabled={submitting}>
            {submitting ? 'Creating...' : 'Create User'}
          </button>
        </form>

        {users.length > 0 && (
          <div style={{ marginTop: '25px' }}>
            <h3 style={{ color: 'var(--neon-cyan)', marginBottom: '10px', fontSize: '14px' }}>Existing Users</h3>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontFamily: 'var(--font-mono)', fontSize: '13px' }}>
              <thead>
                <tr style={{ textAlign: 'left', color: 'var(--text-muted)', borderBottom: '1px solid rgba(255,255,255,0.1)' }}>
                  <th style={{ padding: '6px 4px' }}>ID</th>
                  <th style={{ padding: '6px 4px' }}>Username</th>
                  <th style={{ padding: '6px 4px' }}>Role</th>
                  <th style={{ padding: '6px 4px' }}></th>
                </tr>
              </thead>
              <tbody>
                {users.map(u => (
                  <tr key={u.id} style={{ borderBottom: '1px solid rgba(255,255,255,0.05)', color: 'var(--text-main)' }}>
                    <td style={{ padding: '6px 4px' }}>{u.id}</td>
                    <td style={{ padding: '6px 4px' }}>{u.username}</td>
                    <td style={{ padding: '6px 4px', color: u.role === 'admin' ? 'var(--neon-orange)' : 'var(--text-main)' }}>{u.role}</td>
                    <td style={{ padding: '6px 4px', textAlign: 'right' }}>
                      <button
                        type="button"
                        onClick={() => handleDelete(u)}
                        style={{ background: 'transparent', border: '1px solid var(--neon-red)', color: 'var(--neon-red)', cursor: 'pointer', borderRadius: '3px', padding: '2px 8px', fontFamily: 'var(--font-mono)', fontSize: '12px' }}
                      >DEL</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

export default AddUserModal;
