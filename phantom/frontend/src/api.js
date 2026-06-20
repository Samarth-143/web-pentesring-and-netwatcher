export const API_BASE = import.meta.env.VITE_API_BASE || 'http://127.0.0.1:8000';

export const getToken = () => localStorage.getItem('token');
export const setAuthData = (token, username, role) => {
  localStorage.setItem('token', token);
  localStorage.setItem('username', username);
  localStorage.setItem('role', role);
};

export const clearAuthData = () => {
  localStorage.removeItem('token');
  localStorage.removeItem('username');
  localStorage.removeItem('role');
};

export const fetchAuth = async (url, options = {}) => {
  const token = getToken();
  const headers = options.headers || {};
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  
  const response = await fetch(`${API_BASE}${url}`, {
    cache: 'no-store',
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...headers
    }
  });
  
  if (response.status === 401) {
    clearAuthData();
    window.location.reload(); // App will show login screen since token is gone
    throw new Error('Session expired. Please log in again.');
  }
  
  return response.json();
};
