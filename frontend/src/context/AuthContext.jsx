import { createContext, useContext, useState, useCallback } from 'react';
import http from '../api/http';
import { disconnectSocket } from '../api/socket';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => {
    const stored = localStorage.getItem('threatgate_user');
    return stored ? JSON.parse(stored) : null;
  });
  const [error, setError] = useState('');

  const login = useCallback(async (email, password) => {
    setError('');
    try {
      const { data } = await http.post('/api/auth/login', { email, password });
      localStorage.setItem('threatgate_token', data.token);
      localStorage.setItem('threatgate_user', JSON.stringify(data.user));
      setUser(data.user);
      return true;
    } catch (err) {
      setError(err.response?.data?.error || 'Login failed. Check your connection and try again.');
      return false;
    }
  }, []);

  const logout = useCallback(() => {
    localStorage.removeItem('threatgate_token');
    localStorage.removeItem('threatgate_user');
    disconnectSocket();
    setUser(null);
  }, []);

  const isAdmin = user?.role === 'admin';

  return (
    <AuthContext.Provider value={{ user, login, logout, error, isAdmin }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used inside an AuthProvider');
  return ctx;
}
