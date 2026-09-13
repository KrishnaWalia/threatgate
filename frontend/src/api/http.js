import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:4000';

const http = axios.create({ baseURL: API_BASE_URL });

// Every outgoing request picks up the current token from
// localStorage, if there is one. This is what turns "login once"
// into "stay logged in across every dashboard call".
http.interceptors.request.use((config) => {
  const token = localStorage.getItem('threatgate_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// A 401 anywhere means the token is missing/expired/invalid —
// clear it and bounce to login instead of leaving the app stuck
// showing stale, unauthorized data.
http.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('threatgate_token');
      localStorage.removeItem('threatgate_user');
      if (window.location.pathname !== '/login') {
        window.location.href = '/login';
      }
    }
    return Promise.reject(error);
  }
);

export default http;
export { API_BASE_URL };
