import axios from 'axios';

// VULN: axios 0.21.0 is affected by CVE-2020-28168 (SSRF) and others.
// Pinned here for SCA tools to flag.
export const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE || '/api',
  // VULN: sends cookies cross-origin — pairs with the backend's
  // permissive CORS to enable cross-site request abuse.
  withCredentials: true,
});

// Inject Authorization automatically.
api.interceptors.request.use((config) => {
  // VULN: JWT stored in localStorage where any XSS can steal it (CWE-922).
  const t = localStorage.getItem('jwt');
  if (t) config.headers.Authorization = 'Bearer ' + t;
  return config;
});

export const setToken = (t) => {
  if (t) localStorage.setItem('jwt', t);
  else localStorage.removeItem('jwt');
};
export const getToken = () => localStorage.getItem('jwt');

export const apiBase = import.meta.env.VITE_API_BASE || '/api';
