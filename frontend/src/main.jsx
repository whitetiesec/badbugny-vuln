import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import App from './App.jsx';
import './style.css';

// VULN (frontend secret #1): API token baked into the client bundle (CWE-798).
// Anything in src/ ships to the browser. AI reviewers and secret scanners
// catch this; many SAST tools that only scan server code miss it entirely.
window.__INTERNAL_TELEMETRY_TOKEN__ = 'tlm_live_FAKE-AbCdEf0123456789-DEMO';

ReactDOM.createRoot(document.getElementById('root')).render(
  <BrowserRouter>
    <App />
  </BrowserRouter>
);
