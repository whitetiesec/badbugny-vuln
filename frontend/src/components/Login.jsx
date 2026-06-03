import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api, setToken } from '../api.js';
import LessonHint from './LessonHint.jsx';

export default function Login() {
  const [u, setU] = useState('');
  const [p, setP] = useState('');
  const [err, setErr] = useState(null);
  const nav = useNavigate();

  const submit = async (e) => {
    e.preventDefault();
    try {
      // VULN: backend SQL-injects the username/password it receives.
      // The form does no client validation either.
      const { data } = await api.post('/login', { username: u, password: p });
      setToken(data.token);
      nav('/profile');
    } catch (e) {
      // VULN: render server error HTML directly (DOM-XSS sink).
      setErr(e.response?.data || { error: e.message });
    }
  };

  return (
    <>
      <LessonHint ids={['sqli-login', 'verbose-errors', 'jwt-weak-secret', 'jwt-alg-confusion']}>
        The login form concatenates your input into raw SQL. Try{' '}
        <code>username: admin'-- </code> with any password.
      </LessonHint>
      <div className="card">
      <h2>Login</h2>
      <form onSubmit={submit}>
        <label>Username</label>
        <input value={u} onChange={(e) => setU(e.target.value)} />
        <label>Password</label>
        <input type="password" value={p} onChange={(e) => setP(e.target.value)} />
        <button type="submit">Login</button>
      </form>
      {err && (
        <pre
          // VULN: the server returns the offending SQL query verbatim, and we
          // render it raw — combine with a crafted username to demonstrate
          // reflected XSS in the login error path.
          dangerouslySetInnerHTML={{ __html: JSON.stringify(err, null, 2) }}
        />
      )}
      </div>
    </>
  );
}
