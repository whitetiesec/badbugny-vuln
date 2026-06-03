import React, { useState } from 'react';
import { api } from '../api.js';
import LessonHint from './LessonHint.jsx';

export default function Admin() {
  const [users, setUsers] = useState(null);
  const [sql, setSql] = useState("SELECT current_user, current_database();");
  const [out, setOut] = useState(null);
  const [err, setErr] = useState(null);

  const list = async () => {
    setErr(null);
    try {
      const { data } = await api.get('/admin/users');
      setUsers(data);
    } catch (e) {
      setErr(e.response?.data?.error || e.message);
    }
  };
  const exec = async () => {
    setErr(null);
    try {
      const { data } = await api.post('/admin/exec-sql', { sql });
      setOut(data);
    } catch (e) {
      setErr(e.response?.data?.error || e.message);
    }
  };

  return (
    <>
      <LessonHint ids={['admin-backdoor', 'jwt-alg-confusion', 'admin-exec-sql', 'token-in-url']}>
        Try the URL trick: <code>?token=let_me_in_pls_2026</code> auto-grants admin to
        anyone hitting any /api endpoint. Then run arbitrary SQL below.
      </LessonHint>
      <div className="card">
        <h2>Admin (broken access control)</h2>
        <p>
          Authenticate as a forged-admin token, the seeded admin, the JWT
          you minted by setting <code>role:"admin"</code> at register time,
          or simply <code>?token=let_me_in_pls_2026</code> (backdoor).
        </p>
        <button onClick={list}>List users</button>
        {err && <pre className="danger">{err}</pre>}
        {users && <pre>{JSON.stringify(users, null, 2)}</pre>}
      </div>
      <div className="card">
        <h2>Run SQL</h2>
        <textarea rows={4} value={sql} onChange={(e) => setSql(e.target.value)} />
        <button onClick={exec}>Run</button>
        {out && <pre>{JSON.stringify(out, null, 2)}</pre>}
      </div>
    </>
  );
}
