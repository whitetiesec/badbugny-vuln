import React, { useState } from 'react';
import { api } from '../api.js';
import LessonHint from './LessonHint.jsx';

export default function Register() {
  const [form, setForm] = useState({ username: '', email: '', password: '', role: 'user' });
  const [out, setOut] = useState(null);

  const submit = async (e) => {
    e.preventDefault();
    // VULN: client lets you set role to "admin" and pass it straight through.
    // The backend does mass assignment so this becomes privilege escalation.
    const { data } = await api.post('/register', form);
    setOut(data);
  };

  return (
    <>
      <LessonHint ids={['mass-assign-register']}>
        Whatever you put in the form is mass-assigned server-side. Set <code>role</code>{' '}
        to <code>admin</code>, then login.
      </LessonHint>
      <div className="card">
      <h2>Register</h2>
      <form onSubmit={submit}>
        <label>Username</label>
        <input value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} />
        <label>Email</label>
        <input value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} />
        <label>Password</label>
        <input type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
        <label>Role (try "admin" 👀)</label>
        <input value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })} />
        <button type="submit">Register</button>
      </form>
      {out && <pre>{JSON.stringify(out, null, 2)}</pre>}
      </div>
    </>
  );
}
