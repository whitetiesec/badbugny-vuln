import React, { useState } from 'react';
import { api } from '../api.js';
import LessonHint from './LessonHint.jsx';

export default function Notes() {
  const [id, setId] = useState(1);
  const [note, setNote] = useState(null);
  const [err, setErr] = useState(null);

  const load = async () => {
    setErr(null);
    try {
      const { data } = await api.get('/notes/' + id);
      setNote(data);
    } catch (e) {
      setErr(e.response?.data?.error || e.message);
    }
  };

  return (
    <>
      <LessonHint ids={['missing-authz-notes']}>
        Login as <code>bob</code>, then ask for note id <code>1</code> — you'll read
        admin's private note even though you don't own it.
      </LessonHint>
      <div className="card">
      <h2>Notes (missing-authz / IDOR demo)</h2>
      <p>Login as <code>bob</code> and request <code>id=1</code> — you will read admin's private note.</p>
      <input type="number" value={id} onChange={(e) => setId(e.target.value)} />
      <button onClick={load}>Fetch note</button>
      {err && <pre className="danger">{err}</pre>}
      {note && <pre>{JSON.stringify(note, null, 2)}</pre>}
      </div>
    </>
  );
}
