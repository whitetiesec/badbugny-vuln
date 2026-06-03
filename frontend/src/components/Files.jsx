import React, { useState } from 'react';
import { api } from '../api.js';
import LessonHint from './LessonHint.jsx';

export default function Files() {
  const [file, setFile] = useState(null);
  const [out, setOut] = useState(null);
  const [name, setName] = useState('');
  const [content, setContent] = useState('');

  const upload = async (e) => {
    e.preventDefault();
    const fd = new FormData();
    fd.append('file', file);
    const { data } = await api.post('/upload', fd);
    setOut(data);
  };

  const download = (e) => {
    e.preventDefault();
    // VULN: filename comes straight from a text input — try
    //   ../../../../etc/passwd
    window.location.href = '/api/download?file=' + name;
  };

  return (
    <>
      <LessonHint ids={['unrestricted-upload', 'path-traversal']}>
        Upload anything (no MIME check). For traversal, type{' '}
        <code>../../etc/passwd</code> in the Download box.
      </LessonHint>
      <div className="card">
        <h2>Upload (no MIME / extension validation)</h2>
        <form onSubmit={upload}>
          <input type="file" onChange={(e) => setFile(e.target.files[0])} />
          <button>Upload</button>
        </form>
        {out && <pre>{JSON.stringify(out, null, 2)}</pre>}
      </div>
      <div className="card">
        <h2>Download (path traversal)</h2>
        <form onSubmit={download}>
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="welcome.tpl or ../../etc/passwd" />
          <button>Download</button>
        </form>
      </div>
    </>
  );
}
