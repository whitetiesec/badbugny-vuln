import React, { useState } from 'react';
import marked from 'marked';      // VULN: marked 0.3.6 has known XSS bypasses
import _ from 'lodash';            // VULN: lodash 4.17.4 (prototype pollution)
import LessonHint from './LessonHint.jsx';

export default function Search() {
  const [q, setQ] = useState('');
  const [html, setHtml] = useState('');

  const go = async (e) => {
    e.preventDefault();
    // VULN: the backend /api/search endpoint reflects q into HTML using
    // text/template (not html/template) → reflected XSS at the server.
    // We intentionally hit it here so the DAST pipeline can replay it.
    const res = await fetch('/api/search?q=' + encodeURIComponent(q));
    const text = await res.text();
    setHtml(text);
  };

  // VULN: client-side prototype pollution. Build a "filters" object
  // from the URL hash via lodash _.merge — old lodash recursively
  // assigns __proto__ keys, polluting Object.prototype.
  React.useEffect(() => {
    try {
      const hash = window.location.hash.slice(1);
      if (!hash) return;
      const params = Object.fromEntries(new URLSearchParams(hash));
      const target = {};
      // _.merge in 4.17.4 doesn't block __proto__ keys.
      _.merge(target, JSON.parse(decodeURIComponent(params.filters || '{}')));
    } catch {}
  }, []);

  // VULN: render arbitrary markdown (marked 0.3.6 → XSS via raw HTML).
  const md = marked(q || 'Type something…');

  return (
    <>
      <LessonHint ids={['xss-reflected', 'sqli-search', 'xss-markdown', 'proto-pollution-lodash']}>
        Reflected XSS, LIKE-based SQLi, markdown XSS (marked 0.3.6) and lodash
        prototype pollution all live on this page.
      </LessonHint>
      <div className="card">
      <h2>Search</h2>
      <form onSubmit={go}>
        <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="username substring" />
        <button>Search</button>
      </form>
      <h4>Markdown preview (vulnerable marked 0.3.6)</h4>
      {/* VULN: dangerouslySetInnerHTML on user-controlled markdown */}
      <div className="card" dangerouslySetInnerHTML={{ __html: md }} />
      <h4>Raw server response (text/html)</h4>
      <iframe
        title="search-result"
        style={{ width: '100%', height: 240, background: '#fff', border: '1px solid #30363d' }}
        srcDoc={html}
      />
      </div>
    </>
  );
}
