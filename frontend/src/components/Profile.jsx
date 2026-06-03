import React, { useEffect, useState } from 'react';
import { api } from '../api.js';
import LessonHint from './LessonHint.jsx';

export default function Profile() {
  const [me, setMe] = useState(null);

  useEffect(() => {
    api.get('/profile').then((r) => setMe(r.data));
  }, []);

  if (!me) return <p>loading…</p>;

  // VULN: DOM XSS via location.hash — try /profile#<img src=x onerror=alert(1)>
  const greeting = decodeURIComponent(window.location.hash.slice(1) || `Hi, ${me.username}`);

  return (
    <>
      <LessonHint ids={['xss-dom-hash', 'idor-users', 'jwt-localstorage']}>
        Append <code>#&lt;img src=x onerror=alert(1)&gt;</code> to the URL to fire the
        DOM-XSS sink. Open DevTools → Application → Local Storage to see your JWT.
      </LessonHint>
      <div className="card">
      <h2>Profile</h2>
      <p
        // VULN: unsanitized hash → innerHTML
        dangerouslySetInnerHTML={{ __html: greeting }}
      />
      <pre>{JSON.stringify(me, null, 2)}</pre>
      <p className="tag">api_key shown above is sensitive — IDOR-able via /api/users/:id</p>
      </div>
    </>
  );
}
