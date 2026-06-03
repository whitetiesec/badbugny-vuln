import React from 'react';
import { Routes, Route, Link, Navigate } from 'react-router-dom';
import Login from './components/Login.jsx';
import Register from './components/Register.jsx';
import Profile from './components/Profile.jsx';
import Search from './components/Search.jsx';
import Comments from './components/Comments.jsx';
import Files from './components/Files.jsx';
import Tools from './components/Tools.jsx';
import Admin from './components/Admin.jsx';
import Notes from './components/Notes.jsx';
import Lessons from './components/Lessons.jsx';
import { getToken, setToken } from './api.js';

export default function App() {
  const loggedIn = !!getToken();

  // VULN: open redirect on the client too — ?next= read from URL and
  // window.location.href = ... without validation (CWE-601 client-side).
  React.useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const next = params.get('next');
    if (next) window.location.href = next;
  }, []);

  return (
    <>
      <div className="banner">
        ⚠ BadBugny — INTENTIONALLY VULNERABLE demo. Do not deploy on the
        public internet. For SCA / SAST / DAST / IAST / secret-scanning
        tooling demos only.
      </div>
      <nav>
        <Link to="/" className="brand">
          <img src="/logo.svg" alt="BadBugny logo" className="brand-logo" />
          <b>BadBugny</b>
        </Link>
        <Link to="/">Home</Link>
        <Link to="/lessons"><b>📚 Lessons</b></Link>
        <Link to="/search">Search</Link>
        <Link to="/comments">Comments</Link>
        <Link to="/files">Files</Link>
        <Link to="/tools">Tools</Link>
        <Link to="/notes">Notes</Link>
        <Link to="/admin">Admin</Link>
        <span className="spacer" />
        {loggedIn ? (
          <>
            <Link to="/profile">Profile</Link>
            <a
              href="#"
              onClick={(e) => {
                e.preventDefault();
                setToken(null);
                window.location.href = '/';
              }}
            >
              Logout
            </a>
          </>
        ) : (
          <>
            <Link to="/login">Login</Link>
            <Link to="/register">Register</Link>
          </>
        )}
      </nav>
      <div className="page">
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />
          <Route path="/profile" element={loggedIn ? <Profile /> : <Navigate to="/login" />} />
          <Route path="/search" element={<Search />} />
          <Route path="/comments" element={<Comments />} />
          <Route path="/files" element={<Files />} />
          <Route path="/tools" element={<Tools />} />
          <Route path="/notes" element={<Notes />} />
          <Route path="/admin" element={<Admin />} />
          <Route path="/lessons" element={<Lessons />} />
        </Routes>
      </div>
    </>
  );
}

function Home() {
  return (
    <div>
      <div className="hero">
        <img src="/logo.svg" alt="BadBugny — a bunny in sunglasses on a Harley-style motorbike" className="hero-logo" />
        <div>
          <h1>BadBugny 🐰🏍️</h1>
          <p className="tagline">The fastest bunny in the garage — and the most exploitable.</p>
        </div>
      </div>
      <p>
        A purpose-built vulnerable web app for evaluating SCA, SAST, DAST, IAST and
        secret-scanning tooling — and for self-teaching offensive web security.
        Throttle up through each <Link to="/lessons">lesson</Link>, pop the hood on a
        vuln, and see which scanner in your garage catches it.
      </p>
      <div
        className="card"
        style={{ background: '#1c2128', borderLeft: '3px solid #ffa657' }}
      >
        <h3 style={{ marginTop: 0 }}>📚 New here? Start with the Lessons page.</h3>
        <p>
          Open <Link to="/lessons">Lessons</Link> for a searchable index of every
          vulnerability with a short description, the exact payload to copy/paste,
          the expected result, and which scanner family is meant to catch it.
        </p>
        <p>
          Most pages of the app also carry an inline 💡 hint at the top pointing to
          the relevant lesson(s). The README in the repo carries the same matrix in
          static form for offline study.
        </p>
      </div>
      <div className="card">
        <h3>Default credentials</h3>
        <ul>
          <li><b>admin</b> / admin123 (role=admin)</li>
          <li><b>alice</b> / password1</li>
          <li><b>bob</b> / hunter2</li>
        </ul>
      </div>
      <div className="card">
        <h3>Suggested learning path</h3>
        <ol>
          <li>
            Browse <Link to="/lessons?cat=Injection">Injection</Link> — start with
            the SQLi auth bypass on the <Link to="/login">Login</Link> page.
          </li>
          <li>
            Try <Link to="/lessons?cat=XSS">XSS</Link> — paste a payload into the{' '}
            <Link to="/comments">Comments</Link> page and reload.
          </li>
          <li>
            Move on to <Link to="/lessons?cat=Auth%20%26%20Access%20Control">
              Auth & Access Control
            </Link>{' '}
            — register as admin, forge a JWT, abuse IDOR.
          </li>
          <li>
            Finish with <Link to="/lessons?cat=Business%20Logic">Business Logic</Link>{' '}
            and the <Link to="/lessons?cat=Secrets">Secrets</Link> +{' '}
            <Link to="/lessons?cat=Dependencies%20(SCA)">Dependencies</Link> tracks for
            tooling demos.
          </li>
        </ol>
      </div>
    </div>
  );
}
