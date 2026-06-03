import React, { useMemo, useState } from 'react';
import { useSearchParams, Link } from 'react-router-dom';
import { LESSONS, CATEGORIES, SEVERITIES } from '../lessons.js';

const sevColor = {
  Critical: '#ff7b72',
  High: '#ffa657',
  Medium: '#d2a8ff',
  Low: '#7ee787',
};
const detectorOrder = ['SAST', 'DAST', 'IAST', 'SCA', 'Secrets', 'AI'];

function CopyBtn({ text }) {
  const [done, setDone] = useState(false);
  return (
    <button
      className="secondary"
      style={{ float: 'right' }}
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setDone(true);
          setTimeout(() => setDone(false), 1200);
        } catch {
          /* noop */
        }
      }}
    >
      {done ? 'copied ✓' : 'copy'}
    </button>
  );
}

function DetectorBadge({ name, value }) {
  if (!value) return null;
  const bg = value === 'yes' ? '#238636' : value === 'partial' ? '#9e6a03' : '#6e7681';
  return (
    <span
      title={`${name}: ${value}`}
      style={{
        display: 'inline-block',
        padding: '2px 8px',
        marginRight: 6,
        borderRadius: 10,
        background: bg,
        color: '#fff',
        fontSize: 11,
        fontWeight: 600,
      }}
    >
      {name} {value === 'yes' ? '✓' : value === 'partial' ? '~' : '✗'}
    </span>
  );
}

function Lesson({ l }) {
  const [open, setOpen] = useState(
    typeof window !== 'undefined' && window.location.hash === '#' + l.id
  );
  // If the user navigates here via /lessons#<id>, scroll the matching
  // card into view and open it.
  React.useEffect(() => {
    if (typeof window === 'undefined') return;
    const onHash = () => {
      if (window.location.hash === '#' + l.id) {
        setOpen(true);
        document.getElementById(l.id)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    };
    onHash();
    window.addEventListener('hashchange', onHash);
    return () => window.removeEventListener('hashchange', onHash);
  }, [l.id]);
  return (
    <div className="card" id={l.id}>
      <div
        style={{ cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 10 }}
        onClick={() => setOpen((v) => !v)}
      >
        <span
          style={{
            color: sevColor[l.severity] || '#c9d1d9',
            fontWeight: 700,
            minWidth: 64,
          }}
        >
          {l.severity}
        </span>
        <span style={{ flex: 1 }}>
          <b>{l.title}</b>
          <span className="tag" style={{ marginLeft: 8 }}>
            {l.cwe}
          </span>
          <span className="tag">{l.category}</span>
        </span>
        <span style={{ opacity: 0.7 }}>{open ? '▾' : '▸'}</span>
      </div>

      {open && (
        <div style={{ marginTop: 14 }}>
          <p>
            <b>Where:</b> <code>{l.where}</code>
          </p>
          <p>{l.description}</p>

          {l.formHint && (
            <p>
              <b>In this app:</b> <i>{l.formHint}</i>
            </p>
          )}

          {l.payload && (
            <>
              <h4 style={{ margin: '8px 0 4px' }}>Manual exploit</h4>
              <pre style={{ position: 'relative' }}>
                <CopyBtn text={l.payload} />
                {l.payload}
              </pre>
            </>
          )}

          {l.expected && (
            <p>
              <b>Expected result:</b> {l.expected}
            </p>
          )}

          {l.aiAdvantage && (
            <p>
              <b>Why AI is better at finding it:</b> {l.aiAdvantage}
            </p>
          )}

          <div>
            <b>Likely detected by:</b>{' '}
            {detectorOrder.map((d) => (
              <DetectorBadge key={d} name={d} value={l.detectedBy?.[d]} />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export default function Lessons() {
  const [params, setParams] = useSearchParams();
  const cat = params.get('cat') || '';
  const sev = params.get('sev') || '';
  const q = params.get('q') || '';

  const filtered = useMemo(() => {
    return LESSONS.filter((l) => {
      if (cat && l.category !== cat) return false;
      if (sev && l.severity !== sev) return false;
      if (q) {
        const hay = (l.title + ' ' + l.description + ' ' + l.where).toLowerCase();
        if (!hay.includes(q.toLowerCase())) return false;
      }
      return true;
    });
  }, [cat, sev, q]);

  const counts = useMemo(() => {
    const out = {};
    LESSONS.forEach((l) => {
      out[l.category] = (out[l.category] || 0) + 1;
    });
    return out;
  }, []);

  const update = (k, v) => {
    const p = new URLSearchParams(params);
    if (v) p.set(k, v);
    else p.delete(k);
    setParams(p, { replace: true });
  };

  return (
    <>
      <div className="card">
        <h2>📚 Lessons — exploit each vulnerability by hand</h2>
        <p>
          Every entry below is a deliberately broken thing in this app. Click a card to
          expand the description, the exact payload, and which scanner family is
          expected to catch it. Most entries also point you at a form in the SPA so you
          can replay the attack interactively.
        </p>
        <p>
          ⚠ <b>Run on an isolated host only.</b> Some payloads (XXE, SSRF, command
          injection) can pivot inside your network if exposed.
        </p>

        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center' }}>
          <input
            placeholder="search title / description / location"
            value={q}
            onChange={(e) => update('q', e.target.value)}
            style={{ flex: '1 1 280px' }}
          />
          <select value={cat} onChange={(e) => update('cat', e.target.value)}>
            <option value="">All categories</option>
            {CATEGORIES.map((c) => (
              <option key={c} value={c}>
                {c} ({counts[c] || 0})
              </option>
            ))}
          </select>
          <select value={sev} onChange={(e) => update('sev', e.target.value)}>
            <option value="">All severities</option>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
          <button
            className="secondary"
            onClick={() => {
              update('cat', '');
              update('sev', '');
              update('q', '');
            }}
          >
            reset
          </button>
        </div>
        <p style={{ marginTop: 12, opacity: 0.8 }}>
          Showing <b>{filtered.length}</b> of {LESSONS.length} lessons. Default users:{' '}
          <code>admin/admin123</code>, <code>alice/password1</code>, <code>bob/hunter2</code>.
          Quick links: <Link to="/login">Login</Link> · <Link to="/register">Register</Link> ·{' '}
          <Link to="/comments">Comments</Link> · <Link to="/files">Files</Link> ·{' '}
          <Link to="/tools">Tools</Link> · <Link to="/notes">Notes</Link> ·{' '}
          <Link to="/admin">Admin</Link>.
        </p>
      </div>

      {filtered.map((l) => (
        <Lesson key={l.id} l={l} />
      ))}

      {filtered.length === 0 && (
        <div className="card">
          <p>Nothing matches that filter.</p>
        </div>
      )}
    </>
  );
}
