import React from 'react';
import { Link } from 'react-router-dom';

// Drop into any page to point at the relevant lesson card(s).
// Usage: <LessonHint ids={['xss-stored','xss-dom-hash']} />
export default function LessonHint({ ids = [], children }) {
  return (
    <div
      className="card"
      style={{
        background: '#1c2128',
        borderColor: '#9e6a03',
        borderLeft: '3px solid #ffa657',
      }}
    >
      <b>💡 Self-teach:</b> {children || 'See the matching lesson(s) for descriptions, manual exploits, and detection notes.'}
      <div style={{ marginTop: 6 }}>
        {ids.map((id, i) => (
          <span key={id} style={{ marginRight: 10 }}>
            <Link to={`/lessons#${id}`}>📖 {id}</Link>
            {i < ids.length - 1 ? ' · ' : ''}
          </span>
        ))}
      </div>
    </div>
  );
}
