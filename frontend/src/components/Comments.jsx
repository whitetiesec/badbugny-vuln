import React, { useEffect, useState } from 'react';
import { api } from '../api.js';
import LessonHint from './LessonHint.jsx';

export default function Comments() {
  const [list, setList] = useState([]);
  const [body, setBody] = useState('');
  const [author, setAuthor] = useState('anon');
  const postId = 1;

  const load = async () => {
    const { data } = await api.get('/comments/' + postId);
    setList(data || []);
  };

  useEffect(() => { load(); }, []);

  const submit = async (e) => {
    e.preventDefault();
    await api.post('/comments', { post_id: postId, author, body });
    setBody('');
    load();
  };

  return (
    <>
      <LessonHint ids={['xss-stored', 'sqli-comments-path']}>
        Post a comment containing <code>&lt;img src=x onerror=alert(1)&gt;</code>. Your
        payload runs in every visitor's browser. The comment list also has a path-SQLi
        sink in <code>/api/comments/:postId</code>.
      </LessonHint>
      <div className="card">
      <h2>Comments (Stored XSS demo)</h2>
      <form onSubmit={submit}>
        <label>Author</label>
        <input value={author} onChange={(e) => setAuthor(e.target.value)} />
        <label>Body (try: &lt;img src=x onerror=alert(1)&gt;)</label>
        <textarea value={body} onChange={(e) => setBody(e.target.value)} />
        <button>Post</button>
      </form>
      {list.map((c) => (
        <div className="card" key={c.id}>
          <b>{c.author}</b> · #{c.id}
          {/* VULN: stored XSS — comment.body rendered raw */}
          <div dangerouslySetInnerHTML={{ __html: c.body }} />
        </div>
      ))}
      </div>
    </>
  );
}
