import React, { useState } from 'react';
import Handlebars from 'handlebars'; // VULN: 4.0.5 (RCE via prototype access)
import moment from 'moment';          // VULN: 2.18.1 (ReDoS)
import minimist from 'minimist';      // VULN: 1.2.0 (prototype pollution)
import serialize from 'serialize-javascript'; // VULN: 1.4.0 XSS via injection
import { api } from '../api.js';
import LessonHint from './LessonHint.jsx';

export default function Tools() {
  const [hbs, setHbs] = useState('Hello, {{name}}!');
  const [hbsName, setHbsName] = useState('world');
  const [out, setOut] = useState('');
  const [evalIn, setEvalIn] = useState('1+2');
  const [evalOut, setEvalOut] = useState('');

  const [ssrfUrl, setSsrfUrl] = useState('http://169.254.169.254/latest/meta-data/');
  const [ssrfOut, setSsrfOut] = useState('');

  const [cmdHost, setCmdHost] = useState('127.0.0.1');
  const [cmdOut, setCmdOut] = useState('');

  const [xml, setXml] = useState(`<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>`);
  const [xmlOut, setXmlOut] = useState('');

  const renderHbs = () => {
    // VULN: Handlebars 4.0.5 + user-controlled template == RCE in node;
    // here it runs in the browser and is XSS-equivalent. Also: built
    // template HTML is then innerHTML'd via dangerouslySetInnerHTML.
    const tpl = Handlebars.compile(hbs);
    setOut(tpl({ name: hbsName }));
  };

  const runEval = () => {
    // VULN: eval of user input (CWE-95). Easy to spot — but still
    // present in real apps when devs reach for "tiny calculator" features.
    try {
      // eslint-disable-next-line no-eval
      setEvalOut(String(eval(evalIn)));
    } catch (e) {
      setEvalOut(String(e));
    }
  };

  const ssrf = async () => {
    const { data } = await api.get('/fetch', { params: { url: ssrfUrl } });
    setSsrfOut(typeof data === 'string' ? data : JSON.stringify(data));
  };

  const cmd = async () => {
    const { data } = await api.post('/exec', { host: cmdHost });
    setCmdOut(JSON.stringify(data, null, 2));
  };

  const xxe = async () => {
    const r = await fetch('/api/parse-xml', { method: 'POST', body: xml });
    setXmlOut(await r.text());
  };

  // VULN: prototype pollution playground via minimist.
  // Try opening DevTools and running:
  //   minimist(['--__proto__.polluted','yes']);  // pollutes Object.prototype
  // We expose the parsed argv on window for the demo.
  React.useEffect(() => {
    const argv = minimist(decodeURIComponent(window.location.search.slice(1)).split('&'));
    window.__ARGV__ = argv;
  }, []);

  return (
    <>
      <LessonHint ids={['xss-handlebars', 'eval-rce', 'ssrf', 'cmd-injection', 'xxe', 'proto-pollution-minimist']}>
        This page is a buffet: Handlebars template injection, eval()-based RCE, SSRF,
        OS command injection, XXE and minimist prototype pollution all live here.
      </LessonHint>
      <div className="card">
        <h2>Handlebars 4.0.5 — template injection</h2>
        <textarea value={hbs} onChange={(e) => setHbs(e.target.value)} rows={3} />
        <input value={hbsName} onChange={(e) => setHbsName(e.target.value)} />
        <button onClick={renderHbs}>Render</button>
        {/* VULN: rendered template HTML injected raw */}
        <div className="card" dangerouslySetInnerHTML={{ __html: out }} />
        <p className="tag">moment uptime: {moment().fromNow()}</p>
      </div>

      <div className="card">
        <h2>Calculator (eval)</h2>
        <input value={evalIn} onChange={(e) => setEvalIn(e.target.value)} />
        <button onClick={runEval}>Compute</button>
        <pre>{evalOut}</pre>
      </div>

      <div className="card">
        <h2>URL fetch (SSRF)</h2>
        <input value={ssrfUrl} onChange={(e) => setSsrfUrl(e.target.value)} />
        <button onClick={ssrf}>Fetch</button>
        <pre>{ssrfOut}</pre>
      </div>

      <div className="card">
        <h2>Ping (command injection)</h2>
        <input value={cmdHost} onChange={(e) => setCmdHost(e.target.value)} />
        <button onClick={cmd}>Ping</button>
        <pre>{cmdOut}</pre>
        <small>Try: <code>127.0.0.1; id; cat /etc/passwd</code></small>
      </div>

      <div className="card">
        <h2>XML parser (XXE)</h2>
        <textarea rows={6} value={xml} onChange={(e) => setXml(e.target.value)} />
        <button onClick={xxe}>Parse</button>
        <pre>{xmlOut}</pre>
      </div>

      <div className="card">
        <h2>serialize-javascript 1.4.0 — XSS via output</h2>
        <pre>{serialize({ note: 'serialized output trusted in &lt;script&gt;' })}</pre>
      </div>
    </>
  );
}
