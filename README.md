# API PrivacyGuard

A locally-runnable **BOLA/IDOR security assessment platform** that automatically detects
Broken Object Level Authorization (and Insecure Direct Object Reference) vulnerabilities by
issuing real cross-account requests against an authorised API and comparing the responses
with layered, evidence-based rules — not by treating every HTTP 200 as a vulnerability.

| Layer     | Stack |
|-----------|-------|
| Frontend  | React 18 + Vite + Tailwind CSS + Recharts + Lucide React |
| Backend   | Python + FastAPI + SQLAlchemy 2 + HTTPX + ReportLab |
| Database  | SQLite (`data/privacyguard.db`, auto-created) |
| Mock APIs | Isolated FastAPI apps for legal practice testing (`mock_api/`) |

> **Legal notice** — Only scan APIs you own or have explicit written authorization to test.
> Target creation requires an "authorization confirmed" checkbox, and the scan API refuses to
> run against targets without it.

---

## 1. Project layout

```
API PrivacyGuard/
├── mock_api/       # Local vulnerable + secure practice APIs (Alice/Bob) + tests   [isolated]
├── backend/        # FastAPI app: detection engine, REST API, PDF reports + tests
│   ├── app/
│   │   ├── core/         # config, database, models, Fernet crypto, SSRF guard
│   │   ├── engine/       # detector, comparator, scanner, safe_http, sensitive
│   │   ├── routers/      # targets, accounts, endpoints, scans, findings,
│   │   │                 # matrix, dashboard, reports
│   │   └── reporting/    # ReportLab PDF generator
│   └── tests/
├── frontend/       # React + Vite dashboard (proxies /api -> :8000)
│   └── src/pages/  # Dashboard, Targets, Accounts, Endpoints, NewScan, Findings,
│                   # Matrix, History, Reports, Settings
├── scripts/        # e2e_smoke.py — full-flow HTTP smoke test
└── data/           # SQLite DB + Fernet key (created at first run, git-ignorable)
```

## 2. Prerequisites

- **Python 3.10+** (tested on 3.10.11)
- **Node.js 18+** (tested on v22)
- Windows / macOS / Linux. PowerShell users: separate commands with `;`, not `&&`.

## 3. Installation

```bash
# backend (also covers mock_api deps)
python -m pip install -r backend/requirements.txt

# mock API (optional standalone install)
python -m pip install -r mock_api/requirements.txt

# frontend
cd frontend
npm install
```

## 4. Running the application

Start four processes (each in its own terminal):

```bash
# 1. Mock vulnerable API (no ownership checks)        -> http://127.0.0.1:8011
python mock_api/server.py --mode vulnerable --port 8011

# 2. Mock secure API (enforces ownership, 403)        -> http://127.0.0.1:8012
python mock_api/server.py --mode secure --port 8012

# 3. Backend API                                       -> http://127.0.0.1:8000
cd backend
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000

# 4. Frontend dev server                               -> http://localhost:5173
cd frontend
npm run dev
```

Open **http://localhost:5173**. The Vite dev server proxies `/api/*` to the backend.
Backend interactive docs: http://127.0.0.1:8000/docs.

## 5. Quick start (first assessment in ~3 minutes)

1. **Targets → Add Target**
   - Name: `Vulnerable Mock`, Base URL: `http://127.0.0.1:8011`
   - Tick **Allow localhost** (required for the mock APIs) and
     **Confirm authorization to test**.
2. **Test Accounts → add both accounts** (tokens are Fernet-encrypted at rest, masked in UI):
   | Name | Bearer token | Home resource |
   |------|--------------------------------|---------------|
   | Alice | `mock-token-alice-3f8a9c` | `101` |
   | Bob | `mock-token-bob-77d1e0` | `202` |
3. **Endpoints → Add Endpoint**
   - Name: `Profile (insecure)`, Path: `/v1/insecure/profiles/{resource_id}`,
     Method: `GET`, Resource id: `101`, Owner: `Alice`, Expected access: **Owner only**.
4. **New Scan → Start authorised scan.** The engine runs the full workflow per endpoint:
   owner baseline request → cross-account attempt → response comparison → classification,
   in **both directions**.
5. Inspect **Findings** (with sanitized evidence), the **Access-Control Matrix**, then add a
   second target pointing at `http://127.0.0.1:8012` with path `/v1/profiles/{resource_id}`
   to see the **BLOCKED** (secure) behaviour — zero false positives.
6. **Scan History → Rescan vulnerable / Verify fixes** compares with the previous scan and
   marks each pairing `fixed / still_vulnerable / regressed / unchanged`.
7. **Reports → Download PDF** (assessment summary, findings, masked evidence, remediation).

## 6. The mock API environment

Two synthetic users with separate SQLite-backed resource ownership:
Alice owns `101` (+ `303`), Bob owns `202`. Each server exposes:

- `GET /v1/insecure/profiles/{id}` — **never** checks ownership (classic BOLA, both modes)
- `GET /v1/profiles/{id}` — checks ownership **only in secure mode** (403 on foreign objects)

Expected behaviour (enforced by `mock_api/tests/test_mock_api.py`):

| Test | Vulnerable API | Secure API |
|---|---|---|
| Alice accesses 101 | 200 | 200 |
| Alice accesses 202 | 200 | 403 |
| Bob accesses 202 | 200 | 200 |
| Bob accesses 101 | 200 | 403 |

Responses deliberately include PII (email, phone, address, DOB, national id, credit card)
so sensitive-data detection and evidence masking can be validated. The mock APIs are
isolated from the main application and intended for local development only.

## 7. Detection engine

Classifications: `AUTHORIZED`, `BLOCKED`, `CONFIRMED_BOLA`, `POTENTIAL_BOLA`, `INCONCLUSIVE`.

A cross-account HTTP 200 is only **CONFIRMED** when evidence stacks up:

1. victim identity markers (values/keys unique to the owner's baseline) appear in the
   foreign response, **and**
2. the resource id is echoed / structure matches with high similarity / ownership fields
   claim the victim, **and**
3. the response is not merely the caller's own scoped data (caller-scoped 200s are
   classified `AUTHORIZED`), non-empty and not a generic acknowledgement.

Partial evidence downgrades to `POTENTIAL_BOLA`; missing baselines, transport errors,
3xx/5xx and unverifiable bodies yield `INCONCLUSIVE`. Severity is boosted to **Critical**
when national IDs or credit-card numbers are exposed.

### Safety guardrails (enforced in code, visible on the Settings page)

- Approved-host allow-list; per-request DNS re-resolution and destination-IP validation
  (SSRF guard blocks metadata/link-local/reserved ranges; loopback only via the explicit
  per-target `allow_localhost` flag)
- Redirects are **never** followed; a `Location` to an unapproved host is a policy error
- Read-only methods only (`GET`/`HEAD`, hard-restricted), 15 s timeout, 2 MB response cap
- Bearer tokens encrypted with Fernet (`data/.secret.key`), masked everywhere, never logged
- PII detected (incl. Luhn-validated card numbers) and masked before storing evidence or
  rendering PDFs

## 8. Automated tests

```bash
# Mock API behaviour (17 tests)
cd mock_api
python -m pytest tests -v

# Engine + backend + API (80 tests: detector rules, comparator, SSRF, PII masking,
# live-server end-to-end scans, REST API, reports)
cd ../backend
python -m pytest tests -v
```

An HTTP-level smoke test of the whole user flow (targets → accounts → endpoints → scans →
findings → matrix → rescan → verification → PDF) is provided after all four processes are
running:

```bash
python scripts/e2e_smoke.py
```

## 9. Configuration

Environment variables (all optional):

| Variable | Default | Purpose |
|----------|---------|---------|
| `PG_DATABASE_URL` | `sqlite:///data/privacyguard.db` | Backend database |
| `PG_TIMEOUT` | `15` | Request timeout (s) |
| `PG_MAX_BYTES` | `2097152` | Max response size (bytes) |

The encryption key is generated on first run at `data/.secret.key` — keep it secret and
back it up separately from the database.
