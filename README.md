# Falsky Core — AI Flaky Test Trust Layer (Backend)

Production-ready backend server that analyzes CI test runs and assigns **Trust Scores (0-100)** to every test. Uses Bayesian statistics, z-score anomaly detection, sequential pattern analysis, and environment-aware correlation to detect and categorize flaky tests.

This is the **brain** of Falsky. It receives test data, runs the algorithm, stores history, and serves the dashboard + admin panel.

---

## Architecture

```
GitHub CI Pipeline
       │
       ▼
┌─────────────────┐      API Key       ┌──────────────────┐
│  falsky-action    │────────────────────▶│                  │
│  (GitHub Action)│   JUnit XML +      │   falsky-core      │
│                 │   repo metadata    │   (This Repo)    │
└─────────────────┘                    │                  │
                                       │  ┌────────────┐  │
                                       │  │ FastAPI    │  │
                                       │  │ :8000      │  │
                                       │  └─────┬──────┘  │
                                       │        │         │
                                       │  ┌─────▼──────┐  │
                                       │  │ Trust      │  │
                                       │  │ Engine v2  │  │
                                       │  │ (Python)   │  │
                                       │  └─────┬──────┘  │
                                       │        │         │
                                       │  ┌─────▼──────┐  │
                                       │  │ SQLite DB  │  │
                                       │  └────────────┘  │
                                       │                  │
                                       │  ┌────────────┐  │
                                       │  │ Dashboard  │  │
                                       │  │ Admin      │  │
                                       │  │ Landing    │  │
                                       │  └────────────┘  │
                                       └──────────────────┘
                                               │
                                        PR Comment ◀──┘
```

### How falsky-action connects to falsky-core:

1. **User installs** `falsky-action` in their GitHub repo's workflow
2. **CI runs tests** → generates JUnit XML file
3. **falsky-action reads** the XML file and sends it to **falsky-core's API** (`POST /api/junit`)
4. **falsky-core** runs the Trust Engine algorithm on the data
5. **falsky-core** returns trust scores + flaky categories back to falsky-action
6. **falsky-action** posts a trust report as a **PR comment** on GitHub
7. User sees the report on their PR — flaky tests flagged with scores and categories

---

## What's Inside — File Descriptions

```
falsky-core/
│
├── backend/
│   └── api.py                  # FastAPI server (~520 lines) — THE MAIN ENTRY POINT
│                               #   - Creates FastAPI app with all routes
│                               #   - API key verification (X-Falsky-API-Key header)
│                               #   - Admin auth (cookie-based login/logout/session)
│                               #   - 6 admin endpoints: login, logout, me, stats,
│                               #     users CRUD (create/read/update/delete with search,
│                               #     filter by plan, sort, pagination)
│                               #   - 10+ API endpoints: junit ingestion, dashboard data,
│                               #     test list/detail, runs, repos, quarantined, alerts,
│                               #     badge, delete
│                               #   - Page routes: serves HTML files for landing,
│                               #     dashboard, admin, test-detail, guide
│                               #   - Startup event: initializes database
│                               #   - Env vars: FALSKY_API_KEY, FALSKY_ADMIN_PASSWORD
│
├── engine/
│   ├── __init__.py             # Package init — exports key functions
│   └── trust_engine.py         # Trust Engine v2.0 (~700 lines) — THE BRAIN
│                               #   - Bayesian Trust Scoring (Beta-Binomial conjugate prior)
│                               #   - Z-score anomaly detection on test durations
│                               #   - Sequential pattern detection (alternating, periodic, clustered)
│                               #   - 5 flaky categories: timing, order_dependency,
│                               #     shared_state, non_deterministic_data, environment_specific
│                               #   - JUnit XML parser (handles multi-testsuite files)
│                               #   - SQLite database with 9 tables:
│                               #     repositories, ci_runs, test_results, alerts_config,
│                               #     admin_users, users, user_activity
│                               #   - Dashboard data aggregation functions
│                               #   - Environment-aware correlation (cross-env pass rates)
│                               #   - DB path configurable via FALSKY_DB_PATH env var
│                               #   - Seeds default admin user on first run
│
├── dashboard/
│   ├── index.html              # Test Dashboard — main user-facing page
│                               #   - Repo selector dropdown
│                               #   - 4 stat cards: total tests, avg trust, flaky count,
│                               #     quarantined count
│                               #   - Flaky tests table sorted by trust score (lowest first)
│                               #   - Recent CI runs list
│                               #   - Links to test detail and admin
│                               #   - Dark theme, responsive
│
│   ├── test-detail.html        # Individual Test Detail page
│                               #   - Full test history table (all past runs)
│                               #   - Trust score trend chart (Canvas-based)
│                               #   - Pass/fail pie chart
│                               #   - Score breakdown: Bayesian, trend, duration, error consistency
│                               #   - Flaky category explanation
│                               #   - Duration history chart
│
│   ├── guide.html              # Setup Guide — integration docs
│                               #   - GitHub Action setup (YAML example)
│                               #   - Python SDK usage
│                               #   - REST API reference
│                               #   - Trust score explanation
│                               #
│   └── admin.html              # Admin Panel — user management + analytics
│                               #   - Login screen (cookie-based auth)
│                               #   - Sidebar: Dashboard, Users, Activity, Test Dashboard
│                               #   - 8 stat cards: total users, pro, enterprise, active,
│                               #     new this week, new today, repos, runs today
│                               #   - 30-day signup bar chart (Canvas)
│                               #   - Signup source distribution (github_action, landing_page,
│                               #     marketplace, referral, twitter, blog, word_of_mouth)
│                               #   - Referral tracking, plan distribution
│                               #   - Users table: search, filter by plan, sort, pagination
│                               #   - Add/Edit user modal with all fields
│                               #   - API key copy button
│                               #   - Activity feed (recent actions)
│                               #   - Toast notifications
│                               #   - Dark theme
│
├── landing/
│   └── index.html              # Landing Page (~3100 lines) — Detective + Courtroom theme
│                               #   - 12 CSS animations (float, pulse, slide, glow effects)
│                               #   - Hero section with animated shield
│                               #   - Features grid (Bayesian scoring, real-time alerts, etc.)
│                               #   - Trust score visualization demo
│                               #   - Pricing section
│                               #   - CTA buttons → GitHub Marketplace / Dashboard
│                               #   - Fully responsive, dark theme
│                               #   - Served at root URL "/"
│
├── tests/
│   └── test_engine.py          # Engine tests + demo data seeder
│                               #   - Unit tests for trust scoring
│                               #   - Seeds 3 demo repos with fake CI data
│                               #   - Run locally: python tests/test_engine.py
│
├── requirements.txt            # Python dependencies:
│                               #   fastapi, uvicorn, pydantic
│                               #   (lightweight — no heavy ML libs)
│
├── Dockerfile                  # Railway/Docker deployment config
│                               #   - Base: python:3.11-slim
│                               #   - Copies entire project
│                               #   - Installs requirements
│                               #   - Exposes port 8000
│                               #   - CMD: uvicorn backend.api:app --host 0.0.0.0 --port 8000
│
├── Procfile                    # Railway Procfile: web: uvicorn backend.api:app ...
│                               #   Tells Railway how to start the server
│
└── README.md                   # This file
```

---

## Trust Engine v2.0 — Algorithm Details

The algorithm uses **5 signal components** to calculate a Trust Score (0-100):

| Component | Weight | Method |
|-----------|--------|--------|
| **Bayesian Pass Rate** | 55% | Beta-Binomial conjugate prior (α=2, β=1). Handles small sample sizes better than naive pass/total. |
| **Recent Trend** | 20% | Compares pass rate of last 5 runs vs overall. Detects improving or degrading tests. |
| **Duration Stability** | 10% | Z-score analysis on test durations. \|z\| > 2.0 = timing anomaly. |
| **Error Consistency** | 10% | Normalized error message pattern analysis. Different errors = more suspicious. |
| **Flaky Penalty** | -8 to -20 | Applied when flaky category is detected. Category-specific severity. |

### Flaky Category Detection

| Category | How Detected |
|----------|-------------|
| `timing` | Duration z-score > 2.0 or coefficient of variation > 0.5 |
| `order_dependency` | Alternating pass/fail pattern (sequential analysis) |
| `shared_state` | First-run-fails pattern with same error |
| `non_deterministic_data` | Random failure with high error diversity |
| `environment_specific` | Cross-environment pass rate difference > 30% |

### Sequential Pattern Detection

- **Alternating**: Pass-fail-pass-fail pattern (runs test)
- **Periodic**: Autocorrelation with lag 1-3 (finds cyclical failures)
- **Clustered**: Wald-Wolfowitz runs test (finds batch failures)

---

## API Endpoints

### Test Ingestion (requires API key)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/junit` | Upload JUnit XML test results |
| `POST` | `/api/runs` | Upload raw test result JSON |

### Dashboard Data

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/dashboard?repo_name=X` | Full dashboard data for a repo |
| `GET` | `/api/tests?repo_name=X` | List all tests with trust scores |
| `GET` | `/api/tests/{name}?repo_name=X` | Detailed test history + score breakdown |
| `GET` | `/api/runs?repo_name=X` | Recent CI run history |
| `GET` | `/api/repos` | List all tracked repos |
| `GET` | `/api/quarantined?repo_name=X` | Quarantined tests (below threshold) |

### Admin (requires admin login)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/admin/login` | Admin login (sets cookie) |
| `GET` | `/api/admin/me` | Get current admin session |
| `GET` | `/api/admin/stats` | Platform-wide statistics |
| `GET` | `/api/admin/users` | List users (search, filter, pagination) |
| `POST` | `/api/admin/users` | Create user (auto-generates API key) |
| `PUT` | `/api/admin/users/{id}` | Update user |
| `DELETE` | `/api/admin/users/{id}` | Delete user |

### Alerts

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/alerts/config?repo_name=X` | Set Discord/Slack alert webhook |
| `POST` | `/api/alerts/test?repo_name=X` | Test alert delivery |

### Pages

| Route | Description |
|-------|-------------|
| `/` | **Landing page** — Falsky product page with features, pricing, CTA (Detective + Courtroom theme) |
| `/docs` | FastAPI auto-generated Swagger API docs |
| `/admin/` | Admin panel — user management, analytics, referral tracking (login: admin / admin123) |
| `/dashboard/` | Test dashboard — repo stats, flaky tests table, CI runs |
| `/dashboard/test-detail.html` | Individual test detail — score breakdown, run history, charts |
| `/dashboard/guide.html` | Setup guide — GitHub Action, Python SDK, REST API reference |
| `/badge/{repo_name}` | Trust score SVG badge for README (green/yellow/orange/red) |

---

## Deploy on Railway

### Step 1: Push to GitHub

```bash
git clone https://github.com/Pritahi/falsky-core.git
cd falsky-core
# Make your changes, then:
git add . && git commit -m "your changes" && git push
```

### Step 2: Deploy on Railway

1. Go to [railway.app](https://railway.app) → Login with GitHub
2. Click **"New Project"** → **"Deploy from GitHub repo"**
3. Select **`Pritahi/falsky-core`**
4. Railway will auto-detect Python and install requirements
5. Set environment variables:
   - `FALSKY_API_KEY` — Your secret API key (e.g. `falsky_sk_abc123...`)
   - `FALSKY_ADMIN_PASSWORD` — Admin panel password (default: `admin123`)
6. Click **Deploy**

Railway will give you a URL like: `https://falsky-core-production.up.railway.app`

### Step 3: Connect falsky-action

In your users' GitHub repos, they set up falsky-action with:

```yaml
- uses: Pritahi/falsky-action@v1
  with:
    falsky-api-url: 'https://falsky-core-production.up.railway.app'  # Your Railway URL
    falsky-api-key: ${{ secrets.FALSKY_API_KEY }}                    # User's API key
    test-results-path: '**/test-results/*.xml'
```

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `FALSKY_API_KEY` | Yes | `falsky-dev-key` | API key for test ingestion |
| `FALSKY_ADMIN_PASSWORD` | No | `admin123` | Admin panel login password |
| `FALSKY_DB_PATH` | No | `backend/falsky.db` | SQLite database path |

### Google Sign-In (Supabase)

To enable "Sign in with Google", set these **and make sure they point at the real
public URL — not localhost** (a `localhost` value here is the usual cause of
`ERR_CONNECTION_REFUSED` after picking a Google account):

| Variable | Required | Description |
|----------|----------|-------------|
| `SUPABASE_URL` | Yes | Your Supabase project URL (e.g. `https://xxxx.supabase.co`) |
| `SUPABASE_ANON_KEY` | Yes | Supabase anon/public key |
| `SUPABASE_JWT_SECRET` | Yes | Supabase JWT secret (used to verify the returned token) |
| `SITE_URL` | Yes | Public base URL of THIS app, e.g. `https://poly-core-vercel.vercel.app` (must match where users open the admin panel) |
| `ALLOWED_ADMIN_EMAILS` | No | Comma-separated emails permitted to admin (empty = any verified Google email) |

In the **Supabase dashboard → Authentication → Providers → Google**, add the
authorized redirect URI:

```
<SITE_URL>/api/auth/callback
```

Example (production):

```bash
SUPABASE_URL=https://xxxx.supabase.co
SUPABASE_ANON_KEY=public-xxxx
SUPABASE_JWT_SECRET=xxxx
SITE_URL=https://poly-core-vercel.vercel.app
ALLOWED_ADMIN_EMAILS=you@example.com
```

> ⚠️ If `SITE_URL` is left empty or set to `http://localhost:8000`, Supabase will
> redirect users back to localhost after Google login — which fails with
> `ERR_CONNECTION_REFUSED` unless a server is running there.

---

## Local Development

```bash
# Clone
git clone https://github.com/Pritahi/falsky-core.git
cd falsky-core

# Install dependencies
pip install -r requirements.txt

# Seed demo data (creates sample repos + test runs)
python tests/test_engine.py

# Start server
cd backend && python api.py
# or: uvicorn backend.api:app --reload --port 8000
```

Open:
- Dashboard: http://localhost:8000/dashboard/
- Admin: http://localhost:8000/admin/ (login: admin / admin123)
- API Docs: http://localhost:8000/docs

---

## Tech Stack

- **Backend**: Python 3.10+, FastAPI, Uvicorn
- **Database**: SQLite (zero-config, file-based)
- **Algorithm**: Bayesian inference (Beta-Binomial), Z-score anomaly detection, Wald-Wolfowitz runs test, Autocorrelation
- **Frontend**: Pure HTML/CSS/JS (no framework, no dependencies)
- **Hosting**: Railway (recommended) / Any Python-compatible PaaS

## License

MIT# redeploy trigger Mon Jul 20 20:35:29 CST 2026
# redeploy 1784551531
