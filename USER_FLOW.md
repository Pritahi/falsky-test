# Falsky — User Flow (MVP)

## Core Principle
> GitHub ka kaam GitHub par, Flasky ka kaam analysis dikhana.

---

## Complete User Journey

```
1. Landing Page
   └─ "Sign in with Google" button

2. Login
   └─ Google OAuth → auto-create user → set cookie

3. Dashboard (first time)
   └─ "Connect your first repository"
   └─ GitHub App install flow (NOT in Flasky UI)

4. GitHub (user leaves Flasky)
   ├─ Install Falsky GitHub App on repo
   ├─ Or: Add falsky-action to .github/workflows/
   └─ Push code → GitHub Actions runs

5. Dashboard (after first run)
   └─ Shows connected repos with trust scores
   └─ Auto-refreshes

6. Repository Page (main workspace)
   ├─ Trust Score
   ├─ Flaky Tests
   ├─ Trends
   └─ Run History

7. Test Details
   └─ Deep analysis of one test

8. Settings
   └─ Account, Notifications, Logout
```

---

## Page-by-Page Specification

### 1. Landing Page (`/`)
- Product intro
- Features
- "Sign in with Google" CTA
- No pricing, no billing

### 2. Login (`/login`)
- Google OAuth only
- Auto-creates user in DB
- Generates API key (hidden from user)
- Redirects to dashboard

### 3. Dashboard (`/dashboard/`)
**States:**
- **No repos connected:** "Connect your first repository" + setup guide
- **Repos connected:** Table with trust scores, last run time
- **Workflow running:** "Analyzing..." indicator

**Content:**
- Stats: Total repos, avg trust score, total flaky tests
- Repos table: name, tests count, trust score, flaky count, last run
- "Last synced X sec ago" auto-refresh

**NOT here:**
- ❌ API key display
- ❌ Manual upload
- ❌ Run Analysis button
- ❌ Billing info

### 4. Repository Page (`/dashboard/repo.html?repo=...`)
**This is the main workspace.**

**States:**
- **Waiting for first run:** "Waiting for first analysis..." + setup guide
- **Has data:** Full analysis view
- **Workflow failed:** "Workflow failed" + link to GitHub Actions logs

**Content:**
- Repo info: name, branch, last sync
- Trust gauge (overall score)
- Stats: total, stable, flaky, failed
- Trust distribution chart
- Tabs:
  - Flaky Tests (with search + category filter)
  - All Tests
  - Top Issues (most unstable, recently degraded)
- Each test links to Test Details

**NOT here:**
- ❌ Manual run trigger
- ❌ Upload results
- ❌ API configuration

### 5. Test Details (`/dashboard/test.html?repo=...&test=...`)
**Deep analysis of one test.**

**Content:**
- Trust Score (big)
- Flaky Probability
- Confidence bar
- Score Breakdown:
  - Bayesian Pass Rate
  - Recent Trend
  - Duration Stability
  - Error Consistency
- Flaky Category (if detected)
- Run History table
- Error Patterns

**NOT here:**
- ❌ Edit test
- ❌ Delete test
- ❌ Manual re-run

### 6. Settings (`/dashboard/settings.html`)
**Minimal.**

**Content:**
- Account info (name, email, plan)
- Notifications (Discord/Slack webhooks)
- Sign Out

**NOT here:**
- ❌ API key management
- ❌ Billing
- ❌ Team management
- ❌ Developer settings
- ❌ GitHub App management

---

## Data Flow

```
User pushes code
       │
       ▼
GitHub Actions runs tests
       │
       ▼
falsky-action reads JUnit XML
       │
       ▼
POST /api/runs → falsky-core
       │
       ▼
Trust Engine analyzes
       │
       ▼
Stores in Supabase
       │
       ▼
Dashboard auto-refreshes
       │
       ▦
User sees results
```

---

## Empty States (Important)

### Dashboard (no repos)
```
┌─────────────────────────────────┐
│     📡 Connect Repository       │
│                                 │
│  1. Install Falsky GitHub App   │
│  2. Select your repository      │
│  3. Push code to trigger        │
│                                 │
│  [Install GitHub App →]         │
│                                 │
│  Your API key is auto-configured│
│  No manual setup needed.        │
└─────────────────────────────────┘
```

### Repository (waiting for first run)
```
┌─────────────────────────────────┐
│     ⏳ Waiting for first run    │
│                                 │
│  Add to your workflow:          │
│                                 │
│  - uses: Pritahi/falsky-action  │
│    with:                        │
│      junit-xml-path: ...        │
│      api-url: ...               │
│      api-key: ...               │
│                                 │
│  Then push to trigger.          │
└─────────────────────────────────┘
```

### Repository (workflow failed)
```
┌─────────────────────────────────┐
│     ❌ Workflow Failed          │
│                                 │
│  Last run: 2 min ago            │
│  Error: Action failed           │
│                                 │
│  [View GitHub Actions Logs →]   │
└─────────────────────────────────┘
```

---

## Auto-Refresh

- Dashboard: poll `/api/repos` every 30s
- Repository page: poll `/api/dashboard` every 30s
- Show "Last synced X sec ago" indicator
- No manual refresh button needed

---

## What's NOT in MVP

- ❌ Billing / Pricing
- ❌ Team management
- ❌ API key management (auto-generated, hidden)
- ❌ Manual test upload
- ❌ "Run Analysis" button
- ❌ GitHub App install flow (happens on GitHub)
- ❌ Repository selection UI (happens on GitHub)
- ❌ Workflow editor
- ❌ Logs viewer (link to GitHub Actions)
- ❌ PR comments config (handled by action)
- ❌ Webhook management
- ❌ Custom thresholds
- ❌ Export / Import
- ❌ Audit logs

---

## Summary

**Flasky shows results. GitHub handles everything else.**

6 pages. Clean flow. No bloat.
