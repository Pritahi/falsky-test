# Falsky Action — AI Flaky Test Detector

GitHub Action that analyzes your CI test results using the [Falsky Trust Engine](https://github.com/Pritahi/falsky-test) and posts a trust score report as a PR comment.

![Falsky](https://img.shields.io/badge/Falsky-AI%20Test%20Trust-purple)

---

## What It Does

1. **Reads** JUnit XML test results from your CI pipeline
2. **Sends** them to the Falsky Trust Engine API
3. **Analyzes** tests using Bayesian statistics, anomaly detection, and pattern analysis
4. **Posts** a beautiful trust report as a PR comment

---

## Usage

### Basic

```yaml
name: Test & Analyze
on: [pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Tests
        run: npm test -- --reporter=junit --output-file=test-results.xml

      - name: Analyze with Falsky
        uses: Pritahi/falsky-action@v1
        with:
          junit-xml-path: 'test-results.xml'
          api-url: 'https://your-falsky-api.vercel.app'
          api-key: ${{ secrets.FALSKY_API_KEY }}
```

### Advanced

```yaml
- name: Falsky Trust Report
  uses: Pritahi/falsky-action@v1
  with:
    junit-xml-path: 'test-results/**/*.xml'
    api-url: 'https://your-falsky-api.vercel.app'
    api-key: ${{ secrets.FALSKY_API_KEY }}
    repo-name: 'my-org/my-repo'
    fail-on-flaky: 'true'
    flaky-threshold: '50'
    comment-on-pr: 'true'
    upload-artifact: 'false'
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

---

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `junit-xml-path` | ✅ | `test-results/*.xml` | Path to JUnit XML file(s), supports glob |
| `api-url` | ✅ | `https://falsky-test.vercel.app` | Falsky API base URL |
| `api-key` | ✅ | — | Falsky API key |
| `repo-name` | ❌ | Auto-detected | Repository name |
| `fail-on-flaky` | ❌ | `false` | Fail action if flaky tests found |
| `flaky-threshold` | ❌ | `50` | Trust score threshold for flaky |
| `comment-on-pr` | ❌ | `true` | Post PR comment |
| `upload-artifact` | ❌ | `false` | Upload report as artifact |

## Outputs

| Output | Description |
|--------|-------------|
| `trust-score` | Average trust score (0-100) |
| `flaky-count` | Number of flaky tests |
| `total-tests` | Total tests analyzed |
| `report-url` | Link to Falsky dashboard |

---

## PR Comment Preview

```
## 🟢 Falsky Trust Report

Repository: my-org/my-app
Analyzed: 2026-07-18

| Metric          | Value       |
|-----------------|-------------|
| Total Tests     | 47          |
| Avg Trust Score | 82/100 🟢   |
| Flaky Tests     | 3 ⚠️        |

### 🔬 Flaky Tests

| Test                        | Trust | Category       | Trend       |
|-----------------------------|-------|----------------|-------------|
| test_payment_timeout        | 🟥 23 | ⏱️ Timing      | 📉 Degrading|
| test_concurrent_login       | 🟧 41 | 🤝 Shared      | ➡️ Stable   |

### ✅ Most Reliable (Top 5)

- test_user_signup — 98/100 🟢
- test_api_health — 97/100 🟢
```

---

## Setup

### 1. Deploy Falsky Backend

Follow the [falsky-test setup guide](https://github.com/Pritahi/falsky-test).

### 2. Get API Key

Generate an API key from your Falsky admin panel.

### 3. Add Secret

In your GitHub repo → Settings → Secrets → Actions:
- Add `FALSKY_API_KEY` with your API key

### 4. Add to Workflow

Copy the usage example above into your `.github/workflows/` YAML file.

---

## Supported Test Frameworks

Any framework that outputs JUnit XML format:

- **Jest** — `jest-junit`
- **Pytest** — `--junitxml`
- **Mocha** — `mocha-junit-reporter`
- **Go** — `go test -junitxml`
- **JUnit 5** — Built-in
- **PHPUnit** | **RSpec** | **xUnit** | And more...

---

## License

MIT
