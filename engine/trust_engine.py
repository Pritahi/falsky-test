"""
Poly — AI Flaky Test Trust Layer
Core Trust Engine v2.0: Production-ready flaky detection with Bayesian scoring,
z-score anomaly detection, environment tracking, and sequential analysis.
"""

import xml.etree.ElementTree as ET
import psycopg2
import psycopg2.extras
import psycopg2.pool
import json
import hashlib
import time
import math
import os
import logging
import bcrypt
from datetime import datetime, timezone
from collections import Counter, defaultdict
from contextlib import contextmanager
from typing import Optional

logger = logging.getLogger("poly.engine")

DATABASE_URL = os.environ.get("DATABASE_URL", os.environ.get("SUPABASE_DATABASE_URL", ""))

_pool = None


def _get_pool():
    global _pool
    if _pool is None and DATABASE_URL:
        _pool = psycopg2.pool.ThreadedConnectionPool(
            minconn=1, maxconn=5, dsn=DATABASE_URL,
            connect_timeout=10, options="-c statement_timeout=30000"
        )
        logger.info("Created PostgreSQL connection pool (threaded, serverless-safe)")
    return _pool


@contextmanager
def _get_db():
    """Context manager for DB connections with dict cursor support."""
    pool = _get_pool()
    if pool is None:
        raise RuntimeError("Database not configured. Set DATABASE_URL env var.")
    conn = pool.getconn()
    try:
        yield conn
    finally:
        pool.putconn(conn)


_db_initialized = False


def ensure_initialized():
    """Initialize DB tables (safe to call multiple times)."""
    global _db_initialized
    if not _db_initialized:
        _init_db()
        _db_initialized = True


def _init_db():
    with _get_db() as conn:
        try:
            with conn.cursor() as c:
                c.execute("""
                    CREATE TABLE IF NOT EXISTS repositories (
                        id SERIAL PRIMARY KEY,
                        name TEXT NOT NULL UNIQUE,
                        created_at TIMESTAMPTZ DEFAULT NOW()
                    );
                """)
                c.execute("""
                    CREATE TABLE IF NOT EXISTS test_results (
                        id SERIAL PRIMARY KEY,
                        repo_id INTEGER NOT NULL,
                        test_name TEXT NOT NULL,
                        status TEXT NOT NULL,
                        duration REAL,
                        error_message TEXT,
                        error_type TEXT,
                        flaky_category TEXT,
                        run_id TEXT NOT NULL,
                        run_timestamp TIMESTAMPTZ NOT NULL,
                        trust_score REAL DEFAULT 100,
                        score_confidence REAL DEFAULT 0,
                        environment TEXT,
                        FOREIGN KEY (repo_id) REFERENCES repositories(id)
                    );
                """)
                c.execute("""
                    CREATE TABLE IF NOT EXISTS ci_runs (
                        id SERIAL PRIMARY KEY,
                        repo_id INTEGER NOT NULL,
                        run_id TEXT NOT NULL UNIQUE,
                        branch TEXT DEFAULT 'main',
                        commit_sha TEXT,
                        total_tests INTEGER DEFAULT 0,
                        passed INTEGER DEFAULT 0,
                        failed INTEGER DEFAULT 0,
                        skipped INTEGER DEFAULT 0,
                        avg_trust_score REAL DEFAULT 100,
                        timestamp TIMESTAMPTZ NOT NULL,
                        environment TEXT,
                        FOREIGN KEY (repo_id) REFERENCES repositories(id)
                    );
                """)
                c.execute("""
                    CREATE TABLE IF NOT EXISTS alerts_config (
                        id SERIAL PRIMARY KEY,
                        repo_id INTEGER NOT NULL UNIQUE,
                        webhook_url TEXT,
                        channel_type TEXT DEFAULT 'discord',
                        min_trust_drop REAL DEFAULT 20,
                        alert_on_flaky BOOLEAN DEFAULT TRUE,
                        alert_on_quarantine BOOLEAN DEFAULT TRUE,
                        FOREIGN KEY (repo_id) REFERENCES repositories(id)
                    );
                """)
                c.execute("CREATE INDEX IF NOT EXISTS idx_test_results_repo ON test_results(repo_id)")
                c.execute("CREATE INDEX IF NOT EXISTS idx_test_results_name ON test_results(test_name)")
                c.execute("CREATE INDEX IF NOT EXISTS idx_test_results_run ON test_results(run_id)")
                c.execute("CREATE INDEX IF NOT EXISTS idx_ci_runs_repo ON ci_runs(repo_id)")

                # Admin / Users
                c.execute("""
                    CREATE TABLE IF NOT EXISTS admin_users (
                        id SERIAL PRIMARY KEY,
                        username TEXT NOT NULL UNIQUE,
                        password_hash TEXT NOT NULL,
                        role TEXT DEFAULT 'admin',
                        created_at TIMESTAMPTZ DEFAULT NOW()
                    );
                """)
                c.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id SERIAL PRIMARY KEY,
                        name TEXT,
                        email TEXT UNIQUE,
                        github_username TEXT,
                        api_key TEXT UNIQUE,
                        plan TEXT DEFAULT 'free',
                        referrer TEXT,
                        signup_source TEXT,
                        ip_address TEXT,
                        is_active BOOLEAN DEFAULT TRUE,
                        last_activity TIMESTAMPTZ,
                        created_at TIMESTAMPTZ DEFAULT NOW(),
                        notes TEXT
                    );
                """)
                c.execute("""
                    CREATE TABLE IF NOT EXISTS user_activity (
                        id SERIAL PRIMARY KEY,
                        user_id INTEGER,
                        action TEXT NOT NULL,
                        detail TEXT,
                        ip_address TEXT,
                        created_at TIMESTAMPTZ DEFAULT NOW(),
                        FOREIGN KEY (user_id) REFERENCES users(id)
                    );
                """)
                c.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
                c.execute("CREATE INDEX IF NOT EXISTS idx_users_activity ON user_activity(user_id)")

            # Seed default admin if empty
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as c:
                c.execute("SELECT COUNT(*) as cnt FROM admin_users")
                if c.fetchone()["cnt"] == 0:
                    default_pw = os.environ.get("POLY_ADMIN_PASSWORD", "admin123")
                    pw_hash = bcrypt.hashpw(default_pw.encode(), bcrypt.gensalt()).decode()
                    c.execute(
                        "INSERT INTO admin_users (username, password_hash, role) VALUES (%s,%s,%s) ON CONFLICT DO NOTHING",
                        ("admin", pw_hash, "superadmin")
                    )

            conn.commit()
            logger.info("Database tables initialized successfully")
        except Exception:
            conn.rollback()
            logger.error("Failed to initialize database tables", exc_info=True)
            raise


def _test_hash(test_name, repo_name):
    return hashlib.sha256(f"{repo_name}:{test_name}".encode()).hexdigest()[:16]


# ─────────────────────────────────────────────
# JUnit XML Parsing
# ─────────────────────────────────────────────

def parse_junit_xml(xml_content: str) -> dict:
    """Parse JUnit XML and extract test results."""
    results = {"tests": [], "total": 0, "passed": 0, "failed": 0, "skipped": 0, "duration": 0}
    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError:
        return results

    for testsuite in root.iter("testsuite"):
        for testcase in testsuite.iter("testcase"):
            name = testcase.get("name", "unknown")
            classname = testcase.get("classname", "")
            full_name = f"{classname}.{name}" if classname else name
            duration = float(testcase.get("time", 0))
            results["duration"] += duration
            results["total"] += 1

            status = "passed"
            error_message = ""
            error_type = ""

            failure = testcase.find("failure")
            error = testcase.find("error")
            skipped = testcase.find("skipped")

            if failure is not None:
                status = "failed"
                error_message = (failure.get("message", "") or failure.text or "")[:500]
                error_type = "failure"
            elif error is not None:
                status = "failed"
                error_message = (error.get("message", "") or error.text or "")[:500]
                error_type = "error"
            elif skipped is not None:
                status = "skipped"

            if status == "passed":
                results["passed"] += 1
            elif status == "failed":
                results["failed"] += 1
            else:
                results["skipped"] += 1

            results["tests"].append({
                "name": full_name,
                "status": status,
                "duration": duration,
                "error_message": error_message,
                "error_type": error_type,
            })

    return results


def _get_test_history(conn, repo_id, test_name, limit=50):
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as c:
        c.execute(
            "SELECT status, duration, error_message, run_timestamp, trust_score, environment "
            "FROM test_results WHERE repo_id=%s AND test_name=%s "
            "ORDER BY run_timestamp DESC LIMIT %s",
            (repo_id, test_name, limit)
        )
        return c.fetchall()

# ─────────────────────────────────────────────
# Bayesian Pass Rate (Beta Distribution)
# ─────────────────────────────────────────────

def _beta_pdf(x, alpha, beta_param):
    """Approximate Beta PDF value (log-space for numerical stability)."""
    if x <= 0 or x >= 1:
        return 0.0
    # log(B(alpha, beta)) = log(Gamma(alpha)) + log(Gamma(beta)) - log(Gamma(alpha+beta))
    # Using Stirling's approximation for ln(Gamma)
    def ln_gamma(z):
        if z < 0.5:
            return math.log(math.pi / math.sin(math.pi * z)) - ln_gamma(1 - z)
        z -= 1
        g = 0.99999999999980993 + (
            676.5203681218851 / (z + 1) - 1259.1392167224028 / (z + 2) +
            771.32342877765313 / (z + 3) - 176.61502916214059 / (z + 4) +
            12.507343278686905 / (z + 5) - 0.13857109526572012 / (z + 6) +
            9.9843695780195716e-6 / (z + 7) + 1.5056327351493116e-7 / (z + 8)
        )
        return 0.5 * math.log(2 * math.pi) + (z + 0.5) * math.log(z + 7.5) - (z + 7.5) + math.log(g)

    log_beta = ln_gamma(alpha) + ln_gamma(beta_param) - ln_gamma(alpha + beta_param)
    log_pdf = (alpha - 1) * math.log(x) + (beta_param - 1) * math.log(1 - x) - log_beta
    return math.exp(log_pdf)


def calculate_bayesian_pass_rate(history, prior_alpha=2.0, prior_beta=2.0):
    """
    Bayesian pass rate using Beta-Binomial conjugate prior.
    
    Instead of naive pass/total, we use:
    - Prior: Beta(2, 2) — slight bias toward stability (most tests should pass)
    - Posterior: Beta(2 + passes, 2 + failures)
    - MAP estimate: (alpha - 1) / (alpha + beta - 2)
    
    This means:
    - 0/0 runs → 50% (prior mean) instead of undefined
    - 1/1 run → 60% (pulled toward prior) instead of 100%
    - 10/10 runs → 92% (prior has less influence with more data)
    - 5/10 runs → 46% (properly uncertain)
    """
    if not history:
        return 0.5  # Prior mean

    passed = sum(1 for h in history if h["status"] == "passed")
    failed = len(history) - passed

    alpha = prior_alpha + passed
    beta_p = prior_beta + failed

    # MAP estimate of Beta distribution
    if alpha + beta_p > 2:
        map_estimate = (alpha - 1) / (alpha + beta_p - 2)
    else:
        map_estimate = alpha / (alpha + beta_p)

    return max(0.0, min(1.0, map_estimate))


def calculate_score_confidence(history, prior_alpha=2.0, prior_beta=2.0):
    """
    Calculate confidence in the trust score based on sample size.
    Uses variance of the Beta posterior distribution.
    
    More runs = higher confidence = we trust the score more.
    Fewer runs = lower confidence = score is more uncertain.
    
    Returns 0.0 to 1.0
    """
    if not history:
        return 0.0

    passed = sum(1 for h in history if h["status"] == "passed")
    failed = len(history) - passed

    alpha = prior_alpha + passed
    beta_p = prior_beta + failed

    # Variance of Beta distribution
    n = alpha + beta_p
    if n <= 0:
        return 0.0

    variance = (alpha * beta_p) / (n * n * (n + 1))

    # Standard deviation
    std = math.sqrt(variance)

    # Convert to confidence (lower std = higher confidence)
    # std of Beta(2,2) is ~0.195 → confidence ~0.3
    # std of Beta(20,2) is ~0.084 → confidence ~0.7
    # std of Beta(100,10) is ~0.038 → confidence ~0.9
    confidence = max(0.0, min(1.0, 1.0 - std * 3.5))

    return round(confidence, 3)


# ─────────────────────────────────────────────
# Wilson Score Interval (for pass rate CI)
# ─────────────────────────────────────────────

def wilson_score_interval(history, confidence=0.95):
    """
    Wilson score interval — better than normal approximation for proportions.
    Returns (lower_bound, upper_bound, point_estimate).
    """
    if not history:
        return (0.25, 0.75, 0.5)

    n = len(history)
    p_hat = sum(1 for h in history if h["status"] == "passed") / n

    z = 1.96  # 95% confidence
    denom = 1 + z * z / n
    center = (p_hat + z * z / (2 * n)) / denom
    margin = z * math.sqrt((p_hat * (1 - p_hat) + z * z / (4 * n)) / n) / denom

    lower = max(0.0, center - margin)
    upper = min(1.0, center + margin)

    return (round(lower, 4), round(upper, 4), round(p_hat, 4))


# ─────────────────────────────────────────────
# Z-Score Anomaly Detection (Duration)
# ─────────────────────────────────────────────

def calculate_duration_variance(history):
    """Coefficient of variation of test durations."""
    if len(history) < 3:
        return 0.0
    durations = [h["duration"] for h in history if h["duration"] and h["duration"] > 0]
    if len(durations) < 3:
        return 0.0
    mean = sum(durations) / len(durations)
    variance = sum((d - mean) ** 2 for d in durations) / len(durations)
    std = math.sqrt(variance)
    cv = std / mean if mean > 0 else 0
    return min(cv * 100, 100)


def calculate_duration_zscores(history):
    """
    Calculate z-scores for each duration to detect outliers.
    Returns list of (duration, z_score, is_anomaly) tuples.
    An anomaly = |z_score| > 2.0 (outside 95% of distribution).
    """
    durations = [h["duration"] for h in history if h["duration"] and h["duration"] > 0]
    if len(durations) < 3:
        return []

    mean = sum(durations) / len(durations)
    variance = sum((d - mean) ** 2 for d in durations) / len(durations)
    std = math.sqrt(variance)

    if std == 0:
        return [(d, 0.0, False) for d in durations]

    results = []
    for d in durations:
        z = (d - mean) / std
        is_anomaly = abs(z) > 2.0
        results.append((d, round(z, 2), is_anomaly))

    return results


def duration_anomaly_rate(history):
    """
    What fraction of runs have anomalous durations (|z| > 2).
    High rate = timing is very inconsistent = likely flaky due to race conditions.
    """
    zscores = calculate_duration_zscores(history)
    if not zscores:
        return 0.0
    anomalies = sum(1 for _, _, is_anom in zscores if is_anom)
    return anomalies / len(zscores)


# ─────────────────────────────────────────────
# Recent Trend Analysis (Improved)
# ─────────────────────────────────────────────

def calculate_recent_trend(history, window=5):
    """
    Compare recent pass rate vs older pass rate.
    Returns -100 to +100. Positive = improving, negative = degrading.
    
    Improved: Uses Bayesian pass rate for each window for stability.
    """
    if len(history) < window + 2:
        return 0.0

    recent = history[:window]
    older = history[window:2 * window]

    if not older:
        return 0.0

    recent_rate = calculate_bayesian_pass_rate(recent)
    older_rate = calculate_bayesian_pass_rate(older)

    return (recent_rate - older_rate) * 100


# ─────────────────────────────────────────────
# Error Pattern Analysis (Improved)
# ─────────────────────────────────────────────

def calculate_error_pattern(history):
    """
    How consistent are error messages when the test fails.
    High consistency = same error every time = might be a real bug, not flaky.
    Low consistency = different errors = likely non-deterministic / flaky.
    
    Returns 0-100 where 100 = perfectly consistent errors.
    """
    if not history:
        return 0.0

    errors = [h["error_message"] for h in history if h["status"] == "failed" and h["error_message"]]
    if len(errors) < 2:
        return 0.0

    # Normalize error messages: strip whitespace, lowercase, remove line numbers
    def normalize(err):
        import re
        err = err.strip().lower()
        # Remove common variable parts like line numbers, file paths
        err = re.sub(r'line \d+', 'line N', err)
        err = re.sub(r'at .+:\d+', 'at FILE:LINE', err)
        err = re.sub(r'0x[0-9a-f]+', '0xADDR', err)
        return err

    normalized = [normalize(e) for e in errors]
    error_hashes = [hashlib.md5(e.encode()).hexdigest() for e in normalized]
    counter = Counter(error_hashes)
    most_common_ratio = counter.most_common(1)[0][1] / len(error_hashes)

    return most_common_ratio * 100


def get_unique_error_patterns(history, top_n=5):
    """Extract the top N unique error patterns with frequencies."""
    if not history:
        return []

    errors = [h["error_message"] for h in history if h["status"] == "failed" and h["error_message"]]
    if not errors:
        return []

    def normalize(err):
        import re
        err = err.strip().lower()
        err = re.sub(r'line \d+', 'line N', err)
        err = re.sub(r'at .+:\d+', 'at FILE:LINE', err)
        err = re.sub(r'0x[0-9a-f]+', '0xADDR', err)
        return err

    pattern_counts = Counter()
    pattern_examples = {}
    for e in errors:
        norm = normalize(e)
        pattern_counts[norm] += 1
        if norm not in pattern_examples:
            pattern_examples[norm] = e[:200]

    return [
        {"pattern": pattern_examples[p], "normalized": p, "count": c, "percentage": round(c / len(errors) * 100, 1)}
        for p, c in pattern_counts.most_common(top_n)
    ]


# ─────────────────────────────────────────────
# Sequential Pattern Detection
# ─────────────────────────────────────────────

def detect_sequential_pattern(history):
    """
    Detect if pass/fail follows a sequential pattern (alternating, periodic, etc.).
    Returns pattern type or None.
    
    Checks for:
    - Alternating: P-F-P-F or F-P-F-P
    - Periodic: P-P-F-P-P-F (regular interval failures)
    - Clustered: P-P-P-F-F-F (sudden shift in behavior)
    """
    if len(history) < 6:
        return None

    statuses = [1 if h["status"] == "passed" else 0 for h in history]
    n = len(statuses)

    # Alternating check
    transitions = sum(1 for i in range(n - 1) if statuses[i] != statuses[i + 1])
    transition_rate = transitions / (n - 1)

    if transition_rate > 0.7:
        return "alternating"

    # Clustered check (runs test - Wald-Wolfowitz)
    runs = 1
    for i in range(1, n):
        if statuses[i] != statuses[i - 1]:
            runs += 1

    expected_runs = 1 + (2 * sum(statuses) * (n - sum(statuses))) / n
    if n > 1:
        runs_variance = (2 * sum(statuses) * (n - sum(statuses)) * (2 * sum(statuses) * (n - sum(statuses)) - n)) / (n * n * (n - 1))
        if runs_variance > 0:
            z = (runs - expected_runs) / math.sqrt(runs_variance)
            if z < -1.96:  # Fewer runs than expected = clustered
                return "clustered"

    # Periodic check (autocorrelation at lag 2, 3, 4, 5)
    mean_s = sum(statuses) / n
    if mean_s == 0 or mean_s == 1:
        return None

    variance = sum((s - mean_s) ** 2 for s in statuses) / n
    if variance == 0:
        return None

    for lag in range(2, min(6, n // 2)):
        autocorr = sum((statuses[i] - mean_s) * (statuses[i + lag] - mean_s) for i in range(n - lag)) / (n * variance)
        if autocorr > 0.5:
            return f"periodic_{lag}"

    return None


# ─────────────────────────────────────────────
# Environment-Aware Analysis
# ─────────────────────────────────────────────

def analyze_environment_correlation(history):
    """
    Check if test outcomes correlate with specific environments.
    Returns dict with environment-specific pass rates if significant difference found.
    """
    env_groups = defaultdict(lambda: {"passed": 0, "total": 0, "durations": []})

    for h in history:
        env = h.get("environment") or "unknown"
        env_groups[env]["total"] += 1
        if h["status"] == "passed":
            env_groups[env]["passed"] += 1
        if h["duration"]:
            env_groups[env]["durations"].append(h["duration"])

    if len(env_groups) < 2:
        return None

    rates = {}
    for env, data in env_groups.items():
        if data["total"] >= 2:
            rates[env] = {
                "pass_rate": data["passed"] / data["total"],
                "runs": data["total"],
                "avg_duration": sum(data["durations"]) / len(data["durations"]) if data["durations"] else 0,
            }

    if len(rates) < 2:
        return None

    # Check if there's significant variance between environments
    pass_rates = [r["pass_rate"] for r in rates.values()]
    max_diff = max(pass_rates) - min(pass_rates)

    if max_diff > 0.3:  # 30%+ difference between environments
        return rates

    return None


# ─────────────────────────────────────────────
# Flaky Category Classification (v2 - Stronger)
# ─────────────────────────────────────────────

def classify_flaky_category(history, current_result=None):
    """
    Classify WHY a test is flaky based on multi-signal analysis.
    
    Categories:
    - timing: High duration variance, outliers detected by z-score
    - order_dependency: Alternating/periodic pass-fail patterns
    - shared_state: Consistent errors, clustered pattern
    - non_deterministic_data: Many different error messages, random failures
    - environment_specific: Fails only in specific environments
    
    v2 improvements:
    - Works with just 2+ runs (was 3+)
    - Uses z-score for timing detection
    - Uses sequential pattern detection
    - Considers environment correlation
    - Returns confidence alongside category
    """
    if not history or len(history) < 2:
        return None

    statuses = [h["status"] for h in history]
    pass_rate = sum(1 for s in statuses if s == "passed") / len(statuses)

    # Not flaky if almost always passes or always fails
    if pass_rate > 0.92 or pass_rate < 0.08:
        return None

    durations = [h["duration"] for h in history if h["duration"] and h["duration"] > 0]
    errors = [h["error_message"] for h in history if h.get("error_message")]

    scores = {}  # category -> confidence score

    # ─── Timing detection (z-score based) ───
    if len(durations) >= 3:
        anomaly_rate = duration_anomaly_rate(history)
        cv = calculate_duration_variance(history) / 100  # normalize to 0-1

        # High CV or high anomaly rate = timing issue
        timing_score = max(cv * 1.5, anomaly_rate * 2)
        if timing_score > 0.3:
            scores["timing"] = min(1.0, timing_score)

    # ─── Sequential pattern detection ───
    pattern = detect_sequential_pattern(history)
    if pattern == "alternating":
        scores["order_dependency"] = 0.85
    elif pattern == "clustered":
        scores["shared_state"] = 0.7
    elif pattern and pattern.startswith("periodic_"):
        scores["order_dependency"] = 0.6

    # ─── Non-deterministic data detection ───
    if len(errors) >= 2:
        unique_errors = len(set(errors))
        error_ratio = unique_errors / len(errors)

        # Many different errors = non-deterministic
        if error_ratio > 0.5:
            scores["non_deterministic_data"] = min(1.0, error_ratio)

    # ─── Shared state detection ───
    if len(errors) >= 2:
        error_consistency = calculate_error_pattern(history) / 100

        # Same error but intermittent = shared state corruption
        if error_consistency > 0.6 and 0.15 < pass_rate < 0.85:
            shared_score = error_consistency * (1 - abs(pass_rate - 0.5) * 0.5)
            if "shared_state" not in scores or shared_score > scores.get("shared_state", 0):
                scores["shared_state"] = shared_score

    # ─── Environment-specific detection ───
    env_corr = analyze_environment_correlation(history)
    if env_corr:
        scores["environment_specific"] = 0.8

    # Pick highest confidence category
    if not scores:
        return None

    best_category = max(scores, key=scores.get)
    return best_category


# ─────────────────────────────────────────────
# Trust Score Calculation (v2 - Production)
# ─────────────────────────────────────────────

def calculate_trust_score(history):
    """
    Calculate 0-100 trust score for a test.
    
    Scoring formula (v2):
    - Bayesian Pass Rate (55% weight) — more robust with small samples
    - Recent Trend (20% weight) — is it getting better or worse?
    - Duration Stability (10% weight) — consistent execution time
    - Error Pattern Score (10% weight) — consistent errors = more trustworthy than random
    - Flaky Category Penalty (up to -20 points) — based on category severity
    
    v2 improvements:
    - Bayesian pass rate instead of naive ratio
    - Z-score anomaly detection feeds into duration stability
    - Sequential pattern analysis for flaky detection
    - Confidence score returned alongside trust score
    - Better penalty scaling based on detection confidence
    """
    if not history:
        return 100.0

    # 1. Bayesian Pass Rate (55%)
    bayesian_rate = calculate_bayesian_pass_rate(history)
    pass_score = bayesian_rate * 55

    # 2. Recent Trend (20%)
    trend = calculate_recent_trend(history)
    # Scale trend: +50 trend = full 20pts, -50 trend = 0pts
    trend_score = max(0, (50 + trend)) / 100 * 20

    # 3. Duration Stability (10%)
    duration_var = calculate_duration_variance(history)
    # Use z-score anomaly rate as additional signal
    anomaly_rate = duration_anomaly_rate(history)
    duration_penalty = min(duration_var, 100) * 0.07 + anomaly_rate * 30
    duration_score = max(0, 10 - duration_penalty)

    # 4. Error Pattern Consistency (10%)
    error_pattern = calculate_error_pattern(history)
    # Higher consistency = slightly more trustworthy (we know what the error is)
    # But very high consistency with failures = real bug, not flaky
    error_score = (error_pattern / 100) * 10

    # Combine
    score = pass_score + trend_score + duration_score + error_score

    # 5. Flaky Category Penalty
    flaky_cat = classify_flaky_category(history, None)
    if flaky_cat:
        penalty_map = {
            "timing": 8,
            "order_dependency": 12,
            "shared_state": 15,
            "non_deterministic_data": 20,
            "environment_specific": 10,
        }
        score -= penalty_map.get(flaky_cat, 10)

    return max(0, min(100, round(score, 1)))


def calculate_score_breakdown(history):
    """
    Return detailed breakdown of each scoring component.
    Used by the dashboard's test detail page.
    """
    if not history:
        return {
            "pass_rate": {"value": 1.0, "weight": 0.55, "points": 55},
            "recent_trend": {"value": 0, "weight": 0.20, "points": 10},
            "duration_stability": {"value": 100, "weight": 0.10, "points": 10},
            "error_consistency": {"value": 0, "weight": 0.10, "points": 0},
            "flaky_penalty": {"category": None, "penalty": 0},
            "total": 100.0,
            "confidence": 0.0,
            "bayesian_pass_rate": 0.5,
            "anomaly_rate": 0.0,
            "error_patterns": [],
            "sequential_pattern": None,
        }

    bayesian_rate = calculate_bayesian_pass_rate(history)
    trend = calculate_recent_trend(history)
    duration_var = calculate_duration_variance(history)
    anomaly_rate = duration_anomaly_rate(history)
    error_pat = calculate_error_pattern(history)

    pass_score = bayesian_rate * 55
    trend_score = max(0, (50 + trend)) / 100 * 20
    duration_penalty = min(duration_var, 100) * 0.07 + anomaly_rate * 30
    duration_score = max(0, 10 - duration_penalty)
    error_score = (error_pat / 100) * 10

    total = pass_score + trend_score + duration_score + error_score

    flaky_cat = classify_flaky_category(history, None)
    penalty = 0
    if flaky_cat:
        penalty_map = {
            "timing": 8, "order_dependency": 12, "shared_state": 15,
            "non_deterministic_data": 20, "environment_specific": 10,
        }
        penalty = penalty_map.get(flaky_cat, 10)
        total -= penalty

    total = max(0, min(100, round(total, 1)))
    confidence = calculate_score_confidence(history)
    error_patterns = get_unique_error_patterns(history)
    seq_pattern = detect_sequential_pattern(history)

    return {
        "pass_rate": {"value": round(bayesian_rate, 3), "weight": 0.55, "points": round(pass_score, 1)},
        "recent_trend": {"value": round(trend, 1), "weight": 0.20, "points": round(trend_score, 1)},
        "duration_stability": {"value": round(100 - duration_var, 1), "weight": 0.10, "points": round(duration_score, 1)},
        "error_consistency": {"value": round(error_pat, 1), "weight": 0.10, "points": round(error_score, 1)},
        "flaky_penalty": {"category": flaky_cat, "penalty": penalty},
        "total": total,
        "confidence": round(confidence, 3),
        "bayesian_pass_rate": round(bayesian_rate, 3),
        "anomaly_rate": round(anomaly_rate, 3),
        "error_patterns": error_patterns,
        "sequential_pattern": seq_pattern,
    }


# ─────────────────────────────────────────────
# Flaky Probability (v2)
# ─────────────────────────────────────────────

def calculate_flaky_probability(history):
    """
    Return 0.0-1.0 probability that a test is flaky (not permanently broken).
    
    v2: Uses Bayesian pass rate and multiple signals.
    - Pass rate near 0 or 1 → not flaky (broken or stable)
    - Pass rate near 0.5 → high flaky probability
    - Multiple error patterns → higher flaky probability
    - Sequential patterns → higher flaky probability
    - High duration anomaly → higher flaky probability
    """
    if not history or len(history) < 2:
        return 0.0

    bayesian_rate = calculate_bayesian_pass_rate(history)

    # Extreme pass rates = not flaky
    if bayesian_rate < 0.05:
        return 0.0  # Broken, not flaky
    if bayesian_rate > 0.95:
        return 0.0  # Stable

    # Base probability from distance from 0.5 (most uncertain at 0.5)
    base_prob = 1.0 - abs(bayesian_rate - 0.5) * 2
    base_prob = base_prob ** 0.8  # Flatten the curve slightly

    # Error pattern modifier (many different errors = more likely flaky)
    error_pat = calculate_error_pattern(history) / 100
    error_modifier = 1.0 + (1.0 - error_pat) * 0.3  # Low consistency = higher probability

    # Sequential pattern modifier
    seq_pattern = detect_sequential_pattern(history)
    seq_modifier = 1.0
    if seq_pattern == "alternating":
        seq_modifier = 1.3
    elif seq_pattern == "clustered":
        seq_modifier = 1.15
    elif seq_pattern and seq_pattern.startswith("periodic_"):
        seq_modifier = 1.2

    # Duration anomaly modifier
    anomaly = duration_anomaly_rate(history)
    dur_modifier = 1.0 + anomaly * 0.5

    # Confidence: more runs = more certain about flakiness
    confidence = calculate_score_confidence(history)
    conf_modifier = 0.5 + confidence * 0.5  # Scale 0.5-1.0

    final_prob = base_prob * error_modifier * seq_modifier * dur_modifier * conf_modifier

    return min(1.0, max(0.0, round(final_prob, 3)))


# ─────────────────────────────────────────────
# Core Processing
# ─────────────────────────────────────────────

def _ensure_repo(conn, repo_name):
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as c:
        c.execute("INSERT INTO repositories (name) VALUES (%s) ON CONFLICT (name) DO NOTHING", (repo_name,))
        conn.commit()
        c.execute("SELECT id FROM repositories WHERE name=%s", (repo_name,))
        return c.fetchone()["id"]


def process_test_run(xml_content: str, repo_name: str, run_id: str = None,
                     branch: str = "main", commit_sha: str = None,
                     environment: str = None) -> dict:
    """Main entry point: parse XML, calculate scores, store results."""
    ensure_initialized()
    logger.info("Processing test run for repo=%s run_id=%s", repo_name, run_id)

    with _get_db() as conn:
        try:
            repo_id = _ensure_repo(conn, repo_name)
            parsed = parse_junit_xml(xml_content)

            if not run_id:
                run_id = f"run_{int(time.time())}_{hashlib.md5(xml_content.encode()).hexdigest()[:8]}"

            timestamp = datetime.now(timezone.utc).isoformat()
            total_trust = 0
            test_count = 0

            for test in parsed["tests"]:
                history_rows = _get_test_history(conn, repo_id, test["name"])
                history = [dict(h) for h in history_rows]

                trust_score = calculate_trust_score(history)
                confidence = calculate_score_confidence(history)
                flaky_cat = classify_flaky_category(history, test)
                flaky_prob = calculate_flaky_probability(history)

                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as c:
                    c.execute(
                        "INSERT INTO test_results (repo_id, test_name, status, duration, error_message, "
                        "error_type, flaky_category, run_id, run_timestamp, trust_score, score_confidence, environment) "
                        "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                        (repo_id, test["name"], test["status"], test["duration"],
                         test["error_message"], test["error_type"], flaky_cat,
                         run_id, timestamp, trust_score, confidence, environment)
                    )
                test["trust_score"] = trust_score
                test["score_confidence"] = confidence
                test["flaky_category"] = flaky_cat
                test["flaky_probability"] = flaky_prob
                total_trust += trust_score
                test_count += 1

            avg_trust = total_trust / test_count if test_count > 0 else 100
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as c:
                c.execute(
                    "INSERT INTO ci_runs (repo_id, run_id, branch, commit_sha, total_tests, passed, "
                    "failed, skipped, avg_trust_score, timestamp, environment) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                    (repo_id, run_id, branch, commit_sha,
                     parsed["total"], parsed["passed"], parsed["failed"], parsed["skipped"],
                     round(avg_trust, 1), timestamp, environment)
                )

            conn.commit()
            logger.info("Test run processed successfully: run_id=%s tests=%d avg_trust=%.1f",
                        run_id, test_count, avg_trust)
        except Exception:
            conn.rollback()
            logger.error("Failed to process test run for repo=%s", repo_name, exc_info=True)
            raise

    parsed["run_id"] = run_id
    parsed["avg_trust_score"] = round(avg_trust, 1)
    parsed["timestamp"] = timestamp
    return parsed


# ─────────────────────────────────────────────
# Dashboard Data
# ─────────────────────────────────────────────

def get_dashboard_data(repo_name: str) -> dict:
    """Get aggregated data for the dashboard."""
    ensure_initialized()

    with _get_db() as conn:
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as c:
                c.execute("SELECT id FROM repositories WHERE name=%s", (repo_name,))
                row = c.fetchone()
                if not row:
                    return {"error": "Repository not found"}

                repo_id = row["id"]

                c.execute(
                    "SELECT COUNT(*) as total, "
                    "AVG(CASE WHEN status='passed' THEN 1.0 ELSE 0.0 END) as pass_rate, "
                    "AVG(trust_score) as avg_trust, "
                    "AVG(score_confidence) as avg_confidence, "
                    "COUNT(DISTINCT run_id) as total_runs "
                    "FROM test_results WHERE repo_id=%s", (repo_id,)
                )
                stats = dict(c.fetchone())

                c.execute(
                    "SELECT test_name, AVG(trust_score) as trust_score, "
                    "AVG(score_confidence) as confidence, "
                    "COUNT(*) as runs, flaky_category, "
                    "AVG(CASE WHEN status='passed' THEN 1.0 ELSE 0.0 END) as pass_rate, "
                    "STRING_AGG(DISTINCT status::text, ', ') as recent_statuses "
                    "FROM test_results WHERE repo_id=%s "
                    "GROUP BY test_name, flaky_category HAVING AVG(trust_score) < 80 "
                    "ORDER BY trust_score ASC",
                    (repo_id,)
                )
                flaky_tests = [dict(r) for r in c.fetchall()]

                for ft in flaky_tests:
                    c.execute(
                        "SELECT status, run_timestamp FROM test_results "
                        "WHERE repo_id=%s AND test_name=%s ORDER BY run_timestamp DESC LIMIT 10",
                        (repo_id, ft["test_name"])
                    )
                    ft["recent_results"] = [dict(r) for r in c.fetchall()][::-1]

                c.execute(
                    "SELECT run_id, branch, commit_sha, total_tests, passed, failed, "
                    "avg_trust_score, timestamp FROM ci_runs WHERE repo_id=%s "
                    "ORDER BY timestamp DESC LIMIT 20",
                    (repo_id,)
                )
                recent_runs = [dict(r) for r in c.fetchall()]

                c.execute(
                    "SELECT CASE "
                    "WHEN trust_score >= 90 THEN 'high' "
                    "WHEN trust_score >= 70 THEN 'medium' "
                    "WHEN trust_score >= 50 THEN 'low' "
                    "ELSE 'critical' END as bucket, COUNT(*) as count "
                    "FROM (SELECT test_name, AVG(trust_score) as trust_score "
                    "FROM test_results WHERE repo_id=%s GROUP BY test_name) sub "
                    "GROUP BY bucket",
                    (repo_id,)
                )
                distribution = {r["bucket"]: r["count"] for r in c.fetchall()}
        except Exception:
            logger.error("Failed to get dashboard data for repo=%s", repo_name, exc_info=True)
            raise

    return {
        "stats": stats,
        "flaky_tests": flaky_tests,
        "recent_runs": recent_runs,
        "trust_distribution": distribution,
    }


def get_test_detail(repo_name: str, test_name: str) -> dict:
    """Get detailed analysis for a single test."""
    ensure_initialized()

    with _get_db() as conn:
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as c:
                c.execute("SELECT id FROM repositories WHERE name=%s", (repo_name,))
                row = c.fetchone()
                if not row:
                    return {"error": "Repository not found"}

                repo_id = row["id"]
                history_rows = _get_test_history(conn, repo_id, test_name, limit=100)
                history = [dict(h) for h in history_rows]
        except Exception:
            logger.error("Failed to get test detail for repo=%s test=%s", repo_name, test_name, exc_info=True)
            raise

    trust_score = calculate_trust_score(history)
    flaky_cat = classify_flaky_category(history, None)
    flaky_prob = calculate_flaky_probability(history)
    breakdown = calculate_score_breakdown(history)

    return {
        "test_name": test_name,
        "trust_score": trust_score,
        "flaky_category": flaky_cat,
        "flaky_probability": flaky_prob,
        "total_runs": len(history),
        "pass_rate": calculate_bayesian_pass_rate(history),
        "recent_trend": calculate_recent_trend(history),
        "duration_variance": calculate_duration_variance(history),
        "error_consistency": calculate_error_pattern(history),
        "history": history[::-1],
        "breakdown": breakdown,
    }


def get_quarantined_tests(repo_name: str, threshold: float = 30) -> list:
    """Get tests that should be quarantined (trust score below threshold)."""
    ensure_initialized()

    with _get_db() as conn:
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as c:
                c.execute("SELECT id FROM repositories WHERE name=%s", (repo_name,))
                row = c.fetchone()
                if not row:
                    return []

                repo_id = row["id"]
                c.execute(
                    "SELECT test_name, AVG(trust_score) as trust_score, flaky_category, "
                    "AVG(score_confidence) as confidence, "
                    "COUNT(*) as total_runs, "
                    "AVG(CASE WHEN status='passed' THEN 1.0 ELSE 0.0 END) as pass_rate "
                    "FROM test_results WHERE repo_id=%s "
                    "GROUP BY test_name, flaky_category HAVING AVG(trust_score) < %s "
                    "ORDER BY trust_score ASC",
                    (repo_id, threshold)
                )
                quarantined = [dict(r) for r in c.fetchall()]
        except Exception:
            logger.error("Failed to get quarantined tests for repo=%s", repo_name, exc_info=True)
            raise

    return quarantined


# ─────────────────────────────────────────────
# Alert System
# ─────────────────────────────────────────────

def send_alert(repo_name: str, webhook_url: str, channel_type: str = "discord",
               alert_data: dict = None):
    """Send alert to Discord/Slack webhook."""
    import urllib.request
    import urllib.error

    if channel_type == "discord":
        embed = {
            "title": f"Poly Alert — {repo_name}",
            "color": 0x8B5CF6,
            "fields": [],
            "footer": {"text": "Poly — AI Flaky Test Trust Layer"},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        if alert_data:
            for key, val in alert_data.items():
                embed["fields"].append({"name": key, "value": str(val), "inline": True})
        payload = {"embeds": [embed]}
    else:
        blocks = [{
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Poly Alert — {repo_name}*\n" +
                        "\n".join(f"*{k}*: {v}" for k, v in (alert_data or {}).items())
            }
        }]
        payload = {"blocks": blocks}

    try:
        req = urllib.request.Request(
            webhook_url,
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        urllib.request.urlopen(req, timeout=5)
        return True
    except Exception:
        return False