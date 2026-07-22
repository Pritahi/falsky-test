-- Falsky — Supabase RPC Functions
-- Run this AFTER init.sql in Supabase SQL Editor

-- 1. Get dashboard stats for a repo
CREATE OR REPLACE FUNCTION get_repo_stats(p_repo_name TEXT)
RETURNS TABLE (
    total BIGINT,
    pass_rate DOUBLE PRECISION,
    avg_trust DOUBLE PRECISION,
    avg_confidence DOUBLE PRECISION,
    total_runs BIGINT
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        COUNT(*)::BIGINT,
        AVG(CASE WHEN tr.status='passed' THEN 1.0 ELSE 0.0 END),
        AVG(tr.trust_score)::DOUBLE PRECISION,
        AVG(tr.score_confidence)::DOUBLE PRECISION,
        COUNT(DISTINCT tr.run_id)::BIGINT
    FROM test_results tr
    JOIN repositories r ON r.id = tr.repo_id
    WHERE r.name = p_repo_name;
END;
$$ LANGUAGE plpgsql;

-- 2. Get flaky tests for a repo
CREATE OR REPLACE FUNCTION get_flaky_tests(p_repo_name TEXT)
RETURNS TABLE (
    test_name TEXT,
    trust_score DOUBLE PRECISION,
    confidence DOUBLE PRECISION,
    runs BIGINT,
    flaky_category TEXT,
    pass_rate DOUBLE PRECISION
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        tr.test_name,
        AVG(tr.trust_score)::DOUBLE PRECISION,
        AVG(tr.score_confidence)::DOUBLE PRECISION,
        COUNT(*)::BIGINT,
        tr.flaky_category,
        AVG(CASE WHEN tr.status='passed' THEN 1.0 ELSE 0.0 END)
    FROM test_results tr
    JOIN repositories r ON r.id = tr.repo_id
    WHERE r.name = p_repo_name
    GROUP BY tr.test_name, tr.flaky_category
    HAVING AVG(tr.trust_score) < 80
    ORDER BY AVG(tr.trust_score) ASC;
END;
$$ LANGUAGE plpgsql;

-- 3. Get test history
CREATE OR REPLACE FUNCTION get_test_history(p_repo_name TEXT, p_test_name TEXT, p_limit INT DEFAULT 50)
RETURNS TABLE (
    status TEXT,
    duration DOUBLE PRECISION,
    error_message TEXT,
    run_timestamp TIMESTAMPTZ,
    trust_score DOUBLE PRECISION,
    environment TEXT
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        tr.status,
        tr.duration::DOUBLE PRECISION,
        tr.error_message,
        tr.run_timestamp,
        tr.trust_score::DOUBLE PRECISION,
        tr.environment
    FROM test_results tr
    JOIN repositories r ON r.id = tr.repo_id
    WHERE r.name = p_repo_name AND tr.test_name = p_test_name
    ORDER BY tr.run_timestamp DESC
    LIMIT p_limit;
END;
$$ LANGUAGE plpgsql;

-- 4. Get trust distribution
CREATE OR REPLACE FUNCTION get_trust_distribution(p_repo_name TEXT)
RETURNS TABLE (bucket TEXT, count BIGINT) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        CASE 
            WHEN sub.avg_trust >= 90 THEN 'high'
            WHEN sub.avg_trust >= 70 THEN 'medium'
            WHEN sub.avg_trust >= 50 THEN 'low'
            ELSE 'critical'
        END as bucket,
        COUNT(*)::BIGINT
    FROM (
        SELECT AVG(tr.trust_score) as avg_trust
        FROM test_results tr
        JOIN repositories r ON r.id = tr.repo_id
        WHERE r.name = p_repo_name
        GROUP BY tr.test_name
    ) sub
    GROUP BY bucket;
END;
$$ LANGUAGE plpgsql;

-- 5. Get quarantined tests
CREATE OR REPLACE FUNCTION get_quarantined(p_repo_name TEXT, p_threshold DOUBLE PRECISION DEFAULT 30)
RETURNS TABLE (
    test_name TEXT,
    trust_score DOUBLE PRECISION,
    flaky_category TEXT,
    confidence DOUBLE PRECISION,
    total_runs BIGINT,
    pass_rate DOUBLE PRECISION
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        tr.test_name,
        AVG(tr.trust_score)::DOUBLE PRECISION,
        tr.flaky_category,
        AVG(tr.score_confidence)::DOUBLE PRECISION,
        COUNT(*)::BIGINT,
        AVG(CASE WHEN tr.status='passed' THEN 1.0 ELSE 0.0 END)
    FROM test_results tr
    JOIN repositories r ON r.id = tr.repo_id
    WHERE r.name = p_repo_name
    GROUP BY tr.test_name, tr.flaky_category
    HAVING AVG(tr.trust_score) < p_threshold
    ORDER BY AVG(tr.trust_score) ASC;
END;
$$ LANGUAGE plpgsql;

-- 6. Get admin stats
CREATE OR REPLACE FUNCTION get_admin_stats()
RETURNS TABLE (
    total_users BIGINT,
    pro_users BIGINT,
    enterprise_users BIGINT,
    active_users BIGINT,
    new_this_week BIGINT,
    new_today BIGINT,
    total_repos BIGINT,
    runs_today BIGINT,
    total_test_results BIGINT
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        (SELECT COUNT(*) FROM users)::BIGINT,
        (SELECT COUNT(*) FROM users WHERE plan='pro')::BIGINT,
        (SELECT COUNT(*) FROM users WHERE plan='enterprise')::BIGINT,
        (SELECT COUNT(*) FROM users WHERE is_active=TRUE)::BIGINT,
        (SELECT COUNT(*) FROM users WHERE created_at >= NOW() - INTERVAL '7 days')::BIGINT,
        (SELECT COUNT(*) FROM users WHERE created_at >= NOW() - INTERVAL '1 day')::BIGINT,
        (SELECT COUNT(DISTINCT repo_id) FROM ci_runs)::BIGINT,
        (SELECT COUNT(*) FROM ci_runs WHERE timestamp >= NOW() - INTERVAL '24 hours')::BIGINT,
        (SELECT COUNT(*) FROM test_results)::BIGINT;
END;
$$ LANGUAGE plpgsql;

-- 7. Get top referrers
CREATE OR REPLACE FUNCTION get_top_referrers(p_limit INT DEFAULT 5)
RETURNS TABLE (referrer TEXT, cnt BIGINT) AS $$
BEGIN
    RETURN QUERY
    SELECT u.referrer, COUNT(*)::BIGINT
    FROM users u
    WHERE u.referrer IS NOT NULL
    GROUP BY u.referrer
    ORDER BY cnt DESC
    LIMIT p_limit;
END;
$$ LANGUAGE plpgsql;

-- 8. Get top signup sources
CREATE OR REPLACE FUNCTION get_top_sources(p_limit INT DEFAULT 5)
RETURNS TABLE (signup_source TEXT, cnt BIGINT) AS $$
BEGIN
    RETURN QUERY
    SELECT u.signup_source, COUNT(*)::BIGINT
    FROM users u
    WHERE u.signup_source IS NOT NULL
    GROUP BY u.signup_source
    ORDER BY cnt DESC
    LIMIT p_limit;
END;
$$ LANGUAGE plpgsql;

SELECT 'Supabase RPC functions created!' as status;
