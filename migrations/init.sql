-- Poly — AI Flaky Test Trust Layer
-- Database Initialization Script
-- Run this in Supabase SQL Editor: https://supabase.com/dashboard/project/mzcplqfxrxfsxnwyiyym/sql

-- Tables
CREATE TABLE IF NOT EXISTS repositories (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS test_results (
    id SERIAL PRIMARY KEY,
    repo_id INTEGER REFERENCES repositories(id),
    run_id VARCHAR(255),
    test_name VARCHAR(500),
    classname VARCHAR(500),
    status VARCHAR(50),
    duration REAL,
    trust_score REAL,
    flaky_category VARCHAR(50),
    error_message TEXT,
    branch VARCHAR(255) DEFAULT 'main',
    commit_sha VARCHAR(255),
    environment VARCHAR(255),
    timestamp TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ci_runs (
    id SERIAL PRIMARY KEY,
    repo_id INTEGER REFERENCES repositories(id),
    run_id VARCHAR(255),
    branch VARCHAR(255) DEFAULT 'main',
    commit_sha VARCHAR(255),
    total_tests INTEGER DEFAULT 0,
    passed INTEGER DEFAULT 0,
    failed INTEGER DEFAULT 0,
    avg_trust_score REAL DEFAULT 100,
    timestamp TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS alerts_config (
    id SERIAL PRIMARY KEY,
    repo_id INTEGER UNIQUE REFERENCES repositories(id),
    webhook_url TEXT NOT NULL,
    channel_type VARCHAR(50) DEFAULT 'discord',
    min_trust_drop REAL DEFAULT 20,
    alert_on_flaky BOOLEAN DEFAULT TRUE,
    alert_on_quarantine BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS admin_users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'admin',
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255),
    email VARCHAR(255) UNIQUE,
    github_username VARCHAR(255),
    api_key VARCHAR(255) UNIQUE,
    plan VARCHAR(50) DEFAULT 'free',
    is_active BOOLEAN DEFAULT TRUE,
    referrer VARCHAR(255),
    signup_source VARCHAR(255),
    notes TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS user_activity (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    action VARCHAR(100),
    detail TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS admin_sessions (
    id SERIAL PRIMARY KEY,
    admin_id INTEGER REFERENCES admin_users(id),
    token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_test_results_repo ON test_results(repo_id);
CREATE INDEX IF NOT EXISTS idx_test_results_name ON test_results(test_name);
CREATE INDEX IF NOT EXISTS idx_test_results_run ON test_results(run_id);
CREATE INDEX IF NOT EXISTS idx_ci_runs_repo ON ci_runs(repo_id);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_activity ON user_activity(user_id);
CREATE INDEX IF NOT EXISTS idx_admin_sessions_token ON admin_sessions(token);
CREATE INDEX IF NOT EXISTS idx_admin_sessions_expires ON admin_sessions(expires_at);

-- Admin user (password: _09jLHadvC9j_vnPCb-ZmQ)
-- bcrypt hash generated for the password
INSERT INTO admin_users (username, password_hash, role)
VALUES ('admin', '$2b$12$qNOWxX1e6Hv4iYemtBN5IeRzk70i2I2/CNJImclKVilOn2ifaAZ0W', 'admin')
ON CONFLICT (username) DO NOTHING;

SELECT 'Poly database initialized successfully!' as status;
