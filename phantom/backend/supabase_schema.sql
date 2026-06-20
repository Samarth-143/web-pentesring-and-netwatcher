-- PHANTOM Database Schema for Supabase
-- Run this in Supabase SQL Editor to create all required tables

-- Enable RLS (Row Level Security) - disabled by default for REST API access
-- ALTER DATABASE postgres SET "app.jwt_secret" TO 'your-jwt-secret';

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE,
    hashed_password TEXT,
    google_id TEXT UNIQUE,
    github_id TEXT UNIQUE,
    role TEXT DEFAULT 'user'
);

-- Scan Sessions table
CREATE TABLE IF NOT EXISTS scan_sessions (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
    target TEXT NOT NULL,
    status TEXT DEFAULT 'running',
    overall_risk TEXT DEFAULT 'INFO',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    modules_run JSONB
);

-- Scan Results table
CREATE TABLE IF NOT EXISTS scan_results (
    id BIGSERIAL PRIMARY KEY,
    session_id BIGINT NOT NULL REFERENCES scan_sessions(id) ON DELETE CASCADE,
    module_name TEXT NOT NULL,
    risk_level TEXT DEFAULT 'INFO',
    vulnerable BOOLEAN DEFAULT FALSE,
    duration_seconds DOUBLE PRECISION DEFAULT 0.0,
    result_data JSONB,
    error_message TEXT
);

-- Alerts table
CREATE TABLE IF NOT EXISTS alerts (
    id BIGSERIAL PRIMARY KEY,
    session_id BIGINT NOT NULL REFERENCES scan_sessions(id) ON DELETE CASCADE,
    module_name TEXT NOT NULL,
    severity TEXT DEFAULT 'INFO',
    description TEXT NOT NULL,
    acknowledged BOOLEAN DEFAULT FALSE,
    timestamp TIMESTAMPTZ DEFAULT NOW()
);

-- Scan Reports table
CREATE TABLE IF NOT EXISTS scan_reports (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id BIGINT REFERENCES scan_sessions(id) ON DELETE SET NULL,
    filename TEXT NOT NULL,
    storage_path TEXT UNIQUE NOT NULL,
    target TEXT NOT NULL,
    overall_risk TEXT DEFAULT 'INFO',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_scan_sessions_user_id ON scan_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_scan_results_session_id ON scan_results(session_id);
CREATE INDEX IF NOT EXISTS idx_alerts_session_id ON alerts(session_id);
CREATE INDEX IF NOT EXISTS idx_scan_reports_user_id ON scan_reports(user_id);

-- Disable RLS for all tables (allows REST API access with API key)
ALTER TABLE users DISABLE ROW LEVEL SECURITY;
ALTER TABLE scan_sessions DISABLE ROW LEVEL SECURITY;
ALTER TABLE scan_results DISABLE ROW LEVEL SECURITY;
ALTER TABLE alerts DISABLE ROW LEVEL SECURITY;
ALTER TABLE scan_reports DISABLE ROW LEVEL SECURITY;
