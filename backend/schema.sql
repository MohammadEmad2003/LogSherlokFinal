-- ============================================================================
-- Autonomous Forensic Agent - PostgreSQL Database Schema
-- Neon DB (PostgreSQL) - Production Schema
-- ============================================================================

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================================
-- Users & Authentication
-- ============================================================================

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(255),
    role VARCHAR(50) DEFAULT 'analyst' CHECK (role IN ('admin', 'analyst', 'viewer')),
    is_active BOOLEAN DEFAULT true,
    is_verified BOOLEAN DEFAULT false,
    avatar_url VARCHAR(500),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_login_at TIMESTAMP WITH TIME ZONE,
    login_count INTEGER DEFAULT 0
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_username ON users(username);

-- OTP tokens for password reset and email verification
CREATE TABLE IF NOT EXISTS otp_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(6) NOT NULL,
    token_type VARCHAR(50) NOT NULL CHECK (token_type IN ('password_reset', 'email_verification')),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    is_used BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_otp_user_id ON otp_tokens(user_id);
CREATE INDEX idx_otp_token ON otp_tokens(token);

-- Refresh tokens for JWT
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL,
    device_info VARCHAR(500),
    ip_address VARCHAR(50),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    is_revoked BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_hash ON refresh_tokens(token_hash);

-- ============================================================================
-- Investigations & Sessions
-- ============================================================================

CREATE TABLE IF NOT EXISTS investigations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id VARCHAR(20) UNIQUE NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    artifact_name VARCHAR(500) NOT NULL,
    artifact_path VARCHAR(1000) NOT NULL,
    artifact_type VARCHAR(100) NOT NULL CHECK (artifact_type IN (
        'memory_dump', 'disk_image', 'pcap', 'evtx', 'malware_sample', 'binary', 'archive', 'unknown'
    )),
    artifact_size BIGINT NOT NULL,
    artifact_hash_md5 VARCHAR(32),
    artifact_hash_sha256 VARCHAR(64),
    description TEXT,
    status VARCHAR(50) DEFAULT 'initializing' CHECK (status IN (
        'initializing', 'active', 'paused', 'completed', 'error', 'cancelled'
    )),
    current_phase VARCHAR(100) DEFAULT 'initialization',
    progress DECIMAL(5,2) DEFAULT 0,
    threat_score DECIMAL(5,4) DEFAULT 0,
    overall_confidence DECIMAL(5,4) DEFAULT 0,
    started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE,
    error_message TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_investigations_session_id ON investigations(session_id);
CREATE INDEX idx_investigations_user_id ON investigations(user_id);
CREATE INDEX idx_investigations_status ON investigations(status);
CREATE INDEX idx_investigations_created_at ON investigations(created_at DESC);

-- ============================================================================
-- Investigation Steps (ReAct Loop)
-- ============================================================================

CREATE TABLE IF NOT EXISTS investigation_steps (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    investigation_id UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    step_number INTEGER NOT NULL,
    phase VARCHAR(50) NOT NULL CHECK (phase IN ('reasoning', 'action', 'observation', 'complete')),
    reasoning TEXT,
    action TEXT,
    action_type VARCHAR(50) CHECK (action_type IN ('command', 'analysis', 'query', 'complete')),
    observation TEXT,
    confidence DECIMAL(5,4) DEFAULT 0.5,
    error_message TEXT,
    execution_time_ms INTEGER,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_steps_investigation_id ON investigation_steps(investigation_id);
CREATE INDEX idx_steps_step_number ON investigation_steps(investigation_id, step_number);

-- ============================================================================
-- Evidence
-- ============================================================================

CREATE TABLE IF NOT EXISTS evidence (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    investigation_id UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    step_id UUID REFERENCES investigation_steps(id) ON DELETE SET NULL,
    type VARCHAR(100) NOT NULL,
    value TEXT NOT NULL,
    confidence DECIMAL(5,4) DEFAULT 0.5,
    threat_score DECIMAL(5,4) DEFAULT 0.3,
    source VARCHAR(255),
    context JSONB DEFAULT '{}',
    mitre_tactics TEXT[] DEFAULT '{}',
    mitre_techniques TEXT[] DEFAULT '{}',
    is_ioc BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_evidence_investigation_id ON evidence(investigation_id);
CREATE INDEX idx_evidence_type ON evidence(type);
CREATE INDEX idx_evidence_is_ioc ON evidence(is_ioc);
CREATE INDEX idx_evidence_threat_score ON evidence(threat_score DESC);

-- ============================================================================
-- Attack Hypotheses
-- ============================================================================

CREATE TABLE IF NOT EXISTS hypotheses (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    investigation_id UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    hypothesis TEXT NOT NULL,
    confidence DECIMAL(5,4) DEFAULT 0.5,
    severity VARCHAR(50) DEFAULT 'medium' CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    supporting_evidence TEXT[] DEFAULT '{}',
    mitre_tactics TEXT[] DEFAULT '{}',
    mitre_techniques TEXT[] DEFAULT '{}',
    status VARCHAR(50) DEFAULT 'active' CHECK (status IN ('active', 'confirmed', 'dismissed')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_hypotheses_investigation_id ON hypotheses(investigation_id);
CREATE INDEX idx_hypotheses_severity ON hypotheses(severity);

-- ============================================================================
-- MITRE ATT&CK Coverage
-- ============================================================================

CREATE TABLE IF NOT EXISTS mitre_coverage (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    investigation_id UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    tactic_id VARCHAR(20) NOT NULL,
    tactic_name VARCHAR(100) NOT NULL,
    technique_id VARCHAR(20),
    technique_name VARCHAR(255),
    evidence_count INTEGER DEFAULT 1,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(investigation_id, tactic_id, technique_id)
);

CREATE INDEX idx_mitre_investigation_id ON mitre_coverage(investigation_id);

-- ============================================================================
-- Dynamic To-Do List
-- ============================================================================

CREATE TABLE IF NOT EXISTS investigation_todos (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    investigation_id UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    task TEXT NOT NULL,
    priority VARCHAR(20) DEFAULT 'medium' CHECK (priority IN ('critical', 'high', 'medium', 'low')),
    status VARCHAR(50) DEFAULT 'pending' CHECK (status IN ('pending', 'in_progress', 'completed', 'blocked')),
    rationale TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_todos_investigation_id ON investigation_todos(investigation_id);
CREATE INDEX idx_todos_status ON investigation_todos(status);

-- ============================================================================
-- Chat Messages (Forensic Assistant)
-- ============================================================================

CREATE TABLE IF NOT EXISTS chat_messages (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    investigation_id UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role VARCHAR(20) NOT NULL CHECK (role IN ('user', 'assistant', 'system')),
    content TEXT NOT NULL,
    context JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_chat_investigation_id ON chat_messages(investigation_id);
CREATE INDEX idx_chat_user_id ON chat_messages(user_id);
CREATE INDEX idx_chat_created_at ON chat_messages(created_at);

-- ============================================================================
-- Audit Log
-- ============================================================================

CREATE TABLE IF NOT EXISTS audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100),
    resource_id UUID,
    details JSONB DEFAULT '{}',
    ip_address VARCHAR(50),
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_audit_user_id ON audit_log(user_id);
CREATE INDEX idx_audit_action ON audit_log(action);
CREATE INDEX idx_audit_created_at ON audit_log(created_at DESC);

-- ============================================================================
-- Investigation Timeline Events
-- ============================================================================

CREATE TABLE IF NOT EXISTS timeline_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    investigation_id UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    event_timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    description TEXT NOT NULL,
    severity VARCHAR(50) DEFAULT 'info' CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    actor VARCHAR(255),
    evidence_ids UUID[] DEFAULT '{}',
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_timeline_investigation_id ON timeline_events(investigation_id);
CREATE INDEX idx_timeline_event_timestamp ON timeline_events(event_timestamp);

-- ============================================================================
-- Reports
-- ============================================================================

CREATE TABLE IF NOT EXISTS reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    investigation_id UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    report_type VARCHAR(50) NOT NULL CHECK (report_type IN ('json', 'html', 'pdf', 'stix')),
    file_path VARCHAR(1000),
    content JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_reports_investigation_id ON reports(investigation_id);

-- ============================================================================
-- Functions & Triggers
-- ============================================================================

-- Update updated_at timestamp automatically
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply triggers to tables with updated_at
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_investigations_updated_at BEFORE UPDATE ON investigations
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_hypotheses_updated_at BEFORE UPDATE ON hypotheses
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Function to calculate investigation progress
CREATE OR REPLACE FUNCTION calculate_investigation_progress(inv_id UUID)
RETURNS DECIMAL AS $$
DECLARE
    total_steps INTEGER;
    max_steps INTEGER := 50;
BEGIN
    SELECT COUNT(*) INTO total_steps FROM investigation_steps WHERE investigation_id = inv_id;
    RETURN LEAST((total_steps::DECIMAL / max_steps) * 100, 100);
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- Views
-- ============================================================================

-- Investigation summary view
CREATE OR REPLACE VIEW investigation_summary AS
SELECT
    i.id,
    i.session_id,
    i.artifact_name,
    i.artifact_type,
    i.status,
    i.current_phase,
    i.threat_score,
    i.overall_confidence,
    u.username as investigator,
    u.email as investigator_email,
    (SELECT COUNT(*) FROM investigation_steps WHERE investigation_id = i.id) as total_steps,
    (SELECT COUNT(*) FROM evidence WHERE investigation_id = i.id) as total_evidence,
    (SELECT COUNT(*) FROM hypotheses WHERE investigation_id = i.id) as total_hypotheses,
    i.created_at,
    i.completed_at
FROM investigations i
JOIN users u ON i.user_id = u.id;

-- Evidence with MITRE mapping view
CREATE OR REPLACE VIEW evidence_with_mitre AS
SELECT
    e.*,
    i.session_id,
    i.artifact_name
FROM evidence e
JOIN investigations i ON e.investigation_id = i.id;

-- ============================================================================
-- Initial Data (Admin User - Password: Admin@123)
-- ============================================================================

-- Note: In production, change this password immediately after first login
INSERT INTO users (email, username, password_hash, full_name, role, is_active, is_verified)
VALUES (
    'admin@forensic-agent.local',
    'admin',
    -- bcrypt hash for 'Admin@123' - CHANGE IN PRODUCTION
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.VDlBbQz8G.S1O.',
    'System Administrator',
    'admin',
    true,
    true
) ON CONFLICT (email) DO NOTHING;

-- ============================================================================
-- Comments
-- ============================================================================

COMMENT ON TABLE users IS 'User accounts for authentication and authorization';
COMMENT ON TABLE investigations IS 'Forensic investigation sessions';
COMMENT ON TABLE evidence IS 'Evidence collected during investigations';
COMMENT ON TABLE chat_messages IS 'Chat messages between users and the forensic AI assistant';
COMMENT ON TABLE audit_log IS 'Audit trail for compliance and security';

-- ============================================================================
-- End of Schema
-- ============================================================================
