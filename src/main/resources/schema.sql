-- ============================================================
-- CyberShield: Smart Web Security System for Phishing Detection
-- PostgreSQL / Supabase Schema Definition
-- ============================================================

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. Keywords Table (Layer 1 Aho-Corasick Multi-Pattern Trie)
CREATE TABLE IF NOT EXISTS keywords (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    keyword VARCHAR(255) NOT NULL UNIQUE,
    category VARCHAR(50) NOT NULL, -- URGENCY, CREDENTIAL, FINANCIAL, THREAT, GENERAL
    weight NUMERIC(4,2) NOT NULL DEFAULT 3.00,
    source VARCHAR(50) DEFAULT 'SUPABASE',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Index for rapid keyword retrieval and case-insensitive queries
CREATE INDEX IF NOT EXISTS idx_keywords_category ON keywords(category);
CREATE INDEX IF NOT EXISTS idx_keywords_lower ON keywords(LOWER(keyword));

-- 2. Scans History Table (Audit Log & Forensics)
CREATE TABLE IF NOT EXISTS scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_type VARCHAR(20) NOT NULL, -- EMAIL, URL
    input_target TEXT,
    sender VARCHAR(255),
    subject TEXT,
    overall_risk_score NUMERIC(5,2) NOT NULL,
    classification VARCHAR(20) NOT NULL, -- SAFE, SUSPICIOUS, DANGEROUS
    summary TEXT,
    total_execution_time_ms BIGINT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scans_classification ON scans(classification);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC);

-- 3. Threat Indicators Table (Layer-by-Layer Findings)
CREATE TABLE IF NOT EXISTS threat_indicators (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
    layer VARCHAR(20) NOT NULL, -- Layer 1, Layer 2, Layer 3, Layer 4
    type VARCHAR(100) NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    severity VARCHAR(20) NOT NULL, -- LOW, MEDIUM, HIGH, CRITICAL
    score_contribution NUMERIC(5,2) NOT NULL,
    evidence TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_indicators_scan_id ON threat_indicators(scan_id);

-- 4. VirusTotal Cache Table (Layer 3 Rate Limit Optimization)
CREATE TABLE IF NOT EXISTS virustotal_cache (
    url TEXT PRIMARY KEY,
    malicious_count INT DEFAULT 0,
    suspicious_count INT DEFAULT 0,
    harmless_count INT DEFAULT 0,
    undetected_count INT DEFAULT 0,
    cached_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
