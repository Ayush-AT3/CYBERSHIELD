-- ============================================================
-- CyberShield Seed Data: Phishing Keywords for Aho-Corasick Engine
-- Run this in the Supabase SQL Editor to populate initial knowledge base
-- ============================================================

INSERT INTO keywords (keyword, category, weight, source) VALUES
-- Urgency & Coercion Keywords
('urgent action required', 'URGENCY', 4.5, 'SUPABASE'),
('immediate action required', 'URGENCY', 4.5, 'SUPABASE'),
('account suspended', 'URGENCY', 5.0, 'SUPABASE'),
('account will be locked', 'URGENCY', 4.8, 'SUPABASE'),
('within 24 hours', 'URGENCY', 3.5, 'SUPABASE'),
('within 48 hours', 'URGENCY', 3.2, 'SUPABASE'),
('unauthorized login attempt', 'URGENCY', 4.5, 'SUPABASE'),
('security breach detected', 'URGENCY', 4.5, 'SUPABASE'),
('act immediately', 'URGENCY', 4.0, 'SUPABASE'),
('final notice', 'URGENCY', 4.2, 'SUPABASE'),
('limited time offer', 'URGENCY', 2.5, 'SUPABASE'),
('failure to comply', 'URGENCY', 4.0, 'SUPABASE'),
('security alert', 'URGENCY', 3.8, 'SUPABASE'),

-- Credential Theft & Harvesting Keywords
('verify your password', 'CREDENTIAL', 5.0, 'SUPABASE'),
('confirm your account', 'CREDENTIAL', 4.5, 'SUPABASE'),
('reset your password', 'CREDENTIAL', 3.8, 'SUPABASE'),
('update your credentials', 'CREDENTIAL', 4.8, 'SUPABASE'),
('enter your pin', 'CREDENTIAL', 5.0, 'SUPABASE'),
('social security number', 'CREDENTIAL', 5.0, 'SUPABASE'),
('confirm your identity', 'CREDENTIAL', 4.5, 'SUPABASE'),
('validate your email', 'CREDENTIAL', 3.5, 'SUPABASE'),
('log in here', 'CREDENTIAL', 3.0, 'SUPABASE'),
('update payment information', 'CREDENTIAL', 4.8, 'SUPABASE'),
('billing information update', 'CREDENTIAL', 4.5, 'SUPABASE'),
('sign in to verify', 'CREDENTIAL', 4.0, 'SUPABASE'),

-- Financial Fraud Keywords
('wire transfer', 'FINANCIAL', 4.5, 'SUPABASE'),
('cryptocurrency payout', 'FINANCIAL', 4.8, 'SUPABASE'),
('bitcoin transaction', 'FINANCIAL', 4.2, 'SUPABASE'),
('inheritance fund', 'FINANCIAL', 5.0, 'SUPABASE'),
('claim your prize', 'FINANCIAL', 4.5, 'SUPABASE'),
('lottery winner', 'FINANCIAL', 5.0, 'SUPABASE'),
('tax refund approved', 'FINANCIAL', 4.8, 'SUPABASE'),
('unpaid invoice attached', 'FINANCIAL', 4.2, 'SUPABASE'),
('compensation fund', 'FINANCIAL', 4.5, 'SUPABASE'),
('gift card reward', 'FINANCIAL', 4.0, 'SUPABASE'),

-- Threat Coercion & Defense Evasion
('do not contact support', 'THREAT', 4.8, 'SUPABASE'),
('keep this confidential', 'THREAT', 4.2, 'SUPABASE'),
('enable macros to view', 'THREAT', 5.0, 'SUPABASE'),
('disable your antivirus', 'THREAT', 5.0, 'SUPABASE'),
('click the link below', 'GENERAL', 2.5, 'SUPABASE'),
('open attached document', 'GENERAL', 3.0, 'SUPABASE'),
('session expired', 'CREDENTIAL', 3.5, 'SUPABASE')
ON CONFLICT (keyword) DO NOTHING;
