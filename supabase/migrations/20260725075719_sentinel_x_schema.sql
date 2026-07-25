/*
# ThreatZero Sentinel X - Core Schema

## Overview
Single-tenant persistence for the SOC detection-engineering platform.
No sign-in is required for this app, so policies allow the anon-key frontend
to read and write shared data.

## New Tables
- `incidents`           - Detected incidents with MITRE mapping, scores, AI summary
- `evidence`            - Encrypted evidence records (AES-256, SHA-256 verified)
- `sigma_rules`         - Saved Sigma detection rules authored by analysts
- `rule_runs`           - Audit log of rule validation / run results
- `challenge_scores`    - Detection Academy completion records with precision/recall/FPR

## Columns
incidents:
  id (text PK), timestamp, attack_type, mitre, severity, threat_score,
  risk_score, status, detection_rule, matched_logs, ai_summary,
  recommended_actions (jsonb)

evidence:
  id (text PK), incident_id, timestamp, attack_type, mitre, hash,
  encryption_status, integrity_verified (bool), size_bytes, packaged (bool)

sigma_rules:
  id (uuid PK), title, yaml, level, mitre, created_at, updated_at

rule_runs:
  id (uuid PK), rule_title, dataset_id, matches, precision, recall,
  fpr, accuracy, valid (bool), errors (jsonb), created_at

challenge_scores:
  id (uuid PK), challenge_id, precision, recall, fpr, score, completed_at

## Security
- RLS enabled on every table.
- All tables are intentionally shared/public (single-tenant, no auth) and
  use `TO anon, authenticated` with `USING (true)` / `WITH CHECK (true)`.
*/

CREATE TABLE IF NOT EXISTS incidents (
  id text PRIMARY KEY,
  timestamp timestamptz DEFAULT now(),
  attack_type text NOT NULL,
  mitre text NOT NULL,
  severity text NOT NULL DEFAULT 'high',
  threat_score integer NOT NULL DEFAULT 0,
  risk_score integer NOT NULL DEFAULT 0,
  status text NOT NULL DEFAULT 'open',
  detection_rule text,
  matched_logs integer DEFAULT 0,
  ai_summary text,
  recommended_actions jsonb DEFAULT '[]'::jsonb
);

ALTER TABLE incidents ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "anon_select_incidents" ON incidents;
CREATE POLICY "anon_select_incidents" ON incidents FOR SELECT
  TO anon, authenticated USING (true);
DROP POLICY IF EXISTS "anon_insert_incidents" ON incidents;
CREATE POLICY "anon_insert_incidents" ON incidents FOR INSERT
  TO anon, authenticated WITH CHECK (true);
DROP POLICY IF EXISTS "anon_update_incidents" ON incidents;
CREATE POLICY "anon_update_incidents" ON incidents FOR UPDATE
  TO anon, authenticated USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS "anon_delete_incidents" ON incidents;
CREATE POLICY "anon_delete_incidents" ON incidents FOR DELETE
  TO anon, authenticated USING (true);

CREATE TABLE IF NOT EXISTS evidence (
  id text PRIMARY KEY,
  incident_id text NOT NULL,
  timestamp timestamptz DEFAULT now(),
  attack_type text NOT NULL,
  mitre text NOT NULL,
  hash text NOT NULL,
  encryption_status text NOT NULL DEFAULT 'AES-256 Encrypted',
  integrity_verified boolean NOT NULL DEFAULT true,
  size_bytes integer DEFAULT 0,
  packaged boolean NOT NULL DEFAULT false
);

ALTER TABLE evidence ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "anon_select_evidence" ON evidence;
CREATE POLICY "anon_select_evidence" ON evidence FOR SELECT
  TO anon, authenticated USING (true);
DROP POLICY IF EXISTS "anon_insert_evidence" ON evidence;
CREATE POLICY "anon_insert_evidence" ON evidence FOR INSERT
  TO anon, authenticated WITH CHECK (true);
DROP POLICY IF EXISTS "anon_update_evidence" ON evidence;
CREATE POLICY "anon_update_evidence" ON evidence FOR UPDATE
  TO anon, authenticated USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS "anon_delete_evidence" ON evidence;
CREATE POLICY "anon_delete_evidence" ON evidence FOR DELETE
  TO anon, authenticated USING (true);

CREATE TABLE IF NOT EXISTS sigma_rules (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  title text NOT NULL,
  yaml text NOT NULL,
  level text DEFAULT 'medium',
  mitre text,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now()
);

ALTER TABLE sigma_rules ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "anon_select_sigma_rules" ON sigma_rules;
CREATE POLICY "anon_select_sigma_rules" ON sigma_rules FOR SELECT
  TO anon, authenticated USING (true);
DROP POLICY IF EXISTS "anon_insert_sigma_rules" ON sigma_rules;
CREATE POLICY "anon_insert_sigma_rules" ON sigma_rules FOR INSERT
  TO anon, authenticated WITH CHECK (true);
DROP POLICY IF EXISTS "anon_update_sigma_rules" ON sigma_rules;
CREATE POLICY "anon_update_sigma_rules" ON sigma_rules FOR UPDATE
  TO anon, authenticated USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS "anon_delete_sigma_rules" ON sigma_rules;
CREATE POLICY "anon_delete_sigma_rules" ON sigma_rules FOR DELETE
  TO anon, authenticated USING (true);

CREATE TABLE IF NOT EXISTS rule_runs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  rule_title text NOT NULL,
  dataset_id text NOT NULL,
  matches integer DEFAULT 0,
  precision numeric DEFAULT 0,
  recall numeric DEFAULT 0,
  fpr numeric DEFAULT 0,
  accuracy numeric DEFAULT 0,
  valid boolean DEFAULT true,
  errors jsonb DEFAULT '[]'::jsonb,
  created_at timestamptz DEFAULT now()
);

ALTER TABLE rule_runs ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "anon_select_rule_runs" ON rule_runs;
CREATE POLICY "anon_select_rule_runs" ON rule_runs FOR SELECT
  TO anon, authenticated USING (true);
DROP POLICY IF EXISTS "anon_insert_rule_runs" ON rule_runs;
CREATE POLICY "anon_insert_rule_runs" ON rule_runs FOR INSERT
  TO anon, authenticated WITH CHECK (true);
DROP POLICY IF EXISTS "anon_update_rule_runs" ON rule_runs;
CREATE POLICY "anon_update_rule_runs" ON rule_runs FOR UPDATE
  TO anon, authenticated USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS "anon_delete_rule_runs" ON rule_runs;
CREATE POLICY "anon_delete_rule_runs" ON rule_runs FOR DELETE
  TO anon, authenticated USING (true);

CREATE TABLE IF NOT EXISTS challenge_scores (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  challenge_id text NOT NULL,
  precision numeric DEFAULT 0,
  recall numeric DEFAULT 0,
  fpr numeric DEFAULT 0,
  score integer DEFAULT 0,
  completed_at timestamptz DEFAULT now()
);

ALTER TABLE challenge_scores ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "anon_select_challenge_scores" ON challenge_scores;
CREATE POLICY "anon_select_challenge_scores" ON challenge_scores FOR SELECT
  TO anon, authenticated USING (true);
DROP POLICY IF EXISTS "anon_insert_challenge_scores" ON challenge_scores;
CREATE POLICY "anon_insert_challenge_scores" ON challenge_scores FOR INSERT
  TO anon, authenticated WITH CHECK (true);
DROP POLICY IF EXISTS "anon_update_challenge_scores" ON challenge_scores;
CREATE POLICY "anon_update_challenge_scores" ON challenge_scores FOR UPDATE
  TO anon, authenticated USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS "anon_delete_challenge_scores" ON challenge_scores;
CREATE POLICY "anon_delete_challenge_scores" ON challenge_scores FOR DELETE
  TO anon, authenticated USING (true);

CREATE INDEX IF NOT EXISTS idx_incidents_mitre ON incidents(mitre);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_evidence_incident ON evidence(incident_id);
CREATE INDEX IF NOT EXISTS idx_rule_runs_created ON rule_runs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_challenge_scores_challenge ON challenge_scores(challenge_id);
