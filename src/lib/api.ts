import { supabase } from './supabase';
import { DATASETS } from './datasets';
import { validateRule as localValidate, runRule as localRun } from './sigmaEngine';
export { localValidate };
import type {
  ValidationResult,
  RunRuleResult,
  SigmaRule,
  SecEvent,
  Incident,
  EvidenceRecord,
  ChallengeScore,
} from './types';

// ===== API client =====
// Prefers the server-side edge functions (/functions/v1/validate-rule and /run-rule).
// Falls back to the in-browser engine if the network call fails, so the UI stays usable.

const SUPABASE_URL = import.meta.env.VITE_SUPABASE_URL as string;
const ANON_KEY = import.meta.env.VITE_SUPABASE_ANON_KEY as string;

async function edgeFetch(slug: string, body: unknown): Promise<unknown> {
  const res = await fetch(`${SUPABASE_URL}/functions/v1/${slug}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${ANON_KEY}`,
      apikey: ANON_KEY,
    },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`Edge function ${slug} failed (${res.status}): ${text}`);
  }
  return res.json();
}

export async function validateRuleServer(yaml: string): Promise<ValidationResult> {
  try {
    const data = (await edgeFetch('validate-rule', { rule: yaml })) as ValidationResult;
    if (data && typeof data.valid === 'boolean') return data;
    throw new Error('Unexpected response shape');
  } catch (err) {
    console.warn('[validate-rule] edge call failed, using local engine:', err);
    return localValidate(yaml);
  }
}

export async function runRuleServer(yaml: string, datasetId: string): Promise<RunRuleResult> {
  const dataset = DATASETS.find((d) => d.id === datasetId);
  if (!dataset) throw new Error(`Unknown dataset: ${datasetId}`);
  const events = dataset.events;
  try {
    const data = (await edgeFetch('run-rule', { rule: yaml, dataset: events })) as RunRuleResult;
    if (data && typeof data.matches === 'number') {
      return { ...data, datasetId, ruleTitle: data.ruleTitle || 'Sigma Rule' };
    }
    throw new Error('Unexpected response shape');
  } catch (err) {
    console.warn('[run-rule] edge call failed, using local engine:', err);
    const local = localValidate(yaml);
    if (!local.parsedRule) throw new Error('Rule validation failed before execution');
    const result = localRun(local.parsedRule, events);
    return {
      ...result,
      ruleTitle: local.parsedRule.title,
      datasetId,
      timestamp: new Date().toISOString(),
    };
  }
}

// ===== Supabase persistence helpers =====

export async function loadIncidents(): Promise<Incident[]> {
  const { data, error } = await supabase
    .from('incidents')
    .select('*')
    .order('timestamp', { ascending: false });
  if (error) {
    console.warn('[loadIncidents] failed:', error.message);
    return [];
  }
  return (data || []).map(mapIncident);
}

export async function saveIncident(inc: Incident): Promise<void> {
  const { error } = await supabase.from('incidents').upsert({
    id: inc.id,
    timestamp: inc.timestamp,
    attack_type: inc.attackType,
    mitre: inc.mitre,
    severity: inc.severity,
    threat_score: inc.threatScore,
    risk_score: inc.riskScore,
    status: inc.status,
    detection_rule: inc.detectionRule,
    matched_logs: inc.matchedLogs,
    ai_summary: inc.aiSummary,
    recommended_actions: inc.recommendedActions,
  });
  if (error) console.warn('[saveIncident] failed:', error.message);
}

export async function loadEvidence(): Promise<EvidenceRecord[]> {
  const { data, error } = await supabase
    .from('evidence')
    .select('*')
    .order('timestamp', { ascending: false });
  if (error) {
    console.warn('[loadEvidence] failed:', error.message);
    return [];
  }
  return (data || []).map((r: Record<string, unknown>) => ({
    id: String(r.id),
    incidentId: String(r.incident_id),
    timestamp: String(r.timestamp),
    attackType: String(r.attack_type),
    mitre: String(r.mitre),
    hash: String(r.hash),
    encryptionStatus: String(r.encryption_status) as EvidenceRecord['encryptionStatus'],
    integrityVerified: Boolean(r.integrity_verified),
    sizeBytes: Number(r.size_bytes),
    packaged: Boolean(r.packaged),
  }));
}

export async function saveEvidence(e: EvidenceRecord): Promise<void> {
  const { error } = await supabase.from('evidence').upsert({
    id: e.id,
    incident_id: e.incidentId,
    timestamp: e.timestamp,
    attack_type: e.attackType,
    mitre: e.mitre,
    hash: e.hash,
    encryption_status: e.encryptionStatus,
    integrity_verified: e.integrityVerified,
    size_bytes: e.sizeBytes,
    packaged: e.packaged,
  });
  if (error) console.warn('[saveEvidence] failed:', error.message);
}

export async function loadSavedRules() {
  const { data, error } = await supabase
    .from('sigma_rules')
    .select('*')
    .order('updated_at', { ascending: false });
  if (error) {
    console.warn('[loadSavedRules] failed:', error.message);
    return [];
  }
  return (data || []).map((r: Record<string, unknown>) => ({
    id: String(r.id),
    title: String(r.title),
    yaml: String(r.yaml),
    level: String(r.level),
    mitre: r.mitre ? String(r.mitre) : undefined,
    createdAt: String(r.created_at),
    updatedAt: String(r.updated_at),
  }));
}

export async function saveSigmaRule(rule: { title: string; yaml: string; level?: string; mitre?: string }) {
  const { error } = await supabase.from('sigma_rules').upsert({
    title: rule.title,
    yaml: rule.yaml,
    level: rule.level || 'medium',
    mitre: rule.mitre,
    updated_at: new Date().toISOString(),
  });
  if (error) console.warn('[saveSigmaRule] failed:', error.message);
}

export async function loadChallengeScores(): Promise<ChallengeScore[]> {
  const { data, error } = await supabase
    .from('challenge_scores')
    .select('*')
    .order('completed_at', { ascending: false });
  if (error) {
    console.warn('[loadChallengeScores] failed:', error.message);
    return [];
  }
  return (data || []).map((r: Record<string, unknown>) => ({
    challengeId: String(r.challenge_id),
    precision: Number(r.precision),
    recall: Number(r.recall),
    fpr: Number(r.fpr),
    score: Number(r.score),
    completedAt: String(r.completed_at),
  }));
}

export async function saveChallengeScore(s: ChallengeScore): Promise<void> {
  const { error } = await supabase.from('challenge_scores').insert({
    challenge_id: s.challengeId,
    precision: s.precision,
    recall: s.recall,
    fpr: s.fpr,
    score: s.score,
  });
  if (error) console.warn('[saveChallengeScore] failed:', error.message);
}

export async function loadRuleRuns() {
  const { data, error } = await supabase
    .from('rule_runs')
    .select('*')
    .order('created_at', { ascending: false })
    .limit(50);
  if (error) {
    console.warn('[loadRuleRuns] failed:', error.message);
    return [];
  }
  return (data || []).map((r: Record<string, unknown>) => ({
    id: String(r.id),
    ruleTitle: String(r.rule_title),
    datasetId: String(r.dataset_id),
    matches: Number(r.matches),
    precision: Number(r.precision),
    recall: Number(r.recall),
    fpr: Number(r.fpr),
    accuracy: Number(r.accuracy),
    valid: Boolean(r.valid),
    createdAt: String(r.created_at),
  }));
}

export async function logRuleRun(run: {
  ruleTitle: string;
  datasetId: string;
  matches: number;
  precision: number;
  recall: number;
  fpr: number;
  accuracy: number;
  valid: boolean;
}): Promise<void> {
  const { error } = await supabase.from('rule_runs').insert({
    rule_title: run.ruleTitle,
    dataset_id: run.datasetId,
    matches: run.matches,
    precision: run.precision,
    recall: run.recall,
    fpr: run.fpr,
    accuracy: run.accuracy,
    valid: run.valid,
  });
  if (error) console.warn('[logRuleRun] failed:', error.message);
}

function mapIncident(r: Record<string, unknown>): Incident {
  return {
    id: String(r.id),
    timestamp: String(r.timestamp),
    attackType: String(r.attack_type),
    mitre: String(r.mitre),
    severity: String(r.severity) as Incident['severity'],
    threatScore: Number(r.threat_score),
    riskScore: Number(r.risk_score),
    status: String(r.status) as Incident['status'],
    detectionRule: r.detection_rule ? String(r.detection_rule) : '',
    matchedLogs: Number(r.matched_logs),
    aiSummary: r.ai_summary ? String(r.ai_summary) : '',
    recommendedActions: Array.isArray(r.recommended_actions)
      ? (r.recommended_actions as string[])
      : [],
    evidenceId: undefined,
  };
}
