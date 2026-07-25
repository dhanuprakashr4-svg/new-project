// ===== Core shared types for ThreatZero Sentinel X =====

export type ThreatLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface SecEvent {
  id: string;
  source: string;
  category: EventCategory;
  timestamp: string;
  malicious: boolean;
  mitre?: string;
  fields: Record<string, string | number | boolean>;
}

export type EventCategory =
  | 'process_creation'
  | 'network_connection'
  | 'file_change'
  | 'authentication'
  | 'scheduled_task'
  | 'service_install'
  | 'web_access';

export interface LogDataset {
  id: string;
  name: string;
  description: string;
  source: 'Windows Security' | 'Sysmon' | 'Web Access';
  category: EventCategory;
  eventCount: number;
  maliciousCount: number;
  benignCount: number;
  events: SecEvent[];
}

export interface SigmaRule {
  title: string;
  id?: string;
  status?: string;
  description?: string;
  author?: string;
  level?: SigmaLevel;
  logsource?: {
    category?: string;
    product?: string;
    service?: string;
  };
  detection: {
    [selectionName: string]: unknown;
  } & { condition?: string };
  falsepositives?: string[];
  tags?: string[];
}

export type SigmaLevel = 'informational' | 'low' | 'medium' | 'high' | 'critical';

export interface ValidationIssue {
  line?: number;
  field: string;
  message: string;
  severity: 'error' | 'warning';
}

export interface ValidationResult {
  valid: boolean;
  errors: ValidationIssue[];
  warnings: ValidationIssue[];
  parsedRule?: SigmaRule;
}

export interface MatchResult {
  matches: number;
  matched_events: SecEvent[];
  truePositives: number;
  falsePositives: number;
  falseNegatives: number;
  trueNegatives: number;
  precision: number;
  recall: number;
  falsePositiveRate: number;
  f1: number;
  accuracy: number;
}

export interface RunRuleResult extends MatchResult {
  ruleTitle: string;
  datasetId: string;
  timestamp: string;
}

export interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
  description: string;
  severity: ThreatLevel;
  subtechnique?: boolean;
  parent?: string;
}

export interface ShapFeature {
  feature: string;
  contribution: number;
  description: string;
}

export interface AIDetection {
  id: string;
  timestamp: string;
  attackType: string;
  mitre: string;
  threatScore: number;
  riskScore: number;
  confidence: number;
  shap: ShapFeature[];
  model: 'XGBoost' | 'Random Forest' | 'Ensemble';
  summary: string;
}

export interface Incident {
  id: string;
  timestamp: string;
  attackType: string;
  mitre: string;
  severity: ThreatLevel;
  threatScore: number;
  riskScore: number;
  status: 'open' | 'investigating' | 'contained' | 'resolved';
  detectionRule: string;
  matchedLogs: number;
  aiSummary: string;
  recommendedActions: string[];
  evidenceId?: string;
}

export interface EvidenceRecord {
  id: string;
  incidentId: string;
  timestamp: string;
  attackType: string;
  mitre: string;
  hash: string;
  encryptionStatus: 'AES-256 Encrypted' | 'Plaintext' | 'Encrypting';
  integrityVerified: boolean;
  sizeBytes: number;
  packaged: boolean;
}

export interface Challenge {
  id: string;
  name: string;
  mitre: string;
  tactic: string;
  difficulty: 'Recruit' | 'Analyst' | 'Hunter' | 'Specialist';
  briefing: string;
  datasetId: string;
  starterRule: string;
  targetPrecision: number;
  targetRecall: number;
  targetFpr: number;
  hint: string;
  solutionRule: string;
}

export interface ChallengeScore {
  challengeId: string;
  precision: number;
  recall: number;
  fpr: number;
  score: number;
  completedAt: string;
}
