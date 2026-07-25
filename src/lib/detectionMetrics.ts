import type { RunRuleResult } from './types';

// ===== Detection Metrics & Confusion Matrix Analytics =====
// Aggregates rule run results into confusion matrix visualization data
// and validates FPR compliance (< 0.7 per hackathon requirements).

export interface ConfusionMatrixData {
  truePositives: number;
  falsePositives: number;
  falseNegatives: number;
  trueNegatives: number;
  total: number;
  precision: number;
  recall: number;
  fpr: number;
  fnr: number;
  accuracy: number;
  f1: number;
  fprCompliant: boolean; // FPR < 0.7
}

export interface AggregatedMetrics {
  totalRuns: number;
  validRuns: number;
  avgPrecision: number;
  avgRecall: number;
  avgFpr: number;
  avgAccuracy: number;
  avgF1: number;
  bestPrecision: number;
  bestRecall: number;
  worstFpr: number;
  fprComplianceRate: number; // % of runs with FPR < 0.7
  runs: RunHistoryItem[];
}

export interface RunHistoryItem {
  id: string;
  ruleTitle: string;
  datasetId: string;
  matches: number;
  precision: number;
  recall: number;
  fpr: number;
  accuracy: number;
  valid: boolean;
  fprCompliant: boolean;
  createdAt: string;
}

export const FPR_THRESHOLD = 0.7;

export function buildConfusionMatrix(result: RunRuleResult): ConfusionMatrixData {
  const total = result.truePositives + result.falsePositives + result.falseNegatives + result.trueNegatives;
  const precision = total > 0 ? result.truePositives / (result.truePositives + result.falsePositives || 1) : 0;
  const recall = total > 0 ? result.truePositives / (result.truePositives + result.falseNegatives || 1) : 0;
  const fpr = total > 0 ? result.falsePositives / (result.falsePositives + result.trueNegatives || 1) : 0;
  const fnr = total > 0 ? result.falseNegatives / (result.falseNegatives + result.truePositives || 1) : 0;
  const accuracy = total > 0 ? (result.truePositives + result.trueNegatives) / total : 0;
  const f1 = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;

  return {
    truePositives: result.truePositives,
    falsePositives: result.falsePositives,
    falseNegatives: result.falseNegatives,
    trueNegatives: result.trueNegatives,
    total,
    precision,
    recall,
    fpr,
    fnr,
    accuracy,
    f1,
    fprCompliant: fpr < FPR_THRESHOLD,
  };
}

export function aggregateMetrics(runs: RunHistoryItem[]): AggregatedMetrics {
  if (runs.length === 0) {
    return {
      totalRuns: 0, validRuns: 0,
      avgPrecision: 0, avgRecall: 0, avgFpr: 0, avgAccuracy: 0, avgF1: 0,
      bestPrecision: 0, bestRecall: 0, worstFpr: 0,
      fprComplianceRate: 0, runs: [],
    };
  }

  const valid = runs.filter((r) => r.valid);
  const precisions = valid.map((r) => r.precision);
  const recalls = valid.map((r) => r.recall);
  const fprs = valid.map((r) => r.fpr);
  const accuracies = valid.map((r) => r.accuracy);
  const f1s = valid.map((r) => {
    const p = r.precision, rec = r.recall;
    return p + rec > 0 ? (2 * p * rec) / (p + rec) : 0;
  });

  return {
    totalRuns: runs.length,
    validRuns: valid.length,
    avgPrecision: avg(precisions),
    avgRecall: avg(recalls),
    avgFpr: avg(fprs),
    avgAccuracy: avg(accuracies),
    avgF1: avg(f1s),
    bestPrecision: Math.max(...precisions, 0),
    bestRecall: Math.max(...recalls, 0),
    worstFpr: Math.max(...fprs, 0),
    fprComplianceRate: valid.filter((r) => r.fpr < FPR_THRESHOLD).length / valid.length,
    runs: runs.map((r) => ({ ...r, fprCompliant: r.fpr < FPR_THRESHOLD })),
  };
}

function avg(arr: number[]): number {
  return arr.length > 0 ? arr.reduce((s, v) => s + v, 0) / arr.length : 0;
}

// Threshold compliance table for the hackathon evaluation
export interface ComplianceCheck {
  metric: string;
  value: number;
  threshold: string;
  passed: boolean;
  description: string;
}

export function complianceChecks(cm: ConfusionMatrixData): ComplianceCheck[] {
  return [
    {
      metric: 'False Positive Rate',
      value: cm.fpr,
      threshold: '< 0.7 (70%)',
      passed: cm.fpr < FPR_THRESHOLD,
      description: 'FPR must be below 70% per hackathon requirements',
    },
    {
      metric: 'Precision',
      value: cm.precision,
      threshold: '≥ 0.6 (60%)',
      passed: cm.precision >= 0.6,
      description: 'Detection precision should catch real threats reliably',
    },
    {
      metric: 'Recall',
      value: cm.recall,
      threshold: '≥ 1.0 (100%)',
      passed: cm.recall >= 1.0,
      description: 'Recall should catch all known malicious events',
    },
    {
      metric: 'F1 Score',
      value: cm.f1,
      threshold: '≥ 0.5',
      passed: cm.f1 >= 0.5,
      description: 'Balanced measure of precision and recall',
    },
    {
      metric: 'Accuracy',
      value: cm.accuracy,
      threshold: '≥ 0.7 (70%)',
      passed: cm.accuracy >= 0.7,
      description: 'Overall classification correctness',
    },
  ];
}
