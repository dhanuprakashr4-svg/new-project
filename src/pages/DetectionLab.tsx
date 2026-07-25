import { useState, useCallback } from 'react';
import {
  Play, CheckCircle2, AlertTriangle, AlertOctagon, Save,
  Database, Target, Shield, Zap, FileText, Sparkles, FlaskRound, TrendingUp,
} from 'lucide-react';
import { MonacoYamlEditor } from '@/components/ui/MonacoEditor';
import { Panel, MetricTile, ThreatBadge } from '@/components/ui/Primitives';
import { DATASETS } from '@/lib/datasets';
import { validateRuleServer, runRuleServer, saveSigmaRule, logRuleRun, localValidate } from '@/lib/api';
import { suggestSigmaRule } from '@/lib/aiAssistant';
import { FPR_THRESHOLD } from '@/lib/detectionMetrics';
import type { ValidationResult, RunRuleResult, LogDataset } from '@/lib/types';

const STARTER_RULE = `title: Suspicious Encoded PowerShell Execution
id: 4f7728-9a3b-4c2e-8f1d-t1059_001
status: experimental
description: Detects PowerShell executing with an encoded command payload
author: SOC Analyst
level: high
logsource:
  category: process_creation
  product: windows
detection:
  selection_powershell:
    Image|endswith:
      - '\\\\powershell.exe'
      - '\\\\pwsh.exe'
  selection_encoded:
    CommandLine|contains:
      - '-EncodedCommand'
      - '-enc '
  filter_benign:
    CommandLine|contains:
      - 'Get-Process'
  condition: selection_powershell and selection_encoded and not filter_benign
falsepositives:
  - Legitimate administrative scripts using encoding
tags:
  - attack.execution
  - attack.t1059.001`;

export function DetectionLab() {
  const [yaml, setYaml] = useState(STARTER_RULE);
  const [validation, setValidation] = useState<ValidationResult | null>(null);
  const [result, setResult] = useState<RunRuleResult | null>(null);
  const [selectedDataset, setSelectedDataset] = useState<LogDataset>(DATASETS[4]); // sysmon-proc
  const [validating, setValidating] = useState(false);
  const [running, setRunning] = useState(false);
  const [saved, setSaved] = useState(false);
  const [safeMode, setSafeMode] = useState(true);
  const [optimizing, setOptimizing] = useState(false);
  const [optimization, setOptimization] = useState<{ suggestions: string[]; fprCompliant: boolean } | null>(null);

  const handleValidate = useCallback(async () => {
    setValidating(true);
    const res = await validateRuleServer(yaml);
    setValidation(res);
    setValidating(false);
  }, [yaml]);

  const handleRun = useCallback(async () => {
    setRunning(true);
    // Validate first so we don't run invalid rules
    const v = validation || await validateRuleServer(yaml);
    setValidation(v);
    if (!v.valid) {
      setRunning(false);
      return;
    }
    try {
      const res = await runRuleServer(yaml, selectedDataset.id);
      setResult(res);
      await logRuleRun({
        ruleTitle: res.ruleTitle,
        datasetId: selectedDataset.id,
        matches: res.matches,
        precision: res.precision,
        recall: res.recall,
        fpr: res.falsePositiveRate,
        accuracy: res.accuracy,
        valid: true,
      });
    } catch (err) {
      console.error(err);
    }
    setRunning(false);
  }, [yaml, selectedDataset, validation]);

  const handleSave = useCallback(async () => {
    const parsed = localValidate(yaml);
    if (!parsed.parsedRule) return;
    await saveSigmaRule({
      title: parsed.parsedRule.title,
      yaml,
      level: parsed.parsedRule.level,
      mitre: parsed.parsedRule.tags?.find((t) => t.includes('t1'))?.replace('attack.', '').toUpperCase(),
    });
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  }, [yaml]);

  const handleSuggest = useCallback(() => {
    setYaml(suggestSigmaRule('T1059.001'));
    setValidation(null);
    setResult(null);
    setOptimization(null);
  }, []);

  const handleOptimize = useCallback(async () => {
    if (!result) return;
    setOptimizing(true);
    const suggestions: string[] = [];
    const fprCompliant = result.falsePositiveRate < FPR_THRESHOLD;

    if (result.falsePositives > 0) {
      suggestions.push(`Add a filter selection to exclude ${result.falsePositives} false positive(s) — current FPR is ${(result.falsePositiveRate * 100).toFixed(1)}%`);
    }
    if (result.falseNegatives > 0) {
      suggestions.push(`Widen detection criteria to catch ${result.falseNegatives} missed malicious event(s) — recall is only ${(result.recall * 100).toFixed(0)}%`);
    }
    if (result.precision < 0.6) {
      suggestions.push('Increase precision by adding more specific field matchers or tightening the condition logic');
    }
    if (result.recall < 1.0) {
      suggestions.push('Add additional selection patterns to cover all known malicious variants and improve recall to 100%');
    }
    if (!fprCompliant) {
      suggestions.push(`CRITICAL: FPR (${(result.falsePositiveRate * 100).toFixed(1)}%) exceeds the ${FPR_THRESHOLD * 100}% threshold — add exclusions immediately`);
    }
    if (suggestions.length === 0) {
      suggestions.push('Rule is well-optimized — all metrics meet the hackathon compliance thresholds');
    }
    suggestions.push('Pre-deployment check: rule validated against synthetic dataset in safe testing environment — no production impact');

    setOptimization({ suggestions, fprCompliant });
    setOptimizing(false);
  }, [result]);

  const editorMarkers: { line: number; message: string; severity: 'error' | 'warning' }[] = [
    ...(validation?.errors || []).filter((e) => e.line).map((e) => ({ line: e.line!, message: e.message, severity: 'error' as const })),
    ...(validation?.warnings || []).filter((w) => w.line).map((w) => ({ line: w.line!, message: w.message, severity: 'warning' as const })),
  ];

  return (
    <div className="h-[calc(100vh-120px)] flex flex-col gap-4 animate-fade-in">
      {/* Toolbar */}
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-2">
          <button onClick={handleValidate} disabled={validating} className="soc-btn-ghost">
            <CheckCircle2 className="w-4 h-4" />
            {validating ? 'Validating...' : 'Validate Rule'}
          </button>
          <button onClick={handleRun} disabled={running} className="soc-btn-primary">
            <Play className="w-4 h-4" />
            {running ? 'Running...' : 'Run Detection'}
          </button>
          <button onClick={handleOptimize} disabled={optimizing || !result} className="soc-btn-ghost">
            <TrendingUp className="w-4 h-4 text-cyber-400" />
            {optimizing ? 'Optimizing...' : 'Optimize & Operationalize'}
          </button>
          <button onClick={handleSave} className="soc-btn-ghost">
            <Save className="w-4 h-4" />
            {saved ? 'Saved!' : 'Save Rule'}
          </button>
          <button onClick={handleSuggest} className="soc-btn-ghost">
            <Sparkles className="w-4 h-4 text-cyber-400" />
            AI Suggest
          </button>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setSafeMode(!safeMode)}
            className={`flex items-center gap-2 px-3 py-2 rounded-lg text-xs border transition-all ${
              safeMode ? 'bg-secure-500/15 border-secure-500/40 text-secure-300' : 'bg-soc-800/40 border-soc-700/40 text-soc-400'
            }`}
          >
            <FlaskRound className="w-3.5 h-3.5" />
            {safeMode ? 'Safe Test Mode (No Production Impact)' : 'Safe Test Mode: OFF'}
          </button>
        </div>
      </div>

      {/* Three-pane workspace */}
      <div className="flex-1 grid grid-cols-12 gap-4 min-h-0">
        {/* Left: Monaco Editor */}
        <div className="col-span-12 lg:col-span-6 glass-panel flex flex-col min-h-0">
          <div className="flex items-center justify-between px-4 py-2.5 border-b border-soc-700/60">
            <div className="flex items-center gap-2">
              <FileText className="w-4 h-4 text-cyber-400" />
              <span className="text-sm font-semibold text-soc-100 uppercase tracking-wide">Sigma Rule Editor</span>
            </div>
            <span className="text-xs text-soc-500 font-mono">YAML</span>
          </div>
          <div className="flex-1 min-h-0">
            <MonacoYamlEditor value={yaml} onChange={setYaml} markers={editorMarkers} />
          </div>
        </div>

        {/* Center: Dataset Selection */}
        <div className="col-span-12 lg:col-span-3 flex flex-col gap-4 min-h-0 overflow-y-auto">
          <Panel title="Security Log Datasets" icon={Database} className="flex-none">
            <div className="space-y-2 max-h-64 overflow-y-auto pr-1">
              {DATASETS.map((ds) => (
                <button
                  key={ds.id}
                  onClick={() => setSelectedDataset(ds)}
                  className={`w-full text-left p-3 rounded-lg border transition-all ${
                    selectedDataset.id === ds.id
                      ? 'bg-cyber-500/15 border-cyber-500/50 shadow-glow'
                      : 'bg-soc-800/40 border-soc-700/40 hover:border-cyber-500/30'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-medium text-soc-100">{ds.name}</span>
                    {selectedDataset.id === ds.id && <Zap className="w-3.5 h-3.5 text-cyber-400" />}
                  </div>
                  <div className="flex items-center gap-3 mt-1.5 text-xs text-soc-500">
                    <span>{ds.eventCount} events</span>
                    <span className="text-threat-400">{ds.maliciousCount} mal</span>
                    <span className="text-secure-400">{ds.benignCount} benign</span>
                  </div>
                </button>
              ))}
            </div>
          </Panel>

          <Panel title="Dataset Preview" icon={FileText}>
            <div className="space-y-1.5 max-h-48 overflow-y-auto">
              {selectedDataset.events.slice(0, 6).map((e) => (
                <div
                  key={e.id}
                  className={`p-2 rounded text-xs font-mono border ${
                    e.malicious ? 'bg-threat-500/10 border-threat-500/30' : 'bg-soc-800/40 border-soc-700/40'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-soc-300">{e.fields.EventID ? `EID ${e.fields.EventID}` : e.source}</span>
                    {e.malicious && <ThreatBadge level="high" label="MAL" />}
                  </div>
                  <p className="text-soc-500 truncate mt-1">{String(e.fields.CommandLine || e.fields.URL || e.fields.Image || e.fields.TaskAction || '')}</p>
                </div>
              ))}
            </div>
          </Panel>
        </div>

        {/* Right: Validation + Results */}
        <div className="col-span-12 lg:col-span-3 flex flex-col gap-4 min-h-0 overflow-y-auto">
          {/* Validation */}
          <Panel
            title="Rule Validation"
            icon={validation?.valid ? CheckCircle2 : AlertTriangle}
            action={
              validation && (
                <span className={`text-xs font-semibold ${validation.valid ? 'text-secure-400' : 'text-threat-400'}`}>
                  {validation.valid ? 'VALID' : 'INVALID'}
                </span>
              )
            }
          >
            {!validation ? (
              <p className="text-sm text-soc-500">Click "Validate Rule" to check YAML structure, detection fields, and condition logic.</p>
            ) : (
              <div className="space-y-2">
                {validation.errors.length === 0 && validation.warnings.length === 0 && (
                  <div className="flex items-center gap-2 text-secure-400 text-sm">
                    <CheckCircle2 className="w-4 h-4" /> No issues found.
                  </div>
                )}
                {validation.errors.map((e, i) => (
                  <div key={`e${i}`} className="flex items-start gap-2 p-2 rounded bg-threat-500/10 border border-threat-500/30">
                    <AlertOctagon className="w-3.5 h-3.5 text-threat-400 mt-0.5 shrink-0" />
                    <div>
                      <p className="text-xs text-threat-300 font-medium">{e.field}</p>
                      <p className="text-xs text-soc-400">{e.message}</p>
                    </div>
                  </div>
                ))}
                {validation.warnings.map((w, i) => (
                  <div key={`w${i}`} className="flex items-start gap-2 p-2 rounded bg-alert-500/10 border border-alert-500/30">
                    <AlertTriangle className="w-3.5 h-3.5 text-alert-400 mt-0.5 shrink-0" />
                    <div>
                      <p className="text-xs text-alert-300 font-medium">{w.field}</p>
                      <p className="text-xs text-soc-400">{w.message}</p>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </Panel>

          {/* Detection results */}
          {result && (
            <>
              <Panel title="Detection Metrics" icon={Target}>
                <div className="space-y-3">
                  <div className="grid grid-cols-2 gap-2">
                    <div className="p-2 rounded bg-cyber-500/10 border border-cyber-500/30">
                      <p className="text-xs text-soc-400">Matches</p>
                      <p className="text-xl font-bold text-cyber-300 font-mono">{result.matches}</p>
                    </div>
                    <div className="p-2 rounded bg-secure-500/10 border border-secure-500/30">
                      <p className="text-xs text-soc-400">True Positives</p>
                      <p className="text-xl font-bold text-secure-300 font-mono">{result.truePositives}</p>
                    </div>
                    <div className="p-2 rounded bg-threat-500/10 border border-threat-500/30">
                      <p className="text-xs text-soc-400">False Positives</p>
                      <p className="text-xl font-bold text-threat-300 font-mono">{result.falsePositives}</p>
                    </div>
                    <div className="p-2 rounded bg-alert-500/10 border border-alert-500/30">
                      <p className="text-xs text-soc-400">False Negatives</p>
                      <p className="text-xl font-bold text-alert-300 font-mono">{result.falseNegatives}</p>
                    </div>
                  </div>
                </div>
              </Panel>

              <Panel title="Accuracy Metrics" icon={Shield}>
                <div className="space-y-2.5">
                  <MetricRow label="Precision" value={result.precision} color="cyber" />
                  <MetricRow label="Recall" value={result.recall} color="secure" />
                  <MetricRow label="False Positive Rate" value={result.falsePositiveRate} color="threat" />
                  <MetricRow label="F1 Score" value={result.f1} color="alert" />
                  <MetricRow label="Accuracy" value={result.accuracy} color="cyber" />
                </div>
              </Panel>

              <Panel title="Matched Events" icon={FileText}>
                <div className="space-y-1.5 max-h-48 overflow-y-auto">
                  {result.matched_events.length === 0 ? (
                    <p className="text-xs text-soc-500">No events matched.</p>
                  ) : (
                    result.matched_events.map((e) => (
                      <div key={e.id} className={`p-2 rounded text-xs border ${e.malicious ? 'bg-threat-500/10 border-threat-500/30' : 'bg-alert-500/10 border-alert-500/30'}`}>
                        <div className="flex items-center justify-between">
                          <span className="font-mono text-soc-300">{e.id}</span>
                          <span className={e.malicious ? 'text-threat-400' : 'text-alert-400'}>
                            {e.malicious ? 'TP' : 'FP'}
                          </span>
                        </div>
                        <p className="text-soc-500 truncate mt-0.5">
                          {String(e.fields.CommandLine || e.fields.URL || e.fields.Image || '')}
                        </p>
                      </div>
                    ))
                  )}
                </div>
              </Panel>

              {optimization && (
                <Panel
                  title="Optimization & Operationalization"
                  icon={TrendingUp}
                  action={
                    <span className={`text-xs font-semibold ${optimization.fprCompliant ? 'text-secure-400' : 'text-threat-400'}`}>
                      FPR {optimization.fprCompliant ? 'OK' : 'HIGH'}
                    </span>
                  }
                >
                  {safeMode && (
                    <div className="flex items-center gap-2 p-2 rounded bg-secure-500/10 border border-secure-500/30 mb-2">
                      <FlaskRound className="w-3.5 h-3.5 text-secure-400" />
                      <span className="text-xs text-secure-300">Tested in safe environment — no production systems affected</span>
                    </div>
                  )}
                  <div className="space-y-1.5">
                    {optimization.suggestions.map((s, i) => (
                      <div key={i} className={`flex items-start gap-2 p-2 rounded text-xs ${
                        s.startsWith('CRITICAL') ? 'bg-threat-500/10 border border-threat-500/30' : 'bg-soc-800/40 border border-soc-700/40'
                      }`}>
                        <Zap className={`w-3 h-3 mt-0.5 shrink-0 ${s.startsWith('CRITICAL') ? 'text-threat-400' : 'text-cyber-400'}`} />
                        <span className={s.startsWith('CRITICAL') ? 'text-threat-300' : 'text-soc-300'}>{s}</span>
                      </div>
                    ))}
                  </div>
                </Panel>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function MetricRow({ label, value, color }: { label: string; value: number; color: 'cyber' | 'secure' | 'threat' | 'alert' }) {
  const colors: Record<string, string> = {
    cyber: 'bg-cyber-500',
    secure: 'bg-secure-500',
    threat: 'bg-threat-500',
    alert: 'bg-alert-500',
  };
  const textColors: Record<string, string> = {
    cyber: 'text-cyber-300',
    secure: 'text-secure-300',
    threat: 'text-threat-300',
    alert: 'text-alert-300',
  };
  return (
    <div>
      <div className="flex items-center justify-between text-xs mb-1">
        <span className="text-soc-300">{label}</span>
        <span className={`font-mono font-semibold ${textColors[color]}`}>{(value * 100).toFixed(1)}%</span>
      </div>
      <div className="h-1.5 bg-soc-800 rounded-full overflow-hidden">
        <div className={`h-full ${colors[color]} rounded-full transition-all duration-700`} style={{ width: `${value * 100}%` }} />
      </div>
    </div>
  );
}
