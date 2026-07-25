import { useState, useMemo, useCallback } from 'react';
import {
  Radar, Zap, Cpu, Brain, Sparkles, Play, FileWarning, ChevronRight,
} from 'lucide-react';
import { Panel, ThreatBadge, MetricTile, ScoreRing } from '@/components/ui/Primitives';
import { ShapRadarChart, ShapBarChart } from '@/components/ui/Charts';
import { DATASETS } from '@/lib/datasets';
import { analyzeEvent, suggestSigmaRule, copilotSummarizeAttack } from '@/lib/aiAssistant';
import { getMitre } from '@/lib/mitre';
import { saveIncident } from '@/lib/api';
import type { SecEvent, AIDetection } from '@/lib/types';

export function ThreatDetection() {
  const [datasetId, setDatasetId] = useState('sysmon-proc');
  const [scanning, setScanning] = useState(false);
  const [detections, setDetections] = useState<AIDetection[]>([]);
  const [selected, setSelected] = useState<AIDetection | null>(null);

  const dataset = DATASETS.find((d) => d.id === datasetId)!;
  const maliciousEvents = useMemo(() => dataset.events.filter((e) => e.malicious), [dataset]);

  const scan = useCallback(async () => {
    setScanning(true);
    setDetections([]);
    setSelected(null);
    const results: AIDetection[] = [];
    for (const e of dataset.events) {
      const det = analyzeEvent(e);
      if (det.threatScore > 30) {
        results.push(det);
        setDetections([...results]);
        await new Promise((r) => setTimeout(r, 120));
      }
    }
    setScanning(false);
  }, [dataset]);

  const createIncident = useCallback(async (det: AIDetection) => {
    const m = getMitre(det.mitre);
    const incident = {
      id: `INC-${Date.now().toString(36).toUpperCase()}`,
      timestamp: det.timestamp,
      attackType: det.attackType,
      mitre: det.mitre,
      severity: m?.severity || 'high',
      threatScore: det.threatScore,
      riskScore: det.riskScore,
      status: 'open' as const,
      detectionRule: `AI Detection - ${det.model}`,
      matchedLogs: 1,
      aiSummary: copilotSummarizeAttack(det),
      recommendedActions: [],
    };
    await saveIncident(incident);
    alert(`Incident ${incident.id} created and saved.`);
  }, []);

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Controls */}
      <Panel title="ML Threat Detection Engine" icon={Radar}>
        <div className="flex items-center justify-between gap-4 flex-wrap">
          <div className="flex items-center gap-3">
            <Cpu className="w-5 h-5 text-cyber-400" />
            <div>
              <p className="text-sm font-medium text-soc-100">XGBoost / Random Forest Ensemble</p>
              <p className="text-xs text-soc-500">Analyzes security events, scores threats, maps MITRE, generates SHAP explanations</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <select
              value={datasetId}
              onChange={(e) => setDatasetId(e.target.value)}
              className="soc-input"
            >
              {DATASETS.map((d) => (
                <option key={d.id} value={d.id}>{d.name}</option>
              ))}
            </select>
            <button onClick={scan} disabled={scanning} className="soc-btn-primary">
              <Zap className="w-4 h-4" />
              {scanning ? 'Scanning...' : 'Run ML Scan'}
            </button>
          </div>
        </div>
        {scanning && (
          <div className="mt-4 h-1 bg-soc-800 rounded-full overflow-hidden scan-overlay">
            <div className="h-full bg-cyber-500 animate-data-flow" style={{ width: '40%' }} />
          </div>
        )}
      </Panel>

      {/* Stats */}
      {detections.length > 0 && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <MetricTile label="Threats Detected" value={detections.length} icon={Radar} accent="threat" />
          <MetricTile label="Critical" value={detections.filter((d) => d.threatScore > 70).length} icon={FileWarning} accent="threat" />
          <MetricTile label="High Risk" value={detections.filter((d) => d.riskScore > 60).length} icon={Brain} accent="alert" />
          <MetricTile label="Avg Confidence" value={`${Math.round(detections.reduce((s, d) => s + d.confidence, 0) / detections.length * 100)}%`} icon={Cpu} accent="cyber" />
        </div>
      )}

      <div className="grid grid-cols-12 gap-6">
        {/* Detection list */}
        <div className="col-span-12 lg:col-span-4">
          <Panel title="AI Detections" icon={Radar}>
            {detections.length === 0 ? (
              <p className="text-sm text-soc-500 py-8 text-center">
                {maliciousEvents.length} suspicious events in dataset. Run a scan to analyze.
              </p>
            ) : (
              <div className="space-y-2 max-h-[500px] overflow-y-auto">
                {detections.map((d) => {
                  const m = getMitre(d.mitre);
                  return (
                    <button
                      key={d.id}
                      onClick={() => setSelected(d)}
                      className={`w-full text-left p-3 rounded-lg border transition-all ${
                        selected?.id === d.id
                          ? 'bg-cyber-500/15 border-cyber-500/50'
                          : 'bg-soc-800/40 border-soc-700/40 hover:border-cyber-500/30'
                      }`}
                    >
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-sm font-medium text-soc-100">{d.attackType}</span>
                        <span className="text-xs font-mono text-threat-400">{d.threatScore}/99</span>
                      </div>
                      <div className="flex items-center gap-2 text-xs text-soc-500">
                        <span>{d.mitre}</span>
                        <span>-</span>
                        <span>{m?.tactic.split(',')[0]}</span>
                      </div>
                      <div className="flex items-center gap-2 mt-1.5">
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-soc-700/60 text-soc-300 font-mono">{d.model}</span>
                        <ThreatBadge level={m?.severity || 'high'} />
                      </div>
                    </button>
                  );
                })}
              </div>
            )}
          </Panel>
        </div>

        {/* Detail */}
        <div className="col-span-12 lg:col-span-8 space-y-6">
          {selected ? (
            <>
              <Panel title="Threat Analysis" icon={Brain}>
                <div className="grid grid-cols-12 gap-6">
                  <div className="col-span-12 md:col-span-5 flex flex-col items-center justify-center">
                    <ScoreRing score={selected.threatScore} label="Threat Score" size={130} />
                    <ScoreRing score={selected.riskScore} label="Risk Score" size={110} />
                  </div>
                  <div className="col-span-12 md:col-span-7 space-y-3">
                    <div>
                      <p className="text-xs text-soc-500 uppercase tracking-wider">Attack Type</p>
                      <p className="text-lg font-bold text-soc-50">{selected.attackType}</p>
                    </div>
                    <div className="grid grid-cols-2 gap-3">
                      <div className="p-2.5 rounded bg-soc-800/50">
                        <p className="text-xs text-soc-500">MITRE Technique</p>
                        <p className="text-sm font-mono text-cyber-300">{selected.mitre}</p>
                      </div>
                      <div className="p-2.5 rounded bg-soc-800/50">
                        <p className="text-xs text-soc-500">Detection Model</p>
                        <p className="text-sm font-mono text-soc-200">{selected.model}</p>
                      </div>
                      <div className="p-2.5 rounded bg-soc-800/50">
                        <p className="text-xs text-soc-500">Confidence</p>
                        <p className="text-sm font-mono text-secure-300">{(selected.confidence * 100).toFixed(0)}%</p>
                      </div>
                      <div className="p-2.5 rounded bg-soc-800/50">
                        <p className="text-xs text-soc-500">Timestamp</p>
                        <p className="text-sm font-mono text-soc-300">{selected.timestamp.slice(0, 19)}</p>
                      </div>
                    </div>
                    <div className="p-3 rounded-lg bg-cyber-500/10 border border-cyber-500/30">
                      <p className="text-xs text-cyber-300 font-semibold mb-1">AI Summary</p>
                      <p className="text-sm text-soc-300">{selected.summary}</p>
                    </div>
                    <div className="flex gap-2">
                      <button onClick={() => createIncident(selected)} className="soc-btn-primary text-xs">
                        <FileWarning className="w-3.5 h-3.5" /> Create Incident
                      </button>
                      <a
                        href={`/ai-assistant?mitre=${selected.mitre}`}
                        className="soc-btn-ghost text-xs"
                      >
                        <Sparkles className="w-3.5 h-3.5 text-cyber-400" /> Suggest Sigma Rule
                        <ChevronRight className="w-3.5 h-3.5" />
                      </a>
                    </div>
                  </div>
                </div>
              </Panel>

              <Panel title="SHAP Explainability - Why was this detected?" icon={Brain}>
                <div className="grid grid-cols-12 gap-6">
                  <div className="col-span-12 md:col-span-5">
                    <ShapRadarChart data={selected.shap} />
                  </div>
                  <div className="col-span-12 md:col-span-7">
                    <ShapBarChart data={selected.shap} />
                  </div>
                </div>
              </Panel>
            </>
          ) : (
            <Panel title="Detection Detail" icon={Brain}>
              <div className="py-16 text-center">
                <Radar className="w-12 h-12 text-soc-700 mx-auto mb-3" />
                <p className="text-sm text-soc-500">Run a scan and select a detection to view the full AI analysis.</p>
              </div>
            </Panel>
          )}
        </div>
      </div>
    </div>
  );
}
