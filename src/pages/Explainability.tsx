import { useState, useMemo } from 'react';
import { Brain, Zap, Cpu, Activity } from 'lucide-react';
import { Panel, MetricTile, ScoreRing } from '@/components/ui/Primitives';
import { ShapRadarChart, ShapBarChart, TrendLineChart } from '@/components/ui/Charts';
import { DATASETS } from '@/lib/datasets';
import { analyzeEvent } from '@/lib/aiAssistant';
import { getMitre } from '@/lib/mitre';
import type { AIDetection } from '@/lib/types';

export function Explainability() {
  const [datasetId, setDatasetId] = useState('sysmon-proc');
  const [selectedIdx, setSelectedIdx] = useState(0);

  const dataset = DATASETS.find((d) => d.id === datasetId)!;
  const detections = useMemo<AIDetection[]>(
    () => dataset.events.filter((e) => e.malicious).map((e) => analyzeEvent(e)),
    [dataset],
  );

  const selected = detections[selectedIdx];
  const mitre = selected ? getMitre(selected.mitre) : undefined;

  // Aggregate feature contributions across all detections
  const aggregate = useMemo(() => {
    const map: Record<string, { total: number; count: number; description: string }> = {};
    for (const d of detections) {
      for (const f of d.shap) {
        if (!map[f.feature]) map[f.feature] = { total: 0, count: 0, description: f.description };
        map[f.feature].total += f.contribution;
        map[f.feature].count += 1;
      }
    }
    return Object.entries(map)
      .map(([feature, v]) => ({ feature, contribution: Math.round(v.total / v.count), description: v.description }))
      .sort((a, b) => b.contribution - a.contribution);
  }, [detections]);

  // Confidence trend across detections
  const trend = detections.map((d, i) => ({ name: `D${i + 1}`, value: Math.round(d.confidence * 100) }));

  return (
    <div className="space-y-6 animate-fade-in">
      <Panel title="Explainable AI - SHAP Dashboard" icon={Brain}>
        <div className="flex items-center justify-between flex-wrap gap-3">
          <p className="text-sm text-soc-400 max-w-2xl">
            For every AI detection, see exactly why the model flagged it. SHAP feature contributions
            break down each decision into human-understandable signals.
          </p>
          <select value={datasetId} onChange={(e) => { setDatasetId(e.target.value); setSelectedIdx(0); }} className="soc-input">
            {DATASETS.map((d) => (
              <option key={d.id} value={d.id}>{d.name}</option>
            ))}
          </select>
        </div>
      </Panel>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <MetricTile label="Detections Explained" value={detections.length} icon={Brain} accent="cyber" />
        <MetricTile label="Avg Threat Score" value={Math.round(detections.reduce((s, d) => s + d.threatScore, 0) / detections.length)} icon={Activity} accent="threat" />
        <MetricTile label="Top Feature" value={aggregate[0]?.feature || '-'} icon={Zap} accent="alert" />
        <MetricTile label="Models Used" value={[...new Set(detections.map((d) => d.model))].length} icon={Cpu} accent="secure" />
      </div>

      <div className="grid grid-cols-12 gap-6">
        {/* Detection selector */}
        <div className="col-span-12 lg:col-span-3">
          <Panel title="Detections" icon={Activity}>
            <div className="space-y-2 max-h-96 overflow-y-auto">
              {detections.map((d, i) => (
                <button
                  key={d.id}
                  onClick={() => setSelectedIdx(i)}
                  className={`w-full text-left p-2.5 rounded-lg border transition-all ${
                    selectedIdx === i ? 'bg-cyber-500/15 border-cyber-500/50' : 'bg-soc-800/40 border-soc-700/40 hover:border-cyber-500/30'
                  }`}
                >
                  <div className="flex justify-between">
                    <span className="text-xs font-medium text-soc-100">{d.attackType}</span>
                    <span className="text-xs font-mono text-threat-400">{d.threatScore}</span>
                  </div>
                  <span className="text-[10px] text-soc-500 font-mono">{d.mitre}</span>
                </button>
              ))}
            </div>
          </Panel>
        </div>

        {/* Selected detection SHAP */}
        <div className="col-span-12 lg:col-span-5 space-y-6">
          {selected && (
            <>
              <Panel title={`Why was this detected? - ${selected.attackType}`} icon={Brain}>
                <div className="flex items-center justify-around mb-4">
                  <ScoreRing score={selected.threatScore} label="Threat" size={100} />
                  <ScoreRing score={selected.riskScore} label="Risk" size={100} />
                </div>
                <div className="p-3 rounded-lg bg-cyber-500/10 border border-cyber-500/30 mb-4">
                  <p className="text-xs text-cyber-300 font-semibold mb-1">Model Explanation</p>
                  <p className="text-sm text-soc-300">{selected.summary}</p>
                </div>
                <ShapBarChart data={selected.shap} />
              </Panel>
            </>
          )}
        </div>

        {/* Aggregate + radar */}
        <div className="col-span-12 lg:col-span-4 space-y-6">
          {selected && (
            <Panel title="Feature Contribution Radar" icon={Zap}>
              <ShapRadarChart data={selected.shap} />
            </Panel>
          )}
          <Panel title="Aggregate Feature Importance" icon={Activity}>
            {aggregate.length > 0 && <TrendLineChart data={aggregate.map((a) => ({ name: a.feature.slice(0, 12), value: a.contribution }))} dataKey="value" color="#faad14" name="Avg %" />}
          </Panel>
        </div>
      </div>
    </div>
  );
}
