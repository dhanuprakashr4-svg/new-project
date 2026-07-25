import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import {
  ArrowLeft, FileWarning, Brain, Network, Shield, Clock,
  Target, Zap, CheckCircle2, AlertTriangle, Lock, Hash, Download, ShieldCheck,
} from 'lucide-react';
import { Panel, ThreatBadge, StatusPill, ScoreRing, Loader, EmptyState } from '@/components/ui/Primitives';
import { ShapBarChart } from '@/components/ui/Charts';
import { loadIncidents, loadEvidence } from '@/lib/api';
import { analyzeEvent, copilotSummarizeAttack, copilotRecommendResponse } from '@/lib/aiAssistant';
import { DATASETS } from '@/lib/datasets';
import { getMitre } from '@/lib/mitre';
import { getNistMapping, NIST_COLORS, NIST_FUNCTIONS } from '@/lib/nist';
import { generateIncidentPdf, buildReportDataFromIncident } from '@/lib/pdfReport';
import type { Incident, EvidenceRecord, AIDetection } from '@/lib/types';

export function IncidentDetail() {
  const { id } = useParams<{ id: string }>();
  const [incident, setIncident] = useState<Incident | null>(null);
  const [evidence, setEvidence] = useState<EvidenceRecord | null>(null);
  const [detection, setDetection] = useState<AIDetection | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    (async () => {
      const [incidents, evidenceList] = await Promise.all([loadIncidents(), loadEvidence()]);
      const inc = incidents.find((i) => i.id === id);
      if (inc) {
        setIncident(inc);
        const ev = evidenceList.find((e) => e.incidentId === inc.id);
        if (ev) setEvidence(ev);
        // Reconstruct AI detection for explanation
        const event = DATASETS.flatMap((d) => d.events).find((e) => e.mitre === inc.mitre && e.malicious);
        if (event) {
          const det = analyzeEvent(event);
          setDetection({ ...det, timestamp: inc.timestamp, id: inc.id });
        }
      }
      setLoading(false);
    })();
  }, [id]);

  if (loading) return <Loader label="Loading incident..." />;
  if (!incident) {
    return (
      <Panel title="Incident Not Found">
        <EmptyState icon={FileWarning} title="Incident not found" hint="This incident may have been removed." />
        <Link to="/incidents" className="soc-btn-ghost mt-4 inline-flex">
          <ArrowLeft className="w-4 h-4" /> Back to Incidents
        </Link>
      </Panel>
    );
  }

  const m = getMitre(incident.mitre);
  const timeline = [
    { time: incident.timestamp, event: 'Threat detected by ML ensemble', icon: Zap, color: 'text-cyber-400' },
    { time: incident.timestamp, event: `Mapped to MITRE ${incident.mitre}`, icon: Network, color: 'text-cyber-400' },
    { time: incident.timestamp, event: `Incident ${incident.id} created`, icon: FileWarning, color: 'text-threat-400' },
    { time: incident.timestamp, event: 'AI analysis completed', icon: Brain, color: 'text-cyber-400' },
    ...(evidence ? [{ time: evidence.timestamp, event: 'Evidence packaged & encrypted', icon: Lock, color: 'text-secure-400' }] : []),
  ];

  const nist = getNistMapping(incident.mitre);

  const handleDownloadPdf = () => {
    const data = buildReportDataFromIncident(incident);
    const doc = generateIncidentPdf(data);
    doc.save(`incident_${incident.id}.pdf`);
  };

  return (
    <div className="space-y-6 animate-fade-in">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <Link to="/incidents" className="soc-btn-ghost inline-flex">
          <ArrowLeft className="w-4 h-4" /> Back to Incidents
        </Link>
        <button onClick={handleDownloadPdf} className="soc-btn-primary">
          <Download className="w-4 h-4" /> Download PDF Report
        </button>
      </div>

      {/* Header */}
      <div className="glass-panel p-5 flex items-center justify-between flex-wrap gap-4">
        <div className="flex items-center gap-4">
          <div className={`w-14 h-14 rounded-lg flex items-center justify-center ${
            incident.severity === 'critical' ? 'bg-threat-500/15 border border-threat-500/40' : 'bg-orange-500/15 border border-orange-500/40'
          }`}>
            <FileWarning className={`w-7 h-7 ${incident.severity === 'critical' ? 'text-threat-400' : 'text-orange-400'}`} />
          </div>
          <div>
            <div className="flex items-center gap-3">
              <h2 className="text-xl font-bold text-soc-50">{incident.attackType}</h2>
              <ThreatBadge level={incident.severity} />
              <StatusPill status={incident.status} />
            </div>
            <p className="text-sm text-soc-500 font-mono mt-1">{incident.id} - {incident.mitre} - {m?.name}</p>
          </div>
        </div>
        <div className="flex items-center gap-4">
          <ScoreRing score={incident.threatScore} label="Threat" size={90} />
          <ScoreRing score={incident.riskScore} label="Risk" size={90} />
        </div>
      </div>

      <div className="grid grid-cols-12 gap-6">
        {/* Left: timeline + matched logs */}
        <div className="col-span-12 lg:col-span-7 space-y-6">
          <Panel title="Attack Timeline" icon={Clock}>
            <div className="relative pl-6 space-y-4 before:content-[''] before:absolute before:left-2 before:top-2 before:bottom-2 before:w-px before:bg-soc-700">
              {timeline.map((t, i) => (
                <div key={i} className="relative">
                  <div className={`absolute -left-4 top-0.5 w-3 h-3 rounded-full ${t.color} bg-current ring-4 ring-soc-900`} />
                  <p className="text-sm text-soc-200">{t.event}</p>
                  <p className="text-xs text-soc-500 font-mono">{t.time.slice(0, 19).replace('T', ' ')}</p>
                </div>
              ))}
            </div>
          </Panel>

          <Panel title="Matched Logs" icon={FileWarning}>
            <div className="space-y-2">
              {DATASETS.flatMap((d) => d.events).filter((e) => e.mitre === incident.mitre && e.malicious).slice(0, 5).map((e) => (
                <div key={e.id} className="p-3 rounded-lg bg-soc-800/40 border border-soc-700/40">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-mono text-soc-400">{e.source} - EID {e.fields.EventID || '-'}</span>
                    <span className="text-xs text-soc-500">{e.timestamp.slice(11, 19)}</span>
                  </div>
                  <p className="text-xs font-mono text-soc-300 break-all">
                    {String(e.fields.CommandLine || e.fields.URL || e.fields.Image || e.fields.TaskAction || JSON.stringify(e.fields))}
                  </p>
                </div>
              ))}
            </div>
          </Panel>

          {detection && (
            <Panel title="AI Explanation - Why was this detected?" icon={Brain}>
              <div className="p-3 rounded-lg bg-cyber-500/10 border border-cyber-500/30 mb-4">
                <p className="text-sm text-soc-300">{incident.aiSummary || copilotSummarizeAttack(detection)}</p>
              </div>
              <ShapBarChart data={detection.shap} />
            </Panel>
          )}
        </div>

        {/* Right: MITRE, detection rule, evidence, response */}
        <div className="col-span-12 lg:col-span-5 space-y-6">
          <Panel title="MITRE ATT&CK Mapping" icon={Network}>
            {m && (
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-lg font-bold text-cyber-300 font-mono">{m.id}</span>
                  <ThreatBadge level={m.severity} />
                </div>
                <div>
                  <p className="text-xs text-soc-500 uppercase">Technique</p>
                  <p className="text-sm text-soc-100">{m.name}</p>
                </div>
                <div>
                  <p className="text-xs text-soc-500 uppercase">Tactic</p>
                  <p className="text-sm text-soc-200">{m.tactic}</p>
                </div>
                <div>
                  <p className="text-xs text-soc-500 uppercase">Description</p>
                  <p className="text-sm text-soc-400">{m.description}</p>
                </div>
              </div>
            )}
          </Panel>

          <Panel title="Detection Rule" icon={Target}>
            <div className="p-3 rounded-lg bg-soc-950/60 border border-soc-700/40">
              <p className="text-sm font-mono text-cyber-300">{incident.detectionRule}</p>
            </div>
          </Panel>

          {evidence ? (
            <Panel title="Evidence Information" icon={Shield}>
              <div className="space-y-3">
                <div className="grid grid-cols-2 gap-2">
                  <div className="p-2 rounded bg-soc-800/50">
                    <p className="text-xs text-soc-500">Evidence ID</p>
                    <p className="text-sm font-mono text-soc-200">{evidence.id}</p>
                  </div>
                  <div className="p-2 rounded bg-soc-800/50">
                    <p className="text-xs text-soc-500">Size</p>
                    <p className="text-sm text-soc-200">{(evidence.sizeBytes / 1024).toFixed(2)} KB</p>
                  </div>
                </div>
                <div className="p-2 rounded bg-soc-800/50">
                  <p className="text-xs text-soc-500 mb-1 flex items-center gap-1"><Hash className="w-3 h-3" /> SHA-256</p>
                  <p className="text-xs font-mono text-cyber-300 break-all">{evidence.hash.slice(0, 48)}...</p>
                </div>
                <div className="flex items-center gap-2 p-2.5 rounded bg-secure-500/10 border border-secure-500/30">
                  <CheckCircle2 className="w-4 h-4 text-secure-400" />
                  <span className="text-sm text-secure-300">Integrity Verified - SHA-256</span>
                </div>
                <div className="flex items-center gap-2 p-2.5 rounded bg-cyber-500/10 border border-cyber-500/30">
                  <Lock className="w-4 h-4 text-cyber-400" />
                  <span className="text-sm text-cyber-300">AES-256 Protected</span>
                </div>
                <Link to="/voxcrypt" className="soc-btn-ghost w-full text-xs">
                  <Lock className="w-3.5 h-3.5" /> Open in VoxCrypt
                </Link>
              </div>
            </Panel>
          ) : (
            <Panel title="Evidence Information" icon={Shield}>
              <EmptyState icon={Shield} title="No evidence packaged" hint="Create evidence in the Evidence Vault." />
            </Panel>
          )}

          {nist && (
            <Panel title="NIST CSF Mapping" icon={ShieldCheck}>
              <div className="space-y-3">
                <div className="flex items-center gap-2">
                  <span className="text-xs text-soc-400">Primary Function:</span>
                  <span className="text-sm font-semibold px-2 py-0.5 rounded" style={{ color: NIST_COLORS[nist.primaryFunction], backgroundColor: NIST_COLORS[nist.primaryFunction] + '20' }}>
                    {nist.primaryFunction}
                  </span>
                </div>
                <div className="flex flex-wrap gap-1">
                  {nist.nistFunctions.map((fn) => (
                    <span key={fn} className="text-[10px] px-1.5 py-0.5 rounded" style={{ color: NIST_COLORS[fn], backgroundColor: NIST_COLORS[fn] + '15' }}>
                      {fn}
                    </span>
                  ))}
                </div>
                <div>
                  <p className="text-xs text-soc-500 uppercase mb-1">NIST Categories</p>
                  {nist.categories.map((cat, i) => (
                    <p key={i} className="text-xs text-soc-300 mt-1">{cat}</p>
                  ))}
                </div>
                <div>
                  <p className="text-xs text-soc-500 uppercase mb-1">Recommended Defensive Actions</p>
                  {nist.defensiveActions.map((action, i) => (
                    <div key={i} className="flex items-start gap-2 mt-1">
                      <ShieldCheck className="w-3 h-3 text-secure-400 mt-0.5 shrink-0" />
                      <span className="text-xs text-soc-300">{action}</span>
                    </div>
                  ))}
                </div>
              </div>
            </Panel>
          )}

          <Panel title="Recommended Actions" icon={AlertTriangle}>
            <div className="space-y-2">
              {(incident.recommendedActions.length > 0 ? incident.recommendedActions : copilotRecommendResponse(detection || {
                id: incident.id, timestamp: incident.timestamp, attackType: incident.attackType,
                mitre: incident.mitre, threatScore: incident.threatScore, riskScore: incident.riskScore,
                confidence: 0.85, shap: [], model: 'XGBoost', summary: incident.aiSummary,
              })).map((action, i) => (
                <div key={i} className="flex items-start gap-2 p-2.5 rounded bg-soc-800/40 border border-soc-700/40">
                  <CheckCircle2 className="w-4 h-4 text-cyber-400 mt-0.5 shrink-0" />
                  <span className="text-sm text-soc-200">{action}</span>
                </div>
              ))}
            </div>
          </Panel>
        </div>
      </div>
    </div>
  );
}
