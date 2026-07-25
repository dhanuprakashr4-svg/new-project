import { useState, useEffect, useCallback } from 'react';
import { useSearchParams, Link } from 'react-router-dom';
import {
  Bot, Sparkles, ArrowRight, Copy, Check, FileText, Network, Cpu,
} from 'lucide-react';
import { MonacoYamlEditor } from '@/components/ui/MonacoEditor';
import { Panel, ThreatBadge } from '@/components/ui/Primitives';
import { MITRE_LIST, getMitre } from '@/lib/mitre';
import { suggestSigmaRule } from '@/lib/aiAssistant';
import { validateRuleServer } from '@/lib/api';
import type { ValidationResult } from '@/lib/types';

const WORKFLOW = [
  { label: 'Threat Detected by ML Model', icon: Cpu },
  { label: 'Analyze Behaviour', icon: Network },
  { label: 'Map MITRE Technique', icon: Network },
  { label: 'Suggest Sigma Rule', icon: FileText },
];

export function AiAssistant() {
  const [params] = useSearchParams();
  const initialMitre = params.get('mitre') || 'T1059.001';
  const [mitreId, setMitreId] = useState(initialMitre);
  const [rule, setRule] = useState('');
  const [validation, setValidation] = useState<ValidationResult | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    setRule(suggestSigmaRule(mitreId));
    setValidation(null);
  }, [mitreId]);

  const handleGenerate = useCallback(() => {
    setRule(suggestSigmaRule(mitreId));
    setValidation(null);
  }, [mitreId]);

  const handleValidate = useCallback(async () => {
    const res = await validateRuleServer(rule);
    setValidation(res);
  }, [rule]);

  const handleCopy = useCallback(() => {
    navigator.clipboard.writeText(rule);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }, [rule]);

  const mitre = getMitre(mitreId);

  return (
    <div className="space-y-6 animate-fade-in">
      <Panel title="AI Sigma Assistant Workflow" icon={Bot}>
        <div className="flex items-center gap-2 flex-wrap">
          {WORKFLOW.map((step, i) => (
            <div key={i} className="flex items-center gap-2">
              <div className={`flex items-center gap-2 px-3 py-2 rounded-lg border ${
                i === WORKFLOW.length - 1 ? 'bg-cyber-500/15 border-cyber-500/50' : 'bg-soc-800/50 border-soc-700/50'
              }`}>
                <step.icon className={`w-4 h-4 ${i === WORKFLOW.length - 1 ? 'text-cyber-400' : 'text-soc-400'}`} />
                <span className="text-xs text-soc-200">{step.label}</span>
              </div>
              {i < WORKFLOW.length - 1 && <ArrowRight className="w-4 h-4 text-soc-600" />}
            </div>
          ))}
        </div>
      </Panel>

      <div className="grid grid-cols-12 gap-6">
        {/* MITRE selector */}
        <div className="col-span-12 lg:col-span-4 space-y-4">
          <Panel title="Select Detected Technique" icon={Network}>
            <div className="space-y-2 max-h-96 overflow-y-auto">
              {MITRE_LIST.filter((m) => ['T1059.001', 'T1003', 'T1003.001', 'T1053', 'T1053.005', 'T1550', 'T1550.002', 'T1190'].includes(m.id)).map((m) => (
                <button
                  key={m.id}
                  onClick={() => setMitreId(m.id)}
                  className={`w-full text-left p-3 rounded-lg border transition-all ${
                    mitreId === m.id
                      ? 'bg-cyber-500/15 border-cyber-500/50 shadow-glow'
                      : 'bg-soc-800/40 border-soc-700/40 hover:border-cyber-500/30'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-medium text-soc-100">{m.name}</span>
                    <span className="text-xs font-mono text-cyber-300">{m.id}</span>
                  </div>
                  <p className="text-xs text-soc-500 mt-1">{m.tactic}</p>
                </button>
              ))}
            </div>
          </Panel>

          {mitre && (
            <Panel title="Technique Intelligence" icon={Sparkles}>
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-lg font-bold text-soc-50">{mitre.id}</span>
                  <ThreatBadge level={mitre.severity} />
                </div>
                <div>
                  <p className="text-xs text-soc-500 uppercase">Name</p>
                  <p className="text-sm text-soc-200">{mitre.name}</p>
                </div>
                <div>
                  <p className="text-xs text-soc-500 uppercase">Tactic</p>
                  <p className="text-sm text-soc-200">{mitre.tactic}</p>
                </div>
                <div>
                  <p className="text-xs text-soc-500 uppercase">Description</p>
                  <p className="text-sm text-soc-400">{mitre.description}</p>
                </div>
              </div>
            </Panel>
          )}
        </div>

        {/* Generated rule */}
        <div className="col-span-12 lg:col-span-8 space-y-4">
          <Panel
            title="AI-Generated Sigma Rule"
            icon={FileText}
            action={
              <div className="flex items-center gap-2">
                <button onClick={handleCopy} className="text-xs text-soc-400 hover:text-cyber-300 flex items-center gap-1">
                  {copied ? <Check className="w-3.5 h-3.5 text-secure-400" /> : <Copy className="w-3.5 h-3.5" />}
                  {copied ? 'Copied' : 'Copy'}
                </button>
                <button onClick={handleValidate} className="soc-btn-ghost text-xs">
                  <Sparkles className="w-3.5 h-3.5" /> Validate
                </button>
                <Link to="/lab" className="soc-btn-primary text-xs">
                  Open in Lab <ArrowRight className="w-3.5 h-3.5" />
                </Link>
              </div>
            }
          >
            <div style={{ height: 420 }}>
              <MonacoYamlEditor value={rule} onChange={setRule} height="100%" />
            </div>
          </Panel>

          {validation && (
            <Panel title="Validation Result" icon={validation.valid ? Check : Sparkles}>
              {validation.valid ? (
                <div className="flex items-center gap-2 text-secure-400">
                  <Check className="w-5 h-5" /> Rule is valid and ready for testing.
                </div>
              ) : (
                <div className="space-y-2">
                  {validation.errors.map((e, i) => (
                    <div key={i} className="text-sm text-threat-300">
                      <span className="font-mono">{e.field}:</span> {e.message}
                    </div>
                  ))}
                </div>
              )}
            </Panel>
          )}
        </div>
      </div>
    </div>
  );
}
