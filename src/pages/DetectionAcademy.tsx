import { useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  GraduationCap, Play, CheckCircle2, Trophy, Target, Lightbulb,
  ChevronRight, Award, RotateCcw, Eye, EyeOff,
} from 'lucide-react';
import { MonacoYamlEditor } from '@/components/ui/MonacoEditor';
import { Panel, ThreatBadge, ScoreRing } from '@/components/ui/Primitives';
import { CHALLENGES, scoreChallenge } from '@/lib/challenges';
import { runRuleServer, saveChallengeScore, localValidate } from '@/lib/api';
import { getMitre } from '@/lib/mitre';
import type { Challenge, RunRuleResult } from '@/lib/types';

export function DetectionAcademy() {
  const [selected, setSelected] = useState<Challenge | null>(null);
  const [yaml, setYaml] = useState('');
  const [result, setResult] = useState<RunRuleResult | null>(null);
  const [running, setRunning] = useState(false);
  const [showSolution, setShowSolution] = useState(false);
  const [showHint, setShowHint] = useState(false);
  const navigate = useNavigate();

  const selectChallenge = useCallback((c: Challenge) => {
    setSelected(c);
    setYaml(c.starterRule);
    setResult(null);
    setShowSolution(false);
    setShowHint(false);
  }, []);

  const runChallenge = useCallback(async () => {
    if (!selected) return;
    setRunning(true);
    const v = localValidate(yaml);
    if (!v.valid) {
      setRunning(false);
      return;
    }
    try {
      const res = await runRuleServer(yaml, selected.datasetId);
      setResult(res);
      const score = scoreChallenge(res.precision, res.recall, res.falsePositiveRate);
      await saveChallengeScore({
        challengeId: selected.id,
        precision: res.precision,
        recall: res.recall,
        fpr: res.falsePositiveRate,
        score,
        completedAt: new Date().toISOString(),
      });
    } catch (err) {
      console.error(err);
    }
    setRunning(false);
  }, [selected, yaml]);

  const score = result ? scoreChallenge(result.precision, result.recall, result.falsePositiveRate) : 0;
  const passed = result
    ? result.precision >= selected!.targetPrecision &&
      result.recall >= selected!.targetRecall &&
      result.falsePositiveRate <= selected!.targetFpr
    : false;

  if (selected) {
    const m = getMitre(selected.mitre);
    return (
      <div className="space-y-4 animate-fade-in">
        <div className="flex items-center justify-between">
          <button onClick={() => setSelected(null)} className="soc-btn-ghost">
            <ChevronRight className="w-4 h-4 rotate-180" /> Back to Challenges
          </button>
          <div className="flex items-center gap-3">
            <ThreatBadge level={m?.severity || 'high'} label={selected.mitre} />
            <span className="text-xs text-soc-400 uppercase tracking-wider">{selected.difficulty}</span>
          </div>
        </div>

        {/* Mission briefing */}
        <Panel title="Mission Briefing" icon={GraduationCap}>
          <div className="flex items-start gap-4">
            <div className="w-12 h-12 rounded-lg bg-cyber-500/15 border border-cyber-500/30 flex items-center justify-center shrink-0">
              <Target className="w-6 h-6 text-cyber-400" />
            </div>
            <div>
              <h3 className="text-lg font-bold text-soc-50">{selected.name}</h3>
              <p className="text-sm text-soc-300 mt-1">{m?.name} - {selected.tactic}</p>
              <p className="text-sm text-soc-400 mt-2">{selected.briefing}</p>
              <div className="flex items-center gap-4 mt-3 text-xs">
                <span className="text-soc-500">Targets:</span>
                <span className="text-secure-400">Precision ≥ {(selected.targetPrecision * 100).toFixed(0)}%</span>
                <span className="text-cyber-400">Recall ≥ {(selected.targetRecall * 100).toFixed(0)}%</span>
                <span className="text-threat-400">FPR ≤ {(selected.targetFpr * 100).toFixed(0)}%</span>
              </div>
            </div>
          </div>
        </Panel>

        <div className="grid grid-cols-12 gap-4">
          {/* Editor */}
          <div className="col-span-12 lg:col-span-7 glass-panel flex flex-col" style={{ height: 460 }}>
            <div className="flex items-center justify-between px-4 py-2.5 border-b border-soc-700/60">
              <span className="text-sm font-semibold text-soc-100 uppercase tracking-wide">Your Sigma Rule</span>
              <div className="flex items-center gap-2">
                <button onClick={() => setShowHint(!showHint)} className="text-xs text-alert-400 hover:text-alert-300 flex items-center gap-1">
                  <Lightbulb className="w-3.5 h-3.5" /> Hint
                </button>
                <button onClick={() => setShowSolution(!showSolution)} className="text-xs text-soc-400 hover:text-soc-200 flex items-center gap-1">
                  {showSolution ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                  {showSolution ? 'Hide' : 'Show'} Solution
                </button>
              </div>
            </div>
            <div className="flex-1 min-h-0">
              {showSolution ? (
                <div className="p-4 overflow-auto h-full">
                  <pre className="text-xs font-mono text-secure-300 whitespace-pre-wrap">{selected.solutionRule}</pre>
                  <button
                    onClick={() => { setYaml(selected.solutionRule); setShowSolution(false); }}
                    className="soc-btn-ghost mt-3 text-xs"
                  >
                    <RotateCcw className="w-3 h-3" /> Load Solution
                  </button>
                </div>
              ) : (
                <MonacoYamlEditor value={yaml} onChange={setYaml} height="100%" />
              )}
            </div>
          </div>

          {/* Results */}
          <div className="col-span-12 lg:col-span-5 space-y-4">
            {showHint && (
              <Panel title="Hint" icon={Lightbulb}>
                <p className="text-sm text-alert-300">{selected.hint}</p>
              </Panel>
            )}

            <div className="flex items-center gap-2">
              <button onClick={runChallenge} disabled={running} className="soc-btn-primary flex-1">
                <Play className="w-4 h-4" />
                {running ? 'Executing...' : 'Run Challenge'}
              </button>
            </div>

            {result && (
              <>
                <Panel title="Your Score" icon={Trophy}>
                  <div className="flex items-center gap-6">
                    <ScoreRing score={score} label="Score / 100" />
                    <div className="flex-1 space-y-2">
                      <div className="flex justify-between text-sm">
                        <span className="text-soc-400">Precision</span>
                        <span className="font-mono text-cyber-300">{(result.precision * 100).toFixed(0)}%</span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span className="text-soc-400">Recall</span>
                        <span className="font-mono text-secure-300">{(result.recall * 100).toFixed(0)}%</span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span className="text-soc-400">FPR</span>
                        <span className="font-mono text-threat-300">{(result.falsePositiveRate * 100).toFixed(0)}%</span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span className="text-soc-400">Matches</span>
                        <span className="font-mono text-soc-200">{result.matches}</span>
                      </div>
                    </div>
                  </div>
                  <div className={`mt-4 p-3 rounded-lg text-center ${passed ? 'bg-secure-500/15 border border-secure-500/40' : 'bg-alert-500/15 border border-alert-500/40'}`}>
                    {passed ? (
                      <p className="text-secure-300 font-semibold flex items-center justify-center gap-2">
                        <Award className="w-5 h-5" /> Challenge Passed! All targets met.
                      </p>
                    ) : (
                      <p className="text-alert-300 text-sm">Keep refining your rule to hit the targets.</p>
                    )}
                  </div>
                </Panel>

                <Panel title="Matched Events" icon={Target}>
                  <div className="space-y-1.5 max-h-40 overflow-y-auto">
                    {result.matched_events.map((e) => (
                      <div key={e.id} className={`p-2 rounded text-xs border ${e.malicious ? 'bg-secure-500/10 border-secure-500/30' : 'bg-threat-500/10 border-threat-500/30'}`}>
                        <div className="flex justify-between">
                          <span className="font-mono text-soc-300">{e.id}</span>
                          <span className={e.malicious ? 'text-secure-400' : 'text-threat-400'}>
                            {e.malicious ? 'True Positive' : 'False Positive'}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                </Panel>
              </>
            )}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6 animate-fade-in">
      <Panel title="ThreatZero Detection Academy" icon={GraduationCap}>
        <p className="text-sm text-soc-400">
          Gamified SOC training. Complete 5 MITRE ATT&CK-mapped challenges by writing Sigma rules that catch
          attacks while minimizing false positives. Each challenge is scored on precision, recall, and
          false positive rate.
        </p>
      </Panel>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {CHALLENGES.map((c, i) => {
          const m = getMitre(c.mitre);
          return (
            <button
              key={c.id}
              onClick={() => selectChallenge(c)}
              className="glass-panel p-5 glass-hover text-left group"
            >
              <div className="flex items-start justify-between mb-3">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-lg bg-cyber-500/15 border border-cyber-500/30 flex items-center justify-center font-bold text-cyber-300">
                    {i + 1}
                  </div>
                  <div>
                    <h3 className="font-semibold text-soc-100 group-hover:text-cyber-300 transition-colors">{c.name}</h3>
                    <p className="text-xs text-soc-500">{c.tactic}</p>
                  </div>
                </div>
                <ThreatBadge level={m?.severity || 'high'} label={c.mitre} />
              </div>
              <p className="text-sm text-soc-400 line-clamp-2">{c.briefing}</p>
              <div className="flex items-center justify-between mt-4">
                <span className="text-xs text-soc-500 uppercase tracking-wider">{c.difficulty}</span>
                <ChevronRight className="w-4 h-4 text-soc-600 group-hover:text-cyber-400 group-hover:translate-x-1 transition-all" />
              </div>
            </button>
          );
        })}
      </div>
    </div>
  );
}
