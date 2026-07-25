import { useEffect, useState, useMemo } from 'react';
import { Link } from 'react-router-dom';
import {
  Activity, Shield, AlertTriangle, Target, Brain, FileWarning,
  TrendingUp, FlaskConical, GraduationCap, Lock, Gauge,
} from 'lucide-react';
import { Panel, MetricTile, ThreatBadge, Loader } from '@/components/ui/Primitives';
import {
  DetectionPerformanceChart, AttackCategoriesChart, MitreHeatmapChart, ChallengeScoresChart,
} from '@/components/ui/Charts';
import { loadIncidents, loadChallengeScores, loadRuleRuns } from '@/lib/api';
import { MITRE_LIST, TACTICS, getMitre } from '@/lib/mitre';
import { CHALLENGES } from '@/lib/challenges';
import type { Incident, ChallengeScore } from '@/lib/types';

export function Dashboard() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [scores, setScores] = useState<ChallengeScore[]>([]);
  const [runs, setRuns] = useState<{ ruleTitle: string; precision: number; recall: number; fpr: number; valid: boolean }[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    (async () => {
      const [inc, sc, rn] = await Promise.all([
        loadIncidents(),
        loadChallengeScores(),
        loadRuleRuns(),
      ]);
      setIncidents(inc);
      setScores(sc);
      setRuns(rn);
      setLoading(false);
    })();
  }, []);

  const metrics = useMemo(() => {
    const totalRules = runs.length;
    const avgPrecision = totalRules ? runs.reduce((s, r) => s + r.precision, 0) / totalRules : 0;
    const avgFpr = totalRules ? runs.reduce((s, r) => s + r.fpr, 0) / totalRules : 0;
    const activeIncidents = incidents.filter((i) => i.status === 'open' || i.status === 'investigating').length;
    const criticalIncidents = incidents.filter((i) => i.severity === 'critical').length;
    const threatLevel = criticalIncidents > 0 ? 'CRITICAL' : activeIncidents > 2 ? 'ELEVATED' : 'GUARDED';

    const mitreCoverage = TACTICS.map((tactic) => {
      const techniques = MITRE_LIST.filter((m) => m.tactic.includes(tactic));
      const covered = new Set(
        incidents.filter((i) => getMitre(i.mitre)?.tactic.includes(tactic)).map((i) => i.mitre),
      );
      return { tactic, coverage: techniques.length ? (covered.size / techniques.length) * 100 : 0 };
    });

    const attackCats: Record<string, number> = {};
    for (const inc of incidents) {
      const name = getMitre(inc.mitre)?.name || inc.attackType;
      attackCats[name] = (attackCats[name] || 0) + 1;
    }
    const attackData = Object.entries(attackCats).map(([name, value]) => ({ name, value }));

    const perfData = runs.slice(0, 8).reverse().map((r, i) => ({
      name: `R${i + 1}`,
      precision: r.precision,
      recall: r.recall,
      fpr: r.fpr,
    }));

    const challengeData = CHALLENGES.map((c) => {
      const sc = scores.find((s) => s.challengeId === c.id);
      return { name: c.name.split(' ')[0], score: sc?.score || 0 };
    });

    return {
      totalRules, avgPrecision, avgFpr, activeIncidents, criticalIncidents, threatLevel,
      mitreCoverage: mitreCoverage.filter((m) => m.coverage > 0 || true).slice(0, 8),
      attackData, perfData, challengeData,
    };
  }, [incidents, scores, runs]);

  if (loading) return <Loader label="Initializing SOC telemetry..." />;

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Threat level banner */}
      <div className={`glass-panel p-4 flex items-center justify-between border-l-4 ${
        metrics.threatLevel === 'CRITICAL' ? 'border-l-threat-500' :
        metrics.threatLevel === 'ELEVATED' ? 'border-l-alert-500' : 'border-l-cyber-500'
      }`}>
        <div className="flex items-center gap-4">
          <Gauge className={`w-8 h-8 ${
            metrics.threatLevel === 'CRITICAL' ? 'text-threat-400' :
            metrics.threatLevel === 'ELEVATED' ? 'text-alert-400' : 'text-cyber-400'
          }`} />
          <div>
            <p className="text-xs text-soc-400 uppercase tracking-widest">Current Threat Level</p>
            <p className="text-2xl font-bold text-soc-50">{metrics.threatLevel}</p>
          </div>
        </div>
        <div className="flex items-center gap-6">
          <div className="text-right">
            <p className="text-xs text-soc-400">Active Incidents</p>
            <p className="text-xl font-bold text-threat-400 font-mono">{metrics.activeIncidents}</p>
          </div>
          <div className="text-right">
            <p className="text-xs text-soc-400">Critical</p>
            <p className="text-xl font-bold text-threat-400 font-mono">{metrics.criticalIncidents}</p>
          </div>
        </div>
      </div>

      {/* Metric tiles */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        <MetricTile label="Rules Tested" value={metrics.totalRules} icon={FlaskConical} accent="cyber" />
        <MetricTile
          label="Detection Accuracy"
          value={`${(metrics.avgPrecision * 100).toFixed(0)}%`}
          icon={Target}
          accent="secure"
          trend={`${(metrics.avgPrecision * 100).toFixed(0)}% avg precision`}
          trendUp
        />
        <MetricTile
          label="False Positive Rate"
          value={`${(metrics.avgFpr * 100).toFixed(1)}%`}
          icon={AlertTriangle}
          accent="threat"
          trend={`${(metrics.avgFpr * 100).toFixed(1)}% avg`}
          trendUp={false}
        />
        <MetricTile label="MITRE Coverage" value={`${MITRE_LIST.length}`} icon={Activity} accent="cyber" />
        <MetricTile label="Active Incidents" value={metrics.activeIncidents} icon={FileWarning} accent="threat" />
        <MetricTile label="Threat Level" value={metrics.threatLevel} icon={Shield} accent="alert" />
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Panel title="Detection Performance" icon={TrendingUp}>
          {metrics.perfData.length > 0 ? (
            <DetectionPerformanceChart data={metrics.perfData} />
          ) : (
            <p className="text-sm text-soc-500 py-12 text-center">Run Sigma rules in the Detection Lab to populate metrics.</p>
          )}
        </Panel>
        <Panel title="Attack Categories" icon={AlertTriangle}>
          {metrics.attackData.length > 0 ? (
            <AttackCategoriesChart data={metrics.attackData} />
          ) : (
            <p className="text-sm text-soc-500 py-12 text-center">No incidents detected yet.</p>
          )}
        </Panel>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Panel title="MITRE ATT&CK Coverage" icon={Brain}>
          <MitreHeatmapChart data={metrics.mitreCoverage} />
        </Panel>
        <Panel title="Detection Academy Scores" icon={GraduationCap}>
          <ChallengeScoresChart data={metrics.challengeData} />
        </Panel>
      </div>

      {/* Quick links */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Link to="/lab" className="glass-panel p-5 glass-hover group">
          <FlaskConical className="w-7 h-7 text-cyber-400 mb-3 group-hover:scale-110 transition-transform" />
          <h4 className="font-semibold text-soc-100">Sigma Detection Lab</h4>
          <p className="text-sm text-soc-400 mt-1">Write, validate, and test Sigma rules against realistic datasets.</p>
        </Link>
        <Link to="/academy" className="glass-panel p-5 glass-hover group">
          <GraduationCap className="w-7 h-7 text-cyber-400 mb-3 group-hover:scale-110 transition-transform" />
          <h4 className="font-semibold text-soc-100">Detection Academy</h4>
          <p className="text-sm text-soc-400 mt-1">5 MITRE-mapped challenges. Score on precision, recall, and FPR.</p>
        </Link>
        <Link to="/voxcrypt" className="glass-panel p-5 glass-hover group">
          <Lock className="w-7 h-7 text-cyber-400 mb-3 group-hover:scale-110 transition-transform" />
          <h4 className="font-semibold text-soc-100">VoxCrypt Secure Comms</h4>
          <p className="text-sm text-soc-400 mt-1">AES-256 encrypted evidence packaging and authorized transfer.</p>
        </Link>
      </div>

      {/* Recent incidents */}
      {incidents.length > 0 && (
        <Panel title="Recent Incidents" icon={FileWarning}>
          <div className="space-y-2">
            {incidents.slice(0, 5).map((inc) => {
              const m = getMitre(inc.mitre);
              return (
                <Link
                  key={inc.id}
                  to={`/incidents/${inc.id}`}
                  className="flex items-center justify-between p-3 rounded-lg bg-soc-800/40 hover:bg-soc-800/70 border border-soc-700/40 hover:border-cyber-500/40 transition-all"
                >
                  <div className="flex items-center gap-3">
                    <ThreatBadge level={inc.severity} />
                    <div>
                      <p className="text-sm font-medium text-soc-100">{inc.attackType}</p>
                      <p className="text-xs text-soc-500">{inc.id} - {m?.id || inc.mitre}</p>
                    </div>
                  </div>
                  <span className="text-xs text-soc-400 font-mono">{inc.threatScore}/99</span>
                </Link>
              );
            })}
          </div>
        </Panel>
      )}
    </div>
  );
}
