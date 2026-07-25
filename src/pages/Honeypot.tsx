import { useState } from 'react';
import {
  Shield, Bug, Skull, Eye, Lock, Zap, Activity, Server,
  Globe, AlertTriangle, CheckCircle2, Network,
} from 'lucide-react';
import { Panel, ThreatBadge, MetricTile, StatusPill } from '@/components/ui/Primitives';
import { AttackCategoriesChart } from '@/components/ui/Charts';
import {
  HONEYPOT_SENSORS, HONEYPOT_INTERACTIONS, getHoneypotStats,
  type HoneypotSensor, type HoneypotInteraction,
} from '@/lib/honeypot';
import { getMitre } from '@/lib/mitre';

export function Honeypot() {
  const [selectedSensor, setSelectedSensor] = useState<HoneypotSensor | null>(null);
  const [selectedInteraction, setSelectedInteraction] = useState<HoneypotInteraction | null>(null);
  const stats = getHoneypotStats();

  const interactionsBySensor = (sensorId: string) =>
    HONEYPOT_INTERACTIONS.filter((i) => i.sensorId === sensorId);

  const attackData = HONEYPOT_INTERACTIONS.reduce<Record<string, number>>((acc, i) => {
    const name = getMitre(i.mitre || '')?.name || i.action.split(' —')[0];
    acc[name] = (acc[name] || 0) + 1;
    return acc;
  }, {});
  const chartData = Object.entries(attackData).map(([name, value]) => ({ name, value }));

  return (
    <div className="space-y-6 animate-fade-in">
      <Panel title="Honeypot Deception Defense — Active Trap Network" icon={Bug}>
        <div className="flex items-start gap-4">
          <div className="p-3 rounded-lg bg-threat-500/10 border border-threat-500/30">
            <Skull className="w-6 h-6 text-threat-400" />
          </div>
          <div>
            <p className="text-sm text-soc-300">
              Deception sensors emulate vulnerable services to attract, detect, and deflect attackers
              from real production systems. Every interaction is logged for threat intelligence.
            </p>
            <p className="text-xs text-threat-400 mt-2">
              {stats.sensorsEngaged} sensors engaged — {stats.deflected} attacks deflected — {stats.intelGathered} unique attacker IPs profiled
            </p>
          </div>
        </div>
      </Panel>

      {/* Metrics */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <MetricTile label="Attacks Blocked" value={stats.blocked} icon={Shield} accent="secure" />
        <MetricTile label="Attacks Deflected" value={stats.deflected} icon={Bug} accent="threat" />
        <MetricTile label="Intel Gathered" value={`${stats.intelGathered} IPs`} icon={Eye} accent="cyber" />
        <MetricTile label="Sensors Engaged" value={stats.sensorsEngaged} icon={Server} accent="alert" />
      </div>

      <div className="grid grid-cols-12 gap-6">
        {/* Sensor map */}
        <div className="col-span-12 lg:col-span-7">
          <Panel title="Deception Sensor Network" icon={Network}>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {HONEYPOT_SENSORS.map((sensor) => (
                <button
                  key={sensor.id}
                  onClick={() => { setSelectedSensor(sensor); setSelectedInteraction(null); }}
                  className={`text-left p-4 rounded-lg border transition-all ${
                    selectedSensor?.id === sensor.id
                      ? 'bg-cyber-500/15 border-cyber-500/50 shadow-glow'
                      : 'bg-soc-800/40 border-soc-700/40 hover:border-cyber-500/30'
                  }`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <Server className="w-4 h-4 text-cyber-400" />
                      <span className="text-sm font-semibold text-soc-100">{sensor.name}</span>
                    </div>
                    <StatusPill status={sensor.status === 'armed' ? 'contained' : sensor.status} />
                  </div>
                  <p className="text-xs text-soc-400">{sensor.description}</p>
                  <div className="flex items-center gap-3 mt-2 text-xs text-soc-500 font-mono">
                    <span>{sensor.ip}:{sensor.port}</span>
                    <span className={sensor.decoyValue === 'high' ? 'text-threat-400' : sensor.decoyValue === 'medium' ? 'text-alert-400' : 'text-soc-400'}>
                      decoy: {sensor.decoyValue}
                    </span>
                  </div>
                  <div className="flex items-center gap-1 mt-2 text-xs">
                    <Zap className="w-3 h-3 text-threat-400" />
                    <span className="text-threat-400">{interactionsBySensor(sensor.id).length} interactions</span>
                  </div>
                </button>
              ))}
            </div>
          </Panel>
        </div>

        {/* Detail panel */}
        <div className="col-span-12 lg:col-span-5 space-y-4">
          {selectedSensor ? (
            <Panel title="Sensor Detail" icon={Server}>
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-lg font-bold text-soc-50">{selectedSensor.name}</span>
                  <StatusPill status={selectedSensor.status === 'armed' ? 'contained' : selectedSensor.status} />
                </div>
                <p className="text-sm text-soc-300">{selectedSensor.description}</p>
                <div className="grid grid-cols-2 gap-2">
                  <div className="p-2.5 rounded bg-soc-800/50">
                    <p className="text-xs text-soc-500">IP / Port</p>
                    <p className="text-sm font-mono text-cyber-300">{selectedSensor.ip}:{selectedSensor.port}</p>
                  </div>
                  <div className="p-2.5 rounded bg-soc-800/50">
                    <p className="text-xs text-soc-500">Decoy Value</p>
                    <p className="text-sm text-soc-200 capitalize">{selectedSensor.decoyValue}</p>
                  </div>
                </div>
                <div>
                  <p className="text-xs text-soc-500 uppercase mb-2">Interactions ({interactionsBySensor(selectedSensor.id).length})</p>
                  <div className="space-y-2 max-h-48 overflow-y-auto">
                    {interactionsBySensor(selectedSensor.id).map((i) => (
                      <button
                        key={i.id}
                        onClick={() => setSelectedInteraction(i)}
                        className={`w-full text-left p-2.5 rounded-lg border transition-all ${
                          selectedInteraction?.id === i.id ? 'bg-threat-500/10 border-threat-500/40' : 'bg-soc-800/40 border-soc-700/40'
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-mono text-soc-300">{i.attackerIp}</span>
                          {i.blocked ? <Lock className="w-3 h-3 text-secure-400" /> : <AlertTriangle className="w-3 h-3 text-alert-400" />}
                        </div>
                        <p className="text-xs text-soc-500 mt-1 truncate">{i.action}</p>
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            </Panel>
          ) : (
            <Panel title="Sensor Detail" icon={Server}>
              <div className="py-12 text-center">
                <Server className="w-10 h-10 text-soc-700 mx-auto mb-2" />
                <p className="text-sm text-soc-500">Select a sensor to view details.</p>
              </div>
            </Panel>
          )}

          {selectedInteraction && (
            <Panel title="Attacker Interaction" icon={Skull}>
              <div className="space-y-3">
                <ThreatBadge level={selectedInteraction.threatLevel} />
                <div className="grid grid-cols-2 gap-2">
                  <div className="p-2.5 rounded bg-soc-800/50">
                    <p className="text-xs text-soc-500">Attacker IP</p>
                    <p className="text-sm font-mono text-threat-300">{selectedInteraction.attackerIp}</p>
                  </div>
                  <div className="p-2.5 rounded bg-soc-800/50">
                    <p className="text-xs text-soc-500">Origin</p>
                    <p className="text-sm text-soc-200">{selectedInteraction.attackerCountry}</p>
                  </div>
                </div>
                <div>
                  <p className="text-xs text-soc-500 uppercase">Action</p>
                  <p className="text-sm text-soc-200">{selectedInteraction.action}</p>
                </div>
                {selectedInteraction.mitre && (
                  <div className="p-2.5 rounded bg-soc-800/50">
                    <p className="text-xs text-soc-500">MITRE</p>
                    <p className="text-sm font-mono text-cyber-300">{selectedInteraction.mitre}</p>
                  </div>
                )}
                {selectedInteraction.credentialsTried && (
                  <div>
                    <p className="text-xs text-soc-500 uppercase mb-1">Credentials Tried</p>
                    <div className="flex flex-wrap gap-1">
                      {selectedInteraction.credentialsTried.map((c) => (
                        <span key={c} className="text-xs font-mono px-2 py-0.5 rounded bg-threat-500/15 text-threat-300 border border-threat-500/30">
                          {c}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
                <div className={`flex items-center gap-2 p-2.5 rounded-lg ${
                  selectedInteraction.blocked ? 'bg-secure-500/10 border border-secure-500/30' : 'bg-alert-500/10 border border-alert-500/30'
                }`}>
                  {selectedInteraction.blocked ? <CheckCircle2 className="w-4 h-4 text-secure-400" /> : <AlertTriangle className="w-4 h-4 text-alert-400" />}
                  <span className={`text-sm ${selectedInteraction.blocked ? 'text-secure-300' : 'text-alert-300'}`}>
                    {selectedInteraction.blocked ? 'Attack blocked and logged for intel' : 'Interaction logged — canary triggered'}
                  </span>
                </div>
              </div>
            </Panel>
          )}
        </div>
      </div>

      {/* Attack distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Panel title="Honeypot Attack Distribution" icon={Activity}>
          <AttackCategoriesChart data={chartData} />
        </Panel>
        <Panel title="All Interactions Log" icon={Globe}>
          <div className="space-y-2 max-h-72 overflow-y-auto">
            {HONEYPOT_INTERACTIONS.map((i) => (
              <div key={i.id} className="flex items-center justify-between p-2.5 rounded-lg bg-soc-800/40 border border-soc-700/40">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-mono text-soc-400">{i.attackerIp}</span>
                  <span className="text-xs text-soc-500">→</span>
                  <span className="text-xs text-soc-300">{i.sensorName}</span>
                </div>
                <div className="flex items-center gap-2">
                  <ThreatBadge level={i.threatLevel} />
                  {i.blocked ? <Lock className="w-3 h-3 text-secure-400" /> : <AlertTriangle className="w-3 h-3 text-alert-400" />}
                </div>
              </div>
            ))}
          </div>
        </Panel>
      </div>
    </div>
  );
}
