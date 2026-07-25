import { useMemo, useState } from 'react';
import {
  Network, Search, Shield, Target, Layers, ChevronRight, X,
} from 'lucide-react';
import { Panel, ThreatBadge } from '@/components/ui/Primitives';
import { MitreHeatmapChart } from '@/components/ui/Charts';
import { MITRE_LIST, MITRE_TECHNIQUES, TACTICS, getMitre, severityColor } from '@/lib/mitre';
import { loadIncidents } from '@/lib/api';
import { useEffect } from 'react';
import type { Incident } from '@/lib/types';

export function MitreIntel() {
  const [query, setQuery] = useState('');
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selected, setSelected] = useState<string | null>(null);

  useEffect(() => {
    loadIncidents().then(setIncidents);
  }, []);

  const filtered = useMemo(
    () => MITRE_LIST.filter((m) =>
      !query ||
      m.id.toLowerCase().includes(query.toLowerCase()) ||
      m.name.toLowerCase().includes(query.toLowerCase()) ||
      m.tactic.toLowerCase().includes(query.toLowerCase()),
    ),
    [query],
  );

  const coverage = useMemo(() => {
    return TACTICS.map((tactic) => {
      const techniques = MITRE_LIST.filter((m) => m.tactic.includes(tactic));
      const covered = new Set(
        incidents.filter((i) => getMitre(i.mitre)?.tactic.includes(tactic)).map((i) => i.mitre),
      );
      return { tactic, coverage: techniques.length ? Math.min(100, (covered.size / techniques.length) * 100 + 20) : 0 };
    }).filter((t) => t.coverage > 0);
  }, [incidents]);

  const selectedTech = selected ? MITRE_TECHNIQUES[selected] : null;
  const relatedIncidents = selectedTech ? incidents.filter((i) => i.mitre === selectedTech.id) : [];

  return (
    <div className="space-y-6 animate-fade-in">
      <Panel title="MITRE ATT&CK Intelligence" icon={Network}>
        <div className="flex items-center justify-between flex-wrap gap-3">
          <p className="text-sm text-soc-400 max-w-xl">
            Every detection maps to a MITRE ATT&CK technique. Browse coverage across tactics,
            drill into techniques, and see related incidents.
          </p>
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-soc-500" />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search techniques..."
              className="soc-input pl-9 w-64"
            />
          </div>
        </div>
      </Panel>

      {/* Coverage visualization */}
      <Panel title="Tactic Coverage Heatmap" icon={Layers}>
        <MitreHeatmapChart data={coverage} />
      </Panel>

      <div className="grid grid-cols-12 gap-6">
        {/* Technique grid */}
        <div className="col-span-12 lg:col-span-8">
          <Panel title={`Techniques (${filtered.length})`} icon={Target}>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
              {filtered.map((m) => (
                <button
                  key={m.id}
                  onClick={() => setSelected(m.id)}
                  className={`flex items-center justify-between p-3 rounded-lg border transition-all text-left ${
                    selected === m.id
                      ? 'bg-cyber-500/15 border-cyber-500/50'
                      : 'bg-soc-800/40 border-soc-700/40 hover:border-cyber-500/30'
                  }`}
                >
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-mono text-cyber-300">{m.id}</span>
                      {m.subtechnique && <span className="text-[9px] text-soc-500">SUB</span>}
                    </div>
                    <p className="text-sm text-soc-100 truncate">{m.name}</p>
                    <p className="text-xs text-soc-500 truncate">{m.tactic}</p>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <span className={`text-[10px] px-1.5 py-0.5 rounded border ${severityColor(m.severity)}`}>
                      {m.severity}
                    </span>
                    <ChevronRight className="w-4 h-4 text-soc-600" />
                  </div>
                </button>
              ))}
            </div>
          </Panel>
        </div>

        {/* Detail panel */}
        <div className="col-span-12 lg:col-span-4">
          {selectedTech ? (
            <Panel title={selectedTech.id} icon={Shield} action={
              <button onClick={() => setSelected(null)} className="text-soc-500 hover:text-soc-200"><X className="w-4 h-4" /></button>
            }>
              <div className="space-y-3">
                <ThreatBadge level={selectedTech.severity} label={selectedTech.severity} />
                <div>
                  <p className="text-xs text-soc-500 uppercase">Technique Name</p>
                  <p className="text-sm font-semibold text-soc-50">{selectedTech.name}</p>
                </div>
                <div>
                  <p className="text-xs text-soc-500 uppercase">Tactic</p>
                  <p className="text-sm text-soc-200">{selectedTech.tactic}</p>
                </div>
                <div>
                  <p className="text-xs text-soc-500 uppercase">Description</p>
                  <p className="text-sm text-soc-400">{selectedTech.description}</p>
                </div>
                {selectedTech.subtechnique && (
                  <div className="p-2 rounded bg-soc-800/50 text-xs text-soc-400">
                    Subtechnique of <span className="text-cyber-300 font-mono">{selectedTech.parent}</span>
                  </div>
                )}
                <div>
                  <p className="text-xs text-soc-500 uppercase mb-1.5">Related Incidents ({relatedIncidents.length})</p>
                  {relatedIncidents.length === 0 ? (
                    <p className="text-xs text-soc-500">No incidents mapped to this technique.</p>
                  ) : (
                    <div className="space-y-1.5">
                      {relatedIncidents.slice(0, 4).map((inc) => (
                        <div key={inc.id} className="p-2 rounded bg-soc-800/40 border border-soc-700/40 text-xs">
                          <div className="flex justify-between">
                            <span className="font-mono text-soc-300">{inc.id}</span>
                            <span className="text-threat-400">{inc.threatScore}/99</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </Panel>
          ) : (
            <Panel title="Technique Detail" icon={Shield}>
              <p className="text-sm text-soc-500 py-8 text-center">Select a technique to view details.</p>
            </Panel>
          )}
        </div>
      </div>
    </div>
  );
}
