import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { FileWarning, Search, Filter, ChevronRight } from 'lucide-react';
import { Panel, ThreatBadge, StatusPill, EmptyState, Loader } from '@/components/ui/Primitives';
import { loadIncidents } from '@/lib/api';
import { getMitre } from '@/lib/mitre';
import type { Incident } from '@/lib/types';

const STATUS_FILTERS = ['all', 'open', 'investigating', 'contained', 'resolved'] as const;

export function Incidents() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('all');

  useEffect(() => {
    loadIncidents().then((data) => {
      setIncidents(data);
      setLoading(false);
    });
  }, []);

  const filtered = incidents.filter((i) => {
    if (statusFilter !== 'all' && i.status !== statusFilter) return false;
    if (query) {
      const q = query.toLowerCase();
      return i.attackType.toLowerCase().includes(q) || i.id.toLowerCase().includes(q) || i.mitre.toLowerCase().includes(q);
    }
    return true;
  });

  return (
    <div className="space-y-6 animate-fade-in">
      <Panel title="Incident Investigation" icon={FileWarning}>
        <div className="flex items-center justify-between flex-wrap gap-3">
          <p className="text-sm text-soc-400">All detected security incidents with MITRE mapping, threat scores, and investigation status.</p>
          <div className="flex items-center gap-2">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-soc-500" />
              <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search incidents..." className="soc-input pl-9 w-48" />
            </div>
            <div className="flex items-center gap-1">
              <Filter className="w-4 h-4 text-soc-500" />
              {STATUS_FILTERS.map((s) => (
                <button
                  key={s}
                  onClick={() => setStatusFilter(s)}
                  className={`text-xs px-2.5 py-1 rounded ${statusFilter === s ? 'bg-cyber-500/20 text-cyber-300' : 'text-soc-400 hover:text-soc-200'}`}
                >
                  {s}
                </button>
              ))}
            </div>
          </div>
        </div>
      </Panel>

      {loading ? (
        <Loader label="Loading incidents..." />
      ) : filtered.length === 0 ? (
        <Panel title="Incidents">
          <EmptyState icon={FileWarning} title="No incidents found" hint="Detect threats in the AI Threat Detection engine to generate incidents." />
        </Panel>
      ) : (
        <div className="space-y-2">
          {filtered.map((inc) => {
            const m = getMitre(inc.mitre);
            return (
              <Link
                key={inc.id}
                to={`/incidents/${inc.id}`}
                className="glass-panel p-4 glass-hover flex items-center justify-between group"
              >
                <div className="flex items-center gap-4 min-w-0">
                  <div className={`w-12 h-12 rounded-lg flex items-center justify-center shrink-0 ${
                    inc.severity === 'critical' ? 'bg-threat-500/15 border border-threat-500/30' :
                    inc.severity === 'high' ? 'bg-orange-500/15 border border-orange-500/30' :
                    'bg-alert-500/15 border border-alert-500/30'
                  }`}>
                    <FileWarning className={`w-6 h-6 ${
                      inc.severity === 'critical' ? 'text-threat-400' : inc.severity === 'high' ? 'text-orange-400' : 'text-alert-400'
                    }`} />
                  </div>
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <h3 className="font-semibold text-soc-100 truncate">{inc.attackType}</h3>
                      <ThreatBadge level={inc.severity} />
                    </div>
                    <p className="text-xs text-soc-500 font-mono">{inc.id} - {inc.mitre} - {m?.name}</p>
                  </div>
                </div>
                <div className="flex items-center gap-4 shrink-0">
                  <div className="text-right hidden md:block">
                    <p className="text-xs text-soc-500">Threat</p>
                    <p className="text-sm font-mono text-threat-400">{inc.threatScore}/99</p>
                  </div>
                  <StatusPill status={inc.status} />
                  <ChevronRight className="w-5 h-5 text-soc-600 group-hover:text-cyber-400 group-hover:translate-x-1 transition-all" />
                </div>
              </Link>
            );
          })}
        </div>
      )}
    </div>
  );
}
