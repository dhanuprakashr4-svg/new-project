import { useState, useMemo } from 'react';
import ReactFlow, {
  Background,
  Controls,
  MiniMap,
  type Node,
  type Edge,
  Position,
  Handle,
} from 'reactflow';
import 'reactflow/dist/style.css';
import {
  Network, Crosshair, Shield, Zap, Activity, Eye, AlertTriangle,
  ChevronRight, Lock, Target, Skull, Radar,
} from 'lucide-react';
import { Panel, ThreatBadge, MetricTile } from '@/components/ui/Primitives';
import { ATTACK_CHAINS, getChainMitreCoverage, type AttackChain, type AttackStage } from '@/lib/attackChains';
import { getMitre, severityColor } from '@/lib/mitre';

const KILL_CHAIN_COLORS: Record<string, string> = {
  '1. Reconnaissance': '#64748b',
  '2. Initial Access': '#faad14',
  '3. Execution': '#1890ff',
  '4. Credential Access': '#fa8c16',
  '5. Lateral Movement': '#f5222d',
  '5. Discovery': '#1890ff',
  '6. Persistence': '#722ed1',
  '6. Collection': '#1890ff',
  '7. Impact': '#f5222d',
  '6. Exfiltration': '#f5222d',
};

function StageNode({ data }: { data: AttackStage }) {
  const color = KILL_CHAIN_COLORS[data.killChainPhase] || '#1890ff';
  const m = getMitre(data.mitre);
  return (
    <div
      className="rounded-lg border-2 px-4 py-3 min-w-[220px] backdrop-blur-xl"
      style={{
        backgroundColor: 'rgba(15, 23, 42, 0.92)',
        borderColor: color + '80',
        boxShadow: `0 0 16px ${color}40`,
      }}
    >
      <Handle type="target" position={Position.Left} style={{ background: color }} />
      <div className="flex items-center gap-2 mb-1">
        <span className="text-[10px] font-mono uppercase tracking-wider" style={{ color }}>
          {data.killChainPhase}
        </span>
        {data.detected ? (
          <Shield className="w-3 h-3 text-secure-400" />
        ) : (
          <AlertTriangle className="w-3 h-3 text-threat-400" />
        )}
      </div>
      <p className="text-sm font-semibold text-soc-50">{data.techniqueName}</p>
      <div className="flex items-center gap-2 mt-1">
        <span className="text-xs font-mono" style={{ color }}>{data.mitre}</span>
        <span className="text-[10px] text-soc-500">{data.tactic}</span>
      </div>
      {m && (
        <span className={`inline-block mt-1.5 text-[9px] px-1.5 py-0.5 rounded border ${severityColor(m.severity)}`}>
          {m.severity}
        </span>
      )}
      <Handle type="source" position={Position.Right} style={{ background: color }} />
    </div>
  );
}

const nodeTypes = { stage: StageNode };

export function AttackVisualization() {
  const [selected, setSelected] = useState<AttackChain>(ATTACK_CHAINS[0]);
  const [selectedStage, setSelectedStage] = useState<AttackStage | null>(null);

  const { nodes, edges } = useMemo(() => {
    const chain = selected;
    const stageNodes: Node[] = chain.stages.map((stage, i) => ({
      id: stage.id,
      type: 'stage',
      position: { x: i * 290, y: 80 },
      data: stage,
    }));

    // Add attacker origin node
    const attackerNode: Node = {
      id: 'attacker',
      type: 'stage',
      position: { x: -200, y: 80 },
      data: {
        id: 'attacker',
        killChainPhase: '0. Origin',
        mitre: '—',
        techniqueName: chain.attacker.split(' (')[0],
        tactic: 'Adversary',
        description: chain.attacker,
        severity: 'critical',
        eventCount: 0,
        timestamp: chain.startTime,
        detected: false,
        evidenceSnippet: chain.attacker,
      } as AttackStage,
    };

    // Add target node
    const targetNode: Node = {
      id: 'target',
      type: 'stage',
      position: { x: chain.stages.length * 290, y: 80 },
      data: {
        id: 'target',
        killChainPhase: 'X. Target',
        mitre: '—',
        techniqueName: chain.target,
        tactic: 'Asset',
        description: chain.target,
        severity: 'critical',
        eventCount: chain.stages.reduce((s, st) => s + st.eventCount, 0),
        timestamp: '',
        detected: true,
        evidenceSnippet: chain.target,
      } as AttackStage,
    };

    const allNodes = [attackerNode, ...stageNodes, targetNode];
    const stageEdges: Edge[] = [];
    for (let i = 0; i < allNodes.length - 1; i++) {
      const sourcePhase = (allNodes[i].data as AttackStage).killChainPhase;
      const color = KILL_CHAIN_COLORS[sourcePhase] || '#1890ff';
      stageEdges.push({
        id: `e${i}`,
        source: allNodes[i].id,
        target: allNodes[i + 1].id,
        animated: true,
        style: { stroke: color, strokeWidth: 2 },
      });
    }

    return { nodes: allNodes, edges: stageEdges };
  }, [selected]);

  const coverage = useMemo(() => getChainMitreCoverage(), []);
  const detectedCount = selected.stages.filter((s) => s.detected).length;

  return (
    <div className="space-y-6 animate-fade-in">
      <Panel title="Attack Visualization — AI SOC Kill Chain Analysis" icon={Network}>
        <p className="text-sm text-soc-400 mb-4">
          Interactive attack chain visualization showing how adversaries progress through the cyber kill chain.
          Each stage maps to MITRE ATT&CK techniques with detected evidence snippets.
        </p>
        <div className="flex items-center gap-2 flex-wrap">
          {ATTACK_CHAINS.map((chain) => (
            <button
              key={chain.id}
              onClick={() => { setSelected(chain); setSelectedStage(null); }}
              className={`flex items-center gap-2 px-3 py-2 rounded-lg border text-sm transition-all ${
                selected.id === chain.id
                  ? 'bg-cyber-500/15 border-cyber-500/50 shadow-glow'
                  : 'bg-soc-800/40 border-soc-700/40 hover:border-cyber-500/30'
              }`}
            >
              <Crosshair className="w-4 h-4 text-cyber-400" />
              {chain.name}
            </button>
          ))}
        </div>
      </Panel>

      {/* Metrics */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <MetricTile label="Kill Chain Stages" value={selected.stages.length} icon={Activity} accent="cyber" />
        <MetricTile label="Detected" value={`${detectedCount}/${selected.stages.length}`} icon={Shield} accent="secure" />
        <MetricTile label="Total Threat Score" value={selected.totalThreatScore} icon={Zap} accent="threat" />
        <MetricTile label="Status" value={selected.status} icon={Radar} accent={selected.status === 'active' ? 'threat' : 'secure'} />
      </div>

      <div className="grid grid-cols-12 gap-6">
        {/* React Flow graph */}
        <div className="col-span-12 lg:col-span-8">
          <Panel title={`${selected.name} — Attack Chain Flow`} icon={Network}>
            <div style={{ height: 360 }} className="rounded-lg overflow-hidden bg-soc-950/60">
              <ReactFlow
                nodes={nodes}
                edges={edges}
                nodeTypes={nodeTypes}
                fitView
                fitViewOptions={{ padding: 0.15 }}
                onNodeClick={(_, node) => {
                  if (node.id !== 'attacker' && node.id !== 'target') {
                    setSelectedStage(node.data as AttackStage);
                  }
                }}
                proOptions={{ hideAttribution: true }}
              >
                <Background color="#1e293b" gap={24} />
                <Controls className="!bg-soc-800 !border-soc-700" />
                <MiniMap
                  className="!bg-soc-900 !border-soc-700"
                  nodeColor={(n) => KILL_CHAIN_COLORS[(n.data as AttackStage).killChainPhase] || '#1890ff'}
                />
              </ReactFlow>
            </div>
          </Panel>
        </div>

        {/* Stage detail */}
        <div className="col-span-12 lg:col-span-4">
          {selectedStage ? (
            <Panel title="Stage Detail" icon={Target}>
              <div className="space-y-3">
                <ThreatBadge level={selectedStage.severity} />
                <div>
                  <p className="text-xs text-soc-500 uppercase">Kill Chain Phase</p>
                  <p className="text-sm text-cyber-300 font-mono">{selectedStage.killChainPhase}</p>
                </div>
                <div>
                  <p className="text-xs text-soc-500 uppercase">Technique</p>
                  <p className="text-sm font-semibold text-soc-50">{selectedStage.techniqueName}</p>
                </div>
                <div>
                  <p className="text-xs text-soc-500 uppercase">MITRE</p>
                  <p className="text-sm font-mono text-cyber-300">{selectedStage.mitre} — {selectedStage.tactic}</p>
                </div>
                <div>
                  <p className="text-xs text-soc-500 uppercase">Description</p>
                  <p className="text-sm text-soc-300">{selectedStage.description}</p>
                </div>
                <div className="p-3 rounded-lg bg-soc-950/60 border border-soc-700/60">
                  <p className="text-xs text-soc-500 uppercase mb-1">Evidence Snippet</p>
                  <p className="text-xs font-mono text-alert-300 break-all">{selectedStage.evidenceSnippet}</p>
                </div>
                <div className="flex items-center justify-between text-sm">
                  <span className="text-soc-400">Events: <span className="font-mono text-soc-200">{selectedStage.eventCount}</span></span>
                  <span className={selectedStage.detected ? 'text-secure-400' : 'text-threat-400'}>
                    {selectedStage.detected ? 'Detected by SOC' : 'Missed — Gap Detected'}
                  </span>
                </div>
              </div>
            </Panel>
          ) : (
            <Panel title="Stage Detail" icon={Target}>
              <div className="py-12 text-center">
                <Eye className="w-10 h-10 text-soc-700 mx-auto mb-2" />
                <p className="text-sm text-soc-500">Click a stage node in the graph to view details.</p>
              </div>
            </Panel>
          )}
        </div>
      </div>

      {/* Timeline */}
      <Panel title="Attack Timeline" icon={Activity}>
        <div className="relative pl-6 space-y-3 before:content-[''] before:absolute before:left-2 before:top-2 before:bottom-2 before:w-px before:bg-cyber-700">
          {selected.stages.map((stage) => {
            const color = KILL_CHAIN_COLORS[stage.killChainPhase] || '#1890ff';
            return (
              <div
                key={stage.id}
                className="relative cursor-pointer"
                onClick={() => setSelectedStage(stage)}
              >
                <div className="absolute -left-4 top-1 w-3 h-3 rounded-full ring-4 ring-soc-900" style={{ backgroundColor: color }} />
                <div className={`p-3 rounded-lg border transition-all ${selectedStage?.id === stage.id ? 'bg-cyber-500/10 border-cyber-500/40' : 'bg-soc-800/40 border-soc-700/40 hover:border-cyber-500/30'}`}>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono uppercase" style={{ color }}>{stage.killChainPhase}</span>
                      <span className="text-sm font-medium text-soc-100">{stage.techniqueName}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono text-soc-500">{stage.mitre}</span>
                      {stage.detected ? <Shield className="w-3.5 h-3.5 text-secure-400" /> : <Skull className="w-3.5 h-3.5 text-threat-400" />}
                    </div>
                  </div>
                  <p className="text-xs text-soc-500 mt-1 font-mono">{stage.timestamp.slice(0, 19).replace('T', ' ')} — {stage.eventCount} events</p>
                </div>
              </div>
            );
          })}
        </div>
      </Panel>

      {/* MITRE coverage from chains */}
      <Panel title="MITRE ATT&CK Coverage Across Attack Chains" icon={Network}>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
          {coverage.map((c) => {
            const m = getMitre(c.id);
            return (
              <div key={c.id} className="p-3 rounded-lg bg-soc-800/40 border border-soc-700/40">
                <div className="flex items-center justify-between">
                  <span className="text-sm font-mono text-cyber-300">{c.id}</span>
                  <span className="text-[10px] text-soc-500">{c.chains} chain{c.chains > 1 ? 's' : ''}</span>
                </div>
                <p className="text-sm text-soc-100 mt-1">{c.name}</p>
                <p className="text-xs text-soc-500">{c.tactic}</p>
                {m && (
                  <span className={`inline-block mt-1.5 text-[9px] px-1.5 py-0.5 rounded border ${severityColor(m.severity)}`}>
                    {m.severity}
                  </span>
                )}
              </div>
            );
          })}
        </div>
      </Panel>
    </div>
  );
}
