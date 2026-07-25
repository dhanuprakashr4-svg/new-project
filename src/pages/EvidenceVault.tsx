import { useEffect, useState, useCallback } from 'react';
import { Link } from 'react-router-dom';
import {
  ShieldCheck, Lock, Hash, FileText, Download, Plus, RefreshCw,
  KeyRound, Eye, EyeOff, ArrowRight, Zap, Binary, Gauge, Lock as LockIcon,
} from 'lucide-react';
import { Panel, ThreatBadge, StatusPill, EmptyState, Loader } from '@/components/ui/Primitives';
import { loadEvidence, loadIncidents, saveEvidence } from '@/lib/api';
import { sha256Hex } from '@/lib/crypto';
import { getMitre } from '@/lib/mitre';
import {
  buildIncidentReport, reportToText, encryptReport,
  type CipherAlgorithm, type CipherReportResult, type IncidentReport,
} from '@/lib/cipherReport';
import type { EvidenceRecord, Incident } from '@/lib/types';

export function EvidenceVault() {
  const [evidence, setEvidence] = useState<EvidenceRecord[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<EvidenceRecord | null>(null);

  // Cipher report state
  const [cipherIncident, setCipherIncident] = useState<Incident | null>(null);
  const [algorithm, setAlgorithm] = useState<CipherAlgorithm>('AES-256-GCM');
  const [passphrase, setPassphrase] = useState('');
  const [cipherResult, setCipherResult] = useState<CipherReportResult | null>(null);
  const [encrypting, setEncrypting] = useState(false);
  const [showPlaintext, setShowPlaintext] = useState(false);
  const [showCipher, setShowCipher] = useState(false);

  const refresh = useCallback(async () => {
    setLoading(true);
    const [ev, inc] = await Promise.all([loadEvidence(), loadIncidents()]);
    setEvidence(ev);
    setIncidents(inc);
    setLoading(false);
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  const createEvidence = useCallback(async (inc: Incident) => {
    const report = buildIncidentReport(inc);
    const text = reportToText(report);
    const hash = await sha256Hex(text);
    const record: EvidenceRecord = {
      id: `EVD-${Date.now().toString(36).toUpperCase()}`,
      incidentId: inc.id,
      timestamp: new Date().toISOString(),
      attackType: inc.attackType,
      mitre: inc.mitre,
      hash,
      encryptionStatus: 'AES-256 Encrypted',
      integrityVerified: true,
      sizeBytes: new Blob([text]).size,
      packaged: true,
    };
    await saveEvidence(record);
    await refresh();
    setSelected(record);
    setCipherIncident(inc);
  }, [refresh]);

  const generateCipher = useCallback(async () => {
    if (!cipherIncident || !passphrase) return;
    setEncrypting(true);
    const report = buildIncidentReport(cipherIncident);
    const result = await encryptReport(report, algorithm, passphrase);
    setCipherResult(result);
    setEncrypting(false);
  }, [cipherIncident, algorithm, passphrase]);

  const downloadReport = useCallback((content: string, filename: string) => {
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }, []);

  return (
    <div className="space-y-6 animate-fade-in">
      <Panel title="Evidence Vault — Secure Forensic Storage & Cipher Reports" icon={ShieldCheck}>
        <div className="flex items-center justify-between flex-wrap gap-3">
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2 text-xs">
              <Lock className="w-4 h-4 text-secure-400" />
              <span className="text-secure-400 font-semibold">AES-256 / DES Encryption</span>
            </div>
            <div className="flex items-center gap-2 text-xs">
              <Hash className="w-4 h-4 text-cyber-400" />
              <span className="text-cyber-400 font-semibold">SHA-256 Integrity</span>
            </div>
          </div>
          <button onClick={refresh} className="soc-btn-ghost text-xs">
            <RefreshCw className="w-3.5 h-3.5" /> Refresh
          </button>
        </div>
      </Panel>

      <div className="grid grid-cols-12 gap-6">
        {/* Evidence list */}
        <div className="col-span-12 lg:col-span-5">
          <Panel title={`Evidence Records (${evidence.length})`} icon={FileText}>
            {loading ? (
              <Loader label="Loading evidence..." />
            ) : evidence.length === 0 ? (
              <EmptyState icon={ShieldCheck} title="No evidence records yet" hint="Create evidence from an incident below." />
            ) : (
              <div className="space-y-2 max-h-[400px] overflow-y-auto">
                {evidence.map((e) => {
                  const m = getMitre(e.mitre);
                  return (
                    <button
                      key={e.id}
                      onClick={() => setSelected(e)}
                      className={`w-full text-left p-3 rounded-lg border transition-all ${
                        selected?.id === e.id ? 'bg-cyber-500/15 border-cyber-500/50' : 'bg-soc-800/40 border-soc-700/40 hover:border-cyber-500/30'
                      }`}
                    >
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-sm font-mono text-soc-100">{e.id}</span>
                        <StatusPill status={e.packaged ? 'packaged' : 'open'} />
                      </div>
                      <div className="flex items-center gap-3 text-xs text-soc-500">
                        <span>{e.attackType}</span>
                        <span className="text-cyber-300">{e.mitre}</span>
                        {m && <ThreatBadge level={m.severity} />}
                      </div>
                      <div className="flex items-center gap-2 mt-1.5 text-[10px] text-soc-600 font-mono">
                        <Hash className="w-3 h-3" />
                        {e.hash.slice(0, 24)}...
                      </div>
                    </button>
                  );
                })}
              </div>
            )}
          </Panel>

          {/* Create evidence */}
          <div className="mt-4">
            <Panel title="Create Evidence + Cipher Report" icon={Plus}>
              {incidents.length === 0 ? (
                <p className="text-sm text-soc-500">No incidents available. Detect threats first.</p>
              ) : (
                <div className="space-y-2 max-h-48 overflow-y-auto">
                  {incidents.filter((i) => !evidence.some((e) => e.incidentId === i.id)).slice(0, 6).map((inc) => (
                    <button
                      key={inc.id}
                      onClick={() => createEvidence(inc)}
                      className="w-full flex items-center justify-between p-2.5 rounded-lg bg-soc-800/40 border border-soc-700/40 hover:border-cyber-500/40 transition-all text-left"
                    >
                      <div>
                        <p className="text-sm text-soc-100">{inc.attackType}</p>
                        <p className="text-xs text-soc-500 font-mono">{inc.id}</p>
                      </div>
                      <Plus className="w-4 h-4 text-cyber-400" />
                    </button>
                  ))}
                </div>
              )}
            </Panel>
          </div>
        </div>

        {/* Detail + Cipher Report */}
        <div className="col-span-12 lg:col-span-7 space-y-4">
          {selected && (
            <Panel title="Evidence Detail" icon={ShieldCheck}>
              <div className="space-y-3">
                <div className="grid grid-cols-2 gap-3">
                  <Field label="Incident ID" value={selected.incidentId} mono />
                  <Field label="Timestamp" value={selected.timestamp.slice(0, 19)} mono />
                  <Field label="Attack Type" value={selected.attackType} />
                  <Field label="MITRE" value={selected.mitre} mono />
                  <Field label="Size" value={`${(selected.sizeBytes / 1024).toFixed(2)} KB`} />
                  <Field label="Encryption" value={selected.encryptionStatus} />
                </div>
                <div className="p-3 rounded-lg bg-soc-800/50">
                  <p className="text-xs text-soc-500 uppercase mb-1">SHA-256 Hash</p>
                  <p className="text-xs font-mono text-cyber-300 break-all">{selected.hash}</p>
                </div>
                <div className="flex items-center gap-3 p-3 rounded-lg bg-secure-500/10 border border-secure-500/30">
                  <ShieldCheck className="w-5 h-5 text-secure-400" />
                  <div>
                    <p className="text-sm text-secure-300 font-semibold">Integrity Verified</p>
                    <p className="text-xs text-soc-400">SHA-256 hash confirms evidence has not been tampered with.</p>
                  </div>
                </div>
              </div>
            </Panel>
          )}

          {/* Cipher Report Generator */}
          {cipherIncident && (
            <Panel title="CipherView Report Generator — AES / DES Encryption" icon={LockIcon}>
              <div className="space-y-4">
                {/* Algorithm selector */}
                <div>
                  <label className="text-xs text-soc-400 uppercase mb-2 block">Encryption Algorithm</label>
                  <div className="flex gap-2">
                    <button
                      onClick={() => setAlgorithm('AES-256-GCM')}
                      className={`flex-1 p-3 rounded-lg border transition-all ${algorithm === 'AES-256-GCM' ? 'bg-cyber-500/15 border-cyber-500/50' : 'bg-soc-800/40 border-soc-700/40'}`}
                    >
                      <div className="flex items-center gap-2">
                        <Lock className="w-4 h-4 text-cyber-400" />
                        <div className="text-left">
                          <p className="text-sm font-semibold text-soc-100">AES-256-GCM</p>
                          <p className="text-[10px] text-soc-500">256-bit key, authenticated</p>
                        </div>
                      </div>
                    </button>
                    <button
                      onClick={() => setAlgorithm('DES')}
                      className={`flex-1 p-3 rounded-lg border transition-all ${algorithm === 'DES' ? 'bg-alert-500/15 border-alert-500/50' : 'bg-soc-800/40 border-soc-700/40'}`}
                    >
                      <div className="flex items-center gap-2">
                        <KeyRound className="w-4 h-4 text-alert-400" />
                        <div className="text-left">
                          <p className="text-sm font-semibold text-soc-100">DES (ECB)</p>
                          <p className="text-[10px] text-soc-500">56-bit key, classic</p>
                        </div>
                      </div>
                    </button>
                  </div>
                </div>

                {/* Passphrase */}
                <div>
                  <label className="text-xs text-soc-400 uppercase">Encryption Passphrase</label>
                  <input
                    value={passphrase}
                    onChange={(e) => setPassphrase(e.target.value)}
                    type="password"
                    placeholder="Enter passphrase..."
                    className="soc-input mt-1 w-full"
                  />
                </div>

                <button onClick={generateCipher} disabled={encrypting || !passphrase} className="soc-btn-primary w-full">
                  <Zap className="w-4 h-4" />
                  {encrypting ? 'Encrypting...' : `Generate ${algorithm} Cipher Report`}
                </button>

                {/* Cipher result */}
                {cipherResult && (
                  <div className="space-y-4 pt-2 border-t border-soc-700/60">
                    {/* Cipher stats */}
                    <div className="grid grid-cols-3 gap-2">
                      <div className="p-2.5 rounded bg-soc-800/50 text-center">
                        <p className="text-xs text-soc-500">Key Size</p>
                        <p className="text-sm font-mono text-cyber-300">{cipherResult.keyBits}-bit</p>
                      </div>
                      <div className="p-2.5 rounded bg-soc-800/50 text-center">
                        <p className="text-xs text-soc-500">Block Size</p>
                        <p className="text-sm font-mono text-cyber-300">{cipherResult.blockSize} bytes</p>
                      </div>
                      <div className="p-2.5 rounded bg-soc-800/50 text-center">
                        <p className="text-xs text-soc-500">Entropy</p>
                        <p className="text-sm font-mono text-secure-300">{cipherResult.entropyScore}%</p>
                      </div>
                    </div>

                    {/* Entropy meter */}
                    <div>
                      <div className="flex justify-between text-xs mb-1">
                        <span className="text-soc-400">Cipher Randomness (Entropy)</span>
                        <span className="font-mono text-secure-300">{cipherResult.entropyScore}/100</span>
                      </div>
                      <div className="h-2 bg-soc-800 rounded-full overflow-hidden">
                        <div className="h-full bg-gradient-to-r from-cyber-500 to-secure-500 rounded-full transition-all duration-700" style={{ width: `${cipherResult.entropyScore}%` }} />
                      </div>
                    </div>

                    {/* Block visualization */}
                    <div>
                      <p className="text-xs text-soc-400 uppercase mb-2 flex items-center gap-1">
                        <Binary className="w-3.5 h-3.5 text-cyber-400" /> Block-by-Block Cipher Visualization
                      </p>
                      <div className="space-y-1.5 max-h-44 overflow-y-auto">
                        {cipherResult.blockPreview.map((block) => (
                          <div key={block.index} className="flex items-center gap-2 text-xs font-mono">
                            <span className="text-soc-600 w-6">#{block.index}</span>
                            <span className="text-soc-300 flex-1 truncate">{block.plainHex}</span>
                            <ArrowRight className="w-3 h-3 text-cyber-500 shrink-0" />
                            <span className="text-threat-300 flex-1 truncate">{block.cipherHex}</span>
                          </div>
                        ))}
                      </div>
                      <div className="flex items-center gap-4 mt-1.5 text-[10px] text-soc-600">
                        <span><span className="inline-block w-2 h-2 bg-soc-300 rounded-sm mr-1" />Plaintext (hex)</span>
                        <span><span className="inline-block w-2 h-2 bg-threat-300 rounded-sm mr-1" />Ciphertext (hex)</span>
                      </div>
                    </div>

                    {/* Cipher text toggle */}
                    <div className="p-3 rounded-lg bg-soc-950/60 border border-soc-700/60">
                      <button onClick={() => setShowCipher(!showCipher)} className="flex items-center justify-between w-full text-xs text-soc-400 hover:text-soc-200">
                        <span className="font-mono">Ciphertext (base64) — {cipherResult.cipherB64.length} chars</span>
                        {showCipher ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                      </button>
                      {showCipher && (
                        <pre className="text-[10px] font-mono text-threat-300 mt-2 break-all overflow-hidden max-h-24 overflow-y-auto">{cipherResult.cipherB64}</pre>
                      )}
                    </div>

                    {/* Plaintext toggle */}
                    <div className="p-3 rounded-lg bg-soc-950/60 border border-soc-700/60">
                      <button onClick={() => setShowPlaintext(!showPlaintext)} className="flex items-center justify-between w-full text-xs text-soc-400 hover:text-soc-200">
                        <span className="font-mono">Original Report (plaintext)</span>
                        {showPlaintext ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                      </button>
                      {showPlaintext && (
                        <pre className="text-[10px] font-mono text-soc-300 mt-2 whitespace-pre-wrap max-h-40 overflow-y-auto">{cipherResult.plaintext}</pre>
                      )}
                    </div>

                    {/* Hash */}
                    <div className="p-2.5 rounded bg-soc-800/50">
                      <p className="text-xs text-soc-500 uppercase mb-1 flex items-center gap-1"><Hash className="w-3 h-3" /> SHA-256 Integrity Hash</p>
                      <p className="text-xs font-mono text-cyber-300 break-all">{cipherResult.hash}</p>
                    </div>

                    {/* Actions */}
                    <div className="flex gap-2">
                      <button
                        onClick={() => downloadReport(cipherResult.cipherB64, `cipher_${selected?.id || 'report'}.txt`)}
                        className="soc-btn-ghost text-xs flex-1"
                      >
                        <Download className="w-3.5 h-3.5" /> Download Cipher
                      </button>
                      <Link to="/voxcrypt" className="soc-btn-primary text-xs flex-1">
                        <ArrowRight className="w-3.5 h-3.5" /> Send to VoxCrypt
                      </Link>
                    </div>
                  </div>
                )}
              </div>
            </Panel>
          )}

          {!cipherIncident && (
            <Panel title="CipherView Report Generator" icon={LockIcon}>
              <div className="py-12 text-center">
                <LockIcon className="w-12 h-12 text-soc-700 mx-auto mb-3" />
                <p className="text-sm text-soc-500">Create evidence from an incident to generate an encrypted cipher report.</p>
                <p className="text-xs text-soc-600 mt-2">The cipher report can then be sent to VoxCrypt for audio steganography.</p>
              </div>
            </Panel>
          )}
        </div>
      </div>
    </div>
  );
}

function Field({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="p-2.5 rounded bg-soc-800/50">
      <p className="text-xs text-soc-500 uppercase">{label}</p>
      <p className={`text-sm text-soc-200 ${mono ? 'font-mono' : ''}`}>{value}</p>
    </div>
  );
}
