import { useEffect, useState, useCallback, useRef } from 'react';
import {
  Lock, ShieldCheck, Send, KeyRound, Package, ArrowRight,
  CheckCircle2, Eye, EyeOff, AlertCircle, Volume2, Download,
  AudioLines, Waves, FileAudio, Play, Pause,
} from 'lucide-react';
import { Panel, ThreatBadge, StatusPill, Loader } from '@/components/ui/Primitives';
import { loadEvidence, loadIncidents } from '@/lib/api';
import {
  encryptEvidence, decryptEvidence, packageIncidentReport, generatePassphrase,
  verifyIntegrity, type SecureEnvelope, type EncryptedPayload,
} from '@/lib/crypto';
import {
  embedInAudio, extractFromAudio, base64ToBytes, bytesToBase64,
  waveformPreview, type StegoResult,
} from '@/lib/steganography';
import {
  buildIncidentReport, reportToText, encryptReport,
  type CipherAlgorithm, type CipherReportResult,
} from '@/lib/cipherReport';
import { desDecrypt } from '@/lib/desCrypto';
import { getMitre } from '@/lib/mitre';
import type { EvidenceRecord, Incident } from '@/lib/types';

const PIPELINE = [
  { label: 'Cipher Report', icon: FileAudio },
  { label: 'AES Encryption', icon: Lock },
  { label: 'Audio Embedding', icon: Waves },
  { label: 'Secure Transfer', icon: Send },
];

export function VoxCrypt() {
  const [evidence, setEvidence] = useState<EvidenceRecord[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedEvidence, setSelectedEvidence] = useState<EvidenceRecord | null>(null);
  const [recipient, setRecipient] = useState('soc-command@threatzero.io');
  const [passphrase, setPassphrase] = useState('');
  const [algorithm, setAlgorithm] = useState<CipherAlgorithm>('AES-256-GCM');

  const [cipherResult, setCipherResult] = useState<CipherReportResult | null>(null);
  const [stegoResult, setStegoResult] = useState<StegoResult | null>(null);
  const [processing, setProcessing] = useState(false);
  const [waveform, setWaveform] = useState<number[]>([]);
  const [showCipher, setShowCipher] = useState(false);
  const [decrypting, setDecrypting] = useState(false);
  const [decrypted, setDecrypted] = useState<string | null>(null);
  const [extractValid, setExtractValid] = useState<boolean | null>(null);
  const audioRef = useRef<HTMLAudioElement | null>(null);
  const [playing, setPlaying] = useState(false);

  useEffect(() => {
    (async () => {
      const [ev, inc] = await Promise.all([loadEvidence(), loadIncidents()]);
      setEvidence(ev);
      setIncidents(inc);
      setLoading(false);
    })();
  }, []);

  // Full workflow: cipher report → encrypt → embed in audio
  const handleFullPipeline = useCallback(async () => {
    if (!selectedEvidence) return;
    const inc = incidents.find((i) => i.id === selectedEvidence.incidentId);
    if (!inc) return;
    setProcessing(true);
    setStegoResult(null);
    setDecrypted(null);

    // Step 1: Build + encrypt the report (AES or DES)
    const report = buildIncidentReport(inc);
    const cipher = await encryptReport(report, algorithm, passphrase || generatePassphrase());
    if (!passphrase) setPassphrase(generatePassphrase());
    setCipherResult(cipher);

    // Step 2: Embed cipher bytes into audio carrier (steganography)
    const cipherBytes = base64ToBytes(cipher.cipherB64);
    const stego = await embedInAudio(cipherBytes, 4, 44100);
    setStegoResult(stego);
    setWaveform(waveformPreview(generateCarrierForPreview(stego.durationSec, stego.sampleRate), 64));

    setProcessing(false);
  }, [selectedEvidence, incidents, passphrase, algorithm]);

  // Extract + decrypt from the generated audio
  const handleExtract = useCallback(async () => {
    if (!stegoResult || !passphrase) return;
    setDecrypting(true);
    try {
      const extracted = await extractFromAudio(stegoResult.audioBlob);
      setExtractValid(extracted.valid);
      if (!extracted.valid) {
        setDecrypted('Extraction failed — no valid VoxCrypt payload found in audio.');
        setDecrypting(false);
        return;
      }
      // Reconstruct the cipher base64 and decrypt it
      const cipherB64 = bytesToBase64(extracted.payload);
      if (algorithm === 'AES-256-GCM' && cipherResult) {
        const payload: EncryptedPayload = {
          ciphertext: cipherB64,
          iv: cipherResult.ivB64!,
          salt: cipherResult.saltB64!,
          hash: cipherResult.hash,
          algorithm: 'AES-GCM',
          keyBits: 256,
          packaged: true,
          createdAt: cipherResult.createdAt,
        };
        const plaintext = await decryptEvidence(payload, passphrase);
        const ok = await verifyIntegrity(plaintext, cipherResult.hash);
        setDecrypted(ok ? plaintext : 'Integrity check failed — evidence may be tampered.');
      } else if (algorithm === 'DES' && cipherResult) {
        const plaintext = await desDecrypt(cipherB64, passphrase);
        const ok = await verifyIntegrity(plaintext, cipherResult.hash);
        setDecrypted(ok ? plaintext : 'Integrity check failed.');
      }
    } catch {
      setDecrypted('Decryption failed — check the passphrase.');
    }
    setDecrypting(false);
  }, [stegoResult, passphrase, algorithm, cipherResult]);

  const togglePlay = useCallback(() => {
    if (!audioRef.current) return;
    if (playing) {
      audioRef.current.pause();
    } else {
      audioRef.current.play();
    }
    setPlaying(!playing);
  }, [playing]);

  const downloadAudio = useCallback(() => {
    if (!stegoResult) return;
    const a = document.createElement('a');
    a.href = stegoResult.audioUrl;
    a.download = `voxcrypt_${selectedEvidence?.id || 'evidence'}.wav`;
    a.click();
  }, [stegoResult, selectedEvidence]);

  if (loading) return <Loader label="Loading secure evidence..." />;

  return (
    <div className="space-y-6 animate-fade-in">
      <Panel title="VoxCrypt — Secure Cyber Evidence Communication (Audio Steganography)" icon={Lock}>
        <div className="flex items-start gap-4">
          <div className="p-3 rounded-lg bg-cyber-500/10 border border-cyber-500/30">
            <AudioLines className="w-6 h-6 text-cyber-400" />
          </div>
          <div>
            <p className="text-sm text-soc-300">
              The most secure evidence channel: cipher reports are encrypted (AES/DES), then the ciphertext
              is hidden inside an audio waveform using LSB steganography. The recipient receives an ordinary
              audio file — only VoxCrypt can extract and decrypt the hidden evidence.
            </p>
            <p className="text-xs text-cyber-400 mt-2">Extension module — audio steganography secure channel.</p>
          </div>
        </div>
      </Panel>

      {/* Pipeline */}
      <Panel title="Secure Audio Transfer Pipeline" icon={ArrowRight}>
        <div className="flex items-center gap-2 flex-wrap">
          {PIPELINE.map((step, i) => (
            <div key={i} className="flex items-center gap-2">
              <div className={`flex items-center gap-2 px-3 py-2 rounded-lg border ${
                i === 0 ? 'bg-soc-800/50 border-soc-700/50' :
                i === 1 ? 'bg-cyber-500/10 border-cyber-500/30' :
                i === 2 ? 'bg-alert-500/10 border-alert-500/30' :
                'bg-secure-500/10 border-secure-500/30'
              }`}>
                <step.icon className={`w-4 h-4 ${
                  i === 1 ? 'text-cyber-400' : i === 2 ? 'text-alert-400' : i === 3 ? 'text-secure-400' : 'text-soc-400'
                }`} />
                <span className="text-xs text-soc-200">{step.label}</span>
              </div>
              {i < PIPELINE.length - 1 && <ArrowRight className="w-4 h-4 text-soc-600" />}
            </div>
          ))}
        </div>
      </Panel>

      <div className="grid grid-cols-12 gap-6">
        {/* Evidence + config */}
        <div className="col-span-12 lg:col-span-4 space-y-4">
          <Panel title="Select Evidence" icon={ShieldCheck}>
            {evidence.length === 0 ? (
              <p className="text-sm text-soc-500">No evidence available. Create evidence in the Evidence Vault first.</p>
            ) : (
              <div className="space-y-2 max-h-60 overflow-y-auto">
                {evidence.map((e) => {
                  const m = getMitre(e.mitre);
                  return (
                    <button
                      key={e.id}
                      onClick={() => { setSelectedEvidence(e); setStegoResult(null); setDecrypted(null); setCipherResult(null); }}
                      className={`w-full text-left p-3 rounded-lg border transition-all ${
                        selectedEvidence?.id === e.id ? 'bg-cyber-500/15 border-cyber-500/50' : 'bg-soc-800/40 border-soc-700/40 hover:border-cyber-500/30'
                      }`}
                    >
                      <div className="flex justify-between">
                        <span className="text-sm font-mono text-soc-100">{e.id}</span>
                        {m && <ThreatBadge level={m.severity} />}
                      </div>
                      <p className="text-xs text-soc-500 mt-1">{e.attackType} - {e.mitre}</p>
                    </button>
                  );
                })}
              </div>
            )}
          </Panel>

          {selectedEvidence && (
            <Panel title="Encryption Configuration" icon={KeyRound}>
              <div className="space-y-3">
                <div>
                  <label className="text-xs text-soc-400 uppercase mb-1.5 block">Algorithm</label>
                  <div className="flex gap-2">
                    <button
                      onClick={() => setAlgorithm('AES-256-GCM')}
                      className={`flex-1 p-2 rounded-lg border text-xs transition-all ${algorithm === 'AES-256-GCM' ? 'bg-cyber-500/15 border-cyber-500/50' : 'bg-soc-800/40 border-soc-700/40'}`}
                    >
                      <Lock className="w-3.5 h-3.5 text-cyber-400 inline mr-1" /> AES-256
                    </button>
                    <button
                      onClick={() => setAlgorithm('DES')}
                      className={`flex-1 p-2 rounded-lg border text-xs transition-all ${algorithm === 'DES' ? 'bg-alert-500/15 border-alert-500/50' : 'bg-soc-800/40 border-soc-700/40'}`}
                    >
                      <KeyRound className="w-3.5 h-3.5 text-alert-400 inline mr-1" /> DES
                    </button>
                  </div>
                </div>
                <div>
                  <label className="text-xs text-soc-400 uppercase">Recipient</label>
                  <input value={recipient} onChange={(e) => setRecipient(e.target.value)} className="soc-input mt-1 w-full" />
                </div>
                <div>
                  <label className="text-xs text-soc-400 uppercase">Passphrase</label>
                  <div className="flex gap-2 mt-1">
                    <input value={passphrase} onChange={(e) => setPassphrase(e.target.value)} type="password" placeholder="Auto-generated" className="soc-input flex-1 font-mono text-xs" />
                    <button onClick={() => setPassphrase(generatePassphrase())} className="soc-btn-ghost text-xs">
                      <KeyRound className="w-3.5 h-3.5" /> Gen
                    </button>
                  </div>
                </div>
                <button onClick={handleFullPipeline} disabled={processing} className="soc-btn-primary w-full">
                  <Waves className="w-4 h-4" />
                  {processing ? 'Processing...' : 'Encrypt → Embed in Audio'}
                </button>
              </div>
            </Panel>
          )}
        </div>

        {/* Output: audio + stego info + decrypt */}
        <div className="col-span-12 lg:col-span-8 space-y-4">
          {stegoResult ? (
            <>
              {/* Audio player */}
              <Panel title="Steganographic Audio — Hidden Evidence Carrier" icon={AudioLines} action={<StatusPill status="packaged" />}>
                <div className="space-y-4">
                  {/* Waveform visualization */}
                  <div className="flex items-end justify-center gap-0.5 h-24 bg-soc-950/60 rounded-lg p-3 border border-soc-700/40">
                    {waveform.map((peak, i) => (
                      <div
                        key={i}
                        className="flex-1 rounded-t bg-gradient-to-t from-cyber-700 to-cyber-400 transition-all"
                        style={{ height: `${Math.max(4, peak * 100)}%`, opacity: 0.6 + peak * 0.4 }}
                      />
                    ))}
                  </div>

                  {/* Audio controls */}
                  <div className="flex items-center gap-3">
                    <button onClick={togglePlay} className="soc-btn-primary">
                      {playing ? <Pause className="w-4 h-4" /> : <Play className="w-4 h-4" />}
                      {playing ? 'Pause' : 'Play'}
                    </button>
                    <button onClick={downloadAudio} className="soc-btn-ghost">
                      <Download className="w-4 h-4" /> Download .wav
                    </button>
                    <audio ref={audioRef} src={stegoResult.audioUrl} onEnded={() => setPlaying(false)} className="hidden" />
                    <span className="text-xs text-soc-500 flex items-center gap-1">
                      <Volume2 className="w-3.5 h-3.5" /> {stegoResult.durationSec}s • {stegoResult.sampleRate}Hz
                    </span>
                  </div>

                  {/* Stego stats */}
                  <div className="grid grid-cols-3 gap-2">
                    <div className="p-2.5 rounded bg-soc-800/50">
                      <p className="text-xs text-soc-500">Carrier Samples</p>
                      <p className="text-sm font-mono text-cyber-300">{stegoResult.carrierSamples.toLocaleString()}</p>
                    </div>
                    <div className="p-2.5 rounded bg-soc-800/50">
                      <p className="text-xs text-soc-500">Embedded Bytes</p>
                      <p className="text-sm font-mono text-alert-300">{stegoResult.embeddedBytes}</p>
                    </div>
                    <div className="p-2.5 rounded bg-soc-800/50">
                      <p className="text-xs text-soc-500">Capacity</p>
                      <p className="text-sm font-mono text-secure-300">{stegoResult.capacityBytes} bytes</p>
                    </div>
                  </div>

                  {/* Security badges */}
                  <div className="flex items-center gap-3 p-3 rounded-lg bg-secure-500/10 border border-secure-500/30">
                    <CheckCircle2 className="w-5 h-5 text-secure-400" />
                    <p className="text-sm text-secure-300">
                      Evidence hidden in audio via LSB steganography — appears as ordinary sound, undetectable without the key.
                    </p>
                  </div>
                </div>
              </Panel>

              {/* Cipher preview */}
              {cipherResult && (
                <Panel title="Cipher Report Embedded in Audio" icon={FileAudio}>
                  <div className="space-y-3">
                    <div className="flex items-center gap-3">
                      <span className="text-sm font-semibold text-soc-100">{cipherResult.algorithm}</span>
                      <span className="text-xs text-soc-500">{cipherResult.keyBits}-bit key</span>
                      <span className="text-xs text-soc-500">Entropy: <span className="text-secure-300 font-mono">{cipherResult.entropyScore}%</span></span>
                    </div>
                    <div className="p-3 rounded-lg bg-soc-950/60 border border-soc-700/60">
                      <button onClick={() => setShowCipher(!showCipher)} className="flex items-center justify-between w-full text-xs text-soc-400 hover:text-soc-200">
                        <span className="font-mono">Ciphertext hidden in audio ({cipherResult.cipherB64.length} chars)</span>
                        {showCipher ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                      </button>
                      {showCipher && (
                        <pre className="text-[10px] font-mono text-threat-300 mt-2 break-all overflow-hidden max-h-24 overflow-y-auto">{cipherResult.cipherB64}</pre>
                      )}
                    </div>
                    <div className="p-2.5 rounded bg-soc-800/50">
                      <p className="text-xs text-soc-500 mb-1">SHA-256 Integrity Hash</p>
                      <p className="text-xs font-mono text-cyber-300 break-all">{cipherResult.hash}</p>
                    </div>
                  </div>
                </Panel>
              )}

              {/* Extract + decrypt (recipient side) */}
              <Panel title="Extract & Decrypt from Audio (Recipient Side)" icon={Lock}>
                <p className="text-sm text-soc-400 mb-3">
                  The recipient loads the audio file, extracts the hidden ciphertext, and decrypts it with the passphrase.
                </p>
                <button onClick={handleExtract} disabled={decrypting || !passphrase} className="soc-btn-primary">
                  <Waves className="w-4 h-4" />
                  {decrypting ? 'Extracting...' : 'Extract + Decrypt from Audio'}
                </button>

                {decrypted && (
                  <div className="mt-4 p-3 rounded-lg bg-soc-950/60 border border-soc-700/60">
                    <div className="flex items-center gap-2 mb-2">
                      {decrypted.includes('failed') ? (
                        <AlertCircle className="w-4 h-4 text-threat-400" />
                      ) : (
                        <CheckCircle2 className="w-4 h-4 text-secure-400" />
                      )}
                      <span className={`text-sm font-semibold ${decrypted.includes('failed') ? 'text-threat-300' : 'text-secure-300'}`}>
                        {decrypted.includes('failed') ? 'Extraction/Decryption Failed' : 'Evidence Recovered — Integrity Verified'}
                      </span>
                    </div>
                    {!decrypted.includes('failed') && (
                      <pre className="text-xs font-mono text-soc-300 whitespace-pre-wrap break-all max-h-48 overflow-y-auto">{decrypted}</pre>
                    )}
                    {extractValid === false && (
                      <p className="text-xs text-threat-300 mt-2">No valid VoxCrypt signature found in the audio.</p>
                    )}
                  </div>
                )}
              </Panel>
            </>
          ) : (
            <Panel title="Secure Audio Output" icon={AudioLines}>
              <div className="py-16 text-center">
                <Waves className="w-12 h-12 text-soc-700 mx-auto mb-3" />
                <p className="text-sm text-soc-500">Select evidence and click "Encrypt → Embed in Audio" to generate a steganographic audio file.</p>
                <p className="text-xs text-soc-600 mt-2">The ciphered report from the Evidence Vault is hidden inside a generated audio waveform.</p>
              </div>
            </Panel>
          )}
        </div>
      </div>
    </div>
  );
}

// Generate a small carrier preview for waveform display (without embedding)
function generateCarrierForPreview(durationSec: number, sampleRate: number): Float32Array {
  // Reuse the steganography module's generator logic via a lightweight inline copy
  const samples = new Float32Array(Math.min(durationSec * sampleRate, 44100 * 2));
  for (let i = 0; i < samples.length; i++) {
    const t = i / sampleRate;
    const progress = t / (samples.length / sampleRate);
    const base = Math.sin(2 * Math.PI * 220 * t) * 0.15;
    const sweepFreq = 400 + 600 * progress;
    const sweep = Math.sin(2 * Math.PI * sweepFreq * t) * 0.1;
    const harmonic = Math.sin(2 * Math.PI * 880 * t) * 0.04;
    const env = Math.min(1, t * 3) * Math.min(1, (samples.length / sampleRate - t) * 3);
    samples[i] = (base + sweep + harmonic) * env;
  }
  return samples;
}
