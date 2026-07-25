import { useState, useRef, useEffect, useCallback } from 'react';
import {
  Play, Pause, Square, SkipForward, SkipBack, Volume2, VolumeX,
  Radio, Activity, Clock, MapPin, Server, Crosshair, Zap, Shield,
  Network, Radar, Terminal, KeyRound, Search, Upload, DoorOpen,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { Panel, ThreatBadge, MetricTile } from '@/components/ui/Primitives';
import {
  buildAttackExplanation, AttackNarrator, getAvailableExplanations,
  type AttackExplanation,
} from '@/lib/attackNarration';
import { getMitre, severityColor } from '@/lib/mitre';
import { getNistMapping, NIST_COLORS } from '@/lib/nist';

const VISUAL_ICONS: Record<string, LucideIcon> = {
  Radar, DoorOpen, Terminal, KeyRound, Network, Clock, Crosshair, Search, Upload, Activity,
};

export function AttackExplanation() {
  const [selectedId, setSelectedId] = useState('chain-ransomware');
  const [explanation, setExplanation] = useState<AttackExplanation | null>(null);
  const [currentStep, setCurrentStep] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [muted, setMuted] = useState(false);
  const [progress, setProgress] = useState(0);
  const narratorRef = useRef<AttackNarrator | null>(null);
  const progressTimer = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    const exp = buildAttackExplanation(selectedId);
    setExplanation(exp);
    setCurrentStep(0);
    setPlaying(false);
    setProgress(0);
  }, [selectedId]);

  useEffect(() => {
    narratorRef.current = new AttackNarrator();
    return () => {
      narratorRef.current?.stop();
      if (progressTimer.current) clearInterval(progressTimer.current);
    };
  }, []);

  const handlePlay = useCallback(() => {
    if (!explanation || !narratorRef.current) return;
    setPlaying(true);
    narratorRef.current.start(
      explanation.steps,
      (step) => {
        setCurrentStep(step);
        setProgress(((step + 1) / explanation.steps.length) * 100);
      },
      () => {
        setPlaying(false);
        setProgress(100);
        if (progressTimer.current) clearInterval(progressTimer.current);
      },
    );

    // Progress animation
    if (progressTimer.current) clearInterval(progressTimer.current);
    progressTimer.current = setInterval(() => {
      setProgress((prev) => {
        const next = prev + (100 / (explanation.totalDurationSec));
        return Math.min(next, 100);
      });
    }, 1000);
  }, [explanation]);

  const handlePause = useCallback(() => {
    narratorRef.current?.pause();
    setPlaying(false);
  }, []);

  const handleResume = useCallback(() => {
    narratorRef.current?.resume();
    setPlaying(true);
  }, []);

  const handleStop = useCallback(() => {
    narratorRef.current?.stop();
    setPlaying(false);
    setCurrentStep(0);
    setProgress(0);
    if (progressTimer.current) clearInterval(progressTimer.current);
  }, []);

  const handleNext = useCallback(() => narratorRef.current?.next(), []);
  const handlePrev = useCallback(() => narratorRef.current?.prev(), []);

  const handleMute = useCallback(() => {
    if (muted) {
      narratorRef.current?.resume();
      setMuted(false);
    } else {
      narratorRef.current?.pause();
      setMuted(true);
    }
  }, [muted]);

  if (!explanation) return null;

  const step = explanation.steps[currentStep];
  const stepTechnique = step?.details.technique;
  const mitre = getMitre(stepTechnique || '');
  const nist = getNistMapping(stepTechnique || '');
  const VisualIcon = VISUAL_ICONS[step?.icon] || Activity;
  const isSupported = narratorRef.current?.isSupported() ?? false;

  return (
    <div className="space-y-6 animate-fade-in">
      <Panel title="Audio/Video Attack Explanation — AI Narrated Walkthrough" icon={Volume2}>
        <div className="flex items-start gap-4">
          <div className="p-3 rounded-lg bg-cyber-500/10 border border-cyber-500/30">
            <Radio className="w-6 h-6 text-cyber-400" />
          </div>
          <div className="flex-1">
            <p className="text-sm text-soc-300">
              AI-narrated, step-by-step walkthrough of real attack scenarios. Each phase is explained with audio
              narration and a synchronized visual animation showing the attacker's progression through the kill chain.
            </p>
            <div className="flex items-center gap-2 mt-2">
              {getAvailableExplanations().map((exp) => (
                <button
                  key={exp.id}
                  onClick={() => setSelectedId(exp.id)}
                  className={`text-xs px-3 py-1.5 rounded-lg border transition-all ${
                    selectedId === exp.id ? 'bg-cyber-500/15 border-cyber-500/50' : 'bg-soc-800/40 border-soc-700/40'
                  }`}
                >
                  {exp.name}
                </button>
              ))}
            </div>
            {!isSupported && (
              <p className="text-xs text-alert-400 mt-2">Audio narration not supported in this browser. Visual walkthrough still plays.</p>
            )}
          </div>
        </div>
      </Panel>

      {/* Metrics */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <MetricTile label="Attack Phases" value={explanation.steps.length} icon={Activity} accent="cyber" />
        <MetricTile label="Current Phase" value={currentStep + 1} icon={Crosshair} accent="threat" />
        <MetricTile label="Duration" value={`${explanation.totalDurationSec}s`} icon={Clock} accent="alert" />
        <MetricTile label="Status" value={playing ? 'Playing' : 'Stopped'} icon={Volume2} accent={playing ? 'secure' : 'cyber'} />
      </div>

      {/* Main visual + narration area */}
      <div className="grid grid-cols-12 gap-6">
        {/* Visual animation */}
        <div className="col-span-12 lg:col-span-7">
          <Panel title="Visual Attack Walkthrough" icon={Activity}>
            {/* Animated stage visualization */}
            <div className="relative h-64 rounded-lg bg-soc-950/80 border border-soc-700/40 overflow-hidden scan-overlay">
              {/* Grid background */}
              <div className="absolute inset-0 grid-bg opacity-30" />

              {/* Attack flow animation */}
              <div className="relative h-full flex items-center justify-center">
                <div key={currentStep} className="animate-fade-in flex flex-col items-center gap-4">
                  <div className={`w-20 h-20 rounded-2xl flex items-center justify-center border-2 ${
                    step?.visualType === 'impact' ? 'border-threat-500 bg-threat-500/15 shadow-glow-threat' :
                    step?.visualType === 'access' ? 'border-alert-500 bg-alert-500/15' :
                    'border-cyber-500 bg-cyber-500/15 shadow-glow'
                  }`}>
                    <VisualIcon className={`w-10 h-10 ${
                      step?.visualType === 'impact' ? 'text-threat-400' :
                      step?.visualType === 'access' ? 'text-alert-400' : 'text-cyber-400'
                    }`} />
                  </div>
                  <div className="text-center">
                    <p className="text-lg font-bold text-soc-50">{step?.title}</p>
                    <p className="text-sm text-cyber-300 font-mono mt-1">{stepTechnique}</p>
                  </div>
                </div>
              </div>

              {/* Progress bar overlay */}
              <div className="absolute bottom-0 left-0 right-0 h-1 bg-soc-800">
                <div className="h-full bg-gradient-to-r from-cyber-500 to-cyber-300 transition-all duration-1000" style={{ width: `${progress}%` }} />
              </div>
            </div>

            {/* Step navigator */}
            <div className="flex items-center justify-center gap-2 mt-4">
              <button onClick={handlePrev} disabled={currentStep === 0} className="soc-btn-ghost">
                <SkipBack className="w-4 h-4" />
              </button>
              {playing ? (
                <button onClick={handlePause} className="soc-btn-primary">
                  <Pause className="w-4 h-4" /> Pause
                </button>
              ) : (
                <button onClick={playing ? handleResume : handlePlay} className="soc-btn-primary">
                  <Play className="w-4 h-4" /> {currentStep > 0 && !playing ? 'Resume' : 'Play'}
                </button>
              )}
              <button onClick={handleStop} className="soc-btn-ghost">
                <Square className="w-4 h-4" /> Stop
              </button>
              <button onClick={handleNext} disabled={currentStep >= explanation.steps.length - 1} className="soc-btn-ghost">
                <SkipForward className="w-4 h-4" />
              </button>
              <button onClick={handleMute} className="soc-btn-ghost">
                {muted ? <VolumeX className="w-4 h-4" /> : <Volume2 className="w-4 h-4" />}
              </button>
            </div>
          </Panel>
        </div>

        {/* Narration + details */}
        <div className="col-span-12 lg:col-span-5 space-y-4">
          <Panel title="Audio Narration" icon={Volume2}>
            <div className="p-4 rounded-lg bg-soc-950/60 border border-soc-700/40 min-h-[120px]">
              <div className="flex items-start gap-2 mb-2">
                <span className="text-xs font-mono text-cyber-400 shrink-0">Phase {currentStep + 1}/{explanation.steps.length}</span>
              </div>
              <p className="text-sm text-soc-200 leading-relaxed">{step?.narration}</p>
            </div>
            {/* Audio waveform indicator */}
            {playing && (
              <div className="flex items-end justify-center gap-1 h-8 mt-3">
                {Array.from({ length: 24 }).map((_, i) => (
                  <div
                    key={i}
                    className="w-1 bg-cyber-400 rounded-full animate-pulse"
                    style={{
                      height: `${20 + Math.sin(i * 0.8 + Date.now() / 200) * 50}%`,
                      animationDelay: `${i * 50}ms`,
                    }}
                  />
                ))}
              </div>
            )}
          </Panel>

          {/* Attack details */}
          {step && (
            <Panel title="Attack Details" icon={Server}>
              <div className="space-y-2">
                <DetailRow icon={Server} label="Target Server" value={step.details.server} />
                <DetailRow icon={MapPin} label="Attacker IP" value={step.details.ip} />
                <DetailRow icon={Clock} label="Timestamp" value={step.details.timestamp.slice(0, 19).replace('T', ' ')} />
                <DetailRow icon={Crosshair} label="MITRE" value={stepTechnique || 'N/A'} />
                <div className="p-2.5 rounded bg-soc-950/60 border border-soc-700/40">
                  <p className="text-xs text-soc-500 uppercase mb-1">Evidence Action</p>
                  <p className="text-xs font-mono text-alert-300 break-all">{step.details.action}</p>
                </div>
                {mitre && (
                  <div className="flex items-center gap-2 mt-2">
                    <span className="text-sm font-mono text-cyber-300">{mitre.id}</span>
                    <span className={`text-[10px] px-1.5 py-0.5 rounded border ${severityColor(mitre.severity)}`}>{mitre.severity}</span>
                    <span className="text-xs text-soc-400">{mitre.tactic}</span>
                  </div>
                )}
              </div>
            </Panel>
          )}

          {/* NIST mapping */}
          {nist && (
            <Panel title="NIST CSF Mapping" icon={Shield}>
              <div className="space-y-2">
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
              </div>
            </Panel>
          )}
        </div>
      </div>

      {/* Phase timeline */}
      <Panel title="Complete Attack Phase Timeline" icon={Clock}>
        <div className="relative pl-6 space-y-2 before:content-[''] before:absolute before:left-2 before:top-2 before:bottom-2 before:w-px before:bg-cyber-700">
          {explanation.steps.map((s, i) => (
            <div
              key={s.id}
              className={`relative cursor-pointer transition-all ${i === currentStep ? 'scale-100' : 'opacity-60 hover:opacity-100'}`}
              onClick={() => setCurrentStep(i)}
            >
              <div className={`absolute -left-4 top-1 w-3 h-3 rounded-full ring-4 ring-soc-900 transition-all ${
                i === currentStep ? 'bg-cyber-400 shadow-glow' : i < currentStep ? 'bg-secure-500' : 'bg-soc-600'
              }`} />
              <div className={`p-2.5 rounded-lg border transition-all ${
                i === currentStep ? 'bg-cyber-500/10 border-cyber-500/40' : 'bg-soc-800/40 border-soc-700/40'
              }`}>
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono text-cyber-300">{s.title}</span>
                  <span className="text-xs text-soc-500">{s.details.technique}</span>
                </div>
                <p className="text-xs text-soc-400 mt-0.5 truncate">{s.narration.slice(0, 80)}...</p>
              </div>
            </div>
          ))}
        </div>
      </Panel>
    </div>
  );
}

function DetailRow({ icon: Icon, label, value }: { icon: typeof Server; label: string; value: string }) {
  return (
    <div className="flex items-center gap-2">
      <Icon className="w-3.5 h-3.5 text-soc-500 shrink-0" />
      <span className="text-xs text-soc-500 w-24 shrink-0">{label}</span>
      <span className="text-xs text-soc-200 font-mono truncate">{value}</span>
    </div>
  );
}
