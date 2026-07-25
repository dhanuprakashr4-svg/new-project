import { getMitre } from './mitre';
import { getNistMapping } from './nist';
import { ATTACK_CHAINS, type AttackStage } from './attackChains';

// ===== Audio/Video Attack Explanation =====
// Uses the Web Speech API (SpeechSynthesis) for audio narration of attacks,
// and provides structured walkthrough data for animated visual explanations.

export interface AttackExplanationStep {
  id: number;
  title: string;
  narration: string;
  visualType: 'recon' | 'access' | 'execute' | 'creds' | 'lateral' | 'persist' | 'impact' | 'collect' | 'exfil';
  icon: string;
  durationMs: number;
  details: {
    server: string;
    ip: string;
    timestamp: string;
    technique: string;
    action: string;
  };
}

export interface AttackExplanation {
  attackName: string;
  mitreId: string;
  totalDurationSec: number;
  steps: AttackExplanationStep[];
  summary: string;
  narrationScript: string;
}

// Build a step-by-step explanation for an attack chain
export function buildAttackExplanation(chainId: string): AttackExplanation | null {
  const chain = ATTACK_CHAINS.find((c) => c.id === chainId);
  if (!chain) return null;

  const steps: AttackExplanationStep[] = chain.stages.map((stage, i) => ({
    id: i + 1,
    title: stage.killChainPhase,
    narration: buildNarration(stage, chain.attacker),
    visualType: mapVisualType(stage.killChainPhase),
    icon: mapIcon(stage.killChainPhase),
    durationMs: 4000,
    details: {
      server: chain.target,
      ip: chain.attacker.split(' — ')[1] || chain.attacker,
      timestamp: stage.timestamp,
      technique: stage.mitre,
      action: stage.evidenceSnippet,
    },
  }));

  const totalDurationSec = Math.ceil((steps.length * 4000) / 1000);
  const summary = `${chain.name}: ${chain.stages.length}-stage attack by ${chain.attacker} targeting ${chain.target}. Threat score ${chain.totalThreatScore}/99. Status: ${chain.status}.`;
  const narrationScript = steps.map((s) => s.narration).join(' ');

  return {
    attackName: chain.name,
    mitreId: chain.stages[0]?.mitre || 'T1059.001',
    totalDurationSec,
    steps,
    summary,
    narrationScript,
  };
}

function buildNarration(stage: AttackStage, attacker: string): string {
  const m = getMitre(stage.mitre);
  return `Phase ${stage.killChainPhase}. ${stage.description} The attacker used ${stage.techniqueName}, mapped to MITRE technique ${stage.mitre}, which falls under the ${stage.tactic} tactic. ${stage.detected ? 'This activity was detected by our SOC monitoring.' : 'This activity was missed by our detection — a coverage gap was identified.'} Evidence: ${stage.evidenceSnippet}.`;
}

function mapVisualType(phase: string): AttackExplanationStep['visualType'] {
  const p = phase.toLowerCase();
  if (p.includes('recon')) return 'recon';
  if (p.includes('initial') || p.includes('access')) return 'access';
  if (p.includes('execution')) return 'execute';
  if (p.includes('credential')) return 'creds';
  if (p.includes('lateral')) return 'lateral';
  if (p.includes('persistence')) return 'persist';
  if (p.includes('impact')) return 'impact';
  if (p.includes('collection') || p.includes('discovery')) return 'collect';
  if (p.includes('exfiltration')) return 'exfil';
  return 'execute';
}

function mapIcon(phase: string): string {
  const p = phase.toLowerCase();
  if (p.includes('recon')) return 'Radar';
  if (p.includes('initial') || p.includes('access')) return 'DoorOpen';
  if (p.includes('execution')) return 'Terminal';
  if (p.includes('credential')) return 'KeyRound';
  if (p.includes('lateral')) return 'Network';
  if (p.includes('persistence')) return 'Clock';
  if (p.includes('impact')) return 'Skull';
  if (p.includes('collection') || p.includes('discovery')) return 'Search';
  if (p.includes('exfiltration')) return 'Upload';
  return 'Activity';
}

// Web Speech API narration controller
export class AttackNarrator {
  private synth: SpeechSynthesis | null = null;
  private utterance: SpeechSynthesisUtterance | null = null;
  private currentStep = 0;
  private steps: AttackExplanationStep[] = [];
  private onStepChange: ((step: number) => void) | null = null;
  private onEnd: (() => void) | null = null;
  private paused = false;

  constructor() {
    if (typeof window !== 'undefined' && 'speechSynthesis' in window) {
      this.synth = window.speechSynthesis;
    }
  }

  isSupported(): boolean {
    return this.synth !== null;
  }

  start(steps: AttackExplanationStep[], onStepChange: (step: number) => void, onEnd: () => void) {
    this.stop();
    this.steps = steps;
    this.currentStep = 0;
    this.onStepChange = onStepChange;
    this.onEnd = onEnd;
    this.speakStep(0);
  }

  private speakStep(index: number) {
    if (!this.synth || index >= this.steps.length) {
      this.onEnd?.();
      return;
    }
    this.currentStep = index;
    this.onStepChange?.(index);
    const step = this.steps[index];
    this.utterance = new SpeechSynthesisUtterance(step.narration);
    this.utterance.rate = 0.95;
    this.utterance.pitch = 1;
    this.utterance.volume = 1;

    // Try to use a good voice
    const voices = this.synth.getVoices();
    const preferred = voices.find((v) => v.lang.startsWith('en') && v.name.includes('Google')) || voices.find((v) => v.lang.startsWith('en'));
    if (preferred) this.utterance.voice = preferred;

    this.utterance.onend = () => {
      if (!this.paused && this.currentStep === index) {
        setTimeout(() => this.speakStep(index + 1), 500);
      }
    };

    this.synth.speak(this.utterance);
  }

  pause() {
    if (this.synth) {
      this.synth.pause();
      this.paused = true;
    }
  }

  resume() {
    if (this.synth) {
      this.synth.resume();
      this.paused = false;
    }
  }

  stop() {
    if (this.synth) {
      this.synth.cancel();
    }
    this.paused = false;
    this.currentStep = 0;
  }

  next() {
    if (this.currentStep < this.steps.length - 1) {
      this.speakStep(this.currentStep + 1);
    }
  }

  prev() {
    if (this.currentStep > 0) {
      this.speakStep(this.currentStep - 1);
    }
  }

  get currentStepIndex(): number {
    return this.currentStep;
  }

  get isPlaying(): boolean {
    return this.synth?.speaking === true && !this.paused;
  }
}

// Get available explanations for the UI selector
export function getAvailableExplanations(): { id: string; name: string; mitre: string }[] {
  return ATTACK_CHAINS.map((c) => ({
    id: c.id,
    name: c.name,
    mitre: c.stages[0]?.mitre || 'T1059.001',
  }));
}
