import { useEffect, useState } from 'react';
import { useLocation } from 'react-router-dom';
import { ShieldAlert, Activity, Clock } from 'lucide-react';

const TITLES: Record<string, string> = {
  '/': 'SOC Command Dashboard',
  '/threat-detection': 'AI Threat Detection Engine',
  '/attack-viz': 'Attack Visualization — Kill Chain Analysis',
  '/attack-explain': 'Audio/Video Attack Explanation',
  '/honeypot': 'Honeypot Deception Defense',
  '/detection-metrics': 'Detection Metrics & Confusion Matrix',
  '/incidents': 'Incident Investigation',
  '/lab': 'Sigma Detection Lab',
  '/academy': 'ThreatZero Detection Academy',
  '/ai-assistant': 'AI Sigma Assistant',
  '/explainability': 'Explainable AI - SHAP Dashboard',
  '/mitre': 'MITRE ATT&CK Intelligence',
  '/copilot': 'AI SOC Copilot',
  '/evidence': 'Evidence Vault — Cipher Reports',
  '/voxcrypt': 'VoxCrypt — Secure Audio Steganography',
};

export function Topbar() {
  const location = useLocation();
  const title = TITLES[location.pathname] || 'ThreatZero Sentinel X';
  const [time, setTime] = useState(new Date());

  useEffect(() => {
    const t = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  return (
    <header className="sticky top-0 z-30 glass border-b border-soc-700/60 px-6 py-3 flex items-center justify-between">
      <div className="flex items-center gap-3">
        <h2 className="text-lg font-semibold text-soc-50">{title}</h2>
        <span className="threat-badge bg-threat-500/15 text-threat-300 border border-threat-500/40">
          <ShieldAlert className="w-3 h-3" />
          DEFCON 3
        </span>
      </div>
      <div className="flex items-center gap-5">
        <div className="hidden md:flex items-center gap-2 text-xs text-soc-400">
          <Activity className="w-3.5 h-3.5 text-secure-400" />
          <span>ML Ensemble Active</span>
        </div>
        <div className="flex items-center gap-2 text-xs text-soc-400 font-mono">
          <Clock className="w-3.5 h-3.5 text-cyber-400" />
          {time.toISOString().slice(0, 19).replace('T', ' ')} UTC
        </div>
      </div>
    </header>
  );
}
