import { NavLink, useLocation } from 'react-router-dom';
import { type LucideIcon } from 'lucide-react';
import {
  LayoutDashboard,
  FlaskConical,
  GraduationCap,
  Bot,
  Brain,
  Network,
  MessageSquare,
  Radar,
  ShieldCheck,
  Lock,
  FileWarning,
  Cpu,
  Bug,
  Activity,
} from 'lucide-react';

interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
  group: string;
  badge?: string;
}

const NAV: NavItem[] = [
  { to: '/', label: 'Command Dashboard', icon: LayoutDashboard, group: 'Operations' },
  { to: '/threat-detection', label: 'AI Threat Detection', icon: Radar, group: 'Operations' },
  { to: '/attack-viz', label: 'Attack Visualization', icon: Activity, group: 'Operations', badge: 'New' },
  { to: '/honeypot', label: 'Honeypot Defense', icon: Bug, group: 'Operations', badge: 'New' },
  { to: '/incidents', label: 'Incident Investigation', icon: FileWarning, group: 'Operations' },

  { to: '/lab', label: 'Sigma Detection Lab', icon: FlaskConical, group: 'Detection Engineering', badge: 'Core' },
  { to: '/academy', label: 'Detection Academy', icon: GraduationCap, group: 'Detection Engineering' },

  { to: '/ai-assistant', label: 'AI Sigma Assistant', icon: Bot, group: 'AI Intelligence' },
  { to: '/explainability', label: 'Explainable AI (SHAP)', icon: Brain, group: 'AI Intelligence' },
  { to: '/mitre', label: 'MITRE ATT&CK Intel', icon: Network, group: 'AI Intelligence' },
  { to: '/copilot', label: 'AI SOC Copilot', icon: MessageSquare, group: 'AI Intelligence' },

  { to: '/evidence', label: 'Evidence Vault', icon: ShieldCheck, group: 'Security & Forensics' },
  { to: '/voxcrypt', label: 'VoxCrypt Secure Comms', icon: Lock, group: 'Security & Forensics', badge: 'Ext' },
];

const GROUPS = ['Operations', 'Detection Engineering', 'AI Intelligence', 'Security & Forensics'];

export function Sidebar() {
  const location = useLocation();

  return (
    <aside className="w-64 shrink-0 h-screen sticky top-0 glass border-r border-soc-700/60 flex flex-col">
      {/* Logo */}
      <div className="px-5 py-5 border-b border-soc-700/60">
        <div className="flex items-center gap-3">
          <div className="relative">
            <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-cyber-500 to-cyber-800 flex items-center justify-center shadow-glow">
              <Cpu className="w-6 h-6 text-white" />
            </div>
            <span className="absolute -top-1 -right-1 w-3 h-3 bg-secure-500 rounded-full ring-2 ring-soc-900 animate-pulse-slow" />
          </div>
          <div>
            <h1 className="text-sm font-bold text-soc-50 leading-tight">
              ThreatZero <span className="text-gradient-cyber">Sentinel X</span>
            </h1>
            <p className="text-[10px] text-soc-500 uppercase tracking-widest">SOC Intelligence</p>
          </div>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 overflow-y-auto px-3 py-4 space-y-5">
        {GROUPS.map((group) => (
          <div key={group}>
            <p className="text-[10px] uppercase tracking-widest text-soc-600 font-semibold px-3 mb-2">{group}</p>
            <div className="space-y-0.5">
              {NAV.filter((n) => n.group === group).map((item) => {
                const active = location.pathname === item.to;
                return (
                  <NavLink
                    key={item.to}
                    to={item.to}
                    className={`flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-all duration-200 group ${
                      active
                        ? 'bg-cyber-500/15 text-cyber-300 border border-cyber-500/30 shadow-glow'
                        : 'text-soc-400 hover:text-soc-100 hover:bg-soc-800/60 border border-transparent'
                    }`}
                  >
                    <item.icon className={`w-4 h-4 ${active ? 'text-cyber-400' : 'text-soc-500 group-hover:text-soc-300'}`} />
                    <span className="flex-1 font-medium">{item.label}</span>
                    {item.badge && (
                      <span className="text-[9px] px-1.5 py-0.5 rounded bg-cyber-500/20 text-cyber-400 font-semibold uppercase">
                        {item.badge}
                      </span>
                    )}
                  </NavLink>
                );
              })}
            </div>
          </div>
        ))}
      </nav>

      {/* Status footer */}
      <div className="px-4 py-3 border-t border-soc-700/60">
        <div className="flex items-center justify-between text-xs">
          <span className="text-soc-500">Engine Status</span>
          <span className="flex items-center gap-1.5 text-secure-400">
            <span className="status-dot bg-secure-500 animate-pulse" />
            Online
          </span>
        </div>
      </div>
    </aside>
  );
}
