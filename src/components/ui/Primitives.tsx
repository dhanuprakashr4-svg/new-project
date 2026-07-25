import { type ReactNode } from 'react';
import { type LucideIcon } from 'lucide-react';

// ===== Shared SOC UI primitives =====

export function Panel({
  children,
  className = '',
  title,
  icon: Icon,
  action,
}: {
  children: ReactNode;
  className?: string;
  title?: string;
  icon?: LucideIcon;
  action?: ReactNode;
}) {
  return (
    <div className={`glass-panel ${className}`}>
      {title && (
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-soc-700/60">
          <div className="flex items-center gap-2.5">
            {Icon && <Icon className="w-4 h-4 text-cyber-400" />}
            <h3 className="text-sm font-semibold text-soc-100 tracking-wide uppercase">{title}</h3>
          </div>
          {action}
        </div>
      )}
      <div className="p-5">{children}</div>
    </div>
  );
}

export function MetricTile({
  label,
  value,
  icon: Icon,
  trend,
  trendUp,
  accent = 'cyber',
}: {
  label: string;
  value: string | number;
  icon: LucideIcon;
  trend?: string;
  trendUp?: boolean;
  accent?: 'cyber' | 'threat' | 'secure' | 'alert';
}) {
  const accents: Record<string, string> = {
    cyber: 'text-cyber-400 bg-cyber-500/10 border-cyber-500/30',
    threat: 'text-threat-400 bg-threat-500/10 border-threat-500/30',
    secure: 'text-secure-400 bg-secure-500/10 border-secure-500/30',
    alert: 'text-alert-400 bg-alert-500/10 border-alert-500/30',
  };
  return (
    <div className="glass-panel p-4 glass-hover group">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs text-soc-400 uppercase tracking-wider font-medium">{label}</p>
          <p className="text-2xl font-bold text-soc-50 mt-1.5 font-mono">{value}</p>
        </div>
        <div className={`p-2 rounded-lg border ${accents[accent]} transition-transform group-hover:scale-110`}>
          <Icon className="w-5 h-5" />
        </div>
      </div>
      {trend && (
        <p className={`text-xs mt-2 flex items-center gap-1 ${trendUp ? 'text-secure-400' : 'text-threat-400'}`}>
          {trendUp ? '▲' : '▼'} {trend}
        </p>
      )}
    </div>
  );
}

export function ThreatBadge({ level, label }: { level: 'critical' | 'high' | 'medium' | 'low' | 'info'; label?: string }) {
  const styles: Record<string, string> = {
    critical: 'text-threat-300 bg-threat-500/20 border-threat-500/50',
    high: 'text-orange-300 bg-orange-500/20 border-orange-500/50',
    medium: 'text-alert-300 bg-alert-500/20 border-alert-500/50',
    low: 'text-cyber-300 bg-cyber-500/20 border-cyber-500/50',
    info: 'text-soc-300 bg-soc-600/30 border-soc-500/50',
  };
  return (
    <span className={`threat-badge border ${styles[level]}`}>
      <span className={`status-dot bg-current`} />
      {label || level}
    </span>
  );
}

export function StatusPill({ status }: { status: string }) {
  const map: Record<string, { color: string; label: string }> = {
    open: { color: 'text-threat-400 bg-threat-500/15', label: 'Open' },
    investigating: { color: 'text-alert-400 bg-alert-500/15', label: 'Investigating' },
    contained: { color: 'text-cyber-400 bg-cyber-500/15', label: 'Contained' },
    resolved: { color: 'text-secure-400 bg-secure-500/15', label: 'Resolved' },
    packaged: { color: 'text-cyber-400 bg-cyber-500/15', label: 'Packaged' },
    transferred: { color: 'text-secure-400 bg-secure-500/15', label: 'Transferred' },
    received: { color: 'text-secure-400 bg-secure-500/15', label: 'Received' },
  };
  const s = map[status] || { color: 'text-soc-400 bg-soc-700/40', label: status };
  return (
    <span className={`threat-badge ${s.color}`}>
      <span className="status-dot bg-current" />
      {s.label}
    </span>
  );
}

export function ScoreRing({ score, max = 100, label, size = 120 }: { score: number; max?: number; label: string; size?: number }) {
  const pct = Math.min(1, score / max);
  const radius = size / 2 - 10;
  const circ = 2 * Math.PI * radius;
  const offset = circ * (1 - pct);
  const color = score > 70 ? '#f5222d' : score > 40 ? '#faad14' : '#1890ff';
  return (
    <div className="flex flex-col items-center gap-2">
      <div className="relative" style={{ width: size, height: size }}>
        <svg width={size} height={size} className="-rotate-90">
          <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke="#1e293b" strokeWidth="8" />
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke={color}
            strokeWidth="8"
            strokeDasharray={circ}
            strokeDashoffset={offset}
            strokeLinecap="round"
            style={{ transition: 'stroke-dashoffset 0.8s ease' }}
          />
        </svg>
        <div className="absolute inset-0 flex items-center justify-center">
          <span className="text-2xl font-bold font-mono" style={{ color }}>{score}</span>
        </div>
      </div>
      <span className="text-xs text-soc-400 uppercase tracking-wider">{label}</span>
    </div>
  );
}

export function Loader({ label }: { label?: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-12 gap-3">
      <div className="w-10 h-10 border-2 border-cyber-500/30 border-t-cyber-500 rounded-full animate-spin" />
      {label && <p className="text-sm text-soc-400">{label}</p>}
    </div>
  );
}

export function EmptyState({ icon: Icon, title, hint }: { icon: LucideIcon; title: string; hint?: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-12 text-center">
      <Icon className="w-10 h-10 text-soc-600 mb-3" />
      <p className="text-sm font-medium text-soc-300">{title}</p>
      {hint && <p className="text-xs text-soc-500 mt-1 max-w-xs">{hint}</p>}
    </div>
  );
}
