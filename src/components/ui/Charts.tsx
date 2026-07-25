import {
  ResponsiveContainer,
  AreaChart,
  Area,
  LineChart,
  Line,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  RadarChart,
  Radar,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
} from 'recharts';

// ===== Shared SOC chart components =====

const tooltipStyle = {
  backgroundColor: 'rgba(8, 13, 26, 0.95)',
  border: '1px solid rgba(51, 65, 85, 0.8)',
  borderRadius: '8px',
  fontSize: '12px',
  color: '#e2e8f0',
  backdropFilter: 'blur(8px)',
};

const CYBER = '#1890ff';
const THREAT = '#f5222d';
const SECURE = '#52c41a';
const ALERT = '#faad14';
const ORANGE = '#fa8c16';

export function DetectionPerformanceChart({ data }: { data: { name: string; precision: number; recall: number; fpr: number }[] }) {
  return (
    <ResponsiveContainer width="100%" height={240}>
      <AreaChart data={data} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
        <defs>
          <linearGradient id="precGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={CYBER} stopOpacity={0.4} />
            <stop offset="100%" stopColor={CYBER} stopOpacity={0} />
          </linearGradient>
          <linearGradient id="recallGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={SECURE} stopOpacity={0.4} />
            <stop offset="100%" stopColor={SECURE} stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
        <XAxis dataKey="name" stroke="#64748b" fontSize={11} />
        <YAxis stroke="#64748b" fontSize={11} domain={[0, 1]} tickFormatter={(v) => `${Math.round(v * 100)}%`} />
        <Tooltip contentStyle={tooltipStyle} />
        <Legend wrapperStyle={{ fontSize: 11 }} />
        <Area type="monotone" dataKey="precision" name="Precision" stroke={CYBER} fill="url(#precGrad)" strokeWidth={2} />
        <Area type="monotone" dataKey="recall" name="Recall" stroke={SECURE} fill="url(#recallGrad)" strokeWidth={2} />
      </AreaChart>
    </ResponsiveContainer>
  );
}

export function AttackCategoriesChart({ data }: { data: { name: string; value: number }[] }) {
  const colors = [THREAT, ORANGE, ALERT, CYBER, SECURE, '#722ed1'];
  return (
    <ResponsiveContainer width="100%" height={240}>
      <PieChart>
        <Pie data={data} dataKey="value" nameKey="name" cx="50%" cy="50%" innerRadius={55} outerRadius={90} paddingAngle={3}>
          {data.map((_, i) => (
            <Cell key={i} fill={colors[i % colors.length]} stroke="#0f172a" strokeWidth={2} />
          ))}
        </Pie>
        <Tooltip contentStyle={tooltipStyle} />
        <Legend wrapperStyle={{ fontSize: 11 }} />
      </PieChart>
    </ResponsiveContainer>
  );
}

export function MitreHeatmapChart({ data }: { data: { tactic: string; coverage: number }[] }) {
  return (
    <ResponsiveContainer width="100%" height={260}>
      <BarChart data={data} layout="vertical" margin={{ top: 8, right: 16, left: 60, bottom: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
        <XAxis type="number" stroke="#64748b" fontSize={10} domain={[0, 100]} tickFormatter={(v) => `${v}%`} />
        <YAxis type="category" dataKey="tactic" stroke="#64748b" fontSize={10} width={100} />
        <Tooltip contentStyle={tooltipStyle} cursor={{ fill: 'rgba(24,144,255,0.08)' }} />
        <Bar dataKey="coverage" name="Coverage" radius={[0, 4, 4, 0]}>
          {data.map((d, i) => (
            <Cell key={i} fill={d.coverage > 66 ? SECURE : d.coverage > 33 ? ALERT : THREAT} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

export function ChallengeScoresChart({ data }: { data: { name: string; score: number }[] }) {
  return (
    <ResponsiveContainer width="100%" height={240}>
      <BarChart data={data} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
        <XAxis dataKey="name" stroke="#64748b" fontSize={10} />
        <YAxis stroke="#64748b" fontSize={11} domain={[0, 100]} />
        <Tooltip contentStyle={tooltipStyle} cursor={{ fill: 'rgba(24,144,255,0.08)' }} />
        <Bar dataKey="score" name="Score" radius={[4, 4, 0, 0]}>
          {data.map((d, i) => (
            <Cell key={i} fill={d.score >= 80 ? SECURE : d.score >= 50 ? ALERT : THREAT} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

export function ShapRadarChart({ data }: { data: { feature: string; contribution: number }[] }) {
  return (
    <ResponsiveContainer width="100%" height={260}>
      <RadarChart data={data} cx="50%" cy="50%" outerRadius="75%">
        <PolarGrid stroke="#1e293b" />
        <PolarAngleAxis dataKey="feature" stroke="#64748b" fontSize={10} />
        <PolarRadiusAxis stroke="#334155" fontSize={9} angle={90} domain={[0, 50]} />
        <Radar name="Contribution" dataKey="contribution" stroke={CYBER} fill={CYBER} fillOpacity={0.35} strokeWidth={2} />
        <Tooltip contentStyle={tooltipStyle} />
      </RadarChart>
    </ResponsiveContainer>
  );
}

export function ShapBarChart({ data }: { data: { feature: string; contribution: number; description: string }[] }) {
  const colors = [THREAT, ORANGE, ALERT, CYBER, SECURE, '#722ed1'];
  return (
    <div className="space-y-3">
      {data.map((d, i) => (
        <div key={i}>
          <div className="flex items-center justify-between text-xs mb-1">
            <span className="text-soc-200 font-medium">{d.feature}</span>
            <span className="font-mono text-soc-400">{d.contribution}%</span>
          </div>
          <div className="h-2.5 bg-soc-800 rounded-full overflow-hidden">
            <div
              className="h-full rounded-full transition-all duration-700 ease-out"
              style={{ width: `${d.contribution}%`, backgroundColor: colors[i % colors.length] }}
            />
          </div>
          <p className="text-[10px] text-soc-500 mt-1">{d.description}</p>
        </div>
      ))}
    </div>
  );
}

export function TrendLineChart({ data, dataKey = 'value', color = CYBER, name }: { data: Record<string, string | number>[]; dataKey?: string; color?: string; name?: string }) {
  return (
    <ResponsiveContainer width="100%" height={200}>
      <LineChart data={data} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
        <XAxis dataKey="name" stroke="#64748b" fontSize={11} />
        <YAxis stroke="#64748b" fontSize={11} />
        <Tooltip contentStyle={tooltipStyle} />
        <Line type="monotone" dataKey={dataKey} name={name} stroke={color} strokeWidth={2} dot={{ fill: color, r: 3 }} activeDot={{ r: 5 }} />
      </LineChart>
    </ResponsiveContainer>
  );
}
