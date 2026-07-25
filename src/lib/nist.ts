// ===== NIST Cybersecurity Framework (CSF) =====
// Maps MITRE ATT&CK techniques to NIST CSF functions for compliance
// reporting and defensive coverage visualization.

export type NistFunction = 'Identify' | 'Protect' | 'Detect' | 'Respond' | 'Recover';

export interface NistCategory {
  function: NistFunction;
  category: string;
  subcategory: string;
  description: string;
}

export interface NistMapping {
  mitreId: string;
  nistFunctions: NistFunction[];
  primaryFunction: NistFunction;
  categories: string[];
  defensiveActions: string[];
}

// NIST CSF Function colors for visualization
export const NIST_COLORS: Record<NistFunction, string> = {
  Identify: '#1890ff',
  Protect: '#52c41a',
  Detect: '#faad14',
  Respond: '#f5222d',
  Recover: '#722ed1',
};

// MITRE → NIST CSF mapping
export const NIST_MAPPINGS: Record<string, NistMapping> = {
  'T1059.001': {
    mitreId: 'T1059.001',
    nistFunctions: ['Detect', 'Respond', 'Protect'],
    primaryFunction: 'Detect',
    categories: ['DE.AE-2: Detection events analyzed', 'DE.AE-3: Collection performed', 'PR.IP-12: IPS implemented'],
    defensiveActions: [
      'Monitor PowerShell execution with encoded commands via EDR/Sysmon',
      'Implement PowerShell Constrained Language Mode and Script Block Logging',
      'Block PowerShell execution from Office applications via AppLocker/WDAC',
      'Restrict PowerShell execution to signed scripts only',
    ],
  },
  T1003: {
    mitreId: 'T1003',
    nistFunctions: ['Detect', 'Respond', 'Protect', 'Recover'],
    primaryFunction: 'Respond',
    categories: ['DE.AE-2: Detection events analyzed', 'RS.AN-1: Notifications from detection systems', 'PR.AC-1: Identity and credential management'],
    defensiveActions: [
      'Enable LSASS protection (RunAsPPL) and configure credential guard',
      'Monitor for LSASS access via Sysmon Event ID 10 and EDR',
      'Isolate compromised host and force credential reset for affected accounts',
      'Deploy LSA Protection and Windows Defender Credential Guard',
    ],
  },
  'T1003.001': {
    mitreId: 'T1003.001',
    nistFunctions: ['Detect', 'Respond', 'Protect', 'Recover'],
    primaryFunction: 'Respond',
    categories: ['DE.AE-2: Detection events analyzed', 'RS.AN-1: Notifications from detection systems', 'PR.AC-1: Identity and credential management'],
    defensiveActions: [
      'Enable LSASS protection (RunAsPPL) and configure credential guard',
      'Monitor for LSASS access via Sysmon Event ID 10 and EDR',
      'Isolate compromised host and force credential reset for affected accounts',
      'Deploy LSA Protection and Windows Defender Credential Guard',
    ],
  },
  T1053: {
    mitreId: 'T1053',
    nistFunctions: ['Detect', 'Protect', 'Respond'],
    primaryFunction: 'Detect',
    categories: ['DE.AE-2: Detection events analyzed', 'PR.IP-1: Baselines established', 'DE.CM-1: Network monitored'],
    defensiveActions: [
      'Monitor scheduled task creation via EID 4698 and schtasks.exe',
      'Restrict task creation privileges via Group Policy',
      'Audit scheduled tasks for suspicious actions and unknown task names',
      'Implement EDR rules to alert on task actions executing scripts',
    ],
  },
  'T1053.005': {
    mitreId: 'T1053.005',
    nistFunctions: ['Detect', 'Protect', 'Respond'],
    primaryFunction: 'Detect',
    categories: ['DE.AE-2: Detection events analyzed', 'PR.IP-1: Baselines established', 'DE.CM-1: Network monitored'],
    defensiveActions: [
      'Monitor scheduled task creation via EID 4698 and schtasks.exe',
      'Restrict task creation privileges via Group Policy',
      'Audit scheduled tasks for suspicious actions and unknown task names',
      'Implement EDR rules to alert on task actions executing scripts',
    ],
  },
  T1550: {
    mitreId: 'T1550',
    nistFunctions: ['Detect', 'Respond', 'Protect'],
    primaryFunction: 'Detect',
    categories: ['DE.AE-2: Detection events analyzed', 'DE.CM-3: Personnel activity monitored', 'PR.AC-1: Identity and credential management'],
    defensiveActions: [
      'Monitor NTLM authentication events and flag successful network logons',
      'Disable NTLM where possible and enforce Kerberos with account confinement',
      'Implement lateral movement detection via EDR and network analytics',
      'Deploy Microsoft Local Admin Password Solution (LAPS) for unique local passwords',
    ],
  },
  'T1550.002': {
    mitreId: 'T1550.002',
    nistFunctions: ['Detect', 'Respond', 'Protect'],
    primaryFunction: 'Detect',
    categories: ['DE.AE-2: Detection events analyzed', 'DE.CM-3: Personnel activity monitored', 'PR.AC-1: Identity and credential management'],
    defensiveActions: [
      'Monitor NTLM authentication events and flag successful network logons',
      'Disable NTLM where possible and enforce Kerberos with account confinement',
      'Implement lateral movement detection via EDR and network analytics',
      'Deploy Microsoft Local Admin Password Solution (LAPS) for unique local passwords',
    ],
  },
  T1190: {
    mitreId: 'T1190',
    nistFunctions: ['Detect', 'Protect', 'Respond', 'Recover'],
    primaryFunction: 'Detect',
    categories: ['DE.AE-1: A baseline of network operations is established', 'PR.DS-1: Data-at-rest protected', 'RS.AN-1: Notifications from detection systems'],
    defensiveActions: [
      'Deploy WAF rules to block SQL injection and command injection signatures',
      'Parameterized queries and input validation on all web endpoints',
      'Monitor web access logs for injection patterns (OR 1=1, UNION SELECT, sqlmap)',
      'Apply patches to vulnerable web applications and conduct regular pen testing',
    ],
  },
  T1078: {
    mitreId: 'T1078',
    nistFunctions: ['Detect', 'Respond', 'Protect', 'Identify'],
    primaryFunction: 'Identify',
    categories: ['ID.AM-1: Physical and software assets inventoried', 'PR.AC-1: Identity and credential management', 'DE.AE-2: Detection events analyzed'],
    defensiveActions: [
      'Implement MFA for all remote access and privileged accounts',
      'Monitor for anomalous logon patterns and impossible travel scenarios',
      'Enforce strong password policies and regular credential rotation',
      'Conduct regular access reviews and de-provision inactive accounts',
    ],
  },
  T1047: {
    mitreId: 'T1047',
    nistFunctions: ['Detect', 'Protect', 'Respond'],
    primaryFunction: 'Detect',
    categories: ['DE.AE-2: Detection events analyzed', 'DE.CM-1: Network monitored', 'PR.IP-12: IPS implemented'],
    defensiveActions: [
      'Monitor WMI activity via Sysmon and EDR for suspicious remote execution',
      'Restrict WMI remote access to administrative accounts only',
      'Block WMI over network (port 135) from untrusted hosts',
      'Enable WMI auditing and event logging',
    ],
  },
  T1547: {
    mitreId: 'T1547',
    nistFunctions: ['Detect', 'Protect', 'Respond'],
    primaryFunction: 'Detect',
    categories: ['DE.AE-2: Detection events analyzed', 'PR.IP-1: Baselines established', 'DE.CM-7: Monitoring for unauthorized personnel'],
    defensiveActions: [
      'Monitor for autostart registry modifications and startup folder changes',
      'Implement AppLocker/WDAC to restrict executable execution from startup locations',
      'Audit service installations and registry Run keys',
      'Deploy EDR rules to alert on persistence mechanisms',
    ],
  },
};

export const NIST_FUNCTIONS: { name: NistFunction; description: string; color: string }[] = [
  { name: 'Identify', description: 'Develop organizational understanding to manage cybersecurity risk', color: NIST_COLORS.Identify },
  { name: 'Protect', description: 'Develop and implement safeguards to ensure delivery of services', color: NIST_COLORS.Protect },
  { name: 'Detect', description: 'Develop and implement activities to identify cybersecurity events', color: NIST_COLORS.Detect },
  { name: 'Respond', description: 'Take action regarding a detected cybersecurity incident', color: NIST_COLORS.Respond },
  { name: 'Recover', description: 'Maintain plans for resilience and restore capabilities impaired by incident', color: NIST_COLORS.Recover },
];

export function getNistMapping(mitreId: string): NistMapping | undefined {
  // Try exact match, then parent technique
  if (NIST_MAPPINGS[mitreId]) return NIST_MAPPINGS[mitreId];
  const parent = mitreId.split('.')[0];
  return NIST_MAPPINGS[parent];
}

export function getAllNistMappings(): NistMapping[] {
  return Object.values(NIST_MAPPINGS);
}
