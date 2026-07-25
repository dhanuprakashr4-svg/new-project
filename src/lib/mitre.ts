import type { MitreTechnique } from './types';

// Curated MITRE ATT&CK techniques relevant to the SOC detection scenarios
export const MITRE_TECHNIQUES: Record<string, MitreTechnique> = {
  'T1059.001': {
    id: 'T1059.001',
    name: 'PowerShell',
    tactic: 'Execution',
    description:
      'Adversaries may abuse PowerShell commands and scripts for execution. PowerShell is a powerful interactive command-line interface and scripting environment.',
    severity: 'high',
    subtechnique: true,
    parent: 'T1059',
  },
  T1059: {
    id: 'T1059',
    name: 'Command and Scripting Interpreter',
    tactic: 'Execution',
    description:
      'Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.',
    severity: 'high',
  },
  T1003: {
    id: 'T1003',
    name: 'OS Credential Dumping',
    tactic: 'Credential Access',
    description:
      'Adversaries may attempt to dump credentials from memory or disk to access account credentials.',
    severity: 'critical',
  },
  'T1003.001': {
    id: 'T1003.001',
    name: 'LSASS Memory',
    tactic: 'Credential Access',
    description:
      'Adversaries may attempt to access credential material stored in the LSASS process memory.',
    severity: 'critical',
    subtechnique: true,
    parent: 'T1003',
  },
  T1053: {
    id: 'T1053',
    name: 'Scheduled Task/Job',
    tactic: 'Execution',
    description:
      'Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code.',
    severity: 'high',
  },
  'T1053.005': {
    id: 'T1053.005',
    name: 'Scheduled Task',
    tactic: 'Execution',
    description: 'Adversaries may abuse the schtasks utility to create scheduled tasks.',
    severity: 'high',
    subtechnique: true,
    parent: 'T1053',
  },
  T1550: {
    id: 'T1550',
    name: 'Use Alternate Authentication Material',
    tactic: 'Defense Evasion, Lateral Movement',
    description:
      'Adversaries may use alternate authentication material to move laterally without needing the plaintext password.',
    severity: 'critical',
  },
  'T1550.002': {
    id: 'T1550.002',
    name: 'Pass the Hash',
    tactic: 'Defense Evasion, Lateral Movement',
    description:
      'Adversaries may use Pass the Hash to authenticate with a password hash instead of plaintext.',
    severity: 'critical',
    subtechnique: true,
    parent: 'T1550',
  },
  T1190: {
    id: 'T1190',
    name: 'Exploit Public-Facing Application',
    tactic: 'Initial Access',
    description:
      'Adversaries may attempt to exploit a weakness in an internet-facing host or system to initiate initial access.',
    severity: 'critical',
  },
  T1078: {
    id: 'T1078',
    name: 'Valid Accounts',
    tactic: 'Defense Evasion, Persistence, Privilege Escalation, Initial Access',
    description:
      'Adversaries may use credentials of existing accounts to gain access, persist, or escalate privileges.',
    severity: 'high',
  },
  T1021: {
    id: 'T1021',
    name: 'Remote Services',
    tactic: 'Lateral Movement',
    description: 'Adversaries may use remote services to move laterally across a network.',
    severity: 'high',
  },
  T1047: {
    id: 'T1047',
    name: 'Windows Management Instrumentation',
    tactic: 'Execution',
    description:
      'Adversaries may abuse WMI to achieve local and remote execution and lateral movement.',
    severity: 'medium',
  },
  T1547: {
    id: 'T1547',
    name: 'Boot or Logon Autostart Execution',
    tactic: 'Persistence, Privilege Escalation',
    description: 'Adversaries may configure system settings to execute programs at boot or logon.',
    severity: 'high',
  },
};

export const MITRE_LIST = Object.values(MITRE_TECHNIQUES);

export const TACTICS = [
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'Command and Control',
  'Exfiltration',
  'Impact',
];

export function getMitre(id: string): MitreTechnique | undefined {
  return MITRE_TECHNIQUES[id];
}

export function severityColor(sev: string): string {
  switch (sev) {
    case 'critical':
      return 'text-threat-400 bg-threat-500/15 border-threat-500/40';
    case 'high':
      return 'text-orange-400 bg-orange-500/15 border-orange-500/40';
    case 'medium':
      return 'text-alert-400 bg-alert-500/15 border-alert-500/40';
    case 'low':
      return 'text-cyber-400 bg-cyber-500/15 border-cyber-500/40';
    default:
      return 'text-soc-400 bg-soc-700/40 border-soc-600';
  }
}
