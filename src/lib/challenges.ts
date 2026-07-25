import type { Challenge } from './types';
import { suggestSigmaRule } from './aiAssistant';

// ===== Detection Academy Challenges =====
// 5 MITRE-mapped SOC training challenges. Each has a starter rule the analyst
// improves, a target metric profile, and a known-good solution.

export const CHALLENGES: Challenge[] = [
  {
    id: 'ch1',
    name: 'Encoded PowerShell Detection',
    mitre: 'T1059.001',
    tactic: 'Execution',
    difficulty: 'Recruit',
    briefing:
      'Adversaries use encoded PowerShell commands to hide malicious payloads from simple string-based detections. Your mission: write a Sigma rule that catches encoded PowerShell execution while avoiding benign administrative scripts.',
    datasetId: 'sysmon-proc',
    starterRule: `title: Encoded PowerShell Detection
status: experimental
level: high
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\\\powershell.exe'
  condition: selection
falsepositives:
  - Administrative scripts
tags:
  - attack.execution
  - attack.t1059.001`,
    targetPrecision: 0.6,
    targetRecall: 1.0,
    targetFpr: 0.0,
    hint: 'Look for -EncodedCommand or -enc in the CommandLine. Add a filter selection for benign Get-Process / Get-Service calls.',
    solutionRule: suggestSigmaRule('T1059.001'),
  },
  {
    id: 'ch2',
    name: 'LSASS Credential Access',
    mitre: 'T1003',
    tactic: 'Credential Access',
    difficulty: 'Analyst',
    briefing:
      'Credential dumping tools target the LSASS process to extract passwords and hashes from memory. Build a Sigma rule that detects known credential-access tooling and LSASS-targeting command lines.',
    datasetId: 'sysmon-proc',
    starterRule: `title: LSASS Credential Access
status: experimental
level: critical
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains: 'lsass'
  condition: selection
tags:
  - attack.credential_access
  - attack.t1003`,
    targetPrecision: 0.5,
    targetRecall: 1.0,
    targetFpr: 0.0,
    hint: 'Match on mimikatz.exe and procdump.exe Image names, plus command lines containing sekurlsa or logonpasswords.',
    solutionRule: suggestSigmaRule('T1003.001'),
  },
  {
    id: 'ch3',
    name: 'Scheduled Task Creation',
    mitre: 'T1053',
    tactic: 'Execution / Persistence',
    difficulty: 'Analyst',
    briefing:
      'Attackers create scheduled tasks for persistence and recurring execution. Distinguish malicious task creation (running scripts/binaries) from legitimate OS maintenance tasks.',
    datasetId: 'win-4698',
    starterRule: `title: Suspicious Scheduled Task
status: experimental
level: high
logsource:
  category: scheduled_task
  product: windows
detection:
  selection:
    EventID: 4698
  condition: selection
tags:
  - attack.execution
  - attack.t1053`,
    targetPrecision: 0.66,
    targetRecall: 1.0,
    targetFpr: 0.0,
    hint: 'Filter out TaskName containing Microsoft, Defrag, or Update. Flag TaskAction containing powershell, .bat, or .exe.',
    solutionRule: suggestSigmaRule('T1053.005'),
  },
  {
    id: 'ch4',
    name: 'Pass The Hash',
    mitre: 'T1550',
    tactic: 'Lateral Movement',
    difficulty: 'Hunter',
    briefing:
      'Pass the Hash lets attackers authenticate using NTLM password hashes without knowing the plaintext password. Detect successful NTLM network logons that may indicate PtH lateral movement.',
    datasetId: 'win-4624',
    starterRule: `title: Pass the Hash Detection
status: experimental
level: critical
logsource:
  category: authentication
  product: windows
detection:
  selection:
    EventID: 4624
  condition: selection
tags:
  - attack.lateral_movement
  - attack.t1550.002`,
    targetPrecision: 0.5,
    targetRecall: 1.0,
    targetFpr: 0.0,
    hint: 'Select EventID 4624 with LogonType 3, AuthenticationPackageName NTLM, and Status Success. Benign Kerberos logons should not match.',
    solutionRule: suggestSigmaRule('T1550.002'),
  },
  {
    id: 'ch5',
    name: 'SQL Injection',
    mitre: 'T1190',
    tactic: 'Initial Access',
    difficulty: 'Specialist',
    briefing:
      'SQL and command injection remain top initial-access vectors. Detect malicious patterns in HTTP requests - classic SQLi syntax, command chaining, and known scanner user agents.',
    datasetId: 'web-access',
    starterRule: `title: SQL Injection Detection
status: experimental
level: critical
logsource:
  category: web_access
  product: web
detection:
  selection:
    URL|contains: "'"
  condition: selection
tags:
  - attack.initial_access
  - attack.t1190`,
    targetPrecision: 0.6,
    targetRecall: 1.0,
    targetFpr: 0.0,
    hint: 'Look for OR 1=1, UNION SELECT, --, sqlmap user agent, and command injection (;wget, ;cat). Combine selections with OR.',
    solutionRule: suggestSigmaRule('T1190'),
  },
];

export function getChallenge(id: string): Challenge | undefined {
  return CHALLENGES.find((c) => c.id === id);
}

// Score: weighted blend of precision, recall, and false positive rate.
// Perfect score = 100 (precision 1, recall 1, fpr 0).
export function scoreChallenge(precision: number, recall: number, fpr: number): number {
  const precisionScore = precision * 40;
  const recallScore = recall * 40;
  const fprScore = (1 - Math.min(fpr, 1)) * 20;
  return Math.round(precisionScore + recallScore + fprScore);
}
