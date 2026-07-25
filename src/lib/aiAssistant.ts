import type { AIDetection, SecEvent, ShapFeature, SigmaRule } from './types';
import { getMitre } from './mitre';

// ===== AI Sigma Assistant & Explainability =====
// Simulates an ML detection pipeline (XGBoost / Random Forest ensemble) that:
//   1. inspects a security event
//   2. scores threat + risk
//   3. maps to MITRE
//   4. produces SHAP feature contributions
//   5. suggests a Sigma detection rule

interface DetectionSignals {
  features: { name: string; active: boolean; weight: number; description: string }[];
}

function signalsForEvent(e: SecEvent): DetectionSignals {
  const f = e.fields;
  const cmd = String(f.CommandLine || '');
  const image = String(f.Image || '');
  const parent = String(f.ParentImage || '');
  const url = String(f.URL || f.Body || '');
  const authPkg = String(f.AuthenticationPackageName || '');
  const taskAction = String(f.TaskAction || '');

  return {
    features: [
      {
        name: 'Suspicious Process',
        active: /mimikatz|procdump|beacon|mshta|certutil/i.test(image),
        weight: 0.4,
        description: 'A process with a known offensive-tool signature executed.',
      },
      {
        name: 'Encoded Command',
        active: /-enc(odedcommand)?|-e\s|encodedcommand/i.test(cmd),
        weight: 0.3,
        description: 'PowerShell launched with a base64-encoded command payload.',
      },
      {
        name: 'Abnormal Network Behaviour',
        active: /8443|185\.|beacon|c2/i.test(String(f.DestinationIp || '') + String(f.DestinationHostname || '')),
        weight: 0.2,
        description: 'Outbound connection to a suspicious IP or non-standard port.',
      },
      {
        name: 'Unknown Parent Process',
        active: /winword|excel|mshta|outlook/i.test(parent),
        weight: 0.1,
        description: 'Process spawned from an Office application — unusual parentage.',
      },
      {
        name: 'Credential Access Pattern',
        active: /sekurlsa|lsass|logonpasswords/i.test(cmd + ' ' + image),
        weight: 0.25,
        description: 'Behaviour consistent with credential dumping.',
      },
      {
        name: 'NTLM Pass-the-Hash',
        active: authPkg.toLowerCase() === 'ntlm' && String(f.Status).toLowerCase() === 'success',
        weight: 0.35,
        description: 'Successful NTLM logon — potential Pass-the-Hash authentication.',
      },
      {
        name: 'SQL / Command Injection',
        active: /'|or '1'='1|--|;cat|;wget|sqlmap/i.test(url),
        weight: 0.4,
        description: 'Malicious input pattern in HTTP request — injection attempt.',
      },
      {
        name: 'Persistence via Scheduled Task',
        active: /powershell|\.bat|\.exe/i.test(taskAction) && !/defrag|update|uso/i.test(taskAction),
        weight: 0.3,
        description: 'Scheduled task executes a script or binary — persistence indicator.',
      },
    ],
  };
}

function shapFromSignals(signals: DetectionSignals): ShapFeature[] {
  const active = signals.features.filter((f) => f.active);
  if (active.length === 0) {
    return [{ feature: 'No anomaly detected', contribution: 1, description: 'Event matched benign baseline.' }];
  }
  const total = active.reduce((s, f) => s + f.weight, 0);
  return active
    .map((f) => ({
      feature: f.name,
      contribution: Math.round((f.weight / total) * 100),
      description: f.description,
    }))
    .sort((a, b) => b.contribution - a.contribution);
}

export function analyzeEvent(e: SecEvent): AIDetection {
  const signals = signalsForEvent(e);
  const shap = shapFromSignals(signals);
  const activeCount = signals.features.filter((f) => f.active).length;
  const threatScore = Math.min(99, activeCount * 22 + (e.malicious ? 12 : 0));
  const riskScore = Math.min(99, threatScore * 0.7 + (shap.length > 2 ? 20 : 0));
  const confidence = Math.min(0.99, 0.55 + activeCount * 0.12);
  const mitreId = e.mitre || inferMitre(signals);
  const m = getMitre(mitreId);
  const model: AIDetection['model'] = threatScore > 70 ? 'XGBoost' : threatScore > 40 ? 'Ensemble' : 'Random Forest';

  const summary = m
    ? `AI detected ${m.name} (${mitreId}) in the ${m.tactic} tactic. Threat score ${threatScore}/99 with ${(confidence * 100).toFixed(0)}% confidence. Primary driver: ${shap[0]?.feature}.`
    : `Anomalous security event scored ${threatScore}/99 with ${(confidence * 100).toFixed(0)}% confidence.`;

  return {
    id: `det-${e.id}`,
    timestamp: e.timestamp,
    attackType: m?.name || 'Anomalous Behaviour',
    mitre: mitreId,
    threatScore,
    riskScore,
    confidence,
    shap,
    model,
    summary,
  };
}

function inferMitre(signals: DetectionSignals): string {
  const active = new Set(signals.features.filter((f) => f.active).map((f) => f.name));
  if (active.has('Encoded Command') || active.has('Unknown Parent Process')) return 'T1059.001';
  if (active.has('Credential Access Pattern')) return 'T1003.001';
  if (active.has('NTLM Pass-the-Hash')) return 'T1550.002';
  if (active.has('Persistence via Scheduled Task')) return 'T1053.005';
  if (active.has('SQL / Command Injection')) return 'T1190';
  if (active.has('Abnormal Network Behaviour')) return 'T1078';
  return 'T1059';
}

// ===== AI Sigma Rule Suggestion =====
// Given a detected MITRE technique, propose a Sigma rule the analyst can refine.
export function suggestSigmaRule(mitreId: string): string {
  const templates: Record<string, string> = {
    'T1059.001': `title: Suspicious Encoded PowerShell Execution
id: 4f7728-9a3b-4c2e-8f1d-t1059_001
status: experimental
description: Detects PowerShell executing with an encoded command, often used to hide malicious payloads.
author: ThreatZero Sentinel X AI Assistant
level: high
logsource:
  category: process_creation
  product: windows
detection:
  selection_powershell:
    Image|endswith:
      - '\\\\powershell.exe'
      - '\\\\pwsh.exe'
  selection_encoded:
    CommandLine|contains:
      - '-EncodedCommand'
      - '-enc '
      - ' -e '
  filter_benign:
    CommandLine|contains:
      - 'Get-Process'
      - 'Get-Service'
  condition: selection_powershell and selection_encoded and not filter_benign
falsepositives:
  - Legitimate administrative scripts using encoding
tags:
  - attack.execution
  - attack.t1059.001`,
    'T1003.001': `title: LSASS Memory Access Attempt
id: 7c4a1b-2d8e-4f5a-9b6c-t1003_001
status: experimental
description: Detects processes attempting to access LSASS memory, consistent with credential dumping.
author: ThreatZero Sentinel X AI Assistant
level: critical
logsource:
  category: process_creation
  product: windows
detection:
  selection_tools:
    Image|endswith:
      - '\\\\mimikatz.exe'
      - '\\\\procdump.exe'
      - '\\\\taskmgr.exe'
  selection_lsass:
    CommandLine|contains:
      - 'lsass'
      - 'sekurlsa'
      - 'logonpasswords'
  condition: selection_tools or selection_lsass
falsepositives:
  - Authorized diagnostic tools run by SOC
tags:
  - attack.credential_access
  - attack.t1003.001`,
    'T1053.005': `title: Suspicious Scheduled Task Creation
id: 8e2d4f-1a3b-4c5d-9e7f-t1053_005
status: experimental
description: Detects creation of scheduled tasks that execute scripts or binaries, a common persistence mechanism.
author: ThreatZero Sentinel X AI Assistant
level: high
logsource:
  category: scheduled_task
  product: windows
detection:
  selection_event:
    EventID: 4698
  selection_action:
    TaskAction|contains:
      - 'powershell'
      - '.bat'
      - '.exe'
      - 'cmd.exe'
  filter_known:
    TaskName|contains:
      - 'Microsoft'
      - 'Defrag'
      - 'Update'
  condition: selection_event and selection_action and not filter_known
falsepositives:
  - Software update tasks
tags:
  - attack.execution
  - attack.persistence
  - attack.t1053.005`,
    'T1550.002': `title: Pass the Hash - NTLM Authentication
id: 3f8a2c-6b4d-4e1a-9c5d-t1550_002
status: experimental
description: Detects successful NTLM authentication that may indicate Pass the Hash lateral movement.
author: ThreatZero Sentinel X AI Assistant
level: critical
logsource:
  category: authentication
  product: windows
detection:
  selection_logon:
    EventID: 4624
    LogonType: 3
    AuthenticationPackageName: NTLM
    Status: Success
  condition: selection_logon
falsepositives:
  - Legacy systems requiring NTLM
tags:
  - attack.lateral_movement
  - attack.defense_evasion
  - attack.t1550.002`,
    T1190: `title: Web SQL Injection Attempt
id: 9b3e5a-2c4d-4f1b-8e7a-t1190
status: experimental
description: Detects SQL injection and command injection patterns in HTTP requests.
author: ThreatZero Sentinel X AI Assistant
level: critical
logsource:
  category: web_access
  product: web
detection:
  selection_sqli:
    URL|contains:
      - "' OR '1'='1"
      - 'UNION SELECT'
      - '--'
      - ';cat '
  selection_cmdi:
    URL|contains:
      - ';wget '
      - ';cat%20'
      - '|whoami'
  selection_tools:
    UserAgent|contains:
      - 'sqlmap'
  condition: selection_sqli or selection_cmdi or selection_tools
falsepositives:
  - Security scanners in authorized testing
tags:
  - attack.initial_access
  - attack.t1190`,
  };

  return templates[mitreId] || `title: Detection for ${mitreId}
status: experimental
description: AI-suggested Sigma rule for ${mitreId}.
level: high
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains: 'suspicious'
  condition: selection
tags:
  - attack.${mitreId.toLowerCase()}`;
}

// ===== AI SOC Copilot explanations =====
export function copilotExplainRule(rule: SigmaRule, matchedEvent: SecEvent | undefined): string {
  const m = getMitre(rule.tags?.find((t) => t.includes('t1'))?.replace('attack.', '') || '');
  const parts: string[] = [];
  if (matchedEvent) {
    parts.push(`This rule matched because the event's ${Object.keys(matchedEvent.fields).slice(0, 2).join(' and ')} fields satisfied all selection criteria.`);
  }
  parts.push(`The detection logic selects events where the suspicious field pattern appears, then filters known-benign variations via the condition.`);
  if (m) {
    parts.push(`Behaviour is consistent with ${m.name} (${m.id}) in the ${m.tactic} tactic, severity ${m.severity}.`);
  }
  parts.push(`Recommended response: isolate the affected host, collect memory and process artifacts, and review lateral movement from the same account.`);
  return parts.join(' ');
}

export function copilotSummarizeAttack(detection: AIDetection): string {
  const m = getMitre(detection.mitre);
  return `${detection.attackType} (${detection.mitre}) was detected at ${detection.timestamp}. The ${detection.model} model scored this ${detection.threatScore}/99 threat, ${detection.riskScore}/99 risk, with ${(detection.confidence * 100).toFixed(0)}% confidence. ${m ? `${m.name} falls under the ${m.tactic} tactic. ` : ''}Top contributing factor: ${detection.shap[0]?.feature} at ${detection.shap[0]?.contribution}%. Recommended action: contain the host, preserve evidence, and escalate if risk > 70.`;
}

export function copilotRecommendResponse(detection: AIDetection): string[] {
  const base = [
    'Isolate the affected host from the network',
    'Collect volatile evidence (memory, process tree) before imaging',
    'Rotate credentials for any accounts active on the host',
    'Block the source IP / C2 domain at the perimeter',
  ];
  if (detection.mitre.startsWith('T1003')) base.push('Force password reset for all users with sessions on the host');
  if (detection.mitre === 'T1190') base.push('Apply WAF rules to block the injection signature and patch the vulnerable parameter');
  if (detection.mitre === 'T1550.002') base.push('Disable NTLM where possible and enforce Kerberos with account confinement');
  return base;
}
