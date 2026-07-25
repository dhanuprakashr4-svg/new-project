import type { ThreatLevel } from './types';

// ===== Honeypot Deception Defense =====
// Synthetic honeypot sensors that emulate vulnerable services to attract,
// detect, and deflect attackers from real production systems.

export type HoneypotType =
  | 'ssh-tarpit'
  | 'fake-web-admin'
  | 'decoy-database'
  | 'fake-file-share'
  | 'rdp-trap'
  | 'cowrie-shell';

export interface HoneypotSensor {
  id: string;
  name: string;
  type: HoneypotType;
  ip: string;
  port: number;
  status: 'armed' | 'engaged' | 'offline';
  decoyValue: 'low' | 'medium' | 'high';
  description: string;
}

export interface HoneypotInteraction {
  id: string;
  sensorId: string;
  sensorName: string;
  timestamp: string;
  attackerIp: string;
  attackerCountry: string;
  action: string;
  threatLevel: ThreatLevel;
  blocked: boolean;
  mitre?: string;
  credentialsTried?: string[];
}

export interface HoneypotDefenseResult {
  blocked: number;
  deflected: number;
  intelGathered: number;
  sensorsEngaged: number;
}

export const HONEYPOT_SENSORS: HoneypotSensor[] = [
  {
    id: 'hp-ssh-01',
    name: 'SSH Tarpit (Edge)',
    type: 'ssh-tarpit',
    ip: '10.10.20.5',
    port: 22,
    status: 'armed',
    decoyValue: 'high',
    description: 'Slow SSH handshake tarpit that stalls brute-force scanners indefinitely.',
  },
  {
    id: 'hp-web-01',
    name: 'Fake Admin Portal',
    type: 'fake-web-admin',
    ip: '10.10.20.10',
    port: 8080,
    status: 'armed',
    decoyValue: 'high',
    description: 'Fake admin login page that logs credential stuffing attempts and attacker IPs.',
  },
  {
    id: 'hp-db-01',
    name: 'Decoy Database',
    type: 'decoy-database',
    ip: '10.10.20.15',
    port: 3306,
    status: 'armed',
    decoyValue: 'medium',
    description: 'MySQL honeypot with fake schemas to detect data exfiltration attempts.',
  },
  {
    id: 'hp-share-01',
    name: 'Fake File Share',
    type: 'fake-file-share',
    ip: '10.10.20.20',
    port: 445,
    status: 'armed',
    decoyValue: 'medium',
    description: 'SMB share with bait documents containing tracking canary tokens.',
  },
  {
    id: 'hp-rdp-01',
    name: 'RDP Trap',
    type: 'rdp-trap',
    ip: '10.10.20.25',
    port: 3389,
    status: 'armed',
    decoyValue: 'high',
    description: 'Fake RDP endpoint that captures brute-force attempts and BlueKeep-style probes.',
  },
  {
    id: 'hp-cowrie-01',
    name: 'Cowrie Shell Emulator',
    type: 'cowrie-shell',
    ip: '10.10.20.30',
    port: 2222,
    status: 'armed',
    decoyValue: 'high',
    description: 'Medium-interaction SSH/Telnet honeypot that emulates a shell and logs attacker commands.',
  },
];

export const HONEYPOT_INTERACTIONS: HoneypotInteraction[] = [
  {
    id: 'hi-001',
    sensorId: 'hp-ssh-01',
    sensorName: 'SSH Tarpit (Edge)',
    timestamp: '2025-07-25T08:14:22Z',
    attackerIp: '45.155.205.233',
    attackerCountry: 'Russia',
    action: 'SSH brute-force — 1,240 login attempts (root/admin/user)',
    threatLevel: 'high',
    blocked: true,
    mitre: 'T1110',
    credentialsTried: ['root', 'admin', 'ubuntu', 'test', 'oracle'],
  },
  {
    id: 'hi-002',
    sensorId: 'hp-web-01',
    sensorName: 'Fake Admin Portal',
    timestamp: '2025-07-25T09:02:11Z',
    attackerIp: '198.51.100.7',
    attackerCountry: 'China',
    action: 'Credential stuffing — admin:admin, admin:password123',
    threatLevel: 'high',
    blocked: true,
    mitre: 'T1078',
    credentialsTried: ['admin:admin', 'admin:password123', 'root:toor'],
  },
  {
    id: 'hi-003',
    sensorId: 'hp-cowrie-01',
    sensorName: 'Cowrie Shell Emulator',
    timestamp: '2025-07-25T09:45:33Z',
    attackerIp: '185.220.101.45',
    attackerCountry: 'Tor Exit Node',
    action: 'Interactive shell — wget payload, curl C2 beacon, chmod +x',
    threatLevel: 'critical',
    blocked: true,
    mitre: 'T1059',
    credentialsTried: ['root:123456'],
  },
  {
    id: 'hi-004',
    sensorId: 'hp-rdp-01',
    sensorName: 'RDP Trap',
    timestamp: '2025-07-25T10:12:08Z',
    attackerIp: '91.134.243.12',
    attackerCountry: 'Romania',
    action: 'RDP brute-force + BlueKeep probe (CVE-2019-0708)',
    threatLevel: 'critical',
    blocked: true,
    mitre: 'T1210',
  },
  {
    id: 'hi-005',
    sensorId: 'hp-db-01',
    sensorName: 'Decoy Database',
    timestamp: '2025-07-25T11:33:45Z',
    attackerIp: '203.0.113.50',
    attackerCountry: 'Unknown',
    action: 'SQL injection on fake customer table — UNION SELECT attempt',
    threatLevel: 'high',
    blocked: true,
    mitre: 'T1190',
  },
  {
    id: 'hi-006',
    sensorId: 'hp-share-01',
    sensorName: 'Fake File Share',
    timestamp: '2025-07-25T12:01:19Z',
    attackerIp: '45.155.205.233',
    attackerCountry: 'Russia',
    action: 'Canary token triggered — bait file "salary_2025.xlsx" opened',
    threatLevel: 'medium',
    blocked: false,
    mitre: 'T1083',
  },
];

export function getHoneypotStats(): HoneypotDefenseResult {
  return {
    blocked: HONEYPOT_INTERACTIONS.filter((i) => i.blocked).length,
    deflected: HONEYPOT_INTERACTIONS.length,
    intelGathered: new Set(HONEYPOT_INTERACTIONS.map((i) => i.attackerIp)).size,
    sensorsEngaged: new Set(HONEYPOT_INTERACTIONS.map((i) => i.sensorId)).size,
  };
}

export function getHoneypotSensor(id: string): HoneypotSensor | undefined {
  return HONEYPOT_SENSORS.find((s) => s.id === id);
}
