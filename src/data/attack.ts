/**
 * MITRE ATT&CK® (Enterprise) and ATT&CK® for ICS techniques referenced by the SIGAP rule pack.
 * ATT&CK is a registered trademark of The MITRE Corporation; names are used for reference.
 * https://attack.mitre.org/
 */
export type Technique = { id: string; name: string; tactic: string; domain: 'enterprise' | 'ics' }

const list: Technique[] = [
  { id: 'T1595', name: 'Active Scanning', tactic: 'Reconnaissance', domain: 'enterprise' },
  { id: 'T1595.002', name: 'Active Scanning: Vulnerability Scanning', tactic: 'Reconnaissance', domain: 'enterprise' },
  { id: 'T1595.003', name: 'Active Scanning: Wordlist Scanning', tactic: 'Reconnaissance', domain: 'enterprise' },
  { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access', domain: 'enterprise' },
  { id: 'T1091', name: 'Replication Through Removable Media', tactic: 'Initial Access', domain: 'enterprise' },
  { id: 'T1547.001', name: 'Registry Run Keys / Startup Folder', tactic: 'Persistence', domain: 'enterprise' },
  { id: 'T1543.003', name: 'Create or Modify System Process: Windows Service', tactic: 'Persistence', domain: 'enterprise' },
  { id: 'T1070.002', name: 'Clear Linux or Mac System Logs', tactic: 'Defense Evasion', domain: 'enterprise' },
  { id: 'T1070.003', name: 'Clear Command History', tactic: 'Defense Evasion', domain: 'enterprise' },
  { id: 'T1003.002', name: 'OS Credential Dumping: Security Account Manager', tactic: 'Credential Access', domain: 'enterprise' },
  { id: 'T1003.003', name: 'OS Credential Dumping: NTDS', tactic: 'Credential Access', domain: 'enterprise' },
  { id: 'T1490', name: 'Inhibit System Recovery', tactic: 'Impact', domain: 'enterprise' },
  { id: 'T1491.002', name: 'Defacement: External Defacement', tactic: 'Impact', domain: 'enterprise' },
  { id: 'T1078', name: 'Valid Accounts', tactic: 'Initial Access', domain: 'enterprise' },
  { id: 'T1059.004', name: 'Unix Shell', tactic: 'Execution', domain: 'enterprise' },
  { id: 'T1505.003', name: 'Server Software Component: Web Shell', tactic: 'Persistence', domain: 'enterprise' },
  { id: 'T1098', name: 'Account Manipulation', tactic: 'Persistence', domain: 'enterprise' },
  { id: 'T1548.003', name: 'Abuse Elevation Control: Sudo and Sudo Caching', tactic: 'Privilege Escalation', domain: 'enterprise' },
  { id: 'T1110.001', name: 'Brute Force: Password Guessing', tactic: 'Credential Access', domain: 'enterprise' },
  { id: 'T1083', name: 'File and Directory Discovery', tactic: 'Discovery', domain: 'enterprise' },
  { id: 'T1566.003', name: 'Spearphishing via Service', tactic: 'Initial Access', domain: 'enterprise' },
  { id: 'T1204.002', name: 'User Execution: Malicious File', tactic: 'Execution', domain: 'enterprise' },
  { id: 'T1059', name: 'Command and Scripting Interpreter', tactic: 'Execution', domain: 'enterprise' },
  { id: 'T1059.001', name: 'PowerShell', tactic: 'Execution', domain: 'enterprise' },
  { id: 'T1569.002', name: 'Service Execution', tactic: 'Execution', domain: 'enterprise' },
  { id: 'T1053.005', name: 'Scheduled Task', tactic: 'Persistence', domain: 'enterprise' },
  { id: 'T1136.001', name: 'Create Account: Local Account', tactic: 'Persistence', domain: 'enterprise' },
  { id: 'T1027', name: 'Obfuscated Files or Information', tactic: 'Defense Evasion', domain: 'enterprise' },
  { id: 'T1218.011', name: 'System Binary Proxy Execution: Rundll32', tactic: 'Defense Evasion', domain: 'enterprise' },
  { id: 'T1562.001', name: 'Impair Defenses: Disable or Modify Tools', tactic: 'Defense Evasion', domain: 'enterprise' },
  { id: 'T1070.001', name: 'Clear Windows Event Logs', tactic: 'Defense Evasion', domain: 'enterprise' },
  { id: 'T1003.001', name: 'OS Credential Dumping: LSASS Memory', tactic: 'Credential Access', domain: 'enterprise' },
  { id: 'T1110', name: 'Brute Force', tactic: 'Credential Access', domain: 'enterprise' },
  { id: 'T1021.001', name: 'Remote Desktop Protocol', tactic: 'Lateral Movement', domain: 'enterprise' },
  { id: 'T1021.002', name: 'SMB/Windows Admin Shares', tactic: 'Lateral Movement', domain: 'enterprise' },
  { id: 'T1560.001', name: 'Archive via Utility', tactic: 'Collection', domain: 'enterprise' },
  { id: 'T1071.001', name: 'Application Layer Protocol: Web Protocols', tactic: 'Command and Control', domain: 'enterprise' },
  { id: 'T1071.004', name: 'Application Layer Protocol: DNS', tactic: 'Command and Control', domain: 'enterprise' },
  { id: 'T1105', name: 'Ingress Tool Transfer', tactic: 'Command and Control', domain: 'enterprise' },
  { id: 'T1048', name: 'Exfiltration Over Alternative Protocol', tactic: 'Exfiltration', domain: 'enterprise' },
  { id: 'T1567.002', name: 'Exfiltration to Cloud Storage', tactic: 'Exfiltration', domain: 'enterprise' },
  { id: 'T0886', name: 'Remote Services', tactic: 'Lateral Movement', domain: 'ics' },
  { id: 'T0846', name: 'Remote System Discovery', tactic: 'Discovery', domain: 'ics' },
  { id: 'T0888', name: 'Remote System Information Discovery', tactic: 'Discovery', domain: 'ics' },
  { id: 'T0855', name: 'Unauthorized Command Message', tactic: 'Impair Process Control', domain: 'ics' },
  { id: 'T0836', name: 'Modify Parameter', tactic: 'Impair Process Control', domain: 'ics' },
  { id: 'T0831', name: 'Manipulation of Control', tactic: 'Impact', domain: 'ics' },
  { id: 'T0826', name: 'Loss of Availability', tactic: 'Impact', domain: 'ics' },
]

export const TECHNIQUES = new Map(list.map((t) => [t.id, t]))

/** Rough kill-chain order used to sort tactics on screen. */
export const TACTIC_ORDER = [
  'Reconnaissance', 'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access', 'Discovery',
  'Lateral Movement', 'Collection', 'Command and Control', 'Exfiltration', 'Impair Process Control', 'Impact',
]

/** Bahasa Indonesia names for the tactics, used in incident stories. */
export const TACTIC_LABEL: Record<string, string> = {
  Reconnaissance: 'Pemindaian sasaran',
  'Initial Access': 'Akses awal',
  Execution: 'Eksekusi',
  Persistence: 'Bertahan di sistem',
  'Privilege Escalation': 'Peningkatan hak akses',
  'Defense Evasion': 'Menghindari pertahanan',
  'Credential Access': 'Pencurian kredensial',
  Discovery: 'Pengintaian',
  'Lateral Movement': 'Pergerakan lateral',
  Collection: 'Pengumpulan data',
  'Command and Control': 'Kendali jarak jauh (C2)',
  Exfiltration: 'Eksfiltrasi data',
  'Impair Process Control': 'Gangguan kendali proses OT',
  Impact: 'Dampak',
}

/** Tactic of a technique id, or undefined if the technique is not in the catalog. */
export function tacticOf(techniqueId: string): string | undefined {
  return TECHNIQUES.get(techniqueId)?.tactic ?? TECHNIQUES.get(techniqueId.split('.')[0])?.tactic
}
