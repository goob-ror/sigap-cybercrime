/**
 * MITRE ATT&CK® (Enterprise) and ATT&CK® for ICS techniques referenced by the SIGAP rule pack.
 * ATT&CK is a registered trademark of The MITRE Corporation; names are used for reference.
 * https://attack.mitre.org/
 */
export type Technique = { id: string; name: string; tactic: string; domain: 'enterprise' | 'ics' }

const list: Technique[] = [
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
  'Initial Access', 'Execution', 'Persistence', 'Defense Evasion', 'Credential Access', 'Discovery',
  'Lateral Movement', 'Collection', 'Command and Control', 'Exfiltration', 'Impair Process Control', 'Impact',
]
