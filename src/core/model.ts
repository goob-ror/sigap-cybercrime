// Core domain model shared by the ingest, detection, correlation, triage and evidence engines.
// Pure types only: no React, no storage.

export type SourceKind = 'endpoint' | 'network' | 'ot' | 'mobile'
export type Level = 'informational' | 'low' | 'medium' | 'high' | 'critical'

/** Sigma-style log source description, used to decide which rules apply to an event. */
export type Logsource = { product?: string; category?: string; service?: string }
export type FieldValue = string | number | boolean | null

/** One log record after parsing and normalization. */
export type NormalizedEvent = {
  id: string
  /** Epoch milliseconds (UTC). */
  ts: number
  /** Parser that produced it, e.g. `winevent`, `zeek.conn`, `zeek.modbus`, `kv-syslog`. */
  dataset: string
  sourceKind: SourceKind
  logsource: Logsource
  host?: string
  user?: string
  srcIp?: string
  dstIp?: string
  dstPort?: number
  /** `sha256` is the hash of the process image (Sysmon `Hashes`), not of a dropped file. */
  process?: { name?: string; cmdline?: string; parent?: string; pid?: number; sha256?: string }
  file?: { name?: string; path?: string; sha256?: string }
  domain?: string
  url?: string
  ot?: { protocol: string; unitId?: number; func?: string; register?: number; value?: number }
  message: string
  /** Import batch this event came from (links back to the original artifact). */
  importId: string
  /** Flattened original fields, used by Sigma rules (e.g. `EventID`, `CommandLine`). */
  fields: Record<string, FieldValue>
}

/** A rule match on one or more events. */
export type Detection = {
  id: string
  ruleId: string
  title: string
  level: Level
  /** ATT&CK / ATT&CK for ICS technique IDs, e.g. `T1059.001`, `T0836`. */
  attack: string[]
  eventIds: string[]
  /** Field values that satisfied the rule, shown in "Mengapa ditandai?". */
  matched: Record<string, string>
  ts: number
}

export type EntityType = 'user' | 'host' | 'ip' | 'domain' | 'hash' | 'file' | 'device'
export type Entity = { type: EntityType; value: string }

/** An entity as it appears in an incident. */
export type IncidentEntity = Entity & {
  /** Stable id, e.g. `asset:WS-MIN-03`, `ip:203.0.113.66`, `user:sertu.rina`. */
  key: string
  /** Other identifiers of the same asset, e.g. its IP addresses. */
  aliases: string[]
  detectionIds: string[]
  firstSeen: number
  /** Host where a detection was logged, or the source of the activity. */
  actor: boolean
  /** Seen with more than half of the hosts (DNS, file server, shared account). */
  common: boolean
}

/** A directed link between two entities of an incident, e.g. `WS-MIN-03 -> 203.0.113.66 (HTTPS :443)`. */
export type Relation = { from: string; to: string; labels: string[]; count: number; level: Level; detectionIds: string[]; firstSeen: number }

/** One term of the explainable confidence score `1 - Π(1 - weight)`. */
export type ScoreTerm = { kind: 'rule' | 'killchain' | 'sources'; label: string; weight: number; level?: Level; count?: number }

/** Detections linked by shared entities within a time window. */
export type Incident = {
  id: string
  caseId?: string
  title: string
  /** Assets in order of first appearance (entity keys), e.g. workstation -> server -> PLC. */
  path: string[]
  level: Level
  detectionIds: string[]
  ruleIds: string[]
  entities: IncidentEntity[]
  relations: Relation[]
  /** ATT&CK tactics in kill-chain order. */
  tactics: string[]
  sourceKinds: SourceKind[]
  /** 0–1, computed from `scoreBreakdown`. */
  score: number
  scoreBreakdown: ScoreTerm[]
  firstSeen: number
  lastSeen: number
}

export type CaseStatus = 'Open' | 'Investigating' | 'Resolved'
export type FollowUpStatus = 'Baru' | 'Berjalan' | 'Selesai'
export type CaseHistoryEntry = { ts: number; actor: string; text: string }

/** How the unit handles an incident. Created automatically; survives re-imports. */
export type Case = {
  id: string
  title: string
  status: CaseStatus
  assignee: string
  notes: string
  createdAt: number
  updatedAt: number
  incidentIds: string[]
  /** Response step id (`<detectionId>#<index>`, later playbook steps) -> done. */
  playbookProgress: Record<string, boolean>
  /** Detection id -> follow-up status. */
  followUps: Record<string, FollowUpStatus>
  history: CaseHistoryEntry[]
}

/** A known asset of the unit (from its inventory), used to tie IP addresses to hosts. */
export type UnitAsset = { name: string; ip: string; kind: 'it' | 'ot'; role: string }

/** Unit-specific settings. Edit to match a real unit's network. */
export type UnitProfile = {
  name: string
  /** Hosts allowed to send Modbus commands (HMI / engineering workstations). */
  engineeringHosts: string[]
  /** OT network segments. */
  otSubnets: string[]
  /** Outbound volume to one external destination that counts as possible exfiltration. */
  uploadThresholdBytes: number
  assets: UnitAsset[]
}

/** A file brought into SIGAP: an imported log, an APK under triage, or exported evidence. */
export type Artifact = {
  id: string
  caseId?: string
  filename: string
  sha256: string
  size: number
  mime: string
  kind: 'log' | 'apk' | 'url' | 'file' | 'report'
  addedAt: number
  addedBy: string
  analysis?: unknown
}

export type CustodyAction = 'acquired' | 'imported' | 'analyzed' | 'exported' | 'verified' | 'note'

/** Chain-of-custody record. Each entry commits to the previous one via `prevHash`. */
export type CustodyEntry = {
  seq: number
  ts: number
  actor: string
  action: CustodyAction
  artifactId?: string
  artifactSha256?: string
  detail: string
  prevHash: string
  hash: string
}
