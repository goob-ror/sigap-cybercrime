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
  process?: { name?: string; cmdline?: string; parent?: string; pid?: number }
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

/** One term of the explainable confidence score. */
export type ScoreTerm = { label: string; weight: number }

/** Detections linked by shared entities within a time window. */
export type Incident = {
  id: string
  caseId?: string
  title: string
  detectionIds: string[]
  entities: Entity[]
  /** ATT&CK tactics in kill-chain order. */
  tactics: string[]
  /** 0–1, computed from `scoreBreakdown`. */
  score: number
  scoreBreakdown: ScoreTerm[]
  firstSeen: number
  lastSeen: number
}

export type CaseStatus = 'Open' | 'Investigating' | 'Resolved'
export type FollowUpStatus = 'Baru' | 'Berjalan' | 'Selesai'

export type Case = {
  id: string
  title: string
  status: CaseStatus
  notes: string
  createdAt: number
  updatedAt: number
  incidentIds: string[]
  /** Playbook step id -> done. */
  playbookProgress: Record<string, boolean>
  followUps: Record<string, FollowUpStatus>
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
