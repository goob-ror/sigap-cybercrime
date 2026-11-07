import { foldAttempts, matchRules, runDetections, type RulePack } from '@/core/detect/engine'
import { correlate } from '@/core/correlate/correlate'
import { LEVEL_RANK } from '@/core/labels'
import type { Detection, Incident, Level, NormalizedEvent, UnitProfile } from '@/core/model'

/**
 * SIGAP Pos Jaga, the analysis half: takes events as they are read from the logs and reports what
 * is new. It uses the same rules and correlation as SIGAP Kit, over a sliding window:
 *
 * - Sigma rules look at one event at a time, so each event is checked once, when it arrives.
 * - Aggregate (native) rules count events over time, so they re-run over the whole window.
 * - Correlation re-runs over the window, so an incident grows as the attack goes on.
 *
 * The window is measured in log time (the newest event seen), not wall-clock time, so replaying an
 * old log behaves like the live server did.
 */

export type Alert = { kind: 'temuan'; detection: Detection; event?: NormalizedEvent }
/** `newTactics`: attack stages first seen in this update (all of them for a new incident). */
export type IncidentUpdate = { kind: 'insiden'; incident: Incident; isNew: boolean; newTactics: string[] }

/** The same rule firing again for the same host and source within this time is not re-alerted. */
const REPEAT_MS = 15 * 60_000

export type PenjagaOptions = {
  pack: RulePack
  profile: UnitProfile
  /** Only findings at or above this level raise an alert (all are still correlated). */
  minLevel?: Level
  windowMs?: number
  /** Upper bound on events held in memory; the oldest are dropped first. */
  maxEvents?: number
}

const DAY = 24 * 60 * 60_000

export class Penjaga {
  private readonly sigmaOnly: RulePack
  private readonly nativeOnly: RulePack
  private readonly minLevel: Level
  private readonly windowMs: number
  private readonly maxEvents: number
  private events: NormalizedEvent[] = []
  private readonly ids = new Set<string>()
  private sigmaDetections: Detection[] = []
  /** `ruleId|eventId` pairs already alerted, so a growing cluster is reported once. */
  private readonly alerted = new Set<string>()
  /** Incident id -> number of findings and tactics when last reported. */
  private readonly reported = new Map<string, { count: number; tactics: Set<string> }>()
  /** `ruleId|host|srcIp` -> log time of the last alert, to fold repeats. */
  private readonly lastAlert = new Map<string, number>()
  private latest = 0
  incidents: Incident[] = []
  detections: Detection[] = []

  constructor(private readonly options: PenjagaOptions) {
    this.sigmaOnly = { sigma: options.pack.sigma, native: [], skipped: [] }
    this.nativeOnly = { sigma: [], native: options.pack.native, skipped: [] }
    this.minLevel = options.minLevel ?? 'high'
    this.windowMs = options.windowMs ?? DAY
    this.maxEvents = options.maxEvents ?? 200_000
  }

  get eventCount() {
    return this.events.length
  }

  /** Adds newly read events; returns the alerts and incident changes they cause. */
  push(incoming: readonly NormalizedEvent[]): { alerts: Alert[]; updates: IncidentUpdate[] } {
    const fresh = incoming.filter((e) => !this.ids.has(e.id))
    if (!fresh.length) return { alerts: [], updates: [] }
    for (const e of fresh) {
      this.ids.add(e.id)
      if (e.ts > this.latest) this.latest = e.ts
    }
    this.events.push(...fresh)
    this.events.sort((a, b) => a.ts - b.ts)
    this.evict()

    const kept = this.ids
    // Kept unfolded and folded over the whole window, so batches of any size give the same findings.
    this.sigmaDetections = [...this.sigmaDetections.filter((d) => d.eventIds.every((id) => kept.has(id))), ...matchRules(fresh, this.sigmaOnly)]
    const byId = new Map(this.events.map((e) => [e.id, e]))
    this.detections = foldAttempts([...this.sigmaDetections, ...runDetections(this.events, this.nativeOnly)], (id) => byId.get(id))

    const alerts: Alert[] = []
    for (const d of this.detections) {
      const keys = d.eventIds.map((id) => `${d.ruleId}|${id}`)
      if (keys.some((k) => this.alerted.has(k))) {
        keys.forEach((k) => this.alerted.add(k))
        continue
      }
      keys.forEach((k) => this.alerted.add(k))
      if (LEVEL_RANK[d.level] < LEVEL_RANK[this.minLevel]) continue
      const event = byId.get(d.eventIds.at(-1)!)
      const repeatKey = `${d.ruleId}|${event?.host ?? ''}|${event?.srcIp ?? ''}`
      const previous = this.lastAlert.get(repeatKey)
      // Repeats still count in the incident; only the alert line is folded.
      if (previous !== undefined && d.ts - previous < REPEAT_MS) continue
      this.lastAlert.set(repeatKey, d.ts)
      alerts.push({ kind: 'temuan', detection: d, event })
    }

    this.incidents = correlate(this.detections, this.events, this.options.profile).incidents
    const updates: IncidentUpdate[] = []
    for (const incident of this.incidents) {
      const before = this.reported.get(incident.id)
      if (before?.count === incident.detectionIds.length) continue
      // Only incidents worth a person's attention: at least one finding at the alert level.
      if (LEVEL_RANK[incident.level] < LEVEL_RANK[this.minLevel]) continue
      const newTactics = incident.tactics.filter((t) => !before?.tactics.has(t))
      this.reported.set(incident.id, { count: incident.detectionIds.length, tactics: new Set(incident.tactics) })
      updates.push({ kind: 'insiden', incident, isNew: before === undefined, newTactics })
    }
    return { alerts, updates }
  }

  /** Reloads the saved window after a restart without alerting on it a second time. */
  restore(events: readonly NormalizedEvent[]) {
    this.push(events)
  }

  /** Events kept in the window (for saving and restoring across restarts). */
  windowEvents(): readonly NormalizedEvent[] {
    return this.events
  }

  private evict() {
    const cutoff = this.latest - this.windowMs
    let drop = 0
    while (drop < this.events.length && (this.events[drop].ts < cutoff || this.events.length - drop > this.maxEvents)) drop++
    if (!drop) return
    for (const e of this.events.slice(0, drop)) this.ids.delete(e.id)
    this.events = this.events.slice(drop)
  }
}
