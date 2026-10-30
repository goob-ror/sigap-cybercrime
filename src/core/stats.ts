import type { NormalizedEvent, SourceKind } from '@/core/model'

/** Aggregate counts over all imported events, computed in the worker so the UI never loads every event. */
export type EventStats = {
  total: number
  first: number
  last: number
  byDataset: Record<string, number>
  byKind: Partial<Record<SourceKind, number>>
  hosts: number
  /** Histogram of event counts; bucket `i` starts at `bucketStart + i * bucketMs`. */
  bucketMs: number
  bucketStart: number
  buckets: number[]
}

const MINUTE = 60_000
const HOUR = 60 * MINUTE
const DAY = 24 * HOUR
const BUCKET_SIZES = [MINUTE, 5 * MINUTE, 10 * MINUTE, 15 * MINUTE, 30 * MINUTE, HOUR, 2 * HOUR, 3 * HOUR, 6 * HOUR, 12 * HOUR, DAY, 2 * DAY, 7 * DAY, 30 * DAY]
/** WIB is UTC+7; buckets start on WIB clock boundaries (e.g. midnight for daily buckets). */
const WIB_OFFSET = 7 * HOUR

/** Smallest standard bucket that keeps the histogram at or under `maxBuckets` bars. */
export function bucketSize(spanMs: number, maxBuckets = 48): number {
  return BUCKET_SIZES.find((size) => spanMs / size < maxBuckets) ?? BUCKET_SIZES.at(-1)!
}

export function bucketStartOf(ts: number, size: number): number {
  return Math.floor((ts + WIB_OFFSET) / size) * size - WIB_OFFSET
}

export function computeStats(events: readonly NormalizedEvent[]): EventStats | null {
  if (!events.length) return null
  let first = Infinity
  let last = -Infinity
  const byDataset: Record<string, number> = {}
  const byKind: Partial<Record<SourceKind, number>> = {}
  const hosts = new Set<string>()
  for (const e of events) {
    if (e.ts < first) first = e.ts
    if (e.ts > last) last = e.ts
    byDataset[e.dataset] = (byDataset[e.dataset] ?? 0) + 1
    byKind[e.sourceKind] = (byKind[e.sourceKind] ?? 0) + 1
    if (e.sourceKind === 'endpoint' && e.host) hosts.add(e.host)
  }
  const bucketMs = bucketSize(last - first)
  const bucketStart = bucketStartOf(first, bucketMs)
  const buckets = new Array<number>(Math.floor((last - bucketStart) / bucketMs) + 1).fill(0)
  for (const e of events) buckets[Math.floor((e.ts - bucketStart) / bucketMs)]++
  return { total: events.length, first, last, byDataset, byKind, hosts: hosts.size, bucketMs, bucketStart, buckets }
}
