import type { NormalizedEvent } from '@/core/model'
import { logPredicate, type LogFilter } from '@/core/logQuery'
import { db } from '@/db/db'

const BATCH = 5000

/**
 * What a filter selects. Finding it is the slow part (counting alone walks the whole index), so it
 * is kept apart from reading a page, and turning pages does not repeat it.
 * `ids` is null when the filter is only a time range: the index can then serve pages by position.
 */
export type LogMatch = { total: number; ids: string[] | null }
export type LogPage = { events: NormalizedEvent[]; page: number; pageCount: number }

const timeRange = (filter: LogFilter) => (filter.from !== null || filter.to !== null ? db.events.where('ts').between(filter.from ?? -Infinity, filter.to ?? Infinity, true, true) : db.events.orderBy('ts'))

/**
 * Ids of the matching events in time order. Reads in batches and filters here, because a plain read
 * is several times faster than a filtered cursor, and only ids are kept, so a large log set is not
 * held in memory. Ties in time come out in id order, the same as the index.
 */
async function matchingIds(filter: LogFilter, matches: (event: NormalizedEvent) => boolean): Promise<string[]> {
  const ids: string[] = []
  const upper = filter.to ?? Infinity
  let lower = filter.from ?? -Infinity
  let includeLower = true
  for (;;) {
    const batch = await db.events.where('ts').between(lower, upper, includeLower, true).limit(BATCH).toArray()
    const isLast = batch.length < BATCH
    if (!batch.length) return ids
    // The next batch starts after this one's last time, so every event at that time is read now.
    const lastTs = batch[batch.length - 1].ts
    const complete = isLast ? batch : [...batch.filter((e) => e.ts < lastTs), ...(await db.events.where('ts').equals(lastTs).toArray())]
    for (const event of complete) if (matches(event)) ids.push(event.id)
    if (isLast) return ids
    lower = lastTs
    includeLower = false
  }
}

export async function matchLogs(filter: LogFilter): Promise<LogMatch> {
  const matches = logPredicate(filter)
  if (!matches) return { total: await timeRange(filter).count(), ids: null }
  const ids = await matchingIds(filter, matches)
  return { total: ids.length, ids }
}

/**
 * One page of a match, in time order. `page` is clamped, so a page that no longer exists after a
 * re-analysis shows the last one; a negative `page` also means the last, for jumping to the newest.
 */
export async function readLogPage(filter: LogFilter, match: LogMatch, page: number, size: number): Promise<LogPage> {
  const pageCount = Math.max(1, Math.ceil(match.total / size))
  const at = page < 0 ? pageCount - 1 : Math.min(page, pageCount - 1)
  const start = at * size
  const end = Math.min(start + size, match.total)

  let ids: string[]
  if (match.ids) ids = match.ids.slice(start, end)
  else if (start <= match.total / 2) ids = (await timeRange(filter).offset(start).limit(size).primaryKeys()) as string[]
  // Skipping over the index takes time, so a page nearer the end is counted back from there.
  else ids = ((await timeRange(filter).reverse().offset(match.total - end).limit(end - start).primaryKeys()) as string[]).reverse()

  const events = await db.events.bulkGet(ids)
  return { events: events.filter((e): e is NormalizedEvent => !!e), page: at, pageCount }
}

/** Where an event sits in the unfiltered time order, or null when it is no longer stored. */
export async function eventPosition(id: string): Promise<number | null> {
  const event = await db.events.get(id)
  if (!event) return null
  const before = await db.events.where('ts').below(event.ts).count()
  const sameTime = await db.events.where('ts').equals(event.ts).primaryKeys()
  return before + sameTime.indexOf(id)
}
