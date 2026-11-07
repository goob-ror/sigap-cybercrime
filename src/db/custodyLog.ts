import { appendCustody } from '@/core/evidence/custody'
import { db } from '@/db/db'

/** Adds an entry to the running chain of custody. */
export async function addCustody(entry: Parameters<typeof appendCustody>[1]) {
  const last = await db.custody.orderBy('seq').last()
  const chain = await appendCustody(last ? [last] : [], entry)
  await db.custody.add(chain.at(-1)!)
}
