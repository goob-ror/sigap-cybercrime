import type { Case, CaseStatus, FollowUpStatus } from '@/core/model'
import { CASE_STATUS_LABEL } from '@/core/labels'
import { db } from '@/db/db'

/**
 * Case edits from the UI. Each runs as one read-modify-write transaction, so it cannot overwrite
 * a concurrent change from the worker, and records who did what in the case history.
 */
async function edit(caseId: string, actor: string, change: (c: Case) => string | undefined) {
  await db.cases.where('id').equals(caseId).modify((c) => {
    const text = change(c)
    c.updatedAt = Date.now()
    if (text) c.history.push({ ts: c.updatedAt, actor, text })
  })
}

export function setCaseStatus(caseId: string, status: CaseStatus, actor: string) {
  return edit(caseId, actor, (c) => {
    if (c.status === status) return undefined
    const text = `Status kasus: ${CASE_STATUS_LABEL[c.status]} → ${CASE_STATUS_LABEL[status]}`
    c.status = status
    return text
  })
}

export function setAssignee(caseId: string, assignee: string, actor: string) {
  return edit(caseId, actor, (c) => {
    const name = assignee.trim()
    if (c.assignee === name) return undefined
    c.assignee = name
    return name ? `Ditugaskan kepada ${name}` : 'Penugasan dikosongkan'
  })
}

export function setNotes(caseId: string, notes: string, actor: string) {
  return edit(caseId, actor, (c) => {
    c.notes = notes
    return undefined
  })
}

export function setFollowUp(caseId: string, detectionId: string, title: string, status: FollowUpStatus, actor: string) {
  return edit(caseId, actor, (c) => {
    const before = c.followUps[detectionId] ?? 'Baru'
    if (before === status) return undefined
    c.followUps = { ...c.followUps, [detectionId]: status }
    return `Tindak lanjut "${title}": ${before} → ${status}`
  })
}

export function toggleStep(caseId: string, stepId: string, stepText: string, actor: string) {
  return edit(caseId, actor, (c) => {
    const done = !c.playbookProgress[stepId]
    c.playbookProgress = { ...c.playbookProgress, [stepId]: done }
    return `${done ? 'Langkah selesai' : 'Langkah dibuka kembali'}: ${stepText}`
  })
}
