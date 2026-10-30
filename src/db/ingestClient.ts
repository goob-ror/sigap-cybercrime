import { useCallback, useState } from 'react'
import type { ImportSummary, IngestRequest, IngestResponse } from '@/workers/protocol'

export type Progress = { message: string; done: number; total: number }

let worker: Worker | null = null
function getWorker(): Worker {
  worker ??= new Worker(new URL('../workers/ingest.worker.ts', import.meta.url), { type: 'module' })
  return worker
}

/** Sends one request to the ingest worker; resolves when it reports `done`. */
function send(request: IngestRequest, onProgress: (p: Progress) => void): Promise<ImportSummary> {
  const w = getWorker()
  return new Promise((resolve, reject) => {
    const listener = (e: MessageEvent<IngestResponse>) => {
      const msg = e.data
      if (msg.type === 'progress') return onProgress(msg)
      w.removeEventListener('message', listener)
      if (msg.type === 'done') resolve(msg.summary)
      else reject(new Error(msg.message))
    }
    w.addEventListener('message', listener)
    w.postMessage(request)
  })
}

/** Runs ingest requests one at a time and exposes progress for the UI. */
export function useIngest() {
  const [progress, setProgress] = useState<Progress | null>(null)
  const run = useCallback(async (request: IngestRequest) => {
    setProgress({ message: 'Memulai…', done: 0, total: 1 })
    try {
      return await send(request, setProgress)
    } finally {
      setProgress(null)
    }
  }, [])
  return { run, busy: progress !== null, progress }
}
