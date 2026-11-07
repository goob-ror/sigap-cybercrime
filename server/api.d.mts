import type { IncomingMessage, ServerResponse } from 'node:http'

export type ApiStatus = { safeBrowsing: boolean }

export type ApiOptions = {
  env: Record<string, string | undefined>
  fetchImpl?: typeof fetch
  now?: () => number
}

export function createApi(options: ApiOptions): {
  handle(req: IncomingMessage, res: ServerResponse): Promise<boolean>
  status(): ApiStatus
}

export function decodeHashesResponse(bytes: Uint8Array): { matches: { hash: string; threats: string[] }[]; cacheSeconds: number }
