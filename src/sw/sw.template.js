// SIGAP service worker. Keeps the app openable when its server cannot be reached, so an operator
// still gets to their cases (which live in this browser) during an outage or an incident.
// The build fills in the version and the file list (see `serviceWorker` in vite.config.ts).
// It only ever talks to its own origin.

const CACHE = 'sigap-__VERSION__'
const PRECACHE = __PRECACHE__
const ROOT = new URL('./', self.location).href
/** Longer than a normal page load; after this, an unresponsive server counts as unreachable. */
const NAVIGATION_TIMEOUT_MS = 3000

self.addEventListener('install', (event) => {
  // If any file fails to download, this version is not installed and the app keeps working online.
  event.waitUntil(caches.open(CACHE).then((cache) => cache.addAll(PRECACHE)).then(() => self.skipWaiting()))
})

self.addEventListener('activate', (event) => {
  event.waitUntil(
    (async () => {
      // Keeps the previous version too: a tab opened before an update may still load its code-split
      // pages from it. `keys()` lists oldest first.
      const others = (await caches.keys()).filter((name) => name.startsWith('sigap-') && name !== CACHE)
      await Promise.all(others.slice(0, -1).map((name) => caches.delete(name)))
      await self.clients.claim()
    })(),
  )
})

async function cachedApp() {
  const cache = await caches.open(CACHE)
  return (await cache.match(ROOT, { ignoreVary: true })) ?? (await caches.match(ROOT, { ignoreVary: true })) ?? Response.error()
}

// A browser shows its password prompt for a page's own navigation, not for a fetch made here. So when
// the server asks for a password, step aside: the reload goes straight to the server, which prompts,
// and the app registers this worker again once it loads. Stored cases are not affected.
const STEP_ASIDE = `<!doctype html><meta charset="utf-8"><title>SIGAP</title><script>
navigator.serviceWorker.getRegistration().then((r) => r && r.unregister()).finally(() => location.reload())
</script>`

// The server first, so a new deployment arrives on the next load; the stored copy when it cannot answer.
async function openApp(request) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), NAVIGATION_TIMEOUT_MS)
  try {
    const response = await fetch(request, { signal: controller.signal })
    if (response.status === 401) return new Response(STEP_ASIDE, { status: 401, headers: { 'Content-Type': 'text/html; charset=utf-8' } })
    return response.status >= 500 ? await cachedApp() : response
  } catch {
    return cachedApp()
  } finally {
    clearTimeout(timer)
  }
}

self.addEventListener('fetch', (event) => {
  const { request } = event
  if (request.method !== 'GET') return
  const url = new URL(request.url)
  if (url.origin !== self.location.origin) return

  // The app has one page; any other navigation, such as a download, is not the app's to answer.
  if (request.mode === 'navigate') {
    if (`${url.origin}${url.pathname}` === ROOT || `${url.origin}${url.pathname}` === `${ROOT}index.html`) event.respondWith(openApp(request))
    return
  }
  // Built files have the hash of their content in their name, so a stored copy is never out of date.
  event.respondWith(caches.match(request, { ignoreVary: true }).then((hit) => hit ?? fetch(request)))
})
