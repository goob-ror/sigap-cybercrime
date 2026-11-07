import { useSyncExternalStore } from 'react'

/** Chromium's offer to install the app. Not in the DOM types, because other browsers do not have it. */
type InstallOffer = Event & { prompt(): Promise<void>; userChoice: Promise<{ outcome: 'accepted' | 'dismissed' }> }

let offer: InstallOffer | null = null
const listeners = new Set<() => void>()
const changed = () => { for (const listener of listeners) listener() }

// Listening from load, because the browser makes this offer once, possibly before the first render.
window.addEventListener('beforeinstallprompt', (e) => {
  e.preventDefault()
  offer = e as InstallOffer
  changed()
})
window.addEventListener('appinstalled', () => {
  offer = null
  changed()
})

const subscribe = (listener: () => void) => {
  listeners.add(listener)
  return () => { listeners.delete(listener) }
}

export function useInstallApp() {
  const current = useSyncExternalStore(subscribe, () => offer)
  const runningAsApp = window.matchMedia('(display-mode: standalone)').matches
  return {
    /** In its own window: installed, or opened by the kit's launcher. */
    runningAsApp,
    canInstall: !!current && !runningAsApp,
    install: async () => {
      if (!current) return
      await current.prompt()
      await current.userChoice
      // An offer works once. The browser makes a new one if the operator declined.
      offer = null
      changed()
    },
  }
}
