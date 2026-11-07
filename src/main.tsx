import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import './index.css'

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)

// Lets the app open when its server cannot be reached. Failing to register only loses that.
if (import.meta.env.PROD && 'serviceWorker' in navigator) {
  navigator.serviceWorker.register('./sw.js').catch((err: unknown) => console.warn('SIGAP tidak dapat disiapkan untuk pemakaian offline:', err))
}
