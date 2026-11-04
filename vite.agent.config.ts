import { defineConfig } from 'vite'
import path from 'node:path'

/**
 * Builds SIGAP Pos Jaga into one Node file, `dist-agent/pos-jaga.mjs`, with the rule pack and
 * every dependency bundled in, so a server only needs Node.js 20+ (no npm install, no network).
 */
export default defineConfig({
  resolve: {
    alias: { '@': path.resolve(import.meta.dirname, './src') },
  },
  ssr: { noExternal: true, target: 'node' },
  build: {
    ssr: 'src/agent/cli.ts',
    outDir: 'dist-agent',
    emptyOutDir: true,
    target: 'node20',
    minify: false,
    rollupOptions: {
      output: { entryFileNames: 'pos-jaga.mjs', banner: '#!/usr/bin/env node' },
    },
  },
})
