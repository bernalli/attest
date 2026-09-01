import { defineConfig } from 'vite'

// `base: './'` keeps every emitted reference relative. It is what makes the build
// openable from a path rather than a server — the multi-file output still cannot run
// from file:// (the browser blocks its ES module on an opaque origin), which is why a
// later step inlines everything into one file; relative paths are the precondition.
export default defineConfig({
  base: './',
  build: { target: 'es2022' },
})
