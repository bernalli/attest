import { defineConfig } from 'vite'

// `base: './'` keeps every emitted reference relative. It is what makes the build
// openable from a path rather than a server — the multi-file output still cannot run
// from file:// (the browser blocks its ES module on an opaque origin), which is why a
// later step inlines everything into one file; relative paths are the precondition.
export default defineConfig({
  base: './',
  build: {
    target: 'es2022',
    // `modulePreload: false` removes vite's preload POLYFILL, which is not optional
    // decoration here: it ships a `fetch(i.href, s)` that walks the document for
    // `<link rel=modulepreload>` elements. This artifact has none — the whole bundle is
    // inlined — so the call could never fire, but the mandate is that the app be UNABLE
    // to make a request, and a `fetch(` in the shipped bytes is not that. The inliner's
    // scanner refuses the build over it, which is how it was found.
    modulePreload: false,
  },
})
