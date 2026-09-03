import { defineConfig } from 'vite'

export default defineConfig({
  base: './',
  build: { target: 'es2022' },
  server: {
    // src/exhibits.ts compiles two of the project's own conformance vectors
    // into the page (`?raw`), and they live above this root in
    // docs/spec/vectors. The production build resolves that by itself; the
    // dev server refuses to serve outside its root unless told, so `npm run
    // dev` would 403 on exactly the files the §19 exhibit is made of.
    // Named rather than `'..'`: the exhibits need one directory, not the repo.
    // The root is NOT implied once `allow` is given — Vite appends only its own
    // client directory — so without '.' the dev server answers 403 to
    // index.html and to every module under src/. Exercised by test/dev-server.test.ts,
    // which is the only thing in this repo that runs this configuration at all.
    fs: { allow: ['.', '../docs/spec/vectors'] },
  },
})
