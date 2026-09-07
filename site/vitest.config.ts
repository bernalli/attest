import { configDefaults, defineConfig } from 'vitest/config'

export default defineConfig({
  // NOT redundant with the identical line in vite.config.ts: vitest ignores vite.config.ts
  // entirely whenever a vitest.config.ts exists, so the allow-list declared there governs
  // `npm run dev` and `npm run build` and reaches the test run not at all. Until vitest 3
  // the omission was invisible — the tests were transformed by vitest's own bundled vite 5,
  // which did not apply the server.fs check to module-runner ids. vite 6 does, so the
  // exhibits that import ../docs/spec/vectors/**/*.json?raw failed to load as
  // "Denied ID", taking eight files and 111 assertions out of collection at once.
  server: { fs: { allow: ['.', '../docs/spec/vectors'] } },
  test: { environment: 'node', exclude: [...configDefaults.exclude, 'e2e/**'] },
})
