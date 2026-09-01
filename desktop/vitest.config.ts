import { configDefaults, defineConfig } from 'vitest/config'

// Mirrors the site's configuration deliberately: the default environment is `node`,
// and the few tests that need a DOM declare `// @vitest-environment jsdom` at the top
// of the file, as the site's DOM tests already do. Making jsdom the default here would
// diverge from the suite this package borrows its modules from.
//
// e2e/** is excluded: those run under Playwright against file:// URLs, not under vitest.
export default defineConfig({
  test: { environment: 'node', exclude: [...configDefaults.exclude, 'e2e/**'] },
})
