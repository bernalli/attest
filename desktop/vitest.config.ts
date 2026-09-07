import { configDefaults, defineConfig } from 'vitest/config'

// Mirrors the site's configuration deliberately: the default environment is `node`,
// and the few tests that need a DOM declare `// @vitest-environment jsdom` at the top
// of the file, as the site's DOM tests already do. Making jsdom the default here would
// diverge from the suite this package borrows its modules from.
//
// e2e/** is excluded: those run under Playwright against file:// URLs, not under vitest.
//
// The 5000ms default stays in force for the suite. The one case that needs more than that
// carries its own timeout as a third argument to `it`, next to the code that earns it --
// raising the bound here instead would have bought reporting for one test and sold
// interruption for the other 546, because vitest lets a synchronous body run to the end and
// only reports it late, while an asynchronous one is genuinely cut off at the bound.
export default defineConfig({
  test: { environment: 'node', exclude: [...configDefaults.exclude, 'e2e/**'] },
})
