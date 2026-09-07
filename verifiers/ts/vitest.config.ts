import { defineConfig } from 'vitest/config'

// The 5000ms default stays in force for the suite. The two cases that need more than that
// carry their own timeout as a third argument to `it`, next to the code that earns it --
// raising the bound here instead would have bought reporting for two tests and sold
// interruption for the other 1877, because vitest lets a synchronous body run to the end
// and only reports it late, while an asynchronous one is genuinely cut off at the bound.
export default defineConfig({
  test: { include: ['test/**/*.test.ts'] },
})
