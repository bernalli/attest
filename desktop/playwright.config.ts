import { defineConfig, devices } from '@playwright/test'

// No webServer, deliberately: every scenario opens a file:// URL. A dev server would
// defeat the point — the artifact must work with no server anywhere, and a suite that
// quietly serves the page over HTTP proves nothing about the file a buyer double-clicks.
//
// webkit runs in CI only. Installing its system libraries pulls 202 packages onto a
// shared development container, and WebKit-on-Linux approximates Safari rather than
// being it: the real Safari check is the manual QA gate before release.
const CI = !!process.env.CI

export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: CI,
  reporter: 'list',
  projects: [
    {
      name: 'chromium',
      use: {
        ...devices['Desktop Chrome'],
        // DNS taken away beneath the page, so "no request left the file:// scheme" is
        // not resting on the page's own good behaviour. Chromium only: the flag is
        // Chromium's, and the collectors that DO run everywhere are the authority.
        launchOptions: { args: ['--host-resolver-rules=MAP * ~NOTFOUND'] },
      },
    },
    { name: 'firefox', use: { ...devices['Desktop Firefox'] } },
    ...(CI ? [{ name: 'webkit', use: { ...devices['Desktop Safari'] } }] : []),
  ],
})
