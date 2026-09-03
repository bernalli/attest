import { describe, it, expect, afterAll } from 'vitest'
import { createServer, type ViteDevServer } from 'vite'
import { fileURLToPath, URL as NodeURL } from 'node:url'
import { join } from 'node:path'

// `npm run dev` is a configuration nothing in this repo used to execute.
//
// The exhibits compile two conformance vectors into the page with `?raw`, and
// those live above vite's root, so `server.fs.allow` has to name them. That
// setting was first written `['..']` — the whole repository — and then
// narrowed to the one directory that is needed. The narrowed version was
// shipped WITHOUT ONCE STARTING THE DEV SERVER, and it answered 403 to
// index.html and to every module under src/: `allow` REPLACES the default
// rather than extending it, and vite appends only its own client directory.
// Every other suite stayed green, because every other suite tests the built
// bundle, where `fs.allow` does not apply at all.
//
// So this is the one test that runs the dev server as a contributor runs it.
// It is not about the exhibits: it is about the configuration that decides
// whether the development entry point works at all.

const HERE = fileURLToPath(new NodeURL('.', import.meta.url))
const ROOT = join(HERE, '..')

let server: ViteDevServer | null = null

const start = async (): Promise<ViteDevServer> => {
  if (!server) {
    server = await createServer({
      root: ROOT,
      configFile: join(ROOT, 'vite.config.ts'),
      // Port 0: the OS picks a free one, so this never collides with a dev
      // server a contributor already has open, or with the preview server the
      // e2e suite starts.
      server: { port: 0, host: '127.0.0.1' },
      // Nothing here imports a dependency that needs pre-bundling, and the
      // esbuild scan the optimizer starts outlives `close()` — the suite then
      // hangs on teardown rather than on anything this test is about.
      optimizeDeps: { noDiscovery: true, include: [] },
      logLevel: 'error',
    })
    await server.listen()
  }
  return server
}

afterAll(async () => {
  await server?.close()
  server = null
}, 30_000)

const get = async (path: string): Promise<{ status: number; body: string }> => {
  const dev = await start()
  const address = dev.httpServer?.address()
  if (!address || typeof address === 'string') throw new Error('dev server has no port')
  const res = await fetch(`http://127.0.0.1:${address.port}${path}`)
  return { status: res.status, body: await res.text() }
}

describe('the dev server serves the page a contributor opens', () => {
  it('serves index.html itself', async () => {
    const { status, body } = await get('/')
    expect(status, 'GET / on the dev server').toBe(200)
    expect(body).toContain('<div id="bench" hidden>')
  })

  it.each(['/src/main.ts', '/src/exhibits.ts', '/src/styles.css'])(
    'serves %s, which lives under the root',
    async (path) => {
      const { status } = await get(path)
      expect(status, `GET ${path} on the dev server`).toBe(200)
    },
  )

  it('serves the conformance vectors the exhibits compile in, from above the root', async () => {
    // The reason `fs.allow` names a directory at all. A 403 here is the
    // failure the setting exists to prevent; a 403 on the routes above is the
    // failure the fix for it introduced.
    const vector = join(
      ROOT,
      '..',
      'docs/spec/vectors/41-compromise-cutoff/a-rescued-anchored-before-cutoff/envelope.json',
    )
    const { status, body } = await get(`/@fs${vector}?raw`)
    expect(status, 'GET the §19 vector through the dev server').toBe(200)
    expect(body).toContain('payload')
  })

  it('still refuses a file outside both the root and the named directory', async () => {
    // The narrowing was worth doing: the dev server must not hand out the
    // whole repository. This is the half of the change that was right.
    const outside = join(ROOT, '..', 'pyproject.toml')
    const { status } = await get(`/@fs${outside}`)
    expect(status, 'GET a repo file the exhibits do not need').toBe(403)
  })
})
