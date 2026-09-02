import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath, URL as NodeURL } from 'node:url'

// Every jsdom test drives the REAL page body, never a hand-kept copy of it.
//
// Three test files used to carry their own trimmed `PAGE` fixture. Each new
// control in index.html then had to be remembered three more times, and a
// control that was forgotten simply went untested while the suite stayed
// green — the page could grow a button that nothing exercised. Reading the
// shipped markup closes that gap by construction, and makes `initApp`'s
// required-element check (`byId` throws) a real gate rather than a formality.
//
// Use node:url's URL explicitly: under jsdom the global URL is jsdom's, which
// fileURLToPath does not recognise (same reason as test/helpers/vectors.ts).
const HERE = fileURLToPath(new NodeURL('.', import.meta.url))
const INDEX_PATH = join(HERE, '..', '..', 'index.html')

const BODY_RE = /<body[^>]*>([\s\S]*)<\/body>/
const SCRIPT_RE = /<script[\s\S]*?<\/script>/g

/** index.html's body, with its module script removed.
 *
 * jsdom does not execute a script inserted through `innerHTML` anyway, so
 * dropping it changes nothing about behaviour — it only keeps the fixture
 * from reading as if the page were bootstrapping itself here. Tests call
 * `initApp` themselves, which is what lets them decide when to start.
 */
export function pageBody(): string {
  const html = readFileSync(INDEX_PATH, 'utf-8')
  const match = BODY_RE.exec(html)
  if (!match) throw new Error(`no <body> in ${INDEX_PATH}`)
  return match[1].replace(SCRIPT_RE, '')
}
