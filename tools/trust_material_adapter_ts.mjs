#!/usr/bin/env node
// The TypeScript half of the trust-material differential: same bytes in, the
// boundary's OBSERVABLE answers out.
//
// It reports what a caller can see and nothing else — whether the document was
// admitted, the refusal text, the member the refusal blames, and the issuer
// list — because the property under measurement is that two conforming cores
// answer the same, not that they are written alike.
//
// Reads `dist/`, not `src/`: that is what npm publishes and what a consumer
// runs. A differential against the TypeScript sources would measure a build
// nobody installs.
//
// Usage: node tools/trust_material_adapter_ts.mjs <corpus.json>
//   corpus.json : [{ "id": "...", "b64": "<document bytes, base64>" }, ...]
//   stdout      : one JSON object per line, in input order

import { readFileSync } from 'node:fs'
import { pathToFileURL } from 'node:url'
import path from 'node:path'

const corpusPath = process.argv[2]
if (corpusPath === undefined) {
  console.error('usage: trust_material_adapter_ts.mjs <corpus.json>')
  process.exit(2)
}

const here = path.dirname(new URL(import.meta.url).pathname)
const dist = path.resolve(here, '..', 'verifiers', 'ts', 'dist', 'trustMaterial.js')
const { parseTrustStore, TrustMaterialError } = await import(pathToFileURL(dist).href)

const corpus = JSON.parse(readFileSync(corpusPath, 'utf8'))
const out = []
for (const item of corpus) {
  const bytes = new Uint8Array(Buffer.from(item.b64, 'base64'))
  try {
    const store = parseTrustStore(bytes)
    // The gate's NEGATIVE CONTROL, and it lives here rather than in the product
    // on purpose: it mutates the MEASURING side, so it proves the comparator can
    // see an issuer-order divergence without ever touching what ships. A
    // differential that has never been seen to fail is not a differential.
    const injected = process.env.TM_DIFF_INJECT === 'issuers-reversed'
    const issuers = injected ? store.issuers().reverse() : store.issuers()
    out.push({ id: item.id, admitted: true, issuers })
  } catch (e) {
    if (!(e instanceof TrustMaterialError)) {
      // A refusal that is not the boundary's own is a fact worth reporting
      // rather than smoothing over: the Python side never produces one, so a
      // difference here is a divergence and must not look like an ordinary
      // refusal.
      out.push({ id: item.id, admitted: false, foreign: String(e && e.message) })
      continue
    }
    out.push({ id: item.id, admitted: false, message: e.message, member: e.member ?? null })
  }
}
process.stdout.write(out.map((o) => JSON.stringify(o)).join('\n') + '\n')
