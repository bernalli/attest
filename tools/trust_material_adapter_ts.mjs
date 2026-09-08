#!/usr/bin/env node
// The TypeScript half of the cross-core differential: same bytes in, the
// boundary's OBSERVABLE answers out.
//
// It reports what a caller can see and nothing else — whether the document was
// admitted, the refusal text, the member the refusal blames, and whatever that
// surface exposes as an ordered result — because the property under measurement
// is that two conforming cores answer the same, not that they are written alike.
//
// TWO SURFACES, ONE ENGINE. `store` measures `parseTrustStore`; `manifest`
// measures `parseKeyManifest` and the ordered list `duplicateKids` derives from
// the admitted document. They are never compared against each other: the store
// has a grammar and the manifest deliberately does not (plan section 5.3), so a
// cross-surface comparison would report the contract as a divergence.
//
// The manifest surface's input stays the DOCUMENT, not a hand-built entries
// array: `parseKeyManifest(bytes).data()` is what both cores derive the entries
// from, so the differential keeps its property — same bytes, two answers —
// instead of comparing two calls assembled separately, which looks like the
// same measurement and is a weaker one.
//
// Reads `dist/`, not `src/`: that is what npm publishes and what a consumer
// runs. A differential against the TypeScript sources would measure a build
// nobody installs.
//
// Usage: node tools/trust_material_adapter_ts.mjs <corpus.json> <store|manifest>
//   corpus.json : [{ "id": "...", "b64": "<document bytes, base64>" }, ...]
//   stdout      : one JSON object per line, in input order

import { readFileSync } from 'node:fs'
import { pathToFileURL } from 'node:url'
import path from 'node:path'

const corpusPath = process.argv[2]
const surface = process.argv[3]
if (corpusPath === undefined || (surface !== 'store' && surface !== 'manifest')) {
  console.error('usage: trust_material_adapter_ts.mjs <corpus.json> <store|manifest>')
  process.exit(2)
}

const here = path.dirname(new URL(import.meta.url).pathname)
const distDir = path.resolve(here, '..', 'verifiers', 'ts', 'dist')
const load = (name) => import(pathToFileURL(path.join(distDir, name)).href)
const { parseTrustStore, parseKeyManifest, TrustMaterialError } = await load('trustMaterial.js')
const { duplicateKids } = await load('manifests.js')

// The gate's NEGATIVE CONTROL, and it is PER SURFACE on purpose: one injection
// covering two surfaces can be blind on one of them and green anyway, which
// would be this differential's own defect class applied to the instrument that
// exists to find it. Each value below perturbs the ordered result of exactly
// one surface, and it perturbs the MEASURING side — never the product.
const inject = process.env.TM_DIFF_INJECT ?? ''
const reverseIf = (flag, list) => (inject === flag ? [...list].reverse() : list)

const corpus = JSON.parse(readFileSync(corpusPath, 'utf8'))
const out = []
for (const item of corpus) {
  const bytes = new Uint8Array(Buffer.from(item.b64, 'base64'))
  try {
    if (surface === 'store') {
      const store = parseTrustStore(bytes)
      out.push({ id: item.id, admitted: true, ordered: reverseIf('issuers-reversed', store.issuers()) })
    } else {
      const manifest = parseKeyManifest(bytes)
      const kids = duplicateKids(manifest.data()['keys'])
      out.push({ id: item.id, admitted: true, ordered: reverseIf('dupkids-reversed', kids) })
    }
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
