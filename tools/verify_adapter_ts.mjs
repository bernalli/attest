#!/usr/bin/env node
// The TypeScript half of the receipt-verification differential
// (tools/verify_differential.py): many cases in, one normalized verdict per
// case out, so the driver spawns node once per run instead of once per case.
//
// Reads `dist/`, not `src/`: that is what npm publishes and what a consumer
// runs. Build it first with `npm run build --prefix verifiers/ts`.
//
// stdin, JSON lines, in this order:
//   {"store_id": "...", "store": "<trust store document bytes, base64>"}   (any number)
//   {"id": "...", "store_id": "...", "envelope": "<envelope bytes, base64>"} (any number)
// stdout: one JSON object per case line, in input order, nothing else.
//
// The verdict shape is the one tools/verify_differential.py builds for the
// Python core, member for member:
//   {"verdict": "ok" | "invalid", "result": {...the conformance adapter's fields}}
//   {"verdict": "store_refused"}  the trust store document itself was refused
//   {"verdict": "crash", "error": "..."}  verify() THREW
// A throw is never folded into `invalid`: a verifier that throws where the
// other one answers is exactly the defect class this differential exists to
// find, and mapping it to a refusal would hide it behind a matching verdict.

import { readFileSync } from 'node:fs'
import { pathToFileURL } from 'node:url'
import path from 'node:path'

const here = path.dirname(new URL(import.meta.url).pathname)
const distDir = path.resolve(here, '..', 'verifiers', 'ts', 'dist')
const { verify, isOk, parseTrustStore } = await import(pathToFileURL(path.join(distDir, 'index.js')).href)
const { TrustMaterialError } = await import(pathToFileURL(path.join(distDir, 'trustMaterial.js')).href)

const fromB64 = (s) => new Uint8Array(Buffer.from(s, 'base64'))

// Field for field what tools/conformance_adapter_ts.mjs reports, so the two
// differentials compare the same surface.
function resultToJson(r) {
  return {
    signature: r.signature,
    schema: r.schema,
    trust: r.trust,
    revocation: r.revocation,
    binding: r.binding,
    transparency: r.transparency,
    corroboration: r.corroboration,
    manifest_freshness: r.manifest_freshness,
    grant: r.grant,
    grant_trust: r.grant_trust,
    publisher_authority: r.publisher_authority,
    publisher_authority_trust: r.publisher_authority_trust,
    ok: isOk(r),
    errors: [...r.errors],
    warnings: [...r.warnings],
  }
}

const crash = (e) => ({
  verdict: 'crash',
  error: e instanceof Error ? `${e.constructor.name}: ${e.message}` : `thrown non-Error: ${String(e)}`,
})

const stores = new Map()
const out = []
for (const line of readFileSync(0, 'utf8').split('\n')) {
  if (line.trim() === '') continue
  const item = JSON.parse(line)
  if (item.id === undefined) {
    let store
    try {
      store = { ok: true, value: parseTrustStore(fromB64(item.store)) }
    } catch (e) {
      store = e instanceof TrustMaterialError ? { ok: false, refused: true } : { ok: false, error: e }
    }
    stores.set(item.store_id, store)
    continue
  }
  const store = stores.get(item.store_id)
  if (store === undefined) throw new Error(`case ${item.id}: unknown store ${item.store_id}`)
  let verdict
  if (!store.ok) {
    verdict = store.refused ? { verdict: 'store_refused' } : crash(store.error)
  } else {
    try {
      const r = verify(fromB64(item.envelope), store.value)
      verdict = { verdict: isOk(r) ? 'ok' : 'invalid', result: resultToJson(r) }
    } catch (e) {
      verdict = crash(e)
    }
  }
  out.push(JSON.stringify(verdict))
}
process.stdout.write(out.join('\n') + (out.length ? '\n' : ''))
