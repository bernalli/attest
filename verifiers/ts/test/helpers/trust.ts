/**
 * Building trust material the way a CONSUMER has to build it (plan section 5.8).
 *
 * WHY THESE THREE LINES ARE A FILE
 * --------------------------------
 * `JSON.stringify` is the obvious way to turn a document into bytes and it is
 * wrong here in a way that does not announce itself: the parser hands back
 * integers as `bigint`, and `JSON.stringify` throws on the first one. A test
 * that reached for it would appear to work for as long as its fixtures had no
 * `manifest_version`, and then fail on the fixture that has one — which is
 * every real manifest.
 *
 * `canonicalBytes` is also what every consumer recipe in section 5.8 uses, so
 * a helper that used anything else would be exercising a path no caller takes.
 * One place, so no test has to remember.
 */
import { canonicalBytes, type JsonObject, type JsonValue } from '../../src/canon.js'
import { KeyManifest, TrustStore, parseKeyManifest, parseTrustStore } from '../../src/trustMaterial.js'

/** A document as the bytes a store is imported from. Never `JSON.stringify`. */
export function storeBytes(doc: JsonValue): Uint8Array {
  return canonicalBytes(doc)
}

/** The snapshot a well-formed document imports to. */
export function store(doc: JsonValue): TrustStore {
  return parseTrustStore(storeBytes(doc))
}

/** The snapshot one key manifest document imports to. */
export function keyManifest(manifest: JsonValue): KeyManifest {
  return parseKeyManifest(canonicalBytes(manifest))
}

/**
 * A minimal well-formed key manifest, as DATA.
 *
 * Deliberately not signed and not valid: this suite measures the BOUNDARY —
 * which types survive it, which documents it refuses — and nothing downstream
 * of it. A fixture carrying real keys would suggest the boundary checks them,
 * and section 5.3 is explicit that it does not.
 */
export function manifestDoc(issuer: string, version = 1n): JsonObject {
  return { issuer, manifest_version: version, keys: [] }
}

/**
 * A store document with the members named in `present`, and no others.
 *
 * Absence is a first-class case here (D17): `chains`, `artifact_manifests` and
 * `artifact_manifest_chains` absent is a DIFFERENT document from the same three
 * present and empty, and the two must stay apart all the way to `toBytes()`.
 * Building the document by member name rather than by object literal is what
 * lets a test say which of the two it means.
 */
export function storeDoc(issuers: readonly string[], present: readonly string[]): JsonObject {
  const doc: JsonObject = {}
  const manifests: JsonObject = {}
  const provenance: JsonObject = {}
  for (const issuer of issuers) {
    manifests[issuer] = manifestDoc(issuer)
    provenance[issuer] = 'tls'
  }
  doc.manifests = manifests
  doc.provenance = provenance
  if (present.includes('chains')) {
    const chains: JsonObject = {}
    for (const issuer of issuers) chains[issuer] = [manifestDoc(issuer)]
    doc.chains = chains
  }
  if (present.includes('artifact_manifests')) {
    const artifacts: JsonObject = {}
    for (const issuer of issuers) artifacts[issuer] = { 'series-1': manifestDoc(issuer) }
    doc.artifact_manifests = artifacts
  }
  if (present.includes('artifact_manifest_chains')) {
    const artifactChains: JsonObject = {}
    for (const issuer of issuers) artifactChains[issuer] = { 'series-1': [manifestDoc(issuer)] }
    doc.artifact_manifest_chains = artifactChains
  }
  return doc
}
