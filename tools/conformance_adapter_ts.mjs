// The attest-verifier (TypeScript) conformance adapter for
// tools/conformance_runner.py.
//
// usage: node conformance_adapter_ts.mjs LEAF_DIR
//
// REQUIRES a build first: `npm run build --prefix verifiers/ts` — this file
// imports the COMPILED `verifiers/ts/dist/` (relative path), never
// `verifiers/ts/src/`. Node >= 20, ESM.
//
// Reads one conformance-corpus leaf directory (see
// docs/spec/vectors/README.md for the corpus contract) and prints the
// leaf's VerificationResult (or, for a chain.json leaf, its
// ChainAuditResult) as ONE JSON object on stdout — nothing else on stdout,
// ever.
//
// The loader functions below duplicate (never import) the loader semantics
// of verifiers/ts/test/helpers/vectors.ts byte-for-byte, including the
// strict-parse (bigint) routing for manifests.json, revocation.json,
// transparency.json, revocation-evidence.json, transfer-view.json, and
// chain.json — and the exact verify(...)/auditChain(...) call shapes of
// verifiers/ts/test/conformance.test.ts. Those two files remain the source
// of truth for this adapter's behavior; this file is NOT generated from
// them and must be kept in sync by hand.

import { readFileSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import { verify, isOk, auditChain, loadsStrict } from '../verifiers/ts/dist/index.js'
import { b64uDecode } from '../verifiers/ts/dist/b64u.js'

const loadJson = (p) => JSON.parse(readFileSync(p, 'utf-8'))

// manifests.json / revocation.json / transparency.json /
// revocation-evidence.json / transfer-view.json / chain.json all feed
// verifier code paths that re-canonicalize the data via canonicalBytes(),
// which only accepts `bigint` for JSON integers — a plain JSON.parse yields
// `number`, which would make the self-verify/re-serialize step throw (or,
// worse, be silently swallowed as `false` by a `catch`), a silent fail-open.
// Route these through the SAME strict parser the verifier itself uses for
// envelope bytes so integers arrive as bigint. See vectors.ts's
// loadJsonStrict comment for the same reasoning.
const loadJsonValueStrict = (p) => loadsStrict(new Uint8Array(readFileSync(p)))
const loadJsonStrict = (p) => loadJsonValueStrict(p)

function envelopeBytes(dir) {
  const raw = join(dir, 'envelope.raw.json')
  if (existsSync(raw)) return new Uint8Array(readFileSync(raw))
  return new Uint8Array(readFileSync(join(dir, 'envelope.json')))
}

function trustStore(dir) {
  const d = loadJsonStrict(join(dir, 'manifests.json'))
  return {
    manifests: d.manifests,
    provenance: d.provenance,
    chains: d.chains ?? {},
    // G2/G3 (attest-versioning.md rev 4, group 31 only) — every other leaf
    // keeps these at the empty-object default, same convention as chains.
    artifact_manifests: d.artifact_manifests ?? {},
    artifact_manifest_chains: d.artifact_manifest_chains ?? {},
  }
}

function revocationView(dir) {
  const p = join(dir, 'revocation.json')
  return existsSync(p) ? [loadJsonStrict(p)] : null
}

function disclosure(dir) {
  const p = join(dir, 'disclosure.json')
  if (!existsSync(p)) return null
  const d = loadJson(p)
  if ('salt_b64u' in d) {
    return {
      identifier: d.identifier,
      identifier_type: d.identifier_type,
      salt: b64uDecode(d.salt_b64u),
    }
  }
  return { challenge: [b64uDecode(d.nonce_b64u), b64uDecode(d.sig_b64u)] }
}

// group 28 (transparency/corroboration conformance corpus) only.
function transparencyEvidence(dir) {
  const p = join(dir, 'transparency.json')
  return existsSync(p) ? loadJsonStrict(p) : null
}

function logKeys(dir) {
  const p = join(dir, 'log-keys.json')
  if (!existsSync(p)) return null
  return loadJson(p).map((entry) => ({
    origin: entry.origin,
    name: entry.name,
    ed25519Pub: b64uDecode(entry.ed25519_pub_b64u),
    mldsaPub: b64uDecode(entry.mldsa_pub_b64u),
  }))
}

function anchorPolicy(dir) {
  const p = join(dir, 'anchor-policy.json')
  if (!existsSync(p)) return null
  const data = loadJson(p)
  const pinnedHeaders = {}
  for (const [headerHash, header] of Object.entries(data.pinned_headers)) {
    pinnedHeaders[headerHash] = {
      headerHash: header.header_hash,
      merkleRoot: header.merkle_root,
      time: header.time,
    }
  }
  return { pinnedHeaders, crqcHorizon: data.crqc_horizon }
}

// group 33 (logged-revocation conformance corpus, G5/TM-47) only — a
// DIFFERENT evidence channel from transparency.json.
function revocationEvidence(dir) {
  const p = join(dir, 'revocation-evidence.json')
  return existsSync(p) ? loadJsonStrict(p) : null
}

// group 35 (transfer conformance corpus, v0.2 §17 Stage 3) only.
function transferView(dir) {
  const p = join(dir, 'transfer-view.json')
  return existsSync(p) ? loadJsonValueStrict(p) : null
}

// group 39 (witness-corroboration conformance corpus, v0.2 §11.4, P1.1b)
// only: the TRUSTED attest-witness-policy-v1 DOCUMENT, handed to verify() as
// `witnessPolicy`. Plain JSON.parse, like log-keys.json/anchor-policy.json:
// this is trusted configuration, and verify()'s own validateWitnessPolicy()
// runs parsePolicy() over the document.
function witnessPolicy(dir) {
  const p = join(dir, 'witness-policy.json')
  return existsSync(p) ? loadJson(p) : null
}

// group 36 only: auditChain takes ONE trusted keyManifest, not a full
// TrustStore — every group 36 leaf's manifests.json trusts exactly one
// issuer, so its sole `manifests` value is that manifest.
function soleKeyManifest(dir) {
  const store = trustStore(dir)
  return Object.values(store.manifests)[0]
}

// group 36 (transfer-chain conformance corpus, v0.2 §17.5) only: a leaf
// containing chain.json is routed to auditChain instead of verify().
function chainInput(dir) {
  const p = join(dir, 'chain.json')
  if (!existsSync(p)) return null
  const parsed = loadJsonValueStrict(p)
  return {
    payloads: parsed.payloads,
    transferView: parsed.transfer_view,
    revocationView: parsed.revocation_view,
  }
}

function verifyResultToJson(r) {
  return {
    signature: r.signature,
    schema: r.schema,
    trust: r.trust,
    revocation: r.revocation,
    binding: r.binding,
    transparency: r.transparency,
    corroboration: r.corroboration,
    manifest_freshness: r.manifest_freshness,
    ok: isOk(r),
    errors: [...r.errors],
    warnings: [...r.warnings],
  }
}

function chainResultToJson(r) {
  return {
    valid: r.valid,
    link_status: [...r.linkStatus],
    errors: [...r.errors],
    warnings: [...r.warnings],
  }
}

function runLeaf(dir) {
  const chain = chainInput(dir)
  if (chain !== null) {
    const keys = logKeys(dir)
    const policy = anchorPolicy(dir)
    if (keys === null || policy === null) {
      throw new Error(`${dir}: chain.json leaf missing log-keys.json/anchor-policy.json`)
    }
    const result = auditChain(
      chain.payloads,
      chain.transferView,
      chain.revocationView,
      soleKeyManifest(dir),
      keys,
      policy,
    )
    return chainResultToJson(result)
  }

  const result = verify(envelopeBytes(dir), trustStore(dir), revocationView(dir), disclosure(dir), undefined, {
    transparency: transparencyEvidence(dir),
    logKeys: logKeys(dir),
    anchorPolicy: anchorPolicy(dir),
    revocationEvidence: revocationEvidence(dir),
    transferView: transferView(dir),
    witnessPolicy: witnessPolicy(dir),
  })
  return verifyResultToJson(result)
}

function main(argv) {
  if (argv.length !== 1) {
    process.stderr.write('usage: node conformance_adapter_ts.mjs LEAF_DIR\n')
    return 2
  }
  const output = runLeaf(argv[0])
  process.stdout.write(JSON.stringify(output) + '\n')
  return 0
}

process.exitCode = main(process.argv.slice(2))
