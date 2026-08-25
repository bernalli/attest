# attest-verifier

An independent TypeScript implementation of an attest verifier, covering both published profiles: [v0.1](../../docs/spec/attest-v0.1.md) (Ed25519) and [v0.2](../../docs/spec/attest-v0.2.md) (hybrid Ed25519 + ML-DSA-65, plus Stage 2 transparency and anchoring evidence). It checks a signed attest receipt envelope and reports its signature, schema, trust, revocation, and buyer-binding status — it does not issue, sign, or mutate receipts, manifests, or revocation records. Issuance is the Python reference implementation's job (`attest` package, repo root); this package only ever reads.

## Independence claim

This verifier shares no code with the Python reference implementation. It is a from-scratch reimplementation of the attest verification algorithm (v0.1 design §11, extended by the v0.2 delta spec) in TypeScript:

- **No shared modules, no shared runtime.** The strict JSON parser, JCS-style canonical serializer, Ed25519 verification, key/artifact manifest logic, revocation classification, and buyer-binding checks are each written independently in `src/`, against the spec text and the language-neutral conformance vectors — not against the Python source.
- **Crypto via [`@noble/curves`](https://github.com/paulmillr/noble-curves) and [`@noble/hashes`](https://github.com/paulmillr/noble-hashes)**, pure-JS, audited, dependency-minimal libraries — not libsodium (which the Python reference uses via `pynacl`) and not any WASM build of libsodium. Base64url encode/decode (`src/b64u.ts`) is hand-rolled on `btoa`/`atob`, with no external dependency.
- Two independent implementations converging on identical output for the same input is the actual evidence of a correct, unambiguous specification — that convergence is exactly what the conformance suite below checks.

## Install / build

From npm:

```sh
npm install attest-verifier
```

From a repo checkout:

```sh
npm install
npm run build       # tsc -p tsconfig.json -> dist/
npm run typecheck   # tsc --noEmit, strict
```

## The `verify()` API

```ts
export function verify(
  envelopeBytes: Uint8Array,
  trustStore: TrustStore,
  revocationView?: JsonValue[] | null,
  disclosure?: Disclosure | null,
  maxRevocationRecords?: number,
  options?: VerifyTransparencyOptions,   // { transparency?, logKeys?, anchorPolicy? } — v0.2 Stage 2
): VerificationResult

export function isOk(r: VerificationResult): boolean // signature=valid && schema=valid && revocation!=='revoked' && errors.length===0
```

`maxRevocationRecords` bounds the untrusted `revocationView` (default 10000); a view larger than the cap is not evaluated and fails closed (an `errors` entry, so `isOk()` is `false`) for a revocable receipt, or warns for an irrevocable one.

`options` is how v0.2 Stage 2 evidence enters: `transparency` (the inclusion evidence accompanying the receipt), `logKeys` (the log keys you pin, in your own trust store — never taken from the bundle), and `anchorPolicy` (including the CRQC horizon). Omit it entirely and verification behaves exactly as before, offline and log-free; supply it and the result additionally carries `transparency` / `corroboration`, which never upgrade the `trust` verdict.

`envelopeBytes` is the raw receipt envelope bytes exactly as received (this package parses them itself with a strict, duplicate-key-rejecting JSON reader — never pre-parse with `JSON.parse` and re-stringify, or you'll silently paper over malformed input the reference parser is required to reject). `trustStore` is `{ manifests: Record<string, JsonObject>, provenance: Record<string, string>, chains?: Record<string, JsonObject[]> }` — the issuer key manifests you trust, how you obtained each issuer's manifest (`"tls"` or otherwise), and optionally each issuer's manifest history for rotation-continuity checking.

**Gotcha:** any JSON object you build yourself and pass in as part of `trustStore` or `revocationView` (manifests, revocation records) must represent JSON integers as `bigint`, not `number` — this package's canonical serializer (used internally to re-verify manifest and revocation-record signatures) only accepts `bigint` for integers, by design, to avoid IEEE-754 precision loss on large values. Plain `JSON.parse` gives you `number` and will make those internal self-verify checks fail silently. Parse such data with the exported `loadsStrict()` instead (it returns the same bigint-typed `JsonObject`/`JsonValue` that `verify()` uses internally), or convert integer fields to `bigint` by hand.

### Node usage

```ts
import { readFileSync } from 'node:fs'
import { verify, isOk, loadsStrict } from 'attest-verifier'

const envelopeBytes = readFileSync('./receipt.attest.json')
const trustData = loadsStrict(readFileSync('./issuer-manifests.json')) as any

const result = verify(envelopeBytes, {
  manifests: trustData.manifests,
  provenance: trustData.provenance,
  chains: trustData.chains ?? {},
})

if (isOk(result)) {
  console.log('valid receipt, trust:', result.trust)
} else {
  console.error('rejected:', result.errors, result.warnings)
}
```

### Browser usage

Nothing in `src/` touches `node:*` APIs — base64 uses `btoa`/`atob`, crypto is pure-JS `@noble/*` — so the same build runs unmodified in a browser or any other Web-API runtime:

```html
<script type="module">
  import { verify, isOk, loadsStrict } from 'https://esm.sh/attest-verifier'

  const envelopeBytes = new Uint8Array(await (await fetch('/receipt.attest.json')).arrayBuffer())
  const trustData = loadsStrict(new Uint8Array(await (await fetch('/issuer-manifests.json')).arrayBuffer())) as any

  const result = verify(envelopeBytes, {
    manifests: trustData.manifests,
    provenance: trustData.provenance,
    chains: trustData.chains ?? {},
  })

  document.body.textContent = isOk(result) ? 'valid' : `rejected: ${result.errors.join(', ')}`
</script>
```

## Conformance

```sh
npm test -- conformance
```

This runs `test/conformance.test.ts`, which discovers every leaf directory under [`docs/spec/vectors/`](../../docs/spec/vectors/) (any directory containing an `expected.json`, walked recursively so multi-part vectors like `07-unicode-canon/a-...` and `17-binding-proven/b-...` are included), and routes each leaf to the surface its files name. Most go through this package's `verify()` — envelope bytes, trust store, revocation view, disclosure, and the Stage 2/3 evidence channels — and are matched against `expected.json` with exact match on `signature`/`schema`/`trust`, exact match on `revocation`/`binding`/`ok` when the key is present, exact list match on `errors`/`warnings` when present, and substring containment for `errors_contains`/`warnings_contains`. A leaf carrying `chain.json` goes to `auditChain` instead (v0.2 §17.5), and a leaf carrying `witness-quorum.json` to `evaluateActivationWitnessQuorum` (v0.2 §11.4) — those two surfaces have result shapes of their own, and a quorum leaf carries no envelope or trust store at all. These are the same match rules and the same routing the Python reference implementation's `tests/test_vectors.py` applies to the identical vector files. A guard test asserts at least 130 leaves are discovered, so a loader bug that silently skips vectors fails loudly instead of passing on a truncated set.

**Passing every vector in `docs/spec/vectors/` — reproducing every `expected.json` exactly, with zero vectors skipped — is the definition of attest conformance for this implementation.**

This verifier implements both published profiles: v0.1 (Ed25519) and v0.2, which adds the hybrid Ed25519 + ML-DSA-65 signature profile and the Stage 2 transparency/anchoring evidence — see `src/mldsa.ts`, `src/transparency.ts`, `src/tlog.ts` and `src/anchor.ts`. Hybrid verification is AND semantics: both signature legs must verify or the receipt is rejected. Run `npm test` for the full suite (parser, canonicalization, Ed25519, manifests, revocation, commitment, schema, and this conformance runner together).
